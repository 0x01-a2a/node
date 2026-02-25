mod agent;
mod economy;
mod report;
mod sim;

use clap::Parser;
use rand::SeedableRng;
use rand::rngs::StdRng;
use zerox1_protocol::entropy::{EntropyParams, compute as compute_entropy};

use crate::{
    agent::{Agent, AgentKind, generate_epoch},
    economy::{aggregate, derive_alpha_min, derive_betas},
    sim::{CartelType, SimParams, run_trial},
};

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name    = "zerox1-simulator",
    about   = "Adversarial cartel simulator — derives α_min, β coefficients, and SRI threshold",
)]
struct Cli {
    /// Total agents in the simulated network.
    #[arg(long, default_value_t = 100)]
    agents: usize,

    /// Cartel size as a fraction of total agents (0.02–0.30).
    #[arg(long, default_value_t = 0.10)]
    cartel_fraction: f64,

    /// Cartel attack model: "c1" (static hugging) or "c2" (rotational evasion).
    #[arg(long, default_value = "c1")]
    cartel_type: String,

    /// Number of epochs per trial.
    #[arg(long, default_value_t = 30)]
    epochs: usize,

    /// Number of Monte Carlo trials.
    #[arg(long, default_value_t = 500)]
    trials: usize,

    /// Base stake per agent in USDC.
    #[arg(long, default_value_t = 10.0)]
    base_stake: f64,

    /// Reputation premium per epoch for high-rep agents (USDC).
    #[arg(long, default_value_t = 5.0)]
    rep_premium: f64,

    /// Slash rate when an agent is detected (0.0–1.0).
    #[arg(long, default_value_t = 0.50)]
    slash_rate: f64,

    /// Anomaly score threshold above which an agent is flagged.
    /// Default 0.55 is tuned so that the C-1 cartel (combined Ht+Hb ≈ 0.69)
    /// is detectable but no single component alone (≈ 0.21–0.49) suffices,
    /// which lets the ablation experiment produce meaningful β values.
    #[arg(long, default_value_t = 0.55)]
    anomaly_threshold: f64,

    /// RNG seed for reproducibility.  0 = random seed.
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Output results as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Run a sweep over cartel fractions (0.05, 0.10, 0.20, 0.30) and print
    /// a summary table instead of a single scenario.
    #[arg(long)]
    sweep: bool,
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let cli = Cli::parse();

    let cartel_type = match cli.cartel_type.to_lowercase().as_str() {
        "c2" => CartelType::C2,
        _    => CartelType::C1,
    };

    let base_params = SimParams {
        n_agents:          cli.agents,
        cartel_fraction:   cli.cartel_fraction,
        cartel_type,
        n_epochs:          cli.epochs,
        base_stake:        cli.base_stake,
        rep_premium:       cli.rep_premium,
        slash_rate:        cli.slash_rate,
        anomaly_threshold: cli.anomaly_threshold,
        entropy_params:    EntropyParams::default(),
    };

    if cli.sweep {
        run_sweep(&base_params, cli.trials, cli.seed);
        return;
    }

    let (stats, alpha_min, betas) = run_scenario(&base_params, cli.trials, cli.seed);

    if cli.json {
        report::print_json(&base_params, cli.trials, &stats, alpha_min, &betas);
    } else {
        report::print_report(&base_params, cli.trials, &stats, alpha_min, &betas);
    }
}

// ============================================================================
// Scenario runner
// ============================================================================

fn run_scenario(
    params:   &SimParams,
    n_trials: usize,
    seed:     u64,
) -> (economy::AggregateStats, f64, economy::BetaCoefficients) {
    let mut rng = if seed == 0 {
        StdRng::from_entropy()
    } else {
        StdRng::seed_from_u64(seed)
    };

    eprintln!("Running {n_trials} trials ({} agents, {:.0}% cartel, {} epochs)…",
        params.n_agents,
        params.cartel_fraction * 100.0,
        params.n_epochs,
    );

    let trials: Vec<_> = (0..n_trials)
        .map(|_| run_trial(params, &mut rng))
        .collect();

    let stats     = aggregate(&trials);
    let n_cartel  = ((params.n_agents as f64 * params.cartel_fraction) as usize).max(1);
    let alpha_min = derive_alpha_min(&trials, params, n_cartel);

    // Ablation experiment: measure TPR when each entropy component is removed.
    let betas = ablation_betas(params, n_trials / 5, &mut rng);

    (stats, alpha_min, betas)
}

// ============================================================================
// Ablation experiment → β values
// ============================================================================

/// Run 4 reduced-dimension trials to measure each component's contribution.
fn ablation_betas<R: rand::Rng>(
    params:   &SimParams,
    n_trials: usize,
    rng:      &mut R,
) -> economy::BetaCoefficients {
    let baseline = run_ablation(params, n_trials, rng, true, true, true, true);

    let no_ht = run_ablation(params, n_trials, rng, false, true, true, true);
    let no_hb = run_ablation(params, n_trials, rng, true, false, true, true);
    let no_hs = run_ablation(params, n_trials, rng, true, true, false, true);
    let no_hv = run_ablation(params, n_trials, rng, true, true, true, false);

    derive_betas(baseline, no_ht, no_hb, no_hs, no_hv)
}

/// Run trials with selected entropy components masked (set to 0) and return
/// the mean true-positive rate.
fn run_ablation<R: rand::Rng>(
    params:       &SimParams,
    n_trials:     usize,
    rng:          &mut R,
    use_ht:       bool,
    use_hb:       bool,
    use_hs:       bool,
    use_hv:       bool,
) -> f64 {
    let n_cartel = ((params.n_agents as f64 * params.cartel_fraction) as usize).max(1);
    let n_honest = params.n_agents - n_cartel;
    let cartel_kind = match params.cartel_type {
        CartelType::C1 => AgentKind::CartC1,
        CartelType::C2 => AgentKind::CartC2,
    };

    let all_ids: Vec<[u8; 32]> = (0..params.n_agents).map(|i| {
        let mut id = [0u8; 32]; id[..8].copy_from_slice(&i.to_le_bytes()); id
    }).collect();
    let verifier_ids: Vec<[u8; 32]> = all_ids.iter().take(5).cloned().collect();

    // Build masked entropy params.
    let mut ep = params.entropy_params.clone();
    if !use_ht { ep.w_ht = 0.0; ep.ht_threshold = 0.0; }
    if !use_hb { ep.w_hb = 0.0; ep.hb_threshold = 0.0; }
    if !use_hs { ep.w_hs = 0.0; ep.hs_threshold = 0.0; }
    if !use_hv { ep.w_hv = 0.0; ep.hv_threshold = 0.0; }

    let mut total_detected = 0usize;

    for _ in 0..n_trials {
        let mut cartel_agents: Vec<Agent> = (0..n_cartel)
            .map(|i| Agent::new(n_honest + i, cartel_kind, params.base_stake))
            .collect();

        for epoch in 0..params.n_epochs {
            for agent in &mut cartel_agents {
                if agent.slashed { continue; }
                let data = generate_epoch(agent, epoch as u64, &all_ids, &verifier_ids, rng);
                let ev   = compute_entropy(&data.batch, &data.message_slots, &ep);
                if ev.anomaly > params.anomaly_threshold && !agent.slashed {
                    agent.slashed = true;
                    total_detected += 1;
                }
            }
        }
    }

    // TPR = fraction of cartel agent-epochs that were eventually detected.
    let cartel_agents_total = n_cartel * n_trials;
    total_detected as f64 / cartel_agents_total.max(1) as f64
}

// ============================================================================
// Sweep mode
// ============================================================================

fn run_sweep(base: &SimParams, n_trials: usize, seed: u64) {
    let fractions = [0.05, 0.10, 0.20, 0.30];
    let types     = [CartelType::C1, CartelType::C2];

    println!();
    println!("0x01 Cartel Simulator — Sweep");
    println!();
    println!("{:<8} {:<22} {:>8} {:>8} {:>10} {:>12}",
        "Cartel%", "Type", "TPR%", "FPR%", "Med.Epoch", "α_min($)");
    println!("{}", "─".repeat(72));

    for &ct in &types {
        for &cf in &fractions {
            let params = SimParams {
                cartel_fraction: cf,
                cartel_type:     ct,
                ..base.clone()
            };
            let mut rng = StdRng::seed_from_u64(seed ^ (cf * 1000.0) as u64 ^ ct as u64);
            let trials: Vec<_> = (0..n_trials).map(|_| run_trial(&params, &mut rng)).collect();
            let stats     = aggregate(&trials);
            let n_cartel  = ((params.n_agents as f64 * cf) as usize).max(1);
            let alpha_min = derive_alpha_min(&trials, &params, n_cartel);
            let med_str   = stats.median_detection_epoch
                .map_or("never".to_string(), |e| format!("{e:.0}"));

            println!("{:<8} {:<22} {:>7.1}% {:>7.1}% {:>10} {:>11.0}",
                format!("{:.0}%", cf * 100.0),
                format!("{ct}"),
                stats.mean_detection_rate * 100.0,
                stats.mean_false_pos_rate * 100.0,
                med_str,
                alpha_min,
            );
        }
    }
    println!();
}
