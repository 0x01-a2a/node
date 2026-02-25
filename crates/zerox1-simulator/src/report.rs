//! Human-readable report + JSON output.

use crate::{
    economy::{AggregateStats, BetaCoefficients},
    sim::SimParams,
};

pub fn print_report(
    params:  &SimParams,
    n_trials: usize,
    stats:   &AggregateStats,
    alpha_min: f64,
    betas:   &BetaCoefficients,
) {
    let n_cartel = ((params.n_agents as f64 * params.cartel_fraction) as usize).max(1);

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           0x01 Cartel Simulator — Results                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Network     : {} agents  ({} cartel, {} honest)",
        params.n_agents, n_cartel, params.n_agents - n_cartel);
    println!("  Cartel type : {}", params.cartel_type);
    println!("  Epochs      : {}   Trials: {}", params.n_epochs, n_trials);
    println!("  Base stake  : ${:.0} USDC    Rep premium: ${:.2}/epoch",
        params.base_stake, params.rep_premium);
    println!("  Anomaly τ   : {:.2}   Slash rate: {:.0}%",
        params.anomaly_threshold, params.slash_rate * 100.0);
    println!();
    println!("── Detection ─────────────────────────────────────────────────");
    println!("  True positive rate  : {:.1}%  (cartel agents correctly flagged)",
        stats.mean_detection_rate * 100.0);
    println!("  False positive rate : {:.1}%  (honest agents wrongly flagged)",
        stats.mean_false_pos_rate * 100.0);
    match stats.median_detection_epoch {
        Some(e) => println!("  Median detection    : epoch {e:.0}"),
        None    => println!("  Median detection    : never (cartel undetected)"),
    }
    match stats.p95_detection_epoch {
        Some(e) => println!("  P95 detection       : epoch {e:.0}"),
        None    => println!("  P95 detection       : n/a"),
    }
    println!();
    println!("── Economics ─────────────────────────────────────────────────");
    println!("  Mean net profit     : {:+.2} USDC  ({:.0}% of trials profitable)",
        stats.mean_net_profit, stats.pct_profitable_trials * 100.0);
    println!("  α_min (derived)     : ${alpha_min:.0} USDC");
    println!("  Recommended stake   : ${:.0} USDC  (α_min + 20% safety margin)",
        alpha_min * 1.20);
    println!();
    println!("── Derived Parameters ────────────────────────────────────────");
    println!("  β₁ (anomaly A)      : {:.3}", betas.b1);
    println!("  β₂ (rep decay R)    : {:.3}", betas.b2);
    println!("  β₃ (coordination C) : {:.3}  [GAP-02: pending ownership clustering]", betas.b3);
    println!("  β₄ (systemic S)     : {:.3}  [GAP-06: pending SRI circuit breaker]", betas.b4);
    println!();
    println!("  Stake multiplier formula:");
    println!("    Sv = Sv_base × (1 + {:.3}·A + {:.3}·R + {:.3}·C + {:.3}·S)",
        betas.b1, betas.b2, betas.b3, betas.b4);
    println!();

    if stats.mean_detection_rate < 0.70 {
        println!("  ⚠  Detection rate below 70% — consider lowering anomaly threshold.");
    }
    if stats.mean_false_pos_rate > 0.05 {
        println!("  ⚠  False positive rate above 5% — threshold may be too aggressive.");
    }
    if stats.pct_profitable_trials > 0.10 {
        println!("  ⚠  Attack profitable in >{:.0}% of trials — α_min may need review.",
            stats.pct_profitable_trials * 100.0);
    }
    println!();
}

pub fn print_json(
    params:    &SimParams,
    n_trials:  usize,
    stats:     &AggregateStats,
    alpha_min: f64,
    betas:     &BetaCoefficients,
) {
    let n_cartel = ((params.n_agents as f64 * params.cartel_fraction) as usize).max(1);
    let out = serde_json::json!({
        "network": {
            "n_agents":        params.n_agents,
            "n_cartel":        n_cartel,
            "cartel_fraction": params.cartel_fraction,
            "cartel_type":     format!("{}", params.cartel_type),
            "n_epochs":        params.n_epochs,
            "n_trials":        n_trials,
        },
        "detection": {
            "true_positive_rate":    stats.mean_detection_rate,
            "false_positive_rate":   stats.mean_false_pos_rate,
            "median_detection_epoch": stats.median_detection_epoch,
            "p95_detection_epoch":   stats.p95_detection_epoch,
        },
        "economics": {
            "mean_net_profit":       stats.mean_net_profit,
            "pct_profitable_trials": stats.pct_profitable_trials,
            "alpha_min_usdc":        alpha_min,
            "recommended_stake_usdc": alpha_min * 1.20,
        },
        "derived_params": {
            "beta_1_anomaly":      betas.b1,
            "beta_2_rep_decay":    betas.b2,
            "beta_3_coordination": betas.b3,
            "beta_4_systemic":     betas.b4,
        },
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
