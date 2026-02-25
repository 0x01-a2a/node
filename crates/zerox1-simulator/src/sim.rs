//! Core simulation loop — one trial, many epochs.

use rand::Rng;
use zerox1_protocol::entropy::{compute as compute_entropy, EntropyParams};

use crate::agent::{generate_epoch, Agent, AgentKind};

// ============================================================================
// Parameters
// ============================================================================

#[derive(Debug, Clone)]
pub struct SimParams {
    /// Total agents in the network.
    pub n_agents:         usize,
    /// Fraction that are cartel members (0.02–0.30).
    pub cartel_fraction:  f64,
    /// Which cartel attack model to use.
    pub cartel_type:      CartelType,
    /// How many epochs to simulate per trial.
    pub n_epochs:         usize,
    /// Base stake each agent must lock (USDC).
    pub base_stake:       f64,
    /// Extra income earned per epoch by an agent with reputation ≥ 50.
    /// Represents the premium a high-rep agent can charge.
    pub rep_premium:      f64,
    /// Fraction of stake slashed when an agent is detected and challenged.
    pub slash_rate:       f64,
    /// Anomaly score above which an agent is considered flagged.
    pub anomaly_threshold: f64,
    /// Entropy computation parameters.
    pub entropy_params:   EntropyParams,
}

impl Default for SimParams {
    fn default() -> Self {
        Self {
            n_agents:          100,
            cartel_fraction:   0.10,
            cartel_type:       CartelType::C1,
            n_epochs:          30,
            base_stake:        10.0,
            rep_premium:       5.0, // USDC per epoch for high-rep agents
            slash_rate:        0.50,
            anomaly_threshold: 0.55,
            entropy_params:    EntropyParams::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CartelType { C1, C2 }

impl std::fmt::Display for CartelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::C1 => write!(f, "C-1 (static hugging)"), Self::C2 => write!(f, "C-2 (rotational evasion)") }
    }
}

// ============================================================================
// Per-trial results
// ============================================================================

#[derive(Debug, Default, Clone)]
pub struct TrialResult {
    /// Per-cartel-agent: epoch at which they were first flagged (None = never).
    pub detection_epochs:     Vec<Option<usize>>,
    /// Per-honest-agent: whether they were ever incorrectly flagged.
    pub false_positives:      Vec<bool>,
    /// Net economic gain for the cartel over the whole trial (USDC).
    /// Positive = attack profitable; negative = attack costly.
    pub cartel_net_profit:    f64,
    /// Total stake slashed from cartel agents (retained for future analysis).
    #[allow(dead_code)]
    pub total_slashed:        f64,
    /// Total reputation premium earned by cartel agents before detection.
    pub total_premium_earned: f64,
}

impl TrialResult {
    pub fn detection_rate(&self) -> f64 {
        let detected = self.detection_epochs.iter().filter(|e| e.is_some()).count();
        detected as f64 / self.detection_epochs.len().max(1) as f64
    }

    pub fn false_positive_rate(&self) -> f64 {
        let fp = self.false_positives.iter().filter(|&&b| b).count();
        fp as f64 / self.false_positives.len().max(1) as f64
    }

    #[allow(dead_code)]
    pub fn median_detection_epoch(&self) -> Option<f64> {
        let mut epochs: Vec<usize> = self.detection_epochs.iter()
            .filter_map(|&e| e)
            .collect();
        if epochs.is_empty() { return None; }
        epochs.sort_unstable();
        let mid = epochs.len() / 2;
        Some(epochs[mid] as f64)
    }
}

// ============================================================================
// Single trial
// ============================================================================

pub fn run_trial<R: Rng>(params: &SimParams, rng: &mut R) -> TrialResult {
    let n_cartel = ((params.n_agents as f64 * params.cartel_fraction) as usize).max(1);
    let n_honest = params.n_agents - n_cartel;

    let cartel_kind = match params.cartel_type {
        CartelType::C1 => AgentKind::CartC1,
        CartelType::C2 => AgentKind::CartC2,
    };

    // Build agent pool.
    let mut honest_agents: Vec<Agent> = (0..n_honest)
        .map(|i| Agent::new(i, AgentKind::Honest, params.base_stake))
        .collect();
    let mut cartel_agents: Vec<Agent> = (0..n_cartel)
        .map(|i| Agent::new(n_honest + i, cartel_kind, params.base_stake))
        .collect();

    // Shared peer ID pools.
    let all_ids: Vec<[u8; 32]> = honest_agents.iter()
        .chain(cartel_agents.iter())
        .map(|a| a.id)
        .collect();
    // Verifiers: first 5 agents act as the verifier pool.
    let verifier_ids: Vec<[u8; 32]> = all_ids.iter().take(5).cloned().collect();

    let mut detection_epochs: Vec<Option<usize>> = vec![None; n_cartel];
    let mut false_positives:  Vec<bool>           = vec![false; n_honest];
    let mut total_premium_earned = 0.0f64;
    let mut total_slashed        = 0.0f64;

    for epoch in 0..params.n_epochs {
        // ── Honest agents ───────────────────────────────────────────────────
        let honest_ids: Vec<[u8; 32]> = honest_agents.iter().map(|a| a.id).collect();

        for (i, agent) in honest_agents.iter_mut().enumerate() {
            let data = generate_epoch(agent, epoch as u64, &all_ids, &verifier_ids, rng);
            let ev   = compute_entropy(&data.batch, &data.message_slots, &params.entropy_params);

            // Update reputation (honest agents earn modest rep).
            agent.reputation += 1.0;

            // Check for false positive.
            if ev.anomaly > params.anomaly_threshold {
                false_positives[i] = true;
            }
        }
        let _ = honest_ids; // suppress unused warning

        // ── Cartel agents ───────────────────────────────────────────────────
        for (i, agent) in cartel_agents.iter_mut().enumerate() {
            if agent.slashed { continue; }

            let data = generate_epoch(agent, epoch as u64, &all_ids, &verifier_ids, rng);
            let ev   = compute_entropy(&data.batch, &data.message_slots, &params.entropy_params);

            // Cartel agents gain inflated reputation faster.
            agent.reputation += 3.0;

            // Earn rep premium if reputation is high enough.
            if agent.reputation >= 50.0 {
                total_premium_earned += params.rep_premium;
            }

            // Detection: if anomaly above threshold, agent gets flagged and slashed.
            if ev.anomaly > params.anomaly_threshold && detection_epochs[i].is_none() {
                detection_epochs[i] = Some(epoch);
                let slash = agent.stake * params.slash_rate;
                total_slashed  += slash;
                agent.stake    -= slash;
                agent.slashed   = true;
            }
        }
    }

    let cartel_net_profit = total_premium_earned - total_slashed;

    TrialResult {
        detection_epochs,
        false_positives,
        cartel_net_profit,
        total_slashed,
        total_premium_earned,
    }
}
