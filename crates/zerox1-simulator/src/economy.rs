//! Economic analysis — derives α_min and β coefficients from trial results.

use crate::sim::{SimParams, TrialResult};

// ============================================================================
// α_min derivation
// ============================================================================

/// Find the minimum base stake that makes the attack unprofitable.
///
/// Runs a binary search over stake values, re-scoring each trial's economics
/// with the new stake level.  Returns the smallest stake (in USDC) where
/// median net profit ≤ 0 across all trials.
pub fn derive_alpha_min(trial_results: &[TrialResult], params: &SimParams, n_cartel: usize) -> f64 {
    let mut lo = params.base_stake;
    let mut hi = params.base_stake * 500.0; // search ceiling

    for _ in 0..40 {
        let mid = (lo + hi) / 2.0;
        if median_profit_at_stake(trial_results, params, n_cartel, mid) <= 0.0 {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    // Round up to nearest USDC.
    hi.ceil()
}

/// Compute median net profit across trials at a given stake level.
fn median_profit_at_stake(
    trials: &[TrialResult],
    params: &SimParams,
    n_cartel: usize,
    stake: f64,
) -> f64 {
    let mut profits: Vec<f64> = trials
        .iter()
        .map(|t| {
            // Re-derive slash total at the new stake level.
            let slash_total = t.detection_epochs.iter().filter(|e| e.is_some()).count() as f64
                * stake
                * params.slash_rate;
            t.total_premium_earned - slash_total
        })
        .collect();

    if profits.is_empty() {
        return 0.0;
    }
    profits.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = profits.len() / 2;
    let _ = n_cartel;
    profits[mid]
}

// ============================================================================
// β coefficient derivation
// ============================================================================

/// Derived weights for the stake multiplier formula.
///
/// Strategy: measure how much detection accuracy drops when each entropy
/// component is zeroed out.  The more a component contributes to detection,
/// the higher its weight.
///
/// C (ownership clustering) and S (SRI) are set to 0 until those modules
/// are built (see GAP-02, GAP-06 in docs/09-security-gaps.md).
#[derive(Debug, Clone)]
pub struct BetaCoefficients {
    /// Weight for anomaly score (A).
    pub b1: f64,
    /// Weight for reputation decay (R).  Placeholder — decay module pending.
    pub b2: f64,
    /// Weight for coordination risk (C).  Zero until GAP-02 closed.
    pub b3: f64,
    /// Weight for systemic risk (S).  Zero until GAP-06 closed.
    pub b4: f64,
}

/// Derive β coefficients from component-ablation experiment.
///
/// `baseline_tpr`   — true-positive rate with all components active
/// `tpr_no_timing`  — TPR when timing entropy (Ht) is removed
/// `tpr_no_bids`    — TPR when bid entropy (Hb) is removed
/// `tpr_no_select`  — TPR when selection entropy (Hs) is removed
/// `tpr_no_verifier`— TPR when verifier entropy (Hv) is removed
pub fn derive_betas(
    baseline_tpr: f64,
    tpr_no_timing: f64,
    tpr_no_bids: f64,
    tpr_no_select: f64,
    tpr_no_verifier: f64,
) -> BetaCoefficients {
    // Contribution of each component = drop in TPR when it is removed.
    let c_ht = (baseline_tpr - tpr_no_timing).max(0.0);
    let c_hb = (baseline_tpr - tpr_no_bids).max(0.0);
    let c_hs = (baseline_tpr - tpr_no_select).max(0.0);
    let c_hv = (baseline_tpr - tpr_no_verifier).max(0.0);

    // The A component (β₁) captures combined contribution of all Ht+Hb+Hs+Hv.
    // Normalise so β₁ + β₂ = 1 (β₃ = β₄ = 0 pending GAP-02 and GAP-06).
    let entropy_contribution = c_ht + c_hb + c_hs + c_hv;
    let total = entropy_contribution + 0.15; // 0.15 reserved for rep decay

    let b1 = if total > 0.0 {
        entropy_contribution / total
    } else {
        0.85
    };
    let b2 = 1.0 - b1;

    BetaCoefficients {
        b1,
        b2,
        b3: 0.0,
        b4: 0.0,
    }
}

// ============================================================================
// Aggregate statistics
// ============================================================================

#[derive(Debug, Clone)]
pub struct AggregateStats {
    pub mean_detection_rate: f64,
    pub mean_false_pos_rate: f64,
    pub median_detection_epoch: Option<f64>,
    pub p95_detection_epoch: Option<f64>,
    pub mean_net_profit: f64,
    pub pct_profitable_trials: f64,
}

pub fn aggregate(trials: &[TrialResult]) -> AggregateStats {
    if trials.is_empty() {
        return AggregateStats {
            mean_detection_rate: 0.0,
            mean_false_pos_rate: 0.0,
            median_detection_epoch: None,
            p95_detection_epoch: None,
            mean_net_profit: 0.0,
            pct_profitable_trials: 0.0,
        };
    }

    let n = trials.len() as f64;

    let mean_detection_rate = trials.iter().map(|t| t.detection_rate()).sum::<f64>() / n;
    let mean_false_pos_rate = trials.iter().map(|t| t.false_positive_rate()).sum::<f64>() / n;
    let mean_net_profit = trials.iter().map(|t| t.cartel_net_profit).sum::<f64>() / n;

    let pct_profitable = trials.iter().filter(|t| t.cartel_net_profit > 0.0).count() as f64 / n;

    // Collect all detection epochs across all trials for percentiles.
    let mut all_epochs: Vec<usize> = trials
        .iter()
        .flat_map(|t| t.detection_epochs.iter().filter_map(|&e| e))
        .collect();
    all_epochs.sort_unstable();

    let median = if all_epochs.is_empty() {
        None
    } else {
        Some(all_epochs[all_epochs.len() / 2] as f64)
    };

    let p95 = if all_epochs.is_empty() {
        None
    } else {
        let idx = (all_epochs.len() as f64 * 0.95) as usize;
        Some(all_epochs[idx.min(all_epochs.len() - 1)] as f64)
    };

    AggregateStats {
        mean_detection_rate,
        mean_false_pos_rate,
        median_detection_epoch: median,
        p95_detection_epoch: p95,
        mean_net_profit,
        pct_profitable_trials: pct_profitable,
    }
}
