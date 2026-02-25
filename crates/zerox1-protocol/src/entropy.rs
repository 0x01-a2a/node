//! Entropy vector computation (doc 3, §5).
//!
//! The entropy vector measures predictability of an agent's behaviour
//! across four dimensions.  Low entropy on any dimension signals suspicious
//! regularity that may indicate cartel coordination or scripted gaming.
//!
//! Components:
//!   Ht — timing entropy     : inter-slot interval distribution
//!   Hb — bid entropy        : bid-value magnitude distribution (log-scale)
//!   Hs — selection entropy  : counterparty selection distribution
//!   Hv — verifier entropy   : notary assignment distribution
//!
//! Anomaly score:
//!   A = Σ w_i × max(0, threshold_i − H_i)
//!
//! Anomaly rises when entropy FALLS below a threshold (agent is too regular).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::batch::{BehaviorBatch, TaskSelection, TypedBid, VerifierAssignment};

// ============================================================================
// Parameters
// ============================================================================

/// Thresholds and weights for the anomaly score computation.
/// All entropy thresholds are in bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyParams {
    /// Anomaly triggers when H falls BELOW these thresholds.
    pub ht_threshold: f64,
    pub hb_threshold: f64,
    pub hs_threshold: f64,
    pub hv_threshold: f64,

    /// Weights for anomaly aggregation (typically sum to 1.0).
    pub w_ht: f64,
    pub w_hb: f64,
    pub w_hs: f64,
    pub w_hv: f64,

    /// Minimum sample count required to include a component in the anomaly
    /// score.  Components with fewer samples return `None` for that H and
    /// are excluded from the weighted sum.
    pub min_samples: u32,
}

impl Default for EntropyParams {
    fn default() -> Self {
        Self {
            // Conservative initial thresholds — observe Phase 0 distributions
            // before tightening.
            ht_threshold: 2.0, // bits
            hb_threshold: 1.5,
            hs_threshold: 1.5,
            hv_threshold: 1.0,

            // Timing and selection are the most informative signals.
            w_ht: 0.35,
            w_hb: 0.20,
            w_hs: 0.30,
            w_hv: 0.15,

            min_samples: 4,
        }
    }
}

// ============================================================================
// Output
// ============================================================================

/// Entropy vector for one agent over one epoch.
///
/// Serialises to JSON for pushing to the aggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyVector {
    pub agent_id: [u8; 32],
    pub epoch:    u64,

    /// Timing entropy in bits (inter-slot intervals, log-bucketed).
    /// `None` when fewer than `min_samples` messages were recorded.
    pub ht: Option<f64>,
    /// Bid-value entropy in bits (log-scale bucketed bid magnitudes).
    pub hb: Option<f64>,
    /// Counterparty selection entropy in bits.
    pub hs: Option<f64>,
    /// Verifier assignment entropy in bits.
    pub hv: Option<f64>,

    /// Weighted anomaly score ≥ 0.  Higher = more suspicious.
    /// A = Σ w_i × max(0, threshold_i − H_i)
    pub anomaly: f64,

    /// Sample counts used for each component.
    pub n_ht: u32,
    pub n_hb: u32,
    pub n_hs: u32,
    pub n_hv: u32,
}

// ============================================================================
// Public entry point
// ============================================================================

/// Compute the entropy vector for `batch`.
///
/// `message_slots`: Solana slot numbers of every message sent during the
/// epoch — used for timing entropy (Ht).  If unavailable, pass an empty
/// slice and Ht will be `None`.
pub fn compute(
    batch:         &BehaviorBatch,
    message_slots: &[u64],
    params:        &EntropyParams,
) -> EntropyVector {
    let ht = timing_entropy(message_slots, params.min_samples);
    let hb = bid_entropy(&batch.bid_values, params.min_samples);
    let hs = selection_entropy(&batch.task_selections, params.min_samples);
    let hv = verifier_entropy(&batch.verifier_ids, params.min_samples);

    let anomaly = weighted_anomaly(ht, hb, hs, hv, params);

    EntropyVector {
        agent_id: batch.agent_id,
        epoch:    batch.epoch_number,
        ht,
        hb,
        hs,
        hv,
        anomaly,
        n_ht: message_slots.len() as u32,
        n_hb: batch.bid_values.len() as u32,
        n_hs: batch.task_selections.len() as u32,
        n_hv: batch.verifier_ids.len() as u32,
    }
}

// ============================================================================
// Component computations
// ============================================================================

/// Ht: timing entropy from inter-slot intervals.
///
/// Sorts message slots, computes consecutive differences, log2-buckets each
/// interval, and returns Shannon entropy of the bucket distribution.
fn timing_entropy(slots: &[u64], min_samples: u32) -> Option<f64> {
    if (slots.len() as u32) < min_samples.max(2) {
        return None;
    }
    let mut sorted = slots.to_vec();
    sorted.sort_unstable();
    let buckets: Vec<u32> = sorted
        .windows(2)
        .map(|w| log2_bucket_u64(w[1] - w[0]))
        .collect();
    Some(shannon_entropy_u32(&buckets))
}

/// Hb: bid-value entropy from log-scale magnitude buckets.
///
/// Uses `floor(log2(|bid_value|))` as the bucket key.
/// Zero bids map to bucket -1.
fn bid_entropy(bids: &[TypedBid], min_samples: u32) -> Option<f64> {
    if (bids.len() as u32) < min_samples {
        return None;
    }
    let buckets: Vec<i32> = bids.iter().map(|b| log2_bucket_i128(b.bid_value)).collect();
    Some(shannon_entropy_i32(&buckets))
}

/// Hs: counterparty selection entropy.
fn selection_entropy(selections: &[TaskSelection], min_samples: u32) -> Option<f64> {
    if (selections.len() as u32) < min_samples {
        return None;
    }
    let ids: Vec<[u8; 32]> = selections.iter().map(|s| s.counterparty).collect();
    Some(shannon_entropy_bytes32(&ids))
}

/// Hv: verifier assignment entropy.
fn verifier_entropy(assignments: &[VerifierAssignment], min_samples: u32) -> Option<f64> {
    if (assignments.len() as u32) < min_samples {
        return None;
    }
    let ids: Vec<[u8; 32]> = assignments.iter().map(|v| v.verifier_id).collect();
    Some(shannon_entropy_bytes32(&ids))
}

// ============================================================================
// Anomaly score
// ============================================================================

fn weighted_anomaly(
    ht: Option<f64>,
    hb: Option<f64>,
    hs: Option<f64>,
    hv: Option<f64>,
    p:  &EntropyParams,
) -> f64 {
    let mut score = 0.0_f64;
    if let Some(h) = ht { score += p.w_ht * (p.ht_threshold - h).max(0.0); }
    if let Some(h) = hb { score += p.w_hb * (p.hb_threshold - h).max(0.0); }
    if let Some(h) = hs { score += p.w_hs * (p.hs_threshold - h).max(0.0); }
    if let Some(h) = hv { score += p.w_hv * (p.hv_threshold - h).max(0.0); }
    score
}

// ============================================================================
// Shannon entropy primitives
// ============================================================================

fn shannon_entropy_bytes32(values: &[[u8; 32]]) -> f64 {
    let n = values.len() as f64;
    let mut counts: HashMap<[u8; 32], u32> = HashMap::new();
    for v in values {
        *counts.entry(*v).or_insert(0) += 1;
    }
    -counts
        .values()
        .map(|&c| { let p = c as f64 / n; p * p.log2() })
        .sum::<f64>()
}

fn shannon_entropy_u32(values: &[u32]) -> f64 {
    let n = values.len() as f64;
    let mut counts: HashMap<u32, u32> = HashMap::new();
    for &v in values {
        *counts.entry(v).or_insert(0) += 1;
    }
    -counts
        .values()
        .map(|&c| { let p = c as f64 / n; p * p.log2() })
        .sum::<f64>()
}

fn shannon_entropy_i32(values: &[i32]) -> f64 {
    let n = values.len() as f64;
    let mut counts: HashMap<i32, u32> = HashMap::new();
    for &v in values {
        *counts.entry(v).or_insert(0) += 1;
    }
    -counts
        .values()
        .map(|&c| { let p = c as f64 / n; p * p.log2() })
        .sum::<f64>()
}

// ============================================================================
// Bucketing helpers
// ============================================================================

/// `floor(log2(v))` for u64; returns 0 for v = 0 (zero-interval bucket).
fn log2_bucket_u64(v: u64) -> u32 {
    if v == 0 {
        return 0;
    }
    63 - v.leading_zeros()
}

/// `floor(log2(|v|))` for i128; returns -1 for v = 0 (zero-bid bucket).
fn log2_bucket_i128(v: i128) -> i32 {
    if v == 0 {
        return -1;
    }
    127 - v.unsigned_abs().leading_zeros() as i32
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::{FeedbackEvent, TaskSelection, TypedBid, VerifierAssignment};

    fn make_batch(
        bids:       Vec<TypedBid>,
        selections: Vec<TaskSelection>,
        verifiers:  Vec<VerifierAssignment>,
    ) -> BehaviorBatch {
        BehaviorBatch {
            agent_id:             [0u8; 32],
            epoch_number:         1,
            slot_start:           0,
            slot_end:             1000,
            message_count:        bids.len() as u32,
            msg_type_counts:      [0u32; 16],
            unique_counterparties: 0,
            tasks_completed:      0,
            notarizations:        0,
            disputes:             0,
            bid_values:           bids,
            task_selections:      selections,
            verifier_ids:         verifiers,
            feedback_events:      vec![FeedbackEvent {
                conversation_id:      [0u8; 16],
                from_agent:           [1u8; 32],
                score:                80,
                outcome:              2,
                role:                 0,
                slot:                 500,
                sati_attestation_hash: [0u8; 32],
            }],
            overflow:             false,
            overflow_data_hash:   [0u8; 32],
            log_merkle_root:      [0u8; 32],
        }
    }

    // ── Shannon entropy primitives ──────────────────────────────────────────

    #[test]
    fn uniform_bytes32_has_max_entropy() {
        // 4 distinct agents → H = log2(4) = 2 bits
        let agents: Vec<[u8; 32]> = (0u8..4)
            .map(|i| { let mut a = [0u8; 32]; a[0] = i; a })
            .collect();
        let h = shannon_entropy_bytes32(&agents);
        assert!((h - 2.0_f64).abs() < 1e-10, "h={h}");
    }

    #[test]
    fn single_value_has_zero_entropy() {
        let agents = vec![[1u8; 32]; 10];
        let h = shannon_entropy_bytes32(&agents);
        assert!(h.abs() < 1e-10, "h={h}");
    }

    // ── Bucketing helpers ───────────────────────────────────────────────────

    #[test]
    fn log2_bucket_u64_cases() {
        assert_eq!(log2_bucket_u64(0), 0);
        assert_eq!(log2_bucket_u64(1), 0);
        assert_eq!(log2_bucket_u64(2), 1);
        assert_eq!(log2_bucket_u64(4), 2);
        assert_eq!(log2_bucket_u64(7), 2);
        assert_eq!(log2_bucket_u64(8), 3);
    }

    #[test]
    fn log2_bucket_i128_cases() {
        assert_eq!(log2_bucket_i128(0),   -1);
        assert_eq!(log2_bucket_i128(1),    0);
        assert_eq!(log2_bucket_i128(-1),   0);
        assert_eq!(log2_bucket_i128(4),    2);
        assert_eq!(log2_bucket_i128(-128), 7); // |-128| = 128 = 2^7
    }

    // ── Timing entropy ──────────────────────────────────────────────────────

    #[test]
    fn regular_timing_has_zero_entropy() {
        // All intervals exactly 100 slots → 1 bucket → H = 0
        let slots: Vec<u64> = (0u64..10).map(|i| i * 100).collect();
        assert_eq!(timing_entropy(&slots, 2), Some(0.0));
    }

    #[test]
    fn varied_timing_has_positive_entropy() {
        // Diverse intervals spanning multiple log-buckets → H > 1
        let slots = vec![0u64, 1, 4, 16, 64, 256, 1024, 4096];
        let h = timing_entropy(&slots, 2).unwrap();
        assert!(h > 1.0, "expected h > 1.0, got {h}");
    }

    #[test]
    fn below_min_samples_returns_none() {
        let slots = vec![0u64, 100, 200];
        assert_eq!(timing_entropy(&slots, 10), None);
    }

    // ── Anomaly score integration ───────────────────────────────────────────

    #[test]
    fn regular_agent_has_high_anomaly() {
        let cp  = [1u8; 32];
        let ver = [2u8; 32];

        let bids: Vec<TypedBid> = (0u8..8).map(|i| TypedBid {
            conversation_id: [i; 16],
            counterparty:    cp,
            bid_value:       1_000_000,   // identical every time
            slot:            i as u64 * 100,
        }).collect();

        let selections: Vec<TaskSelection> = (0u8..8).map(|i| TaskSelection {
            conversation_id: [i; 16],
            counterparty:    cp,           // always same agent
            slot:            i as u64 * 100,
        }).collect();

        let verifiers: Vec<VerifierAssignment> = (0u8..8).map(|i| VerifierAssignment {
            conversation_id: [i; 16],
            verifier_id:     ver,          // always same notary
            slot:            i as u64 * 100,
        }).collect();

        let batch  = make_batch(bids, selections, verifiers);
        let slots: Vec<u64> = (0u64..8).map(|i| i * 100).collect(); // regular spacing
        let ev     = compute(&batch, &slots, &EntropyParams::default());

        assert_eq!(ev.ht, Some(0.0), "timing entropy should be 0");
        assert_eq!(ev.hb, Some(0.0), "bid entropy should be 0");
        assert_eq!(ev.hs, Some(0.0), "selection entropy should be 0");
        assert_eq!(ev.hv, Some(0.0), "verifier entropy should be 0");
        assert!(ev.anomaly > 0.0, "anomaly should be positive, got {}", ev.anomaly);
    }

    #[test]
    fn diverse_agent_has_low_anomaly() {
        // Build bids across 8 distinct log-scale magnitudes.
        let bids: Vec<TypedBid> = (0u8..8).map(|i| TypedBid {
            conversation_id: [i; 16],
            counterparty:    { let mut a = [0u8; 32]; a[0] = i; a },
            bid_value:       1i128 << (i * 4), // very different magnitudes
            slot:            i as u64,
        }).collect();

        // 8 distinct counterparties.
        let selections: Vec<TaskSelection> = (0u8..8).map(|i| TaskSelection {
            conversation_id: [i; 16],
            counterparty:    { let mut a = [0u8; 32]; a[0] = i; a },
            slot:            i as u64,
        }).collect();

        // 8 distinct verifiers.
        let verifiers: Vec<VerifierAssignment> = (0u8..8).map(|i| VerifierAssignment {
            conversation_id: [i; 16],
            verifier_id:     { let mut a = [0u8; 32]; a[0] = i; a },
            slot:            i as u64,
        }).collect();

        let batch = make_batch(bids, selections, verifiers);
        // Very irregular slot spacing → high timing entropy.
        let slots: Vec<u64> = vec![0, 1, 3, 7, 15, 31, 63, 127];
        let ev    = compute(&batch, &slots, &EntropyParams::default());

        // All H components should be at or above thresholds → near-zero anomaly.
        assert!(ev.anomaly < 0.1, "expected low anomaly, got {}", ev.anomaly);
    }
}
