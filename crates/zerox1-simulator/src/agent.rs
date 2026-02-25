//! Agent behaviour models.
//!
//! Each agent generates a BehaviorBatch each epoch.  Honest agents produce
//! naturally varied data; cartel agents try to game reputation while staying
//! below the entropy detection threshold.

use rand::Rng;
use rand::distributions::{Distribution, WeightedIndex};
use zerox1_protocol::batch::{
    BehaviorBatch, FeedbackEvent, TaskSelection, TypedBid, VerifierAssignment,
};

// ============================================================================
// Agent types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AgentKind {
    /// Normal participant — varied behaviour, no coordination.
    Honest,
    /// Type C-1: static threshold hugging — maintains just enough randomness
    /// to stay above each entropy threshold every epoch.
    CartC1,
    /// Type C-2: rotational evasion — rotates which dimension to regularise
    /// each epoch, so per-epoch entropy always looks fine but behaviour is
    /// correlated across epochs.
    CartC2,
}

#[derive(Debug, Clone)]
pub struct Agent {
    pub id:         [u8; 32],
    pub kind:       AgentKind,
    pub reputation: f64,   // cumulative score
    pub stake:      f64,   // USDC locked
    pub slashed:    bool,
}

impl Agent {
    pub fn new(idx: usize, kind: AgentKind, base_stake: f64) -> Self {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&idx.to_le_bytes());
        Self { id, kind, reputation: 0.0, stake: base_stake, slashed: false }
    }

    pub fn is_cartel(&self) -> bool {
        self.kind != AgentKind::Honest
    }
}

// ============================================================================
// Behaviour generation
// ============================================================================

/// All data produced by one agent in one epoch.
pub struct EpochData {
    pub batch:         BehaviorBatch,
    pub message_slots: Vec<u64>,
}

/// Generate one epoch's worth of behaviour for an agent.
///
/// `epoch`        — current epoch index
/// `peer_ids`     — pool of other agent IDs to interact with
/// `verifier_ids` — pool of designated verifier IDs
pub fn generate_epoch<R: Rng>(
    agent:       &Agent,
    epoch:       u64,
    peer_ids:    &[[u8; 32]],
    verifier_ids: &[[u8; 32]],
    rng:         &mut R,
) -> EpochData {
    match agent.kind {
        AgentKind::Honest  => honest_epoch(agent, epoch, peer_ids, verifier_ids, rng),
        AgentKind::CartC1  => cart_c1_epoch(agent, epoch, peer_ids, verifier_ids, rng),
        AgentKind::CartC2  => cart_c2_epoch(agent, epoch, peer_ids, verifier_ids, rng),
    }
}

// ── Honest ──────────────────────────────────────────────────────────────────

fn honest_epoch<R: Rng>(
    agent:        &Agent,
    epoch:        u64,
    peer_ids:     &[[u8; 32]],
    verifier_ids: &[[u8; 32]],
    rng:          &mut R,
) -> EpochData {
    let n_msgs = poisson(rng, 20.0).max(2);

    // Irregular timing: exponential inter-arrival, base slot 100.
    let message_slots = exponential_slots(rng, n_msgs, 100.0);

    // Bids: log-normal magnitudes across a wide range.
    let n_bids = (n_msgs / 4).max(1);
    let bids   = (0..n_bids).map(|i| TypedBid {
        conversation_id: conv_id(epoch, i as u64),
        counterparty:    *pick_zipf(peer_ids, rng),
        bid_value:       lognormal_bid(rng),
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    // Counterparty selections: Zipf — some popular, most rare.
    let n_sel = (n_msgs / 5).max(1);
    let selections = (0..n_sel).map(|i| TaskSelection {
        conversation_id: conv_id(epoch, 100 + i as u64),
        counterparty:    *pick_zipf(peer_ids, rng),
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    // Verifier assignments: pick from pool uniformly.
    let n_ver = (n_sel / 2).max(1);
    let verifier_ids_used: Vec<VerifierAssignment> = (0..n_ver).map(|i| VerifierAssignment {
        conversation_id: conv_id(epoch, 200 + i as u64),
        verifier_id:     verifier_ids[rng.gen_range(0..verifier_ids.len())],
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    build(agent, epoch, message_slots, bids, selections, verifier_ids_used, rng)
}

// ── Cartel C-1: static threshold hugging ────────────────────────────────────
//
// Adds just enough noise to each dimension to stay above the threshold.
// Uses same 2-3 counterparties and same 1-2 notaries but introduces minimal
// variation so per-epoch entropy ≥ threshold.

fn cart_c1_epoch<R: Rng>(
    agent:        &Agent,
    epoch:        u64,
    peer_ids:     &[[u8; 32]],
    verifier_ids: &[[u8; 32]],
    rng:          &mut R,
) -> EpochData {
    let n_msgs = poisson(rng, 20.0).max(8);

    // Timing: mostly regular (fixed interval) with occasional jitter.
    // This keeps Ht just above threshold by ensuring 2+ distinct buckets.
    let message_slots = mostly_regular_slots(rng, n_msgs, 50, 0.15);

    // Bids: 90% same value, 10% slightly different → barely above Hb threshold.
    let n_bids    = (n_msgs / 4).max(2);
    let ring_size = 3usize; // collude with 3 peers
    let bids      = (0..n_bids).map(|i| TypedBid {
        conversation_id: conv_id(epoch, i as u64),
        counterparty:    peer_ids[i % ring_size.min(peer_ids.len())],
        bid_value:       if rng.gen_bool(0.1) { 2_000_000 } else { 1_000_000 },
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    // Selections: rotate through ring of 3 peers.
    let n_sel      = (n_msgs / 5).max(2);
    let selections = (0..n_sel).map(|i| TaskSelection {
        conversation_id: conv_id(epoch, 100 + i as u64),
        counterparty:    peer_ids[i % ring_size.min(peer_ids.len())],
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    // Verifiers: rotate through 2 controlled notaries.
    let n_ver  = (n_sel / 2).max(2);
    let n_vids = verifier_ids.len().min(2);
    let vers   = (0..n_ver).map(|i| VerifierAssignment {
        conversation_id: conv_id(epoch, 200 + i as u64),
        verifier_id:     verifier_ids[i % n_vids],
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    build(agent, epoch, message_slots, bids, selections, vers, rng)
}

// ── Cartel C-2: rotational evasion ──────────────────────────────────────────
//
// Each epoch, pick a different dimension to regularise.  The other three
// dimensions look normal.  Per-epoch detection misses it; rolling-window
// analysis would catch the pattern.

fn cart_c2_epoch<R: Rng>(
    agent:        &Agent,
    epoch:        u64,
    peer_ids:     &[[u8; 32]],
    verifier_ids: &[[u8; 32]],
    rng:          &mut R,
) -> EpochData {
    let dim = (epoch % 4) as usize; // rotate: 0=timing, 1=bids, 2=selection, 3=verifier
    let n_msgs = poisson(rng, 20.0).max(8);

    // Timing.
    let message_slots = if dim == 0 {
        mostly_regular_slots(rng, n_msgs, 50, 0.0) // perfectly regular
    } else {
        exponential_slots(rng, n_msgs, 100.0)       // natural
    };

    // Bids.
    let n_bids = (n_msgs / 4).max(2);
    let bids   = (0..n_bids).map(|i| TypedBid {
        conversation_id: conv_id(epoch, i as u64),
        counterparty:    *pick_zipf(peer_ids, rng),
        bid_value:       if dim == 1 { 1_000_000 } else { lognormal_bid(rng) },
        slot:            message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    // Selections.
    let n_sel      = (n_msgs / 5).max(2);
    let ring_size  = 3usize;
    let selections = (0..n_sel).map(|i| TaskSelection {
        conversation_id: conv_id(epoch, 100 + i as u64),
        counterparty:    if dim == 2 {
            peer_ids[i % ring_size.min(peer_ids.len())]
        } else {
            *pick_zipf(peer_ids, rng)
        },
        slot: message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    // Verifiers.
    let n_ver  = (n_sel / 2).max(2);
    let n_vids = verifier_ids.len().min(2);
    let vers   = (0..n_ver).map(|i| VerifierAssignment {
        conversation_id: conv_id(epoch, 200 + i as u64),
        verifier_id:     if dim == 3 {
            verifier_ids[i % n_vids]
        } else {
            verifier_ids[rng.gen_range(0..verifier_ids.len())]
        },
        slot: message_slots[i.min(message_slots.len() - 1)],
    }).collect();

    build(agent, epoch, message_slots, bids, selections, vers, rng)
}

// ============================================================================
// Helpers
// ============================================================================

fn build<R: Rng>(
    agent:         &Agent,
    epoch:         u64,
    message_slots: Vec<u64>,
    bids:          Vec<TypedBid>,
    selections:    Vec<TaskSelection>,
    verifiers:     Vec<VerifierAssignment>,
    rng:           &mut R,
) -> EpochData {
    let score: i8 = if agent.is_cartel() {
        // Cartels give each other inflated scores.
        rng.gen_range(70i8..=100)
    } else {
        rng.gen_range(-20i8..=100)
    };

    let feedback = vec![FeedbackEvent {
        conversation_id:      conv_id(epoch, 999),
        from_agent:           agent.id,
        score,
        outcome:              if score > 0 { 2 } else if score == 0 { 1 } else { 0 },
        role:                 0,
        slot:                 *message_slots.last().unwrap_or(&0),
        sati_attestation_hash: [0u8; 32],
    }];

    let batch = BehaviorBatch {
        agent_id:             agent.id,
        epoch_number:         epoch,
        slot_start:           *message_slots.first().unwrap_or(&0),
        slot_end:             *message_slots.last().unwrap_or(&0),
        message_count:        message_slots.len() as u32,
        msg_type_counts:      [0u32; 16],
        unique_counterparties: selections.len() as u32,
        tasks_completed:      selections.len() as u32,
        notarizations:        verifiers.len() as u32,
        disputes:             0,
        bid_values:           bids,
        task_selections:      selections,
        verifier_ids:         verifiers,
        feedback_events:      feedback,
        overflow:             false,
        overflow_data_hash:   [0u8; 32],
        log_merkle_root:      [0u8; 32],
    };

    EpochData { batch, message_slots }
}

fn conv_id(epoch: u64, idx: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&epoch.to_le_bytes());
    id[8..].copy_from_slice(&idx.to_le_bytes());
    id
}

// ── Distributions ────────────────────────────────────────────────────────────

/// Poisson-distributed count (Knuth algorithm).
fn poisson<R: Rng>(rng: &mut R, lambda: f64) -> usize {
    let l = (-lambda).exp();
    let mut k = 0usize;
    let mut p = 1.0f64;
    loop {
        k += 1;
        p *= rng.gen::<f64>();
        if p <= l { return k - 1; }
    }
}

/// Exponentially distributed inter-arrival slots (natural timing).
fn exponential_slots<R: Rng>(rng: &mut R, n: usize, mean: f64) -> Vec<u64> {
    let mut slot = 0u64;
    (0..n).map(|_| {
        let interval = (-mean * rng.gen::<f64>().ln()) as u64;
        slot += interval.max(1);
        slot
    }).collect()
}

/// Mostly regular timing with occasional jitter (C-1 evasion).
/// `jitter_prob`: probability of a slot being irregular.
fn mostly_regular_slots<R: Rng>(
    rng: &mut R, n: usize, interval: u64, jitter_prob: f64,
) -> Vec<u64> {
    let mut slot = 0u64;
    (0..n).map(|_| {
        let step = if rng.gen_bool(jitter_prob) {
            // Add a large jitter to push into a different log-bucket.
            interval * 8 + rng.gen_range(0..interval)
        } else {
            interval
        };
        slot += step.max(1);
        slot
    }).collect()
}

/// Log-normal bid value (varied magnitudes, realistic for service pricing).
fn lognormal_bid<R: Rng>(rng: &mut R) -> i128 {
    // mu=14 (≈e^14 ≈ 1.2M lamports), sigma=2 → range roughly 10K–10B
    let normal = {
        // Box-Muller transform.
        let u1: f64 = rng.gen::<f64>().max(1e-10);
        let u2: f64 = rng.gen::<f64>();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    };
    let value = (14.0 + 2.0 * normal).exp() as i128;
    value.max(1)
}

/// Zipf-distributed pick (some counterparties are very popular).
fn pick_zipf<'a, R: Rng>(peers: &'a [[u8; 32]], rng: &mut R) -> &'a [u8; 32] {
    if peers.is_empty() { return &peers[0]; }
    // Weights: 1/rank (rank 1 is most popular).
    let weights: Vec<f64> = (1..=peers.len()).map(|r| 1.0 / r as f64).collect();
    let dist = WeightedIndex::new(&weights).unwrap();
    &peers[dist.sample(rng)]
}
