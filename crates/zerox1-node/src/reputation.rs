use std::collections::HashMap;
use zerox1_protocol::constants::{
    DECAY_WINDOW_EPOCHS, REPUTATION_DECAY_DENOMINATOR, REPUTATION_DECAY_NUMERATOR,
};

/// Real-time (gossip) reputation vector (doc 5, §7.1).
///
/// Scores are in fixed-precision units (×1_000). So score 0 = neutral,
/// +100_000 = maximum positive, -100_000 = maximum negative.
/// Used for local decisions and UI display only — not authoritative.
#[derive(Debug, Clone, Default)]
pub struct ReputationVector {
    #[allow(dead_code)]
    pub agent_id:          [u8; 32],
    /// Reliability / task completion quality.
    pub reliability_score: i64,
    /// Cooperation / counterparty satisfaction.
    pub cooperation_index: i64,
    /// Accuracy of notary judgments.
    pub notary_accuracy:   i64,
    pub total_tasks:       u32,
    pub total_notarized:   u32,
    pub total_disputes:    u32,
    pub last_active_epoch: u64,
}

/// Gossip-based real-time reputation tracker (doc 5, §7.3).
pub struct ReputationTracker {
    scores:        HashMap<[u8; 32], ReputationVector>,
    current_epoch: u64,
}

impl ReputationTracker {
    pub fn new() -> Self {
        Self { scores: HashMap::new(), current_epoch: 0 }
    }

    pub fn get(&self, agent_id: &[u8; 32]) -> Option<&ReputationVector> {
        self.scores.get(agent_id)
    }

    #[allow(dead_code)]
    pub fn all(&self) -> impl Iterator<Item = &ReputationVector> {
        self.scores.values()
    }

    /// Apply a FEEDBACK message to the gossip scores.
    /// `role` = 0 (participant), 1 (notary).
    pub fn apply_feedback(
        &mut self,
        target:    [u8; 32],
        score:     i8,
        role:      u8,
        epoch:     u64,
    ) {
        let entry = self.scores.entry(target).or_insert_with(|| ReputationVector {
            agent_id: target,
            ..Default::default()
        });

        entry.last_active_epoch = entry.last_active_epoch.max(epoch);

        // Running average: new_score = (old × (n-1) + delta) / n
        let delta = score as i64 * 1_000; // fixed-precision ×1000

        if role == 0 {
            let n = (entry.total_tasks + 1) as i64;
            entry.reliability_score = (entry.reliability_score * (n - 1) + delta) / n;
            entry.cooperation_index = (entry.cooperation_index * (n - 1) + delta) / n;
            entry.total_tasks += 1;
        } else {
            let n = (entry.total_notarized + 1) as i64;
            entry.notary_accuracy = (entry.notary_accuracy * (n - 1) + delta) / n;
            entry.total_notarized += 1;
        }
    }

    pub fn record_dispute(&mut self, agent_id: [u8; 32]) {
        self.scores
            .entry(agent_id)
            .or_insert_with(|| ReputationVector { agent_id, ..Default::default() })
            .total_disputes += 1;
    }

    pub fn record_activity(&mut self, agent_id: [u8; 32], epoch: u64) {
        let e = self.scores
            .entry(agent_id)
            .or_insert_with(|| ReputationVector { agent_id, ..Default::default() });
        if epoch > e.last_active_epoch {
            e.last_active_epoch = epoch;
        }
    }

    /// Advance to a new epoch and apply decay to idle agents (§7.4).
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        let prev = self.current_epoch;
        self.current_epoch = new_epoch;

        for entry in self.scores.values_mut() {
            let idle = new_epoch.saturating_sub(entry.last_active_epoch);
            if idle > DECAY_WINDOW_EPOCHS {
                let decay_steps = (idle - DECAY_WINDOW_EPOCHS).min(new_epoch - prev);
                for _ in 0..decay_steps {
                    entry.reliability_score = entry.reliability_score
                        * REPUTATION_DECAY_NUMERATOR as i64
                        / REPUTATION_DECAY_DENOMINATOR as i64;
                    entry.cooperation_index = entry.cooperation_index
                        * REPUTATION_DECAY_NUMERATOR as i64
                        / REPUTATION_DECAY_DENOMINATOR as i64;
                    entry.notary_accuracy = entry.notary_accuracy
                        * REPUTATION_DECAY_NUMERATOR as i64
                        / REPUTATION_DECAY_DENOMINATOR as i64;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}
