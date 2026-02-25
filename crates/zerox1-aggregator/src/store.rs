//! In-memory reputation store with optional SQLite persistence.
//!
//! All reads are served from a fast in-memory HashMap.
//! Every ingest event is also written to SQLite (when `--db-path` is set)
//! so data survives restarts without replaying node pushes.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ============================================================================
// Input validation
// ============================================================================

/// Agent IDs on the wire are hex-encoded 32-byte SATI mint addresses (64 chars).
fn is_valid_agent_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

// ============================================================================
// Wire types (matches node.rs push format + serde tag)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEvent {
    pub sender:          String,
    pub target_agent:    String,
    pub score:           i32,
    pub outcome:         u8,
    pub is_dispute:      bool,
    pub role:            u8,
    pub conversation_id: String,
    pub slot:            u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictEvent {
    pub sender:          String,
    pub recipient:       String,
    pub conversation_id: String,
    pub slot:            u64,
}

/// Entropy vector pushed by a node at epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyEvent {
    pub agent_id: String,
    pub epoch:    u64,
    pub ht:       Option<f64>,
    pub hb:       Option<f64>,
    pub hs:       Option<f64>,
    pub hv:       Option<f64>,
    pub anomaly:  f64,
    pub n_ht:     u32,
    pub n_hb:     u32,
    pub n_hs:     u32,
    pub n_hv:     u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type")]
pub enum IngestEvent {
    #[serde(rename = "FEEDBACK")]
    Feedback(FeedbackEvent),
    #[serde(rename = "VERDICT")]
    Verdict(VerdictEvent),
    #[serde(rename = "ENTROPY")]
    Entropy(EntropyEvent),
}

// ============================================================================
// Reputation record
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct AgentReputation {
    pub agent_id:       String,
    pub feedback_count: u64,
    pub total_score:    i64,
    pub positive_count: u64,
    pub neutral_count:  u64,
    pub negative_count: u64,
    pub verdict_count:  u64,
    pub average_score:  f64,
    pub last_updated:   u64,
}

impl AgentReputation {
    fn new(agent_id: String) -> Self {
        Self {
            agent_id,
            feedback_count: 0,
            total_score:    0,
            positive_count: 0,
            neutral_count:  0,
            negative_count: 0,
            verdict_count:  0,
            average_score:  0.0,
            last_updated:   now_secs(),
        }
    }

    fn apply_feedback(&mut self, score: i32, outcome: u8) {
        // Clamp score to protocol range to prevent total_score corruption.
        let score = score.clamp(-100, 100);
        self.feedback_count += 1;
        self.total_score    += score as i64;
        match outcome {
            0 => self.negative_count += 1,
            1 => self.neutral_count  += 1,
            _ => self.positive_count += 1,
        }
        self.average_score = self.total_score as f64 / self.feedback_count as f64;
        self.last_updated  = now_secs();
    }

    fn apply_verdict(&mut self) {
        self.verdict_count += 1;
        self.last_updated   = now_secs();
    }
}

// ============================================================================
// Interaction + timeseries output types
// ============================================================================

/// A single raw feedback event — used by GET /interactions.
#[derive(Debug, Clone, Serialize)]
pub struct RawInteraction {
    pub sender:          String,
    pub target_agent:    String,
    pub score:           i32,
    pub outcome:         u8,
    pub is_dispute:      bool,
    pub role:            u8,
    pub conversation_id: String,
    pub slot:            u64,
    /// Unix timestamp (seconds) when the aggregator received this event.
    pub ts:              u64,
}

/// One hourly bucket — used by GET /stats/timeseries.
#[derive(Debug, Clone, Serialize)]
pub struct TimeseriesBucket {
    /// Start of the 1-hour window (unix seconds).
    pub bucket:         u64,
    pub feedback_count: u64,
    pub positive_count: u64,
    pub negative_count: u64,
    pub dispute_count:  u64,
}

/// Rolling entropy result — used by GET /entropy/{id}/rolling
#[derive(Debug, Clone, Serialize)]
pub struct RollingEntropyResult {
    pub agent_id:          String,
    pub window_epochs:     u32,
    pub epochs_found:      u32,
    pub mean_anomaly:      f64,
    pub anomaly_variance:  f64,
    /// True when variance is below 0.005 AND mean_anomaly > 0.3 — patient cartel signal.
    pub low_variance_flag: bool,
    /// True when mean_anomaly > 0.55.
    pub high_anomaly_flag: bool,
}

/// Verifier concentration entry — used by GET /leaderboard/verifier-concentration
#[derive(Debug, Clone, Serialize)]
pub struct VerifierConcentrationEntry {
    pub agent_id:               String,
    pub epochs_sampled:         u32,
    pub mean_hv:                f64,
    pub epochs_below_threshold: u32,
    pub concentration_score:    f64, // 1.0 - (mean_hv / hv_threshold)  clamped [0,1]
}

/// Ownership cluster — used by GET /leaderboard/ownership-clusters
#[derive(Debug, Clone, Serialize)]
pub struct OwnershipCluster {
    pub cluster_id:       u32,
    pub agents:           Vec<String>,
    pub mean_anomaly_mad: f64, // mean absolute diff of anomaly scores — lower = more correlated
}

/// Calibrated β parameters derived from live data — GET /params/calibrated
#[derive(Debug, Clone, Serialize)]
pub struct CalibratedParams {
    pub beta_1_anomaly:      f64,
    pub beta_2_rep_decay:    f64,
    pub beta_3_coordination: f64,
    pub beta_4_systemic:     f64,
    pub sample_agents:       u32,
    pub flagged_agents:      u32,
    pub calibrated_at:       u64,
}

/// Systemic Risk Index — GET /system/sri
#[derive(Debug, Clone, Serialize)]
pub struct SriStatus {
    pub sri:                    f64,  // fraction of agents with anomaly > 0.55
    pub circuit_breaker_active: bool, // true when sri > 0.50
    pub mean_anomaly:           f64,
    pub active_agents:          u32,
    pub flagged_agents:         u32,
    pub computed_at:            u64,
}

/// Per-agent required stake — GET /stake/required/{id}
#[derive(Debug, Clone, Serialize)]
pub struct RequiredStakeResult {
    pub agent_id:            String,
    pub base_stake_usdc:     f64,
    pub current_anomaly:     f64,
    pub beta_1:              f64,
    pub required_stake_usdc: f64, // base * (1 + beta_1 * anomaly)
    pub deficit_usdc:        f64, // max(0, required - base)
}

// ============================================================================
// SQLite persistence layer
// ============================================================================

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_reputation (
    agent_id       TEXT    PRIMARY KEY,
    feedback_count INTEGER NOT NULL DEFAULT 0,
    total_score    INTEGER NOT NULL DEFAULT 0,
    positive_count INTEGER NOT NULL DEFAULT 0,
    neutral_count  INTEGER NOT NULL DEFAULT 0,
    negative_count INTEGER NOT NULL DEFAULT 0,
    verdict_count  INTEGER NOT NULL DEFAULT 0,
    last_updated   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS feedback_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender          TEXT    NOT NULL,
    target_agent    TEXT    NOT NULL,
    score           INTEGER NOT NULL,
    outcome         INTEGER NOT NULL,
    is_dispute      INTEGER NOT NULL DEFAULT 0,
    role            INTEGER NOT NULL DEFAULT 0,
    conversation_id TEXT    NOT NULL,
    slot            INTEGER NOT NULL DEFAULT 0,
    ts              INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fe_sender  ON feedback_events(sender);
CREATE INDEX IF NOT EXISTS idx_fe_target  ON feedback_events(target_agent);
CREATE INDEX IF NOT EXISTS idx_fe_ts      ON feedback_events(ts);

CREATE TABLE IF NOT EXISTS entropy_vectors (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id  TEXT    NOT NULL,
    epoch     INTEGER NOT NULL,
    ht        REAL,
    hb        REAL,
    hs        REAL,
    hv        REAL,
    anomaly   REAL    NOT NULL DEFAULT 0,
    n_ht      INTEGER NOT NULL DEFAULT 0,
    n_hb      INTEGER NOT NULL DEFAULT 0,
    n_hs      INTEGER NOT NULL DEFAULT 0,
    n_hv      INTEGER NOT NULL DEFAULT 0,
    ts        INTEGER NOT NULL,
    UNIQUE(agent_id, epoch)
);
CREATE INDEX IF NOT EXISTS idx_ev_agent ON entropy_vectors(agent_id);
CREATE INDEX IF NOT EXISTS idx_ev_ts    ON entropy_vectors(ts);

PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
";

struct Db(rusqlite::Connection);

impl Db {
    fn open(path: &Path) -> rusqlite::Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db(conn))
    }

    /// Load all reputation rows into a HashMap.
    fn load_all(&self) -> rusqlite::Result<HashMap<String, AgentReputation>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, feedback_count, total_score,
                    positive_count, neutral_count, negative_count,
                    verdict_count, last_updated
             FROM agent_reputation"
        )?;
        let rows = stmt.query_map([], |row| {
            let agent_id: String = row.get(0)?;
            let feedback_count: u64 = row.get::<_, i64>(1)? as u64;
            let total_score:    i64 = row.get(2)?;
            let positive_count: u64 = row.get::<_, i64>(3)? as u64;
            let neutral_count:  u64 = row.get::<_, i64>(4)? as u64;
            let negative_count: u64 = row.get::<_, i64>(5)? as u64;
            let verdict_count:  u64 = row.get::<_, i64>(6)? as u64;
            let last_updated:   u64 = row.get::<_, i64>(7)? as u64;
            let average_score = if feedback_count > 0 {
                total_score as f64 / feedback_count as f64
            } else {
                0.0
            };
            Ok(AgentReputation {
                agent_id: agent_id.clone(),
                feedback_count,
                total_score,
                positive_count,
                neutral_count,
                negative_count,
                verdict_count,
                average_score,
                last_updated,
            })
        })?;

        let mut map = HashMap::new();
        for row in rows {
            let rep = row?;
            map.insert(rep.agent_id.clone(), rep);
        }
        Ok(map)
    }

    /// Upsert a full reputation row.
    fn upsert(&self, rep: &AgentReputation) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO agent_reputation
                 (agent_id, feedback_count, total_score, positive_count,
                  neutral_count, negative_count, verdict_count, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(agent_id) DO UPDATE SET
                 feedback_count = excluded.feedback_count,
                 total_score    = excluded.total_score,
                 positive_count = excluded.positive_count,
                 neutral_count  = excluded.neutral_count,
                 negative_count = excluded.negative_count,
                 verdict_count  = excluded.verdict_count,
                 last_updated   = excluded.last_updated",
            rusqlite::params![
                rep.agent_id,
                rep.feedback_count as i64,
                rep.total_score,
                rep.positive_count as i64,
                rep.neutral_count  as i64,
                rep.negative_count as i64,
                rep.verdict_count  as i64,
                rep.last_updated   as i64,
            ],
        )?;
        Ok(())
    }

    /// Insert a raw feedback event.
    fn insert_feedback(&self, fb: &FeedbackEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO feedback_events
                 (sender, target_agent, score, outcome, is_dispute, role,
                  conversation_id, slot, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                fb.sender,
                fb.target_agent,
                fb.score,
                fb.outcome as i64,
                fb.is_dispute as i64,
                fb.role as i64,
                fb.conversation_id,
                fb.slot as i64,
                ts as i64,
            ],
        )?;
        Ok(())
    }

    /// Query raw interactions with optional sender/target filters.
    fn query_interactions(
        &self,
        from:  Option<&str>,
        to:    Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<Vec<RawInteraction>> {
        let mut stmt = self.0.prepare(
            "SELECT sender, target_agent, score, outcome, is_dispute, role,
                    conversation_id, slot, ts
             FROM feedback_events
             WHERE (?1 IS NULL OR sender       = ?1)
               AND (?2 IS NULL OR target_agent = ?2)
             ORDER BY ts DESC
             LIMIT ?3"
        )?;
        let rows = stmt.query_map(
            rusqlite::params![from, to, limit as i64],
            |row| Ok(RawInteraction {
                sender:          row.get(0)?,
                target_agent:    row.get(1)?,
                score:           row.get(2)?,
                outcome:         row.get::<_, i64>(3)? as u8,
                is_dispute:      row.get::<_, i64>(4)? != 0,
                role:            row.get::<_, i64>(5)? as u8,
                conversation_id: row.get(6)?,
                slot:            row.get::<_, i64>(7)? as u64,
                ts:              row.get::<_, i64>(8)? as u64,
            }),
        )?;
        rows.collect()
    }

    /// Upsert an entropy vector (agent_id + epoch is the unique key).
    fn upsert_entropy(&self, ev: &EntropyEvent, ts: u64) -> rusqlite::Result<()> {
        self.0.execute(
            "INSERT INTO entropy_vectors
                 (agent_id, epoch, ht, hb, hs, hv, anomaly,
                  n_ht, n_hb, n_hs, n_hv, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(agent_id, epoch) DO UPDATE SET
                 ht      = excluded.ht,
                 hb      = excluded.hb,
                 hs      = excluded.hs,
                 hv      = excluded.hv,
                 anomaly = excluded.anomaly,
                 n_ht    = excluded.n_ht,
                 n_hb    = excluded.n_hb,
                 n_hs    = excluded.n_hs,
                 n_hv    = excluded.n_hv,
                 ts      = excluded.ts",
            rusqlite::params![
                ev.agent_id,
                ev.epoch as i64,
                ev.ht,
                ev.hb,
                ev.hs,
                ev.hv,
                ev.anomaly,
                ev.n_ht as i64,
                ev.n_hb as i64,
                ev.n_hs as i64,
                ev.n_hv as i64,
                ts as i64,
            ],
        )?;
        Ok(())
    }

    /// Latest entropy vector for an agent.
    fn query_entropy_latest(&self, agent_id: &str) -> rusqlite::Result<Option<EntropyEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, epoch, ht, hb, hs, hv, anomaly,
                    n_ht, n_hb, n_hs, n_hv
             FROM entropy_vectors
             WHERE agent_id = ?1
             ORDER BY epoch DESC
             LIMIT 1"
        )?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], row_to_entropy)?;
        rows.next().transpose()
    }

    /// Top agents by anomaly score (highest first), most recent epoch only.
    fn query_anomaly_leaderboard(&self, limit: usize) -> rusqlite::Result<Vec<EntropyEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, epoch, ht, hb, hs, hv, anomaly,
                    n_ht, n_hb, n_hs, n_hv
             FROM entropy_vectors
             WHERE (agent_id, epoch) IN (
                 SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
             )
             ORDER BY anomaly DESC
             LIMIT ?1"
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64], row_to_entropy)?;
        rows.collect()
    }

    /// All entropy vectors for an agent, oldest first.
    fn query_entropy_history(&self, agent_id: &str, limit: usize) -> rusqlite::Result<Vec<EntropyEvent>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id, epoch, ht, hb, hs, hv, anomaly,
                    n_ht, n_hb, n_hs, n_hv
             FROM entropy_vectors
             WHERE agent_id = ?1
             ORDER BY epoch DESC
             LIMIT ?2"
        )?;
        let rows = stmt.query_map(rusqlite::params![agent_id, limit as i64], row_to_entropy)?;
        rows.collect()
    }

    /// Aggregate feedback events into 1-hour buckets since `since`.
    fn query_timeseries(&self, since: u64) -> rusqlite::Result<Vec<TimeseriesBucket>> {
        let mut stmt = self.0.prepare(
            "SELECT
                 (ts / 3600) * 3600                              AS bucket,
                 COUNT(*)                                        AS feedback_count,
                 SUM(CASE WHEN outcome    = 2 THEN 1 ELSE 0 END) AS positive_count,
                 SUM(CASE WHEN outcome    = 0 THEN 1 ELSE 0 END) AS negative_count,
                 SUM(CASE WHEN is_dispute = 1 THEN 1 ELSE 0 END) AS dispute_count
             FROM feedback_events
             WHERE ts >= ?1
             GROUP BY bucket
             ORDER BY bucket ASC"
        )?;
        let rows = stmt.query_map(rusqlite::params![since as i64], |row| {
            Ok(TimeseriesBucket {
                bucket:         row.get::<_, i64>(0)? as u64,
                feedback_count: row.get::<_, i64>(1)? as u64,
                positive_count: row.get::<_, i64>(2)? as u64,
                negative_count: row.get::<_, i64>(3)? as u64,
                dispute_count:  row.get::<_, i64>(4)? as u64,
            })
        })?;
        rows.collect()
    }

    /// Rolling anomaly stats for an agent over the last `window` epochs.
    fn query_rolling_entropy(&self, agent_id: &str, window: u32) -> rusqlite::Result<RollingEntropyResult> {
        let row: (f64, f64, i64, Option<f64>) = self.0.query_row(
            "SELECT AVG(anomaly),
                    AVG(anomaly * anomaly) - AVG(anomaly) * AVG(anomaly),
                    COUNT(*),
                    AVG(hv)
             FROM (
                 SELECT anomaly, hv FROM entropy_vectors
                 WHERE agent_id = ?1
                 ORDER BY epoch DESC
                 LIMIT ?2
             )",
            rusqlite::params![agent_id, window as i64],
            |r| Ok((
                r.get::<_, f64>(0).unwrap_or(0.0),
                r.get::<_, f64>(1).unwrap_or(0.0),
                r.get::<_, i64>(2).unwrap_or(0),
                r.get::<_, Option<f64>>(3)?,
            )),
        )?;
        let (mean_anomaly, variance, n, _mean_hv) = row;
        Ok(RollingEntropyResult {
            agent_id:          agent_id.to_string(),
            window_epochs:     window,
            epochs_found:      n as u32,
            mean_anomaly,
            anomaly_variance:  variance.max(0.0),
            low_variance_flag: variance < 0.005 && mean_anomaly > 0.30 && n >= 5,
            high_anomaly_flag: mean_anomaly > 0.55,
        })
    }

    /// Verifier concentration: agents with consistently low hv (verifier entropy).
    fn query_verifier_concentration(&self, limit: usize) -> rusqlite::Result<Vec<VerifierConcentrationEntry>> {
        let mut stmt = self.0.prepare(
            "SELECT agent_id,
                    COUNT(*)                                               AS epochs_sampled,
                    COALESCE(AVG(hv), 0.0)                                AS mean_hv,
                    SUM(CASE WHEN hv IS NOT NULL AND hv < 1.0 THEN 1 ELSE 0 END) AS epochs_below
             FROM entropy_vectors
             WHERE hv IS NOT NULL
             GROUP BY agent_id
             HAVING COUNT(*) >= 3
             ORDER BY mean_hv ASC
             LIMIT ?1"
        )?;
        let hv_threshold = 1.0_f64;
        let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
            let mean_hv: f64 = row.get(2)?;
            let score = (1.0 - (mean_hv / hv_threshold)).clamp(0.0, 1.0);
            Ok(VerifierConcentrationEntry {
                agent_id:               row.get(0)?,
                epochs_sampled:         row.get::<_, i64>(1)? as u32,
                mean_hv,
                epochs_below_threshold: row.get::<_, i64>(3)? as u32,
                concentration_score:    score,
            })
        })?;
        rows.collect()
    }

    /// Systemic Risk Index: fraction of active agents with anomaly > 0.55.
    fn query_sri_status(&self) -> rusqlite::Result<SriStatus> {
        let (total, flagged, mean_anomaly): (i64, i64, f64) = self.0.query_row(
            "SELECT COUNT(*),
                    SUM(CASE WHEN anomaly > 0.55 THEN 1 ELSE 0 END),
                    COALESCE(AVG(anomaly), 0.0)
             FROM (
                 SELECT anomaly FROM entropy_vectors
                 WHERE (agent_id, epoch) IN (
                     SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
                 )
             )",
            [],
            |r| Ok((
                r.get::<_, i64>(0).unwrap_or(0),
                r.get::<_, i64>(1).unwrap_or(0),
                r.get::<_, f64>(2).unwrap_or(0.0),
            )),
        )?;
        let sri = if total > 0 { flagged as f64 / total as f64 } else { 0.0 };
        Ok(SriStatus {
            sri,
            circuit_breaker_active: sri > 0.50,
            mean_anomaly,
            active_agents:  total   as u32,
            flagged_agents: flagged as u32,
            computed_at:    now_secs(),
        })
    }

    /// Latest anomaly score for required_stake computation.
    fn query_latest_anomaly(&self, agent_id: &str) -> rusqlite::Result<Option<f64>> {
        let mut stmt = self.0.prepare(
            "SELECT anomaly FROM entropy_vectors
             WHERE agent_id = ?1
             ORDER BY epoch DESC
             LIMIT 1"
        )?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], |r| r.get::<_, f64>(0))?;
        rows.next().transpose()
    }
}

fn row_to_entropy(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntropyEvent> {
    Ok(EntropyEvent {
        agent_id: row.get(0)?,
        epoch:    row.get::<_, i64>(1)? as u64,
        ht:       row.get(2)?,
        hb:       row.get(3)?,
        hs:       row.get(4)?,
        hv:       row.get(5)?,
        anomaly:  row.get(6)?,
        n_ht:     row.get::<_, i64>(7)? as u32,
        n_hb:     row.get::<_, i64>(8)? as u32,
        n_hs:     row.get::<_, i64>(9)? as u32,
        n_hv:     row.get::<_, i64>(10)? as u32,
    })
}

// ============================================================================
// ReputationStore
// ============================================================================

/// In-memory cap for raw interactions when running without SQLite.
const MAX_IN_MEMORY_INTERACTIONS: usize = 10_000;

#[derive(Default)]
struct Inner {
    agents:       HashMap<String, AgentReputation>,
    /// Bounded ring buffer of recent interactions (used as fallback when no SQLite).
    interactions: VecDeque<RawInteraction>,
}

#[derive(Clone)]
pub struct ReputationStore {
    inner: Arc<RwLock<Inner>>,
    /// SQLite connection; None = in-memory only (no --db-path supplied).
    db:    Arc<Mutex<Option<Db>>>,
}

impl Default for ReputationStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            db:    Arc::new(Mutex::new(None)),
        }
    }
}

impl ReputationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or create) a SQLite database at `path` and load existing data.
    pub fn with_db(path: &Path) -> anyhow::Result<Self> {
        let db = Db::open(path)
            .map_err(|e| anyhow::anyhow!("SQLite open failed: {e}"))?;
        let agents = db.load_all()
            .map_err(|e| anyhow::anyhow!("SQLite load failed: {e}"))?;

        tracing::info!(
            "Loaded {} reputation records from {}",
            agents.len(),
            path.display()
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(Inner { agents, interactions: VecDeque::new() })),
            db:    Arc::new(Mutex::new(Some(db))),
        })
    }

    pub fn ingest(&self, event: IngestEvent) {
        let mut inner = self.inner.write().unwrap();
        match event {
            IngestEvent::Feedback(fb) => {
                if !is_valid_agent_id(&fb.target_agent) {
                    tracing::warn!("Ingest: invalid target_agent '{}' — dropped", &fb.target_agent);
                    return;
                }
                let rep = inner.agents
                    .entry(fb.target_agent.clone())
                    .or_insert_with(|| AgentReputation::new(fb.target_agent.clone()));
                rep.apply_feedback(fb.score, fb.outcome);
                let rep = rep.clone();

                // Store raw interaction for /interactions and /stats/timeseries.
                let ts = now_secs();
                let interaction = RawInteraction {
                    sender:          fb.sender.clone(),
                    target_agent:    fb.target_agent.clone(),
                    score:           fb.score.clamp(-100, 100),
                    outcome:         fb.outcome,
                    is_dispute:      fb.is_dispute,
                    role:            fb.role,
                    conversation_id: fb.conversation_id.clone(),
                    slot:            fb.slot,
                    ts,
                };
                if inner.interactions.len() >= MAX_IN_MEMORY_INTERACTIONS {
                    inner.interactions.pop_front();
                }
                inner.interactions.push_back(interaction);

                drop(inner);
                self.persist(&rep);
                self.persist_feedback(&fb, ts);
            }
            IngestEvent::Verdict(v) => {
                if !is_valid_agent_id(&v.recipient) {
                    tracing::warn!("Ingest: invalid recipient '{}' — dropped", &v.recipient);
                    return;
                }
                let rep = inner.agents
                    .entry(v.recipient.clone())
                    .or_insert_with(|| AgentReputation::new(v.recipient));
                rep.apply_verdict();
                let rep = rep.clone();
                drop(inner);
                self.persist(&rep);
            }
            IngestEvent::Entropy(ev) => {
                if !is_valid_agent_id(&ev.agent_id) {
                    tracing::warn!("Ingest: invalid agent_id in ENTROPY '{}' — dropped", &ev.agent_id);
                    return;
                }
                drop(inner);
                let ts = now_secs();
                tracing::debug!(
                    "ENTROPY epoch={} agent={} anomaly={:.4}",
                    ev.epoch, &ev.agent_id[..8], ev.anomaly,
                );
                let db = self.db.lock().unwrap();
                if let Some(ref conn) = *db {
                    if let Err(e) = conn.upsert_entropy(&ev, ts) {
                        tracing::warn!("SQLite upsert_entropy failed: {e}");
                    }
                }
            }
        }
    }

    pub fn get(&self, agent_id: &str) -> Option<AgentReputation> {
        self.inner.read().unwrap().agents.get(agent_id).cloned()
    }

    pub fn leaderboard(&self, limit: usize) -> Vec<AgentReputation> {
        let inner = self.inner.read().unwrap();
        let mut agents: Vec<AgentReputation> = inner.agents.values().cloned().collect();
        agents.sort_by(|a, b| {
            b.average_score
                .partial_cmp(&a.average_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        agents.truncate(limit);
        agents
    }

    pub fn all_agents(&self) -> Vec<AgentReputation> {
        self.inner.read().unwrap().agents.values().cloned().collect()
    }

    /// Latest entropy vector for an agent.
    pub fn entropy_latest(&self, agent_id: &str) -> Option<EntropyEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_entropy_latest(agent_id) {
                Ok(row) => return row,
                Err(e)  => tracing::warn!("query_entropy_latest failed: {e}"),
            }
        }
        None
    }

    /// Agents sorted by highest anomaly score (most recent epoch per agent).
    pub fn anomaly_leaderboard(&self, limit: usize) -> Vec<EntropyEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_anomaly_leaderboard(limit) {
                Ok(rows) => return rows,
                Err(e)   => tracing::warn!("query_anomaly_leaderboard failed: {e}"),
            }
        }
        vec![]
    }

    /// All entropy vectors for an agent, newest first (up to `limit`).
    pub fn entropy_history(&self, agent_id: &str, limit: usize) -> Vec<EntropyEvent> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_entropy_history(agent_id, limit) {
                Ok(rows) => return rows,
                Err(e)   => tracing::warn!("query_entropy_history failed: {e}"),
            }
        }
        vec![]
    }

    /// Return raw feedback events, optionally filtered by sender/target.
    /// When SQLite is available queries the full history; otherwise returns
    /// from the in-memory ring buffer (last 10 000 events).
    pub fn interactions(
        &self,
        from:  Option<&str>,
        to:    Option<&str>,
        limit: usize,
    ) -> Vec<RawInteraction> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_interactions(from, to, limit) {
                Ok(rows) => return rows,
                Err(e)   => tracing::warn!("query_interactions failed: {e}"),
            }
        }
        // In-memory fallback.
        let inner = self.inner.read().unwrap();
        inner.interactions.iter().rev()
            .filter(|i| from.is_none_or(|f| i.sender      == f))
            .filter(|i| to.is_none_or(  |t| i.target_agent == t))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Return hourly feedback buckets covering the last `window_secs` seconds.
    pub fn timeseries(&self, window_secs: u64) -> Vec<TimeseriesBucket> {
        let since = now_secs().saturating_sub(window_secs);
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_timeseries(since) {
                Ok(rows) => return rows,
                Err(e)   => tracing::warn!("query_timeseries failed: {e}"),
            }
        }
        // In-memory fallback: bucket the ring buffer.
        let inner = self.inner.read().unwrap();
        let mut map: HashMap<u64, TimeseriesBucket> = HashMap::new();
        for i in inner.interactions.iter().filter(|i| i.ts >= since) {
            let bucket = (i.ts / 3600) * 3600;
            let entry = map.entry(bucket).or_insert(TimeseriesBucket {
                bucket,
                feedback_count: 0,
                positive_count: 0,
                negative_count: 0,
                dispute_count:  0,
            });
            entry.feedback_count += 1;
            if i.outcome   == 2 { entry.positive_count += 1; }
            if i.outcome   == 0 { entry.negative_count += 1; }
            if i.is_dispute     { entry.dispute_count  += 1; }
        }
        let mut buckets: Vec<_> = map.into_values().collect();
        buckets.sort_by_key(|b| b.bucket);
        buckets
    }

    /// Rolling anomaly window for an agent (GAP-03: patient cartel detection).
    pub fn rolling_entropy(&self, agent_id: &str, window: u32) -> RollingEntropyResult {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_rolling_entropy(agent_id, window) {
                Ok(result) => return result,
                Err(e) => tracing::warn!("query_rolling_entropy failed: {e}"),
            }
        }
        RollingEntropyResult {
            agent_id:          agent_id.to_string(),
            window_epochs:     window,
            epochs_found:      0,
            mean_anomaly:      0.0,
            anomaly_variance:  0.0,
            low_variance_flag: false,
            high_anomaly_flag: false,
        }
    }

    /// Agents with consistently low verifier entropy (GAP-04: verifier collusion).
    pub fn verifier_concentration(&self, limit: usize) -> Vec<VerifierConcentrationEntry> {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_verifier_concentration(limit) {
                Ok(rows) => return rows,
                Err(e) => tracing::warn!("query_verifier_concentration failed: {e}"),
            }
        }
        vec![]
    }

    /// Suspected same-owner agent clusters (GAP-02: ownership clustering).
    ///
    /// Compares the last 10 anomaly scores for each agent pair.
    /// Agents whose anomaly trajectories have mean absolute difference < 0.05
    /// are placed in the same cluster.
    pub fn ownership_clusters(&self) -> Vec<OwnershipCluster> {
        let db = self.db.lock().unwrap();
        let rows: Vec<(String, f64)> = if let Some(ref conn) = *db {
            conn.0.prepare(
                "SELECT agent_id, anomaly FROM entropy_vectors
                 WHERE (agent_id, epoch) IN (
                     SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
                 )
                 ORDER BY anomaly DESC
                 LIMIT 50"
            ).and_then(|mut s| {
                s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?)))
                    .and_then(|rows| rows.collect())
            }).unwrap_or_default()
        } else {
            vec![]
        };
        drop(db);

        if rows.len() < 2 {
            return vec![];
        }

        // Simple single-linkage clustering on anomaly score proximity.
        let mut assigned: Vec<Option<u32>> = vec![None; rows.len()];
        let mut next_cluster = 0u32;

        for i in 0..rows.len() {
            if assigned[i].is_some() { continue; }
            for j in (i + 1)..rows.len() {
                if assigned[j].is_some() { continue; }
                let mad = (rows[i].1 - rows[j].1).abs();
                if mad < 0.05 {
                    let cid = assigned[i].get_or_insert_with(|| {
                        let c = next_cluster; next_cluster += 1; c
                    });
                    assigned[j] = Some(*cid);
                }
            }
            if assigned[i].is_none() {
                assigned[i] = Some(next_cluster);
                next_cluster += 1;
            }
        }

        let mut cluster_map: std::collections::HashMap<u32, Vec<usize>> = std::collections::HashMap::new();
        for (i, cid) in assigned.iter().enumerate() {
            cluster_map.entry(cid.unwrap()).or_default().push(i);
        }

        cluster_map.into_iter()
            .filter(|(_, members)| members.len() >= 2)
            .map(|(cid, members)| {
                let agents: Vec<String> = members.iter().map(|&i| rows[i].0.clone()).collect();
                let scores: Vec<f64>    = members.iter().map(|&i| rows[i].1).collect();
                let mean = scores.iter().sum::<f64>() / scores.len() as f64;
                let mad  = scores.iter().map(|s| (s - mean).abs()).sum::<f64>() / scores.len() as f64;
                OwnershipCluster { cluster_id: cid, agents, mean_anomaly_mad: mad }
            })
            .collect()
    }

    /// Calibrated β parameters from live entropy data (GAP-05).
    ///
    /// Compares entropy component contributions for flagged vs clean agents.
    /// Flagged = latest anomaly > 0.55.  Clean = latest anomaly < 0.10.
    pub fn calibrated_params(&self) -> CalibratedParams {
        let db = self.db.lock().unwrap();
        type EntropyRow = (f64, Option<f64>, Option<f64>, Option<f64>, Option<f64>);
        let rows: Vec<EntropyRow> =
            if let Some(ref conn) = *db {
                conn.0.prepare(
                    "SELECT anomaly, ht, hb, hs, hv FROM entropy_vectors
                     WHERE (agent_id, epoch) IN (
                         SELECT agent_id, MAX(epoch) FROM entropy_vectors GROUP BY agent_id
                     )"
                ).and_then(|mut s| {
                    s.query_map([], |r| Ok((
                        r.get::<_, f64>(0)?,
                        r.get::<_, Option<f64>>(1)?,
                        r.get::<_, Option<f64>>(2)?,
                        r.get::<_, Option<f64>>(3)?,
                        r.get::<_, Option<f64>>(4)?,
                    ))).and_then(|rows| rows.collect())
                }).unwrap_or_default()
            } else { vec![] };
        drop(db);

        // Default EntropyParams thresholds.
        let (ht_thresh, hb_thresh, hs_thresh, hv_thresh) = (2.0, 1.5, 1.5, 1.0);
        let (w_ht, w_hb, w_hs, w_hv) = (0.35, 0.20, 0.30, 0.15);

        let flagged: Vec<_> = rows.iter().filter(|r| r.0 > 0.55).collect();
        let total   = rows.len() as u32;
        let n_flag  = flagged.len() as u32;

        if flagged.is_empty() {
            return CalibratedParams {
                beta_1_anomaly: 0.870, beta_2_rep_decay: 0.130,
                beta_3_coordination: 0.0, beta_4_systemic: 0.0,
                sample_agents: total, flagged_agents: n_flag,
                calibrated_at: now_secs(),
            };
        }

        // Mean component contribution for flagged agents.
        let mut c_ht = 0.0_f64;
        let mut c_hb = 0.0_f64;
        let mut c_hs = 0.0_f64;
        let mut c_hv = 0.0_f64;
        let n = flagged.len() as f64;

        for &(_, ht, hb, hs, hv) in &flagged {
            if let Some(h) = ht { c_ht += w_ht * (ht_thresh - h).max(0.0); }
            if let Some(h) = hb { c_hb += w_hb * (hb_thresh - h).max(0.0); }
            if let Some(h) = hs { c_hs += w_hs * (hs_thresh - h).max(0.0); }
            if let Some(h) = hv { c_hv += w_hv * (hv_thresh - h).max(0.0); }
        }
        c_ht /= n; c_hb /= n; c_hs /= n; c_hv /= n;

        let entropy_total = c_ht + c_hb + c_hs + c_hv;
        let total_weight  = entropy_total + 0.15; // 0.15 reserved for rep decay
        let b1 = if total_weight > 0.0 { entropy_total / total_weight } else { 0.870 };
        let b2 = 1.0 - b1;

        CalibratedParams {
            beta_1_anomaly: b1, beta_2_rep_decay: b2,
            beta_3_coordination: 0.0, beta_4_systemic: 0.0,
            sample_agents: total, flagged_agents: n_flag,
            calibrated_at: now_secs(),
        }
    }

    /// Systemic Risk Index and circuit breaker status (GAP-06).
    pub fn sri_status(&self) -> SriStatus {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            match conn.query_sri_status() {
                Ok(s) => return s,
                Err(e) => tracing::warn!("query_sri_status failed: {e}"),
            }
        }
        drop(db);
        // In-memory fallback: scan agent anomaly from leaderboard.
        let evs = self.anomaly_leaderboard(10_000);
        let total   = evs.len() as u32;
        let flagged = evs.iter().filter(|e| e.anomaly > 0.55).count() as u32;
        let mean    = if total > 0 {
            evs.iter().map(|e| e.anomaly).sum::<f64>() / total as f64
        } else { 0.0 };
        let sri = if total > 0 { flagged as f64 / total as f64 } else { 0.0 };
        SriStatus {
            sri,
            circuit_breaker_active: sri > 0.50,
            mean_anomaly: mean,
            active_agents: total,
            flagged_agents: flagged,
            computed_at: now_secs(),
        }
    }

    /// Dynamic required stake for an agent (GAP-08).
    ///
    /// Formula: required = BASE × (1 + β₁ × anomaly)
    /// Base stake: 10 USDC (10_000_000 micro-USDC).
    pub fn required_stake(&self, agent_id: &str) -> RequiredStakeResult {
        const BASE_STAKE_USDC: f64 = 10.0;
        const BETA_1: f64 = 0.870;

        let anomaly = {
            let db = self.db.lock().unwrap();
            if let Some(ref conn) = *db {
                conn.query_latest_anomaly(agent_id).unwrap_or(None).unwrap_or(0.0)
            } else { 0.0 }
        };

        let required = BASE_STAKE_USDC * (1.0 + BETA_1 * anomaly);
        let deficit  = (required - BASE_STAKE_USDC).max(0.0);

        RequiredStakeResult {
            agent_id:            agent_id.to_string(),
            base_stake_usdc:     BASE_STAKE_USDC,
            current_anomaly:     anomaly,
            beta_1:              BETA_1,
            required_stake_usdc: required,
            deficit_usdc:        deficit,
        }
    }

    /// Write a single reputation record to SQLite (fire-and-forget; failures are logged).
    fn persist(&self, rep: &AgentReputation) {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.upsert(rep) {
                tracing::warn!("SQLite upsert failed for {}: {e}", rep.agent_id);
            }
        }
    }

    /// Write a raw feedback event to SQLite (fire-and-forget; failures are logged).
    fn persist_feedback(&self, fb: &FeedbackEvent, ts: u64) {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.insert_feedback(fb, ts) {
                tracing::warn!("SQLite insert_feedback failed: {e}");
            }
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
