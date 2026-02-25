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
