//! In-memory reputation store with optional SQLite persistence.
//!
//! All reads are served from a fast in-memory HashMap.
//! Every ingest event is also written to SQLite (when `--db-path` is set)
//! so data survives restarts without replaying node pushes.

use std::collections::HashMap;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg_type")]
pub enum IngestEvent {
    #[serde(rename = "FEEDBACK")]
    Feedback(FeedbackEvent),
    #[serde(rename = "VERDICT")]
    Verdict(VerdictEvent),
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

    /// Load all rows into a HashMap.
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
}

// ============================================================================
// ReputationStore
// ============================================================================

#[derive(Default)]
struct Inner {
    agents: HashMap<String, AgentReputation>,
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
            inner: Arc::new(RwLock::new(Inner { agents })),
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
                    .or_insert_with(|| AgentReputation::new(fb.target_agent));
                rep.apply_feedback(fb.score, fb.outcome);
                let rep = rep.clone();
                drop(inner);
                self.persist(&rep);
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

    /// Write a single record to SQLite (fire-and-forget; failures are logged).
    fn persist(&self, rep: &AgentReputation) {
        let db = self.db.lock().unwrap();
        if let Some(ref conn) = *db {
            if let Err(e) = conn.upsert(rep) {
                tracing::warn!("SQLite upsert failed for {}: {e}", rep.agent_id);
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
