use anyhow::Result;
use sqlx::SqlitePool;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Debug, sqlx::FromRow)]
pub struct Message {
    pub id: String,
    #[allow(dead_code)]
    pub to_agent: String,
    pub from_agent: Option<String>,
    /// Raw bytes of the encrypted message payload
    pub payload: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
}

pub async fn init(pool: &SqlitePool) -> Result<()> {
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(pool)
        .await?;
    sqlx::query("PRAGMA synchronous=NORMAL")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS messages (
            id         TEXT PRIMARY KEY,
            to_agent   TEXT NOT NULL,
            from_agent TEXT,
            payload    BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_msg_to  ON messages(to_agent)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_msg_exp ON messages(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn message_count(pool: &SqlitePool, to_agent: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM messages WHERE to_agent = ? AND expires_at > ?",
    )
    .bind(to_agent)
    .bind(now_secs())
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn insert_message(
    pool: &SqlitePool,
    id: &str,
    to_agent: &str,
    from_agent: Option<&str>,
    payload: &[u8],
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO messages
         (id, to_agent, from_agent, payload, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(to_agent)
    .bind(from_agent)
    .bind(payload)
    .bind(now_secs())
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically drain all pending messages for an agent (pickup = delete).
pub async fn drain_messages(pool: &SqlitePool, to_agent: &str) -> Result<Vec<Message>> {
    let msgs: Vec<Message> = sqlx::query_as(
        "DELETE FROM messages WHERE to_agent = ? AND expires_at > ?
         RETURNING id, to_agent, from_agent, payload, created_at, expires_at",
    )
    .bind(to_agent)
    .bind(now_secs())
    .fetch_all(pool)
    .await?;
    Ok(msgs)
}

/// GC: delete expired messages, return count removed.
pub async fn delete_expired(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM messages WHERE expires_at <= ?")
        .bind(now_secs())
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
