use crate::{config::Config, node_client::{AgentId, ConversationId, InboundEnvelope, NodeClient}, store};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use tracing::{info, warn};
use uuid::Uuid;

// ── Wire types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct MailboxPropose {
    op: String,
    /// Deposit: base64 encrypted message bytes
    #[serde(default)]
    msg: Option<String>,
    /// Deposit: recipient agent_id (hex 32 bytes)
    #[serde(default)]
    to: Option<String>,
    /// Deposit: TTL override in seconds
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
struct PickupMessage {
    id: String,
    from: Option<String>,
    msg: String, // base64 payload
    created_at: i64,
    expires_at: i64,
}

// ── Dispatch ──────────────────────────────────────────────────────────────

pub async fn handle_propose(
    env: InboundEnvelope,
    client: &NodeClient,
    db: &SqlitePool,
    config: &Config,
) -> Result<()> {
    let payload_bytes = B64.decode(&env.payload_b64).unwrap_or_default();
    let propose: MailboxPropose = match serde_json::from_slice(&payload_bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!("malformed PROPOSE from {}…: {e}", &env.sender[..8.min(env.sender.len())]);
            return Ok(());
        }
    };

    match propose.op.as_str() {
        "deposit" => handle_deposit(env, propose, client, db, config).await,
        "pickup"  => handle_pickup(env, client, db).await,
        other => {
            warn!("unknown op '{other}' from {}…", &env.sender[..8.min(env.sender.len())]);
            Ok(())
        }
    }
}

// ── deposit ───────────────────────────────────────────────────────────────

async fn handle_deposit(
    env: InboundEnvelope,
    propose: MailboxPropose,
    client: &NodeClient,
    db: &SqlitePool,
    config: &Config,
) -> Result<()> {
    let sender = AgentId::from_hex(&env.sender)?;
    let conv   = ConversationId::from_hex(&env.conversation_id)?;

    let to_hex = match propose.to {
        Some(t) => t,
        None => return send_feedback(client, &sender, &conv, json!({"ok":false,"error":"missing 'to'"})).await,
    };
    let msg_b64 = match propose.msg {
        Some(m) => m,
        None => return send_feedback(client, &sender, &conv, json!({"ok":false,"error":"missing 'msg'"})).await,
    };

    let payload = match B64.decode(&msg_b64) {
        Ok(b) => b,
        Err(_) => return send_feedback(client, &sender, &conv, json!({"ok":false,"error":"invalid base64"})).await,
    };

    if payload.is_empty() {
        return send_feedback(client, &sender, &conv, json!({"ok":false,"error":"empty payload"})).await;
    }
    if payload.len() > config.max_msg_bytes {
        return send_feedback(client, &sender, &conv, json!({"ok":false,"error":"payload too large"})).await;
    }

    let count = store::message_count(db, &to_hex).await.unwrap_or(0);
    if count >= config.max_messages_per_mailbox {
        return send_feedback(client, &sender, &conv, json!({"ok":false,"error":"mailbox full"})).await;
    }

    let id = Uuid::new_v4().to_string();
    let ttl = propose.ttl_seconds.unwrap_or(config.default_ttl_secs).min(config.default_ttl_secs);
    let expires_at = store::now_secs() + ttl as i64;

    store::insert_message(db, &id, &to_hex, Some(&env.sender), &payload, expires_at).await?;

    info!("deposit id={} → {}…  {}B", &id[..8], &to_hex[..8.min(to_hex.len())], payload.len());

    send_feedback(client, &sender, &conv, json!({"ok":true,"id":id})).await
}

// ── pickup ────────────────────────────────────────────────────────────────

async fn handle_pickup(env: InboundEnvelope, client: &NodeClient, db: &SqlitePool) -> Result<()> {
    let sender = AgentId::from_hex(&env.sender)?;
    let conv   = ConversationId::from_hex(&env.conversation_id)?;

    let messages = store::drain_messages(db, &env.sender).await?;
    let n = messages.len();

    let out: Vec<PickupMessage> = messages
        .into_iter()
        .map(|m| PickupMessage {
            id: m.id,
            from: m.from_agent,
            msg: B64.encode(&m.payload),
            created_at: m.created_at,
            expires_at: m.expires_at,
        })
        .collect();

    if n > 0 {
        info!("pickup: {}… drained {n} messages", &env.sender[..8.min(env.sender.len())]);
    }

    send_feedback(client, &sender, &conv, json!({"ok":true,"messages":out})).await
}

// ── notify ────────────────────────────────────────────────────────────────

pub async fn send_notify(client: &NodeClient, mailbox_id: &AgentId, recipient: &AgentId, count: i64) {
    let payload = json!({"op":"notify","mailbox":mailbox_id.to_hex(),"count":count});
    let conv = ConversationId::new_random();
    if let Err(e) = client.send_envelope("PROPOSE", Some(recipient), &conv, payload.to_string().as_bytes()).await {
        warn!("notify → {}…: {e}", &recipient.to_hex()[..8]);
    } else {
        info!("notify → {}…  ({count} pending)", &recipient.to_hex()[..8]);
    }
}

// ── helpers ───────────────────────────────────────────────────────────────

async fn send_feedback(
    client: &NodeClient,
    recipient: &AgentId,
    conv: &ConversationId,
    payload: serde_json::Value,
) -> Result<()> {
    client
        .send_envelope("FEEDBACK", Some(recipient), conv, payload.to_string().as_bytes())
        .await
        .map(|_| ())
        .map_err(|e| {
            warn!("feedback → {}…: {e}", &recipient.to_hex()[..8]);
            e
        })
}
