//! Push Notary — FCM token registration and sleeping node coordination.
//!
//! A phone node registers its Firebase Cloud Messaging device token with the
//! aggregator on startup. If the phone goes offline, the aggregator can send a
//! push notification to wake the app when a PROPOSE arrives for that agent.
//!
//! Flow:
//!   1. Node starts → register_fcm_token() + set_sleep_mode(false) + pull_pending_messages()
//!   2. App backgrounds / process ends → set_sleep_mode(true)  [called by app layer]
//!   3. Sender's SDK detects target is sleeping → POST /agents/{id}/pending on aggregator
//!   4. Aggregator sends FCM push → phone wakes, app re-establishes relay reservation
//!   5. Sender retries the bilateral PROPOSE → normal protocol flow resumes

use serde::Deserialize;

// ============================================================================
// Types
// ============================================================================

/// A message the aggregator held for this agent while it was sleeping.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // fields consumed by app layer / SDK, not by node internals
pub struct PendingMessage {
    /// Unique message ID (nanoscecond hex timestamp on the aggregator).
    pub id:       String,
    /// Hex-encoded agent_id of the sender.
    pub from:     String,
    /// Protocol message type, e.g. "PROPOSE".
    pub msg_type: String,
    /// Base64-encoded raw CBOR envelope bytes.
    pub payload:  String,
    /// Unix timestamp (seconds) when the aggregator received it.
    pub ts:       u64,
}

// ============================================================================
// Registration
// ============================================================================

/// Register this node's FCM device token with the aggregator.
///
/// Called on startup when `--fcm-token` is set. The aggregator stores the
/// token so it can send a push notification when this agent receives a PROPOSE
/// while sleeping.
pub async fn register_fcm_token(
    aggregator_url: &str,
    agent_id_hex:   &str,
    fcm_token:      &str,
    client:         &reqwest::Client,
) -> anyhow::Result<()> {
    let url  = format!("{aggregator_url}/fcm/register");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "agent_id":  agent_id_hex,
            "fcm_token": fcm_token,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("FCM register returned HTTP {}", resp.status());
    }
    Ok(())
}

// ============================================================================
// Sleep state
// ============================================================================

/// Notify the aggregator that this agent is sleeping (offline) or awake.
///
/// Call with `sleeping = false` on startup (after relay reservation) and
/// `sleeping = true` before graceful shutdown or backgrounding.
pub async fn set_sleep_mode(
    aggregator_url: &str,
    agent_id_hex:   &str,
    sleeping:       bool,
    client:         &reqwest::Client,
) -> anyhow::Result<()> {
    let url  = format!("{aggregator_url}/fcm/sleep");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "agent_id": agent_id_hex,
            "sleeping": sleeping,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("FCM sleep update returned HTTP {}", resp.status());
    }
    Ok(())
}

// ============================================================================
// Pending message pull
// ============================================================================

/// Pull messages the aggregator held while this agent was sleeping.
///
/// Called on startup before entering the main event loop. Returns an empty
/// vec if there are no pending messages or if the aggregator returns 404.
/// The aggregator drains the queue on pull (messages are delivered once).
pub async fn pull_pending_messages(
    aggregator_url: &str,
    agent_id_hex:   &str,
    client:         &reqwest::Client,
) -> anyhow::Result<Vec<PendingMessage>> {
    let url  = format!("{aggregator_url}/agents/{agent_id_hex}/pending");
    let resp = client.get(&url).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(vec![]);
    }
    if !resp.status().is_success() {
        anyhow::bail!("Pending pull returned HTTP {}", resp.status());
    }
    let msgs: Vec<PendingMessage> = resp.json().await?;
    Ok(msgs)
}
