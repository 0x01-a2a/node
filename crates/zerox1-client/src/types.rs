//! Canonical wire types for the zerox1-node REST and WebSocket APIs.

use serde::{Deserialize, Serialize};

// ── Identity types ─────────────────────────────────────────────────────────

/// A 32-byte Ed25519 agent identity, hex-encoded on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId(pub [u8; 32]);

impl AgentId {
    /// Parse from a 64-char hex string.
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("AgentId must be 32 bytes"))?;
        Ok(Self(arr))
    }

    /// Encode to lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A 16-byte conversation identifier, hex-encoded on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConversationId(pub [u8; 16]);

impl ConversationId {
    /// Generate a fresh random conversation ID.
    pub fn new_random() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Parse from a 32-char hex string.
    pub fn from_hex(s: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("ConversationId must be 16 bytes"))?;
        Ok(Self(arr))
    }

    /// Encode to lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ConversationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ── Node API types ─────────────────────────────────────────────────────────

/// Inbound envelope received from `GET /ws/inbox`.
///
/// `sender` is Ed25519-authenticated at the protocol layer — it cannot be
/// spoofed regardless of what the payload claims.
#[derive(Debug, Clone, Deserialize)]
pub struct InboundEnvelope {
    /// Message type: `"PROPOSE"`, `"ACCEPT"`, `"REJECT"`, `"DELIVER"`, `"FEEDBACK"`, …
    pub msg_type: String,
    /// Authenticated sender agent_id (hex 32 bytes).
    pub sender: String,
    /// Recipient agent_id — typically the local node (hex 32 bytes).
    #[serde(default)]
    pub recipient: Option<String>,
    /// Conversation identifier (hex 16 bytes).
    pub conversation_id: String,
    /// Beacon slot the envelope was committed in.
    pub slot: u64,
    /// Per-sender replay-prevention nonce.
    pub nonce: u64,
    /// Payload bytes as base64.
    pub payload_b64: String,
    /// Decoded FEEDBACK fields (only present for FEEDBACK messages).
    #[serde(default)]
    pub feedback: Option<serde_json::Value>,
}

/// Request body for `POST /envelopes/send`.
#[derive(Debug, Serialize)]
pub struct SendEnvelopeRequest {
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub conversation_id: String,
    pub payload_b64: String,
}

/// Response from `POST /envelopes/send`.
#[derive(Debug, Deserialize)]
pub struct SendEnvelopeResponse {
    pub nonce: u64,
    pub payload_hash: String,
}

/// Request body for `POST /hosted/send` (hosted-agent mode).
#[derive(Debug, Serialize)]
pub struct HostedSendRequest {
    pub msg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub conversation_id: String,
    /// Payload bytes as hex (hosted API requirement).
    pub payload_hex: String,
}

// ── Aggregator types ───────────────────────────────────────────────────────

/// Activity event broadcast on the aggregator's `GET /ws/activity` stream.
#[derive(Debug, Clone, Deserialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub ts: i64,
    /// `"JOIN"` | `"FEEDBACK"` | `"DISPUTE"` | `"VERDICT"` | `"REJECT"` | `"DELIVER"`
    pub event_type: String,
    /// Primary agent_id (hex).
    pub agent_id: String,
    /// Secondary agent_id for bilateral events (hex).
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub score: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub conversation_id: Option<String>,
}

/// Identity response from `GET /identity`.
#[derive(Debug, Deserialize)]
pub struct IdentityResponse {
    pub agent_id: String,
}
