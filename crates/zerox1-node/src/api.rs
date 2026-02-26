//! Visualization API + Agent Integration API.
//!
//! Visualization (read-only):
//!   GET  /ws/events              — WebSocket stream of node events
//!   GET  /peers                  — All known peers with SATI/lease status
//!   GET  /reputation/:agent_id   — Reputation vector for an agent
//!   GET  /batch/:agent_id/:epoch — Batch summary (own node only)
//!
//! Agent integration:
//!   POST /envelopes/send         — Send an envelope (node signs + routes)
//!   GET  /ws/inbox               — WebSocket stream of inbound envelopes

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};

use zerox1_protocol::{
    envelope::BROADCAST_RECIPIENT,
    message::MsgType,
    payload::{FeedbackPayload, NotarizeBidPayload},
};

// ============================================================================
// Snapshot types — serialisable views of node state (visualization)
// ============================================================================

#[derive(Clone, Serialize)]
pub struct PeerSnapshot {
    pub agent_id:          String,
    pub peer_id:           Option<String>,
    pub sati_ok:           Option<bool>,
    pub lease_ok:          Option<bool>,
    pub last_active_epoch: u64,
}

#[derive(Clone, Serialize)]
pub struct ReputationSnapshot {
    pub agent_id:          String,
    pub reliability:       i64,
    pub cooperation:       i64,
    pub notary_accuracy:   i64,
    pub total_tasks:       u32,
    pub total_disputes:    u32,
    pub last_active_epoch: u64,
}

#[derive(Clone, Serialize)]
pub struct BatchSnapshot {
    pub agent_id:        String,
    pub epoch:           u64,
    pub message_count:   u32,
    pub log_merkle_root: String,
    pub batch_hash:      String,
}

// ============================================================================
// Visualization events — broadcast to /ws/events subscribers
// ============================================================================

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiEvent {
    Envelope {
        sender:   String,
        msg_type: String,
        slot:     u64,
    },
    PeerRegistered {
        agent_id: String,
        peer_id:  String,
    },
    ReputationUpdate {
        agent_id:    String,
        reliability: i64,
        cooperation: i64,
    },
    BatchSubmitted {
        epoch:         u64,
        message_count: u32,
        batch_hash:    String,
    },
    LeaseStatus {
        agent_id: String,
        active:   bool,
    },
    SatiStatus {
        agent_id:   String,
        registered: bool,
    },
}

// ============================================================================
// Agent integration types
// ============================================================================

/// Request body for POST /envelopes/send.
#[derive(Deserialize)]
pub struct SendEnvelopeRequest {
    /// Message type string, e.g. "PROPOSE", "ACCEPT", "DELIVER".
    pub msg_type: String,
    /// Recipient agent ID as hex (32 bytes). Omit or null for broadcast types.
    pub recipient: Option<String>,
    /// Conversation ID as hex (16 bytes).
    pub conversation_id: String,
    /// Payload bytes as base64.
    pub payload_b64: String,
}

/// Response body for POST /envelopes/send.
#[derive(Serialize)]
pub struct SentConfirmation {
    pub nonce:        u64,
    pub payload_hash: String, // hex keccak256
}

/// Outbound request queued by POST /envelopes/send, consumed by the node loop.
pub struct OutboundRequest {
    pub msg_type:        MsgType,
    pub recipient:       [u8; 32],
    pub conversation_id: [u8; 16],
    pub payload:         Vec<u8>,
    pub reply:           tokio::sync::oneshot::Sender<Result<SentConfirmation, String>>,
}

/// Inbound envelope pushed from the node loop to /ws/inbox subscribers.
#[derive(Clone, Serialize)]
pub struct InboundEnvelope {
    pub msg_type:        String,
    pub sender:          String, // hex
    pub recipient:       String, // hex
    pub conversation_id: String, // hex
    pub slot:            u64,
    pub nonce:           u64,
    pub payload_b64:     String,
    /// Decoded FEEDBACK payload fields (only present for FEEDBACK messages).
    pub feedback:        Option<serde_json::Value>,
    /// Decoded NOTARIZE_BID payload fields (only present for NOTARIZE_BID messages).
    pub notarize_bid:    Option<serde_json::Value>,
}

// ============================================================================
// Shared API state
// ============================================================================

struct ApiInner {
    // Visualization state
    peers:      RwLock<HashMap<[u8; 32], PeerSnapshot>>,
    reputation: RwLock<HashMap<[u8; 32], ReputationSnapshot>>,
    batches:    RwLock<Vec<BatchSnapshot>>,
    event_tx:   broadcast::Sender<ApiEvent>,
    self_agent: [u8; 32],

    // Agent integration channels
    /// Outbound requests from HTTP handlers to the node loop.
    outbound_tx: mpsc::Sender<OutboundRequest>,
    /// Inbound envelopes from node loop to /ws/inbox subscribers.
    inbox_tx:    broadcast::Sender<InboundEnvelope>,
    /// Optional bearer token to authenticate mutating API endpoints.
    api_secret:  Option<String>,
}

/// Cheaply cloneable shared state passed to all axum handlers.
#[derive(Clone)]
pub struct ApiState(Arc<ApiInner>);

impl ApiState {
    /// Create a new ApiState.
    ///
    /// Returns `(state, outbound_rx)`. The caller (node) must hold onto
    /// `outbound_rx` and drive it in the main event loop.
    pub fn new(self_agent: [u8; 32], api_secret: Option<String>) -> (Self, mpsc::Receiver<OutboundRequest>) {
        let (event_tx, _)    = broadcast::channel(512);
        let (inbox_tx, _)    = broadcast::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);

        let state = Self(Arc::new(ApiInner {
            peers:      RwLock::new(HashMap::new()),
            reputation: RwLock::new(HashMap::new()),
            batches:    RwLock::new(Vec::new()),
            event_tx,
            self_agent,
            outbound_tx,
            inbox_tx,
            api_secret,
        }));

        (state, outbound_rx)
    }

    // ── Visualization update helpers ─────────────────────────────────────────

    pub async fn upsert_peer(&self, agent_id: [u8; 32], snap: PeerSnapshot) {
        self.0.peers.write().await.insert(agent_id, snap);
    }

    pub async fn upsert_reputation(&self, agent_id: [u8; 32], snap: ReputationSnapshot) {
        self.0.reputation.write().await.insert(agent_id, snap);
    }

    pub async fn push_batch(&self, snap: BatchSnapshot) {
        let mut batches = self.0.batches.write().await;
        batches.push(snap);
        if batches.len() > 200 {
            batches.remove(0);
        }
    }

    /// Broadcast a visualization event to all /ws/events subscribers.
    pub fn send_event(&self, event: ApiEvent) {
        let _ = self.0.event_tx.send(event);
    }

    // ── Agent integration helpers ─────────────────────────────────────────────

    /// Push a validated inbound envelope to all /ws/inbox subscribers.
    ///
    /// Called by the node loop after every successfully validated envelope.
    pub fn push_inbound(&self, env: &zerox1_protocol::envelope::Envelope, slot: u64) {
        // Decode protocol-defined payloads for convenience.
        let feedback = if env.msg_type == zerox1_protocol::message::MsgType::Feedback {
            FeedbackPayload::decode(&env.payload).ok().map(|p| {
                serde_json::json!({
                    "conversation_id": hex::encode(p.conversation_id),
                    "target_agent":    hex::encode(p.target_agent),
                    "score":           p.score,
                    "outcome":         p.outcome,
                    "is_dispute":      p.is_dispute,
                    "role":            p.role,
                })
            })
        } else {
            None
        };

        let notarize_bid = if env.msg_type == zerox1_protocol::message::MsgType::NotarizeBid {
            NotarizeBidPayload::decode(&env.payload).ok().map(|p| {
                serde_json::json!({
                    "bid_type":        p.bid_type,
                    "conversation_id": hex::encode(p.conversation_id),
                    "opaque_b64":      B64.encode(&p.opaque),
                })
            })
        } else {
            None
        };

        let inbound = InboundEnvelope {
            msg_type:        format!("{}", env.msg_type),
            sender:          hex::encode(env.sender),
            recipient:       hex::encode(env.recipient),
            conversation_id: hex::encode(env.conversation_id),
            slot,
            nonce:           env.nonce,
            payload_b64:     B64.encode(&env.payload),
            feedback,
            notarize_bid,
        };

        let _ = self.0.inbox_tx.send(inbound);
    }

    /// Queue an outbound envelope request to the node loop.
    ///
    /// Called by the POST /envelopes/send handler.
    pub async fn send_outbound(&self, req: OutboundRequest) -> Result<(), String> {
        self.0.outbound_tx.send(req).await
            .map_err(|_| "node loop unavailable".to_string())
    }
}

// ============================================================================
// Server
// ============================================================================

pub async fn serve(state: ApiState, addr: SocketAddr) {
    let router = Router::new()
        // Visualization
        .route("/ws/events",              get(ws_events_handler))
        .route("/peers",                  get(get_peers))
        .route("/reputation/:agent_id",   get(get_reputation))
        .route("/batch/:agent_id/:epoch", get(get_batch))
        // Agent integration
        .route("/envelopes/send",         post(send_envelope))
        .route("/ws/inbox",               get(ws_inbox_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("API listener bind failed");

    tracing::info!("API listening on http://{addr}");

    axum::serve(listener, router)
        .await
        .expect("API server error");
}

// ============================================================================
// Visualization route handlers
// ============================================================================

async fn ws_events_handler(
    ws:           WebSocketUpgrade,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| ws_events_task(socket, state))
}

async fn ws_events_task(mut socket: WebSocket, state: ApiState) {
    let mut rx = state.0.event_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => match serde_json::to_string(&event) {
                Ok(json) => {
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("WS events serialize error: {e}"),
            },
            Err(broadcast::error::RecvError::Closed)    => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

async fn get_peers(State(state): State<ApiState>) -> impl IntoResponse {
    let peers = state.0.peers.read().await;
    let list: Vec<_> = peers.values().cloned().collect();
    Json(serde_json::to_value(list).unwrap_or_default())
}

async fn get_reputation(
    Path(agent_id_hex): Path<String>,
    State(state):       State<ApiState>,
) -> impl IntoResponse {
    let Ok(bytes) = hex::decode(&agent_id_hex) else {
        return Json(serde_json::json!({ "error": "invalid agent_id hex" }));
    };
    let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> else {
        return Json(serde_json::json!({ "error": "agent_id must be 32 bytes" }));
    };
    let rep = state.0.reputation.read().await;
    match rep.get(&arr) {
        Some(snap) => Json(serde_json::to_value(snap).unwrap_or_default()),
        None       => Json(serde_json::json!({ "agent_id": agent_id_hex, "score": null })),
    }
}

async fn get_batch(
    Path((agent_id_hex, epoch)): Path<(String, u64)>,
    State(state):                State<ApiState>,
) -> impl IntoResponse {
    let self_hex = hex::encode(state.0.self_agent);
    if agent_id_hex != self_hex {
        return Json(serde_json::json!({
            "error": "batch history is only available for this node's own agent_id"
        }));
    }
    let batches = state.0.batches.read().await;
    match batches.iter().find(|b| b.epoch == epoch) {
        Some(snap) => Json(serde_json::to_value(snap).unwrap_or_default()),
        None       => Json(serde_json::json!({ "error": "epoch not found" })),
    }
}

// ============================================================================
// Agent integration route handlers
// ============================================================================

async fn send_envelope(
    State(state): State<ApiState>,
    headers:      HeaderMap,
    Json(req):    Json<SendEnvelopeRequest>,
) -> impl IntoResponse {
    // Authenticate outbound transmission requests.
    if let Some(ref secret) = state.0.api_secret {
        let expected = format!("Bearer {secret}");
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct_eq(provided, &expected) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "unauthorized" })),
            );
        }
    }

    // Parse msg_type.
    let msg_type = match parse_msg_type(&req.msg_type) {
        Some(t) => t,
        None    => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("unknown msg_type: {}", req.msg_type) })),
        ),
    };

    // Parse recipient.
    let recipient: [u8; 32] = if msg_type.is_broadcast()
        || msg_type.is_notary_pubsub()
        || msg_type.is_reputation_pubsub()
    {
        BROADCAST_RECIPIENT
    } else {
        match &req.recipient {
            None => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient required for bilateral messages" })),
            ),
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(b) => match b.try_into() {
                    Ok(arr) => arr,
                    Err(_)  => return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "recipient must be 32 bytes" })),
                    ),
                },
                Err(_) => return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "recipient: invalid hex" })),
                ),
            },
        }
    };

    // Parse conversation_id.
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id) {
        Ok(b) => match b.try_into() {
            Ok(arr) => arr,
            Err(_)  => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "conversation_id must be 16 bytes" })),
            ),
        },
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "conversation_id: invalid hex" })),
        ),
    };

    // Decode payload.
    let payload = match B64.decode(&req.payload_b64) {
        Ok(b)  => b,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "payload_b64: invalid base64" })),
        ),
    };

    // Send to node loop via oneshot.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest { msg_type, recipient, conversation_id, payload, reply: reply_tx };

    if state.send_outbound(outbound).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }

    match reply_rx.await {
        Ok(Ok(conf)) => (
            StatusCode::OK,
            Json(serde_json::to_value(conf).unwrap_or_default()),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "node loop dropped reply" })),
        ),
    }
}

async fn ws_inbox_handler(
    ws:           WebSocketUpgrade,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| ws_inbox_task(socket, state))
}

async fn ws_inbox_task(mut socket: WebSocket, state: ApiState) {
    let mut rx = state.0.inbox_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(env) => match serde_json::to_string(&env) {
                Ok(json) => {
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("WS inbox serialize error: {e}"),
            },
            Err(broadcast::error::RecvError::Closed)    => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_msg_type(s: &str) -> Option<MsgType> {
    match s.to_uppercase().as_str() {
        "ADVERTISE"       => Some(MsgType::Advertise),
        "DISCOVER"        => Some(MsgType::Discover),
        "PROPOSE"         => Some(MsgType::Propose),
        "COUNTER"         => Some(MsgType::Counter),
        "ACCEPT"          => Some(MsgType::Accept),
        "REJECT"          => Some(MsgType::Reject),
        "DELIVER"         => Some(MsgType::Deliver),
        "NOTARIZE_BID"    => Some(MsgType::NotarizeBid),
        "NOTARIZE_ASSIGN" => Some(MsgType::NotarizeAssign),
        "VERDICT"         => Some(MsgType::Verdict),
        "FEEDBACK"        => Some(MsgType::Feedback),
        "DISPUTE"         => Some(MsgType::Dispute),
        _                 => None,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let len = a.len().max(b.len());
    let mut diff: u8 = (a.len() ^ b.len()) as u8;
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}
