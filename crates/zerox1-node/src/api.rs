//! Visualization API + Agent Integration API.
//!
//! Visualization (read-only):
//!   GET  /ws/events              — WebSocket stream of node events
//!   GET  /peers                  — All known peers with SATI/lease status
//!   GET  /reputation/{agent_id}    — Reputation vector for an agent
//!   GET  /batch/{agent_id}/{epoch} — Batch summary (own node only)
//!
//! Agent integration:
//!   POST /envelopes/send         — Send an envelope (node signs + routes)
//!   GET  /ws/inbox               — WebSocket stream of inbound envelopes

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};

use zerox1_protocol::{
    envelope::{Envelope, BROADCAST_RECIPIENT},
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
// Hosted-agent session state
// ============================================================================

/// Hard cap on concurrent hosted sessions to prevent memory DoS.
const MAX_HOSTED_SESSIONS: usize = 10_000;
/// Sessions older than this are evicted and their tokens rejected.
const SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
/// Maximum outbound sends per 60-second window per session.
const MAX_SENDS_PER_MINUTE: u32 = 60;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Active hosted-agent session — one per registered hosted agent.
///
/// On registration the host generates a fresh ed25519 sub-keypair.
/// `agent_id = verifying_key.to_bytes()`. All outbound envelopes for this
/// agent are signed with `signing_key` by the host.
pub struct HostedSession {
    /// 32-byte verifying key — used as the agent_id on the mesh.
    pub agent_id:                [u8; 32],
    pub signing_key:             SigningKey,
    pub created_at:              u64,
    pub nonce:                   u64,
    /// Start of the current 60-second rate-limit window (unix seconds).
    pub rate_window_start:       u64,
    /// Number of sends in the current rate-limit window.
    pub sends_in_window:         u32,
}

/// Request body for POST /hosted/send.
#[derive(Deserialize)]
pub struct HostedSendRequest {
    pub msg_type:        String,
    pub recipient:       Option<String>,
    pub conversation_id: String,
    pub payload_hex:     String,
}

/// Query parameters for GET /ws/hosted/inbox (token fallback only).
#[derive(Deserialize)]
pub struct HostedInboxQuery {
    pub token: Option<String>,
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

    // Hosted-agent state
    /// token (hex-32) → HostedSession
    hosted_sessions:    Arc<RwLock<HashMap<String, HostedSession>>>,
    #[allow(dead_code)]
    hosting_fee_bps:    u32,
    /// Pre-signed envelopes from hosted-agent send handler → node loop.
    hosted_outbound_tx: mpsc::Sender<Envelope>,
}

/// Cheaply cloneable shared state passed to all axum handlers.
#[derive(Clone)]
pub struct ApiState(Arc<ApiInner>);

impl ApiState {
    /// Create a new ApiState.
    ///
    /// Returns `(state, outbound_rx, hosted_outbound_rx)`. The caller (node)
    /// must hold onto both receivers and drive them in the main event loop.
    pub fn new(
        self_agent:      [u8; 32],
        api_secret:      Option<String>,
        hosting_fee_bps: u32,
    ) -> (Self, mpsc::Receiver<OutboundRequest>, mpsc::Receiver<Envelope>) {
        let (event_tx, _)    = broadcast::channel(512);
        let (inbox_tx, _)    = broadcast::channel(256);
        let (outbound_tx, outbound_rx)               = mpsc::channel(64);
        let (hosted_outbound_tx, hosted_outbound_rx) = mpsc::channel(64);

        let state = Self(Arc::new(ApiInner {
            peers:      RwLock::new(HashMap::new()),
            reputation: RwLock::new(HashMap::new()),
            batches:    RwLock::new(Vec::new()),
            event_tx,
            self_agent,
            outbound_tx,
            inbox_tx,
            api_secret,
            hosted_sessions:    Arc::new(RwLock::new(HashMap::new())),
            hosting_fee_bps,
            hosted_outbound_tx,
        }));

        (state, outbound_rx, hosted_outbound_rx)
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

    /// Queue a pre-signed hosted-agent envelope to the node loop for gossipsub broadcast.
    pub async fn send_hosted_outbound(&self, env: Envelope) -> Result<(), String> {
        self.0.hosted_outbound_tx.send(env).await
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
        .route("/reputation/{agent_id}",    get(get_reputation))
        .route("/batch/{agent_id}/{epoch}", get(get_batch))
        // Agent integration
        .route("/envelopes/send",         post(send_envelope))
        .route("/ws/inbox",               get(ws_inbox_handler))
        // Hosted-agent API
        .route("/hosted/ping",            get(hosted_ping))
        .route("/hosted/register",        post(hosted_register))
        .route("/hosted/send",            post(hosted_send))
        .route("/ws/hosted/inbox",        get(ws_hosted_inbox_handler))
        .layer(tower_http::cors::CorsLayer::permissive())
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
// Hosted-agent route handlers
// ============================================================================

/// GET /hosted/ping — no auth. Returns immediately; used by mobile for RTT probing.
async fn hosted_ping() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

/// POST /hosted/register — open (no auth).
///
/// Generates a fresh ed25519 sub-keypair for the hosted agent.
/// Returns `{ "agent_id": "<hex64>", "token": "<hex64>" }`.
async fn hosted_register(State(state): State<ApiState>) -> impl IntoResponse {
    let now = now_secs();

    let mut sessions = state.0.hosted_sessions.write().await;

    // Evict expired sessions before checking capacity.
    sessions.retain(|_, s| now.saturating_sub(s.created_at) < SESSION_TTL_SECS);

    if sessions.len() >= MAX_HOSTED_SESSIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "host at capacity" })),
        );
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let agent_id    = signing_key.verifying_key().to_bytes();
    let token       = hex::encode(rand::random::<[u8; 32]>());

    let session = HostedSession {
        agent_id,
        signing_key,
        created_at:        now,
        nonce:             0,
        rate_window_start: now,
        sends_in_window:   0,
    };
    sessions.insert(token.clone(), session);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "agent_id": hex::encode(agent_id),
            "token":    token,
        })),
    )
}

/// POST /hosted/send — `Authorization: Bearer <token>`.
///
/// Signs an envelope using the session sub-keypair and forwards it to the
/// node loop for gossipsub broadcast.
async fn hosted_send(
    State(state): State<ApiState>,
    headers:      HeaderMap,
    Json(req):    Json<HostedSendRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None    => return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing Bearer token" })),
        ),
    };

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
    let payload = match hex::decode(&req.payload_hex) {
        Ok(b)  => b,
        Err(_) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "payload_hex: invalid hex" })),
        ),
    };

    // Build pre-signed envelope using the session sub-keypair.
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None    => return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid token" })),
            ),
        };

        // Session TTL check.
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }

        // Rate limiting: sliding 60-second window.
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window   = 0;
        }
        session.sends_in_window += 1;
        if session.sends_in_window > MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }

        session.nonce += 1;
        Envelope::build(
            msg_type,
            session.agent_id,
            recipient,
            0,
            session.nonce,
            conversation_id,
            payload,
            &session.signing_key,
        )
    };

    if state.send_hosted_outbound(env).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }

    (StatusCode::NO_CONTENT, Json(serde_json::json!(null)))
}

/// GET /ws/hosted/inbox
///
/// Opens a WebSocket and streams inbound envelopes addressed to the hosted
/// agent's agent_id.
///
/// Token is resolved with the following priority:
///   1. `Authorization: Bearer <token>` header (preferred — never logged)
///   2. `?token=<hex>` query param (deprecated — visible in server logs)
async fn ws_hosted_inbox_handler(
    ws:           WebSocketUpgrade,
    headers:      HeaderMap,
    Query(q):     Query<HostedInboxQuery>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    let token = resolve_hosted_token(&headers)
        .or_else(|| {
            if q.token.is_some() {
                tracing::warn!(
                    "WS /ws/hosted/inbox: token passed via query param (deprecated). \
                     Use Authorization: Bearer header instead."
                );
            }
            q.token
        });

    match token {
        Some(t) => ws.on_upgrade(|socket| ws_hosted_inbox_task(socket, state, t))
            .into_response(),
        None    => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing Bearer token" })),
        ).into_response(),
    }
}

async fn ws_hosted_inbox_task(mut socket: WebSocket, state: ApiState, token: String) {
    // Resolve session to get agent_id for filtering; reject expired tokens.
    let agent_id_hex = {
        let sessions = state.0.hosted_sessions.read().await;
        match sessions.get(&token) {
            Some(s) => {
                if now_secs().saturating_sub(s.created_at) >= SESSION_TTL_SECS {
                    let _ = socket.send(Message::Text(
                        r#"{"error":"session expired"}"#.into()
                    )).await;
                    return;
                }
                hex::encode(s.agent_id)
            }
            None    => {
                let _ = socket.send(Message::Text(
                    r#"{"error":"invalid token"}"#.into()
                )).await;
                return;
            }
        }
    };

    let mut rx = state.0.inbox_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(env) => {
                // Only forward envelopes addressed to this hosted agent.
                if env.recipient != agent_id_hex {
                    continue;
                }
                match serde_json::to_string(&env) {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::warn!("WS hosted inbox serialize error: {e}"),
                }
            }
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

/// Extract the Bearer token from an `Authorization: Bearer <token>` header.
fn resolve_hosted_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}
