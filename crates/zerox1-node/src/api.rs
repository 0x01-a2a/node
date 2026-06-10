//! Visualization API + Agent Integration API.
//!
//! Visualization (read-only):
//!   GET  /ws/events              — WebSocket stream of node events
//!   GET  /peers                  — All known peers with lease status
//!   GET  /reputation/{agent_id}  — Reputation vector for an agent
//!   GET  /batch/{agent_id}/{epoch} — Batch summary (own node only)
//!
//! Agent integration:
//!   POST /envelopes/send         — Send an envelope (node signs + routes)
//!   GET  /ws/inbox               — WebSocket stream of inbound envelopes
//!
//! High-level negotiation (encode + send in one call):
//!   POST /negotiate/propose      — Send PROPOSE with structured payload
//!   POST /negotiate/counter      — Send COUNTER with structured payload
//!   POST /negotiate/accept       — Send ACCEPT with agreed amount encoded
//!   POST /hosted/negotiate/propose  — Same, for hosted agents (Bearer token)
//!   POST /hosted/negotiate/counter  — Same, for hosted agents
//!   POST /hosted/negotiate/accept   — Same, for hosted agents
//!
//! Escrow (explicit on-chain locking):
//!   POST /escrow/lock            — Lock USDC in escrow (requester → provider)
//!   POST /escrow/approve         — Approve and release locked payment
//!
//! 8004 Solana Agent Registry:
//!   GET  /registry/8004/info              — Program IDs, collection, step-by-step guide
//!   POST /registry/8004/register-prepare  — Build partially-signed tx (agent signs message_b64)
//!   POST /registry/8004/register-submit   — Inject owner sig + broadcast to Solana

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
#[cfg(feature = "pilot")]
use std::collections::HashSet;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use zerox1_protocol::{
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::{BroadcastPayload, FeedbackPayload, NotarizeBidPayload},
};

// ============================================================================
// Snapshot types — serialisable views of node state (visualization)
// ============================================================================

#[derive(Clone, Serialize)]
pub struct PeerSnapshot {
    pub agent_id: String,
    pub peer_id: Option<String>,
    #[cfg(feature = "settlement")]
    pub lease_ok: Option<bool>,
    pub last_active_epoch: u64,
}

#[derive(Clone, Serialize)]
pub struct ReputationSnapshot {
    pub agent_id: String,
    pub reliability: i64,
    pub cooperation: i64,
    pub notary_accuracy: i64,
    pub total_tasks: u32,
    pub total_disputes: u32,
    pub last_active_epoch: u64,
}

#[derive(Clone, Serialize)]
pub struct BatchSnapshot {
    pub agent_id: String,
    pub epoch: u64,
    pub message_count: u32,
    pub log_merkle_root: String,
    pub batch_hash: String,
}

// ============================================================================
// Visualization events — broadcast to /ws/events subscribers
// ============================================================================

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiEvent {
    Envelope {
        sender: String,
        msg_type: String,
        slot: u64,
    },
    PeerRegistered {
        agent_id: String,
        peer_id: String,
    },
    ReputationUpdate {
        agent_id: String,
        reliability: i64,
        cooperation: i64,
    },
    BatchSubmitted {
        epoch: u64,
        message_count: u32,
        batch_hash: String,
    },
}

// ============================================================================
// Portfolio types
// ============================================================================

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PortfolioEvent {
    Swap {
        input_mint: String,
        output_mint: String,
        input_amount: f64,
        output_amount: f64,
        txid: String,
        timestamp: u64,
    },
    Bounty {
        amount_usdc: f64,
        from_agent: String,
        conversation_id: String,
        timestamp: u64,
    },
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PortfolioHistory {
    pub events: Vec<PortfolioEvent>,
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
    pub nonce: u64,
    pub payload_hash: String, // hex keccak256
}

// ── Negotiate endpoint types ──────────────────────────────────────────────

/// Build the standard negotiate payload wire format:
/// `[16-byte LE i128 amount_usdc_micro][JSON extra]`
fn build_negotiate_payload(amount_usdc_micro: u64, extra: serde_json::Value) -> Vec<u8> {
    let mut payload = (amount_usdc_micro as i128).to_le_bytes().to_vec();
    payload.extend_from_slice(extra.to_string().as_bytes());
    payload
}

/// Request body for POST /negotiate/propose (and /hosted/negotiate/propose).
#[derive(Deserialize)]
pub struct NegotiateProposeRequest {
    pub recipient: String,
    /// 16-byte hex conversation ID. Auto-generated if omitted.
    pub conversation_id: Option<String>,
    /// Bid amount in USD microunits. Default: 0 (unspecified).
    pub amount_usdc_micro: Option<u64>,
    /// Max counter rounds (default: 2).
    pub max_rounds: Option<u8>,
    pub message: String,
    // ── Token payment fields ──────────────────────────────────────────────
    /// Solana base58 mint of the receiving agent's token (payment currency).
    pub token_mint: Option<String>,
    /// Solana tx signature proving downpayment token purchase.
    pub payment_tx: Option<String>,
    /// USD value of the downpayment in microunits (1 USD = 1_000_000).
    pub payment_usd_micro: Option<u64>,
    /// Total agreed price in USD microunits (full job, not just downpayment).
    pub total_price_usd_micro: Option<u64>,
}

/// Request body for POST /negotiate/counter (and /hosted/negotiate/counter).
#[derive(Deserialize)]
pub struct NegotiateCounterRequest {
    pub recipient: String,
    pub conversation_id: String,
    pub amount_usdc_micro: u64,
    pub round: u8,
    pub max_rounds: Option<u8>,
    pub message: Option<String>,
    /// Solana base58 mint of the agent's token (so counterparty knows what to buy).
    pub token_mint: Option<String>,
}

/// Request body for POST /negotiate/accept (and /hosted/negotiate/accept).
#[derive(Deserialize)]
pub struct NegotiateAcceptRequest {
    pub recipient: String,
    pub conversation_id: String,
    pub amount_usdc_micro: u64,
    pub message: Option<String>,
    /// Solana base58 mint of the agent's token (payment currency for remainder).
    pub token_mint: Option<String>,
    /// USD value of downpayment already received (microunits).
    pub downpayment_usd_micro: Option<u64>,
    /// USD value of remaining balance due after preview (microunits).
    pub remaining_usd_micro: Option<u64>,
}

// Escrow endpoint types removed — on-chain settlement moved to settlement/solana.

// (Removed duplicate PortfolioBalances)

/// Outbound request queued by POST /envelopes/send, consumed by the node loop.
pub struct OutboundRequest {
    pub msg_type: MsgType,
    pub recipient: [u8; 32],
    pub conversation_id: [u8; 16],
    pub payload: Vec<u8>,
    pub reply: tokio::sync::oneshot::Sender<Result<SentConfirmation, String>>,
}

/// Inbound envelope pushed from the node loop to /ws/inbox subscribers.
#[derive(Clone, Serialize)]
pub struct InboundEnvelope {
    pub msg_type: String,
    pub sender: String,          // hex
    pub recipient: String,       // hex
    pub conversation_id: String, // hex
    pub slot: u64,
    pub nonce: u64,
    pub payload_b64: String,
    /// Decoded FEEDBACK payload fields (only present for FEEDBACK messages).
    pub feedback: Option<serde_json::Value>,
    /// Decoded NOTARIZE_BID payload fields (only present for NOTARIZE_BID messages).
    pub notarize_bid: Option<serde_json::Value>,
    /// Decoded DELIVER payload fields (only present for DELIVER messages).
    /// `inline_b64` carries content directly; `payload_uri` carries a storage ref.
    pub deliver: Option<serde_json::Value>,
}

// ============================================================================
// Hosted-agent session state
// ============================================================================

/// Hard cap on concurrent hosted sessions to prevent memory DoS.
#[cfg(feature = "pilot")]
const MAX_HOSTED_SESSIONS: usize = 10_000;
/// Sessions older than this are evicted and their tokens rejected.
const SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
/// Maximum outbound sends per 60-second window per session.
#[cfg(feature = "pilot")]
const MAX_SENDS_PER_MINUTE: u32 = 60;
/// Maximum API `/envelopes/send` requests per 60-second window.
const MAX_API_SENDS_PER_MINUTE: u32 = 120;
/// Maximum `/identity/sign` requests per 60-second window.
const MAX_SIGN_PER_MINUTE: u32 = 60;
/// Maximum `/registry/8004/register-prepare` requests per 60-second window.
/// Each request makes an external Solana RPC call, so cap tightly.
const MAX_REGISTRY_PREPARE_PER_MINUTE: u32 = 10;
/// Maximum `/registry/8004/register-submit` requests per 60-second window.
const MAX_REGISTRY_SUBMIT_PER_MINUTE: u32 = 20;
/// Maximum `/hosted/send` requests per 60-second window.
/// Maximum Kora gas sponsorships per 24-hour window.
/// After this, callers fall back to agent-pays-SOL.
#[allow(dead_code)]
const MAX_KORA_DAILY_USES: u32 = 100;
/// Maximum byte length of the `message` field in negotiate endpoints.
/// Prevents a large JSON serialisation from creating an oversized envelope.
const MAX_NEGOTIATE_MESSAGE_LEN: usize = 4_096;

struct RateLimitWindow {
    window_start: u64,
    count: u32,
}

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
    pub agent_id: [u8; 32],
    pub signing_key: SigningKey,
    pub created_at: u64,
    pub nonce: u64,
    /// Start of the current 60-second rate-limit window (unix seconds).
    pub rate_window_start: u64,
    /// Number of sends in the current rate-limit window.
    pub sends_in_window: u32,
}

/// Request body for POST /hosted/send.
#[derive(Deserialize)]
pub struct HostedSendRequest {
    pub msg_type: String,
    pub recipient: Option<String>,
    pub conversation_id: String,
    pub payload_hex: String,
}

/// Query parameters for GET /ws/hosted/inbox (token fallback only).
#[derive(Deserialize)]
pub struct HostedInboxQuery {
    pub token: Option<String>,
}

/// Query parameters for GET /ws/topics.
#[derive(Deserialize)]
pub struct BroadcastTopicQuery {
    /// Named topic to subscribe to (e.g. "radio:defi-daily").
    pub topic: String,
    /// Optional token for token-based auth fallback.
    pub token: Option<String>,
}

// ============================================================================
// Shared API state
// ============================================================================

pub struct ApiInner {
    // Visualization state
    peers: RwLock<HashMap<[u8; 32], PeerSnapshot>>,
    reputation: RwLock<HashMap<[u8; 32], ReputationSnapshot>>,
    batches: RwLock<VecDeque<BatchSnapshot>>,
    event_tx: broadcast::Sender<ApiEvent>,
    self_agent: [u8; 32],
    self_name: String,

    // Agent integration channels
    /// Outbound requests from HTTP handlers to the node loop.
    outbound_tx: mpsc::Sender<OutboundRequest>,
    /// Inbound envelopes from node loop to /ws/inbox subscribers.
    inbox_tx: broadcast::Sender<InboundEnvelope>,
    /// Optional bearer token to authenticate mutating API endpoints.
    api_secret: Option<String>,
    /// Read-only bearer tokens — grants access to GET/WS visualization endpoints
    /// but NOT to mutating endpoints like /envelopes/send.
    api_read_keys: Vec<String>,

    // Named-topic BROADCAST channels
    /// Fan-out channel for inbound BROADCAST (0x0E) envelopes.
    named_broadcast_tx: broadcast::Sender<InboundEnvelope>,
    /// Sends gossipsub topic subscription requests to the node loop.
    sub_topic_tx: mpsc::Sender<String>,

    // Hosted-agent state
    /// token (hex-32) → HostedSession
    pub hosted_sessions: Arc<RwLock<HashMap<String, HostedSession>>>,
    /// Pre-signed envelopes from hosted-agent send handler → node loop.
    hosted_outbound_tx: mpsc::Sender<Envelope>,
    /// Global rate limit window for `/envelopes/send`.
    send_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/hosted/register`.
    #[cfg(feature = "pilot")]
    hosted_register_rate_limit: Mutex<RateLimitWindow>,
    /// Solana RPC URL — retained as an informational config string for the
    /// dashboard. No Solana RPC calls are issued from the node anymore.
    pub rpc_url: String,
    /// Node's own Ed25519 signing key — used for envelope signing.
    pub node_signing_key: Arc<SigningKey>,
    /// Shared HTTP client for outbound requests (aggregator, webhook).
    pub(crate) http_client: reqwest::Client,
    /// Optional aggregator URL for LLM proxy forwarding (/chat/completions → aggregator /llm/chat).
    /// Set when --aggregator-url is configured; used by zeroclaw "default" provider.
    #[cfg(feature = "pilot")]
    pub(crate) llm_proxy_url: Option<String>,
    /// Optional override for the 8004 base collection. Retained as a passive
    /// config string for the dashboard — no on-chain calls happen here.
    #[allow(dead_code)]
    registry_8004_collection: Option<String>,
    /// The current "slot" — now a monotonic unix-second counter, updated by the node event loop.
    current_slot: core::sync::atomic::AtomicU64,
    /// Agent IDs exempt from stake/lease/registration checks.
    /// Shared with Node so either side can read it; admin API writes via POST/DELETE /admin/exempt.
    #[cfg(feature = "pilot")]
    exempt_agents: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
    /// Path to persist exempt_agents across restarts (log_dir/exempt_agents.json).
    /// Also used as a log_dir anchor by agent_profile_read/write.
    exempt_persist_path: PathBuf,

    // Portfolio state
    pub portfolio_history: RwLock<PortfolioHistory>,
    portfolio_persist_path: RwLock<PathBuf>,

    // Agent (zeroclaw) process management
    /// PID of the running zeroclaw agent process. Set by POST /agent/register-pid.
    /// Used by POST /agent/reload to restart the agent so new skills are loaded.
    pub agent_pid: Mutex<Option<u32>>,
    /// Rate limit for POST /identity/sign — max 60 signs per minute.
    sign_rate_limit: Mutex<RateLimitWindow>,
    /// Rate limit for POST /agent/reload — max 3 reloads per minute.
    #[cfg(feature = "pilot")]
    agent_reload_rate_limit: Mutex<RateLimitWindow>,

    // Skill manager
    /// Zeroclaw workspace directory. When set, skill management endpoints are active.
    pub skill_workspace: Option<std::path::PathBuf>,

    // File delivery
    /// Optional file delivery adapter for large DELIVER payload offload.
    /// On send: payloads > INLINE_PAYLOAD_LIMIT are uploaded; envelope carries URI.
    /// On receive: DeliverPayload with payload_uri is decoded and exposed in inbox event.
    /// Currently always None — 0G adapter temporarily disabled pending re-integration.
    pub file_delivery: Option<Arc<dyn zerox1_filedelivery_core::FileDelivery>>,

    // Task audit log
    /// SQLite-backed log of completed tasks. Present when --task-log-path is set.
    /// Zeroclaw writes entries via POST /tasks/log; mobile reads them via GET /tasks/log.
    pub task_log: Option<Arc<crate::task_log::TaskLog>>,
}

/// Cheaply cloneable shared state passed to all axum handlers.
#[derive(Clone)]
pub struct ApiState(Arc<ApiInner>);

impl ApiState {
    /// Create a new ApiState.
    ///
    /// Returns `(state, outbound_rx, hosted_outbound_rx, sub_topic_rx)`. The caller (node)
    /// must hold onto all receivers and drive them in the main event loop.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        self_agent: [u8; 32],
        self_name: String,
        api_secret: Option<String>,
        api_read_keys: Vec<String>,
        rpc_url: String,
        http_client: reqwest::Client,
        #[cfg(feature = "pilot")] llm_proxy_url: Option<String>,
        registry_8004_collection: Option<String>,
        node_signing_key: Arc<SigningKey>,
        #[cfg(feature = "pilot")] exempt_agents: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
        exempt_persist_path: PathBuf,
        skill_workspace: Option<std::path::PathBuf>,
        file_delivery: Option<Arc<dyn zerox1_filedelivery_core::FileDelivery>>,
        task_log: Option<Arc<crate::task_log::TaskLog>>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundRequest>,
        mpsc::Receiver<Envelope>,
        mpsc::Receiver<String>,
    ) {
        let (event_tx, _) = broadcast::channel(512);
        let (inbox_tx, _) = broadcast::channel(256);
        let (named_broadcast_tx, _) = broadcast::channel(256);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (hosted_outbound_tx, hosted_outbound_rx) = mpsc::channel(64);
        let (sub_topic_tx, sub_topic_rx) = mpsc::channel(64);

        let state = Self(Arc::new(ApiInner {
            peers: RwLock::new(HashMap::new()),
            reputation: RwLock::new(HashMap::new()),
            batches: RwLock::new(VecDeque::new()),
            event_tx,
            self_agent,
            self_name,
            outbound_tx,
            inbox_tx,
            api_secret,
            api_read_keys,
            named_broadcast_tx,
            sub_topic_tx,
            hosted_sessions: Arc::new(RwLock::new(HashMap::new())),
            hosted_outbound_tx,
            send_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            #[cfg(feature = "pilot")]
            hosted_register_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            rpc_url,
            node_signing_key,
            http_client,
            #[cfg(feature = "pilot")]
            llm_proxy_url,
            registry_8004_collection,
            current_slot: core::sync::atomic::AtomicU64::new(0),
            #[cfg(feature = "pilot")]
            exempt_agents,
            exempt_persist_path,
            portfolio_history: RwLock::new(PortfolioHistory::default()),
            portfolio_persist_path: RwLock::new(PathBuf::new()), // set during init
            agent_pid: Mutex::new(None),
            sign_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            #[cfg(feature = "pilot")]
            agent_reload_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            skill_workspace,
            file_delivery,
            task_log,
        }));

        // Background task: evict expired hosted sessions every hour so the
        // HashMap doesn't grow unbounded if tokens are registered but never used.
        {
            let evict_state = state.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    let now = now_secs();
                    let mut sessions = evict_state.0.hosted_sessions.write().await;
                    let before = sessions.len();
                    sessions.retain(|_, s| now.saturating_sub(s.created_at) < SESSION_TTL_SECS);
                    let evicted = before - sessions.len();
                    if evicted > 0 {
                        tracing::info!("hosted session GC: evicted {evicted} expired sessions");
                    }
                }
            });
        }

        if state.0.api_secret.is_none() {
            tracing::warn!(
                "No api_secret configured — mutating endpoints (/envelopes/send) are \
                 unauthenticated. Set --api-secret / ZX01_API_SECRET for production use."
            );
        }

        (state, outbound_rx, hosted_outbound_rx, sub_topic_rx)
    }

    pub async fn load_portfolio_history(&self, path: PathBuf) -> anyhow::Result<()> {
        *self.0.portfolio_persist_path.write().await = path.clone();

        if path.exists() {
            let data = tokio::fs::read_to_string(&path).await?;
            let history: PortfolioHistory = serde_json::from_str(&data)?;
            *self.0.portfolio_history.write().await = history;
        }
        Ok(())
    }

    pub async fn record_portfolio_event(&self, event: PortfolioEvent) {
        let mut history = self.0.portfolio_history.write().await;
        history.events.insert(0, event);
        if history.events.len() > 1000 {
            history.events.truncate(1000);
        }

        // Persist asynchronously — drop the write lock first so other tasks
        // can access portfolio_history while we do the (potentially slow) write.
        let path = self.0.portfolio_persist_path.read().await.clone();
        if !path.as_os_str().is_empty() {
            if let Ok(json) = serde_json::to_string_pretty(&*history) {
                drop(history);
                let _ = tokio::fs::write(&path, json).await;
            }
        }
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
        if batches.len() >= 200 {
            batches.pop_front();
        }
        batches.push_back(snap);
    }

    /// Broadcast a visualization event to all /ws/events subscribers.
    pub fn send_event(&self, event: ApiEvent) {
        let _ = self.0.event_tx.send(event);
    }

    pub fn set_current_slot(&self, slot: u64) {
        self.0
            .current_slot
            .store(slot, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_current_slot(&self) -> u64 {
        self.0
            .current_slot
            .load(core::sync::atomic::Ordering::Relaxed)
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

        let deliver = if env.msg_type == zerox1_protocol::message::MsgType::Deliver {
            zerox1_protocol::payload::DeliverPayload::decode(&env.payload)
                .ok()
                .map(|p| {
                    serde_json::json!({
                        "conversation_id": hex::encode(p.conversation_id),
                        "content_type":    p.content_type,
                        "inline_b64":      p.inline.as_deref().map(|b| B64.encode(b)),
                        "payload_uri":     p.payload_uri,
                        "payload_size":    p.payload_size,
                    })
                })
        } else {
            None
        };

        let inbound = InboundEnvelope {
            msg_type: format!("{}", env.msg_type),
            sender: hex::encode(env.sender),
            recipient: hex::encode(env.recipient),
            conversation_id: hex::encode(env.conversation_id),
            slot,
            nonce: env.nonce,
            payload_b64: B64.encode(&env.payload),
            feedback,
            notarize_bid,
            deliver,
        };

        let _ = self.0.inbox_tx.send(inbound.clone());
        if env.msg_type == zerox1_protocol::message::MsgType::Broadcast {
            let _ = self.0.named_broadcast_tx.send(inbound);
        }
    }

    /// Queue an outbound envelope request to the node loop.
    ///
    /// Called by the POST /envelopes/send handler.
    pub async fn send_outbound(&self, req: OutboundRequest) -> Result<(), String> {
        self.0
            .outbound_tx
            .send(req)
            .await
            .map_err(|_| "node loop unavailable".to_string())
    }

    /// Queue a pre-signed hosted-agent envelope to the node loop for gossipsub broadcast.
    pub async fn send_hosted_outbound(&self, env: Envelope) -> Result<(), String> {
        self.0
            .hosted_outbound_tx
            .send(env)
            .await
            .map_err(|_| "node loop unavailable".to_string())
    }
}

// ============================================================================
// Server
// ============================================================================

pub fn build_router(state: ApiState, cors_origins: Vec<String>) -> axum::Router {
    let router = Router::new()
        // Visualization
        .route("/ws/events", get(ws_events_handler))
        .route("/identity", get(get_identity))
        .route("/identity/sign", post(identity_sign))
        .route("/identity/export-key", get(identity_export_key))
        .route("/peers", get(get_peers))
        .route("/reputation/{agent_id}", get(get_reputation))
        .route("/batch/{agent_id}/{epoch}", get(get_batch))
        // Agent integration
        .route("/envelopes/send", post(send_envelope))
        .route("/ws/inbox", get(ws_inbox_handler))
        // High-level negotiate endpoints (encode + send)
        .route("/negotiate/propose", post(negotiate_propose))
        .route("/negotiate/counter", post(negotiate_counter))
        .route("/negotiate/accept", post(negotiate_accept))
        // Named-topic BROADCAST subscriptions
        .route("/topics/{slug}/broadcast", post(topic_broadcast))
        .route("/ws/topics", get(ws_topics_handler))
        // Agent memory + persona (passive observation files)
        .route("/agent/memory", get(agent_memory_read))
        .route("/agent/memory/write", post(agent_memory_write))
        .route("/agent/persona", get(agent_persona_read))
        .route("/agent/persona/write", post(agent_persona_write))
        .route("/agent/conversation/export", get(agent_conversation_export))
        .route("/podcast/produce-local", post(podcast_produce_local))
        .route("/agent/profile", get(agent_profile_read).post(agent_profile_write))
        // Skill manager — safe Rust-side file operations (no shell injection)
        .route("/skill/list", get(skill_list_handler))
        .route("/skill/write", post(skill_write_handler))
        .route("/skill/install-url", post(skill_install_url_handler))
        .route("/skill/remove", post(skill_remove_handler))
        // Task audit log
        .route("/tasks/log", post(task_log_insert).get(task_log_list))
        .route("/tasks/log/{id}/shared", patch(task_log_mark_shared))
        .route("/tasks/log/{id}", delete(task_log_delete));

    #[cfg(feature = "pilot")]
    let router = router
        // Admin — exempt agent management (loopback only; requires api_secret)
        .route("/admin/exempt", get(admin_exempt_list).post(admin_exempt_add))
        .route("/admin/exempt/{agent_id}", delete(admin_exempt_remove))
        // Hosted-agent API
        .route("/hosted/ping", get(hosted_ping))
        .route("/hosted/register", post(hosted_register))
        .route("/hosted/send", post(hosted_send))
        .route("/hosted/negotiate/propose", post(hosted_negotiate_propose))
        .route("/hosted/negotiate/counter", post(hosted_negotiate_counter))
        .route("/hosted/negotiate/accept", post(hosted_negotiate_accept))
        .route("/ws/hosted/inbox", get(ws_hosted_inbox_handler))
        // ZeroClaw process management
        .route("/agent/register-pid", post(agent_register_pid))
        .route("/agent/reload", post(agent_reload))
        // LLM relay — forwards to aggregator /llm/chat with agent_id injected
        .route("/chat/completions", post(chat_completions_relay));

    let router = router.route("/portfolio/history", get(portfolio_history));

    router
        .layer({
            // Always include loopback origins so zeroclaw and React Native WebView
            // continue to work even when additional origins are added.
            let mut origins: Vec<axum::http::HeaderValue> = vec![
                "http://127.0.0.1".parse().expect("valid CORS origin"),
                "http://localhost".parse().expect("valid CORS origin"),
            ];
            for o in &cors_origins {
                if let Ok(v) = o.parse() {
                    origins.push(v);
                }
            }
            tower_http::cors::CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers(tower_http::cors::Any)
        })
        .with_state(state)
}

pub async fn serve(state: ApiState, addr: SocketAddr, cors_origins: Vec<String>) {
    let app = build_router(state, cors_origins);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("API listener bind failed on {addr}: {e}");
            return;
        }
    };

    tracing::info!("API listening on http://{addr}");

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("API server error: {e}");
    }
}

// ============================================================================
// Visualization route handlers
// ============================================================================

async fn ws_events_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(resp) = require_read_or_master_ws(&state, &headers, &params) {
        return resp;
    }
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
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

async fn get_identity(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    Json(serde_json::json!({
        "agent_id": hex::encode(state.0.self_agent),
        "name":     state.0.self_name,
    }))
    .into_response()
}

/// Sign arbitrary bytes with the node's Ed25519 identity key.
///
/// Used by zeroclaw to sign capability proof hashes before broadcasting ADVERTISE.
/// Requires read or master access. Max input: 256 bytes (512 hex chars).
async fn identity_sign(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    // Per-minute rate limit to prevent key-oracle abuse if credentials leak.
    {
        let now = now_secs();
        let mut rl = state.0.sign_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_SIGN_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            )
                .into_response();
        }
        rl.count += 1;
    }
    let bytes_hex = match body.get("bytes_hex").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return Json(serde_json::json!({ "error": "bytes_hex required" })).into_response(),
    };
    if bytes_hex.len() > 512 {
        return Json(serde_json::json!({ "error": "bytes_hex too long (max 256 bytes)" }))
            .into_response();
    }
    let bytes = match hex::decode(bytes_hex) {
        Ok(b) => b,
        Err(_) => return Json(serde_json::json!({ "error": "invalid hex" })).into_response(),
    };
    use ed25519_dalek::Signer as _;
    let sig = state.0.node_signing_key.sign(&bytes);
    Json(serde_json::json!({
        "signature_hex": hex::encode(sig.to_bytes()),
        "agent_id":      hex::encode(state.0.self_agent),
    }))
    .into_response()
}

/// Export the node's Ed25519 identity keypair as a base58 string.
///
/// Returns the 64-byte Solana-compatible keypair (seed || pubkey) encoded as
/// base58 — the same format used by Solana CLI and most wallets. This allows
/// the user to import their agent's hot wallet into any Solana wallet app.
///
/// Requires master (api_secret) access only — never accessible with read-only keys.
async fn identity_export_key(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    // Always require the master secret — never open even in dev mode.
    if state.0.api_secret.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "key export requires api_secret to be configured" })),
        )
            .into_response();
    }
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let seed = state.0.node_signing_key.to_bytes(); // [u8; 32]
    let pubkey = state.0.node_signing_key.verifying_key().to_bytes(); // [u8; 32]
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(&seed);
    keypair_bytes[32..].copy_from_slice(&pubkey);
    Json(serde_json::json!({
        "secret_key_b58": bs58::encode(&keypair_bytes).into_string(),
    }))
    .into_response()
}

async fn get_peers(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let peers = state.0.peers.read().await;
    let list: Vec<_> = peers.values().cloned().collect();
    Json(serde_json::to_value(list).unwrap_or_default()).into_response()
}

async fn get_reputation(
    Path(agent_id_hex): Path<String>,
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let Ok(bytes) = hex::decode(&agent_id_hex) else {
        return Json(serde_json::json!({ "error": "invalid agent_id hex" })).into_response();
    };
    let Ok(arr) = bytes.try_into() as Result<[u8; 32], _> else {
        return Json(serde_json::json!({ "error": "agent_id must be 32 bytes" })).into_response();
    };
    let rep = state.0.reputation.read().await;
    match rep.get(&arr) {
        Some(snap) => Json(serde_json::to_value(snap).unwrap_or_default()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no reputation data" })),
        )
            .into_response(),
    }
}

async fn get_batch(
    Path((agent_id_hex, epoch)): Path<(String, u64)>,
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let self_hex = hex::encode(state.0.self_agent);
    if agent_id_hex != self_hex {
        return Json(serde_json::json!({
            "error": "batch history is only available for this node's own agent_id"
        }))
        .into_response();
    }
    let batches = state.0.batches.read().await;
    match batches.iter().find(|b| b.epoch == epoch) {
        Some(snap) => Json(serde_json::to_value(snap).unwrap_or_default()).into_response(),
        None => Json(serde_json::json!({ "error": "epoch not found" })).into_response(),
    }
}

// ============================================================================
// Agent integration route handlers
// ============================================================================

async fn send_envelope(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<SendEnvelopeRequest>,
) -> impl IntoResponse {
    // Authenticate: only the master secret (not read-only keys) can send envelopes.
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }

    // Shared API-level rate limit to reduce flooding impact if credentials leak.
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }

    // Parse msg_type.
    let msg_type = match parse_msg_type(&req.msg_type) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("unknown msg_type: {}", req.msg_type) })),
            )
        }
    };

    // Parse recipient.
    let recipient: [u8; 32] = if msg_type.is_broadcast()
        || msg_type.is_notary_pubsub()
        || msg_type.is_reputation_pubsub()
        || msg_type.is_named_broadcast()
    {
        BROADCAST_RECIPIENT
    } else {
        match &req.recipient {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "recipient required for bilateral messages" }),
                    ),
                )
            }
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(b) => match b.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": "recipient must be 32 bytes" })),
                        )
                    }
                },
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "recipient: invalid hex" })),
                    )
                }
            },
        }
    };

    // Parse conversation_id.
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id) {
        Ok(b) => match b.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "conversation_id must be 16 bytes" })),
                )
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "conversation_id: invalid hex" })),
            )
        }
    };

    // Guard against oversized payloads before decoding — base64 of 64 KB ≈ 88 KB.
    const MAX_PAYLOAD_B64_LEN: usize = (zerox1_protocol::constants::MAX_MESSAGE_SIZE / 3 + 1) * 4;
    if req.payload_b64.len() > MAX_PAYLOAD_B64_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "payload_b64: exceeds maximum envelope size" })),
        );
    }

    // Decode payload.
    let raw_payload = match B64.decode(&req.payload_b64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payload_b64: invalid base64" })),
            )
        }
    };

    // If this is a FEEDBACK message and the payload is JSON (starts with '{'),
    // convert it to the canonical CBOR FeedbackPayload wire format expected by
    // the recipient node. The panel sends JSON {"score":N,"outcome":"..."} for
    // convenience; this normalises it before forwarding over the mesh.
    let payload = if msg_type == zerox1_protocol::message::MsgType::Feedback
        && raw_payload.first() == Some(&b'{')
    {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw_payload) {
            let score = v
                .get("score")
                .and_then(|x| x.as_i64())
                .unwrap_or(0)
                .clamp(-100, 100) as i8;
            let outcome_str = v
                .get("outcome")
                .and_then(|x| x.as_str())
                .unwrap_or("neutral");
            let outcome: u8 = match outcome_str {
                "positive" => 2,
                "negative" => 0,
                _ => 1,
            };
            zerox1_protocol::payload::FeedbackPayload {
                conversation_id,
                target_agent: recipient,
                score,
                outcome,
                is_dispute: false,
                role: zerox1_protocol::payload::FeedbackPayload::ROLE_PARTICIPANT,
            }
            .encode()
        } else {
            raw_payload
        }
    } else if msg_type == zerox1_protocol::message::MsgType::Deliver {
        // Wrap DELIVER payloads in the protocol-defined DeliverPayload CBOR format.
        // If a file delivery adapter is configured and the payload exceeds the inline
        // limit, upload the content and replace with a zerog:// URI reference so the
        // envelope stays within the 64 KB transport limit.
        let limit = zerox1_filedelivery_core::INLINE_PAYLOAD_LIMIT;
        if raw_payload.len() > limit {
            if let Some(fd) = &state.0.file_delivery {
                match fd.upload(raw_payload.clone(), None).await {
                    Ok(ref_) => {
                        tracing::info!(
                            uri = %ref_.uri,
                            bytes = ref_.size_bytes,
                            "DELIVER payload offloaded to 0G Storage"
                        );
                        zerox1_protocol::payload::DeliverPayload {
                            conversation_id,
                            content_type: ref_.content_type,
                            inline: None,
                            payload_uri: Some(ref_.uri),
                            payload_size: Some(ref_.size_bytes),
                        }
                        .encode()
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "0G Storage upload failed; sending inline (may exceed size limit)");
                        zerox1_protocol::payload::DeliverPayload {
                            conversation_id,
                            content_type: None,
                            inline: Some(raw_payload),
                            payload_uri: None,
                            payload_size: None,
                        }
                        .encode()
                    }
                }
            } else {
                // No file delivery configured — pass through raw (may hit size limit).
                raw_payload
            }
        } else {
            zerox1_protocol::payload::DeliverPayload {
                conversation_id,
                content_type: None,
                inline: Some(raw_payload),
                payload_uri: None,
                payload_size: None,
            }
            .encode()
        }
    } else {
        raw_payload
    };

    // Send to node loop via oneshot.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };

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

// ── POST /topics/{slug}/broadcast ─────────────────────────────────────────────

/// Request body for POST /topics/{slug}/broadcast.
#[derive(Deserialize)]
struct TopicBroadcastRequest {
    title: String,
    #[serde(default)]
    tags: Vec<String>,
    /// "audio" | "text" | "data" — defaults to "text"
    #[serde(default = "default_broadcast_format")]
    format: String,
    /// URL pointing to content (audio file, data feed, etc.)
    content_url: Option<String>,
    /// MIME type of content_url (e.g. "audio/mpeg", "application/json")
    content_type: Option<String>,
    /// Duration in milliseconds (for audio/video content)
    duration_ms: Option<u32>,
    /// Subscription price in micro-USDC per epoch (0 = free)
    price_per_epoch_micro: Option<u64>,
    /// Epoch number for sequenced content
    epoch: Option<u64>,
}

fn default_broadcast_format() -> String {
    "text".to_string()
}

/// POST /topics/:slug/broadcast — publish a BROADCAST envelope to a named gossipsub topic.
///
/// Accepts human-friendly JSON, builds the BroadcastPayload CBOR internally,
/// signs with the node identity key, and publishes to gossipsub.
async fn topic_broadcast(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Json(req): Json<TopicBroadcastRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }

    // Validate slug: alphanumeric, hyphens, underscores, colons — max 128 chars.
    if slug.is_empty()
        || slug.len() > 128
        || !slug
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ':')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid topic slug" })),
        );
    }

    if req.title.is_empty() || req.title.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "title must be 1–256 characters" })),
        );
    }

    // Validate format allowlist.
    if !matches!(req.format.as_str(), "text" | "audio" | "data") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "format must be \"text\", \"audio\", or \"data\"" })),
        );
    }

    // Validate tags: max 32 entries, max 64 chars each.
    if req.tags.len() > 32 || req.tags.iter().any(|t| t.is_empty() || t.len() > 64) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "tags: max 32 entries, max 64 chars each" })),
        );
    }

    // Validate content_url: must be http/https URL, max 2048 chars.
    if let Some(ref url) = req.content_url {
        if url.len() > 2048 || (!url.starts_with("https://") && !url.starts_with("http://")) {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "content_url must be an http/https URL, max 2048 chars" }),
                ),
            );
        }
    }

    // Validate content_type: max 128 chars.
    if req.content_type.as_deref().map(|s| s.len()).unwrap_or(0) > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "content_type max 128 characters" })),
        );
    }

    // Rate limit — shared with /envelopes/send and other send endpoints.
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }

    // Build content bytes: store content_url as UTF-8 bytes when provided.
    let content: Option<Vec<u8>> = req.content_url.as_deref().map(|u| u.as_bytes().to_vec());

    let payload_cbor = zerox1_protocol::payload::BroadcastPayload {
        topic: slug.clone(),
        title: req.title,
        tags: req.tags,
        format: req.format,
        content,
        content_type: req.content_type,
        chunk_index: None,
        total_chunks: None,
        duration_ms: req.duration_ms,
        price_per_epoch_micro: req.price_per_epoch_micro,
        epoch: req.epoch,
    }
    .encode();

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: zerox1_protocol::message::MsgType::Broadcast,
        recipient: zerox1_protocol::envelope::BROADCAST_RECIPIENT,
        conversation_id: [0u8; 16],
        payload: payload_cbor,
        reply: reply_tx,
    };

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
            Json(serde_json::json!({ "error": "reply channel closed" })),
        ),
    }
}

async fn ws_inbox_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(resp) = require_read_or_master_ws(&state, &headers, &params) {
        return resp;
    }
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
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

// ============================================================================
// Named-topic BROADCAST subscriber — GET /ws/topics?topic=<name>
// ============================================================================

/// Subscribe to inbound BROADCAST (0x0E) envelopes on a named topic.
///
/// The node automatically subscribes to the gossipsub topic on first connection.
/// Subsequent connections share the same subscription.
async fn ws_topics_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(q): Query<BroadcastTopicQuery>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    // Build params map for auth helper.
    let mut params = HashMap::new();
    if let Some(ref t) = q.token {
        params.insert("token".to_string(), t.clone());
    }
    if let Some(resp) = require_read_or_master_ws(&state, &headers, &params) {
        return resp;
    }

    // Validate topic: non-empty, no path separators, reasonable length.
    let topic = q.topic.trim().to_string();
    if topic.is_empty() || topic.len() > 128 || topic.contains('/') || topic.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid topic" })),
        )
            .into_response();
    }

    // Request the node loop to subscribe to this gossipsub topic (best-effort).
    if let Err(e) = state.0.sub_topic_tx.try_send(topic.clone()) {
        tracing::warn!(
            "sub_topic_tx full, subscription request for {:?} dropped: {e}",
            topic
        );
    }

    ws.on_upgrade(move |socket| ws_topics_task(socket, state, topic))
        .into_response()
}

async fn ws_topics_task(mut socket: WebSocket, state: ApiState, topic: String) {
    let mut rx = state.0.named_broadcast_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(env) => {
                // Filter by topic: decode the BroadcastPayload to extract the topic field.
                let payload_bytes = match B64.decode(&env.payload_b64) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let broadcast_topic = match BroadcastPayload::decode(&payload_bytes) {
                    Ok(p) => p.topic,
                    Err(e) => {
                        tracing::debug!("ws_topics: BroadcastPayload decode failed: {e:?}");
                        continue;
                    }
                };
                if broadcast_topic != topic {
                    continue;
                }
                match serde_json::to_string(&env) {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => tracing::warn!("WS topics serialize error: {e}"),
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

// ============================================================================
// Negotiate route handlers (local)
// ============================================================================

/// POST /negotiate/propose
///
/// Encodes amount + message into the standard negotiate wire format and sends
/// a PROPOSE envelope. Conversation ID is auto-generated if not supplied.
async fn negotiate_propose(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateProposeRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let (conv_id_hex, conversation_id) = match req.conversation_id {
        Some(ref s) => match hex::decode(s).ok().and_then(|b| b.try_into().ok()) {
            Some(a) => (s.clone(), a),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                    ),
                )
            }
        },
        None => {
            let b = rand::Rng::gen::<[u8; 16]>(&mut OsRng);
            (hex::encode(b), b)
        }
    };
    if req.message.len() > MAX_NEGOTIATE_MESSAGE_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "message: exceeds maximum length" })),
        );
    }
    let amount = req.amount_usdc_micro.unwrap_or(0);
    let max_rounds = req.max_rounds.unwrap_or(2);
    let mut propose_extra = serde_json::json!({
        "max_rounds": max_rounds,
        "message": req.message,
    });
    if let Some(ref mint) = req.token_mint {
        propose_extra["token_mint"] = serde_json::Value::String(mint.clone());
    }
    if let Some(ref tx) = req.payment_tx {
        propose_extra["payment_tx"] = serde_json::Value::String(tx.clone());
    }
    if let Some(usd) = req.payment_usd_micro {
        propose_extra["payment_usd_micro"] = serde_json::Value::Number(usd.into());
    }
    if let Some(total) = req.total_price_usd_micro {
        propose_extra["total_price_usd_micro"] = serde_json::Value::Number(total.into());
    }
    let payload = build_negotiate_payload(amount, propose_extra);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: MsgType::Propose,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };
    if state.send_outbound(outbound).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "node loop unavailable" })),
        );
    }
    match reply_rx.await {
        Ok(Ok(conf)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "conversation_id": conv_id_hex,
                "nonce": conf.nonce,
                "payload_hash": conf.payload_hash,
            })),
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

/// POST /negotiate/counter
async fn negotiate_counter(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateCounterRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }
    let max_rounds = req.max_rounds.unwrap_or(2);
    if req.round == 0 || req.round > max_rounds {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("round {} is out of range [1, {}]", req.round, max_rounds)
            })),
        );
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let message = req.message.unwrap_or_default();
    if message.len() > MAX_NEGOTIATE_MESSAGE_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "message: exceeds maximum length" })),
        );
    }
    let mut counter_extra = serde_json::json!({
        "round": req.round,
        "max_rounds": max_rounds,
        "message": message,
    });
    if let Some(ref mint) = req.token_mint {
        counter_extra["token_mint"] = serde_json::Value::String(mint.clone());
    }
    let payload = build_negotiate_payload(req.amount_usdc_micro, counter_extra);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: MsgType::Counter,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };
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

/// POST /negotiate/accept
async fn negotiate_accept(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateAcceptRequest>,
) -> impl IntoResponse {
    if require_api_secret_or_unauthorized(&state, &headers).is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        );
    }
    {
        let now = now_secs();
        let mut rl = state.0.send_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_API_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let message = req.message.unwrap_or_default();
    if message.len() > MAX_NEGOTIATE_MESSAGE_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "message: exceeds maximum length" })),
        );
    }
    let mut accept_extra = serde_json::json!({ "message": message });
    if let Some(ref mint) = req.token_mint {
        accept_extra["token_mint"] = serde_json::Value::String(mint.clone());
    }
    if let Some(dp) = req.downpayment_usd_micro {
        accept_extra["downpayment_usd_micro"] = serde_json::Value::Number(dp.into());
    }
    if let Some(rem) = req.remaining_usd_micro {
        accept_extra["remaining_usd_micro"] = serde_json::Value::Number(rem.into());
    }
    let payload = build_negotiate_payload(req.amount_usdc_micro, accept_extra);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let outbound = OutboundRequest {
        msg_type: MsgType::Accept,
        recipient,
        conversation_id,
        payload,
        reply: reply_tx,
    };
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

// ============================================================================
// Hosted-agent route handlers
// ============================================================================

/// GET /hosted/ping — no auth. Returns immediately; used by mobile for RTT probing.
#[cfg(feature = "pilot")]
async fn hosted_ping() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

/// POST /hosted/register — open (no auth).
///
/// Generates a fresh ed25519 sub-keypair for the hosted agent.
/// Returns `{ "agent_id": "<hex64>", "token": "<hex64>" }`.
#[cfg(feature = "pilot")]
async fn hosted_register(State(state): State<ApiState>) -> impl IntoResponse {
    if state.0.api_secret.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "hosting requires api_secret" })),
        );
    }
    let now = now_secs();

    // Global rate limit for unauthenticated registration to prevent memory/RPC DoS
    {
        let mut rl = state.0.hosted_register_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        // Allow up to 60 registrations per minute globally (1 per second average).
        // This accommodates normal web/mobile app usage while preventing massive DoS bursts.
        if rl.count >= 60 {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "registration rate limit exceeded" })),
            );
        }
        rl.count += 1;
    }

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
    let agent_id = signing_key.verifying_key().to_bytes();
    // Use OsRng explicitly for session tokens — same source as the signing key above.
    let token = hex::encode(rand::Rng::gen::<[u8; 32]>(&mut OsRng));

    let session = HostedSession {
        agent_id,
        signing_key,
        created_at: now,
        nonce: 0,
        rate_window_start: now,
        sends_in_window: 0,
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
#[cfg(feature = "pilot")]
async fn hosted_send(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<HostedSendRequest>,
) -> Response {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
                .into_response()
        }
    };

    // MPP payment gate removed along with the Solana strip.

    // Parse msg_type.
    let msg_type =
        match parse_msg_type(&req.msg_type) {
            Some(t) => t,
            None => return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("unknown msg_type: {}", req.msg_type) })),
            )
                .into_response(),
        };

    // Parse recipient.
    let recipient: [u8; 32] =
        if msg_type.is_broadcast()
            || msg_type.is_notary_pubsub()
            || msg_type.is_reputation_pubsub()
            || msg_type.is_named_broadcast()
        {
            BROADCAST_RECIPIENT
        } else {
            match &req.recipient {
                None => return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "recipient required for bilateral messages" }),
                    ),
                )
                    .into_response(),
                Some(hex_str) => {
                    match hex::decode(hex_str) {
                        Ok(b) => match b.try_into() {
                            Ok(arr) => arr,
                            Err(_) => return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "error": "recipient must be 32 bytes" })),
                            )
                                .into_response(),
                        },
                        Err(_) => {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({ "error": "recipient: invalid hex" })),
                            )
                                .into_response()
                        }
                    }
                }
            }
        };

    // Parse conversation_id.
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id) {
        Ok(b) => match b.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "conversation_id must be 16 bytes" })),
                )
                    .into_response()
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "conversation_id: invalid hex" })),
            )
                .into_response()
        }
    };

    // Guard against oversized payloads before decoding — hex of 64 KB = 128 KB.
    const MAX_PAYLOAD_HEX_LEN: usize = zerox1_protocol::constants::MAX_MESSAGE_SIZE * 2;
    if req.payload_hex.len() > MAX_PAYLOAD_HEX_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "payload_hex: exceeds maximum envelope size" })),
        )
            .into_response();
    }

    // Decode payload.
    let payload = match hex::decode(&req.payload_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payload_hex: invalid hex" })),
            )
                .into_response()
        }
    };

    // Build pre-signed envelope using the session sub-keypair.
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
                    .into_response()
            }
        };

        // Session TTL check.
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            )
                .into_response();
        }

        // Rate limiting: sliding 60-second window.
        // Check *before* incrementing so the counter never drifts past the
        // limit on rejected requests, preventing counter wrap-around.
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        if session.sends_in_window >= MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            )
                .into_response();
        }
        session.sends_in_window += 1;

        session.nonce += 1;
        Envelope::build(
            msg_type,
            session.agent_id,
            recipient,
            state.get_current_slot(),
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
        )
            .into_response();
    }

    (StatusCode::NO_CONTENT, Json(serde_json::json!(null))).into_response()
}

/// POST /hosted/negotiate/propose — `Authorization: Bearer <token>`.
#[cfg(feature = "pilot")]
async fn hosted_negotiate_propose(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateProposeRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let (conv_id_hex, conversation_id) = match req.conversation_id {
        Some(ref s) => match hex::decode(s).ok().and_then(|b| b.try_into().ok()) {
            Some(a) => (s.clone(), a),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                    ),
                )
            }
        },
        None => {
            let b = rand::Rng::gen::<[u8; 16]>(&mut OsRng);
            (hex::encode(b), b)
        }
    };
    if req.message.len() > zerox1_protocol::constants::MAX_MESSAGE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "message exceeds maximum size" })),
        );
    }
    let amount = req.amount_usdc_micro.unwrap_or(0);
    let max_rounds = req.max_rounds.unwrap_or(2);
    let mut hosted_propose_extra = serde_json::json!({
        "max_rounds": max_rounds,
        "message": req.message,
    });
    if let Some(ref mint) = req.token_mint {
        hosted_propose_extra["token_mint"] = serde_json::Value::String(mint.clone());
    }
    if let Some(ref tx) = req.payment_tx {
        hosted_propose_extra["payment_tx"] = serde_json::Value::String(tx.clone());
    }
    if let Some(usd) = req.payment_usd_micro {
        hosted_propose_extra["payment_usd_micro"] = serde_json::Value::Number(usd.into());
    }
    if let Some(total) = req.total_price_usd_micro {
        hosted_propose_extra["total_price_usd_micro"] = serde_json::Value::Number(total.into());
    }
    let payload = build_negotiate_payload(amount, hosted_propose_extra);
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        if session.sends_in_window >= MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        session.sends_in_window += 1;
        session.nonce += 1;
        Envelope::build(
            MsgType::Propose,
            session.agent_id,
            recipient,
            state.get_current_slot(),
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
    (
        StatusCode::OK,
        Json(serde_json::json!({ "conversation_id": conv_id_hex })),
    )
}

/// POST /hosted/negotiate/counter — `Authorization: Bearer <token>`.
#[cfg(feature = "pilot")]
async fn hosted_negotiate_counter(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateCounterRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };
    if req.message.as_deref().map_or(false, |m| m.len() > zerox1_protocol::constants::MAX_MESSAGE_SIZE) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "message exceeds maximum size" })),
        );
    }
    let max_rounds = req.max_rounds.unwrap_or(2);
    if req.round == 0 || req.round > max_rounds {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("round {} is out of range [1, {}]", req.round, max_rounds)
            })),
        );
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let mut hosted_counter_extra = serde_json::json!({
        "round": req.round,
        "max_rounds": max_rounds,
        "message": req.message.unwrap_or_default(),
    });
    if let Some(ref mint) = req.token_mint {
        hosted_counter_extra["token_mint"] = serde_json::Value::String(mint.clone());
    }
    let payload = build_negotiate_payload(req.amount_usdc_micro, hosted_counter_extra);
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        if session.sends_in_window >= MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        session.sends_in_window += 1;
        session.nonce += 1;
        Envelope::build(
            MsgType::Counter,
            session.agent_id,
            recipient,
            state.get_current_slot(),
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

/// POST /hosted/negotiate/accept — `Authorization: Bearer <token>`.
#[cfg(feature = "pilot")]
async fn hosted_negotiate_accept(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<NegotiateAcceptRequest>,
) -> impl IntoResponse {
    let token = match resolve_hosted_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
        }
    };
    if req.message.as_deref().map_or(false, |m| m.len() > zerox1_protocol::constants::MAX_MESSAGE_SIZE) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "message exceeds maximum size" })),
        );
    }
    let recipient: [u8; 32] = match hex::decode(&req.recipient)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "recipient: invalid hex or not 32 bytes" })),
            )
        }
    };
    let conversation_id: [u8; 16] = match hex::decode(&req.conversation_id)
        .ok()
        .and_then(|b| b.try_into().ok())
    {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "conversation_id: invalid hex or not 16 bytes" }),
                ),
            )
        }
    };
    let mut hosted_accept_extra = serde_json::json!({ "message": req.message.unwrap_or_default() });
    if let Some(ref mint) = req.token_mint {
        hosted_accept_extra["token_mint"] = serde_json::Value::String(mint.clone());
    }
    if let Some(dp) = req.downpayment_usd_micro {
        hosted_accept_extra["downpayment_usd_micro"] = serde_json::Value::Number(dp.into());
    }
    if let Some(rem) = req.remaining_usd_micro {
        hosted_accept_extra["remaining_usd_micro"] = serde_json::Value::Number(rem.into());
    }
    let payload = build_negotiate_payload(req.amount_usdc_micro, hosted_accept_extra);
    let env = {
        let now = now_secs();
        let mut sessions = state.0.hosted_sessions.write().await;
        let session = match sessions.get_mut(&token) {
            Some(s) => s,
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
            }
        };
        if now.saturating_sub(session.created_at) >= SESSION_TTL_SECS {
            sessions.remove(&token);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "session expired" })),
            );
        }
        if now.saturating_sub(session.rate_window_start) >= 60 {
            session.rate_window_start = now;
            session.sends_in_window = 0;
        }
        if session.sends_in_window >= MAX_SENDS_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded" })),
            );
        }
        session.sends_in_window += 1;
        session.nonce += 1;
        Envelope::build(
            MsgType::Accept,
            session.agent_id,
            recipient,
            state.get_current_slot(),
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
#[cfg(feature = "pilot")]
async fn ws_hosted_inbox_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    Query(q): Query<HostedInboxQuery>,
    State(state): State<ApiState>,
) -> Response {
    let token = resolve_hosted_token(&headers).or_else(|| {
        if q.token.is_some() {
            tracing::warn!(
                "WS /ws/hosted/inbox: token passed via query param (deprecated). \
                     Use Authorization: Bearer header instead."
            );
        }
        q.token.clone()
    });

    let t = match token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "missing Bearer token" })),
            )
                .into_response()
        }
    };

    // MPP payment gate removed along with the Solana strip.

    ws.on_upgrade(|socket| ws_hosted_inbox_task(socket, state, t))
        .into_response()
}

#[cfg(feature = "pilot")]
async fn ws_hosted_inbox_task(mut socket: WebSocket, state: ApiState, token: String) {
    // Resolve session to get agent_id for filtering; reject expired tokens.
    let agent_id_hex = {
        let sessions = state.0.hosted_sessions.read().await;
        match sessions.get(&token) {
            Some(s) => {
                if now_secs().saturating_sub(s.created_at) >= SESSION_TTL_SECS {
                    let _ = socket
                        .send(Message::Text(r#"{"error":"session expired"}"#.into()))
                        .await;
                    return;
                }
                hex::encode(s.agent_id)
            }
            None => {
                let _ = socket
                    .send(Message::Text(r#"{"error":"invalid token"}"#.into()))
                    .await;
                return;
            }
        }
    };

    let mut rx = state.0.inbox_tx.subscribe();
    loop {
        // Re-check TTL on each loop to avoid long-lived sockets after expiry.
        {
            let sessions = state.0.hosted_sessions.read().await;
            match sessions.get(&token) {
                Some(s) if now_secs().saturating_sub(s.created_at) < SESSION_TTL_SECS => {}
                _ => {
                    let _ = socket
                        .send(Message::Text(r#"{"error":"session expired"}"#.into()))
                        .await;
                    break;
                }
            }
        }
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
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_msg_type(s: &str) -> Option<MsgType> {
    match s.to_uppercase().as_str() {
        "ADVERTISE" => Some(MsgType::Advertise),
        "DISCOVER" => Some(MsgType::Discover),
        "PROPOSE" => Some(MsgType::Propose),
        "COUNTER" => Some(MsgType::Counter),
        "ACCEPT" => Some(MsgType::Accept),
        "REJECT" => Some(MsgType::Reject),
        "DELIVER" => Some(MsgType::Deliver),
        "NOTARIZE_BID" => Some(MsgType::NotarizeBid),
        "NOTARIZE_ASSIGN" => Some(MsgType::NotarizeAssign),
        "VERDICT" => Some(MsgType::Verdict),
        "FEEDBACK" => Some(MsgType::Feedback),
        "DISPUTE" => Some(MsgType::Dispute),
        "BROADCAST" => Some(MsgType::Broadcast),
        _ => None,
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    // Compare in constant time — no early return on length mismatch.
    // Use usize accumulator so length XOR never truncates (u8 would wrap at 256).
    let a = a.as_bytes();
    let b = b.as_bytes();
    let len = a.len().max(b.len());
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

pub(crate) fn require_api_secret_or_unauthorized(
    state: &ApiState,
    headers: &HeaderMap,
) -> Option<Response> {
    let has_read_keys = !state.0.api_read_keys.is_empty();
    if let Some(ref secret) = state.0.api_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, secret.as_str()) {
            return Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "unauthorized" })),
                )
                    .into_response(),
            );
        }
        return None;
    }

    if has_read_keys {
        // Operator intended to secure the node but forgot the master secret.
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(
                    serde_json::json!({ "error": "unauthorized: mutating endpoints require api_secret" }),
                ),
            )
                .into_response(),
        );
    }
    None
}

/// Like `require_api_secret_or_unauthorized` but ALSO accepts any read-only key
/// from `--api-read-keys`. Used for GET/WS visualization endpoints that the
/// explorer team needs without granting write access.
fn require_read_or_master_access(state: &ApiState, headers: &HeaderMap) -> Option<Response> {
    // If no master secret is configured, all endpoints are open (dev mode).
    let has_master = state.0.api_secret.is_some();
    let has_read_keys = !state.0.api_read_keys.is_empty();
    if !has_master && !has_read_keys {
        return None;
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    // Check master key first.
    if let Some(ref secret) = state.0.api_secret {
        if ct_eq(provided, secret.as_str()) {
            return None; // master key — full access
        }
    }

    // Check read-only keys.
    for key in &state.0.api_read_keys {
        if ct_eq(provided, key.as_str()) {
            return None; // valid read key
        }
    }

    Some(
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response(),
    )
}

/// WS variant: extract token from `Authorization` header OR `?token=` query param,
/// then check read-only OR master key.
fn require_read_or_master_ws(
    state: &ApiState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Option<Response> {
    let has_master = state.0.api_secret.is_some();
    let has_read_keys = !state.0.api_read_keys.is_empty();
    if !has_master && !has_read_keys {
        return None;
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| params.get("token").map(|s| s.as_str()))
        .unwrap_or("");

    if let Some(ref secret) = state.0.api_secret {
        if ct_eq(provided, secret.as_str()) {
            return None;
        }
    }
    for key in &state.0.api_read_keys {
        if ct_eq(provided, key.as_str()) {
            return None;
        }
    }

    Some(StatusCode::UNAUTHORIZED.into_response())
}

/// Extract the Bearer token from an `Authorization: Bearer <token>` header.
pub(crate) fn resolve_hosted_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

#[cfg(feature = "trade")]
pub(crate) async fn resolve_active_hosted_signing_key(
    state: &ApiState,
    token: &str,
) -> Option<SigningKey> {
    let now = now_secs();
    let mut sessions = state.0.hosted_sessions.write().await;
    match sessions.get(token) {
        Some(session) if now.saturating_sub(session.created_at) < SESSION_TTL_SECS => {
            Some(session.signing_key.clone())
        }
        Some(_) => {
            sessions.remove(token);
            None
        }
        None => None,
    }
}


// ============================================================================
// Admin — exempt agent management
//
// All three routes require the master api_secret (Authorization: Bearer <secret>).
// They are registered on the same local API server (127.0.0.1:9090 by default),
// so they are only reachable by someone with SSH access to the host.
//
// Usage (from GCP instance or via ssh -L tunnel):
//   # Add Guardian NPC
//   curl -X POST http://127.0.0.1:9090/admin/exempt \
//        -H 'Authorization: Bearer <api_secret>' \
//        -H 'Content-Type: application/json' \
//        -d '{"agent_id":"<64-hex-char-agent-id>"}'
//
//   # List current exemptions
//   curl -H 'Authorization: Bearer <api_secret>' http://127.0.0.1:9090/admin/exempt
//
//   # Remove an exemption
//   curl -X DELETE -H 'Authorization: Bearer <api_secret>' \
//        http://127.0.0.1:9090/admin/exempt/<64-hex-char-agent-id>
//
// Changes are persisted to log_dir/exempt_agents.json and survive node restarts.
// ============================================================================

#[cfg(feature = "pilot")]
fn save_exempt_agents(path: &std::path::Path, set: &HashSet<[u8; 32]>) {
    let ids: Vec<String> = set.iter().map(hex::encode).collect();
    match serde_json::to_string(&ids) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, &json) {
                tracing::warn!("Failed to persist exempt_agents to {:?}: {e}", path);
            }
        }
        Err(e) => tracing::warn!("Failed to serialize exempt_agents: {e}"),
    }
}

/// GET /admin/exempt — list all currently exempt agent IDs.
#[cfg(feature = "pilot")]
async fn admin_exempt_list(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let set = state.0.exempt_agents.read().unwrap();
    let ids: Vec<String> = set.iter().map(hex::encode).collect();
    Json(serde_json::json!({ "exempt_agents": ids, "count": ids.len() })).into_response()
}

/// POST /admin/exempt — add an agent ID to the exempt set.
/// Body: `{ "agent_id": "<64-hex-char-id>" }`
#[cfg(feature = "pilot")]
async fn admin_exempt_add(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let Some(hex_str) = body.get("agent_id").and_then(|v| v.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_id required" })),
        )
            .into_response();
    };
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid hex" })),
            )
                .into_response()
        }
    };
    let arr: [u8; 32] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "agent_id must be 32 bytes (64 hex chars)" })),
            )
                .into_response()
        }
    };
    {
        let mut set = state.0.exempt_agents.write().unwrap();
        set.insert(arr);
        save_exempt_agents(&state.0.exempt_persist_path, &set);
    }
    tracing::info!("Admin: added exempt agent {hex_str}");
    Json(serde_json::json!({ "ok": true, "agent_id": hex_str })).into_response()
}

/// DELETE /admin/exempt/{agent_id} — remove an agent ID from the exempt set.
#[cfg(feature = "pilot")]
async fn admin_exempt_remove(
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let bytes = match hex::decode(&agent_id) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid hex" })),
            )
                .into_response()
        }
    };
    let arr: [u8; 32] = match bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "agent_id must be 32 bytes (64 hex chars)" })),
            )
                .into_response()
        }
    };
    {
        let mut set = state.0.exempt_agents.write().unwrap();
        set.remove(&arr);
        save_exempt_agents(&state.0.exempt_persist_path, &set);
    }
    tracing::info!("Admin: removed exempt agent {agent_id}");
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn portfolio_history(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let history = state.0.portfolio_history.read().await;
    Json(history.clone()).into_response()
}

#[derive(Serialize)]
pub struct TokenBalance {
    pub mint: String,
    pub amount: f64,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct PortfolioBalances {
    pub tokens: Vec<TokenBalance>,
}



// ============================================================================
// Agent process management — skill hot-reload
// ============================================================================

#[cfg(feature = "pilot")]
const MAX_AGENT_RELOAD_PER_MINUTE: u32 = 3;

#[cfg(feature = "pilot")]
#[derive(Deserialize)]
struct RegisterPidRequest {
    pid: u32,
}

/// Return the real UID of `pid` by reading /proc/{pid}/status.
/// Returns `None` if the file cannot be read or parsed.
#[cfg(all(feature = "pilot", unix))]
fn proc_uid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Format: "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// POST /agent/register-pid — called by NodeService after starting zeroclaw.
///
/// Requires auth (same as other mutating endpoints). Validates that the given
/// PID belongs to a user-space process owned by the same UID as the node to
/// prevent an attacker from registering arbitrary system PIDs.
#[cfg(feature = "pilot")]
async fn agent_register_pid(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterPidRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Reject system PIDs and kernel threads — user processes start at 1024+.
    if req.pid < 1024 || req.pid > 4_194_304 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "pid out of user-space range"})),
        )
            .into_response();
    }

    // Verify the PID belongs to the same UID as the current process.
    // Prevents an attacker from registering a PID they don't own.
    #[cfg(unix)]
    {
        let our_uid = unsafe { libc::getuid() };
        match proc_uid(req.pid) {
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "process not found or not readable"})),
                )
                    .into_response()
            }
            Some(pid_uid) if pid_uid != our_uid => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "pid belongs to a different user"})),
                )
                    .into_response()
            }
            _ => {}
        }
    }

    *state.0.agent_pid.lock().await = Some(req.pid);
    tracing::info!("Agent PID registered: {}", req.pid);
    Json(serde_json::json!({"ok": true})).into_response()
}

/// POST /agent/reload — signal zeroclaw to restart so it picks up new skills.
///
/// Sends SIGTERM to the registered zeroclaw PID. NodeService's restart loop
/// automatically re-launches zeroclaw, which re-reads all SKILL.toml files.
/// Rate-limited to 3 reloads per minute to prevent DoS via reload loop.
#[cfg(feature = "pilot")]
async fn agent_reload(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Rate limit: max 3 reloads per minute.
    {
        let mut rl = state.0.agent_reload_rate_limit.lock().await;
        let now = now_secs();
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_AGENT_RELOAD_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "reload rate limit exceeded (max 3/min)"})),
            )
                .into_response();
        }
        rl.count += 1;
    }

    let pid = *state.0.agent_pid.lock().await;
    match pid {
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "No agent PID registered — is zeroclaw running?"})),
        )
            .into_response(),
        Some(pid) => {
            // SIGTERM — zeroclaw exits gracefully, NodeService auto-restarts it.
            // kill(2) is Unix-only; on Windows the skill manager cannot be used
            // (zeroclaw only runs on Android/Linux), so return a clear error.
            #[cfg(unix)]
            {
                let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                if result == 0 {
                    tracing::info!("Sent SIGTERM to agent PID {pid} for skill reload");
                    Json(serde_json::json!({"ok": true, "pid": pid})).into_response()
                } else {
                    let err = std::io::Error::last_os_error();
                    tracing::warn!("Failed to send SIGTERM to agent PID {pid}: {err}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("kill({pid}): {err}")})),
                    )
                        .into_response()
                }
            }
            #[cfg(not(unix))]
            {
                let _ = pid;
                (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(
                        serde_json::json!({"error": "agent reload not supported on this platform"}),
                    ),
                )
                    .into_response()
            }
        }
    }
}

// ============================================================================
// Skill manager REST endpoints — safe Rust-side file operations
// ============================================================================

/// Validate a skill name: lowercase alphanumeric + hyphens + underscores,
/// no path separators, no leading hyphens, 1–64 chars.
const RESERVED_SKILL_NAMES: &[&str] = &[
    "bags", "trade", "launchlab", "cpmm",
    "health", "skill_manager", "web", "phone-ui",
];

fn validate_skill_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 64 {
        return Err("skill name must be 1–64 chars");
    }
    if name.starts_with('-') || name.starts_with('_') {
        return Err("skill name must start with a letter or digit");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("skill name may only contain lowercase letters, digits, hyphens, underscores");
    }
    if RESERVED_SKILL_NAMES.contains(&name) {
        return Err("reserved skill name — cannot be overwritten via the API");
    }
    Ok(())
}

/// Check that `path` is strictly inside `base` (no path traversal).
fn is_inside(path: &std::path::Path, base: &std::path::Path) -> bool {
    // Both paths must be canonicalized by the caller.
    path.starts_with(base)
}

macro_rules! skill_workspace {
    ($state:expr) => {
        match $state.0.skill_workspace.as_ref() {
            Some(w) => w,
            None => return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "skill workspace not configured (--skill-workspace)"})),
            ).into_response(),
        }
    };
}

// ── Agent memory / persona endpoints ─────────────────────────────────────────

/// Maximum size for MEMORY.md and PERSONA.md writes (32 KiB).
const MAX_MEMORY_FILE_BYTES: usize = 32 * 1024;

/// GET /agent/memory — read MEMORY.md from the skill workspace.
async fn agent_memory_read(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let workspace = skill_workspace!(state);
    let path = workspace.join("MEMORY.md");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Json(serde_json::json!({ "content": content })).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Json(serde_json::json!({ "content": "" })).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to read MEMORY.md" })),
        )
            .into_response(),
    }
}

/// POST /agent/memory/write — overwrite MEMORY.md with new content.
/// Body: `{ "content": "..." }`
async fn agent_memory_write(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let workspace = skill_workspace!(state);
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing content field" })),
            )
                .into_response()
        }
    };
    if content.len() > MAX_MEMORY_FILE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "content exceeds 32 KiB limit" })),
        )
            .into_response();
    }
    let path = workspace.join("MEMORY.md");
    match tokio::fs::write(&path, &content).await {
        Ok(_) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to write MEMORY.md" })),
        )
            .into_response(),
    }
}

/// GET /agent/persona — read PERSONA.md from the skill workspace.
async fn agent_persona_read(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let workspace = skill_workspace!(state);
    let path = workspace.join("PERSONA.md");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Json(serde_json::json!({ "content": content })).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Json(serde_json::json!({ "content": "" })).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to read PERSONA.md" })),
        )
            .into_response(),
    }
}

/// POST /agent/persona/write — overwrite PERSONA.md with new content.
/// Body: `{ "content": "..." }`
async fn agent_persona_write(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let workspace = skill_workspace!(state);
    let content = match body.get("content").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing content field" })),
            )
                .into_response()
        }
    };
    if content.len() > MAX_MEMORY_FILE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "content exceeds 32 KiB limit" })),
        )
            .into_response();
    }
    let path = workspace.join("PERSONA.md");
    match tokio::fs::write(&path, &content).await {
        Ok(_) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to write PERSONA.md" })),
        )
            .into_response(),
    }
}

/// GET /agent/conversation/export — export recent conversation history for podcast production.
///
/// Reads conversation-category memory entries from the zeroclaw gateway's memory API.
/// Falls back to an empty transcript if the gateway is unreachable or has no history.
///
/// Response: `{ "messages": [{ "role": "user"|"assistant", "text": "...", "ts": unix_ms }] }`
async fn agent_conversation_export(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }

    // Try the zeroclaw gateway memory API first (conversation category).
    // The gateway runs on 127.0.0.1:9093 (iOS) or 127.0.0.1:42617 (Android).
    let gateway_ports = [9093u16, 42617];
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    for port in gateway_ports {
        let url = format!(
            "http://127.0.0.1:{}/api/memory?category=conversation&limit=200",
            port
        );
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    // Transform memory entries into podcast-friendly transcript format.
                    let messages: Vec<serde_json::Value> = data["entries"]
                        .as_array()
                        .unwrap_or(&vec![])
                        .iter()
                        .filter_map(|entry| {
                            let value = entry.get("value")?.as_str()?;
                            let key = entry.get("key")?.as_str().unwrap_or("");
                            let role = if key.contains("user") || key.contains("human") {
                                "user"
                            } else {
                                "assistant"
                            };
                            Some(serde_json::json!({
                                "role": role,
                                "text": value,
                                "ts": entry.get("timestamp").and_then(|t| t.as_i64()).unwrap_or(0),
                            }))
                        })
                        .collect();

                    return Json(serde_json::json!({ "messages": messages })).into_response();
                }
            }
        }
    }

    // Fallback: return empty transcript — agent can still produce from its in-memory context.
    Json(serde_json::json!({ "messages": [] })).into_response()
}

/// POST /podcast/produce-local — concatenate audio segments on-device into a single MP3.
///
/// Body: `{ "title": "...", "transcript": [{ "role": "user", "audio_uri": "/path/to/file.m4a" }, ...] }`
///
/// Reads local audio files from the transcript, concatenates them using raw byte append
/// (works for same-format files) or FFmpeg if available, and saves the result to the
/// skill workspace. Returns the local file path.
async fn podcast_produce_local(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    let workspace = skill_workspace!(state);
    let title = body["title"].as_str().unwrap_or("Episode");

    // Collect audio file paths from transcript
    let mut audio_paths: Vec<std::path::PathBuf> = Vec::new();
    if let Some(messages) = body["transcript"].as_array() {
        for msg in messages {
            let uri = msg["audio_uri"]
                .as_str()
                .or_else(|| msg["audioUri"].as_str())
                .unwrap_or("");
            if uri.is_empty() {
                continue;
            }
            // Strip file:// prefix if present
            let path_str = uri.strip_prefix("file://").unwrap_or(uri);
            let path = std::path::PathBuf::from(path_str);
            if path.exists() {
                audio_paths.push(path);
            }
        }
    }

    if audio_paths.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No audio files found in transcript. Record voice messages first."
            })),
        )
            .into_response();
    }

    // Generate episode ID and output path
    let episode_id = format!("{:016x}", rand::random::<u64>());
    let podcast_dir = workspace.join("podcasts");
    let _ = std::fs::create_dir_all(&podcast_dir);
    let output_path = podcast_dir.join(format!("{}_{}.mp3", episode_id, sanitize_filename(title)));

    // Try FFmpeg concat first (best quality — handles format conversion)
    let ffmpeg_success = try_ffmpeg_concat(&audio_paths, &output_path).await;

    if !ffmpeg_success {
        // Fallback: raw byte concatenation (works for same-format files like m4a/mp4)
        let mut output = Vec::new();
        for path in &audio_paths {
            if let Ok(bytes) = tokio::fs::read(path).await {
                output.extend_from_slice(&bytes);
            }
        }
        if output.is_empty() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to read audio files"})),
            )
                .into_response();
        }
        if let Err(e) = tokio::fs::write(&output_path, &output).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to write output: {e}")})),
            )
                .into_response();
        }
    }

    // Get file size to estimate duration (rough: 128kbps = 16KB/sec)
    let file_size = tokio::fs::metadata(&output_path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    let duration_secs = file_size / 16_000;

    let file_uri = format!("file://{}", output_path.display());

    Json(serde_json::json!({
        "episode_id": episode_id,
        "title": title,
        "audio_url": file_uri,
        "duration_secs": duration_secs,
        "segments_count": audio_paths.len(),
    }))
    .into_response()
}

/// Try to concat audio files using FFmpeg. Returns true on success.
async fn try_ffmpeg_concat(
    inputs: &[std::path::PathBuf],
    output: &std::path::Path,
) -> bool {
    // Build concat list file
    let concat_dir = output.parent().unwrap_or(std::path::Path::new("/tmp"));
    let list_path = concat_dir.join(".concat_list.txt");
    let list_content: String = inputs
        .iter()
        .map(|p| format!("file '{}'\n", p.display()))
        .collect();

    if tokio::fs::write(&list_path, &list_content).await.is_err() {
        return false;
    }

    let result = tokio::process::Command::new("ffmpeg")
        .args([
            "-y",
            "-f", "concat",
            "-safe", "0",
            "-i", list_path.to_str().unwrap_or(""),
            "-c:a", "libmp3lame",
            "-b:a", "128k",
            "-ar", "44100",
            output.to_str().unwrap_or(""),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    let _ = tokio::fs::remove_file(&list_path).await;

    matches!(result, Ok(status) if status.success())
}

/// Sanitize a string for use as a filename (remove special chars, limit length).
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == ' ')
        .take(40)
        .collect::<String>()
        .trim()
        .replace(' ', "_")
}

/// GET /agent/profile — read operator onboarding profile (profile.json in log_dir).
async fn agent_profile_read(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let log_dir = match state.0.exempt_persist_path.parent() {
        Some(p) => p.to_path_buf(),
        None => return Json(serde_json::json!({})).into_response(),
    };
    let path = log_dir.join("profile.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(v)  => Json(v).into_response(),
            Err(_) => Json(serde_json::json!({})).into_response(),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Json(serde_json::json!({})).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to read profile" })),
        ).into_response(),
    }
}

/// POST /agent/profile — write operator onboarding profile (profile.json in log_dir).
/// Body: `{ "motivation": "...", "use_cases": [...], "referral": "..." }`
async fn agent_profile_write(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let log_dir = match state.0.exempt_persist_path.parent() {
        Some(p) => p.to_path_buf(),
        None => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "log_dir unavailable" })),
        ).into_response(),
    };
    let path = log_dir.join("profile.json");
    let content = serde_json::to_string_pretty(&body).unwrap_or_default();
    if content.len() > 4096 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "profile exceeds 4 KB limit" })),
        ).into_response();
    }
    match tokio::fs::write(&path, content).await {
        Ok(_)  => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "failed to write profile" })),
        ).into_response(),
    }
}

/// GET /skill/list — list installed skill names.
async fn skill_list_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let workspace = skill_workspace!(state);
    let skills_dir = workspace.join("skills");
    let mut skills: Vec<String> = Vec::new();
    match tokio::fs::read_dir(&skills_dir).await {
        Ok(mut dir) => {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Ok(ft) = entry.file_type().await {
                    if ft.is_dir() {
                        skills.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
            }
        }
        Err(_) => { /* directory doesn't exist yet — empty list */ }
    }
    skills.sort();
    Json(serde_json::json!({"skills": skills})).into_response()
}

#[derive(Deserialize)]
struct SkillWriteRequest {
    name: String,
    /// Base64-encoded SKILL.toml content.
    content_b64: String,
}

/// POST /skill/write — install a new skill by writing its SKILL.toml.
///
/// `content_b64` must be the base64-encoded UTF-8 SKILL.toml. The name is
/// validated before any filesystem operation — no path traversal possible.
async fn skill_write_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SkillWriteRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if let Err(e) = validate_skill_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }
    let workspace = skill_workspace!(state);

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let content_bytes = match B64.decode(&req.content_b64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "content_b64 is not valid base64"})),
            )
                .into_response()
        }
    };
    if content_bytes.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "decoded content is empty"})),
        )
            .into_response();
    }
    let content_str = match String::from_utf8(content_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "content is not valid UTF-8"})),
            )
                .into_response()
        }
    };

    let skill_dir = workspace.join("skills").join(&req.name);
    if let Err(e) = tokio::fs::create_dir_all(&skill_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("mkdir: {e}")})),
        )
            .into_response();
    }
    let toml_path = skill_dir.join("SKILL.toml");
    if let Err(e) = tokio::fs::write(&toml_path, &content_str).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write: {e}")})),
        )
            .into_response();
    }
    tracing::info!("Skill '{}' written ({} bytes)", req.name, content_str.len());
    Json(serde_json::json!({"ok": true, "name": req.name})).into_response()
}

#[derive(Deserialize)]
struct SkillInstallUrlRequest {
    name: String,
    url: String,
}

fn is_private_ipv4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
}

/// Reject private/loopback IP ranges used in SSRF attacks.
fn is_private_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => is_private_ipv4(v4),
            std::net::IpAddr::V6(v6) => {
                let segs = v6.segments();
                let is_link_local = (segs[0] & 0xffc0) == 0xfe80; // fe80::/10
                let is_unique_local = (segs[0] & 0xfe00) == 0xfc00; // fc00::/7
                v6.is_loopback()
                    || v6.is_unspecified()
                    || is_link_local
                    || is_unique_local
                    || v6.to_ipv4_mapped().map(is_private_ipv4).unwrap_or(false)
            }
        };
    }
    false
}

/// POST /skill/install-url — fetch a SKILL.toml from an HTTPS URL and install it.
///
/// Only HTTPS is accepted. Private/loopback hosts are rejected to prevent SSRF.
/// The content size is capped at 128 KiB.
async fn skill_install_url_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SkillInstallUrlRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if let Err(e) = validate_skill_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }

    // Parse and validate URL.
    let parsed = match req.url.parse::<url::Url>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid URL"})),
            )
                .into_response()
        }
    };
    if parsed.scheme() != "https" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "only HTTPS URLs are accepted"})),
        )
            .into_response();
    }
    if let Some(host) = parsed.host_str() {
        if is_private_host(host) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "private/loopback hosts are not allowed"})),
            )
                .into_response();
        }
    }

    let workspace = skill_workspace!(state);

    // Fetch content via the shared HTTP client (safe, no shell involved).
    let resp = match state
        .0
        .http_client
        .get(parsed)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("fetch failed: {e}")})),
            )
                .into_response()
        }
    };
    if !resp.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("remote returned {}", resp.status())})),
        )
            .into_response();
    }

    const MAX_SKILL_BYTES: usize = 128 * 1024; // 128 KiB
    let content = match resp.text().await {
        Ok(t) if t.len() <= MAX_SKILL_BYTES => t,
        Ok(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({"error": "SKILL.toml exceeds 128 KiB limit"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("read body: {e}")})),
            )
                .into_response()
        }
    };

    let skill_dir = workspace.join("skills").join(&req.name);
    if let Err(e) = tokio::fs::create_dir_all(&skill_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("mkdir: {e}")})),
        )
            .into_response();
    }
    if let Err(e) = tokio::fs::write(skill_dir.join("SKILL.toml"), &content).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write: {e}")})),
        )
            .into_response();
    }
    tracing::info!(
        "Skill '{}' installed from URL ({} bytes)",
        req.name,
        content.len()
    );
    Json(serde_json::json!({"ok": true, "name": req.name, "bytes": content.len()})).into_response()
}

#[derive(Deserialize)]
struct SkillRemoveRequest {
    name: String,
}

/// POST /skill/remove — remove an installed skill by name.
///
/// The skill name is validated (no path traversal). The resulting path is
/// verified to be inside the skills directory before deletion.
async fn skill_remove_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SkillRemoveRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if let Err(e) = validate_skill_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }
    let workspace = skill_workspace!(state);
    let skills_root = workspace.join("skills");
    let skill_dir = skills_root.join(&req.name);

    // Canonicalize both paths and verify containment — belt-and-suspenders against symlinks.
    let canonical_root = match skills_root.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "skills directory does not exist"})),
            )
                .into_response()
        }
    };
    let canonical_skill = match skill_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("skill '{}' not found", req.name)})),
            )
                .into_response()
        }
    };
    if !is_inside(&canonical_skill, &canonical_root) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "path traversal detected"})),
        )
            .into_response();
    }

    if let Err(e) = tokio::fs::remove_dir_all(&skill_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("remove: {e}")})),
        )
            .into_response();
    }
    tracing::info!("Skill '{}' removed", req.name);
    Json(serde_json::json!({"ok": true, "name": req.name})).into_response()
}

// ============================================================================
// Task audit log handlers — POST /tasks/log, GET /tasks/log,
//   PATCH /tasks/log/{id}/shared, DELETE /tasks/log/{id}
// ============================================================================

/// Helper: return 503 if task log is not configured.
macro_rules! task_log {
    ($state:expr) => {
        match &$state.0.task_log {
            Some(tl) => tl.clone(),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"error": "task log not configured (--task-log-path)"})),
                )
                    .into_response()
            }
        }
    };
}

/// POST /tasks/log — zeroclaw writes a new task entry.
/// Requires api_secret.
/// Body: NewTaskLogEntry JSON.
async fn task_log_insert(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<crate::task_log::NewTaskLogEntry>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let tl = task_log!(state);
    match tl.insert(&req) {
        Ok(id) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TaskLogListQuery {
    #[serde(default = "default_task_limit")]
    limit: u32,
    before_id: Option<i64>,
}

fn default_task_limit() -> u32 {
    50
}

/// GET /tasks/log?limit=50&before_id=X — mobile reads the task log.
/// Requires read or master auth.
async fn task_log_list(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Query(q): Query<TaskLogListQuery>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let tl = task_log!(state);
    let limit = q.limit.min(200);
    match tl.list(limit, q.before_id) {
        Ok(entries) => Json(entries).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

/// PATCH /tasks/log/{id}/shared — mark an entry as posted to socials.
/// Requires read or master auth.
async fn task_log_mark_shared(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let tl = task_log!(state);
    match tl.mark_shared(id) {
        Ok(true) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "entry not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

/// DELETE /tasks/log/{id} — owner privacy control.
/// Requires api_secret (master only — this is a destructive action).
async fn task_log_delete(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let tl = task_log!(state);
    match tl.delete(id) {
        Ok(true) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "entry not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

// ── LLM proxy relay ───────────────────────────────────────────────────────────
//
// Zeroclaw with `default_provider = "custom:http://127.0.0.1:9090"` calls
// `POST http://127.0.0.1:9090/chat/completions` with a standard OpenAI-compat
// body.  This handler injects the node's agent_id and forwards to the
// aggregator's `/llm/chat` endpoint, which gates access by Bags.fm token
// trading history and 01PL balance.
//
// Authentication: loopback-only (bound to 127.0.0.1); no secret needed because
// only zeroclaw running on this device can reach port 9090 from localhost.

#[cfg(feature = "pilot")]
async fn chat_completions_relay(
    State(state): State<ApiState>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    let Some(base) = state.0.llm_proxy_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "LLM proxy not configured — set aggregator URL to enable default provider"})),
        )
            .into_response();
    };

    // Inject this node's agent_id so the aggregator can gate access.
    let agent_id = hex::encode(state.0.self_agent);
    body["agent_id"] = serde_json::json!(agent_id);

    let url = format!("{}/llm/chat", base.trim_end_matches('/'));
    match state
        .0
        .http_client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status();
            let resp_body: serde_json::Value = r
                .json()
                .await
                .unwrap_or_else(|_| serde_json::json!({"error": "upstream response invalid"}));
            (
                StatusCode::from_u16(status.as_u16())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(resp_body),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!("chat_completions_relay: aggregator request failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "upstream request failed"})),
            )
                .into_response()
        }
    }
}

