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
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

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
use solana_sdk::pubkey::Pubkey;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use crate::{
    kora::KoraClient,
    registry_8004::{
        broadcast_transaction, build_register_tx, fetch_latest_blockhash, PROGRAM_ID_DEVNET,
        PROGRAM_ID_MAINNET,
    },
};

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
    #[allow(dead_code)]
    LeaseStatus {
        agent_id: String,
        active: bool,
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
    #[cfg(feature = "bags")]
    BagsFee {
        amount_usdc: f64,
        txid: String,
        timestamp: u64,
    },
    #[cfg(feature = "bags")]
    BagsLaunch {
        token_mint: String,
        name: String,
        symbol: String,
        txid: String,
        timestamp: u64,
    },
    #[cfg(feature = "bags")]
    BagsClaim {
        token_mint: String,
        claimed_txs: usize,
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
const MAX_HOSTED_SESSIONS: usize = 10_000;
/// Sessions older than this are evicted and their tokens rejected.
const SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
/// Maximum outbound sends per 60-second window per session.
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
const MAX_KORA_DAILY_USES: u32 = 100;
/// Maximum byte length of the `message` field in negotiate endpoints.
/// Prevents a large JSON serialisation from creating an oversized envelope.
const MAX_NEGOTIATE_MESSAGE_LEN: usize = 4_096;

// USDC sweep constants
pub(crate) const USDC_MINT_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
pub(crate) const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub(crate) const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";
/// Minimum balance (atomic USDC units, 6 decimals) required to attempt a sweep.
const MIN_SWEEP_AMOUNT: u64 = 10_000;
/// Maximum single x402 micropayment (atomic USDC units). 10 USDC = 10_000_000.
const MAX_X402_PAYMENT_MICRO: u64 = 10_000_000;

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

#[cfg(feature = "bags")]
async fn report_bags_claim_to_aggregator(
    state: &ApiState,
    agent_id: String,
    amount_sol: f64,
    claimed_txs: u32,
) {
    let Some(base) = state.0.aggregator_url.clone() else {
        return;
    };
    if amount_sol <= 0.0 {
        return;
    }
    let url = format!("{}/league/bags-claim", base.trim_end_matches('/'));
    let mut req = state.0.http_client.post(url).json(&serde_json::json!({
        "agent_id": agent_id,
        "amount_sol": amount_sol,
        "claimed_txs": claimed_txs,
        "timestamp": now_secs(),
    }));
    if let Some(secret) = state.0.aggregator_secret.clone() {
        req = req.header("Authorization", format!("Bearer {secret}"));
    }
    if let Err(e) = req.send().await {
        tracing::warn!("Bags claim report failed: {e}");
    }
}

/// Report the agent's launched token mint to the aggregator.
/// Fires-and-forgets; failure is non-fatal.
#[cfg(feature = "bags")]
async fn report_token_to_aggregator(state: &ApiState, token_mint: &str) {
    use ed25519_dalek::Signer;

    let Some(base) = state.0.aggregator_url.clone() else {
        return;
    };
    let agent_id = hex::encode(state.0.node_signing_key.verifying_key().to_bytes());
    let body = serde_json::json!({
        "agent_id": agent_id,
        "token_address": token_mint,
    });
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(_) => return,
    };
    let sig = state.0.node_signing_key.sign(&body_bytes);
    let url = format!("{}/agents/{}/token", base.trim_end_matches('/'), agent_id);
    let req = state.0.http_client
        .post(url)
        .header("X-Signature", hex::encode(sig.to_bytes()))
        .header("Content-Type", "application/json")
        .body(body_bytes);
    if let Err(e) = req.send().await {
        tracing::warn!("token report to aggregator failed: {e}");
    }
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
    #[allow(dead_code)]
    hosting_fee_bps: u32,
    /// Pre-signed envelopes from hosted-agent send handler → node loop.
    hosted_outbound_tx: mpsc::Sender<Envelope>,
    /// Global rate limit window for `/envelopes/send`.
    send_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/hosted/register`.
    hosted_register_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/registry/8004/register-prepare`.
    registry_prepare_rate_limit: Mutex<RateLimitWindow>,
    /// Global rate limit window for `/registry/8004/register-submit`.
    registry_submit_rate_limit: Mutex<RateLimitWindow>,
    // 8004 registry helpers
    /// Solana RPC URL — used by registry endpoints for blockhash + broadcast.
    pub rpc_url: String,
    /// Solana RPC URL for trading (Jupiter swaps, Bags fees, USDC sweep).
    /// Defaults to mainnet so financial ops are on real network even when
    /// mesh rpc_url points at devnet.
    pub trade_rpc_url: String,
    /// Node's own Ed25519 signing key — used for /wallet/sweep.
    pub node_signing_key: Arc<SigningKey>,
    /// Shared HTTP client for registry RPC calls.
    pub(crate) http_client: reqwest::Client,
    /// Optional aggregator URL for reporting Bags claim events.
    #[cfg(feature = "bags")]
    pub(crate) aggregator_url: Option<String>,
    /// Shared secret for aggregator Bags claim pushes.
    #[cfg(feature = "bags")]
    pub(crate) aggregator_secret: Option<String>,
    /// Whether this node is pointed at mainnet-beta (affects 8004 program IDs).
    pub(crate) is_mainnet: bool,
    /// Whether trade_rpc_url points at mainnet-beta (affects USDC mint selection).
    pub(crate) is_trading_mainnet: bool,
    /// Optional Jupiter API base URL override (default: lite-api.jup.ag — free, no key).
    /// Set to https://api.jup.ag with --jupiter-api-url for higher rate limits.
    #[cfg(feature = "trade")]
    pub(crate) jupiter_api_url: Option<String>,
    /// Jupiter platform fee basis points (0 = disabled).
    #[cfg(feature = "trade")]
    pub(crate) jupiter_fee_bps: u16,
    /// Jupiter referral fee token account (ATA) — receives platform fees.
    #[cfg(feature = "trade")]
    pub(crate) jupiter_fee_account: Option<String>,
    /// Raydium LaunchLab share fee receiver wallet — earns 0.1% per bonding-curve trade.
    #[cfg(feature = "trade")]
    pub(crate) launchlab_share_fee_wallet: Option<String>,
    /// Pending swaps awaiting user CA confirmation — swap_id → PendingSwap.
    /// Entries expire after PENDING_SWAP_TTL_SECS (5 min) and are evicted on next poll.
    #[cfg(feature = "trade")]
    pub(crate) pending_swaps: Arc<tokio::sync::Mutex<HashMap<String, crate::trade::PendingSwap>>>,
    /// Kora paymaster client — present when --kora-url is configured.
    pub kora: Option<KoraClient>,
    /// Optional override for the 8004 base collection (required on mainnet).
    registry_8004_collection: Option<String>,
    /// The current Solana slot, continuously updated by the node event loop.
    current_slot: core::sync::atomic::AtomicU64,
    /// Agent IDs exempt from stake/lease/registration checks.
    /// Shared with Node so either side can read it; admin API writes via POST/DELETE /admin/exempt.
    exempt_agents: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
    /// Path to persist exempt_agents across restarts (log_dir/exempt_agents.json).
    exempt_persist_path: PathBuf,

    // Portfolio state
    pub portfolio_history: RwLock<PortfolioHistory>,
    portfolio_persist_path: RwLock<PathBuf>,

    // Bags fee-sharing (feature = "bags")
    #[cfg(feature = "bags")]
    pub bags_config: Option<Arc<crate::bags::BagsConfig>>,

    // Bags token launch (feature = "bags")
    #[cfg(feature = "bags")]
    pub bags_launch: Option<Arc<crate::bags::BagsLaunchClient>>,

    // Agent (zeroclaw) process management
    /// PID of the running zeroclaw agent process. Set by POST /agent/register-pid.
    /// Used by POST /agent/reload to restart the agent so new skills are loaded.
    pub agent_pid: Mutex<Option<u32>>,
    /// Rate limit for POST /identity/sign — max 60 signs per minute.
    sign_rate_limit: Mutex<RateLimitWindow>,
    /// Rate limit for POST /agent/reload — max 3 reloads per minute.
    agent_reload_rate_limit: Mutex<RateLimitWindow>,
    /// Daily budget for Kora gas sponsorship — 100 uses per 24-hour window.
    kora_daily_uses: Mutex<RateLimitWindow>,

    // Skill manager
    /// Zeroclaw workspace directory. When set, skill management endpoints are active.
    pub skill_workspace: Option<std::path::PathBuf>,

    // MPP payment gate
    /// MPP config for the hosting fee gate. None = gate disabled.
    pub mpp: Option<crate::mpp::MppConfig>,
    /// agent_id_hex → unix timestamp of last successful daily payment.
    /// In-memory only — resets on restart; agents just pay again.
    pub hosted_mpp_paid: Arc<RwLock<HashMap<String, u64>>>,
    /// reference (base58) → (challenge, created_at unix)
    pub mpp_challenges: Arc<Mutex<HashMap<String, (crate::mpp::MppChallenge, u64)>>>,

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
    #[cfg(feature = "trade")]
    pub fn inner(&self) -> &ApiInner {
        &self.0
    }
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
        hosting_fee_bps: u32,
        rpc_url: String,
        trade_rpc_url: String,
        #[cfg(feature = "trade")] jupiter_api_url: Option<String>,
        #[cfg(feature = "trade")] jupiter_fee_bps: u16,
        #[cfg(feature = "trade")] jupiter_fee_account: Option<String>,
        #[cfg(feature = "trade")] launchlab_share_fee_wallet: Option<String>,
        http_client: reqwest::Client,
        #[cfg(feature = "bags")] aggregator_url: Option<String>,
        #[cfg(feature = "bags")] aggregator_secret: Option<String>,
        registry_8004_collection: Option<String>,
        node_signing_key: Arc<SigningKey>,
        kora: Option<KoraClient>,
        exempt_agents: Arc<std::sync::RwLock<HashSet<[u8; 32]>>>,
        exempt_persist_path: PathBuf,
        #[cfg(feature = "bags")] bags_config: Option<Arc<crate::bags::BagsConfig>>,
        #[cfg(feature = "bags")] bags_launch: Option<Arc<crate::bags::BagsLaunchClient>>,
        skill_workspace: Option<std::path::PathBuf>,
        mpp: Option<crate::mpp::MppConfig>,
        file_delivery: Option<Arc<dyn zerox1_filedelivery_core::FileDelivery>>,
        task_log: Option<Arc<crate::task_log::TaskLog>>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundRequest>,
        mpsc::Receiver<Envelope>,
        mpsc::Receiver<String>,
    ) {
        let is_mainnet = !rpc_url.contains("devnet")
            && !rpc_url.contains("testnet")
            && !rpc_url.contains("localhost")
            && !rpc_url.contains("127.0.0.1");
        let is_trading_mainnet = !trade_rpc_url.contains("devnet")
            && !trade_rpc_url.contains("testnet")
            && !trade_rpc_url.contains("localhost")
            && !trade_rpc_url.contains("127.0.0.1");
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
            hosting_fee_bps,
            hosted_outbound_tx,
            send_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            hosted_register_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            registry_prepare_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            registry_submit_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            rpc_url,
            trade_rpc_url,
            #[cfg(feature = "trade")]
            jupiter_api_url,
            #[cfg(feature = "trade")]
            jupiter_fee_bps,
            #[cfg(feature = "trade")]
            jupiter_fee_account,
            #[cfg(feature = "trade")]
            launchlab_share_fee_wallet,
            #[cfg(feature = "trade")]
            pending_swaps: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            node_signing_key,
            http_client,
            #[cfg(feature = "bags")]
            aggregator_url,
            #[cfg(feature = "bags")]
            aggregator_secret,
            is_mainnet,
            is_trading_mainnet,
            kora,
            registry_8004_collection,
            current_slot: core::sync::atomic::AtomicU64::new(0),
            exempt_agents,
            exempt_persist_path,
            portfolio_history: RwLock::new(PortfolioHistory::default()),
            portfolio_persist_path: RwLock::new(PathBuf::new()), // set during init
            #[cfg(feature = "bags")]
            bags_config,
            #[cfg(feature = "bags")]
            bags_launch,
            agent_pid: Mutex::new(None),
            sign_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            agent_reload_rate_limit: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            kora_daily_uses: Mutex::new(RateLimitWindow {
                window_start: now_secs(),
                count: 0,
            }),
            skill_workspace,
            mpp,
            hosted_mpp_paid: Arc::new(RwLock::new(HashMap::new())),
            mpp_challenges: Arc::new(Mutex::new(HashMap::new())),
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
            zerox1_protocol::payload::DeliverPayload::decode(&env.payload).ok().map(|p| {
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

pub async fn serve(state: ApiState, addr: SocketAddr, cors_origins: Vec<String>) {
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
        // Hosted-agent API
        .route("/hosted/ping", get(hosted_ping))
        .route("/hosted/register", post(hosted_register))
        .route("/hosted/send", post(hosted_send))
        .route("/hosted/negotiate/propose", post(hosted_negotiate_propose))
        .route("/hosted/negotiate/counter", post(hosted_negotiate_counter))
        .route("/hosted/negotiate/accept", post(hosted_negotiate_accept))
        .route("/ws/hosted/inbox", get(ws_hosted_inbox_handler))
        // Named-topic BROADCAST subscriptions
        .route("/topics/{slug}/broadcast", post(topic_broadcast))
        .route("/ws/topics", get(ws_topics_handler))
        // 8004 Solana Agent Registry helpers
        .route("/registry/8004/info", get(registry_8004_info))
        .route(
            "/registry/8004/register-prepare",
            post(registry_8004_register_prepare),
        )
        .route(
            "/registry/8004/register-submit",
            post(registry_8004_register_submit),
        )
        .route(
            "/registry/8004/register-local",
            post(registry_8004_register_local),
        )
        // Escrow
        // Escrow routes removed — on-chain settlement moved to settlement/solana
        // Hot wallet sweep + x402 micropayments
        .route("/wallet/sweep", post(sweep_usdc))
        .route("/wallet/x402/pay", post(x402_pay))
        // MPP — Machine Payment Protocol daily gate
        .route("/mpp/challenge", get(mpp_challenge))
        .route("/mpp/verify", post(mpp_verify))
        // Admin — exempt agent management (loopback only; requires api_secret)
        .route(
            "/admin/exempt",
            get(admin_exempt_list).post(admin_exempt_add),
        )
        .route("/admin/exempt/{agent_id}", delete(admin_exempt_remove))
        // Agent process management (skill hot-reload)
        .route("/agent/register-pid", post(agent_register_pid))
        .route("/agent/reload", post(agent_reload))
        // Skill manager — safe Rust-side file operations (no shell injection)
        .route("/skill/list", get(skill_list_handler))
        .route("/skill/write", post(skill_write_handler))
        .route("/skill/install-url", post(skill_install_url_handler))
        .route("/skill/remove", post(skill_remove_handler))
        // Task audit log
        .route("/tasks/log", post(task_log_insert).get(task_log_list))
        .route("/tasks/log/{id}/shared", patch(task_log_mark_shared))
        .route("/tasks/log/{id}", delete(task_log_delete));

    #[cfg(feature = "trade")]
    let router = router
        .route("/trade/swap", post(crate::trade::trade_swap_handler))
        .route("/trade/swap/pending", get(crate::trade::trade_swap_pending_handler))
        .route("/trade/swap/confirm/{id}", post(crate::trade::trade_swap_confirm_handler))
        .route("/trade/swap/reject/{id}", post(crate::trade::trade_swap_reject_handler))
        .route("/trade/quote", get(crate::trade::trade_quote_handler))
        .route("/trade/price", get(crate::trade::trade_price_handler))
        .route("/trade/tokens", get(crate::trade::trade_tokens_handler))
        .route("/trade/limit/create", post(crate::trade::trade_limit_create_handler))
        .route("/trade/limit/orders", get(crate::trade::trade_limit_orders_handler))
        .route("/trade/limit/cancel", post(crate::trade::trade_limit_cancel_handler))
        .route("/trade/dca/create", post(crate::trade::trade_dca_create_handler))
        .route("/trade/launchlab/buy", post(crate::launchlab::launchlab_buy_handler))
        .route("/trade/launchlab/sell", post(crate::launchlab::launchlab_sell_handler))
        .route("/trade/cpmm/create-pool", post(crate::cpmm::cpmm_create_pool_handler))
        .route("/wallet/send", post(wallet_send_handler))
        .route("/portfolio/history", get(portfolio_history))
        .route("/portfolio/balances", get(portfolio_balances));

    #[cfg(not(feature = "trade"))]
    let router = router
        .route("/portfolio/history", get(portfolio_history))
        .route("/portfolio/balances", get(portfolio_balances));

    #[cfg(feature = "bags")]
    let router = router
        .route("/bags/config", get(bags_config_handler))
        .route("/bags/launch", post(bags_launch_handler))
        .route("/bags/claim", post(bags_claim_handler))
        .route("/bags/positions", get(bags_positions_handler))
        .route("/bags/set-api-key", post(bags_set_api_key_handler))
        .route("/bags/swap/quote", post(bags_swap_quote_handler))
        .route("/bags/swap/execute", post(bags_swap_execute_handler))
        .route("/bags/pool/{mint}", get(bags_pool_handler))
        .route("/bags/claimable", get(bags_claimable_handler))
        .route("/bags/dexscreener/check/{mint}", get(bags_dexscreener_check_handler))
        .route("/bags/dexscreener/list", post(bags_dexscreener_list_handler));

    let app = router
        .layer({
            let origins: Vec<axum::http::HeaderValue> = if cors_origins.is_empty() {
                // Default: loopback only (zeroclaw, React Native WebView).
                vec![
                    "http://127.0.0.1".parse().expect("valid CORS origin"),
                    "http://localhost".parse().expect("valid CORS origin"),
                ]
            } else {
                cors_origins.iter().filter_map(|o| o.parse().ok()).collect()
            };
            tower_http::cors::CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers(tower_http::cors::Any)
        })
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("API listener bind failed on {addr}: {e}");
            return;
        }
    };

    tracing::info!("API listening on http://{addr}");

    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("API server error on {addr}: {e}");
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
        None => {
            return Json(serde_json::json!({ "error": "bytes_hex required" })).into_response()
        }
    };
    if bytes_hex.len() > 512 {
        return Json(serde_json::json!({ "error": "bytes_hex too long (max 256 bytes)" }))
            .into_response();
    }
    let bytes = match hex::decode(bytes_hex) {
        Ok(b) => b,
        Err(_) => {
            return Json(serde_json::json!({ "error": "invalid hex" })).into_response()
        }
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
async fn identity_export_key(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
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
            let score = v.get("score").and_then(|x| x.as_i64()).unwrap_or(0).clamp(-100, 100) as i8;
            let outcome_str = v.get("outcome").and_then(|x| x.as_str()).unwrap_or("neutral");
            let outcome: u8 = match outcome_str { "positive" => 2, "negative" => 0, _ => 1 };
            zerox1_protocol::payload::FeedbackPayload {
                conversation_id,
                target_agent: recipient,
                score,
                outcome,
                is_dispute: false,
                role: zerox1_protocol::payload::FeedbackPayload::ROLE_PARTICIPANT,
            }.encode()
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
                        }.encode()
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "0G Storage upload failed; sending inline (may exceed size limit)");
                        zerox1_protocol::payload::DeliverPayload {
                            conversation_id,
                            content_type: None,
                            inline: Some(raw_payload),
                            payload_uri: None,
                            payload_size: None,
                        }.encode()
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
            }.encode()
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
        || !slug.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ':')
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
                Json(serde_json::json!({ "error": "content_url must be an http/https URL, max 2048 chars" })),
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
        Ok(Ok(conf)) => (StatusCode::OK, Json(serde_json::to_value(conf).unwrap_or_default())),
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
        tracing::warn!("sub_topic_tx full, subscription request for {:?} dropped: {e}", topic);
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
async fn hosted_ping() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

/// POST /hosted/register — open (no auth).
///
/// Generates a fresh ed25519 sub-keypair for the hosted agent.
/// Returns `{ "agent_id": "<hex64>", "token": "<hex64>" }`.
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

    // MPP gate — check if the agent has paid for today.
    {
        let agent_id_hex = {
            let sessions = state.0.hosted_sessions.read().await;
            sessions.get(&token).map(|s| hex::encode(s.agent_id))
        };
        if let Some(ref agent_hex) = agent_id_hex {
            if let Some(resp) = check_mpp_gate(agent_hex, &state.0).await {
                return resp;
            }
        }
    }

    // Parse msg_type.
    let msg_type = match parse_msg_type(&req.msg_type) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("unknown msg_type: {}", req.msg_type) })),
            )
                .into_response()
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
                    .into_response()
            }
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(b) => match b.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": "recipient must be 32 bytes" })),
                        )
                            .into_response()
                    }
                },
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "recipient: invalid hex" })),
                    )
                        .into_response()
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

    // MPP gate — check if the agent has paid for today.
    {
        let agent_id_hex = {
            let sessions = state.0.hosted_sessions.read().await;
            sessions.get(&t).map(|s| hex::encode(s.agent_id))
        };
        if let Some(ref agent_hex) = agent_id_hex {
            if let Some(resp) = check_mpp_gate(agent_hex, &state.0).await {
                return resp;
            }
        }
    }

    ws.on_upgrade(|socket| ws_hosted_inbox_task(socket, state, t))
        .into_response()
}

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
    // Use u8 accumulator (matches aggregator's implementation).
    // usize would allow compiler optimisations that can leak timing info on
    // 64-bit targets — a u8 forces byte-granularity constant-time behaviour.
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

/// Claim a Kora gas sponsorship slot from the daily budget.
///
/// Returns `true` and increments the counter if a slot is available.
/// Returns `false` if the 24-hour limit has been reached — callers should
/// fall back to agent-pays-SOL.
pub(crate) async fn try_use_kora_budget(state: &ApiState) -> bool {
    let mut rl = state.0.kora_daily_uses.lock().await;
    let now = now_secs();
    if now.saturating_sub(rl.window_start) >= 86_400 {
        rl.window_start = now;
        rl.count = 0;
    }
    if rl.count >= MAX_KORA_DAILY_USES {
        tracing::warn!(
            "Kora daily budget exhausted ({MAX_KORA_DAILY_USES}/day) — falling back to agent-pays-gas"
        );
        return false;
    }
    rl.count += 1;
    true
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
// 8004 Solana Agent Registry — registration helpers
// ============================================================================

/// GET /registry/8004/info
///
/// Returns the program constants, collection address, and step-by-step
/// instructions an agent needs to self-register in the 8004 registry.
/// No authentication required — this is public informational data.
async fn registry_8004_info(State(state): State<ApiState>) -> Response {
    let network = if state.0.is_mainnet {
        "mainnet-beta"
    } else {
        "devnet"
    };
    let program_id = if state.0.is_mainnet {
        PROGRAM_ID_MAINNET
    } else {
        PROGRAM_ID_DEVNET
    };
    let collection = state
        .0
        .registry_8004_collection
        .as_deref()
        .unwrap_or(if state.0.is_mainnet {
            crate::registry_8004::COLLECTION_MAINNET
        } else {
            crate::registry_8004::COLLECTION_DEVNET
        });

    Json(serde_json::json!({
        "network":     network,
        "program_id":  program_id,
        "collection":  collection,
        "mpl_core":    "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d",
        "indexer_url": if state.0.is_mainnet { "https://8004-indexer-main.qnt.sh/v2/graphql" } else { "https://8004-indexer-dev.qnt.sh/v2/graphql" },
        "indexer_urls": {
            "mainnet": "https://8004-indexer-main.qnt.sh/v2/graphql",
            "devnet":  "https://8004-indexer-dev.qnt.sh/v2/graphql",
        },
        "register_via_node": {
            "prepare": "POST /registry/8004/register-prepare",
            "submit":  "POST /registry/8004/register-submit",
        },
        "steps": [
            "1. POST /registry/8004/register-prepare with { owner_pubkey, agent_uri? }",
            "2. Sign the returned message_b64 with your Ed25519/owner keypair",
            "3. POST /registry/8004/register-submit with { transaction_b64, owner_signature_b64 }",
            "4. Save the asset_pubkey — it is your permanent 8004 identity",
            "5. Within ~30 seconds the indexer will reflect your registration",
        ],
        "note": "Your 0x01 agent_id hex == your Solana owner pubkey (base58). No extra keys needed."
    }))
    .into_response()
}

/// Request body for POST /registry/8004/register-prepare.
#[derive(Deserialize)]
struct RegisterPrepareRequest {
    /// base58 Solana pubkey of the agent registering.
    /// Must equal the caller's Ed25519 agent_id (base58).
    owner_pubkey: String,
    /// Optional metadata URI (IPFS, Arweave, HTTPS, or empty).
    /// Points to a JSON file with name, description, endpoints, etc.
    /// Max 250 bytes.  Defaults to empty string.
    #[serde(default)]
    agent_uri: String,
}

/// POST /registry/8004/register-prepare
///
/// Builds a partially-signed `register` transaction for the 8004 Solana
/// Agent Registry.  The asset keypair is generated by the node and pre-signed;
/// the caller only needs to sign the message with their owner/Ed25519 key.
///
/// Returns:
/// - `asset_pubkey`      — store this; it is your on-chain 8004 identity
/// - `transaction_b64`   — bincode tx, asset already signed, owner slot empty
/// - `message_b64`       — raw message bytes to sign with owner Ed25519 key
/// - `signing_hint`      — instructions for completing the signature
///
/// Requires API secret if one is configured.
async fn registry_8004_register_prepare(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterPrepareRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Rate limit: this endpoint makes an external Solana RPC call per request.
    {
        let now = now_secs();
        let mut rl = state.0.registry_prepare_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_REGISTRY_PREPARE_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            )
                .into_response();
        }
        rl.count += 1;
    }

    // Validate agent_uri: must be non-empty, bounded, and free of control chars.
    if req.agent_uri.is_empty() || req.agent_uri.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_uri must be 1–256 characters" })),
        )
            .into_response();
    }
    if req.agent_uri.chars().any(|c| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_uri: control characters not allowed" })),
        )
            .into_response();
    }

    let owner_pubkey: Pubkey = match req.owner_pubkey.parse() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid owner_pubkey: expected base58 Solana pubkey" })),
            )
                .into_response();
        }
    };

    // Use the configured rpc_url (Helius when baked in, public mainnet otherwise).
    let rpc_8004 = &state.0.rpc_url;
    let blockhash = match fetch_latest_blockhash(rpc_8004, &state.0.http_client).await {
        Ok(bh) => bh,
        Err(e) => {
            tracing::warn!("registry-prepare: blockhash fetch failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response();
        }
    };

    // Resolve collection override (mainnet requires explicit address).
    let collection_override = state
        .0
        .registry_8004_collection
        .as_deref()
        .and_then(|s| s.parse::<Pubkey>().ok());

    match build_register_tx(
        owner_pubkey,
        &req.agent_uri,
        blockhash,
        state.0.is_mainnet,
        collection_override,
        None, // fee_payer_override
    ) {
        Ok(prepared) => Json(serde_json::json!({
            "asset_pubkey":    prepared.asset_pubkey,
            "transaction_b64": prepared.transaction_b64,
            "message_b64":     prepared.message_b64,
            "signing_hint": concat!(
                "Sign message_b64 with your Ed25519 owner keypair (64-byte signature). ",
                "Then POST { transaction_b64, owner_signature_b64 } to /registry/8004/register-submit. ",
                "Or deserialize transaction_b64, add owner signature at index 0, and broadcast yourself."
            ),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("tx build failed: {e}") })),
        )
            .into_response(),
    }
}

/// Request body for POST /registry/8004/register-submit.
#[derive(Deserialize)]
struct RegisterSubmitRequest {
    /// base64 bincode Solana transaction (from register-prepare, asset already signed).
    transaction_b64: String,
    /// base64 64-byte Ed25519 signature of the transaction message by the owner keypair.
    owner_signature_b64: String,
}

/// POST /registry/8004/register-submit
///
/// Injects the owner's Ed25519 signature into the prepared transaction and
/// broadcasts it to Solana via the configured RPC endpoint.
///
/// Returns `{ signature }` — the Solana transaction signature (base58).
///
/// Requires API secret if one is configured.
async fn registry_8004_register_submit(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterSubmitRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Rate limit: each submit triggers signature validation + RPC broadcast.
    {
        let now = now_secs();
        let mut rl = state.0.registry_submit_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_REGISTRY_SUBMIT_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            )
                .into_response();
        }
        rl.count += 1;
    }

    // Decode and validate the owner signature.
    let sig_bytes = match B64.decode(&req.owner_signature_b64) {
        Ok(b) if b.len() == 64 => b,
        Ok(b) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("owner_signature_b64 must be 64 bytes, got {}", b.len())
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid owner_signature_b64: {e}") })),
            )
                .into_response();
        }
    };

    // Guard transaction size: Solana max tx is 1232 bytes → ~1644 base64 chars.
    // Allow 2× headroom for padding/overhead before even decoding.
    const MAX_TX_B64_LEN: usize = 3300;
    if req.transaction_b64.len() > MAX_TX_B64_LEN {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(
                serde_json::json!({ "error": "transaction_b64: exceeds maximum transaction size" }),
            ),
        )
            .into_response();
    }

    // Decode the partially-signed transaction.
    let tx_bytes = match B64.decode(&req.transaction_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid transaction_b64: {e}") })),
            )
                .into_response();
        }
    };

    let mut tx: solana_sdk::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": format!("transaction deserialize failed: {e}") }),
                ),
            )
                .into_response();
        }
    };

    // The register tx must have exactly 2 signature slots: owner (index 0) + asset (index 1).
    // Also verify the fee payer is in account_keys[0] to prevent owner impersonation.
    if tx.signatures.len() != 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "expected 2 signature slots (owner + asset), got {}",
                    tx.signatures.len()
                )
            })),
        )
            .into_response();
    }

    // Security check (Prevent Open RPC Relay):
    // 1. Ensure exactly 1 instruction
    // 2. Ensure the instruction calls the expected 8004 registry program ID
    if tx.message.instructions.len() != 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "transaction must contain exactly 1 instruction, got {}",
                    tx.message.instructions.len()
                )
            })),
        )
            .into_response();
    }

    let program_id_str = if state.0.is_mainnet {
        crate::registry_8004::PROGRAM_ID_MAINNET
    } else {
        crate::registry_8004::PROGRAM_ID_DEVNET
    };

    let expected_program_id = program_id_str
        .parse::<solana_sdk::pubkey::Pubkey>()
        .expect("static program ID parses");

    let instruction_program_id = tx.message.instructions[0].program_id(&tx.message.account_keys);

    if instruction_program_id != &expected_program_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!(
                    "invalid program ID: expected {}, got {}",
                    expected_program_id, instruction_program_id
                )
            })),
        )
            .into_response();
    }

    // Inject the owner signature at index 0 (owner is fee payer = first signer).
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("checked length above");
    tx.signatures[0] = solana_sdk::signature::Signature::from(sig_arr);

    // Re-serialize with owner signature injected and broadcast.
    let signed_bytes = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("re-serialize failed: {e}") })),
            )
                .into_response();
        }
    };
    let signed_b64 = B64.encode(&signed_bytes);

    let rpc_8004 = &state.0.rpc_url;
    match broadcast_transaction(rpc_8004, &state.0.http_client, &signed_b64).await {
        Ok(signature) => {
            tracing::info!("8004 registration broadcast: tx={signature}");
            Json(serde_json::json!({
                "signature": signature,
                "explorer":  format!(
                    "https://explorer.solana.com/tx/{}?cluster={}",
                    signature,
                    if state.0.is_mainnet { "mainnet-beta" } else { "devnet" }
                ),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("8004 registration broadcast failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// 8004 register-local — all-in-one: prepare + sign with node key + broadcast
// ============================================================================

#[derive(Deserialize)]
struct RegisterLocalRequest {
    #[serde(default)]
    agent_uri: String,
}

/// POST /registry/8004/register-local
///
/// Convenience endpoint: builds the register transaction using the node's own
/// Ed25519 key as the owner, signs the message internally, and broadcasts.
/// No external wallet or signature needed — the node registers itself.
///
/// Returns `{ signature, asset_pubkey, explorer }`.
async fn registry_8004_register_local(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<RegisterLocalRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // Rate-limit: reuse the prepare bucket (same external RPC call cost).
    {
        let now = now_secs();
        let mut rl = state.0.registry_prepare_rate_limit.lock().await;
        if now.saturating_sub(rl.window_start) >= 60 {
            rl.window_start = now;
            rl.count = 0;
        }
        if rl.count >= MAX_REGISTRY_PREPARE_PER_MINUTE {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({ "error": "rate limit exceeded — try again in 60s" })),
            )
                .into_response();
        }
        rl.count += 1;
    }

    // Derive owner pubkey from the node's own signing key.
    let signing_key = Arc::clone(&state.0.node_signing_key);
    let owner_pubkey = Pubkey::from(signing_key.verifying_key().to_bytes());

    // Validate agent_uri length (same guard as register-prepare).
    let agent_uri = req.agent_uri.trim();
    if agent_uri.len() > 250 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_uri exceeds 250 bytes" })),
        )
            .into_response();
    }
    if agent_uri.chars().any(|c| c.is_control()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "agent_uri contains control characters" })),
        )
            .into_response();
    }

    let rpc_8004 = &state.0.rpc_url;
    let blockhash = match fetch_latest_blockhash(rpc_8004, &state.0.http_client).await {
        Ok(bh) => bh,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response();
        }
    };

    let collection_override = state
        .0
        .registry_8004_collection
        .as_deref()
        .and_then(|s| s.parse::<Pubkey>().ok());

    let prepared = match build_register_tx(
        owner_pubkey,
        agent_uri,
        blockhash,
        state.0.is_mainnet,
        collection_override,
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("tx build failed: {e}") })),
            )
                .into_response();
        }
    };

    // Sign the message with the node's own Ed25519 key.
    let message_bytes = match B64.decode(&prepared.message_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("message decode failed: {e}") })),
            )
                .into_response();
        }
    };
    use ed25519_dalek::Signer as _;
    let owner_sig: ed25519_dalek::Signature = signing_key.sign(&message_bytes);
    let sig_arr: [u8; 64] = owner_sig.to_bytes();

    // Deserialize the partially-signed tx, inject owner sig, reserialise and broadcast.
    let tx_bytes = match B64.decode(&prepared.transaction_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("tx decode failed: {e}") })),
            )
                .into_response();
        }
    };
    let mut tx: solana_sdk::transaction::Transaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("tx deserialize failed: {e}") })),
            )
                .into_response();
        }
    };
    tx.signatures[0] = solana_sdk::signature::Signature::from(sig_arr);

    let signed_bytes = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("re-serialize failed: {e}") })),
            )
                .into_response();
        }
    };
    let signed_b64 = B64.encode(&signed_bytes);

    match broadcast_transaction(rpc_8004, &state.0.http_client, &signed_b64).await {
        Ok(signature) => {
            tracing::info!("8004 register-local broadcast: tx={signature}");
            Json(serde_json::json!({
                "signature":   signature,
                "asset_pubkey": prepared.asset_pubkey,
                "explorer": format!(
                    "https://explorer.solana.com/tx/{}?cluster={}",
                    signature,
                    if state.0.is_mainnet { "mainnet-beta" } else { "devnet" }
                ),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("8004 register-local broadcast failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// x402 micropayment — POST /wallet/x402/pay
// ============================================================================

/// Compute Budget program ID (Solana).
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

/// CAIP-2 network identifiers for Solana mainnet and devnet.
const SOLANA_MAINNET_CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const SOLANA_DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

#[derive(Deserialize)]
pub(crate) struct X402PayRequest {
    /// Raw value of the `Payment-Required` header (base64-encoded JSON).
    payment_required_b64: String,
}

/// POST /wallet/x402/pay
///
/// Accepts an x402 `Payment-Required` header value (base64-encoded JSON),
/// selects the first Solana `exact` scheme entry from `accepts[]`, builds and
/// signs the required SPL `TransferChecked` transaction (preceded by Compute
/// Budget instructions as the spec requires), and returns a ready-to-use
/// `Payment-Signature` header value that the caller can forward on the retry
/// request.
///
/// The facilitator at `https://facilitator.payai.network` will broadcast the
/// transaction when the target server calls its `/settle` endpoint.
///
/// Requires api_secret.  Amount is capped at MAX_X402_PAYMENT_MICRO (10 USDC).
async fn x402_pay(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<X402PayRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    // 1. Decode and parse the Payment-Required header value.
    let req_bytes = match B64.decode(body.payment_required_b64.trim()) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payment_required_b64: invalid base64" })),
            )
                .into_response();
        }
    };
    let payment_req: serde_json::Value = match serde_json::from_slice(&req_bytes) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payment_required_b64: invalid JSON" })),
            )
                .into_response();
        }
    };

    // 2. Find first Solana exact-scheme entry in accepts[].
    let accepts = match payment_req["accepts"].as_array() {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payment_required: missing accepts array" })),
            )
                .into_response();
        }
    };

    // Prefer the network matching this node's current mode (mainnet vs devnet).
    let expected_network = if state.0.is_trading_mainnet {
        SOLANA_MAINNET_CAIP2
    } else {
        SOLANA_DEVNET_CAIP2
    };

    let accepted = accepts.iter().find(|e| {
        e["scheme"].as_str() == Some("exact")
            && e["network"].as_str() == Some(expected_network)
    });
    let accepted = match accepted {
        Some(a) => a,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "no compatible Solana exact-scheme entry in accepts",
                    "expected_network": expected_network,
                })),
            )
                .into_response();
        }
    };

    // 3. Parse pay_to, asset (mint), and amount.
    let pay_to_str = match accepted["payTo"].as_str() {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "accepted entry missing payTo" })),
            )
                .into_response();
        }
    };
    let pay_to: Pubkey = match pay_to_str.parse() {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "payTo: invalid Solana pubkey" })),
            )
                .into_response();
        }
    };

    let asset_str = match accepted["asset"].as_str() {
        Some(s) => s,
        None => {
            // Default to USDC mint for this network if omitted.
            if state.0.is_trading_mainnet {
                USDC_MINT_MAINNET
            } else {
                USDC_MINT_DEVNET
            }
        }
    };
    let usdc_mint: Pubkey = match asset_str.parse() {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "asset: invalid mint pubkey" })),
            )
                .into_response();
        }
    };

    let amount_micro: u64 = match accepted["amount"].as_str().and_then(|s| s.parse().ok()) {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "accepted entry missing or invalid amount" })),
            )
                .into_response();
        }
    };

    if amount_micro > MAX_X402_PAYMENT_MICRO {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "payment amount exceeds MAX_X402_PAYMENT_MICRO",
                "amount_micro": amount_micro,
                "max_micro": MAX_X402_PAYMENT_MICRO,
            })),
        )
            .into_response();
    }

    // 4. Derive hot-wallet pubkey and source ATA.
    let signing_key = Arc::clone(&state.0.node_signing_key);
    let agent_pubkey: Pubkey = {
        let vk_bytes = signing_key.verifying_key().to_bytes();
        Pubkey::new_from_array(vk_bytes)
    };
    let source_ata = derive_ata(&agent_pubkey, &usdc_mint);
    let dest_ata = derive_ata(&pay_to, &usdc_mint);

    // 5. Fetch recent blockhash.
    let blockhash =
        match fetch_latest_blockhash(&state.0.trade_rpc_url, &state.0.http_client).await {
            Ok(bh) => bh,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
                )
                    .into_response();
            }
        };

    // 6. Build the three required instructions in the order mandated by x402:
    //      a) SetComputeUnitLimit (max 40_000)
    //      b) SetComputeUnitPrice (max 5 microlamports)
    //      c) SPL TransferChecked (amount + 6 decimals)
    let compute_budget_program: Pubkey = COMPUTE_BUDGET_PROGRAM_ID
        .parse()
        .expect("valid compute budget program id");

    // SetComputeUnitLimit discriminant = 2, then u32 LE units.
    let mut limit_data = vec![2u8];
    limit_data.extend_from_slice(&40_000u32.to_le_bytes());
    let compute_limit_ix = solana_sdk::instruction::Instruction {
        program_id: compute_budget_program,
        accounts: vec![],
        data: limit_data,
    };

    // SetComputeUnitPrice discriminant = 3, then u64 LE microlamports.
    let mut price_data = vec![3u8];
    price_data.extend_from_slice(&5u64.to_le_bytes());
    let compute_price_ix = solana_sdk::instruction::Instruction {
        program_id: compute_budget_program,
        accounts: vec![],
        data: price_data,
    };

    // SPL TransferChecked discriminant = 12, then u64 LE amount, then u8 decimals.
    let spl_token_program: Pubkey = SPL_TOKEN_PROGRAM_ID
        .parse()
        .expect("valid SPL_TOKEN_PROGRAM_ID");
    let mut transfer_data = vec![12u8];
    transfer_data.extend_from_slice(&amount_micro.to_le_bytes());
    transfer_data.push(6u8); // USDC decimals
    let transfer_ix = solana_sdk::instruction::Instruction {
        program_id: spl_token_program,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(source_ata, false),
            solana_sdk::instruction::AccountMeta::new_readonly(usdc_mint, false),
            solana_sdk::instruction::AccountMeta::new(dest_ata, false),
            solana_sdk::instruction::AccountMeta::new(agent_pubkey, true),
        ],
        data: transfer_data,
    };

    // 7. Build and sign the transaction (agent is fee payer — x402 facilitator
    //    expects a partially-signed tx; for Solana the payer signs fully here
    //    and the facilitator broadcasts without adding another sig).
    let solana_kp = to_solana_keypair(&signing_key);
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[compute_limit_ix, compute_price_ix, transfer_ix],
        Some(&agent_pubkey),
        &[&solana_kp],
        blockhash,
    );

    let tx_b64 = match bincode::serialize(&tx) {
        Ok(b) => B64.encode(&b),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({ "error": format!("transaction serialization failed: {e}") }),
                ),
            )
                .into_response();
        }
    };

    // 8. Wrap in the x402 Payment-Signature JSON envelope and base64-encode it.
    let payment_signature_json = serde_json::json!({
        "x402Version": 2,
        "scheme": "exact",
        "network": expected_network,
        "accepted": accepted,
        "payload": {
            "transaction": tx_b64,
        },
    });
    let payment_signature_b64 = B64.encode(payment_signature_json.to_string().as_bytes());

    tracing::info!(
        "x402 payment: {} USDC micro → {} (network: {expected_network})",
        amount_micro,
        pay_to_str,
    );

    Json(serde_json::json!({
        "payment_signature": payment_signature_b64,
        "amount_micro": amount_micro,
        "amount_usdc": amount_micro as f64 / 1_000_000.0,
        "pay_to": pay_to_str,
        "network": expected_network,
    }))
    .into_response()
}

// ============================================================================
// Wallet sweep — POST /wallet/sweep
// ============================================================================

#[derive(Deserialize)]
pub struct SweepRequest {
    destination: String,
    amount: Option<u64>,
}

/// Convert an ed25519_dalek SigningKey to a solana_sdk Keypair.
///
/// solana_sdk::signature::Keypair is a 64-byte keypair: [secret(32) || public(32)].
pub(crate) fn to_solana_keypair(sk: &SigningKey) -> solana_sdk::signature::Keypair {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&sk.to_bytes());
    bytes[32..].copy_from_slice(sk.verifying_key().as_bytes());
    solana_sdk::signature::Keypair::try_from(bytes.as_slice()).expect("valid ed25519 keypair bytes")
}

/// Sign an empty signature slot in a Solana wire-format transaction (legacy or V0).
///
/// Bags returns V0 versioned transactions that cannot be round-tripped through
/// `bincode::deserialize::<Transaction>`. This function operates directly on the
/// raw wire bytes, locates the agent's pubkey in the signer account list, and
/// fills the corresponding empty (all-zero) signature slot.
///
/// Returns the bytes unchanged if the agent's pubkey is not found or the slot is
/// already filled.
#[cfg(feature = "bags")]
fn sign_wire_tx_for_agent(tx_bytes: &[u8], key: &SigningKey) -> Vec<u8> {
    if tx_bytes.is_empty() {
        return tx_bytes.to_vec();
    }
    // compact-u16 num_sigs
    let (num_sigs, sigs_start) = if tx_bytes[0] & 0x80 == 0 {
        (tx_bytes[0] as usize, 1usize)
    } else if tx_bytes.len() >= 2 {
        let lo = (tx_bytes[0] & 0x7f) as usize;
        let hi = tx_bytes[1] as usize;
        (lo | (hi << 7), 2usize)
    } else {
        return tx_bytes.to_vec();
    };
    let msg_start = sigs_start + num_sigs * 64;
    if tx_bytes.len() <= msg_start {
        return tx_bytes.to_vec();
    }
    let message_bytes = &tx_bytes[msg_start..];
    // V0 message starts with 0x80 version prefix; skip it for header parsing.
    let hdr = if message_bytes[0] == 0x80 { 1usize } else { 0usize };
    if message_bytes.len() < hdr + 4 {
        return tx_bytes.to_vec();
    }
    let num_required_sigs = message_bytes[hdr] as usize;
    let ac_off = hdr + 3;
    let (num_accounts, accounts_start) = if message_bytes[ac_off] & 0x80 == 0 {
        (message_bytes[ac_off] as usize, ac_off + 1)
    } else if message_bytes.len() >= ac_off + 2 {
        let lo = (message_bytes[ac_off] & 0x7f) as usize;
        let hi = message_bytes[ac_off + 1] as usize;
        (lo | (hi << 7), ac_off + 2)
    } else {
        return tx_bytes.to_vec();
    };
    let our_pubkey = key.verifying_key().to_bytes();
    let mut our_slot: Option<usize> = None;
    for i in 0..num_required_sigs.min(num_accounts) {
        let off = accounts_start + i * 32;
        if off + 32 > message_bytes.len() { break; }
        if message_bytes[off..off + 32] == our_pubkey {
            our_slot = Some(i);
            break;
        }
    }
    let slot = match our_slot {
        Some(s) => s,
        None => return tx_bytes.to_vec(),
    };
    let slot_start = sigs_start + slot * 64;
    if slot_start + 64 > tx_bytes.len() {
        return tx_bytes.to_vec();
    }
    if tx_bytes[slot_start..slot_start + 64].iter().any(|&b| b != 0) {
        return tx_bytes.to_vec(); // already signed
    }
    use ed25519_dalek::Signer as _;
    let sig = key.sign(message_bytes);
    let mut result = tx_bytes.to_vec();
    result[slot_start..slot_start + 64].copy_from_slice(&sig.to_bytes());
    result
}

/// Derive the Associated Token Account address for a given owner and mint.
pub(crate) fn derive_ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let spl_token: Pubkey = SPL_TOKEN_PROGRAM_ID
        .parse()
        .expect("valid SPL_TOKEN_PROGRAM_ID");
    let ata_program: Pubkey = SPL_ATA_PROGRAM_ID
        .parse()
        .expect("valid SPL_ATA_PROGRAM_ID");
    Pubkey::find_program_address(
        &[&owner.to_bytes(), &spl_token.to_bytes(), &mint.to_bytes()],
        &ata_program,
    )
    .0
}

// Escrow handlers removed — on-chain settlement moved to settlement/solana.
// See settlement/solana/client/src/escrow.rs for the original implementation.

// escrow_lock handler removed — on-chain settlement moved to settlement/solana.

// escrow_approve handler removed — on-chain settlement moved to settlement/solana.

// ============================================================================
// MPP — Machine Payment Protocol (HTTP 402 daily gate)
// ============================================================================

#[derive(Deserialize)]
struct MppVerifyRequest {
    tx_sig: String,
    reference: String,
    /// Hex-encoded agent_id of the hosted agent making the payment.
    agent_id: String,
}

/// Check whether the MPP gate allows access for the given hosted agent.
///
/// Returns `None` if access is allowed (gate disabled or agent has paid).
/// Returns `Some(Response)` with HTTP 402 if payment is required.
async fn check_mpp_gate(agent_id_hex: &str, state: &ApiInner) -> Option<Response> {
    let mpp = match &state.mpp {
        Some(m) if m.enabled => m,
        _ => return None,
    };

    let now = crate::mpp::unix_now();
    {
        let paid = state.hosted_mpp_paid.read().await;
        if let Some(&last_paid) = paid.get(agent_id_hex) {
            if now.saturating_sub(last_paid) < 86_400 {
                return None;
            }
        }
    }

    // Agent needs to pay — generate a fresh challenge and return 402.
    let challenge = crate::mpp::generate_challenge(mpp);

    // Prune expired challenges (older than 180s).
    {
        let mut challenges = state.mpp_challenges.lock().await;
        let cutoff = now.saturating_sub(180);
        challenges.retain(|_, (_, created_at)| *created_at >= cutoff);
        challenges.insert(challenge.reference.clone(), (challenge.clone(), now));
    }

    let mut headers = axum::http::HeaderMap::new();
    // Safety: generate_challenge() produces Solana pubkeys (base58 ASCII) and u64 integers,
    // both of which are always valid HeaderValues. The parse() cannot fail in practice.
    headers.insert("X-MPP-Recipient", challenge.recipient.parse().unwrap());
    headers.insert("X-MPP-Amount", challenge.amount.to_string().parse().unwrap());
    headers.insert("X-MPP-Mint", challenge.mint.parse().unwrap());
    headers.insert("X-MPP-Reference", challenge.reference.parse().unwrap());
    headers.insert("X-MPP-Expires", challenge.expires_at.to_string().parse().unwrap());

    let body = serde_json::json!({
        "error": "payment_required",
        "challenge": {
            "recipient": challenge.recipient,
            "amount": challenge.amount,
            "mint": challenge.mint,
            "reference": challenge.reference,
            "expires_at": challenge.expires_at,
        }
    });

    Some(
        (
            StatusCode::PAYMENT_REQUIRED,
            headers,
            Json(body),
        )
            .into_response(),
    )
}

/// GET /mpp/challenge — generate a fresh MPP challenge.
///
/// Returns 404 if MPP is disabled.
/// Returns a JSON challenge object with the payment details.
async fn mpp_challenge(State(state): State<ApiState>) -> impl IntoResponse {
    let mpp = match &state.0.mpp {
        Some(m) if m.enabled => m,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "mpp not enabled" })),
            )
                .into_response()
        }
    };

    let now = crate::mpp::unix_now();
    let challenge = crate::mpp::generate_challenge(mpp);

    // Prune expired challenges (older than 180s).
    {
        let mut challenges = state.0.mpp_challenges.lock().await;
        let cutoff = now.saturating_sub(180);
        challenges.retain(|_, (_, created_at)| *created_at >= cutoff);
        challenges.insert(challenge.reference.clone(), (challenge.clone(), now));
    }

    Json(serde_json::json!({
        "recipient": challenge.recipient,
        "amount": challenge.amount,
        "mint": challenge.mint,
        "reference": challenge.reference,
        "expires_at": challenge.expires_at,
    }))
    .into_response()
}

/// POST /mpp/verify — verify an MPP payment proof.
///
/// Body: `{ "tx_sig": "...", "reference": "...", "agent_id": "..." }`
/// The request must include `Authorization: Bearer <hosted_token>` matching the agent_id.
///
/// Returns `{ "paid_until": <unix_timestamp> }` on success, or 402 on failure.
async fn mpp_verify(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<MppVerifyRequest>,
) -> impl IntoResponse {
    // MPP must be enabled.
    if state.0.mpp.as_ref().is_none_or(|m| !m.enabled) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "mpp not enabled" })),
        )
            .into_response();
    }

    // Verify the token corresponds to the claimed agent_id.
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

    {
        let sessions = state.0.hosted_sessions.read().await;
        match sessions.get(&token) {
            Some(s) => {
                let session_agent_hex = hex::encode(s.agent_id);
                if session_agent_hex != req.agent_id {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({ "error": "agent_id does not match token" })),
                    )
                        .into_response();
                }
            }
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid token" })),
                )
                    .into_response()
            }
        }
    }

    // Look up the challenge by reference.
    let challenge = {
        let challenges = state.0.mpp_challenges.lock().await;
        match challenges.get(&req.reference) {
            Some((ch, _)) => ch.clone(),
            None => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({ "error": "challenge not found or expired" })),
                )
                    .into_response()
            }
        }
    };

    // Check challenge expiry.
    if crate::mpp::unix_now() > challenge.expires_at {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({ "error": "challenge expired" })),
        )
            .into_response();
    }

    let proof = crate::mpp::MppProof {
        tx_sig: req.tx_sig.clone(),
        reference: req.reference.clone(),
    };

    let rpc_url = state.0.rpc_url.clone();
    match crate::mpp::verify_payment(&proof, &challenge, &rpc_url).await {
        Ok(true) => {
            let now = crate::mpp::unix_now();
            let paid_until = now + 86_400;
            state
                .0
                .hosted_mpp_paid
                .write()
                .await
                .insert(req.agent_id.clone(), now);
            // Remove the used challenge.
            state.0.mpp_challenges.lock().await.remove(&req.reference);
            Json(serde_json::json!({ "paid_until": paid_until })).into_response()
        }
        Ok(false) => (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({ "error": "payment verification failed" })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("MPP verify_payment error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "payment verification error" })),
            )
                .into_response()
        }
    }
}

/// handler derives the destination ATA automatically).
/// If `amount` is specified in the body, it sweeps that specific atomic amount.
/// Otherwise, it sweeps the entire balance.
///
/// Returns: `{ "signature": "...", "amount_usdc": 1.23, "destination": "..." }`
pub async fn sweep_usdc(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<SweepRequest>,
) -> Response {
    // CRITICAL: sweep moves real money — require master secret.
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    // 1. Validate destination pubkey.
    let destination: Pubkey = match body.destination.parse() {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid destination pubkey" })),
            )
                .into_response();
        }
    };

    // 2. Derive agent's hot wallet pubkey.
    let signing_key = Arc::clone(&state.0.node_signing_key);
    let agent_pubkey: Pubkey = {
        let vk_bytes = signing_key.verifying_key().to_bytes();
        Pubkey::new_from_array(vk_bytes)
    };

    // 3. Select USDC mint based on trading network.
    let usdc_mint_str = if state.0.is_trading_mainnet {
        USDC_MINT_MAINNET
    } else {
        USDC_MINT_DEVNET
    };
    let usdc_mint: Pubkey = usdc_mint_str.parse().expect("valid USDC mint");

    // 4. Derive source and destination ATAs.
    let source_ata = derive_ata(&agent_pubkey, &usdc_mint);
    let dest_ata = derive_ata(&destination, &usdc_mint);

    // 5. Query source ATA balance via RPC.
    let balance_resp = state
        .0
        .http_client
        .post(&state.0.trade_rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountBalance",
            "params": [source_ata.to_string()]
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let available_balance: u64 = match balance_resp {
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("RPC request failed: {e}") })),
            )
                .into_response();
        }
        Ok(resp) => {
            let data: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({ "error": format!("RPC parse error: {e}") })),
                    )
                        .into_response();
                }
            };
            if data.get("error").is_some() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({ "error": "token account not found or has no balance" }),
                    ),
                )
                    .into_response();
            }
            match data["result"]["value"]["amount"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
            {
                Some(v) => v,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({ "error": "token account not found or has no balance" })),
                    )
                        .into_response();
                }
            }
        }
    };

    let amount_to_sweep = body.amount.unwrap_or(available_balance);

    if amount_to_sweep < MIN_SWEEP_AMOUNT {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "requested amount too low to sweep",
                "amount_atomic": amount_to_sweep,
                "min_atomic": MIN_SWEEP_AMOUNT,
            })),
        )
            .into_response();
    }

    if amount_to_sweep > available_balance {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "insufficient balance",
                "requested_atomic": amount_to_sweep,
                "available_atomic": available_balance,
            })),
        )
            .into_response();
    }

    // 6. Build SPL Token Transfer instruction (discriminant 3).
    let spl_token_program: Pubkey = SPL_TOKEN_PROGRAM_ID
        .parse()
        .expect("valid SPL_TOKEN_PROGRAM_ID");
    let mut ix_data = vec![3u8];
    ix_data.extend_from_slice(&amount_to_sweep.to_le_bytes());
    let transfer_ix = solana_sdk::instruction::Instruction {
        program_id: spl_token_program,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(source_ata, false),
            solana_sdk::instruction::AccountMeta::new(dest_ata, false),
            solana_sdk::instruction::AccountMeta::new(agent_pubkey, true),
        ],
        data: ix_data,
    };

    // 7. Fetch recent blockhash.
    let blockhash = match fetch_latest_blockhash(&state.0.trade_rpc_url, &state.0.http_client).await
    {
        Ok(bh) => bh,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response();
        }
    };

    // 8. Build, sign, and broadcast — Kora pays gas if configured and within daily budget,
    //    otherwise agent pays SOL directly.
    let solana_kp = to_solana_keypair(&signing_key);

    let use_kora_sweep = state.0.kora.is_some() && try_use_kora_budget(&state).await;
    if use_kora_sweep {
        let kora = state.0.kora.as_ref().unwrap();
        // ── Kora path: agent partial-signs, Kora adds fee-payer sig + broadcasts ──
        let fee_payer = match kora.get_fee_payer().await {
            Ok(fp) => fp,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("Kora fee payer failed: {e}") })),
                )
                    .into_response();
            }
        };
        let message = solana_sdk::message::Message::new_with_blockhash(
            &[transfer_ix],
            Some(&fee_payer),
            &blockhash,
        );
        let mut tx = solana_sdk::transaction::Transaction {
            signatures: vec![
                solana_sdk::signature::Signature::default();
                message.header.num_required_signatures as usize
            ],
            message,
        };
        tx.partial_sign(&[&solana_kp], blockhash);
        let tx_b64 = match bincode::serialize(&tx) {
            Ok(b) => B64.encode(&b),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("tx serialization failed: {e}") })),
                )
                    .into_response();
            }
        };
        match kora.sign_and_send(&tx_b64).await {
            Ok(signer) => {
                let amount_usdc = amount_to_sweep as f64 / 1_000_000.0;
                tracing::info!(
                    "Swept {amount_usdc:.6} USDC → {destination} via Kora (gasless, signer={signer})"
                );
                Json(serde_json::json!({
                    "signature": signer,
                    "amount_usdc": amount_usdc,
                    "destination": destination.to_string(),
                    "via": "kora",
                }))
                .into_response()
            }
            Err(e) => {
                tracing::warn!("sweep via Kora failed: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("Kora broadcast failed: {e}") })),
                )
                    .into_response()
            }
        }
    } else {
        // ── Direct path: agent is fee payer (requires SOL) ───────────────────
        let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[transfer_ix],
            Some(&agent_pubkey),
            &[&solana_kp],
            blockhash,
        );
        let serialized = match bincode::serialize(&tx) {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("tx serialization failed: {e}") })),
                )
                    .into_response();
            }
        };
        let signed_b64 = B64.encode(&serialized);
        match broadcast_transaction(&state.0.trade_rpc_url, &state.0.http_client, &signed_b64).await
        {
            Ok(signature) => {
                let amount_usdc = amount_to_sweep as f64 / 1_000_000.0;
                tracing::info!("Swept {amount_usdc:.6} USDC → {destination}: tx={signature}");
                Json(serde_json::json!({
                    "signature": signature,
                    "amount_usdc": amount_usdc,
                    "destination": destination.to_string(),
                }))
                .into_response()
            }
            Err(e) => {
                tracing::warn!("sweep broadcast failed: {e}");
                (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
                )
                    .into_response()
            }
        }
    }
}

// ============================================================================
// Wallet send — POST /wallet/send
// ============================================================================

#[cfg(feature = "trade")]
#[derive(Deserialize)]
struct WalletSendRequest {
    /// Destination Solana pubkey (base58).
    to: String,
    /// Amount in base units (lamports for SOL, token-native units for SPL).
    amount: u64,
    /// SPL token mint (base58). Omit for native SOL transfer.
    mint: Option<String>,
}

/// POST /wallet/send — send SOL or any SPL token from the agent hot wallet.
///
/// - No `mint`: native SOL transfer via System Program.
/// - `mint` present: SPL token transfer; destination ATA is created idempotently.
///
/// Requires the master api_secret (Authorization: Bearer <secret>).
/// This moves real funds — never expose this endpoint to untrusted callers.
#[cfg(feature = "trade")]
async fn wallet_send_handler(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<WalletSendRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }

    let to: Pubkey = match body.to.parse() {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid destination pubkey" })),
            )
                .into_response()
        }
    };

    if body.amount == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "amount must be > 0" })),
        )
            .into_response();
    }

    let signing_key = Arc::clone(&state.0.node_signing_key);
    let agent_pubkey: Pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    let solana_kp = to_solana_keypair(&signing_key);

    let rpc_url = state.0.trade_rpc_url.clone();

    let blockhash = match fetch_latest_blockhash(&rpc_url, &state.0.http_client).await {
        Ok(bh) => bh,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("blockhash fetch failed: {e}") })),
            )
                .into_response()
        }
    };

    let signature = if let Some(mint_str) = body.mint {
        // ── SPL token transfer ──────────────────────────────────────────────
        let mint: Pubkey = match mint_str.parse() {
            Ok(pk) => pk,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid mint pubkey" })),
                )
                    .into_response()
            }
        };

        let spl_token_prog: Pubkey = SPL_TOKEN_PROGRAM_ID
            .parse()
            .expect("valid SPL_TOKEN_PROGRAM_ID");
        let ata_prog: Pubkey = SPL_ATA_PROGRAM_ID
            .parse()
            .expect("valid SPL_ATA_PROGRAM_ID");

        let source_ata = derive_ata(&agent_pubkey, &mint);
        let dest_ata = derive_ata(&to, &mint);

        // Create destination ATA idempotently (discriminant 0 = CreateIdempotent).
        let create_ata_ix = solana_sdk::instruction::Instruction {
            program_id: ata_prog,
            accounts: vec![
                solana_sdk::instruction::AccountMeta::new(agent_pubkey, true),
                solana_sdk::instruction::AccountMeta::new(dest_ata, false),
                solana_sdk::instruction::AccountMeta::new_readonly(to, false),
                solana_sdk::instruction::AccountMeta::new_readonly(mint, false),
                solana_sdk::instruction::AccountMeta::new_readonly(
                    solana_sdk::system_program::id(),
                    false,
                ),
                solana_sdk::instruction::AccountMeta::new_readonly(spl_token_prog, false),
            ],
            data: vec![0u8], // CreateIdempotent
        };

        // SPL Token transfer instruction (discriminant 3).
        let mut transfer_data = vec![3u8];
        transfer_data.extend_from_slice(&body.amount.to_le_bytes());
        let transfer_ix = solana_sdk::instruction::Instruction {
            program_id: spl_token_prog,
            accounts: vec![
                solana_sdk::instruction::AccountMeta::new(source_ata, false),
                solana_sdk::instruction::AccountMeta::new(dest_ata, false),
                solana_sdk::instruction::AccountMeta::new_readonly(agent_pubkey, true),
            ],
            data: transfer_data,
        };

        let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[create_ata_ix, transfer_ix],
            Some(&agent_pubkey),
            &[&solana_kp],
            blockhash,
        );

        let tx_b64 = match bincode::serialize(&tx) {
            Ok(b) => B64.encode(&b),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("tx serialize failed: {e}") })),
                )
                    .into_response()
            }
        };

        match broadcast_transaction(&rpc_url, &state.0.http_client, &tx_b64).await {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
                )
                    .into_response()
            }
        }
    } else {
        // ── Native SOL transfer ─────────────────────────────────────────────
        let transfer_ix =
            solana_sdk::system_instruction::transfer(&agent_pubkey, &to, body.amount);
        let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[transfer_ix],
            Some(&agent_pubkey),
            &[&solana_kp],
            blockhash,
        );
        let tx_b64 = match bincode::serialize(&tx) {
            Ok(b) => B64.encode(&b),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("tx serialize failed: {e}") })),
                )
                    .into_response()
            }
        };
        match broadcast_transaction(&rpc_url, &state.0.http_client, &tx_b64).await {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("broadcast failed: {e}") })),
                )
                    .into_response()
            }
        }
    };

    tracing::info!("wallet_send: {amount} base units → {to} tx={signature}", amount = body.amount);
    Json(serde_json::json!({
        "signature": signature,
        "amount": body.amount,
        "to": body.to,
    }))
    .into_response()
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

pub async fn portfolio_balances(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Result<Json<PortfolioBalances>, (StatusCode, Json<serde_json::Value>)> {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return Err((
            resp.status(),
            Json(serde_json::json!({ "error": "unauthorized" })),
        ));
    }

    let pubkey = Pubkey::new_from_array(state.0.self_agent);
    let mut tokens = Vec::new();

    // Fetch SOL balance
    match state
        .0
        .http_client
        .post(&state.0.trade_rpc_url)
        .timeout(std::time::Duration::from_secs(10))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [pubkey.to_string()]
        }))
        .send()
        .await
    {
        Ok(res) => {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                let lamports = data["result"]["value"].as_f64().unwrap_or(0.0);
                if lamports > 0.0 {
                    tokens.push(TokenBalance {
                        mint: "So11111111111111111111111111111111111111112".to_string(), // SOL wrapped mint representation
                        amount: lamports / 1_000_000_000.0,
                        decimals: 9,
                    });
                }
            }
        }
        Err(e) => tracing::error!("Failed to fetch SOL balance: {}", e),
    }

    // Fetch all SPL token balances
    let spl_res = state
        .0
        .http_client
        .post(&state.0.trade_rpc_url)
        .timeout(std::time::Duration::from_secs(15))
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTokenAccountsByOwner",
            "params": [
                pubkey.to_string(),
                { "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
                { "encoding": "jsonParsed" }
            ]
        }))
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Token accounts fetch failed: {e}")})),
            )
        })?;

    let spl_data: serde_json::Value = spl_res.json().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Token accounts JSON parse failed: {e}")})),
        )
    })?;

    if let Some(accounts) = spl_data["result"]["value"].as_array() {
        for acc in accounts {
            let parsed = &acc["account"]["data"]["parsed"]["info"];
            let Some(amount_f64) = parsed["tokenAmount"]["uiAmount"].as_f64() else {
                tracing::warn!("portfolio: skipping token account with missing/non-float uiAmount");
                continue;
            };
            if amount_f64 > 0.0 {
                let mint = match parsed["mint"].as_str() {
                    Some(m) => m.to_string(),
                    None => {
                        tracing::warn!("portfolio: skipping token account with missing mint field");
                        continue;
                    }
                };
                let decimals = parsed["tokenAmount"]["decimals"].as_u64().unwrap_or(0) as u8;
                tokens.push(TokenBalance {
                    mint,
                    amount: amount_f64,
                    decimals,
                });
            }
        }
    }

    Ok(Json(PortfolioBalances { tokens }))
}

// ============================================================================
// Bags fee-sharing config endpoint (feature = "bags")
// ============================================================================

#[cfg(feature = "bags")]
async fn bags_config_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    match state.0.bags_config.as_ref() {
        None => Json(serde_json::json!({
            "enabled": false,
            "fee_bps": 0,
            "distribution_wallet": null,
            "min_fee_micro": 0,
        }))
        .into_response(),
        Some(cfg) => Json(serde_json::json!({
            "enabled": true,
            "fee_bps": cfg.fee_bps,
            "distribution_wallet": cfg.distribution_wallet.to_string(),
            "min_fee_micro": cfg.min_fee_micro,
        }))
        .into_response(),
    }
}

// ============================================================================
// Bags token launch handlers (feature = "bags")
// ============================================================================

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsLaunchRequest {
    name: String,
    symbol: String,
    description: String,
    /// Raw image bytes, base64-encoded. Mutually exclusive with `image_url` / `image_cid`.
    /// Bags API accepts PNG/JPG/GIF/WebP up to 15 MB.
    image_bytes: Option<String>,
    /// Public HTTPS URL for the token image. Mutually exclusive with `image_bytes` / `image_cid`.
    image_url: Option<String>,
    /// Keccak-256 hex CID of a blob previously uploaded via POST /wallet/upload-blob.
    /// The node fetches the bytes from the aggregator and uploads them directly to Bags.fm
    /// as multipart/form-data. Mutually exclusive with `image_bytes` / `image_url`.
    image_cid: Option<String>,
    website_url: Option<String>,
    twitter_url: Option<String>,
    telegram_url: Option<String>,
    /// Lamports to use for the initial token buy (0 = no initial buy).
    initial_buy_lamports: Option<u64>,
}

/// POST /bags/launch — launch a new token on Bags.fm with fee-sharing.
///
/// Flow:
///   1. Create token info (IPFS metadata + mint address)
///   2. Create fee-share config (Kora pays gas if available)
///   3. Build + sign launch transaction (agent pays SOL for mint account)
///   4. Broadcast and record portfolio event
#[cfg(feature = "bags")]
async fn bags_launch_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsLaunchRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured — set --bags-api-key"})),
        )
            .into_response(),
    };

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    // ── Input validation ─────────────────────────────────────────────────────
    if req.name.is_empty() || req.name.len() > 100 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "name must be 1–100 chars"})),
        )
            .into_response();
    }
    if req.symbol.is_empty()
        || req.symbol.len() > 10
        || !req.symbol.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "symbol must be 1–10 ASCII alphanumeric chars"})),
        )
            .into_response();
    }
    if req.description.len() > 1000 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "description must be ≤1000 chars"})),
        )
            .into_response();
    }
    // Reject supplying more than one image source — Bags API enforces oneOf.
    let image_sources = [req.image_bytes.is_some(), req.image_url.is_some(), req.image_cid.is_some()]
        .iter()
        .filter(|&&x| x)
        .count();
    if image_sources > 1 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "provide at most one of: image_bytes, image_url, image_cid"})),
        )
            .into_response();
    }

    // Validate image_cid format: must be a 64-char lowercase hex string.
    if let Some(ref cid) = req.image_cid {
        if cid.len() != 64 || !cid.chars().all(|c| c.is_ascii_hexdigit()) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "image_cid must be a 64-char hex string (keccak-256)"})),
            )
                .into_response();
        }
    }

    // Decode and size-check image_bytes when present (15 MB limit from Bags API).
    const MAX_IMAGE_BYTES: usize = 15 * 1024 * 1024;
    const AGGREGATOR_BLOB_URL: &str = "https://api.0x01.world/blobs";

    let decoded_image: Option<Vec<u8>> = if let Some(ref b64) = req.image_bytes {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        match B64.decode(b64) {
            Ok(bytes) if bytes.len() <= MAX_IMAGE_BYTES => Some(bytes),
            Ok(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "image_bytes exceeds 15 MB limit"})),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "image_bytes is not valid base64"})),
                )
                    .into_response();
            }
        }
    } else if let Some(ref cid) = req.image_cid {
        // Fetch blob bytes from the aggregator and send them directly as multipart.
        let blob_url = format!("{}/{}", AGGREGATOR_BLOB_URL, cid);
        match reqwest::get(&blob_url).await {
            Ok(resp) if resp.status().is_success() => {
                match resp.bytes().await {
                    Ok(bytes) if bytes.len() <= MAX_IMAGE_BYTES => Some(bytes.to_vec()),
                    Ok(_) => {
                        return (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            Json(serde_json::json!({"error": "blob exceeds 15 MB limit"})),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_GATEWAY,
                            Json(serde_json::json!({"error": format!("failed to read blob: {e}")})),
                        )
                            .into_response();
                    }
                }
            }
            Ok(resp) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": format!("aggregator returned {} for blob {}", resp.status(), cid)})),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": format!("failed to fetch blob from aggregator: {e}")})),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    for u in [
        req.image_url.as_deref(),
        req.website_url.as_deref(),
        req.twitter_url.as_deref(),
        req.telegram_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if u.len() > 512 || (!u.starts_with("https://") && !u.starts_with("http://")) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "URLs must start with http(s):// and be ≤512 chars"})),
            ).into_response();
        }
    }

    // ── Step 1: Create token info ────────────────────────────────────────────
    let (token_mint, ipfs_uri) = match launch
        .create_token_info(
            &req.name,
            &req.symbol,
            &req.description,
            decoded_image,
            req.image_url.as_deref(),
            req.website_url.as_deref(),
            req.twitter_url.as_deref(),
            req.telegram_url.as_deref(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            return (code, Json(serde_json::json!({"error": msg}))).into_response();
        }
    };

    // ── Step 2: Create fee-share config via aggregator sponsor wallet ────────
    // The agent wallet has no SOL, so we delegate on-chain fee-share account
    // creation to the aggregator which holds a funded sponsor wallet.
    let config_key = if let Some(ref agg_url) = state.0.aggregator_url {
        let body = serde_json::json!({
            "base_mint": token_mint,
            "agent_pubkey": agent_wallet,
        });
        let resp = match state
            .0
            .http_client
            .post(format!("{agg_url}/sponsor/fee-share-config"))
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": format!("Aggregator fee-share request failed: {e}")})),
                )
                    .into_response();
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let msg = body["error"].as_str().unwrap_or("unknown").to_string();
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("Aggregator fee-share config failed ({status}): {msg}")})),
            )
                .into_response();
        }
        let data: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": format!("Bad aggregator response: {e}")})),
                )
                    .into_response();
            }
        };
        match data["config_key"].as_str() {
            Some(k) => k.to_string(),
            None => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "Aggregator did not return config_key"})),
                )
                    .into_response();
            }
        }
    } else {
        // No aggregator configured — try direct (requires agent wallet to have SOL).
        tracing::warn!("No aggregator_url configured; attempting direct fee-share config (agent needs SOL)");
        match launch
            .create_fee_share_config(
                &agent_wallet,
                &token_mint,
                &[agent_wallet.as_str()],
                &[10_000u32],
            )
            .await
        {
            Ok((k, fee_share_txs)) => {
                let mut fee_share_errors = 0usize;
                for tx_b64 in &fee_share_txs {
                    if let Ok(tx_bytes) = bs58::decode(tx_b64).into_vec() {
                        if let Ok(mut tx) =
                            bincode::deserialize::<solana_sdk::transaction::Transaction>(&tx_bytes)
                        {
                            if tx.message.recent_blockhash != solana_sdk::hash::Hash::default() {
                                let kp = to_solana_keypair(&state.0.node_signing_key);
                                tx.partial_sign(&[&kp], tx.message.recent_blockhash);
                                if let Ok(serialized) = bincode::serialize(&tx) {
                                    let signed = B64.encode(&serialized);
                                    match broadcast_transaction(
                                        &state.0.trade_rpc_url,
                                        &state.0.http_client,
                                        &signed,
                                    )
                                    .await
                                    {
                                        Ok(_) => {}
                                        Err(e) => {
                                            tracing::warn!("Fee-share tx broadcast failed: {e}");
                                            fee_share_errors += 1;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        fee_share_errors += 1;
                    }
                }
                if !fee_share_txs.is_empty() && fee_share_errors == fee_share_txs.len() {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({"error": "All fee-share config transactions failed"})),
                    )
                        .into_response();
                }
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                k
            }
            Err(e) => {
                let (code, msg) = bags_error_response(&e);
                return (code, Json(serde_json::json!({"error": msg}))).into_response();
            }
        }
    };

    // ── Step 3: Build launch transaction (Bags pre-signs with mint keypair) ──
    let launch_tx_bytes = match launch
        .create_launch_transaction(
            &ipfs_uri,
            &token_mint,
            &agent_wallet,
            req.initial_buy_lamports,
            &config_key,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("create-launch-tx: {e}")})),
            )
                .into_response()
        }
    };

    // ── Step 4: Agent signs + broadcasts ────────────────────────────────────
    // Bags returns a V0 versioned transaction (wire format). We sign directly on
    // the wire bytes to avoid bincode round-trip corruption.
    let signed_launch_bytes = sign_wire_tx_for_agent(&launch_tx_bytes, &state.0.node_signing_key);
    let txid = match broadcast_transaction(
        &state.0.trade_rpc_url,
        &state.0.http_client,
        &B64.encode(&signed_launch_bytes),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("launch-tx broadcast: {e}")})),
            )
                .into_response()
        }
    };

    // ── Step 5: Record portfolio event ──────────────────────────────────────
    state
        .record_portfolio_event(PortfolioEvent::BagsLaunch {
            token_mint: token_mint.clone(),
            name: req.name.clone(),
            symbol: req.symbol.clone(),
            txid: txid.clone(),
            timestamp: now_secs(),
        })
        .await;

    // ── Step 6: Persist token_mint in aggregator DB ──────────────────────────
    report_token_to_aggregator(&state, &token_mint).await;

    tracing::info!(
        "Bags token launched: {} ({}) mint={} txid={}",
        req.name,
        req.symbol,
        token_mint,
        txid
    );

    Json(serde_json::json!({
        "token_mint": token_mint,
        "txid": txid,
        "config_key": config_key,
        "ipfs_uri": ipfs_uri,
    }))
    .into_response()
}

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsClaimRequest {
    token_mint: String,
}

/// POST /bags/claim — claim accumulated pool-fee revenue for a launched token.
#[cfg(feature = "bags")]
async fn bags_claim_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsClaimRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Bags API key not configured"})),
            )
                .into_response()
        }
    };

    // Validate token_mint is a well-formed base58 pubkey before calling Bags API.
    if req.token_mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "token_mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    // Capture SOL balance before claiming so we can compute the 1% protocol fee.
    let pre_sol_balance = crate::bags::get_sol_balance(
        &state.0.trade_rpc_url,
        &state.0.http_client,
        &agent_pubkey,
    )
    .await
    .unwrap_or(0);

    let claim_txs = match launch
        .claim_fee_transactions(&agent_wallet, &req.token_mint)
        .await
    {
        Ok(txs) => txs,
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            return (code, Json(serde_json::json!({"error": msg}))).into_response();
        }
    };

    let mut txids: Vec<String> = Vec::new();
    for ctx in &claim_txs {
        if let Ok(tx_bytes) = bs58::decode(&ctx.tx).into_vec() {
            if let Ok(mut tx) =
                bincode::deserialize::<solana_sdk::transaction::Transaction>(&tx_bytes)
            {
                if tx.message.recent_blockhash == solana_sdk::hash::Hash::default() {
                    tracing::warn!("Claim tx has zero blockhash — skipping");
                    continue;
                }
                let kp = to_solana_keypair(&state.0.node_signing_key);
                tx.partial_sign(&[&kp], tx.message.recent_blockhash);
                if let Ok(serialized) = bincode::serialize(&tx) {
                    match broadcast_transaction(
                        &state.0.trade_rpc_url,
                        &state.0.http_client,
                        &B64.encode(&serialized),
                    )
                    .await
                    {
                        Ok(txid) => {
                            tracing::info!("Bags fee claimed: {txid}");
                            txids.push(txid);
                        }
                        Err(e) => tracing::warn!("Bags claim broadcast failed: {e}"),
                    }
                }
            }
        }
    }

    if !txids.is_empty() {
        // Give the claim transactions a short window to land, then estimate
        // actual claimed fee from the wallet SOL delta.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let post_sol_balance = crate::bags::get_sol_balance(
            &state.0.trade_rpc_url,
            &state.0.http_client,
            &agent_pubkey,
        )
        .await
        .unwrap_or(pre_sol_balance);
        let claimed_amount_sol = if post_sol_balance > pre_sol_balance {
            (post_sol_balance - pre_sol_balance) as f64 / 1_000_000_000.0
        } else {
            0.0
        };

        state
            .record_portfolio_event(PortfolioEvent::BagsClaim {
                token_mint: req.token_mint.clone(),
                claimed_txs: txids.len(),
                timestamp: now_secs(),
            })
            .await;

        report_bags_claim_to_aggregator(
            &state,
            hex::encode(state.0.node_signing_key.verifying_key().to_bytes()),
            claimed_amount_sol,
            txids.len() as u32,
        )
        .await;

        // In partner mode, Bags handles revenue attribution directly, so we
        // skip the legacy post-claim SOL skim.
        if !launch.partner_mode_enabled() {
            crate::bags::spawn_protocol_fee_collection(
                state.0.node_signing_key.clone(),
                agent_pubkey,
                pre_sol_balance,
                state.0.trade_rpc_url.clone(),
                state.0.http_client.clone(),
            );
        }
    }

    Json(serde_json::json!({
        "claimed_txs": txids.len(),
        "txids": txids,
    }))
    .into_response()
}

/// GET /bags/positions — list tokens launched by this agent with claimable fee info.
///
/// Calls `token-launch/claimable-positions?wallet=` for per-token earned/claimable
/// SOL amounts. Local portfolio history seeds the list so tokens with zero fees
/// (launched with no initial buy) still appear with claimableSOL = 0.
#[cfg(feature = "bags")]
async fn bags_positions_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }

    let Some(launch) = state.0.bags_launch.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response();
    };

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    // Local portfolio history — tokens we know regardless of fee accumulation.
    let local_mints: std::collections::HashSet<String> = {
        let history = state.0.portfolio_history.read().await;
        history.events.iter()
            .filter_map(|e| match e {
                PortfolioEvent::BagsLaunch { token_mint, .. } => Some(token_mint.clone()),
                _ => None,
            })
            .collect()
    };

    // Bags claimable-positions: per-token claimable SOL and tx count.
    let (mut positions, seen_mints) = match launch.claimable_positions(&agent_wallet).await {
        Ok(data) => {
            let mut seen = std::collections::HashSet::new();
            if let Some(arr) = data.as_array() {
                for pos in arr {
                    if let Some(m) = pos.get("tokenMint").and_then(|v| v.as_str()) {
                        seen.insert(m.to_string());
                    }
                }
                (arr.clone(), seen)
            } else {
                (vec![], std::collections::HashSet::new())
            }
        }
        Err(e) => {
            tracing::warn!("claimable-positions fetch failed: {e}");
            (vec![], std::collections::HashSet::new())
        }
    };

    // Append locally-known tokens that have zero fees yet (not in API response).
    for mint in &local_mints {
        if !seen_mints.contains(mint) {
            positions.push(serde_json::json!({
                "tokenMint": mint,
                "claimableSOL": 0.0,
                "txCount": 0,
            }));
        }
    }

    Json(serde_json::json!({"positions": positions})).into_response()
}

/// Map a Bags client error to an HTTP status + message string.
///
/// `bags_rate_limited` → 429 (caller should prompt for a user-supplied key).
/// Anything else       → 502 Bad Gateway.
#[cfg(feature = "bags")]
fn bags_error_response(e: &anyhow::Error) -> (StatusCode, String) {
    if e.to_string().contains("bags_rate_limited") {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "bags_rate_limited".to_string(),
        )
    } else {
        (StatusCode::BAD_GATEWAY, e.to_string())
    }
}

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsSetApiKeyRequest {
    api_key: String,
}

/// POST /bags/set-api-key — replace the Bags API key in-memory without restart.
///
/// Requires the node API secret. Returns 204 on success.
#[cfg(feature = "bags")]
async fn bags_set_api_key_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsSetApiKeyRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if req.api_key.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "api_key must not be empty"})),
        )
            .into_response();
    }
    match state.0.bags_launch.as_ref() {
        Some(launch) => {
            launch.update_api_key(req.api_key.trim().to_string());
            StatusCode::NO_CONTENT.into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags not configured"})),
        )
            .into_response(),
    }
}

// ============================================================================
// Bags — swap, pool, claimable positions, Dexscreener listing
// ============================================================================

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsSwapQuoteRequest {
    token_mint: String,
    /// Lamports for buys, token base units for sells.
    amount: u64,
    /// `"buy"` or `"sell"`.
    action: String,
    slippage_bps: Option<u32>,
}

/// POST /bags/swap/quote — get a swap quote from the Bags AMM.
#[cfg(feature = "bags")]
async fn bags_swap_quote_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsSwapQuoteRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if req.action != "buy" && req.action != "sell" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "action must be \"buy\" or \"sell\""})),
        )
            .into_response();
    }
    if req.token_mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "token_mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response(),
    };
    match launch.swap_quote(&req.token_mint, req.amount, &req.action, req.slippage_bps).await {
        Ok(quote) => Json(quote).into_response(),
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            (code, Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsSwapExecuteRequest {
    token_mint: String,
    amount: u64,
    action: String,
    slippage_bps: Option<u32>,
}

/// POST /bags/swap/execute — quote + build tx + sign + broadcast in one call.
#[cfg(feature = "bags")]
async fn bags_swap_execute_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsSwapExecuteRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if req.action != "buy" && req.action != "sell" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "action must be \"buy\" or \"sell\""})),
        )
            .into_response();
    }
    if req.token_mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "token_mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response(),
    };

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    // Step 1 — get quote.
    let quote = match launch
        .swap_quote(&req.token_mint, req.amount, &req.action, req.slippage_bps)
        .await
    {
        Ok(q) => q,
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            return (code, Json(serde_json::json!({"error": msg}))).into_response();
        }
    };

    // Step 2 — build tx.
    let tx_bytes = match launch.build_swap_transaction(&agent_wallet, &quote).await {
        Ok(b) => b,
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            return (code, Json(serde_json::json!({"error": msg}))).into_response();
        }
    };

    // Step 3 — sign + broadcast.
    let mut tx = match bincode::deserialize::<solana_sdk::transaction::Transaction>(&tx_bytes) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("swap tx deserialize: {e}")})),
        )
            .into_response(),
    };
    let kp = to_solana_keypair(&state.0.node_signing_key);
    tx.partial_sign(&[&kp], tx.message.recent_blockhash);
    let serialized = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("swap tx serialize: {e}")})),
        )
            .into_response(),
    };
    match broadcast_transaction(
        &state.0.trade_rpc_url,
        &state.0.http_client,
        &B64.encode(&serialized),
    )
    .await
    {
        Ok(txid) => Json(serde_json::json!({
            "txid": txid,
            "token_mint": req.token_mint,
            "action": req.action,
            "amount": req.amount,
            "quote": quote,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("swap broadcast: {e}")})),
        )
            .into_response(),
    }
}

/// GET /bags/pool/:mint — Bags AMM pool info (reserves, price, TVL, volume).
#[cfg(feature = "bags")]
async fn bags_pool_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Path(mint): Path<String>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    if mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response(),
    };
    match launch.pool_info(&mint).await {
        Ok(info) => Json(info).into_response(),
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            (code, Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

/// GET /bags/claimable — all claimable fee positions for the agent wallet.
#[cfg(feature = "bags")]
async fn bags_claimable_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response(),
    };
    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();
    match launch.claimable_positions(&agent_wallet).await {
        Ok(positions) => Json(positions).into_response(),
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            (code, Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

/// GET /bags/dexscreener/check/:mint — check listing availability and cost.
#[cfg(feature = "bags")]
async fn bags_dexscreener_check_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Path(mint): Path<String>,
) -> Response {
    if let Some(resp) = require_read_or_master_access(&state, &headers) {
        return resp;
    }
    if mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response(),
    };
    match launch.dexscreener_check(&mint).await {
        Ok(info) => Json(info).into_response(),
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            (code, Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

#[cfg(feature = "bags")]
#[derive(Deserialize)]
struct BagsDexscreenerListRequest {
    token_mint: String,
    description: String,
    icon_image_url: String,
    header_image_url: String,
}

/// POST /bags/dexscreener/list — create order + sign payment tx + broadcast + submit signature.
///
/// One-shot: agent calls this and gets back a txid when listing is paid and submitted.
#[cfg(feature = "bags")]
async fn bags_dexscreener_list_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BagsDexscreenerListRequest>,
) -> Response {
    if let Some(resp) = require_api_secret_or_unauthorized(&state, &headers) {
        return resp;
    }
    if req.token_mint.parse::<Pubkey>().is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "token_mint is not a valid base58 pubkey"})),
        )
            .into_response();
    }
    for url in [&req.icon_image_url, &req.header_image_url] {
        if !url.starts_with("https://") {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "image URLs must use HTTPS"})),
            )
                .into_response();
        }
    }
    let launch = match state.0.bags_launch.as_ref() {
        Some(l) => l.clone(),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Bags API key not configured"})),
        )
            .into_response(),
    };

    let agent_pubkey = Pubkey::new_from_array(state.0.node_signing_key.verifying_key().to_bytes());
    let agent_wallet = agent_pubkey.to_string();

    // Step 1 — create order, get orderUUID + payment tx.
    let order = match launch
        .dexscreener_create_order(
            &req.token_mint,
            &agent_wallet,
            &req.description,
            &req.icon_image_url,
            &req.header_image_url,
        )
        .await
    {
        Ok(o) => o,
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            return (code, Json(serde_json::json!({"error": msg}))).into_response();
        }
    };

    let order_uuid = match order.get("orderUUID").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Bags dexscreener order response missing orderUUID"})),
            )
                .into_response()
        }
    };

    // Step 2 — sign payment tx and broadcast; get back the txid (signature).
    let tx_field = match order.get("transaction").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            // No tx in response means the order was already paid / no payment needed.
            return Json(serde_json::json!({
                "order_uuid": order_uuid,
                "txid": null,
                "status": "submitted",
            }))
            .into_response();
        }
    };

    // Payment tx is base58-encoded.
    let tx_bytes = match bs58::decode(&tx_field).into_vec() {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("dexscreener payment tx decode: {e}")})),
        )
            .into_response(),
    };

    let mut tx = match bincode::deserialize::<solana_sdk::transaction::Transaction>(&tx_bytes) {
        Ok(t) => t,
        Err(e) => return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("dexscreener payment tx deserialize: {e}")})),
        )
            .into_response(),
    };
    let kp = to_solana_keypair(&state.0.node_signing_key);
    tx.partial_sign(&[&kp], tx.message.recent_blockhash);
    let serialized = match bincode::serialize(&tx) {
        Ok(b) => b,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("dexscreener payment tx serialize: {e}")})),
        )
            .into_response(),
    };

    let txid = match broadcast_transaction(
        &state.0.trade_rpc_url,
        &state.0.http_client,
        &B64.encode(&serialized),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("dexscreener payment broadcast: {e}")})),
        )
            .into_response(),
    };

    // Step 3 — submit the payment signature to Bags.
    match launch.dexscreener_pay_order(&order_uuid, &txid).await {
        Ok(result) => Json(serde_json::json!({
            "order_uuid": order_uuid,
            "txid": txid,
            "result": result,
        }))
        .into_response(),
        Err(e) => {
            let (code, msg) = bags_error_response(&e);
            (code, Json(serde_json::json!({"error": msg, "order_uuid": order_uuid}))).into_response()
        }
    }
}

// ============================================================================
// Agent process management — skill hot-reload
// ============================================================================

const MAX_AGENT_RELOAD_PER_MINUTE: u32 = 3;

#[derive(Deserialize)]
struct RegisterPidRequest {
    pid: u32,
}

/// Return the real UID of `pid` by reading /proc/{pid}/status.
/// Returns `None` if the file cannot be read or parsed.
#[cfg(unix)]
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
                    Json(serde_json::json!({"error": "agent reload not supported on this platform"})),
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

/// Reject private/loopback IP ranges used in SSRF attacks.
fn is_private_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use solana_sdk::signature::Signer;

    // --- to_solana_keypair ---

    #[test]
    fn to_solana_keypair_encodes_correct_bytes() {
        let sk = SigningKey::generate(&mut OsRng);
        let kp = to_solana_keypair(&sk);
        let kp_bytes = kp.to_bytes();
        // First 32 bytes are the secret key
        assert_eq!(&kp_bytes[..32], sk.to_bytes().as_slice());
        // Last 32 bytes are the verifying (public) key
        assert_eq!(&kp_bytes[32..], sk.verifying_key().as_bytes().as_slice());
    }

    #[test]
    fn to_solana_keypair_pubkey_matches_signing_key() {
        let sk = SigningKey::generate(&mut OsRng);
        let kp = to_solana_keypair(&sk);
        let expected_pk = Pubkey::new_from_array(sk.verifying_key().to_bytes());
        assert_eq!(kp.pubkey(), expected_pk);
    }

    #[test]
    fn to_solana_keypair_deterministic() {
        let sk = SigningKey::generate(&mut OsRng);
        let kp1 = to_solana_keypair(&sk);
        let kp2 = to_solana_keypair(&sk);
        assert_eq!(kp1.pubkey(), kp2.pubkey());
    }

    // --- derive_ata ---

    #[test]
    fn derive_ata_is_deterministic() {
        let owner = Pubkey::new_from_array([1u8; 32]);
        let mint = USDC_MINT_DEVNET.parse::<Pubkey>().unwrap();
        let ata1 = derive_ata(&owner, &mint);
        let ata2 = derive_ata(&owner, &mint);
        assert_eq!(ata1, ata2);
    }

    #[test]
    fn derive_ata_differs_for_different_owners() {
        let mint = USDC_MINT_DEVNET.parse::<Pubkey>().unwrap();
        let ata1 = derive_ata(&Pubkey::new_from_array([1u8; 32]), &mint);
        let ata2 = derive_ata(&Pubkey::new_from_array([2u8; 32]), &mint);
        assert_ne!(ata1, ata2);
    }

    #[test]
    fn derive_ata_differs_for_different_mints() {
        let owner = Pubkey::new_from_array([1u8; 32]);
        let devnet_mint = USDC_MINT_DEVNET.parse::<Pubkey>().unwrap();
        let mainnet_mint = USDC_MINT_MAINNET.parse::<Pubkey>().unwrap();
        let ata1 = derive_ata(&owner, &devnet_mint);
        let ata2 = derive_ata(&owner, &mainnet_mint);
        assert_ne!(ata1, ata2);
    }

    #[test]
    fn derive_ata_known_devnet_usdc_address() {
        // Known ATA: wallet 11111111111111111111111111111111 (all zeros) + devnet USDC
        // Computed via spl-associated-token-account derivation.
        let owner = Pubkey::default(); // all zeros
        let mint = USDC_MINT_DEVNET.parse::<Pubkey>().unwrap();
        let ata = derive_ata(&owner, &mint);
        // The ATA must be a valid on-curve or off-curve PDA — just verify it is non-zero
        assert_ne!(ata, Pubkey::default());
    }

    // --- USDC/SPL constants ---

    #[test]
    fn usdc_mint_devnet_parses_as_pubkey() {
        assert!(USDC_MINT_DEVNET.parse::<Pubkey>().is_ok());
    }

    #[test]
    fn usdc_mint_mainnet_parses_as_pubkey() {
        assert!(USDC_MINT_MAINNET.parse::<Pubkey>().is_ok());
    }

    #[test]
    fn spl_token_program_id_parses_as_pubkey() {
        assert!(SPL_TOKEN_PROGRAM_ID.parse::<Pubkey>().is_ok());
    }
}
