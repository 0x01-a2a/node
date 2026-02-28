//! REST API handlers.

use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;

use crate::store::{
    ActivityEvent, AgentProfile, AgentRegistryEntry, CapabilityMatch, DisputeRecord, HostingNode,
    IngestEvent, NetworkStats, PendingMessage, ReputationStore,
};

// ============================================================================
// App state
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub store:          ReputationStore,
    /// Shared secret for POST /ingest/envelope.
    /// None = unauthenticated (dev/local only).
    pub ingest_secret:  Option<String>,
    /// Shared secret for POST /hosting/register.
    /// None = unauthenticated (dev/local only); set in production.
    pub hosting_secret: Option<String>,
    /// Firebase server key for sending FCM push notifications.
    /// Required for the sleeping node wake-push feature.
    /// Set via --fcm-server-key / FCM_SERVER_KEY env var.
    pub fcm_server_key: Option<String>,
    /// Shared HTTP client for FCM push calls.
    pub http_client:    reqwest::Client,
    /// Broadcast channel for real-time activity events (GET /ws/activity).
    pub activity_tx:    broadcast::Sender<ActivityEvent>,
}

// ============================================================================
// Constant-time string comparison (prevents timing attacks on the secret).
// ============================================================================

fn ct_eq(a: &str, b: &str) -> bool {
    // Compare in constant time — no early return on length mismatch to prevent
    // timing side-channels that would reveal secret length.
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

// ============================================================================
// Health
// ============================================================================

pub async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// GET /version
///
/// Returns the current expected SDK and node version.
/// Agents check this on startup and warn if their installed version is behind.
pub async fn get_version() -> impl IntoResponse {
    // SDK_VERSION is the npm package version that ships the current binary.
    // Update this string on every release — it drives the SDK update warning.
    const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
    Json(json!({
        "sdk":  SDK_VERSION,
        "node": SDK_VERSION,
    }))
}

// ============================================================================
// Network stats
// ============================================================================

/// GET /stats/network
///
/// Returns a quick summary of network-wide activity:
/// - agent_count: distinct agents seen by the aggregator
/// - interaction_count: total feedback events recorded (all-time)
/// - started_at: unix timestamp when this aggregator process started
pub async fn get_network_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats: NetworkStats = state.store.network_stats();
    Json(stats)
}

// ============================================================================
// Ingest
// ============================================================================

pub async fn ingest_envelope(
    State(state): State<AppState>,
    headers:      HeaderMap,
    Json(event):  Json<IngestEvent>,
) -> impl IntoResponse {
    // Authenticate ingest requests when a secret is configured.
    if let Some(ref secret) = state.ingest_secret {
        let expected = format!("Bearer {secret}");
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct_eq(provided, &expected) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            ).into_response();
        }
    }
    tracing::info!("Ingest: received event: {:?}", event);
    if let Some(activity) = state.store.ingest(event) {
        let _ = state.activity_tx.send(activity);
    }
    StatusCode::NO_CONTENT.into_response()
}

// ============================================================================
// Reputation
// ============================================================================

pub async fn get_reputation(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match state.store.get(&agent_id) {
        Some(rep) => Json(rep).into_response(),
        None      => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "agent not found" })),
        ).into_response(),
    }
}

// ============================================================================
// Leaderboard
// ============================================================================

#[derive(Deserialize)]
pub struct LeaderboardParams {
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize { 50 }

pub async fn get_leaderboard(
    State(state):  State<AppState>,
    Query(params): Query<LeaderboardParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let board = state.store.leaderboard(limit);
    Json(board)
}

#[derive(Deserialize)]
pub struct AgentsParams {
    #[serde(default = "default_limit")]
    limit:  usize,
    #[serde(default = "default_offset")]
    offset: usize,
    #[serde(default = "default_sort")]
    sort:   String,
}

fn default_offset() -> usize { 0 }
fn default_sort() -> String { "reputation".to_string() }

pub async fn get_agents(
    State(state):  State<AppState>,
    Query(params): Query<AgentsParams>,
) -> impl IntoResponse {
    let limit  = params.limit.min(200);
    let agents = state.store.list_agents(limit, params.offset, &params.sort);
    Json(agents)
}

// ============================================================================
// Agent Registry (BEACON tracking)
// ============================================================================

pub async fn get_registry(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.get_registry())
}

// ============================================================================
// Interactions — raw feedback graph edges for visualisation
// ============================================================================

#[derive(Deserialize)]
pub struct InteractionsParams {
    /// Filter by sender agent_id (hex).
    from:  Option<String>,
    /// Filter by target agent_id (hex).
    to:    Option<String>,
    #[serde(default = "default_interactions_limit")]
    limit: usize,
}

fn default_interactions_limit() -> usize { 100 }

/// GET /interactions[?from=<agent_id>&to=<agent_id>&limit=N]
///
/// Returns raw FEEDBACK events, newest first. Use `from`/`to` to filter
/// edges originating from or arriving at a specific agent. Maximum 1 000
/// per request.
pub async fn get_interactions(
    State(state):  State<AppState>,
    Query(params): Query<InteractionsParams>,
) -> impl IntoResponse {
    let limit  = params.limit.min(1_000);
    let result = state.store.interactions(
        params.from.as_deref(),
        params.to.as_deref(),
        limit,
    );
    Json(result)
}

// ============================================================================
// Timeseries — hourly feedback volume for charts
// ============================================================================

#[derive(Deserialize)]
pub struct TimeseriesParams {
    /// Look-back window. Accepted values: "1h", "24h", "7d", "30d".
    /// Default: "24h".
    #[serde(default = "default_window")]
    window: String,
}

fn default_window() -> String { "24h".to_string() }

fn parse_window(s: &str) -> u64 {
    match s {
        "1h"  =>     3_600,
        "7d"  =>   604_800,
        "30d" => 2_592_000,
        _     =>    86_400, // "24h" and anything unrecognised
    }
}

// ============================================================================
// Entropy
// ============================================================================

/// GET /leaderboard/anomaly[?limit=50]
///
/// Agents ranked by highest anomaly score (most recent epoch per agent).
/// Score > 0 means at least one entropy component fell below its threshold.
/// Higher score = more suspicious.
pub async fn get_anomaly_leaderboard(
    State(state):  State<AppState>,
    Query(params): Query<LeaderboardParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    Json(state.store.anomaly_leaderboard(limit))
}

/// GET /entropy/:agent_id
///
/// Latest entropy vector for the agent (the most recent epoch).
/// Returns 404 when the agent has no recorded entropy yet.
pub async fn get_entropy(
    State(state):       State<AppState>,
    Path(agent_id):     Path<String>,
) -> impl IntoResponse {
    match state.store.entropy_latest(&agent_id) {
        Some(ev) => Json(serde_json::to_value(ev).unwrap_or_default()).into_response(),
        None     => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no entropy data for agent" })),
        ).into_response(),
    }
}

#[derive(Deserialize)]
pub struct EntropyHistoryParams {
    #[serde(default = "default_entropy_limit")]
    limit: usize,
}

fn default_entropy_limit() -> usize { 30 }

/// GET /entropy/:agent_id/history[?limit=30]
///
/// All recorded entropy vectors for the agent (newest first, up to 100).
/// Useful for plotting anomaly score over time.
pub async fn get_entropy_history(
    State(state):  State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<EntropyHistoryParams>,
) -> impl IntoResponse {
    let limit  = params.limit.min(100);
    let rows   = state.store.entropy_history(&agent_id, limit);
    Json(rows)
}

/// GET /stats/timeseries[?window=24h]
///
/// Returns hourly feedback buckets (bucket = unix timestamp of window start).
/// Each bucket contains feedback_count, positive_count, negative_count,
/// dispute_count. Useful for activity charts.
pub async fn get_timeseries(
    State(state):  State<AppState>,
    Query(params): Query<TimeseriesParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(&params.window);
    Json(state.store.timeseries(window_secs))
}

// ============================================================================
// GAP-03: Rolling entropy — patient cartel detection
// ============================================================================

#[derive(Deserialize)]
pub struct RollingEntropyParams {
    #[serde(default = "default_rolling_window")]
    window: u32,
}

fn default_rolling_window() -> u32 { 10 }

/// GET /entropy/{agent_id}/rolling[?window=10]
pub async fn get_rolling_entropy(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
    Query(params):  Query<RollingEntropyParams>,
) -> impl IntoResponse {
    let window = params.window.clamp(3, 100);
    Json(state.store.rolling_entropy(&agent_id, window))
}

// ============================================================================
// GAP-04: Verifier concentration
// ============================================================================

/// GET /leaderboard/verifier-concentration[?limit=50]
pub async fn get_verifier_concentration(
    State(state):  State<AppState>,
    Query(params): Query<LeaderboardParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    Json(state.store.verifier_concentration(limit))
}

// ============================================================================
// GAP-02: Ownership clustering
// ============================================================================

/// GET /leaderboard/ownership-clusters
pub async fn get_ownership_clusters(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.ownership_clusters())
}

// ============================================================================
// GAP-05: Calibrated β parameters
// ============================================================================

/// GET /params/calibrated
pub async fn get_calibrated_params(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.calibrated_params())
}

// ============================================================================
// GAP-06: SRI / circuit breaker
// ============================================================================

/// GET /system/sri
pub async fn get_sri_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.sri_status())
}

// ============================================================================
// GAP-08: Required stake
// ============================================================================

/// GET /stake/required/{agent_id}
pub async fn get_required_stake(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    Json(state.store.required_stake(&agent_id))
}

// ============================================================================
// GAP-02: Capital flow graph
// ============================================================================

#[derive(Deserialize)]
pub struct FlowParams {
    /// Look-back window — same values as timeseries: "1h", "24h", "7d", "30d".
    #[serde(default = "default_flow_window")]
    window: String,
    #[serde(default = "default_flow_limit")]
    limit: usize,
}

fn default_flow_window() -> String { "30d".to_string() }
fn default_flow_limit()  -> usize  { 500 }

/// GET /graph/flow[?window=30d&limit=500]
///
/// Directed capital flow edges: (from, to, positive_flow, interaction_count).
/// Pairs with high mutual flow are the primary Sybil signal.
pub async fn get_flow_graph(
    State(state):  State<AppState>,
    Query(params): Query<FlowParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(&params.window);
    let limit       = params.limit.min(2_000);
    Json(state.store.capital_flow_edges(window_secs, limit))
}

/// GET /graph/clusters[?window=30d]
///
/// Ownership clusters detected via mutual positive-feedback analysis.
/// Each cluster's `c_coefficient` feeds β₃ in the stake multiplier.
pub async fn get_flow_clusters(
    State(state):  State<AppState>,
    Query(params): Query<FlowParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(&params.window);
    Json(state.store.flow_clusters(window_secs))
}

/// GET /graph/agent/{agent_id}[?window=30d]
///
/// Graph position for one agent: cluster membership, C coefficient,
/// concentration ratio, and top counterparties.
pub async fn get_agent_flow(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
    Query(params):  Query<FlowParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(&params.window);
    Json(state.store.agent_flow_info(&agent_id, window_secs))
}

// ============================================================================
// GAP-07: Raw envelope retrieval for Merkle proof construction
// ============================================================================

#[derive(Deserialize)]
pub struct EpochPath {
    agent_id: String,
    epoch:    u64,
}

/// GET /epochs/{agent_id}/{epoch}/envelopes
///
/// Returns ordered raw CBOR envelope bytes for a specific agent epoch.
/// Used by the challenger bot to construct Merkle inclusion proofs.
/// Up to 1000 entries, ordered by sequence (node's log order).
pub async fn get_epoch_envelopes(
    State(state):  State<AppState>,
    Path(params):  Path<EpochPath>,
) -> impl IntoResponse {
    Json(state.store.epoch_envelopes(&params.agent_id, params.epoch))
}

// ============================================================================
// Capability discovery (ADVERTISE indexing)
// ============================================================================

#[derive(Deserialize)]
pub struct SearchParams {
    /// Capability name to search for (e.g. "translation", "price-feed").
    capability: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// GET /agents/search?capability=<name>[&limit=50]
///
/// Returns agents that have advertised the given capability, newest first.
/// Agents must have broadcast an ADVERTISE message with a matching
/// capabilities JSON array to appear here.
pub async fn search_agents(
    State(state):  State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let limit: usize = params.limit.min(200);
    // Sanitise capability string: alphanumeric + dash/underscore, max 64 chars.
    let cap = params.capability.trim().to_lowercase();
    if cap.is_empty() || cap.len() > 64 || !cap.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid capability name" })),
        ).into_response();
    }
    let results: Vec<CapabilityMatch> = state.store.search_by_capability(&cap, limit);
    Json(results).into_response()
}

// ============================================================================
// Agent full profile
// ============================================================================

/// GET /agents/{agent_id}/profile
///
/// Returns reputation + entropy + capabilities + recent disputes + name in one call.
/// Avoids 4 separate round trips for dashboard use.
pub async fn get_agent_profile(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    if agent_id.len() != 64 || !agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid agent_id" })),
        ).into_response();
    }
    let profile: AgentProfile = state.store.agent_profile(&agent_id);
    Json(profile).into_response()
}

// ============================================================================
// Agent search by name
// ============================================================================

#[derive(Deserialize)]
pub struct NameSearchParams {
    name: String,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// GET /agents/search/name?name=X[&limit=50]
///
/// Case-insensitive substring search against names broadcast in BEACON messages.
pub async fn search_agents_by_name(
    State(state):  State<AppState>,
    Query(params): Query<NameSearchParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let name  = params.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid name" })),
        ).into_response();
    }
    let results: Vec<AgentRegistryEntry> = state.store.search_by_name(&name, limit);
    Json(results).into_response()
}

// ============================================================================
// Sender-side interactions
// ============================================================================

/// GET /interactions/by/{agent_id}[?limit=100]
///
/// All interactions where the given agent was the *sender* (outbound history).
/// Complements GET /interactions?to=X which shows inbound.
pub async fn get_interactions_by(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
    Query(params):  Query<InteractionsParams>,
) -> impl IntoResponse {
    let limit  = params.limit.min(1_000);
    let result = state.store.interactions(Some(&agent_id), None, limit);
    Json(result)
}

// ============================================================================
// Disputes
// ============================================================================

#[derive(Deserialize)]
pub struct DisputeParams {
    #[serde(default = "default_limit")]
    limit: usize,
}

/// GET /disputes/{agent_id}[?limit=50]
///
/// Returns recent disputes targeting the given agent, newest first.
/// Used by the challenger bot to identify agents that should be investigated.
pub async fn get_disputes(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
    Query(params):  Query<DisputeParams>,
) -> impl IntoResponse {
    let limit: usize = params.limit.min(500);
    let results: Vec<DisputeRecord> = state.store.disputes_for_agent(&agent_id, limit);
    Json(results)
}

// ============================================================================
// FCM / Sleeping node
// ============================================================================

#[derive(Deserialize)]
pub struct FcmRegisterBody {
    pub agent_id:  String,
    pub fcm_token: String,
}

#[derive(Deserialize)]
pub struct FcmSleepBody {
    pub agent_id: String,
    pub sleeping: bool,
}

#[derive(Deserialize)]
pub struct PostPendingBody {
    /// Hex-encoded agent_id of the sender.
    pub from:     String,
    /// Protocol message type, e.g. "PROPOSE".
    pub msg_type: String,
    /// Base64-encoded raw CBOR envelope bytes.
    pub payload:  String,
}

/// POST /fcm/register
///
/// Register or update the FCM device token for an agent.
/// Called by a mobile node on startup to enable push-wake behaviour.
pub async fn fcm_register(
    State(state): State<AppState>,
    Json(body):   Json<FcmRegisterBody>,
) -> impl IntoResponse {
    if body.agent_id.len() != 64 || !body.agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    state.store.store_fcm_token(body.agent_id.clone(), body.fcm_token);
    tracing::debug!("FCM token registered for agent {}", body.agent_id);
    StatusCode::OK.into_response()
}

/// POST /fcm/sleep
///
/// Mark an agent as sleeping (offline) or awake.
/// Called by a mobile node before backgrounding and on wakeup.
pub async fn fcm_sleep(
    State(state): State<AppState>,
    Json(body):   Json<FcmSleepBody>,
) -> impl IntoResponse {
    if body.agent_id.len() != 64 || !body.agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    state.store.set_sleeping(&body.agent_id, body.sleeping);
    tracing::debug!(
        "Agent {} sleep state → {}",
        body.agent_id,
        if body.sleeping { "sleeping" } else { "awake" }
    );
    StatusCode::OK.into_response()
}

/// GET /agents/{agent_id}/sleeping
///
/// Returns whether the agent is currently in sleep mode.
/// Senders check this before posting a pending message.
pub async fn get_sleep_status(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    Json(serde_json::json!({ "sleeping": state.store.is_sleeping(&agent_id) }))
}

/// GET /agents/{agent_id}/pending
///
/// Drain and return all pending messages held for this agent.
/// The queue is cleared on retrieval — messages are delivered exactly once.
/// Returns 200 with an empty array when there are no pending messages.
pub async fn get_pending(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    let msgs = state.store.drain_pending(&agent_id);
    // Mark the agent as awake now that it is polling.
    state.store.set_sleeping(&agent_id, false);
    Json(msgs)
}

/// POST /agents/{agent_id}/pending
///
/// Submit a message to be held for a sleeping agent.
/// If the agent has a registered FCM token and is sleeping, a push
/// notification is fired immediately to wake the app.
pub async fn post_pending(
    State(state):   State<AppState>,
    Path(agent_id): Path<String>,
    Json(body):     Json<PostPendingBody>,
) -> impl IntoResponse {
    if agent_id.len() != 64 || !agent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let msg = PendingMessage {
        id:       format!("{ts:016x}"),
        from:     body.from.clone(),
        msg_type: body.msg_type.clone(),
        payload:  body.payload,
        ts:       (ts / 1_000_000_000) as u64,
    };

    state.store.push_pending(&agent_id, msg);

    // Fire FCM push if the agent is sleeping and has a token.
    if state.store.is_sleeping(&agent_id) {
        if let Some(token) = state.store.get_fcm_token(&agent_id) {
            if let Some(ref fcm_key) = state.fcm_server_key {
                let client  = state.http_client.clone();
                let key     = fcm_key.clone();
                let aid     = agent_id.clone();
                let from    = body.from.clone();
                let msgtype = body.msg_type.clone();
                tokio::spawn(async move {
                    send_fcm_push(&key, &token, &aid, &from, &msgtype, &client).await;
                });
            }
        }
    }

    StatusCode::ACCEPTED.into_response()
}

// ============================================================================
// Activity feed
// ============================================================================

#[derive(Deserialize)]
pub struct ActivityParams {
    #[serde(default = "default_activity_limit")]
    limit:  usize,
    before: Option<i64>,
}

fn default_activity_limit() -> usize { 50 }

/// GET /activity[?limit=50&before=<id>]
///
/// Returns recent activity events (JOIN, FEEDBACK, DISPUTE, VERDICT), newest first.
/// Use `before=<id>` for cursor-based pagination.
pub async fn get_activity(
    State(state):  State<AppState>,
    Query(params): Query<ActivityParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    Json(state.store.list_activity(limit, params.before))
}

/// GET /ws/activity
///
/// WebSocket endpoint that streams activity events in real-time.
/// Sends JSON-encoded ActivityEvent frames as they are ingested.
pub async fn ws_activity(
    ws:           WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        use axum::extract::ws::Message;
        let mut rx = state.activity_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if let Ok(text) = serde_json::to_string(&ev) {
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Skip missed events and continue.
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Fire a Firebase Cloud Messaging push to wake a sleeping node.
///
/// Uses the FCM legacy HTTP API (v1 API requires OAuth2 which adds
/// unnecessary complexity for this use-case).
async fn send_fcm_push(
    fcm_key:      &str,
    device_token: &str,
    agent_id:     &str,
    from:         &str,
    msg_type:     &str,
    client:       &reqwest::Client,
) {
    let payload = serde_json::json!({
        "to": device_token,
        "data": {
            "action":   "wake",
            "agent_id": agent_id,
            "from":     from,
            "msg_type": msg_type,
        },
        "notification": {
            "title": "0x01 — New job offer",
            "body":  format!("{msg_type} from {}", &from[..8.min(from.len())]),
        },
    });

    match client
        .post("https://fcm.googleapis.com/fcm/send")
        .header("Authorization", format!("key={fcm_key}"))
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!("FCM push sent for agent {agent_id}");
        }
        Ok(resp) => {
            tracing::warn!("FCM push HTTP {} for agent {agent_id}", resp.status());
        }
        Err(e) => {
            tracing::warn!("FCM push error for agent {agent_id}: {e}");
        }
    }
}

// ============================================================================
// Hosting node registry
// ============================================================================

#[derive(Deserialize)]
pub struct HostingRegisterBody {
    node_id: String,
    name:    String,
    fee_bps: u32,
    api_url: String,
}

/// Validate that a host `api_url` is safe to store and surface to mobile clients.
///
/// Requirements:
///   - Parseable as an absolute URL
///   - Scheme is `http` or `https`
///   - No loopback / link-local / unspecified addresses (prevents SSRF when
///     mobile probes the URL)
///   - Length ≤ 256 bytes (prevents database bloat)
fn validate_host_api_url(url: &str) -> Result<(), &'static str> {
    if url.len() > 256 {
        return Err("api_url exceeds 256 characters");
    }

    // Must be a parseable absolute URL with http or https scheme.
    let parsed: reqwest::Url = url.parse().map_err(|_| "api_url is not a valid URL")?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("api_url scheme must be http or https"),
    }

    // Reject private / loopback / link-local hosts to prevent SSRF from
    // mobile clients that blindly fetch the advertised URL.
    if let Some(host) = parsed.host() {
        let host_str = host.to_string();

        // Loopback and unspecified.
        if host_str == "localhost"
            || host_str == "::1"
            || host_str.starts_with("127.")
            || host_str == "0.0.0.0"
        {
            return Err("api_url must not be a loopback address");
        }

        // Private RFC-1918 ranges (simple prefix checks).
        if host_str.starts_with("10.")
            || host_str.starts_with("192.168.")
            || is_rfc1918_172(&host_str)
        {
            return Err("api_url must not be a private IP address");
        }

        // Link-local.
        if host_str.starts_with("169.254.") || host_str.starts_with("fe80:") {
            return Err("api_url must not be a link-local address");
        }
    } else {
        return Err("api_url has no host");
    }

    Ok(())
}

fn is_rfc1918_172(host: &str) -> bool {
    // 172.16.0.0/12 = 172.16.x.x – 172.31.x.x
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 2 || parts[0] != "172" { return false; }
    if let Ok(second) = parts[1].parse::<u8>() {
        return (16..=31).contains(&second);
    }
    false
}

/// POST /hosting/register — called by host nodes on startup and every 60s.
///
/// Requires `Authorization: Bearer <hosting_secret>` when `--hosting-secret`
/// is configured on the aggregator. Validates `api_url` format to prevent
/// SSRF vectors from reaching mobile clients.
pub async fn post_hosting_register(
    State(state): State<AppState>,
    headers:      HeaderMap,
    Json(body):   Json<HostingRegisterBody>,
) -> impl IntoResponse {
    // Bearer token auth (if configured).
    if let Some(ref secret) = state.hosting_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, secret) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    // Validate api_url before persisting.
    if let Err(e) = validate_host_api_url(&body.api_url) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e })),
        ).into_response();
    }

    state.store.register_hosting_node(&body.node_id, &body.name, body.fee_bps, &body.api_url);
    StatusCode::OK.into_response()
}

/// GET /hosting/nodes — returns hosting nodes seen within the last 120 seconds.
pub async fn get_hosting_nodes(State(state): State<AppState>) -> impl IntoResponse {
    let nodes: Vec<HostingNode> = state.store.list_hosting_nodes();
    Json(nodes)
}
