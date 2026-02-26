//! REST API handlers.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::store::{CapabilityMatch, DisputeRecord, IngestEvent, NetworkStats, ReputationStore};

// ============================================================================
// App state
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub store:         ReputationStore,
    /// Shared secret for POST /ingest/envelope.
    /// None = unauthenticated (dev/local only).
    pub ingest_secret: Option<String>,
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
    state.store.ingest(event);
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

// ============================================================================
// Agents list
// ============================================================================

pub async fn get_agents(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.all_agents())
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
