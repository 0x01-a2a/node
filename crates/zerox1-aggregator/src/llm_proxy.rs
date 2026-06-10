//! LLM proxy — forwards requests to Gemini 3 Flash on behalf of agents.
//!
//! # Tiers
//! - Free:     agent's registered wallet holds < PRESENCE_THRESHOLD 01PL → capped at
//!             `free_daily_tokens` tokens/day (tracked per-agent in `llm_usage`).
//! - Eligible: agent's registered wallet holds ≥ PRESENCE_THRESHOLD 01PL → uncapped.
//!
//! All Bags.fm token-launch / trading-fee gating has been removed in the web3 strip.
//! The only on-chain read that remains is the 01PL holding check, which is a
//! lightweight Solana JSON-RPC `getTokenAccountsByOwner` call with a 5-minute cache.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(feature = "pilot")]
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
#[cfg(feature = "pilot")]
use serde_json::json;
use serde_json::Value;

#[cfg(feature = "pilot")]
use crate::api::AppState;

// ── Constants ──────────────────────────────────────────────────────────────

#[cfg(feature = "pilot")]
const GEMINI_COMPAT_URL: &str =
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";

/// Model used for all proxy requests — not configurable by callers.
#[cfg(feature = "pilot")]
const GEMINI_MODEL: &str = "gemini-3-flash-preview";

/// Solana mainnet RPC endpoint for 01PL balance checks.
#[cfg(feature = "pilot")]
const SOL_RPC: &str = "https://api.mainnet-beta.solana.com";

/// 01PL token mint on Solana mainnet.
#[cfg(feature = "pilot")]
const PILOT_TOKEN_MINT: &str = "2MchUMEvadoTbSvC4b1uLAmEhv8Yz8ngwEt24q21BAGS";

/// Minimum 01PL balance for uncapped access (500 000 tokens × 10^6 decimals).
#[cfg(feature = "pilot")]
const PRESENCE_THRESHOLD: u64 = 500_000_000_000;

/// How long to cache a wallet's 01PL eligibility result.
#[cfg(feature = "pilot")]
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of messages in a single request.
#[cfg(feature = "pilot")]
const MAX_MESSAGES: usize = 200;

// ── In-memory 01PL eligibility cache ──────────────────────────────────────

#[derive(Clone)]
pub struct PlCache(pub Arc<Mutex<HashMap<String, (bool, Instant)>>>);

impl Default for PlCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PlCache {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    #[cfg(feature = "pilot")]
    fn get(&self, wallet: &str) -> Option<bool> {
        let map = self.0.lock().unwrap();
        if let Some((eligible, ts)) = map.get(wallet) {
            if ts.elapsed() < CACHE_TTL {
                return Some(*eligible);
            }
        }
        None
    }

    #[cfg(feature = "pilot")]
    fn set(&self, wallet: &str, eligible: bool) {
        let mut map = self.0.lock().unwrap();
        map.insert(wallet.to_string(), (eligible, Instant::now()));
    }
}

// ── Request / response types ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LlmChatRequest {
    /// Hex-encoded agent Ed25519 pubkey — used for usage tracking.
    pub agent_id: String,
    /// OpenAI-compatible messages array.
    pub messages: Vec<Value>,
    /// Optional max tokens cap.
    pub max_tokens: Option<u32>,
    /// Optional temperature.
    pub temperature: Option<f32>,
}

// ── 01PL eligibility check ────────────────────────────────────────────────

#[cfg(feature = "pilot")]
async fn fetch_token_balance(
    client: &reqwest::Client,
    wallet: &str,
) -> u64 {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            { "mint": PILOT_TOKEN_MINT },
            { "encoding": "jsonParsed" }
        ]
    });

    let Ok(resp) = client
        .post(SOL_RPC)
        .json(&body)
        .timeout(Duration::from_secs(8))
        .send()
        .await
    else {
        return 0;
    };

    let Ok(json) = resp.json::<Value>().await else {
        return 0;
    };

    let accounts = json["result"]["value"].as_array().cloned().unwrap_or_default();
    let mut total: u64 = 0;
    for acct in accounts {
        if let Some(amount) = acct["account"]["data"]["parsed"]["info"]["tokenAmount"]["amount"]
            .as_str()
        {
            total += amount.parse::<u64>().unwrap_or(0);
        }
    }
    total
}

#[cfg(feature = "pilot")]
async fn check_eligible(
    client: &reqwest::Client,
    cache: &PlCache,
    wallets: &[String],
) -> bool {
    if wallets.is_empty() {
        return false;
    }

    // Fast path: any cached-eligible wallet.
    if wallets.iter().any(|w| cache.get(w) == Some(true)) {
        return true;
    }

    // Fetch wallets not yet in cache.
    let to_fetch: Vec<&str> = wallets.iter().map(String::as_str).filter(|w| cache.get(w).is_none()).collect();

    let mut combined: u64 = 0;
    for wallet in &to_fetch {
        combined += fetch_token_balance(client, wallet).await;
    }

    let eligible = combined >= PRESENCE_THRESHOLD;

    for wallet in &to_fetch {
        cache.set(wallet, eligible);
    }
    if eligible {
        for wallet in wallets.iter().map(String::as_str).filter(|w| cache.get(w) == Some(false)) {
            cache.set(wallet, true);
        }
    }

    eligible
}

// ── Handler ───────────────────────────────────────────────────────────────

#[cfg(feature = "pilot")]
pub async fn post_llm_chat(
    State(state): State<AppState>,
    Json(req): Json<LlmChatRequest>,
) -> impl IntoResponse {
    // ── Feature gate ──────────────────────────────────────────────────────
    let api_key = match &state.gemini_api_key {
        Some(k) => k.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "LLM proxy not configured on this aggregator"})),
            )
                .into_response();
        }
    };

    // ── Validate agent_id ─────────────────────────────────────────────────
    let agent_id = req.agent_id.trim().to_lowercase();
    if agent_id.len() != 64 || hex::decode(&agent_id).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "agent_id must be a 64-char hex string"})),
        )
            .into_response();
    }

    // ── Validate messages ─────────────────────────────────────────────────
    if req.messages.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "messages must not be empty"})),
        )
            .into_response();
    }
    if req.messages.len() > MAX_MESSAGES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("too many messages (max {MAX_MESSAGES})")})),
        )
            .into_response();
    }

    // ── 01PL eligibility ──────────────────────────────────────────────────
    // Holders of ≥ 500,000 01PL bypass the free-tier daily cap.
    let registered_wallets = state.store.get_agent_wallets(&agent_id);
    let eligible = check_eligible(&state.http_client, &state.pl_cache, &registered_wallets).await;

    if !eligible {
        // ── Per-agent free-tier daily cap ────────────────────────────────
        let used = state.store.llm_today_tokens(&agent_id);
        if used >= state.llm_proxy_free_daily_tokens {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "daily token limit reached",
                    "used": used,
                    "limit": state.llm_proxy_free_daily_tokens,
                    "upgrade": "hold 500,000 01PL for unlimited access",
                })),
            )
                .into_response();
        }
    }

    // ── Build Gemini request ──────────────────────────────────────────────
    // Model is fixed server-side — callers cannot select a different (more expensive) model.
    let mut gemini_body = json!({
        "model": GEMINI_MODEL,
        "messages": req.messages,
    });
    if let Some(mt) = req.max_tokens {
        gemini_body["max_tokens"] = mt.into();
    }
    if let Some(t) = req.temperature {
        gemini_body["temperature"] = t.into();
    }

    // ── Forward to Gemini ─────────────────────────────────────────────────
    let gemini_resp = state
        .http_client
        .post(GEMINI_COMPAT_URL)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .json(&gemini_body)
        .timeout(Duration::from_secs(60))
        .send()
        .await;

    let resp = match gemini_resp {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("llm_proxy: gemini request failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "upstream request failed"})),
            )
                .into_response();
        }
    };

    let status = resp.status();
    let body: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("llm_proxy: gemini response parse failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "upstream response invalid"})),
            )
                .into_response();
        }
    };

    // ── Track usage from response ─────────────────────────────────────────
    if status.is_success() {
        let tokens = body["usage"]["total_tokens"]
            .as_u64()
            .unwrap_or(0);
        if tokens > 0 {
            state.store.llm_add_usage(&agent_id, tokens);
        }
    }

    (StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
     Json(body)).into_response()
}
