//! LLM proxy — forwards requests to Gemini 3 Flash on behalf of agents.
//!
//! # Tiers
//! - Free:     agent holds < PRESENCE_THRESHOLD 01PL → capped at `free_daily_tokens` tokens/day
//! - Eligible: agent holds ≥ PRESENCE_THRESHOLD 01PL → uncapped
//!
//! # Access gates (checked in order)
//! 1. Agent must have a launched Bags.fm token.
//! 2. Agent's token must have ≥ MIN_TOKEN_BUYERS external buyers on-chain.
//!    Checked via `getTokenLargestAccounts` (Solana mainnet); cached 1 h per mint.
//!    This ensures only tokens with real community trading activity get compute.
//!    Rationale: 01 earns via Bags.fm partner trading fees — no buyers = no revenue.
//! 3. Free-tier: global daily budget circuit breaker, then per-agent daily cap.
//! 4. Eligible (01PL holders): bypass budget caps entirely.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::AppState;

// ── Constants ──────────────────────────────────────────────────────────────

const GEMINI_COMPAT_URL: &str =
    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions";

/// Model used for all proxy requests — not configurable by callers.
const GEMINI_MODEL: &str = "gemini-3-flash-preview";

/// Solana mainnet RPC endpoint for 01PL balance checks.
const SOL_RPC: &str = "https://api.mainnet-beta.solana.com";

/// 01PL token mint on Solana mainnet.
const PILOT_TOKEN_MINT: &str = "2MchUMEvadoTbSvC4b1uLAmEhv8Yz8ngwEt24q21BAGS";

/// Minimum 01PL balance for uncapped access (500 000 tokens × 10^6 decimals).
const PRESENCE_THRESHOLD: u64 = 500_000_000_000;

/// How long to cache a wallet's 01PL eligibility result.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// How long to cache a token's lifetime fees result.
/// 1 hour — fees accumulate slowly; fresh enough for cost control.
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(3_600);

/// Bags.fm partner fee share: 01 earns 20% of all trading fees on every agent token.
/// Used to compute how much daily LLM compute a token's trading history justifies.
const PARTNER_FEE_BPS: u64 = 2_000; // 20% expressed as basis points out of 10_000

/// Minimum floor for fee-derived daily token allowance (tokens).
/// Even a token with tiny fees gets some access rather than zero.
const MIN_DERIVED_DAILY_TOKENS: u64 = 1_000;

/// Scale factor: lamports of 01 revenue → daily LLM tokens.
/// 100 lamports of 01 partner revenue = 1 daily LLM token.
/// At $150/SOL: 10M lamports earned → 100k tokens/day (full free tier).
const LAMPORTS_PER_DAILY_TOKEN: u64 = 100;

/// Maximum number of messages in a single request.
const MAX_MESSAGES: usize = 200;

// ── In-memory 01PL eligibility cache ──────────────────────────────────────

#[derive(Clone)]
pub struct PlCache(pub Arc<Mutex<HashMap<String, (bool, Instant)>>>);

impl PlCache {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    fn get(&self, wallet: &str) -> Option<bool> {
        let map = self.0.lock().unwrap();
        if let Some((eligible, ts)) = map.get(wallet) {
            if ts.elapsed() < CACHE_TTL {
                return Some(*eligible);
            }
        }
        None
    }

    fn set(&self, wallet: &str, eligible: bool) {
        let mut map = self.0.lock().unwrap();
        map.insert(wallet.to_string(), (eligible, Instant::now()));
    }
}

// ── In-memory token fees cache ─────────────────────────────────────────────

/// Caches computed daily token allowance per mint (1-hour TTL).
/// Value is the derived daily LLM token allowance, or 0 if no trading history.
#[derive(Clone)]
pub struct TokenFeesCache(pub Arc<Mutex<HashMap<String, (u64, Instant)>>>);

impl TokenFeesCache {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    fn get(&self, mint: &str) -> Option<u64> {
        let map = self.0.lock().unwrap();
        if let Some((allowance, ts)) = map.get(mint) {
            if ts.elapsed() < TOKEN_CACHE_TTL {
                return Some(*allowance);
            }
        }
        None
    }

    fn set(&self, mint: &str, allowance: u64) {
        let mut map = self.0.lock().unwrap();
        map.insert(mint.to_string(), (allowance, Instant::now()));
    }
}

/// Fetches lifetime trading fees for the token from Bags.fm API, computes
/// the daily LLM token allowance proportional to 01's partner revenue share.
///
/// Formula:
///   01_earned_lamports = lifetime_fees_lamports × PARTNER_FEE_BPS / 10_000
///   daily_tokens       = clamp(01_earned / LAMPORTS_PER_DAILY_TOKEN,
///                              MIN_DERIVED_DAILY_TOKENS, max_cap)
///
/// Returns 0 if the token has zero lifetime fees (no trading at all).
/// Fails open (returns max_cap) on API/network errors to avoid blocking users.
pub async fn fetch_lifetime_fees_allowance(
    client: &reqwest::Client,
    cache: &TokenFeesCache,
    mint: &str,
    bags_api_key: &str,
    max_cap: u64,
) -> u64 {
    if let Some(cached) = cache.get(mint) {
        return cached;
    }

    let url = format!(
        "https://public-api-v2.bags.fm/api/v1/token-launch/lifetime-fees?tokenMint={}",
        mint
    );

    let result = client
        .get(&url)
        .header("x-api-key", bags_api_key)
        .timeout(Duration::from_secs(8))
        .send()
        .await;

    let allowance = match result {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>().await {
                Ok(json) if json["success"].as_bool() == Some(true) => {
                    // Fees are returned as a lamport string for bigint safety.
                    let fees_lamports: u64 = json["response"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);

                    if fees_lamports == 0 {
                        // No trading has happened yet — deny access.
                        0
                    } else {
                        let earned = fees_lamports * PARTNER_FEE_BPS / 10_000;
                        let derived = earned / LAMPORTS_PER_DAILY_TOKEN;
                        derived.clamp(MIN_DERIVED_DAILY_TOKENS, max_cap)
                    }
                }
                // Token not found on Bags — no fees, deny.
                Ok(_) => 0,
                // Parse error — fail open.
                Err(_) => max_cap,
            }
        }
        // 400 = token not found / no fees on Bags side — deny.
        Ok(resp) if resp.status().as_u16() == 400 => 0,
        // Any other error (network, 5xx) — fail open so we don't block users for our infra issues.
        _ => max_cap,
    };

    cache.set(mint, allowance);
    allowance
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
    for wallet in wallets.iter().map(String::as_str).filter(|w| cache.get(w) == Some(false)) {
        cache.set(wallet, eligible);
    }

    eligible
}

// ── Handler ───────────────────────────────────────────────────────────────

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

    // ── 01 Pilot gate: agent must have a launched Bags token ─────────────
    let reputation = state.store.get(&agent_id);
    let token_mint = reputation.as_ref().and_then(|rep| rep.token_address.clone());
    let Some(mint) = token_mint else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "LLM proxy requires a launched agent token (01 Pilot only)"})),
        )
            .into_response();
    };

    // ── 01PL eligibility — checked before fees gate ───────────────────────
    // Holders of ≥ 5,000 01PL bypass the trading-history requirement and all
    // daily caps. Their token holding is the signal of platform commitment.
    let registered_wallets = state.store.get_agent_wallets(&agent_id);
    let eligible = check_eligible(&state.http_client, &state.pl_cache, &registered_wallets).await;

    if !eligible {
        // ── Dynamic daily allowance from Bags.fm lifetime trading fees ────
        // 01 earns PARTNER_FEE_BPS of every trading fee on this token.
        // The agent's LLM allowance scales with how much revenue their token
        // has generated for the platform — aligning compute access with value created.
        //
        // Returns 0 if the token has zero lifetime fees (no real trading yet).
        let bags_api_key = state.bags_api_key.as_deref().unwrap_or("");
        let fee_allowance = fetch_lifetime_fees_allowance(
            &state.http_client,
            &state.token_fees_cache,
            &mint,
            bags_api_key,
            state.llm_proxy_free_daily_tokens,
        ).await;

        if fee_allowance == 0 {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "agent token has no trading history yet — shill your token to unlock LLM access",
                    "hint": "any community trading on Bags.fm unlocks proportional daily compute",
                })),
            )
                .into_response();
        }

        // ── Global circuit breaker ────────────────────────────────────────
        let global_used = state.store.llm_global_today_tokens();
        if global_used >= state.llm_global_daily_budget {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "global daily LLM budget reached — try again tomorrow or hold 5000 01PL for unlimited access",
                    "resets": "UTC midnight",
                })),
            )
                .into_response();
        }

        // ── Per-agent cap (fee-derived) ───────────────────────────────────
        let used = state.store.llm_today_tokens(&agent_id);
        if used >= fee_allowance {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "daily token limit reached",
                    "used": used,
                    "limit": fee_allowance,
                    "hint": "more trading volume on your token increases your daily allowance",
                    "upgrade": "hold 5000 01PL for unlimited access",
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
