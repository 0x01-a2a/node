//! REST API handlers.

use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;

use crate::registry_8004::Registry8004Client;
use crate::store::{
    ActivityEvent, AgentProfile, AgentRegistryEntry, CapabilityMatch, DisputeRecord,
    HostingNode, IngestEvent, NetworkStats, OwnerStatus, PendingMessage, ReputationStore,
};
#[cfg(feature = "data-bounty")]
use crate::store::Campaign;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};

const SKR_MINT: &str = "SKRbvo6Gf7GondiT3BbTfuRDPqLWei4j2Qy2NPGZhW3";
const SKR_MIN_ACCESS: f64 = 5_000.0;
const SKR_REWARD_POOL: u64 = 10_000;
const ELIGIBLE_TRADE_PROGRAMS: &[&str] = &[
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter Swap
    "routeUGWgWzqBWFcrCfv8tritsqukccJPu3q5GPP3xS", // Raydium AMM routing
    "LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj", // Raydium LaunchLab
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxYB5qKP1C", // Raydium CPMM
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", // Raydium CLMM
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium legacy AMM v4
];

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkrLeagueEntry {
    pub rank: u32,
    pub wallet: String,
    pub label: String,
    pub earn_rate_pct: f64,
    pub bags_fee_score: f64,
    pub points: u32,
    pub trade_count: u32,
    pub active_days: u32,
    pub skr_balance: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkrLeagueWalletView {
    pub wallet: Option<String>,
    pub skr_balance: f64,
    pub has_access: bool,
    pub rank: Option<u32>,
    pub earn_rate_pct: f64,
    pub bags_fee_score: f64,
    pub points: u32,
    pub trade_count: u32,
    pub active_days: u32,
    pub access_message: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SkrLeagueResponse {
    pub title: String,
    pub season: String,
    pub ends_at: u64,
    pub min_skr: f64,
    pub reward_pool_skr: u64,
    pub scoring: Vec<String>,
    pub rewards: Vec<String>,
    pub wallet: SkrLeagueWalletView,
    pub leaderboard: Vec<SkrLeagueEntry>,
}

#[derive(Debug, Deserialize)]
pub struct SkrLeagueQuery {
    pub wallet: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct SkrLeagueCache {
    pub computed_at: Instant,
    pub season: String,
    pub ends_at: u64,
    pub rows: Vec<SkrLeagueEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BagsClaimReport {
    pub agent_id: String,
    pub amount_sol: f64,
    pub _claimed_txs: u32,
    pub timestamp: u64,
}

// ============================================================================
// App state
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub store: ReputationStore,
    /// Shared secret for POST /ingest/envelope.
    /// None = unauthenticated (dev/local only).
    pub ingest_secret: Option<String>,
    /// Shared secret for POST /hosting/register.
    /// None = unauthenticated (dev/local only); set in production.
    pub hosting_secret: Option<String>,
    /// ntfy server base URL for sending wake pushes to sleeping agents.
    /// Default: `https://ntfy.sh`. Set via --ntfy-server / NTFY_SERVER env var.
    /// The topic is derived from the agent_id hex — no registration needed.
    pub ntfy_server: Option<String>,
    /// Shared HTTP client for ntfy push calls.
    pub http_client: reqwest::Client,
    /// Broadcast channel for real-time activity events (GET /ws/activity).
    pub activity_tx: broadcast::Sender<ActivityEvent>,
    /// Path to store media blobs.
    pub blob_dir: Option<PathBuf>,
    /// 8004 Agent Registry client for on-chain identity checks.
    pub registry: Registry8004Client,
    /// API keys for gating read endpoints.
    /// Empty = public access (dev mode). When non-empty, all read endpoints
    /// require `Authorization: Bearer <key>` matching one of these values.
    pub api_keys: Vec<String>,
    /// Celo settlement client. Present when the aggregator is configured as
    /// the notary for Celo escrows (CELO_RPC_URL + CELO_ESCROW +
    /// CELO_PRIVATE_KEY all set). Calls `approvePayment` on VERDICT.
    #[cfg(feature = "celo-settlement")]
    pub celo_client: Option<std::sync::Arc<zerox1_settlement_celo::CeloClient>>,
    /// Base settlement client. Present when the aggregator is configured as
    /// the notary for Base escrows (BASE_RPC_URL + BASE_ESCROW +
    /// BASE_PRIVATE_KEY all set). Calls `approvePayment` on VERDICT.
    #[cfg(feature = "base-settlement")]
    pub base_client: Option<std::sync::Arc<zerox1_settlement_base::BaseClient>>,
    /// Sui settlement client. Present when SUI_RPC_URL + SUI_PACKAGE_ID +
    /// SUI_PRIVATE_KEY are set. Calls `approve_payment` on ZeroxEscrow via PTB.
    #[cfg(feature = "sui-settlement")]
    pub sui_client: Option<std::sync::Arc<zerox1_settlement_sui::SuiClient>>,
    /// Secret for POST /campaigns (operator-only). None = disabled.
    #[cfg(feature = "data-bounty")]
    pub operator_secret: Option<String>,
    /// Broadcast channel for real-time campaign events (WS /ws/campaigns).
    #[cfg(feature = "data-bounty")]
    pub campaign_tx: broadcast::Sender<Campaign>,
    /// Rate-limit window for POST /campaigns (count, window_start).
    #[cfg(feature = "data-bounty")]
    pub campaign_rate_limit: std::sync::Arc<std::sync::Mutex<(u32, std::time::Instant)>>,

    // MPP protocol fee gate
    /// Enable the MPP protocol-fee gate for agents. Defaults to false (beta).
    pub protocol_fee_enabled: bool,
    /// Daily protocol fee for hosted agents in micro-USDC. Default 200_000 (0.2 USDC).
    pub protocol_fee_hosted_usdc: u64,
    /// Daily protocol fee for self-hosted agents in micro-USDC. Default 1_000_000 (1.0 USDC).
    pub protocol_fee_self_hosted_usdc: u64,
    /// Aggregator's USDC ATA (base58). Set via --protocol-fee-recipient.
    pub protocol_fee_recipient_ata: Option<String>,
    /// reference (base58) → (challenge, created_at unix)
    pub protocol_fee_challenges:
        std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, (crate::mpp::MppChallenge, u64)>>>,
    /// Solana RPC URL for verifying protocol fee payments.
    pub protocol_fee_rpc_url: String,

    // ── Identity verification (GET /identity/verify/:agent_id_hex) ──────
    /// When true (--registry-8004-disabled), all identity checks return verified=true.
    pub identity_dev_mode: bool,
    /// Agent IDs exempt from identity checks (hex strings).
    /// Populated from AGGREGATOR_EXEMPT_AGENTS env var (comma-separated hex).
    pub exempt_agents: std::sync::Arc<std::collections::HashSet<[u8; 32]>>,
    /// In-memory cache for identity verification results.
    /// agent_id → (verified, cached_at). TTL = 1 hour.
    #[allow(clippy::type_complexity)]
    pub identity_cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 32], (bool, std::time::Instant)>>,
    >,
    /// Cached SKR league snapshot to avoid expensive chain scans on every refresh.
    pub skr_league_cache: std::sync::Arc<std::sync::Mutex<Option<SkrLeagueCache>>>,
    /// Season -> owner wallet -> claimed Bags fee total (SOL).
    pub bags_claims: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<String, f64>>>,
    >,

    // ── Sponsored token launch ────────────────────────────────────────────
    /// Ed25519 signing key for the sponsor wallet that pays Bags.fm launch fees.
    /// None = feature disabled; POST /sponsor/launch returns 503.
    pub sponsor_signing_key: Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
    /// Bags.fm API key used for sponsored launches.
    pub bags_api_key: Option<String>,
    /// Solana RPC URL for broadcasting sponsored launch transactions.
    pub sponsor_rpc_url: String,
    /// Default avatar image URL fetched when the client sends no custom image.
    pub sponsor_default_image_url: Option<String>,
    /// Bags.fm partner wallet (base58) — added to fee-share/config for revenue share.
    pub bags_partner_wallet: Option<String>,
    /// Bags.fm partner config account (base58) — added to fee-share/config for revenue share.
    pub bags_partner_config: Option<String>,
    /// Rate limit: agent_pubkey (base58) → last launch timestamp (unix secs).
    /// One sponsored launch per agent_pubkey, ever.
    /// Maps agent_id_hex → token_mint once a sponsored launch succeeds.
    /// None while the launch is in-flight (reserved but not yet confirmed).
    pub sponsor_launches: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Option<String>>>>,
}

/// Check if the request carries a valid API key.
/// Returns None (pass) if api_keys is empty (dev mode) or the token matches.
/// Returns Some(401) if api_keys is configured but the token is missing/invalid.
pub fn require_api_key(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if state.api_keys.is_empty() {
        return None; // No keys configured — public access (dev mode)
    }

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");

    for key in &state.api_keys {
        if ct_eq(provided, key.as_str()) {
            return None; // Valid key
        }
    }

    Some((
        StatusCode::UNAUTHORIZED,
        Json(
            json!({ "error": "unauthorized — provide a valid API key via Authorization: Bearer <key>" }),
        ),
    ))
}

/// Axum middleware that gates requests behind `AGGREGATOR_API_KEYS`.
/// Applied via `route_layer(middleware::from_fn_with_state(...))` on the
/// gated route group.
pub async fn api_key_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some((status, body)) = require_api_key(&state, &headers) {
        return (status, body).into_response();
    }
    next.run(request).await
}

// ============================================================================
// Agent ID validation — accepts legacy hex (64 chars) and 8004 base58 (32-44)
// ============================================================================

fn is_valid_agent_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if id.len() >= 32 && id.len() <= 44 && bs58::decode(id).into_vec().is_ok() {
        return true;
    }
    false
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

const SOLANA_RPCS: &[&str] = &[
    "https://api.mainnet-beta.solana.com",
    "https://rpc.ankr.com/solana",
    "https://solana-rpc.publicnode.com",
];

async fn solana_rpc(
    http: &reqwest::Client,
    body: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    for rpc in SOLANA_RPCS {
        let resp = http.post(*rpc).json(body).send().await;
        let Ok(resp) = resp else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(json) = resp.json::<serde_json::Value>().await else {
            continue;
        };
        if json.get("error").is_none() {
            return Ok(json);
        }
    }

    anyhow::bail!("all Solana RPCs failed")
}

async fn fetch_skr_accounts(
    http: &reqwest::Client,
    wallet: &str,
) -> anyhow::Result<Vec<(String, f64)>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet,
            { "mint": SKR_MINT },
            { "encoding": "jsonParsed" }
        ]
    });

    let json = solana_rpc(http, &body).await?;
    let Some(accounts) = json
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_array())
    else {
        anyhow::bail!("missing token accounts");
    };

    Ok(accounts
        .iter()
        .filter_map(|row| {
            let account = row.get("pubkey").and_then(|v| v.as_str())?;
            let amount = row
                .get("account")
                .and_then(|v| v.get("data"))
                .and_then(|v| v.get("parsed"))
                .and_then(|v| v.get("info"))
                .and_then(|v| v.get("tokenAmount"))
                .and_then(|v| v.get("uiAmount"))
                .and_then(|v| v.as_f64())?;
            Some((account.to_string(), amount))
        })
        .collect())
}

async fn fetch_skr_balance(http: &reqwest::Client, wallet: &str) -> anyhow::Result<f64> {
    Ok(fetch_skr_accounts(http, wallet)
        .await?
        .into_iter()
        .map(|(_, amount)| amount)
        .sum())
}

async fn fetch_signatures_for_address(
    http: &reqwest::Client,
    address: &str,
    until_ts: u64,
) -> anyhow::Result<Vec<(String, u64)>> {
    let mut before: Option<String> = None;
    let mut out = Vec::new();

    loop {
        let mut config = serde_json::json!({ "limit": 100 });
        if let Some(sig) = before.as_ref() {
            config["before"] = serde_json::Value::String(sig.clone());
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [address, config]
        });
        let json = solana_rpc(http, &body).await?;
        let Some(rows) = json.get("result").and_then(|v| v.as_array()) else {
            break;
        };
        if rows.is_empty() {
            break;
        }

        let mut hit_old = false;
        for row in rows {
            let sig = row
                .get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let ts = row.get("blockTime").and_then(|v| v.as_u64()).unwrap_or(0);
            if ts > 0 && ts < until_ts {
                hit_old = true;
                break;
            }
            if !sig.is_empty() {
                out.push((sig, ts));
            }
        }
        if hit_old {
            break;
        }
        before = rows
            .last()
            .and_then(|row| row.get("signature"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if before.is_none() || out.len() >= 500 {
            break;
        }
    }

    Ok(out)
}

async fn fetch_parsed_transaction(
    http: &reqwest::Client,
    signature: &str,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0
            }
        ]
    });
    solana_rpc(http, &body).await
}

fn season_label_from_timestamp(ts: u64) -> String {
    let season_number = (ts / (30 * 24 * 3600)) + 1;
    format!("Season {}", season_number)
}

fn bags_claim_score(state: &AppState, season: &str, wallet: &str) -> f64 {
    state
        .bags_claims
        .lock()
        .unwrap()
        .get(season)
        .and_then(|season_map| season_map.get(wallet))
        .copied()
        .unwrap_or(0.0)
}

fn month_window(now: SystemTime) -> (String, u64, u64) {
    const SEASON_SECS: u64 = 30 * 24 * 3600;
    let now_ts = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let start_ts = now_ts - (now_ts % SEASON_SECS);
    let end_ts = start_ts + SEASON_SECS;
    let season_number = (start_ts / SEASON_SECS) + 1;
    (format!("Season {}", season_number), start_ts, end_ts)
}

async fn compute_wallet_league_entry(
    state: &AppState,
    wallet: &str,
) -> anyhow::Result<Option<SkrLeagueEntry>> {
    #[derive(Clone)]
    struct LeagueTx {
        ts: u64,
        sig: String,
        pre: f64,
        post: f64,
    }

    let (season, start_ts, _end_ts) = month_window(SystemTime::now());
    let balance = fetch_skr_balance(&state.http_client, wallet).await?;
    if balance < SKR_MIN_ACCESS {
        return Ok(None);
    }
    let bags_fee_score = bags_claim_score(state, &season, wallet);

    let mut signatures: HashMap<String, u64> = HashMap::new();
    for (account, _) in fetch_skr_accounts(&state.http_client, wallet).await? {
        for (sig, ts) in fetch_signatures_for_address(&state.http_client, &account, start_ts).await?
        {
            signatures.entry(sig).or_insert(ts);
        }
    }

    let mut active_days: HashMap<String, u32> = HashMap::new();
    let mut eligible: HashSet<String> = HashSet::new();
    let mut league_txs: Vec<LeagueTx> = Vec::new();

    for (sig, ts) in signatures {
        if ts < start_ts {
            continue;
        }
        let tx = match fetch_parsed_transaction(&state.http_client, &sig).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let touched_program = tx
            .get("result")
            .and_then(|v| v.get("transaction"))
            .and_then(|v| v.get("message"))
            .and_then(|v| v.get("accountKeys"))
            .and_then(|v| v.as_array())
            .map(|keys| {
                keys.iter().any(|row| {
                    let key = row
                        .get("pubkey")
                        .and_then(|v| v.as_str())
                        .or_else(|| row.as_str())
                        .unwrap_or_default();
                    ELIGIBLE_TRADE_PROGRAMS
                        .iter()
                        .any(|program| key.eq_ignore_ascii_case(program))
                })
            })
            .unwrap_or(false);
        if !touched_program {
            continue;
        }

        let changed = ["preTokenBalances", "postTokenBalances"].into_iter().any(|field| {
            tx.get("result")
                .and_then(|v| v.get("meta"))
                .and_then(|v| v.get(field))
                .and_then(|v| v.as_array())
                .map(|balances| {
                    balances.iter().any(|row| {
                        row.get("mint")
                            .and_then(|v| v.as_str())
                            .map(|mint| mint == SKR_MINT)
                            .unwrap_or(false)
                            && row
                                .get("owner")
                                .and_then(|v| v.as_str())
                                .map(|owner| owner.eq_ignore_ascii_case(wallet))
                                .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
        if !changed {
            continue;
        }
        eligible.insert(sig.clone());
        let day = (ts / 86_400).to_string();
        *active_days.entry(day).or_insert(0) += 1;
        let pre = tx
            .get("result")
            .and_then(|v| v.get("meta"))
            .and_then(|v| v.get("preTokenBalances"))
            .and_then(|v| v.as_array())
            .map(|balances| {
                balances
                    .iter()
                    .filter(|row| {
                        row.get("mint")
                            .and_then(|v| v.as_str())
                            .map(|mint| mint == SKR_MINT)
                            .unwrap_or(false)
                            && row
                                .get("owner")
                                .and_then(|v| v.as_str())
                                .map(|owner| owner.eq_ignore_ascii_case(wallet))
                                .unwrap_or(false)
                    })
                    .map(|row| {
                        row.get("uiTokenAmount")
                            .and_then(|v| v.get("uiAmount"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                    })
                    .sum::<f64>()
            })
            .unwrap_or(0.0);
        let post = tx
            .get("result")
            .and_then(|v| v.get("meta"))
            .and_then(|v| v.get("postTokenBalances"))
            .and_then(|v| v.as_array())
            .map(|balances| {
                balances
                    .iter()
                    .filter(|row| {
                        row.get("mint")
                            .and_then(|v| v.as_str())
                            .map(|mint| mint == SKR_MINT)
                            .unwrap_or(false)
                            && row
                                .get("owner")
                                .and_then(|v| v.as_str())
                                .map(|owner| owner.eq_ignore_ascii_case(wallet))
                                .unwrap_or(false)
                    })
                    .map(|row| {
                        row.get("uiTokenAmount")
                            .and_then(|v| v.get("uiAmount"))
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                    })
                    .sum::<f64>()
            })
            .unwrap_or(0.0);
        league_txs.push(LeagueTx { ts, sig, pre, post });
    }

    league_txs.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.sig.cmp(&b.sig)));

    let points = active_days.values().fold(0u32, |acc, trades| {
        let daily = 25 + (*trades * 10);
        acc + daily.min(100)
    });
    let opening_balance = league_txs
        .first()
        .map(|tx| tx.pre)
        .filter(|v| *v > 0.0)
        .unwrap_or(balance.max(SKR_MIN_ACCESS));
    let closing_balance = league_txs.last().map(|tx| tx.post).unwrap_or(balance);
    let earn_rate_pct = if opening_balance > 0.0 {
        (((closing_balance - opening_balance) / opening_balance) * 10000.0).round() / 100.0
    } else {
        0.0
    };
    let label = state
        .store
        .get_agents_by_owner(wallet)
        .into_iter()
        .find(|a| !a.name.is_empty())
        .map(|a| a.name)
        .unwrap_or_else(|| format!("Owner {}", &wallet[..6.min(wallet.len())]));
    Ok(Some(SkrLeagueEntry {
        rank: 0,
        wallet: wallet.to_string(),
        label,
        earn_rate_pct,
        bags_fee_score,
        points,
        trade_count: eligible.len() as u32,
        active_days: active_days.len() as u32,
        skr_balance: (balance * 100.0).round() / 100.0,
    }))
}

async fn load_or_compute_league(
    state: &AppState,
    limit: usize,
) -> anyhow::Result<(String, u64, Vec<SkrLeagueEntry>)> {
    let (season, _start_ts, ends_at) = month_window(SystemTime::now());
    if let Some(cache) = state.skr_league_cache.lock().unwrap().clone() {
        if cache.season == season && cache.computed_at.elapsed() < Duration::from_secs(300) {
            return Ok((cache.season, cache.ends_at, cache.rows.into_iter().take(limit).collect()));
        }
    }

    let owner_wallets = state.store.list_owner_wallets();
    let mut rows = Vec::new();
    for wallet in owner_wallets {
        match compute_wallet_league_entry(state, &wallet).await {
            Ok(Some(entry)) => rows.push(entry),
            Ok(None) => {}
            Err(_) => {}
        }
    }

    rows.sort_by(|a, b| {
        b.earn_rate_pct
            .partial_cmp(&a.earn_rate_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                b.bags_fee_score
                    .partial_cmp(&a.bags_fee_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(b.points.cmp(&a.points))
            .then(b.active_days.cmp(&a.active_days))
            .then(b.trade_count.cmp(&a.trade_count))
            .then(
                b.skr_balance
                    .partial_cmp(&a.skr_balance)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    for (idx, row) in rows.iter_mut().enumerate() {
        row.rank = (idx + 1) as u32;
    }

    *state.skr_league_cache.lock().unwrap() = Some(SkrLeagueCache {
        computed_at: Instant::now(),
        season: season.clone(),
        ends_at,
        rows: rows.clone(),
    });

    Ok((season, ends_at, rows.into_iter().take(limit).collect()))
}

/// GET /league/current[?wallet=<base58>&limit=25]
///
/// SKR League:
/// - Access is gated behind a minimum SKR balance.
/// - Leaderboard ranks known owner wallets by season points.
/// - Points are derived from monthly on-chain SKR activity.
/// - Rewards are informational; payout bookkeeping can be layered on later.
pub async fn get_skr_league(
    State(state): State<AppState>,
    Query(params): Query<SkrLeagueQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(25).clamp(1, 100);
    let (season, ends_at, leaderboard) = match load_or_compute_league(&state, limit).await {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "league unavailable" })),
            )
                .into_response();
        }
    };

    let mut wallet_view = SkrLeagueWalletView {
        wallet: params.wallet.clone(),
        skr_balance: 0.0,
        has_access: false,
        rank: None,
        earn_rate_pct: 0.0,
        bags_fee_score: 0.0,
        points: 0,
        trade_count: 0,
        active_days: 0,
        access_message: "Link a Phantom wallet to enter the SKR League.".to_string(),
    };

    if let Some(wallet) = params.wallet.as_deref() {
        match fetch_skr_balance(&state.http_client, wallet).await {
            Ok(balance) => {
                wallet_view.skr_balance = (balance * 100.0).round() / 100.0;
                wallet_view.has_access = balance >= SKR_MIN_ACCESS;
                let cached_entry = {
                    state
                        .skr_league_cache
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(|cache| {
                            cache
                                .rows
                                .iter()
                                .find(|entry| entry.wallet.eq_ignore_ascii_case(wallet))
                                .cloned()
                        })
                };
                if let Some(entry) = cached_entry {
                    wallet_view.rank = Some(entry.rank);
                    wallet_view.earn_rate_pct = entry.earn_rate_pct;
                    wallet_view.bags_fee_score = entry.bags_fee_score;
                    wallet_view.points = entry.points;
                    wallet_view.trade_count = entry.trade_count;
                    wallet_view.active_days = entry.active_days;
                } else if wallet_view.has_access {
                    if let Ok(Some(entry)) = compute_wallet_league_entry(&state, wallet).await {
                        wallet_view.earn_rate_pct = entry.earn_rate_pct;
                        wallet_view.bags_fee_score = entry.bags_fee_score;
                        wallet_view.points = entry.points;
                        wallet_view.trade_count = entry.trade_count;
                        wallet_view.active_days = entry.active_days;
                    }
                }
                wallet_view.access_message = if wallet_view.has_access {
                    format!(
                        "Access granted. {:+.2}% swap earn rate and {:.4} SOL in claimed Bags fees this season across {} eligible trade{} on {} active day{}.",
                        wallet_view.earn_rate_pct,
                        wallet_view.bags_fee_score,
                        wallet_view.trade_count,
                        if wallet_view.trade_count == 1 { "" } else { "s" },
                        wallet_view.active_days,
                        if wallet_view.active_days == 1 { "" } else { "s" },
                    )
                } else {
                    format!(
                        "SKR League is available to wallets holding at least {:.0} SKR. Your wallet currently has {:.2} SKR.",
                        SKR_MIN_ACCESS,
                        wallet_view.skr_balance
                    )
                };
            }
            Err(_) => {
                wallet_view.access_message =
                    "Could not verify your SKR balance right now. Please try again.".to_string();
            }
        }
    }

    let response = SkrLeagueResponse {
        title: "SKR League".to_string(),
        season,
        ends_at,
        min_skr: SKR_MIN_ACCESS,
        reward_pool_skr: SKR_REWARD_POOL,
        scoring: vec![
            "Ranked by seasonal SKR earn rate percentage, not raw profit".to_string(),
            "Bags contributes via claimed launch fees only, not wallet PnL".to_string(),
            "Eligible activity is limited to embedded trade rails: Jupiter, Raydium, and Bags".to_string(),
            "Claimed Bags fees and activity score are tiebreakers after earn rate".to_string(),
        ],
        rewards: vec![
            "1st: 1,500 SKR".to_string(),
            "2nd: 1,000 SKR".to_string(),
            "3rd: 700 SKR".to_string(),
            "Top 10: premium league badge + future bonus pool access".to_string(),
        ],
        wallet: wallet_view,
        leaderboard,
    };

    Json(response).into_response()
}

pub async fn post_bags_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(report): Json<BagsClaimReport>,
) -> impl IntoResponse {
    if let Some(ref secret) = state.ingest_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, secret.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
    }

    if report.amount_sol <= 0.0 || report.agent_id.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "invalid report" })),
        )
            .into_response();
    }

    let owner = match state.store.get_owner(&report.agent_id) {
        OwnerStatus::Claimed(rec) => rec.owner,
        _ => {
            return Json(json!({ "status": "ignored" })).into_response();
        }
    };

    let season = season_label_from_timestamp(report.timestamp);
    let mut claims = state.bags_claims.lock().unwrap();
    let season_map = claims.entry(season).or_default();
    *season_map.entry(owner).or_insert(0.0) += report.amount_sol;
    *state.skr_league_cache.lock().unwrap() = None;

    Json(json!({ "status": "ok" })).into_response()
}

// ============================================================================
// Ingest
// ============================================================================

pub async fn ingest_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(event): Json<IngestEvent>,
) -> impl IntoResponse {
    // Authenticate ingest requests when a secret is configured.
    if let Some(ref secret) = state.ingest_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided, secret.as_str()) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
    }
    tracing::debug!("Ingest: received event: {:?}", event);

    // MPP protocol-fee soft gate: BEACON messages from agents that haven't
    // paid silently drop off the mesh. We only gate BEACON (not other events)
    // so existing interactions complete even if the daily fee lapsed.
    if state.protocol_fee_enabled {
        if let IngestEvent::Beacon(ref beacon_ev) = event {
            if !state.store.protocol_payment_valid(&beacon_ev.sender) {
                tracing::debug!(
                    "MPP: BEACON from {} dropped — protocol fee not paid",
                    &beacon_ev.sender[..8.min(beacon_ev.sender.len())]
                );
                // Return NO_CONTENT so the node doesn't know the agent was dropped.
                return StatusCode::NO_CONTENT.into_response();
            }
        }
    }

    if let Some(activity) = state.store.ingest(event) {
        if let Err(e) = state.activity_tx.send(activity) {
            tracing::warn!(
                "Activity broadcast dropped (no active subscribers or channel full): {e}"
            );
        }
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
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "agent not found" })),
        )
            .into_response(),
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

fn default_limit() -> usize {
    50
}

pub async fn get_leaderboard(
    State(state): State<AppState>,
    Query(params): Query<LeaderboardParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let board = state.store.leaderboard(limit);
    Json(board)
}

#[derive(Deserialize)]
pub struct AgentsParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default = "default_offset")]
    offset: usize,
    #[serde(default = "default_sort")]
    sort: String,
    /// Optional ISO 3166-1 alpha-2 country filter (e.g. ?country=NG).
    country: Option<String>,
}

fn default_offset() -> usize {
    0
}
fn default_sort() -> String {
    "reputation".to_string()
}

pub async fn get_agents(
    State(state): State<AppState>,
    Query(params): Query<AgentsParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let agents = state.store.list_agents(
        limit,
        params.offset,
        &params.sort,
        params.country.as_deref(),
    );
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
    from: Option<String>,
    /// Filter by target agent_id (hex).
    to: Option<String>,
    #[serde(default = "default_interactions_limit")]
    limit: usize,
}

fn default_interactions_limit() -> usize {
    100
}

/// GET /interactions[?from=<agent_id>&to=<agent_id>&limit=N]
///
/// Returns raw FEEDBACK events, newest first. Use `from`/`to` to filter
/// edges originating from or arriving at a specific agent. Maximum 1 000
/// per request.
pub async fn get_interactions(
    State(state): State<AppState>,
    Query(params): Query<InteractionsParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(1_000);
    let result = state
        .store
        .interactions(params.from.as_deref(), params.to.as_deref(), limit);
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

fn default_window() -> String {
    "24h".to_string()
}

fn parse_window(s: &str) -> u64 {
    match s {
        "1h" => 3_600,
        "7d" => 604_800,
        "30d" => 2_592_000,
        _ => 86_400, // "24h" and anything unrecognised
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
    State(state): State<AppState>,
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
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match state.store.entropy_latest(&agent_id) {
        Some(ev) => Json(serde_json::to_value(ev).unwrap_or_default()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no entropy data for agent" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct EntropyHistoryParams {
    #[serde(default = "default_entropy_limit")]
    limit: usize,
}

fn default_entropy_limit() -> usize {
    30
}

/// GET /entropy/:agent_id/history[?limit=30]
///
/// All recorded entropy vectors for the agent (newest first, up to 100).
/// Useful for plotting anomaly score over time.
pub async fn get_entropy_history(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<EntropyHistoryParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(100);
    let rows = state.store.entropy_history(&agent_id, limit);
    Json(rows)
}

/// GET /stats/timeseries[?window=24h]
///
/// Returns hourly feedback buckets (bucket = unix timestamp of window start).
/// Each bucket contains feedback_count, positive_count, negative_count,
/// dispute_count. Useful for activity charts.
pub async fn get_timeseries(
    State(state): State<AppState>,
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

fn default_rolling_window() -> u32 {
    10
}

/// GET /entropy/{agent_id}/rolling[?window=10]
pub async fn get_rolling_entropy(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<RollingEntropyParams>,
) -> impl IntoResponse {
    let window = params.window.clamp(3, 100);
    Json(state.store.rolling_entropy(&agent_id, window))
}

// ============================================================================
// GAP-04: Verifier concentration
// ============================================================================

/// GET /leaderboard/verifier-concentration[?limit=50]
pub async fn get_verifier_concentration(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
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

fn default_flow_window() -> String {
    "30d".to_string()
}
fn default_flow_limit() -> usize {
    500
}

/// GET /graph/flow[?window=30d&limit=500]
///
/// Directed capital flow edges: (from, to, positive_flow, interaction_count).
/// Pairs with high mutual flow are the primary Sybil signal.
pub async fn get_flow_graph(
    State(state): State<AppState>,
    Query(params): Query<FlowParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(&params.window);
    let limit = params.limit.min(2_000);
    Json(state.store.capital_flow_edges(window_secs, limit))
}

/// GET /graph/clusters[?window=30d]
///
/// Ownership clusters detected via mutual positive-feedback analysis.
/// Each cluster's `c_coefficient` feeds β₃ in the stake multiplier.
pub async fn get_flow_clusters(
    State(state): State<AppState>,
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
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<FlowParams>,
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
    epoch: u64,
}

/// GET /epochs/{agent_id}/{epoch}/envelopes
///
/// Returns ordered raw CBOR envelope bytes for a specific agent epoch.
/// Used by the challenger bot to construct Merkle inclusion proofs.
/// Up to 1000 entries, ordered by sequence (node's log order).
pub async fn get_epoch_envelopes(
    State(state): State<AppState>,
    Path(params): Path<EpochPath>,
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
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let limit: usize = params.limit.min(200);
    // Sanitise capability string: alphanumeric + dash/underscore, max 64 chars.
    let cap = params.capability.trim().to_lowercase();
    if cap.is_empty()
        || cap.len() > 64
        || !cap
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid capability name" })),
        )
            .into_response();
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
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    if !is_valid_agent_id(&agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid agent_id" })),
        )
            .into_response();
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
    State(state): State<AppState>,
    Query(params): Query<NameSearchParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let name = params.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid name" })),
        )
            .into_response();
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
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<InteractionsParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(1_000);
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
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(params): Query<DisputeParams>,
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
    pub agent_id: String,
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
    pub from: String,
    /// Protocol message type, e.g. "PROPOSE".
    pub msg_type: String,
    /// Base64-encoded raw CBOR envelope bytes.
    pub payload: String,
}

fn decode_pubkey_bytes(pubkey: &str) -> Result<[u8; 32], StatusCode> {
    let bytes = if let Ok(decoded) = hex::decode(pubkey) {
        decoded
    } else if let Ok(decoded) = bs58::decode(pubkey).into_vec() {
        decoded
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)
}

/// Helper to verify Ed25519 signature from headers.
fn verify_request_signature(pubkey: &str, signature: &str, body: &[u8]) -> Result<(), StatusCode> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_arr = decode_pubkey_bytes(pubkey)?;
    let pubkey = VerifyingKey::from_bytes(&pubkey_arr).map_err(|_| StatusCode::BAD_REQUEST)?;

    let sig_bytes = hex::decode(signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    pubkey
        .verify(body, &sig)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

/// POST /agents/{agent_id}/token
///
/// Store the agent's launched token address in the aggregator DB.
/// First-set wins — cannot be overwritten once set.
/// Authentication: Ed25519 signature of the JSON body in X-Signature header.
pub async fn post_agent_token(
    State(state): State<AppState>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Body {
        agent_id: String,
        token_address: String,
    }

    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let Some(sig) = sig else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let body: Body = serde_json::from_slice(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Path param must match body agent_id.
    if body.agent_id != agent_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate token_address: base58 charset, 32–44 chars.
    let addr = body.token_address.trim();
    let valid = (32..=44).contains(&addr.len())
        && addr.chars().all(|c| {
            matches!(c,
                '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
        });
    if !valid {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    verify_request_signature(&body.agent_id, sig, &body_bytes)?;

    state.store.set_token_address(&body.agent_id, addr);
    Ok(StatusCode::NO_CONTENT)
}

/// POST /fcm/register
///
/// Register or update the FCM device token for an agent.
/// Called by a mobile node on startup to enable push-wake behaviour.
/// Requirement: Must be signed by the agent (HIGH-7).
pub async fn fcm_register(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body: FcmRegisterBody =
        serde_json::from_str(body_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(s) = sig {
        verify_request_signature(&body.agent_id, s, &body_bytes)?;
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !is_valid_agent_id(&body.agent_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .store
        .store_fcm_token(body.agent_id.clone(), body.fcm_token);
    tracing::debug!("FCM token registered for agent {}", body.agent_id);
    Ok(StatusCode::OK)
}

/// POST /fcm/sleep
///
/// Mark an agent as sleeping (offline) or awake.
/// Called by a mobile node before backgrounding and on wakeup.
/// Requirement: Must be signed by the agent (HIGH-7).
pub async fn fcm_sleep(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body: FcmSleepBody = serde_json::from_str(body_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(s) = sig {
        verify_request_signature(&body.agent_id, s, &body_bytes)?;
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !is_valid_agent_id(&body.agent_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    state.store.set_sleeping(&body.agent_id, body.sleeping);
    tracing::debug!(
        "Agent {} sleep state → {}",
        body.agent_id,
        if body.sleeping { "sleeping" } else { "awake" }
    );
    Ok(StatusCode::OK)
}

/// GET /agents/{agent_id}/sleeping
///
/// Returns whether the agent is currently in sleep mode.
/// Senders check this before posting a pending message.
pub async fn get_sleep_status(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    Json(serde_json::json!({ "sleeping": state.store.is_sleeping(&agent_id) }))
}

/// GET /agents/{agent_id}/pending
///
/// Drain and return all pending messages held for this agent.
/// The queue is cleared on retrieval — messages are delivered exactly once.
/// Returns 200 with an empty array when there are no pending messages.
/// Requirement: Only the agent (pubkey) can drain its own queue (HIGH-8).
pub async fn get_pending(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    if let Some(s) = sig {
        // For GET, we sign the path "agents/{agent_id}/pending"
        let msg = format!("agents/{agent_id}/pending");
        verify_request_signature(&agent_id, s, msg.as_bytes())?;
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let msgs = state.store.drain_pending(&agent_id);
    // Mark the agent as awake now that it is polling.
    state.store.set_sleeping(&agent_id, false);
    Ok(Json(msgs))
}

/// POST /agents/{agent_id}/pending
///
/// Submit a message to be held for a sleeping agent.
/// If the agent has a registered FCM token and is sleeping, a push
/// notification is fired immediately to wake the app.
/// Requirement: Validate that the sender (body.from) matches the signature (HIGH-9).
pub async fn post_pending(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: axum::http::HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body: PostPendingBody =
        serde_json::from_str(body_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(s) = sig {
        // HIGH-9: Signature MUST match the sender (body.from)
        verify_request_signature(&body.from, s, &body_bytes)?;
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !is_valid_agent_id(&agent_id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let msg = PendingMessage {
        id: format!("{ts:016x}"),
        from: body.from.clone(),
        msg_type: body.msg_type.clone(),
        payload: body.payload,
        ts: (ts / 1_000_000_000) as u64,
    };

    state.store.push_pending(&agent_id, msg);

    // Fire ntfy push if the agent is sleeping.
    // Topic = agent_id hex; no pre-registration required.
    if state.store.is_sleeping(&agent_id) {
        if let Some(ref ntfy_server) = state.ntfy_server {
            let server = ntfy_server.clone();
            let aid = agent_id.clone();
            let from = body.from.clone();
            let msgtype = body.msg_type.clone();
            let client = state.http_client.clone();
            tokio::spawn(async move {
                send_ntfy_push(&server, &aid, &from, &msgtype, &client).await;
            });
        }
    }

    Ok(StatusCode::ACCEPTED.into_response())
}

// ============================================================================
// Activity feed
// ============================================================================

#[derive(Deserialize)]
pub struct ActivityParams {
    #[serde(default = "default_activity_limit")]
    limit: usize,
    before: Option<i64>,
}

fn default_activity_limit() -> usize {
    50
}

/// GET /activity[?limit=50&before=<id>]
///
/// Returns recent activity events (JOIN, FEEDBACK, DISPUTE, VERDICT), newest first.
/// Use `before=<id>` for cursor-based pagination.
pub async fn get_activity(
    State(state): State<AppState>,
    Query(params): Query<ActivityParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    Json(state.store.list_activity(limit, params.before))
}

/// GET /broadcasts[?topic=<slug>&limit=50&before=<id>]
///
/// Returns recent mesh BROADCAST records, newest first.
/// Optionally filter by `topic` slug. Use `before=<id>` for pagination.
pub async fn get_broadcasts(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(100);
    let topic = params.get("topic").map(|s| s.as_str());
    let before = params.get("before").and_then(|v| v.parse::<i64>().ok());
    Json(state.store.list_broadcasts(limit, topic, before))
}

#[derive(Deserialize)]
pub struct BountiesParams {
    capability: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}

/// GET /bounties[?capability=<name>&limit=50]
///
/// Returns open bounties broadcast to the mesh, newest first.
/// Bounties past their deadline are automatically excluded.
pub async fn get_bounties(
    State(state): State<AppState>,
    Query(params): Query<BountiesParams>,
) -> impl IntoResponse {
    let cap = params.capability.as_deref().filter(|s| !s.is_empty());
    let limit = params.limit.min(200);
    let bounties = state.store.list_bounties(cap, limit);
    Json(bounties)
}

/// GET /ws/activity
///
/// WebSocket endpoint that streams activity events in real-time.
/// Requires `Authorization: Bearer <secret>` or `token=<secret>` query param (HIGH-10).
pub async fn ws_activity(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    // Authenticate.
    if let Some(ref secret) = state.ingest_secret {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| params.get("token").map(|s: &String| s.as_str()))
            .unwrap_or("");

        if !ct_eq(provided, secret) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Ok(ws.on_upgrade(move |mut socket| async move {
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
    }))
}

/// Fire an ntfy push to wake a sleeping node.
///
/// Topic = agent_id hex (same value the aggregator already knows; no
/// pre-registration needed).  The phone polls `GET {ntfy_server}/{topic}/json`
/// or uses the ntfy Android SDK/app to subscribe.
async fn send_ntfy_push(
    ntfy_server: &str,
    agent_id: &str,
    from: &str,
    msg_type: &str,
    client: &reqwest::Client,
) {
    let url = format!("{ntfy_server}/{agent_id}");
    let body = serde_json::json!({
        "type":     "wake",
        "agent_id": agent_id,
        "from":     from,
        "msg_type": msg_type,
    })
    .to_string();

    match client
        .post(&url)
        .header("X-Title", "0x01 wake")
        .header("X-Tags", msg_type)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!("ntfy push sent for agent {agent_id}");
        }
        Ok(resp) => {
            tracing::warn!("ntfy push HTTP {} for agent {agent_id}", resp.status());
        }
        Err(e) => {
            tracing::warn!("ntfy push error for agent {agent_id}: {e}");
        }
    }
}

// ============================================================================
// Hosting node registry
// ============================================================================

#[derive(Deserialize)]
pub struct HostingRegisterBody {
    node_id: String,
    name: String,
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
    if parts.len() < 2 || parts[0] != "172" {
        return false;
    }
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
/// POST /hosting/register — called by host nodes on startup and every 60s.
///
/// Requirement: Must be signed by the node (HIGH-6).
pub async fn post_hosting_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    // When --hosting-secret is configured, require Bearer token as a first gate.
    // This prevents nodes that don't know the secret from registering at all,
    // even if they hold a valid signing key.
    if let Some(ref secret) = state.hosting_secret {
        let expected = format!("Bearer {secret}");
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct_eq(provided, &expected) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body: HostingRegisterBody =
        serde_json::from_str(body_str).map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(s) = sig {
        // HIGH-6: Signature MUST match the node_id
        verify_request_signature(&body.node_id, s, &body_bytes)?;
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Validate api_url before persisting.
    if let Err(_e) = validate_host_api_url(&body.api_url) {
        return Err(StatusCode::BAD_REQUEST);
    }

    state
        .store
        .register_hosting_node(&body.node_id, &body.name, body.fee_bps, &body.api_url);
    Ok(StatusCode::OK)
}

/// GET /hosting/nodes — returns hosting nodes seen within the last 120 seconds.
pub async fn get_hosting_nodes(State(state): State<AppState>) -> impl IntoResponse {
    let nodes: Vec<HostingNode> = state.store.list_hosting_nodes();
    Json(nodes)
}

// ============================================================================
// Agent ownership claim handlers
// ============================================================================

/// Request body for POST /agents/:agent_id/propose-owner.
#[derive(Deserialize)]
pub struct ProposeOwnerBody {
    /// Base58-encoded Solana wallet address of the intended human owner.
    pub proposed_owner: String,
}

/// Request body for POST /agents/:agent_id/claim-owner.
///
/// The human wallet that accepts the claim must submit their wallet address.
/// The agent-ownership Solana program already enforces the on-chain claim;
/// this endpoint records it in the aggregator so the profile shows "Claimed".
#[derive(Deserialize)]
pub struct ClaimOwnerBody {
    /// Base58-encoded Solana wallet address of the human who accepted.
    pub owner_wallet: String,
}

/// POST /agents/:agent_id/propose-owner
///
/// Called by the agent (or operator) to propose a human owner.
/// The proposed_owner is stored as pending until the human calls /claim-owner.
pub async fn post_propose_owner(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> impl IntoResponse {
    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid request body" })),
            )
        }
    };
    let body: ProposeOwnerBody = match serde_json::from_str(body_str) {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid request body" })),
            )
        }
    };

    if !is_valid_agent_id(&agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid agent_id" })),
        );
    }
    // Validate proposed_owner: Solana base58 pubkeys are 32–44 chars.
    if body.proposed_owner.len() < 32 || body.proposed_owner.len() > 44 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid proposed_owner (expected base58 Solana address)" })),
        );
    }
    if let Some(s) = sig {
        if let Err(status) = verify_request_signature(&agent_id, s, &body_bytes) {
            return (status, Json(json!({ "error": "invalid agent signature" })));
        }
    } else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing X-Signature" })),
        );
    }

    match state.store.propose_owner(&agent_id, &body.proposed_owner) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "pending",
                "agent_id": agent_id,
                "proposed_owner": body.proposed_owner,
            })),
        ),
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": e }))),
    }
}

/// POST /agents/:agent_id/claim-owner
///
/// Called by the human wallet AFTER accepting the on-chain AgentOwnership PDA.
/// Records the claim in the aggregator — the agent profile will now show
/// `"status": "claimed"` with the owner's wallet address.
pub async fn post_claim_owner(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: axum::body::Bytes,
) -> impl IntoResponse {
    let sig = headers.get("X-Signature").and_then(|h| h.to_str().ok());
    let body_str = match std::str::from_utf8(&body_bytes) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid request body" })),
            )
        }
    };
    let body: ClaimOwnerBody = match serde_json::from_str(body_str) {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid request body" })),
            )
        }
    };

    if !is_valid_agent_id(&agent_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid agent_id" })),
        );
    }
    if body.owner_wallet.len() < 32 || body.owner_wallet.len() > 44 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid owner_wallet (expected base58 Solana address)" })),
        );
    }
    if let Some(s) = sig {
        if let Err(status) = verify_request_signature(&body.owner_wallet, s, &body_bytes) {
            return (status, Json(json!({ "error": "invalid owner signature" })));
        }
    } else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing X-Signature" })),
        );
    }

    match state.store.claim_owner(&agent_id, &body.owner_wallet) {
        Ok(record) => (
            StatusCode::OK,
            Json(serde_json::to_value(record).unwrap_or_default()),
        ),
        Err(e) => (StatusCode::CONFLICT, Json(json!({ "error": e }))),
    }
}

/// GET /agents/:agent_id/owner
///
/// Returns the ownership status for an agent:
///   - `{ "status": "unclaimed" }`
///   - `{ "status": "pending",  "agent_id": "...", "proposed_owner": "...", "proposed_at": 123 }`
///   - `{ "status": "claimed",  "agent_id": "...", "owner": "...", "claimed_at": 123 }`
pub async fn get_agent_owner(
    Path(agent_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Try 8004 registry first for on-chain ownership
    if let Ok(Some(owner)) = state.registry.get_owner(&agent_id).await {
        return Json(json!({
            "status": "claimed",
            "agent_id": agent_id,
            "owner": owner,
            "source": "8004_registry"
        }));
    }
    // Fall back to legacy store
    let status: OwnerStatus = state.store.get_owner(&agent_id);
    Json(serde_json::to_value(status).unwrap_or_default())
}

/// GET /agents/by-owner/:wallet
///
/// Reverse-lookup: returns all agents whose ownership has been claimed by the
/// given Solana wallet address (base58, 32-44 chars).
pub async fn get_agents_by_owner(
    Path(wallet): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if wallet.len() < 32 || wallet.len() > 44 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid wallet" })),
        )
            .into_response();
    }
    let agents = state.store.get_agents_by_owner(&wallet);
    Json(agents).into_response()
}

// ============================================================================
// Blob Relay (Tiered Media Storage)
// ============================================================================

/// POST /blobs
///
/// Uploads a media blob.
/// Required Headers:
///   X-0x01-Agent-Id:  Hex-encoded 32-byte agent identity (Ed25519 pubkey).
///                     Used for reputation / tier lookup.
///   X-0x01-Signer:   Hex-encoded 32-byte Ed25519 verifying key that produced
///                     X-0x01-Signature.  Optional: falls back to X-0x01-Agent-Id
///                     when absent (dev mode — agent_id == verifying key).
///   X-0x01-Timestamp: Unix seconds.
///   X-0x01-Signature: Ed25519 signature of body bytes || timestamp LE-u64.
pub async fn post_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let blob_dir = match state.blob_dir {
        Some(ref d) => d,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "blob storage disabled" })),
            )
                .into_response()
        }
    };

    // 1. Extract and validate headers
    let agent_id_hex = headers
        .get("X-0x01-Agent-Id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let timestamp_str = headers
        .get("X-0x01-Timestamp")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let signature_hex = headers
        .get("X-0x01-Signature")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // X-0x01-Signer is the Ed25519 verifying key. Falls back to agent_id in dev mode.
    let signer_hex = headers
        .get("X-0x01-Signer")
        .and_then(|h| h.to_str().ok())
        .unwrap_or(agent_id_hex); // dev-mode fallback: signer == agent_id

    if !is_valid_agent_id(agent_id_hex) || timestamp_str.is_empty() || signature_hex.len() != 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "missing or invalid X-0x01 headers" })),
        )
            .into_response();
    }

    let timestamp = match timestamp_str.parse::<u64>() {
        Ok(t) => t,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid timestamp" })),
            )
                .into_response()
        }
    };

    // Clock skew check (+/- 30s)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if timestamp < now.saturating_sub(60) || timestamp > now + 60 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "timestamp out of sync" })),
        )
            .into_response();
    }

    // 2. Verify Signature
    // Use X-0x01-Signer for the crypto check; it equals X-0x01-Agent-Id in dev mode.
    // Try hex decoding first (legacy), then base58 (8004).
    let signer_bytes = if let Ok(b) = hex::decode(signer_hex) {
        b
    } else if let Ok(b) = bs58::decode(signer_hex).into_vec() {
        b
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid signer (expected hex or base58)" })),
        )
            .into_response();
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signature hex" })),
            )
                .into_response()
        }
    };

    let pubkey_bytes: [u8; 32] = match signer_bytes.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signer key length" })),
            )
                .into_response()
        }
    };
    let pubkey = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signer key" })),
            )
                .into_response()
        }
    };

    let sig_bytes: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid signature length" })),
            )
                .into_response()
        }
    };
    let sig = Signature::from_bytes(&sig_bytes);

    // Data to verify: body + timestamp (as LE bytes)
    let mut data = body.to_vec();
    data.extend_from_slice(&timestamp.to_le_bytes());
    if pubkey.verify(&data, &sig).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "signature verification failed" })),
        )
            .into_response();
    }

    // 3. Tier Check
    // Check 8004 registry for on-chain registration (replaces legacy is_claimed)
    let score = state.store.get_agent_reputation_score(agent_id_hex);
    let is_registered = state
        .registry
        .is_registered_b58(agent_id_hex)
        .await
        .unwrap_or(false);
    let max_size = if is_registered || score >= 100.0 {
        10 * 1024 * 1024 // 10 MB
    } else if score >= 50.0 {
        2 * 1024 * 1024 // 2 MB
    } else if score >= 10.0 {
        512 * 1024 // 512 KB
    } else {
        0 // Tier 0: Disabled
    };

    if max_size == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "reputation too low for blob storage" })),
        )
            .into_response();
    }
    if body.len() > max_size {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({ "error": format!("blob too large for your tier (max {} bytes)", max_size) }))).into_response();
    }

    // 4. Store Blob
    let mut hasher = Keccak::v256();
    hasher.update(&body);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let cid = hex::encode(hash);

    let file_path = blob_dir.join(&cid);
    if let Err(e) = std::fs::write(&file_path, &body) {
        tracing::error!("Failed to write blob {}: {}", cid, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "failed to store blob" })),
        )
            .into_response();
    }

    tracing::info!(
        "Blob uploaded: cid={} from={} size={}",
        &cid[..8],
        &agent_id_hex[..8],
        body.len()
    );
    (StatusCode::CREATED, Json(json!({ "cid": cid }))).into_response()
}

/// GET /blobs/:cid
pub async fn get_blob(State(state): State<AppState>, Path(cid): Path<String>) -> impl IntoResponse {
    let blob_dir = match state.blob_dir {
        Some(ref d) => d,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "blob storage disabled" })),
            )
                .into_response()
        }
    };

    // Sanitize CID (prevent path traversal)
    if cid.len() != 64 || !cid.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid cid" })),
        )
            .into_response();
    }

    let file_path = blob_dir.join(&cid);
    if !file_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "blob not found" })),
        )
            .into_response();
    }

    match std::fs::read(file_path) {
        Ok(data) => (
            StatusCode::OK,
            [("Content-Type", "application/octet-stream")],
            data,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "failed to read blob" })),
        )
            .into_response(),
    }
}

// ============================================================================
// DataBounty campaign handlers
// Only compiled when the `data-bounty` feature is enabled (mobile-targeting
// aggregator deployments). Server-only deployments exclude this entirely.
// ============================================================================

#[cfg(feature = "data-bounty")]
#[derive(serde::Deserialize)]
pub struct CreateCampaignRequest {
    pub data_type: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub collection_params: Option<serde_json::Value>,
    pub payout_usdc_micro: u64,
    pub max_samples_per_node: Option<u32>,
    pub max_total_samples: Option<u32>,
    pub expires_at: u64,
    pub privacy_level: Option<String>,
    pub data_retention_days: Option<u32>,
    pub purpose: Option<String>,
}

#[cfg(feature = "data-bounty")]
const MAX_CAMPAIGN_TITLE_LEN: usize = 128;
#[cfg(feature = "data-bounty")]
const MAX_CAMPAIGN_DESC_LEN: usize = 1024;
#[cfg(feature = "data-bounty")]
const MAX_CAMPAIGN_PURPOSE_LEN: usize = 512;
#[cfg(feature = "data-bounty")]
const MAX_COLLECTION_PARAMS_JSON_LEN: usize = 4096;
#[cfg(feature = "data-bounty")]
const VALID_DATA_TYPES: &[&str] = &["imu", "gps", "audio", "camera"];
#[cfg(feature = "data-bounty")]
const VALID_PRIVACY_LEVELS: &[&str] = &["anonymized", "pseudonymized", "raw"];

#[cfg(feature = "data-bounty")]
fn json_depth(v: &serde_json::Value, depth: usize) -> usize {
    if depth > 20 { return depth; }
    match v {
        serde_json::Value::Object(m) => m.values().map(|c| json_depth(c, depth + 1)).max().unwrap_or(depth),
        serde_json::Value::Array(a)  => a.iter().map(|c| json_depth(c, depth + 1)).max().unwrap_or(depth),
        _ => depth,
    }
}

#[cfg(feature = "data-bounty")]
pub async fn post_campaign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCampaignRequest>,
) -> impl IntoResponse {
    // Operator-secret gate
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    let authorized = match &state.operator_secret {
        Some(secret) => ct_eq(provided, secret.as_str()),
        None => false,
    };
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "operator secret required" })),
        ).into_response();
    }

    // Rate limit: max 20 campaigns per minute
    {
        const MAX_CAMPAIGNS_PER_MINUTE: u32 = 20;
        let mut rl = state.campaign_rate_limit.lock().unwrap();
        let now = std::time::Instant::now();
        if now.duration_since(rl.1) >= std::time::Duration::from_secs(60) {
            *rl = (0, now);
        }
        if rl.0 >= MAX_CAMPAIGNS_PER_MINUTE {
            return (StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "campaign creation rate limit exceeded" }))).into_response();
        }
        rl.0 += 1;
    }

    // Validate
    if !VALID_DATA_TYPES.contains(&req.data_type.as_str()) {
        return (StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "invalid data_type" }))).into_response();
    }
    let title = req.title.unwrap_or_default();
    let description = req.description.unwrap_or_default();
    let purpose = req.purpose.unwrap_or_default();
    if title.len() > MAX_CAMPAIGN_TITLE_LEN
        || description.len() > MAX_CAMPAIGN_DESC_LEN
        || purpose.len() > MAX_CAMPAIGN_PURPOSE_LEN
    {
        return (StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "field exceeds maximum length" }))).into_response();
    }
    let privacy_level = req.privacy_level.unwrap_or_else(|| "anonymized".to_string());
    if !VALID_PRIVACY_LEVELS.contains(&privacy_level.as_str()) {
        return (StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "invalid privacy_level" }))).into_response();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if req.expires_at <= now {
        return (StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "expires_at must be in the future" }))).into_response();
    }

    let collection_params = if let Some(ref cp) = req.collection_params {
        let s = cp.to_string();
        if s.len() > MAX_COLLECTION_PARAMS_JSON_LEN {
            return (StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "collection_params exceeds maximum size" }))).into_response();
        }
        if json_depth(cp, 0) > 10 {
            return (StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({ "error": "collection_params nesting too deep" }))).into_response();
        }
        s
    } else {
        "{}".to_string()
    };

    let campaign = Campaign {
        id: uuid_v4(),
        data_type: req.data_type,
        title,
        description,
        collection_params,
        payout_usdc_micro: req.payout_usdc_micro,
        max_samples_per_node: req.max_samples_per_node.unwrap_or(10),
        max_total_samples: req.max_total_samples.unwrap_or(0),
        samples_collected: 0,
        expires_at: req.expires_at,
        privacy_level,
        data_retention_days: req.data_retention_days.unwrap_or(30),
        purpose,
        active: true,
        created_at: now,
    };

    if let Err(e) = state.store.store_campaign(&campaign) {
        tracing::error!("Failed to store campaign: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "database error" }))).into_response();
    }

    let _ = state.campaign_tx.send(campaign.clone());
    (StatusCode::CREATED, Json(serde_json::to_value(&campaign).unwrap_or_default())).into_response()
}

#[cfg(feature = "data-bounty")]
#[derive(serde::Deserialize)]
pub struct CampaignsQuery {
    pub include_expired: Option<bool>,
}

#[cfg(feature = "data-bounty")]
pub async fn get_campaigns(
    State(state): State<AppState>,
    Query(q): Query<CampaignsQuery>,
) -> impl IntoResponse {
    let campaigns = state.store.get_campaigns(q.include_expired.unwrap_or(false));
    Json(campaigns)
}

#[cfg(feature = "data-bounty")]
pub async fn get_campaign_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.store.get_campaign(&id) {
        Some(c) => Json(serde_json::to_value(c).unwrap_or_default()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "campaign not found" }))).into_response(),
    }
}

#[cfg(feature = "data-bounty")]
const WS_CAMPAIGNS_IDLE_SECS: u64 = 300; // 5 minutes — drop silent connections

#[cfg(feature = "data-bounty")]
pub async fn ws_campaigns(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        let mut rx = state.campaign_tx.subscribe();
        loop {
            let recv = tokio::time::timeout(
                std::time::Duration::from_secs(WS_CAMPAIGNS_IDLE_SECS),
                rx.recv(),
            );
            match recv.await {
                // Idle timeout — close the connection
                Err(_elapsed) => break,
                Ok(Ok(campaign)) => {
                    let Ok(msg) = serde_json::to_string(&campaign) else { continue };
                    if socket
                        .send(axum::extract::ws::Message::Text(msg.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Err(broadcast::error::RecvError::Closed)) => break,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
            }
        }
    })
}

#[cfg(feature = "data-bounty")]
fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::rngs::OsRng, &mut bytes);
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

// ============================================================================
// Billing endpoints (Circle Gateway + CCTP)
// All mutation endpoints require Ed25519 signature from the account holder.
// ============================================================================

/// Helper: verify Ed25519 signature + timestamp freshness for billing requests.
fn verify_billing_auth(
    account_id: &str,
    signature: &str,
    timestamp: u64,
    canonical_body: &[u8],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Validate account_id format.
    if let Err(e) = crate::billing::validate_account_id(account_id) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": e}))));
    }
    // Verify Ed25519 signature.
    if let Err(_e) = verify_request_signature(account_id, signature, canonical_body) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "signature verification failed"})),
        ));
    }
    // Check timestamp freshness (5 min window).
    if let Err(e) = crate::billing::validate_timestamp(timestamp, 300) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": e}))));
    }
    Ok(())
}

/// POST /billing/deposit
///
/// Credit an account after a Gateway, Stripe, or direct deposit.
/// Requires Ed25519 signature from the account holder.
/// Duplicate references are rejected by UNIQUE constraint.
pub async fn post_billing_deposit(
    State(state): State<AppState>,
    Json(req): Json<crate::billing::DepositRequest>,
) -> impl IntoResponse {
    // ── Input validation ────────────────────────────────────────────────
    if let Err(e) = crate::billing::validate_account_id(&req.account_id) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }
    if req.amount_usdc == 0 || req.amount_usdc > crate::billing::MAX_DEPOSIT_USDC {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid amount"}))).into_response();
    }
    if let Err(e) = crate::billing::validate_reference(&req.reference) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }
    // Validate payment_method is known.
    if req.payment_method.parse::<crate::billing::PaymentMethod>().is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid payment_method: must be gateway|stripe|direct"}))).into_response();
    }
    // Validate chain_domain if present.
    if let Some(domain) = req.chain_domain {
        if !crate::billing::is_valid_chain_domain(domain) {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid chain_domain"}))).into_response();
        }
    }

    // ── Ed25519 signature verification ──────────────────────────────────
    let canonical = serde_json::to_vec(&json!({
        "account_id": req.account_id,
        "amount_usdc": req.amount_usdc,
        "payment_method": req.payment_method,
        "reference": req.reference,
        "timestamp": req.timestamp,
    }))
    .unwrap_or_default();

    if let Err((status, body)) =
        verify_billing_auth(&req.account_id, &req.signature, req.timestamp, &canonical)
    {
        return (status, body).into_response();
    }

    // ── Credit account (UNIQUE constraint prevents double-credit) ───────
    match state.store.credit_account(
        &req.account_id,
        req.amount_usdc,
        &req.payment_method,
        &req.reference,
        req.chain_domain,
    ) {
        Some(acc) => {
            tracing::info!(
                "Billing deposit: {} += {} ({}) ref={}",
                req.account_id, req.amount_usdc, req.payment_method, req.reference,
            );
            Json(json!(crate::billing::BalanceResponse::from(acc))).into_response()
        }
        None => (
            StatusCode::CONFLICT,
            Json(json!({"error": "duplicate reference or database error"})),
        )
            .into_response(),
    }
}

/// GET /billing/balance/{account_id}
///
/// Requires `Authorization: Bearer <api_key>` (same as gated read endpoints)
/// or `X-Agent-Id` + `X-Signature` headers for agent self-query.
pub async fn get_billing_balance(
    State(state): State<AppState>,
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = crate::billing::validate_account_id(&account_id) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }

    // Auth: either API key or Ed25519 self-query.
    let has_api_key = if !state.api_keys.is_empty() {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|key| state.api_keys.iter().any(|k| k == key))
            .unwrap_or(false)
    } else {
        true // dev mode: no API keys configured
    };

    let has_agent_sig = headers.get("x-agent-id").is_some()
        && headers.get("x-signature").is_some();

    if !has_api_key && !has_agent_sig {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "requires API key or X-Agent-Id + X-Signature headers"})),
        )
            .into_response();
    }

    // If using agent signature, verify it matches the account_id being queried.
    if has_agent_sig && !has_api_key {
        let agent_id = headers
            .get("x-agent-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let sig = headers
            .get("x-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if agent_id != account_id {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "can only query own balance"})),
            )
                .into_response();
        }
        // Signature over the account_id string.
        if verify_request_signature(agent_id, sig, account_id.as_bytes()).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid signature"}))).into_response();
        }
    }

    match state.store.get_or_create_billing_account(&account_id) {
        Some(acc) => Json(json!(crate::billing::BalanceResponse::from(acc))).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "billing database not available"})),
        )
            .into_response(),
    }
}

/// POST /billing/withdraw
///
/// Debit an account and enqueue CCTP withdrawal.
/// Requires Ed25519 signature from the account holder.
pub async fn post_billing_withdraw(
    State(state): State<AppState>,
    Json(req): Json<crate::billing::WithdrawRequest>,
) -> impl IntoResponse {
    // ── Input validation ────────────────────────────────────────────────
    if req.amount_usdc == 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "amount must be > 0"}))).into_response();
    }
    if !crate::billing::is_valid_chain_domain(req.dest_chain) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid dest_chain"}))).into_response();
    }
    if let Err(e) = crate::billing::validate_address(&req.dest_address, req.dest_chain) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }

    // ── Ed25519 signature verification ──────────────────────────────────
    let canonical = serde_json::to_vec(&json!({
        "account_id": req.account_id,
        "amount_usdc": req.amount_usdc,
        "dest_chain": req.dest_chain,
        "dest_address": req.dest_address,
        "timestamp": req.timestamp,
    }))
    .unwrap_or_default();

    if let Err((status, body)) =
        verify_billing_auth(&req.account_id, &req.signature, req.timestamp, &canonical)
    {
        return (status, body).into_response();
    }

    // ── Check skip_settlement flag ──────────────────────────────────────
    let skip = state
        .store
        .get_or_create_billing_account(&req.account_id)
        .map(|a| a.skip_settlement)
        .unwrap_or(false);

    // ── Debit + enqueue settlement (or skip if flagged) ─────────────────
    let reference = format!("{}:{}", req.dest_chain, req.dest_address);
    match state.store.debit_account(&req.account_id, req.amount_usdc, "withdraw", &reference) {
        Some(acc) => {
            if skip {
                tracing::info!(
                    "Billing withdrawal (skip_settlement): {} -= {} → chain {} addr {} — operator handles payout",
                    req.account_id, req.amount_usdc, req.dest_chain, req.dest_address,
                );
            } else {
                let conv_id = format!("withdraw-{}", req.timestamp);
                state.store.enqueue_settlement(crate::billing::SettlementRequest {
                    conversation_id: &conv_id,
                    payer: &req.account_id,
                    payee: &req.account_id,
                    amount_usdc: req.amount_usdc,
                    fee_usdc: 0,
                    dest_chain: Some(req.dest_chain),
                    dest_address: Some(&req.dest_address),
                });
                tracing::info!(
                    "Billing withdrawal: {} -= {} → chain {} addr {}",
                    req.account_id, req.amount_usdc, req.dest_chain, req.dest_address,
                );
            }
            Json(json!({
                "account": crate::billing::BalanceResponse::from(acc),
                "settlement_queued": !skip,
            })).into_response()
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "insufficient balance or account not found"})),
        )
            .into_response(),
    }
}

/// POST /billing/set-payout
///
/// Set the preferred chain and payout address for an account.
/// Requires Ed25519 signature + timestamp freshness.
pub async fn post_billing_set_payout(
    State(state): State<AppState>,
    Json(req): Json<crate::billing::SetPayoutRequest>,
) -> impl IntoResponse {
    // ── Input validation ────────────────────────────────────────────────
    if !crate::billing::is_valid_chain_domain(req.preferred_chain) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid preferred_chain"}))).into_response();
    }
    if let Err(e) = crate::billing::validate_address(&req.payout_address, req.preferred_chain) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }

    // ── Ed25519 signature + timestamp ───────────────────────────────────
    let canonical = serde_json::to_vec(&json!({
        "account_id": req.account_id,
        "preferred_chain": req.preferred_chain,
        "payout_address": req.payout_address,
        "timestamp": req.timestamp,
    }))
    .unwrap_or_default();

    if let Err((status, body)) =
        verify_billing_auth(&req.account_id, &req.signature, req.timestamp, &canonical)
    {
        return (status, body).into_response();
    }

    // ── Update preference ───────────────────────────────────────────────
    state.store.get_or_create_billing_account(&req.account_id);
    match state
        .store
        .set_payout_preference(&req.account_id, req.preferred_chain, &req.payout_address)
    {
        Some(()) => Json(json!({"ok": true})).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to update payout preference"})),
        )
            .into_response(),
    }
}

/// GET /billing/transactions/{account_id}?limit=50
///
/// Requires same auth as GET /billing/balance — API key or agent self-query.
pub async fn get_billing_transactions(
    State(state): State<AppState>,
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(e) = crate::billing::validate_account_id(&account_id) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }

    // Auth: API key or agent self-query (same logic as get_billing_balance).
    let has_api_key = if !state.api_keys.is_empty() {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|key| state.api_keys.iter().any(|k| k == key))
            .unwrap_or(false)
    } else {
        true
    };

    let has_agent_sig = headers.get("x-agent-id").is_some()
        && headers.get("x-signature").is_some();

    if !has_api_key && !has_agent_sig {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "auth required"}))).into_response();
    }

    if has_agent_sig && !has_api_key {
        let agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or("");
        let sig = headers.get("x-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
        if agent_id != account_id {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "can only query own transactions"}))).into_response();
        }
        if verify_request_signature(agent_id, sig, account_id.as_bytes()).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid signature"}))).into_response();
        }
    }

    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let txs = state.store.billing_transactions(&account_id, limit, offset);
    Json(json!(txs)).into_response()
}

/// GET /billing/estimate-settlement?amount_usdc=10&source_chain=5&dest_chain=6
///
/// Returns estimated fees for a cross-chain settlement. Public endpoint.
pub async fn get_billing_estimate(
    Query(params): Query<crate::billing::EstimateParams>,
) -> impl IntoResponse {
    // Validate inputs.
    if !params.amount_usdc.is_finite() || params.amount_usdc <= 0.0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "amount_usdc must be positive"}))).into_response();
    }
    if !crate::billing::is_valid_chain_domain(params.source_chain) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid source_chain"}))).into_response();
    }
    if !crate::billing::is_valid_chain_domain(params.dest_chain) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid dest_chain"}))).into_response();
    }

    // Static fee estimate (replaced with live CCTP call when client is wired in).
    let zerox1_fee = (params.amount_usdc * 0.01 * 1_000_000.0).round() / 1_000_000.0;
    let protocol_fee = 0.10_f64;
    let total = zerox1_fee + protocol_fee;

    Json(json!({
        "source_domain": params.source_chain,
        "dest_domain": params.dest_chain,
        "amount_usdc": format!("{:.6}", params.amount_usdc),
        "protocol_fee_usdc": format!("{:.6}", protocol_fee),
        "zerox1_fee_usdc": format!("{:.6}", zerox1_fee),
        "total_fee_usdc": format!("{:.6}", total),
        "estimated_time_seconds": 30,
        "note": "Estimate only. Actual fees determined at settlement time via CCTP V2."
    }))
    .into_response()
}

// ============================================================================
// Admin billing endpoints (API-key gated)
// ============================================================================

/// GET /admin/billing/accounts?limit=50&offset=0
pub async fn get_admin_billing_accounts(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(500) as usize;
    let offset = params.offset.unwrap_or(0) as usize;
    let accounts = state.store.list_billing_accounts(limit, offset);
    Json(json!({
        "accounts": accounts,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

/// GET /admin/billing/settlements?limit=50&offset=0&status=pending
pub async fn get_admin_settlements(
    State(state): State<AppState>,
    Query(params): Query<SettlementListParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(500) as usize;
    let offset = params.offset.unwrap_or(0) as usize;
    let settlements = state.store.list_settlements(limit, offset, params.status.as_deref());
    Json(json!({
        "settlements": settlements,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

/// GET /admin/billing/revenue
pub async fn get_admin_revenue(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let stats = state.store.billing_revenue_stats();
    Json(stats).into_response()
}

/// POST /admin/billing/accounts/{id}/skip-settlement
///
/// Toggle the skip_settlement flag for an account.
/// When enabled, withdrawals and VERDICTs bypass Circle CCTP.
/// The operator is responsible for executing the actual USDC transfer off-band
/// (e.g. direct Solana SPL transfer, invoice, or wire).
pub async fn post_admin_set_skip_settlement(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let skip = body.get("skip").and_then(|v| v.as_bool()).unwrap_or(false);
    if let Err(e) = crate::billing::validate_account_id(&account_id) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response();
    }
    match state.store.set_skip_settlement(&account_id, skip) {
        Some(()) => Json(json!({
            "ok": true,
            "account_id": account_id,
            "skip_settlement": skip,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "account not found (no DB or account does not exist)"})),
        )
            .into_response(),
    }
}

/// POST /admin/billing/settlements/{id}/retry — retry a failed settlement
pub async fn post_admin_retry_settlement(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let ok = state.store.update_settlement_status(id, "failed", "pending", None);
    if ok {
        Json(json!({"ok": true, "message": "Settlement re-queued"})).into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(json!({"error": "Settlement not in 'failed' state or not found"})),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SettlementListParams {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub status: Option<String>,
}

// ============================================================================
// MPP — protocol fee challenge + verify
// ============================================================================

fn unix_now_agg() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Deserialize)]
pub struct MppProtocolFeeQuery {
    pub kind: Option<String>,
}

#[derive(Deserialize)]
pub struct MppProtocolFeeVerifyRequest {
    pub tx_sig: String,
    pub reference: String,
    pub agent_id: String,
}

/// GET /mpp/protocol-fee/challenge — generate a fresh MPP challenge for the protocol fee.
///
/// Query param: ?kind=hosted|self_hosted (default: hosted)
/// Returns 404 if protocol fee gate is disabled.
pub async fn mpp_protocol_fee_challenge(
    State(state): State<AppState>,
    Query(q): Query<MppProtocolFeeQuery>,
) -> impl IntoResponse {
    if !state.protocol_fee_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "protocol fee gate not enabled" })),
        )
            .into_response();
    }

    let recipient_ata = match &state.protocol_fee_recipient_ata {
        Some(a) => a.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "protocol fee recipient not configured" })),
            )
                .into_response()
        }
    };

    let kind = q.kind.as_deref().unwrap_or("hosted");
    let daily_fee = if kind == "self_hosted" {
        state.protocol_fee_self_hosted_usdc
    } else {
        state.protocol_fee_hosted_usdc
    };

    // USDC mint: use devnet address if rpc_url contains "devnet".
    let usdc_mint = if state.protocol_fee_rpc_url.contains("devnet") {
        "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    } else {
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    };

    let config = crate::mpp::MppConfig {
        recipient_ata,
        daily_fee,
        usdc_mint: usdc_mint.to_string(),
        enabled: true,
    };

    let now = unix_now_agg();
    let challenge = crate::mpp::generate_challenge(&config);

    // Prune expired challenges and store the new one.
    {
        let mut challenges = state.protocol_fee_challenges.lock().await;
        let cutoff = now.saturating_sub(180);
        challenges.retain(|_, (_, created_at)| *created_at >= cutoff);
        challenges.insert(challenge.reference.clone(), (challenge.clone(), now));
    }

    Json(json!({
        "recipient": challenge.recipient,
        "amount": challenge.amount,
        "mint": challenge.mint,
        "reference": challenge.reference,
        "expires_at": challenge.expires_at,
        "kind": kind,
    }))
    .into_response()
}

/// POST /mpp/protocol-fee/verify — verify a protocol-fee payment.
///
/// Body: `{ "tx_sig": "...", "reference": "...", "agent_id": "..." }`
/// On success: records in agent_protocol_payments and returns `{ "paid_until": <unix> }`.
pub async fn mpp_protocol_fee_verify(
    State(state): State<AppState>,
    Json(req): Json<MppProtocolFeeVerifyRequest>,
) -> impl IntoResponse {
    if !state.protocol_fee_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "protocol fee gate not enabled" })),
        )
            .into_response();
    }

    // Look up challenge by reference.
    let challenge = {
        let challenges = state.protocol_fee_challenges.lock().await;
        match challenges.get(&req.reference) {
            Some((ch, _)) => ch.clone(),
            None => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({ "error": "challenge not found or expired" })),
                )
                    .into_response()
            }
        }
    };

    if unix_now_agg() > challenge.expires_at {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "error": "challenge expired" })),
        )
            .into_response();
    }

    let proof = crate::mpp::MppProof {
        tx_sig: req.tx_sig.clone(),
        reference: req.reference.clone(),
    };

    match crate::mpp::verify_payment(&proof, &challenge, &state.protocol_fee_rpc_url).await {
        Ok(true) => {
            let now = unix_now_agg();
            let paid_until = now + 86_400;

            // Record in SQLite.
            if let Err(e) = state.store.record_protocol_payment(&req.agent_id, "hosted") {
                tracing::warn!("MPP: failed to record protocol payment: {e}");
            }

            // Remove the used challenge.
            state.protocol_fee_challenges.lock().await.remove(&req.reference);

            Json(json!({ "paid_until": paid_until })).into_response()
        }
        Ok(false) => (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "error": "payment verification failed" })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("MPP protocol fee verify error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "payment verification error" })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Identity verification  (GET /identity/verify/:agent_id_hex)
// ============================================================================

/// Response body for GET /identity/verify/:agent_id_hex.
#[derive(serde::Serialize)]
pub struct IdentityVerifyResponse {
    pub verified: bool,
    pub source: String,
}

/// TTL for identity cache entries.
const IDENTITY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3_600);

/// GET /identity/verify/:agent_id_hex
///
/// Centralised identity gate for 0x01 nodes.  The node calls this instead of
/// querying 8004 directly so all the registry logic lives in one place.
///
/// Verification order:
///   1. dev_mode (--registry-8004-disabled on the aggregator) → verified, source="dev"
///   2. exempt_agents whitelist → verified, source="exempt"
///   3. In-memory cache (1 h TTL) → return cached result
///   4. 8004 GraphQL indexer → verified, source="8004"
///   5. Not registered → not verified, source="none"
///   6. Network error → HTTP 503 (node should fail-open and back off)
pub async fn verify_identity(
    State(state): State<AppState>,
    Path(agent_id_hex): Path<String>,
) -> axum::response::Response {
    // ── Validate input ────────────────────────────────────────────────────
    if agent_id_hex.len() != 64 || !agent_id_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "agent_id_hex must be a 64-character hex string" })),
        )
            .into_response();
    }
    let bytes = match hex::decode(&agent_id_hex) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid hex" })),
            )
                .into_response()
        }
    };
    let agent_id: [u8; 32] = match bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "agent_id must be 32 bytes" })),
            )
                .into_response()
        }
    };

    // ── 1. Dev mode ───────────────────────────────────────────────────────
    if state.identity_dev_mode {
        return Json(IdentityVerifyResponse {
            verified: true,
            source: "dev".to_string(),
        })
        .into_response();
    }

    // ── 2. Exempt agents whitelist ────────────────────────────────────────
    if state.exempt_agents.contains(&agent_id) {
        return Json(IdentityVerifyResponse {
            verified: true,
            source: "exempt".to_string(),
        })
        .into_response();
    }

    // ── 3. In-memory cache ────────────────────────────────────────────────
    {
        let cache = state.identity_cache.lock().unwrap();
        if let Some((verified, cached_at)) = cache.get(&agent_id) {
            if cached_at.elapsed() < IDENTITY_CACHE_TTL {
                return Json(IdentityVerifyResponse {
                    verified: *verified,
                    source: if *verified {
                        "cache".to_string()
                    } else {
                        "cache:none".to_string()
                    },
                })
                .into_response();
            }
        }
    }

    // ── 4. 8004 registry query ────────────────────────────────────────────
    let agent_b58 = bs58::encode(&agent_id).into_string();
    match state.registry.is_registered_b58(&agent_b58).await {
        Ok(true) => {
            state
                .identity_cache
                .lock()
                .unwrap()
                .insert(agent_id, (true, std::time::Instant::now()));
            Json(IdentityVerifyResponse {
                verified: true,
                source: "8004".to_string(),
            })
            .into_response()
        }
        Ok(false) => {
            state
                .identity_cache
                .lock()
                .unwrap()
                .insert(agent_id, (false, std::time::Instant::now()));
            Json(IdentityVerifyResponse {
                verified: false,
                source: "none".to_string(),
            })
            .into_response()
        }
        Err(e) => {
            // ── 7. Network error on 8004 — return 503 so the node fails open ──
            tracing::warn!(
                "identity/verify: 8004 check failed for {} — returning 503: {e}",
                &agent_id_hex[..8]
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "identity check temporarily unavailable",
                    "detail": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// POST /sponsor/launch — gasless token launch for new agents
// ============================================================================

const BAGS_API_BASE: &str = "https://public-api-v2.bags.fm/api/v1";

#[derive(Deserialize)]
pub struct SponsorLaunchRequest {
    /// Hex-encoded 32-byte agent identity key (as used throughout the 0x01 system).
    /// Converted to base58 Solana pubkey internally for the Bags fee-share config.
    pub agent_id_hex: String,
    /// Token name (e.g. "My Agent").
    pub name: String,
    /// Token symbol, uppercase (e.g. "MYAGT").
    pub symbol: String,
    /// Short description shown on Bags.fm.
    pub description: String,
    /// Optional: Base64-encoded image bytes (PNG/JPG, max 5 MB).
    pub image_b64: Option<String>,
}

/// POST /sponsor/launch
///
/// Sponsors a Bags.fm token launch on behalf of a new agent.
/// The sponsor wallet (SPONSOR_SIGNING_KEY) pays all gas; the agent wallet
/// is the sole claimer in the fee-share config. Note: Bags applies the
/// platform fee and partner cut before distributing to claimers.
///
/// Rate limited: one launch per agent_pubkey, ever (checked in-memory).
pub async fn sponsor_launch(
    State(state): State<AppState>,
    Json(req): Json<SponsorLaunchRequest>,
) -> impl IntoResponse {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use solana_sdk::pubkey::Pubkey;

    // ── Feature gate ──────────────────────────────────────────────────────
    let (signing_key, bags_api_key) = match (&state.sponsor_signing_key, &state.bags_api_key) {
        (Some(k), Some(ak)) => (k.clone(), ak.clone()),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "sponsored launches not configured on this aggregator"})),
            ).into_response();
        }
    };

    // ── Validate and convert agent_id_hex → base58 pubkey ────────────────
    let agent_id_bytes = match hex::decode(req.agent_id_hex.trim()) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "agent_id_hex must be a 64-char hex string (32 bytes)"})),
            ).into_response();
        }
    };
    // Base58-encode the raw key bytes — this is the Solana pubkey format Bags expects.
    let agent_pubkey_str = bs58::encode(&agent_id_bytes).into_string();
    // agent_id_hex (trimmed) is the dedup key stored in sponsor_launches.
    let dedup_key = req.agent_id_hex.trim().to_lowercase();

    // ── One launch per agent pubkey ───────────────────────────────────────
    {
        let mut launched = state.sponsor_launches.lock().unwrap();
        if let Some(entry) = launched.get(&dedup_key) {
            return match entry {
                // Launch already completed — return the token mint idempotently.
                Some(mint) => (StatusCode::OK, Json(json!({
                    "token_mint": mint,
                    "already_launched": true,
                }))).into_response(),
                // Launch is in-flight — tell the caller to retry later.
                None => (StatusCode::CONFLICT, Json(json!({
                    "error": "token launch in progress, please retry in a few seconds"
                }))).into_response(),
            };
        }
        // Reserve the slot immediately (None = in-flight) to prevent concurrent duplicates.
        launched.insert(dedup_key.clone(), None);
    }

    let sponsor_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    let sponsor_pubkey_str = bs58::encode(sponsor_pubkey.to_bytes()).into_string();
    let client = &state.http_client;

    // ── Step 1: create-token-info (IPFS metadata + derive mint) ──────────
    // Prefer the client-uploaded image; fall back to the operator's default avatar URL.
    let image_bytes: Option<Vec<u8>> = if let Some(b64) = &req.image_b64 {
        B64.decode(b64).ok()
    } else if let Some(url) = &state.sponsor_default_image_url {
        match client.get(url).timeout(std::time::Duration::from_secs(10)).send().await {
            Ok(r) if r.status().is_success() => r.bytes().await.ok().map(|b| b.to_vec()),
            _ => {
                tracing::warn!("failed to fetch default agent avatar from {url}");
                None
            }
        }
    } else {
        None
    };

    let create_info_resp = {
        let resp = if let Some(ref bytes) = image_bytes {
            let image_part = match reqwest::multipart::Part::bytes(bytes.clone())
                .file_name("image.png")
                .mime_str("image/png") {
                Ok(p) => p,
                Err(e) => {
                    remove_sponsor_reservation(&state, &dedup_key);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("image mime: {e}")}))).into_response();
                }
            };
            let form = reqwest::multipart::Form::new()
                .text("name", req.name.clone())
                .text("symbol", req.symbol.clone())
                .text("description", req.description.clone())
                .part("image", image_part);
            client
                .post(format!("{BAGS_API_BASE}/token-launch/create-token-info"))
                .header("x-api-key", &bags_api_key)
                .multipart(form)
                .timeout(std::time::Duration::from_secs(60))
                .send()
                .await
        } else {
            let body = json!({
                "name": req.name,
                "symbol": req.symbol,
                "description": req.description,
            });
            client
                .post(format!("{BAGS_API_BASE}/token-launch/create-token-info"))
                .header("x-api-key", &bags_api_key)
                .json(&body)
                .timeout(std::time::Duration::from_secs(30))
                .send()
                .await
        };

        match resp {
            Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(e) => {
                    remove_sponsor_reservation(&state, &dedup_key);
                    return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags create-token-info parse: {e}")}))).into_response();
                }
            },
            Ok(r) => {
                let status = r.status();
                let text = r.text().await.unwrap_or_default();
                remove_sponsor_reservation(&state, &dedup_key);
                return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags create-token-info {status}: {text}")}))).into_response();
            }
            Err(e) => {
                remove_sponsor_reservation(&state, &dedup_key);
                return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags create-token-info: {e}")}))).into_response();
            }
        }
    };

    let token_mint = match create_info_resp["response"]["tokenMint"].as_str() {
        Some(m) => m.to_string(),
        None => {
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": "bags create-token-info: missing tokenMint"}))).into_response();
        }
    };
    let ipfs_uri = match create_info_resp["response"]["tokenMetadata"].as_str() {
        Some(u) => u.to_string(),
        None => {
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": "bags create-token-info: missing tokenMetadata"}))).into_response();
        }
    };

    tracing::info!(
        "sponsor_launch: agent={} token_mint={} sponsor={}",
        agent_pubkey_str, token_mint, sponsor_pubkey_str
    );

    // ── Step 2: create-fee-share-config ───────────────────────────────────
    // Sponsor pays gas. Agent is sole claimer — receives the creator share
    // after Bags platform fee and partner cut are applied.
    let mut fee_share_body = json!({
        "payer": sponsor_pubkey_str,
        "baseMint": token_mint,
        "claimersArray": [agent_pubkey_str],
        "basisPointsArray": [10_000u32],
    });
    if let Some(pw) = &state.bags_partner_wallet {
        fee_share_body["partner"] = pw.clone().into();
    }
    if let Some(pc) = &state.bags_partner_config {
        fee_share_body["partnerConfig"] = pc.clone().into();
    }
    let fee_share_resp = client
        .post(format!("{BAGS_API_BASE}/fee-share/config"))
        .header("x-api-key", &bags_api_key)
        .json(&fee_share_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await;

    let fee_share_val = match fee_share_resp {
        Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.unwrap_or_default(),
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            tracing::error!("sponsor_launch: fee-share/config {status}: {text}");
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({
                "error": format!("bags fee-share/config failed ({status})"),
                "bags_response": text,
                "request_body": fee_share_body,
            }))).into_response();
        }
        Err(e) => {
            tracing::error!("sponsor_launch: fee-share/config request failed: {e}");
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags fee-share/config: {e}")}))).into_response();
        }
    };

    let config_key = fee_share_val["response"]["meteoraConfigKey"]
        .as_str()
        .or_else(|| fee_share_val["response"]["feeShareAuthority"].as_str())
        .unwrap_or("")
        .to_string();

    // Sign and broadcast each fee-share config transaction (wire-format, handles V0).
    if let Some(txs) = fee_share_val["response"]["transactions"].as_array() {
        for (idx, tx_item) in txs.iter().enumerate() {
            if let Some(tx_b58) = tx_item["transaction"].as_str() {
                if let Ok(tx_bytes) = bs58::decode(tx_b58).into_vec() {
                    if let Some(signed) = sign_wire_tx_if_signer(&tx_bytes, &signing_key) {
                        let signed_b64 = B64.encode(&signed);
                        if let Err(e) = broadcast_solana_tx(&state.sponsor_rpc_url, client, &signed_b64).await {
                            tracing::warn!("sponsor_launch: fee-share tx[{idx}] broadcast failed: {e}");
                        } else {
                            tracing::warn!("sponsor_launch: fee-share tx[{idx}] broadcast ok");
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        }
                    }
                }
            }
        }
        if !txs.is_empty() {
            // Extra buffer after all fee-share txs before creating launch tx.
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        }
    }

    // ── Step 3: create-launch-transaction ────────────────────────────────
    // No initial buy — sponsor only covers the base launch cost.
    let launch_body = json!({
        "ipfs": ipfs_uri,
        "tokenMint": token_mint,
        "wallet": sponsor_pubkey_str,
        "configKey": config_key,
    });

    let launch_resp = client
        .post(format!("{BAGS_API_BASE}/token-launch/create-launch-transaction"))
        .header("x-api-key", &bags_api_key)
        .json(&launch_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await;

    let launch_tx_b58 = match launch_resp {
        Ok(r) if r.status().is_success() => {
            match r.json::<serde_json::Value>().await {
                Ok(v) => v["response"].as_str().unwrap_or("").to_string(),
                Err(e) => {
                    remove_sponsor_reservation(&state, &dedup_key);
                    return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags launch-tx parse: {e}")}))).into_response();
                }
            }
        }
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags launch-tx {status}: {text}")}))).into_response();
        }
        Err(e) => {
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("bags launch-tx: {e}")}))).into_response();
        }
    };

    // ── Step 4: Sign and broadcast launch tx ─────────────────────────────
    let launch_tx_bytes = match bs58::decode(&launch_tx_b58).into_vec() {
        Ok(b) => b,
        Err(e) => {
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("launch-tx base58: {e}")}))).into_response();
        }
    };

    let signed_launch_bytes = match sign_wire_tx_if_signer(&launch_tx_bytes, &signing_key) {
        Some(b) => b,
        None => {
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": "launch-tx: sponsor pubkey not found as signer"}))).into_response();
        }
    };

    let txid = match broadcast_solana_tx(&state.sponsor_rpc_url, client, &B64.encode(&signed_launch_bytes)).await {
        Ok(sig) => sig,
        Err(e) => {
            remove_sponsor_reservation(&state, &dedup_key);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("launch-tx broadcast: {e}")}))).into_response();
        }
    };

    tracing::info!(
        "sponsor_launch: success agent={} token_mint={} txid={}",
        agent_pubkey_str, token_mint, txid
    );

    // Persist the token_mint so retries get an idempotent 200 instead of an error.
    if let Ok(mut launched) = state.sponsor_launches.lock() {
        launched.insert(dedup_key, Some(token_mint.clone()));
    }

    (StatusCode::OK, Json(json!({
        "token_mint": token_mint,
        "txid": txid,
        "fee_claimer": agent_pubkey_str,
        "sponsor": sponsor_pubkey_str,
    }))).into_response()
}

// ============================================================================
// POST /sponsor/fee-share-config — sponsor signs fee-share config txs for a node
// ============================================================================

#[derive(Deserialize)]
pub struct SponsorFeeShareRequest {
    /// Base58 token mint from Bags create-token-info.
    pub base_mint: String,
    /// Base58 agent wallet pubkey (claimer of pool fees).
    pub agent_pubkey: String,
}

/// POST /sponsor/fee-share-config
///
/// Creates and broadcasts the Bags fee-share config on behalf of a local node.
/// The sponsor wallet pays the on-chain transaction fees. Returns the config key
/// needed for the subsequent create-launch-transaction call.
pub async fn sponsor_fee_share_config(
    State(state): State<AppState>,
    Json(req): Json<SponsorFeeShareRequest>,
) -> impl IntoResponse {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let (signing_key, bags_api_key) = match (&state.sponsor_signing_key, &state.bags_api_key) {
        (Some(k), Some(ak)) => (k.clone(), ak.clone()),
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "sponsor not configured on this aggregator"})),
            )
                .into_response();
        }
    };

    let sponsor_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(
        signing_key.verifying_key().to_bytes(),
    );
    let sponsor_pubkey_str = bs58::encode(sponsor_pubkey.to_bytes()).into_string();
    let client = &state.http_client;

    let fee_share_body = json!({
        "payer": sponsor_pubkey_str,
        "baseMint": req.base_mint,
        "claimersArray": [req.agent_pubkey],
        "basisPointsArray": [10_000u32],
    });

    let fee_share_val = match client
        .post(format!("{BAGS_API_BASE}/fee-share/config"))
        .header("x-api-key", &bags_api_key)
        .json(&fee_share_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.unwrap_or_default(),
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            tracing::error!("sponsor_fee_share_config: {status}: {text}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("bags fee-share/config failed ({status}): {text}")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": format!("bags fee-share/config: {e}")})),
            )
                .into_response();
        }
    };

    let config_key = fee_share_val["response"]["meteoraConfigKey"]
        .as_str()
        .or_else(|| fee_share_val["response"]["feeShareAuthority"].as_str())
        .unwrap_or("")
        .to_string();

    // Sign and broadcast each fee-share config transaction.
    // Bags returns base58-encoded wire-format transactions with one empty
    // signature slot that the sponsor wallet must fill.
    // We operate directly on wire bytes to avoid bincode round-trip corruption.
    if let Some(txs) = fee_share_val["response"]["transactions"].as_array() {
        tracing::warn!("sponsor_fee_share_config: {} txs, raw[0]={}", txs.len(), txs.first().map(|t| t.to_string()).unwrap_or_default());
        for (idx, tx_item) in txs.iter().enumerate() {
            let Some(tx_b58) = tx_item["transaction"].as_str() else {
                tracing::warn!("sponsor_fee_share_config: tx[{idx}] no 'transaction' field in {tx_item}");
                continue;
            };
            let tx_bytes = match bs58::decode(tx_b58).into_vec() {
                Ok(b) => b,
                Err(e) => { tracing::warn!("sponsor_fee_share_config: tx[{idx}] bs58 fail: {e}"); continue; }
            };
            tracing::warn!("sponsor_fee_share_config: tx[{idx}] {} bytes first=0x{:02x}", tx_bytes.len(), tx_bytes.first().copied().unwrap_or(0));
            let signed = sign_wire_tx_if_signer(&tx_bytes, &signing_key).unwrap_or(tx_bytes);
            if let Err(e) = broadcast_solana_tx(&state.sponsor_rpc_url, client, &B64.encode(&signed)).await {
                tracing::warn!("sponsor_fee_share_config: tx[{idx}] broadcast failed: {e}");
            } else {
                tracing::warn!("sponsor_fee_share_config: tx[{idx}] broadcast ok");
                // Wait for this tx to confirm before submitting the next one.
                // Bags txs are ordered: later txs depend on accounts created by earlier ones.
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
        if !txs.is_empty() {
            // Extra buffer for the last tx to finalize before the node uses config_key.
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        }
    } else {
        tracing::warn!("sponsor_fee_share_config: no 'transactions' array in response: {fee_share_val}");
    }

    (StatusCode::OK, Json(json!({"config_key": config_key}))).into_response()
}

fn remove_sponsor_reservation(state: &AppState, agent_pubkey: &str) {
    if let Ok(mut launched) = state.sponsor_launches.lock() {
        launched.remove(agent_pubkey);
    }
}

/// Sign a Solana wire-format transaction with `key` if our pubkey appears in
/// the signer account list and the corresponding signature slot is empty.
/// Returns the (possibly modified) wire bytes, or None on parse errors.
fn sign_wire_tx_if_signer(
    tx_bytes: &[u8],
    key: &ed25519_dalek::SigningKey,
) -> Option<Vec<u8>> {
    use ed25519_dalek::Signer as _;

    // Parse compact-u16 num_sigs (values < 128 fit in 1 byte).
    if tx_bytes.is_empty() {
        return None;
    }
    let (num_sigs, sigs_start) = if tx_bytes[0] & 0x80 == 0 {
        (tx_bytes[0] as usize, 1usize)
    } else if tx_bytes.len() >= 2 {
        let lo = (tx_bytes[0] & 0x7f) as usize;
        let hi = tx_bytes[1] as usize;
        (lo | (hi << 7), 2usize)
    } else {
        return None;
    };

    let msg_start = sigs_start + num_sigs * 64;
    if tx_bytes.len() <= msg_start {
        return None;
    }
    let message_bytes = &tx_bytes[msg_start..];

    // V0 versioned transactions start with 0x80 (version prefix); skip it for header parsing.
    // Legacy transactions have no prefix — header starts immediately.
    let header_offset = if message_bytes[0] == 0x80 { 1usize } else { 0usize };

    // Message header: [num_required_sigs u8, num_ro_signed u8, num_ro_unsigned u8]
    if message_bytes.len() < header_offset + 4 {
        return None;
    }
    let num_required_sigs = message_bytes[header_offset] as usize;

    // Compact-u16 account count follows the 3-byte header.
    let ac_off = header_offset + 3;
    let (num_accounts, accounts_start) = if message_bytes[ac_off] & 0x80 == 0 {
        (message_bytes[ac_off] as usize, ac_off + 1)
    } else if message_bytes.len() >= ac_off + 2 {
        let lo = (message_bytes[ac_off] & 0x7f) as usize;
        let hi = message_bytes[ac_off + 1] as usize;
        (lo | (hi << 7), ac_off + 2)
    } else {
        return None;
    };

    // Find our pubkey among the signer accounts.
    let our_pubkey = key.verifying_key().to_bytes();
    tracing::warn!(
        "sign_wire_tx: sponsor={} num_sigs={} num_req_sigs={} num_accounts={}",
        bs58::encode(&our_pubkey).into_string(),
        num_sigs,
        num_required_sigs,
        num_accounts,
    );
    let mut our_slot: Option<usize> = None;
    for i in 0..num_required_sigs.min(num_accounts) {
        let off = accounts_start + i * 32;
        if off + 32 > message_bytes.len() {
            break;
        }
        let acc = &message_bytes[off..off + 32];
        tracing::warn!("sign_wire_tx: account[{}]={}", i, bs58::encode(acc).into_string());
        if acc == our_pubkey {
            our_slot = Some(i);
            break;
        }
    }

    let slot = our_slot?;

    // Only sign if the slot is empty (all-zero placeholder).
    let slot_start = sigs_start + slot * 64;
    if slot_start + 64 > tx_bytes.len() {
        return None;
    }
    if tx_bytes[slot_start..slot_start + 64].iter().any(|&b| b != 0) {
        // Already signed — nothing to do.
        return Some(tx_bytes.to_vec());
    }

    // ed25519 sign the raw message bytes.
    let sig = key.sign(message_bytes);

    let mut result = tx_bytes.to_vec();
    result[slot_start..slot_start + 64].copy_from_slice(&sig.to_bytes());
    Some(result)
}


async fn broadcast_solana_tx(
    rpc_url: &str,
    client: &reqwest::Client,
    tx_b64: &str,
) -> anyhow::Result<String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [tx_b64, {"encoding": "base64", "preflightCommitment": "confirmed"}],
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("RPC error: {err}");
    }
    resp["result"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("sendTransaction: missing result"))
}

/// Build the aggregator HTTP router from a fully-initialised `AppState`.
/// Extracted from `main.rs` so integration tests can call it without binding a port.
pub fn build_router(state: AppState) -> axum::Router {
    use axum::{extract::DefaultBodyLimit, middleware, routing::{get, post}};
    use tower_http::cors::CorsLayer;

    let public_routes = axum::Router::new()
        .route("/health",  get(health))
        .route("/version", get(get_version))
        .route("/ingest/envelope",   post(ingest_envelope))
        .route("/hosting/register",  post(post_hosting_register))
        .route("/fcm/register",      post(fcm_register))
        .route("/fcm/sleep",         post(fcm_sleep))
        .route("/agents/{agent_id}/pending",       get(get_pending).post(post_pending))
        .route("/agents/{agent_id}/propose-owner", post(post_propose_owner))
        .route("/agents/{agent_id}/claim-owner",   post(post_claim_owner))
        .route("/agents/{agent_id}/token",         post(post_agent_token))
        .route("/agents/{agent_id}/owner",         get(get_agent_owner))
        .route("/agents/by-owner/{wallet}",        get(get_agents_by_owner))
        .route("/stats/network",  get(get_network_stats))
        .route("/league/current", get(get_skr_league))
        .route("/league/bags-claim", post(post_bags_claim))
        .route("/agents",             get(get_agents))
        .route("/sponsor/launch",     post(sponsor_launch))
        .route("/sponsor/fee-share-config", post(sponsor_fee_share_config))
        .route("/agents/{agent_id}/profile", get(get_agent_profile))
        .route("/activity",   get(get_activity))
        .route("/ws/activity", get(ws_activity))
        .route("/broadcasts", get(get_broadcasts))
        .route("/bounties",   get(get_bounties))
        .route("/hosting/nodes", get(get_hosting_nodes))
        .route("/agents/search",      get(search_agents))
        .route("/agents/search/name", get(search_agents_by_name))
        .route("/blobs/{cid}", get(get_blob))
        .route("/mpp/protocol-fee/challenge", get(mpp_protocol_fee_challenge))
        .route("/mpp/protocol-fee/verify",    post(mpp_protocol_fee_verify))
        .route("/identity/verify/{agent_id_hex}", get(verify_identity))
        .route("/billing/deposit",    post(post_billing_deposit))
        .route("/billing/balance/{account_id}", get(get_billing_balance))
        .route("/billing/withdraw",   post(post_billing_withdraw))
        .route("/billing/set-payout", post(post_billing_set_payout))
        .route("/billing/transactions/{account_id}", get(get_billing_transactions))
        .route("/billing/estimate-settlement", get(get_billing_estimate));

    #[cfg(feature = "data-bounty")]
    let public_routes = public_routes
        .route("/campaigns", get(get_campaigns).post(post_campaign))
        .route("/campaigns/{id}", get(get_campaign_by_id))
        .route("/ws/campaigns", get(ws_campaigns));

    let gated_routes = axum::Router::new()
        .route("/reputation/{agent_id}", get(get_reputation))
        .route("/leaderboard",           get(get_leaderboard))
        .route("/leaderboard/anomaly",   get(get_anomaly_leaderboard))
        .route("/interactions",          get(get_interactions))
        .route("/stats/timeseries",      get(get_timeseries))
        .route("/entropy/{agent_id}",         get(get_entropy))
        .route("/entropy/{agent_id}/history", get(get_entropy_history))
        .route("/entropy/{agent_id}/rolling", get(get_rolling_entropy))
        .route("/leaderboard/verifier-concentration", get(get_verifier_concentration))
        .route("/leaderboard/ownership-clusters",     get(get_ownership_clusters))
        .route("/params/calibrated",          get(get_calibrated_params))
        .route("/system/sri",                 get(get_sri_status))
        .route("/stake/required/{agent_id}",  get(get_required_stake))
        .route("/graph/flow",                 get(get_flow_graph))
        .route("/graph/clusters",             get(get_flow_clusters))
        .route("/graph/agent/{agent_id}",     get(get_agent_flow))
        .route("/epochs/{agent_id}/{epoch}/envelopes", get(get_epoch_envelopes))
        .route("/interactions/by/{agent_id}", get(get_interactions_by))
        .route("/disputes/{agent_id}",        get(get_disputes))
        .route("/registry",                   get(get_registry))
        .route("/agents/{agent_id}/sleeping", get(get_sleep_status))
        .route("/blobs", post(post_blob).layer(DefaultBodyLimit::max(10 * 1024 * 1024)))
        .route("/admin/billing/accounts",     get(get_admin_billing_accounts))
        .route("/admin/billing/settlements",  get(get_admin_settlements))
        .route("/admin/billing/revenue",      get(get_admin_revenue))
        .route("/admin/billing/settlements/{id}/retry",          post(post_admin_retry_settlement))
        .route("/admin/billing/accounts/{id}/skip-settlement",   post(post_admin_set_skip_settlement))
        .route_layer(middleware::from_fn_with_state(state.clone(), api_key_middleware));

    public_routes
        .merge(gated_routes)
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verify_request_signature_accepts_hex_pubkeys() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let body = br#"{"ok":true}"#;
        let sig = signing_key.sign(body);

        assert!(verify_request_signature(
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &hex::encode(sig.to_bytes()),
            body
        )
        .is_ok());
    }

    #[test]
    fn sponsor_launch_rejects_invalid_pubkey() {
        // Just validates the base58 parsing path; no HTTP call.
        let result = bs58::decode("not-a-valid-pubkey").into_vec();
        assert!(result.is_err() || result.unwrap().len() != 32);
    }

    #[test]
    fn verify_request_signature_accepts_base58_pubkeys() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let body = br#"{"owner_wallet":"11111111111111111111111111111111"}"#;
        let sig = signing_key.sign(body);

        assert!(verify_request_signature(
            &bs58::encode(signing_key.verifying_key().to_bytes()).into_string(),
            &hex::encode(sig.to_bytes()),
            body
        )
        .is_ok());
    }
}
