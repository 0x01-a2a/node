// The trade feature bundles Jupiter swap routing, USDC portfolio tracking, and
// Bags fee distribution — functionality that only makes sense on always-on
// mobile nodes (Android). Enabling it on server or desktop builds is a mistake.
#[cfg(not(target_os = "android"))]
compile_error!(
    "feature \"trade\" may only be enabled for Android targets \
     (target_os = \"android\"). Use `cargo ndk --target aarch64-linux-android`."
);

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

use ed25519_dalek::Signer;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::transaction::VersionedTransaction;

use crate::api::{
    require_api_secret_or_unauthorized, resolve_active_hosted_signing_key, resolve_hosted_token,
    ApiState, PortfolioEvent,
};

#[derive(Deserialize)]
pub struct SwapRequest {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: u64,
    pub slippage_bps: Option<u16>,
}

#[derive(Serialize)]
pub struct SwapResponse {
    pub out_amount: u64,
    pub txid: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct JupiterQuoteResponse {
    #[serde(rename = "outAmount")]
    out_amount: String,
    // (Other fields are ignored)
}

// ── Jupiter API endpoints ─────────────────────────────────────────────────
/// Free public endpoint — no API key required, rate-limited.
/// Use `--jupiter-api-url https://api.jup.ag` with x-api-key for higher limits.
const JUPITER_LITE_BASE: &str = "https://lite-api.jup.ag";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JupiterSwapRequest {
    user_public_key: String,
    quote_response: serde_json::Value,
    dynamic_compute_unit_limit: bool,
    /// `{ "priorityLevelWithMaxLamports": { "maxLamports": 1000000, "priorityLevel": "high" } }`
    prioritization_fee_lamports: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_account: Option<String>,
}

#[derive(Deserialize, Debug)]
struct JupiterSwapResponse {
    #[serde(rename = "swapTransaction")]
    swap_transaction: String,
}

// ── Swap whitelist ────────────────────────────────────────────────────────

/// Previously enforced whitelist — kept for reference, no longer checked at runtime.
#[allow(dead_code)]
/// Token mints allowed in agent-to-agent swaps.
///
/// Enforced at the node level so the protection applies to every caller
/// (SDK, ZeroClaw, custom agents) regardless of which client they use.
/// Both mainnet and devnet mints are included.
const SWAP_WHITELIST: &[&str] = &[
    // SOL (wrapped)
    "So11111111111111111111111111111111111111112",
    // USDC — mainnet
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    // USDC — devnet
    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    // USDT — mainnet
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    // JUP
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN",
    // BONK
    "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
    // RAY
    "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
    // WIF
    "EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm",
    // BAGS — mainnet
    "Bags4uLBdNscWBnHmqBozrjSScnEqPx5qZBzLiqnRVN7",
];

#[allow(dead_code)]
fn is_whitelisted(mint: &str) -> bool {
    SWAP_WHITELIST.contains(&mint)
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Returns true if `s` looks like a valid base58-encoded Solana public key
/// (32-44 characters, base58 alphabet only).
fn is_valid_pubkey(s: &str) -> bool {
    matches!(s.len(), 32..=44)
        && s.chars().all(|c| {
            matches!(c,
                '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
            )
        })
}

/// Known token mint decimal precision. Returns `None` for unrecognised mints.
fn mint_decimals(mint: &str) -> Option<i32> {
    match mint {
        // SOL (wrapped)
        "So11111111111111111111111111111111111111112" => Some(9),
        // USDC mainnet
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" => Some(6),
        // USDC devnet
        "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" => Some(6),
        // USDT
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" => Some(6),
        // mSOL
        "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So" => Some(9),
        // ETH (Wormhole)
        "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs" => Some(8),
        // BONK
        "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263" => Some(5),
        _ => None,
    }
}

/// POST /trade/swap
pub async fn trade_swap_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<SwapRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        if let Some(signing_key) = resolve_active_hosted_signing_key(&state, &token).await {
            signing_key
        } else {
            return err_resp(StatusCode::UNAUTHORIZED, "invalid or expired token".into());
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    };

    let signer = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes());

    // ── Input validation ──────────────────────────────────────────────────
    if !is_valid_pubkey(&req.input_mint) || !is_valid_pubkey(&req.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid mint".into());
    }
    if req.input_mint == req.output_mint {
        return err_resp(StatusCode::BAD_REQUEST, "mints must differ".into());
    }
    if req.amount == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "amount must be > 0".into());
    }

    let slippage = req.slippage_bps.unwrap_or(50);
    if slippage > 1_000 {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "slippage_bps cannot exceed 1000 (10%)".into(),
        );
    }

    let input_decimals = mint_decimals(&req.input_mint).unwrap_or(6);
    let output_decimals = mint_decimals(&req.output_mint).unwrap_or(6);

    tracing::info!(
        "Swap: {} - {} to {} amount {}",
        signer,
        req.input_mint,
        req.output_mint,
        req.amount
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    // 1. Get Jupiter Quote
    let jupiter_base = state
        .inner()
        .jupiter_api_url
        .as_deref()
        .unwrap_or(JUPITER_LITE_BASE);
    let fee_bps = state.inner().jupiter_fee_bps;
    let quote_url = if fee_bps > 0 && state.inner().jupiter_fee_account.is_some() {
        format!(
            "{}/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}&platformFeeBps={}",
            jupiter_base, req.input_mint, req.output_mint, req.amount, slippage, fee_bps
        )
    } else {
        format!(
            "{}/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
            jupiter_base, req.input_mint, req.output_mint, req.amount, slippage
        )
    };

    let quote_res = match client.get(&quote_url).send().await {
        Ok(res) => res,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Quote fail: {e}")),
    };

    if !quote_res.status().is_success() {
        return err_resp(
            StatusCode::BAD_GATEWAY,
            "Jupiter Quote returned error".into(),
        );
    }

    let quote_json: serde_json::Value = match quote_res.json().await {
        Ok(j) => j,
        Err(e) => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse quote: {e}"),
            )
        }
    };

    let out_amount_str = quote_json
        .get("outAmount")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let out_amount: u64 = out_amount_str.parse().unwrap_or(0);

    // Wrapped SOL mint — if the user is selling SOL they already have gas,
    // so Kora sponsorship is unnecessary. Only sponsor token→anything swaps.
    const WRAPPED_SOL: &str = "So11111111111111111111111111111111111111112";
    let selling_sol = req.input_mint == WRAPPED_SOL;

    // Resolve Kora fee payer only when sponsorship is appropriate and the
    // daily budget has not been exhausted.
    let kora_fee_payer_opt =
        if !selling_sol && crate::api::try_use_kora_budget(&state).await {
            if let Some(ref kora) = state.inner().kora {
                match kora.get_fee_payer().await {
                    Ok(fp) => Some(fp),
                    Err(e) => {
                        tracing::warn!("Kora fee payer unavailable, agent pays gas: {e}");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

    let swap_req = JupiterSwapRequest {
        user_public_key: signer.to_string(),
        quote_response: quote_json,
        dynamic_compute_unit_limit: true,
        prioritization_fee_lamports: serde_json::json!({
            "priorityLevelWithMaxLamports": {
                "maxLamports": 1_000_000,
                "priorityLevel": "high"
            }
        }),
        // When Kora is active it sets the gas fee payer; otherwise use our
        // Jupiter referral token account to collect platform fees.
        fee_account: if kora_fee_payer_opt.is_some() {
            kora_fee_payer_opt
                .as_ref()
                .map(|p: &solana_sdk::pubkey::Pubkey| p.to_string())
        } else {
            state.inner().jupiter_fee_account.clone()
        },
    };

    let swap_url = format!("{}/swap/v1/swap", jupiter_base);
    let swap_res = match client
        .post(&swap_url)
        .json(&swap_req)
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Swap req fail: {e}")),
    };

    if !swap_res.status().is_success() {
        return err_resp(
            StatusCode::BAD_GATEWAY,
            "Jupiter Swap returned error".into(),
        );
    }

    let swap_data: JupiterSwapResponse = match swap_res.json().await {
        Ok(d) => d,
        Err(_) => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid JSON from Jupiter".into(),
            )
        }
    };

    let tx_bytes = B64.decode(&swap_data.swap_transaction).unwrap_or_default();
    let mut versioned_tx: VersionedTransaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Invalid tx bytes".into()),
    };

    if kora_fee_payer_opt.is_none() {
        let fee_payer_ok = match &versioned_tx.message {
            solana_sdk::message::VersionedMessage::Legacy(msg) => {
                msg.account_keys.first() == Some(&signer)
            }
            solana_sdk::message::VersionedMessage::V0(msg) => {
                msg.account_keys.first() == Some(&signer)
            }
        };
        if !fee_payer_ok {
            return err_resp(
                StatusCode::BAD_GATEWAY,
                "Jupiter returned unexpected fee payer".into(),
            );
        }
    }

    let msg_bytes = versioned_tx.message.serialize();
    let sig = signing_key.sign(&msg_bytes);

    // Use Kora only when a fee payer was successfully resolved above
    // (i.e. not selling SOL, budget available, Kora online).
    let txid = if let Some(ref kora_fee_payer) = kora_fee_payer_opt {
        let _ = kora_fee_payer; // fee payer already embedded in the Jupiter tx
        let kora = state.inner().kora.as_ref().unwrap(); // safe: kora_fee_payer_opt implies kora is Some
        let signer_index = versioned_tx
            .message
            .static_account_keys()
            .iter()
            .position(|&k| k == signer);
        if let Some(idx) = signer_index {
            if idx < versioned_tx.signatures.len() {
                versioned_tx.signatures[idx] =
                    solana_sdk::signature::Signature::from(sig.to_bytes());
            } else {
                return err_resp(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Signer missing from signatures".into(),
                );
            }
        }

        let tx_b64 = B64.encode(bincode::serialize(&versioned_tx).unwrap());
        match kora.sign_and_send(&tx_b64).await {
            Ok(s) => s,
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Kora send failed: {e}")),
        }
    } else {
        // Agent is fee payer — normal broadcast (works for SOL swaps and Kora fallback).
        if !versioned_tx.signatures.is_empty() {
            versioned_tx.signatures[0] = solana_sdk::signature::Signature::from(sig.to_bytes());
        }
        let rpc_client = RpcClient::new(state.inner().trade_rpc_url.clone());
        match rpc_client.send_and_confirm_transaction(&versioned_tx).await {
            Ok(s) => s.to_string(),
            Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Broadcast failed: {e}")),
        }
    };

    // 5a. Bags fee-sharing: route a cut of the swap output to the Bags distribution wallet.
    #[cfg(feature = "bags")]
    if let Some(bags) = state.inner().bags_config.as_ref() {
        // out_amount is in the output token's native units. Only apply when
        // swapping to USDC so the fee is paid in a stable asset.
        let is_usdc_output = req.output_mint == crate::api::USDC_MINT_MAINNET
            || req.output_mint == crate::api::USDC_MINT_DEVNET;
        if is_usdc_output {
            let fee = ((out_amount as u128 * bags.fee_bps as u128) / 10_000) as u64;
            if fee >= bags.min_fee_micro {
                let bags = bags.clone();
                let sk = state.inner().node_signing_key.clone();
                let rpc = state.inner().trade_rpc_url.clone();
                let client = state.inner().http_client.clone();
                let mainnet = state.inner().is_trading_mainnet;
                let state2 = state.clone();
                tokio::spawn(async move {
                    match crate::bags::distribute_fee(sk, fee, &bags, &rpc, &client, mainnet).await
                    {
                        Ok(txid) => {
                            tracing::info!("Bags swap fee distributed: {txid} ({fee} micro)");
                            state2
                                .record_portfolio_event(PortfolioEvent::BagsFee {
                                    amount_usdc: fee as f64 / 1_000_000.0,
                                    txid,
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                })
                                .await;
                        }
                        Err(e) => tracing::warn!("Bags swap fee failed: {e}"),
                    }
                });
            }
        }
    }

    // 5b. Record swap event in portfolio history
    state
        .record_portfolio_event(PortfolioEvent::Swap {
            input_mint: req.input_mint.clone(),
            output_mint: req.output_mint.clone(),
            input_amount: req.amount as f64 / 10f64.powi(input_decimals),
            output_amount: out_amount as f64 / 10f64.powi(output_decimals),
            txid: txid.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
        .await;

    Json(SwapResponse { out_amount, txid }).into_response()
}

fn err_resp(code: StatusCode, msg: String) -> Response {
    tracing::warn!("trade_swap_handler error: {}", msg);
    (code, Json(serde_json::json!({ "error": msg }))).into_response()
}

// ============================================================================
// Quote API
// ============================================================================

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuoteQuery {
    pub input_mint: String,
    pub output_mint: String,
    pub amount: u64,
    pub slippage_bps: Option<u16>,
}

/// GET /trade/quote
pub async fn trade_quote_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<QuoteQuery>,
) -> Response {
    if resolve_hosted_token(&headers).is_none()
        && require_api_secret_or_unauthorized(&state, &headers).is_some()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "error": "unauthorized. require api secret or hosted token" }),
            ),
        )
            .into_response();
    }

    if !is_valid_pubkey(&query.input_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid input_mint".into());
    }
    if !is_valid_pubkey(&query.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid output_mint".into());
    }
    if query.amount == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "amount must be > 0".into());
    }

    let slippage = query.slippage_bps.unwrap_or(50);
    let client = reqwest::Client::new();

    let jupiter_base = state
        .inner()
        .jupiter_api_url
        .as_deref()
        .unwrap_or(JUPITER_LITE_BASE);
    let quote_url = format!(
        "{}/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        jupiter_base, query.input_mint, query.output_mint, query.amount, slippage
    );

    let res = match client.get(&quote_url).send().await {
        Ok(r) => r,
        Err(e) => {
            return err_resp(
                StatusCode::BAD_GATEWAY,
                format!("Jupiter request failed: {e}"),
            )
        }
    };

    if !res.status().is_success() {
        return err_resp(
            StatusCode::BAD_GATEWAY,
            format!("Jupiter Error: {}", res.status()),
        );
    }

    let json: serde_json::Value = match res.json().await {
        Ok(j) => j,
        Err(_) => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid JSON from Jupiter".into(),
            )
        }
    };

    Json(json).into_response()
}

// ============================================================================
// Price, token search, limit orders, DCA
// ============================================================================

/// Jupiter token list base — free, no key required.
const JUPITER_TOKEN_BASE: &str = "https://tokens.jup.ag";

/// Jupiter full API base — used for limit orders and DCA.
/// Identical to the lite base for price/quote but needed separately for routing.
const JUPITER_FULL_BASE: &str = "https://api.jup.ag";

fn jup_swap_base(state: &ApiState) -> &str {
    state.inner().jupiter_api_url.as_deref().unwrap_or(JUPITER_LITE_BASE)
}

// ── Price ──────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct PriceQuery {
    /// Comma-separated list of token mint addresses.
    pub ids: String,
}

/// GET /trade/price?ids=mint1,mint2,...
///
/// Returns current USD price for each mint via Jupiter Price API v2.
pub async fn trade_price_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<PriceQuery>,
) -> Response {
    if resolve_hosted_token(&headers).is_none()
        && require_api_secret_or_unauthorized(&state, &headers).is_some()
    {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    }
    // Validate each mint looks like a pubkey before hitting upstream.
    for id in query.ids.split(',') {
        let id = id.trim();
        if !id.is_empty() && !is_valid_pubkey(id) {
            return err_resp(StatusCode::BAD_REQUEST, format!("invalid mint: {id}"));
        }
    }
    let url = format!(
        "{}/price/v2?ids={}",
        jup_swap_base(&state),
        query.ids
    );
    let client = reqwest::Client::new();
    let res = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("Jupiter price failed: {e}")),
    };
    if !res.status().is_success() {
        return err_resp(StatusCode::BAD_GATEWAY, format!("Jupiter price error: {}", res.status()));
    }
    match res.json::<serde_json::Value>().await {
        Ok(j) => Json(j).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("Jupiter price parse: {e}")),
    }
}

// ── Token search ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct TokenSearchQuery {
    /// Search term — matches name or symbol.
    pub q: String,
}

/// GET /trade/tokens?q=search_term
///
/// Searches the Jupiter verified token list by name or symbol.
pub async fn trade_tokens_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<TokenSearchQuery>,
) -> Response {
    if resolve_hosted_token(&headers).is_none()
        && require_api_secret_or_unauthorized(&state, &headers).is_some()
    {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    }
    let q = query.q.trim().to_string();
    if q.is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "q must not be empty".into());
    }
    // Encode the query param safely.
    let encoded: String = q.chars().flat_map(|c| {
        if c.is_alphanumeric() || matches!(c, '-' | '_' | ' ') {
            vec![c]
        } else {
            format!("%{:02X}", c as u32).chars().collect()
        }
    }).collect::<String>().replace(' ', "+");

    let url = format!("{}/search?query={}&limit=20", JUPITER_TOKEN_BASE, encoded);
    let client = reqwest::Client::new();
    let res = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("token search failed: {e}")),
    };
    if !res.status().is_success() {
        return err_resp(StatusCode::BAD_GATEWAY, format!("token search error: {}", res.status()));
    }
    match res.json::<serde_json::Value>().await {
        Ok(j) => Json(j).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("token search parse: {e}")),
    }
}

// ── Limit orders ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct LimitCreateRequest {
    pub input_mint: String,
    pub output_mint: String,
    /// Amount of input_mint to spend (in base units).
    pub making_amount: u64,
    /// Amount of output_mint to receive (in base units).
    pub taking_amount: u64,
    /// Optional unix timestamp when the order expires.
    pub expired_at: Option<u64>,
}

/// POST /trade/limit/create — place a limit order via Jupiter Limit Order v2.
///
/// Builds the order tx, signs with the agent key, and broadcasts.
pub async fn trade_limit_create_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<LimitCreateRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        match resolve_active_hosted_signing_key(&state, &token).await {
            Some(k) => k,
            None => return err_resp(StatusCode::UNAUTHORIZED, "invalid token".into()),
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    };

    if !is_valid_pubkey(&req.input_mint) || !is_valid_pubkey(&req.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid mint".into());
    }
    if req.input_mint == req.output_mint {
        return err_resp(StatusCode::BAD_REQUEST, "mints must differ".into());
    }
    if req.making_amount == 0 || req.taking_amount == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "amounts must be > 0".into());
    }

    let wallet = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes()).to_string();
    let url = format!("{}/limit/v2/createOrder", JUPITER_FULL_BASE);
    let body = serde_json::json!({
        "inputMint": req.input_mint,
        "outputMint": req.output_mint,
        "maker": wallet,
        "payer": wallet,
        "params": {
            "makingAmount": req.making_amount.to_string(),
            "takingAmount": req.taking_amount.to_string(),
            "expiredAt": req.expired_at,
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let res = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("limit create failed: {e}")),
    };
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return err_resp(StatusCode::BAD_GATEWAY, format!("limit create error {status}: {text}"));
    }
    let order_json: serde_json::Value = match res.json().await {
        Ok(j) => j,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("limit parse: {e}")),
    };

    // Sign and broadcast the returned transaction.
    let tx_b64 = match order_json.get("tx").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_resp(StatusCode::BAD_GATEWAY, "limit create: missing tx field".into()),
    };
    let order_key = order_json.get("order").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let tx_bytes = match B64.decode(&tx_b64) {
        Ok(b) => b,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("limit tx decode: {e}")),
    };
    let mut versioned_tx: VersionedTransaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("limit tx deserialize: {e}")),
    };
    let signer_pk = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes());
    let msg_bytes = versioned_tx.message.serialize();
    let sig = signing_key.sign(&msg_bytes);
    if let Some(idx) = versioned_tx.message.static_account_keys().iter().position(|&k| k == signer_pk) {
        if idx < versioned_tx.signatures.len() {
            versioned_tx.signatures[idx] = solana_sdk::signature::Signature::from(sig.to_bytes());
        }
    }
    let rpc = RpcClient::new(state.inner().trade_rpc_url.clone());
    match rpc.send_and_confirm_transaction(&versioned_tx).await {
        Ok(txid) => Json(serde_json::json!({ "order": order_key, "txid": txid.to_string() })).into_response(),
        Err(e) => err_resp(StatusCode::BAD_GATEWAY, format!("limit broadcast: {e}")),
    }
}

#[derive(serde::Deserialize)]
pub struct LimitOrdersQuery {
    pub wallet: Option<String>,
}

/// GET /trade/limit/orders — list open limit orders for the agent wallet.
pub async fn trade_limit_orders_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<LimitOrdersQuery>,
) -> Response {
    if resolve_hosted_token(&headers).is_none()
        && require_api_secret_or_unauthorized(&state, &headers).is_some()
    {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    }
    let wallet = match query.wallet {
        Some(w) => w,
        None => {
            let pk = solana_sdk::pubkey::Pubkey::from(state.inner().node_signing_key.verifying_key().to_bytes());
            pk.to_string()
        }
    };
    let url = format!("{}/limit/v2/openOrders?wallet={}", JUPITER_FULL_BASE, wallet);
    let client = reqwest::Client::new();
    let res = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("limit orders failed: {e}")),
    };
    if !res.status().is_success() {
        return err_resp(StatusCode::BAD_GATEWAY, format!("limit orders error: {}", res.status()));
    }
    match res.json::<serde_json::Value>().await {
        Ok(j) => Json(j).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("limit orders parse: {e}")),
    }
}

#[derive(serde::Deserialize)]
pub struct LimitCancelRequest {
    pub orders: Vec<String>,
}

/// POST /trade/limit/cancel — cancel one or more open limit orders.
///
/// Signs and broadcasts each cancel transaction returned by Jupiter.
pub async fn trade_limit_cancel_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<LimitCancelRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        match resolve_active_hosted_signing_key(&state, &token).await {
            Some(k) => k,
            None => return err_resp(StatusCode::UNAUTHORIZED, "invalid token".into()),
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    };

    if req.orders.is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "orders must not be empty".into());
    }

    let wallet = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes()).to_string();
    let url = format!("{}/limit/v2/cancelOrders", JUPITER_FULL_BASE);
    let body = serde_json::json!({
        "maker": wallet,
        "computeUnitPrice": "auto",
        "orders": req.orders,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let res = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("limit cancel failed: {e}")),
    };
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return err_resp(StatusCode::BAD_GATEWAY, format!("limit cancel error {status}: {text}"));
    }
    let cancel_json: serde_json::Value = match res.json().await {
        Ok(j) => j,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("cancel parse: {e}")),
    };

    let txs = cancel_json.get("txs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let signer_pk = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes());
    let rpc = RpcClient::new(state.inner().trade_rpc_url.clone());
    let mut txids: Vec<String> = Vec::new();

    for tx_val in &txs {
        let tx_b64 = match tx_val.as_str() {
            Some(s) => s,
            None => continue,
        };
        let tx_bytes = match B64.decode(tx_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut vtx: VersionedTransaction = match bincode::deserialize(&tx_bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let msg_bytes = vtx.message.serialize();
        let sig = signing_key.sign(&msg_bytes);
        if let Some(idx) = vtx.message.static_account_keys().iter().position(|&k| k == signer_pk) {
            if idx < vtx.signatures.len() {
                vtx.signatures[idx] = solana_sdk::signature::Signature::from(sig.to_bytes());
            }
        }
        match rpc.send_and_confirm_transaction(&vtx).await {
            Ok(s) => txids.push(s.to_string()),
            Err(e) => tracing::warn!("limit cancel broadcast failed: {e}"),
        }
    }

    Json(serde_json::json!({ "cancelled": txids.len(), "txids": txids })).into_response()
}

// ── DCA ────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct DcaCreateRequest {
    pub input_mint: String,
    pub output_mint: String,
    /// Total amount of input_mint to DCA (base units).
    pub in_amount: u64,
    /// Amount to swap per cycle (base units).
    pub in_amount_per_cycle: u64,
    /// Seconds between each swap cycle.
    pub cycle_seconds: u64,
    /// Optional minimum output per cycle (base units).
    pub min_out_amount_per_cycle: Option<u64>,
    /// Optional maximum output per cycle (base units).
    pub max_out_amount_per_cycle: Option<u64>,
}

/// POST /trade/dca/create — create a DCA (dollar-cost averaging) order.
///
/// Builds the DCA tx, signs, and broadcasts.
pub async fn trade_dca_create_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<DcaCreateRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        match resolve_active_hosted_signing_key(&state, &token).await {
            Some(k) => k,
            None => return err_resp(StatusCode::UNAUTHORIZED, "invalid token".into()),
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err_resp(StatusCode::UNAUTHORIZED, "unauthorized".into());
    };

    if !is_valid_pubkey(&req.input_mint) || !is_valid_pubkey(&req.output_mint) {
        return err_resp(StatusCode::BAD_REQUEST, "invalid mint".into());
    }
    if req.input_mint == req.output_mint {
        return err_resp(StatusCode::BAD_REQUEST, "mints must differ".into());
    }
    if req.in_amount == 0 || req.in_amount_per_cycle == 0 || req.cycle_seconds == 0 {
        return err_resp(StatusCode::BAD_REQUEST, "amounts and cycle_seconds must be > 0".into());
    }
    if req.in_amount_per_cycle > req.in_amount {
        return err_resp(StatusCode::BAD_REQUEST, "in_amount_per_cycle cannot exceed in_amount".into());
    }

    let wallet = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes()).to_string();
    let url = format!("{}/dca/v2/createDca", JUPITER_FULL_BASE);
    let body = serde_json::json!({
        "payer": wallet,
        "inputMint": req.input_mint,
        "outputMint": req.output_mint,
        "inAmount": req.in_amount,
        "inAmountPerCycle": req.in_amount_per_cycle,
        "cycleSecondsApart": req.cycle_seconds,
        "minOutAmountPerCycle": req.min_out_amount_per_cycle,
        "maxOutAmountPerCycle": req.max_out_amount_per_cycle,
        "startAt": null,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    let res = match client.post(&url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("DCA create failed: {e}")),
    };
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return err_resp(StatusCode::BAD_GATEWAY, format!("DCA create error {status}: {text}"));
    }
    let dca_json: serde_json::Value = match res.json().await {
        Ok(j) => j,
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("DCA parse: {e}")),
    };

    let tx_b64 = match dca_json.get("tx").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err_resp(StatusCode::BAD_GATEWAY, "DCA create: missing tx field".into()),
    };
    let dca_key = dca_json.get("dcaKey").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let tx_bytes = match B64.decode(&tx_b64) {
        Ok(b) => b,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("DCA tx decode: {e}")),
    };
    let mut versioned_tx: VersionedTransaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, format!("DCA tx deserialize: {e}")),
    };
    let signer_pk = solana_sdk::pubkey::Pubkey::from(signing_key.verifying_key().to_bytes());
    let msg_bytes = versioned_tx.message.serialize();
    let sig = signing_key.sign(&msg_bytes);
    if let Some(idx) = versioned_tx.message.static_account_keys().iter().position(|&k| k == signer_pk) {
        if idx < versioned_tx.signatures.len() {
            versioned_tx.signatures[idx] = solana_sdk::signature::Signature::from(sig.to_bytes());
        }
    }
    let rpc = RpcClient::new(state.inner().trade_rpc_url.clone());
    match rpc.send_and_confirm_transaction(&versioned_tx).await {
        Ok(txid) => Json(serde_json::json!({ "dca_key": dca_key, "txid": txid.to_string() })).into_response(),
        Err(e) => err_resp(StatusCode::BAD_GATEWAY, format!("DCA broadcast: {e}")),
    }
}
