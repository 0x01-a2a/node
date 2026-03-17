// LaunchLab (Raydium bonding-curve launchpad) integration.
//
// Revenue model: every buy/sell transaction on the LaunchLab bonding curve can
// include a `share_fee_receiver` account that earns 0.1% of the trade value
// atomically on-chain — no claiming step needed.
//
// Programmatic interface (no REST API exists; transactions are built client-side):
//   POST /trade/launchlab/buy  — buy tokens from bonding curve with share fee
//   POST /trade/launchlab/sell — sell tokens back to bonding curve with share fee
//
// References:
//   https://docs.raydium.io/raydium/pool-creation/launchlab
//   https://github.com/raydium-io/raydium-sdk-V2 (src/raydium/launchpad/)
//   Program ID: LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj (mainnet)

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
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
    transaction::Transaction,
};
use std::str::FromStr;

use crate::api::{
    require_api_secret_or_unauthorized, resolve_active_hosted_signing_key, resolve_hosted_token,
    ApiState,
};

// ── Program constants ─────────────────────────────────────────────────────

const LAUNCHPAD_PROGRAM: &str = "LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj";
/// Fixed authority PDA — derived from program with seed b"vault_and_lp_mint_auth_seed"
const LAUNCHPAD_AUTH: &str = "WLHv2UAZm6z4KyaaELi5pjdbJh6RESMva1Rnn8pJVVh";
/// Global config account (mainnet)
const LAUNCHPAD_CONFIG: &str = "6s1xP3hpbAfFoNtUNF8mfHsjr2Bd97JxFJRWLbL6aHuX";
/// Default Raydium platform account (mainnet)
const LAUNCHPAD_PLATFORM: &str = "4Bu96XjU84XjPDSpveTVf6LYGCkfW5FK7SNkREWcEfV4";

/// Raydium read-only API base.
const LAUNCHLAB_API_BASE: &str = "https://launch-mint-v1.raydium.io";

/// SPL Token program.
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Token-2022 program.
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
/// Associated Token Account program.
const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe8pb";

/// Share fee rate for our referral — 0.1% in LaunchLab's bps×100 scale
/// (10 000 = 1 %, so 1 000 = 0.1 %).
pub const DEFAULT_SHARE_FEE_RATE: u64 = 1_000;

// ── Anchor discriminator ──────────────────────────────────────────────────

/// Compute an 8-byte Anchor instruction discriminator:
/// `sha256("global:<name>")[0..8]`
fn discriminator(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}"));
    h.finalize()[..8].try_into().expect("sha256 is 32 bytes")
}

// ── Raydium pool info ─────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LaunchpadPoolInfo {
    pool_id: String,
    mint_a: String,
    mint_b: String,
    vault_a: String,
    vault_b: String,
    platform_id: Option<String>,
    /// Pool status — "1" = active on bonding curve, "2" = graduated.
    #[allow(dead_code)]
    status: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct LaunchpadApiResponse {
    data: Vec<LaunchpadPoolInfo>,
}

async fn fetch_pool_info(
    client: &reqwest::Client,
    mint: &str,
) -> Result<LaunchpadPoolInfo, String> {
    let url = format!("{LAUNCHLAB_API_BASE}/get/by/mints?ids={mint}");
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("LaunchLab API request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("LaunchLab API error: {}", resp.status()));
    }

    let body: LaunchpadApiResponse = resp
        .json()
        .await
        .map_err(|e| format!("LaunchLab API parse failed: {e}"))?;

    body.data
        .into_iter()
        .find(|p| p.mint_a.eq_ignore_ascii_case(mint))
        .ok_or_else(|| format!("Token {mint} not found on LaunchLab"))
}

// ── ATA derivation ────────────────────────────────────────────────────────

fn find_ata(wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()],
        &Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM).unwrap(),
    )
    .0
}

fn event_authority(program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], program)
        .0
}

// ── Instruction builders ──────────────────────────────────────────────────

/// Build instruction data for `buy`:
///   [discriminator:8][amount_in:u64 LE][minimum_amount_out:u64 LE][share_fee_rate:u64 LE]
fn build_buy_data(amount_in: u64, minimum_amount_out: u64, share_fee_rate: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(&discriminator("buy"));
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());
    data.extend_from_slice(&share_fee_rate.to_le_bytes());
    data
}

/// Build instruction data for `sell`:
///   [discriminator:8][amount_in:u64 LE][minimum_amount_out:u64 LE][share_fee_rate:u64 LE]
fn build_sell_data(amount_in: u64, minimum_amount_out: u64, share_fee_rate: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(&discriminator("sell"));
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());
    data.extend_from_slice(&share_fee_rate.to_le_bytes());
    data
}

fn pubkey(s: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(s).map_err(|e| format!("invalid pubkey {s}: {e}"))
}

/// Assemble the account list for a buy or sell instruction.
/// `share_fee_receiver` is appended last when set — the LaunchLab program
/// reads it by position, consistent with the TypeScript SDK's `instrument.ts`.
fn build_accounts(
    payer: &Pubkey,
    pool: &LaunchpadPoolInfo,
    share_fee_receiver: Option<&Pubkey>,
) -> Result<Vec<AccountMeta>, String> {
    let program = pubkey(LAUNCHPAD_PROGRAM)?;
    let mint_a = pubkey(&pool.mint_a)?;
    let mint_b = pubkey(&pool.mint_b)?;
    let vault_a = pubkey(&pool.vault_a)?;
    let vault_b = pubkey(&pool.vault_b)?;
    let pool_id = pubkey(&pool.pool_id)?;
    let platform_id = pubkey(
        pool.platform_id
            .as_deref()
            .unwrap_or(LAUNCHPAD_PLATFORM),
    )?;
    let auth = pubkey(LAUNCHPAD_AUTH)?;
    let config = pubkey(LAUNCHPAD_CONFIG)?;
    let token_program = pubkey(TOKEN_PROGRAM)?;
    let token_2022 = pubkey(TOKEN_2022_PROGRAM)?;
    let ata_program = pubkey(ASSOCIATED_TOKEN_PROGRAM)?;

    // Determine the token program for mintA (use Token-2022 for new launches
    // which default to Token-2022; Token for legacy mints).
    // We use Token-2022 as the default since LaunchLab v2 uses it.
    let mint_a_token_program = token_2022;

    let user_ata_a = find_ata(payer, &mint_a, &mint_a_token_program);
    let user_ata_b = find_ata(payer, &mint_b, &token_program);
    let event_auth = event_authority(&program);

    let mut accounts = vec![
        AccountMeta::new(*payer, true),          // payer / user (signer, writable)
        AccountMeta::new_readonly(auth, false),  // authority
        AccountMeta::new_readonly(config, false), // global config
        AccountMeta::new_readonly(platform_id, false), // platform
        AccountMeta::new(pool_id, false),        // launchpad pool (writable)
        AccountMeta::new_readonly(mint_a, false), // token mint
        AccountMeta::new(user_ata_a, false),     // user token ATA (writable)
        AccountMeta::new(vault_a, false),        // pool token vault (writable)
        AccountMeta::new_readonly(mint_b, false), // payment mint (SOL/USDC)
        AccountMeta::new(user_ata_b, false),     // user payment ATA (writable)
        AccountMeta::new(vault_b, false),        // pool payment vault (writable)
        AccountMeta::new_readonly(event_auth, false), // event authority
        AccountMeta::new_readonly(mint_a_token_program, false), // token program for mintA
        AccountMeta::new_readonly(token_program, false), // SPL Token program
        AccountMeta::new_readonly(token_2022, false), // Token-2022 program
        AccountMeta::new_readonly(ata_program, false), // ATA program
        AccountMeta::new_readonly(system_program::ID, false), // System program
    ];

    // Append share fee receiver as a writable account (no signer required).
    // This is exactly how the TypeScript SDK appends it in instrument.ts.
    if let Some(receiver) = share_fee_receiver {
        accounts.push(AccountMeta::new(*receiver, false));
    }

    Ok(accounts)
}

// ── HTTP request / response types ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct LaunchlabBuyRequest {
    /// Token mint address (base58) to buy from the LaunchLab bonding curve.
    pub mint: String,
    /// Amount of payment token (mintB, usually lamports of SOL) to spend.
    pub amount_in: u64,
    /// Minimum tokens to receive (0 = no slippage protection).
    pub minimum_amount_out: Option<u64>,
}

#[derive(Deserialize)]
pub struct LaunchlabSellRequest {
    /// Token mint address (base58) to sell back to the bonding curve.
    pub mint: String,
    /// Amount of tokens (mintA, base units) to sell.
    pub amount_in: u64,
    /// Minimum payment tokens to receive (0 = no slippage protection).
    pub minimum_amount_out: Option<u64>,
}

#[derive(Serialize)]
pub struct LaunchlabTradeResponse {
    pub txid: String,
    pub mint: String,
    /// Share fee rate actually used (0 if no fee receiver configured).
    pub share_fee_rate: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    let m = msg.into();
    tracing::warn!("launchlab error: {m}");
    (code, Json(serde_json::json!({ "error": m }))).into_response()
}

/// POST /trade/launchlab/buy
pub async fn launchlab_buy_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<LaunchlabBuyRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        match resolve_active_hosted_signing_key(&state, &token).await {
            Some(k) => k,
            None => return err(StatusCode::UNAUTHORIZED, "invalid or expired token"),
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };

    let payer = Pubkey::from(signing_key.verifying_key().to_bytes());

    // Validate mint
    let mint_pk = match Pubkey::from_str(&req.mint) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid mint pubkey"),
    };
    if req.amount_in == 0 {
        return err(StatusCode::BAD_REQUEST, "amount_in must be > 0");
    }

    // Fetch pool info from Raydium read API
    let pool = match fetch_pool_info(&state.inner().http_client, &req.mint).await {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_GATEWAY, e),
    };

    // Resolve share fee config
    let (share_fee_receiver, share_fee_rate) =
        match &state.inner().launchlab_share_fee_wallet {
            Some(wallet) => {
                let pk = match Pubkey::from_str(wallet) {
                    Ok(p) => p,
                    Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "invalid launchlab_share_fee_wallet config"),
                };
                (Some(pk), DEFAULT_SHARE_FEE_RATE)
            }
            None => (None, 0u64),
        };

    // Build instruction
    let accounts = match build_accounts(&payer, &pool, share_fee_receiver.as_ref()) {
        Ok(a) => a,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let data = build_buy_data(
        req.amount_in,
        req.minimum_amount_out.unwrap_or(0),
        share_fee_rate,
    );
    let program = match Pubkey::from_str(LAUNCHPAD_PROGRAM) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "invalid program id"),
    };
    let ix = Instruction { program_id: program, accounts, data };

    // Build, sign, and broadcast transaction
    let rpc = RpcClient::new(state.inner().trade_rpc_url.clone());
    let blockhash = match rpc.get_latest_blockhash().await {
        Ok(h) => h,
        Err(e) => return err(StatusCode::BAD_GATEWAY, format!("get blockhash: {e}")),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&ed25519_signing_key_to_solana(&signing_key)],
        blockhash,
    );

    match rpc.send_and_confirm_transaction(&tx).await {
        Ok(sig) => Json(LaunchlabTradeResponse {
            txid: sig.to_string(),
            mint: mint_pk.to_string(),
            share_fee_rate,
        })
        .into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("broadcast failed: {e}")),
    }
}

/// POST /trade/launchlab/sell
pub async fn launchlab_sell_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<LaunchlabSellRequest>,
) -> Response {
    let signing_key = if let Some(token) = resolve_hosted_token(&headers) {
        match resolve_active_hosted_signing_key(&state, &token).await {
            Some(k) => k,
            None => return err(StatusCode::UNAUTHORIZED, "invalid or expired token"),
        }
    } else if require_api_secret_or_unauthorized(&state, &headers).is_none() {
        state.inner().node_signing_key.as_ref().clone()
    } else {
        return err(StatusCode::UNAUTHORIZED, "unauthorized");
    };

    let payer = Pubkey::from(signing_key.verifying_key().to_bytes());

    let mint_pk = match Pubkey::from_str(&req.mint) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid mint pubkey"),
    };
    if req.amount_in == 0 {
        return err(StatusCode::BAD_REQUEST, "amount_in must be > 0");
    }

    let pool = match fetch_pool_info(&state.inner().http_client, &req.mint).await {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_GATEWAY, e),
    };

    let (share_fee_receiver, share_fee_rate) =
        match &state.inner().launchlab_share_fee_wallet {
            Some(wallet) => {
                let pk = match Pubkey::from_str(wallet) {
                    Ok(p) => p,
                    Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "invalid launchlab_share_fee_wallet config"),
                };
                (Some(pk), DEFAULT_SHARE_FEE_RATE)
            }
            None => (None, 0u64),
        };

    let accounts = match build_accounts(&payer, &pool, share_fee_receiver.as_ref()) {
        Ok(a) => a,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let data = build_sell_data(
        req.amount_in,
        req.minimum_amount_out.unwrap_or(0),
        share_fee_rate,
    );
    let program = match Pubkey::from_str(LAUNCHPAD_PROGRAM) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "invalid program id"),
    };
    let ix = Instruction { program_id: program, accounts, data };

    let rpc = RpcClient::new(state.inner().trade_rpc_url.clone());
    let blockhash = match rpc.get_latest_blockhash().await {
        Ok(h) => h,
        Err(e) => return err(StatusCode::BAD_GATEWAY, format!("get blockhash: {e}")),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&ed25519_signing_key_to_solana(&signing_key)],
        blockhash,
    );

    match rpc.send_and_confirm_transaction(&tx).await {
        Ok(sig) => Json(LaunchlabTradeResponse {
            txid: sig.to_string(),
            mint: mint_pk.to_string(),
            share_fee_rate,
        })
        .into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("broadcast failed: {e}")),
    }
}

// ── Solana signer adapter ─────────────────────────────────────────────────

/// Wrap an `ed25519_dalek::SigningKey` in a type that implements
/// `solana_sdk::signer::Signer`, which is required by `Transaction::new_signed_with_payer`.
struct Ed25519Signer(ed25519_dalek::SigningKey);

impl solana_sdk::signer::Signer for Ed25519Signer {
    fn pubkey(&self) -> solana_sdk::pubkey::Pubkey {
        solana_sdk::pubkey::Pubkey::from(self.0.verifying_key().to_bytes())
    }

    fn try_pubkey(&self) -> Result<solana_sdk::pubkey::Pubkey, solana_sdk::signer::SignerError> {
        Ok(self.pubkey())
    }

    fn sign_message(&self, message: &[u8]) -> solana_sdk::signature::Signature {
        let sig = self.0.sign(message);
        solana_sdk::signature::Signature::from(sig.to_bytes())
    }

    fn try_sign_message(
        &self,
        message: &[u8],
    ) -> Result<solana_sdk::signature::Signature, solana_sdk::signer::SignerError> {
        Ok(self.sign_message(message))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

fn ed25519_signing_key_to_solana(key: &ed25519_dalek::SigningKey) -> Ed25519Signer {
    Ed25519Signer(key.clone())
}
