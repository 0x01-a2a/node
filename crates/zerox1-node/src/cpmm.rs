// Raydium CPMM (Constant Product Market Maker) pool creation.
//
// Creates a new CPMM liquidity pool for a token pair.  Typical use case:
// create an AMM trading pool immediately after launching a token on Bags.
//
// Revenue model: the pool creator earns a share of every swap fee forever.
// With the default 0.25% fee tier, ~0.04% goes to LPs (pro-rata by share).
//
// Programmatic interface:
//   POST /trade/cpmm/create-pool — build, sign, and broadcast initialize ix
//
// References:
//   https://docs.raydium.io/raydium/pool-creation/creating-a-standard-amm-pool/raydium-cp-swap-cpmm
//   Program: CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxYB5qKP1C

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

// ── Program constants ──────────────────────────────────────────────────────

const CPMM_PROGRAM: &str = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxYB5qKP1C";
/// Raydium fee collection account for pool creation (~0.15 SOL).
const CPMM_CREATE_POOL_FEE: &str = "DNXgeM9EiiaAbaWvwjHj9fQQLAX5ZsfHyvmYUNRAdNC8";

const RAYDIUM_API_BASE: &str = "https://api-v3.raydium.io";

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe8pb";
/// Rent sysvar account address.
const SYSVAR_RENT: &str = "SysvarRent111111111111111111111111111111111";

// ── PDA seeds (from CPMM program source) ──────────────────────────────────

const AUTH_SEED: &[u8] = b"vault_and_lp_mint_auth_seed";
const POOL_SEED: &[u8] = b"pool";
const POOL_LP_MINT_SEED: &[u8] = b"pool_lp_mint";
const POOL_VAULT_SEED: &[u8] = b"pool_vault";
const OBSERVATION_SEED: &[u8] = b"observation";

// ── Raydium fee config API ─────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct CpmmFeeConfig {
    id: String,
    index: u64,
    #[allow(dead_code)]
    #[serde(rename = "tradeFeeRate")]
    trade_fee_rate: u64,
}

#[derive(Deserialize)]
struct CpmmConfigResponse {
    data: Vec<CpmmFeeConfig>,
}

async fn fetch_fee_config(
    client: &reqwest::Client,
    index: u64,
) -> Result<CpmmFeeConfig, String> {
    let url = format!("{RAYDIUM_API_BASE}/main/cpmm-config");
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("CPMM config API request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("CPMM config API error: {}", resp.status()));
    }

    let body: CpmmConfigResponse = resp
        .json()
        .await
        .map_err(|e| format!("CPMM config API parse failed: {e}"))?;

    body.data
        .into_iter()
        .find(|c| c.index == index)
        .ok_or_else(|| format!("CPMM fee config index {index} not found"))
}

// ── Mint program detection ─────────────────────────────────────────────────

/// Returns the token program that owns this mint (Token or Token-2022).
/// Falls back to TOKEN_PROGRAM if the RPC call fails.
async fn get_mint_program(rpc: &RpcClient, mint: &Pubkey) -> Pubkey {
    match rpc.get_account(mint).await {
        Ok(account) => account.owner,
        Err(_) => Pubkey::from_str(TOKEN_PROGRAM).unwrap(),
    }
}

// ── PDA derivation ─────────────────────────────────────────────────────────

fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}

fn cpmm_auth(program: &Pubkey) -> Pubkey {
    pda(&[AUTH_SEED], program)
}

fn pool_pda(program: &Pubkey, config: &Pubkey, mint_0: &Pubkey, mint_1: &Pubkey) -> Pubkey {
    pda(
        &[POOL_SEED, config.as_ref(), mint_0.as_ref(), mint_1.as_ref()],
        program,
    )
}

fn lp_mint_pda(program: &Pubkey, pool: &Pubkey) -> Pubkey {
    pda(&[POOL_LP_MINT_SEED, pool.as_ref()], program)
}

fn vault_pda(program: &Pubkey, pool: &Pubkey, mint: &Pubkey) -> Pubkey {
    pda(&[POOL_VAULT_SEED, pool.as_ref(), mint.as_ref()], program)
}

fn observation_pda(program: &Pubkey, pool: &Pubkey) -> Pubkey {
    pda(&[OBSERVATION_SEED, pool.as_ref()], program)
}

/// ATA derivation — same as in launchlab.rs.
fn find_ata(wallet: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()],
        &Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM).unwrap(),
    )
    .0
}

// ── Anchor discriminator ───────────────────────────────────────────────────

fn discriminator(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}"));
    h.finalize()[..8].try_into().expect("sha256 is 32 bytes")
}

// ── Instruction builder ────────────────────────────────────────────────────

/// Build instruction data for CPMM `initialize`:
///   [discriminator:8][init_amount_0:u64 LE][init_amount_1:u64 LE][open_time:u64 LE]
fn build_initialize_data(init_amount_0: u64, init_amount_1: u64, open_time: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(&discriminator("initialize"));
    data.extend_from_slice(&init_amount_0.to_le_bytes());
    data.extend_from_slice(&init_amount_1.to_le_bytes());
    data.extend_from_slice(&open_time.to_le_bytes());
    data
}

fn pubkey(s: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(s).map_err(|e| format!("invalid pubkey {s}: {e}"))
}

// ── HTTP request / response types ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct CpmmCreatePoolRequest {
    /// First token mint (will be sorted canonically with mint_b).
    pub mint_a: String,
    /// Second token mint (e.g. WSOL `So11111111111111111111111111111111111111112` or USDC).
    pub mint_b: String,
    /// Initial liquidity for mint_a (base units).
    pub amount_a: u64,
    /// Initial liquidity for mint_b (base units).
    pub amount_b: u64,
    /// Unix timestamp when swapping opens (0 = immediately).
    pub open_time: Option<u64>,
    /// Raydium fee tier index (0 = 0.25% default, see GET /main/cpmm-config).
    pub fee_config_index: Option<u64>,
}

#[derive(Serialize)]
pub struct CpmmCreatePoolResponse {
    pub txid: String,
    pub pool_id: String,
    pub lp_mint: String,
    /// Fee config ID used.
    pub fee_config_id: String,
}

// ── Handler ────────────────────────────────────────────────────────────────

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    let m = msg.into();
    tracing::warn!("cpmm error: {m}");
    (code, Json(serde_json::json!({ "error": m }))).into_response()
}

/// POST /trade/cpmm/create-pool
pub async fn cpmm_create_pool_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<CpmmCreatePoolRequest>,
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

    // Validate mint addresses.
    let mint_a_pk = match Pubkey::from_str(&req.mint_a) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid mint_a pubkey"),
    };
    let mint_b_pk = match Pubkey::from_str(&req.mint_b) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid mint_b pubkey"),
    };
    if req.amount_a == 0 || req.amount_b == 0 {
        return err(StatusCode::BAD_REQUEST, "amount_a and amount_b must be > 0");
    }

    let fee_config_index = req.fee_config_index.unwrap_or(0);
    let open_time = req.open_time.unwrap_or(0);

    // Fetch fee config from Raydium API.
    let fee_config = match fetch_fee_config(&state.inner().http_client, fee_config_index).await {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_GATEWAY, e),
    };
    let config_pk = match pubkey(&fee_config.id) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_GATEWAY, e),
    };

    let rpc = RpcClient::new(state.inner().trade_rpc_url.clone());

    // Detect token programs for each mint (Token vs Token-2022).
    let (prog_a, prog_b) = tokio::join!(
        get_mint_program(&rpc, &mint_a_pk),
        get_mint_program(&rpc, &mint_b_pk),
    );

    // CPMM requires mints sorted by pubkey bytes (ascending).
    // Adjust amounts to match the sorted order.
    let (mint_0, mint_1, prog_0, prog_1, amount_0, amount_1) =
        if mint_a_pk.as_ref() <= mint_b_pk.as_ref() {
            (mint_a_pk, mint_b_pk, prog_a, prog_b, req.amount_a, req.amount_b)
        } else {
            (mint_b_pk, mint_a_pk, prog_b, prog_a, req.amount_b, req.amount_a)
        };

    let payer = Pubkey::from(signing_key.verifying_key().to_bytes());

    let program = match pubkey(CPMM_PROGRAM) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // Derive all PDAs.
    let authority = cpmm_auth(&program);
    let pool_state = pool_pda(&program, &config_pk, &mint_0, &mint_1);
    let lp_mint = lp_mint_pda(&program, &pool_state);
    let token_0_vault = vault_pda(&program, &pool_state, &mint_0);
    let token_1_vault = vault_pda(&program, &pool_state, &mint_1);
    let observation_state = observation_pda(&program, &pool_state);

    // Creator token accounts (ATAs using the correct token program per mint).
    let creator_token_0 = find_ata(&payer, &mint_0, &prog_0);
    let creator_token_1 = find_ata(&payer, &mint_1, &prog_1);
    // LP token ATA uses SPL Token (LP mint is always standard SPL Token).
    let token_program_pk = match pubkey(TOKEN_PROGRAM) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let creator_lp_token = find_ata(&payer, &lp_mint, &token_program_pk);

    let create_pool_fee_pk = match pubkey(CPMM_CREATE_POOL_FEE) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let ata_program_pk = match pubkey(ASSOCIATED_TOKEN_PROGRAM) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let rent_pk = match pubkey(SYSVAR_RENT) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let token_2022_pk = match pubkey(TOKEN_2022_PROGRAM) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };

    // Build account list (matches Raydium SDK order exactly).
    let accounts = vec![
        AccountMeta::new(payer, true),                          // 0 creator (signer, writable)
        AccountMeta::new_readonly(config_pk, false),            // 1 amm_config
        AccountMeta::new_readonly(authority, false),            // 2 authority PDA
        AccountMeta::new(pool_state, false),                    // 3 pool_state PDA (writable)
        AccountMeta::new_readonly(mint_0, false),               // 4 token_0_mint
        AccountMeta::new_readonly(mint_1, false),               // 5 token_1_mint
        AccountMeta::new(lp_mint, false),                       // 6 lp_mint PDA (writable)
        AccountMeta::new(creator_token_0, false),               // 7 creator_token_0 (writable)
        AccountMeta::new(creator_token_1, false),               // 8 creator_token_1 (writable)
        AccountMeta::new(creator_lp_token, false),              // 9 creator_lp_token (writable)
        AccountMeta::new(token_0_vault, false),                 // 10 token_0_vault PDA (writable)
        AccountMeta::new(token_1_vault, false),                 // 11 token_1_vault PDA (writable)
        AccountMeta::new(create_pool_fee_pk, false),            // 12 create_pool_fee (writable)
        AccountMeta::new(observation_state, false),             // 13 observation PDA (writable)
        AccountMeta::new_readonly(token_program_pk, false),     // 14 token_program (SPL Token)
        AccountMeta::new_readonly(prog_0, false),               // 15 token_0_program
        AccountMeta::new_readonly(prog_1, false),               // 16 token_1_program
        AccountMeta::new_readonly(ata_program_pk, false),       // 17 associated_token_program
        AccountMeta::new_readonly(system_program::ID, false),   // 18 system_program
        AccountMeta::new_readonly(rent_pk, false),              // 19 rent sysvar
    ];
    // Token-2022 program is only added when at least one mint uses it.
    // The CPMM program resolves it at runtime via the per-mint token program accounts (15, 16).
    // However some versions of the program expect token_2022 as account 20 always.
    // We include it unconditionally to be safe.
    let mut accounts = accounts;
    accounts.push(AccountMeta::new_readonly(token_2022_pk, false)); // 20 token_2022_program

    let data = build_initialize_data(amount_0, amount_1, open_time);
    let ix = Instruction { program_id: program, accounts, data };

    // Fetch blockhash and broadcast.
    let blockhash = match rpc.get_latest_blockhash().await {
        Ok(h) => h,
        Err(e) => return err(StatusCode::BAD_GATEWAY, format!("get blockhash: {e}")),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer),
        &[&cpmm_signing_key_to_solana(&signing_key)],
        blockhash,
    );

    match rpc.send_and_confirm_transaction(&tx).await {
        Ok(sig) => Json(CpmmCreatePoolResponse {
            txid: sig.to_string(),
            pool_id: pool_state.to_string(),
            lp_mint: lp_mint.to_string(),
            fee_config_id: fee_config.id,
        })
        .into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, format!("broadcast failed: {e}")),
    }
}

// ── Solana signer adapter (same pattern as launchlab.rs) ──────────────────

struct CpmmSigner(ed25519_dalek::SigningKey);

impl solana_sdk::signer::Signer for CpmmSigner {
    fn pubkey(&self) -> Pubkey {
        Pubkey::from(self.0.verifying_key().to_bytes())
    }

    fn try_pubkey(&self) -> Result<Pubkey, solana_sdk::signer::SignerError> {
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

fn cpmm_signing_key_to_solana(key: &ed25519_dalek::SigningKey) -> CpmmSigner {
    CpmmSigner(key.clone())
}
