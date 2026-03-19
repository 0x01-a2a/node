//! Machine Payment Protocol (MPP) — HTTP 402 daily payment gate.
//!
//! Hosted agents pay 1.0 USDC/day to the host node.
//! Both gates default to DISABLED (beta). Enabled via CLI flags.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use solana_sdk::pubkey::Pubkey;

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct MppConfig {
    /// Node operator's USDC ATA (derived from wallet).
    pub recipient_ata: Pubkey,
    /// Daily fee in micro-USDC. Default 1_000_000 (1.0 USDC).
    pub daily_fee: u64,
    pub usdc_mint: Pubkey,
    pub enabled: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MppChallenge {
    /// Base58 USDC ATA that must receive the payment.
    pub recipient: String,
    /// Amount in micro-USDC.
    pub amount: u64,
    /// Base58 USDC mint pubkey.
    pub mint: String,
    /// Random base58 pubkey added to the tx accounts — used to locate the tx.
    pub reference: String,
    /// Unix timestamp after which this challenge is expired.
    pub expires_at: u64,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct MppProof {
    pub tx_sig: String,
    pub reference: String,
}

/// Generate a fresh MPP challenge.
///
/// Returns the challenge (to be sent to the agent) and the reference pubkey.
/// The pubkey bytes are stored in the challenge map to identify the tx later.
pub fn generate_challenge(config: &MppConfig) -> MppChallenge {
    // Generate a random Ed25519 keypair; the public key bytes serve as the
    // reference — a unique value injected into the tx account list so we can
    // find this specific payment on-chain.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let reference_pubkey = Pubkey::from(signing_key.verifying_key().to_bytes());

    MppChallenge {
        recipient: config.recipient_ata.to_string(),
        amount: config.daily_fee,
        mint: config.usdc_mint.to_string(),
        reference: reference_pubkey.to_string(),
        expires_at: unix_now() + 120,
    }
}

/// Verify an MPP payment proof by querying the Solana JSON-RPC.
///
/// Checks:
///  1. The reference pubkey appears in `transaction.message.accountKeys`.
///  2. The destination account matches `challenge.recipient`.
///  3. The amount transferred >= `challenge.amount`.
pub async fn verify_payment(
    proof: &MppProof,
    challenge: &MppChallenge,
    rpc_url: &str,
) -> anyhow::Result<bool> {
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            proof.tx_sig,
            {
                "encoding": "jsonParsed",
                "commitment": "confirmed",
                "maxSupportedTransactionVersion": 0
            }
        ]
    });

    let resp = client
        .post(rpc_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .context("getTransaction HTTP request failed")?;

    let data: serde_json::Value = resp.json().await.context("getTransaction JSON parse failed")?;

    if let Some(err) = data.get("error") {
        anyhow::bail!("RPC getTransaction error: {err}");
    }

    let result = &data["result"];
    if result.is_null() {
        // Transaction not found or not yet confirmed.
        return Ok(false);
    }

    // Extract account keys from the transaction message.
    let account_keys = result["transaction"]["message"]["accountKeys"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no accountKeys in transaction"))?;

    // Check 1: reference pubkey must appear in account keys.
    let reference_found = account_keys.iter().any(|key| {
        // jsonParsed: accountKeys is an array of objects with "pubkey" field.
        key.get("pubkey")
            .and_then(|p| p.as_str())
            .map(|p| p == challenge.reference)
            .unwrap_or(false)
            || key.as_str().map(|p| p == challenge.reference).unwrap_or(false)
    });

    if !reference_found {
        return Ok(false);
    }

    // Check 2 & 3: find an SPL Token Transfer (instruction[0] == 3) with the
    // right destination and sufficient amount.
    let instructions = result["transaction"]["message"]["instructions"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Also look in inner instructions (for versioned transactions).
    let inner_ixs: Vec<serde_json::Value> = result["meta"]["innerInstructions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .flat_map(|group| {
                    group["instructions"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    let all_ixs: Vec<serde_json::Value> = instructions.into_iter().chain(inner_ixs).collect();

    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    for ix in &all_ixs {
        // jsonParsed path: program + parsed.info.destination + parsed.info.amount
        if let Some(program) = ix.get("program").and_then(|p| p.as_str()) {
            if program != "spl-token" {
                continue;
            }
            let parsed = &ix["parsed"];
            if parsed["type"].as_str() != Some("transfer")
                && parsed["type"].as_str() != Some("transferChecked")
            {
                continue;
            }
            let info = &parsed["info"];
            let destination = info["destination"].as_str().unwrap_or("");
            if destination != challenge.recipient {
                continue;
            }
            let amount: u64 = info["amount"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| info["tokenAmount"]["amount"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(0);
            if amount >= challenge.amount {
                return Ok(true);
            }
        }

        // Raw/base64 path: check program account index matches TOKEN_PROGRAM,
        // then decode instruction data bytes.
        if let Some(program_id_index) = ix.get("programIdIndex").and_then(|i| i.as_u64()) {
            let prog_key = account_keys
                .get(program_id_index as usize)
                .and_then(|k| k.get("pubkey").and_then(|p| p.as_str()).or_else(|| k.as_str()));
            if prog_key != Some(TOKEN_PROGRAM) {
                continue;
            }

            // data is base58 or base64 encoded.
            let data_str = match ix.get("data").and_then(|d| d.as_str()) {
                Some(s) => s,
                None => continue,
            };

            let data_bytes = bs58::decode(data_str)
                .into_vec()
                .or_else(|_| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD.decode(data_str)
                })
                .unwrap_or_default();

            if data_bytes.len() < 9 || data_bytes[0] != 3 {
                continue;
            }

            let amount = u64::from_le_bytes(data_bytes[1..9].try_into().unwrap_or([0; 8]));

            // destination is accounts[1] for Transfer instruction.
            let accounts_arr = ix.get("accounts").and_then(|a| a.as_array());
            let dest_index = accounts_arr
                .and_then(|a| a.get(1))
                .and_then(|i| i.as_u64());
            if let Some(idx) = dest_index {
                let dest_key = account_keys
                    .get(idx as usize)
                    .and_then(|k| k.get("pubkey").and_then(|p| p.as_str()).or_else(|| k.as_str()));
                if dest_key == Some(&challenge.recipient) && amount >= challenge.amount {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}
