//! Machine Payment Protocol (MPP) — protocol fee gate for the aggregator.
//!
//! Agents pay 0.2 USDC/day to the 0x01 aggregator as a protocol fee.
//! Gate defaults to DISABLED (beta). Enabled via --protocol-fee-enabled.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[allow(dead_code)]
pub struct MppConfig {
    /// Aggregator's USDC ATA (base58).
    pub recipient_ata: String,
    /// Daily fee in micro-USDC.
    pub daily_fee: u64,
    /// USDC mint pubkey (base58).
    pub usdc_mint: String,
    pub enabled: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct MppChallenge {
    pub recipient: String,
    pub amount: u64,
    pub mint: String,
    pub reference: String,
    pub expires_at: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
pub struct MppProof {
    pub tx_sig: String,
    pub reference: String,
}

/// Generate a fresh MPP challenge.
pub fn generate_challenge(config: &MppConfig) -> MppChallenge {
    // Use ed25519_dalek to generate a random keypair; the public key bytes
    // become the reference pubkey added to the tx accounts list.
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let ref_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let reference = bs58::encode(ref_bytes).into_string();

    MppChallenge {
        recipient: config.recipient_ata.clone(),
        amount: config.daily_fee,
        mint: config.usdc_mint.clone(),
        reference,
        expires_at: unix_now() + 120,
    }
}

/// Verify an MPP payment proof by querying the Solana JSON-RPC.
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
        return Ok(false);
    }

    let account_keys = result["transaction"]["message"]["accountKeys"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no accountKeys in transaction"))?;

    // Check 1: reference pubkey must appear in account keys.
    let reference_found = account_keys.iter().any(|key| {
        key.get("pubkey")
            .and_then(|p| p.as_str())
            .map(|p| p == challenge.reference)
            .unwrap_or(false)
            || key.as_str().map(|p| p == challenge.reference).unwrap_or(false)
    });

    if !reference_found {
        return Ok(false);
    }

    let instructions = result["transaction"]["message"]["instructions"]
        .as_array()
        .cloned()
        .unwrap_or_default();

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
        // jsonParsed path.
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
                .or_else(|| {
                    info["tokenAmount"]["amount"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                })
                .unwrap_or(0);
            if amount >= challenge.amount {
                return Ok(true);
            }
        }

        // Raw/index path.
        if let Some(program_id_index) = ix.get("programIdIndex").and_then(|i| i.as_u64()) {
            let prog_key = account_keys
                .get(program_id_index as usize)
                .and_then(|k| k.get("pubkey").and_then(|p| p.as_str()).or_else(|| k.as_str()));
            if prog_key != Some(TOKEN_PROGRAM) {
                continue;
            }

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
