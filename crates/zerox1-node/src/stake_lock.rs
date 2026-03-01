//! StakeLock mechanism client (doc 5, §10.5).
//!
//! Handles:
//!   - Building and submitting `lock_stake` instructions (USDC gas via Kora or direct)
//!   - Building and submitting `queue_unlock` instructions

#![allow(dead_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    transaction::Transaction,
};

use crate::{identity::AgentIdentity, kora::KoraClient, lease::get_ata};
use zerox1_protocol::SATI_PROGRAM_ID;

// ============================================================================
// Constants
// ============================================================================

/// StakeLock program ID (doc 5, §10.5).
const STAKE_LOCK_PROGRAM_ID_STR: &str = "Dvf1qPzzvW1BkSUogRMaAvxZpXrmeTqYutTCBKpzHB1A";
/// Lease program ID.
const LEASE_PROGRAM_ID_STR: &str = "5P8uXqavnQFGXbHKE3tQDezh41D7ZutHsT2jY6gZ3C3x";
/// USDC mainnet mint.
const USDC_MINT_STR: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// SPL Token program.
const SPL_TOKEN_PROGRAM_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Associated Token Program.
const ASSOCIATED_TOKEN_PROGRAM_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";

/// 10 USDC stake (6 decimal places).
pub const MIN_STAKE_USDC: u64 = 10_000_000;

pub fn stake_lock_program_id() -> Pubkey {
    STAKE_LOCK_PROGRAM_ID_STR
        .parse()
        .expect("valid stakelock program ID")
}

fn lease_program_id() -> Pubkey {
    LEASE_PROGRAM_ID_STR
        .parse()
        .expect("valid lease program ID")
}

fn usdc_mint() -> Pubkey {
    USDC_MINT_STR.parse().expect("valid USDC mint")
}

fn spl_token_program() -> Pubkey {
    SPL_TOKEN_PROGRAM_STR
        .parse()
        .expect("valid SPL token program ID")
}

fn associated_token_program() -> Pubkey {
    ASSOCIATED_TOKEN_PROGRAM_STR
        .parse()
        .expect("valid ATA program ID")
}

// ============================================================================
// PDA derivation helpers
// ============================================================================

pub fn stake_pda(agent_mint: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"stake", agent_mint.as_ref()], &stake_lock_program_id()).0
}

pub fn vault_authority_pda(agent_mint: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[b"stake_vault", agent_mint.as_ref()],
        &stake_lock_program_id(),
    )
    .0
}

pub fn lease_pda(agent_mint: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"lease", agent_mint.as_ref()], &lease_program_id()).0
}

// ============================================================================
// lock_stake instruction
// ============================================================================

/// Build and submit a `lock_stake` transaction.
pub async fn lock_stake_onchain(
    rpc: &RpcClient,
    identity: &AgentIdentity,
    kora: Option<&KoraClient>,
) -> anyhow::Result<()> {
    let program_id = stake_lock_program_id();
    let usdc = usdc_mint();
    let agent_pubkey = Pubkey::new_from_array(identity.verifying_key.to_bytes());
    let agent_mint = Pubkey::new_from_array(identity.agent_id);

    let stake_account = stake_pda(&identity.agent_id);
    let vault_auth = vault_authority_pda(&identity.agent_id);
    let vault_ata = get_ata(&vault_auth, &usdc);
    let owner_ata = get_ata(&agent_pubkey, &usdc);
    let owner_sati_ata = get_ata(&agent_pubkey, &agent_mint);

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    let solana_kp = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&identity.signing_key.to_bytes());
        b[32..].copy_from_slice(&identity.verifying_key.to_bytes());
        Keypair::try_from(b.as_slice()).map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
    };

    if let Some(kora) = kora {
        let fee_payer = kora.get_fee_payer().await?;

        let ix = build_lock_stake_ix(
            &fee_payer,
            &agent_pubkey,
            &owner_ata,
            &stake_account,
            &vault_auth,
            &vault_ata,
            &agent_mint,
            &owner_sati_ata,
            &usdc,
            &program_id,
            identity.agent_id,
            MIN_STAKE_USDC,
        );

        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &recent_blockhash);
        let mut tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        tx.partial_sign(&[&solana_kp], recent_blockhash);

        let tx_bytes =
            bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?;
        let tx_b64 = BASE64.encode(&tx_bytes);

        kora.sign_and_send(&tx_b64).await?;

        tracing::info!(agent = %hex::encode(identity.agent_id), "Stake locked via Kora (gasless)");
    } else {
        let ix = build_lock_stake_ix(
            &agent_pubkey,
            &agent_pubkey,
            &owner_ata,
            &stake_account,
            &vault_auth,
            &vault_ata,
            &agent_mint,
            &owner_sati_ata,
            &usdc,
            &program_id,
            identity.agent_id,
            MIN_STAKE_USDC,
        );

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&agent_pubkey),
            &[&solana_kp],
            recent_blockhash,
        );

        let sig = rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| anyhow::anyhow!("lock_stake: {e}"))?;

        tracing::info!(tx = %sig, agent = %hex::encode(identity.agent_id), "Stake locked directly (agent pays gas)");
    }

    Ok(())
}

// ============================================================================
// queue_unlock instruction
// ============================================================================

/// Build and submit a `queue_unlock` transaction.
pub async fn queue_unlock_onchain(rpc: &RpcClient, identity: &AgentIdentity) -> anyhow::Result<()> {
    let program_id = stake_lock_program_id();
    let agent_pubkey = Pubkey::new_from_array(identity.verifying_key.to_bytes());

    let stake_account = stake_pda(&identity.agent_id);
    let lease_account = lease_pda(&identity.agent_id);

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    let solana_kp = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&identity.signing_key.to_bytes());
        b[32..].copy_from_slice(&identity.verifying_key.to_bytes());
        Keypair::try_from(b.as_slice()).map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
    };

    let ix = build_queue_unlock_ix(&agent_pubkey, &stake_account, &lease_account, &program_id);

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&agent_pubkey),
        &[&solana_kp],
        recent_blockhash,
    );

    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow::anyhow!("queue_unlock: {e}"))?;

    tracing::info!(tx = %sig, agent = %hex::encode(identity.agent_id), "Unlock queued on-chain");

    Ok(())
}

// ============================================================================
// Instruction builder
// ============================================================================

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn build_lock_stake_ix(
    payer: &Pubkey,
    owner: &Pubkey,
    owner_usdc: &Pubkey,
    stake_account: &Pubkey,
    stake_vault_auth: &Pubkey,
    stake_vault: &Pubkey,
    agent_mint: &Pubkey,
    owner_sati_token: &Pubkey,
    usdc_mint: &Pubkey,
    program_id: &Pubkey,
    agent_id: [u8; 32],
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&anchor_discriminator("lock_stake"));
    data.extend_from_slice(&agent_id); // LockStakeArgs { agent_mint }
    data.extend_from_slice(&amount.to_le_bytes()); // LockStakeArgs { amount }

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*owner, true),
            AccountMeta::new(*owner_usdc, false),
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(*stake_vault_auth, false),
            AccountMeta::new(*stake_vault, false),
            AccountMeta::new_readonly(*agent_mint, false),
            AccountMeta::new_readonly(*owner_sati_token, false),
            AccountMeta::new_readonly(SATI_PROGRAM_ID.parse().expect("valid SATI program ID"), false), // sati_token_program
            AccountMeta::new_readonly(*usdc_mint, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(associated_token_program(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

fn build_queue_unlock_ix(
    owner: &Pubkey,
    stake_account: &Pubkey,
    lease_account: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(*stake_account, false),
            AccountMeta::new_readonly(*lease_account, false),
        ],
        data: anchor_discriminator("queue_unlock").to_vec(),
    }
}
