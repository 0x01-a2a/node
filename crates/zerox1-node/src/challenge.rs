//! Challenge mechanism client (doc 5, §10.4).
//!
//! Handles:
//!   - Deriving batch PDA and challenge PDA addresses
//!   - Building and submitting `submit_challenge` instructions (USDC, via Kora or direct)
//!   - Merkle proof construction from the local envelope log
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

// ============================================================================
// Constants
// ============================================================================

/// Challenge program ID (doc 5, §10.4).
const CHALLENGE_PROGRAM_ID_STR: &str = "7FoisCiS1gyUx7osQkCLk4A1zNKGq37yHpVhL2BFgk1Y";

const BEHAVIOR_LOG_PROGRAM_ID_STR: &str = "35DAMPQVu6wsmMEGv67URFAGgyauEYD73egd74uiX1sM";
/// USDC mainnet mint.
const USDC_MINT_STR: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// SPL Token program.
const SPL_TOKEN_PROGRAM_STR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// Associated Token Program.
const ASSOCIATED_TOKEN_PROGRAM_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";
/// Treasury pubkey (receives forfeited stake).
pub const TREASURY_PUBKEY_STR: &str = "qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX";

/// 10 USDC challenge stake (6 decimal places).
pub const CHALLENGE_STAKE_USDC: u64 = 10_000_000;

fn challenge_program_id() -> Pubkey {
    CHALLENGE_PROGRAM_ID_STR.parse().expect("valid challenge program ID")
}

fn behavior_log_program_id() -> Pubkey {
    BEHAVIOR_LOG_PROGRAM_ID_STR.parse().expect("valid behavior-log program ID")
}

fn treasury_pubkey() -> Pubkey {
    TREASURY_PUBKEY_STR.parse().expect("valid treasury pubkey")
}

fn usdc_mint() -> Pubkey {
    USDC_MINT_STR.parse().expect("valid USDC mint")
}

fn spl_token_program() -> Pubkey {
    SPL_TOKEN_PROGRAM_STR.parse().expect("valid SPL token program ID")
}

fn associated_token_program() -> Pubkey {
    ASSOCIATED_TOKEN_PROGRAM_STR.parse().expect("valid ATA program ID")
}

// ============================================================================
// PDA derivation helpers
// ============================================================================

/// Derive the BatchAccount PDA for (agent_id, epoch_number).
///
/// seeds = ["batch", agent_id, epoch_number.to_le_bytes()]
pub fn batch_pda(agent_id: &[u8; 32], epoch_number: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[b"batch", agent_id.as_ref(), &epoch_number.to_le_bytes()],
        &behavior_log_program_id(),
    )
    .0
}

/// Derive the ChallengeAccount PDA for (batch_key, challenger_pubkey).
///
/// seeds = ["challenge", batch_pda_key, challenger_pubkey]
pub fn challenge_pda(batch_key: &Pubkey, challenger: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[b"challenge", batch_key.as_ref(), challenger.as_ref()],
        &challenge_program_id(),
    )
    .0
}

/// Derive the vault authority PDA for a given challenge account key.
///
/// seeds = ["challenge_vault", challenge_account_key]
pub fn vault_authority_pda(challenge_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"challenge_vault", challenge_key.as_ref()],
        &challenge_program_id(),
    )
}

// ============================================================================
// submit_challenge
// ============================================================================

/// Build and submit a `submit_challenge` transaction.
///
/// Gas path:
///   Kora present  → payer = Kora; challenger = agent (partial sign)
///   Kora absent   → payer = challenger = agent (direct)
///
/// `contradicting_entry`: CBOR bytes of a signed Envelope from the log.
/// `merkle_proof`:        Merkle sibling hashes from entry leaf to log_merkle_root.
pub struct SubmitChallengeArgs {
    pub target_agent_id:     [u8; 32],
    pub epoch_number:        u64,
    pub leaf_index:          u64,
    pub contradicting_entry: Vec<u8>,
    pub merkle_proof:        Vec<[u8; 32]>,
}

pub async fn submit_challenge_onchain(
    rpc:                 &RpcClient,
    identity:            &AgentIdentity,
    kora:                Option<&KoraClient>,
    args:                SubmitChallengeArgs,
) -> anyhow::Result<()> {
    let program_id       = challenge_program_id();
    let usdc             = usdc_mint();
    let challenger_pubkey = Pubkey::new_from_array(identity.verifying_key.to_bytes());

    let batch_key      = batch_pda(&args.target_agent_id, args.epoch_number);
    let challenge_key  = challenge_pda(&batch_key, &challenger_pubkey);
    let (vault_auth, _) = vault_authority_pda(&challenge_key);
    let vault_ata       = get_ata(&vault_auth, &usdc);
    let challenger_ata  = get_ata(&challenger_pubkey, &usdc);

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    let solana_kp = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&identity.signing_key.to_bytes());
        b[32..].copy_from_slice(&identity.verifying_key.to_bytes());
        Keypair::try_from(b.as_slice())
            .map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
    };

    if let Some(kora) = kora {
        // ── Kora path ────────────────────────────────────────────────────────
        let fee_payer = kora.get_fee_payer().await?;

        let ix = build_submit_challenge_ix(
            &fee_payer,
            &challenger_pubkey,
            &challenger_ata,
            &challenge_key,
            &vault_auth,
            &vault_ata,
            &batch_key,
            &usdc,
            &program_id,
            args.target_agent_id,
            args.epoch_number,
            args.leaf_index,
            args.contradicting_entry.clone(),
            args.merkle_proof.clone(),
        );

        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &recent_blockhash);
        let mut tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };
        tx.partial_sign(&[&solana_kp], recent_blockhash);

        let tx_bytes = bincode::serialize(&tx)
            .map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?;
        let tx_b64 = BASE64.encode(&tx_bytes);

        kora.sign_and_send(&tx_b64).await?;

        tracing::info!(
            target_agent = %hex::encode(args.target_agent_id),
            epoch         = args.epoch_number,
            "Challenge submitted via Kora (gasless)",
        );
    } else {
        // ── Direct path ──────────────────────────────────────────────────────
        let ix = build_submit_challenge_ix(
            &challenger_pubkey,
            &challenger_pubkey,
            &challenger_ata,
            &challenge_key,
            &vault_auth,
            &vault_ata,
            &batch_key,
            &usdc,
            &program_id,
            args.target_agent_id,
            args.epoch_number,
            args.leaf_index,
            args.contradicting_entry,
            args.merkle_proof,
        );

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&challenger_pubkey),
            &[&solana_kp],
            recent_blockhash,
        );

        let sig = rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| anyhow::anyhow!("submit_challenge: {e}"))?;

        tracing::info!(
            tx            = %sig,
            target_agent  = %hex::encode(args.target_agent_id),
            epoch         = args.epoch_number,
            "Challenge submitted directly (agent pays gas)",
        );
    }

    Ok(())
}

// ============================================================================
// resolve_challenge
// ============================================================================

/// Build and submit a `resolve_challenge` transaction.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_challenge_onchain(
    rpc:                 &RpcClient,
    identity:            &AgentIdentity,
    target_agent_id:     [u8; 32],
    epoch_number:        u64,
    challenger:          &Pubkey,
    contradicting_entry: Vec<u8>,
    merkle_proof:        Vec<[u8; 32]>,
    contradicts_batch:   bool,
) -> anyhow::Result<()> {
    let program_id = challenge_program_id();
    let usdc = usdc_mint();
    let resolver_pubkey = Pubkey::new_from_array(identity.verifying_key.to_bytes());

    let batch_key = batch_pda(&target_agent_id, epoch_number);
    let challenge_key = challenge_pda(&batch_key, challenger);
    let (vault_auth, _) = vault_authority_pda(&challenge_key);
    let vault_ata = get_ata(&vault_auth, &usdc);
    let challenger_ata = get_ata(challenger, &usdc);
    
    let treasury = treasury_pubkey();
    let treasury_ata = get_ata(&treasury, &usdc);

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    let solana_kp = {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&identity.signing_key.to_bytes());
        b[32..].copy_from_slice(&identity.verifying_key.to_bytes());
        Keypair::try_from(b.as_slice()).map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
    };

    let ix = build_resolve_challenge_ix(
        &resolver_pubkey,
        &challenge_key,
        &vault_auth,
        &vault_ata,
        &challenger_ata,
        &treasury_ata,
        &treasury,
        &batch_key,
        &usdc,
        &program_id,
        contradicting_entry,
        merkle_proof,
        contradicts_batch,
    );

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&resolver_pubkey),
        &[&solana_kp],
        recent_blockhash,
    );

    let sig = rpc.send_and_confirm_transaction(&tx).await.map_err(|e| anyhow::anyhow!("resolve_challenge: {e}"))?;

    tracing::info!(
        tx           = %sig,
        target_agent = %hex::encode(target_agent_id),
        epoch        = epoch_number,
        "Challenge resolved on-chain",
    );

    Ok(())
}

// ============================================================================
// Instruction builder
// ============================================================================

/// Compute an Anchor instruction discriminator: sha256("global:<name>")[..8].
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

/// Build the `submit_challenge` instruction.
///
/// Accounts (matching SubmitChallenge struct):
///   0.  payer                    (signer, writable) — Kora or challenger
///   1.  challenger               (signer, writable) — USDC authority
///   2.  challenger_usdc          (writable) — challenger's USDC ATA
///   3.  challenge_account        (PDA, writable)
///   4.  challenge_vault_authority (PDA, readonly)
///   5.  challenge_vault          (writable) — vault ATA
///   6.  batch_account            (readonly) — the batch being challenged
///   7.  usdc_mint                (readonly)
///   8.  token_program            (readonly)
///   9.  associated_token_program (readonly)
///   10. system_program           (readonly)
///
/// Args: discriminator(8) + Borsh(SubmitChallengeArgs).
#[allow(clippy::too_many_arguments)]
fn build_submit_challenge_ix(
    payer:               &Pubkey,
    challenger:          &Pubkey,
    challenger_ata:      &Pubkey,
    challenge_pda_key:   &Pubkey,
    vault_auth:          &Pubkey,
    vault_ata:           &Pubkey,
    batch_account:       &Pubkey,
    usdc:                &Pubkey,
    program_id:          &Pubkey,
    agent_id:            [u8; 32],
    epoch_number:        u64,
    leaf_index:          u64,
    contradicting_entry: Vec<u8>,
    merkle_proof:        Vec<[u8; 32]>,
) -> Instruction {
    // Borsh-encode SubmitChallengeArgs manually (no borsh dep in node crate).
    let mut data = Vec::new();
    data.extend_from_slice(&anchor_discriminator("submit_challenge"));
    // agent_id: [u8; 32]
    data.extend_from_slice(&agent_id);
    // epoch_number: u64 (LE)
    data.extend_from_slice(&epoch_number.to_le_bytes());
    // contradicting_entry: Vec<u8> — 4-byte LE length + bytes
    data.extend_from_slice(&(contradicting_entry.len() as u32).to_le_bytes());
    data.extend_from_slice(&contradicting_entry);
    // merkle_proof: Vec<[u8; 32]> — 4-byte LE length + 32*n bytes
    data.extend_from_slice(&(merkle_proof.len() as u32).to_le_bytes());
    for hash in &merkle_proof {
        data.extend_from_slice(hash);
    }
    // leaf_index: u64 (LE)
    data.extend_from_slice(&leaf_index.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*challenger, true),
            AccountMeta::new(*challenger_ata, false),
            AccountMeta::new(*challenge_pda_key, false),
            AccountMeta::new_readonly(*vault_auth, false),
            AccountMeta::new(*vault_ata, false),
            AccountMeta::new_readonly(*batch_account, false),
            AccountMeta::new_readonly(*usdc, false),
            AccountMeta::new_readonly(spl_token_program(), false),
            AccountMeta::new_readonly(associated_token_program(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    }
}

/// Build the `resolve_challenge` instruction.
#[allow(clippy::too_many_arguments)]
fn build_resolve_challenge_ix(
    resolver:            &Pubkey,
    challenge_account:   &Pubkey,
    vault_auth:          &Pubkey,
    vault_ata:           &Pubkey,
    challenger_ata:      &Pubkey,
    treasury_usdc:       &Pubkey,
    treasury:            &Pubkey,
    batch_account:       &Pubkey,
    usdc:                &Pubkey,
    program_id:          &Pubkey,
    contradicting_entry: Vec<u8>,
    merkle_proof:        Vec<[u8; 32]>,
    contradicts_batch:   bool,
) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&anchor_discriminator("resolve_challenge"));
    
    // contradicting_entry: Vec<u8>
    data.extend_from_slice(&(contradicting_entry.len() as u32).to_le_bytes());
    data.extend_from_slice(&contradicting_entry);
    
    // merkle_proof: Vec<[u8; 32]>
    data.extend_from_slice(&(merkle_proof.len() as u32).to_le_bytes());
    for hash in &merkle_proof {
        data.extend_from_slice(hash);
    }
    
    // contradicts_batch: bool
    data.push(contradicts_batch as u8);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*resolver, true),
            AccountMeta::new(*challenge_account, false),
            AccountMeta::new_readonly(*vault_auth, false),
            AccountMeta::new(*vault_ata, false),
            AccountMeta::new(*challenger_ata, false),
            AccountMeta::new(*treasury_usdc, false),
            AccountMeta::new_readonly(*treasury, false),
            AccountMeta::new_readonly(*batch_account, false),
            AccountMeta::new_readonly(*usdc, false),
            AccountMeta::new_readonly(spl_token_program(), false),
        ],
        data,
    }
}

// ============================================================================
// Merkle proof helpers
// ============================================================================

/// Build a Merkle proof for `leaf_index` in `leaves`.
///
/// Uses the same tree construction as `zerox1_protocol::hash::merkle_root`:
/// - keccak256 leaves, next_power_of_two padding with zero hashes
/// - Internal hash: keccak256(0x01 || left || right)
///
/// Returns sibling hashes from leaf level up to (but not including) root.
pub fn build_merkle_proof(leaves: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> {
    use zerox1_protocol::hash::keccak256;
    const MERKLE_INTERNAL_DOMAIN: u8 = 0x01;

    if leaves.len() <= 1 {
        return vec![];
    }

    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(leaves);
    layer.resize(n, [0u8; 32]);

    let mut proof = Vec::new();
    let mut idx = leaf_index;

    while layer.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
        proof.push(layer[sibling_idx]);

        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            let mut combined = [0u8; 65];
            combined[0] = MERKLE_INTERNAL_DOMAIN;
            combined[1..33].copy_from_slice(&chunk[0]);
            combined[33..65].copy_from_slice(&chunk[1]);
            next.push(keccak256(&combined));
        }
        layer = next;
        idx /= 2;
    }

    proof
}
