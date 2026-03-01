//! On-chain batch submission (doc 5, §9 step 6).
//!
//! Builds a two-instruction Solana transaction:
//!   1. Ed25519 precompile instruction — proves the agent signed the batch CBOR.
//!   2. `submit_batch` instruction to the BehaviorLog program.
//!
//! Gas payment:
//!   - If a KoraClient is provided (--kora-url set): transaction is submitted via
//!     Kora with the fee payer set to Kora's pubkey. Agent never needs SOL.
//!     Gas is reimbursed to the Kora operator in USDC (doc 5, §4.4).
//!   - If no KoraClient: transaction is submitted directly with the agent as fee
//!     payer. Requires the agent wallet to hold SOL for gas.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::Signer as DalekSigner;
use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
// System program ID (11111111111111111111111111111111).
use solana_sdk::system_program::id as system_program_id;

use zerox1_protocol::batch::BehaviorBatch;

use crate::{identity::AgentIdentity, kora::KoraClient};

use crate::constants;

fn behavior_log_program_id() -> Pubkey {
    constants::behavior_log_program_id()
}

// ============================================================================
// Public entry point
// ============================================================================

/// Submit a finalized BehaviorBatch commitment on-chain.
///
/// Builds and sends a transaction with:
///   1. Solana Ed25519 precompile instruction (batch CBOR signature verification)
///   2. `submit_batch` instruction storing the commitment in a PDA
///
/// If `kora` is Some, gas is paid via the Kora paymaster (USDC reimbursement).
/// If `kora` is None, the agent's keypair pays gas directly (requires SOL).
pub async fn submit_batch_onchain(
    rpc: &RpcClient,
    identity: &AgentIdentity,
    batch: &BehaviorBatch,
    epoch_number: u64,
    kora: Option<&KoraClient>,
) -> anyhow::Result<()> {
    // 1. Compute batch hash.
    let batch_hash = batch.batch_hash()?;

    // 2. Sign the batch_hash with the agent's Ed25519 key.
    // Doc 5 §9 step 6: The signed message is the 32-byte keccak256(CBOR).
    let dalek_sig: ed25519_dalek::Signature = identity.signing_key.sign(&batch_hash);
    let sig_bytes: [u8; 64] = dalek_sig.to_bytes();
    let vk_bytes: [u8; 32] = identity.verifying_key.to_bytes();

    // 3. Derive PDAs.
    let program_id = behavior_log_program_id();
    let (batch_pda, _) = Pubkey::find_program_address(
        &[b"batch", &identity.agent_id, &epoch_number.to_le_bytes()],
        &program_id,
    );
    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"agent_registry", &identity.agent_id], &program_id);

    // 4. Build instructions.
    // We verify the signature over the batch_hash (32 bytes).
    let verify_ix = build_ed25519_verify_ix(&vk_bytes, &sig_bytes, &batch_hash);

    let recent_blockhash = rpc.get_latest_blockhash().await?;

    if let Some(kora) = kora {
        // ── Kora path: gasless, fee payer = Kora's pubkey ────────────────────
        let fee_payer = kora
            .get_fee_payer()
            .await
            .map_err(|e| anyhow::anyhow!("Kora get_fee_payer: {e}"))?;

        let submit_ix = build_submit_batch_ix(
            &fee_payer, // Kora pays PDA rent
            &batch_pda,
            &registry_pda,
            &program_id,
            &identity.agent_id,
            epoch_number,
            &batch.log_merkle_root,
            &batch_hash,
            &sig_bytes,
        );

        // Build unsigned transaction — Kora is the sole required signer.
        // Agent identity is proven by the Ed25519 precompile, not by tx signer.
        let message = Message::new_with_blockhash(
            &[verify_ix, submit_ix],
            Some(&fee_payer),
            &recent_blockhash,
        );
        let tx = Transaction {
            signatures: vec![Signature::default(); message.header.num_required_signatures as usize],
            message,
        };

        let tx_bytes =
            bincode::serialize(&tx).map_err(|e| anyhow::anyhow!("bincode serialize: {e}"))?;
        let tx_b64 = BASE64.encode(&tx_bytes);

        let signer_pubkey = kora
            .sign_and_send(&tx_b64)
            .await
            .map_err(|e| anyhow::anyhow!("Kora sign_and_send: {e}"))?;

        tracing::info!(
            epoch        = epoch_number,
            hash         = %hex::encode(batch_hash),
            kora_signer  = %signer_pubkey,
            "Epoch batch submitted via Kora (gasless)",
        );
    } else {
        // ── Direct path: agent pays gas in SOL ───────────────────────────────
        let solana_kp = {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&identity.signing_key.to_bytes());
            b[32..].copy_from_slice(&vk_bytes);
            Keypair::try_from(b.as_slice())
                .map_err(|e| anyhow::anyhow!("keypair conversion: {e}"))?
        };

        let submit_ix = build_submit_batch_ix(
            &solana_kp.pubkey(),
            &batch_pda,
            &registry_pda,
            &program_id,
            &identity.agent_id,
            epoch_number,
            &batch.log_merkle_root,
            &batch_hash,
            &sig_bytes,
        );

        let tx = Transaction::new_signed_with_payer(
            &[verify_ix, submit_ix],
            Some(&solana_kp.pubkey()),
            &[&solana_kp],
            recent_blockhash,
        );

        let tx_sig = rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| anyhow::anyhow!("send_and_confirm_transaction: {e}"))?;

        tracing::info!(
            tx    = %tx_sig,
            epoch = epoch_number,
            hash  = %hex::encode(batch_hash),
            "Epoch batch submitted on-chain (direct)",
        );
    }

    Ok(())
}

// ============================================================================
// Instruction builders
// ============================================================================

/// Compute an Anchor instruction discriminator: sha256("global:<name>")[..8].
fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = Sha256::digest(format!("global:{name}").as_bytes());
    hash[..8].try_into().unwrap()
}

/// Build the Solana Ed25519 precompile instruction.
///
/// Binary layout (all offsets relative to start of instruction data field):
/// ```text
/// [u8:  num_sigs = 1]
/// [u8:  padding  = 0]
/// [u16: sig_offset]   [u16: 0xFFFF]   (0xFFFF = "this instruction")
/// [u16: pk_offset]    [u16: 0xFFFF]
/// [u16: msg_offset]   [u16: msg_len]  [u16: 0xFFFF]
/// [64 bytes: signature]
/// [32 bytes: pubkey]
/// [n  bytes: message]
/// ```
fn build_ed25519_verify_ix(
    pubkey_bytes: &[u8; 32],
    signature_bytes: &[u8; 64],
    message: &[u8],
) -> Instruction {
    // Header = 1 (count) + 1 (padding) + 14 (one offsets entry) = 16 bytes.
    const HEADER: u16 = 2 + 14;
    let sig_off = HEADER;
    let pk_off = HEADER + 64;
    let msg_off = HEADER + 64 + 32;
    let msg_len = message.len() as u16;

    let mut data = Vec::with_capacity(HEADER as usize + 64 + 32 + message.len());
    data.push(1u8); // num_sigs
    data.push(0u8); // padding
                    // 7 × u16 LE offsets entry
    for val in [
        sig_off,
        u16::MAX,
        pk_off,
        u16::MAX,
        msg_off,
        msg_len,
        u16::MAX,
    ] {
        data.extend_from_slice(&val.to_le_bytes());
    }
    data.extend_from_slice(signature_bytes);
    data.extend_from_slice(pubkey_bytes);
    data.extend_from_slice(message);

    Instruction {
        program_id: solana_sdk::ed25519_program::id(),
        accounts: vec![],
        data,
    }
}

/// Build the BehaviorLog `submit_batch` instruction.
///
/// Accounts (matching the Anchor `SubmitBatch` struct):
///   0. payer         (signer, writable) — Kora's pubkey when using gasless path
///   1. batch_account (PDA, writable — init)
///   2. registry      (PDA, writable — init_if_needed)
///   3. system_program (readonly)
///
/// Instruction data: discriminator(8) + Borsh(SubmitBatchArgs)(168).
#[allow(clippy::too_many_arguments)]
fn build_submit_batch_ix(
    payer: &Pubkey,
    batch_pda: &Pubkey,
    registry_pda: &Pubkey,
    program_id: &Pubkey,
    agent_id: &[u8; 32],
    epoch_number: u64,
    log_merkle_root: &[u8; 32],
    batch_hash: &[u8; 32],
    signature: &[u8; 64],
) -> Instruction {
    // Anchor Borsh discriminator.
    let mut data = Vec::with_capacity(8 + 168);
    data.extend_from_slice(&anchor_discriminator("submit_batch"));

    // SubmitBatchArgs (Borsh — all fixed-size, little-endian):
    //   agent_id:         [u8; 32]
    //   epoch_number:     u64
    //   log_merkle_root:  [u8; 32]
    //   batch_hash:       [u8; 32]
    //   signature:        [u8; 64]
    data.extend_from_slice(agent_id);
    data.extend_from_slice(&epoch_number.to_le_bytes());
    data.extend_from_slice(log_merkle_root);
    data.extend_from_slice(batch_hash);
    data.extend_from_slice(signature);

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*batch_pda, false),
            AccountMeta::new(*registry_pda, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::instructions::ID, false),
            AccountMeta::new_readonly(system_program_id(), false),
        ],
        data,
    }
}
