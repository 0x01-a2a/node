//! Escrow program client (approve_payment).
//!
//! Called automatically when this node sends a VERDICT with approve type (0x00).
//! Payload convention: [verdict_type(1)][requester(32)][provider(32)]
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::Keypair,
    transaction::Transaction,
};

use crate::lease::get_ata;

// ============================================================================
// Constants
// ============================================================================

/// Escrow program ID — placeholder until mainnet deploy.
const ESCROW_PROGRAM_ID_STR: &str = "11111111111111111111111111111111";

const USDC_MINT_STR:              &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SPL_TOKEN_PROGRAM_STR:      &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED_TOKEN_PROGRAM_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo";
const TREASURY_PUBKEY_STR:        &str = "qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX";

fn escrow_program_id() -> Pubkey {
    ESCROW_PROGRAM_ID_STR.parse().expect("valid escrow program ID")
}

fn usdc_mint() -> Pubkey {
    USDC_MINT_STR.parse().expect("valid USDC mint")
}

fn spl_token_program() -> Pubkey {
    SPL_TOKEN_PROGRAM_STR.parse().expect("valid SPL token program")
}

fn associated_token_program() -> Pubkey {
    ASSOCIATED_TOKEN_PROGRAM_STR.parse().expect("valid ATA program")
}

fn treasury() -> Pubkey {
    TREASURY_PUBKEY_STR.parse().expect("valid treasury pubkey")
}

// ============================================================================
// PDA helpers
// ============================================================================

fn escrow_pda(requester: &Pubkey, provider: &Pubkey, conversation_id: &[u8; 16]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"escrow", requester.as_ref(), provider.as_ref(), conversation_id.as_ref()],
        &escrow_program_id(),
    )
}

fn vault_authority_pda(escrow_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"escrow_vault", escrow_key.as_ref()],
        &escrow_program_id(),
    )
}

// ============================================================================
// Instruction discriminator
// ============================================================================

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let preimage = format!("global:{name}");
    let hash = Sha256::digest(preimage.as_bytes());
    hash[..8].try_into().unwrap()
}

// ============================================================================
// Public entry point
// ============================================================================

/// Call escrow `approve_payment` on behalf of the notary/requester.
///
/// `notary_bytes` — agent_id of the notary (needed to derive their USDC ATA for the fee).
///   Pass the same bytes as `vk_bytes` (self) when the requester is approving and no
///   separate notary was designated.
pub async fn approve_payment_onchain(
    rpc:             &RpcClient,
    sk_bytes:        [u8; 32],
    vk_bytes:        [u8; 32],
    requester_bytes: [u8; 32],
    provider_bytes:  [u8; 32],
    conversation_id: [u8; 16],
    notary_bytes:    [u8; 32],
) -> anyhow::Result<()> {
    let usdc          = usdc_mint();
    let treasury_key  = treasury();

    let approver_pubkey  = Pubkey::new_from_array(vk_bytes);
    let requester_pubkey = Pubkey::new_from_array(requester_bytes);
    let provider_pubkey  = Pubkey::new_from_array(provider_bytes);
    let notary_pubkey    = Pubkey::new_from_array(notary_bytes);

    let (escrow_key, _)     = escrow_pda(&requester_pubkey, &provider_pubkey, &conversation_id);
    let (vault_auth, _)     = vault_authority_pda(&escrow_key);
    let vault_ata           = get_ata(&vault_auth, &usdc);
    let provider_ata        = get_ata(&provider_pubkey, &usdc);
    let treasury_ata        = get_ata(&treasury_key, &usdc);
    let notary_ata          = get_ata(&notary_pubkey, &usdc);

    let ix = build_approve_payment_ix(ApprovePaymentAccounts {
        approver:     &approver_pubkey,
        escrow_key:   &escrow_key,
        vault_auth:   &vault_auth,
        vault_ata:    &vault_ata,
        provider_ata: &provider_ata,
        treasury_ata: &treasury_ata,
        treasury_key: &treasury_key,
        notary_ata:   &notary_ata,
        usdc:         &usdc,
    });

    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(&sk_bytes);
    kp_bytes[32..].copy_from_slice(&vk_bytes);
    let kp = Keypair::try_from(kp_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("keypair: {e}"))?;

    let blockhash = rpc.get_latest_blockhash().await?;
    let msg       = Message::new_with_blockhash(&[ix], Some(&approver_pubkey), &blockhash);
    let mut tx    = Transaction::new_unsigned(msg);
    tx.sign(&[&kp], blockhash);

    let sig = rpc.send_and_confirm_transaction(&tx).await?;
    tracing::info!(
        "Escrow approve_payment confirmed: {} (requester={}, provider={})",
        sig,
        hex::encode(requester_bytes),
        hex::encode(provider_bytes),
    );
    Ok(())
}

// ============================================================================
// Instruction builder
// ============================================================================

pub struct ApprovePaymentAccounts<'a> {
    pub approver:     &'a Pubkey,
    pub escrow_key:   &'a Pubkey,
    pub vault_auth:   &'a Pubkey,
    pub vault_ata:    &'a Pubkey,
    pub provider_ata: &'a Pubkey,
    pub treasury_ata: &'a Pubkey,
    pub treasury_key: &'a Pubkey,
    pub notary_ata:   &'a Pubkey,
    pub usdc:         &'a Pubkey,
}

fn build_approve_payment_ix(accs: ApprovePaymentAccounts) -> Instruction {
    // Account order must match ApprovePayment<'info> struct field order.
    let accounts = vec![
        AccountMeta::new_readonly(*accs.approver,     true),  // approver (signer)
        AccountMeta::new(*accs.escrow_key,            false), // escrow_account (writable)
        AccountMeta::new_readonly(*accs.vault_auth,   false), // escrow_vault_authority
        AccountMeta::new(*accs.vault_ata,             false), // escrow_vault (writable)
        AccountMeta::new(*accs.provider_ata,          false), // provider_usdc (writable)
        AccountMeta::new(*accs.treasury_ata,          false), // treasury_usdc (writable)
        AccountMeta::new_readonly(*accs.treasury_key, false), // treasury
        AccountMeta::new(*accs.notary_ata,            false), // notary_usdc (writable; skip when notary_fee=0)
        AccountMeta::new_readonly(*accs.usdc,         false), // usdc_mint
        AccountMeta::new_readonly(spl_token_program(), false), // token_program
    ];

    // approve_payment has no instruction arguments — data is discriminator only.
    let data = anchor_discriminator("approve_payment").to_vec();

    Instruction {
        program_id: escrow_program_id(),
        accounts,
        data,
    }
}
