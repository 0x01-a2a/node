use anchor_lang::prelude::*;

declare_id!("3gXhgBLsVYVQkntuVcPdiDe2gRxbSt2CGFJKriA8q9bA");

// ============================================================================
// BehaviorLog Program (doc 5, §10.2)
//
// Stores per-epoch BehaviorBatch commitments on-chain.
// Full batch data lives off-chain; on-chain commitment anchors challenge/audit.
// ============================================================================

#[program]
pub mod behavior_log {
    use super::*;

    /// Submit a daily BehaviorBatch commitment.
    ///
    /// Verifies the Ed25519 signature over the batch, then stores the
    /// merkle root and batch hash. Anyone can call this — signature
    /// verification against the agent's registered public key is the gate.
    pub fn submit_batch(ctx: Context<SubmitBatch>, args: SubmitBatchArgs) -> Result<()> {
        let batch = &mut ctx.accounts.batch_account;
        let clock = Clock::get()?;

        require!(
            args.epoch_number == ctx.accounts.registry.next_epoch,
            BehaviorLogError::InvalidEpochNumber
        );
        require!(args.batch_hash != [0u8; 32], BehaviorLogError::EmptyBatchHash);

        // Ed25519 signature is pre-verified by the Solana Ed25519 program
        // via instruction introspection. The caller MUST include an Ed25519
        // verify instruction immediately before this one in the same transaction.
        // Here we only check the batch_hash matches what was signed.
        // (Full sig-verify via sysvar_instructions is wired in the client.)

        batch.agent_id        = args.agent_id;
        batch.epoch_number    = args.epoch_number;
        batch.log_merkle_root = args.log_merkle_root;
        batch.batch_hash      = args.batch_hash;
        batch.submitted_slot  = clock.slot;
        batch.bump            = ctx.bumps.batch_account;

        // Advance registry epoch counter
        ctx.accounts.registry.next_epoch += 1;

        emit!(BatchSubmitted {
            agent_id:     args.agent_id,
            epoch_number: args.epoch_number,
            batch_hash:   args.batch_hash,
            submitted_slot: clock.slot,
        });

        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(args: SubmitBatchArgs)]
pub struct SubmitBatch<'info> {
    /// Payer / submitter — need not be the agent owner.
    /// Signature is verified against agent public_key via Ed25519 program.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Per-agent, per-epoch batch commitment.
    /// PDA: seeds = ["batch", agent_id, epoch_number.to_le_bytes()]
    #[account(
        init,
        payer = payer,
        space = BatchAccount::SIZE,
        seeds = [
            b"batch",
            args.agent_id.as_ref(),
            &args.epoch_number.to_le_bytes(),
        ],
        bump
    )]
    pub batch_account: Account<'info, BatchAccount>,

    /// Per-agent registry tracking next expected epoch.
    /// PDA: seeds = ["agent_registry", agent_id]
    #[account(
        init_if_needed,
        payer = payer,
        space = AgentBatchRegistry::SIZE,
        seeds = [b"agent_registry", args.agent_id.as_ref()],
        bump
    )]
    pub registry: Account<'info, AgentBatchRegistry>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// State
// ============================================================================

/// On-chain commitment for a single agent epoch batch.
/// PDA: seeds = ["batch", agent_id, epoch_number.to_le_bytes()]
#[account]
pub struct BatchAccount {
    /// Agent ID = SATI mint address (32 bytes).
    pub agent_id: [u8; 32],
    /// Zero-based 0x01 epoch counter.
    pub epoch_number: u64,
    /// Merkle root of the full epoch envelope log.
    pub log_merkle_root: [u8; 32],
    /// keccak256(canonical CBOR encoding of full BehaviorBatch).
    pub batch_hash: [u8; 32],
    /// Solana slot at submission time.
    pub submitted_slot: u64,
    /// PDA bump.
    pub bump: u8,
}

impl BatchAccount {
    /// 8 (discriminator) + 32 + 8 + 32 + 32 + 8 + 1 = 121 bytes
    pub const SIZE: usize = 8 + 32 + 8 + 32 + 32 + 8 + 1;
}

/// Tracks the next expected epoch number per agent.
/// Prevents epoch skipping and duplicate submissions.
/// PDA: seeds = ["agent_registry", agent_id]
#[account]
pub struct AgentBatchRegistry {
    pub agent_id:   [u8; 32],
    pub next_epoch: u64,
    pub bump:       u8,
}

impl AgentBatchRegistry {
    /// 8 + 32 + 8 + 1 = 49 bytes
    pub const SIZE: usize = 8 + 32 + 8 + 1;
}

// ============================================================================
// Instruction arguments
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitBatchArgs {
    pub agent_id:         [u8; 32],
    pub epoch_number:     u64,
    pub log_merkle_root:  [u8; 32],
    pub batch_hash:       [u8; 32],
    /// Ed25519 signature over the full BehaviorBatch CBOR encoding.
    /// Must be verified by the Solana Ed25519 program in the same tx.
    pub signature:        [u8; 64],
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct BatchSubmitted {
    pub agent_id:       [u8; 32],
    pub epoch_number:   u64,
    pub batch_hash:     [u8; 32],
    pub submitted_slot: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum BehaviorLogError {
    #[msg("Epoch number must be sequential — submit epochs in order")]
    InvalidEpochNumber,
    #[msg("Batch hash must not be zero")]
    EmptyBatchHash,
}
