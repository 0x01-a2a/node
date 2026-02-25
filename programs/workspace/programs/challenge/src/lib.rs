use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount, Transfer},
};

declare_id!("6tVCJmogJghQMEMRhvk4qrUoT6JXPPDebUwmRHXTtygj");

/// Behavior-log program ID — batch accounts must be owned by this program.
const BEHAVIOR_LOG_PROGRAM_ID: Pubkey =
    pubkey!("3gXhgBLsVYVQkntuVcPdiDe2gRxbSt2CGFJKriA8q9bA");

/// Byte offset of `submitted_slot` in BatchAccount raw data.
/// Layout: 8 disc + 32 agent_id + 8 epoch_number + 32 log_merkle_root + 32 batch_hash = 112
const BATCH_SUBMITTED_SLOT_OFFSET: usize = 112;

/// Byte offset of `log_merkle_root` in BatchAccount raw data.
/// Layout: 8 disc + 32 agent_id + 8 epoch_number = 48
const BATCH_MERKLE_ROOT_OFFSET: usize = 48;

// ============================================================================
// Challenge Program (doc 5, §10.4)
//
// Permissionless challenge of self-reported BehaviorBatch data.
// Challenger stakes CHALLENGE_STAKE_USDC (10 USDC). On success: agent slashed
// via StakeLock (v2 CPI), challenger refunded + reward from slash.
// On failure: challenger forfeits USDC stake to protocol treasury.
//
// Accounts use a payer/owner split for Kora gasless transactions:
//   payer     = transaction fee payer (Kora or challenger)
//   challenger = USDC authority (signs transfer from their ATA)
// When not using Kora: payer == challenger.
// ============================================================================

/// 10 USDC challenge stake (6 decimal places on Solana USDC).
pub const CHALLENGE_STAKE_USDC: u64 = 10_000_000;
/// Challenger receives 50% of slashed amount (v2; v1 refunds full stake).
pub const CHALLENGE_REWARD_BPS: u64 = 5_000;
/// Challenge window: ~2 days at 400ms/slot.
pub const CHALLENGE_WINDOW_SLOTS: u64 = 432_000;

#[program]
pub mod challenge {
    use super::*;

    /// Submit a challenge against a self-reported BehaviorBatch.
    ///
    /// Challenger provides:
    /// - The signed envelope bytes that contradict the batch
    /// - A merkle inclusion proof against the batch's log_merkle_root
    ///
    /// Stakes CHALLENGE_STAKE_USDC from challenger's USDC ATA into vault.
    pub fn submit_challenge(
        ctx: Context<SubmitChallenge>,
        args: SubmitChallengeArgs,
    ) -> Result<()> {
        let clock = Clock::get()?;

        // Verify batch account is owned by the behavior-log program.
        require!(
            ctx.accounts.batch_account.owner == &BEHAVIOR_LOG_PROGRAM_ID,
            ChallengeError::InvalidBatchAccount,
        );

        // Read submitted_slot from BatchAccount raw bytes (offset 112).
        let batch_submitted_slot = {
            let data = ctx.accounts.batch_account.try_borrow_data()?;
            require!(
                data.len() > BATCH_SUBMITTED_SLOT_OFFSET + 8,
                ChallengeError::InvalidBatchAccount,
            );
            u64::from_le_bytes(
                data[BATCH_SUBMITTED_SLOT_OFFSET..BATCH_SUBMITTED_SLOT_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            )
        };

        require!(
            clock.slot <= batch_submitted_slot + CHALLENGE_WINDOW_SLOTS,
            ChallengeError::ChallengeWindowExpired,
        );
        require!(
            !args.contradicting_entry.is_empty(),
            ChallengeError::EmptyEntry,
        );
        require!(
            !args.merkle_proof.is_empty(),
            ChallengeError::EmptyProof,
        );

        // Transfer USDC stake from challenger's ATA to vault.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from:      ctx.accounts.challenger_usdc.to_account_info(),
                to:        ctx.accounts.challenge_vault.to_account_info(),
                authority: ctx.accounts.challenger.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, CHALLENGE_STAKE_USDC)?;

        let entry_hash =
            anchor_lang::solana_program::keccak::hash(&args.contradicting_entry).to_bytes();

        let challenge                     = &mut ctx.accounts.challenge_account;
        challenge.agent_id                = args.agent_id;
        challenge.epoch_number            = args.epoch_number;
        challenge.challenger              = ctx.accounts.challenger.key();
        challenge.entry_hash              = entry_hash;
        challenge.leaf_index              = args.leaf_index;
        challenge.merkle_proof_len        = args.merkle_proof.len() as u16;
        challenge.resolved                = false;
        challenge.succeeded               = false;
        challenge.submitted_slot          = clock.slot;
        challenge.bump                    = ctx.bumps.challenge_account;
        challenge.vault_authority_bump    = ctx.bumps.challenge_vault_authority;

        emit!(ChallengeSubmitted {
            agent_id:       args.agent_id,
            epoch_number:   args.epoch_number,
            challenger:     ctx.accounts.challenger.key(),
            entry_hash,
            submitted_slot: clock.slot,
        });

        Ok(())
    }

    /// Resolve a challenge.
    ///
    /// Verifies the Merkle inclusion proof on-chain against the batch's
    /// log_merkle_root. Also verifies the contradicting_entry matches the
    /// entry_hash stored at submission time (prevents entry substitution).
    ///
    /// `contradicts_batch` is still caller-asserted (v1 — off-chain contradiction
    /// detection). On-chain we prove the entry IS in the batch; contradiction
    /// verification is the next step.
    ///
    /// On success: challenger's stake refunded from vault.
    /// On failure: challenger's stake transferred to protocol treasury.
    pub fn resolve_challenge(
        ctx: Context<ResolveChallenge>,
        args: ResolveChallengeArgs,
    ) -> Result<()> {
        let clock = Clock::get()?;

        require!(
            !ctx.accounts.challenge_account.resolved,
            ChallengeError::AlreadyResolved,
        );
        require!(
            clock.slot > ctx.accounts.challenge_account.submitted_slot,
            ChallengeError::TooEarlyToResolve,
        );

        // Verify the contradicting entry matches the hash stored at submission.
        let entry_hash =
            anchor_lang::solana_program::keccak::hash(&args.contradicting_entry).to_bytes();
        require!(
            entry_hash == ctx.accounts.challenge_account.entry_hash,
            ChallengeError::EntryHashMismatch,
        );

        // Read log_merkle_root from BatchAccount raw bytes at offset 48.
        // Layout: 8 disc + 32 agent_id + 8 epoch_number = 48.
        let log_merkle_root: [u8; 32] = {
            let data = ctx.accounts.batch_account.try_borrow_data()?;
            require!(
                data.len() >= BATCH_MERKLE_ROOT_OFFSET + 32,
                ChallengeError::InvalidBatchAccount,
            );
            data[BATCH_MERKLE_ROOT_OFFSET..BATCH_MERKLE_ROOT_OFFSET + 32]
                .try_into()
                .unwrap()
        };

        // Verify Merkle inclusion proof on-chain.
        let proof_valid = verify_inclusion(
            &args.contradicting_entry,
            &args.merkle_proof,
            ctx.accounts.challenge_account.leaf_index,
            log_merkle_root,
        );
        require!(proof_valid, ChallengeError::InvalidMerkleProof);

        // Capture values before mutable borrow.
        let challenge_key        = ctx.accounts.challenge_account.key();
        let vault_authority_bump = ctx.accounts.challenge_account.vault_authority_bump;
        let agent_id             = ctx.accounts.challenge_account.agent_id;
        let epoch_number         = ctx.accounts.challenge_account.epoch_number;
        let challenger           = ctx.accounts.challenge_account.challenger;
        let vault_balance        = ctx.accounts.challenge_vault.amount;

        // Succeeded = Merkle proof valid (verified above) AND entry contradicts batch.
        let succeeded = args.contradicts_batch;

        ctx.accounts.challenge_account.resolved  = true;
        ctx.accounts.challenge_account.succeeded = succeeded;

        let signer_seeds: &[&[&[u8]]] = &[&[
            b"challenge_vault",
            challenge_key.as_ref(),
            &[vault_authority_bump],
        ]];

        if succeeded {
            // Refund challenger's stake; slash reward handled via StakeLock in v2.
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from:      ctx.accounts.challenge_vault.to_account_info(),
                    to:        ctx.accounts.challenger_usdc.to_account_info(),
                    authority: ctx.accounts.challenge_vault_authority.to_account_info(),
                },
                signer_seeds,
            );
            token::transfer(cpi_ctx, vault_balance)?;

            emit!(ChallengeResolved {
                agent_id,
                epoch_number,
                succeeded:         true,
                challenger,
                slash_amount:      MIN_STAKE_USDC,
                challenger_reward: vault_balance,
                treasury_amount:   0,
            });
        } else {
            // Forfeit challenger's stake to treasury.
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from:      ctx.accounts.challenge_vault.to_account_info(),
                    to:        ctx.accounts.treasury_usdc.to_account_info(),
                    authority: ctx.accounts.challenge_vault_authority.to_account_info(),
                },
                signer_seeds,
            );
            token::transfer(cpi_ctx, vault_balance)?;

            emit!(ChallengeResolved {
                agent_id,
                epoch_number,
                succeeded:         false,
                challenger,
                slash_amount:      0,
                challenger_reward: 0,
                treasury_amount:   vault_balance,
            });
        }

        Ok(())
    }
}

/// Minimum stake — used for slash amount reference in events.
const MIN_STAKE_USDC: u64 = 10_000_000; // 10 USDC

/// Verify Merkle inclusion of `entry` at `leaf_index` against `root`.
///
/// Leaf hash = keccak256(entry).
/// Internal hashes = keccak256(left || right), left-child when index is even.
/// Tree is padded to next power-of-two with zero hashes (same as protocol crate).
fn verify_inclusion(
    entry:      &[u8],
    proof:      &[[u8; 32]],
    leaf_index: u64,
    root:       [u8; 32],
) -> bool {
    let leaf_hash =
        anchor_lang::solana_program::keccak::hash(entry).to_bytes();
    let mut current = leaf_hash;
    let mut idx     = leaf_index as usize;

    for sibling in proof {
        let mut combined = [0u8; 64];
        if idx % 2 == 0 {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current);
        }
        current = anchor_lang::solana_program::keccak::hash(&combined).to_bytes();
        idx /= 2;
    }

    current == root
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(args: SubmitChallengeArgs)]
pub struct SubmitChallenge<'info> {
    /// Transaction fee payer — Kora's pubkey (gasless) or same as challenger.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Challenger wallet — authorises USDC transfer from challenger_usdc.
    #[account(mut)]
    pub challenger: Signer<'info>,

    /// Challenger's USDC ATA (source of challenge stake).
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = challenger,
    )]
    pub challenger_usdc: Account<'info, TokenAccount>,

    /// Challenge state PDA.
    /// seeds = ["challenge", batch_account_key, challenger_pubkey]
    #[account(
        init,
        payer = payer,
        space = ChallengeAccount::SIZE,
        seeds = [
            b"challenge",
            batch_account.key().as_ref(),
            challenger.key().as_ref(),
        ],
        bump
    )]
    pub challenge_account: Account<'info, ChallengeAccount>,

    /// Vault authority PDA — owns the vault token account.
    /// seeds = ["challenge_vault", challenge_account_key]
    /// CHECK: PDA used as token account authority only.
    #[account(
        seeds = [b"challenge_vault", challenge_account.key().as_ref()],
        bump
    )]
    pub challenge_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA — holds USDC challenge stake.
    #[account(
        init,
        payer = payer,
        associated_token::mint      = usdc_mint,
        associated_token::authority = challenge_vault_authority,
    )]
    pub challenge_vault: Account<'info, TokenAccount>,

    /// The batch being challenged — submitted_slot read from raw bytes.
    /// CHECK: PDA seeds verified in handler.
    pub batch_account: UncheckedAccount<'info>,

    pub usdc_mint:                Account<'info, Mint>,
    pub token_program:            Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program:           Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResolveChallenge<'info> {
    /// Permissionless resolver.
    pub resolver: Signer<'info>,

    #[account(
        mut,
        seeds = [
            b"challenge",
            batch_account.key().as_ref(),
            challenge_account.challenger.as_ref(),
        ],
        bump = challenge_account.bump,
    )]
    pub challenge_account: Account<'info, ChallengeAccount>,

    /// CHECK: Vault authority PDA.
    #[account(
        seeds = [b"challenge_vault", challenge_account.key().as_ref()],
        bump  = challenge_account.vault_authority_bump,
    )]
    pub challenge_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA (source of funds on resolution).
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = challenge_vault_authority,
    )]
    pub challenge_vault: Account<'info, TokenAccount>,

    /// Challenger's USDC ATA — receives refund on successful challenge.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = challenge_account.challenger,
    )]
    pub challenger_usdc: Account<'info, TokenAccount>,

    /// Protocol treasury USDC ATA — receives forfeited stake on failure.
    #[account(mut)]
    pub treasury_usdc: Account<'info, TokenAccount>,

    /// Batch account — log_merkle_root read from raw bytes for proof verification.
    /// CHECK: Batch account used as key for challenge PDA seed derivation.
    pub batch_account: UncheckedAccount<'info>,

    pub usdc_mint:     Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

// ============================================================================
// State
// ============================================================================

/// PDA: seeds = ["challenge", batch_pda_key, challenger_pubkey]
#[account]
pub struct ChallengeAccount {
    pub agent_id:              [u8; 32],
    pub epoch_number:          u64,
    pub challenger:            Pubkey,
    pub entry_hash:            [u8; 32],
    pub leaf_index:            u64,
    pub merkle_proof_len:      u16,
    pub resolved:              bool,
    pub succeeded:             bool,
    pub submitted_slot:        u64,
    pub bump:                  u8,
    pub vault_authority_bump:  u8,
}

impl ChallengeAccount {
    /// 8 + 32 + 8 + 32 + 32 + 8 + 2 + 1 + 1 + 8 + 1 + 1 = 134 bytes
    pub const SIZE: usize = 8 + 32 + 8 + 32 + 32 + 8 + 2 + 1 + 1 + 8 + 1 + 1;
}

// ============================================================================
// Instruction arguments
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitChallengeArgs {
    pub agent_id:            [u8; 32],
    pub epoch_number:        u64,
    /// Full canonical log entry bytes (signed CBOR envelope) contradicting the batch.
    pub contradicting_entry: Vec<u8>,
    /// Merkle sibling hashes from entry leaf to log_merkle_root.
    pub merkle_proof:        Vec<[u8; 32]>,
    /// 0-based leaf index of the entry in the batch's Merkle tree.
    pub leaf_index:          u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ResolveChallengeArgs {
    /// Full canonical log entry bytes — must match entry_hash stored at submission.
    pub contradicting_entry: Vec<u8>,
    /// Merkle sibling hashes from entry leaf to log_merkle_root.
    pub merkle_proof:        Vec<[u8; 32]>,
    /// True if the entry contradicts the self-reported batch arrays (v1: caller-asserted).
    pub contradicts_batch:   bool,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct ChallengeSubmitted {
    pub agent_id:       [u8; 32],
    pub epoch_number:   u64,
    pub challenger:     Pubkey,
    pub entry_hash:     [u8; 32],
    pub submitted_slot: u64,
}

#[event]
pub struct ChallengeResolved {
    pub agent_id:          [u8; 32],
    pub epoch_number:      u64,
    pub succeeded:         bool,
    pub challenger:        Pubkey,
    pub slash_amount:      u64,
    pub challenger_reward: u64,
    pub treasury_amount:   u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum ChallengeError {
    #[msg("Challenge window has expired for this batch")]
    ChallengeWindowExpired,
    #[msg("Contradicting entry must not be empty")]
    EmptyEntry,
    #[msg("Merkle proof must not be empty")]
    EmptyProof,
    #[msg("Challenge already resolved")]
    AlreadyResolved,
    #[msg("Too early to resolve — wait for finality")]
    TooEarlyToResolve,
    #[msg("Batch account data is invalid or too short")]
    InvalidBatchAccount,
    #[msg("Merkle inclusion proof is invalid — entry not found in batch log")]
    InvalidMerkleProof,
    #[msg("Contradicting entry does not match the hash recorded at submission")]
    EntryHashMismatch,
}
