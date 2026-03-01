use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    Mint as MintInterface, TokenAccount as TokenAccountInterface, TokenInterface,
};

declare_id!("9GYVDTgc345bBa2k7j9a15aJSeKjzC75eyxdL3XCYVS9");

// ============================================================================
// AgentOwnership Program
//
// Lets an agent propose a human owner for its identity, and the human
// accept on-chain. Once claimed, the association is immutable.
//
// Flow:
//   1. Agent (or operator) calls propose_ownership(agent_id, proposed_owner)
//      → creates / overwrites ClaimInvitation PDA (pending)
//   2. Human wallet calls accept_claim()
//      → creates an immutable AgentOwnership PDA
//   3. Aggregator reads AgentOwnership PDA → shows "Claimed by <owner>"
//
// PDAs:
//   ClaimInvitation : seeds = ["claim_invite", agent_id]
//   AgentOwnership  : seeds = ["agent_owner",  agent_id]
// ============================================================================

#[program]
pub mod agent_ownership {
    use super::*;

    /// Propose a human owner for an agent.
    ///
    /// Creates (or overwrites) a ClaimInvitation PDA. Fails if the agent
    /// already has an accepted owner (AgentOwnership PDA exists).
    pub fn propose_ownership(
        ctx: Context<ProposeOwnership>,
        agent_id: [u8; 32],
        proposed_owner: Pubkey,
    ) -> Result<()> {
        require!(
            proposed_owner != Pubkey::default(),
            OwnershipError::ZeroAddress
        );

        // Reject if already claimed — AgentOwnership PDA exists (non-zero lamports).
        require!(
            ctx.accounts.agent_ownership_check.lamports() == 0,
            OwnershipError::AlreadyClaimed,
        );

        let invite = &mut ctx.accounts.claim_invitation;

        if invite.proposed_at != 0 {
            require!(
                ctx.accounts.proposer.key() == invite.proposer,
                OwnershipError::NotOriginalProposer,
            );
        }

        invite.version = 1;
        invite.agent_id = agent_id;
        invite.proposed_owner = proposed_owner;
        invite.proposer = ctx.accounts.proposer.key();
        invite.proposed_at = Clock::get()?.unix_timestamp;
        invite.bump = ctx.bumps.claim_invitation;

        emit!(OwnershipProposed {
            agent_id,
            proposed_owner,
            proposer: ctx.accounts.proposer.key(),
        });

        Ok(())
    }

    /// Accept the pending ownership claim.
    ///
    /// Must be signed by the proposed_owner wallet.
    /// Creates an immutable AgentOwnership PDA; ownership cannot be changed.
    pub fn accept_claim(ctx: Context<AcceptClaim>) -> Result<()> {
        let invite = &ctx.accounts.claim_invitation;

        require!(
            ctx.accounts.owner.key() == invite.proposed_owner,
            OwnershipError::NotProposedOwner,
        );

        let ownership = &mut ctx.accounts.agent_ownership;
        ownership.version = 1;
        ownership.agent_id = invite.agent_id;
        ownership.owner = ctx.accounts.owner.key();
        ownership.claimed_at = Clock::get()?.unix_timestamp;
        ownership.bump = ctx.bumps.agent_ownership;

        emit!(OwnershipClaimed {
            agent_id: invite.agent_id,
            owner: ctx.accounts.owner.key(),
            claimed_at: ownership.claimed_at,
        });

        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(agent_id: [u8; 32], proposed_owner: Pubkey)]
pub struct ProposeOwnership<'info> {
    /// Proposer — must hold the SATI NFT for this agent.
    #[account(mut)]
    pub proposer: Signer<'info>,

    /// The agent's SATI NFT mint — must match agent_id (Token-2022).
    #[account(constraint = agent_mint.key().to_bytes() == agent_id @ OwnershipError::AgentMintMismatch)]
    pub agent_mint: InterfaceAccount<'info, MintInterface>,

    /// Proposer's token account proving SATI NFT ownership.
    #[account(
        token::mint = agent_mint,
        token::authority = proposer,
        token::token_program = sati_token_program,
        constraint = proposer_sati_token.amount == 1 @ OwnershipError::NotAgentHolder,
    )]
    pub proposer_sati_token: InterfaceAccount<'info, TokenAccountInterface>,

    /// Claim invitation PDA — created on first call, overwritten on re-proposal.
    /// PDA: seeds = ["claim_invite", agent_id]
    #[account(
        init_if_needed,
        payer  = proposer,
        space  = ClaimInvitation::SIZE,
        seeds  = [b"claim_invite", agent_id.as_ref()],
        bump,
    )]
    pub claim_invitation: Account<'info, ClaimInvitation>,

    /// Read-only guard: must have zero lamports (uncreated) to allow new proposals.
    /// If the AgentOwnership PDA exists, lamports > 0 and propose_ownership rejects.
    /// CHECK: only used for lamport check — no reads or writes.
    #[account(seeds = [b"agent_owner", agent_id.as_ref()], bump)]
    pub agent_ownership_check: UncheckedAccount<'info>,

    /// Token program for SATI NFTs (Token-2022).
    pub sati_token_program: Interface<'info, TokenInterface>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptClaim<'info> {
    /// Must be the proposed_owner wallet to prove consent.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The pending invitation — closed on acceptance; rent returned to owner.
    #[account(
        mut,
        close = owner,
        seeds = [b"claim_invite", claim_invitation.agent_id.as_ref()],
        bump  = claim_invitation.bump,
    )]
    pub claim_invitation: Account<'info, ClaimInvitation>,

    /// Immutable ownership record created on acceptance.
    /// PDA: seeds = ["agent_owner", agent_id]
    #[account(
        init,
        payer = owner,
        space = AgentOwnership::SIZE,
        seeds = [b"agent_owner", claim_invitation.agent_id.as_ref()],
        bump,
    )]
    pub agent_ownership: Account<'info, AgentOwnership>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// State
// ============================================================================

/// Pending invitation — overwritable until accepted.
/// PDA: seeds = ["claim_invite", agent_id]
#[account]
pub struct ClaimInvitation {
    pub version: u8,
    /// 0x01 agent ID = SATI mint address (32 bytes).
    pub agent_id: [u8; 32],
    /// Human wallet being invited to claim ownership.
    pub proposed_owner: Pubkey,
    /// Wallet that submitted the proposal (agent key, operator, etc.).
    pub proposer: Pubkey,
    /// Unix timestamp of the proposal.
    pub proposed_at: i64,
    pub bump: u8,
}

impl ClaimInvitation {
    /// 8 discriminator + 1 + 32 + 32 + 32 + 8 + 1 = 114 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 32 + 8 + 1;
}

/// Immutable ownership record — created once the human accepts.
/// PDA: seeds = ["agent_owner", agent_id]
#[account]
pub struct AgentOwnership {
    pub version: u8,
    /// 0x01 agent ID = SATI mint address (32 bytes).
    pub agent_id: [u8; 32],
    /// Human wallet that accepted the claim.
    pub owner: Pubkey,
    /// Unix timestamp of acceptance.
    pub claimed_at: i64,
    pub bump: u8,
}

impl AgentOwnership {
    /// 8 discriminator + 1 + 32 + 32 + 8 + 1 = 82 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 8 + 1;
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct OwnershipProposed {
    pub agent_id: [u8; 32],
    pub proposed_owner: Pubkey,
    pub proposer: Pubkey,
}

#[event]
pub struct OwnershipClaimed {
    pub agent_id: [u8; 32],
    pub owner: Pubkey,
    pub claimed_at: i64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum OwnershipError {
    #[msg("proposed_owner must not be the zero address")]
    ZeroAddress,
    #[msg("Only the proposed_owner wallet may accept this claim")]
    NotProposedOwner,
    #[msg("This agent already has an accepted owner — ownership is immutable")]
    AlreadyClaimed,
    #[msg("Only the original proposer may overwrite a pending proposal")]
    NotOriginalProposer,
    #[msg("agent_mint does not match the provided agent_id")]
    AgentMintMismatch,
    #[msg("Proposer must hold the SATI NFT for this agent")]
    NotAgentHolder,
}
