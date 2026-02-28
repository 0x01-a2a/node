use anchor_lang::prelude::*;

declare_id!("AgntownERRBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

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
    /// already has an accepted owner (AgentOwnership PDA discriminator check).
    pub fn propose_ownership(
        ctx: Context<ProposeOwnership>,
        agent_id: [u8; 32],
        proposed_owner: Pubkey,
    ) -> Result<()> {
        require!(proposed_owner != Pubkey::default(), OwnershipError::ZeroAddress);

        // Reject if already claimed — AgentOwnership PDA exists (non-zero data).
        let ownership_info = &ctx.accounts.agent_ownership_check;
        require!(
            ownership_info.data_is_empty(),
            OwnershipError::AlreadyClaimed,
        );

        let invite = &mut ctx.accounts.claim_invitation;
        invite.version        = 1;
        invite.agent_id       = agent_id;
        invite.proposed_owner = proposed_owner;
        invite.proposer       = ctx.accounts.proposer.key();
        invite.proposed_at    = Clock::get()?.unix_timestamp;
        invite.bump           = ctx.bumps.claim_invitation;

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
        ownership.version    = 1;
        ownership.agent_id   = invite.agent_id;
        ownership.owner      = ctx.accounts.owner.key();
        ownership.claimed_at = Clock::get()?.unix_timestamp;
        ownership.bump       = ctx.bumps.agent_ownership;

        emit!(OwnershipClaimed {
            agent_id:   invite.agent_id,
            owner:      ctx.accounts.owner.key(),
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
    /// Proposer — typically the agent's operator wallet or the agent itself.
    #[account(mut)]
    pub proposer: Signer<'info>,

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

    /// Read-only guard: must be empty (uncreated) for proposal to proceed.
    /// CHECK: we only inspect data_is_empty(); no write to this account.
    #[account(seeds = [b"agent_owner", agent_id.as_ref()], bump)]
    pub agent_ownership_check: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptClaim<'info> {
    /// Must be the proposed_owner wallet to prove consent.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// The pending invitation.
    #[account(
        mut,
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
    pub version:        u8,
    /// 0x01 agent ID = SATI mint address (32 bytes).
    pub agent_id:       [u8; 32],
    /// Human wallet being invited to claim ownership.
    pub proposed_owner: Pubkey,
    /// Wallet that submitted the proposal (agent key, operator, etc.).
    pub proposer:       Pubkey,
    /// Unix timestamp of the proposal.
    pub proposed_at:    i64,
    pub bump:           u8,
}

impl ClaimInvitation {
    /// 8 discriminator + 1 + 32 + 32 + 32 + 8 + 1 = 114 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 32 + 8 + 1;
}

/// Immutable ownership record — created once the human accepts.
/// PDA: seeds = ["agent_owner", agent_id]
#[account]
pub struct AgentOwnership {
    pub version:    u8,
    /// 0x01 agent ID = SATI mint address (32 bytes).
    pub agent_id:   [u8; 32],
    /// Human wallet that accepted the claim.
    pub owner:      Pubkey,
    /// Unix timestamp of acceptance.
    pub claimed_at: i64,
    pub bump:       u8,
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
    pub agent_id:       [u8; 32],
    pub proposed_owner: Pubkey,
    pub proposer:       Pubkey,
}

#[event]
pub struct OwnershipClaimed {
    pub agent_id:   [u8; 32],
    pub owner:      Pubkey,
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
}
