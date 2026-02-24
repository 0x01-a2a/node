use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use zerox1_protocol::constants::SATI_PROGRAM_ID;
use crate::error::SatiClientError;

/// Token-2022 program ID (same on mainnet + devnet).
const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Minimal Rust client for querying SATI on-chain state.
///
/// Used by zerox1-node to validate sender registration (§5.5 rule 3)
/// without the TypeScript SATI SDK.
pub struct SatiClient {
    rpc: RpcClient,
    #[allow(dead_code)]
    program_id: Pubkey,
    token22: Pubkey,
}

impl SatiClient {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url.to_owned()),
            program_id: Pubkey::from_str(SATI_PROGRAM_ID).expect("valid SATI program ID"),
            token22: Pubkey::from_str(TOKEN_2022_PROGRAM_ID).expect("valid Token-2022 ID"),
        }
    }

    /// Check whether a given mint address is a registered SATI agent.
    ///
    /// A SATI agent is a Token-2022 NFT mint.  We cannot easily verify the
    /// AgentIndex PDA without knowing the member_number, so we check that:
    ///   1. The mint account exists on-chain.
    ///   2. It is owned by the Token-2022 program.
    ///
    /// Returns:
    ///   `Ok(true)`  — registered (mint exists under Token-2022)
    ///   `Ok(false)` — not registered (account absent or wrong owner)
    ///   `Err(_)`    — RPC failure (caller should treat as *unknown*, not *unregistered*)
    pub async fn is_registered(&self, agent_mint: &[u8; 32]) -> Result<bool, SatiClientError> {
        let mint_pubkey = Pubkey::new_from_array(*agent_mint);
        match self.rpc.get_account(&mint_pubkey).await {
            Ok(account) => Ok(account.owner == self.token22),
            Err(e) => {
                // Propagate RPC errors — the caller decides whether to allow
                // optimistically or to block pessimistically.
                Err(SatiClientError::Rpc(e.to_string()))
            }
        }
    }
}
