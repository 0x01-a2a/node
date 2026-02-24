use thiserror::Error;

#[derive(Debug, Error)]
pub enum SatiClientError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("agent not found: {0}")]
    AgentNotFound(String),
    #[error("invalid pubkey: {0}")]
    InvalidPubkey(String),
}
