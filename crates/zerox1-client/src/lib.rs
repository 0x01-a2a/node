//! # zerox1-client
//!
//! Official client SDK for building agents and services on the 0x01 mesh network.
//!
//! ## Quick start
//!
//! ```no_run
//! use zerox1_client::{NodeClient, ConversationId};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = NodeClient::new("http://127.0.0.1:9090", None)?;
//!
//!     // Discover own identity
//!     let me = client.identity().await?;
//!     println!("agent_id: {me}");
//!
//!     // Listen for inbound envelopes
//!     client.listen_inbox(|env| async move {
//!         println!("{} from {}", env.msg_type, env.sender);
//!         Ok(())
//!     }).await?;
//!
//!     Ok(())
//! }
//! ```

mod client;
mod types;

pub use client::NodeClient;
pub use types::{
    ActivityEvent, AgentId, ConversationId, HostedSendRequest, IdentityResponse,
    InboundEnvelope, SendEnvelopeRequest, SendEnvelopeResponse,
};
