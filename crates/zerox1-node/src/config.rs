use clap::Parser;
use libp2p::Multiaddr;
use solana_sdk::pubkey::Pubkey;
use std::{path::PathBuf, str::FromStr};

// ============================================================================
// 0x01 bootstrap fleet (always-on libp2p nodes for mesh entry)
// ============================================================================
//
// These multiaddrs must be updated when the bootstrap fleet is deployed.
// Format: /ip4/<addr>/tcp/<port>/p2p/<PeerId>
// TODO: replace placeholders with real peer IDs once deployed.

const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[
    // bootstrap-1.0x01.world
    "/dns4/bootstrap-1.0x01.world/tcp/9000/p2p/12D3KooWBootstrap1PlaceholderPeerIdAAAAAAAAAAAAAAAAAAAAA",
    // bootstrap-2.0x01.world
    "/dns4/bootstrap-2.0x01.world/tcp/9000/p2p/12D3KooWBootstrap2PlaceholderPeerIdAAAAAAAAAAAAAAAAAAAAA",
    // bootstrap-3.0x01.world (EU)
    "/dns4/bootstrap-3.0x01.world/tcp/9000/p2p/12D3KooWBootstrap3PlaceholderPeerIdAAAAAAAAAAAAAAAAAAAAA",
];

#[derive(Parser, Debug)]
#[command(name = "zerox1-node", about = "0x01 mesh node (doc 5, §9)")]
pub struct Config {
    /// libp2p listen multiaddr.
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    pub listen_addr: Multiaddr,

    /// Bootstrap peer multiaddrs (can repeat).
    /// The 0x01 bootstrap fleet is used by default; pass --no-default-bootstrap
    /// if you want to run a fully isolated private mesh.
    #[arg(long)]
    pub bootstrap: Vec<Multiaddr>,

    /// Disable the built-in 0x01 bootstrap peers.
    /// By default, the node connects to the 0x01 always-on bootstrap fleet so
    /// agents can find each other without any manual configuration.
    #[arg(long, default_value = "false")]
    pub no_default_bootstrap: bool,

    /// Solana RPC endpoint for slot queries and batch submission.
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    pub rpc_url: String,

    /// SATI mint address (hex, 32 bytes) = this agent's ID.
    /// If absent, the node runs in dev mode with agent_id = verifying_key bytes.
    #[arg(long, env = "ZX01_SATI_MINT")]
    pub sati_mint: Option<String>,

    /// Display name for BEACON messages.
    #[arg(long, default_value = "zerox1-agent")]
    pub agent_name: String,

    /// Path to the 32-byte Ed25519 secret key file.
    #[arg(long, default_value = "zerox1-identity.key")]
    pub keypair_path: PathBuf,

    /// Directory for per-epoch CBOR envelope logs.
    #[arg(long, default_value = ".")]
    pub log_dir: PathBuf,

    /// Kora paymaster URL for gasless on-chain transactions (USDC gas payment).
    /// Defaults to the 0x01-hosted Kora instance.
    /// Override with --kora-url to use your own node, or set to "none" to
    /// disable Kora entirely (transactions will require SOL for gas).
    #[arg(long, env = "ZX01_KORA_URL", default_value = "https://kora.0x01.world")]
    pub kora_url: String,

    /// Visualization API listen address (HTTP + WebSocket).
    /// Enables: GET /peers, GET /reputation/:id, GET /batch/:id/:epoch, GET /ws/events
    /// Example: 127.0.0.1:8080
    /// If absent, the API server is not started.
    #[arg(long, env = "ZX01_API_ADDR")]
    pub api_addr: Option<String>,

    /// USDC SPL token mint address (base58).
    /// Required for inactivity slash enforcement — enables the node to receive
    /// slash bounties into its USDC ATA.
    #[arg(long, env = "ZX01_USDC_MINT")]
    pub usdc_mint: Option<String>,

    /// Reputation aggregator URL.
    /// When set, FEEDBACK and VERDICT envelopes are pushed to this service.
    /// Example: http://127.0.0.1:8081
    #[arg(long, env = "ZX01_AGGREGATOR_URL")]
    pub aggregator_url: Option<String>,

    /// Shared secret for authenticating pushes to the reputation aggregator.
    /// Must match the aggregator's --ingest-secret.
    #[arg(long, env = "ZX01_AGGREGATOR_SECRET")]
    pub aggregator_secret: Option<String>,
}

impl Config {
    /// Return the full bootstrap peer list: user-supplied + default fleet
    /// (unless --no-default-bootstrap is set).
    pub fn all_bootstrap_peers(&self) -> Vec<Multiaddr> {
        let mut peers = self.bootstrap.clone();
        if !self.no_default_bootstrap {
            for addr_str in DEFAULT_BOOTSTRAP_PEERS {
                match addr_str.parse::<Multiaddr>() {
                    Ok(addr) => peers.push(addr),
                    Err(e) => tracing::warn!("Invalid default bootstrap addr '{addr_str}': {e}"),
                }
            }
        }
        peers
    }

    /// Parse USDC mint as Pubkey, if provided.
    pub fn usdc_mint_pubkey(&self) -> anyhow::Result<Option<Pubkey>> {
        match &self.usdc_mint {
            None => Ok(None),
            Some(s) => Ok(Some(
                Pubkey::from_str(s)
                    .map_err(|e| anyhow::anyhow!("invalid usdc_mint: {e}"))?,
            )),
        }
    }

    /// Parse SATI mint from hex string to bytes32, if provided.
    pub fn sati_mint_bytes(&self) -> anyhow::Result<Option<[u8; 32]>> {
        match &self.sati_mint {
            None => Ok(None),
            Some(s) => {
                let bytes = hex::decode(s.trim_start_matches("0x"))
                    .map_err(|e| anyhow::anyhow!("invalid sati_mint hex: {e}"))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("sati_mint must be 32 bytes"))?;
                Ok(Some(arr))
            }
        }
    }
}
