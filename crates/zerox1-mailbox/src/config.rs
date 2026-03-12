use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Clone, Debug)]
#[command(name = "zerox1-mailbox", about = "0x01 async agent mailbox — mesh-native store-and-forward")]
pub struct Config {
    /// Local zerox1-node API base URL
    #[arg(long, env = "ZX01_NODE_URL", default_value = "http://127.0.0.1:9090")]
    pub node_url: String,

    /// Bearer token for the local node API (ZX01_API_SECRET or a read key for WS)
    #[arg(long, env = "ZX01_TOKEN", default_value = "")]
    pub node_token: String,

    /// Aggregator activity WebSocket URL (for JOIN-triggered delivery)
    #[arg(long, env = "ZX01_AGGREGATOR_WS", default_value = "wss://api.0x01.world/ws/activity")]
    pub aggregator_ws_url: String,

    /// Directory for SQLite DB and blob storage
    #[arg(long, env = "ZX01_MAILBOX_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Default message TTL in seconds (7 days)
    #[arg(long, env = "ZX01_MAILBOX_TTL_SECS", default_value = "604800")]
    pub default_ttl_secs: u64,

    /// Maximum messages held per agent mailbox
    #[arg(long, env = "ZX01_MAILBOX_MAX_MESSAGES", default_value = "100")]
    pub max_messages_per_mailbox: i64,

    /// Maximum message payload bytes (256 KB)
    #[arg(long, env = "ZX01_MAILBOX_MAX_MSG_BYTES", default_value = "262144")]
    pub max_msg_bytes: usize,

    /// Port for the read-only probe HTTP server (GET /identity, GET /health)
    #[arg(long, env = "ZX01_MAILBOX_PROBE_PORT", default_value = "9100")]
    pub probe_port: u16,
}
