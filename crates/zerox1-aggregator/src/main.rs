use zerox1_aggregator::api;
#[cfg(any(feature = "celo-settlement", feature = "base-settlement", feature = "sui-settlement"))]
use zerox1_aggregator::billing;
#[allow(unused_imports)]
use zerox1_aggregator::mpp;
use zerox1_aggregator::registry_8004;
use zerox1_aggregator::store;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use clap::Parser;
use ed25519_dalek::SigningKey as EdSigningKey;
use tokio::sync::broadcast;

use api::AppState;
use store::{ActivityEvent, ReputationStore};
#[cfg(feature = "data-bounty")]
use store::Campaign;

#[derive(Parser, Debug)]
#[command(
    name = "zerox1-aggregator",
    about = "0x01 reputation aggregator service"
)]
struct Config {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:80", env = "AGGREGATOR_LISTEN")]
    listen: std::net::SocketAddr,

    /// Shared secret for POST /ingest/envelope.
    /// When set, requests must include `Authorization: Bearer <secret>`.
    /// Omit only in development / closed-network deployments.
    #[arg(long, env = "AGGREGATOR_INGEST_SECRET")]
    ingest_secret: Option<String>,

    /// Path to the SQLite database file for persistent reputation storage.
    /// If absent, data is in-memory only and lost on restart.
    /// Example: /var/lib/zerox1/reputation.db
    #[arg(long, env = "AGGREGATOR_DB_PATH")]
    db_path: Option<std::path::PathBuf>,

    /// ntfy server base URL for wake-push notifications to sleeping phone nodes.
    /// Defaults to `https://ntfy.sh` when set to any non-empty value; pass a
    /// custom URL for self-hosted ntfy instances.
    /// When absent, wake-push is disabled (sleep-state tracking still works).
    #[arg(long, env = "NTFY_SERVER", default_value = "https://ntfy.sh")]
    ntfy_server: Option<String>,

    /// Shared secret for POST /hosting/register.
    /// Host nodes must include `Authorization: Bearer <secret>` in their
    /// heartbeat requests. When absent, the endpoint is unauthenticated
    /// (dev/local only — always set this in production).
    #[arg(long, env = "AGGREGATOR_HOSTING_SECRET")]
    hosting_secret: Option<String>,

    /// Path to a directory for storing large media blobs.
    /// If absent, blob uploads are disabled.
    #[arg(long, env = "AGGREGATOR_BLOB_DIR")]
    blob_dir: Option<std::path::PathBuf>,

    /// Path to a directory for storing agent highlight reel videos.
    /// If absent, reel uploads are disabled (agents can still post external URLs).
    /// Example: /var/lib/zerox1/reels
    #[arg(long, env = "AGGREGATOR_REEL_DIR")]
    reel_dir: Option<std::path::PathBuf>,

    /// 8004 Agent Registry GraphQL indexer URL.
    /// Defaults to the production indexer at Railway.
    #[arg(long, env = "ZX01_REGISTRY_8004_URL")]
    registry_8004_url: Option<String>,

    /// Minimum trust tier for 8004 registry checks (0-4).
    /// Agents below this tier are treated as unregistered.
    #[arg(long, default_value = "0", env = "ZX01_REGISTRY_8004_MIN_TIER")]
    registry_8004_min_tier: u8,

    /// Comma-separated API keys for gating read endpoints.
    /// When set, all GET endpoints (reputation, leaderboard, agents, entropy,
    /// interactions, etc.) require `Authorization: Bearer <key>`.
    /// /health, /version, and internal POST endpoints (ingest, hosting) are exempt.
    /// When absent, all read endpoints are public (dev/local mode).
    /// Example: "explorer-abc123,devteam-xyz789,paid-client-001"
    #[arg(long, env = "AGGREGATOR_API_KEYS", value_delimiter = ',')]
    api_keys: Vec<String>,

    /// Shared secret for POST /campaigns (operator-only campaign creation).
    /// When absent, campaign creation is disabled.
    #[cfg(feature = "data-bounty")]
    #[arg(long, env = "AGGREGATOR_OPERATOR_SECRET")]
    operator_secret: Option<String>,

    // ── Celo settlement ───────────────────────────────────────────────────

    /// Celo JSON-RPC URL for the settlement worker.
    /// Required to execute approvePayment on VERDICT for Celo agents.
    /// Mainnet: https://forno.celo.org  Testnet: https://celo-sepolia.drpc.org
    #[cfg(feature = "celo-settlement")]
    #[arg(long, env = "CELO_RPC_URL")]
    celo_rpc_url: Option<String>,

    /// Deployed ZeroxEscrow contract address on Celo (0x...).
    #[cfg(feature = "celo-settlement")]
    #[arg(long, env = "CELO_ESCROW")]
    celo_escrow: Option<String>,

    /// Deployed ZeroxLease contract address on Celo (0x...).
    #[cfg(feature = "celo-settlement")]
    #[arg(long, env = "CELO_LEASE")]
    celo_lease: Option<String>,

    /// Deployed ZeroxStakeLock contract address on Celo (0x...).
    #[cfg(feature = "celo-settlement")]
    #[arg(long, env = "CELO_STAKE_LOCK")]
    celo_stake_lock: Option<String>,

    /// Deployed AgentRegistry contract address on Celo (0x...).
    #[cfg(feature = "celo-settlement")]
    #[arg(long, env = "CELO_REGISTRY")]
    celo_registry: Option<String>,

    /// Celo private key (0x-prefixed hex) for the aggregator's notary EOA.
    /// The aggregator is designated as notary in Celo escrows so it can call
    /// approvePayment automatically on VERDICT without requiring the requester online.
    #[cfg(feature = "celo-settlement")]
    #[arg(long, env = "CELO_PRIVATE_KEY")]
    celo_private_key: Option<String>,

    // ── Base settlement ───────────────────────────────────────────────────

    /// Base JSON-RPC URL for the settlement worker.
    /// Required to execute approvePayment on VERDICT for Base agents.
    /// Mainnet: https://mainnet.base.org  Testnet: https://sepolia.base.org
    #[cfg(feature = "base-settlement")]
    #[arg(long, env = "BASE_RPC_URL")]
    base_rpc_url: Option<String>,

    /// Deployed ZeroxEscrow contract address on Base (0x...).
    #[cfg(feature = "base-settlement")]
    #[arg(long, env = "BASE_ESCROW")]
    base_escrow: Option<String>,

    /// Deployed ZeroxLease contract address on Base (0x...).
    #[cfg(feature = "base-settlement")]
    #[arg(long, env = "BASE_LEASE")]
    base_lease: Option<String>,

    /// Deployed ZeroxStakeLock contract address on Base (0x...).
    #[cfg(feature = "base-settlement")]
    #[arg(long, env = "BASE_STAKE_LOCK")]
    base_stake_lock: Option<String>,

    /// Deployed AgentRegistry contract address on Base (0x...).
    #[cfg(feature = "base-settlement")]
    #[arg(long, env = "BASE_REGISTRY")]
    base_registry: Option<String>,

    /// Base private key (0x-prefixed hex) for the aggregator's notary EOA.
    /// The aggregator is designated as notary in Base escrows so it can call
    /// approvePayment automatically on VERDICT without requiring the requester online.
    #[cfg(feature = "base-settlement")]
    #[arg(long, env = "BASE_PRIVATE_KEY")]
    base_private_key: Option<String>,

    // ── Sui settlement ────────────────────────────────────────────────────

    /// Sui JSON-RPC fullnode URL.
    /// Mainnet: https://fullnode.mainnet.sui.io  Testnet: https://fullnode.testnet.sui.io
    #[cfg(feature = "sui-settlement")]
    #[arg(long, env = "SUI_RPC_URL")]
    sui_rpc_url: Option<String>,

    /// Deployed zerox1_escrow Move package ID on Sui (0x<64-hex>).
    #[cfg(feature = "sui-settlement")]
    #[arg(long, env = "SUI_PACKAGE_ID")]
    sui_package_id: Option<String>,

    /// Escrow module name within the Sui package.
    #[cfg(feature = "sui-settlement")]
    #[arg(long, env = "SUI_ESCROW_MODULE", default_value = "zerox1_escrow")]
    sui_escrow_module: String,

    /// USDC coin type string for Sui Move type arguments.
    /// Mainnet: 0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC
    /// Testnet: 0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC
    #[cfg(feature = "sui-settlement")]
    #[arg(long, env = "SUI_COIN_TYPE")]
    sui_coin_type: Option<String>,

    /// Ed25519 private key for the Sui notary (0x-prefixed 32-byte hex seed).
    /// The aggregator address derived from this key must be set as `notary`
    /// in each ZeroxEscrow created by agents.
    #[cfg(feature = "sui-settlement")]
    #[arg(long, env = "SUI_PRIVATE_KEY")]
    sui_private_key: Option<String>,

    // ── MPP protocol fee gate ─────────────────────────────────────────────

    /// Enable the MPP protocol-fee gate. When set, BEACON messages from agents
    /// that haven't paid are silently dropped (soft gate). Disabled by default (beta).
    #[arg(long, env = "AGGREGATOR_PROTOCOL_FEE_ENABLED", default_value_t = false)]
    protocol_fee_enabled: bool,

    /// Daily protocol fee for hosted agents in USDC (float). Default: 0.2 USDC.
    #[arg(long, env = "AGGREGATOR_PROTOCOL_FEE_HOSTED_USDC", default_value_t = 0.2f64)]
    protocol_fee_hosted_usdc: f64,

    /// Daily protocol fee for self-hosted agents in USDC (float). Default: 1.0 USDC.
    #[arg(long, env = "AGGREGATOR_PROTOCOL_FEE_SELF_HOSTED_USDC", default_value_t = 1.0f64)]
    protocol_fee_self_hosted_usdc: f64,

    /// Base58 Solana pubkey of the aggregator operator's wallet.
    /// When set, the USDC ATA is derived from this and used as the payment recipient.
    #[arg(long, env = "AGGREGATOR_PROTOCOL_FEE_RECIPIENT")]
    protocol_fee_recipient: Option<String>,

    /// Solana RPC URL used for verifying protocol-fee payments via getTransaction.
    /// Defaults to devnet. Override with the mainnet endpoint for production.
    #[arg(
        long,
        env = "AGGREGATOR_PROTOCOL_FEE_RPC_URL",
        default_value = "https://api.devnet.solana.com"
    )]
    protocol_fee_rpc_url: String,

    // ── Identity verification ─────────────────────────────────────────────

    /// Disable the 8004 identity gate.
    /// When set, GET /identity/verify/:id always returns verified=true.
    /// Use only in development / closed-network deployments.
    #[arg(long, env = "ZX01_REGISTRY_8004_DISABLED", default_value_t = false)]
    registry_8004_disabled: bool,

    /// Comma-separated hex agent IDs that bypass identity checks.
    /// Useful for genesis/genesis-relay nodes and internal tooling.
    #[arg(long, env = "AGGREGATOR_EXEMPT_AGENTS", value_delimiter = ',')]
    exempt_agents: Vec<String>,

    // ── Sponsored token launch ────────────────────────────────────────────

    /// Base58-encoded Ed25519 private key (64 bytes: seed || pubkey) for the
    /// sponsor wallet that pays Bags.fm launch fees on behalf of new agents.
    /// The same format as Phantom / Solana CLI keypair export.
    /// When absent, POST /sponsor/launch returns 503.
    #[arg(long, env = "SPONSOR_SIGNING_KEY")]
    sponsor_signing_key: Option<String>,

    /// Bags.fm API key used for sponsored token launches.
    /// Required when SPONSOR_SIGNING_KEY is set.
    #[arg(long, env = "BAGS_API_KEY")]
    bags_api_key: Option<String>,

    /// Solana RPC URL used for sponsored launch transactions.
    #[arg(
        long,
        env = "SPONSOR_RPC_URL",
        default_value = "https://api.mainnet-beta.solana.com"
    )]
    sponsor_rpc_url: String,

    /// Public URL of the default agent avatar image (PNG/JPG, ≤1 MB).
    /// Fetched once per launch when the mobile client sends no custom image.
    /// Host it anywhere accessible from the aggregator server.
    /// Example: https://0x01.world/default-agent.png
    #[arg(long, env = "SPONSOR_DEFAULT_IMAGE_URL")]
    sponsor_default_image_url: Option<String>,

    /// Bags.fm partner wallet (base58 Solana pubkey) to receive partner fee share.
    /// Must be set together with BAGS_PARTNER_CONFIG.
    #[arg(long, env = "BAGS_PARTNER_WALLET")]
    bags_partner_wallet: Option<String>,

    /// Bags.fm partner config account address (base58) returned by partner registration.
    /// Must be set together with BAGS_PARTNER_WALLET.
    #[arg(long, env = "BAGS_PARTNER_CONFIG")]
    bags_partner_config: Option<String>,

    /// Development / local mode.
    /// When set, missing ingest_secret and empty api_keys are warnings rather than
    /// fatal errors. NEVER use this in internet-facing production deployments.
    #[arg(long, env = "AGGREGATOR_DEV", default_value_t = false)]
    dev: bool,

    /// Admin-only API key for /admin/* billing management routes.
    /// When absent, all /admin/* routes return 403 Forbidden.
    /// Set via AGGREGATOR_ADMIN_KEY; keep separate from general api_keys.
    #[arg(long, env = "AGGREGATOR_ADMIN_KEY")]
    admin_api_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_aggregator=info".parse().unwrap()),
        )
        .init();

    let config = Config::parse();

    if config.ingest_secret.is_none() {
        if config.dev {
            tracing::warn!(
                "No ingest_secret configured — /ingest/* routes are unauthenticated (dev mode)."
            );
        } else {
            tracing::error!(
                "ingest_secret is required in production. \
                 Set --ingest-secret or AGGREGATOR_INGEST_SECRET. Use --dev to bypass."
            );
            std::process::exit(1);
        }
    }

    if config.api_keys.is_empty() {
        if config.dev {
            tracing::warn!(
                "No API keys configured — all gated routes are publicly accessible (dev mode)."
            );
        } else {
            tracing::error!(
                "api_keys is required in production. Configure at least one API key via \
                 --api-keys or AGGREGATOR_API_KEYS. Use --dev to bypass."
            );
            std::process::exit(1);
        }
    }

    if config.admin_api_key.is_none() {
        tracing::warn!("[WARN] No admin API key configured — /admin/* routes are disabled.");
    }

    let store = match config.db_path.as_ref() {
        Some(path) => ReputationStore::with_db(path)?,
        None => {
            tracing::warn!(
                "No --db-path set. Reputation data is in-memory only and \
                 will be lost on restart. Set AGGREGATOR_DB_PATH in production."
            );
            ReputationStore::new()
        }
    };

    if config.ntfy_server.is_none() {
        tracing::info!(
            "No --ntfy-server set. Wake-push notifications are disabled. \
             Sleep-state tracking still works."
        );
    } else {
        tracing::info!(
            "ntfy wake-push enabled: {}",
            config.ntfy_server.as_deref().unwrap_or("https://ntfy.sh")
        );
    }

    if config.hosting_secret.is_none() {
        tracing::warn!(
            "No --hosting-secret set. POST /hosting/register is unauthenticated. \
             Set AGGREGATOR_HOSTING_SECRET in production."
        );
    }

    let (activity_tx, _) = broadcast::channel::<ActivityEvent>(512);
    #[cfg(feature = "data-bounty")]
    let (campaign_tx, _) = broadcast::channel::<Campaign>(64);

    let http_client = reqwest::Client::new();
    let registry = registry_8004::Registry8004Client::new(
        config.registry_8004_url.as_deref(),
        http_client.clone(),
        config.registry_8004_min_tier,
    );

    tracing::info!(
        "8004 registry client configured: url={} min_tier={}",
        registry.url,
        config.registry_8004_min_tier,
    );

    // ── Celo settlement client ────────────────────────────────────────────
    #[cfg(feature = "celo-settlement")]
    let celo_client = build_celo_client(&config);

    // ── Base settlement client ────────────────────────────────────────────
    #[cfg(feature = "base-settlement")]
    let base_client = build_base_client(&config);

    // ── Sui settlement client ─────────────────────────────────────────────
    #[cfg(feature = "sui-settlement")]
    let sui_client = build_sui_client(&config);

    // Derive MPP fields before partial-moving config fields.
    let protocol_fee_recipient_ata = derive_protocol_fee_ata(&config);
    let protocol_fee_enabled = config.protocol_fee_enabled;
    let protocol_fee_hosted_usdc = (config.protocol_fee_hosted_usdc * 1_000_000.0) as u64;
    let protocol_fee_self_hosted_usdc = (config.protocol_fee_self_hosted_usdc * 1_000_000.0) as u64;
    let protocol_fee_rpc_url = config.protocol_fee_rpc_url.clone();

    // ── Identity verification: build exempt set ──────────────────────────
    let identity_dev_mode = config.registry_8004_disabled;
    if identity_dev_mode {
        tracing::warn!(
            "Identity dev mode enabled (--registry-8004-disabled). \
             GET /identity/verify/* always returns verified=true."
        );
    }
    let mut exempt_set = std::collections::HashSet::<[u8; 32]>::new();
    for hex_str in &config.exempt_agents {
        match hex::decode(hex_str) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(arr) => {
                    exempt_set.insert(arr);
                    tracing::info!("Aggregator exempt agent: {}", hex_str);
                }
                Err(_) => tracing::warn!(
                    "Exempt agent '{}' is not 32 bytes — skipped",
                    hex_str
                ),
            },
            Err(_) => tracing::warn!("Exempt agent '{}' is not valid hex — skipped", hex_str),
        }
    }

    // ── Sponsor signing key ───────────────────────────────────────────────
    let sponsor_signing_key = config.sponsor_signing_key.as_deref().and_then(|s| {
        match bs58::decode(s).into_vec() {
            Ok(bytes) if bytes.len() == 64 => {
                let seed: [u8; 32] = bytes[..32].try_into().ok()?;
                let key = EdSigningKey::from_bytes(&seed);
                let pubkey = bs58::encode(key.verifying_key().to_bytes()).into_string();
                tracing::info!("Sponsor wallet: {pubkey}");
                Some(std::sync::Arc::new(key))
            }
            Ok(bytes) if bytes.len() == 32 => {
                let seed: [u8; 32] = bytes.try_into().ok()?;
                let key = EdSigningKey::from_bytes(&seed);
                let pubkey = bs58::encode(key.verifying_key().to_bytes()).into_string();
                tracing::info!("Sponsor wallet: {pubkey}");
                Some(std::sync::Arc::new(key))
            }
            _ => {
                tracing::warn!("SPONSOR_SIGNING_KEY is set but not a valid base58 keypair — sponsored launches disabled");
                None
            }
        }
    });
    if sponsor_signing_key.is_none() && config.bags_api_key.is_some() {
        tracing::warn!("BAGS_API_KEY is set but SPONSOR_SIGNING_KEY is missing — sponsored launches disabled");
    }

    let state = AppState {
        store,
        ingest_secret: config.ingest_secret,
        hosting_secret: config.hosting_secret,
        blob_dir: config.blob_dir,
        reel_dir: config.reel_dir,
        ntfy_server: config.ntfy_server,
        http_client,
        activity_tx,
        registry,
        api_keys: config.api_keys,
        #[cfg(feature = "celo-settlement")]
        celo_client,
        #[cfg(feature = "base-settlement")]
        base_client,
        #[cfg(feature = "sui-settlement")]
        sui_client,
        #[cfg(feature = "data-bounty")]
        operator_secret: config.operator_secret,
        #[cfg(feature = "data-bounty")]
        campaign_tx,
        #[cfg(feature = "data-bounty")]
        campaign_rate_limit: std::sync::Arc::new(std::sync::Mutex::new(
            (0u32, std::time::Instant::now()),
        )),
        protocol_fee_enabled,
        protocol_fee_hosted_usdc,
        protocol_fee_self_hosted_usdc,
        protocol_fee_recipient_ata,
        protocol_fee_challenges: std::sync::Arc::new(tokio::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        protocol_fee_rpc_url,
        identity_dev_mode,
        exempt_agents: std::sync::Arc::new(exempt_set),
        identity_cache: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        skr_league_cache: std::sync::Arc::new(std::sync::Mutex::new(None)),
        bags_claims: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        sponsor_signing_key,
        bags_api_key: config.bags_api_key,
        sponsor_rpc_url: config.sponsor_rpc_url,
        sponsor_default_image_url: config.sponsor_default_image_url,
        bags_partner_wallet: config.bags_partner_wallet,
        bags_partner_config: config.bags_partner_config,
        sponsor_launches: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        admin_api_key: config.admin_api_key,
    };

    // Capital Flow indexer (GAP-02) moved to settlement/solana.

    // ── Public routes (no API key required) ──────────────────────────────
    let public_routes = Router::new()
        .route("/health", get(api::health))
        .route("/version", get(api::get_version))
        // Internal push endpoints — use their own secrets
        .route("/ingest/envelope", post(api::ingest_envelope))
        .route("/hosting/register", post(api::post_hosting_register))
        // FCM registration & push-receive (agent-authenticated via Ed25519)
        .route("/fcm/register", post(api::fcm_register))
        .route("/fcm/sleep", post(api::fcm_sleep))
        .route(
            "/agents/{agent_id}/pending",
            get(api::get_pending).post(api::post_pending),
        )
        // Agent-authenticated ownership endpoints
        .route(
            "/agents/{agent_id}/propose-owner",
            post(api::post_propose_owner),
        )
        .route(
            "/agents/{agent_id}/claim-owner",
            post(api::post_claim_owner),
        )
        // Agent token registration (node calls after bags/launch)
        .route(
            "/agents/{agent_id}/token",
            post(api::post_agent_token),
        )
        // Public ownership lookup — mobile app needs this without an API key
        .route("/agents/{agent_id}/owner", get(api::get_agent_owner))
        .route("/agents/by-owner/{wallet}", get(api::get_agents_by_owner))
        // High-level public stats for the landing page
        .route("/stats/network", get(api::get_network_stats))
        .route("/league/current", get(api::get_skr_league))
        .route("/league/bags-claim", post(api::post_bags_claim))
        .route("/agents", get(api::get_agents))
        // Sponsored token launch — no auth, rate-limited per agent pubkey
        .route("/sponsor/launch", post(api::sponsor_launch))
        // Sponsored fee-share config — called by local nodes to pay on-chain creation fees
        .route("/sponsor/fee-share-config", post(api::sponsor_fee_share_config))
        // Mobile app read endpoints — must be public (mobile has no API key)
        .route("/agents/{agent_id}/profile", get(api::get_agent_profile))
        .route("/activity", get(api::get_activity))
        .route("/ws/activity", get(api::ws_activity))
        .route("/broadcasts", get(api::get_broadcasts))
        .route("/bounties", get(api::get_bounties))
        .route("/hosting/nodes", get(api::get_hosting_nodes))
        // Agent search — public discovery feature, no API key required
        .route("/agents/search", get(api::search_agents))
        .route("/agents/search/name", get(api::search_agents_by_name))
        .route("/blobs/{cid}", get(api::get_blob))
        // MPP protocol fee endpoints — public (agents call these directly)
        .route(
            "/mpp/protocol-fee/challenge",
            get(api::mpp_protocol_fee_challenge),
        )
        .route(
            "/mpp/protocol-fee/verify",
            post(api::mpp_protocol_fee_verify),
        )
        // Identity verification endpoint — called by nodes to check BEACON senders.
        // Public: nodes have no API key; ingest_secret only applies to /ingest/*.
        .route(
            "/identity/verify/{agent_id_hex}",
            get(api::verify_identity),
        );
    // DataBounty campaigns — only compiled when the data-bounty feature is enabled
    #[cfg(feature = "data-bounty")]
    let public_routes = public_routes
        .route("/campaigns", get(api::get_campaigns).post(api::post_campaign))
        .route("/campaigns/{id}", get(api::get_campaign_by_id))
        .route("/ws/campaigns", get(api::ws_campaigns));

    // ── Billing routes ────────────────────────────────────────────────
    // POST endpoints: Ed25519-signed by account holder.
    // GET  endpoints: require API key or X-Agent-Id + X-Signature self-query.
    // GET /billing/estimate-settlement: public (no auth).
    let public_routes = public_routes
        .route("/billing/deposit", post(api::post_billing_deposit))
        .route(
            "/billing/balance/{account_id}",
            get(api::get_billing_balance),
        )
        .route("/billing/withdraw", post(api::post_billing_withdraw))
        .route("/billing/set-payout", post(api::post_billing_set_payout))
        .route(
            "/billing/transactions/{account_id}",
            get(api::get_billing_transactions),
        )
        .route(
            "/billing/estimate-settlement",
            get(api::get_billing_estimate),
        );

    // ── API-key gated routes (read endpoints for explorer / dev team / paid clients) ──
    let gated_routes = Router::new()
        .route("/reputation/{agent_id}", get(api::get_reputation))
        .route("/leaderboard", get(api::get_leaderboard))
        .route("/leaderboard/anomaly", get(api::get_anomaly_leaderboard))
        .route("/interactions", get(api::get_interactions))
        .route("/stats/timeseries", get(api::get_timeseries))
        .route("/entropy/{agent_id}", get(api::get_entropy))
        .route("/entropy/{agent_id}/history", get(api::get_entropy_history))
        .route("/entropy/{agent_id}/rolling", get(api::get_rolling_entropy))
        .route(
            "/leaderboard/verifier-concentration",
            get(api::get_verifier_concentration),
        )
        .route(
            "/leaderboard/ownership-clusters",
            get(api::get_ownership_clusters),
        )
        .route("/params/calibrated", get(api::get_calibrated_params))
        .route("/system/sri", get(api::get_sri_status))
        .route("/stake/required/{agent_id}", get(api::get_required_stake))
        .route("/graph/flow", get(api::get_flow_graph))
        .route("/graph/clusters", get(api::get_flow_clusters))
        .route("/graph/agent/{agent_id}", get(api::get_agent_flow))
        .route(
            "/epochs/{agent_id}/{epoch}/envelopes",
            get(api::get_epoch_envelopes),
        )
        .route("/interactions/by/{agent_id}", get(api::get_interactions_by))
        .route("/disputes/{agent_id}", get(api::get_disputes))
        .route("/registry", get(api::get_registry))
        .route("/agents/{agent_id}/sleeping", get(api::get_sleep_status))
        .route(
            "/blobs",
            post(api::post_blob).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::api_key_middleware,
        ));

    // ── Admin-key gated routes (/admin/*) — require separate admin_api_key ──
    let admin_routes = Router::new()
        .route("/admin/billing/accounts", get(api::get_admin_billing_accounts))
        .route("/admin/billing/settlements", get(api::get_admin_settlements))
        .route("/admin/billing/revenue", get(api::get_admin_revenue))
        .route("/admin/billing/settlements/{id}/retry", post(api::post_admin_retry_settlement))
        .route("/admin/billing/accounts/{id}/skip-settlement", post(api::post_admin_set_skip_settlement))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::admin_key_middleware,
        ));

    // ── Settlement worker (processes payouts from the queue) ─────────────
    // Dispatches each pending settlement to the correct adapter:
    //   • dest_chain 42220 / 44787 → Celo ZeroxEscrow.approvePayment
    //   • dest_chain 8453  / 84532 → Base ZeroxEscrow.approvePayment
    //   • other CCTP domains       → Circle CCTP burn (TODO: wire CctpClient)
    {
        let worker_store = state.store.clone();
        #[cfg(feature = "celo-settlement")]
        let worker_celo = state.celo_client.clone();
        #[cfg(feature = "base-settlement")]
        let worker_base = state.base_client.clone();
        #[cfg(feature = "sui-settlement")]
        let worker_sui = state.sui_client.clone();
        tokio::spawn(async move {
            tracing::info!("Settlement worker started (polling every 30s)");
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let pending = worker_store.pending_settlements();
                for entry in pending {
                    if !worker_store.claim_settlement(entry.id) {
                        continue;
                    }
                    tracing::info!(
                        "Processing settlement #{}: {} → {} ({} USDC minor, chain={:?})",
                        entry.id, entry.payer_account, entry.payee_account,
                        entry.amount_usdc, entry.dest_chain,
                    );

                    // ── Celo direct settlement ──────────────────────────
                    #[cfg(feature = "celo-settlement")]
                    if billing::is_celo_domain(entry.dest_chain.unwrap_or(0)) {
                        process_celo_settlement(
                            entry.id,
                            &entry.conversation_id,
                            entry.dest_address.as_deref(),
                            &worker_store,
                            worker_celo.as_deref(),
                        )
                        .await;
                        continue;
                    }

                    // ── Base direct settlement ──────────────────────────
                    #[cfg(feature = "base-settlement")]
                    if billing::is_base_domain(entry.dest_chain.unwrap_or(0)) {
                        process_base_settlement(
                            entry.id,
                            &entry.conversation_id,
                            entry.dest_address.as_deref(),
                            &worker_store,
                            worker_base.as_deref(),
                        )
                        .await;
                        continue;
                    }

                    // ── Sui Move settlement ─────────────────────────────
                    #[cfg(feature = "sui-settlement")]
                    if billing::is_sui_domain(entry.dest_chain.unwrap_or(0)) {
                        process_sui_settlement(
                            entry.id,
                            &entry.conversation_id,
                            entry.dest_address.as_deref(),
                            &worker_store,
                            worker_sui.as_deref(),
                        )
                        .await;
                        continue;
                    }

                    // ── Circle CCTP settlement (other EVM / Solana) ─────
                    if entry.dest_chain.is_some() && entry.dest_address.is_some() {
                        // TODO: Execute CCTP burn via CctpClient when wired in.
                        tracing::warn!(
                            "Settlement #{}: CCTP not wired — marking completed. \
                             Wire CctpClient to execute actual bridge.",
                            entry.id,
                        );
                        worker_store.update_settlement_status(
                            entry.id, "processing", "completed", None,
                        );
                    } else {
                        tracing::warn!(
                            "Settlement #{}: no dest_chain/dest_address — marking failed",
                            entry.id,
                        );
                        worker_store.update_settlement_status(
                            entry.id, "processing", "failed", None,
                        );
                    }
                }
            }
        });
    }

    // ── Social attestation verifier ─────────────────────────────────────────
    // Polls every 5 minutes for unverified human-delegated capability proofs.
    // Fetches the attestation_url and checks the agent's token_address or agent_id
    // appears in the page content. Marks verified=1 if found.
    {
        let verifier_store = state.store.clone();
        let verifier_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("zerox1-aggregator/attestation-verifier")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build attestation verifier HTTP client");
        tokio::spawn(async move {
            tracing::info!("Attestation verifier started (polling every 5m)");
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let rows = verifier_store.pending_attestations();
                for (agent_id, capability, attestation_url, token_address) in rows {
                    if !is_safe_attestation_url(&attestation_url) {
                        tracing::warn!(
                            "Attestation URL rejected (SSRF guard): agent={} url={}",
                            &agent_id[..agent_id.len().min(8)],
                            &attestation_url[..attestation_url.len().min(64)],
                        );
                        continue;
                    }
                    match verifier_client.get(&attestation_url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            match resp.text().await {
                                Ok(body) => {
                                    // Check that the page content references either the
                                    // agent's token address or the agent_id (hex).
                                    let found = (!token_address.is_empty() && body.contains(&token_address))
                                        || body.contains(&agent_id);
                                    if found {
                                        verifier_store.mark_attestation_verified(&agent_id, &capability);
                                        tracing::info!(
                                            "Attestation verified: agent={} capability={}",
                                            &agent_id[..agent_id.len().min(8)], capability
                                        );
                                    } else {
                                        tracing::debug!(
                                            "Attestation not yet confirmed: agent={} capability={}",
                                            &agent_id[..agent_id.len().min(8)], capability
                                        );
                                    }
                                }
                                Err(e) => tracing::warn!("Attestation body read failed: {e}"),
                            }
                        }
                        Ok(resp) => tracing::warn!(
                            "Attestation URL returned {}: {}",
                            resp.status(),
                            &attestation_url[..attestation_url.len().min(64)],
                        ),
                        Err(e) => tracing::warn!(
                            "Attestation fetch failed for {}: {e}",
                            &attestation_url[..attestation_url.len().min(64)],
                        ),
                    }
                }
            }
        });
    }

    let app = public_routes
        .merge(gated_routes)
        .merge(admin_routes)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        )
        .with_state(state);

    tracing::info!("zerox1-aggregator listening on {}", config.listen);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ============================================================================
// SSRF guard for social attestation verifier
// ============================================================================

/// Returns `true` only if the URL is safe to fetch for social attestation.
///
/// Rules (H-2 fix):
/// - Scheme must be `https` (rejects `http`, `file`, `ftp`, etc.)
/// - Host must not be a raw IP in loopback (127.x.x.x, ::1), link-local
///   (169.254.x.x), or RFC1918 ranges (10.x, 172.16-31.x, 192.168.x).
/// - We do not perform DNS resolution; we only reject hosts that are already
///   expressed as blocked IP literals in the URL.
fn is_safe_attestation_url(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    // Scheme must be https.
    if parsed.scheme() != "https" {
        return false;
    }

    // Extract raw host string — reject if absent.
    let host_str = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };

    // If the host is a numeric IPv4 address, check blocked ranges.
    if let Ok(addr) = host_str.parse::<std::net::Ipv4Addr>() {
        let octets = addr.octets();
        // Loopback: 127.0.0.0/8
        if octets[0] == 127 {
            return false;
        }
        // Link-local: 169.254.0.0/16
        if octets[0] == 169 && octets[1] == 254 {
            return false;
        }
        // RFC1918: 10.0.0.0/8
        if octets[0] == 10 {
            return false;
        }
        // RFC1918: 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return false;
        }
        // RFC1918: 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return false;
        }
        return true;
    }

    // Strip surrounding brackets for IPv6 literals (e.g. "[::1]").
    let ipv6_candidate = host_str
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_str);

    if let Ok(addr) = ipv6_candidate.parse::<std::net::Ipv6Addr>() {
        // Block loopback (::1).
        if addr.is_loopback() {
            return false;
        }
        let segments = addr.segments();
        // Link-local: fe80::/10
        if (segments[0] & 0xffc0) == 0xfe80 {
            return false;
        }
        // Unique-local: fc00::/7 (covers fc00:: and fd00::)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return false;
        }
        // IPv4-mapped: ::ffff:0:0/96
        if segments[0] == 0 && segments[1] == 0 && segments[2] == 0
            && segments[3] == 0 && segments[4] == 0 && segments[5] == 0xffff
        {
            return false;
        }
        return true;
    }

    // Domain names are allowed — DNS resolution is not performed here.
    true
}

// ============================================================================
// Celo settlement helpers
// ============================================================================

/// Derive the protocol-fee recipient USDC ATA from the operator's wallet pubkey.
///
/// Uses the SPL Associated Token Account program derivation.
/// Returns `None` if `--protocol-fee-recipient` is not set or is invalid.
fn derive_protocol_fee_ata(config: &Config) -> Option<String> {
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    let recipient_str = config.protocol_fee_recipient.as_deref()?;
    let wallet: Pubkey = match Pubkey::from_str(recipient_str) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                "MPP: invalid --protocol-fee-recipient '{}': {e}",
                recipient_str
            );
            return None;
        }
    };

    let usdc_mint_str = if config.protocol_fee_rpc_url.contains("devnet") {
        "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    } else {
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    };
    let mint: Pubkey = usdc_mint_str.parse().expect("valid USDC mint");
    let spl_token: Pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        .parse()
        .expect("valid SPL token program");
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bJo"
        .parse()
        .expect("valid ATA program");
    let (ata, _) = Pubkey::find_program_address(
        &[&wallet.to_bytes(), &spl_token.to_bytes(), &mint.to_bytes()],
        &ata_program,
    );
    tracing::info!(
        "MPP protocol fee: recipient_ata={} daily_hosted={:.2} USDC",
        ata,
        config.protocol_fee_hosted_usdc,
    );
    Some(ata.to_string())
}

/// Build a `CeloClient` from aggregator config, if all required fields are set.
/// Returns `None` with a warn log if any required field is missing.
#[cfg(feature = "celo-settlement")]
fn build_celo_client(
    config: &Config,
) -> Option<std::sync::Arc<zerox1_settlement_celo::CeloClient>> {
    use zerox1_settlement_celo::CeloClient;

    let rpc_url = match config.celo_rpc_url.as_deref() {
        Some(u) => u,
        None => return None, // Celo not configured — silently skip
    };

    // All four contract addresses are required together.
    let registry   = config.celo_registry.as_deref().unwrap_or("");
    let escrow     = config.celo_escrow.as_deref().unwrap_or("");
    let lease      = config.celo_lease.as_deref().unwrap_or("");
    let stake_lock = config.celo_stake_lock.as_deref().unwrap_or("");

    if registry.is_empty() || escrow.is_empty() || lease.is_empty() || stake_lock.is_empty() {
        tracing::warn!(
            "Celo settlement: CELO_RPC_URL is set but contract addresses are incomplete. \
             Set CELO_REGISTRY, CELO_ESCROW, CELO_LEASE, CELO_STAKE_LOCK to enable Celo settlement."
        );
        return None;
    }

    match CeloClient::from_strings(
        rpc_url,
        config.celo_private_key.as_deref(),
        registry,
        escrow,
        lease,
        stake_lock,
    ) {
        Ok(client) => {
            if let Some(addr) = client.signer_address() {
                tracing::info!("Celo settlement enabled — notary EOA: {}", addr);
            } else {
                tracing::warn!(
                    "Celo settlement: no private key configured — approvePayment calls will fail. \
                     Set CELO_PRIVATE_KEY to enable automatic VERDICT settlement on Celo."
                );
            }
            Some(std::sync::Arc::new(client))
        }
        Err(e) => {
            tracing::error!("Celo settlement: failed to build client: {}", e);
            None
        }
    }
}

// ============================================================================
// Base settlement helpers
// ============================================================================

/// Build a `BaseClient` from aggregator config, if all required fields are set.
#[cfg(feature = "base-settlement")]
fn build_base_client(
    config: &Config,
) -> Option<std::sync::Arc<zerox1_settlement_base::BaseClient>> {
    use zerox1_settlement_base::BaseClient;

    let rpc_url = match config.base_rpc_url.as_deref() {
        Some(u) => u,
        None => return None,
    };

    let registry   = config.base_registry.as_deref().unwrap_or("");
    let escrow     = config.base_escrow.as_deref().unwrap_or("");
    let lease      = config.base_lease.as_deref().unwrap_or("");
    let stake_lock = config.base_stake_lock.as_deref().unwrap_or("");

    if registry.is_empty() || escrow.is_empty() || lease.is_empty() || stake_lock.is_empty() {
        tracing::warn!(
            "Base settlement: BASE_RPC_URL is set but contract addresses are incomplete. \
             Set BASE_REGISTRY, BASE_ESCROW, BASE_LEASE, BASE_STAKE_LOCK to enable Base settlement."
        );
        return None;
    }

    match BaseClient::from_strings(
        rpc_url,
        config.base_private_key.as_deref(),
        registry,
        escrow,
        lease,
        stake_lock,
    ) {
        Ok(client) => {
            if let Some(addr) = client.signer_address() {
                tracing::info!("Base settlement enabled — notary EOA: {}", addr);
            } else {
                tracing::warn!(
                    "Base settlement: no private key configured — approvePayment calls will fail. \
                     Set BASE_PRIVATE_KEY to enable automatic VERDICT settlement on Base."
                );
            }
            Some(std::sync::Arc::new(client))
        }
        Err(e) => {
            tracing::error!("Base settlement: failed to build client: {}", e);
            None
        }
    }
}

/// Execute a Base escrow settlement for a queued VERDICT.
///
/// The `dest_address` field in the settlement queue holds the bytes32 escrow ID
/// (hex, 0x-prefixed) that the aggregator's notary key will approve.
///
/// Settlement queue convention for Base:
///   dest_chain   = 8453 (mainnet) or 84532 (testnet)
///   dest_address = 0x<64-hex-chars>  (the bytes32 escrow ID from ZeroxEscrow)
#[cfg(feature = "base-settlement")]
async fn process_base_settlement(
    id: i64,
    conversation_id: &str,
    dest_address: Option<&str>,
    store: &store::ReputationStore,
    client: Option<&zerox1_settlement_base::BaseClient>,
) {
    use zerox1_settlement_base::B256;
    use std::str::FromStr;

    let Some(client) = client else {
        tracing::warn!(
            "Settlement #{}: Base client not configured — marking failed. \
             Set BASE_RPC_URL, BASE_ESCROW, BASE_PRIVATE_KEY on the aggregator.",
            id,
        );
        store.update_settlement_status(id, "processing", "failed", None);
        return;
    };

    let Some(escrow_id_hex) = dest_address else {
        tracing::warn!(
            "Settlement #{} (conversation {}): no escrow_id in dest_address — marking failed",
            id, conversation_id,
        );
        store.update_settlement_status(id, "processing", "failed", None);
        return;
    };

    let escrow_id = match B256::from_str(escrow_id_hex) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "Settlement #{}: invalid escrow_id '{}': {} — marking failed",
                id, escrow_id_hex, e,
            );
            store.update_settlement_status(id, "processing", "failed", None);
            return;
        }
    };

    match client.approve_payment(escrow_id).await {
        Ok(tx_hash) => {
            let hash_hex = format!("{:#x}", tx_hash);
            tracing::info!(
                "Settlement #{} approved on Base: tx={} escrow={}",
                id, hash_hex, escrow_id_hex,
            );
            store.update_settlement_status(id, "processing", "completed", Some(&hash_hex));
        }
        Err(e) => {
            tracing::error!(
                "Settlement #{}: ZeroxEscrow.approvePayment failed on Base: {} — marking failed",
                id, e,
            );
            store.update_settlement_status(id, "processing", "failed", None);
        }
    }
}

// ============================================================================
// Sui settlement helpers
// ============================================================================

/// Build a `SuiClient` from aggregator config, if all required fields are set.
#[cfg(feature = "sui-settlement")]
fn build_sui_client(
    config: &Config,
) -> Option<std::sync::Arc<zerox1_settlement_sui::SuiClient>> {
    use zerox1_settlement_sui::{SuiClient, SUI_MAINNET_USDC_TYPE};

    let rpc_url = match config.sui_rpc_url.as_deref() {
        Some(u) => u,
        None => return None, // Sui not configured — silently skip
    };

    let package_id = match config.sui_package_id.as_deref() {
        Some(p) => p,
        None => {
            tracing::warn!(
                "Sui settlement: SUI_RPC_URL is set but SUI_PACKAGE_ID is missing — \
                 set SUI_PACKAGE_ID to enable Sui settlement."
            );
            return None;
        }
    };

    let coin_type = config
        .sui_coin_type
        .as_deref()
        .unwrap_or(SUI_MAINNET_USDC_TYPE);

    match SuiClient::from_strings(
        rpc_url,
        config.sui_private_key.as_deref(),
        package_id,
        &config.sui_escrow_module,
        coin_type,
    ) {
        Ok(client) => {
            if let Some(addr) = client.signer_address() {
                tracing::info!("Sui settlement enabled — notary: {}", addr);
            } else {
                tracing::warn!(
                    "Sui settlement: no private key configured — approve_payment calls will fail. \
                     Set SUI_PRIVATE_KEY to enable automatic VERDICT settlement on Sui."
                );
            }
            Some(std::sync::Arc::new(client))
        }
        Err(e) => {
            tracing::error!("Sui settlement: failed to build client: {}", e);
            None
        }
    }
}

/// Execute a Sui escrow settlement for a queued VERDICT.
///
/// The `dest_address` field in the settlement queue holds the Sui object ID
/// of the ZeroxEscrow shared object (0x-prefixed 64 hex chars = 66 chars total).
///
/// Settlement queue convention for Sui:
///   dest_chain   = 8 (mainnet) or 9 (testnet)
///   dest_address = 0x<64-hex-chars>  (the ZeroxEscrow shared object ID)
#[cfg(feature = "sui-settlement")]
async fn process_sui_settlement(
    id: i64,
    conversation_id: &str,
    dest_address: Option<&str>,
    store: &store::ReputationStore,
    client: Option<&zerox1_settlement_sui::SuiClient>,
) {
    let Some(client) = client else {
        tracing::warn!(
            "Settlement #{}: Sui client not configured — marking failed. \
             Set SUI_RPC_URL, SUI_PACKAGE_ID, SUI_PRIVATE_KEY on the aggregator.",
            id,
        );
        store.update_settlement_status(id, "processing", "failed", None);
        return;
    };

    let Some(escrow_id_hex) = dest_address else {
        tracing::warn!(
            "Settlement #{} (conversation {}): no escrow object ID in dest_address — marking failed",
            id, conversation_id,
        );
        store.update_settlement_status(id, "processing", "failed", None);
        return;
    };

    // Parse 0x<64 hex> → [u8; 32]
    let hex_str = escrow_id_hex.strip_prefix("0x").unwrap_or(escrow_id_hex);
    let escrow_bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "Settlement #{}: invalid escrow object ID '{}': {} — marking failed",
                id, escrow_id_hex, e,
            );
            store.update_settlement_status(id, "processing", "failed", None);
            return;
        }
    };
    let escrow_id: [u8; 32] = match escrow_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            tracing::error!(
                "Settlement #{}: escrow object ID '{}' is not 32 bytes — marking failed",
                id, escrow_id_hex,
            );
            store.update_settlement_status(id, "processing", "failed", None);
            return;
        }
    };

    match client.approve_payment(escrow_id).await {
        Ok(digest) => {
            let digest_str = digest.to_string();
            tracing::info!(
                "Settlement #{} approved on Sui: tx={} escrow={}",
                id, digest_str, escrow_id_hex,
            );
            store.update_settlement_status(id, "processing", "completed", Some(&digest_str));
        }
        Err(e) => {
            tracing::error!(
                "Settlement #{}: ZeroxEscrow.approve_payment failed on Sui: {} — marking failed",
                id, e,
            );
            store.update_settlement_status(id, "processing", "failed", None);
        }
    }
}

/// Execute a Celo escrow settlement for a queued VERDICT.
///
/// The `dest_address` field in the settlement queue holds the bytes32 escrow ID
/// (hex, 0x-prefixed) that the aggregator's notary key will approve.
///
/// Settlement queue convention for Celo:
///   dest_chain   = 42220 (mainnet) or 44787 (testnet)
///   dest_address = 0x<64-hex-chars>  (the bytes32 escrow ID from ZeroxEscrow)
#[cfg(feature = "celo-settlement")]
async fn process_celo_settlement(
    id: i64,
    conversation_id: &str,
    dest_address: Option<&str>,
    store: &store::ReputationStore,
    client: Option<&zerox1_settlement_celo::CeloClient>,
) {
    use zerox1_settlement_celo::B256;
    use std::str::FromStr;

    let Some(client) = client else {
        tracing::warn!(
            "Settlement #{}: Celo client not configured — marking failed. \
             Set CELO_RPC_URL, CELO_ESCROW, CELO_PRIVATE_KEY on the aggregator.",
            id,
        );
        store.update_settlement_status(id, "processing", "failed", None);
        return;
    };

    let Some(escrow_id_hex) = dest_address else {
        tracing::warn!(
            "Settlement #{} (conversation {}): no escrow_id in dest_address — marking failed",
            id, conversation_id,
        );
        store.update_settlement_status(id, "processing", "failed", None);
        return;
    };

    let escrow_id = match B256::from_str(escrow_id_hex) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                "Settlement #{}: invalid escrow_id '{}': {} — marking failed",
                id, escrow_id_hex, e,
            );
            store.update_settlement_status(id, "processing", "failed", None);
            return;
        }
    };

    match client.approve_payment(escrow_id).await {
        Ok(tx_hash) => {
            let hash_hex = format!("{:#x}", tx_hash);
            tracing::info!(
                "Settlement #{} approved on Celo: tx={} escrow={}",
                id, hash_hex, escrow_id_hex,
            );
            store.update_settlement_status(id, "processing", "completed", Some(&hash_hex));
        }
        Err(e) => {
            tracing::error!(
                "Settlement #{}: ZeroxEscrow.approvePayment failed: {} — marking failed",
                id, e,
            );
            store.update_settlement_status(id, "processing", "failed", None);
        }
    }
}
