mod api;
mod billing;
mod mpp;
mod registry_8004;
mod store;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};
use clap::Parser;
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

    /// Firebase Cloud Messaging server key for sending push notifications to
    /// sleeping phone nodes. Obtain from the Firebase project console under
    /// Project Settings → Cloud Messaging → Server key.
    /// When absent, the FCM push feature is disabled (token registration and
    /// sleep-state tracking still work, but no pushes are sent).
    #[arg(long, env = "FCM_SERVER_KEY")]
    fcm_server_key: Option<String>,

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

    /// Disable the 8004 + SATI identity gate.
    /// When set, GET /identity/verify/:id always returns verified=true.
    /// Use only in development / closed-network deployments.
    #[arg(long, env = "ZX01_REGISTRY_8004_DISABLED", default_value_t = false)]
    registry_8004_disabled: bool,

    /// Comma-separated hex agent IDs that bypass identity checks.
    /// Useful for genesis/genesis-relay nodes and internal tooling.
    #[arg(long, env = "AGGREGATOR_EXEMPT_AGENTS", value_delimiter = ',')]
    exempt_agents: Vec<String>,
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
        tracing::warn!(
            "No --ingest-secret set. POST /ingest/envelope is unauthenticated. \
             Set AGGREGATOR_INGEST_SECRET in production."
        );
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

    if config.fcm_server_key.is_none() {
        tracing::info!(
            "No --fcm-server-key set. FCM push notifications are disabled. \
             Token registration and sleep-state tracking still work."
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

    let state = AppState {
        store,
        ingest_secret: config.ingest_secret,
        hosting_secret: config.hosting_secret,
        blob_dir: config.blob_dir,
        fcm_server_key: config.fcm_server_key,
        http_client,
        activity_tx,
        registry,
        api_keys: config.api_keys,
        #[cfg(feature = "celo-settlement")]
        celo_client,
        #[cfg(feature = "base-settlement")]
        base_client,
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
        // Public ownership lookup — mobile app needs this without an API key
        .route("/agents/{agent_id}/owner", get(api::get_agent_owner))
        .route("/agents/by-owner/{wallet}", get(api::get_agents_by_owner))
        // High-level public stats for the landing page
        .route("/stats/network", get(api::get_network_stats))
        .route("/league/current", get(api::get_skr_league))
        .route("/league/bags-claim", post(api::post_bags_claim))
        .route("/agents", get(api::get_agents))
        // Mobile app read endpoints — must be public (mobile has no API key)
        .route("/agents/{agent_id}/profile", get(api::get_agent_profile))
        .route("/activity", get(api::get_activity))
        .route("/ws/activity", get(api::ws_activity))
        .route("/hosting/nodes", get(api::get_hosting_nodes))
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
        .route("/agents/search", get(api::search_agents))
        .route("/agents/search/name", get(api::search_agents_by_name))
        .route("/interactions/by/{agent_id}", get(api::get_interactions_by))
        .route("/disputes/{agent_id}", get(api::get_disputes))
        .route("/registry", get(api::get_registry))
        .route("/agents/{agent_id}/sleeping", get(api::get_sleep_status))
        .route(
            "/blobs",
            post(api::post_blob).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        // ── Admin billing endpoints ────────────────────────────────────
        .route("/admin/billing/accounts", get(api::get_admin_billing_accounts))
        .route("/admin/billing/settlements", get(api::get_admin_settlements))
        .route("/admin/billing/revenue", get(api::get_admin_revenue))
        .route("/admin/billing/settlements/{id}/retry", post(api::post_admin_retry_settlement))
        .route("/admin/billing/accounts/{id}/skip-settlement", post(api::post_admin_set_skip_settlement))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::api_key_middleware,
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
                    if crate::billing::is_celo_domain(entry.dest_chain.unwrap_or(0)) {
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
                    if crate::billing::is_base_domain(entry.dest_chain.unwrap_or(0)) {
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

    let app = public_routes
        .merge(gated_routes)
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
