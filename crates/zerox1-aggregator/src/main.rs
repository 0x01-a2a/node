mod api;
mod billing;
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
        #[cfg(feature = "data-bounty")]
        operator_secret: config.operator_secret,
        #[cfg(feature = "data-bounty")]
        campaign_tx,
        #[cfg(feature = "data-bounty")]
        campaign_rate_limit: std::sync::Arc::new(std::sync::Mutex::new(
            (0u32, std::time::Instant::now()),
        )),
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
        .route("/agents", get(api::get_agents))
        // Mobile app read endpoints — must be public (mobile has no API key)
        .route("/agents/{agent_id}/profile", get(api::get_agent_profile))
        .route("/activity", get(api::get_activity))
        .route("/ws/activity", get(api::ws_activity))
        .route("/hosting/nodes", get(api::get_hosting_nodes))
        .route("/blobs/{cid}", get(api::get_blob));
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

    // ── Settlement worker (processes CCTP payouts from the queue) ────────
    {
        let worker_store = state.store.clone();
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
                        "Processing settlement #{}: {} → {} ({} USDC minor)",
                        entry.id, entry.payer_account, entry.payee_account, entry.amount_usdc,
                    );
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
                            "Settlement #{}: no dest — marking failed", entry.id,
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
