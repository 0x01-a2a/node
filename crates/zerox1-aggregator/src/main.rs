mod api;
mod store;
mod capital_flow;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;

use api::AppState;
use store::ReputationStore;

#[derive(Parser, Debug)]
#[command(name = "zerox1-aggregator", about = "0x01 reputation aggregator service")]
struct Config {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:8081", env = "AGGREGATOR_LISTEN")]
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

    /// Solana RPC URL for Capital Flow Correlation (GAP-02 Sybil deterrence).
    /// Used by the background indexer to fetch funding/sweep graphs.
    #[arg(long, env = "ZX01_SOLANA_RPC")]
    solana_rpc: Option<String>,
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

    let store = match config.db_path {
        Some(ref path) => ReputationStore::with_db(path)?,
        None => {
            tracing::warn!(
                "No --db-path set. Reputation data is in-memory only and \
                 will be lost on restart. Set AGGREGATOR_DB_PATH in production."
            );
            ReputationStore::new()
        }
    };

    let state = AppState {
        store,
        ingest_secret: config.ingest_secret,
    };

    if let Some(rpc_url) = config.solana_rpc {
        tracing::info!("Starting Capital Flow indexer (GAP-02) using RPC: {}", rpc_url);
        let indexer_state = state.clone();
        tokio::spawn(async move {
            capital_flow::run_indexer(rpc_url, indexer_state).await;
        });
    } else {
        tracing::info!("No --solana-rpc provided - Capital Flow analysis (GAP-02) disabled.");
    }

    let app = Router::new()
        .route("/health",                 get(api::health))
        .route("/stats/network",          get(api::get_network_stats))
        .route("/ingest/envelope",        post(api::ingest_envelope))
        .route("/reputation/{agent_id}",  get(api::get_reputation))
        .route("/leaderboard",            get(api::get_leaderboard))
        .route("/agents",                 get(api::get_agents))
        .route("/leaderboard/anomaly",            get(api::get_anomaly_leaderboard))
        .route("/interactions",                   get(api::get_interactions))
        .route("/stats/timeseries",               get(api::get_timeseries))
        .route("/entropy/{agent_id}",             get(api::get_entropy))
        .route("/entropy/{agent_id}/history",     get(api::get_entropy_history))
        .route("/entropy/{agent_id}/rolling",         get(api::get_rolling_entropy))
        .route("/leaderboard/verifier-concentration", get(api::get_verifier_concentration))
        .route("/leaderboard/ownership-clusters",     get(api::get_ownership_clusters))
        .route("/params/calibrated",                  get(api::get_calibrated_params))
        .route("/system/sri",                         get(api::get_sri_status))
        .route("/stake/required/{agent_id}",          get(api::get_required_stake))
        .route("/graph/flow",                         get(api::get_flow_graph))
        .route("/graph/clusters",                     get(api::get_flow_clusters))
        .route("/graph/agent/{agent_id}",             get(api::get_agent_flow))
        .route("/epochs/{agent_id}/{epoch}/envelopes", get(api::get_epoch_envelopes))
        .route("/agents/search",                       get(api::search_agents))
        .route("/agents/search/name",                  get(api::search_agents_by_name))
        .route("/agents/{agent_id}/profile",           get(api::get_agent_profile))
        .route("/interactions/by/{agent_id}",          get(api::get_interactions_by))
        .route("/disputes/{agent_id}",                 get(api::get_disputes))
        .route("/registry",                            get(api::get_registry))
        .with_state(state);

    tracing::info!("zerox1-aggregator listening on {}", config.listen);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
