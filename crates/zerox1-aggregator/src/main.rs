mod api;
mod store;

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

    let app = Router::new()
        .route("/health",                 get(api::health))
        .route("/ingest/envelope",        post(api::ingest_envelope))
        .route("/reputation/{agent_id}",   get(api::get_reputation))
        .route("/leaderboard",            get(api::get_leaderboard))
        .route("/agents",                 get(api::get_agents))
        .with_state(state);

    tracing::info!("zerox1-aggregator listening on {}", config.listen);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
