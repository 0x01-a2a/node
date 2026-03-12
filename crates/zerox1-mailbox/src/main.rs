mod agent;
mod cleanup;
mod config;
mod handler;
mod node_client;
mod probe;
mod store;
mod watcher;

use anyhow::Result;
use clap::Parser;
use sqlx::sqlite::SqlitePoolOptions;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zerox1_client::NodeClient;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("zerox1_mailbox=info".parse()?)
                .add_directive("tower_http=warn".parse()?),
        )
        .init();

    let config = config::Config::parse();

    tokio::fs::create_dir_all(&config.data_dir).await?;

    let db_path = config.data_dir.join("mailbox.db");
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect(&format!("sqlite:{}?mode=rwc", db_path.display()))
        .await?;

    store::init(&pool).await?;

    let token = if config.node_token.is_empty() { None } else { Some(config.node_token.clone()) };
    let client = NodeClient::new(&config.node_url, token)?;

    // Wait for node to be ready
    let mailbox_id = loop {
        match client.identity().await {
            Ok(id) => break id,
            Err(e) => {
                tracing::warn!("waiting for node ({e}), retry in 3s…");
                sleep(Duration::from_secs(3)).await;
            }
        }
    };

    info!("zerox1-mailbox online  agent={mailbox_id}");

    tokio::spawn(cleanup::run(pool.clone()));

    tokio::spawn(watcher::run(
        config.aggregator_ws_url.clone(),
        client.clone(),
        pool.clone(),
        mailbox_id.clone(),
    ));

    tokio::spawn(probe::serve(config.probe_port, mailbox_id.to_hex()));

    agent::run(client, pool, config).await;
    Ok(())
}
