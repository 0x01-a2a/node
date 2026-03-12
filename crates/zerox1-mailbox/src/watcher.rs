use crate::{handler, node_client::{AgentId, NodeClient}, store};
use futures_util::StreamExt;
use sqlx::SqlitePool;
use std::time::Duration;
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{info, warn};
use zerox1_client::ActivityEvent;

pub async fn run(
    aggregator_ws_url: String,
    client: NodeClient,
    db: SqlitePool,
    mailbox_id: AgentId,
) {
    loop {
        if let Err(e) = run_once(&aggregator_ws_url, &client, &db, &mailbox_id).await {
            warn!("aggregator WS closed: {e:#}  — reconnecting in 10s");
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn run_once(
    url: &str,
    client: &NodeClient,
    db: &SqlitePool,
    mailbox_id: &AgentId,
) -> anyhow::Result<()> {
    let (ws, _) = connect_async(url).await?;
    info!("aggregator WS connected");
    let (_, mut rx) = ws.split();
    let mailbox_hex = mailbox_id.to_hex();

    while let Some(msg) = rx.next().await {
        let text = match msg? {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };

        let ev: ActivityEvent = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if ev.event_type != "JOIN" || ev.agent_id == mailbox_hex {
            continue;
        }

        if let Ok(recipient) = AgentId::from_hex(&ev.agent_id) {
            match store::message_count(db, &ev.agent_id).await {
                Ok(0) => {}
                Ok(n) => handler::send_notify(client, mailbox_id, &recipient, n).await,
                Err(e) => warn!("message_count: {e}"),
            }
        }
    }
    Ok(())
}
