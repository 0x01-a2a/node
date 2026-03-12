use crate::{config::Config, handler, node_client::NodeClient};
use sqlx::SqlitePool;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

pub async fn run(client: NodeClient, db: SqlitePool, config: Config) {
    loop {
        info!("connecting to inbox…");
        let err = client
            .listen_inbox(|env| {
                let db = db.clone();
                let client = client.clone();
                let config = config.clone();
                async move {
                    if env.msg_type == "PROPOSE" {
                        if let Err(e) = handler::handle_propose(env, &client, &db, &config).await {
                            warn!("handler error: {e}");
                        }
                    }
                    Ok(())
                }
            })
            .await;

        if let Err(e) = err {
            warn!("inbox WS closed: {e:#}  — reconnecting in 5s");
        }
        sleep(Duration::from_secs(5)).await;
    }
}
