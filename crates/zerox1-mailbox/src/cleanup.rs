use crate::store;
use sqlx::SqlitePool;
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

pub async fn run(pool: SqlitePool) {
    let mut interval = time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        match store::delete_expired(&pool).await {
            Ok(n) if n > 0 => info!("gc: expired {n} messages"),
            Ok(_) => {}
            Err(e) => warn!("gc: cleanup failed: {e}"),
        }
    }
}
