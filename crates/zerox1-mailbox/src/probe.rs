//! Minimal HTTP probe server — exposes GET /identity and GET /health.
//! Read-only, no auth required.

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone)]
pub struct ProbeState {
    pub agent_id: String,
}

pub async fn serve(port: u16, agent_id: String) {
    let state = Arc::new(ProbeState { agent_id });
    let router = Router::new()
        .route("/identity", get(identity_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.expect("probe bind");
    info!("probe HTTP on {addr}");
    axum::serve(listener, router).await.expect("probe serve");
}

async fn identity_handler(State(s): State<Arc<ProbeState>>) -> impl IntoResponse {
    Json(serde_json::json!({ "agent_id": s.agent_id }))
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}
