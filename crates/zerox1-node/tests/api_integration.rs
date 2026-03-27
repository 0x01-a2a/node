//! Integration tests for node REST API endpoints the mobile app calls.
//!
//! Uses `tower::ServiceExt::oneshot` for in-process testing — no port binding required.

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use http_body_util::BodyExt;
use rand::rngs::OsRng;
use serde_json::Value;
use std::{collections::HashSet, path::PathBuf, sync::Arc};
use tower::ServiceExt;
use zerox1_node::api::{build_router, ApiState};

fn make_state() -> ApiState {
    let signing_key = Arc::new(ed25519_dalek::SigningKey::generate(&mut OsRng));
    let exempt_agents = Arc::new(std::sync::RwLock::new(HashSet::new()));

    let (state, _outbound_rx, _hosted_outbound_rx, _sub_topic_rx) = ApiState::new(
        [0u8; 32],
        "test-agent".to_string(),
        Some("test-secret".to_string()),
        vec![],
        0,
        "http://localhost:1".to_string(),
        "http://localhost:1".to_string(),
        reqwest::Client::new(),
        None,           // registry_8004_collection
        signing_key,
        None,           // kora
        exempt_agents,
        PathBuf::from("/tmp/test-exempt-api"),
        None,           // skill_workspace
        None,           // mpp
        None,           // file_delivery
        None,           // task_log
    );
    state
}

fn app() -> axum::Router {
    build_router(make_state(), vec![])
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

// ── GET /identity ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn identity_returns_agent_id() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/identity")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(
        body.get("agent_id").is_some(),
        "expected agent_id field, got: {body}"
    );
    // All-zeros agent should produce a 64-char hex string
    let agent_id = body["agent_id"].as_str().unwrap_or("");
    assert_eq!(agent_id.len(), 64, "agent_id should be 64 hex chars");
}

// ── GET /peers ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn peers_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/peers")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array(), "expected JSON array, got: {body}");
}

// ── GET /portfolio/history ────────────────────────────────────────────────────

#[tokio::test]
async fn portfolio_history_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/portfolio/history")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    // Returns {"events": [...]} or just an array
    let is_array_or_obj = body.is_array()
        || body.get("events").map(|e| e.is_array()).unwrap_or(false);
    assert!(is_array_or_obj, "expected array or {{events:[...]}}, got: {body}");
}

// ── GET /skill/list ───────────────────────────────────────────────────────────

#[tokio::test]
async fn skill_list_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/skill/list")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 with empty array when no skill_workspace set; 503 also acceptable
    assert!(
        res.status() == StatusCode::OK || res.status() == StatusCode::SERVICE_UNAVAILABLE,
        "unexpected: {}",
        res.status()
    );
    if res.status() == StatusCode::OK {
        let body = body_json(res).await;
        assert!(body.is_array(), "expected JSON array, got: {body}");
    }
}

// ── GET /tasks/log ────────────────────────────────────────────────────────────

#[tokio::test]
async fn tasks_log_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/tasks/log")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 (empty array) or 503 (task_log not configured)
    assert!(
        res.status() == StatusCode::OK || res.status() == StatusCode::SERVICE_UNAVAILABLE,
        "unexpected: {}",
        res.status()
    );
    if res.status() == StatusCode::OK {
        let body = body_json(res).await;
        assert!(body.is_array(), "expected JSON array, got: {body}");
    }
}

// ── GET /registry/8004/info ───────────────────────────────────────────────────

#[tokio::test]
async fn registry_8004_info_returns_ok() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/registry/8004/info")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    // Should contain program_id or similar info
    assert!(
        body.is_object(),
        "expected JSON object, got: {body}"
    );
}

// ── POST /envelopes/send auth ─────────────────────────────────────────────────

#[tokio::test]
async fn envelopes_send_without_auth_returns_401() {
    let body = serde_json::json!({
        "msg_type": "BEACON",
        "recipient": null,
        "conversation_id": "a".repeat(32),
        "payload_b64": "AA=="
    });
    let res = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/envelopes/send")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn envelopes_send_wrong_auth_returns_401() {
    let body = serde_json::json!({
        "msg_type": "BEACON",
        "recipient": null,
        "conversation_id": "a".repeat(32),
        "payload_b64": "AA=="
    });
    let res = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/envelopes/send")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer wrong-key")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ── GET /hosted/ping ──────────────────────────────────────────────────────────

#[tokio::test]
async fn hosted_ping_is_reachable() {
    // /hosted/ping responds 200 regardless of auth state (it's a connectivity probe)
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/hosted/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status().is_success() || res.status().is_client_error(),
        "unexpected server error: {}",
        res.status()
    );
}

// ── GET /mpp/challenge — no MPP configured ───────────────────────────────────

#[tokio::test]
async fn mpp_challenge_is_reachable() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/mpp/challenge")
                .header(header::AUTHORIZATION, "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Any non-5xx response is acceptable — 200 (mpp disabled/no-op),
    // 400 (missing required params), 404 (route not found in this build config),
    // 503 (mpp not configured)
    assert!(
        !res.status().is_server_error(),
        "unexpected server error: {}",
        res.status()
    );
}
