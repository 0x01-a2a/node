//! Integration tests for all aggregator API endpoints the mobile app calls.
//!
//! Uses `tower::ServiceExt::oneshot` for in-process testing — no port binding required.
//! Tests use a fully in-memory `AppState` (no SQLite file, no external services).

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio::sync::broadcast;
use tower::ServiceExt;
use zerox1_aggregator::api::{build_router, AppState};
use zerox1_aggregator::registry_8004::Registry8004Client;
use zerox1_aggregator::store::ReputationStore;

fn test_state() -> AppState {
    let store = ReputationStore::new();
    let (activity_tx, _) = broadcast::channel(16);
    let http_client = reqwest::Client::new();
    let registry = Registry8004Client::new(None, http_client.clone(), 0);

    AppState {
        store,
        ingest_secret: None,
        hosting_secret: None,
        ntfy_server: None,
        http_client,
        activity_tx,
        blob_dir: None,
        registry,
        api_keys: vec![],
        protocol_fee_enabled: false,
        protocol_fee_hosted_usdc: 0,
        protocol_fee_self_hosted_usdc: 0,
        protocol_fee_recipient_ata: None,
        protocol_fee_challenges: std::sync::Arc::new(tokio::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        protocol_fee_rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
        identity_dev_mode: true,
        exempt_agents: std::sync::Arc::new(std::collections::HashSet::new()),
        identity_cache: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        skr_league_cache: std::sync::Arc::new(std::sync::Mutex::new(None)),
        bags_claims: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        sponsor_signing_key: None,
        bags_api_key: None,
        sponsor_rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
        sponsor_default_image_url: None,
        bags_partner_wallet: None,
        bags_partner_config: None,
        sponsor_launches: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
    }
}

fn app() -> axum::Router {
    build_router(test_state())
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

// ── Health & version ──────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_200() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn version_returns_version_string() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    // Response is {"node": "x.y.z", "sdk": "x.y.z"} or {"version": "x.y.z"}
    let has_version = body.get("version").is_some()
        || body.get("node").is_some()
        || body.get("sdk").is_some();
    assert!(has_version, "expected version-related field, got: {body}");
}

// ── Agents ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn agents_list_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array(), "expected JSON array, got: {body}");
}

#[tokio::test]
async fn agents_list_sort_recent() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/agents?sort=recent&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array());
}

#[tokio::test]
async fn agent_profile_unknown_returns_ok_or_404() {
    // all-zeros agent ID — not registered; endpoint may return 200 (empty) or 404
    let fake_id = "0".repeat(64);
    let res = app()
        .oneshot(
            Request::builder()
                .uri(format!("/agents/{fake_id}/profile"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status() == StatusCode::OK || res.status() == StatusCode::NOT_FOUND,
        "unexpected: {}",
        res.status()
    );
}

#[tokio::test]
async fn agents_by_owner_unknown_wallet_returns_empty_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/agents/by-owner/11111111111111111111111111111111")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);
}

// ── Activity feed ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn activity_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/activity?limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array(), "expected JSON array, got: {body}");
}

// ── Hosting nodes ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn hosting_nodes_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/hosting/nodes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array());
}

// ── Network stats ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn network_stats_has_agent_count() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/stats/network")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(
        body.get("agent_count").is_some(),
        "expected agent_count, got: {body}"
    );
}

// ── SKR League ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn league_current_returns_ok() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/league/current")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // May return 200 (empty league) or 503 (RPC unavailable) — both valid for empty state
    assert!(
        res.status() == StatusCode::OK || res.status() == StatusCode::SERVICE_UNAVAILABLE,
        "unexpected status: {}",
        res.status()
    );
}

// ── Ingest auth ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn ingest_envelope_requires_json_body() {
    // No Content-Type header → should 415 or 400, not 500
    let res = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ingest/envelope")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status().is_client_error(),
        "expected 4xx, got {}",
        res.status()
    );
}

#[tokio::test]
async fn ingest_envelope_no_secret_accepts_valid_body() {
    // state has ingest_secret = None → unauthenticated
    // Invalid envelope data → expect 400/422, not 500
    let body = serde_json::json!({
        "agent_id": "0".repeat(64),
        "epoch": 1,
        "data": {}
    });
    let res = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ingest/envelope")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        res.status().is_client_error() || res.status().is_success(),
        "expected 2xx or 4xx, got {}",
        res.status()
    );
}

// ── Ingest requires secret when set ──────────────────────────────────────────

#[tokio::test]
async fn ingest_envelope_rejects_without_secret_when_required() {
    let mut state = test_state();
    state.ingest_secret = Some("super-secret".to_string());
    let secured_app = build_router(state);

    let body = serde_json::json!({"agent_id": "a".repeat(64), "epoch": 1});
    let res = secured_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ingest/envelope")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    // 401 if auth check runs before body parsing; 422 if body is parsed first
    // (implementation detail). Either way it must NOT be 200.
    assert!(
        res.status() == StatusCode::UNAUTHORIZED || res.status().is_client_error(),
        "expected auth failure, got {}",
        res.status()
    );
}

// ── Gated routes require API key ──────────────────────────────────────────────

#[tokio::test]
async fn gated_reputation_requires_api_key_when_keys_set() {
    let mut state = test_state();
    state.api_keys = vec!["test-key-123".to_string()];
    let gated_app = build_router(state);

    let res = gated_app
        .oneshot(
            Request::builder()
                .uri(&format!("/reputation/{}", "a".repeat(64)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn gated_reputation_accepts_valid_api_key() {
    let mut state = test_state();
    state.api_keys = vec!["test-key-123".to_string()];
    let gated_app = build_router(state);

    let res = gated_app
        .oneshot(
            Request::builder()
                .uri(&format!("/reputation/{}", "a".repeat(64)))
                .header(header::AUTHORIZATION, "Bearer test-key-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 (empty rep) or 404 — both are valid for an unknown agent
    assert!(
        res.status() == StatusCode::OK || res.status() == StatusCode::NOT_FOUND,
        "unexpected: {}",
        res.status()
    );
}

// ── Broadcasts / bounties ─────────────────────────────────────────────────────

#[tokio::test]
async fn broadcasts_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/broadcasts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array());
}

#[tokio::test]
async fn bounties_returns_array() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/bounties")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body.is_array());
}

// ── Identity verify ───────────────────────────────────────────────────────────

#[tokio::test]
async fn identity_verify_dev_mode_returns_verified() {
    // identity_dev_mode = true → returns verified:true without calling 8004
    let agent_id = "a".repeat(64);
    let res = app()
        .oneshot(
            Request::builder()
                .uri(format!("/identity/verify/{agent_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(
        body.get("verified").and_then(|v| v.as_bool()),
        Some(true),
        "dev mode should return verified:true, got: {body}"
    );
}

// ── Billing estimate (public) ─────────────────────────────────────────────────

#[tokio::test]
async fn billing_estimate_settlement_returns_ok_or_bad_request() {
    let res = app()
        .oneshot(
            Request::builder()
                .uri("/billing/estimate-settlement")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 200 with default params or 400 if required query params are missing
    assert!(
        res.status() == StatusCode::OK || res.status() == StatusCode::BAD_REQUEST,
        "unexpected: {}",
        res.status()
    );
}
