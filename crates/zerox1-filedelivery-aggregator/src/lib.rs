//! `zerox1-filedelivery-aggregator` — 0x01 aggregator blob relay adapter.
//!
//! Uploads large DELIVER payloads to the 0x01 aggregator blob store
//! (`POST /blobs`) and returns an `agg://<cid>` URI that the receiving node
//! resolves via the public `GET /blobs/<cid>` endpoint.
//!
//! # Authentication
//!
//! Uploads are signed with the node's Ed25519 identity key so the aggregator
//! can apply reputation-based size limits (premium=10 MB, silver=2 MB,
//! bronze=512 KB). The GET endpoint is unauthenticated.
//!
//! # URI scheme
//!
//!   `agg://<64-char-keccak256-hex>`

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use zerox1_filedelivery_core::{DeliveryRef, FileDelivery};

/// URI scheme prefix used by this adapter.
const URI_SCHEME: &str = "agg://";

/// Aggregator blob relay adapter.
///
/// Construct with [`AggregatorBlobDelivery::new`] and pass the node's signing
/// key. The key is used to authenticate uploads; no separate API key required.
pub struct AggregatorBlobDelivery {
    /// Base URL of the aggregator, e.g. `https://api.0x01.world`.
    base_url: String,
    /// Hex-encoded 32-byte agent identity (Ed25519 verifying key).
    agent_id_hex: String,
    /// Node signing key — used to sign blob uploads.
    signing_key: Arc<SigningKey>,
    http: reqwest::Client,
}

impl AggregatorBlobDelivery {
    /// Create a new adapter.
    ///
    /// `base_url` should be the aggregator root without a trailing slash,
    /// e.g. `"https://api.0x01.world"`.
    pub fn new(base_url: impl Into<String>, signing_key: Arc<SigningKey>) -> Self {
        let agent_id_hex = hex::encode(signing_key.verifying_key().as_bytes());
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent_id_hex,
            signing_key,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
        }
    }
}

#[async_trait]
impl FileDelivery for AggregatorBlobDelivery {
    async fn upload(
        &self,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> anyhow::Result<DeliveryRef> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before epoch")?
            .as_secs();

        // Signature covers body bytes || timestamp as little-endian u64.
        let mut msg = data.clone();
        msg.extend_from_slice(&ts.to_le_bytes());
        let sig = self.signing_key.sign(&msg);
        let sig_hex = hex::encode(sig.to_bytes());

        let size = data.len() as u64;
        let ct = content_type.unwrap_or("application/octet-stream");

        let res = self
            .http
            .post(format!("{}/blobs", self.base_url))
            .header("Content-Type", ct)
            .header("X-0x01-Agent-Id", &self.agent_id_hex)
            .header("X-0x01-Signer", &self.agent_id_hex)
            .header("X-0x01-Timestamp", ts.to_string())
            .header("X-0x01-Signature", sig_hex)
            .body(data)
            .send()
            .await
            .context("blob upload request failed")?;

        let status = res.status();
        if status != reqwest::StatusCode::CREATED {
            let body = res.text().await.unwrap_or_default();
            anyhow::bail!("aggregator returned {status}: {body}");
        }

        let json: serde_json::Value = res.json().await.context("invalid JSON in upload response")?;
        let cid = json["cid"]
            .as_str()
            .context("missing 'cid' in upload response")?
            .to_string();

        tracing::info!(
            cid = &cid[..8],
            bytes = size,
            "DELIVER payload offloaded to aggregator blob store"
        );

        Ok(DeliveryRef {
            uri: format!("{URI_SCHEME}{cid}"),
            size_bytes: size,
            content_type: Some(ct.to_string()),
        })
    }

    async fn download(&self, uri: &str) -> anyhow::Result<Vec<u8>> {
        let cid = uri
            .strip_prefix(URI_SCHEME)
            .context("uri does not start with agg://")?;

        // Basic sanity-check — aggregator rejects non-hex CIDs anyway.
        anyhow::ensure!(
            cid.len() == 64 && cid.chars().all(|c| c.is_ascii_hexdigit()),
            "invalid cid in agg:// uri"
        );

        let res = self
            .http
            .get(format!("{}/blobs/{cid}", self.base_url))
            .send()
            .await
            .context("blob download request failed")?;

        let status = res.status();
        anyhow::ensure!(status.is_success(), "aggregator returned {status} for GET /blobs/{cid}");

        Ok(res.bytes().await.context("reading blob bytes")?.to_vec())
    }

    fn handles(&self, uri: &str) -> bool {
        uri.starts_with(URI_SCHEME)
    }
}
