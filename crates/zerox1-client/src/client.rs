//! HTTP client for the zerox1-node local REST API.

use crate::types::{
    AgentId, ConversationId, HostedSendRequest, IdentityResponse, InboundEnvelope,
    SendEnvelopeRequest, SendEnvelopeResponse,
};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use futures_util::StreamExt;
use http::Request;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::debug;

/// HTTP client for the local zerox1-node REST API.
///
/// Supports both **local-node** mode (`POST /envelopes/send`, `GET /ws/inbox`)
/// and **hosted-agent** mode (`POST /hosted/send`, `GET /ws/hosted/inbox`).
///
/// # Example
/// ```no_run
/// use zerox1_client::NodeClient;
///
/// let client = NodeClient::new("http://127.0.0.1:9090", Some("my-secret".into()));
/// ```
#[derive(Clone, Debug)]
pub struct NodeClient {
    pub api_base: String,
    pub token: Option<String>,
    http: reqwest::Client,
}

impl NodeClient {
    /// Create a new client. `token` is the `ZX01_API_SECRET` or a read key.
    pub fn new(api_base: impl Into<String>, token: Option<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { api_base: api_base.into(), token, http })
    }

    // ── URL helpers ─────────────────────────────────────────────────────

    /// Derive the WebSocket base URL (`http` → `ws`, `https` → `wss`).
    pub fn ws_base(&self) -> String {
        self.api_base
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1)
    }

    /// WebSocket URL for `GET /ws/inbox`.
    pub fn inbox_ws_url(&self) -> String {
        format!("{}/ws/inbox", self.ws_base())
    }

    /// WebSocket URL for `GET /ws/hosted/inbox` (hosted-agent mode).
    pub fn hosted_inbox_ws_url(&self, hosted_token: &str) -> String {
        format!("{}/ws/hosted/inbox?token={hosted_token}", self.ws_base())
    }

    // ── Auth helper ─────────────────────────────────────────────────────

    fn auth_header(&self) -> Option<String> {
        self.token.as_deref().filter(|t| !t.is_empty()).map(|t| format!("Bearer {t}"))
    }

    fn add_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(auth) = self.auth_header() {
            builder.header("Authorization", auth)
        } else {
            builder
        }
    }

    // ── Node endpoints ──────────────────────────────────────────────────

    /// `GET /hosted/ping` — lightweight reachability probe.
    pub async fn ping(&self) -> bool {
        let url = format!("{}/hosted/ping", self.api_base);
        self.http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    /// `GET /identity` — fetch the node's own agent_id.
    pub async fn identity(&self) -> Result<AgentId> {
        let url = format!("{}/identity", self.api_base);
        let resp: IdentityResponse = self
            .add_auth(self.http.get(&url))
            .send()
            .await
            .context("GET /identity")?
            .json()
            .await
            .context("deserialize /identity")?;
        debug!("identity: {}", resp.agent_id);
        AgentId::from_hex(&resp.agent_id).context("invalid agent_id in /identity response")
    }

    /// `POST /envelopes/send` — local-node mode.
    ///
    /// `payload` is raw bytes; base64-encoding is handled internally.
    pub async fn send_envelope(
        &self,
        msg_type: &str,
        recipient: Option<&AgentId>,
        conversation_id: &ConversationId,
        payload: &[u8],
    ) -> Result<SendEnvelopeResponse> {
        let url = format!("{}/envelopes/send", self.api_base);
        let body = SendEnvelopeRequest {
            msg_type: msg_type.to_uppercase(),
            recipient: recipient.map(|id| id.to_hex()),
            conversation_id: conversation_id.to_hex(),
            payload_b64: BASE64.encode(payload),
        };
        let resp = self
            .add_auth(self.http.post(&url).json(&body))
            .send()
            .await
            .context("POST /envelopes/send")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("/envelopes/send {status}: {text}");
        }
        resp.json::<SendEnvelopeResponse>().await.context("deserialize /envelopes/send response")
    }

    /// `POST /hosted/send` — hosted-agent mode.
    ///
    /// `payload` is raw bytes; hex-encoding is handled internally.
    pub async fn hosted_send(
        &self,
        hosted_token: &str,
        msg_type: &str,
        recipient: Option<&AgentId>,
        conversation_id: &ConversationId,
        payload: &[u8],
    ) -> Result<()> {
        let url = format!("{}/hosted/send", self.api_base);
        let body = HostedSendRequest {
            msg_type: msg_type.to_uppercase(),
            recipient: recipient.map(|id| id.to_hex()),
            conversation_id: conversation_id.to_hex(),
            payload_hex: hex::encode(payload),
        };
        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {hosted_token}"))
            .json(&body)
            .send()
            .await
            .context("POST /hosted/send")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("/hosted/send {status}: {text}");
        }
        Ok(())
    }

    // ── WS inbox ────────────────────────────────────────────────────────

    /// Open a `GET /ws/inbox` stream and call `handler` for each inbound envelope.
    ///
    /// Returns when the connection closes or an error occurs. The caller is
    /// responsible for reconnect logic.
    ///
    /// # Example
    /// ```no_run
    /// # use zerox1_client::{NodeClient, InboundEnvelope};
    /// # async fn example(client: NodeClient) {
    /// client.listen_inbox(|env| async move {
    ///     println!("{} from {}", env.msg_type, env.sender);
    ///     Ok(())
    /// }).await.ok();
    /// # }
    /// ```
    pub async fn listen_inbox<F, Fut>(&self, mut handler: F) -> Result<()>
    where
        F: FnMut(InboundEnvelope) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let url = self.inbox_ws_url();
        let key = base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
        let mut req = Request::builder()
            .uri(&url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", key)
            .header("Sec-WebSocket-Version", "13");
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }
        let (ws, _) = connect_async(req.body(())?).await.context("connect /ws/inbox")?;
        let (_, mut rx) = ws.split();

        while let Some(msg) = rx.next().await {
            match msg? {
                Message::Text(t) => {
                    if let Ok(env) = serde_json::from_str::<InboundEnvelope>(t.as_ref()) {
                        handler(env).await?;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok(())
    }
}
