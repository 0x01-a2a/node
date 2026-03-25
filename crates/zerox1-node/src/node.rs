use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;
use url::Host;

use base64::Engine as _;

use ed25519_dalek::{Signer, VerifyingKey};
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response,
    swarm::SwarmEvent, PeerId, Swarm,
};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;

use zerox1_protocol::{
    batch::{FeedbackEvent, TaskSelection, TypedBid, VerifierAssignment},
    constants::{TOPIC_BROADCAST, TOPIC_NAMED_PREFIX, TOPIC_NOTARY, TOPIC_REPUTATION},
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::{BroadcastPayload, FeedbackPayload},
};

use solana_sdk::pubkey::Pubkey;

use crate::{
    api::{
        ApiEvent, ApiState, BatchSnapshot, OutboundRequest, PeerSnapshot, PortfolioEvent,
        ReputationSnapshot, SentConfirmation,
    },
    batch::{current_epoch, now_micros, BatchAccumulator},
    config::Config,
    identity::AgentIdentity,
    kora::KoraClient,
    logger::EnvelopeLogger,
    network::{Zx01Behaviour, Zx01BehaviourEvent},
    peer_state::PeerStateMap,
    push_notary,
    reputation::ReputationTracker,
};

// ============================================================================
// Payload layout conventions (documented for agent application authors)
//
// BEACON:          [agent_id(32)][verifying_key(32)][name(utf-8)]
// PROPOSE/COUNTER: [bid_value(16, LE i128)][opaque agent payload...]
// NOTARIZE_ASSIGN: [verifier_agent_id(32)][opaque...]
// ============================================================================

const BEACON_VK_OFFSET: usize = 32;
const BEACON_NAME_OFFSET: usize = 64;
const BID_VALUE_LEN: usize = 16;
const NOTARIZE_ASSIGN_VERIFIER_OFFSET: usize = 32;

/// Maximum bytes read from BEACON name field.
const MAX_NAME_LEN: usize = 64;
/// Maximum tracked conversations (bilateral message sender ↔ conversation).
const MAX_ACTIVE_CONVERSATIONS: usize = 10_000;
/// Maximum number of notary candidates tracked.
const MAX_NOTARY_POOL: usize = 100;
/// Maximum broadcast envelopes queued while waiting for mesh peers.
const MAX_PENDING_BROADCASTS: usize = 20;
/// Maximum number of distinct peers tracked in the rate-limit table.
/// When full, expired entries are evicted; if still full the new peer is skipped.
const MAX_RATE_LIMITER_PEERS: usize = 10_000;
/// Maximum number of identity-check failure cache entries retained.
const MAX_REG8004_FAILURE_CACHE: usize = 50_000;

// ============================================================================
// Zx01Node
// ============================================================================

pub struct Zx01Node {
    pub config: Config,
    pub identity: AgentIdentity,
    pub peer_states: PeerStateMap,
    pub reputation: ReputationTracker,
    pub logger: EnvelopeLogger,
    pub batch: BatchAccumulator,

    /// Nonblocking Solana RPC client (slot polling + batch submission).
    rpc: RpcClient,
    /// Kora paymaster client — present when --kora-url is configured.
    /// Enables gasless on-chain transactions (gas reimbursed in USDC, §4.4).
    #[allow(dead_code)]
    kora: Option<KoraClient>,
    /// True when running with --registry-8004-disabled (open/dev mode).
    dev_mode: bool,
    /// Visualization API shared state (always present; server only started when
    /// --api-addr is configured).
    api: ApiState,

    nonce: u64,
    current_slot: u64,
    current_epoch: u64,
    conversations: HashMap<[u8; 16], PeerId>,
    conversation_lru: VecDeque<[u8; 16]>,

    /// Receives outbound envelope requests from the Agent API (POST /envelopes/send).
    outbound_rx: tokio::sync::mpsc::Receiver<OutboundRequest>,
    /// Receives pre-signed envelopes from the hosted-agent API (POST /hosted/send).
    hosted_outbound_rx: tokio::sync::mpsc::Receiver<zerox1_protocol::envelope::Envelope>,
    /// Receives gossipsub topic subscription requests from the API (/ws/topics).
    sub_topic_rx: tokio::sync::mpsc::Receiver<String>,

    /// USDC mint pubkey — used for inactivity slash bounty payout.
    usdc_mint: Option<Pubkey>,
    /// Reputation aggregator base URL — FEEDBACK/VERDICT envelopes are pushed here.
    aggregator_url: Option<String>,
    /// Shared secret sent in Authorization header when pushing to the aggregator.
    aggregator_secret: Option<String>,
    /// App webhook URL — every validated inbound envelope is POSTed here.
    app_webhook_url: Option<String>,
    /// Bearer token for the app webhook Authorization header.
    app_webhook_secret: Option<String>,
    /// Msg type filter for the app webhook. Empty = all types.
    app_webhook_types: std::collections::HashSet<String>,
    /// Shared HTTP client for aggregator pushes — avoids per-push TCP setup.
    http_client: reqwest::Client,
    /// Per-peer message rate limiter: PeerId → (count_in_window, window_start).
    rate_limiter: std::collections::HashMap<libp2p::PeerId, (u32, std::time::Instant)>,
    /// Agents known to offer notary services (populated from NOTARIZE_BID broadcasts).
    /// Used to auto-assign a notary when this node sends ACCEPT.
    /// agent_id → libp2p PeerId (needed for bilateral send).
    notary_pool: HashMap<[u8; 32], PeerId>,
    /// Bootstrap peer multiaddrs — used to redial when the node loses all connections.
    bootstrap_peers: Vec<libp2p::Multiaddr>,
    /// Broadcasts queued when gossipsub had no mesh peers (InsufficientPeers).
    /// Flushed the moment any peer subscribes to our topic.
    pending_broadcasts: Vec<Envelope>,
    /// Throttle map for latency reports: last time we pushed a LATENCY event
    /// for each peer. Prevents flooding the aggregator with per-ping pushes.
    /// Only populated when --node-region is set.
    last_ping_push: HashMap<PeerId, std::time::Instant>,
    /// Per-agent identity-check failure timestamps (1-hour backoff).
    /// Prevents hammering the aggregator when /identity/verify returns 503.
    reg8004_failures: HashMap<[u8; 32], std::time::Instant>,
    /// Agent IDs exempt from lease and registration checks.
    /// Shared with ApiState so the admin API can mutate it at runtime without restart.
    #[allow(dead_code)]
    exempt_agents: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
}

impl Zx01Node {
    pub async fn new(
        mut config: Config,
        identity: AgentIdentity,
        bootstrap_peers: Vec<libp2p::Multiaddr>,
    ) -> anyhow::Result<Self> {
        // If no name was configured, derive one from the first 4 bytes of the
        // agent ID (8 hex chars) so every node has a unique, stable default.
        if config.agent_name.is_empty() {
            config.agent_name = hex::encode(&identity.agent_id[..4]);
        }
        let epoch = current_epoch();
        let log_dir = config.log_dir.clone();
        let rpc = RpcClient::new(config.rpc_url.clone());
        // "none" disables Kora entirely; otherwise use the configured URL.
        let kora = if config.kora_url.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(KoraClient::new(&config.kora_url))
        };
        // Dev mode: 8004 registry gate disabled — all agents allowed through.
        let dev_mode = config.registry_8004_disabled;
        let http_client = reqwest::Client::new();
        let usdc_mint = config.usdc_mint_pubkey().ok().flatten();
        let aggregator_url = validated_aggregator_url(config.aggregator_url.clone());
        let aggregator_secret = config.aggregator_secret.clone();
        let app_webhook_url = config.app_webhook_url.clone();
        let app_webhook_secret = config.app_webhook_secret.clone();
        let app_webhook_types: std::collections::HashSet<String> = config
            .app_webhook_types
            .iter()
            .map(|s| s.to_uppercase())
            .collect();
        // ── Exempt agents: load persisted runtime mutations + merge env/CLI config ──
        let exempt_persist_path = config.log_dir.join("exempt_agents.json");
        let mut exempt_set = std::collections::HashSet::<[u8; 32]>::new();

        if let Ok(data) = tokio::fs::read_to_string(&exempt_persist_path).await {
            if let Ok(ids) = serde_json::from_str::<Vec<String>>(&data) {
                for hex_str in ids {
                    if let Ok(bytes) = hex::decode(&hex_str) {
                        if let Ok(arr) = bytes.try_into() {
                            exempt_set.insert(arr);
                            tracing::info!("Loaded exempt agent from persist: {}", hex_str);
                        }
                    }
                }
            }
        }

        for hex_str in &config.exempt_agents {
            if let Ok(bytes) = hex::decode(hex_str) {
                if let Ok(arr) = bytes.try_into() {
                    if exempt_set.insert(arr) {
                        tracing::info!("Registered exempt agent: {}", hex_str);
                    }
                } else {
                    tracing::warn!(
                        "Invalid exempt agent length (expected 32 bytes): {}",
                        hex_str
                    );
                }
            } else {
                tracing::warn!("Invalid hex for exempt agent: {}", hex_str);
            }
        }

        let exempt_agents = std::sync::Arc::new(std::sync::RwLock::new(exempt_set));

        // ── Bags fee-sharing: resolve distribution address at startup ─────────
        #[cfg(feature = "bags")]
        let bags_config: Option<std::sync::Arc<crate::bags::BagsConfig>> = 'bags: {
            use std::str::FromStr as _;
            if config.bags_fee_bps == 0 {
                None
            } else {
                if config.bags_fee_bps > 500 {
                    anyhow::bail!(
                        "--bags-fee-bps {} exceeds maximum allowed value of 500 (5%)",
                        config.bags_fee_bps
                    );
                }
                let distribution_wallet = if let Some(ref w) = config.bags_wallet {
                    solana_sdk::pubkey::Pubkey::from_str(w)
                        .map_err(|e| anyhow::anyhow!("Invalid --bags-wallet '{w}': {e}"))?
                } else {
                    let api_client = crate::bags::BagsApiClient::new(
                        config.bags_api_url.clone(),
                        http_client.clone(),
                    )?;
                    match api_client.resolve_distribution_address().await {
                        Ok(wallet) => wallet,
                        Err(e) => {
                            tracing::warn!(
                                "Bags fee-sharing disabled for this run: Bags API unavailable and \
                                 --bags-wallet not set: {e}"
                            );
                            break 'bags None;
                        }
                    }
                };
                tracing::info!(
                    "Bags fee-sharing enabled: {} bps → {}",
                    config.bags_fee_bps,
                    distribution_wallet
                );
                Some(std::sync::Arc::new(crate::bags::BagsConfig {
                    fee_bps: config.bags_fee_bps,
                    distribution_wallet,
                    min_fee_micro: 1_000,
                }))
            }
        };

        #[cfg(feature = "bags")]
        let bags_launch: Option<std::sync::Arc<crate::bags::BagsLaunchClient>> =
            config
                .bags_api_key
                .as_ref()
                .or(config.bags_partner_key.as_ref())
                .map(|key| {
                if config.bags_partner_key.is_some() {
                    tracing::info!("Bags launch API enabled in partner-first mode");
                } else {
                    tracing::info!("Bags launch API enabled (API key configured)");
                }
                std::sync::Arc::new(crate::bags::BagsLaunchClient::new(
                    key.clone(),
                    config.bags_partner_key.clone(),
                    http_client.clone(),
                ))
            });

        // ── MPP config: derive ATA from recipient wallet if enabled ──────────
        let mpp_config: Option<crate::mpp::MppConfig> = if config.mpp_enabled {
            match &config.mpp_recipient {
                Some(recipient_str) => {
                    match recipient_str.parse::<Pubkey>() {
                        Ok(recipient_wallet) => {
                            let usdc_mint_str = if config.rpc_url.contains("devnet") {
                                crate::api::USDC_MINT_DEVNET
                            } else {
                                crate::api::USDC_MINT_MAINNET
                            };
                            match usdc_mint_str.parse::<Pubkey>() {
                                Ok(mint) => {
                                    let recipient_ata = crate::api::derive_ata(&recipient_wallet, &mint);
                                    let daily_fee = (config.mpp_fee_usdc * 1_000_000.0) as u64;
                                    tracing::info!(
                                        "MPP gate enabled: recipient_ata={} daily_fee={} micro-USDC",
                                        recipient_ata,
                                        daily_fee
                                    );
                                    Some(crate::mpp::MppConfig {
                                        recipient_ata,
                                        daily_fee,
                                        usdc_mint: mint,
                                        enabled: true,
                                    })
                                }
                                Err(e) => {
                                    tracing::warn!("MPP: invalid USDC mint pubkey: {e}");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("MPP: invalid --mpp-recipient pubkey '{recipient_str}': {e}");
                            None
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        "MPP: --mpp-enabled set but --mpp-recipient not provided. Gate disabled."
                    );
                    None
                }
            }
        } else {
            None
        };

        let (api, outbound_rx, hosted_outbound_rx, sub_topic_rx) = ApiState::new(
            identity.agent_id,
            config.agent_name.clone(),
            config.api_secret.clone(),
            config.api_read_keys.clone(),
            config.hosting_fee_bps,
            config.rpc_url.clone(),
            config.trade_rpc_url.clone(),
            #[cfg(feature = "trade")]
            config.jupiter_api_url.clone(),
            #[cfg(feature = "trade")]
            config.jupiter_fee_bps,
            #[cfg(feature = "trade")]
            config.jupiter_fee_account.clone(),
            #[cfg(feature = "trade")]
            config.launchlab_share_fee_wallet.clone(),
            http_client.clone(),
            #[cfg(feature = "bags")]
            config.aggregator_url.clone(),
            #[cfg(feature = "bags")]
            config.aggregator_secret.clone(),
            config.registry_8004_collection.clone(),
            std::sync::Arc::new(identity.signing_key.clone()),
            kora.clone(),
            std::sync::Arc::clone(&exempt_agents),
            exempt_persist_path,
            #[cfg(feature = "bags")]
            bags_config,
            #[cfg(feature = "bags")]
            bags_launch,
            config.skill_workspace.clone(),
            mpp_config,
            // Build file delivery adapter if a gateway URL is configured.
            config.filedelivery_0g_gateway.as_deref().map(|gateway| {
                let indexer = config.filedelivery_0g_indexer.as_deref()
                    .unwrap_or("https://indexer-storage-turbo.0g.ai");
                std::sync::Arc::new(zerox1_filedelivery_0g::ZeroGStorage::new(gateway, indexer))
            }),
        );

        // Load portfolio history from disk
        let portfolio_path = config.log_dir.join("portfolio_history.json");
        let _ = api.load_portfolio_history(portfolio_path).await;

        let batch = BatchAccumulator::new(epoch, 0);
        let logger = EnvelopeLogger::new(log_dir, epoch);

        if dev_mode {
            tracing::warn!(
                "Running in dev mode (--registry-8004-disabled). \
                 Identity checks delegated to aggregator in dev mode — all agents allowed."
            );
        } else {
            tracing::info!(
                "Identity verification delegated to aggregator at {}.",
                config.aggregator_url.as_deref().unwrap_or("(no aggregator URL configured)")
            );
        }

        if kora.is_some() {
            tracing::info!("Kora paymaster enabled — on-chain transactions use gasless USDC path.");
        } else {
            tracing::info!("No --kora-url set — on-chain transactions require SOL for gas.");
        }

        if let Some(ref url) = app_webhook_url {
            if app_webhook_types.is_empty() {
                tracing::info!("App webhook: {} (all msg types)", url);
            } else {
                let types: Vec<&str> = app_webhook_types.iter().map(|s| s.as_str()).collect();
                tracing::info!("App webhook: {} (filter: {})", url, types.join(","));
            }
        }

        Ok(Self {
            config,
            identity,
            peer_states: PeerStateMap::new(),
            reputation: ReputationTracker::new(),
            logger,
            batch,
            rpc,
            kora,
            dev_mode,
            api,
            nonce: 0,
            current_slot: 0,
            current_epoch: epoch,
            conversations: HashMap::new(),
            conversation_lru: VecDeque::new(),
            outbound_rx,
            hosted_outbound_rx,
            sub_topic_rx,
            usdc_mint,
            aggregator_url,
            aggregator_secret,
            app_webhook_url,
            app_webhook_secret,
            app_webhook_types,
            http_client,
            rate_limiter: std::collections::HashMap::new(),
            notary_pool: HashMap::new(),
            bootstrap_peers,
            pending_broadcasts: Vec::new(),
            last_ping_push: HashMap::new(),
            reg8004_failures: HashMap::new(),
            exempt_agents,
        })
    }

    // ========================================================================
    // Main event loop
    // ========================================================================

    pub async fn run(&mut self, swarm: &mut Swarm<Zx01Behaviour>) -> anyhow::Result<()> {
        // ── Visualization API server ─────────────────────────────────────────
        if let Some(ref addr_str) = self.config.api_addr.clone() {
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(addr) => {
                    // Safety: refuse to bind to a non-loopback address without an API secret.
                    // Without a secret every mutating endpoint (/envelopes/send, /wallet/sweep,
                    // /registry/8004/register-*) would be open to anyone on the network.
                    if !addr.ip().is_loopback() && self.config.api_secret.is_none() {
                        anyhow::bail!(
                            "--api-addr {} is a non-loopback address but --api-secret is not \
                             set. All mutating endpoints would be unauthenticated. \
                             Set ZX01_API_SECRET or bind to 127.0.0.1.",
                            addr
                        );
                    }
                    let api = self.api.clone();
                    tokio::spawn(crate::api::serve(
                        api,
                        addr,
                        self.config.api_cors_origins.clone(),
                    ));
                }
                Err(e) => tracing::warn!("Invalid --api-addr '{addr_str}': {e}"),
            }
        }

        // ── Hosting registration heartbeat ────────────────────────────────────
        // When --hosting is set, advertise this node to the aggregator every 60s.
        if self.config.hosting {
            if let Some(ref agg_url) = self.aggregator_url.clone() {
                let agg_url_log = agg_url.clone();
                let agg_url = agg_url.clone();
                let public_url = self.config.public_api_url.clone().unwrap_or_default();
                let node_id = hex::encode(self.identity.agent_id);
                let name = self.config.agent_name.clone();
                let fee_bps = self.config.hosting_fee_bps;
                let aggregator_secret = self.config.aggregator_secret.clone();
                let signing_key = self.identity.signing_key.clone();

                tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    loop {
                        let body = serde_json::json!({
                            "node_id": node_id,
                            "name":    name,
                            "fee_bps": fee_bps,
                            "api_url": public_url,
                        });
                        let body_bytes = match serde_json::to_vec(&body) {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!("Failed to serialize hosting heartbeat body: {e}");
                                break;
                            }
                        };
                        let signature = signing_key.sign(&body_bytes);

                        let mut req = client
                            .post(format!("{agg_url}/hosting/register"))
                            .header("X-Signature", hex::encode(signature.to_bytes()))
                            .body(body_bytes);

                        if let Some(ref secret) = aggregator_secret {
                            req = req.header("Authorization", format!("Bearer {secret}"));
                        }
                        if let Err(e) = req.send().await {
                            tracing::warn!("Hosting registration heartbeat failed: {e}");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }
                });

                tracing::info!("Hosting mode enabled — advertising to aggregator at {agg_url_log}");
            } else {
                tracing::warn!(
                    "--hosting set but no --aggregator-url configured; \
                     hosting registration heartbeat disabled."
                );
            }
        }

        // ── Auto-onboard: stake + lease ───────────────────────────────────────
        #[cfg(feature = "settlement")]
        self.ensure_stake_and_lease().await;

        // ── Startup lease check ───────────────────────────────────────────────
        // Verify our own agent's lease before joining the mesh.
        #[cfg(feature = "settlement")]
        self.check_own_lease().await?;

        // ── Geo self-registration ─────────────────────────────────────────────
        if let Some(ref country) = self.config.geo_country {
            self.push_to_aggregator(serde_json::json!({
                "msg_type":     "ADVERTISE",
                "sender":       hex::encode(self.identity.agent_id),
                "capabilities": [],
                "slot":         self.current_slot,
                "geo": {
                    "country": country,
                    "city":    self.config.geo_city.clone(),
                }
            }));
            tracing::info!("Geo registered: country={country}");
        }

        // ── FCM registration (phone-as-node) ─────────────────────────────────
        // If a Firebase device token is configured, register it with the
        // aggregator and pull any messages that arrived while sleeping.
        if let (Some(ref fcm_token), Some(ref agg_url)) =
            (self.config.fcm_token.clone(), self.aggregator_url.clone())
        {
            let agent_id_hex = hex::encode(self.identity.agent_id);
            // Register token.
            if let Err(e) = push_notary::register_fcm_token(
                agg_url,
                &agent_id_hex,
                fcm_token,
                &self.identity.signing_key,
                &self.http_client,
            )
            .await
            {
                tracing::warn!("FCM token registration failed: {e}");
            } else {
                tracing::info!("FCM token registered with aggregator.");
            }
            // Mark this node as awake.
            if let Err(e) = push_notary::set_sleep_mode(
                agg_url,
                &agent_id_hex,
                false,
                &self.identity.signing_key,
                &self.http_client,
            )
            .await
            {
                tracing::warn!("FCM wake notification failed: {e}");
            }
            // Pull any messages held while sleeping.
            match push_notary::pull_pending_messages(
                agg_url,
                &agent_id_hex,
                &self.identity.signing_key,
                &self.http_client,
            )
            .await
            {
                Ok::<Vec<push_notary::PendingMessage>, _>(msgs) if !msgs.is_empty() => {
                    tracing::info!(
                        "{} pending message(s) retrieved from aggregator while sleeping.",
                        msgs.len()
                    );
                    for msg in &msgs {
                        tracing::info!("Pending [{}] from {} — {}", msg.msg_type, msg.from, msg.id);
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("Failed to pull pending messages: {e}"),
            }
        }

        let mut beacon_timer = tokio::time::interval(Duration::from_secs(30));
        let mut epoch_timer = tokio::time::interval(Duration::from_secs(30));
        let mut slot_timer = tokio::time::interval(Duration::from_millis(400));
        // Inactivity check: once per hour is sufficient; skip in dev mode.
        let mut inactive_timer = tokio::time::interval(Duration::from_secs(3_600));
        // Reconnect check: if we have no peers, redial bootstrap nodes.
        let mut reconnect_timer = tokio::time::interval(Duration::from_secs(60));

        self.send_beacon(swarm).await;

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    self.handle_swarm_event(swarm, event).await;
                }
                Some(req) = self.outbound_rx.recv() => {
                    self.handle_outbound(swarm, req).await;
                }
                Some(env) = self.hosted_outbound_rx.recv() => {
                    // Registration/lease gates disabled — network-first mode.

                    // Record it in the batch so it's not bypassing the epoch logging!
                    self.batch.record_message(env.msg_type, env.sender, self.current_slot);
                    if let Err(e) = self.logger.log(&env) {
                        tracing::warn!("Logger error on hosted outbound: {e}");
                    }

                    if env.msg_type.is_bilateral() {
                        // Route bilateral hosted messages via request-response.
                        match self.peer_states.peer_id_for_agent(&env.recipient) {
                            Some(peer_id) => {
                                if let Err(e) = self.send_bilateral(swarm, peer_id, &env) {
                                    tracing::warn!(
                                        "Hosted bilateral send failed ({} → {}): {e}",
                                        env.msg_type,
                                        hex::encode(env.recipient),
                                    );
                                }
                            }
                            None => {
                                tracing::warn!(
                                    "Hosted bilateral {}: no known peer_id for recipient {}",
                                    env.msg_type,
                                    hex::encode(env.recipient),
                                );
                            }
                        }
                    } else if let Err(e) = self.publish_envelope(swarm, &env) {
                        tracing::warn!("Hosted outbound publish failed: {e}");
                    }
                }
                Some(topic) = self.sub_topic_rx.recv() => {
                    // Subscribe to a named gossipsub topic requested by a /ws/topics client.
                    let full_topic = format!("{}{}", TOPIC_NAMED_PREFIX, topic);
                    let ident_topic = libp2p::gossipsub::IdentTopic::new(&full_topic);
                    match swarm.behaviour_mut().gossipsub.subscribe(&ident_topic) {
                        Ok(true) => tracing::info!("Subscribed to named topic: {full_topic}"),
                        Ok(false) => {} // already subscribed
                        Err(e) => tracing::warn!("Failed to subscribe to {full_topic}: {e:?}"),
                    }
                }
                _ = beacon_timer.tick() => {
                    // Retry any queued broadcasts before sending the new BEACON.
                    self.flush_pending_broadcasts(swarm);
                    self.send_beacon(swarm).await;
                }
                _ = epoch_timer.tick() => {
                    self.check_epoch_boundary(swarm).await;
                }
                _ = slot_timer.tick() => {
                    self.poll_slot().await;
                }
                _ = inactive_timer.tick() => {
                    self.check_inactive_agents().await;
                }
                _ = reconnect_timer.tick() => {
                    let n = swarm.connected_peers().count();
                    if n == 0 && !self.bootstrap_peers.is_empty() {
                        tracing::info!("No peers connected — redialling {} bootstrap node(s)", self.bootstrap_peers.len());
                        for addr in self.bootstrap_peers.clone() {
                            if let Err(e) = swarm.dial(addr.clone()) {
                                tracing::warn!("Reconnect dial failed for {addr}: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Own lease management
    // ========================================================================

    /// Ensure this agent has both a stake lock and an initialized lease.
    /// Called once at startup before check_own_lease().
    #[cfg(feature = "settlement")]
    async fn ensure_stake_and_lease(&mut self) {
        tracing::debug!("On-chain stake/lease check skipped (settlement decoupled).");
    }

    /// Check this agent's own lease on startup.
    #[cfg(feature = "settlement")]
    async fn check_own_lease(&mut self) -> anyhow::Result<()> {
        tracing::debug!("On-chain lease check skipped (settlement decoupled).");
        Ok(())
    }

    /// Check if own lease needs renewal and pay if so.
    /// Called at each epoch boundary.
    #[cfg(feature = "settlement")]
    async fn maybe_renew_own_lease(&mut self) {}

    #[cfg(feature = "settlement")]
    #[allow(dead_code)]
    async fn renew_own_lease(&mut self) {}

    // ========================================================================
    // Peer lease verification
    // ========================================================================

    /// Query lease status for `agent_id` and cache in peer_states.
    #[cfg(feature = "settlement")]
    #[allow(dead_code)]
    async fn verify_peer_lease(&mut self, _agent_id: [u8; 32]) {
        // On-chain lease verification moved to settlement/solana. No-op.
    }

    /// Returns true if this agent's messages should pass the lease gate.
    /// Without the settlement feature, all peers are always allowed.
    #[cfg(not(feature = "settlement"))]
    #[allow(dead_code)]
    fn lease_gate_allows(&self, _agent_id: &[u8; 32]) -> bool {
        true
    }

    #[cfg(feature = "settlement")]
    #[allow(dead_code)]
    fn lease_gate_allows(&self, _agent_id: &[u8; 32]) -> bool {
        true
    }

    // ========================================================================
    // Slot polling
    // ========================================================================

    async fn poll_slot(&mut self) {
        match self.rpc.get_slot().await {
            Ok(slot) => {
                self.current_slot = slot;
                self.api.set_current_slot(slot);
            }
            Err(e) => tracing::trace!("Slot poll failed: {e}"),
        }
    }

    // ========================================================================
    // Identity verification (delegated to aggregator)
    // ========================================================================

    /// Check whether `agent_id` is verified, via the aggregator's
    /// `/identity/verify/:hex` endpoint.
    ///
    /// Logic:
    ///   1. dev_mode → return true immediately (no network call)
    ///   2. exempt_agents → return true immediately
    ///   3. local failure cache (1 h) → return false (don't hammer aggregator)
    ///   4. GET {aggregator_url}/identity/verify/{hex} (10 s timeout)
    ///   5. HTTP 503 → insert failure, return true (fail-open)
    ///   6. verified: true → clear failure, return true
    ///   7. verified: false → insert failure, return false
    ///   8. any other error → insert failure, return true (fail-open)
    #[allow(dead_code)]
    async fn check_identity(&mut self, agent_id: &[u8; 32]) -> bool {
        // 1. Dev mode
        if self.dev_mode {
            return true;
        }

        // 2. Exempt agents
        if let Ok(exempt) = self.exempt_agents.read() {
            if exempt.contains(agent_id) {
                return true;
            }
        }

        // 3. Local failure cache
        let backoff = std::time::Duration::from_secs(3_600);
        if let Some(ts) = self.reg8004_failures.get(agent_id) {
            if ts.elapsed() < backoff {
                return false;
            }
        }

        // 4. Aggregator call
        let aggregator_url = match &self.aggregator_url {
            Some(u) => u.clone(),
            None => {
                // No aggregator configured — fail open.
                return true;
            }
        };
        let hex = hex::encode(agent_id);
        let url = format!("{aggregator_url}/identity/verify/{hex}");

        let result = self
            .http_client
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                // 5. 503 — aggregator temporarily unavailable, fail open
                tracing::warn!(
                    "identity/verify: aggregator returned 503 for {} — failing open",
                    &hex[..8]
                );
                self.reg8004_failures
                    .insert(*agent_id, std::time::Instant::now());
                true
            }
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        let verified = body
                            .get("verified")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let source = body
                            .get("source")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown");
                        if verified {
                            // 6. Verified — clear any stale failure
                            self.reg8004_failures.remove(agent_id);
                            tracing::debug!(
                                "identity/verify: {} verified (source={})",
                                &hex[..8],
                                source
                            );
                        } else {
                            // 7. Not verified — cache the negative result
                            self.reg8004_failures
                                .insert(*agent_id, std::time::Instant::now());
                            tracing::debug!(
                                "identity/verify: {} NOT verified (source={})",
                                &hex[..8],
                                source
                            );
                        }
                        verified
                    }
                    Err(e) => {
                        // 8. JSON parse error — fail open
                        tracing::warn!(
                            "identity/verify: failed to parse response for {}: {e}",
                            &hex[..8]
                        );
                        self.reg8004_failures
                            .insert(*agent_id, std::time::Instant::now());
                        true
                    }
                }
            }
            Ok(resp) => {
                // 8. Unexpected HTTP status — fail open
                tracing::warn!(
                    "identity/verify: unexpected HTTP {} for {} — failing open",
                    resp.status(),
                    &hex[..8]
                );
                self.reg8004_failures
                    .insert(*agent_id, std::time::Instant::now());
                true
            }
            Err(e) => {
                // 8. Network error — fail open
                tracing::warn!(
                    "identity/verify: network error for {}: {e} — failing open",
                    &hex[..8]
                );
                self.reg8004_failures
                    .insert(*agent_id, std::time::Instant::now());
                true
            }
        }
    }

    /// Returns true if this agent's messages should be forwarded.
    /// Gate currently disabled — network-first mode.
    #[allow(dead_code)]
    fn registration_gate_allows(&self, _agent_id: &[u8; 32]) -> bool {
        true
    }

    // ========================================================================
    // Swarm event dispatch
    // ========================================================================

    async fn handle_swarm_event(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        event: SwarmEvent<Zx01BehaviourEvent>,
    ) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Listening on {address}");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                tracing::debug!("Connected to {peer_id} via {endpoint:?}");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::debug!("Disconnected from {peer_id}");
                self.last_ping_push.remove(&peer_id);
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(swarm, behaviour_event).await;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!("Outgoing connection error to {peer_id:?}: {error}");
            }
            _ => {}
        }
    }

    async fn handle_behaviour_event(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        event: Zx01BehaviourEvent,
    ) {
        match event {
            Zx01BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                self.handle_pubsub_message(swarm, propagation_source, message)
                    .await;
            }
            Zx01BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                tracing::debug!("{peer_id} subscribed to {topic}");
                self.flush_pending_broadcasts(swarm);
            }
            Zx01BehaviourEvent::Gossipsub(_) => {}

            Zx01BehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer_id, addr) in peers {
                    tracing::info!("mDNS discovered {peer_id} at {addr}");
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    let _ = swarm.dial(peer_id);
                }
            }
            Zx01BehaviourEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer_id, _addr) in peers {
                    tracing::debug!("mDNS expired {peer_id}");
                }
            }

            Zx01BehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. }) => {
                tracing::debug!("Kademlia routing updated: {peer}");
            }
            Zx01BehaviourEvent::Kademlia(_) => {}

            Zx01BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                tracing::info!("Identified {peer_id}: agent={}", info.agent_version);
                for addr in &info.listen_addrs {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                if let Ok(ed_pk) = info.public_key.try_into_ed25519() {
                    if let Ok(vk) = VerifyingKey::from_bytes(&ed_pk.to_bytes()) {
                        // The agent_id is the raw Ed25519 public key bytes.
                        // Register the authoritative peer_id → agent_id mapping
                        // from the identify handshake (direct connection), so
                        // bilateral routing uses the actual peer rather than
                        // the gossipsub propagation-source hop.
                        let agent_id: [u8; 32] = ed_pk.to_bytes();
                        tracing::info!(
                            "Identify: mapping agent {} → peer {}",
                            hex::encode(agent_id),
                            peer_id,
                        );
                        self.peer_states.register_peer(agent_id, peer_id);
                        self.peer_states.set_verifying_key(agent_id, vk);
                    }
                }
            }
            Zx01BehaviourEvent::Identify(_) => {}

            Zx01BehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
                ..
            }) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.handle_bilateral_request(swarm, peer, request, channel)
                        .await;
                }
                request_response::Message::Response { response, .. } => {
                    tracing::trace!("Bilateral ACK from {peer}: {:?}", response);
                }
            },
            Zx01BehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                peer,
                error,
                ..
            }) => {
                tracing::warn!("Bilateral outbound failure to {peer}: {error}");
            }
            Zx01BehaviourEvent::RequestResponse(request_response::Event::InboundFailure {
                peer,
                error,
                ..
            }) => {
                tracing::warn!("Bilateral inbound failure from {peer}: {error}");
            }
            Zx01BehaviourEvent::RequestResponse(_) => {}

            // ── Relay server events (genesis nodes) ──────────────────────────
            Zx01BehaviourEvent::RelayServer(relay::Event::ReservationReqAccepted {
                src_peer_id,
                ..
            }) => {
                tracing::info!("Relay: reservation accepted from {src_peer_id}");
            }
            Zx01BehaviourEvent::RelayServer(relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            }) => {
                tracing::debug!("Relay: circuit opened {src_peer_id} → {dst_peer_id}");
            }
            Zx01BehaviourEvent::RelayServer(relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                ..
            }) => {
                tracing::debug!("Relay: circuit closed {src_peer_id} → {dst_peer_id}");
            }
            Zx01BehaviourEvent::RelayServer(_) => {}

            // ── Relay client events (mobile / NAT-restricted nodes) ──────────
            Zx01BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                ..
            }) => {
                tracing::info!("Circuit relay reservation accepted by {relay_peer_id}");
            }
            Zx01BehaviourEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished {
                relay_peer_id,
                ..
            }) => {
                tracing::debug!("Relay circuit established via {relay_peer_id}");
            }
            Zx01BehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
                src_peer_id,
                ..
            }) => {
                tracing::debug!("Inbound relay circuit from {src_peer_id}");
            }

            // ── dcutr — upgrades relay connections to direct connections ─────
            // dcutr::Event is a struct with remote_peer_id and result fields.
            Zx01BehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => match result {
                Ok(_) => {
                    tracing::info!("dcutr: direct connection established with {remote_peer_id}")
                }
                Err(e) => tracing::debug!("dcutr: upgrade failed with {remote_peer_id}: {e}"),
            },

            // ── AutoNAT — external reachability probe ────────────────────────
            Zx01BehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new }) => {
                tracing::info!("AutoNAT status: {old:?} → {new:?}");
            }
            Zx01BehaviourEvent::Autonat(_) => {}

            // ── Ping — RTT measurement for geo plausibility ───────────────────
            // Only report when --node-region is configured (genesis/reference nodes).
            Zx01BehaviourEvent::Ping(ping::Event { peer, result, .. }) => {
                if let (Ok(rtt), Some(ref region)) = (result, self.config.node_region.clone()) {
                    if let Some(agent_id) = self.peer_states.agent_id_for_peer(&peer) {
                        let now = std::time::Instant::now();
                        let should_push = self
                            .last_ping_push
                            .get(&peer)
                            .map(|t| now.duration_since(*t).as_secs() >= 60)
                            .unwrap_or(true);
                        if should_push {
                            let rtt_ms = rtt.as_millis() as u64;
                            self.push_to_aggregator(serde_json::json!({
                                "msg_type": "LATENCY",
                                "agent_id": hex::encode(agent_id),
                                "region":   region,
                                "rtt_ms":   rtt_ms,
                                "slot":     self.current_slot,
                            }));
                            self.last_ping_push.insert(peer, now);
                            tracing::debug!(
                                "Latency: agent={} region={region} rtt={rtt_ms}ms",
                                hex::encode(agent_id),
                            );
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Pubsub message handling
    // ========================================================================

    async fn handle_pubsub_message(
        &mut self,
        _swarm: &mut Swarm<Zx01Behaviour>,
        source_peer: PeerId,
        message: gossipsub::Message,
    ) {
        // Drop if peer is flooding above the allowed rate.
        if !self.check_rate_limit(&source_peer) {
            tracing::debug!("Rate limit exceeded for pubsub peer {source_peer} — dropping");
            return;
        }

        let topic_str = message.topic.as_str();

        if let Err(e) = Envelope::check_size(message.data.len()) {
            tracing::debug!("Pubsub envelope too large from {source_peer}: {e}");
            return;
        }

        let env = match Envelope::from_cbor(&message.data) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("Pubsub CBOR decode failed from {source_peer}: {e}");
                return;
            }
        };

        // Resolve VK and validate envelope.
        // BEACONs are self-authenticating: extract VK from payload, validate
        // FIRST, then store only if the signature is valid. This prevents
        // attackers from overwriting a legitimate agent's VK with a forged one.
        // Use per-type nonce tracking: BEACONs get their own nonce lane so
        // high-frequency BEACONs don't block lower-nonce non-BEACON messages
        // that may arrive out of gossipsub propagation order.
        if env.msg_type == MsgType::Beacon {
            let last_nonce = self.peer_states.last_beacon_nonce(&env.sender);
            let vk = match self.extract_beacon_vk(&env) {
                Some(vk) => vk,
                None => {
                    tracing::debug!("BEACON from {source_peer}: invalid VK in payload");
                    return;
                }
            };
            if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
                tracing::debug!("BEACON validation failed from {source_peer}: {e}");
                return;
            }
            self.process_beacon_payload(&env, source_peer);
        } else {
            let last_nonce = self.peer_states.last_nonce(&env.sender);
            let vk = match self.peer_states.verifying_key(&env.sender) {
                Some(vk) => *vk,
                None => {
                    tracing::debug!(
                        "No VK for {} — dropping (BEACON required first)",
                        hex::encode(env.sender),
                    );
                    return;
                }
            };
            if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
                tracing::debug!("Envelope validation failed from {source_peer}: {e}");
                return;
            }
        }

        // Registration + Lease gates disabled — network-first mode.
        // Gates always return true; 8004 verification is passive (not blocking).

        // Update peer state (per-type nonce lane).
        if env.msg_type == MsgType::Beacon {
            self.peer_states.update_beacon_nonce(env.sender, env.nonce);
        } else {
            self.peer_states.update_nonce(env.sender, env.nonce);
        }
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation
            .record_activity(env.sender, self.current_epoch);

        // Log envelope.
        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        // Emit visualization event.
        self.api.send_event(ApiEvent::Envelope {
            sender: hex::encode(env.sender),
            msg_type: format!("{:?}", env.msg_type),
            slot: self.current_slot,
        });

        // Push to agent inbox.
        self.api.push_inbound(&env, self.current_slot);

        // Forward to community app webhook (if configured).
        self.push_to_app_webhook(&env);

        self.batch
            .record_message(env.msg_type, env.sender, self.current_slot);

        // Route.
        if topic_str == TOPIC_REPUTATION && env.msg_type == MsgType::Feedback {
            self.handle_feedback_envelope(&env);
        } else if topic_str == TOPIC_NOTARY && env.msg_type == MsgType::NotarizeBid {
            tracing::info!(
                "NOTARIZE_BID from {} (conversation {})",
                hex::encode(env.sender),
                hex::encode(env.conversation_id),
            );
            // Track as notary candidate (cap pool to prevent memory exhaustion).
            if env.sender != self.identity.agent_id && self.notary_pool.len() < MAX_NOTARY_POOL {
                self.notary_pool.insert(env.sender, source_peer);
            }
            self.push_to_aggregator(serde_json::json!({
                "msg_type":        "NOTARIZE_BID",
                "sender":          hex::encode(env.sender),
                "conversation_id": hex::encode(env.conversation_id),
                "slot":            self.current_slot,
            }));
        } else if topic_str.starts_with(TOPIC_NAMED_PREFIX) {
            // Named-topic BROADCAST (0x0E) — already pushed to /ws/topics via push_inbound.
            if env.msg_type == MsgType::Broadcast {
                let topic_name = topic_str
                    .strip_prefix(TOPIC_NAMED_PREFIX)
                    .unwrap_or(topic_str);
                tracing::debug!(
                    "BROADCAST on topic {} from {}",
                    topic_str,
                    hex::encode(env.sender),
                );
                if let Ok(payload) = BroadcastPayload::decode(&env.payload) {
                    // Extract content_url if content is a UTF-8 URL (skip raw binary blobs).
                    let content_url: Option<String> = payload.content.as_ref().and_then(|b| {
                        std::str::from_utf8(b).ok().and_then(|s| {
                            if s.starts_with("http://") || s.starts_with("https://") {
                                Some(s.to_string())
                            } else {
                                None
                            }
                        })
                    });
                    self.push_to_aggregator(serde_json::json!({
                        "msg_type":               "BROADCAST",
                        "sender":                 hex::encode(env.sender),
                        "conversation_id":        hex::encode(env.conversation_id),
                        "topic":                  payload.topic,
                        "topic_slug":             topic_name,
                        "title":                  payload.title,
                        "tags":                   payload.tags,
                        "format":                 payload.format,
                        "content_url":            content_url,
                        "content_type":           payload.content_type,
                        "chunk_index":            payload.chunk_index,
                        "total_chunks":           payload.total_chunks,
                        "duration_ms":            payload.duration_ms,
                        "price_per_epoch_micro":  payload.price_per_epoch_micro,
                        "epoch":                  payload.epoch,
                        "slot":                   self.current_slot,
                    }));
                }
            }
        } else if topic_str == TOPIC_BROADCAST {
            match env.msg_type {
                MsgType::Advertise => {
                    tracing::info!(
                        "ADVERTISE from {} ({} bytes)",
                        hex::encode(env.sender),
                        env.payload.len(),
                    );
                    // Parse capabilities JSON: {"capabilities": ["translation", "price-feed"]}
                    if let Ok(text) = std::str::from_utf8(&env.payload) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
                            let caps: Vec<String> = val
                                .get("capabilities")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|c| c.as_str().map(|s| s.to_string()))
                                        .take(32)
                                        .collect()
                                })
                                .unwrap_or_default();
                            let has_geo = val.get("geo").is_some();
                            // Validate token_address: 32–44 chars, base58 charset only.
                            let validated_token_address: Option<String> = val
                                .get("token_address")
                                .and_then(|v| v.as_str())
                                .and_then(|s| {
                                    let len = s.len();
                                    if (32..=44).contains(&len)
                                        && s.chars().all(|c| {
                                            matches!(c,
                                                '1'..='9'
                                                | 'A'..='H'
                                                | 'J'..='N'
                                                | 'P'..='Z'
                                                | 'a'..='k'
                                                | 'm'..='z'
                                            )
                                        })
                                    {
                                        Some(s.to_string())
                                    } else {
                                        None
                                    }
                                });
                            // Pass capability_proofs through as-is (validated by aggregator).
                            let proofs: Vec<serde_json::Value> = val
                                .get("capability_proofs")
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let min_token_hold: Option<u64> = val
                                .get("min_token_hold")
                                .and_then(|v| v.as_u64());
                            // Downpayment model fields: cap bps at 5000 (50%).
                            let downpayment_bps: Option<u32> = val
                                .get("downpayment_bps")
                                .and_then(|v| v.as_u64())
                                .map(|n| (n.min(5000)) as u32);
                            let price_range_usd: Option<[f64; 2]> = val
                                .get("price_range_usd")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| {
                                    if arr.len() == 2 {
                                        let min = arr[0].as_f64()?;
                                        let max = arr[1].as_f64()?;
                                        Some([min, max])
                                    } else {
                                        None
                                    }
                                });
                            // Forward whenever there are caps OR geo OR token_address.
                            if !caps.is_empty() || has_geo || validated_token_address.is_some() {
                                let mut push = serde_json::json!({
                                    "msg_type":     "ADVERTISE",
                                    "sender":       hex::encode(env.sender),
                                    "capabilities": caps,
                                    "slot":         self.current_slot,
                                });
                                if let Some(geo) = val.get("geo") {
                                    push["geo"] = geo.clone();
                                }
                                if let Some(token_addr) = validated_token_address {
                                    push["token_address"] = serde_json::Value::String(token_addr);
                                }
                                if !proofs.is_empty() {
                                    push["capability_proofs"] = serde_json::Value::Array(proofs);
                                }
                                if let Some(hold) = min_token_hold {
                                    push["min_token_hold"] = serde_json::Value::Number(hold.into());
                                }
                                if let Some(bps) = downpayment_bps {
                                    push["downpayment_bps"] = serde_json::Value::Number(bps.into());
                                }
                                if let Some([min, max]) = price_range_usd {
                                    push["price_range_usd"] = serde_json::json!([min, max]);
                                }
                                self.push_to_aggregator(push);
                            }
                        }
                    }
                }
                MsgType::Discover => {
                    tracing::debug!("DISCOVER from {}", hex::encode(env.sender));
                }
                MsgType::Beacon => { /* already handled above */ }
                _ => {}
            }
        }
    }

    // ========================================================================
    // Bilateral (request-response) handling
    // ========================================================================

    async fn handle_bilateral_request(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        peer_id: PeerId,
        data: Vec<u8>,
        channel: request_response::ResponseChannel<Vec<u8>>,
    ) {
        // Rate limit check — ACK anyway to avoid hanging the sender's channel.
        if !self.check_rate_limit(&peer_id) {
            tracing::debug!("Rate limit exceeded for bilateral peer {peer_id} — dropping");
            let _ = swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, b"ACK".to_vec());
            return;
        }

        // Always ACK immediately (§5.5).
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, b"ACK".to_vec());

        if let Err(e) = Envelope::check_size(data.len()) {
            tracing::debug!("Bilateral envelope too large from {peer_id}: {e}");
            return;
        }

        let env = match Envelope::from_cbor(&data) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("Bilateral CBOR decode failed from {peer_id}: {e}");
                return;
            }
        };

        // The sender's agent_id IS its Ed25519 public key bytes — derive VK directly.
        // This means bilateral messages work even before a gossipsub BEACON is received.
        let vk = match VerifyingKey::from_bytes(&env.sender) {
            Ok(vk) => {
                // Cache for future lookups (e.g. latency tracking).
                self.peer_states.set_verifying_key(env.sender, vk);
                vk
            }
            Err(e) => {
                tracing::debug!(
                    "Invalid sender pubkey in bilateral from {peer_id}: {e}"
                );
                return;
            }
        };

        let last_nonce = self.peer_states.last_nonce(&env.sender);
        if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
            tracing::debug!("Bilateral validation failed from {peer_id}: {e}");
            return;
        }

        // Registration/lease gates disabled — network-first mode.

        self.peer_states.update_nonce(env.sender, env.nonce);
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation
            .record_activity(env.sender, self.current_epoch);

        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        self.batch
            .record_message(env.msg_type, env.sender, self.current_slot);
        self.track_conversation_peer(env.conversation_id, peer_id);

        // Push to agent inbox.
        self.api.push_inbound(&env, self.current_slot);

        // Forward to community app webhook (if configured).
        self.push_to_app_webhook(&env);

        match env.msg_type {
            MsgType::Propose => {
                // Convention: first 16 bytes of payload = LE i128 bid amount.
                let bid_value: i128 = if env.payload.len() >= BID_VALUE_LEN {
                    i128::from_le_bytes(
                        env.payload[..BID_VALUE_LEN]
                            .try_into()
                            .expect("slice length == BID_VALUE_LEN"),
                    )
                } else {
                    0
                };
                self.batch.add_bid(TypedBid {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    bid_value,
                    slot: self.current_slot,
                });
            }
            MsgType::Counter => {
                // Same bid extraction as PROPOSE — the counter-offered amount
                // is in the first 16 bytes of the payload.
                let bid_value: i128 = if env.payload.len() >= BID_VALUE_LEN {
                    i128::from_le_bytes(
                        env.payload[..BID_VALUE_LEN]
                            .try_into()
                            .expect("slice length == BID_VALUE_LEN"),
                    )
                } else {
                    0
                };
                self.batch.add_bid(TypedBid {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    bid_value,
                    slot: self.current_slot,
                });
                tracing::info!(
                    "COUNTER from {} for conversation {} (bid={})",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                    bid_value,
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "COUNTER",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "bid_value":       bid_value,
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Accept => {
                tracing::info!(
                    "ACCEPT from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.batch.record_accept(TaskSelection {
                    conversation_id: env.conversation_id,
                    counterparty: env.sender,
                    slot: self.current_slot,
                });
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "ACCEPT",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::NotarizeAssign => {
                if env.payload.len() >= NOTARIZE_ASSIGN_VERIFIER_OFFSET {
                    let mut vid = [0u8; 32];
                    vid.copy_from_slice(&env.payload[..NOTARIZE_ASSIGN_VERIFIER_OFFSET]);
                    self.batch.record_notarize_assign(VerifierAssignment {
                        conversation_id: env.conversation_id,
                        verifier_id: vid,
                        slot: self.current_slot,
                    });
                } else {
                    tracing::debug!(
                        "NOTARIZE_ASSIGN from {} has short payload — verifier_id not recorded",
                        hex::encode(env.sender),
                    );
                }
            }
            MsgType::Verdict => {
                self.batch.record_verdict_received();
                tracing::info!(
                    "VERDICT received from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "VERDICT",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Reject => {
                tracing::info!(
                    "REJECT from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "REJECT",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Deliver => {
                tracing::info!(
                    "DELIVER from {} for conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "DELIVER",
                    "sender":          hex::encode(env.sender),
                    "recipient":       hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            MsgType::Dispute => {
                self.batch.record_dispute();
                self.reputation.record_dispute(env.sender);
                tracing::warn!(
                    "DISPUTE from {} on conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
                self.push_to_aggregator(serde_json::json!({
                    "msg_type":        "DISPUTE",
                    "sender":          hex::encode(env.sender),
                    "disputed_agent":  hex::encode(env.recipient),
                    "conversation_id": hex::encode(env.conversation_id),
                    "slot":            self.current_slot,
                }));
            }
            _ => {}
        }
    }

    // ========================================================================
    // FEEDBACK
    // ========================================================================

    fn handle_feedback_envelope(&mut self, env: &Envelope) {
        match FeedbackPayload::decode(&env.payload) {
            Ok(fb) => {
                tracing::info!(
                    "FEEDBACK from {} → {} score={} outcome={}",
                    hex::encode(env.sender),
                    hex::encode(fb.target_agent),
                    fb.score,
                    fb.outcome,
                );
                self.reputation.apply_feedback(
                    fb.target_agent,
                    fb.score,
                    fb.role,
                    self.current_epoch,
                );

                // Encode envelope to CBOR for Merkle proof support (GAP-07).
                let raw_b64 = env
                    .to_cbor()
                    .ok()
                    .map(|b| base64::engine::general_purpose::STANDARD.encode(&b));

                // Push to aggregator.
                self.push_to_aggregator(serde_json::json!({
                    "msg_type": "FEEDBACK",
                    "sender":          hex::encode(env.sender),
                    "target_agent":    hex::encode(fb.target_agent),
                    "score":           fb.score,
                    "outcome":         fb.outcome,
                    "is_dispute":      fb.is_dispute,
                    "role":            fb.role,
                    "conversation_id": hex::encode(fb.conversation_id),
                    "slot":            self.current_slot,
                    "raw_b64":         raw_b64,
                }));

                // Update reputation snapshot.
                if let Some(rv) = self.reputation.get(&fb.target_agent) {
                    let snap = ReputationSnapshot {
                        agent_id: hex::encode(fb.target_agent),
                        reliability: rv.reliability_score,
                        cooperation: rv.cooperation_index,
                        notary_accuracy: rv.notary_accuracy,
                        total_tasks: rv.total_tasks,
                        total_disputes: rv.total_disputes,
                        last_active_epoch: rv.last_active_epoch,
                    };
                    self.api.send_event(ApiEvent::ReputationUpdate {
                        agent_id: hex::encode(fb.target_agent),
                        reliability: rv.reliability_score,
                        cooperation: rv.cooperation_index,
                    });
                    let api = self.api.clone();
                    let target = fb.target_agent;
                    tokio::spawn(async move { api.upsert_reputation(target, snap).await });
                }
                if fb.target_agent == self.identity.agent_id {
                    self.batch.record_feedback(FeedbackEvent {
                        conversation_id: fb.conversation_id,
                        from_agent: env.sender,
                        score: fb.score,
                        outcome: fb.outcome,
                        role: fb.role,
                        slot: self.current_slot,
                    });

                    // Record bounty in portfolio if positive score
                    if fb.score > 0 {
                        let api = self.api.clone();
                        let from = env.sender;
                        let cid = hex::encode(fb.conversation_id);
                        let score = fb.score;
                        tokio::spawn(async move {
                            api.record_portfolio_event(PortfolioEvent::Bounty {
                                amount_usdc: score as f64 / 10.0, // 10 score = $1.00
                                from_agent: hex::encode(from),
                                conversation_id: cid,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            })
                            .await;
                        });
                    }
                }
            }
            Err(e) => tracing::debug!("FEEDBACK payload parse failed: {e}"),
        }
    }

    // ========================================================================
    // BEACON processing
    // ========================================================================

    fn extract_beacon_vk(&self, env: &Envelope) -> Option<VerifyingKey> {
        let p = &env.payload;
        if p.len() < BEACON_NAME_OFFSET {
            return None;
        }
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&p[BEACON_VK_OFFSET..BEACON_VK_OFFSET + 32]);
        VerifyingKey::from_bytes(&vk_bytes).ok()
    }

    fn process_beacon_payload(&mut self, env: &Envelope, source_peer: PeerId) {
        let p = &env.payload;
        if p.len() < BEACON_NAME_OFFSET {
            return;
        }

        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&p[BEACON_VK_OFFSET..BEACON_VK_OFFSET + 32]);

        if let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) {
            self.peer_states.set_verifying_key(env.sender, vk);
            // Only use the gossipsub propagation source as the peer_id if
            // identify has not yet established an authoritative mapping.
            // Identify gives us the direct connection peer_id; gossipsub
            // may deliver via a hop that is not the agent's own peer.
            if self.peer_states.peer_id_for_agent(&env.sender).is_none() {
                self.peer_states.register_peer(env.sender, source_peer);
            }
            tracing::info!(
                "BEACON: registered agent {} (peer {source_peer})",
                hex::encode(env.sender),
            );

            // Update peer snapshot and emit event.
            let snap = PeerSnapshot {
                agent_id: hex::encode(env.sender),
                peer_id: Some(source_peer.to_string()),
                #[cfg(feature = "settlement")]
                lease_ok: self.peer_states.lease_status(&env.sender),
                last_active_epoch: self.peer_states.last_active_epoch(&env.sender),
            };
            self.api.send_event(ApiEvent::PeerRegistered {
                agent_id: hex::encode(env.sender),
                peer_id: source_peer.to_string(),
            });
            let api = self.api.clone();
            let sender = env.sender;
            tokio::spawn(async move { api.upsert_peer(sender, snap).await });
        }

        if p.len() > BEACON_NAME_OFFSET {
            // Limit to MAX_NAME_LEN bytes and filter non-printable ASCII to
            // prevent log injection via crafted BEACON payloads.
            let raw_len = (p.len() - BEACON_NAME_OFFSET).min(MAX_NAME_LEN);
            let raw = &p[BEACON_NAME_OFFSET..BEACON_NAME_OFFSET + raw_len];
            if let Ok(name) = std::str::from_utf8(raw) {
                let safe: String = name
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect();
                tracing::debug!("Agent name: {safe}");

                self.push_to_aggregator(serde_json::json!({
                    "msg_type": "BEACON",
                    "sender":   hex::encode(env.sender),
                    "name":     safe,
                    "slot":     self.current_slot,
                }));
            }
        }
    }

    // ========================================================================
    // Outbound helpers
    // ========================================================================

    pub fn build_envelope(
        &mut self,
        msg_type: MsgType,
        recipient: [u8; 32],
        conversation_id: [u8; 16],
        payload: Vec<u8>,
    ) -> Envelope {
        self.nonce += 1;
        Envelope::build(
            msg_type,
            self.identity.agent_id,
            recipient,
            self.current_slot,
            self.nonce,
            conversation_id,
            payload,
            &self.identity.signing_key,
        )
    }

    pub fn publish_envelope(
        &self,
        swarm: &mut Swarm<Zx01Behaviour>,
        env: &Envelope,
    ) -> anyhow::Result<()> {
        let cbor = env.to_cbor()?;

        if env.msg_type.is_named_broadcast() {
            // Decode the BroadcastPayload to extract the user-defined topic.
            let p = BroadcastPayload::decode(&env.payload)
                .map_err(|e| anyhow::anyhow!("BROADCAST payload decode: {e:?}"))?;
            let full_topic = format!("{}{}", TOPIC_NAMED_PREFIX, p.topic);
            // Auto-subscribe to the topic so we receive our own and peers' publishes.
            let ident = gossipsub::IdentTopic::new(&full_topic);
            let _ = swarm.behaviour_mut().gossipsub.subscribe(&ident);
            swarm
                .behaviour_mut()
                .gossipsub
                .publish(ident, cbor)
                .map_err(|e| anyhow::anyhow!("gossipsub publish: {e:?}"))?;
            return Ok(());
        }

        let topic_str = if env.msg_type.is_broadcast() {
            TOPIC_BROADCAST
        } else if env.msg_type.is_notary_pubsub() {
            TOPIC_NOTARY
        } else if env.msg_type.is_reputation_pubsub() {
            TOPIC_REPUTATION
        } else {
            anyhow::bail!("msg_type {:?} is not a pubsub type", env.msg_type);
        };

        swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossipsub::IdentTopic::new(topic_str), cbor)
            .map_err(|e| anyhow::anyhow!("gossipsub publish: {e:?}"))?;
        Ok(())
    }

    /// Deliver any broadcasts that were queued due to InsufficientPeers.
    /// Called each time a peer subscribes to a gossipsub topic.
    fn flush_pending_broadcasts(&mut self, swarm: &mut Swarm<Zx01Behaviour>) {
        if self.pending_broadcasts.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending_broadcasts);
        tracing::info!(
            "Mesh peer joined — flushing {} queued broadcast(s)",
            pending.len()
        );
        for env in pending {
            if let Err(e) = self.publish_envelope(swarm, &env) {
                tracing::warn!("Queued broadcast flush failed ({}): {e}", env.msg_type);
                // Re-queue so the next subscription event or BEACON timer retries.
                if self.pending_broadcasts.len() < MAX_PENDING_BROADCASTS {
                    self.pending_broadcasts.push(env);
                }
            }
        }
    }

    pub fn send_bilateral(
        &self,
        swarm: &mut Swarm<Zx01Behaviour>,
        peer_id: PeerId,
        env: &Envelope,
    ) -> anyhow::Result<()> {
        let cbor = env.to_cbor()?;
        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, cbor);
        Ok(())
    }

    // ========================================================================
    // Outbound request handler (from Agent API)
    // ========================================================================

    async fn handle_outbound(&mut self, swarm: &mut Swarm<Zx01Behaviour>, req: OutboundRequest) {
        let env = self.build_envelope(
            req.msg_type,
            req.recipient,
            req.conversation_id,
            req.payload,
        );

        let payload_hash = hex::encode(env.payload_hash);
        let nonce = env.nonce;

        // Route: pubsub or bilateral.
        let result = if req.msg_type.is_broadcast()
            || req.msg_type.is_notary_pubsub()
            || req.msg_type.is_reputation_pubsub()
            || req.msg_type.is_named_broadcast()
        {
            match self.publish_envelope(swarm, &env) {
                Ok(()) => Ok(()),
                Err(e) if e.to_string().contains("InsufficientPeers") => {
                    // No mesh peers yet — queue and deliver once the first peer joins.
                    // Return early: queued envelopes are not logged/batched until sent.
                    if self.pending_broadcasts.len() < MAX_PENDING_BROADCASTS {
                        tracing::debug!(
                            "No mesh peers — queuing {} (queue len {})",
                            req.msg_type,
                            self.pending_broadcasts.len() + 1,
                        );
                        self.pending_broadcasts.push(env);
                    } else {
                        tracing::warn!(
                            "Pending broadcast queue full ({}); dropping {}",
                            MAX_PENDING_BROADCASTS,
                            req.msg_type,
                        );
                    }
                    let _ = req.reply.send(Ok(SentConfirmation {
                        nonce,
                        payload_hash,
                    }));
                    return;
                }
                Err(e) => Err(e.to_string()),
            }
        } else {
            match self.peer_states.peer_id_for_agent(&req.recipient) {
                Some(peer_id) => self
                    .send_bilateral(swarm, peer_id, &env)
                    .map_err(|e| e.to_string()),
                None => Err(format!(
                    "no known peer_id for agent {}",
                    hex::encode(req.recipient),
                )),
            }
        };

        match &result {
            Ok(_) => {
                // Log and accumulate.
                if let Err(e) = self.logger.log(&env) {
                    tracing::warn!("Logger error on outbound: {e}");
                }
                self.batch
                    .record_message(req.msg_type, self.identity.agent_id, self.current_slot);
                tracing::debug!("Sent {} nonce={nonce}", req.msg_type);

                // VERDICT with approve payload → trigger escrow approve_payment on-chain.
                // Payload convention: [0x00=approve | 0x01=reject][requester(32)][provider(32)]
                if req.msg_type == MsgType::Verdict
                    && env.payload.len() >= 65
                    && env.payload[0] == 0x00
                {
                    let mut requester = [0u8; 32];
                    let mut provider = [0u8; 32];
                    requester.copy_from_slice(&env.payload[1..33]);
                    provider.copy_from_slice(&env.payload[33..65]);
                    // On-chain escrow approval has been moved to settlement/solana.
                    // The aggregator handles off-chain credit release.
                    tracing::debug!(
                        "VERDICT approve for conversation {} (on-chain escrow disabled)",
                        hex::encode(req.conversation_id),
                    );
                }

                // FEEDBACK sent → push to aggregator so the feed reflects the outcome.
                if req.msg_type == MsgType::Feedback {
                    if let Ok(fb) = FeedbackPayload::decode(&env.payload) {
                        let raw_b64 = env
                            .to_cbor()
                            .ok()
                            .map(|b| base64::engine::general_purpose::STANDARD.encode(&b));
                        self.push_to_aggregator(serde_json::json!({
                            "msg_type":        "FEEDBACK",
                            "sender":          hex::encode(env.sender),
                            "target_agent":    hex::encode(fb.target_agent),
                            "score":           fb.score,
                            "outcome":         fb.outcome,
                            "is_dispute":      fb.is_dispute,
                            "role":            fb.role,
                            "conversation_id": hex::encode(fb.conversation_id),
                            "slot":            self.current_slot,
                            "raw_b64":         raw_b64,
                        }));
                        tracing::info!(
                            "FEEDBACK sent → {} score={} outcome={}",
                            hex::encode(fb.target_agent),
                            fb.score,
                            fb.outcome,
                        );
                    }
                }

                // ACCEPT sent → auto-assign a notary for this conversation (if pool non-empty).
                // This populates batch.verifier_ids, making hv (GAP-04) non-None.
                if req.msg_type == MsgType::Accept {
                    self.try_assign_notary(swarm, req.conversation_id);
                    // Escrow lock is SDK-layer responsibility — called explicitly via POST /escrow/lock.
                }
            }
            Err(e) => tracing::warn!("Outbound send failed: {e}"),
        }

        let _ = req.reply.send(result.map(|_| SentConfirmation {
            nonce,
            payload_hash,
        }));
    }

    // ========================================================================
    // Notary auto-assignment (triggered on ACCEPT send)
    // ========================================================================

    /// Pick a notary from the pool and send NOTARIZE_ASSIGN for `conversation_id`.
    ///
    /// Uses the first 8 bytes of conversation_id as a selection seed so different
    /// conversations pick different notaries — maximising verifier entropy (hv).
    fn try_assign_notary(&mut self, swarm: &mut Swarm<Zx01Behaviour>, conversation_id: [u8; 16]) {
        // Build a snapshot excluding ourselves.
        let candidates: Vec<([u8; 32], PeerId)> = self
            .notary_pool
            .iter()
            .filter(|(agent_id, _)| **agent_id != self.identity.agent_id)
            .map(|(a, p)| (*a, *p))
            .collect();

        if candidates.is_empty() {
            return;
        }

        // Use conversation_id[0..8] as an index seed for diverse selection.
        let seed = u64::from_le_bytes(
            conversation_id[..8]
                .try_into()
                .expect("conversation_id is [u8;16], first 8 bytes always fit [u8;8]"),
        );
        let idx = (seed as usize) % candidates.len();
        let (notary_agent_id, notary_peer_id) = candidates[idx];

        // Payload: notary's agent_id (32 bytes), confirming who is being assigned.
        let env = self.build_envelope(
            MsgType::NotarizeAssign,
            notary_agent_id,
            conversation_id,
            notary_agent_id.to_vec(),
        );

        match self.send_bilateral(swarm, notary_peer_id, &env) {
            Ok(_) => {
                self.batch.record_notarize_assign(VerifierAssignment {
                    conversation_id,
                    verifier_id: notary_agent_id,
                    slot: self.current_slot,
                });
                tracing::info!(
                    "NOTARIZE_ASSIGN → {} for conversation {}",
                    &hex::encode(notary_agent_id)[..12],
                    hex::encode(conversation_id),
                );
            }
            Err(e) => tracing::warn!(
                "NOTARIZE_ASSIGN send failed for {}: {e}",
                &hex::encode(notary_agent_id)[..12],
            ),
        }
    }

    // ========================================================================
    // BEACON heartbeat
    // ========================================================================

    async fn send_beacon(&mut self, swarm: &mut Swarm<Zx01Behaviour>) {
        let mut payload = Vec::with_capacity(64 + self.config.agent_name.len());
        payload.extend_from_slice(&self.identity.agent_id);
        payload.extend_from_slice(&self.identity.verifying_key.to_bytes());
        payload.extend_from_slice(self.config.agent_name.as_bytes());

        let env = self.build_envelope(MsgType::Beacon, BROADCAST_RECIPIENT, [0u8; 16], payload);

        match self.publish_envelope(swarm, &env) {
            Ok(()) => {
                tracing::debug!("BEACON sent (nonce={})", self.nonce);
                // Gossipsub does not loop published messages back to the publisher,
                // so we push our own BEACON directly to the aggregator here.
                self.push_to_aggregator(serde_json::json!({
                    "msg_type": "BEACON",
                    "sender":   hex::encode(self.identity.agent_id),
                    "name":     self.config.agent_name,
                    "slot":     self.current_slot,
                }));
            }
            Err(e) if e.to_string().contains("InsufficientPeers") => {
                // No mesh peers yet — queue exactly one BEACON so it fires the
                // moment the first peer subscribes.  Deduplicate: if one is
                // already queued from a previous tick, replace it with the fresh
                // (higher-nonce) envelope so peers always see the latest state.
                self.pending_broadcasts
                    .retain(|e| e.msg_type != MsgType::Beacon);
                if self.pending_broadcasts.len() < MAX_PENDING_BROADCASTS {
                    tracing::debug!("No mesh peers — queuing BEACON for flush");
                    self.pending_broadcasts.push(env);
                }
            }
            Err(e) => {
                tracing::warn!("BEACON publish failed: {e}");
            }
        }
    }

    // ========================================================================
    // Epoch management + on-chain batch submission
    // ========================================================================

    async fn check_epoch_boundary(&mut self, _swarm: &mut Swarm<Zx01Behaviour>) {
        let new_epoch = current_epoch();
        if new_epoch <= self.current_epoch {
            return;
        }

        tracing::info!(
            "Epoch boundary: {} → {}. Finalising batch.",
            self.current_epoch,
            new_epoch,
        );

        let leaves = match self.logger.advance_epoch(new_epoch) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Logger advance failed: {e}");
                return;
            }
        };

        let (batch, message_slots) =
            self.batch
                .finalize(self.identity.agent_id, self.current_slot, &leaves);
        let epoch = self.current_epoch;

        let batch_hash_hex = match batch.batch_hash() {
            Ok(hash) => {
                let h = hex::encode(hash);
                tracing::info!(
                    "Epoch {epoch} batch finalised: hash={h} messages={}",
                    batch.message_count,
                );
                h
            }
            Err(e) => {
                tracing::error!("Batch hash error: {e}");
                String::new()
            }
        };

        // Push batch snapshot to visualization API.
        let batch_snap = BatchSnapshot {
            agent_id: hex::encode(self.identity.agent_id),
            epoch,
            message_count: batch.message_count,
            log_merkle_root: hex::encode(batch.log_merkle_root),
            batch_hash: batch_hash_hex.clone(),
        };
        self.api.push_batch(batch_snap).await;
        self.api.send_event(ApiEvent::BatchSubmitted {
            epoch,
            message_count: batch.message_count,
            batch_hash: batch_hash_hex,
        });

        // GAP-04: Compute verifier ID histogram and push to aggregator
        let mut verifier_histogram: HashMap<String, u32> = HashMap::new();
        for assignment in &batch.verifier_ids {
            let vid = hex::encode(assignment.verifier_id);
            *verifier_histogram.entry(vid).or_insert(0) += 1;
        }

        if !verifier_histogram.is_empty() {
            self.push_to_aggregator(serde_json::json!({
                "msg_type":  "VERIFIER_HISTOGRAM",
                "agent_id":  hex::encode(batch.agent_id),
                "epoch":     batch.epoch_number,
                "histogram": verifier_histogram,
            }));
        }

        // Compute entropy vector and push to aggregator.
        let ev = zerox1_protocol::entropy::compute(
            &batch,
            &message_slots,
            &zerox1_protocol::entropy::EntropyParams::default(),
        );
        tracing::info!(
            "Epoch {epoch} entropy: ht={:?} hb={:?} hs={:?} hv={:?} anomaly={:.4}",
            ev.ht,
            ev.hb,
            ev.hs,
            ev.hv,
            ev.anomaly,
        );
        self.push_to_aggregator(serde_json::json!({
            "msg_type":  "ENTROPY",
            "agent_id":  hex::encode(ev.agent_id),
            "epoch":     ev.epoch,
            "ht":        ev.ht,
            "hb":        ev.hb,
            "hs":        ev.hs,
            "hv":        ev.hv,
            "anomaly":   ev.anomaly,
            "n_ht":      ev.n_ht,
            "n_hb":      ev.n_hb,
            "n_hs":      ev.n_hs,
            "n_hv":      ev.n_hv,
        }));

        // On-chain batch submission has been moved to settlement/solana.
        // The aggregator tracks batches off-chain via envelope ingest.
        tracing::debug!("Epoch {epoch} batch finalized (on-chain submission disabled).");

        self.current_epoch = new_epoch;
        self.batch = BatchAccumulator::new(new_epoch, self.current_slot);
        self.reputation.advance_epoch(new_epoch);

        // Purge stale identity-check failure cache entries (TTL = 1 hour).
        let ttl = std::time::Duration::from_secs(3_600);
        self.reg8004_failures
            .retain(|_, ts| ts.elapsed() < ttl);
        if self.reg8004_failures.len() > MAX_REG8004_FAILURE_CACHE {
            let over = self.reg8004_failures.len() - MAX_REG8004_FAILURE_CACHE;
            let mut by_age: Vec<_> = self
                .reg8004_failures
                .iter()
                .map(|(k, ts)| (*k, ts.elapsed()))
                .collect();
            by_age.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            for (k, _) in by_age.into_iter().take(over) {
                self.reg8004_failures.remove(&k);
            }
        }

        // Check own lease renewal at each epoch boundary.
        #[cfg(feature = "settlement")]
        self.maybe_renew_own_lease().await;
    }

    // ========================================================================
    // Inactivity enforcement
    // ========================================================================

    async fn check_inactive_agents(&self) {
        if self.dev_mode {
            return;
        }
        let _usdc_mint = match self.usdc_mint {
            Some(ref m) => *m,
            None => {
                tracing::debug!("Skipping inactivity check — no --usdc-mint configured.");
                return;
            }
        };

        let agents = self.peer_states.all_agent_ids();
        if agents.is_empty() {
            return;
        }

        tracing::debug!("Running inactivity check for {} known agents", agents.len());
        // On-chain inactivity slashing has been moved to settlement/solana.
        tracing::debug!("Inactivity check skipped (settlement decoupled).");
    }

    // ========================================================================
    // Aggregator push
    // ========================================================================

    // ========================================================================
    // SRI circuit breaker (GAP-06)
    // ========================================================================

    /// Query the aggregator's /system/sri endpoint.
    /// Returns true if the circuit breaker is active (SRI > 0.50).
    /// Fails open (returns false) if no aggregator is configured or the
    /// request fails, so a network partition never blocks honest nodes.
    #[allow(dead_code)]
    async fn check_sri_circuit_breaker(&self) -> bool {
        let url = match &self.aggregator_url {
            Some(u) => format!("{}/system/sri", u.trim_end_matches('/')),
            None => return false,
        };
        let client = self.http_client.clone();
        let secret = self.aggregator_secret.clone();
        let result: Result<bool, _> = async move {
            let mut req = client.get(&url);
            if let Some(s) = secret {
                req = req.header("Authorization", format!("Bearer {s}"));
            }
            let text = req.send().await?.text().await?;
            let val: serde_json::Value = serde_json::from_str(&text)?;
            Ok::<bool, anyhow::Error>(
                val.get("circuit_breaker_active")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            )
        }
        .await;
        match result {
            Ok(active) => {
                if active {
                    tracing::warn!("SRI circuit breaker is active (aggregator reports SRI > 0.50)");
                }
                active
            }
            Err(e) => {
                tracing::debug!("SRI check failed (fail-open): {e}");
                false
            }
        }
    }

    /// Forward a validated inbound envelope to the configured app webhook.
    ///
    /// Fires-and-forgets an HTTP POST with full envelope metadata. The app can
    /// react however it likes and call POST /envelopes/send on the node API to
    /// send back. 503/network errors are logged as warnings and ignored.
    fn push_to_app_webhook(&self, env: &Envelope) {
        let url = match &self.app_webhook_url {
            Some(u) => u.clone(),
            None => return,
        };

        // Apply type filter if configured.
        if !self.app_webhook_types.is_empty() {
            let type_str = format!("{:?}", env.msg_type).to_uppercase();
            if !self.app_webhook_types.contains(&type_str) {
                return;
            }
        }

        let payload = serde_json::json!({
            "msg_type":        format!("{:?}", env.msg_type),
            "sender":          hex::encode(env.sender),
            "recipient":       hex::encode(env.recipient),
            "conversation_id": hex::encode(env.conversation_id),
            "payload_b64":     base64::engine::general_purpose::STANDARD.encode(&env.payload),
            "timestamp":       env.timestamp,
            "slot":            env.block_ref,
            "nonce":           env.nonce,
        });

        let client = self.http_client.clone();
        let secret = self.app_webhook_secret.clone();
        tokio::spawn(async move {
            let mut req = client.post(&url).json(&payload);
            if let Some(s) = secret {
                req = req.header("Authorization", format!("Bearer {s}"));
            }
            match req.send().await {
                Ok(resp) if !resp.status().is_success() => {
                    tracing::warn!(
                        "App webhook returned HTTP {} for {} envelope",
                        resp.status(),
                        payload["msg_type"].as_str().unwrap_or("?"),
                    );
                }
                Err(e) => tracing::warn!("App webhook POST failed: {e}"),
                _ => {}
            }
        });
    }

    fn push_to_aggregator(&self, payload: serde_json::Value) {
        let url = match &self.aggregator_url {
            Some(u) => format!("{}/ingest/envelope", u.trim_end_matches('/')),
            None => return,
        };
        let client = self.http_client.clone();
        let secret = self.aggregator_secret.clone();
        tokio::spawn(async move {
            let mut req = client.post(&url).json(&payload);
            if let Some(s) = secret {
                req = req.header("Authorization", format!("Bearer {s}"));
            }
            if let Err(e) = req.send().await {
                tracing::warn!("Aggregator push failed: {e}");
            }
        });
    }

    fn track_conversation_peer(&mut self, conversation_id: [u8; 16], peer_id: PeerId) {
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.conversations.entry(conversation_id)
        {
            entry.insert(peer_id);
            self.conversation_lru.retain(|cid| *cid != conversation_id);
            self.conversation_lru.push_back(conversation_id);
            return;
        }

        while self.conversations.len() >= MAX_ACTIVE_CONVERSATIONS {
            if let Some(oldest) = self.conversation_lru.pop_front() {
                self.conversations.remove(&oldest);
            } else {
                break;
            }
        }

        self.conversations.insert(conversation_id, peer_id);
        self.conversation_lru.push_back(conversation_id);
    }

    // ========================================================================
    // Per-peer rate limiting
    // ========================================================================

    /// Returns false if the peer has exceeded MESSAGE_RATE_LIMIT in the
    /// current 1-second window. The caller should drop the message silently.
    fn check_rate_limit(&mut self, peer: &libp2p::PeerId) -> bool {
        use zerox1_protocol::constants::MESSAGE_RATE_LIMIT;
        let now = std::time::Instant::now();

        // Fast path: peer already tracked.
        if let Some(entry) = self.rate_limiter.get_mut(peer) {
            if now.duration_since(entry.1).as_secs() >= 1 {
                *entry = (1, now);
                return true;
            }
            if entry.0 >= MESSAGE_RATE_LIMIT {
                return false;
            }
            entry.0 += 1;
            return true;
        }

        // New peer — enforce cap before inserting.
        if self.rate_limiter.len() >= MAX_RATE_LIMITER_PEERS {
            // Evict entries whose window has already expired.
            self.rate_limiter
                .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 1);
            // If still at capacity, skip tracking this peer (allow the message).
            if self.rate_limiter.len() >= MAX_RATE_LIMITER_PEERS {
                tracing::debug!("rate_limiter at capacity — skipping tracking for {peer}");
                return true;
            }
        }

        self.rate_limiter.insert(*peer, (1, now));
        true
    }
}

fn validated_aggregator_url(url: Option<String>) -> Option<String> {
    let raw = url?;

    let parsed = match reqwest::Url::parse(&raw) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("Ignoring invalid --aggregator-url '{raw}': {e}");
            return None;
        }
    };

    let is_internal = match parsed.host() {
        Some(Host::Domain(h)) => {
            h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local")
        }
        Some(Host::Ipv4(ip)) => is_private_or_local_ip(IpAddr::V4(ip)),
        Some(Host::Ipv6(ip)) => is_private_or_local_ip(IpAddr::V6(ip)),
        None => false,
    };

    if parsed.scheme() != "https" && !is_internal {
        tracing::warn!("Ignoring non-HTTPS aggregator URL: {raw}");
        return None;
    }

    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => {
            tracing::warn!("Ignoring aggregator URL without host: {raw}");
            return None;
        }
    };

    if !is_internal {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_or_local_ip(ip) {
                tracing::warn!("Ignoring aggregator URL with local/private host: {raw}");
                return None;
            }
        } else {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let addrs: Vec<_> = match (host.as_str(), port).to_socket_addrs() {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    tracing::warn!("Ignoring aggregator URL; failed to resolve host '{host}': {e}");
                    return None;
                }
            };
            if addrs.is_empty() {
                tracing::warn!("Ignoring aggregator URL; host '{host}' resolved to no addresses");
                return None;
            }
            if addrs.iter().any(|addr| is_private_or_local_ip(addr.ip())) {
                tracing::warn!(
                    "Ignoring aggregator URL with host resolving to local/private IPs: {raw}"
                );
                return None;
            }
        }
    }

    Some(parsed.to_string())
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
        }
    }
}
