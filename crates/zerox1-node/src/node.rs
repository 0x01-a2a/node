use std::collections::HashMap;
use std::time::Duration;

use zerox1_sati_client::client::SatiClient;
use ed25519_dalek::VerifyingKey;
use futures::StreamExt;
use libp2p::{
    gossipsub, identify, kad, mdns, request_response, swarm::SwarmEvent, PeerId, Swarm,
};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;

use zerox1_protocol::{
    batch::{FeedbackEvent, TaskSelection, TypedBid, VerifierAssignment},
    envelope::{Envelope, BROADCAST_RECIPIENT},
    message::MsgType,
    payload::FeedbackPayload,
    constants::{TOPIC_BROADCAST, TOPIC_NOTARY, TOPIC_REPUTATION},
};

use solana_sdk::pubkey::Pubkey;

use crate::{
    api::{ApiEvent, ApiState, BatchSnapshot, OutboundRequest, PeerSnapshot, ReputationSnapshot,
          SentConfirmation},
    batch::{current_epoch, now_micros, BatchAccumulator},
    config::Config,
    identity::AgentIdentity,
    inactive,
    kora::KoraClient,
    lease,
    logger::EnvelopeLogger,
    network::{Zx01Behaviour, Zx01BehaviourEvent},
    peer_state::PeerStateMap,
    reputation::ReputationTracker,
    submit,
};

// ============================================================================
// Payload layout conventions (documented for agent application authors)
//
// BEACON:          [agent_id(32)][verifying_key(32)][name(utf-8)]
// PROPOSE/COUNTER: [bid_value(16, LE i128)][opaque agent payload...]
// NOTARIZE_ASSIGN: [verifier_agent_id(32)][opaque...]
// ============================================================================

const BEACON_VK_OFFSET:                usize = 32;
const BEACON_NAME_OFFSET:              usize = 64;
const BID_VALUE_LEN:                   usize = 16;
const NOTARIZE_ASSIGN_VERIFIER_OFFSET: usize = 32;

/// Maximum bytes read from BEACON name field.
const MAX_NAME_LEN: usize = 64;
/// Maximum tracked conversations (bilateral message sender ↔ conversation).
const MAX_ACTIVE_CONVERSATIONS: usize = 10_000;

// ============================================================================
// Zx01Node
// ============================================================================

pub struct Zx01Node {
    pub config:      Config,
    pub identity:    AgentIdentity,
    pub peer_states: PeerStateMap,
    pub reputation:  ReputationTracker,
    pub logger:      EnvelopeLogger,
    pub batch:       BatchAccumulator,

    /// Nonblocking Solana RPC client (slot polling + batch submission).
    rpc:  RpcClient,
    /// SATI registration checker.
    sati: SatiClient,
    /// Kora paymaster client — present when --kora-url is configured.
    /// Enables gasless on-chain transactions (gas reimbursed in USDC, §4.4).
    kora: Option<KoraClient>,
    /// True when running without a SATI mint (testing / local dev).
    /// In dev mode, SATI failures produce warnings instead of message drops.
    dev_mode: bool,
    /// Visualization API shared state (always present; server only started when
    /// --api-addr is configured).
    api: ApiState,

    nonce:         u64,
    current_slot:  u64,
    current_epoch: u64,
    conversations: HashMap<[u8; 16], PeerId>,

    /// Receives outbound envelope requests from the Agent API (POST /envelopes/send).
    outbound_rx: tokio::sync::mpsc::Receiver<OutboundRequest>,

    /// USDC mint pubkey — used for inactivity slash bounty payout.
    usdc_mint: Option<Pubkey>,
    /// Reputation aggregator base URL — FEEDBACK/VERDICT envelopes are pushed here.
    aggregator_url: Option<String>,
    /// Shared secret sent in Authorization header when pushing to the aggregator.
    aggregator_secret: Option<String>,
    /// Shared HTTP client for aggregator pushes — avoids per-push TCP setup.
    http_client: reqwest::Client,
    /// Per-peer message rate limiter: PeerId → (count_in_window, window_start).
    rate_limiter: std::collections::HashMap<libp2p::PeerId, (u32, std::time::Instant)>,
}

impl Zx01Node {
    pub fn new(config: Config, identity: AgentIdentity) -> Self {
        let epoch          = current_epoch();
        let log_dir        = config.log_dir.clone();
        let rpc            = RpcClient::new(config.rpc_url.clone());
        let sati           = SatiClient::new(&config.rpc_url);
        // "none" disables Kora entirely; otherwise use the configured URL.
        let kora = if config.kora_url.eq_ignore_ascii_case("none") {
            None
        } else {
            Some(KoraClient::new(&config.kora_url))
        };
        let dev_mode       = config.sati_mint.is_none();
        let usdc_mint         = config.usdc_mint_pubkey().ok().flatten();
        let aggregator_url    = config.aggregator_url.clone();
        let aggregator_secret = config.aggregator_secret.clone();
        let (api, outbound_rx) = ApiState::new(identity.agent_id);
        let batch    = BatchAccumulator::new(epoch, 0);
        let logger   = EnvelopeLogger::new(log_dir, epoch);

        if dev_mode {
            tracing::warn!(
                "Running in dev mode (no --sati-mint). \
                 SATI verification is advisory only — unregistered peers are allowed."
            );
        }

        if kora.is_some() {
            tracing::info!("Kora paymaster enabled — on-chain transactions use gasless USDC path.");
        } else {
            tracing::info!("No --kora-url set — on-chain transactions require SOL for gas.");
        }

        Self {
            config,
            identity,
            peer_states:   PeerStateMap::new(),
            reputation:    ReputationTracker::new(),
            logger,
            batch,
            rpc,
            sati,
            kora,
            dev_mode,
            api,
            nonce:         0,
            current_slot:  0,
            current_epoch: epoch,
            conversations: HashMap::new(),
            outbound_rx,
            usdc_mint,
            aggregator_url,
            aggregator_secret,
            http_client: reqwest::Client::new(),
            rate_limiter: std::collections::HashMap::new(),
        }
    }

    // ========================================================================
    // Main event loop
    // ========================================================================

    pub async fn run(&mut self, swarm: &mut Swarm<Zx01Behaviour>) -> anyhow::Result<()> {
        // ── Visualization API server ─────────────────────────────────────────
        if let Some(ref addr_str) = self.config.api_addr.clone() {
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(addr) => {
                    let api = self.api.clone();
                    tokio::spawn(crate::api::serve(api, addr));
                }
                Err(e) => tracing::warn!("Invalid --api-addr '{addr_str}': {e}"),
            }
        }

        // ── Startup lease check ───────────────────────────────────────────────
        // Verify our own agent's lease before joining the mesh.
        self.check_own_lease().await?;

        let mut beacon_timer   = tokio::time::interval(Duration::from_secs(60));
        let mut epoch_timer    = tokio::time::interval(Duration::from_secs(30));
        let mut slot_timer     = tokio::time::interval(Duration::from_millis(400));
        // Inactivity check: once per hour is sufficient; skip in dev mode.
        let mut inactive_timer = tokio::time::interval(Duration::from_secs(3_600));

        self.send_beacon(swarm).await;

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    self.handle_swarm_event(swarm, event).await;
                }
                Some(req) = self.outbound_rx.recv() => {
                    self.handle_outbound(swarm, req).await;
                }
                _ = beacon_timer.tick() => {
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
            }
        }
    }

    // ========================================================================
    // Own lease management
    // ========================================================================

    /// Check this agent's own lease on startup.
    ///
    /// - No account: warn (agent must call `init_lease` before running)
    /// - Deactivated: fatal — refuse to start
    /// - Grace period: warn, continue (but should pay ASAP)
    /// - Needs renewal: auto-renew immediately
    async fn check_own_lease(&mut self) -> anyhow::Result<()> {
        if self.dev_mode {
            tracing::debug!("Dev mode — skipping own lease check.");
            return Ok(());
        }

        match lease::get_lease_status(&self.rpc, &self.identity.agent_id).await {
            Ok(None) => {
                tracing::warn!(
                    "No lease account found for agent {}. \
                     Call `init_lease` before running on the mesh.",
                    hex::encode(self.identity.agent_id),
                );
            }
            Ok(Some(status)) => {
                if status.deactivated {
                    anyhow::bail!(
                        "Agent {} is DEACTIVATED — lease expired beyond grace period. \
                         Cannot join the mesh.",
                        hex::encode(self.identity.agent_id),
                    );
                }
                if status.in_grace_period {
                    tracing::warn!(
                        "Agent {} is in grace period (paid_through={}, current={}). \
                         Pay lease immediately to avoid deactivation.",
                        hex::encode(self.identity.agent_id),
                        status.paid_through_epoch,
                        status.current_epoch,
                    );
                }
                if status.needs_renewal() {
                    tracing::info!("Lease near expiry — auto-renewing.");
                    self.renew_own_lease().await;
                } else {
                    tracing::info!(
                        "Lease OK: paid_through_epoch={} current_epoch={}",
                        status.paid_through_epoch,
                        status.current_epoch,
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Lease check failed (RPC): {e}. Continuing in optimistic mode.");
            }
        }
        Ok(())
    }

    /// Check if own lease needs renewal and pay if so.
    /// Called at each epoch boundary.
    async fn maybe_renew_own_lease(&mut self) {
        if self.dev_mode {
            return;
        }
        match lease::get_lease_status(&self.rpc, &self.identity.agent_id).await {
            Ok(Some(status)) if status.needs_renewal() => {
                self.renew_own_lease().await;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!("Own lease account not found at epoch boundary.");
            }
            Err(e) => {
                tracing::warn!("Lease check at epoch boundary failed: {e}");
            }
        }
    }

    async fn renew_own_lease(&mut self) {
        if let Err(e) = lease::pay_lease_onchain(
            &self.rpc,
            &self.identity,
            self.kora.as_ref(),
        ).await {
            tracing::error!("Lease renewal failed: {e}");
        }
    }

    // ========================================================================
    // Peer lease verification
    // ========================================================================

    /// Query lease status for `agent_id` and cache in peer_states.
    ///
    /// On RPC error: leaves status as None (will retry on next BEACON).
    async fn verify_peer_lease(&mut self, agent_id: [u8; 32]) {
        match lease::get_lease_status(&self.rpc, &agent_id).await {
            Ok(Some(status)) => {
                let active = status.is_active();
                self.peer_states.set_lease_status(agent_id, active);
                self.api.send_event(ApiEvent::LeaseStatus {
                    agent_id: hex::encode(agent_id),
                    active,
                });
                if active {
                    tracing::debug!(
                        "Lease: agent {} ✓ active (paid_through={})",
                        hex::encode(agent_id),
                        status.paid_through_epoch,
                    );
                } else {
                    tracing::warn!(
                        "Lease: agent {} DEACTIVATED — messages will be dropped",
                        hex::encode(agent_id),
                    );
                }
            }
            Ok(None) => {
                // No lease account — treat as inactive in prod mode.
                self.peer_states.set_lease_status(agent_id, false);
                tracing::warn!(
                    "Lease: no account for agent {} — treating as inactive",
                    hex::encode(agent_id),
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Lease check failed for {}: {e} (will retry on next BEACON)",
                    hex::encode(agent_id),
                );
            }
        }
    }

    /// Returns true if this agent's messages should pass the lease gate.
    ///
    /// - Dev mode: always true
    /// - Prod mode: false only when lease_status = Some(false)
    fn lease_gate_allows(&self, agent_id: &[u8; 32]) -> bool {
        if self.dev_mode {
            return true;
        }
        match self.peer_states.lease_status(agent_id) {
            Some(false) => false,
            _ => true,
        }
    }

    // ========================================================================
    // Slot polling
    // ========================================================================

    async fn poll_slot(&mut self) {
        match self.rpc.get_slot().await {
            Ok(slot) => self.current_slot = slot,
            Err(e)   => tracing::trace!("Slot poll failed: {e}"),
        }
    }

    // ========================================================================
    // SATI registration verification
    // ========================================================================

    /// Query SATI for `agent_id` and cache the result in peer_states.
    ///
    /// On RPC error the status is left as `None` (unchecked) so the next
    /// message triggers a fresh attempt — infrastructure failures must not
    /// permanently block legitimate agents.
    async fn verify_sati_registration(&mut self, agent_id: [u8; 32]) {
        match self.sati.is_registered(&agent_id).await {
            Ok(true) => {
                self.peer_states.set_sati_status(agent_id, true);
                self.api.send_event(ApiEvent::SatiStatus {
                    agent_id:   hex::encode(agent_id),
                    registered: true,
                });
                tracing::info!(
                    "SATI: agent {} ✓ registered",
                    hex::encode(agent_id),
                );
            }
            Ok(false) => {
                self.peer_states.set_sati_status(agent_id, false);
                self.api.send_event(ApiEvent::SatiStatus {
                    agent_id:   hex::encode(agent_id),
                    registered: false,
                });
                if self.dev_mode {
                    tracing::debug!(
                        "SATI: agent {} not registered (dev mode — allowed)",
                        hex::encode(agent_id),
                    );
                } else {
                    tracing::warn!(
                        "SATI: agent {} NOT registered — future messages will be dropped",
                        hex::encode(agent_id),
                    );
                }
            }
            Err(e) => {
                // RPC failure: leave sati_status as None so we retry next time.
                tracing::warn!(
                    "SATI check failed for {}: {e} (will retry on next BEACON)",
                    hex::encode(agent_id),
                );
            }
        }
    }

    /// Returns true if this agent's messages should be forwarded.
    ///
    /// In dev mode: always true (warn on unregistered).
    /// In prod mode: true only if SATI status is confirmed `Some(true)` or
    ///               still `None` (not yet checked — optimistic until BEACON fires check).
    fn sati_gate_allows(&self, agent_id: &[u8; 32]) -> bool {
        match self.peer_states.sati_status(agent_id) {
            Some(false) if !self.dev_mode => false,
            _ => true,
        }
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
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                tracing::debug!("Connected to {peer_id} via {endpoint:?}");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::debug!("Disconnected from {peer_id}");
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
                self.handle_pubsub_message(swarm, propagation_source, message).await;
            }
            Zx01BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                tracing::debug!("{peer_id} subscribed to {topic}");
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
                tracing::debug!("Identified {peer_id}: agent={}", info.agent_version);
                for addr in &info.listen_addrs {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                }
                if let Ok(ed_pk) = info.public_key.try_into_ed25519() {
                    if let Ok(vk) = VerifyingKey::from_bytes(&ed_pk.to_bytes()) {
                        self.peer_states.set_key_for_peer(&peer_id, vk);
                    }
                }
            }
            Zx01BehaviourEvent::Identify(_) => {}

            Zx01BehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
                ..
            }) => match message {
                request_response::Message::Request { request, channel, .. } => {
                    self.handle_bilateral_request(swarm, peer, request, channel).await;
                }
                request_response::Message::Response { response, .. } => {
                    tracing::trace!("Bilateral ACK from {peer}: {:?}", response);
                }
            },
            Zx01BehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                peer, error, ..
            }) => {
                tracing::warn!("Bilateral outbound failure to {peer}: {error}");
            }
            Zx01BehaviourEvent::RequestResponse(request_response::Event::InboundFailure {
                peer, error, ..
            }) => {
                tracing::warn!("Bilateral inbound failure from {peer}: {error}");
            }
            Zx01BehaviourEvent::RequestResponse(_) => {}
        }
    }

    // ========================================================================
    // Pubsub message handling
    // ========================================================================

    async fn handle_pubsub_message(
        &mut self,
        _swarm:      &mut Swarm<Zx01Behaviour>,
        source_peer: PeerId,
        message:     gossipsub::Message,
    ) {
        // Drop if peer is flooding above the allowed rate.
        if !self.check_rate_limit(&source_peer) {
            tracing::debug!("Rate limit exceeded for pubsub peer {source_peer} — dropping");
            return;
        }

        let topic_str = message.topic.as_str();

        let env = match Envelope::from_cbor(&message.data) {
            Ok(e)  => e,
            Err(e) => {
                tracing::debug!("Pubsub CBOR decode failed from {source_peer}: {e}");
                return;
            }
        };

        // BEACON: extract + register VK before VK lookup (self-authenticating).
        // The SATI check is deferred to after signature validation so we don't
        // pay RPC latency on malformed / unvalidatable BEACONs.
        if env.msg_type == MsgType::Beacon {
            self.process_beacon_payload(&env, source_peer);
        }

        // VK gate — only BEACON can register a VK; no fallback.
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

        // Validate envelope signature + nonce + timestamp.
        let last_nonce = self.peer_states.last_nonce(&env.sender);
        if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
            tracing::debug!("Envelope validation failed from {source_peer}: {e}");
            return;
        }

        // SATI + Lease gates — checked after signature validation.
        // BEACONs are exempt: they ARE the trigger for both checks.
        if env.msg_type == MsgType::Beacon {
            if self.peer_states.sati_status(&env.sender).is_none() {
                self.verify_sati_registration(env.sender).await;
            }
            if self.peer_states.lease_status(&env.sender).is_none() {
                self.verify_peer_lease(env.sender).await;
            }
        } else {
            if !self.sati_gate_allows(&env.sender) {
                tracing::warn!(
                    "Dropping {} from unregistered agent {}",
                    env.msg_type,
                    hex::encode(env.sender),
                );
                return;
            }
            if !self.lease_gate_allows(&env.sender) {
                tracing::warn!(
                    "Dropping {} from deactivated agent {}",
                    env.msg_type,
                    hex::encode(env.sender),
                );
                return;
            }
        }

        // Update peer state.
        self.peer_states.update_nonce(env.sender, env.nonce);
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation.record_activity(env.sender, self.current_epoch);

        // Log envelope.
        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        // Emit visualization event.
        self.api.send_event(ApiEvent::Envelope {
            sender:   hex::encode(env.sender),
            msg_type: format!("{:?}", env.msg_type),
            slot:     self.current_slot,
        });

        // Push to agent inbox.
        self.api.push_inbound(&env, self.current_slot);

        self.batch.record_message(env.msg_type, env.sender);

        // Route.
        if topic_str == TOPIC_REPUTATION && env.msg_type == MsgType::Feedback {
            self.handle_feedback_envelope(&env);
        } else if topic_str == TOPIC_NOTARY && env.msg_type == MsgType::NotarizeBid {
            tracing::info!(
                "NOTARIZE_BID from {} (conversation {})",
                hex::encode(env.sender),
                hex::encode(env.conversation_id),
            );
        } else if topic_str == TOPIC_BROADCAST {
            match env.msg_type {
                MsgType::Advertise => {
                    tracing::info!(
                        "ADVERTISE from {} ({} bytes)",
                        hex::encode(env.sender),
                        env.payload.len(),
                    );
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
        swarm:   &mut Swarm<Zx01Behaviour>,
        peer_id: PeerId,
        data:    Vec<u8>,
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

        let env = match Envelope::from_cbor(&data) {
            Ok(e)  => e,
            Err(e) => {
                tracing::debug!("Bilateral CBOR decode failed from {peer_id}: {e}");
                return;
            }
        };

        let vk = match self.peer_states.verifying_key(&env.sender).copied() {
            Some(vk) => vk,
            None => {
                tracing::debug!(
                    "No VK for bilateral sender {}",
                    hex::encode(env.sender),
                );
                return;
            }
        };

        let last_nonce = self.peer_states.last_nonce(&env.sender);
        if let Err(e) = env.validate(last_nonce, &vk, now_micros()) {
            tracing::debug!("Bilateral validation failed from {peer_id}: {e}");
            return;
        }

        // SATI + Lease gates for bilateral messages.
        if !self.sati_gate_allows(&env.sender) {
            tracing::warn!(
                "Dropping bilateral {} from unregistered agent {}",
                env.msg_type,
                hex::encode(env.sender),
            );
            return;
        }
        if !self.lease_gate_allows(&env.sender) {
            tracing::warn!(
                "Dropping bilateral {} from deactivated agent {}",
                env.msg_type,
                hex::encode(env.sender),
            );
            return;
        }

        self.peer_states.update_nonce(env.sender, env.nonce);
        self.peer_states.touch_epoch(env.sender, self.current_epoch);
        self.reputation.record_activity(env.sender, self.current_epoch);

        if let Err(e) = self.logger.log(&env) {
            tracing::warn!("Logger error: {e}");
        }

        self.batch.record_message(env.msg_type, env.sender);
        // Cap conversation map to prevent memory exhaustion from message floods.
        if self.conversations.len() >= MAX_ACTIVE_CONVERSATIONS {
            if let Some(&oldest_id) = self.conversations.keys().next() {
                self.conversations.remove(&oldest_id);
            }
        }
        self.conversations.insert(env.conversation_id, peer_id);

        // Push to agent inbox.
        self.api.push_inbound(&env, self.current_slot);

        match env.msg_type {
            MsgType::Propose | MsgType::Counter => {
                // Convention: first 16 bytes of payload = LE i128 bid amount.
                let bid_value: i128 = if env.payload.len() >= BID_VALUE_LEN {
                    i128::from_le_bytes(
                        env.payload[..BID_VALUE_LEN].try_into().unwrap(),
                    )
                } else {
                    0
                };
                self.batch.add_bid(TypedBid {
                    conversation_id: env.conversation_id,
                    counterparty:    env.sender,
                    bid_value,
                    slot:            self.current_slot,
                });
            }
            MsgType::Accept => {
                self.batch.record_accept(TaskSelection {
                    conversation_id: env.conversation_id,
                    counterparty:    env.sender,
                    slot:            self.current_slot,
                });
            }
            MsgType::NotarizeAssign => {
                if env.payload.len() >= NOTARIZE_ASSIGN_VERIFIER_OFFSET {
                    let mut vid = [0u8; 32];
                    vid.copy_from_slice(&env.payload[..NOTARIZE_ASSIGN_VERIFIER_OFFSET]);
                    self.batch.record_notarize_assign(VerifierAssignment {
                        conversation_id: env.conversation_id,
                        verifier_id:     vid,
                        slot:            self.current_slot,
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
            MsgType::Dispute => {
                self.batch.record_dispute();
                self.reputation.record_dispute(env.sender);
                tracing::warn!(
                    "DISPUTE from {} on conversation {}",
                    hex::encode(env.sender),
                    hex::encode(env.conversation_id),
                );
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
                }));

                // Update reputation snapshot.
                if let Some(rv) = self.reputation.get(&fb.target_agent) {
                    let snap = ReputationSnapshot {
                        agent_id:          hex::encode(fb.target_agent),
                        reliability:       rv.reliability_score,
                        cooperation:       rv.cooperation_index,
                        notary_accuracy:   rv.notary_accuracy,
                        total_tasks:       rv.total_tasks,
                        total_disputes:    rv.total_disputes,
                        last_active_epoch: rv.last_active_epoch,
                    };
                    self.api.send_event(ApiEvent::ReputationUpdate {
                        agent_id:    hex::encode(fb.target_agent),
                        reliability: rv.reliability_score,
                        cooperation: rv.cooperation_index,
                    });
                    let api = self.api.clone();
                    let target = fb.target_agent;
                    tokio::spawn(async move { api.upsert_reputation(target, snap).await });
                }
                if fb.target_agent == self.identity.agent_id {
                    self.batch.record_feedback(FeedbackEvent {
                        conversation_id:       fb.conversation_id,
                        from_agent:            env.sender,
                        score:                 fb.score,
                        outcome:               fb.outcome,
                        role:                  fb.role,
                        slot:                  self.current_slot,
                        sati_attestation_hash: [0u8; 32],
                    });
                }
            }
            Err(e) => tracing::debug!("FEEDBACK payload parse failed: {e}"),
        }
    }

    // ========================================================================
    // BEACON processing
    // ========================================================================

    fn process_beacon_payload(&mut self, env: &Envelope, source_peer: PeerId) {
        let p = &env.payload;
        if p.len() < BEACON_NAME_OFFSET {
            return;
        }

        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&p[BEACON_VK_OFFSET..BEACON_VK_OFFSET + 32]);

        if let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) {
            self.peer_states.set_verifying_key(env.sender, vk);
            self.peer_states.register_peer(env.sender, source_peer);
            tracing::info!(
                "BEACON: registered agent {} (peer {source_peer})",
                hex::encode(env.sender),
            );

            // Update peer snapshot and emit event.
            let snap = PeerSnapshot {
                agent_id:          hex::encode(env.sender),
                peer_id:           Some(source_peer.to_string()),
                sati_ok:           self.peer_states.sati_status(&env.sender),
                lease_ok:          self.peer_states.lease_status(&env.sender),
                last_active_epoch: self.peer_states.last_active_epoch(&env.sender),
            };
            self.api.send_event(ApiEvent::PeerRegistered {
                agent_id: hex::encode(env.sender),
                peer_id:  source_peer.to_string(),
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
            }
        }
    }

    // ========================================================================
    // Outbound helpers
    // ========================================================================

    pub fn build_envelope(
        &mut self,
        msg_type:        MsgType,
        recipient:       [u8; 32],
        conversation_id: [u8; 16],
        payload:         Vec<u8>,
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
        env:   &Envelope,
    ) -> anyhow::Result<()> {
        let topic_str = if env.msg_type.is_broadcast() {
            TOPIC_BROADCAST
        } else if env.msg_type.is_notary_pubsub() {
            TOPIC_NOTARY
        } else if env.msg_type.is_reputation_pubsub() {
            TOPIC_REPUTATION
        } else {
            anyhow::bail!("msg_type {:?} is not a pubsub type", env.msg_type);
        };

        let cbor = env.to_cbor()?;
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossipsub::IdentTopic::new(topic_str), cbor)
            .map_err(|e| anyhow::anyhow!("gossipsub publish: {e:?}"))?;
        Ok(())
    }

    pub fn send_bilateral(
        &self,
        swarm:   &mut Swarm<Zx01Behaviour>,
        peer_id: PeerId,
        env:     &Envelope,
    ) -> anyhow::Result<()> {
        let cbor = env.to_cbor()?;
        swarm.behaviour_mut().request_response.send_request(&peer_id, cbor);
        Ok(())
    }

    // ========================================================================
    // Outbound request handler (from Agent API)
    // ========================================================================

    async fn handle_outbound(
        &mut self,
        swarm: &mut Swarm<Zx01Behaviour>,
        req:   OutboundRequest,
    ) {
        self.nonce += 1;

        let env = self.build_envelope(
            req.msg_type,
            req.recipient,
            req.conversation_id,
            req.payload,
        );

        let payload_hash = hex::encode(env.payload_hash);
        let nonce        = env.nonce;

        // Route: pubsub or bilateral.
        let result = if req.msg_type.is_broadcast()
            || req.msg_type.is_notary_pubsub()
            || req.msg_type.is_reputation_pubsub()
        {
            self.publish_envelope(swarm, &env)
                .map_err(|e| e.to_string())
        } else {
            match self.peer_states.peer_id_for_agent(&req.recipient) {
                Some(peer_id) => self.send_bilateral(swarm, peer_id, &env)
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
                self.batch.record_message(req.msg_type, self.identity.agent_id);
                tracing::debug!("Sent {} nonce={nonce}", req.msg_type);
            }
            Err(e) => tracing::warn!("Outbound send failed: {e}"),
        }

        let _ = req.reply.send(result.map(|_| SentConfirmation { nonce, payload_hash }));
    }

    // ========================================================================
    // BEACON heartbeat
    // ========================================================================

    async fn send_beacon(&mut self, swarm: &mut Swarm<Zx01Behaviour>) {
        let mut payload = Vec::with_capacity(64 + self.config.agent_name.len());
        payload.extend_from_slice(&self.identity.agent_id);
        payload.extend_from_slice(&self.identity.verifying_key.to_bytes());
        payload.extend_from_slice(self.config.agent_name.as_bytes());

        let env = self.build_envelope(
            MsgType::Beacon,
            BROADCAST_RECIPIENT,
            [0u8; 16],
            payload,
        );

        if let Err(e) = self.publish_envelope(swarm, &env) {
            tracing::warn!("BEACON publish failed: {e}");
        } else {
            tracing::debug!("BEACON sent (nonce={})", self.nonce);
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
            self.current_epoch, new_epoch,
        );

        let leaves = match self.logger.advance_epoch(new_epoch) {
            Ok(l)  => l,
            Err(e) => {
                tracing::error!("Logger advance failed: {e}");
                return;
            }
        };

        let batch = self.batch.finalize(
            self.identity.agent_id,
            self.current_slot,
            &leaves,
        );
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
            agent_id:        hex::encode(self.identity.agent_id),
            epoch,
            message_count:   batch.message_count,
            log_merkle_root: hex::encode(batch.log_merkle_root),
            batch_hash:      batch_hash_hex.clone(),
        };
        self.api.push_batch(batch_snap).await;
        self.api.send_event(ApiEvent::BatchSubmitted {
            epoch,
            message_count: batch.message_count,
            batch_hash:    batch_hash_hex,
        });

        if let Err(e) = submit::submit_batch_onchain(
            &self.rpc,
            &self.identity,
            &batch,
            epoch,
            self.kora.as_ref(),
        ).await {
            tracing::error!("Batch submission failed for epoch {epoch}: {e}");
        }

        self.current_epoch = new_epoch;
        self.batch = BatchAccumulator::new(new_epoch, self.current_slot);
        self.reputation.advance_epoch(new_epoch);

        // Check own lease renewal at each epoch boundary.
        self.maybe_renew_own_lease().await;
    }

    // ========================================================================
    // Inactivity enforcement
    // ========================================================================

    async fn check_inactive_agents(&self) {
        if self.dev_mode {
            return;
        }
        let usdc_mint = match self.usdc_mint {
            Some(ref m) => *m,
            None => {
                tracing::debug!(
                    "Skipping inactivity check — no --usdc-mint configured."
                );
                return;
            }
        };

        let agents = self.peer_states.all_agent_ids();
        if agents.is_empty() {
            return;
        }

        tracing::debug!("Running inactivity check for {} known agents", agents.len());
        inactive::check_and_slash_inactive(
            &self.rpc,
            &self.identity,
            self.kora.as_ref(),
            &usdc_mint,
            &agents,
        ).await;
    }

    // ========================================================================
    // Aggregator push
    // ========================================================================

    fn push_to_aggregator(&self, payload: serde_json::Value) {
        let url = match &self.aggregator_url {
            Some(u) => format!("{}/ingest/envelope", u.trim_end_matches('/')),
            None    => return,
        };
        let client = self.http_client.clone();
        let secret = self.aggregator_secret.clone();
        tokio::spawn(async move {
            let mut req = client.post(&url).json(&payload);
            if let Some(s) = secret {
                req = req.header("Authorization", format!("Bearer {s}"));
            }
            if let Err(e) = req.send().await {
                tracing::debug!("Aggregator push failed: {e}");
            }
        });
    }

    // ========================================================================
    // Per-peer rate limiting
    // ========================================================================

    /// Returns false if the peer has exceeded MESSAGE_RATE_LIMIT in the
    /// current 1-second window. The caller should drop the message silently.
    fn check_rate_limit(&mut self, peer: &libp2p::PeerId) -> bool {
        use zerox1_protocol::constants::MESSAGE_RATE_LIMIT;
        let now = std::time::Instant::now();
        let entry = self.rate_limiter.entry(*peer).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 1 {
            // New window — reset counter.
            *entry = (1, now);
            true
        } else if entry.0 >= MESSAGE_RATE_LIMIT {
            false
        } else {
            entry.0 += 1;
            true
        }
    }
}
