pub mod api;
pub mod task_log;
pub mod batch;
pub mod config;
pub mod identity;
pub mod logger;
pub mod network;
pub mod node;
pub mod peer_state;
pub mod push_notary;
pub mod reputation;

#[cfg(feature = "ios-ffi")]
pub mod ffi;

/// Run the node given an already-constructed `Config` and `AgentIdentity`.
///
/// This is the shared entry-point used by both the CLI binary (`main.rs`) and
/// the iOS FFI layer (`ffi.rs`).  It builds the libp2p swarm, dials the
/// bootstrap fleet, creates the `Zx01Node`, and drives the event loop to
/// completion (or until the tokio runtime is shut down).
pub async fn run_from_parts(
    mut config: config::Config,
    identity: identity::AgentIdentity,
) -> anyhow::Result<()> {
    tracing::info!(
        agent_id = %hex::encode(identity.agent_id),
        "0x01 node starting",
    );

    // ── Dashboard auto-setup ─────────────────────────────────────────────────
    // Default the API to loopback so the dashboard works out of the box.
    if config.api_addr.is_none() {
        config.api_addr = Some("127.0.0.1:9090".to_string());
    }

    // Auto-generate and persist a dashboard token when none is configured.
    // Stored in {log_dir}/dashboard_token so it survives restarts.
    // Ensure the hosted dashboard can reach the node API.
    // If no explicit origins are configured, always add the public dashboard so
    // browser-based dashboards (api.0x01.world) are not blocked by CORS.
    {
        const DASHBOARD_ORIGIN: &str = "https://dashboard.0x01.world";
        if !config.api_cors_origins.iter().any(|o| o == DASHBOARD_ORIGIN) {
            config.api_cors_origins.push(DASHBOARD_ORIGIN.to_string());
        }
    }

    if config.api_secret.is_none() {
        let token_path = config.log_dir.join("dashboard_token");
        let token = if token_path.exists() {
            std::fs::read_to_string(&token_path)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            use rand::Rng;
            let t: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            if let Err(e) = std::fs::write(&token_path, &t) {
                tracing::warn!("Could not persist dashboard token to {}: {e}", token_path.display());
            }
            t
        };
        if !token.is_empty() {
            config.api_secret = Some(token);
        }
    }

    // Default task log to {log_dir}/task_log.db so the dashboard jobs page works
    // without the user having to set ZX01_TASK_LOG_PATH explicitly.
    if config.task_log_path.is_none() {
        config.task_log_path = Some(config.log_dir.join("task_log.db"));
    }

    let bootstrap_peers = config.all_bootstrap_peers();
    let mut swarm = network::build_swarm(
        identity.libp2p_keypair.clone(),
        config.listen_addr.clone(),
        &bootstrap_peers,
        config.relay_server,
    )?;

    // Mobile / NAT-restricted mode: listen on a circuit relay address so that
    // peers can reach this node through the relay even from behind CGNAT.
    if let Some(ref relay_addr) = config.relay_addr {
        match swarm.listen_on(relay_addr.clone()) {
            Ok(_) => tracing::info!("Listening on relay circuit: {relay_addr}"),
            Err(e) => tracing::warn!("Failed to listen on relay circuit {relay_addr}: {e}"),
        }
    }

    tracing::info!(
        peer_id = %swarm.local_peer_id(),
        listen  = %config.listen_addr,
        "0x01 bootstrap multiaddr: {}/p2p/{}",
        config.listen_addr,
        swarm.local_peer_id(),
    );

    for addr in &bootstrap_peers {
        if let Err(e) = swarm.dial(addr.clone()) {
            tracing::warn!("Failed to dial bootstrap peer {addr}: {e}");
        }
    }

    let mut node = node::Zx01Node::new(config, identity, bootstrap_peers).await?;
    node.run(&mut swarm).await
}
