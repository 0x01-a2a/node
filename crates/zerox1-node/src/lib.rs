pub mod api;
#[cfg(feature = "bags")]
pub mod bags;
pub mod task_log;
pub mod batch;
pub mod config;
pub mod constants;
pub mod identity;
pub mod kora;
pub mod logger;
pub mod mpp;
pub mod network;
pub mod node;
pub mod peer_state;
pub mod push_notary;
pub mod registry_8004;
pub mod reputation;
#[cfg(feature = "trade")]
pub mod cpmm;
#[cfg(feature = "trade")]
pub mod launchlab;
#[cfg(feature = "trade")]
pub mod trade;

#[cfg(feature = "ios-ffi")]
pub mod ffi;

/// Run the node given an already-constructed `Config` and `AgentIdentity`.
///
/// This is the shared entry-point used by both the CLI binary (`main.rs`) and
/// the iOS FFI layer (`ffi.rs`).  It builds the libp2p swarm, dials the
/// bootstrap fleet, creates the `Zx01Node`, and drives the event loop to
/// completion (or until the tokio runtime is shut down).
pub async fn run_from_parts(
    config: config::Config,
    identity: identity::AgentIdentity,
) -> anyhow::Result<()> {
    tracing::info!(
        agent_id = %hex::encode(identity.agent_id),
        "0x01 node starting",
    );

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
