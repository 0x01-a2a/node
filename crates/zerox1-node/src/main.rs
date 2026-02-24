mod api;
mod batch;
mod challenge;
mod config;
mod identity;
mod inactive;
mod kora;
mod lease;
mod logger;
mod network;
mod node;
mod peer_state;
mod reputation;
mod submit;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_node=info,libp2p=warn".parse().unwrap()),
        )
        .init();

    let config = config::Config::parse();
    let sati_mint = config.sati_mint_bytes()?;
    let identity = identity::AgentIdentity::load_or_generate(&config.keypair_path, sati_mint)?;

    tracing::info!(
        agent_id = %hex::encode(identity.agent_id),
        "0x01 node starting",
    );

    let bootstrap_peers = config.all_bootstrap_peers();
    let mut swarm = network::build_swarm(
        identity.libp2p_keypair.clone(),
        config.listen_addr.clone(),
        &bootstrap_peers,
    )?;

    // Log the full multiaddr so operators can copy it into config.rs.
    tracing::info!(
        peer_id = %swarm.local_peer_id(),
        listen  = %config.listen_addr,
        "0x01 bootstrap multiaddr: {}/p2p/{}",
        config.listen_addr,
        swarm.local_peer_id(),
    );

    let mut node = node::Zx01Node::new(config, identity);
    node.run(&mut swarm).await
}
