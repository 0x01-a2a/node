use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_node=info,libp2p=warn".parse().unwrap()),
        )
        .init();

    let config = zerox1_node::config::Config::parse();
    let identity =
        zerox1_node::identity::AgentIdentity::load_or_generate(&config.keypair_path)?;
    zerox1_node::run_from_parts(config, identity).await
}
