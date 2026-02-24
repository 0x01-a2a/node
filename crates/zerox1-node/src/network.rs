use std::io;
use std::time::Duration;
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    gossipsub, identify, kad, mdns, noise, request_response, tcp, yamux,
    swarm::NetworkBehaviour,
    StreamProtocol,
};
use zerox1_protocol::constants::MAX_MESSAGE_SIZE;

/// libp2p protocol string for bilateral 0x01 envelopes.
pub const BILATERAL_PROTOCOL: &str = "/0x01/bilateral/1.0.0";

// ============================================================================
// Combined behaviour
// ============================================================================

#[derive(NetworkBehaviour)]
pub struct Zx01Behaviour {
    pub gossipsub:        gossipsub::Behaviour,
    pub kademlia:         kad::Behaviour<kad::store::MemoryStore>,
    pub mdns:             mdns::tokio::Behaviour,
    pub identify:         identify::Behaviour,
    pub request_response: request_response::Behaviour<Zx01Codec>,
}

// ============================================================================
// Length-prefixed request-response codec for bilateral envelopes
// ============================================================================

/// Simple 4-byte LE length prefix codec.
/// Request  = CBOR-encoded 0x01 envelope (Vec<u8>)
/// Response = 3-byte ACK b"ACK"
#[derive(Clone, Default)]
pub struct Zx01Codec;

#[async_trait]
impl request_response::Codec for Zx01Codec {
    type Protocol = StreamProtocol;
    type Request  = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T)
        -> io::Result<Self::Request>
    where T: AsyncRead + Unpin + Send {
        read_framed(io, MAX_MESSAGE_SIZE).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T)
        -> io::Result<Self::Response>
    where T: AsyncRead + Unpin + Send {
        read_framed(io, 64).await
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request)
        -> io::Result<()>
    where T: AsyncWrite + Unpin + Send {
        write_framed(io, &req).await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response)
        -> io::Result<()>
    where T: AsyncWrite + Unpin + Send {
        write_framed(io, &res).await
    }
}

async fn read_framed<T: AsyncRead + Unpin>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds limit"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed<T: AsyncWrite + Unpin>(io: &mut T, data: &[u8]) -> io::Result<()> {
    io.write_all(&(data.len() as u32).to_le_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await
}

// ============================================================================
// Swarm builder
// ============================================================================

pub fn build_swarm(
    keypair: libp2p::identity::Keypair,
    listen_addr: libp2p::Multiaddr,
    bootstrap_peers: &[libp2p::Multiaddr],
) -> anyhow::Result<libp2p::Swarm<Zx01Behaviour>> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            let gossip_cfg = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(MAX_MESSAGE_SIZE)
                .build()
                .expect("static gossipsub config is valid");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossip_cfg,
            )
            .expect("gossipsub init");

            let mut kademlia =
                kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
            kademlia.set_mode(Some(kad::Mode::Server));

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>)?;

            let identify = identify::Behaviour::new(identify::Config::new(
                "/0x01/identify/1.0.0".to_string(),
                key.public(),
            ));

            let request_response = request_response::Behaviour::<Zx01Codec>::new(
                [(
                    StreamProtocol::new(BILATERAL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            Ok(Zx01Behaviour {
                gossipsub,
                kademlia,
                mdns,
                identify,
                request_response,
            })
        })?
        .build();

    // Subscribe to all 0x01 pubsub topics
    for topic_str in [
        zerox1_protocol::constants::TOPIC_BROADCAST,
        zerox1_protocol::constants::TOPIC_NOTARY,
        zerox1_protocol::constants::TOPIC_REPUTATION,
    ] {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(topic_str))?;
    }

    // Add bootstrap peers to Kademlia
    for addr in bootstrap_peers {
        if let Some(peer_id) = addr.iter().find_map(|p| {
            if let libp2p::multiaddr::Protocol::P2p(pid) = p {
                Some(pid)
            } else {
                None
            }
        }) {
            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        }
    }

    swarm.listen_on(listen_addr)?;
    Ok(swarm)
}
