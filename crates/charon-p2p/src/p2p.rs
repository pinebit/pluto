#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(unused)]

//! P2P core concepts

use std::{sync::Once, time::Duration};

use libp2p::{
    Swarm, SwarmBuilder, identify,
    identity::Keypair,
    noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};

use libp2p::mdns;

use crate::{config::P2PConfig, gater::ConnGater};

#[derive(Debug, thiserror::Error)]
pub enum P2PError {
    /// Failed to build the swarm.
    #[error("Failed to build the swarm: {0}")]
    FailedToBuildSwarm(Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to convert the secret key to a libp2p keypair: {0}")]
    FailedToConvertSecretKeyToLibp2pKeypair(#[from] k256::pkcs8::der::Error),

    #[error("Failed to decode the libp2p keypair: {0}")]
    FailedToDecodeLibp2pKeypair(#[from] libp2p::identity::DecodingError),
}

impl P2PError {
    pub fn failed_to_build_swarm(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::FailedToBuildSwarm(Box::new(error))
    }
}

type Result<T> = std::result::Result<T, P2PError>;

pub enum NodeType {
    TCP,
    QUIC,
}

pub struct Node<B: NetworkBehaviour> {
    pub swarm: Swarm<B>,
}

impl<B: NetworkBehaviour> Node<B> {
    pub fn new<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        node_type: NodeType,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        match node_type {
            NodeType::TCP => {
                Self::new_with_tcp(cfg, key, conn_gater, filter_private_addrs, behaviour_fn)
            }
            NodeType::QUIC => {
                Self::new_with_quic(cfg, key, conn_gater, filter_private_addrs, behaviour_fn)
            }
        }
    }

    fn default_swarm_config(cfg: libp2p::swarm::Config) -> libp2p::swarm::Config {
        cfg.with_idle_connection_timeout(Duration::from_secs(300))
    }

    fn default_tcp_config() -> tcp::Config {
        tcp::Config::default()
    }

    pub fn new_with_quic<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let mut der = key.to_sec1_der()?;
        let keypair = Keypair::secp256k1_from_der(&mut der)?;

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                Self::default_tcp_config(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_quic()
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(Self::default_swarm_config)
            .build();

        Ok(Node { swarm })
    }

    pub fn new_with_tcp<F>(
        cfg: P2PConfig,
        key: k256::SecretKey,
        conn_gater: ConnGater,
        filter_private_addrs: bool,
        behaviour_fn: F,
    ) -> Result<Self>
    where
        F: Fn(&Keypair, relay::client::Behaviour) -> B,
    {
        let mut der = key.to_sec1_der().unwrap();
        let keypair = Keypair::secp256k1_from_der(&mut der).unwrap();

        let mut swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                Self::default_tcp_config(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(P2PError::failed_to_build_swarm)?
            .with_dns()
            .map_err(P2PError::failed_to_build_swarm)?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_behaviour(behaviour_fn)
            .map_err(P2PError::failed_to_build_swarm)?
            .with_swarm_config(Self::default_swarm_config)
            .build();

        Ok(Node { swarm })
    }
}
