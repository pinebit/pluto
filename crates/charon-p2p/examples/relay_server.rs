#![allow(missing_docs)]
use std::str::FromStr;

use charon_p2p::{
    config::P2PConfig,
    relay::{config::Config, p2p::run_relay_p2p_node},
};
use charon_tracing::TracingConfig;
use k256::SecretKey;
use libp2p::multiaddr;
use rand::rngs::OsRng;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::main]
async fn main() {
    charon_tracing::init(&TracingConfig::default()).unwrap();

    let config = Config::builder()
        .with_p2p_config(
            P2PConfig::builder()
                .with_tcp_addrs(vec![
                    multiaddr::Multiaddr::from_str("/ip4/0.0.0.0/tcp/0")
                        .unwrap()
                        .to_string(),
                ])
                .build(),
        )
        .with_max_conns(100)
        .with_max_res_per_peer(10)
        .with_http_addr(Some("0.0.0.0:8888".to_string()))
        .build();
    let key = SecretKey::random(&mut OsRng);

    let ct = CancellationToken::new();

    tokio::select! {
        result = run_relay_p2p_node(&config, key, ct.child_token()) => {
            result.unwrap();
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received, shutting down gracefully...");
            ct.cancel();
            
        }
    }

    info!("Shutdown complete");
}
