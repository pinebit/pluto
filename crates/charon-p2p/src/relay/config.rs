use std::{path::PathBuf, time::Duration};

use charon_tracing::TracingConfig;
use libp2p::relay;

use crate::config::P2PConfig;

pub const ONE_HOUR_SECONDS: u64 = 60 * 60;
pub const ONE_MINUTE_SECONDS: u64 = 60;
pub const MB_32: u64 = 32 * 1024 * 1024;
pub const EXTERNAL_HOST_RESOLVE_INTERVAL: Duration = Duration::from_secs(5 * 60);

// todo: make more typed
/// Configuration for the relay P2P layer.
#[derive(Default, Debug, Clone)]
pub struct Config {
    /// The directory to store the relay data.
    pub data_dir: PathBuf,
    /// The HTTP address to listen on.
    pub http_addr: Option<String>,
    /// The monitoring address to listen on.
    pub monitoring_addr: String,
    /// The debug address to listen on.
    pub debug_addr: String,
    /// The P2P configuration.
    pub p2p_config: P2PConfig,
    /// The logging configuration.
    pub log_config: TracingConfig,
    /// Whether to automatically generate a P2P key.
    pub auto_p2p_key: bool,
    /// The maximum number of resources per peer.
    pub max_res_per_peer: usize,
    /// The maximum number of connections.
    pub max_conns: usize,
    /// Whether to filter private addresses.
    pub filter_private_addrs: bool,
    /// LibP2PLogLevel.
    pub libp2p_log_level: String,
}

impl Config {
    /// Creates a new configuration.
    pub fn new(
        data_dir: PathBuf,
        http_addr: Option<String>,
        monitoring_addr: String,
        debug_addr: String,
        p2p_config: P2PConfig,
        log_config: TracingConfig,
        auto_p2p_key: bool,
        max_res_per_peer: usize,
        max_conns: usize,
        filter_private_addrs: bool,
        libp2p_log_level: String,
    ) -> Self {
        Self {
            data_dir,
            http_addr,
            monitoring_addr,
            debug_addr,
            p2p_config,
            log_config,
            auto_p2p_key,
            max_res_per_peer,
            max_conns,
            filter_private_addrs,
            libp2p_log_level,
        }
    }

    /// Returns a new builder for configuring a relay P2P layer.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

/// Builder for [`Config`].
#[derive(Default, Debug, Clone)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Creates a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Sets the data directory.
    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.config.data_dir = data_dir;
        self
    }

    /// Sets the HTTP address.
    pub fn with_http_addr(mut self, http_addr: Option<String>) -> Self {
        self.config.http_addr = http_addr;
        self
    }

    /// Sets the monitoring address.
    pub fn with_monitoring_addr(mut self, monitoring_addr: String) -> Self {
        self.config.monitoring_addr = monitoring_addr;
        self
    }

    /// Sets the debug address.
    pub fn with_debug_addr(mut self, debug_addr: String) -> Self {
        self.config.debug_addr = debug_addr;
        self
    }

    /// Sets the P2P configuration.
    pub fn with_p2p_config(mut self, p2p_config: P2PConfig) -> Self {
        self.config.p2p_config = p2p_config;
        self
    }

    /// Sets the logging configuration.
    pub fn with_log_config(mut self, log_config: TracingConfig) -> Self {
        self.config.log_config = log_config;
        self
    }

    /// Sets whether to automatically generate a P2P key.
    pub fn with_auto_p2p_key(mut self, auto_p2p_key: bool) -> Self {
        self.config.auto_p2p_key = auto_p2p_key;
        self
    }

    /// Sets the maximum number of resources per peer.
    pub fn with_max_res_per_peer(mut self, max_res_per_peer: usize) -> Self {
        self.config.max_res_per_peer = max_res_per_peer;
        self
    }

    /// Sets the maximum number of connections.
    pub fn with_max_conns(mut self, max_conns: usize) -> Self {
        self.config.max_conns = max_conns;
        self
    }

    /// Sets whether to filter private addresses.
    pub fn with_filter_private_addrs(mut self, filter_private_addrs: bool) -> Self {
        self.config.filter_private_addrs = filter_private_addrs;
        self
    }

    /// Sets the LibP2P log level.
    pub fn with_libp2p_log_level(mut self, libp2p_log_level: String) -> Self {
        self.config.libp2p_log_level = libp2p_log_level;
        self
    }

    /// Builds the [`Config`].
    pub fn build(self) -> Config {
        self.config
    }
}

pub(crate) fn create_relay_config(config: &Config) -> relay::Config {
    relay::Config {
        max_reservations: config.max_conns,
        max_reservations_per_peer: config.max_res_per_peer,
        reservation_duration: Duration::from_secs(ONE_HOUR_SECONDS),
        reservation_rate_limiters: vec![],
        // todo(varex83): check if this is correct, since it's aligned with the original
        // implementation, but I'm not sure if it's the correct way to do it.
        // Would it be better to use max_res_per_peer * max_conns?
        max_circuits: config.max_res_per_peer,
        max_circuits_per_peer: config.max_res_per_peer,
        max_circuit_duration: Duration::from_secs(ONE_MINUTE_SECONDS),
        max_circuit_bytes: MB_32,
        circuit_src_rate_limiters: vec![],
    }
}
