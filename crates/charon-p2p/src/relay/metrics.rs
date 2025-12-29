use vise::*;

use crate::metrics::BUCKETS;

#[derive(Debug, Metrics)]
#[metrics(prefix = "relay_p2p")]
pub struct RelayMetrics {
    /// Total number of new connections by peer and cluster.
    connection_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Current number of active connections by peer and cluster.
    active_connections: Family<PeerWithPeerClusterLabels, Gauge>,

    /// Total number of network bytes sent to the peer and cluster.
    network_sent_bytes_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Total number of network bytes received from the peer and cluster.
    network_received_bytes_total: Family<PeerWithPeerClusterLabels, Counter>,

    /// Ping latency by peer and cluster.
    #[metrics(buckets = &BUCKETS)]
    ping_latency: Family<PeerWithPeerClusterLabels, Histogram>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EncodeLabelSet)]
pub struct PeerWithPeerClusterLabels {
    peer: String,
    peer_cluster: String,
}

#[vise::register]
pub static RELAY_METRICS: Global<RelayMetrics> = Global::new();
