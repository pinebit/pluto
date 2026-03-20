//! Partial signature exchange protocol.

pub mod behaviour;
mod handler;
mod protocol;

pub use behaviour::{
    Behaviour, Config, DutyGater, Error as BehaviourError, Event, Handle, Verifier, VerifyError,
};
pub use handler::Handler;
pub use protocol::{decode_message, encode_message};

use libp2p::PeerId;
use pluto_core::ParSigExCodecError;

/// The protocol name for partial signature exchange (version 2.0.0).
pub const PROTOCOL_NAME: libp2p::swarm::StreamProtocol =
    libp2p::swarm::StreamProtocol::new("/charon/parsigex/2.0.0");

/// Returns the supported protocols in precedence order.
pub fn protocols() -> Vec<libp2p::swarm::StreamProtocol> {
    vec![PROTOCOL_NAME]
}

/// Error type for proto and conversion operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Core codec error.
    #[error(transparent)]
    Codec(#[from] ParSigExCodecError),

    /// Broadcast failed for a peer.
    #[error("broadcast to peer {peer} failed")]
    BroadcastPeer {
        /// Peer for which the broadcast failed.
        peer: PeerId,
    },
}

/// Result type for partial signature exchange operations.
pub type Result<T> = std::result::Result<T, Error>;
