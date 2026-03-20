//! Network behaviour and control handle for partial signature exchange.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use either::Either;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, NotifyHandler, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, dummy,
    },
};
use tokio::sync::mpsc;

use pluto_core::types::{Duty, ParSignedData, ParSignedDataSet, PubKey};
use pluto_p2p::p2p_context::P2PContext;

use super::{Error as CodecError, Handler, encode_message};
use crate::handler::{Failure as HandlerFailure, FromHandler, ToHandler};

/// Future returned by verifier callbacks.
pub type VerifyFuture =
    Pin<Box<dyn Future<Output = std::result::Result<(), VerifyError>> + Send + 'static>>;

/// Verifier callback type.
pub type Verifier =
    Arc<dyn Fn(Duty, PubKey, ParSignedData) -> VerifyFuture + Send + Sync + 'static>;

/// Duty gate callback type.
pub type DutyGater = Arc<dyn Fn(&Duty) -> bool + Send + Sync + 'static>;

/// Error type for signature verification callbacks.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Unknown validator public key.
    #[error("unknown pubkey, not part of cluster lock")]
    UnknownPubKey,

    /// Invalid share index for the validator.
    #[error("invalid shareIdx")]
    InvalidShareIndex,

    /// Invalid signed-data family for the duty.
    #[error("invalid eth2 signed data")]
    InvalidSignedDataFamily,

    /// Generic verification error.
    #[error("{0}")]
    Other(String),
}

/// Error type for behaviour operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Message conversion failed.
    #[error(transparent)]
    Codec(#[from] CodecError),

    /// Channel closed.
    #[error("parsigex handle closed")]
    Closed,

    /// Broadcast failed for a peer.
    #[error("broadcast to peer {peer} failed: {source}")]
    BroadcastPeer {
        /// Peer for which the broadcast failed.
        peer: PeerId,
        /// Source error.
        #[source]
        source: HandlerFailure,
    },

    /// Peer is not currently connected.
    #[error("peer {0} is not connected")]
    PeerNotConnected(PeerId),
}

/// Result type for partial signature exchange behaviour operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Event emitted by the partial signature exchange behaviour.
#[derive(Debug)]
pub enum Event {
    /// A verified partial signature set was received from a peer.
    Received {
        /// The remote peer.
        peer: PeerId,
        /// Connection on which it was received.
        connection: ConnectionId,
        /// Duty associated with the data set.
        duty: Duty,
        /// Partial signature set.
        data_set: ParSignedDataSet,
    },
    /// A peer sent invalid data or verification failed.
    Error {
        /// The remote peer.
        peer: PeerId,
        /// Connection on which the error occurred.
        connection: ConnectionId,
        /// Failure reason.
        error: HandlerFailure,
    },
    /// Broadcast failed.
    BroadcastError {
        /// Request identifier.
        request_id: u64,
        /// Peer for which the broadcast failed.
        peer: Option<PeerId>,
        /// Failure reason.
        error: HandlerFailure,
    },
    /// Broadcast completed successfully for all targeted peers.
    BroadcastComplete {
        /// Request identifier.
        request_id: u64,
    },
    /// Broadcast finished after one or more peer failures.
    BroadcastFinished {
        /// Request identifier.
        request_id: u64,
    },
}

#[derive(Debug)]
struct PendingBroadcast {
    remaining: usize,
    failed: bool,
}

#[derive(Debug)]
enum Command {
    Broadcast {
        request_id: u64,
        duty: Duty,
        data_set: ParSignedDataSet,
    },
}

/// Async handle for outbound partial signature broadcasts.
#[derive(Debug, Clone)]
pub struct Handle {
    tx: mpsc::UnboundedSender<Command>,
    next_request_id: Arc<AtomicU64>,
}

impl Handle {
    /// Broadcasts a partial signature set to all peers except self.
    pub async fn broadcast(&self, duty: Duty, data_set: ParSignedDataSet) -> Result<u64> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.tx
            .send(Command::Broadcast {
                request_id,
                duty,
                data_set,
            })
            .map_err(|_| Error::Closed)?;

        Ok(request_id)
    }
}

/// Configuration for the partial signature exchange behaviour.
#[derive(Clone)]
pub struct Config {
    peer_id: PeerId,
    p2p_context: P2PContext,
    verifier: Verifier,
    duty_gater: DutyGater,
    timeout: Duration,
}

impl Config {
    /// Creates a new configuration.
    pub fn new(
        peer_id: PeerId,
        p2p_context: P2PContext,
        verifier: Verifier,
        duty_gater: DutyGater,
    ) -> Self {
        Self {
            peer_id,
            p2p_context,
            verifier,
            duty_gater,
            timeout: Duration::from_secs(20),
        }
    }

    /// Sets the send/receive timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Behaviour for partial signature exchange.
pub struct Behaviour {
    config: Config,
    rx: mpsc::UnboundedReceiver<Command>,
    pending_actions: VecDeque<ToSwarm<Event, THandlerInEvent<Self>>>,
    events: VecDeque<Event>,
    pending_broadcasts: HashMap<u64, PendingBroadcast>,
}

impl Behaviour {
    /// Creates a behaviour and a clonable broadcast handle.
    pub fn new(config: Config, peer_id: PeerId) -> (Self, Handle) {
        debug_assert_eq!(config.peer_id, peer_id);
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = Handle {
            tx,
            next_request_id: Arc::new(AtomicU64::new(0)),
        };

        (
            Self {
                config,
                rx,
                pending_actions: VecDeque::new(),
                events: VecDeque::new(),
                pending_broadcasts: HashMap::new(),
            },
            handle,
        )
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Broadcast {
                request_id,
                duty,
                data_set,
            } => {
                let message = match encode_message(&duty, &data_set) {
                    Ok(message) => message,
                    Err(err) => {
                        self.broadcast_error(request_id, None, HandlerFailure::Codec(err));
                        return;
                    }
                };

                let peers: Vec<_> = self
                    .config
                    .p2p_context
                    .known_peers()
                    .iter()
                    .copied()
                    .collect();
                let mut targeted = 0usize;
                for peer in peers {
                    if peer == self.config.peer_id {
                        continue;
                    }

                    if self
                        .config
                        .p2p_context
                        .peer_store_lock()
                        .connections_to_peer(&peer)
                        .is_empty()
                    {
                        self.broadcast_error(
                            request_id,
                            Some(peer),
                            HandlerFailure::Io(format!("peer {peer} is not connected")),
                        );
                        continue;
                    }

                    self.pending_actions.push_back(ToSwarm::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::Any,
                        event: Either::Left(ToHandler::Send {
                            request_id,
                            payload: message.clone(),
                        }),
                    });
                    targeted = targeted.saturating_add(1);
                }

                if targeted == 0 {
                    return;
                }

                self.pending_broadcasts.insert(
                    request_id,
                    PendingBroadcast {
                        remaining: targeted,
                        failed: false,
                    },
                );
            }
        }
    }

    fn finish_broadcast_result(&mut self, request_id: u64, failed: bool) {
        let Some(entry) = self.pending_broadcasts.get_mut(&request_id) else {
            return;
        };

        entry.failed |= failed;
        entry.remaining = entry.remaining.saturating_sub(1);
        if entry.remaining == 0 {
            let failed = self
                .pending_broadcasts
                .remove(&request_id)
                .map(|entry| entry.failed)
                .unwrap_or(failed);
            if failed {
                self.events
                    .push_back(Event::BroadcastFinished { request_id });
            } else {
                self.events
                    .push_back(Event::BroadcastComplete { request_id });
            }
        }
    }

    fn broadcast_error(&mut self, request_id: u64, peer: Option<PeerId>, error: HandlerFailure) {
        self.events.push_back(Event::BroadcastError {
            request_id,
            peer,
            error,
        });
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Either<Handler, dummy::ConnectionHandler>;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        if !self.config.p2p_context.is_known_peer(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }

        tracing::trace!("establishing inbound connection to peer: {:?}", peer);
        Ok(Either::Left(Handler::new(
            self.config.timeout,
            self.config.verifier.clone(),
            self.config.duty_gater.clone(),
            peer,
        )))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> std::result::Result<THandler<Self>, ConnectionDenied> {
        if !self.config.p2p_context.is_known_peer(&peer) {
            return Ok(Either::Right(dummy::ConnectionHandler));
        }

        tracing::trace!("establishing outbound connection to peer: {:?}", peer);
        Ok(Either::Left(Handler::new(
            self.config.timeout,
            self.config.verifier.clone(),
            self.config.duty_gater.clone(),
            peer,
        )))
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        let event = match event {
            Either::Left(event) => event,
            Either::Right(value) => match value {},
        };

        tracing::trace!("received connection handler event: {:?}", event);
        match event {
            FromHandler::Received { duty, data_set } => {
                self.events.push_back(Event::Received {
                    peer: peer_id,
                    connection: connection_id,
                    duty,
                    data_set,
                });
            }
            FromHandler::InboundError(error) => {
                self.events.push_back(Event::Error {
                    peer: peer_id,
                    connection: connection_id,
                    error,
                });
            }
            FromHandler::OutboundSuccess { request_id } => {
                self.finish_broadcast_result(request_id, false);
            }
            FromHandler::OutboundError { request_id, error } => {
                self.finish_broadcast_result(request_id, true);
                self.broadcast_error(request_id, Some(peer_id), error);
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        tracing::trace!("polling parsigex behaviour");

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        if let Poll::Ready(Some(command)) = self.rx.poll_recv(cx) {
            self.handle_command(command);
        }

        if let Some(action) = self.pending_actions.pop_front() {
            return Poll::Ready(action);
        }

        Poll::Pending
    }
}
