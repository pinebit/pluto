//! Connection handler for the partial signature exchange protocol.

use std::{
    collections::VecDeque,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::BoxFuture, prelude::*};
use futures_timer::Delay;
use libp2p::{
    PeerId,
    core::upgrade::ReadyUpgrade,
    swarm::{
        ConnectionHandler, ConnectionHandlerEvent, StreamProtocol, StreamUpgradeError,
        SubstreamProtocol,
        handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
        },
    },
};

use pluto_core::types::{Duty, ParSignedDataSet};

use super::{DutyGater, PROTOCOL_NAME, Verifier, protocol};
use crate::Error as CodecError;

/// Failure type for the partial signature exchange handler.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// Stream negotiation timed out.
    #[error("parsigex protocol negotiation timed out")]
    Timeout,
    /// Invalid payload.
    #[error("invalid parsigex payload")]
    InvalidPayload,
    /// Duty not accepted by the gater.
    #[error("invalid duty")]
    InvalidDuty,
    /// Signature verification failed.
    #[error("invalid partial signature")]
    InvalidPartialSignature,
    /// I/O error.
    #[error("{0}")]
    Io(String),
    /// Codec error.
    #[error("codec error: {0}")]
    Codec(CodecError),
}

impl Failure {
    fn io(error: impl std::fmt::Display) -> Self {
        Self::Io(error.to_string())
    }
}

/// Command sent from the behaviour to a handler.
#[derive(Debug)]
pub enum ToHandler {
    /// Send the encoded payload to the remote peer.
    Send {
        /// Request identifier used to correlate broadcast completions.
        request_id: u64,
        /// Encoded protobuf payload.
        payload: Vec<u8>,
    },
}

/// Event sent from the handler back to the behaviour.
#[derive(Debug)]
pub enum FromHandler {
    /// A verified message was received.
    Received {
        /// Duty from the message.
        duty: Duty,
        /// Verified partial signature set.
        data_set: ParSignedDataSet,
    },
    /// An inbound message failed decoding, gating, or verification.
    InboundError(Failure),
    /// Outbound send completed successfully.
    OutboundSuccess {
        /// Request identifier.
        request_id: u64,
    },
    /// Outbound send failed.
    OutboundError {
        /// Request identifier.
        request_id: u64,
        /// Failure reason.
        error: Failure,
    },
}

type SendFuture = BoxFuture<'static, Result<(), Failure>>;
type RecvFuture = BoxFuture<'static, Result<(Duty, ParSignedDataSet), Failure>>;

enum OutboundState {
    IdleStream { stream: libp2p::swarm::Stream },
    RequestOpenStream { request_id: u64, payload: Vec<u8> },
    Sending { request_id: u64, future: SendFuture },
}

impl std::fmt::Debug for OutboundState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundState::IdleStream { .. } => {
                write!(f, "IdleStream {{ stream: <libp2p::swarm::Stream> }}")
            }
            OutboundState::RequestOpenStream {
                request_id,
                payload,
            } => write!(
                f,
                "RequestOpenStream {{ request_id: {}, payload: {:?} }}",
                request_id, payload
            ),
            OutboundState::Sending { request_id, .. } => write!(
                f,
                "Sending {{ request_id: {}, future: <dynamic> }}",
                request_id
            ),
        }
    }
}

fn recv_message(
    mut stream: libp2p::swarm::Stream,
    verifier: Verifier,
    duty_gater: DutyGater,
    timeout: Duration,
) -> RecvFuture {
    async move {
        let recv = async {
            let bytes = protocol::recv_message(&mut stream)
                .await
                .map_err(Failure::io)?;
            let (duty, data_set) =
                protocol::decode_message(&bytes).map_err(|_| Failure::InvalidPayload)?;
            if !(duty_gater)(&duty) {
                return Err(Failure::InvalidDuty);
            }

            for (pub_key, par_sig) in data_set.inner() {
                verifier(duty.clone(), *pub_key, par_sig.clone())
                    .await
                    .map_err(|_| Failure::InvalidPartialSignature)?;
            }

            Ok((duty, data_set))
        };

        futures::pin_mut!(recv);
        match futures::future::select(recv, Delay::new(timeout)).await {
            futures::future::Either::Left((result, _)) => result,
            futures::future::Either::Right(((), _)) => Err(Failure::Timeout),
        }
    }
    .boxed()
}

fn send_message(
    mut stream: libp2p::swarm::Stream,
    payload: Vec<u8>,
    timeout: Duration,
) -> SendFuture {
    async move {
        let send =
            protocol::send_message(&mut stream, &payload).map(|result| result.map_err(Failure::io));
        futures::pin_mut!(send);
        match futures::future::select(send, Delay::new(timeout)).await {
            futures::future::Either::Left((result, _)) => result,
            futures::future::Either::Right(((), _)) => Err(Failure::Timeout),
        }
    }
    .boxed()
}

/// Connection handler for parsigex.
pub struct Handler {
    timeout: Duration,
    verifier: Verifier,
    duty_gater: DutyGater,
    outbound_queue: VecDeque<(u64, Vec<u8>)>,
    outbound: Option<OutboundState>,
    inbound: Option<RecvFuture>,
    pending_events: VecDeque<FromHandler>,
}

impl Handler {
    /// Creates a new handler for one connection.
    pub fn new(
        timeout: Duration,
        verifier: Verifier,
        duty_gater: DutyGater,
        _peer: PeerId,
    ) -> Self {
        Self {
            timeout,
            verifier,
            duty_gater,
            outbound_queue: VecDeque::new(),
            outbound: None,
            inbound: None,
            pending_events: VecDeque::new(),
        }
    }

    fn on_dial_upgrade_error(
        &mut self,
        error: DialUpgradeError<(), <Self as ConnectionHandler>::OutboundProtocol>,
    ) {
        let Some(OutboundState::RequestOpenStream { request_id, .. }) = self.outbound.take() else {
            return;
        };

        let failure = match error.error {
            StreamUpgradeError::Timeout => Failure::Timeout,
            StreamUpgradeError::NegotiationFailed => Failure::io("protocol negotiation failed"),
            StreamUpgradeError::Apply(e) => libp2p::core::util::unreachable(e),
            StreamUpgradeError::Io(e) => Failure::io(e),
        };

        self.pending_events.push_back(FromHandler::OutboundError {
            request_id,
            error: failure,
        });
    }
}

impl ConnectionHandler for Handler {
    type FromBehaviour = ToHandler;
    type InboundOpenInfo = ();
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundOpenInfo = ();
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type ToBehaviour = FromHandler;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {
            ToHandler::Send {
                request_id,
                payload,
            } => self.outbound_queue.push_back((request_id, payload)),
        }
    }

    #[tracing::instrument(level = "trace", name = "ConnectionHandler::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }

        if let Some(fut) = self.inbound.as_mut() {
            match fut.poll_unpin(cx) {
                Poll::Pending => {}
                Poll::Ready(Ok((duty, data_set))) => {
                    self.inbound = None;
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        FromHandler::Received { duty, data_set },
                    ));
                }
                Poll::Ready(Err(error)) => {
                    self.inbound = None;
                    return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        FromHandler::InboundError(error),
                    ));
                }
            }
        }

        if let Some(outbound) = self.outbound.take() {
            match outbound {
                OutboundState::IdleStream { stream } => {
                    if let Some((request_id, payload)) = self.outbound_queue.pop_front() {
                        self.outbound = Some(OutboundState::Sending {
                            request_id,
                            future: send_message(stream, payload, self.timeout),
                        });
                    } else {
                        self.outbound = Some(OutboundState::IdleStream { stream });
                    }
                }
                OutboundState::RequestOpenStream {
                    request_id,
                    payload,
                } => {
                    // Waiting for stream negotiation - put state back and return pending.
                    // The OutboundSubstreamRequest was already emitted when first entering this
                    // state. Returning it again would cause libp2p to panic
                    // with "cannot extract twice".
                    self.outbound = Some(OutboundState::RequestOpenStream {
                        request_id,
                        payload,
                    });
                }
                OutboundState::Sending {
                    request_id,
                    mut future,
                } => match future.poll_unpin(cx) {
                    Poll::Pending => {
                        self.outbound = Some(OutboundState::Sending { request_id, future });
                    }
                    Poll::Ready(Ok(())) => {
                        self.outbound = None;
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            FromHandler::OutboundSuccess { request_id },
                        ));
                    }
                    Poll::Ready(Err(error)) => {
                        self.outbound = None;
                        return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                            FromHandler::OutboundError { request_id, error },
                        ));
                    }
                },
            }
        }

        // Only start a new outbound operation if none is in progress.
        // This prevents overwriting RequestOpenStream or Sending states.
        if self.outbound.is_none()
            && let Some((request_id, payload)) = self.outbound_queue.pop_front()
        {
            self.outbound = Some(OutboundState::RequestOpenStream {
                request_id,
                payload,
            });
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(PROTOCOL_NAME), ()),
            });
        }

        Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: mut stream,
                ..
            }) => {
                stream.ignore_for_keep_alive();
                self.inbound = Some(recv_message(
                    stream,
                    self.verifier.clone(),
                    self.duty_gater.clone(),
                    self.timeout,
                ));
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: mut stream,
                ..
            }) => {
                stream.ignore_for_keep_alive();
                match self.outbound.take() {
                    Some(OutboundState::RequestOpenStream {
                        request_id,
                        payload,
                    }) => {
                        self.outbound = Some(OutboundState::Sending {
                            request_id,
                            future: send_message(stream, payload, self.timeout),
                        });
                    }
                    Some(OutboundState::Sending { request_id, future }) => {
                        self.outbound = Some(OutboundState::Sending { request_id, future });
                        tracing::debug!(
                            "dropping unexpected outbound parsigex stream while a send is already in progress"
                        );
                    }
                    Some(OutboundState::IdleStream {
                        stream: idle_stream,
                    }) => {
                        self.outbound = Some(OutboundState::IdleStream {
                            stream: idle_stream,
                        });
                        tracing::debug!(
                            "dropping unexpected outbound parsigex stream while an idle stream is already cached"
                        );
                    }
                    None => {
                        self.outbound = Some(OutboundState::IdleStream { stream });
                    }
                }
            }
            ConnectionEvent::DialUpgradeError(error) => self.on_dial_upgrade_error(error),
            _ => {}
        }
    }
}
