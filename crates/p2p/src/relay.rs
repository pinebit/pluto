//! Relay reservation functionality.
//!
//! This behaviour is responsible for resolving relays that are being passed by
//! a mutable peer.
//!
//! Mutable peer is used for updating the relay addresses in the background by
//! fetching the enr servers.

use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use crate::peer::MutablePeer;
use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        ToSwarm, dial_opts::DialOpts, dummy,
    },
};

/// Mutable relay reservation behaviour.
pub struct MutableRelayReservation {
    events: Arc<Mutex<VecDeque<ToSwarm<Infallible, Infallible>>>>,
}

impl MutableRelayReservation {
    /// Creates a new mutable relay reservation.
    pub fn new(mutable_peer: Vec<MutablePeer>) -> Self {
        let events = Arc::new(Mutex::new(VecDeque::new()));
        for mutable_peer in &mutable_peer {
            let events_clone = events.clone();
            // Dial the relay for the first time
            {
                if let Ok(Some(peer)) = mutable_peer.peer() {
                    let mut events = events.lock().unwrap();
                    events.push_back(ToSwarm::Dial {
                        opts: DialOpts::peer_id(peer.id)
                            .addresses(peer.addresses.clone())
                            .build(),
                    });
                }
            }
            mutable_peer
                .subscribe(Box::new(move |peer| {
                    let mut events = events_clone.lock().unwrap();
                    events.push_back(ToSwarm::Dial {
                        opts: DialOpts::peer_id(peer.id)
                            .addresses(peer.addresses.clone())
                            .build(),
                    });
                }))
                .unwrap();
        }
        Self { events }
    }
}

impl NetworkBehaviour for MutableRelayReservation {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {
        // No special handling needed for swarm events
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: libp2p::PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        // No special handling needed for connection handler events
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        let mut events = self.events.lock().unwrap();
        if let Some(event) = events.pop_front() {
            return Poll::Ready(event);
        }
        Poll::Pending
    }
}
