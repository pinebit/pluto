#![allow(missing_docs)]

use std::{
    collections::HashSet,
    sync::{Arc, RwLock, RwLockReadGuard}, task::{Context, Poll},
};

use libp2p::{Multiaddr, PeerId, swarm::{ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm, behaviour::ConnectionEstablished}};

#[derive(Debug, Clone)]
pub struct PeerStore {
    inner: Arc<RwLock<PeerStoreInner>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Peer {
    pub id: PeerId,
    pub connection_id: ConnectionId,
}

#[derive(Debug, Clone)]
pub struct PeerStoreInner {
    active_peers: HashSet<Peer>,
    inactive_peers: HashSet<Peer>,
}

impl PeerStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerStoreInner {
                active_peers: HashSet::new(),
                inactive_peers: HashSet::new(),
            })),
        }
    }

    pub fn add_active_peer(&self, peer: Peer) {
        let mut inner = self.inner.write().unwrap();
        inner.inactive_peers.remove(&peer);
        inner.active_peers.insert(peer);
    }

    pub fn remove_active_peer(&self, peer: &Peer) {
        let mut inner = self.inner.write().unwrap();
        inner.active_peers.remove(peer);
    }

    pub fn peers_lock<'a>(&'a self) -> RwLockReadGuard<'a, PeerStoreInner> {
        self.inner.read().unwrap()
    }

    pub fn peers<T: FromIterator<Peer>>(&self) -> T {
        let inner = self.inner.read().unwrap();
        inner.active_peers.iter().cloned().collect()
    }

    pub fn inactive_peers<T: FromIterator<Peer>>(&self) -> T {
        let inner = self.inner.read().unwrap();
        inner.inactive_peers.iter().cloned().collect()
    }

    pub fn all_peers<T: FromIterator<Peer>>(&self) -> T {
        let inner = self.peers_lock();
        inner.active_peers.iter().chain(inner.inactive_peers.iter()).cloned().collect()
    }
}


#[derive(Debug, Clone)]
pub enum Event {
    /// A peer was added to the peer store.
    PeerAdded(Peer),
    /// A peer was removed from the peer store.
    PeerRemoved(Peer),
}


impl NetworkBehaviour for PeerStore {
    type ConnectionHandler = crate::gater::handler::Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Self::ConnectionHandler::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(Self::ConnectionHandler::new())
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, connection_id, .. }) => {
                self.add_active_peer(Peer { id: peer_id, connection_id });
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { peer_id, connection_id, .. }) => {
                self.remove_active_peer(&Peer { id: peer_id, connection_id });
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        // Handler events are Void, so this is unreachable
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}
