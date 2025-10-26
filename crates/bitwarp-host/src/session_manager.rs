use std::{collections::HashMap, fmt::Debug, net::{IpAddr, SocketAddr}, time::Instant};

use bitwarp_core::{
    config::Config,
    packet_pool::PacketAllocator,
    interceptor::{Interceptor, NoOpInterceptor},
    transport::Socket as TransportSocket,
};
use crossbeam_channel::{unbounded, Receiver, Sender};
use tracing::error;

use crate::{
    event_types::Action,
    session::{Session, SessionEventAddress},
};

// ============================================================================
// Event Sink (Internal)
// ============================================================================

/// Minimal event sink abstraction to decouple from a concrete channel.
trait EventSink<E> {
    fn send(&mut self, event: E);
}

/// Channel-backed event sink using crossbeam `Sender`.
#[derive(Debug)]
struct ChannelSink<E>(Sender<E>);

impl<E> ChannelSink<E> {
    fn new(sender: Sender<E>) -> Self {
        Self(sender)
    }
}

impl<E> EventSink<E> for ChannelSink<E> {
    fn send(&mut self, event: E) {
        self.0.send(event).expect("Receiver must exist");
    }
}

struct SocketEventSenderAndConfig<TSocket: TransportSocket, ReceiveEvent: Debug> {
    config: Config,
    socket: TSocket,
    event_sender: ChannelSink<ReceiveEvent>,
    pending_sends: Vec<(SocketAddr, Vec<u8>)>,
    pending_events: Vec<ReceiveEvent>,
    interceptor: Box<dyn Interceptor>,
    /// Pool to recycle send buffers and reduce allocations on hot paths
    send_pool: PacketAllocator,
}

impl<TSocket: TransportSocket, ReceiveEvent: Debug> std::fmt::Debug
    for SocketEventSenderAndConfig<TSocket, ReceiveEvent>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketEventSenderAndConfig")
            .field("config", &self.config)
            .field("socket", &"<socket>")
            .field("event_sender", &self.event_sender)
            .field("pending_sends", &self.pending_sends)
            .field("pending_events", &self.pending_events)
            .field("interceptor", &"<interceptor>")
            .finish()
    }
}

impl<TSocket: TransportSocket, ReceiveEvent: Debug>
    SocketEventSenderAndConfig<TSocket, ReceiveEvent>
{
    fn new(
        config: Config,
        socket: TSocket,
        event_sender: Sender<ReceiveEvent>,
        interceptor: Box<dyn Interceptor>,
    ) -> Self {
        // Pre-size pool buffers to typical max packet size; keep a modest pool
        let pool = PacketAllocator::new(config.max_packet_size, 256);
        Self {
            config,
            socket,
            event_sender: ChannelSink::new(event_sender),
            pending_sends: Vec::new(),
            pending_events: Vec::new(),
            interceptor,
            send_pool: pool,
        }
    }

    fn handle_actions(&mut self, address: &SocketAddr, actions: Vec<Action<ReceiveEvent>>) {
        for action in actions {
            match action {
                Action::Send(bytes) => self.pending_sends.push((*address, bytes)),
                Action::Emit(ev) => self.pending_events.push(ev),
            }
        }
    }

    fn flush(&mut self) {
        for (addr, mut payload) in self.pending_sends.drain(..) {
            // Call interceptor before sending
            if !self.interceptor.on_send(&addr, &mut payload) {
                // Interceptor dropped the packet
                // Return buffer to pool for reuse
                self.send_pool.deallocate(payload);
                continue;
            }

            if let Err(err) = self.socket.send_packet(&addr, &payload) {
                error!("Error occured sending a packet (to {}): {}", addr, err)
            }
            // Return the buffer to the pool for reuse
            self.send_pool.deallocate(payload);
        }
        for event in self.pending_events.drain(..) {
            self.event_sender.send(event);
        }
    }
}

/// Session manager over a datagram socket and generic `Session` engine.
#[derive(Debug)]
pub struct SessionManager<TSocket: TransportSocket, TSession: Session> {
    sessions: HashMap<SocketAddr, TSession>,
    receive_buffer: Vec<u8>,
    user_event_receiver: Receiver<TSession::SendEvent>,
    messenger: SocketEventSenderAndConfig<TSocket, TSession::ReceiveEvent>,
    event_receiver: Receiver<TSession::ReceiveEvent>,
    user_event_sender: Sender<TSession::SendEvent>,
    max_unestablished_sessions: u16,
    /// Tracks the number of connections per IP address for duplicate peer management
    duplicate_peer_count: HashMap<IpAddr, usize>,
    /// Maximum number of duplicate peers allowed (0 = unlimited)
    max_duplicate_peers: u16,
}

impl<TSocket: TransportSocket, TSession: Session> SessionManager<TSocket, TSession> {
    /// Creates a new session manager.
    pub fn new(socket: TSocket, config: Config) -> Self {
        Self::new_with_interceptor(socket, config, None)
    }

    /// Creates a new session manager with a custom interceptor.
    pub fn new_with_interceptor(
        socket: TSocket,
        config: Config,
        interceptor: Option<Box<dyn Interceptor>>,
    ) -> Self {
        let (event_sender, event_receiver) = unbounded();
        let (user_event_sender, user_event_receiver) = unbounded();
        let max_unestablished_sessions = config.max_unestablished_connections;
        let max_duplicate_peers = config.max_duplicate_peers;

        let interceptor = interceptor.unwrap_or_else(|| Box::new(NoOpInterceptor));

        SessionManager {
            receive_buffer: vec![0; config.receive_buffer_max_size],
            sessions: Default::default(),
            user_event_receiver: user_event_receiver,
            messenger: SocketEventSenderAndConfig::new(config, socket, event_sender, interceptor),
            user_event_sender,
            event_receiver,
            max_unestablished_sessions,
            duplicate_peer_count: HashMap::new(),
            max_duplicate_peers,
        }
    }

    /// Polls for network I/O and processes all sessions.
    pub fn manual_poll(&mut self, time: Instant) {
        let mut unestablished_sessions = self.unestablished_session_count();

        loop {
            match self.messenger.socket.receive_packet(self.receive_buffer.as_mut()) {
                Ok((payload, address)) => {
                    let payload_len = payload.len();

                    // Call interceptor on received data
                    let should_process = {
                        let buf_slice = &mut self.receive_buffer[..payload_len];
                        self.messenger.interceptor.on_receive(&address, buf_slice)
                    };

                    if !should_process {
                        // Interceptor dropped the packet
                        continue;
                    }

                    // Re-get payload reference after interceptor potentially modified it
                    let payload = &self.receive_buffer[..payload_len];

                    if let Some(session) = self.sessions.get_mut(&address) {
                        let was_est = session.is_established();
                        let actions = session.process_packet(payload, time);
                        self.messenger.handle_actions(&address, actions);
                        if !was_est && session.is_established() {
                            unestablished_sessions -= 1;
                        }
                    } else {
                        let mut session =
                            TSession::create_session(&self.messenger.config, address, time);
                        let actions = session.process_packet(payload, time);
                        self.messenger.handle_actions(&address, actions);
                        // Check both unestablished limit and duplicate peer limit
                        if unestablished_sessions < self.max_unestablished_sessions as usize
                            && self.can_accept_duplicate(&address)
                        {
                            self.sessions.insert(address, session);
                            self.increment_duplicate_count(&address);
                            unestablished_sessions += 1;
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        error!("Encountered an error receiving data: {:?}", e);
                    }
                    break;
                }
            }
            if self.messenger.socket.is_blocking_mode() {
                break;
            }
        }

        while let Ok(event) = self.user_event_receiver.try_recv() {
            let addr = event.address();

            // Check if session exists and if we can accept a new duplicate
            let is_new_session = !self.sessions.contains_key(&addr);
            let can_create = !is_new_session || self.can_accept_duplicate(&addr);

            // Skip if we can't create a new session due to duplicate limit
            if is_new_session && !can_create {
                continue;
            }

            // Use entry API and process in one scope
            use std::collections::hash_map::Entry;
            match self.sessions.entry(addr) {
                Entry::Occupied(mut entry) => {
                    let session = entry.get_mut();
                    let was_est = session.is_established();
                    let actions = session.process_event(event, time);
                    self.messenger.handle_actions(&addr, actions);
                    if !was_est && session.is_established() {
                        unestablished_sessions -= 1;
                    }
                }
                Entry::Vacant(entry) => {
                    let mut session = TSession::create_session(&self.messenger.config, addr, time);
                    let actions = session.process_event(event, time);
                    entry.insert(session);
                    self.messenger.handle_actions(&addr, actions);
                    self.increment_duplicate_count(&addr);
                }
            }
        }

        for (addr, session) in self.sessions.iter_mut() {
            let actions = session.update(time);
            self.messenger.handle_actions(addr, actions);
        }

        // Collect addresses to drop
        let mut to_drop = Vec::new();
        for (addr, session) in self.sessions.iter_mut() {
            let (drop, actions) = session.should_drop(time);
            self.messenger.handle_actions(addr, actions);
            if drop {
                to_drop.push(*addr);
            }
        }

        // Remove dropped sessions and decrement duplicate counts
        for addr in to_drop {
            self.sessions.remove(&addr);
            self.decrement_duplicate_count(&addr);
        }

        self.messenger.flush();
    }

    /// Returns the event sender for sending user events to sessions.
    pub fn event_sender(&self) -> &Sender<TSession::SendEvent> {
        &self.user_event_sender
    }

    /// Returns the event receiver for receiving session events.
    pub fn event_receiver(&self) -> &Receiver<TSession::ReceiveEvent> {
        &self.event_receiver
    }

    /// Returns a reference to the underlying socket.
    pub fn socket(&self) -> &TSocket {
        &self.messenger.socket
    }

    fn unestablished_session_count(&self) -> usize {
        self.sessions.iter().filter(|s| !s.1.is_established()).count()
    }

    #[allow(dead_code)]
    /// Returns a mutable reference to the underlying socket.
    pub fn socket_mut(&mut self) -> &mut TSocket {
        &mut self.messenger.socket
    }

    /// Returns the number of active sessions.
    pub fn sessions_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns a mutable reference to a specific session by address.
    pub fn session_mut(&mut self, addr: &SocketAddr) -> Option<&mut TSession> {
        self.sessions.get_mut(addr)
    }

    /// Returns an iterator over all established session addresses.
    pub fn established_sessions(&self) -> impl Iterator<Item = &SocketAddr> {
        self.sessions.iter().filter(|(_, s)| s.is_established()).map(|(addr, _)| addr)
    }

    /// Returns the number of established sessions.
    pub fn established_sessions_count(&self) -> usize {
        self.sessions.iter().filter(|(_, s)| s.is_established()).count()
    }

    /// Increments the duplicate peer count for the given address's IP.
    fn increment_duplicate_count(&mut self, addr: &SocketAddr) {
        let ip = addr.ip();
        *self.duplicate_peer_count.entry(ip).or_insert(0) += 1;
    }

    /// Decrements the duplicate peer count for the given address's IP.
    /// Removes the entry if count reaches zero.
    fn decrement_duplicate_count(&mut self, addr: &SocketAddr) {
        let ip = addr.ip();
        if let Some(count) = self.duplicate_peer_count.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                self.duplicate_peer_count.remove(&ip);
            }
        }
    }

    /// Checks if adding a connection from this address would exceed the duplicate peer limit.
    /// Returns true if the connection is allowed, false if it would exceed the limit.
    fn can_accept_duplicate(&self, addr: &SocketAddr) -> bool {
        // 0 means unlimited duplicates
        if self.max_duplicate_peers == 0 {
            return true;
        }

        let ip = addr.ip();
        let current_count = self.duplicate_peer_count.get(&ip).copied().unwrap_or(0);
        current_count < self.max_duplicate_peers as usize
    }

    /// Returns the number of connections from a specific IP address.
    pub fn duplicate_peer_count(&self, addr: &SocketAddr) -> usize {
        self.duplicate_peer_count.get(&addr.ip()).copied().unwrap_or(0)
    }
}
