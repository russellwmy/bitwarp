//! Event and action types for the runtime layer.
//!
//! This module defines the core types used for communication between
//! the connection layer and the user:
//! - `Action`: Instructions from connections to the runtime (send bytes or emit events)
//! - `SocketEvent`: Events emitted to the user (packets, connections, disconnections)

use std::net::SocketAddr;

use bitwarp_protocol::packet::Packet;

/// Actions that connections can request from the runtime.
/// Used by the Connection trait to return instructions to the connection manager.
#[derive(Debug)]
pub enum Action<E> {
    /// Send the given bytes to the connection's remote address
    Send(Vec<u8>),
    /// Emit an event to the user
    Emit(E),
}

/// Events that can occur and are pushed through the event_receiver.
/// These are user-facing events emitted by the socket/connection manager.
#[derive(Debug, PartialEq)]
pub enum SocketEvent {
    /// A packet was received from a client.
    Packet(Packet),
    /// A new connection has been established.
    Connect(SocketAddr),
    /// The client has been idling longer than the idle_connection_timeout.
    Timeout(SocketAddr),
    /// The established connection to a client has timed out.
    Disconnect(SocketAddr),
}
