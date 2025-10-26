use std::{fmt::Debug, net::SocketAddr, time::Instant};

use bitwarp_core::config::Config;

use crate::event_types::Action;

/// Returns an address of an event.
pub trait SessionEventAddress {
    /// Returns event address
    fn address(&self) -> SocketAddr;
}

/// Manages the lifecycle and state of a peer session.
/// Defines a type of `Send` and `Receive` events used by a session.
pub trait Session: Debug {
    /// Defines a user event type.
    type SendEvent: Debug + SessionEventAddress;
    /// Defines a session event type.
    type ReceiveEvent: Debug + SessionEventAddress;

    /// Creates new session and initialize it.
    fn create_session(config: &Config, address: SocketAddr, time: Instant) -> Self;

    /// Sessions are considered established once they have both had a send and a receive.
    fn is_established(&self) -> bool;

    /// Determines if the session should be dropped due to its state.
    fn should_drop(&mut self, time: Instant) -> (bool, Vec<Action<Self::ReceiveEvent>>);

    /// Processes a received packet: parse it and emit an event.
    fn process_packet(&mut self, payload: &[u8], time: Instant) -> Vec<Action<Self::ReceiveEvent>>;

    /// Processes a received event and send a packet.
    fn process_event(
        &mut self,
        event: Self::SendEvent,
        time: Instant,
    ) -> Vec<Action<Self::ReceiveEvent>>;

    /// Processes session-related tasks: resend dropped packets, send heartbeat, etc.
    fn update(&mut self, time: Instant) -> Vec<Action<Self::ReceiveEvent>>;
}
