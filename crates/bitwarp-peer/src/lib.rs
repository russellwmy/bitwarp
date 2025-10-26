#![warn(missing_docs)]

//! bitwarp-peer: peer state machine for managing remote endpoints.

/// Command queue for batching operations.
pub mod command_queue;
mod peer;
mod peer_state;

pub use peer::Peer;
pub use peer_state::PeerState;
