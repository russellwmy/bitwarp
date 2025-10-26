#![warn(missing_docs)]

//! bitwarp-host: host socket + session manager over transport/peer.

/// Event and action types (Action, SocketEvent).
pub mod event_types;
/// Session trait for managing a peer lifecycle.
pub mod session;
/// Session manager for handling multiple peer sessions.
pub mod session_manager;
/// High-level socket API wrapping session manager.
pub mod socket;
/// Throughput monitoring utilities.
pub mod throughput;
/// Time utilities for the host.
pub mod time;

mod peer_session;

pub use event_types::{Action, SocketEvent};
pub use session::{Session, SessionEventAddress};
pub use session_manager::SessionManager;
pub use socket::Host;
