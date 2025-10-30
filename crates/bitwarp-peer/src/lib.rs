#![warn(missing_docs)]

//! bitwarp-peer: peer state machine for managing remote endpoints.

/// Bandwidth throttling and utilization tracking.
pub mod bandwidth_throttle;
/// Command queue for batching operations.
pub mod command_queue;
mod channel_state;
/// Window-based flow control for reliable data transmission.
pub mod flow_control;
/// Fragment reassembly management for command packets.
mod fragment_buffer;
mod peer;
mod peer_state;
/// Path MTU discovery implementation.
pub mod pmtu_discovery;
/// Peer connection statistics tracking.
pub mod statistics;
/// Unsequenced packet duplicate detection.
pub mod unsequenced;

pub use bandwidth_throttle::BandwidthThrottle;
pub use flow_control::FlowControl;
pub use peer::Peer;
pub use peer_state::PeerState;
pub use statistics::PeerStatistics;
