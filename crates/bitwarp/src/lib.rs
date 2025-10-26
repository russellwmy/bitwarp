#![warn(missing_docs)]

//! Bitwarp: a small public API facade for the workspace.
//!
//! This crate provides a clean, stable surface that re-exports
//! the most commonly used types to build reliable UDP apps:
//!
//! - Host and events (`Host`, `SocketEvent`)
//! - Packet types and guarantees (`Packet`, `DeliveryGuarantee`, ...)
//! - Core configuration (`Config`)
//!
//! Example
//! ```ignore
//! use bitwarp::{Host, SocketEvent, Packet, DeliveryGuarantee, OrderingGuarantee};
//!
//! let mut host = Host::bind_any().unwrap();
//! let remote = host.local_addr().unwrap();
//!
//! // Send a reliable, unordered packet to ourselves
//! let pkt = Packet::reliable_unordered(remote, b"hello".to_vec());
//! host.send(pkt).unwrap();
//!
//! // Poll once
//! use std::time::Instant;
//! host.manual_poll(Instant::now());
//!
//! if let Some(SocketEvent::Packet(rx)) = host.recv() {
//!     assert_eq!(rx.payload(), b"hello");
//! }
//! ```

// Core config
pub use bitwarp_core::config::{CompressionAlgorithm, Config};
// Host: manages multiple peer sessions and events
pub use bitwarp_host::{Host, SocketEvent};
// Protocol: packets and guarantees
pub use bitwarp_protocol::packet::{
    DeliveryGuarantee, OrderingGuarantee, Packet, PacketInfo, PacketType,
};

/// Convenience prelude with the most commonly used items.
pub mod prelude {
    pub use crate::{
        CompressionAlgorithm, Config, DeliveryGuarantee, Host, OrderingGuarantee, Packet,
        PacketInfo, PacketType, SocketEvent,
    };
}
