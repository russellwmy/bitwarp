#![warn(missing_docs)]

//! bitwarp-core: foundational types and utilities.
//!
//! This crate provides the minimal set of core utilities shared across all layers:
//! - Configuration types
//! - Error handling
//! - Protocol constants
//! - Memory utilities (packet pooling)
//!
//! Protocol-specific logic has been moved to specialized crates:
//! - `bitwarp-protocol`: command codec, congestion control, bandwidth management, channels
//! - `bitwarp-peer`: command queue for session batching
//! - `bitwarp-runtime`: connection management, throughput monitoring

/// Protocol constants shared across layers.
pub mod constants {
    /// The size of the fragment header.
    pub const FRAGMENT_HEADER_SIZE: u8 = 4;
    /// The size of the acknowledgment header.
    pub const ACKED_PACKET_HEADER: u8 = 8;
    /// The size of the arranging header.
    pub const ARRANGING_PACKET_HEADER: u8 = 3;
    /// The size of the standard header.
    pub const STANDARD_HEADER_SIZE: u8 = 5;
    /// The ordering stream that will be used to order on if none was specified.
    pub const DEFAULT_ORDERING_STREAM: u8 = 255;
    /// The sequencing stream that will be used to sequence packets on if none was specified.
    pub const DEFAULT_SEQUENCING_STREAM: u8 = 255;
    /// Default maximal number of fragments to size.
    pub const MAX_FRAGMENTS_DEFAULT: u16 = 16;
    /// Default maximal size of each fragment.
    pub const FRAGMENT_SIZE_DEFAULT: u16 = 1024;
    /// Maximum transmission unit of the payload.
    ///
    /// Derived from ethernet_mtu - ipv6_header_size - udp_header_size - packet header size
    ///       1452 = 1500         - 40               - 8               - 8
    ///
    /// This is not strictly guaranteed -- there may be less room in an ethernet frame than this due to
    /// variability in ipv6 header size.
    pub const DEFAULT_MTU: u16 = 1452;
    /// This is the current protocol version.
    ///
    /// Incremental monolithic protocol number.
    pub const PROTOCOL_VERSION: u16 = 3;
}

/// Configuration options for the protocol and runtime.
pub mod config;
/// Either/Or type for type-level choices.
pub mod either;
/// Error types and results.
pub mod error;
/// Packet interception for custom processing.
pub mod interceptor;
/// Packet pooling for memory efficiency.
pub mod packet_pool;
/// Transport abstraction for pluggable I/O.
pub mod transport;
/// Shared, reference-counted byte slices with zero-copy slicing.
pub mod shared;
