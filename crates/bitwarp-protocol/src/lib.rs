#![warn(missing_docs)]

//! bitwarp-protocol: packet types, headers, and protocol logic.

/// Acknowledgment tracking and reliable delivery.
pub mod acknowledgment;
/// Bandwidth management and throttling.
pub mod bandwidth;
/// Channel abstraction for independent communication streams.
pub mod channel;
/// Protocol command types.
pub mod command;
/// Command serialization and deserialization.
pub mod command_codec;
/// Congestion control and RTT tracking.
pub mod congestion;
/// Packet types and structures.
pub mod packet;
/// Sequence buffers for tracking sent/received packets.
pub mod sequence_buffer;

pub use acknowledgment::{AcknowledgmentHandler, SentPacket};
pub use packet::{
    DeliveryGuarantee, IncomingPackets, OrderingGuarantee, Packet, PacketInfo, PacketType,
};
