//! Packet types and structures for the command-based protocol.
//!
//! This module provides the core packet types used throughout the protocol:
//! - `Packet`: User-facing packet with payload and guarantees
//! - `PacketInfo`: Non-owning packet metadata for processing
//! - `IncomingPackets`: Collection type for returning 0, 1, or many packets
//! - Delivery and ordering guarantee enums

use std::{collections::VecDeque, convert::TryFrom, net::SocketAddr, sync::Arc};

use bitwarp_core::{
    either::Either,
    error::{DecodingErrorKind, ErrorKind},
};

/// 16-bit sequence number type used by protocol.
pub type SequenceNumber = u16;

/// Helper trait to convert enums to u8 values for wire format.
pub trait EnumConverter {
    /// The enum type this converter works with.
    type Enum;

    /// Converts the enum to a u8 for serialization.
    fn to_u8(&self) -> u8;
}

// ============================================================================
// Delivery and Ordering Guarantees
// ============================================================================

/// Enum to specify how a packet should be delivered.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq)]
pub enum DeliveryGuarantee {
    /// Packet may or may not be delivered
    Unreliable,
    /// Packet will be delivered
    Reliable,
}

impl EnumConverter for DeliveryGuarantee {
    type Enum = DeliveryGuarantee;

    /// Returns an integer value from `DeliveryGuarantee` enum.
    fn to_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for DeliveryGuarantee {
    type Error = ErrorKind;
    /// Gets the `DeliveryGuarantee` enum instance from integer value.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DeliveryGuarantee::Unreliable),
            1 => Ok(DeliveryGuarantee::Reliable),
            _ => Err(ErrorKind::DecodingError(DecodingErrorKind::DeliveryGuarantee)),
        }
    }
}

/// Enum to specify how a packet should be arranged.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq, Default)]
pub enum OrderingGuarantee {
    /// No arranging will be done.
    #[default]
    None,
    /// Packets will be arranged in sequence.
    Sequenced(Option<u8>),
    /// Packets will be arranged in order.
    Ordered(Option<u8>),
    /// Unsequenced delivery - prevents duplicates but allows out-of-order.
    Unsequenced,
}

impl EnumConverter for OrderingGuarantee {
    type Enum = OrderingGuarantee;

    /// Returns the integer value from `OrderingGuarantee` enum.
    fn to_u8(&self) -> u8 {
        match self {
            OrderingGuarantee::None => 0,
            OrderingGuarantee::Sequenced(_) => 1,
            OrderingGuarantee::Ordered(_) => 2,
            OrderingGuarantee::Unsequenced => 3,
        }
    }
}

impl TryFrom<u8> for OrderingGuarantee {
    type Error = ErrorKind;
    /// Returns the `OrderingGuarantee` enum instance from integer value.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(OrderingGuarantee::None),
            1 => Ok(OrderingGuarantee::Sequenced(None)),
            2 => Ok(OrderingGuarantee::Ordered(None)),
            3 => Ok(OrderingGuarantee::Unsequenced),
            _ => Err(ErrorKind::DecodingError(DecodingErrorKind::OrderingGuarantee)),
        }
    }
}

/// Id to identify a certain packet type.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
pub enum PacketType {
    /// Full packet that is not fragmented
    Packet = 0,
    /// Fragment of a full packet
    Fragment = 1,
    /// Heartbeat packet
    Heartbeat = 2,
}

impl EnumConverter for PacketType {
    type Enum = PacketType;

    fn to_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for PacketType {
    type Error = ErrorKind;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketType::Packet),
            1 => Ok(PacketType::Fragment),
            2 => Ok(PacketType::Heartbeat),
            _ => Err(ErrorKind::DecodingError(DecodingErrorKind::PacketType)),
        }
    }
}

// ============================================================================
// Packet Structures
// ============================================================================

/// User-friendly packet containing payload, endpoint, and guarantees.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Packet {
    addr: SocketAddr,
    payload: Arc<[u8]>,
    delivery: DeliveryGuarantee,
    ordering: OrderingGuarantee,
    channel_id: u8,
}

impl Packet {
    /// Creates a new packet with the specified guarantees and channel.
    pub fn new(
        addr: SocketAddr,
        payload: Arc<[u8]>,
        delivery: DeliveryGuarantee,
        ordering: OrderingGuarantee,
        channel_id: u8,
    ) -> Packet {
        Packet { addr, payload, delivery, ordering, channel_id }
    }

    /// Creates an unreliable, unordered packet on channel 0 (fire-and-forget).
    pub fn unreliable(addr: SocketAddr, payload: Vec<u8>) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Unreliable,
            ordering: OrderingGuarantee::None,
            channel_id: 0,
        }
    }

    /// Creates an unreliable, sequenced packet on channel 0 (drops out-of-order).
    pub fn unreliable_sequenced(
        addr: SocketAddr,
        payload: Vec<u8>,
        stream_id: Option<u8>,
    ) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Unreliable,
            ordering: OrderingGuarantee::Sequenced(stream_id),
            channel_id: 0,
        }
    }

    /// Creates an unreliable, unsequenced packet on channel 0 (prevents duplicates, allows out-of-order).
    pub fn unsequenced(addr: SocketAddr, payload: Vec<u8>) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Unreliable,
            ordering: OrderingGuarantee::Unsequenced,
            channel_id: 0,
        }
    }

    /// Creates a reliable, unordered packet on channel 0 (guaranteed delivery).
    pub fn reliable_unordered(addr: SocketAddr, payload: Vec<u8>) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Reliable,
            ordering: OrderingGuarantee::None,
            channel_id: 0,
        }
    }

    /// Creates a reliable, ordered packet on channel 0 (TCP-like).
    pub fn reliable_ordered(addr: SocketAddr, payload: Vec<u8>, stream_id: Option<u8>) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Reliable,
            ordering: OrderingGuarantee::Ordered(stream_id),
            channel_id: 0,
        }
    }

    /// Creates a reliable, sequenced packet on channel 0 (keeps latest).
    pub fn reliable_sequenced(addr: SocketAddr, payload: Vec<u8>, stream_id: Option<u8>) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Reliable,
            ordering: OrderingGuarantee::Sequenced(stream_id),
            channel_id: 0,
        }
    }

    /// Creates an unreliable, unordered packet on specified channel (fire-and-forget).
    pub fn unreliable_on_channel(addr: SocketAddr, payload: Vec<u8>, channel_id: u8) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Unreliable,
            ordering: OrderingGuarantee::None,
            channel_id,
        }
    }

    /// Creates a reliable, unordered packet on specified channel (guaranteed delivery).
    pub fn reliable_on_channel(addr: SocketAddr, payload: Vec<u8>, channel_id: u8) -> Packet {
        Packet {
            addr,
            payload: Arc::<[u8]>::from(payload),
            delivery: DeliveryGuarantee::Reliable,
            ordering: OrderingGuarantee::None,
            channel_id,
        }
    }

    /// Returns a slice of the packet payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the packet and returns the payload.
    pub fn into_payload(self) -> Arc<[u8]> {
        self.payload
    }

    /// Returns a clone of the underlying Arc payload for zero-copy sharing.
    pub fn payload_arc(&self) -> Arc<[u8]> {
        self.payload.clone()
    }

    /// Returns the remote endpoint address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the delivery guarantee for this packet.
    pub fn delivery_guarantee(&self) -> DeliveryGuarantee {
        self.delivery
    }

    /// Returns the ordering guarantee for this packet.
    pub fn order_guarantee(&self) -> OrderingGuarantee {
        self.ordering
    }

    /// Returns the channel ID for this packet.
    pub fn channel_id(&self) -> u8 {
        self.channel_id
    }
}

/// Non-owning packet metadata used during processing.
#[derive(Debug)]
pub struct PacketInfo<'a> {
    /// Type of packet (user data, heartbeat, fragment, etc.)
    pub packet_type: PacketType,
    /// Reference to the packet payload
    pub payload: &'a [u8],
    /// Delivery guarantee for this packet
    pub delivery: DeliveryGuarantee,
    /// Ordering guarantee for this packet
    pub ordering: OrderingGuarantee,
}

impl<'a> PacketInfo<'a> {
    /// Creates packet info for user data with specified guarantees.
    pub fn user_packet(
        payload: &'a [u8],
        delivery: DeliveryGuarantee,
        ordering: OrderingGuarantee,
    ) -> Self {
        PacketInfo { packet_type: PacketType::Packet, payload, delivery, ordering }
    }

    /// Creates packet info for a heartbeat/keepalive packet.
    pub fn heartbeat_packet(payload: &'a [u8]) -> Self {
        PacketInfo {
            packet_type: PacketType::Heartbeat,
            payload,
            delivery: DeliveryGuarantee::Unreliable,
            ordering: OrderingGuarantee::None,
        }
    }
}

// ============================================================================
// Collection Types for Packet Processing
// ============================================================================

/// Iterator over 0, 1, or many items.
#[derive(Debug)]
pub struct ZeroOrMore<T> {
    data: Either<Option<T>, VecDeque<T>>,
}

impl<T> ZeroOrMore<T> {
    pub(crate) fn zero() -> Self {
        Self { data: Either::Left(None) }
    }
    pub(crate) fn one(data: T) -> Self {
        Self { data: Either::Left(Some(data)) }
    }
    pub(crate) fn many(vec: VecDeque<T>) -> Self {
        Self { data: Either::Right(vec) }
    }
}

impl<T> Iterator for ZeroOrMore<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.data {
            Either::Left(option) => option.take(),
            Either::Right(vec) => vec.pop_front(),
        }
    }
}

/// Collection of incoming packets (0, 1, or many) with their types.
/// Used by command-based packet processing to return variable numbers of packets.
#[derive(Debug)]
pub struct IncomingPackets {
    data: ZeroOrMore<(Packet, PacketType)>,
}

impl IncomingPackets {
    /// Creates an empty collection (no packets received).
    pub fn zero() -> Self {
        Self { data: ZeroOrMore::zero() }
    }

    /// Creates a collection with a single packet and type.
    pub fn one(packet: Packet, packet_type: PacketType) -> Self {
        Self { data: ZeroOrMore::one((packet, packet_type)) }
    }

    /// Creates a collection with multiple packets.
    pub fn many(vec: VecDeque<(Packet, PacketType)>) -> Self {
        Self { data: ZeroOrMore::many(vec) }
    }
}

impl IntoIterator for IncomingPackets {
    type Item = (Packet, PacketType);
    type IntoIter = ZeroOrMore<Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.data
    }
}
