//! Protocol command types for command-based architecture.
//!
//! Everything is a command: sending data, acknowledging packets,
//! pinging, disconnecting, etc. Commands are aggregated into larger packets
//! to improve bandwidth utilization.

use std::time::Instant;
use bitwarp_core::shared::SharedBytes;

/// Protocol commands that can be sent between peers.
///
/// All protocol operations are represented as discrete commands that can be aggregated.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolCommand {
    /// Send reliable data on a channel
    SendReliable {
        /// Channel identifier (0-255)
        channel_id: u8,
        /// Sequence number for ordering
        sequence: u16,
        /// Whether to deliver in order on receive (true) or unordered (false)
        ordered: bool,
        /// Payload data (shared, sliceable)
        data: SharedBytes,
    },

    /// Send unreliable data on a channel
    SendUnreliable {
        /// Channel identifier (0-255)
        channel_id: u8,
        /// Payload data (shared slice)
        data: SharedBytes,
    },

    /// Send sequenced unreliable data (drops old packets)
    SendUnreliableSequenced {
        /// Channel identifier (0-255)
        channel_id: u8,
        /// Sequence number for dropping old packets
        sequence: u16,
        /// Payload data (shared slice)
        data: SharedBytes,
    },

    /// Send unsequenced unreliable data (prevents duplicates without ordering)
    SendUnsequenced {
        /// Channel identifier (0-255)
        channel_id: u8,
        /// Unsequenced group identifier for duplicate detection
        unsequenced_group: u16,
        /// Payload data (shared slice)
        data: SharedBytes,
    },

    /// Fragment of a larger reliable packet
    SendFragment {
        /// Channel identifier (0-255)
        channel_id: u8,
        /// Sequence number of the original packet
        sequence: u16,
        /// Whether to deliver in order on receive (true) or unordered (false)
        ordered: bool,
        /// Fragment index (0-based)
        fragment_id: u8,
        /// Total number of fragments
        fragment_count: u8,
        /// Fragment data (shared slice)
        data: SharedBytes,
    },

    /// Fragment of a larger unreliable packet
    SendUnreliableFragment {
        /// Channel identifier (0-255)
        channel_id: u8,
        /// Sequence number of the original packet (for reassembly)
        sequence: u16,
        /// Fragment index (0-based)
        fragment_id: u8,
        /// Total number of fragments
        fragment_count: u8,
        /// Fragment data (shared slice)
        data: SharedBytes,
    },

    /// Acknowledge received reliable packets
    Acknowledge {
        /// Sequence number being acknowledged
        sequence: u16,
        /// Bitfield of additional acknowledged packets (32 packets before sequence)
        received_mask: u32,
        /// Timestamp for RTT calculation (optional)
        sent_time: Option<u32>,
    },

    /// Ping to measure RTT and keep connection alive
    Ping {
        /// Timestamp (milliseconds since epoch or relative)
        timestamp: u32,
    },

    /// Pong response to ping
    Pong {
        /// Original timestamp from ping
        timestamp: u32,
    },

    /// Request to establish connection (3-way handshake step 1)
    Connect {
        /// Number of channels to allocate
        channels: u8,
        /// Maximum transmission unit
        mtu: u16,
        /// Protocol version
        protocol_version: u16,
        /// Outgoing session ID from client
        outgoing_session_id: u16,
        /// Connect ID for replay protection
        connect_id: u32,
    },

    /// Verify connection (3-way handshake step 2) - replaces old ConnectAck
    VerifyConnect {
        /// Assigned peer ID
        peer_id: u16,
        /// Channels allocated
        channels: u8,
        /// Maximum transmission unit
        mtu: u16,
        /// Incoming session ID (from server's perspective)
        incoming_session_id: u16,
        /// Outgoing session ID (from server's perspective)
        outgoing_session_id: u16,
        /// Window size for flow control
        window_size: u32,
    },

    /// Request to disconnect
    Disconnect {
        /// Reason code (application-defined)
        reason: u32,
    },

    /// Bandwidth limit notification
    BandwidthLimit {
        /// Incoming bandwidth limit (bytes/sec, 0 = unlimited)
        incoming: u32,
        /// Outgoing bandwidth limit (bytes/sec, 0 = unlimited)
        outgoing: u32,
    },

    /// Throttle configuration for congestion control
    ThrottleConfigure {
        /// Throttle interval in milliseconds
        interval: u32,
        /// Throttle acceleration rate
        acceleration: u32,
        /// Throttle deceleration rate
        deceleration: u32,
    },

    /// Path MTU probe: request to test a payload of given size
    PMTUProbe {
        /// Probe payload size in bytes
        size: u16,
        /// Correlation token
        token: u32,
        /// Probe payload (shared slice) sized to `size`
        payload: SharedBytes,
    },

    /// Path MTU reply: response to a PMTU probe
    PMTUReply {
        /// Echoed probe size
        size: u16,
        /// Echoed token
        token: u32,
    },
}

impl ProtocolCommand {
    /// Returns the command type identifier for serialization
    pub fn command_type(&self) -> u8 {
        match self {
            ProtocolCommand::SendReliable { .. } => 1,
            ProtocolCommand::SendUnreliable { .. } => 2,
            ProtocolCommand::SendUnreliableSequenced { .. } => 3,
            ProtocolCommand::SendUnsequenced { .. } => 4,
            ProtocolCommand::SendFragment { .. } => 5,
            ProtocolCommand::SendUnreliableFragment { .. } => 6,
            ProtocolCommand::Acknowledge { .. } => 7,
            ProtocolCommand::Ping { .. } => 8,
            ProtocolCommand::Pong { .. } => 9,
            ProtocolCommand::Connect { .. } => 10,
            ProtocolCommand::VerifyConnect { .. } => 11,
            ProtocolCommand::Disconnect { .. } => 12,
            ProtocolCommand::BandwidthLimit { .. } => 13,
            ProtocolCommand::ThrottleConfigure { .. } => 14,
            ProtocolCommand::PMTUProbe { .. } => 15,
            ProtocolCommand::PMTUReply { .. } => 16,
        }
    }

    /// Returns true if this command requires reliable delivery
    pub fn is_reliable(&self) -> bool {
        matches!(
            self,
            ProtocolCommand::SendReliable { .. }
                | ProtocolCommand::SendFragment { .. }
                | ProtocolCommand::Connect { .. }
                | ProtocolCommand::VerifyConnect { .. }
                | ProtocolCommand::Disconnect { .. }
        )
    }

    /// Returns the channel ID if this is a data command
    pub fn channel_id(&self) -> Option<u8> {
        match self {
            ProtocolCommand::SendReliable { channel_id, .. }
            | ProtocolCommand::SendUnreliable { channel_id, .. }
            | ProtocolCommand::SendUnreliableSequenced { channel_id, .. }
            | ProtocolCommand::SendUnsequenced { channel_id, .. }
            | ProtocolCommand::SendFragment { channel_id, .. }
            | ProtocolCommand::SendUnreliableFragment { channel_id, .. } => Some(*channel_id),
            _ => None,
        }
    }
}

/// Aggregated packet containing multiple protocol commands.
///
/// Aggregates commands into larger packets to reduce overhead
/// and improve bandwidth utilization.
#[derive(Debug, Clone)]
pub struct CommandPacket {
    /// Protocol commands in this packet
    pub commands: Vec<ProtocolCommand>,
    /// Timestamp when packet was created
    pub timestamp: Instant,
}

impl CommandPacket {
    /// Creates a new empty command packet
    pub fn new() -> Self {
        Self { commands: Vec::new(), timestamp: Instant::now() }
    }

    /// Creates a command packet with a single command
    pub fn single(command: ProtocolCommand) -> Self {
        Self { commands: vec![command], timestamp: Instant::now() }
    }

    /// Adds a command to this packet
    pub fn add_command(&mut self, command: ProtocolCommand) {
        self.commands.push(command);
    }

    /// Returns true if the packet has no commands
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Returns the number of commands in this packet
    pub fn len(&self) -> usize {
        self.commands.len()
    }
}

impl Default for CommandPacket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_types() {
        use bitwarp_core::shared::SharedBytes;
        let cmd = ProtocolCommand::SendReliable { channel_id: 0, sequence: 1, ordered: true, data: SharedBytes::from_vec(vec![1, 2, 3]) };
        assert_eq!(cmd.command_type(), 1);
        assert!(cmd.is_reliable());
        assert_eq!(cmd.channel_id(), Some(0));
    }

    #[test]
    fn test_command_packet_aggregation() {
        let mut packet = CommandPacket::new();
        assert!(packet.is_empty());

        packet.add_command(ProtocolCommand::Ping { timestamp: 100 });
        packet.add_command(ProtocolCommand::SendUnreliable { channel_id: 0, data: SharedBytes::from_vec(vec![1, 2, 3]) });

        assert_eq!(packet.len(), 2);
        assert!(!packet.is_empty());
    }
}
