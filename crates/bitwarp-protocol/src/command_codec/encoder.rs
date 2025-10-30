//! Command packet encoding.
//!
//! Provides efficient binary serialization of protocol commands
//! for transmission over the network.

use std::io::{self, Write};

use byteorder::{BigEndian, WriteBytesExt};

use crate::command::{CommandPacket, ProtocolCommand};

/// Serializes a command packet into bytes for transmission.
pub struct CommandEncoder;

impl CommandEncoder {
    /// Encodes a single command into the provided buffer (appends bytes).
    pub fn encode_command_into(buffer: &mut Vec<u8>, command: &ProtocolCommand) -> io::Result<()> {
        // Write command type
        buffer.write_u8(command.command_type())?;

        match command {
            ProtocolCommand::SendReliable { channel_id, sequence, ordered, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u8(if *ordered { 1 } else { 0 })?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnreliable { channel_id, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnreliableSequenced { channel_id, sequence, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnsequenced { channel_id, unsequenced_group, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*unsequenced_group)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendFragment { channel_id, sequence, ordered, fragment_id, fragment_count, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u8(if *ordered { 1 } else { 0 })?;
                buffer.write_u8(*fragment_id)?;
                buffer.write_u8(*fragment_count)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnreliableFragment { channel_id, sequence, fragment_id, fragment_count, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u8(*fragment_id)?;
                buffer.write_u8(*fragment_count)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::Acknowledge { sequence, received_mask, sent_time } => {
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u32::<BigEndian>(*received_mask)?;
                if let Some(time) = sent_time {
                    buffer.write_u32::<BigEndian>(*time)?;
                }
            }
            ProtocolCommand::Ping { timestamp } => {
                buffer.write_u32::<BigEndian>(*timestamp)?;
            }
            ProtocolCommand::Pong { timestamp } => {
                buffer.write_u32::<BigEndian>(*timestamp)?;
            }
            ProtocolCommand::Connect { channels, mtu, protocol_version, outgoing_session_id, connect_id } => {
                buffer.write_u8(*channels)?;
                buffer.write_u16::<BigEndian>(*mtu)?;
                buffer.write_u16::<BigEndian>(*protocol_version)?;
                buffer.write_u16::<BigEndian>(*outgoing_session_id)?;
                buffer.write_u32::<BigEndian>(*connect_id)?;
            }
            ProtocolCommand::VerifyConnect { peer_id, channels, mtu, incoming_session_id, outgoing_session_id, window_size } => {
                buffer.write_u16::<BigEndian>(*peer_id)?;
                buffer.write_u8(*channels)?;
                buffer.write_u16::<BigEndian>(*mtu)?;
                buffer.write_u16::<BigEndian>(*incoming_session_id)?;
                buffer.write_u16::<BigEndian>(*outgoing_session_id)?;
                buffer.write_u32::<BigEndian>(*window_size)?;
            }
            ProtocolCommand::Disconnect { reason } => {
                buffer.write_u32::<BigEndian>(*reason)?;
            }
            ProtocolCommand::BandwidthLimit { incoming, outgoing } => {
                buffer.write_u32::<BigEndian>(*incoming)?;
                buffer.write_u32::<BigEndian>(*outgoing)?;
            }
            ProtocolCommand::ThrottleConfigure { interval, acceleration, deceleration } => {
                buffer.write_u32::<BigEndian>(*interval)?;
                buffer.write_u32::<BigEndian>(*acceleration)?;
                buffer.write_u32::<BigEndian>(*deceleration)?;
            }
            ProtocolCommand::PMTUProbe { size, token, payload } => {
                buffer.write_u16::<BigEndian>(*size)?;
                buffer.write_u32::<BigEndian>(*token)?;
                buffer.write_u16::<BigEndian>(payload.len() as u16)?;
                buffer.write_all(payload.as_slice())?;
            }
            ProtocolCommand::PMTUReply { size, token } => {
                buffer.write_u16::<BigEndian>(*size)?;
                buffer.write_u32::<BigEndian>(*token)?;
            }
        }

        Ok(())
    }

    /// Encodes a command packet into the provided buffer (appends bytes) without intermediate allocations per command.
    pub fn encode_packet_into(buffer: &mut Vec<u8>, packet: &CommandPacket) -> io::Result<()> {
        // Write command count
        buffer.write_u8(packet.commands.len() as u8)?;

        // Write each command with a length prefix. We first reserve space for the length,
        // encode the command, then patch the length in place.
        for command in &packet.commands {
            let len_pos = buffer.len();
            buffer.write_u16::<BigEndian>(0)?; // placeholder for length
            let start = buffer.len();
            Self::encode_command_into(buffer, command)?;
            let cmd_len = buffer.len() - start;
            // Patch the length
            buffer[len_pos] = ((cmd_len >> 8) & 0xFF) as u8;
            buffer[len_pos + 1] = (cmd_len & 0xFF) as u8;
        }

        Ok(())
    }

    /// Encodes a single command into a byte vector
    pub fn encode_command(command: &ProtocolCommand) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write command type
        buffer.write_u8(command.command_type())?;

        match command {
            ProtocolCommand::SendReliable { channel_id, sequence, ordered, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u8(if *ordered { 1 } else { 0 })?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnreliable { channel_id, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnreliableSequenced { channel_id, sequence, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnsequenced { channel_id, unsequenced_group, data } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*unsequenced_group)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendFragment {
                channel_id,
                sequence,
                ordered,
                fragment_id,
                fragment_count,
                data,
            } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u8(if *ordered { 1 } else { 0 })?;
                buffer.write_u8(*fragment_id)?;
                buffer.write_u8(*fragment_count)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::SendUnreliableFragment {
                channel_id,
                sequence,
                fragment_id,
                fragment_count,
                data,
            } => {
                buffer.write_u8(*channel_id)?;
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u8(*fragment_id)?;
                buffer.write_u8(*fragment_count)?;
                buffer.write_u16::<BigEndian>(data.len() as u16)?;
                buffer.write_all(data.as_slice())?;
            }
            ProtocolCommand::Acknowledge { sequence, received_mask, sent_time } => {
                buffer.write_u16::<BigEndian>(*sequence)?;
                buffer.write_u32::<BigEndian>(*received_mask)?;
                if let Some(time) = sent_time {
                    buffer.write_u32::<BigEndian>(*time)?;
                }
            }
            ProtocolCommand::Ping { timestamp } => {
                buffer.write_u32::<BigEndian>(*timestamp)?;
            }
            ProtocolCommand::Pong { timestamp } => {
                buffer.write_u32::<BigEndian>(*timestamp)?;
            }
            ProtocolCommand::Connect {
                channels,
                mtu,
                protocol_version,
                outgoing_session_id,
                connect_id,
            } => {
                buffer.write_u8(*channels)?;
                buffer.write_u16::<BigEndian>(*mtu)?;
                buffer.write_u16::<BigEndian>(*protocol_version)?;
                buffer.write_u16::<BigEndian>(*outgoing_session_id)?;
                buffer.write_u32::<BigEndian>(*connect_id)?;
            }
            ProtocolCommand::VerifyConnect {
                peer_id,
                channels,
                mtu,
                incoming_session_id,
                outgoing_session_id,
                window_size,
            } => {
                buffer.write_u16::<BigEndian>(*peer_id)?;
                buffer.write_u8(*channels)?;
                buffer.write_u16::<BigEndian>(*mtu)?;
                buffer.write_u16::<BigEndian>(*incoming_session_id)?;
                buffer.write_u16::<BigEndian>(*outgoing_session_id)?;
                buffer.write_u32::<BigEndian>(*window_size)?;
            }
            ProtocolCommand::Disconnect { reason } => {
                buffer.write_u32::<BigEndian>(*reason)?;
            }
            ProtocolCommand::BandwidthLimit { incoming, outgoing } => {
                buffer.write_u32::<BigEndian>(*incoming)?;
                buffer.write_u32::<BigEndian>(*outgoing)?;
            }
            ProtocolCommand::ThrottleConfigure { interval, acceleration, deceleration } => {
                buffer.write_u32::<BigEndian>(*interval)?;
                buffer.write_u32::<BigEndian>(*acceleration)?;
                buffer.write_u32::<BigEndian>(*deceleration)?;
            }
            ProtocolCommand::PMTUProbe { size, token, payload } => {
                buffer.write_u16::<BigEndian>(*size)?;
                buffer.write_u32::<BigEndian>(*token)?;
                buffer.write_u16::<BigEndian>(payload.len() as u16)?;
                buffer.write_all(payload.as_slice())?;
            }
            ProtocolCommand::PMTUReply { size, token } => {
                buffer.write_u16::<BigEndian>(*size)?;
                buffer.write_u32::<BigEndian>(*token)?;
            }
        }

        Ok(buffer)
    }

    /// Encodes a command packet with multiple commands
    pub fn encode_packet(packet: &CommandPacket) -> io::Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // Write command count
        buffer.write_u8(packet.commands.len() as u8)?;

        // Write each command with length prefix
        for command in &packet.commands {
            let cmd_bytes = Self::encode_command(command)?;
            buffer.write_u16::<BigEndian>(cmd_bytes.len() as u16)?;
            buffer.write_all(&cmd_bytes)?;
        }

        Ok(buffer)
    }
}
