//! Command serialization and deserialization.
//!
//! Provides efficient binary encoding/decoding of protocol commands
//! for transmission over the network.

use std::io::{self, Cursor, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crc32fast::Hasher;
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};

use bitwarp_core::{config::CompressionAlgorithm, shared::SharedBytes};
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

    /// Appends a CRC32 checksum to the encoded packet data.
    /// Returns a new vector with the checksum appended.
    pub fn append_checksum(data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let checksum = hasher.finalize();

        let mut result = Vec::with_capacity(data.len() + 4);
        result.extend_from_slice(data);
        result.extend_from_slice(&checksum.to_be_bytes());
        result
    }

    /// Appends a CRC32 checksum to the provided buffer in-place.
    pub fn append_checksum_in_place(data: &mut Vec<u8>) {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let checksum = hasher.finalize();
        data.extend_from_slice(&checksum.to_be_bytes());
    }

    /// Compresses data using the specified algorithm.
    /// Returns compressed data with 1-byte header: `[algorithm_id][compressed_data]`
    /// Returns original data with header `[0][original_data]` if compression is disabled or ineffective.
    pub fn compress(data: &[u8], algorithm: CompressionAlgorithm, threshold: usize) -> io::Result<Vec<u8>> {
        // Don't compress small packets
        if data.len() < threshold {
            let mut result = Vec::with_capacity(data.len() + 1);
            result.push(0); // Uncompressed marker
            result.extend_from_slice(data);
            return Ok(result);
        }

        match algorithm {
            CompressionAlgorithm::None => {
                let mut result = Vec::with_capacity(data.len() + 1);
                result.push(0); // Uncompressed marker
                result.extend_from_slice(data);
                Ok(result)
            }
            CompressionAlgorithm::Zlib => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                let compressed = encoder.finish()?;

                // Only use compression if it actually reduces size
                if compressed.len() < data.len() {
                    let mut result = Vec::with_capacity(compressed.len() + 1);
                    result.push(1); // Zlib marker
                    result.extend_from_slice(&compressed);
                    Ok(result)
                } else {
                    let mut result = Vec::with_capacity(data.len() + 1);
                    result.push(0); // Uncompressed marker
                    result.extend_from_slice(data);
                    Ok(result)
                }
            }
            CompressionAlgorithm::Lz4 => {
                let compressed = lz4::block::compress(data, None, false)?;

                // Only use compression if it actually reduces size
                if compressed.len() + 4 < data.len() { // +4 for original size storage
                    let mut result = Vec::with_capacity(compressed.len() + 5);
                    result.push(2); // LZ4 marker
                    // Store original size as u32 for decompression
                    result.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    result.extend_from_slice(&compressed);
                    Ok(result)
                } else {
                    let mut result = Vec::with_capacity(data.len() + 1);
                    result.push(0); // Uncompressed marker
                    result.extend_from_slice(data);
                    Ok(result)
                }
            }
        }
    }

    /// Compresses data using the specified algorithm with a provided output buffer.
    /// This version reuses the output buffer to reduce allocations in hot paths.
    /// Returns the compressed data, reusing the provided buffer when possible.
    pub fn compress_with_buffer(
        data: &[u8],
        algorithm: CompressionAlgorithm,
        threshold: usize,
        mut output: Vec<u8>,
    ) -> io::Result<Vec<u8>> {
        output.clear();

        // Don't compress small packets
        if data.len() < threshold {
            output.reserve(data.len() + 1);
            output.push(0); // Uncompressed marker
            output.extend_from_slice(data);
            return Ok(output);
        }

        match algorithm {
            CompressionAlgorithm::None => {
                output.reserve(data.len() + 1);
                output.push(0); // Uncompressed marker
                output.extend_from_slice(data);
                Ok(output)
            }
            CompressionAlgorithm::Zlib => {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                let compressed = encoder.finish()?;

                // Only use compression if it actually reduces size
                if compressed.len() < data.len() {
                    output.reserve(compressed.len() + 1);
                    output.push(1); // Zlib marker
                    output.extend_from_slice(&compressed);
                    Ok(output)
                } else {
                    output.reserve(data.len() + 1);
                    output.push(0); // Uncompressed marker
                    output.extend_from_slice(data);
                    Ok(output)
                }
            }
            CompressionAlgorithm::Lz4 => {
                let compressed = lz4::block::compress(data, None, false)?;

                // Only use compression if it actually reduces size
                if compressed.len() + 4 < data.len() {
                    output.reserve(compressed.len() + 5);
                    output.push(2); // LZ4 marker
                    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    output.extend_from_slice(&compressed);
                    Ok(output)
                } else {
                    output.reserve(data.len() + 1);
                    output.push(0); // Uncompressed marker
                    output.extend_from_slice(data);
                    Ok(output)
                }
            }
        }
    }
}

/// Deserializes commands from network bytes.
pub struct CommandDecoder;

impl CommandDecoder {
    /// Decodes a single command from a cursor
    pub fn decode_command(cursor: &mut Cursor<&[u8]>) -> io::Result<ProtocolCommand> {
        let cmd_type = cursor.read_u8()?;

        let command = match cmd_type {
            1 => {
                // SendReliable
                let channel_id = cursor.read_u8()?;
                let sequence = cursor.read_u16::<BigEndian>()?;
                let ordered = cursor.read_u8()? != 0;
                let data_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut data_vec = vec![0u8; data_len];
                cursor.read_exact(&mut data_vec)?;
                let data = SharedBytes::from_vec(data_vec);
                ProtocolCommand::SendReliable { channel_id, sequence, ordered, data }
            }
            2 => {
                // SendUnreliable
                let channel_id = cursor.read_u8()?;
                let data_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut data_vec = vec![0u8; data_len];
                cursor.read_exact(&mut data_vec)?;
                let data = SharedBytes::from_vec(data_vec);
                ProtocolCommand::SendUnreliable { channel_id, data }
            }
            3 => {
                // SendUnreliableSequenced
                let channel_id = cursor.read_u8()?;
                let sequence = cursor.read_u16::<BigEndian>()?;
                let data_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut data_vec = vec![0u8; data_len];
                cursor.read_exact(&mut data_vec)?;
                let data = SharedBytes::from_vec(data_vec);
                ProtocolCommand::SendUnreliableSequenced { channel_id, sequence, data }
            }
            4 => {
                // SendUnsequenced
                let channel_id = cursor.read_u8()?;
                let unsequenced_group = cursor.read_u16::<BigEndian>()?;
                let data_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut data_vec = vec![0u8; data_len];
                cursor.read_exact(&mut data_vec)?;
                let data = SharedBytes::from_vec(data_vec);
                ProtocolCommand::SendUnsequenced { channel_id, unsequenced_group, data }
            }
            5 => {
                // SendFragment (reliable)
                let channel_id = cursor.read_u8()?;
                let sequence = cursor.read_u16::<BigEndian>()?;
                let ordered = cursor.read_u8()? != 0;
                let fragment_id = cursor.read_u8()?;
                let fragment_count = cursor.read_u8()?;
                let data_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut data_vec = vec![0u8; data_len];
                cursor.read_exact(&mut data_vec)?;
                let data = SharedBytes::from_vec(data_vec);
                ProtocolCommand::SendFragment {
                    channel_id,
                    sequence,
                    ordered,
                    fragment_id,
                    fragment_count,
                    data,
                }
            }
            6 => {
                // SendUnreliableFragment
                let channel_id = cursor.read_u8()?;
                let sequence = cursor.read_u16::<BigEndian>()?;
                let fragment_id = cursor.read_u8()?;
                let fragment_count = cursor.read_u8()?;
                let data_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut data_vec = vec![0u8; data_len];
                cursor.read_exact(&mut data_vec)?;
                let data = SharedBytes::from_vec(data_vec);
                ProtocolCommand::SendUnreliableFragment {
                    channel_id,
                    sequence,
                    fragment_id,
                    fragment_count,
                    data,
                }
            }
            7 => {
                // Acknowledge
                let sequence = cursor.read_u16::<BigEndian>()?;
                let received_mask = cursor.read_u32::<BigEndian>()?;
                // sent_time is optional, check if there's more data
                let sent_time = if cursor.position() < cursor.get_ref().len() as u64 {
                    Some(cursor.read_u32::<BigEndian>()?)
                } else {
                    None
                };
                ProtocolCommand::Acknowledge { sequence, received_mask, sent_time }
            }
            8 => {
                // Ping
                let timestamp = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::Ping { timestamp }
            }
            9 => {
                // Pong
                let timestamp = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::Pong { timestamp }
            }
            10 => {
                // Connect
                let channels = cursor.read_u8()?;
                let mtu = cursor.read_u16::<BigEndian>()?;
                let protocol_version = cursor.read_u16::<BigEndian>()?;
                let outgoing_session_id = cursor.read_u16::<BigEndian>()?;
                let connect_id = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::Connect {
                    channels,
                    mtu,
                    protocol_version,
                    outgoing_session_id,
                    connect_id,
                }
            }
            11 => {
                // VerifyConnect
                let peer_id = cursor.read_u16::<BigEndian>()?;
                let channels = cursor.read_u8()?;
                let mtu = cursor.read_u16::<BigEndian>()?;
                let incoming_session_id = cursor.read_u16::<BigEndian>()?;
                let outgoing_session_id = cursor.read_u16::<BigEndian>()?;
                let window_size = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::VerifyConnect {
                    peer_id,
                    channels,
                    mtu,
                    incoming_session_id,
                    outgoing_session_id,
                    window_size,
                }
            }
            12 => {
                // Disconnect
                let reason = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::Disconnect { reason }
            }
            13 => {
                // BandwidthLimit
                let incoming = cursor.read_u32::<BigEndian>()?;
                let outgoing = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::BandwidthLimit { incoming, outgoing }
            }
            14 => {
                // ThrottleConfigure
                let interval = cursor.read_u32::<BigEndian>()?;
                let acceleration = cursor.read_u32::<BigEndian>()?;
                let deceleration = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::ThrottleConfigure { interval, acceleration, deceleration }
            }
            15 => {
                // PMTUProbe
                let size = cursor.read_u16::<BigEndian>()?;
                let token = cursor.read_u32::<BigEndian>()?;
                let payload_len = cursor.read_u16::<BigEndian>()? as usize;
                let mut payload = vec![0u8; payload_len];
                cursor.read_exact(&mut payload)?;
                ProtocolCommand::PMTUProbe { size, token, payload: SharedBytes::from_vec(payload) }
            }
            16 => {
                // PMTUReply
                let size = cursor.read_u16::<BigEndian>()?;
                let token = cursor.read_u32::<BigEndian>()?;
                ProtocolCommand::PMTUReply { size, token }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unknown command type: {}", cmd_type),
                ));
            }
        };

        Ok(command)
    }

    /// Decodes a command packet containing multiple commands
    pub fn decode_packet(data: &[u8]) -> io::Result<CommandPacket> {
        let mut cursor = Cursor::new(data);
        let mut packet = CommandPacket::new();

        // Read command count
        let cmd_count = cursor.read_u8()?;

        // Read each command
        for _ in 0..cmd_count {
            let cmd_len = cursor.read_u16::<BigEndian>()? as usize;
            let pos = cursor.position() as usize;

            if pos + cmd_len > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Command length exceeds buffer",
                ));
            }

            let cmd_data = &data[pos..pos + cmd_len];
            let mut cmd_cursor = Cursor::new(cmd_data);
            let command = Self::decode_command(&mut cmd_cursor)?;

            packet.add_command(command);
            cursor.set_position((pos + cmd_len) as u64);
        }

        Ok(packet)
    }

    /// Validates and strips the CRC32 checksum from packet data.
    /// Returns the data without checksum if valid, or an error if checksum fails.
    pub fn validate_and_strip_checksum(data: &[u8]) -> io::Result<&[u8]> {
        if data.len() < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Data too short for checksum"));
        }

        let (payload, checksum_bytes) = data.split_at(data.len() - 4);
        let received_checksum = u32::from_be_bytes([
            checksum_bytes[0],
            checksum_bytes[1],
            checksum_bytes[2],
            checksum_bytes[3],
        ]);

        let mut hasher = Hasher::new();
        hasher.update(payload);
        let computed_checksum = hasher.finalize();

        if received_checksum != computed_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CRC32 checksum mismatch: expected {}, got {}",
                    computed_checksum, received_checksum
                ),
            ));
        }

        Ok(payload)
    }

    /// Decompresses data based on the 1-byte header.
    /// Header format: `[algorithm_id][data]`
    /// - 0: Uncompressed
    /// - 1: Zlib
    /// - 2: LZ4
    pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty data for decompression"));
        }

        let algorithm_id = data[0];
        let payload = &data[1..];

        match algorithm_id {
            0 => {
                // Uncompressed
                Ok(payload.to_vec())
            }
            1 => {
                // Zlib
                let mut decoder = ZlibDecoder::new(payload);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            2 => {
                // LZ4 - first 4 bytes are original size
                if payload.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "LZ4 payload too short"));
                }
                let original_size = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                let compressed_data = &payload[4..];
                let decompressed = lz4::block::decompress(compressed_data, Some(original_size as i32))?;
                Ok(decompressed)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown compression algorithm: {}", algorithm_id),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_send_reliable() {
        let cmd = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 42,
            ordered: true,
            data: SharedBytes::from_vec(vec![1, 2, 3, 4]),
        };

        let encoded = CommandEncoder::encode_command(&cmd).unwrap();
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = CommandDecoder::decode_command(&mut cursor).unwrap();

        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_acknowledge() {
        let cmd = ProtocolCommand::Acknowledge {
            sequence: 100,
            received_mask: 0xFFFF0000,
            sent_time: Some(12345),
        };

        let encoded = CommandEncoder::encode_command(&cmd).unwrap();
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = CommandDecoder::decode_command(&mut cursor).unwrap();

        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_packet() {
        let mut packet = CommandPacket::new();
        packet.add_command(ProtocolCommand::Ping { timestamp: 1000 });
        packet.add_command(ProtocolCommand::SendUnreliable { channel_id: 0, data: SharedBytes::from_vec(vec![5, 6, 7]) });
        packet.add_command(ProtocolCommand::Acknowledge {
            sequence: 10,
            received_mask: 0xFF,
            sent_time: None,
        });

        let encoded = CommandEncoder::encode_packet(&packet).unwrap();
        let decoded = CommandDecoder::decode_packet(&encoded).unwrap();

        assert_eq!(packet.commands.len(), decoded.commands.len());
        for (orig, dec) in packet.commands.iter().zip(decoded.commands.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn test_checksum_append_and_validate() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Append checksum
        let with_checksum = CommandEncoder::append_checksum(&data);

        // Should be 4 bytes longer (CRC32 is 4 bytes)
        assert_eq!(with_checksum.len(), data.len() + 4);

        // Validate and strip checksum
        let validated = CommandDecoder::validate_and_strip_checksum(&with_checksum).unwrap();

        // Should get back original data
        assert_eq!(validated, &data[..]);
    }

    #[test]
    fn test_checksum_detects_corruption() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut with_checksum = CommandEncoder::append_checksum(&data);

        // Corrupt the data (but not the checksum)
        with_checksum[0] = 99;

        // Should fail validation
        let result = CommandDecoder::validate_and_strip_checksum(&with_checksum);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CRC32 checksum mismatch"));
    }

    #[test]
    fn test_checksum_rejects_short_data() {
        let data = vec![1, 2, 3]; // Only 3 bytes, too short for checksum

        let result = CommandDecoder::validate_and_strip_checksum(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Data too short for checksum"));
    }

    #[test]
    fn test_checksum_with_empty_data() {
        let data = vec![];
        let with_checksum = CommandEncoder::append_checksum(&data);

        // Should be exactly 4 bytes (just the checksum)
        assert_eq!(with_checksum.len(), 4);

        // Validate and strip
        let validated = CommandDecoder::validate_and_strip_checksum(&with_checksum).unwrap();
        assert_eq!(validated.len(), 0);
    }

    #[test]
    fn test_compression_none() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Compress with None algorithm
        let compressed = CommandEncoder::compress(&data, CompressionAlgorithm::None, 128).unwrap();

        // Should have 1-byte header (0) + original data
        assert_eq!(compressed.len(), data.len() + 1);
        assert_eq!(compressed[0], 0); // Uncompressed marker

        // Decompress
        let decompressed = CommandDecoder::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_packet_into_matches_encode_packet() {
        use crate::command::CommandPacket;

        let mut packet = CommandPacket::new();
        packet.add_command(ProtocolCommand::Ping { timestamp: 123 });
        packet.add_command(ProtocolCommand::Pong { timestamp: 456 });
        packet.add_command(ProtocolCommand::Disconnect { reason: 42 });

        let encoded_vec = CommandEncoder::encode_packet(&packet).unwrap();

        let mut into_buf = Vec::new();
        CommandEncoder::encode_packet_into(&mut into_buf, &packet).unwrap();

        assert_eq!(encoded_vec, into_buf);
    }

    #[test]
    fn test_compression_zlib() {
        // Use highly compressible data
        let data = vec![42; 200]; // 200 bytes of the same value

        // Compress with Zlib
        let compressed = CommandEncoder::compress(&data, CompressionAlgorithm::Zlib, 128).unwrap();

        // Should be compressed (marker 1) and smaller than original
        assert_eq!(compressed[0], 1); // Zlib marker
        assert!(compressed.len() < data.len());

        // Decompress
        let decompressed = CommandDecoder::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_lz4() {
        // Use highly compressible data
        let data = vec![99; 200]; // 200 bytes of the same value

        // Compress with LZ4
        let compressed = CommandEncoder::compress(&data, CompressionAlgorithm::Lz4, 128).unwrap();

        // Should be compressed (marker 2) and smaller than original
        assert_eq!(compressed[0], 2); // LZ4 marker
        assert!(compressed.len() < data.len());

        // Decompress
        let decompressed = CommandDecoder::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_below_threshold() {
        let data = vec![1, 2, 3, 4, 5]; // Only 5 bytes

        // Compress with Zlib but below 128-byte threshold
        let compressed = CommandEncoder::compress(&data, CompressionAlgorithm::Zlib, 128).unwrap();

        // Should NOT be compressed (marker 0)
        assert_eq!(compressed[0], 0); // Uncompressed marker
        assert_eq!(compressed.len(), data.len() + 1);

        // Decompress
        let decompressed = CommandDecoder::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_ineffective() {
        // Use random-like data that doesn't compress well
        let data: Vec<u8> = (0..200).map(|i| (i * 13) as u8).collect();

        // Try to compress with Zlib
        let compressed = CommandEncoder::compress(&data, CompressionAlgorithm::Zlib, 128).unwrap();

        // If compression doesn't help, should fall back to uncompressed
        let decompressed = CommandDecoder::decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompression_unknown_algorithm() {
        let data = vec![99, 1, 2, 3, 4]; // Unknown algorithm ID 99

        let result = CommandDecoder::decompress(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown compression algorithm"));
    }
}
