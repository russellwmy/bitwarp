//! Command packet decoding and deserialization.
//!
//! Provides efficient binary decoding of protocol commands received from the network.
//! This module handles the deserialization of command packets, including support for
//! compression and checksum validation through companion modules.

use std::io::{self, Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};

use bitwarp_core::shared::SharedBytes;
use crate::command::{CommandPacket, ProtocolCommand};

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
    ///
    /// This is a convenience wrapper around the checksum module's validation function.
    pub fn validate_and_strip_checksum(data: &[u8]) -> io::Result<&[u8]> {
        super::checksum::validate_and_strip_checksum(data)
    }

    /// Decompresses data based on the 1-byte header.
    /// Header format: `[algorithm_id][data]`
    /// - 0: Uncompressed
    /// - 1: Zlib
    /// - 2: LZ4
    ///
    /// This is a convenience wrapper around the compression module's decompression function.
    pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
        super::compression::decompress(data)
    }
}
