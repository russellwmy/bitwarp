use bitwarp_protocol::{
    command::CommandPacket,
    command_codec::{self, CommandEncoder},
};

use crate::peer::Peer;

impl Peer {
    /// Encodes all queued commands into a CommandPacket and returns the bytes.
    /// Drains the command queue in the process.
    /// Applies compression if enabled, then appends CRC32 checksum if enabled.
    pub fn encode_queued_commands(&mut self) -> std::io::Result<Vec<u8>> {
        let mut packet = CommandPacket::new();
        for command in self.drain_commands() {
            packet.add_command(command);
        }

        // Encode into a pooled scratch buffer to avoid intermediate Vec allocations per step
        let mut scratch = self.tx_pool.allocate();
        scratch.clear();
        CommandEncoder::encode_packet_into(&mut scratch, &packet)?;

        // Apply compression using pooled buffer to reduce allocations
        let compression_buffer = self.compression_pool.acquire();
        let mut final_data = command_codec::compress_with_buffer(
            &scratch,
            self.config.compression,
            self.config.compression_threshold,
            compression_buffer,
        )?;

        // Return scratch to pool
        self.tx_pool.deallocate(scratch);

        // Record packet being sent
        self.record_packet_sent();

        // Append checksum if enabled (after compression) in-place
        if self.config.use_checksums {
            command_codec::append_checksum_in_place(&mut final_data);
        }

        // Track bytes sent
        self.record_data_sent(final_data.len());

        Ok(final_data)
    }

    /// Encodes up to `max_size` bytes worth of queued commands into a single datagram.
    ///
    /// - Returns `Ok(None)` if there are no queued commands.
    /// - Returns `Ok(Some(bytes))` where `bytes.len() <= max_size` when data was produced.
    ///
    /// This prevents producing UDP payloads larger than the configured receive buffer (and typical MTUs),
    /// avoiding OS-level EMSGSIZE errors and IP fragmentation.
    pub fn encode_queued_commands_bounded(
        &mut self,
        max_size: usize,
    ) -> std::io::Result<Option<Vec<u8>>> {
        if !self.has_queued_commands() {
            return Ok(None);
        }

        // Worst-case overhead outside of command bytes:
        // - 1 byte command count header
        // - per-command 2-byte length prefix
        // - compression marker/header (1 byte; LZ4 adds extra 4 bytes to store original size)
        // - optional checksum (4 bytes)
        let compression_overhead = match self.config.compression {
            bitwarp_core::config::CompressionAlgorithm::Lz4 => 5, // 1 marker + 4 original size
            _ => 1, // 1 marker for None/Zlib
        };
        let checksum_overhead = if self.config.use_checksums { 4 } else { 0 };
        let static_overhead = 1 /* command count */ + compression_overhead + checksum_overhead;

        // Select as many commands as will fit within max_size when encoded
        let mut selected_count = 0usize;
        let mut aggregated_len = 0; // track only command bytes (static_overhead already includes command count)

        // Pre-encode commands individually to know precise sizes
        let mut per_command_sizes: Vec<usize> = Vec::new();
        for cmd in self.command_queue.iter() {
            let encoded = bitwarp_protocol::command_codec::CommandEncoder::encode_command(cmd)?;
            let cmd_total = 2 /* length prefix */ + encoded.len();

            // Check if adding this command would exceed limit (including trailing overhead)
            if static_overhead + aggregated_len + cmd_total > max_size {
                break;
            }

            aggregated_len += cmd_total;
            per_command_sizes.push(cmd_total);
            selected_count += 1;
        }

        if selected_count == 0 {
            // First command is too large to fit within max_size
            // This can happen with very large data payloads or very small MTU
            if let Some(first_cmd) = self.command_queue.iter().next() {
                let encoded = bitwarp_protocol::command_codec::CommandEncoder::encode_command(first_cmd)?;
                let cmd_size = 2 + encoded.len();
                let total_with_overhead = static_overhead + cmd_size;

                tracing::warn!(
                    "Command too large for MTU: command type {:?}, encoded size {} bytes, total with overhead {} bytes, max allowed {} bytes. Command will remain queued.",
                    first_cmd.command_type(),
                    cmd_size,
                    total_with_overhead,
                    max_size
                );
            }
            // Nothing selected within the budget; avoid emitting oversize datagrams.
            return Ok(None);
        }

        // Drain exactly selected_count commands, requeue the rest to preserve order
        let drained: Vec<_> = self.drain_commands().collect();
        let mut packet = CommandPacket::new();
        for cmd in drained.iter().take(selected_count) {
            packet.add_command(cmd.clone());
        }
        for cmd in drained.into_iter().skip(selected_count) {
            self.enqueue_command(cmd);
        }

        // Encode into pooled scratch buffer
        let mut scratch = self.tx_pool.allocate();
        scratch.clear();
        bitwarp_protocol::command_codec::CommandEncoder::encode_packet_into(&mut scratch, &packet)?;

        // Apply compression using pooled buffer
        let compression_buffer = self.compression_pool.acquire();
        let mut final_data = command_codec::compress_with_buffer(
            &scratch,
            self.config.compression,
            self.config.compression_threshold,
            compression_buffer,
        )?;
        self.tx_pool.deallocate(scratch);

        // Record packet and bytes sent
        self.record_packet_sent();

        if self.config.use_checksums {
            command_codec::append_checksum_in_place(&mut final_data);
        }

        // Track bytes sent (full encoded size after compression/checksum)
        self.record_data_sent(final_data.len());

        // Sanity guard: ensure we did not exceed max_size
        if final_data.len() > max_size {
            tracing::error!(
                "Encoded packet exceeded max_size after compression: {} bytes > {} bytes max. Selected {} commands, pre-compression size was {} bytes (command bytes) + {} bytes (overhead). Commands will remain queued.",
                final_data.len(),
                max_size,
                selected_count,
                aggregated_len,
                static_overhead
            );
            // Avoid producing oversize datagrams; keep commands queued for next attempt
            return Ok(None);
        }

        Ok(Some(final_data))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bitwarp_core::config::{CompressionAlgorithm, Config};
    use bitwarp_protocol::command::ProtocolCommand;

    use super::*;

    fn create_virtual_connection() -> Peer {
        Peer::new(get_fake_addr(), &Config::default(), Instant::now())
    }

    fn get_fake_addr() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn test_encode_decode_command_packet() {
        let mut peer = create_virtual_connection();

        // Enqueue several commands
        peer.enqueue_command(ProtocolCommand::Ping { timestamp: 100 });
        peer.enqueue_command(ProtocolCommand::SendUnreliable {
            channel_id: 0,
            data: vec![1, 2, 3].into(),
        });
        peer.enqueue_ack_command(Some(5000));

        assert_eq!(peer.queued_commands_count(), 3);

        // Encode to bytes
        let bytes = peer.encode_queued_commands().unwrap();
        assert!(!bytes.is_empty());
        assert!(!peer.has_queued_commands()); // Should be drained

        // Decode and process on another peer
        let mut peer2 = create_virtual_connection();
        let result = peer2.process_command_packet(&bytes, Instant::now()).unwrap();

        // Should have received the unreliable data packet
        let packets: Vec<_> = result.into_iter().collect();
        assert_eq!(packets.len(), 1);

        // peer2 should have queued responses (Pong for Ping)
        assert!(peer2.has_queued_commands());
    }

    #[test]
    fn test_checksum_enabled_end_to_end() {
        let mut config = Config::default();
        config.use_checksums = true;

        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Enqueue a command
        peer.enqueue_command(ProtocolCommand::Ping { timestamp: 1234 });

        // Encode with checksum
        let encoded = peer.encode_queued_commands().unwrap();

        // Should be longer due to checksum (4 bytes)
        assert!(encoded.len() > 10); // At least command data + checksum

        // Process the packet with checksum validation
        let result = peer.process_command_packet(&encoded, time);
        assert!(result.is_ok()); // Should succeed with valid checksum
    }

    #[test]
    fn test_checksum_detects_corruption_in_peer() {
        let mut config = Config::default();
        config.use_checksums = true;

        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Enqueue a command
        peer.enqueue_command(ProtocolCommand::SendUnreliable {
            channel_id: 0,
            data: vec![1, 2, 3, 4, 5].into(),
        });

        // Encode with checksum
        let mut encoded = peer.encode_queued_commands().unwrap();

        // Corrupt the data (but not the checksum at the end)
        if encoded.len() > 5 {
            encoded[0] = 99;
        }

        // Process the corrupted packet - should fail checksum validation
        let result = peer.process_command_packet(&encoded, time);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_disabled_backward_compatibility() {
        let mut config = Config::default();
        config.use_checksums = false; // Disabled (default)

        let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
        let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Enqueue a command on peer1
        peer1.enqueue_command(ProtocolCommand::Ping { timestamp: 5678 });

        // Encode without checksum
        let encoded = peer1.encode_queued_commands().unwrap();

        // Process on peer2 (also without checksum validation)
        let result = peer2.process_command_packet(&encoded, time);
        assert!(result.is_ok()); // Should work without checksums
    }

    #[test]
    fn test_compression_zlib_end_to_end() {
        let mut config = Config::default();
        config.compression = CompressionAlgorithm::Zlib;
        config.compression_threshold = 10;

        let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
        let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Enqueue a large, compressible command
        peer1.enqueue_command(ProtocolCommand::SendUnreliable {
            channel_id: 0,
            data: vec![42; 300].into(), // Highly compressible
        });

        // Encode with compression
        let encoded = peer1.encode_queued_commands().unwrap();

        // Should be compressed (smaller than uncompressed would be)
        // Uncompressed would be ~300 + overhead, compressed should be much smaller
        assert!(encoded.len() < 100); // Compressed size

        // Process on peer2
        let result = peer2.process_command_packet(&encoded, time);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compression_lz4_end_to_end() {
        let mut config = Config::default();
        config.compression = CompressionAlgorithm::Lz4;
        config.compression_threshold = 10;

        let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
        let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Enqueue a large, compressible command
        peer1.enqueue_command(ProtocolCommand::SendUnreliable {
            channel_id: 0,
            data: vec![99; 300].into(), // Highly compressible
        });

        // Encode with compression
        let encoded = peer1.encode_queued_commands().unwrap();

        // Should be compressed
        assert!(encoded.len() < 100);

        // Process on peer2
        let result = peer2.process_command_packet(&encoded, time);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compression_disabled_by_default() {
        let config = Config::default();

        let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
        let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Enqueue a command
        peer1.enqueue_command(ProtocolCommand::Ping { timestamp: 1234 });

        // Encode without compression (default)
        let encoded = peer1.encode_queued_commands().unwrap();

        // First byte (after any header) should be 0 (uncompressed marker)
        assert_eq!(encoded[0], 0);

        // Process on peer2
        let result = peer2.process_command_packet(&encoded, time);
        assert!(result.is_ok());
    }

    #[test]
    fn test_statistics_with_compression() {
        let mut config = Config::default();
        config.compression = CompressionAlgorithm::Lz4;
        config.compression_threshold = 10;
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        // Enqueue data that will be compressed
        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![1; 100].into(), // Repeating data compresses well
        });

        let encoded = peer.encode_queued_commands().unwrap();

        // bytes_sent should track the compressed size
        assert_eq!(peer.statistics().bytes_sent, encoded.len() as u64);
        assert!(peer.statistics().bytes_sent < 100); // Should be compressed
    }

    #[test]
    fn test_statistics_with_checksums() {
        let mut config = Config::default();
        config.use_checksums = true;
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![1, 2, 3].into(),
        });

        let encoded = peer.encode_queued_commands().unwrap();

        // bytes_sent should include checksum overhead (4 bytes)
        assert_eq!(peer.statistics().bytes_sent, encoded.len() as u64);
        assert!(encoded.len() >= 4); // At least checksum size
    }

    #[test]
    fn test_mtu_boundary_calculation() {
        let mut config = Config::default();
        config.use_checksums = false;
        config.compression = bitwarp_core::config::CompressionAlgorithm::None;
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        // Calculate exact payload size that should fit in 1440 bytes MTU
        // Packet structure:
        // - 1 byte command count
        // - 1 byte compression marker (even for None)
        // - 2 bytes length prefix per command
        // - SendReliable command: 1 (type) + 1 (channel) + 2 (seq) + 1 (ordered) + 2 (data len) + data
        // Total: 1 + 1 + 2 + (1 + 1 + 2 + 1 + 2) + data = 11 + data
        // So max data = 1440 - 11 = 1429 bytes
        let max_payload_for_mtu = 1429;

        // Enqueue a command with exactly max_payload_for_mtu bytes
        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![42u8; max_payload_for_mtu].into(),
        });

        // Should fit within MTU (1440 bytes)
        let result = peer.encode_queued_commands_bounded(1440);
        assert!(result.is_ok());
        let encoded = result.unwrap();
        assert!(encoded.is_some(), "Command should fit within MTU");

        let bytes = encoded.unwrap();
        assert_eq!(bytes.len(), 1440, "Encoded size should be exactly 1440 bytes");

        // Verify no commands remain queued
        assert!(!peer.has_queued_commands());
    }

    #[test]
    fn test_mtu_boundary_too_large() {
        let mut config = Config::default();
        config.use_checksums = false;
        config.compression = bitwarp_core::config::CompressionAlgorithm::None;
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        // Try to enqueue a command that's 1 byte too large
        let too_large_payload = 1430; // 11 + 1430 = 1441 bytes total

        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![42u8; too_large_payload].into(),
        });

        // Should NOT fit within MTU (would be 1441 bytes)
        let result = peer.encode_queued_commands_bounded(1440);
        assert!(result.is_ok());
        let encoded = result.unwrap();
        assert!(encoded.is_none(), "Command should NOT fit within MTU");

        // Command should remain queued
        assert!(peer.has_queued_commands());
    }
}
