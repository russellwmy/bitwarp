use std::sync::Arc;

use bitwarp_core::shared::SharedBytes;
use bitwarp_protocol::command::ProtocolCommand;

use super::Peer;

impl Peer {
    /// Enqueues reliable data, automatically fragmenting if necessary.
    /// Returns the sequence number used for the packet(s).
    pub fn enqueue_reliable_data(&mut self, channel_id: u8, data: Arc<[u8]>, ordered: bool) -> u16 {
        let sequence = self.acknowledge_handler.local_sequence_num();

        // Compute datagram cap and per-command payload budget so a single
        // SendReliable or SendFragment fits within one UDP datagram when encoded.
        let datagram_cap = std::cmp::min(
            self.current_fragment_size() as usize,
            self.config.receive_buffer_max_size,
        );
        // Overheads common to any datagram containing exactly one command
        let compression_overhead = match self.config.compression {
            bitwarp_core::config::CompressionAlgorithm::Lz4 => 5, // marker + original size
            _ => 1, // marker only
        };
        let checksum_overhead = if self.config.use_checksums { 4 } else { 0 };
        let per_packet_overhead = 1 /* command count */ + compression_overhead + checksum_overhead;

        // Header sizes for commands (not including the 2-byte length prefix)
        let send_reliable_header = 1 /* type */ + 1 /* channel */ + 2 /* sequence */
            + 1 /* ordered flag */ + 2 /* payload len */; // = 7
        let send_fragment_header = 1 /* type */ + 1 /* channel */ + 2 /* sequence */
            + 1 /* ordered flag */ + 1 /* frag_id */ + 1 /* frag_count */ + 2 /* len */; // = 9

        // Maximum payload that fits for non-fragmented reliable
        let max_payload_reliable = datagram_cap
            .saturating_sub(per_packet_overhead)
            .saturating_sub(2 /* len prefix */)
            .saturating_sub(send_reliable_header);

        // Validate MTU is large enough for minimum payload
        if max_payload_reliable < 1 {
            tracing::error!(
                "MTU too small: datagram_cap={}, overhead={}, can't fit minimum payload",
                datagram_cap,
                per_packet_overhead + 2 + send_reliable_header
            );
            // Send nothing but log the error
            return sequence;
        }

        if data.len() <= max_payload_reliable {
            // No fragmentation needed (fits as a single SendReliable)
            self.enqueue_command(ProtocolCommand::SendReliable {
                channel_id,
                sequence,
                ordered,
                data: SharedBytes::from_arc(data),
            });
        } else {
            // Fragment the data; compute fragment payload budget so each fragment packet fits
            let fragment_payload = datagram_cap
                .saturating_sub(per_packet_overhead)
                .saturating_sub(2 /* len prefix */)
                .saturating_sub(send_fragment_header);

            if fragment_payload < 1 {
                tracing::error!(
                    "MTU too small for fragmentation: datagram_cap={}, overhead={}, can't fit minimum fragment payload",
                    datagram_cap,
                    per_packet_overhead + 2 + send_fragment_header
                );
                return sequence;
            }

            // Check for integer overflow before casting to u8
            let total_fragments_usize = (data.len() + fragment_payload - 1) / fragment_payload;
            if total_fragments_usize > u8::MAX as usize {
                tracing::warn!(
                    "Payload {} bytes too large to fragment: would require {} fragments (max {}), dropping packet",
                    data.len(),
                    total_fragments_usize,
                    u8::MAX
                );
                return sequence;
            }
            let total_fragments = total_fragments_usize as u8;

            if total_fragments > self.config.max_fragments {
                tracing::warn!(
                    "Payload requires {} fragments but max allowed is {}, sending first fragment only",
                    total_fragments,
                    self.config.max_fragments
                );
                // Too many fragments - send the first fragment only (best-effort)
                let base = SharedBytes::from_arc(data);
                let fragment_data = base.slice(0, fragment_payload.min(base.len()));
                self.enqueue_command(ProtocolCommand::SendFragment {
                    channel_id,
                    sequence,
                    ordered,
                    fragment_id: 0,
                    fragment_count: 1,
                    data: fragment_data,
                });
                return sequence;
            }

            tracing::trace!(
                "Fragmenting {} byte payload into {} fragments ({} bytes each)",
                data.len(),
                total_fragments,
                fragment_payload
            );

            for fragment_id in 0..total_fragments {
                let start = (fragment_id as usize) * fragment_payload;
                let end = ((fragment_id as usize + 1) * fragment_payload).min(data.len());
                let base = SharedBytes::from_arc(data.clone());
                let fragment_data = base.slice(start, end - start);
                self.enqueue_command(ProtocolCommand::SendFragment {
                    channel_id,
                    sequence,
                    ordered,
                    fragment_id,
                    fragment_count: total_fragments,
                    data: fragment_data,
                });
            }
        }

        sequence
    }

    /// Enqueues unreliable data, automatically fragmenting if necessary.
    /// Returns the sequence number used for reassembly.
    pub fn enqueue_unreliable_data(&mut self, channel_id: u8, data: Arc<[u8]>) -> u16 {
        // Use a sequence number for fragment reassembly (but not for reliability)
        let sequence = self.next_unreliable_sequence;
        self.next_unreliable_sequence = self.next_unreliable_sequence.wrapping_add(1);

        // Compute datagram cap and per-command payload budget so a single
        // SendUnreliable or SendUnreliableFragment fits within one UDP datagram when encoded.
        let datagram_cap = std::cmp::min(
            self.current_fragment_size() as usize,
            self.config.receive_buffer_max_size,
        );
        let compression_overhead = match self.config.compression {
            bitwarp_core::config::CompressionAlgorithm::Lz4 => 5,
            _ => 1,
        };
        let checksum_overhead = if self.config.use_checksums { 4 } else { 0 };
        let per_packet_overhead = 1 /* command count */ + compression_overhead + checksum_overhead;

        // Header sizes (without the 2-byte length prefix)
        let send_unrel_header = 1 /* type */ + 1 /* channel */ + 2 /* payload len */; // = 4
        let send_unrel_frag_header = 1 /* type */ + 1 /* channel */ + 2 /* sequence */
            + 1 /* frag_id */ + 1 /* frag_count */ + 2 /* len */; // = 8

        let max_payload_unreliable = datagram_cap
            .saturating_sub(per_packet_overhead)
            .saturating_sub(2 /* len prefix */)
            .saturating_sub(send_unrel_header);

        // Validate MTU is large enough for minimum payload
        if max_payload_unreliable < 1 {
            tracing::error!(
                "MTU too small: datagram_cap={}, overhead={}, can't fit minimum unreliable payload",
                datagram_cap,
                per_packet_overhead + 2 + send_unrel_header
            );
            return sequence;
        }

        if data.len() <= max_payload_unreliable {
            // No fragmentation needed
            self.enqueue_command(ProtocolCommand::SendUnreliable {
                channel_id,
                data: SharedBytes::from_arc(data),
            });
        } else {
            // Fragment the data so each fragment fits
            let fragment_payload = datagram_cap
                .saturating_sub(per_packet_overhead)
                .saturating_sub(2 /* len prefix */)
                .saturating_sub(send_unrel_frag_header);

            if fragment_payload < 1 {
                tracing::error!(
                    "MTU too small for unreliable fragmentation: datagram_cap={}, overhead={}, can't fit minimum fragment payload",
                    datagram_cap,
                    per_packet_overhead + 2 + send_unrel_frag_header
                );
                return sequence;
            }

            // Check for integer overflow before casting to u8
            let total_fragments_usize = (data.len() + fragment_payload - 1) / fragment_payload;
            if total_fragments_usize > u8::MAX as usize {
                tracing::warn!(
                    "Unreliable payload {} bytes too large to fragment: would require {} fragments (max {}), dropping packet",
                    data.len(),
                    total_fragments_usize,
                    u8::MAX
                );
                return sequence;
            }
            let total_fragments = total_fragments_usize as u8;

            if total_fragments > self.config.max_fragments {
                tracing::warn!(
                    "Unreliable payload requires {} fragments but max allowed is {}, sending first fragment only",
                    total_fragments,
                    self.config.max_fragments
                );
                // Too many fragments - send first fragment only (best-effort)
                let base = SharedBytes::from_arc(data);
                let fragment_data = base.slice(0, fragment_payload.min(base.len()));
                self.enqueue_command(ProtocolCommand::SendUnreliableFragment {
                    channel_id,
                    sequence,
                    fragment_id: 0,
                    fragment_count: 1,
                    data: fragment_data,
                });
                return sequence;
            }

            tracing::trace!(
                "Fragmenting {} byte unreliable payload into {} fragments ({} bytes each)",
                data.len(),
                total_fragments,
                fragment_payload
            );

            for fragment_id in 0..total_fragments {
                let start = (fragment_id as usize) * fragment_payload;
                let end = ((fragment_id as usize + 1) * fragment_payload).min(data.len());
                let base = SharedBytes::from_arc(data.clone());
                let fragment_data = base.slice(start, end - start);

                self.enqueue_command(ProtocolCommand::SendUnreliableFragment {
                    channel_id,
                    sequence,
                    fragment_id,
                    fragment_count: total_fragments,
                    data: fragment_data,
                });
            }
        }

        sequence
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bitwarp_core::config::Config;
    use bitwarp_protocol::{
        command::ProtocolCommand,
        packet::DeliveryGuarantee,
    };

    use super::*;

    fn create_virtual_connection() -> Peer {
        Peer::new(get_fake_addr(), &Config::default(), Instant::now())
    }

    fn get_fake_addr() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    // ===== Reliable Fragment Tests =====

    #[test]
    fn test_enqueue_reliable_data_with_fragmentation() {
        let mut peer = create_virtual_connection();

        // Create data larger than fragment size (default is 1024)
        let large_data = vec![42u8; 3000];

        // Enqueue the data - should automatically fragment
        let _sequence = peer.enqueue_reliable_data(0, large_data.into(), true);

        // Should have multiple SendFragment commands queued
        assert!(peer.has_queued_commands());
        let count = peer.queued_commands_count();
        assert!(count >= 3); // 3000 bytes / 1024 = at least 3 fragments

        // Verify commands are SendFragment
        let commands: Vec<_> = peer.drain_commands().collect();
        for cmd in &commands {
            assert!(matches!(cmd, ProtocolCommand::SendFragment { .. }));
        }
    }

    #[test]
    fn test_fragment_reassembly() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Create fragmented data
        let fragment1 = std::sync::Arc::<[u8]>::from(vec![1, 2, 3].into_boxed_slice());
        let fragment2 = std::sync::Arc::<[u8]>::from(vec![4, 5, 6].into_boxed_slice());
        let fragment3 = std::sync::Arc::<[u8]>::from(vec![7, 8, 9].into_boxed_slice());

        // Send fragments
        let cmd1 = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            fragment_id: 0,
            fragment_count: 3,
            data: fragment1.into(),
        };

        let cmd2 = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            fragment_id: 1,
            fragment_count: 3,
            data: fragment2.into(),
        };

        let cmd3 = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            fragment_id: 2,
            fragment_count: 3,
            data: fragment3.into(),
        };

        // Process first two fragments - should not produce a packet yet
        let result1 = peer.process_command(&cmd1, time).unwrap();
        assert_eq!(result1.into_iter().count(), 0);

        let result2 = peer.process_command(&cmd2, time).unwrap();
        assert_eq!(result2.into_iter().count(), 0);

        // Process final fragment - should produce reassembled packet
        let result3 = peer.process_command(&cmd3, time).unwrap();
        let packets: Vec<_> = result3.into_iter().collect();
        assert_eq!(packets.len(), 1);

        // Verify reassembled data
        assert_eq!(packets[0].0.payload(), &[1, 2, 3, 4, 5, 6, 7, 8, 9]);

        // Should have ACK queued
        assert!(peer.has_queued_commands());
    }

    #[test]
    fn test_round_trip_large_data_with_fragmentation() {
        let mut peer1 = create_virtual_connection();
        let mut peer2 = create_virtual_connection();
        let time = Instant::now();

        // Create large data that will be fragmented
        let large_data = vec![99u8; 2500];

        // peer1 sends large data - should automatically fragment
        peer1.enqueue_reliable_data(0, large_data.clone().into(), true);
        let bytes = peer1.encode_queued_commands().unwrap();

        // peer2 receives and reassembles fragments
        let result = peer2.process_command_packet(&bytes, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();

        // Should receive one reassembled packet
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0.payload(), &large_data[..]);

        // peer2 should have ACK queued
        assert!(peer2.has_queued_commands());
    }

    #[test]
    fn test_fragment_out_of_order_delivery() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send fragments out of order
        let cmd2 = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            fragment_id: 1,
            fragment_count: 3,
            data: vec![20, 21, 22].into(),
        };

        let cmd0 = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            fragment_id: 0,
            fragment_count: 3,
            data: vec![10, 11, 12].into(),
        };

        let cmd1 = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            fragment_id: 2,
            fragment_count: 3,
            data: vec![30, 31, 32].into(),
        };

        // Process in order: 1, 0, 2
        peer.process_command(&cmd2, time).unwrap();
        peer.process_command(&cmd0, time).unwrap();
        let result = peer.process_command(&cmd1, time).unwrap();

        let packets: Vec<_> = result.into_iter().collect();
        assert_eq!(packets.len(), 1);

        // Should be reassembled in correct order
        assert_eq!(packets[0].0.payload(), &[10, 11, 12, 20, 21, 22, 30, 31, 32]);
    }

    // ===== Unreliable Fragment Tests =====

    #[test]
    fn test_enqueue_unreliable_data_with_fragmentation() {
        let mut peer = create_virtual_connection();

        // Create data larger than fragment size (default is 1024)
        let large_data = vec![99u8; 3000];

        // Enqueue the data - should automatically fragment
        let _sequence = peer.enqueue_unreliable_data(0, large_data.into());

        // Should have multiple SendUnreliableFragment commands queued
        assert!(peer.has_queued_commands());
        let count = peer.queued_commands_count();
        assert!(count >= 3); // 3000 bytes / 1024 = at least 3 fragments

        // Verify commands are SendUnreliableFragment
        let commands: Vec<_> = peer.drain_commands().collect();
        for cmd in &commands {
            assert!(matches!(cmd, ProtocolCommand::SendUnreliableFragment { .. }));
        }
    }

    #[test]
    fn test_unreliable_fragment_reassembly() {
        let config = Config::default();
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        // Simulate receiving fragments manually
        let fragment1 = vec![1, 2, 3];
        let fragment2 = vec![4, 5, 6];
        let fragment3 = vec![7, 8, 9];

        // Send fragments
        let cmd1 = ProtocolCommand::SendUnreliableFragment {
            channel_id: 0,
            sequence: 1,
            fragment_id: 0,
            fragment_count: 3,
            data: fragment1.into(),
        };

        let cmd2 = ProtocolCommand::SendUnreliableFragment {
            channel_id: 0,
            sequence: 1,
            fragment_id: 1,
            fragment_count: 3,
            data: fragment2.into(),
        };

        let cmd3 = ProtocolCommand::SendUnreliableFragment {
            channel_id: 0,
            sequence: 1,
            fragment_id: 2,
            fragment_count: 3,
            data: fragment3.into(),
        };

        let time = Instant::now();

        // Process first two fragments - should not deliver yet
        let result1 = peer.process_command(&cmd1, time).unwrap();
        assert_eq!(result1.into_iter().count(), 0);

        let result2 = peer.process_command(&cmd2, time).unwrap();
        assert_eq!(result2.into_iter().count(), 0);

        // Process last fragment - should deliver complete packet
        let result3 = peer.process_command(&cmd3, time).unwrap();
        let packets: Vec<_> = result3.into_iter().collect();
        assert_eq!(packets.len(), 1);

        let (packet, _) = &packets[0];
        assert_eq!(packet.channel_id(), 0);
        assert_eq!(packet.payload(), &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(packet.delivery_guarantee(), DeliveryGuarantee::Unreliable);
    }

    #[test]
    fn test_unreliable_fragment_out_of_order_delivery() {
        let config = Config::default();
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Send fragments out of order
        let cmd2 = ProtocolCommand::SendUnreliableFragment {
            channel_id: 0,
            sequence: 5,
            fragment_id: 1,
            fragment_count: 3,
            data: vec![20, 21, 22].into(),
        };

        let cmd0 = ProtocolCommand::SendUnreliableFragment {
            channel_id: 0,
            sequence: 5,
            fragment_id: 0,
            fragment_count: 3,
            data: vec![10, 11, 12].into(),
        };

        let cmd1 = ProtocolCommand::SendUnreliableFragment {
            channel_id: 0,
            sequence: 5,
            fragment_id: 2,
            fragment_count: 3,
            data: vec![30, 31, 32].into(),
        };

        // Process out of order (1, 0, 2)
        let result1 = peer.process_command(&cmd2, time).unwrap();
        assert_eq!(result1.into_iter().count(), 0);

        let result2 = peer.process_command(&cmd0, time).unwrap();
        assert_eq!(result2.into_iter().count(), 0);

        // Last fragment completes the packet
        let result3 = peer.process_command(&cmd1, time).unwrap();
        let packets: Vec<_> = result3.into_iter().collect();
        assert_eq!(packets.len(), 1);

        let (packet, _) = &packets[0];
        // Should reassemble correctly despite out-of-order arrival
        assert_eq!(packet.payload(), &[10, 11, 12, 20, 21, 22, 30, 31, 32]);
    }

    #[test]
    fn test_round_trip_unreliable_large_data_with_fragmentation() {
        let config = Config::default();
        let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
        let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // Create large data that will be fragmented
        let large_data = vec![123u8; 2500];

        // peer1 sends large unreliable data - should automatically fragment
        peer1.enqueue_unreliable_data(0, large_data.clone().into());
        let bytes = peer1.encode_queued_commands().unwrap();

        // peer2 receives and reassembles fragments
        let result = peer2.process_command_packet(&bytes, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();

        // Should get one reassembled packet
        assert_eq!(packets.len(), 1);

        let (packet, _) = &packets[0];
        assert_eq!(packet.payload(), large_data.as_slice());
        assert_eq!(packet.delivery_guarantee(), DeliveryGuarantee::Unreliable);
    }

    #[test]
    fn test_unreliable_fragments_no_ack_sent() {
        let config = Config::default();
        let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
        let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
        let time = Instant::now();

        // peer1 sends large unreliable data
        peer1.enqueue_unreliable_data(0, vec![55u8; 2000].into());
        let bytes = peer1.encode_queued_commands().unwrap();

        // peer2 receives it
        let _ = peer2.process_command_packet(&bytes, time).unwrap();

        // peer2 should NOT have queued ACK commands (unreliable doesn't need ACK)
        assert!(
            !peer2.has_queued_commands() || {
                // If there are commands, none should be Acknowledge
                let commands: Vec<_> = peer2.drain_commands().collect();
                !commands.iter().any(|cmd| matches!(cmd, ProtocolCommand::Acknowledge { .. }))
            }
        );
    }

    // ===== Stale Fragment Cleanup Tests =====

    #[test]
    fn test_stale_fragment_cleanup() {
        let config = Config::default();
        let start_time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, start_time);

        // Create incomplete fragmented packet by sending only first fragment
        let fragment1 = vec![1, 2, 3];
        let cmd = ProtocolCommand::SendFragment {
            channel_id: 0,
            sequence: 100,
            ordered: true,
            fragment_id: 0,
            fragment_count: 3, // Expecting 3 fragments total
            data: fragment1.into(),
        };

        // Process the first fragment
        let result = peer.process_command(&cmd, start_time).unwrap();
        assert_eq!(result.into_iter().count(), 0); // No complete packet yet

        // Verify fragment buffer was created
        assert_eq!(peer.command_fragments.len(), 1);

        // Cleanup immediately - should not remove anything (< 5 second timeout)
        peer.cleanup_stale_fragments(start_time);
        assert_eq!(peer.command_fragments.len(), 1, "Fragment buffer should still exist");

        // Wait for timeout period (5 seconds)
        let later = start_time + std::time::Duration::from_secs(6);
        peer.cleanup_stale_fragments(later);

        // Stale buffer should be cleaned up
        assert_eq!(peer.command_fragments.len(), 0, "Stale fragment buffer should be cleaned up");
    }

    #[test]
    fn test_complete_fragments_not_cleaned() {
        let config = Config::default();
        let start_time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, start_time);

        // Send all 3 fragments to complete the packet
        for frag_id in 0..3 {
            let fragment_data = vec![frag_id, frag_id + 1, frag_id + 2];
            let cmd = ProtocolCommand::SendFragment {
                channel_id: 0,
                sequence: 200,
                ordered: false,
                fragment_id: frag_id,
                fragment_count: 3,
                data: fragment_data.into(),
            };
            peer.process_command(&cmd, start_time).unwrap();
        }

        // Complete fragments should be removed automatically after reassembly
        assert_eq!(peer.command_fragments.len(), 0, "Complete fragments should be removed");

        // Cleanup should not affect anything
        let later = start_time + std::time::Duration::from_secs(10);
        peer.cleanup_stale_fragments(later);
        assert_eq!(peer.command_fragments.len(), 0);
    }

    #[test]
    fn test_multiple_stale_fragments_cleanup() {
        let config = Config::default();
        let start_time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, start_time);

        // Create multiple incomplete fragment buffers
        for seq in 0..5 {
            let cmd = ProtocolCommand::SendFragment {
                channel_id: 0,
                sequence: seq,
                ordered: true,
                fragment_id: 0,
                fragment_count: 2,
                data: vec![seq as u8].into(),
            };
            peer.process_command(&cmd, start_time).unwrap();
        }

        // Should have 5 incomplete fragment buffers
        assert_eq!(peer.command_fragments.len(), 5);

        // Cleanup after timeout
        let later = start_time + std::time::Duration::from_secs(6);
        peer.cleanup_stale_fragments(later);

        // All stale buffers should be cleaned up
        assert_eq!(peer.command_fragments.len(), 0, "All stale fragment buffers should be cleaned up");
    }
}
