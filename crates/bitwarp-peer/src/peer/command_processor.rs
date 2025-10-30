use std::{collections::VecDeque, time::Instant};

use bitwarp_core::error::{ErrorKind, Result};
use bitwarp_protocol::{
    command::ProtocolCommand,
    command_codec::CommandDecoder,
    packet::{DeliveryGuarantee, IncomingPackets, OrderingGuarantee, Packet, PacketType},
};

use crate::{channel_state::ChannelState, fragment_buffer::CommandFragmentBuffer, peer_state::PeerState, pmtu_discovery::PmtuDiscovery};

use super::Peer;

impl Peer {
    /// Decodes and processes an incoming command packet.
    /// This is the command-based alternative to `process_incoming`.
    /// Returns all user packets that resulted from processing the commands.
    /// Validates CRC32 checksum if enabled, then decompresses if needed.
    pub fn process_command_packet(
        &mut self,
        data: &[u8],
        time: Instant,
    ) -> Result<IncomingPackets> {
        // Track bytes received
        self.record_data_received(data.len());

        // Validate and strip checksum if enabled (before decompression)
        let payload = if self.config.use_checksums {
            CommandDecoder::validate_and_strip_checksum(data)
                .map_err(|e| ErrorKind::CouldNotReadHeader(e.to_string()))?
        } else {
            data
        };

        // Decompress if needed
        let decompressed = CommandDecoder::decompress(payload)
            .map_err(|e| ErrorKind::CouldNotReadHeader(e.to_string()))?;

        let command_packet = CommandDecoder::decode_packet(&decompressed)
            .map_err(|e| ErrorKind::CouldNotReadHeader(e.to_string()))?;

        // Record packet being received
        self.record_packet_received();

        let mut all_packets = std::collections::VecDeque::new();

        for command in &command_packet.commands {
            let packets = self.process_command(command, time)?;
            for packet in packets.into_iter() {
                all_packets.push_back(packet);
            }
        }

        Ok(IncomingPackets::many(all_packets))
    }

    /// Processes an incoming protocol command and returns resulting actions.
    /// This is the command-based alternative to `process_incoming`.
    /// Automatically enqueues response commands (ACK, Pong) when appropriate.
    pub fn process_command(
        &mut self,
        command: &ProtocolCommand,
        time: Instant,
    ) -> Result<IncomingPackets> {
        self.last_heard = time;

        match command {
            ProtocolCommand::Acknowledge { sequence, received_mask, .. } => {
                self.acknowledge_handler.process_incoming(
                    *sequence,
                    *sequence,
                    *received_mask,
                    time,
                );
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::Ping { timestamp } => {
                // Automatically respond with Pong
                self.enqueue_pong_command(*timestamp);
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::Pong { .. } => {
                // Pong received, RTT calculated in acknowledgment handler
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::SendReliable { channel_id, sequence, ordered, data } => {
                // Process reliable data command
                self.acknowledge_handler.process_incoming(*sequence, *sequence, 0, time);

                // Automatically enqueue ACK for reliable data
                self.enqueue_ack_command(None);
                if *ordered {
                    // Ordered delivery via per-channel buffering
                    let channel_state =
                        self.channel_states.entry(*channel_id).or_insert_with(ChannelState::new);

                    let ordered_packets = channel_state.process_ordered(
                        *sequence,
                        bitwarp_core::shared::SharedBytes::from_arc(
                            data.clone().into_full_arc().unwrap_or_else(|| {
                                std::sync::Arc::<[u8]>::from(
                                    data.as_slice().to_vec().into_boxed_slice(),
                                )
                            }),
                        ),
                    );

                    // Convert all ready packets to IncomingPackets
                    let mut packets = VecDeque::new();
                    for packet_data in ordered_packets {
                        packets.push_back((
                            Packet::new(
                                self.remote_address,
                                {
                                    if let Some(full) = packet_data.clone().into_full_arc() {
                                        full
                                    } else {
                                        std::sync::Arc::<[u8]>::from(
                                            packet_data.as_slice().to_vec().into_boxed_slice(),
                                        )
                                    }
                                },
                                DeliveryGuarantee::Reliable,
                                OrderingGuarantee::Ordered(None),
                                *channel_id,
                            ),
                            PacketType::Packet,
                        ));
                    }

                    Ok(IncomingPackets::many(packets))
                } else {
                    // Unordered reliable: deliver immediately
                    Ok(IncomingPackets::one(
                        Packet::new(
                            self.remote_address,
                            data.clone().into_full_arc().unwrap_or_else(|| {
                                std::sync::Arc::<[u8]>::from(
                                    data.as_slice().to_vec().into_boxed_slice(),
                                )
                            }),
                            DeliveryGuarantee::Reliable,
                            OrderingGuarantee::None,
                            *channel_id,
                        ),
                        PacketType::Packet,
                    ))
                }
            }
            ProtocolCommand::SendUnreliable { channel_id, data } => {
                // Process unreliable data command (no ACK needed)
                Ok(IncomingPackets::one(
                    Packet::new(
                        self.remote_address,
                        data.clone().into_full_arc().unwrap_or_else(|| {
                            std::sync::Arc::<[u8]>::from(
                                data.as_slice().to_vec().into_boxed_slice(),
                            )
                        }),
                        DeliveryGuarantee::Unreliable,
                        OrderingGuarantee::None,
                        *channel_id,
                    ),
                    PacketType::Packet,
                ))
            }
            ProtocolCommand::SendUnreliableSequenced { channel_id, sequence, data } => {
                // Get or create channel state for sequencing
                let channel_state =
                    self.channel_states.entry(*channel_id).or_insert_with(ChannelState::new);

                // Apply per-channel sequencing (drops old packets)
                if let Some(packet_data) = channel_state.process_sequenced(
                    *sequence,
                    bitwarp_core::shared::SharedBytes::from_arc(
                        data.clone().into_full_arc().unwrap_or_else(|| {
                            std::sync::Arc::<[u8]>::from(
                                data.as_slice().to_vec().into_boxed_slice(),
                            )
                        }),
                    ),
                ) {
                    Ok(IncomingPackets::one(
                        Packet::new(
                            self.remote_address,
                            {
                                if let Some(full) = packet_data.clone().into_full_arc() {
                                    full
                                } else {
                                    std::sync::Arc::<[u8]>::from(
                                        packet_data.as_slice().to_vec().into_boxed_slice(),
                                    )
                                }
                            },
                            DeliveryGuarantee::Unreliable,
                            OrderingGuarantee::Sequenced(None),
                            *channel_id,
                        ),
                        PacketType::Packet,
                    ))
                } else {
                    // Old packet, drop it
                    Ok(IncomingPackets::zero())
                }
            }
            ProtocolCommand::SendUnsequenced { channel_id, unsequenced_group, data } => {
                // Check if this is a duplicate using the sliding window
                if self.is_unsequenced_duplicate(*unsequenced_group) {
                    // Duplicate packet, drop it
                    Ok(IncomingPackets::zero())
                } else {
                    // Mark as received in the window
                    self.mark_unsequenced_received(*unsequenced_group);

                    // Deliver the packet
                    Ok(IncomingPackets::one(
                        Packet::new(
                            self.remote_address,
                            data.clone().into_full_arc().unwrap_or_else(|| {
                                std::sync::Arc::<[u8]>::from(
                                    data.as_slice().to_vec().into_boxed_slice(),
                                )
                            }),
                            DeliveryGuarantee::Unreliable,
                            OrderingGuarantee::Unsequenced,
                            *channel_id,
                        ),
                        PacketType::Packet,
                    ))
                }
            }
            ProtocolCommand::SendFragment {
                channel_id,
                sequence,
                ordered,
                fragment_id,
                fragment_count,
                data,
            } => {
                // Process fragment and reassemble if complete
                self.acknowledge_handler.process_incoming(*sequence, *sequence, 0, time);

                // Get or create fragment buffer for this sequence
                let buffer = self.command_fragments.entry(*sequence).or_insert_with(|| {
                    CommandFragmentBuffer::new(*channel_id, *fragment_count, *ordered, time)
                });

                // Add this fragment
                buffer.add_fragment(
                    *fragment_id,
                    data.clone().into_full_arc().unwrap_or_else(|| {
                        std::sync::Arc::<[u8]>::from(data.as_slice().to_vec().into_boxed_slice())
                    }),
                );

                // Check if reassembly is complete
                if buffer.is_complete() {
                    // Remove buffer and reassemble
                    if let Some(buffer) = self.command_fragments.remove(sequence) {
                        let channel_id = buffer.channel_id();
                        let is_ordered = buffer.is_ordered();
                        if let Some(reassembled) = buffer.reassemble() {
                            // Automatically enqueue ACK for the complete fragmented packet
                            self.enqueue_ack_command(None);

                            if is_ordered {
                                // For ordered: push through channel ordering using the sequence
                                let channel_state = self
                                    .channel_states
                                    .entry(channel_id)
                                    .or_insert_with(ChannelState::new);

                                let ready_packets = channel_state.process_ordered(
                                    *sequence,
                                    bitwarp_core::shared::SharedBytes::from_vec(reassembled),
                                );
                                if ready_packets.is_empty() {
                                    return Ok(IncomingPackets::zero());
                                } else if ready_packets.len() == 1 {
                                    return Ok(IncomingPackets::one(
                                        Packet::new(
                                            self.remote_address,
                                            ready_packets[0]
                                                .clone()
                                                .into_full_arc()
                                                .unwrap_or_else(|| {
                                                    std::sync::Arc::<[u8]>::from(
                                                        ready_packets[0]
                                                            .as_slice()
                                                            .to_vec()
                                                            .into_boxed_slice(),
                                                    )
                                                }),
                                            DeliveryGuarantee::Reliable,
                                            OrderingGuarantee::None,
                                            channel_id,
                                        ),
                                        PacketType::Packet,
                                    ));
                                } else {
                                    let mut vec = std::collections::VecDeque::new();
                                    for payload in ready_packets {
                                        vec.push_back((
                                            Packet::new(
                                                self.remote_address,
                                                {
                                                    if let Some(full) =
                                                        payload.clone().into_full_arc()
                                                    {
                                                        full
                                                    } else {
                                                        std::sync::Arc::<[u8]>::from(
                                                            payload
                                                                .as_slice()
                                                                .to_vec()
                                                                .into_boxed_slice(),
                                                        )
                                                    }
                                                },
                                                DeliveryGuarantee::Reliable,
                                                OrderingGuarantee::None,
                                                channel_id,
                                            ),
                                            PacketType::Packet,
                                        ));
                                    }
                                    return Ok(IncomingPackets::many(vec));
                                }
                            } else {
                                // Unordered reliable: deliver immediately
                                return Ok(IncomingPackets::one(
                                    Packet::new(
                                        self.remote_address,
                                        std::sync::Arc::<[u8]>::from(
                                            reassembled.into_boxed_slice(),
                                        ),
                                        DeliveryGuarantee::Reliable,
                                        OrderingGuarantee::None,
                                        channel_id,
                                    ),
                                    PacketType::Packet,
                                ));
                            }
                        }
                    }
                }

                // Not complete yet, or reassembly failed
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::SendUnreliableFragment {
                channel_id,
                sequence,
                fragment_id,
                fragment_count,
                data,
            } => {
                // Process unreliable fragment and reassemble if complete (no ACK needed)
                // Get or create fragment buffer for this sequence
                let buffer = self.command_fragments.entry(*sequence).or_insert_with(|| {
                    CommandFragmentBuffer::new(*channel_id, *fragment_count, false, time)
                });

                // Add this fragment
                buffer.add_fragment(
                    *fragment_id,
                    data.clone().into_full_arc().unwrap_or_else(|| {
                        std::sync::Arc::<[u8]>::from(data.as_slice().to_vec().into_boxed_slice())
                    }),
                );

                // Check if reassembly is complete
                if buffer.is_complete() {
                    // Remove buffer and reassemble
                    if let Some(buffer) = self.command_fragments.remove(sequence) {
                        let channel_id = buffer.channel_id();
                        if let Some(reassembled) = buffer.reassemble() {
                            // Return unreliable packet (no ACK)
                            return Ok(IncomingPackets::one(
                                Packet::new(
                                    self.remote_address,
                                    std::sync::Arc::<[u8]>::from(reassembled.into_boxed_slice()),
                                    DeliveryGuarantee::Unreliable,
                                    OrderingGuarantee::None,
                                    channel_id,
                                ),
                                PacketType::Packet,
                            ));
                        }
                    }
                }

                // Not complete yet, or reassembly failed
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::Disconnect { reason: _ } => {
                // Mark peer as zombie - session manager will emit disconnect event and clean up
                self.state = PeerState::Zombie;
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::Connect {
                channels,
                mtu: _,
                protocol_version: _,
                outgoing_session_id,
                connect_id,
            } => {
                // Server-side: Received CONNECT from client (step 1 of 3-way handshake)
                // Validate connect_id for replay protection
                if self.state == PeerState::Idle {
                    use rand::Rng;
                    let mut rng = rand::rng();

                    // Store client's session ID as our incoming
                    self.incoming_session_id = *outgoing_session_id;
                    // Assign a peer ID (in real impl, this would be managed by host)
                    self.peer_id = rng.random();
                    // Store connect ID for validation
                    self.connect_id = *connect_id;

                    // Transition to AcknowledgingConnect
                    self.state = PeerState::AcknowledgingConnect;

                    // Send VERIFY_CONNECT (step 2 of 3-way handshake)
                    let verify_command = ProtocolCommand::VerifyConnect {
                        peer_id: self.peer_id,
                        channels: *channels.min(&self.config.channel_count), // Negotiate
                        mtu: 1400,                                           // Negotiate MTU
                        incoming_session_id: self.incoming_session_id,
                        outgoing_session_id: self.outgoing_session_id,
                        window_size: self.window_size(), // Send our window size
                    };
                    self.command_queue.enqueue(verify_command);
                }
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::VerifyConnect {
                peer_id,
                channels: _,
                mtu: _,
                incoming_session_id,
                outgoing_session_id,
                window_size,
            } => {
                // Client-side: Received VERIFY_CONNECT from server (step 2 of 3-way handshake)
                if self.state == PeerState::Connecting {
                    // Store server's session IDs
                    self.peer_id = *peer_id;
                    self.incoming_session_id = *incoming_session_id;

                    // Negotiate window size (take minimum of ours and server's)
                    if self.config.use_window_flow_control {
                        self.set_window_size((*window_size).min(self.window_size()));
                    }
                    // Verify outgoing session ID matches
                    if *outgoing_session_id != self.outgoing_session_id {
                        // Session ID mismatch - potential attack
                        return Err(ErrorKind::CouldNotReadHeader(
                            "Session ID mismatch".to_string(),
                        ));
                    }

                    // Transition to ConnectionSucceeded
                    self.state = PeerState::ConnectionSucceeded;

                    // Send ACK (any data packet serves as implicit ACK - step 3)
                    // The next data packet sent will complete the handshake
                }
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::BandwidthLimit { incoming, outgoing } => {
                // Dynamically adjust bandwidth limits at runtime
                self.config.incoming_bandwidth_limit = *incoming;
                self.config.outgoing_bandwidth_limit = *outgoing;
                self.bandwidth_throttle.set_incoming_bandwidth_limit(*incoming);
                self.bandwidth_throttle.set_outgoing_bandwidth_limit(*outgoing);
                tracing::debug!(
                    "Applied BandwidthLimit: incoming={}B/s outgoing={}B/s",
                    incoming,
                    outgoing
                );
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::ThrottleConfigure { interval, acceleration, deceleration } => {
                // Update throttle configuration dynamically
                self.acknowledge_handler.congestion_mut().configure_throttle(
                    *interval,
                    *acceleration,
                    *deceleration,
                );
                tracing::debug!(
                    "Throttle configured: interval={}ms, accel={}, decel={}",
                    interval,
                    acceleration,
                    deceleration
                );
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::PMTUProbe { size, token, .. } => {
                // Respond to PMTU probe with a reply (small control)
                let reply = PmtuDiscovery::create_reply(*size, *token);
                self.enqueue_command(reply);
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::PMTUReply { size, token } => {
                // Process the reply through the PMTU discovery module
                self.pmtu.process_reply(*size, *token, time);
                Ok(IncomingPackets::zero())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitwarp_core::config::Config;
    use bitwarp_protocol::command::ProtocolCommand;

    fn create_virtual_connection() -> Peer {
        Peer::new(get_fake_addr(), &Config::default(), Instant::now())
    }

    fn get_fake_addr() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn test_command_queue_integration() {
        let mut peer = create_virtual_connection();

        // Test enqueuing commands
        assert!(!peer.has_queued_commands());
        assert_eq!(peer.queued_commands_count(), 0);

        peer.enqueue_command(ProtocolCommand::Ping { timestamp: 1000 });
        assert!(peer.has_queued_commands());
        assert_eq!(peer.queued_commands_count(), 1);

        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![1, 2, 3].into(),
        });
        assert_eq!(peer.queued_commands_count(), 2);

        // Test draining commands
        let commands: Vec<_> = peer.drain_commands().collect();
        assert_eq!(commands.len(), 2);
        assert!(!peer.has_queued_commands());
    }

    #[test]
    fn test_process_command_reliable_data() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        let command = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![1, 2, 3, 4].into(),
        };

        let result = peer.process_command(&command, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();

        assert_eq!(packets.len(), 1);
        let (packet, _) = &packets[0];
        assert_eq!(packet.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_process_command_unreliable_data() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        let command = ProtocolCommand::SendUnreliable { channel_id: 0, data: vec![5, 6, 7].into() };

        let result = peer.process_command(&command, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();

        assert_eq!(packets.len(), 1);
        let (packet, _) = &packets[0];
        assert_eq!(packet.payload(), &[5, 6, 7]);
    }

    #[test]
    fn test_automatic_pong_response() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Initially no queued commands
        assert!(!peer.has_queued_commands());

        // Process Ping command
        let ping = ProtocolCommand::Ping { timestamp: 12345 };
        peer.process_command(&ping, time).unwrap();

        // Should have automatically enqueued a Pong response
        assert!(peer.has_queued_commands());
        assert_eq!(peer.queued_commands_count(), 1);

        let commands: Vec<_> = peer.drain_commands().collect();
        assert_eq!(commands.len(), 1);
        match &commands[0] {
            ProtocolCommand::Pong { timestamp } => {
                assert_eq!(*timestamp, 12345);
            }
            _ => panic!("Expected Pong command"),
        }
    }

    #[test]
    fn test_automatic_ack_response() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Initially no queued commands
        assert!(!peer.has_queued_commands());

        // Process SendReliable command (sequence starts at 0)
        let reliable = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![1, 2, 3, 4].into(),
        };
        let result = peer.process_command(&reliable, time).unwrap();

        // Should have data packet
        assert_eq!(result.into_iter().count(), 1);

        // Should have automatically enqueued an ACK
        assert!(peer.has_queued_commands());
        let commands: Vec<_> = peer.drain_commands().collect();
        assert_eq!(commands.len(), 1);
        match &commands[0] {
            ProtocolCommand::Acknowledge { .. } => {
                // ACK command was enqueued
            }
            _ => panic!("Expected Acknowledge command"),
        }
    }

    #[test]
    fn test_round_trip_ping_pong() {
        let mut peer1 = create_virtual_connection();
        let mut peer2 = create_virtual_connection();
        let time = Instant::now();

        // peer1 sends Ping
        peer1.enqueue_ping_command(1000);
        let bytes = peer1.encode_queued_commands().unwrap();

        // peer2 receives Ping and auto-responds with Pong
        peer2.process_command_packet(&bytes, time).unwrap();
        assert!(peer2.has_queued_commands());

        let pong_bytes = peer2.encode_queued_commands().unwrap();

        // peer1 receives Pong
        peer1.process_command_packet(&pong_bytes, time).unwrap();
        assert!(!peer1.has_queued_commands()); // No response to Pong
    }

    #[test]
    fn test_round_trip_reliable_with_ack() {
        let mut peer1 = create_virtual_connection();
        let mut peer2 = create_virtual_connection();
        let time = Instant::now();

        // peer1 sends reliable data
        peer1.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![1, 2, 3, 4, 5].into(),
        });
        let bytes = peer1.encode_queued_commands().unwrap();

        // peer2 receives data and auto-responds with ACK
        let result = peer2.process_command_packet(&bytes, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0.payload(), &[1, 2, 3, 4, 5]);

        // peer2 should have ACK queued
        assert!(peer2.has_queued_commands());
        let ack_bytes = peer2.encode_queued_commands().unwrap();

        // peer1 receives ACK (no packets produced, but internal state updated)
        let result = peer1.process_command_packet(&ack_bytes, time).unwrap();
        assert_eq!(result.into_iter().count(), 0);
    }

    #[test]
    fn test_bandwidth_limit_command_updates_config() {
        let start = Instant::now();
        let cfg = Config::default();
        let mut peer = Peer::new(get_fake_addr(), &cfg, start);

        // Initially unlimited
        assert_eq!(peer.config().incoming_bandwidth_limit, 0);
        assert_eq!(peer.config().outgoing_bandwidth_limit, 0);

        // Apply BandwidthLimit command
        let _ = peer
            .process_command(
                &ProtocolCommand::BandwidthLimit { incoming: 1234, outgoing: 5678 },
                start,
            )
            .unwrap();

        assert_eq!(peer.config().incoming_bandwidth_limit, 1234);
        assert_eq!(peer.config().outgoing_bandwidth_limit, 5678);
    }

    #[test]
    fn test_multi_channel_packets() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send data on different channels (each channel has independent sequences starting at 0)
        let cmd_ch0 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![0, 1, 2].into(),
        };
        let cmd_ch1 = ProtocolCommand::SendReliable {
            channel_id: 1,
            sequence: 0,
            ordered: true,
            data: vec![10, 11, 12].into(),
        };
        let cmd_ch5 =
            ProtocolCommand::SendUnreliable { channel_id: 5, data: vec![50, 51, 52].into() };

        // Process commands
        let result0 = peer.process_command(&cmd_ch0, time).unwrap();
        let result1 = peer.process_command(&cmd_ch1, time).unwrap();
        let result5 = peer.process_command(&cmd_ch5, time).unwrap();

        // Verify packets have correct channel IDs
        let packets0: Vec<_> = result0.into_iter().collect();
        assert_eq!(packets0.len(), 1);
        assert_eq!(packets0[0].0.channel_id(), 0);
        assert_eq!(packets0[0].0.payload(), &[0, 1, 2]);

        let packets1: Vec<_> = result1.into_iter().collect();
        assert_eq!(packets1.len(), 1);
        assert_eq!(packets1[0].0.channel_id(), 1);
        assert_eq!(packets1[0].0.payload(), &[10, 11, 12]);

        let packets5: Vec<_> = result5.into_iter().collect();
        assert_eq!(packets5.len(), 1);
        assert_eq!(packets5[0].0.channel_id(), 5);
        assert_eq!(packets5[0].0.payload(), &[50, 51, 52]);
    }

    #[test]
    fn test_per_channel_ordering() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send packets out of order on channel 0
        let cmd2 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 2,
            ordered: true,
            data: vec![20, 21, 22].into(),
        };
        let cmd0 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![0, 1, 2].into(),
        };
        let cmd1 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 1,
            ordered: true,
            data: vec![10, 11, 12].into(),
        };

        // Process out of order: 2, then 0, then 1
        let result2 = peer.process_command(&cmd2, time).unwrap();
        assert_eq!(result2.into_iter().count(), 0); // Buffered, waiting for 0 and 1

        let result0 = peer.process_command(&cmd0, time).unwrap();
        assert_eq!(result0.into_iter().count(), 1); // Delivers 0

        let result1 = peer.process_command(&cmd1, time).unwrap();
        let packets: Vec<_> = result1.into_iter().collect();
        assert_eq!(packets.len(), 2); // Delivers 1 and 2 (buffered)

        // Verify order
        assert_eq!(packets[0].0.payload(), &[10, 11, 12]); // sequence 1
        assert_eq!(packets[1].0.payload(), &[20, 21, 22]); // sequence 2
    }

    #[test]
    fn test_reliable_unordered_delivery() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send reliable packets out of order but mark as unordered
        let cmd2 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 2,
            ordered: false,
            data: vec![20, 21, 22].into(),
        };
        let cmd0 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: false,
            data: vec![0, 1, 2].into(),
        };
        let cmd1 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 1,
            ordered: false,
            data: vec![10, 11, 12].into(),
        };

        // Process in order: 2, then 0, then 1 — each should be delivered immediately
        let r2 = peer.process_command(&cmd2, time).unwrap();
        let v2: Vec<_> = r2.into_iter().collect();
        assert_eq!(v2.len(), 1);
        assert_eq!(v2[0].0.payload(), &[20, 21, 22]);

        let r0 = peer.process_command(&cmd0, time).unwrap();
        let v0: Vec<_> = r0.into_iter().collect();
        assert_eq!(v0.len(), 1);
        assert_eq!(v0[0].0.payload(), &[0, 1, 2]);

        let r1 = peer.process_command(&cmd1, time).unwrap();
        let v1: Vec<_> = r1.into_iter().collect();
        assert_eq!(v1.len(), 1);
        assert_eq!(v1[0].0.payload(), &[10, 11, 12]);
    }

    #[test]
    fn test_per_channel_sequencing() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send unreliable sequenced packets
        let cmd0 = ProtocolCommand::SendUnreliableSequenced {
            channel_id: 0,
            sequence: 0,
            data: vec![0, 1, 2].into(),
        };
        let cmd2 = ProtocolCommand::SendUnreliableSequenced {
            channel_id: 0,
            sequence: 2,
            data: vec![20, 21, 22].into(),
        };
        let cmd1 = ProtocolCommand::SendUnreliableSequenced {
            channel_id: 0,
            sequence: 1,
            data: vec![10, 11, 12].into(),
        };

        // Process in order: 0, 2, 1
        let result0 = peer.process_command(&cmd0, time).unwrap();
        assert_eq!(result0.into_iter().count(), 1); // Accepted

        let result2 = peer.process_command(&cmd2, time).unwrap();
        assert_eq!(result2.into_iter().count(), 1); // Accepted (newer)

        let result1 = peer.process_command(&cmd1, time).unwrap();
        assert_eq!(result1.into_iter().count(), 0); // Dropped (older than 2)
    }

    #[test]
    fn test_independent_channel_ordering() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send packets on different channels, out of order
        let ch0_cmd1 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 1,
            ordered: true,
            data: vec![0, 1].into(),
        };
        let ch1_cmd1 = ProtocolCommand::SendReliable {
            channel_id: 1,
            sequence: 1,
            ordered: true,
            data: vec![1, 1].into(),
        };
        let ch0_cmd0 = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 0,
            ordered: true,
            data: vec![0, 0].into(),
        };
        let ch1_cmd0 = ProtocolCommand::SendReliable {
            channel_id: 1,
            sequence: 0,
            ordered: true,
            data: vec![1, 0].into(),
        };

        // Channel 0: send 1 first (buffered)
        let result = peer.process_command(&ch0_cmd1, time).unwrap();
        assert_eq!(result.into_iter().count(), 0);

        // Channel 1: send 1 first (buffered)
        let result = peer.process_command(&ch1_cmd1, time).unwrap();
        assert_eq!(result.into_iter().count(), 0);

        // Channel 0: send 0 (delivers 0 and 1)
        let result = peer.process_command(&ch0_cmd0, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].0.channel_id(), 0);

        // Channel 1: send 0 (delivers 0 and 1)
        let result = peer.process_command(&ch1_cmd0, time).unwrap();
        let packets: Vec<_> = result.into_iter().collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].0.channel_id(), 1);
    }

    #[test]
    fn test_unsequenced_packets_basic() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send unsequenced packets in order
        let cmd1 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 0,
            data: vec![1, 2, 3].into(),
        };
        let cmd2 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 1,
            data: vec![4, 5, 6].into(),
        };

        // Process both packets
        let result1 = peer.process_command(&cmd1, time).unwrap();
        let result2 = peer.process_command(&cmd2, time).unwrap();

        // Both should be delivered
        assert_eq!(result1.into_iter().count(), 1);
        assert_eq!(result2.into_iter().count(), 1);
    }

    #[test]
    fn test_unsequenced_packets_prevent_duplicates() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send the same unsequenced packet twice
        let cmd = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 5,
            data: vec![1, 2, 3].into(),
        };

        // First delivery should succeed
        let result1 = peer.process_command(&cmd, time).unwrap();
        assert_eq!(result1.into_iter().count(), 1);

        // Second delivery (duplicate) should be dropped
        let result2 = peer.process_command(&cmd, time).unwrap();
        assert_eq!(result2.into_iter().count(), 0); // Dropped as duplicate
    }

    #[test]
    fn test_unsequenced_packets_allow_out_of_order() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send packets out of order (10, 5, 15)
        let cmd10 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 10,
            data: vec![10].into(),
        };
        let cmd5 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 5,
            data: vec![5].into(),
        };
        let cmd15 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 15,
            data: vec![15].into(),
        };

        // All should be delivered (out of order is allowed)
        let result10 = peer.process_command(&cmd10, time).unwrap();
        let result5 = peer.process_command(&cmd5, time).unwrap();
        let result15 = peer.process_command(&cmd15, time).unwrap();

        assert_eq!(result10.into_iter().count(), 1);
        assert_eq!(result5.into_iter().count(), 1);
        assert_eq!(result15.into_iter().count(), 1);
    }

    #[test]
    fn test_unsequenced_window_sliding() {
        let mut peer = create_virtual_connection();
        let time = Instant::now();

        // Send a packet at group 0
        let cmd0 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 0,
            data: vec![0].into(),
        };
        let result0 = peer.process_command(&cmd0, time).unwrap();
        assert_eq!(result0.into_iter().count(), 1);

        // Send a packet far ahead (group 1500, outside window of 1024)
        let cmd1500 = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 1500,
            data: vec![1].into(),
        };
        let result1500 = peer.process_command(&cmd1500, time).unwrap();
        assert_eq!(result1500.into_iter().count(), 1); // Should be delivered, window slides

        // Now send group 0 again - should be treated as very old and dropped
        let result0_again = peer.process_command(&cmd0, time).unwrap();
        assert_eq!(result0_again.into_iter().count(), 0); // Dropped as old/duplicate
    }
}
