//! Integration tests for the bitwarp-peer crate.
//!
//! These tests verify the complete behavior of the Peer struct and how
//! multiple systems interact together.

use std::time::Instant;

use bitwarp_core::config::Config;
use bitwarp_peer::Peer;
use bitwarp_protocol::{command::ProtocolCommand, packet::OrderingGuarantee};

fn create_virtual_connection() -> Peer {
    Peer::new(get_fake_addr(), &Config::default(), Instant::now())
}

fn get_fake_addr() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[test]
fn test_unsequenced_window_wrapping() {
    let mut peer = create_virtual_connection();
    let time = Instant::now();

    // Start by receiving some packets to establish a base around 65000
    for i in 0..3 {
        let cmd = ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: 65000 + i,
            data: vec![i as u8].into(),
        };
        let result = peer.process_command(&cmd, time).unwrap();
        assert_eq!(result.into_iter().count(), 1);
    }

    // Now send near the end of u16 range
    let cmd65500 = ProtocolCommand::SendUnsequenced {
        channel_id: 0,
        unsequenced_group: 65500,
        data: vec![1].into(),
    };
    let result1 = peer.process_command(&cmd65500, time).unwrap();
    assert_eq!(result1.into_iter().count(), 1);

    // Wrap around to 10 (should be treated as newer, after 65535)
    let cmd10 = ProtocolCommand::SendUnsequenced {
        channel_id: 0,
        unsequenced_group: 10,
        data: vec![2].into(),
    };
    let result2 = peer.process_command(&cmd10, time).unwrap();
    assert_eq!(result2.into_iter().count(), 1);

    // Sending 65002 (old packet from before) should be dropped
    let cmd65002 = ProtocolCommand::SendUnsequenced {
        channel_id: 0,
        unsequenced_group: 65002,
        data: vec![3].into(),
    };
    let result3 = peer.process_command(&cmd65002, time).unwrap();
    assert_eq!(result3.into_iter().count(), 0); // Should be dropped as old/duplicate
}

#[test]
fn test_unsequenced_per_channel() {
    let mut peer = create_virtual_connection();
    let time = Instant::now();

    // Send on channel 0
    let cmd_ch0 = ProtocolCommand::SendUnsequenced {
        channel_id: 0,
        unsequenced_group: 5,
        data: vec![0].into(),
    };

    // Send on channel 1 with same group (should not conflict)
    let cmd_ch1 = ProtocolCommand::SendUnsequenced {
        channel_id: 1,
        unsequenced_group: 5,
        data: vec![1].into(),
    };

    // Both should be delivered (unsequenced is global, not per-channel)
    // Note: Unlike ordered/sequenced which are per-channel, unsequenced
    // uses a global window
    let result0 = peer.process_command(&cmd_ch0, time).unwrap();
    let result1 = peer.process_command(&cmd_ch1, time).unwrap();

    assert_eq!(result0.into_iter().count(), 1);
    // Second one with same group is a duplicate (global window)
    assert_eq!(result1.into_iter().count(), 0);
}

#[test]
fn test_unsequenced_end_to_end() {
    let config = Config::default();
    let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
    let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());
    let time = Instant::now();

    // peer1 sends several unsequenced packets
    for i in 0..5 {
        let group = peer1.next_unsequenced_group();
        peer1.enqueue_command(ProtocolCommand::SendUnsequenced {
            channel_id: 0,
            unsequenced_group: group,
            data: vec![i].into(),
        });
    }

    let encoded = peer1.encode_queued_commands().unwrap();

    // peer2 receives all 5 packets
    let result = peer2.process_command_packet(&encoded, time).unwrap();
    let packets: Vec<_> = result.into_iter().collect();
    assert_eq!(packets.len(), 5);

    // Verify all packets have Unsequenced ordering
    for (pkt, _) in &packets {
        assert_eq!(pkt.order_guarantee(), OrderingGuarantee::Unsequenced);
    }

    // Send the same encoded data again - all should be dropped as duplicates
    let result2 = peer2.process_command_packet(&encoded, time).unwrap();
    assert_eq!(result2.into_iter().count(), 0);
}

#[test]
fn test_waiting_data_limit_drops_excess() {
    let mut config = Config::default();
    config.max_waiting_data = 1000; // Limit to 1KB
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Enqueue 500 bytes - should succeed
    let data1 = vec![1u8; 500];
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 1,
        ordered: true,
        data: data1.into(),
    });
    assert_eq!(peer.queued_commands_count(), 1);

    // Enqueue another 500 bytes - should succeed (total = 1000)
    let data2 = vec![2u8; 500];
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 2,
        ordered: true,
        data: data2.into(),
    });
    assert_eq!(peer.queued_commands_count(), 2);

    // Try to enqueue 100 more bytes - should be dropped (would exceed limit)
    let data3 = vec![3u8; 100];
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 3,
        ordered: true,
        data: data3.into(),
    });
    assert_eq!(peer.queued_commands_count(), 2); // Still 2, third was dropped
}

#[test]
fn test_waiting_data_unlimited_when_zero() {
    let mut config = Config::default();
    config.max_waiting_data = 0; // Unlimited
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Enqueue large amounts of data
    for i in 0..100 {
        let data = std::sync::Arc::<[u8]>::from(vec![i as u8; 10000].into_boxed_slice()); // 10KB each
        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: i,
            ordered: true,
            data: data.into(),
        });
    }

    // All 100 commands should be queued (total = 1MB)
    assert_eq!(peer.queued_commands_count(), 100);
}

#[test]
fn test_waiting_data_resets_on_drain() {
    let mut config = Config::default();
    config.max_waiting_data = 1000;
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Enqueue 1000 bytes
    let data1 = std::sync::Arc::<[u8]>::from(vec![1u8; 1000].into_boxed_slice());
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 1,
        ordered: true,
        data: data1.into(),
    });
    assert_eq!(peer.queued_commands_count(), 1);

    // Try to enqueue more - should be dropped
    let data2 = std::sync::Arc::<[u8]>::from(vec![2u8; 100].into_boxed_slice());
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 2,
        ordered: true,
        data: data2.into(),
    });
    assert_eq!(peer.queued_commands_count(), 1); // Still 1

    // Drain commands (simulating send)
    let _commands: Vec<_> = peer.drain_commands().collect();

    // Now we can enqueue again
    let data3 = std::sync::Arc::<[u8]>::from(vec![3u8; 1000].into_boxed_slice());
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 3,
        ordered: true,
        data: data3.into(),
    });
    assert_eq!(peer.queued_commands_count(), 1); // New command enqueued successfully
}

#[test]
fn test_waiting_data_control_commands_not_counted() {
    let mut config = Config::default();
    config.max_waiting_data = 100;
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Enqueue control commands (no data) - should always succeed
    peer.enqueue_command(ProtocolCommand::Ping { timestamp: 1 });
    peer.enqueue_command(ProtocolCommand::Pong { timestamp: 2 });
    peer.enqueue_command(ProtocolCommand::Disconnect { reason: 0 });
    peer.enqueue_command(ProtocolCommand::Acknowledge {
        sequence: 1,
        received_mask: 0xFF,
        sent_time: None,
    });

    assert_eq!(peer.queued_commands_count(), 4);

    // Now enqueue data commands up to the limit
    let data = std::sync::Arc::<[u8]>::from(vec![1u8; 100].into_boxed_slice());
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 1,
        ordered: true,
        data: data.into(),
    });

    assert_eq!(peer.queued_commands_count(), 5); // All commands enqueued
}

#[test]
fn test_window_flow_control_enabled() {
    let mut config = Config::default();
    config.use_window_flow_control = true;
    config.initial_window_size = 100;
    let peer = Peer::new(get_fake_addr(), &config, Instant::now());

    assert_eq!(peer.window_size(), 100);
    assert_eq!(peer.reliable_data_in_transit(), 0);
    assert!(peer.can_send_reliable());
}

#[test]
fn test_window_flow_control_tracks_in_transit_data() {
    let mut config = Config::default();
    config.use_window_flow_control = true;
    config.initial_window_size = 10; // Small window
    config.fragment_size = 1024;
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Initially can send
    assert!(peer.can_send_reliable());

    // Record sending 5KB of data
    peer.record_reliable_data_sent(5 * 1024);
    assert_eq!(peer.reliable_data_in_transit(), 5 * 1024);

    // Can still send (5KB < 10 packets * 1024 bytes = 10KB window)
    assert!(peer.can_send_reliable());

    // Record sending another 6KB (total 11KB, exceeds 10KB window)
    peer.record_reliable_data_sent(6 * 1024);
    assert_eq!(peer.reliable_data_in_transit(), 11 * 1024);

    // Now cannot send (exceeds window)
    assert!(!peer.can_send_reliable());

    // ACK some data (3KB)
    peer.record_reliable_data_acked(3 * 1024);
    assert_eq!(peer.reliable_data_in_transit(), 8 * 1024);

    // Now can send again (8KB < 10KB window)
    assert!(peer.can_send_reliable());
}

#[test]
fn test_window_size_negotiation() {
    let mut config = Config::default();
    config.use_window_flow_control = true;
    config.initial_window_size = 1000;
    config.min_window_size = 64;
    config.max_window_size = 2048;
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    assert_eq!(peer.window_size(), 1000);

    // Set to a value within range
    peer.set_window_size(512);
    assert_eq!(peer.window_size(), 512);

    // Set to value above max - should clamp
    peer.set_window_size(3000);
    assert_eq!(peer.window_size(), 2048);

    // Set to value below min - should clamp
    peer.set_window_size(32);
    assert_eq!(peer.window_size(), 64);
}

#[test]
fn test_window_adjustment_increases_on_good_conditions() {
    let mut config = Config::default();
    config.use_window_flow_control = true;
    config.initial_window_size = 100;
    config.max_window_size = 200;
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    let initial_window = peer.window_size();

    // Simulate good conditions (no loss, low RTT)
    // peer.loss_rate() will be 0.0 by default
    // peer.rtt() is 50ms by default

    peer.adjust_window_size();

    // Window should increase
    assert!(peer.window_size() > initial_window);
}

#[test]
fn test_window_flow_control_disabled_uses_packet_limit() {
    let mut config = Config::default();
    config.use_window_flow_control = false; // Disabled
    config.max_packets_in_flight = 10;
    let peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // When disabled, should use packets_in_flight limit
    // Initially 0 packets in flight, so can send
    assert!(peer.can_send_reliable());
    assert_eq!(peer.packets_in_flight(), 0);
}

// ===== Statistics Tests =====

#[test]
fn test_statistics_initialized_to_zero() {
    let config = Config::default();
    let peer = Peer::new(get_fake_addr(), &config, Instant::now());

    let stats = peer.statistics();
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_received, 0);
    assert_eq!(stats.packets_lost, 0);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
    assert_eq!(stats.packet_loss_rate(), 0.0);
}

#[test]
fn test_statistics_track_packets_sent() {
    let config = Config::default();
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Enqueue and encode a command
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 0,
        ordered: true,
        data: vec![1, 2, 3].into(),
    });

    // Encode should increment packets_sent
    let _ = peer.encode_queued_commands().unwrap();
    assert_eq!(peer.statistics().packets_sent, 1);
    assert!(peer.statistics().bytes_sent > 0);
}

#[test]
fn test_statistics_track_packets_received() {
    let config = Config::default();
    let mut peer1 = Peer::new(get_fake_addr(), &config, Instant::now());
    let mut peer2 = Peer::new(get_fake_addr(), &config, Instant::now());

    // Use peer1 to create a proper packet
    peer1.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 0,
        ordered: true,
        data: vec![1, 2, 3, 4, 5].into(),
    });
    let encoded = peer1.encode_queued_commands().unwrap();

    // Process the packet with peer2
    let _ = peer2.process_command_packet(&encoded, Instant::now()).unwrap();

    assert_eq!(peer2.statistics().packets_received, 1);
    assert_eq!(peer2.statistics().bytes_received, encoded.len() as u64);
}

#[test]
fn test_statistics_track_multiple_packets() {
    let config = Config::default();
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Send multiple packets
    for i in 0..5 {
        peer.enqueue_command(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: i,
            ordered: true,
            data: vec![1, 2, 3].into(),
        });
        let _ = peer.encode_queued_commands().unwrap();
    }

    assert_eq!(peer.statistics().packets_sent, 5);
    assert!(peer.statistics().bytes_sent > 0);
}

#[test]
fn test_statistics_track_packet_loss() {
    let config = Config::default();
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Manually set some packets as lost to test tracking
    peer.statistics_mut().packets_lost = 5;

    assert_eq!(peer.statistics().packets_lost, 5);
}

#[test]
fn test_statistics_packet_loss_rate() {
    let config = Config::default();
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Manually set statistics for controlled test
    peer.statistics_mut().packets_sent = 100;
    peer.statistics_mut().packets_lost = 10;

    let loss_rate = peer.statistics().packet_loss_rate();
    assert!((loss_rate - 0.1).abs() < 0.001); // 10/100 = 0.1 = 10%
}

#[test]
fn test_statistics_bytes_sent_includes_overhead() {
    let config = Config::default();
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Enqueue a small data packet
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 0,
        ordered: true,
        data: vec![1, 2, 3].into(),
    });

    let encoded = peer.encode_queued_commands().unwrap();

    // bytes_sent should equal the full encoded packet size (data + protocol overhead)
    assert_eq!(peer.statistics().bytes_sent, encoded.len() as u64);
    assert!(peer.statistics().bytes_sent > 3); // More than just the 3 data bytes
}

#[test]
fn test_statistics_reset() {
    let config = Config::default();
    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

    // Generate some statistics
    peer.enqueue_command(ProtocolCommand::SendReliable {
        channel_id: 0,
        sequence: 0,
        ordered: true,
        data: vec![1, 2, 3].into(),
    });
    let _ = peer.encode_queued_commands().unwrap();

    assert!(peer.statistics().packets_sent > 0);
    assert!(peer.statistics().bytes_sent > 0);

    // Reset statistics
    peer.statistics_mut().reset();

    assert_eq!(peer.statistics().packets_sent, 0);
    assert_eq!(peer.statistics().packets_received, 0);
    assert_eq!(peer.statistics().packets_lost, 0);
    assert_eq!(peer.statistics().bytes_sent, 0);
    assert_eq!(peer.statistics().bytes_received, 0);
}

#[test]
fn test_pmtu_discovery_can_be_disabled() {
    let mut config = Config::default();
    config.use_pmtu_discovery = false;
    assert!(!config.use_pmtu_discovery);

    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());
    let time = Instant::now();

    // Should not generate any probes when disabled
    peer.handle_pmtu(time);
    assert!(!peer.has_queued_commands());
}

#[test]
fn test_pmtu_discovery_convergence() {
    let mut config = Config::default();
    config.use_pmtu_discovery = true;
    config.pmtu_min = 1200;
    config.pmtu_max = 1232; // Within convergence threshold
    config.pmtu_converge_threshold = 64;

    let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());
    let time = Instant::now();

    // When high - low <= threshold, should converge to low
    peer.handle_pmtu(time);

    // Should converge and use pmtu_low as fragment size
    assert_eq!(peer.current_fragment_size(), config.pmtu_min);
}
