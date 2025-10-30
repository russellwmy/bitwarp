use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

use bitwarp_core::{
    config::Config,
    packet_pool::PacketAllocator,
};
use bitwarp_protocol::{
    command::ProtocolCommand,
    AcknowledgmentHandler, SentPacket,
};

use crate::{
    bandwidth_throttle::BandwidthThrottle, channel_state::ChannelState,
    command_queue::CommandQueue,
    flow_control::FlowControl,
    fragment_buffer::{cleanup_stale_fragments, CommandFragmentBuffer},
    peer_state::PeerState, pmtu_discovery::PmtuDiscovery, statistics::PeerStatistics,
    unsequenced::UnsequencedState,
};

mod command_processor;
mod encoder;
mod fragmenter;

/// Represents a remote peer in the network.
/// Tracks network quality, processes packets, and manages connection state.
pub struct Peer {
    /// Last time we received a packet from this client
    pub last_heard: Instant,
    /// Last time we sent a packet to this client
    pub last_sent: Instant,
    /// The address of the remote endpoint
    pub remote_address: SocketAddr,

    /// Current connection state
    state: PeerState,

    // Connection handshake tracking
    /// Assigned peer ID (from server)
    peer_id: u16,
    /// Incoming session ID (from remote peer's perspective)
    incoming_session_id: u16,
    /// Outgoing session ID (our perspective)
    outgoing_session_id: u16,
    /// Connect ID for replay protection
    connect_id: u32,

    /// Outgoing reliable packet sequence number
    #[allow(dead_code)]
    outgoing_reliable_sequence: u16,
    /// Outgoing unreliable packet sequence number
    #[allow(dead_code)]
    outgoing_unreliable_sequence: u16,
    /// Incoming reliable packet sequence number
    #[allow(dead_code)]
    incoming_reliable_sequence: u16,
    /// Incoming unreliable packet sequence number
    #[allow(dead_code)]
    incoming_unreliable_sequence: u16,
    /// Sequence number for unreliable fragment reassembly (increments for each fragmented unreliable packet)
    next_unreliable_sequence: u16,

    /// Unsequenced packet duplicate detection state
    unsequenced_state: UnsequencedState,

    /// Handler for reliable delivery acknowledgments and congestion control
    acknowledge_handler: AcknowledgmentHandler,

    /// Configuration parameters for this peer
    config: Config,

    /// Command queue for batching protocol commands
    command_queue: CommandQueue,
    /// Total bytes of packet data waiting in the command queue
    total_waiting_data: usize,
    /// Fragment reassembly buffer for command-based fragments (indexed by sequence number)
    command_fragments: HashMap<u16, CommandFragmentBuffer>,
    /// Per-channel ordering/sequencing state
    channel_states: HashMap<u8, ChannelState>,

    // Window-based flow control
    /// Flow control state for reliable data transmission
    flow_control: FlowControl,

    // Bandwidth throttling
    /// Bandwidth tracking and limiting
    bandwidth_throttle: BandwidthThrottle,

    // Statistics tracking
    /// Comprehensive statistics for this peer
    statistics: PeerStatistics,

    /// Scratch buffer pool for encoding/compression to reduce heap allocations
    tx_pool: PacketAllocator,
    /// Compression output buffer pool for reducing compression allocations
    compression_pool: bitwarp_core::packet_pool::CompressionBufferPool,

    /// Path MTU discovery manager
    pmtu: PmtuDiscovery,
}

impl Peer {
    /// Creates and returns a new peer for the provided socket address.
    pub fn new(addr: SocketAddr, config: &Config, time: Instant) -> Peer {
        use rand::Rng;
        let mut rng = rand::rng();

        Peer {
            last_heard: time,
            last_sent: time,
            remote_address: addr,
            state: PeerState::Idle,
            peer_id: 0, // Will be assigned during handshake
            incoming_session_id: 0,
            outgoing_session_id: rng.random(), // Random session ID for security
            connect_id: rng.random(),          // Random connect ID for replay protection
            outgoing_reliable_sequence: 0,
            outgoing_unreliable_sequence: 0,
            incoming_reliable_sequence: 0,
            incoming_unreliable_sequence: 0,
            next_unreliable_sequence: 0,
            unsequenced_state: UnsequencedState::new(),
            acknowledge_handler: {
                let mut handler = AcknowledgmentHandler::new();
                // Configure advanced throttling if enabled
                if config.use_advanced_throttling {
                    handler.congestion_mut().enable_advanced_throttling(
                        config.throttle_scale,
                        config.throttle_acceleration,
                        config.throttle_deceleration,
                        config.throttle_interval,
                    );
                }
                handler
            },
            config: config.to_owned(),
            command_queue: CommandQueue::default(),
            total_waiting_data: 0,
            command_fragments: HashMap::new(),
            channel_states: HashMap::new(),
            flow_control: FlowControl::new(config),
            bandwidth_throttle: BandwidthThrottle::new(
                config.outgoing_bandwidth_limit,
                config.incoming_bandwidth_limit,
                time,
            ),
            statistics: PeerStatistics::default(),
            tx_pool: PacketAllocator::new(config.max_packet_size, 256),
            compression_pool: bitwarp_core::packet_pool::CompressionBufferPool::default(),
            pmtu: PmtuDiscovery::new(config, time),
        }
    }

    /// Records that this connection has sent a packet. Returns whether the connection has
    /// become acknowledged because of this send.
    pub fn record_send(&mut self) -> bool {
        let was_est = self.is_established();

        // Update state based on send
        match self.state {
            PeerState::Idle => {
                if self.config.use_connection_handshake {
                    // Initiate formal 3-way handshake
                    self.initiate_connect();
                } else {
                    // Simple implicit connection (backward compatible)
                    self.state = PeerState::Connecting;
                }
            }
            PeerState::ConnectionSucceeded => {
                // Client completing handshake with implicit ACK
                self.state = PeerState::Connected;
            }
            _ => {}
        }

        !was_est && self.is_established()
    }

    /// Records that this connection has received a packet. Returns whether the connection has
    /// become acknowledged because of this receive.
    pub fn record_recv(&mut self) -> bool {
        let was_est = self.is_established();

        // Update state based on receive
        match self.state {
            PeerState::Idle => {
                if !self.config.use_connection_handshake {
                    // Simple implicit connection (backward compatible)
                    // Server receiving packet from unknown client
                    self.state = PeerState::Connected;
                }
                // Otherwise, formal handshake via Connect command will handle state
            }
            PeerState::Connecting => {
                if !self.config.use_connection_handshake {
                    // Simple implicit connection (backward compatible)
                    self.state = PeerState::Connected;
                }
                // Otherwise, formal handshake via VerifyConnect command will handle state
            }
            PeerState::AcknowledgingConnect => {
                // Server received ACK (any data packet) from client
                self.state = PeerState::Connected;
            }
            _ => {}
        }

        !was_est && self.is_established()
    }

    /// Returns if the connection has been established
    pub fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// Returns the current peer state
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Initiates graceful disconnect
    pub fn disconnect(&mut self) {
        if !self.state.is_disconnecting() {
            self.state = PeerState::Disconnecting;
            self.command_queue.enqueue(ProtocolCommand::Disconnect { reason: 0 });
        }
    }

    // ===== Connection Handshake (3-way) =====

    /// Initiates a connection handshake by sending CONNECT command (step 1 of 3).
    /// Should be called when transitioning from Idle to Connecting.
    pub fn initiate_connect(&mut self) {
        if self.state == PeerState::Idle {
            self.state = PeerState::Connecting;
            let connect_command = ProtocolCommand::Connect {
                channels: self.config.channel_count,
                mtu: 1400,           // Default MTU
                protocol_version: 1, // Protocol version
                outgoing_session_id: self.outgoing_session_id,
                connect_id: self.connect_id,
            };
            self.command_queue.enqueue(connect_command);
        }
    }

    /// Returns the current number of not yet acknowledged packets
    pub fn packets_in_flight(&self) -> u16 {
        self.acknowledge_handler.packets_in_flight()
    }

    /// Returns a [Duration] representing the interval since we last heard from the client
    pub fn last_heard(&self, time: Instant) -> Duration {
        time.duration_since(self.last_heard)
    }

    /// Returns a [Duration] representing the interval since we last sent to the client
    pub fn last_sent(&self, time: Instant) -> Duration {
        time.duration_since(self.last_sent)
    }

    /// Returns the current round-trip time for this connection.
    pub fn rtt(&self) -> Duration {
        self.acknowledge_handler.rtt()
    }

    /// Returns the retransmission timeout for this connection.
    pub fn rto(&self) -> Duration {
        self.acknowledge_handler.rto()
    }

    /// Returns the current packet loss rate (0.0 to 1.0).
    pub fn loss_rate(&self) -> f32 {
        self.acknowledge_handler.loss_rate()
    }

    /// Returns the current congestion throttle value (0.0 to 1.0).
    pub fn throttle(&self) -> f32 {
        self.acknowledge_handler.throttle()
    }

    /// Updates the congestion throttle based on current network conditions.
    pub fn update_throttle(&mut self, time: Instant) -> bool {
        self.acknowledge_handler.update_throttle(time)
    }

    /// Returns the configuration for this peer.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Gathers dropped packets from the acknowledgment handler.
    pub fn gather_dropped_packets(&mut self) -> Vec<SentPacket> {
        let dropped = self.acknowledge_handler.dropped_packets();

        // Track packet loss
        for _ in &dropped {
            self.record_packet_lost();
        }

        dropped
    }

    // ===== Statistics =====

    /// Returns a reference to the peer's statistics.
    pub fn statistics(&self) -> &PeerStatistics {
        &self.statistics
    }

    /// Returns a mutable reference to the peer's statistics.
    pub fn statistics_mut(&mut self) -> &mut PeerStatistics {
        &mut self.statistics
    }

    /// Records a packet being sent.
    fn record_packet_sent(&mut self) {
        self.statistics.packets_sent += 1;
    }

    /// Records a packet being received.
    fn record_packet_received(&mut self) {
        self.statistics.packets_received += 1;
    }

    /// Records a packet being lost.
    fn record_packet_lost(&mut self) {
        self.statistics.packets_lost += 1;
    }

    /// Records data bytes being sent (payload only, not protocol overhead).
    fn record_data_sent(&mut self, bytes: usize) {
        self.statistics.bytes_sent += bytes as u64;
    }

    /// Records data bytes being received (payload only, not protocol overhead).
    fn record_data_received(&mut self, bytes: usize) {
        self.statistics.bytes_received += bytes as u64;
    }

    /// Returns current per-peer fragment size in bytes.
    pub fn current_fragment_size(&self) -> u16 {
        self.pmtu.current_fragment_size()
    }

    /// Handles PMTU probing state machine (enqueue probes, process timeouts).
    pub fn handle_pmtu(&mut self, time: Instant) {
        let rto = self.rto();
        if let Some(probe_cmd) = self.pmtu.handle_pmtu(time, rto) {
            self.enqueue_command(probe_cmd);
        }
    }

    // ===== Window-based Flow Control =====

    /// Returns the current window size (in packets).
    pub fn window_size(&self) -> u32 {
        self.flow_control.window_size()
    }

    /// Returns the amount of reliable data currently in transit (in bytes).
    pub fn reliable_data_in_transit(&self) -> u32 {
        self.flow_control.reliable_data_in_transit()
    }

    /// Sets the window size (for negotiation during handshake).
    pub fn set_window_size(&mut self, window_size: u32) {
        self.flow_control.set_window_size(&self.config, window_size);
    }

    /// Records reliable data being sent (adds to in-transit counter).
    pub fn record_reliable_data_sent(&mut self, data_size: u32) {
        self.flow_control.record_reliable_data_sent(data_size);
    }

    /// Records reliable data being acknowledged (removes from in-transit counter).
    pub fn record_reliable_data_acked(&mut self, data_size: u32) {
        self.flow_control.record_reliable_data_acked(data_size);
    }

    /// Checks if we can send more data based on window-based flow control.
    /// Returns true if we have room in the window.
    pub fn can_send_reliable(&self) -> bool {
        self.flow_control.can_send_reliable(&self.config, self.packets_in_flight())
    }

    /// Dynamically adjusts the window size based on network conditions.
    /// Called periodically to adapt to changing network conditions.
    pub fn adjust_window_size(&mut self) {
        let loss_rate = self.loss_rate();
        let rtt_ms = self.rtt().as_millis() as u32;
        self.flow_control.adjust_window_size(&self.config, loss_rate, rtt_ms);
    }

    // ===== Bandwidth Throttling =====

    /// Updates bandwidth tracking window, resetting counters if window expired.
    /// Returns true if the window was reset.
    pub fn update_bandwidth_window(&mut self, time: Instant) -> bool {
        self.bandwidth_throttle.update_bandwidth_window(time)
    }

    /// Records bytes sent for bandwidth tracking.
    pub fn record_bytes_sent(&mut self, bytes: u32) {
        self.bandwidth_throttle.record_bytes_sent(bytes);
    }

    /// Records bytes received for bandwidth tracking.
    pub fn record_bytes_received(&mut self, bytes: u32) {
        self.bandwidth_throttle.record_bytes_received(bytes);
    }

    /// Checks if we can send based on outgoing bandwidth limit.
    /// Returns true if we're under the limit or if throttling is disabled (limit == 0).
    pub fn can_send_within_bandwidth(&self) -> bool {
        self.bandwidth_throttle.can_send_within_bandwidth()
    }

    /// Returns current bandwidth utilization (0.0 to 1.0+).
    /// Returns 0.0 if bandwidth limiting is disabled.
    pub fn bandwidth_utilization(&self) -> f32 {
        self.bandwidth_throttle.bandwidth_utilization()
    }

    /// Checks if we can receive based on incoming bandwidth limit.
    /// Returns true if we're under the limit or if throttling is disabled (limit == 0).
    pub fn can_receive_within_bandwidth(&self) -> bool {
        self.bandwidth_throttle.can_receive_within_bandwidth()
    }

    /// Returns current incoming bandwidth utilization (0.0 to 1.0+).
    /// Returns 0.0 if bandwidth limiting is disabled.
    pub fn incoming_bandwidth_utilization(&self) -> f32 {
        self.bandwidth_throttle.incoming_bandwidth_utilization()
    }

    // ===== Unsequenced Packet Handling =====

    /// Gets the next outgoing unsequenced group ID and increments the counter.
    pub fn next_unsequenced_group(&mut self) -> u16 {
        self.unsequenced_state.next_outgoing_group()
    }

    /// Checks if an incoming unsequenced group is a duplicate or within the window.
    /// Returns true if this is a duplicate (already received), false if new.
    pub fn is_unsequenced_duplicate(&self, group: u16) -> bool {
        self.unsequenced_state.is_duplicate(group)
    }

    /// Marks an incoming unsequenced group as received in the window.
    /// Advances the window base if necessary.
    pub fn mark_unsequenced_received(&mut self, group: u16) {
        self.unsequenced_state.mark_received(group);
    }

    /// Cleans up stale fragment buffers that haven't been completed within the timeout period.
    /// This prevents memory leaks from incomplete fragments (e.g., due to packet loss or malicious behavior).
    ///
    /// Call this periodically (e.g., once per second) to prevent accumulation of stale buffers.
    /// Default timeout is 5 seconds after the first fragment is received.
    pub fn cleanup_stale_fragments(&mut self, time: Instant) {
        cleanup_stale_fragments(&mut self.command_fragments, time);
    }

    // ===== Command-based API =====

    /// Returns the size of data carried by a protocol command.
    /// Only counts actual packet payload data, not protocol overhead.
    fn command_data_size(command: &ProtocolCommand) -> usize {
        match command {
            ProtocolCommand::SendReliable { data, .. }
            | ProtocolCommand::SendUnreliable { data, .. }
            | ProtocolCommand::SendUnreliableSequenced { data, .. }
            | ProtocolCommand::SendUnsequenced { data, .. }
            | ProtocolCommand::SendFragment { data, .. }
            | ProtocolCommand::SendUnreliableFragment { data, .. } => data.len(),
            _ => 0, // Control commands have no data
        }
    }

    /// Enqueues a protocol command for batching.
    /// Returns true if the queue should be flushed (reached max size).
    /// Returns false and drops the command if it would exceed max_waiting_data limit.
    pub fn enqueue_command(&mut self, command: ProtocolCommand) -> bool {
        let data_size = Self::command_data_size(&command);

        // Check if adding this command would exceed the limit (0 = unlimited)
        if self.config.max_waiting_data > 0 {
            let new_total = self.total_waiting_data + data_size;
            if new_total > self.config.max_waiting_data {
                // Drop the command to prevent memory exhaustion
                tracing::warn!(
                    "Dropping command: would exceed max_waiting_data limit ({} + {} > {})",
                    self.total_waiting_data,
                    data_size,
                    self.config.max_waiting_data
                );
                return false;
            }
        }

        self.total_waiting_data += data_size;
        self.command_queue.enqueue(command)
    }

    /// Generates and enqueues an Acknowledge command based on current state.
    /// This should be called after receiving reliable packets to send ACKs back.
    pub fn enqueue_ack_command(&mut self, sent_time: Option<u32>) {
        let ack_command = ProtocolCommand::Acknowledge {
            sequence: self.acknowledge_handler.remote_sequence_num(),
            received_mask: self.acknowledge_handler.ack_bitfield(),
            sent_time,
        };
        self.enqueue_command(ack_command);
    }

    /// Generates and enqueues a Ping command with the current timestamp.
    pub fn enqueue_ping_command(&mut self, timestamp: u32) {
        self.enqueue_command(ProtocolCommand::Ping { timestamp });
    }

    /// Generates and enqueues a Pong command in response to a Ping.
    pub fn enqueue_pong_command(&mut self, timestamp: u32) {
        self.enqueue_command(ProtocolCommand::Pong { timestamp });
    }

    /// Drains all pending commands from the queue.
    /// Resets the total_waiting_data counter since commands are being sent.
    pub fn drain_commands(&mut self) -> impl Iterator<Item = ProtocolCommand> + '_ {
        self.total_waiting_data = 0; // Reset since we're draining all commands
        self.command_queue.drain()
    }

    /// Returns the number of queued commands.
    pub fn queued_commands_count(&self) -> usize {
        self.command_queue.len()
    }

    /// Returns true if the command queue is empty.
    pub fn has_queued_commands(&self) -> bool {
        !self.command_queue.is_empty()
    }

}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.remote_address.ip(), self.remote_address.port())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bitwarp_core::config::Config;

    use super::Peer;

    fn get_fake_addr() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    // Unit tests that access private fields (acknowledge_handler, pmtu, state)
    // Integration tests that only use public API are in tests/integration.rs

    #[test]
    fn test_window_adjustment_decreases_on_poor_conditions() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 200;
        config.min_window_size = 64;
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        let initial_window = peer.window_size();

        // Simulate poor conditions (high packet loss)
        // Need to record packets and losses
        for _ in 0..100 {
            peer.acknowledge_handler.congestion_mut().record_sent();
        }
        for _ in 0..10 {
            peer.acknowledge_handler.congestion_mut().record_loss();
        } // 10% loss

        peer.adjust_window_size();

        // Window should decrease
        assert!(peer.window_size() < initial_window);
    }

    #[test]
    fn test_window_flow_control_respects_min_max() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 100;
        config.min_window_size = 64;
        config.max_window_size = 128;
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        // Repeatedly adjust upward
        for _ in 0..50 {
            peer.adjust_window_size();
        }

        // Should not exceed max
        assert!(peer.window_size() <= 128);

        // Simulate sustained poor conditions
        for _round in 0..50 {
            for _ in 0..100 {
                peer.acknowledge_handler.congestion_mut().record_sent();
            }
            for _ in 0..10 {
                peer.acknowledge_handler.congestion_mut().record_loss();
            }
            peer.adjust_window_size();
        }

        // Should not go below min
        assert!(peer.window_size() >= 64);
    }

    #[test]
    fn test_pmtu_discovery_probe_reply() {
        let mut config = Config::default();
        config.use_pmtu_discovery = true;
        config.pmtu_min = 576;
        config.pmtu_max = 1400;
        config.pmtu_interval_ms = 100; // Short interval for testing

        let start_time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, start_time);

        // Initially, peer should use config fragment_size
        assert_eq!(peer.current_fragment_size(), config.fragment_size);

        // Advance time past the probe interval to trigger first probe
        let time = start_time + std::time::Duration::from_millis(150);
        peer.handle_pmtu(time);

        // Should have queued a probe command
        assert!(peer.has_queued_commands());

        // Encode and check for PMTUProbe command
        let encoded = peer.encode_queued_commands().unwrap();
        assert!(!encoded.is_empty());

        // Check that peer is waiting for reply
        assert!(peer.pmtu.has_outstanding_probe());

        // Simulate successful reply (this would update low bound)
        if let Some((size, token, _)) = peer.pmtu.outstanding_probe() {
            let reply = bitwarp_protocol::command::ProtocolCommand::PMTUReply { size, token };
            let _ = peer.process_command(&reply, time).unwrap();

            // After successful reply, low bound should be updated
            assert_eq!(peer.current_fragment_size(), size);
        }
    }

    #[test]
    fn test_pmtu_discovery_timeout() {
        let mut config = Config::default();
        config.use_pmtu_discovery = true;
        config.pmtu_min = 576;
        config.pmtu_max = 1400;
        config.pmtu_interval_ms = 100;

        let start_time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, start_time);

        // Advance time to trigger initial probe
        let mut time = start_time + std::time::Duration::from_millis(150);
        peer.handle_pmtu(time);
        assert!(peer.has_queued_commands());
        let _ = peer.encode_queued_commands().unwrap();

        let high_before = peer.pmtu.high_bound();

        // Advance time beyond RTO to trigger timeout (RTO is typically 200ms+)
        time = time + std::time::Duration::from_secs(2);

        // Handle PMTU again - should timeout the outstanding probe
        peer.handle_pmtu(time);

        // After timeout, outstanding should be cleared and high bound reduced
        assert!(!peer.pmtu.has_outstanding_probe());
        assert!(peer.pmtu.high_bound() < high_before);
    }

    #[test]
    fn test_pmtu_discovery_enabled_by_default() {
        let config = Config::default();
        assert!(config.use_pmtu_discovery);

        let creation_time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, creation_time);
        // Move peer to connected state via state transitions
        peer.state = crate::peer_state::PeerState::Connected;

        // Wait for the PMTU interval to elapse before checking for probes
        let probe_time = creation_time + std::time::Duration::from_millis(config.pmtu_interval_ms as u64 + 100);

        // Should generate probes when enabled and connected after interval
        peer.handle_pmtu(probe_time);
        assert!(peer.has_queued_commands()); // Should have queued a PMTUProbe command
    }
}
