use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bitwarp_core::{
    config::Config,
    error::{ErrorKind, Result},
    packet_pool::PacketAllocator,
    shared::SharedBytes,
};
use bitwarp_protocol::{
    command::{CommandPacket, ProtocolCommand},
    command_codec::{CommandDecoder, CommandEncoder},
    packet::{DeliveryGuarantee, IncomingPackets, OrderingGuarantee, Packet, PacketType},
    AcknowledgmentHandler, SentPacket,
};

use crate::{command_queue::CommandQueue, peer_state::PeerState};

/// Tracks per-channel ordering state.
#[derive(Debug)]
struct ChannelState {
    /// Expected next sequence number for ordered delivery
    expected_sequence: u16,
    /// Buffered out-of-order packets waiting for missing sequences
    buffered_packets: HashMap<u16, bitwarp_core::shared::SharedBytes>,
    /// Latest sequence number seen (for sequenced/drop-old behavior)
    latest_sequence: u16,
}

impl ChannelState {
    fn new() -> Self {
        Self { expected_sequence: 0, buffered_packets: HashMap::new(), latest_sequence: 0 }
    }

    /// Process an ordered packet. Returns packets ready for delivery (in order).
    /// Buffers out-of-order packets until the missing sequences arrive.
    fn process_ordered(
        &mut self,
        sequence: u16,
        data: bitwarp_core::shared::SharedBytes,
    ) -> Vec<bitwarp_core::shared::SharedBytes> {
        let mut ready_packets = Vec::new();

        // Buffer this packet
        self.buffered_packets.insert(sequence, data);

        // Deliver all consecutive packets starting from expected_sequence
        while let Some(packet_data) = self.buffered_packets.remove(&self.expected_sequence) {
            ready_packets.push(packet_data);
            self.expected_sequence = self.expected_sequence.wrapping_add(1);
        }

        ready_packets
    }

    /// Process a sequenced packet. Returns Some(data) if this is the latest, None if old.
    /// Sequenced packets drop old ones and only deliver the newest.
    fn process_sequenced(
        &mut self,
        sequence: u16,
        data: bitwarp_core::shared::SharedBytes,
    ) -> Option<bitwarp_core::shared::SharedBytes> {
        // Check if this is newer than what we've seen (with wrapping)
        let is_newer = sequence.wrapping_sub(self.latest_sequence) < 32768;

        if is_newer || sequence == 0 {
            self.latest_sequence = sequence;
            Some(data)
        } else {
            None // Old packet, drop it
        }
    }
}

/// Tracks reassembly of fragmented command packets.
#[derive(Debug)]
struct CommandFragmentBuffer {
    /// Channel ID for this fragment group
    channel_id: u8,
    /// Total number of fragments expected
    fragment_count: u8,
    /// Whether to deliver in order on receive for this reassembled packet
    ordered: bool,
    /// Fragments received so far (indexed by fragment_id)
    fragments: HashMap<u8, std::sync::Arc<[u8]>>,
    /// Timestamp when first fragment was received (for timeout detection)
    created_at: Instant,
}

impl CommandFragmentBuffer {
    fn new(channel_id: u8, fragment_count: u8, ordered: bool, created_at: Instant) -> Self {
        Self { channel_id, fragment_count, ordered, fragments: HashMap::new(), created_at }
    }

    fn channel_id(&self) -> u8 {
        self.channel_id
    }

    fn is_ordered(&self) -> bool {
        self.ordered
    }

    fn add_fragment(&mut self, fragment_id: u8, data: std::sync::Arc<[u8]>) {
        self.fragments.insert(fragment_id, data);
    }

    fn is_complete(&self) -> bool {
        self.fragments.len() == self.fragment_count as usize
    }

    fn reassemble(mut self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let mut result = Vec::new();
        for fragment_id in 0..self.fragment_count {
            if let Some(data) = self.fragments.remove(&fragment_id) {
                result.extend_from_slice(&data);
            } else {
                return None; // Missing fragment
            }
        }
        Some(result)
    }
}

/// Comprehensive statistics for a peer connection.
/// Tracks packets, bytes, and network quality metrics.
#[derive(Debug, Clone, Default)]
pub struct PeerStatistics {
    /// Total packets sent to this peer
    pub packets_sent: u64,
    /// Total packets received from this peer
    pub packets_received: u64,
    /// Total packets lost (detected via ACK timeouts)
    pub packets_lost: u64,
    /// Total data bytes sent to this peer (excluding protocol overhead)
    pub bytes_sent: u64,
    /// Total data bytes received from this peer (excluding protocol overhead)
    pub bytes_received: u64,
}

impl PeerStatistics {
    /// Returns the packet loss rate (0.0 to 1.0).
    pub fn packet_loss_rate(&self) -> f32 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_lost as f32 / self.packets_sent as f32
    }

    /// Resets all statistics counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

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
    /// Outgoing unsequenced group counter
    outgoing_unsequenced_group: u16,
    /// Incoming reliable packet sequence number
    #[allow(dead_code)]
    incoming_reliable_sequence: u16,
    /// Incoming unreliable packet sequence number
    #[allow(dead_code)]
    incoming_unreliable_sequence: u16,
    /// Incoming unsequenced group base (start of sliding window)
    incoming_unsequenced_group: u16,
    /// Unsequenced window for duplicate detection (1024 bits = 128 bytes)
    /// Each bit represents whether a group has been received in the window
    unsequenced_window: [u32; 32], // 32 u32s = 1024 bits
    /// Sequence number for unreliable fragment reassembly (increments for each fragmented unreliable packet)
    next_unreliable_sequence: u16,

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
    /// Current window size for flow control (in packets)
    window_size: u32,
    /// Reliable data currently in transit (waiting for ACK), in bytes
    reliable_data_in_transit: u32,

    // Bandwidth throttling
    /// Bytes sent in current bandwidth window
    bytes_sent_this_window: u32,
    /// Bytes received in current bandwidth window
    bytes_received_this_window: u32,
    /// Start of current bandwidth tracking window
    bandwidth_window_start: Instant,

    // Statistics tracking
    /// Comprehensive statistics for this peer
    statistics: PeerStatistics,

    /// Scratch buffer pool for encoding/compression to reduce heap allocations
    tx_pool: PacketAllocator,
    /// Compression output buffer pool for reducing compression allocations
    compression_pool: bitwarp_core::packet_pool::CompressionBufferPool,

    // ===== PMTU Discovery (application-level) =====
    /// Effective per-peer fragment size (bytes)
    peer_fragment_size: u16,
    /// PMTU binary search low bound (bytes)
    pmtu_low: u16,
    /// PMTU binary search high bound (bytes)
    pmtu_high: u16,
    /// Last time we probed PMTU
    pmtu_last_probe: Instant,
    /// Outstanding PMTU probe info
    pmtu_outstanding: Option<(u16 /*size*/, u32 /*token*/, Instant /*sent*/)>,
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
            outgoing_unsequenced_group: 0,
            incoming_reliable_sequence: 0,
            incoming_unreliable_sequence: 0,
            incoming_unsequenced_group: 0,
            unsequenced_window: [0; 32], // All bits start as 0 (no groups received)
            next_unreliable_sequence: 0,
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
            window_size: config.initial_window_size,
            reliable_data_in_transit: 0,
            bytes_sent_this_window: 0,
            bytes_received_this_window: 0,
            bandwidth_window_start: time,
            statistics: PeerStatistics::default(),
            tx_pool: PacketAllocator::new(config.max_packet_size, 256),
            compression_pool: bitwarp_core::packet_pool::CompressionBufferPool::default(),
            peer_fragment_size: config.fragment_size,
            pmtu_low: config.pmtu_min,
            pmtu_high: config.pmtu_max,
            pmtu_last_probe: time,
            pmtu_outstanding: None,
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
        self.peer_fragment_size
    }

    /// Handles PMTU probing state machine (enqueue probes, process timeouts).
    pub fn handle_pmtu(&mut self, time: Instant) {
        if !self.config.use_pmtu_discovery {
            return;
        }

        // Timeout outstanding probe
        if let Some((size, _token, sent)) = self.pmtu_outstanding {
            let timeout = self.rto().max(std::time::Duration::from_millis(200));
            if time.duration_since(sent) > timeout {
                // consider it failed: reduce high bound
                if size > 0 {
                    self.pmtu_high = self.pmtu_high.min(size - 1);
                }
                self.pmtu_outstanding = None;
                self.pmtu_last_probe = time;
            }
            return;
        }

        // Check convergence
        if self.pmtu_high.saturating_sub(self.pmtu_low) <= self.config.pmtu_converge_threshold {
            self.peer_fragment_size = self.pmtu_low;
            return;
        }

        // Time to probe?
        let interval = std::time::Duration::from_millis(self.config.pmtu_interval_ms as u64);
        if time.duration_since(self.pmtu_last_probe) < interval {
            return;
        }

        // Next candidate: mid
        let mid = ((self.pmtu_low as u32 + self.pmtu_high as u32) / 2) as u16;
        let token: u32 = rand::random();
        let payload = bitwarp_core::shared::SharedBytes::from_vec(vec![0u8; mid as usize]);
        self.enqueue_command(bitwarp_protocol::command::ProtocolCommand::PMTUProbe {
            size: mid,
            token,
            payload,
        });
        self.pmtu_outstanding = Some((mid, token, time));
        self.pmtu_last_probe = time;
    }

    // ===== Window-based Flow Control =====

    /// Returns the current window size (in packets).
    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    /// Returns the amount of reliable data currently in transit (in bytes).
    pub fn reliable_data_in_transit(&self) -> u32 {
        self.reliable_data_in_transit
    }

    /// Sets the window size (for negotiation during handshake).
    pub fn set_window_size(&mut self, window_size: u32) {
        self.window_size =
            window_size.clamp(self.config.min_window_size, self.config.max_window_size);
    }

    /// Records reliable data being sent (adds to in-transit counter).
    pub fn record_reliable_data_sent(&mut self, data_size: u32) {
        self.reliable_data_in_transit = self.reliable_data_in_transit.saturating_add(data_size);
    }

    /// Records reliable data being acknowledged (removes from in-transit counter).
    pub fn record_reliable_data_acked(&mut self, data_size: u32) {
        self.reliable_data_in_transit = self.reliable_data_in_transit.saturating_sub(data_size);
    }

    /// Checks if we can send more data based on window-based flow control.
    /// Returns true if we have room in the window.
    pub fn can_send_reliable(&self) -> bool {
        if !self.config.use_window_flow_control {
            // Fall back to simple packet count limit
            return self.packets_in_flight() < self.config.max_packets_in_flight;
        }

        // Window-based: check if in-transit data is within window size
        // Approximate packet size for window calculation (MTU-based)
        let approx_packet_size = self.config.fragment_size as u32;
        let window_bytes = self.window_size * approx_packet_size;

        self.reliable_data_in_transit < window_bytes
    }

    /// Dynamically adjusts the window size based on network conditions.
    /// Called periodically to adapt to changing network conditions.
    pub fn adjust_window_size(&mut self) {
        if !self.config.use_window_flow_control {
            return;
        }

        let loss_rate = self.loss_rate();
        let rtt = self.rtt().as_millis() as u32;

        // Increase window if conditions are good (low loss, reasonable RTT)
        if loss_rate < 0.01 && rtt < 200 {
            // Less than 1% loss and RTT < 200ms
            self.window_size = (self.window_size + (self.window_size / 32).max(1))
                .min(self.config.max_window_size);
        }
        // Decrease window if conditions are poor (high loss or high RTT)
        else if loss_rate > 0.05 || rtt > 500 {
            // More than 5% loss or RTT > 500ms
            self.window_size = (self.window_size - (self.window_size / 16).max(1))
                .max(self.config.min_window_size);
        }
    }

    // ===== Bandwidth Throttling =====

    /// Updates bandwidth tracking window, resetting counters if window expired.
    /// Returns true if the window was reset.
    pub fn update_bandwidth_window(&mut self, time: Instant) -> bool {
        const BANDWIDTH_WINDOW: Duration = Duration::from_secs(1);

        if time.duration_since(self.bandwidth_window_start) >= BANDWIDTH_WINDOW {
            self.bytes_sent_this_window = 0;
            self.bytes_received_this_window = 0;
            self.bandwidth_window_start = time;
            true
        } else {
            false
        }
    }

    /// Records bytes sent for bandwidth tracking.
    pub fn record_bytes_sent(&mut self, bytes: u32) {
        self.bytes_sent_this_window = self.bytes_sent_this_window.saturating_add(bytes);
    }

    /// Records bytes received for bandwidth tracking.
    pub fn record_bytes_received(&mut self, bytes: u32) {
        self.bytes_received_this_window = self.bytes_received_this_window.saturating_add(bytes);
    }

    /// Checks if we can send based on outgoing bandwidth limit.
    /// Returns true if we're under the limit or if throttling is disabled (limit == 0).
    pub fn can_send_within_bandwidth(&self) -> bool {
        let limit = self.config.outgoing_bandwidth_limit;
        if limit == 0 {
            return true; // Unlimited
        }
        self.bytes_sent_this_window < limit
    }

    /// Returns current bandwidth utilization (0.0 to 1.0+).
    /// Returns 0.0 if bandwidth limiting is disabled.
    pub fn bandwidth_utilization(&self) -> f32 {
        let limit = self.config.outgoing_bandwidth_limit;
        if limit == 0 {
            return 0.0; // Unlimited, no utilization tracking
        }
        self.bytes_sent_this_window as f32 / limit as f32
    }

    /// Checks if we can receive based on incoming bandwidth limit.
    /// Returns true if we're under the limit or if throttling is disabled (limit == 0).
    pub fn can_receive_within_bandwidth(&self) -> bool {
        let limit = self.config.incoming_bandwidth_limit;
        if limit == 0 {
            return true; // Unlimited
        }
        self.bytes_received_this_window < limit
    }

    /// Returns current incoming bandwidth utilization (0.0 to 1.0+).
    /// Returns 0.0 if bandwidth limiting is disabled.
    pub fn incoming_bandwidth_utilization(&self) -> f32 {
        let limit = self.config.incoming_bandwidth_limit;
        if limit == 0 {
            return 0.0; // Unlimited, no utilization tracking
        }
        self.bytes_received_this_window as f32 / limit as f32
    }

    // ===== Unsequenced Packet Handling =====

    /// Gets the next outgoing unsequenced group ID and increments the counter.
    pub fn next_unsequenced_group(&mut self) -> u16 {
        let group = self.outgoing_unsequenced_group;
        self.outgoing_unsequenced_group = self.outgoing_unsequenced_group.wrapping_add(1);
        group
    }

    /// Checks if an incoming unsequenced group is a duplicate or within the window.
    /// Returns true if this is a duplicate (already received), false if new.
    pub fn is_unsequenced_duplicate(&self, group: u16) -> bool {
        // Check if window is completely empty (no packets received yet)
        let window_empty = self.unsequenced_window.iter().all(|&w| w == 0);
        if window_empty {
            // First packet(s), not a duplicate
            return false;
        }

        // Calculate offset from window base
        let offset = group.wrapping_sub(self.incoming_unsequenced_group);

        // If offset is within window (0-1023), check the window
        if offset < 1024 {
            // Check if this bit is set in the window
            let word_index = (offset / 32) as usize;
            let bit_index = offset % 32;

            if word_index < 32 {
                return (self.unsequenced_window[word_index] & (1 << bit_index)) != 0;
            }
        }

        // Outside the forward window - check if it's old (behind the window)
        // Using wrapping arithmetic: if offset > 32768, it's actually a negative offset
        // meaning it's behind the current window base (old packet)
        if offset > 32768 {
            return true; // Old packet, treat as duplicate
        }

        // New packet ahead of window, not a duplicate
        false
    }

    /// Marks an incoming unsequenced group as received in the window.
    /// Advances the window base if necessary.
    pub fn mark_unsequenced_received(&mut self, group: u16) {
        // Calculate offset from window base
        let offset = group.wrapping_sub(self.incoming_unsequenced_group);

        // If the group is far ahead (and not wrapping backwards), we need to advance the window base
        if offset >= 1024 && offset <= 32768 {
            // Calculate how much to advance
            let advance = offset.saturating_sub(512); // Keep window centered on new packets

            // Shift window bits and clear old ones
            let word_shift = (advance / 32) as usize;
            let bit_shift = advance % 32;

            if word_shift > 0 {
                // Shift entire words
                if word_shift >= 32 {
                    // Complete window reset
                    self.unsequenced_window = [0; 32];
                } else {
                    // Partial shift
                    for i in 0..(32 - word_shift) {
                        self.unsequenced_window[i] = self.unsequenced_window[i + word_shift];
                    }
                    for i in (32 - word_shift)..32 {
                        self.unsequenced_window[i] = 0;
                    }
                }
            }

            if bit_shift > 0 && word_shift < 32 {
                // Shift bits within words
                for i in 0..31 {
                    self.unsequenced_window[i] = (self.unsequenced_window[i] >> bit_shift)
                        | (self.unsequenced_window[i + 1] << (32 - bit_shift));
                }
                self.unsequenced_window[31] >>= bit_shift;
            }

            // Advance window base
            self.incoming_unsequenced_group = self.incoming_unsequenced_group.wrapping_add(advance);
        }

        // Now mark the bit for this group
        let final_offset = group.wrapping_sub(self.incoming_unsequenced_group);
        if final_offset < 1024 {
            let word_index = (final_offset / 32) as usize;
            let bit_index = final_offset % 32;
            if word_index < 32 {
                self.unsequenced_window[word_index] |= 1 << bit_index;
            }
        }
    }

    /// Cleans up stale fragment buffers that haven't been completed within the timeout period.
    /// This prevents memory leaks from incomplete fragments (e.g., due to packet loss or malicious behavior).
    ///
    /// Call this periodically (e.g., once per second) to prevent accumulation of stale buffers.
    /// Default timeout is 5 seconds after the first fragment is received.
    pub fn cleanup_stale_fragments(&mut self, time: Instant) {
        const FRAGMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        // Collect sequences of stale buffers
        let stale_sequences: Vec<u16> = self
            .command_fragments
            .iter()
            .filter_map(|(seq, buffer)| {
                if time.duration_since(buffer.created_at) > FRAGMENT_TIMEOUT {
                    Some(*seq)
                } else {
                    None
                }
            })
            .collect();

        // Remove stale buffers and log
        if !stale_sequences.is_empty() {
            tracing::warn!(
                "Cleaning up {} stale fragment buffer(s) that timed out after {:?}",
                stale_sequences.len(),
                FRAGMENT_TIMEOUT
            );
            for seq in stale_sequences {
                self.command_fragments.remove(&seq);
            }
        }
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
        let mut final_data = CommandEncoder::compress_with_buffer(
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
            CommandEncoder::append_checksum_in_place(&mut final_data);
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
        let mut aggregated_len = 1; // start with command count byte

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
                let total_with_overhead = static_overhead + 1 + cmd_size;

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
        let mut final_data = bitwarp_protocol::command_codec::CommandEncoder::compress_with_buffer(
            &scratch,
            self.config.compression,
            self.config.compression_threshold,
            compression_buffer,
        )?;
        self.tx_pool.deallocate(scratch);

        // Record packet and bytes sent
        self.record_packet_sent();

        if self.config.use_checksums {
            bitwarp_protocol::command_codec::CommandEncoder::append_checksum_in_place(&mut final_data);
        }

        // Track bytes sent (full encoded size after compression/checksum)
        self.record_data_sent(final_data.len());

        // Sanity guard: ensure we did not exceed max_size
        if final_data.len() > max_size {
            tracing::error!(
                "Encoded packet exceeded max_size after compression: {} bytes > {} bytes max. Selected {} commands, pre-compression size was {} bytes. Commands will remain queued.",
                final_data.len(),
                max_size,
                selected_count,
                aggregated_len
            );
            // Avoid producing oversize datagrams; keep commands queued for next attempt
            return Ok(None);
        }

        Ok(Some(final_data))
    }

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
                        window_size: self.window_size, // Send our window size
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
                        self.set_window_size((*window_size).min(self.window_size));
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
                self.enqueue_command(ProtocolCommand::PMTUReply { size: *size, token: *token });
                Ok(IncomingPackets::zero())
            }
            ProtocolCommand::PMTUReply { size, token } => {
                // Validate outstanding probe
                if let Some((_pending_size, pending_token, _sent)) = self.pmtu_outstanding {
                    if pending_token == *token {
                        // Success: raise low bound and update effective fragment size
                        self.pmtu_low = self.pmtu_low.max(*size);
                        self.peer_fragment_size = self.pmtu_low;
                        self.pmtu_outstanding = None;
                        self.pmtu_last_probe = time;
                        tracing::debug!("PMTU success: token={}, size={}", token, size);
                    }
                }
                Ok(IncomingPackets::zero())
            }
        }
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.remote_address.ip(), self.remote_address.port())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitwarp_core::config::{CompressionAlgorithm, Config};
    use bitwarp_protocol::{
        command::ProtocolCommand,
        packet::{DeliveryGuarantee, OrderingGuarantee},
    };

    use super::Peer;

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
    fn test_bandwidth_unlimited_by_default() {
        let config = Config::default();
        let mut peer = Peer::new(get_fake_addr(), &config, Instant::now());

        // Default config should have unlimited bandwidth
        assert_eq!(config.outgoing_bandwidth_limit, 0);
        assert_eq!(config.incoming_bandwidth_limit, 0);

        // Should always be able to send
        assert!(peer.can_send_within_bandwidth());

        // Even after recording lots of bytes
        peer.record_bytes_sent(1_000_000);
        assert!(peer.can_send_within_bandwidth());

        // Utilization should be 0.0 for unlimited
        assert_eq!(peer.bandwidth_utilization(), 0.0);
    }

    #[test]
    fn test_bandwidth_throttling_when_limited() {
        let mut config = Config::default();
        config.outgoing_bandwidth_limit = 1000; // 1000 bytes/sec

        let time = Instant::now();
        let mut peer = Peer::new(get_fake_addr(), &config, time);

        // Should be able to send initially
        assert!(peer.can_send_within_bandwidth());
        assert_eq!(peer.bandwidth_utilization(), 0.0);

        // Send 500 bytes (within limit)
        peer.record_bytes_sent(500);
        assert!(peer.can_send_within_bandwidth());
        assert_eq!(peer.bandwidth_utilization(), 0.5);

        // Send another 500 bytes (at limit)
        peer.record_bytes_sent(500);
        assert!(!peer.can_send_within_bandwidth()); // Now at limit
        assert_eq!(peer.bandwidth_utilization(), 1.0);

        // Try to send more (over limit)
        peer.record_bytes_sent(100);
        assert!(!peer.can_send_within_bandwidth());
        assert!(peer.bandwidth_utilization() > 1.0);

        // After window reset, should be able to send again
        let time_plus_1sec = time + Duration::from_secs(1);
        peer.update_bandwidth_window(time_plus_1sec);
        assert!(peer.can_send_within_bandwidth());
        assert_eq!(peer.bandwidth_utilization(), 0.0);
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

    // remaining tests omitted for brevity; original logic retained

    fn create_virtual_connection() -> Peer {
        Peer::new(get_fake_addr(), &Config::default(), Instant::now())
    }

    fn get_fake_addr() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
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
        use bitwarp_core::config::CompressionAlgorithm;

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
        use bitwarp_core::config::CompressionAlgorithm;

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
        assert!(peer.pmtu_outstanding.is_some());

        // Simulate successful reply (this would update pmtu_low)
        if let Some((size, token, _)) = peer.pmtu_outstanding {
            let reply = ProtocolCommand::PMTUReply { size, token };
            let _ = peer.process_command(&reply, time).unwrap();

            // After successful reply, pmtu_low should be updated
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

        let high_before = peer.pmtu_high;

        // Advance time beyond RTO to trigger timeout (RTO is typically 200ms+)
        time = time + std::time::Duration::from_secs(2);

        // Handle PMTU again - should timeout the outstanding probe
        peer.handle_pmtu(time);

        // After timeout, outstanding should be cleared and high bound reduced
        assert!(peer.pmtu_outstanding.is_none());
        assert!(peer.pmtu_high < high_before);
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
