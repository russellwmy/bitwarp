use std::{default::Default, time::Duration};

use crate::constants::{DEFAULT_MTU, FRAGMENT_SIZE_DEFAULT, MAX_FRAGMENTS_DEFAULT};

/// Compression algorithm to use for packet data.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// Zlib compression (balanced speed/ratio)
    Zlib,
    /// LZ4 compression (fast, lower ratio)
    Lz4,
}

#[derive(Clone, Debug)]
/// Configuration options to tune protocol and runtime behavior.
pub struct Config {
    /// Make the underlying UDP socket block when true, otherwise non-blocking.
    pub blocking_mode: bool,
    /// Max idle time before considering a connection disconnected.
    pub idle_connection_timeout: Duration,
    /// Interval for heartbeat packets if no data is sent. None disables heartbeats.
    pub heartbeat_interval: Option<Duration>,
    /// Max total packet size in bytes (including fragmentation).
    pub max_packet_size: usize,
    /// Max number of fragments per packet (u8).
    pub max_fragments: u8,
    /// Max size of each fragment.
    pub fragment_size: u16,
    /// Size of the fragment reassembly buffer.
    pub fragment_reassembly_buffer_size: u16,
    /// Max receive buffer size in bytes.
    pub receive_buffer_max_size: usize,
    /// Smoothing factor (0..1) for RTT measurements.
    pub rtt_smoothing_factor: f32,
    /// Max acceptable RTT in milliseconds before considering a problem.
    pub rtt_max_value: u16,
    /// Size of the event buffer for socket events.
    pub socket_event_buffer_size: usize,
    /// How long to block when polling socket events.
    pub socket_polling_timeout: Option<Duration>,
    /// Max reliable packets in flight before dropping a connection.
    pub max_packets_in_flight: u16,
    /// Max number of unestablished connections to prevent DoS.
    pub max_unestablished_connections: u16,
    /// Number of channels per peer connection (1-255).
    pub channel_count: u8,
    /// Incoming bandwidth limit in bytes/sec (0 = unlimited).
    pub incoming_bandwidth_limit: u32,
    /// Outgoing bandwidth limit in bytes/sec (0 = unlimited).
    pub outgoing_bandwidth_limit: u32,
    /// Enable CRC32 checksums for data integrity verification (default: false).
    pub use_checksums: bool,
    /// Compression algorithm to use (default: None).
    pub compression: CompressionAlgorithm,
    /// Minimum packet size to compress in bytes (default: 128). Packets smaller than this won't be compressed.
    pub compression_threshold: usize,
    /// Use formal 3-way connection handshake for enhanced security (default: false).
    /// When enabled, uses Connect->VerifyConnect->ACK handshake with session IDs.
    pub use_connection_handshake: bool,
    /// Maximum buffered packet data per peer in bytes (0 = unlimited).
    /// Prevents memory exhaustion from malicious/buggy clients.
    pub max_waiting_data: usize,
    /// Enable advanced packet throttling with acceleration/deceleration.
    /// When enabled, uses dynamic throttle adjustment based on packet loss.
    pub use_advanced_throttling: bool,
    /// Throttle scale (maximum throttle value, typically 32).
    pub throttle_scale: u32,
    /// Throttle acceleration (rate of improvement when conditions are good).
    pub throttle_acceleration: u32,
    /// Throttle deceleration (rate of degradation when packet loss occurs).
    pub throttle_deceleration: u32,
    /// Interval for throttle updates in milliseconds.
    pub throttle_interval: u32,
    /// Enable dynamic window-based flow control.
    /// When enabled, uses adaptive window sizing based on network conditions.
    pub use_window_flow_control: bool,
    /// Initial window size for flow control (in packets).
    pub initial_window_size: u32,
    /// Minimum window size (in packets).
    pub min_window_size: u32,
    /// Maximum window size (in packets).
    pub max_window_size: u32,
    /// Maximum number of connections allowed from the same IP address (0 = unlimited).
    /// Useful for NAT scenarios where multiple clients share the same public IP.
    pub max_duplicate_peers: u16,
    /// Socket receive buffer size in bytes (None = use system default).
    /// Corresponds to SO_RCVBUF socket option.
    pub socket_recv_buffer_size: Option<usize>,
    /// Socket send buffer size in bytes (None = use system default).
    /// Corresponds to SO_SNDBUF socket option.
    pub socket_send_buffer_size: Option<usize>,
    /// Time-to-live for outgoing packets (None = use system default).
    /// Corresponds to IP_TTL socket option.
    pub socket_ttl: Option<u32>,
    /// Enable broadcast mode (default: false).
    /// Corresponds to SO_BROADCAST socket option.
    pub socket_broadcast: bool,
    /// Enable application-level PMTU discovery (default: false).
    /// Sends probe commands with increasing sizes and tunes per-peer fragment size.
    pub use_pmtu_discovery: bool,
    /// Minimum PMTU probe size (bytes).
    pub pmtu_min: u16,
    /// Maximum PMTU probe size (bytes).
    pub pmtu_max: u16,
    /// Interval between PMTU probes in milliseconds.
    pub pmtu_interval_ms: u32,
    /// Threshold (bytes) at which PMTU search is considered converged.
    pub pmtu_converge_threshold: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            blocking_mode: false,
            idle_connection_timeout: Duration::from_secs(5),
            heartbeat_interval: None,
            max_packet_size: (MAX_FRAGMENTS_DEFAULT * FRAGMENT_SIZE_DEFAULT) as usize,
            max_fragments: MAX_FRAGMENTS_DEFAULT as u8,
            fragment_size: FRAGMENT_SIZE_DEFAULT,
            fragment_reassembly_buffer_size: 64,
            receive_buffer_max_size: DEFAULT_MTU as usize,
            rtt_smoothing_factor: 0.10,
            rtt_max_value: 250,
            socket_event_buffer_size: 1024,
            socket_polling_timeout: Some(Duration::from_millis(1)),
            max_packets_in_flight: 512,
            max_unestablished_connections: 50,
            channel_count: 1, // Default to single channel like most simple uses
            incoming_bandwidth_limit: 0, // Unlimited
            outgoing_bandwidth_limit: 0, // Unlimited
            use_checksums: false, // Disabled by default for backward compatibility
            compression: CompressionAlgorithm::None, // Disabled by default
            compression_threshold: 128, // Don't compress packets smaller than 128 bytes
            use_connection_handshake: false, // Disabled by default for backward compatibility
            max_waiting_data: 32 * 1024 * 1024, // 32 MB - prevents memory exhaustion
            use_advanced_throttling: false, // Disabled by default for backward compatibility
            throttle_scale: 32,      // Default scale
            throttle_acceleration: 2, // Default acceleration
            throttle_deceleration: 2, // Default deceleration
            throttle_interval: 5000,  // 5 seconds (default)
            use_window_flow_control: false, // Disabled by default for backward compatibility
            initial_window_size: 512,  // Start with 512 packets (matches max_packets_in_flight)
            min_window_size: 64,       // Minimum 64 packets
            max_window_size: 4096,     // Maximum 4096 packets
            max_duplicate_peers: 0,    // Unlimited by default
            socket_recv_buffer_size: None,  // Use system default
            socket_send_buffer_size: None,  // Use system default
            socket_ttl: None,  // Use system default
            socket_broadcast: false,  // Disabled by default
            use_pmtu_discovery: true,
            pmtu_min: 576,
            pmtu_max: 1400,
            pmtu_interval_ms: 5000,
            pmtu_converge_threshold: 64,
        }
    }
}
