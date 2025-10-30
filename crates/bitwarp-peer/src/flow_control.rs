//! Window-based flow control for reliable data transmission.
//!
//! This module implements a sliding window flow control mechanism that prevents overwhelming
//! the receiver with too much data at once. The window size represents the maximum amount of
//! unacknowledged data (in packets) that can be in flight at any given time.
//!
//! # Flow Control Strategy
//!
//! The flow control system uses a dynamic window that adapts to network conditions:
//!
//! - **Window Size**: Measured in packets, controls how much data can be sent without acknowledgment
//! - **In-Transit Tracking**: Monitors bytes of reliable data waiting for ACK
//! - **Dynamic Adjustment**: Window grows during good conditions (low loss, low RTT) and shrinks
//!   during poor conditions (high loss, high RTT)
//!
//! # Window Adjustment Algorithm
//!
//! The window size adjusts based on:
//! - Packet loss rate (lower is better)
//! - Round-trip time (RTT) (lower is better)
//!
//! **Increase conditions**: Loss rate < 1% and RTT < 200ms
//! - Window grows by ~3% (1/32) per adjustment
//!
//! **Decrease conditions**: Loss rate > 5% or RTT > 500ms
//! - Window shrinks by ~6% (1/16) per adjustment
//!
//! # Example
//!
//! ```
//! use bitwarp_peer::flow_control::FlowControl;
//! use bitwarp_core::config::Config;
//!
//! let config = Config::default();
//! let mut flow_control = FlowControl::new(&config);
//!
//! // Check if we can send data
//! if flow_control.can_send_reliable(&config, 0) {
//!     // Send data and record it
//!     flow_control.record_reliable_data_sent(1024);
//! }
//!
//! // Later, when data is acknowledged
//! flow_control.record_reliable_data_acked(1024);
//!
//! // Periodically adjust window based on network conditions
//! let loss_rate = 0.02; // 2% loss
//! let rtt_ms = 150;
//! flow_control.adjust_window_size(&config, loss_rate, rtt_ms);
//! ```

use bitwarp_core::config::Config;

/// Window-based flow control state for managing reliable data transmission.
///
/// This struct encapsulates the state needed for sliding window flow control,
/// including the current window size and tracking of in-transit reliable data.
#[derive(Debug, Clone)]
pub struct FlowControl {
    /// Current window size for flow control (in packets)
    window_size: u32,
    /// Reliable data currently in transit (waiting for ACK), in bytes
    reliable_data_in_transit: u32,
}

impl FlowControl {
    /// Creates a new flow control instance with configuration defaults.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing initial window size and limits
    ///
    /// # Example
    ///
    /// ```
    /// use bitwarp_peer::flow_control::FlowControl;
    /// use bitwarp_core::config::Config;
    ///
    /// let config = Config::default();
    /// let flow_control = FlowControl::new(&config);
    /// ```
    pub fn new(config: &Config) -> Self {
        Self {
            window_size: config.initial_window_size,
            reliable_data_in_transit: 0,
        }
    }

    /// Returns the current window size (in packets).
    ///
    /// The window size represents the maximum number of packets that can be
    /// in flight (unacknowledged) at any given time.
    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    /// Returns the amount of reliable data currently in transit (in bytes).
    ///
    /// This tracks the total bytes of reliable data that have been sent but
    /// not yet acknowledged by the receiver.
    pub fn reliable_data_in_transit(&self) -> u32 {
        self.reliable_data_in_transit
    }

    /// Sets the window size (for negotiation during handshake).
    ///
    /// The provided window size will be clamped to the configured min/max bounds.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing min and max window size limits
    /// * `window_size` - Desired window size (will be clamped to min/max)
    pub fn set_window_size(&mut self, config: &Config, window_size: u32) {
        self.window_size =
            window_size.clamp(config.min_window_size, config.max_window_size);
    }

    /// Records reliable data being sent (adds to in-transit counter).
    ///
    /// Call this method whenever reliable data is transmitted to track how much
    /// data is waiting for acknowledgment.
    ///
    /// # Arguments
    ///
    /// * `data_size` - Size of the data being sent, in bytes
    pub fn record_reliable_data_sent(&mut self, data_size: u32) {
        self.reliable_data_in_transit = self.reliable_data_in_transit.saturating_add(data_size);
    }

    /// Records reliable data being acknowledged (removes from in-transit counter).
    ///
    /// Call this method when an acknowledgment is received to reduce the amount
    /// of tracked in-transit data.
    ///
    /// # Arguments
    ///
    /// * `data_size` - Size of the data being acknowledged, in bytes
    pub fn record_reliable_data_acked(&mut self, data_size: u32) {
        self.reliable_data_in_transit = self.reliable_data_in_transit.saturating_sub(data_size);
    }

    /// Checks if we can send more data based on window-based flow control.
    ///
    /// Returns `true` if we have room in the window, `false` if the window is full.
    /// When window flow control is disabled, this falls back to checking a simple
    /// packet count limit.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing window control settings
    /// * `packets_in_flight` - Current number of unacknowledged packets (used when
    ///   window flow control is disabled)
    ///
    /// # Returns
    ///
    /// `true` if more reliable data can be sent, `false` if the window is full
    pub fn can_send_reliable(&self, config: &Config, packets_in_flight: u16) -> bool {
        if !config.use_window_flow_control {
            // Fall back to simple packet count limit
            return packets_in_flight < config.max_packets_in_flight;
        }

        // Window-based: check if in-transit data is within window size
        // Approximate packet size for window calculation (MTU-based)
        let approx_packet_size = config.fragment_size as u32;
        let window_bytes = self.window_size * approx_packet_size;

        self.reliable_data_in_transit < window_bytes
    }

    /// Dynamically adjusts the window size based on network conditions.
    ///
    /// This should be called periodically to adapt the window size to changing
    /// network conditions. The window grows during good conditions and shrinks
    /// during poor conditions.
    ///
    /// # Adjustment Logic
    ///
    /// - **Increase**: When loss rate < 1% and RTT < 200ms, grow window by ~3% (1/32)
    /// - **Decrease**: When loss rate > 5% or RTT > 500ms, shrink window by ~6% (1/16)
    /// - **No change**: Otherwise maintain current window size
    ///
    /// The window size is always clamped to the configured min/max bounds.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration containing window control settings and limits
    /// * `loss_rate` - Current packet loss rate (0.0 to 1.0)
    /// * `rtt_ms` - Current round-trip time in milliseconds
    pub fn adjust_window_size(&mut self, config: &Config, loss_rate: f32, rtt_ms: u32) {
        if !config.use_window_flow_control {
            return;
        }

        // Increase window if conditions are good (low loss, reasonable RTT)
        if loss_rate < 0.01 && rtt_ms < 200 {
            // Less than 1% loss and RTT < 200ms
            self.window_size = (self.window_size + (self.window_size / 32).max(1))
                .min(config.max_window_size);
        }
        // Decrease window if conditions are poor (high loss or high RTT)
        else if loss_rate > 0.05 || rtt_ms > 500 {
            // More than 5% loss or RTT > 500ms
            self.window_size = (self.window_size - (self.window_size / 16).max(1))
                .max(config.min_window_size);
        }
    }
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::new(&Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_flow_control_enabled() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 100;
        let flow_control = FlowControl::new(&config);

        assert_eq!(flow_control.window_size(), 100);
        assert_eq!(flow_control.reliable_data_in_transit(), 0);
        assert!(flow_control.can_send_reliable(&config, 0));
    }

    #[test]
    fn test_window_flow_control_tracks_in_transit_data() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 10; // Small window
        config.fragment_size = 1024;
        let mut flow_control = FlowControl::new(&config);

        // Initially can send
        assert!(flow_control.can_send_reliable(&config, 0));

        // Record sending 5KB of data
        flow_control.record_reliable_data_sent(5 * 1024);
        assert_eq!(flow_control.reliable_data_in_transit(), 5 * 1024);

        // Can still send (5KB < 10 packets * 1024 bytes = 10KB window)
        assert!(flow_control.can_send_reliable(&config, 0));

        // Record sending another 6KB (total 11KB, exceeds 10KB window)
        flow_control.record_reliable_data_sent(6 * 1024);
        assert_eq!(flow_control.reliable_data_in_transit(), 11 * 1024);

        // Now cannot send (exceeds window)
        assert!(!flow_control.can_send_reliable(&config, 0));

        // ACK some data (3KB)
        flow_control.record_reliable_data_acked(3 * 1024);
        assert_eq!(flow_control.reliable_data_in_transit(), 8 * 1024);

        // Now can send again (8KB < 10KB window)
        assert!(flow_control.can_send_reliable(&config, 0));
    }

    #[test]
    fn test_window_size_negotiation() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 1000;
        config.min_window_size = 64;
        config.max_window_size = 2048;
        let mut flow_control = FlowControl::new(&config);

        assert_eq!(flow_control.window_size(), 1000);

        // Set to a value within range
        flow_control.set_window_size(&config, 512);
        assert_eq!(flow_control.window_size(), 512);

        // Set to value above max - should clamp
        flow_control.set_window_size(&config, 3000);
        assert_eq!(flow_control.window_size(), 2048);

        // Set to value below min - should clamp
        flow_control.set_window_size(&config, 32);
        assert_eq!(flow_control.window_size(), 64);
    }

    #[test]
    fn test_window_adjustment_increases_on_good_conditions() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 100;
        config.max_window_size = 200;
        let mut flow_control = FlowControl::new(&config);

        let initial_window = flow_control.window_size();

        // Simulate good conditions (no loss, low RTT)
        let loss_rate = 0.0;
        let rtt_ms = 50;

        flow_control.adjust_window_size(&config, loss_rate, rtt_ms);

        // Window should increase
        assert!(flow_control.window_size() > initial_window);
    }

    #[test]
    fn test_window_adjustment_decreases_on_poor_conditions() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 200;
        config.min_window_size = 64;
        let mut flow_control = FlowControl::new(&config);

        let initial_window = flow_control.window_size();

        // Simulate poor conditions (high packet loss)
        let loss_rate = 0.10; // 10% loss
        let rtt_ms = 100;

        flow_control.adjust_window_size(&config, loss_rate, rtt_ms);

        // Window should decrease
        assert!(flow_control.window_size() < initial_window);
    }

    #[test]
    fn test_window_flow_control_respects_min_max() {
        let mut config = Config::default();
        config.use_window_flow_control = true;
        config.initial_window_size = 100;
        config.min_window_size = 64;
        config.max_window_size = 128;
        let mut flow_control = FlowControl::new(&config);

        // Repeatedly adjust upward
        for _ in 0..50 {
            flow_control.adjust_window_size(&config, 0.0, 50);
        }

        // Should not exceed max
        assert!(flow_control.window_size() <= 128);

        // Simulate sustained poor conditions
        for _ in 0..50 {
            flow_control.adjust_window_size(&config, 0.10, 600);
        }

        // Should not go below min
        assert!(flow_control.window_size() >= 64);
    }

    #[test]
    fn test_window_flow_control_disabled_uses_packet_limit() {
        let mut config = Config::default();
        config.use_window_flow_control = false; // Disabled
        config.max_packets_in_flight = 10;
        let flow_control = FlowControl::new(&config);

        // When disabled, should use packets_in_flight limit
        // Initially 0 packets in flight, so can send
        assert!(flow_control.can_send_reliable(&config, 0));

        // With 10 packets in flight (at limit), should not be able to send
        assert!(!flow_control.can_send_reliable(&config, 10));

        // With 9 packets in flight (under limit), should be able to send
        assert!(flow_control.can_send_reliable(&config, 9));
    }

    #[test]
    fn test_record_data_sent_saturating() {
        let config = Config::default();
        let mut flow_control = FlowControl::new(&config);

        // Test that adding doesn't overflow
        flow_control.record_reliable_data_sent(u32::MAX);
        assert_eq!(flow_control.reliable_data_in_transit(), u32::MAX);

        flow_control.record_reliable_data_sent(1000);
        assert_eq!(flow_control.reliable_data_in_transit(), u32::MAX); // Should saturate
    }

    #[test]
    fn test_record_data_acked_saturating() {
        let config = Config::default();
        let mut flow_control = FlowControl::new(&config);

        // Test that subtracting doesn't underflow
        flow_control.record_reliable_data_sent(1000);
        flow_control.record_reliable_data_acked(2000);
        assert_eq!(flow_control.reliable_data_in_transit(), 0); // Should saturate at 0
    }

    #[test]
    fn test_default_initialization() {
        let flow_control = FlowControl::default();
        let default_config = Config::default();

        assert_eq!(flow_control.window_size(), default_config.initial_window_size);
        assert_eq!(flow_control.reliable_data_in_transit(), 0);
    }
}
