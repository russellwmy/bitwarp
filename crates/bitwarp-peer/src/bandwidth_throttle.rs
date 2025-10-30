//! Bandwidth throttling and utilization tracking.
//!
//! This module provides functionality for monitoring and limiting network bandwidth usage.
//! It tracks bytes sent and received within sliding time windows and provides methods to
//! check whether operations can proceed within configured bandwidth limits.
//!
//! # Bandwidth Limiting
//!
//! Bandwidth limits are enforced per connection on a per-second basis:
//! - **Outgoing bandwidth**: Limits the number of bytes sent per second
//! - **Incoming bandwidth**: Limits the number of bytes received per second
//!
//! A limit of `0` means unlimited bandwidth.
//!
//! # Utilization Tracking
//!
//! The module calculates bandwidth utilization as a ratio of bytes transferred to the
//! configured limit. A utilization of:
//! - `0.0` = No bandwidth used (or unlimited)
//! - `0.5` = 50% of limit used
//! - `1.0` = At the limit
//! - `>1.0` = Over the limit (throttling should occur)

use std::time::{Duration, Instant};

/// Duration of the bandwidth tracking window (1 second).
const BANDWIDTH_WINDOW: Duration = Duration::from_secs(1);

/// Tracks bandwidth usage and enforces bandwidth limits.
///
/// This structure maintains a sliding window of bandwidth consumption,
/// resetting counters every second to provide accurate per-second limiting.
pub struct BandwidthThrottle {
    /// Bytes sent in the current bandwidth window
    bytes_sent_this_window: u32,
    /// Bytes received in the current bandwidth window
    bytes_received_this_window: u32,
    /// Start time of the current bandwidth tracking window
    bandwidth_window_start: Instant,
    /// Outgoing bandwidth limit in bytes per second (0 = unlimited)
    outgoing_bandwidth_limit: u32,
    /// Incoming bandwidth limit in bytes per second (0 = unlimited)
    incoming_bandwidth_limit: u32,
}

impl BandwidthThrottle {
    /// Creates a new bandwidth throttle with the specified limits.
    ///
    /// # Arguments
    ///
    /// * `outgoing_limit` - Maximum bytes per second for outgoing traffic (0 = unlimited)
    /// * `incoming_limit` - Maximum bytes per second for incoming traffic (0 = unlimited)
    /// * `start_time` - Initial timestamp for the bandwidth window
    pub fn new(outgoing_limit: u32, incoming_limit: u32, start_time: Instant) -> Self {
        Self {
            bytes_sent_this_window: 0,
            bytes_received_this_window: 0,
            bandwidth_window_start: start_time,
            outgoing_bandwidth_limit: outgoing_limit,
            incoming_bandwidth_limit: incoming_limit,
        }
    }

    /// Updates bandwidth tracking window, resetting counters if the window has expired.
    ///
    /// This should be called periodically (e.g., before each send/receive operation)
    /// to ensure accurate bandwidth tracking.
    ///
    /// # Returns
    ///
    /// Returns `true` if the window was reset, `false` otherwise.
    pub fn update_bandwidth_window(&mut self, time: Instant) -> bool {
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
    ///
    /// This increments the send counter using saturating addition to prevent overflow.
    pub fn record_bytes_sent(&mut self, bytes: u32) {
        self.bytes_sent_this_window = self.bytes_sent_this_window.saturating_add(bytes);
    }

    /// Records bytes received for bandwidth tracking.
    ///
    /// This increments the receive counter using saturating addition to prevent overflow.
    pub fn record_bytes_received(&mut self, bytes: u32) {
        self.bytes_received_this_window = self.bytes_received_this_window.saturating_add(bytes);
    }

    /// Checks if we can send based on the outgoing bandwidth limit.
    ///
    /// # Returns
    ///
    /// Returns `true` if we're under the limit or if throttling is disabled (limit == 0).
    pub fn can_send_within_bandwidth(&self) -> bool {
        if self.outgoing_bandwidth_limit == 0 {
            return true; // Unlimited
        }
        self.bytes_sent_this_window < self.outgoing_bandwidth_limit
    }

    /// Returns current outgoing bandwidth utilization (0.0 to 1.0+).
    ///
    /// # Returns
    ///
    /// - `0.0` if bandwidth limiting is disabled
    /// - `0.5` if at 50% of the limit
    /// - `1.0` if at the limit
    /// - `>1.0` if over the limit
    pub fn bandwidth_utilization(&self) -> f32 {
        if self.outgoing_bandwidth_limit == 0 {
            return 0.0; // Unlimited, no utilization tracking
        }
        self.bytes_sent_this_window as f32 / self.outgoing_bandwidth_limit as f32
    }

    /// Checks if we can receive based on the incoming bandwidth limit.
    ///
    /// # Returns
    ///
    /// Returns `true` if we're under the limit or if throttling is disabled (limit == 0).
    pub fn can_receive_within_bandwidth(&self) -> bool {
        if self.incoming_bandwidth_limit == 0 {
            return true; // Unlimited
        }
        self.bytes_received_this_window < self.incoming_bandwidth_limit
    }

    /// Returns current incoming bandwidth utilization (0.0 to 1.0+).
    ///
    /// # Returns
    ///
    /// - `0.0` if bandwidth limiting is disabled
    /// - `0.5` if at 50% of the limit
    /// - `1.0` if at the limit
    /// - `>1.0` if over the limit
    pub fn incoming_bandwidth_utilization(&self) -> f32 {
        if self.incoming_bandwidth_limit == 0 {
            return 0.0; // Unlimited, no utilization tracking
        }
        self.bytes_received_this_window as f32 / self.incoming_bandwidth_limit as f32
    }

    /// Updates the outgoing bandwidth limit.
    ///
    /// # Arguments
    ///
    /// * `limit` - New outgoing bandwidth limit in bytes per second (0 = unlimited)
    pub fn set_outgoing_bandwidth_limit(&mut self, limit: u32) {
        self.outgoing_bandwidth_limit = limit;
    }

    /// Updates the incoming bandwidth limit.
    ///
    /// # Arguments
    ///
    /// * `limit` - New incoming bandwidth limit in bytes per second (0 = unlimited)
    pub fn set_incoming_bandwidth_limit(&mut self, limit: u32) {
        self.incoming_bandwidth_limit = limit;
    }

    /// Returns the current outgoing bandwidth limit.
    pub fn outgoing_bandwidth_limit(&self) -> u32 {
        self.outgoing_bandwidth_limit
    }

    /// Returns the current incoming bandwidth limit.
    pub fn incoming_bandwidth_limit(&self) -> u32 {
        self.incoming_bandwidth_limit
    }

    /// Returns the bytes sent in the current window.
    pub fn bytes_sent_this_window(&self) -> u32 {
        self.bytes_sent_this_window
    }

    /// Returns the bytes received in the current window.
    pub fn bytes_received_this_window(&self) -> u32 {
        self.bytes_received_this_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_unlimited_by_default() {
        let time = Instant::now();
        let mut throttle = BandwidthThrottle::new(0, 0, time);

        // Should always be able to send with unlimited bandwidth
        assert!(throttle.can_send_within_bandwidth());

        // Even after recording lots of bytes
        throttle.record_bytes_sent(1_000_000);
        assert!(throttle.can_send_within_bandwidth());

        // Utilization should be 0.0 for unlimited
        assert_eq!(throttle.bandwidth_utilization(), 0.0);
    }

    #[test]
    fn test_bandwidth_throttling_when_limited() {
        let time = Instant::now();
        let mut throttle = BandwidthThrottle::new(1000, 0, time); // 1000 bytes/sec outgoing

        // Should be able to send initially
        assert!(throttle.can_send_within_bandwidth());
        assert_eq!(throttle.bandwidth_utilization(), 0.0);

        // Send 500 bytes (within limit)
        throttle.record_bytes_sent(500);
        assert!(throttle.can_send_within_bandwidth());
        assert_eq!(throttle.bandwidth_utilization(), 0.5);

        // Send another 500 bytes (at limit)
        throttle.record_bytes_sent(500);
        assert!(!throttle.can_send_within_bandwidth()); // Now at limit
        assert_eq!(throttle.bandwidth_utilization(), 1.0);

        // Try to send more (over limit)
        throttle.record_bytes_sent(100);
        assert!(!throttle.can_send_within_bandwidth());
        assert!(throttle.bandwidth_utilization() > 1.0);

        // After window reset, should be able to send again
        let time_plus_1sec = time + Duration::from_secs(1);
        throttle.update_bandwidth_window(time_plus_1sec);
        assert!(throttle.can_send_within_bandwidth());
        assert_eq!(throttle.bandwidth_utilization(), 0.0);
    }

    #[test]
    fn test_bandwidth_limit_updates() {
        let time = Instant::now();
        let mut throttle = BandwidthThrottle::new(0, 0, time);

        // Initially unlimited
        assert_eq!(throttle.outgoing_bandwidth_limit(), 0);
        assert_eq!(throttle.incoming_bandwidth_limit(), 0);

        // Update limits
        throttle.set_incoming_bandwidth_limit(1234);
        throttle.set_outgoing_bandwidth_limit(5678);

        assert_eq!(throttle.incoming_bandwidth_limit(), 1234);
        assert_eq!(throttle.outgoing_bandwidth_limit(), 5678);
    }

    #[test]
    fn test_incoming_bandwidth_throttling() {
        let time = Instant::now();
        let mut throttle = BandwidthThrottle::new(0, 2000, time); // 2000 bytes/sec incoming

        // Should be able to receive initially
        assert!(throttle.can_receive_within_bandwidth());
        assert_eq!(throttle.incoming_bandwidth_utilization(), 0.0);

        // Receive 1000 bytes (within limit)
        throttle.record_bytes_received(1000);
        assert!(throttle.can_receive_within_bandwidth());
        assert_eq!(throttle.incoming_bandwidth_utilization(), 0.5);

        // Receive another 1000 bytes (at limit)
        throttle.record_bytes_received(1000);
        assert!(!throttle.can_receive_within_bandwidth()); // Now at limit
        assert_eq!(throttle.incoming_bandwidth_utilization(), 1.0);

        // After window reset, should be able to receive again
        let time_plus_1sec = time + Duration::from_secs(1);
        throttle.update_bandwidth_window(time_plus_1sec);
        assert!(throttle.can_receive_within_bandwidth());
        assert_eq!(throttle.incoming_bandwidth_utilization(), 0.0);
    }

    #[test]
    fn test_bytes_tracking() {
        let time = Instant::now();
        let mut throttle = BandwidthThrottle::new(1000, 2000, time);

        assert_eq!(throttle.bytes_sent_this_window(), 0);
        assert_eq!(throttle.bytes_received_this_window(), 0);

        throttle.record_bytes_sent(100);
        throttle.record_bytes_received(200);

        assert_eq!(throttle.bytes_sent_this_window(), 100);
        assert_eq!(throttle.bytes_received_this_window(), 200);

        // After window reset, counters should be zero
        let time_plus_1sec = time + Duration::from_secs(1);
        throttle.update_bandwidth_window(time_plus_1sec);

        assert_eq!(throttle.bytes_sent_this_window(), 0);
        assert_eq!(throttle.bytes_received_this_window(), 0);
    }

    #[test]
    fn test_saturating_addition() {
        let time = Instant::now();
        let mut throttle = BandwidthThrottle::new(1000, 2000, time);

        // Send maximum u32 bytes (should saturate, not overflow)
        throttle.record_bytes_sent(u32::MAX);
        throttle.record_bytes_sent(100); // Should saturate at u32::MAX
        assert_eq!(throttle.bytes_sent_this_window(), u32::MAX);

        // Receive maximum u32 bytes (should saturate, not overflow)
        throttle.record_bytes_received(u32::MAX);
        throttle.record_bytes_received(100); // Should saturate at u32::MAX
        assert_eq!(throttle.bytes_received_this_window(), u32::MAX);
    }
}
