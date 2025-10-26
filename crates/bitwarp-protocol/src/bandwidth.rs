use std::time::{Duration, Instant};

/// Bandwidth manager for controlling incoming/outgoing data rates.
#[derive(Debug, Clone)]
pub struct BandwidthManager {
    /// Maximum bytes per second for outgoing traffic (0 = unlimited)
    outgoing_bandwidth: u32,
    /// Maximum bytes per second for incoming traffic (0 = unlimited)
    incoming_bandwidth: u32,
    /// Bytes sent in current window
    bytes_sent_this_window: u32,
    /// Bytes received in current window
    bytes_recv_this_window: u32,
    /// Start of current measurement window
    window_start: Instant,
    /// Window duration for bandwidth measurement
    window_duration: Duration,
}

impl BandwidthManager {
    /// Creates a new bandwidth manager with specified limits (bytes/sec).
    pub fn new(outgoing_bw: u32, incoming_bw: u32, window_duration: Duration) -> Self {
        Self {
            outgoing_bandwidth: outgoing_bw,
            incoming_bandwidth: incoming_bw,
            bytes_sent_this_window: 0,
            bytes_recv_this_window: 0,
            window_start: Instant::now(),
            window_duration,
        }
    }

    /// Creates an unlimited bandwidth manager (no throttling).
    pub fn unlimited() -> Self {
        Self::new(0, 0, Duration::from_secs(1))
    }

    /// Sets the outgoing bandwidth limit in bytes per second.
    pub fn set_outgoing_bandwidth(&mut self, bytes_per_sec: u32) {
        self.outgoing_bandwidth = bytes_per_sec;
    }

    /// Sets the incoming bandwidth limit in bytes per second.
    pub fn set_incoming_bandwidth(&mut self, bytes_per_sec: u32) {
        self.incoming_bandwidth = bytes_per_sec;
    }

    /// Updates the bandwidth window if needed.
    pub fn update_window(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= self.window_duration {
            self.bytes_sent_this_window = 0;
            self.bytes_recv_this_window = 0;
            self.window_start = now;
        }
    }

    /// Checks if sending the given number of bytes is allowed.
    /// Returns true if allowed, false if would exceed bandwidth limit.
    pub fn can_send_outgoing(&self, byte_count: usize) -> bool {
        self.update_window_if_needed();

        if self.outgoing_bandwidth == 0 {
            return true; // Unlimited
        }

        let allowed = self.bytes_sent_this_window + byte_count as u32 <= self.outgoing_bandwidth;
        allowed
    }

    /// Records that the given number of bytes were sent.
    pub fn record_sent(&mut self, byte_count: usize) {
        self.bytes_sent_this_window += byte_count as u32;
    }

    /// Checks if receiving the given number of bytes is allowed.
    pub fn can_receive_incoming(&self, byte_count: usize) -> bool {
        self.update_window_if_needed();

        if self.incoming_bandwidth == 0 {
            return true; // Unlimited
        }

        self.bytes_recv_this_window + byte_count as u32 <= self.incoming_bandwidth
    }

    /// Records that the given number of bytes were received.
    pub fn record_received(&mut self, byte_count: usize) {
        self.bytes_recv_this_window += byte_count as u32;
    }

    /// Returns the current outgoing bandwidth utilization (0.0 to 1.0+).
    pub fn outgoing_utilization(&self) -> f32 {
        if self.outgoing_bandwidth == 0 {
            return 0.0; // Unlimited
        }
        self.bytes_sent_this_window as f32 / self.outgoing_bandwidth as f32
    }

    /// Returns the current incoming bandwidth utilization (0.0 to 1.0+).
    pub fn incoming_utilization(&self) -> f32 {
        if self.incoming_bandwidth == 0 {
            return 0.0; // Unlimited
        }
        self.bytes_recv_this_window as f32 / self.incoming_bandwidth as f32
    }

    fn update_window_if_needed(&self) {
        // This is a const method check - actual update happens via update_window()
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn test_unlimited_bandwidth() {
        let bw = BandwidthManager::unlimited();

        // Should allow any amount
        assert!(bw.can_send_outgoing(1_000_000));
        assert!(bw.can_receive_incoming(1_000_000));
        assert_eq!(bw.outgoing_utilization(), 0.0);
        assert_eq!(bw.incoming_utilization(), 0.0);
    }

    #[test]
    fn test_utilization() {
        let mut bw = BandwidthManager::new(1000, 2000, Duration::from_secs(1));

        bw.record_sent(500);
        assert_eq!(bw.outgoing_utilization(), 0.5);

        bw.record_received(1000);
        assert_eq!(bw.incoming_utilization(), 0.5);
    }

    #[test]
    fn test_outgoing_bandwidth_limit() {
        let mut bw = BandwidthManager::new(1000, 0, Duration::from_secs(1));

        // Should allow within limit
        assert!(bw.can_send_outgoing(500));
        bw.record_sent(500);

        assert!(bw.can_send_outgoing(500));
        bw.record_sent(500);

        // Should deny exceeding limit
        assert!(!bw.can_send_outgoing(100));
    }

    #[test]
    fn test_bandwidth_window_reset() {
        let mut bw = BandwidthManager::new(1000, 0, Duration::from_millis(10));

        bw.record_sent(1000);
        assert!(!bw.can_send_outgoing(100));

        // Wait for window to reset
        sleep(Duration::from_millis(15));
        bw.update_window(Instant::now());

        // Should allow again after window reset
        assert!(bw.can_send_outgoing(500));
    }
}
