use std::time::{Duration, Instant};

/// Congestion control and RTT tracking with dynamic throttle.
#[derive(Debug, Clone)]
pub struct CongestionControl {
    /// Smoothed round-trip time
    rtt: Duration,
    /// RTT variance
    rtt_variance: Duration,
    /// Smoothing factor for RTT calculations (typically 0.1)
    rtt_alpha: f32,
    /// Variance smoothing factor (typically 0.25)
    rtt_beta: f32,
    /// Number of packets lost
    packets_lost: u32,
    /// Number of packets sent
    packets_sent: u32,
    /// Current throttle value (probability of dropping unreliable packets, 0.0-1.0)
    throttle: f32,
    /// Minimum throttle value
    min_throttle: f32,
    /// Maximum throttle value
    max_throttle: f32,
    /// Last time throttle was updated
    last_throttle_update: Instant,
    /// Throttle update interval
    throttle_interval: Duration,

    // Advanced throttling
    /// Enable advanced throttling with acceleration/deceleration
    use_advanced_throttling: bool,
    /// Throttle scale (maximum value, typically 32)
    throttle_scale: u32,
    /// Current throttle value in scale units (0 to throttle_scale)
    packet_throttle: u32,
    /// Throttle acceleration (rate of improvement)
    throttle_acceleration: u32,
    /// Throttle deceleration (rate of degradation)
    throttle_deceleration: u32,
}

impl CongestionControl {
    /// Creates a new congestion control instance.
    pub fn new(rtt_alpha: f32, rtt_beta: f32) -> Self {
        Self {
            rtt: Duration::from_millis(50), // Initial estimate
            rtt_variance: Duration::from_millis(25),
            rtt_alpha,
            rtt_beta,
            packets_lost: 0,
            packets_sent: 0,
            throttle: 0.0,
            min_throttle: 0.0,
            max_throttle: 1.0,
            last_throttle_update: Instant::now(),
            throttle_interval: Duration::from_secs(1),
            use_advanced_throttling: false,
            throttle_scale: 32,          // Default scale
            packet_throttle: 32,         // Start at maximum (no throttling)
            throttle_acceleration: 2,    // Default acceleration
            throttle_deceleration: 2,    // Default deceleration
        }
    }

    /// Enables advanced throttling with custom parameters.
    pub fn enable_advanced_throttling(
        &mut self,
        scale: u32,
        acceleration: u32,
        deceleration: u32,
        interval_ms: u32,
    ) {
        self.use_advanced_throttling = true;
        self.throttle_scale = scale;
        self.packet_throttle = scale; // Start at maximum (no throttling)
        self.throttle_acceleration = acceleration;
        self.throttle_deceleration = deceleration;
        self.throttle_interval = Duration::from_millis(interval_ms as u64);
    }

    /// Updates RTT measurement with a new sample.
    /// Uses exponential weighted moving average (EWMA).
    pub fn update_rtt(&mut self, sample: Duration) {
        let sample_ms = sample.as_millis() as f32;
        let rtt_ms = self.rtt.as_millis() as f32;

        // EWMA for RTT: RTT = (1 - α) * RTT + α * sample
        let new_rtt_ms = (1.0 - self.rtt_alpha) * rtt_ms + self.rtt_alpha * sample_ms;
        self.rtt = Duration::from_millis(new_rtt_ms as u64);

        // Update variance: Var = (1 - β) * Var + β * |RTT - sample|
        let diff = (rtt_ms - sample_ms).abs();
        let var_ms = self.rtt_variance.as_millis() as f32;
        let new_var_ms = (1.0 - self.rtt_beta) * var_ms + self.rtt_beta * diff;
        self.rtt_variance = Duration::from_millis(new_var_ms as u64);
    }

    /// Returns the current smoothed RTT.
    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Returns the RTT variance.
    pub fn rtt_variance(&self) -> Duration {
        self.rtt_variance
    }

    /// Returns the retransmission timeout (RTO) based on RTT.
    /// Uses the standard RTO = RTT + 4 * variance formula.
    pub fn rto(&self) -> Duration {
        self.rtt + Duration::from_millis(4 * self.rtt_variance.as_millis() as u64)
    }

    /// Records a packet loss event.
    pub fn record_loss(&mut self) {
        self.packets_lost += 1;
    }

    /// Records a packet send event.
    pub fn record_sent(&mut self) {
        self.packets_sent += 1;
    }

    /// Returns the packet loss rate (0.0 to 1.0).
    pub fn loss_rate(&self) -> f32 {
        if self.packets_sent == 0 {
            return 0.0;
        }
        self.packets_lost as f32 / self.packets_sent as f32
    }

    /// Updates the dynamic throttle based on current network conditions.
    /// Returns true if throttle was updated.
    pub fn update_throttle(&mut self, now: Instant) -> bool {
        if now.duration_since(self.last_throttle_update) < self.throttle_interval {
            return false;
        }

        let loss_rate = self.loss_rate();

        if self.use_advanced_throttling {
            // Advanced throttling with acceleration/deceleration
            self.update_advanced_throttle(loss_rate);
        } else {
            // Simple throttling (backward compatible)
            self.update_simple_throttle(loss_rate);
        }

        // Reset counters
        self.packets_lost = 0;
        self.packets_sent = 0;
        self.last_throttle_update = now;

        true
    }

    /// Simple throttle update (original implementation).
    fn update_simple_throttle(&mut self, loss_rate: f32) {
        // Increase throttle if packet loss is high
        if loss_rate > 0.05 {
            // More than 5% loss
            self.throttle = (self.throttle + 0.1).min(self.max_throttle);
        } else if loss_rate < 0.01 && self.throttle > self.min_throttle {
            // Less than 1% loss, decrease throttle
            self.throttle = (self.throttle - 0.05).max(self.min_throttle);
        }
    }

    /// Advanced throttle update with acceleration/deceleration.
    fn update_advanced_throttle(&mut self, loss_rate: f32) {
        // packet_throttle ranges from 0 (drop everything) to throttle_scale (drop nothing)
        // Higher packet_throttle = less throttling = better conditions

        if loss_rate > 0.01 {
            // Packet loss detected - decrease packet_throttle (increase throttling)
            // Use deceleration to control how fast we throttle
            if self.packet_throttle > self.throttle_deceleration {
                self.packet_throttle -= self.throttle_deceleration;
            } else {
                self.packet_throttle = 0;
            }
        } else if loss_rate < 0.005 && self.packet_throttle < self.throttle_scale {
            // Low/no packet loss - increase packet_throttle (decrease throttling)
            // Use acceleration to control how fast we recover
            self.packet_throttle = (self.packet_throttle + self.throttle_acceleration)
                .min(self.throttle_scale);
        }

        // Convert packet_throttle to 0.0-1.0 throttle value
        // packet_throttle=scale means no throttling (throttle=0.0)
        // packet_throttle=0 means maximum throttling (throttle=1.0)
        self.throttle = 1.0 - (self.packet_throttle as f32 / self.throttle_scale as f32);
    }

    /// Returns whether an unreliable packet should be dropped based on throttle.
    /// Uses throttle as drop probability.
    pub fn should_drop_unreliable(&self) -> bool {
        if self.throttle == 0.0 {
            return false;
        }
        rand::random::<f32>() < self.throttle
    }

    /// Returns the current throttle value.
    pub fn throttle(&self) -> f32 {
        self.throttle
    }

    /// Returns the current packet throttle value (0 to throttle_scale).
    pub fn packet_throttle(&self) -> u32 {
        self.packet_throttle
    }

    /// Returns the throttle scale.
    pub fn throttle_scale(&self) -> u32 {
        self.throttle_scale
    }

    /// Returns whether advanced throttling is enabled.
    pub fn is_advanced_throttling_enabled(&self) -> bool {
        self.use_advanced_throttling
    }

    /// Sets the throttle range.
    pub fn set_throttle_range(&mut self, min: f32, max: f32) {
        self.min_throttle = min.clamp(0.0, 1.0);
        self.max_throttle = max.clamp(0.0, 1.0);
    }

    /// Configures throttle parameters dynamically (for ThrottleConfigure command).
    pub fn configure_throttle(&mut self, interval_ms: u32, acceleration: u32, deceleration: u32) {
        self.throttle_interval = Duration::from_millis(interval_ms as u64);
        self.throttle_acceleration = acceleration;
        self.throttle_deceleration = deceleration;
    }

    /// Resets all statistics.
    pub fn reset_stats(&mut self) {
        self.packets_lost = 0;
        self.packets_sent = 0;
    }
}

impl Default for CongestionControl {
    fn default() -> Self {
        Self::new(0.1, 0.25)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtt_update() {
        let mut cc = CongestionControl::default();

        cc.update_rtt(Duration::from_millis(100));
        assert!(cc.rtt() > Duration::from_millis(50)); // Should increase from initial

        cc.update_rtt(Duration::from_millis(100));
        assert!(cc.rtt() < Duration::from_millis(100)); // Smoothed, so less than sample
    }

    #[test]
    fn test_rto_calculation() {
        let mut cc = CongestionControl::default();

        cc.update_rtt(Duration::from_millis(100));
        let rto = cc.rto();

        // RTO should be RTT + 4 * variance
        assert!(rto > cc.rtt());
    }

    #[test]
    fn test_loss_rate() {
        let mut cc = CongestionControl::default();

        assert_eq!(cc.loss_rate(), 0.0);

        cc.record_sent();
        cc.record_sent();
        cc.record_loss();

        assert!((cc.loss_rate() - 0.5).abs() < 0.01); // 1 lost out of 2 sent = 50%
    }

    #[test]
    fn test_throttle_increases_with_loss() {
        let mut cc = CongestionControl::default();
        let _start = Instant::now();

        // Simulate high packet loss
        for _ in 0..100 {
            cc.record_sent();
        }
        for _ in 0..10 {
            cc.record_loss();
        } // 10% loss

        std::thread::sleep(Duration::from_millis(1100));
        let later = Instant::now();

        let updated = cc.update_throttle(later);
        assert!(updated);
        assert!(cc.throttle() > 0.0);
    }

    #[test]
    fn test_advanced_throttling_enabled() {
        let mut cc = CongestionControl::default();

        assert!(!cc.is_advanced_throttling_enabled());

        cc.enable_advanced_throttling(32, 2, 2, 5000);

        assert!(cc.is_advanced_throttling_enabled());
        assert_eq!(cc.throttle_scale(), 32);
        assert_eq!(cc.packet_throttle(), 32); // Starts at max (no throttling)
    }

    #[test]
    fn test_advanced_throttle_decreases_with_loss() {
        let mut cc = CongestionControl::default();
        cc.enable_advanced_throttling(32, 2, 2, 100); // 100ms interval for faster testing

        let initial_throttle = cc.packet_throttle();
        assert_eq!(initial_throttle, 32); // Start at max

        // Simulate moderate packet loss (2%)
        for _ in 0..100 {
            cc.record_sent();
        }
        for _ in 0..2 {
            cc.record_loss();
        }

        std::thread::sleep(Duration::from_millis(150));
        let later = Instant::now();

        let updated = cc.update_throttle(later);
        assert!(updated);

        // packet_throttle should decrease (more throttling)
        assert!(cc.packet_throttle() < initial_throttle);
        // Overall throttle value should increase (0.0-1.0 scale)
        assert!(cc.throttle() > 0.0);
    }

    #[test]
    fn test_advanced_throttle_increases_with_good_conditions() {
        let mut cc = CongestionControl::default();
        cc.enable_advanced_throttling(32, 2, 2, 100);

        // First, decrease throttle by simulating loss
        for _ in 0..100 {
            cc.record_sent();
        }
        for _ in 0..2 {
            cc.record_loss();
        }

        std::thread::sleep(Duration::from_millis(150));
        cc.update_throttle(Instant::now());

        let throttled_value = cc.packet_throttle();
        assert!(throttled_value < 32);

        // Now simulate good conditions (low loss)
        for _ in 0..1000 {
            cc.record_sent();
        }
        // Only 2 losses = 0.2% loss rate

        std::thread::sleep(Duration::from_millis(150));
        cc.update_throttle(Instant::now());

        // packet_throttle should increase (less throttling)
        assert!(cc.packet_throttle() > throttled_value);
    }

    #[test]
    fn test_advanced_throttle_respects_scale() {
        let mut cc = CongestionControl::default();
        cc.enable_advanced_throttling(64, 5, 5, 100); // Higher scale and rates

        assert_eq!(cc.throttle_scale(), 64);
        assert_eq!(cc.packet_throttle(), 64);

        // Simulate sustained packet loss
        for _round in 0..20 {
            for _ in 0..100 {
                cc.record_sent();
            }
            for _ in 0..5 {
                cc.record_loss();
            } // 5% loss

            std::thread::sleep(Duration::from_millis(150));
            cc.update_throttle(Instant::now());
        }

        // Should throttle heavily but not go below 0
        assert!(cc.packet_throttle() <= 64);
        // throttle (0.0-1.0) should be high
        assert!(cc.throttle() > 0.5);
    }

    #[test]
    fn test_configure_throttle_dynamically() {
        let mut cc = CongestionControl::default();
        cc.enable_advanced_throttling(32, 2, 2, 5000);

        // Dynamically reconfigure
        cc.configure_throttle(1000, 5, 3);

        // Verify the configuration was updated (interval is harder to test without waiting)
        // Just verify it doesn't panic and throttle still works
        for _ in 0..50 {
            cc.record_sent();
        }
        cc.record_loss();

        std::thread::sleep(Duration::from_millis(1100));
        assert!(cc.update_throttle(Instant::now()));
    }
}
