//! Path MTU (Maximum Transmission Unit) Discovery
//!
//! This module implements application-level PMTU discovery for bitwarp peers.
//! PMTU discovery helps determine the largest packet size that can be transmitted
//! without fragmentation across the network path between two peers.
//!
//! # Algorithm
//!
//! The implementation uses a binary search approach:
//! - Maintains a low bound (minimum successful size) and high bound (maximum to test)
//! - Periodically sends probe packets of varying sizes
//! - Adjusts bounds based on probe success/failure
//! - Converges when the search space becomes smaller than a threshold
//!
//! # Probe Flow
//!
//! 1. Sender generates a PMTUProbe with a test size and unique token
//! 2. If the probe reaches the receiver, they respond with PMTUReply
//! 3. On successful reply: increase low bound (larger packets work)
//! 4. On timeout: decrease high bound (that size is too large)
//! 5. Continue until convergence
//!
//! # Configuration
//!
//! Key parameters from `Config`:
//! - `use_pmtu_discovery`: Enable/disable PMTU discovery
//! - `pmtu_min`: Minimum MTU to probe (low bound starting point)
//! - `pmtu_max`: Maximum MTU to probe (high bound starting point)
//! - `pmtu_interval_ms`: Time between probes
//! - `pmtu_converge_threshold`: Convergence threshold (stop when high - low <= this)

use std::time::{Duration, Instant};

use bitwarp_core::{config::Config, shared::SharedBytes};
use bitwarp_protocol::command::ProtocolCommand;

/// Manages Path MTU discovery state for a peer connection.
///
/// This struct tracks the binary search for optimal packet size and manages
/// outstanding probes.
#[derive(Debug)]
pub struct PmtuDiscovery {
    /// Configuration reference
    config: Config,
    /// Effective per-peer fragment size (bytes)
    fragment_size: u16,
    /// PMTU binary search low bound (bytes)
    low: u16,
    /// PMTU binary search high bound (bytes)
    high: u16,
    /// Last time we probed PMTU
    last_probe: Instant,
    /// Outstanding PMTU probe info: (size, token, sent_time)
    outstanding: Option<(u16, u32, Instant)>,
}

impl PmtuDiscovery {
    /// Creates a new PMTU discovery instance.
    pub fn new(config: &Config, time: Instant) -> Self {
        Self {
            config: config.clone(),
            fragment_size: config.fragment_size,
            low: config.pmtu_min,
            high: config.pmtu_max,
            last_probe: time,
            outstanding: None,
        }
    }

    /// Returns the current effective fragment size in bytes.
    pub fn current_fragment_size(&self) -> u16 {
        self.fragment_size
    }

    /// Sets the fragment size to a specific value.
    pub fn set_fragment_size(&mut self, size: u16) {
        self.fragment_size = size;
    }

    /// Returns the current low bound of the PMTU search.
    pub fn low_bound(&self) -> u16 {
        self.low
    }

    /// Returns the current high bound of the PMTU search.
    pub fn high_bound(&self) -> u16 {
        self.high
    }

    /// Returns whether there is an outstanding probe.
    pub fn has_outstanding_probe(&self) -> bool {
        self.outstanding.is_some()
    }

    /// Returns the outstanding probe information for testing purposes.
    #[cfg(test)]
    pub fn outstanding_probe(&self) -> Option<(u16, u32, Instant)> {
        self.outstanding
    }

    /// Handles PMTU probing state machine.
    ///
    /// This should be called periodically to:
    /// - Check for probe timeouts
    /// - Check for convergence
    /// - Generate new probes when appropriate
    ///
    /// Returns `Some(ProtocolCommand)` if a new probe should be sent.
    pub fn handle_pmtu(&mut self, time: Instant, rto: Duration) -> Option<ProtocolCommand> {
        if !self.config.use_pmtu_discovery {
            return None;
        }

        // Timeout outstanding probe
        if let Some((size, _token, sent)) = self.outstanding {
            let timeout = rto.max(Duration::from_millis(200));
            if time.duration_since(sent) > timeout {
                // Consider it failed: reduce high bound
                if size > 0 {
                    self.high = self.high.min(size - 1);
                }
                self.outstanding = None;
                self.last_probe = time;
            }
            return None;
        }

        // Check convergence
        if self.high.saturating_sub(self.low) <= self.config.pmtu_converge_threshold {
            self.fragment_size = self.low;
            return None;
        }

        // Time to probe?
        let interval = Duration::from_millis(self.config.pmtu_interval_ms as u64);
        if time.duration_since(self.last_probe) < interval {
            return None;
        }

        // Next candidate: mid
        let mid = ((self.low as u32 + self.high as u32) / 2) as u16;
        let token: u32 = rand::random();
        let payload = SharedBytes::from_vec(vec![0u8; mid as usize]);

        let command = ProtocolCommand::PMTUProbe { size: mid, token, payload };

        self.outstanding = Some((mid, token, time));
        self.last_probe = time;

        Some(command)
    }

    /// Processes a PMTUReply command.
    ///
    /// Returns `true` if the reply was valid and processed successfully.
    pub fn process_reply(&mut self, size: u16, token: u32, time: Instant) -> bool {
        if let Some((_pending_size, pending_token, _sent)) = self.outstanding {
            if pending_token == token {
                // Success: raise low bound and update effective fragment size
                self.low = self.low.max(size);
                self.fragment_size = self.low;
                self.outstanding = None;
                self.last_probe = time;
                tracing::debug!("PMTU success: token={}, size={}", token, size);
                return true;
            }
        }
        false
    }

    /// Creates a PMTUReply command for a received probe.
    ///
    /// This should be called when receiving a PMTUProbe command.
    pub fn create_reply(size: u16, token: u32) -> ProtocolCommand {
        ProtocolCommand::PMTUReply { size, token }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmtu_discovery_probe_reply() {
        let mut config = Config::default();
        config.use_pmtu_discovery = true;
        config.pmtu_min = 576;
        config.pmtu_max = 1400;
        config.pmtu_interval_ms = 100; // Short interval for testing

        let start_time = Instant::now();
        let mut pmtu = PmtuDiscovery::new(&config, start_time);

        // Initially, should use config fragment_size
        assert_eq!(pmtu.current_fragment_size(), config.fragment_size);

        // Advance time past the probe interval to trigger first probe
        let time = start_time + Duration::from_millis(150);
        let rto = Duration::from_millis(200);
        let probe_cmd = pmtu.handle_pmtu(time, rto);

        // Should have generated a probe command
        assert!(probe_cmd.is_some());
        assert!(pmtu.has_outstanding_probe());

        // Simulate successful reply
        if let Some(outstanding) = pmtu.outstanding {
            let (size, token, _) = outstanding;
            let success = pmtu.process_reply(size, token, time);
            assert!(success);
            // After successful reply, low should be updated
            assert_eq!(pmtu.current_fragment_size(), size);
            assert!(!pmtu.has_outstanding_probe());
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
        let mut pmtu = PmtuDiscovery::new(&config, start_time);

        // Advance time to trigger initial probe
        let mut time = start_time + Duration::from_millis(150);
        let rto = Duration::from_millis(200);
        let probe_cmd = pmtu.handle_pmtu(time, rto);
        assert!(probe_cmd.is_some());

        let high_before = pmtu.high_bound();

        // Advance time beyond RTO to trigger timeout
        time = time + Duration::from_secs(2);

        // Handle PMTU again - should timeout the outstanding probe
        let result = pmtu.handle_pmtu(time, rto);

        // After timeout, outstanding should be cleared and high bound reduced
        assert!(!pmtu.has_outstanding_probe());
        assert!(pmtu.high_bound() < high_before);
        assert!(result.is_none()); // No new probe until interval passes
    }

    #[test]
    fn test_pmtu_discovery_enabled_by_default() {
        let config = Config::default();
        assert!(config.use_pmtu_discovery);

        let creation_time = Instant::now();
        let mut pmtu = PmtuDiscovery::new(&config, creation_time);

        // Wait for the PMTU interval to elapse before checking for probes
        let probe_time =
            creation_time + Duration::from_millis(config.pmtu_interval_ms as u64 + 100);

        // Should generate probes when enabled after interval
        let rto = Duration::from_millis(200);
        let probe = pmtu.handle_pmtu(probe_time, rto);
        assert!(probe.is_some());
    }

    #[test]
    fn test_pmtu_discovery_can_be_disabled() {
        let mut config = Config::default();
        config.use_pmtu_discovery = false;
        assert!(!config.use_pmtu_discovery);

        let mut pmtu = PmtuDiscovery::new(&config, Instant::now());
        let time = Instant::now();
        let rto = Duration::from_millis(200);

        // Should not generate any probes when disabled
        let probe = pmtu.handle_pmtu(time, rto);
        assert!(probe.is_none());
    }

    #[test]
    fn test_pmtu_discovery_convergence() {
        let mut config = Config::default();
        config.use_pmtu_discovery = true;
        config.pmtu_min = 1200;
        config.pmtu_max = 1232; // Within convergence threshold
        config.pmtu_converge_threshold = 64;

        let mut pmtu = PmtuDiscovery::new(&config, Instant::now());
        let time = Instant::now();
        let rto = Duration::from_millis(200);

        // When high - low <= threshold, should converge to low
        let probe = pmtu.handle_pmtu(time, rto);

        // Should converge and not generate probe
        assert!(probe.is_none());
        // Should use low bound as fragment size
        assert_eq!(pmtu.current_fragment_size(), config.pmtu_min);
    }

    #[test]
    fn test_pmtu_invalid_reply_token() {
        let mut config = Config::default();
        config.use_pmtu_discovery = true;

        let start_time = Instant::now();
        let mut pmtu = PmtuDiscovery::new(&config, start_time);

        // Generate a probe
        let time = start_time + Duration::from_millis(config.pmtu_interval_ms as u64 + 100);
        let rto = Duration::from_millis(200);
        pmtu.handle_pmtu(time, rto);

        // Send reply with wrong token
        let wrong_token = 99999;
        let success = pmtu.process_reply(1000, wrong_token, time);

        // Should reject invalid token
        assert!(!success);
        // Probe should still be outstanding
        assert!(pmtu.has_outstanding_probe());
    }

    #[test]
    fn test_pmtu_create_reply() {
        let size = 1200;
        let token = 12345;
        let reply = PmtuDiscovery::create_reply(size, token);

        match reply {
            ProtocolCommand::PMTUReply { size: s, token: t } => {
                assert_eq!(s, size);
                assert_eq!(t, token);
            }
            _ => panic!("Expected PMTUReply command"),
        }
    }
}
