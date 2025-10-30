//! Peer connection statistics tracking.
//!
//! This module provides comprehensive statistics tracking for peer connections,
//! including metrics for packets sent/received, bytes transferred, and network
//! quality indicators like packet loss rate.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistics_initialized_to_zero() {
        let stats = PeerStatistics::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.packet_loss_rate(), 0.0);
    }

    #[test]
    fn test_statistics_packet_loss_rate() {
        let mut stats = PeerStatistics::default();
        stats.packets_sent = 100;
        stats.packets_lost = 10;

        let loss_rate = stats.packet_loss_rate();
        assert!((loss_rate - 0.1).abs() < 0.001); // 10/100 = 0.1 = 10%
    }

    #[test]
    fn test_statistics_packet_loss_rate_no_packets_sent() {
        let stats = PeerStatistics::default();
        assert_eq!(stats.packet_loss_rate(), 0.0);
    }

    #[test]
    fn test_statistics_reset() {
        let mut stats = PeerStatistics::default();
        stats.packets_sent = 100;
        stats.packets_received = 90;
        stats.packets_lost = 10;
        stats.bytes_sent = 10000;
        stats.bytes_received = 9000;

        stats.reset();

        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_lost, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_statistics_track_packet_loss() {
        let mut stats = PeerStatistics::default();
        stats.packets_lost = 5;
        assert_eq!(stats.packets_lost, 5);
    }
}
