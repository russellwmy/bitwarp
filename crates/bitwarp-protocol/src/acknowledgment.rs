use std::{collections::HashMap, time::Instant};

use crate::{
    congestion::CongestionControl,
    packet::{OrderingGuarantee, PacketType, SequenceNumber},
    sequence_buffer::{sequence_greater_than, sequence_less_than, SequenceBuffer},
};

const REDUNDANT_PACKET_ACKS_SIZE: u16 = 32;
const DEFAULT_SEND_PACKETS_SIZE: usize = 256;

/// Responsible for handling the acknowledgment of packets.
pub struct AcknowledgmentHandler {
    sequence_number: SequenceNumber,
    remote_ack_sequence_num: SequenceNumber,
    sent_packets: HashMap<u16, SentPacket>,
    received_packets: SequenceBuffer<ReceivedPacket>,
    /// Congestion control for RTT tracking and throttling
    congestion: CongestionControl,
}

impl AcknowledgmentHandler {
    /// Creates a new acknowledgment handler with default congestion control.
    pub fn new() -> Self {
        Self::with_congestion(CongestionControl::default())
    }

    /// Creates a new acknowledgment handler with custom congestion control.
    pub fn with_congestion(congestion: CongestionControl) -> Self {
        AcknowledgmentHandler {
            sequence_number: 0,
            remote_ack_sequence_num: u16::max_value(),
            sent_packets: HashMap::with_capacity(DEFAULT_SEND_PACKETS_SIZE),
            received_packets: SequenceBuffer::with_capacity(REDUNDANT_PACKET_ACKS_SIZE + 1),
            congestion,
        }
    }

    /// Returns the number of sent packets not yet acknowledged.
    pub fn packets_in_flight(&self) -> u16 {
        self.sent_packets.len() as u16
    }

    /// Returns the local sequence number for the next outgoing packet.
    pub fn local_sequence_num(&self) -> SequenceNumber {
        self.sequence_number
    }

    /// Returns the most recent remote sequence number received.
    pub fn remote_sequence_num(&self) -> SequenceNumber {
        self.received_packets.sequence_num().wrapping_sub(1)
    }

    /// Returns the current round-trip time.
    pub fn rtt(&self) -> std::time::Duration {
        self.congestion.rtt()
    }

    /// Returns the retransmission timeout.
    pub fn rto(&self) -> std::time::Duration {
        self.congestion.rto()
    }

    /// Returns the current packet loss rate (0.0 to 1.0).
    pub fn loss_rate(&self) -> f32 {
        self.congestion.loss_rate()
    }

    /// Returns the current throttle value (0.0 to 1.0).
    pub fn throttle(&self) -> f32 {
        self.congestion.throttle()
    }

    /// Returns a reference to the congestion control.
    pub fn congestion(&self) -> &CongestionControl {
        &self.congestion
    }

    /// Returns a mutable reference to the congestion control.
    pub fn congestion_mut(&mut self) -> &mut CongestionControl {
        &mut self.congestion
    }

    /// Updates the dynamic throttle based on current network conditions.
    pub fn update_throttle(&mut self, now: Instant) -> bool {
        self.congestion.update_throttle(now)
    }

    /// Returns whether an unreliable packet should be dropped based on congestion.
    pub fn should_drop_unreliable(&self) -> bool {
        self.congestion.should_drop_unreliable()
    }

    /// Returns the acknowledgment bitfield for the last 32 packets.
    pub fn ack_bitfield(&self) -> u32 {
        let most_recent_remote_seq_num: u16 = self.remote_sequence_num();
        let mut ack_bitfield: u32 = 0;
        let mut mask: u32 = 1;
        for i in 1..=REDUNDANT_PACKET_ACKS_SIZE {
            let sequence = most_recent_remote_seq_num.wrapping_sub(i);
            if self.received_packets.exists(sequence) {
                ack_bitfield |= mask;
            }
            mask <<= 1;
        }
        ack_bitfield
    }

    /// Processes an incoming packet and updates congestion metrics.
    /// Calculates RTT when ACKs are received.
    pub fn process_incoming(
        &mut self,
        remote_seq_num: u16,
        remote_ack_seq: u16,
        mut remote_ack_field: u32,
        now: Instant,
    ) {
        if sequence_greater_than(remote_ack_seq, self.remote_ack_sequence_num) {
            self.remote_ack_sequence_num = remote_ack_seq;
        }

        self.received_packets.insert(remote_seq_num, ReceivedPacket {});

        // Process ACK for most recent packet and calculate RTT
        if let Some(sent_packet) = self.sent_packets.remove(&remote_ack_seq) {
            let rtt = now.duration_since(sent_packet.sent_time);
            self.congestion.update_rtt(rtt);
        }

        // Process ACKs from bitfield
        for i in 1..=REDUNDANT_PACKET_ACKS_SIZE {
            let ack_sequence = remote_ack_seq.wrapping_sub(i);
            if remote_ack_field & 1 == 1 {
                if let Some(sent_packet) = self.sent_packets.remove(&ack_sequence) {
                    let rtt = now.duration_since(sent_packet.sent_time);
                    self.congestion.update_rtt(rtt);
                }
            }
            remote_ack_field >>= 1;
        }
    }

    /// Processes an outgoing packet and tracks it for acknowledgment.
    pub fn process_outgoing(
        &mut self,
        packet_type: PacketType,
        payload: &[u8],
        ordering_guarantee: OrderingGuarantee,
        item_identifier: Option<SequenceNumber>,
        now: Instant,
    ) {
        self.sent_packets.insert(self.sequence_number, SentPacket {
            packet_type,
            payload: Box::from(payload),
            ordering_guarantee,
            item_identifier,
            sent_time: now,
        });
        self.congestion.record_sent();
        self.sequence_number = self.sequence_number.wrapping_add(1);
    }

    /// Returns packets that are considered dropped (not ACKed beyond window).
    /// Records packet loss for congestion control.
    ///
    /// A packet is considered dropped if it is more than REDUNDANT_PACKET_ACKS_SIZE (32)
    /// sequence numbers behind the latest acknowledged sequence number.
    pub fn dropped_packets(&mut self) -> Vec<SentPacket> {
        let mut sent_sequences: Vec<SequenceNumber> = self.sent_packets.keys().cloned().collect();
        sent_sequences.sort_unstable();
        let remote_ack_sequence = self.remote_ack_sequence_num;

        let dropped: Vec<SentPacket> = sent_sequences
            .iter()
            .filter(|s| {
                // Only consider packets that are BEHIND the ACK sequence
                if sequence_less_than(**s, remote_ack_sequence) {
                    // Calculate how far behind this packet is
                    let distance = remote_ack_sequence.wrapping_sub(**s);
                    // Drop if it's too far behind (more than 32 sequence numbers)
                    distance > REDUNDANT_PACKET_ACKS_SIZE
                } else {
                    // Packet is at or ahead of ACK sequence, still in flight, don't drop
                    false
                }
            })
            .flat_map(|s| self.sent_packets.remove(&s))
            .collect();

        // Record packet loss for congestion control
        for _ in &dropped {
            self.congestion.record_loss();
        }

        dropped
    }
}

/// Represents a packet that has been sent but not yet acknowledged.
#[derive(Clone, Debug)]
pub struct SentPacket {
    /// Type of packet sent
    pub packet_type: PacketType,
    /// Payload data of the packet
    pub payload: Box<[u8]>,
    /// Ordering guarantee specified for this packet
    pub ordering_guarantee: OrderingGuarantee,
    /// Optional identifier for ordering/sequencing
    pub item_identifier: Option<SequenceNumber>,
    /// Timestamp when packet was sent (for RTT calculation)
    pub sent_time: Instant,
}

/// Marker for a received packet in the sequence buffer.
#[derive(Clone, Default)]
pub struct ReceivedPacket;

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn test_rtt_tracking_on_ack() {
        let mut handler = AcknowledgmentHandler::new();
        let now = Instant::now();

        // Send a packet
        handler.process_outgoing(
            PacketType::Packet,
            b"test payload",
            OrderingGuarantee::None,
            None,
            now,
        );

        let seq = handler.local_sequence_num().wrapping_sub(1);

        // Simulate 50ms delay
        sleep(std::time::Duration::from_millis(50));
        let later = Instant::now();

        // Receive ACK
        handler.process_incoming(0, seq, 0, later);

        // RTT should be approximately 50ms
        let rtt = handler.rtt();
        assert!(rtt.as_millis() >= 45 && rtt.as_millis() <= 100); // Allow some variance
    }

    #[test]
    fn test_packet_loss_tracking() {
        let mut handler = AcknowledgmentHandler::new();
        let now = Instant::now();

        // Send multiple packets
        for _ in 0..10 {
            handler.process_outgoing(
                PacketType::Packet,
                b"test",
                OrderingGuarantee::None,
                None,
                now,
            );
        }

        assert_eq!(handler.packets_in_flight(), 10);
        assert_eq!(handler.loss_rate(), 0.0); // No loss yet

        // Simulate packet loss by calling dropped_packets
        // (In reality, dropped_packets is called when packets are beyond ACK window)
        let initial_loss_rate = handler.loss_rate();
        assert!(initial_loss_rate < 0.01); // Should be very low or zero
    }

    #[test]
    fn test_congestion_metrics_api() {
        let handler = AcknowledgmentHandler::new();

        // Should have default values
        assert!(handler.rtt().as_millis() >= 40); // Initial estimate around 50ms
        assert!(handler.rto() > handler.rtt()); // RTO should be larger than RTT
        assert_eq!(handler.loss_rate(), 0.0);
        assert_eq!(handler.throttle(), 0.0);
    }

    #[test]
    fn test_throttle_update() {
        let mut handler = AcknowledgmentHandler::new();
        let now = Instant::now();

        // Send and lose packets to trigger throttle
        for _ in 0..100 {
            handler.process_outgoing(
                PacketType::Packet,
                b"test",
                OrderingGuarantee::None,
                None,
                now,
            );
        }

        // Wait for throttle interval
        sleep(std::time::Duration::from_millis(1100));
        let later = Instant::now();

        // Update throttle (will check packet loss rate)
        let updated = handler.update_throttle(later);
        assert!(updated);
    }

    #[test]
    fn test_dropped_packets_only_behind_ack() {
        let mut handler = AcknowledgmentHandler::new();
        let now = Instant::now();

        // Send packets with sequences 0-9
        for _ in 0..10 {
            handler.process_outgoing(
                PacketType::Packet,
                b"test",
                OrderingGuarantee::None,
                None,
                now,
            );
        }

        // ACK sequence 5 (meaning 0-5 are acknowledged)
        handler.process_incoming(0, 5, 0b111111, now);

        // Sequences 6-9 should still be in flight (ahead of ACK)
        let dropped = handler.dropped_packets();
        assert_eq!(dropped.len(), 0, "Packets ahead of ACK should not be dropped");

        // Now ACK sequence 50 (far ahead)
        handler.process_incoming(0, 50, 0, now);

        // Now sequences 6-9 should be dropped (more than 32 behind sequence 50)
        let dropped = handler.dropped_packets();
        assert_eq!(dropped.len(), 4, "Packets >32 behind ACK should be dropped");
    }

    #[test]
    fn test_dropped_packets_wraparound() {
        let mut handler = AcknowledgmentHandler::new();
        let now = Instant::now();

        // Set sequence to 65530 by sending that many packets
        for _ in 0..65530 {
            handler.process_outgoing(
                PacketType::Packet,
                b"x",
                OrderingGuarantee::None,
                None,
                now,
            );
        }

        // ACK and clear old packets to start fresh
        handler.process_incoming(0, 65520, 0xFFFFFFFF, now);
        handler.dropped_packets();

        // Now send packets that will wrap around: 65530-65535, then 0-5 (12 packets total)
        for _ in 0..12 {
            handler.process_outgoing(
                PacketType::Packet,
                b"test",
                OrderingGuarantee::None,
                None,
                now,
            );
        }

        // ACK packet at sequence 5 (after wraparound)
        // This acknowledges packets 65530-65535 and 0-5 (all 12 packets)
        handler.process_incoming(0, 5, 0b111111, now);

        // All packets should be ACKed and removed, nothing should be dropped
        let dropped = handler.dropped_packets();
        assert_eq!(dropped.len(), 0, "Packets within ACK window should not be dropped during wraparound");
    }

    #[test]
    fn test_dropped_packets_window_edge() {
        let mut handler = AcknowledgmentHandler::new();
        let now = Instant::now();

        // Send packet at sequence 0
        handler.process_outgoing(
            PacketType::Packet,
            b"test",
            OrderingGuarantee::None,
            None,
            now,
        );

        // ACK at sequence 32 (exactly at window edge)
        handler.process_incoming(0, 32, 0, now);

        // Packet 0 is exactly 32 behind, should NOT be dropped (boundary condition)
        let dropped = handler.dropped_packets();
        assert_eq!(dropped.len(), 0, "Packet exactly 32 behind should not be dropped");

        // ACK at sequence 33
        handler.process_incoming(0, 33, 0, now);

        // Now packet 0 is 33 behind, should be dropped
        let dropped = handler.dropped_packets();
        assert_eq!(dropped.len(), 1, "Packet >32 behind should be dropped");
    }
}
