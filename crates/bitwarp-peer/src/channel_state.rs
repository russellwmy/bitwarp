//! Channel ordering and sequencing logic.
//!
//! This module provides the `ChannelState` struct which manages per-channel ordering
//! and sequencing guarantees for packet delivery. It handles:
//!
//! - **Ordered delivery**: Buffers out-of-order packets and delivers them in sequence order
//! - **Sequenced delivery**: Drops old packets and only delivers the newest ones
//!
//! Each channel maintains its own state to track expected sequence numbers and buffer
//! packets that arrive out of order.

use std::collections::HashMap;

use bitwarp_core::shared::SharedBytes;

/// Tracks per-channel ordering state.
#[derive(Debug)]
pub struct ChannelState {
    /// Expected next sequence number for ordered delivery
    expected_sequence: u16,
    /// Buffered out-of-order packets waiting for missing sequences
    buffered_packets: HashMap<u16, SharedBytes>,
    /// Latest sequence number seen (for sequenced/drop-old behavior)
    latest_sequence: u16,
}

impl ChannelState {
    /// Creates a new `ChannelState` with initial sequence numbers set to 0.
    pub fn new() -> Self {
        Self { expected_sequence: 0, buffered_packets: HashMap::new(), latest_sequence: 0 }
    }

    /// Process an ordered packet. Returns packets ready for delivery (in order).
    /// Buffers out-of-order packets until the missing sequences arrive.
    pub fn process_ordered(&mut self, sequence: u16, data: SharedBytes) -> Vec<SharedBytes> {
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
    pub fn process_sequenced(&mut self, sequence: u16, data: SharedBytes) -> Option<SharedBytes> {
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
