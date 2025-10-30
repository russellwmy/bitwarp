//! Fragment reassembly management for command packets.
//!
//! This module provides functionality for tracking and reassembling fragmented command packets
//! in the Bitwarp networking protocol. Large packets that exceed the maximum transmission unit
//! (MTU) are split into multiple fragments and reassembled on the receiving end.
//!
//! # Fragment Lifecycle
//!
//! 1. **Fragment Reception**: When a fragment arrives, a `CommandFragmentBuffer` is created
//!    (or an existing one is updated) to track all fragments for a given sequence number.
//! 2. **Reassembly**: Once all fragments are received, they are reassembled in order to
//!    reconstruct the original packet.
//! 3. **Timeout**: Incomplete fragment buffers that don't complete within a timeout period
//!    (default 5 seconds) are cleaned up to prevent memory leaks from packet loss or
//!    malicious behavior.
//!
//! # Usage
//!
//! The `CommandFragmentBuffer` is typically used internally by the `Peer` struct to manage
//! fragment reassembly:
//!
//! ```ignore
//! // Create a new fragment buffer when first fragment arrives
//! let buffer = CommandFragmentBuffer::new(channel_id, fragment_count, ordered, Instant::now());
//!
//! // Add fragments as they arrive
//! buffer.add_fragment(fragment_id, fragment_data);
//!
//! // Check if all fragments have been received
//! if buffer.is_complete() {
//!     // Reassemble into complete packet
//!     let complete_packet = buffer.reassemble().unwrap();
//! }
//! ```

use std::{collections::HashMap, sync::Arc, time::Instant};

/// Tracks reassembly of fragmented command packets.
///
/// When a large packet is fragmented for transmission, each fragment shares the same
/// sequence number but has a unique fragment ID. This buffer collects all fragments
/// and reassembles them in order once complete.
#[derive(Debug)]
pub struct CommandFragmentBuffer {
    /// Channel ID for this fragment group
    channel_id: u8,
    /// Total number of fragments expected
    fragment_count: u8,
    /// Whether to deliver in order on receive for this reassembled packet
    ordered: bool,
    /// Fragments received so far (indexed by fragment_id)
    fragments: HashMap<u8, Arc<[u8]>>,
    /// Timestamp when first fragment was received (for timeout detection)
    created_at: Instant,
}

impl CommandFragmentBuffer {
    /// Creates a new fragment buffer for a fragmented packet.
    ///
    /// # Arguments
    ///
    /// * `channel_id` - The channel ID for this fragment group
    /// * `fragment_count` - Total number of fragments expected
    /// * `ordered` - Whether to deliver in order on receive for this reassembled packet
    /// * `created_at` - Timestamp when the first fragment was received
    pub fn new(channel_id: u8, fragment_count: u8, ordered: bool, created_at: Instant) -> Self {
        Self { channel_id, fragment_count, ordered, fragments: HashMap::new(), created_at }
    }

    /// Returns the channel ID for this fragment group.
    pub fn channel_id(&self) -> u8 {
        self.channel_id
    }

    /// Returns whether this packet should be delivered in order.
    pub fn is_ordered(&self) -> bool {
        self.ordered
    }

    /// Adds a fragment to the buffer.
    ///
    /// # Arguments
    ///
    /// * `fragment_id` - The ID of this fragment (0-based index)
    /// * `data` - The fragment data
    pub fn add_fragment(&mut self, fragment_id: u8, data: Arc<[u8]>) {
        self.fragments.insert(fragment_id, data);
    }

    /// Checks if all fragments have been received.
    ///
    /// Returns `true` if the number of received fragments equals the expected fragment count.
    pub fn is_complete(&self) -> bool {
        self.fragments.len() == self.fragment_count as usize
    }

    /// Reassembles all fragments into a complete packet.
    ///
    /// This consumes the buffer and returns the reassembled data if all fragments
    /// are present and can be assembled in order.
    ///
    /// # Returns
    ///
    /// * `Some(Vec<u8>)` - The reassembled packet data if complete
    /// * `None` - If fragments are missing or cannot be reassembled
    pub fn reassemble(mut self) -> Option<Vec<u8>> {
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

    /// Returns the timestamp when the first fragment was received.
    ///
    /// This is used for timeout detection to clean up stale fragment buffers.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }
}

/// Default timeout duration for incomplete fragment buffers.
///
/// If a fragment buffer doesn't complete within this duration, it will be
/// considered stale and eligible for cleanup.
pub const FRAGMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Cleans up stale fragment buffers that haven't been completed within the timeout period.
///
/// This prevents memory leaks from incomplete fragments (e.g., due to packet loss or
/// malicious behavior). This should be called periodically (e.g., once per second) to
/// prevent accumulation of stale buffers.
///
/// # Arguments
///
/// * `command_fragments` - Mutable reference to the fragment buffer map
/// * `time` - Current time for calculating fragment age
///
/// # Example
///
/// ```ignore
/// // In your peer update loop
/// cleanup_stale_fragments(&mut self.command_fragments, Instant::now());
/// ```
pub fn cleanup_stale_fragments(command_fragments: &mut HashMap<u16, CommandFragmentBuffer>, time: Instant) {
    // Collect sequences of stale buffers
    let stale_sequences: Vec<u16> = command_fragments
        .iter()
        .filter_map(|(seq, buffer)| {
            if time.duration_since(buffer.created_at()) > FRAGMENT_TIMEOUT {
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
            command_fragments.remove(&seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_buffer_creation() {
        let buffer = CommandFragmentBuffer::new(0, 3, true, Instant::now());
        assert_eq!(buffer.channel_id(), 0);
        assert_eq!(buffer.is_ordered(), true);
        assert!(!buffer.is_complete());
    }

    #[test]
    fn test_fragment_buffer_add_and_complete() {
        let mut buffer = CommandFragmentBuffer::new(1, 3, false, Instant::now());

        // Add first fragment
        buffer.add_fragment(0, Arc::from(vec![1, 2, 3]));
        assert!(!buffer.is_complete());

        // Add second fragment
        buffer.add_fragment(1, Arc::from(vec![4, 5, 6]));
        assert!(!buffer.is_complete());

        // Add third fragment
        buffer.add_fragment(2, Arc::from(vec![7, 8, 9]));
        assert!(buffer.is_complete());
    }

    #[test]
    fn test_fragment_buffer_reassemble() {
        let mut buffer = CommandFragmentBuffer::new(0, 3, true, Instant::now());

        // Add all fragments
        buffer.add_fragment(0, Arc::from(vec![1, 2, 3]));
        buffer.add_fragment(1, Arc::from(vec![4, 5, 6]));
        buffer.add_fragment(2, Arc::from(vec![7, 8, 9]));

        // Reassemble
        let result = buffer.reassemble().unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_fragment_buffer_reassemble_incomplete() {
        let mut buffer = CommandFragmentBuffer::new(0, 3, true, Instant::now());

        // Add only 2 of 3 fragments
        buffer.add_fragment(0, Arc::from(vec![1, 2, 3]));
        buffer.add_fragment(1, Arc::from(vec![4, 5, 6]));

        // Should not be able to reassemble
        assert!(buffer.reassemble().is_none());
    }

    #[test]
    fn test_cleanup_stale_fragments() {
        let mut fragments: HashMap<u16, CommandFragmentBuffer> = HashMap::new();
        let start_time = Instant::now();

        // Create a fragment buffer
        let buffer = CommandFragmentBuffer::new(0, 3, true, start_time);
        fragments.insert(100, buffer);

        // Cleanup immediately - should not remove anything
        cleanup_stale_fragments(&mut fragments, start_time);
        assert_eq!(fragments.len(), 1, "Fragment buffer should still exist");

        // Cleanup after timeout
        let later = start_time + std::time::Duration::from_secs(6);
        cleanup_stale_fragments(&mut fragments, later);

        // Stale buffer should be cleaned up
        assert_eq!(fragments.len(), 0, "Stale fragment buffer should be cleaned up");
    }

    #[test]
    fn test_cleanup_multiple_stale_fragments() {
        let mut fragments: HashMap<u16, CommandFragmentBuffer> = HashMap::new();
        let start_time = Instant::now();

        // Create multiple fragment buffers
        for seq in 0..5 {
            let buffer = CommandFragmentBuffer::new(0, 2, true, start_time);
            fragments.insert(seq, buffer);
        }

        assert_eq!(fragments.len(), 5);

        // Cleanup after timeout
        let later = start_time + std::time::Duration::from_secs(6);
        cleanup_stale_fragments(&mut fragments, later);

        // All stale buffers should be cleaned up
        assert_eq!(fragments.len(), 0, "All stale fragment buffers should be cleaned up");
    }

    #[test]
    fn test_cleanup_mixed_fresh_and_stale_fragments() {
        let mut fragments: HashMap<u16, CommandFragmentBuffer> = HashMap::new();
        let start_time = Instant::now();

        // Create old fragment buffer
        let old_buffer = CommandFragmentBuffer::new(0, 3, true, start_time);
        fragments.insert(100, old_buffer);

        // Wait a bit
        let later = start_time + std::time::Duration::from_secs(6);

        // Create new fragment buffer
        let new_buffer = CommandFragmentBuffer::new(1, 3, false, later);
        fragments.insert(200, new_buffer);

        // Cleanup - should only remove the old one
        cleanup_stale_fragments(&mut fragments, later);

        assert_eq!(fragments.len(), 1, "Only fresh fragment buffer should remain");
        assert!(fragments.contains_key(&200), "Fresh buffer should still exist");
        assert!(!fragments.contains_key(&100), "Stale buffer should be removed");
    }
}
