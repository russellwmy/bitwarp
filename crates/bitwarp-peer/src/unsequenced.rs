//! Unsequenced packet duplicate detection using a sliding window.
//!
//! This module implements a 1024-bit sliding window for detecting duplicate unsequenced packets.
//! Unsequenced packets can arrive in any order and may be duplicated by the network, so we need
//! to track which group IDs have already been received to filter out duplicates.
//!
//! # Design
//!
//! The sliding window uses 1024 bits (32 u32 words) to track received group IDs:
//! - Each bit represents whether a specific group ID has been received
//! - The window base (`incoming_unsequenced_group`) tracks the oldest group in the window
//! - When packets arrive far ahead of the window, the window slides forward
//! - Old packets (behind the window) are treated as duplicates
//!
//! # Wrapping Arithmetic
//!
//! Group IDs are u16 values that wrap around at 65536. The window uses wrapping arithmetic
//! to correctly handle the transition from 65535 to 0.

/// State for tracking unsequenced packet duplicates using a sliding window.
///
/// This struct maintains a 1024-bit window for duplicate detection of unsequenced packets.
/// It tracks which group IDs have been received and automatically slides the window forward
/// when new packets arrive far ahead of the current window base.
#[derive(Debug, Clone)]
pub struct UnsequencedState {
    /// Incoming unsequenced group base (start of sliding window)
    incoming_unsequenced_group: u16,
    /// Unsequenced window for duplicate detection (1024 bits = 128 bytes)
    /// Each bit represents whether a group has been received in the window
    unsequenced_window: [u32; 32], // 32 u32s = 1024 bits
    /// Outgoing unsequenced group counter
    outgoing_unsequenced_group: u16,
}

impl Default for UnsequencedState {
    fn default() -> Self {
        Self::new()
    }
}

impl UnsequencedState {
    /// Creates a new unsequenced state with an empty window.
    pub fn new() -> Self {
        Self {
            incoming_unsequenced_group: 0,
            unsequenced_window: [0; 32], // All bits start as 0 (no groups received)
            outgoing_unsequenced_group: 0,
        }
    }

    /// Gets the next outgoing unsequenced group ID and increments the counter.
    pub fn next_outgoing_group(&mut self) -> u16 {
        let group = self.outgoing_unsequenced_group;
        self.outgoing_unsequenced_group = self.outgoing_unsequenced_group.wrapping_add(1);
        group
    }

    /// Returns the current incoming unsequenced group (window base).
    pub fn incoming_group(&self) -> u16 {
        self.incoming_unsequenced_group
    }

    /// Returns the current outgoing unsequenced group.
    pub fn outgoing_group(&self) -> u16 {
        self.outgoing_unsequenced_group
    }

    /// Checks if an incoming unsequenced group is a duplicate or within the window.
    /// Returns true if this is a duplicate (already received), false if new.
    pub fn is_duplicate(&self, group: u16) -> bool {
        // Check if window is completely empty (no packets received yet)
        let window_empty = self.unsequenced_window.iter().all(|&w| w == 0);
        if window_empty {
            // First packet(s), not a duplicate
            return false;
        }

        // Calculate offset from window base
        let offset = group.wrapping_sub(self.incoming_unsequenced_group);

        // If offset is within window (0-1023), check the window
        if offset < 1024 {
            // Check if this bit is set in the window
            let word_index = (offset / 32) as usize;
            let bit_index = offset % 32;

            if word_index < 32 {
                return (self.unsequenced_window[word_index] & (1 << bit_index)) != 0;
            }
        }

        // Outside the forward window - check if it's old (behind the window)
        // Using wrapping arithmetic: if offset > 32768, it's actually a negative offset
        // meaning it's behind the current window base (old packet)
        if offset > 32768 {
            return true; // Old packet, treat as duplicate
        }

        // New packet ahead of window, not a duplicate
        false
    }

    /// Marks an incoming unsequenced group as received in the window.
    /// Advances the window base if necessary.
    pub fn mark_received(&mut self, group: u16) {
        // Calculate offset from window base
        let offset = group.wrapping_sub(self.incoming_unsequenced_group);

        // If the group is far ahead (and not wrapping backwards), we need to advance the window base
        if offset >= 1024 && offset <= 32768 {
            // Calculate how much to advance
            let advance = offset.saturating_sub(512); // Keep window centered on new packets

            // Shift window bits and clear old ones
            let word_shift = (advance / 32) as usize;
            let bit_shift = advance % 32;

            if word_shift > 0 {
                // Shift entire words
                if word_shift >= 32 {
                    // Complete window reset
                    self.unsequenced_window = [0; 32];
                } else {
                    // Partial shift
                    for i in 0..(32 - word_shift) {
                        self.unsequenced_window[i] = self.unsequenced_window[i + word_shift];
                    }
                    for i in (32 - word_shift)..32 {
                        self.unsequenced_window[i] = 0;
                    }
                }
            }

            if bit_shift > 0 && word_shift < 32 {
                // Shift bits within words
                for i in 0..31 {
                    self.unsequenced_window[i] = (self.unsequenced_window[i] >> bit_shift)
                        | (self.unsequenced_window[i + 1] << (32 - bit_shift));
                }
                self.unsequenced_window[31] >>= bit_shift;
            }

            // Advance window base
            self.incoming_unsequenced_group = self.incoming_unsequenced_group.wrapping_add(advance);
        }

        // Now mark the bit for this group
        let final_offset = group.wrapping_sub(self.incoming_unsequenced_group);
        if final_offset < 1024 {
            let word_index = (final_offset / 32) as usize;
            let bit_index = final_offset % 32;
            if word_index < 32 {
                self.unsequenced_window[word_index] |= 1 << bit_index;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsequenced_window_sliding() {
        let mut state = UnsequencedState::new();

        // Receive a packet at group 0
        assert!(!state.is_duplicate(0));
        state.mark_received(0);

        // Same packet again should be duplicate
        assert!(state.is_duplicate(0));

        // Receive a packet far ahead (group 1500, outside window of 1024)
        assert!(!state.is_duplicate(1500));
        state.mark_received(1500);

        // Now group 0 should be treated as very old and duplicate
        assert!(state.is_duplicate(0));
    }

    #[test]
    fn test_unsequenced_window_wrapping() {
        let mut state = UnsequencedState::new();

        // Start by receiving some packets to establish a base around 65000
        for i in 0..3 {
            let group = 65000 + i;
            assert!(!state.is_duplicate(group));
            state.mark_received(group);
        }

        // Now receive near the end of u16 range
        assert!(!state.is_duplicate(65500));
        state.mark_received(65500);

        // Wrap around to 10 (should be treated as newer, after 65535)
        assert!(!state.is_duplicate(10));
        state.mark_received(10);

        // Sending 65002 (old packet from before) should be duplicate
        assert!(state.is_duplicate(65002));
    }

    #[test]
    fn test_unsequenced_basic_duplicate_detection() {
        let mut state = UnsequencedState::new();

        // First packet should not be duplicate
        assert!(!state.is_duplicate(5));
        state.mark_received(5);

        // Same packet again should be duplicate
        assert!(state.is_duplicate(5));

        // Different packet should not be duplicate
        assert!(!state.is_duplicate(10));
        state.mark_received(10);

        // Both should now be marked
        assert!(state.is_duplicate(5));
        assert!(state.is_duplicate(10));
    }

    #[test]
    fn test_unsequenced_window_boundaries() {
        let mut state = UnsequencedState::new();

        // Mark group 100 as base
        state.mark_received(100);

        // Within window (100 + 1023 = 1123)
        assert!(!state.is_duplicate(1123));
        state.mark_received(1123);
        assert!(state.is_duplicate(1123));

        // Just outside window should trigger slide
        assert!(!state.is_duplicate(1124));
        state.mark_received(1124);

        // Old packet should now be duplicate
        assert!(state.is_duplicate(100));
    }

    #[test]
    fn test_next_outgoing_group() {
        let mut state = UnsequencedState::new();

        assert_eq!(state.next_outgoing_group(), 0);
        assert_eq!(state.next_outgoing_group(), 1);
        assert_eq!(state.next_outgoing_group(), 2);

        // Test wrapping
        state.outgoing_unsequenced_group = 65535;
        assert_eq!(state.next_outgoing_group(), 65535);
        assert_eq!(state.next_outgoing_group(), 0);
    }

    #[test]
    fn test_getters() {
        let mut state = UnsequencedState::new();

        assert_eq!(state.incoming_group(), 0);
        assert_eq!(state.outgoing_group(), 0);

        state.mark_received(100);
        assert_eq!(state.incoming_group(), 0); // Base doesn't move for small offsets

        state.mark_received(1500); // Far ahead, should trigger slide
        assert!(state.incoming_group() > 0); // Base should have moved

        state.next_outgoing_group();
        assert_eq!(state.outgoing_group(), 1);
    }

    #[test]
    fn test_empty_window() {
        let state = UnsequencedState::new();

        // Empty window should not consider anything a duplicate
        assert!(!state.is_duplicate(0));
        assert!(!state.is_duplicate(100));
        assert!(!state.is_duplicate(65535));
    }

    #[test]
    fn test_complete_window_reset() {
        let mut state = UnsequencedState::new();

        // Mark some packets
        state.mark_received(0);
        state.mark_received(1);
        state.mark_received(2);

        // Jump very far ahead (more than 32 words)
        state.mark_received(2000);

        // Old packets should be duplicates (window was reset and moved)
        assert!(state.is_duplicate(0));
        assert!(state.is_duplicate(1));
        assert!(state.is_duplicate(2));

        // New packet in the new window should work
        assert!(!state.is_duplicate(2001));
        state.mark_received(2001);
        assert!(state.is_duplicate(2001));
    }
}
