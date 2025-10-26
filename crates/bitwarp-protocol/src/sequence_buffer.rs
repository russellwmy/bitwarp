use std::clone::Clone;

use crate::packet::SequenceNumber;

/// Circular buffer for tracking sequenced items with wrapping sequence numbers.
/// Used by AcknowledgmentHandler to track received packets for ACK bitfield generation.
#[derive(Debug)]
pub struct SequenceBuffer<T: Clone + Default> {
    sequence_num: SequenceNumber,
    entry_sequences: Box<[Option<SequenceNumber>]>,
    entries: Box<[T]>,
}

impl<T: Clone + Default> SequenceBuffer<T> {
    /// Creates a new sequence buffer with the specified capacity.
    pub fn with_capacity(size: u16) -> Self {
        Self {
            sequence_num: 0,
            entry_sequences: vec![None; size as usize].into_boxed_slice(),
            entries: vec![T::default(); size as usize].into_boxed_slice(),
        }
    }

    /// Returns the current sequence number.
    pub fn sequence_num(&self) -> SequenceNumber {
        self.sequence_num
    }

    /// Gets a mutable reference to an entry by sequence number.
    pub fn get_mut(&mut self, sequence_num: SequenceNumber) -> Option<&mut T> {
        if self.exists(sequence_num) {
            let index = self.index(sequence_num);
            return Some(&mut self.entries[index]);
        }
        None
    }

    /// Inserts an entry at the specified sequence number.
    pub fn insert(&mut self, sequence_num: SequenceNumber, entry: T) -> Option<&mut T> {
        if sequence_less_than(
            sequence_num,
            self.sequence_num.wrapping_sub(self.entry_sequences.len() as u16),
        ) {
            return None;
        }
        self.advance_sequence(sequence_num);
        let index = self.index(sequence_num);
        self.entry_sequences[index] = Some(sequence_num);
        self.entries[index] = entry;
        Some(&mut self.entries[index])
    }

    /// Checks if an entry exists at the given sequence number.
    pub fn exists(&self, sequence_num: SequenceNumber) -> bool {
        let index = self.index(sequence_num);
        if let Some(s) = self.entry_sequences[index] {
            return s == sequence_num;
        }
        false
    }

    /// Removes and returns the entry at the specified sequence number.
    pub fn remove(&mut self, sequence_num: SequenceNumber) -> Option<T> {
        if self.exists(sequence_num) {
            let index = self.index(sequence_num);
            let value = std::mem::take(&mut self.entries[index]);
            self.entry_sequences[index] = None;
            return Some(value);
        }
        None
    }

    fn advance_sequence(&mut self, sequence_num: SequenceNumber) {
        if sequence_greater_than(sequence_num.wrapping_add(1), self.sequence_num) {
            self.remove_entries(u32::from(sequence_num));
            self.sequence_num = sequence_num.wrapping_add(1);
        }
    }

    fn remove_entries(&mut self, mut finish_sequence: u32) {
        let start_sequence = u32::from(self.sequence_num);
        if finish_sequence < start_sequence {
            finish_sequence += 65536;
        }
        if finish_sequence - start_sequence < self.entry_sequences.len() as u32 {
            for sequence in start_sequence..=finish_sequence {
                self.remove(sequence as u16);
            }
        } else {
            for index in 0..self.entry_sequences.len() {
                self.entries[index] = T::default();
                self.entry_sequences[index] = None;
            }
        }
    }

    fn index(&self, sequence: SequenceNumber) -> usize {
        sequence as usize % self.entry_sequences.len()
    }
}

/// Compares sequence numbers with wrapping arithmetic.
pub fn sequence_greater_than(s1: u16, s2: u16) -> bool {
    ((s1 > s2) && (s1 - s2 <= 32768)) || ((s1 < s2) && (s2 - s1 > 32768))
}

/// Compares sequence numbers with wrapping arithmetic.
pub fn sequence_less_than(s1: u16, s2: u16) -> bool {
    sequence_greater_than(s2, s1)
}
