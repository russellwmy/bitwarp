//! Command serialization and deserialization.
//!
//! Provides efficient binary encoding/decoding of protocol commands
//! for transmission over the network.
//!
//! # Module Organization
//!
//! - [`encoder`] - Command and packet encoding to binary format
//! - [`decoder`] - Command and packet decoding from binary format
//! - [`checksum`] - CRC32 checksum utilities for data integrity
//! - [`compression`] - Data compression/decompression (Zlib, LZ4)

pub mod checksum;
pub mod compression;
pub mod encoder;
pub mod decoder;

#[cfg(test)]
mod tests;

// Re-export main types for backward compatibility
pub use encoder::CommandEncoder;
pub use decoder::CommandDecoder;

// Re-export utility functions for convenience
pub use checksum::{append_checksum, append_checksum_in_place, validate_and_strip_checksum};
pub use compression::{compress, compress_with_buffer, decompress};
