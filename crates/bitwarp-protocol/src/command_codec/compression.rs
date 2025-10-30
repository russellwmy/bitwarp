//! Data compression and decompression utilities.

use std::io::{self, Read, Write};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use bitwarp_core::config::CompressionAlgorithm;

/// Compresses data using the specified algorithm.
/// Returns compressed data with 1-byte header: `[algorithm_id][compressed_data]`
/// Returns original data with header `[0][original_data]` if compression is disabled or ineffective.
pub fn compress(data: &[u8], algorithm: CompressionAlgorithm, threshold: usize) -> io::Result<Vec<u8>> {
    compress_with_buffer(data, algorithm, threshold, Vec::new())
}

/// Compresses data using the specified algorithm with a provided output buffer.
/// This version reuses the output buffer to reduce allocations in hot paths.
/// Returns the compressed data, reusing the provided buffer when possible.
pub fn compress_with_buffer(
    data: &[u8],
    algorithm: CompressionAlgorithm,
    threshold: usize,
    mut output: Vec<u8>,
) -> io::Result<Vec<u8>> {
    output.clear();

    // Don't compress small packets
    if data.len() < threshold {
        output.reserve(data.len() + 1);
        output.push(0); // Uncompressed marker
        output.extend_from_slice(data);
        return Ok(output);
    }

    match algorithm {
        CompressionAlgorithm::None => {
            output.reserve(data.len() + 1);
            output.push(0); // Uncompressed marker
            output.extend_from_slice(data);
            Ok(output)
        }
        CompressionAlgorithm::Zlib => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            let compressed = encoder.finish()?;

            // Only use compression if it actually reduces size
            if compressed.len() < data.len() {
                output.reserve(compressed.len() + 1);
                output.push(1); // Zlib marker
                output.extend_from_slice(&compressed);
                Ok(output)
            } else {
                output.reserve(data.len() + 1);
                output.push(0); // Uncompressed marker
                output.extend_from_slice(data);
                Ok(output)
            }
        }
        CompressionAlgorithm::Lz4 => {
            let compressed = lz4::block::compress(data, None, false)?;

            // Only use compression if it actually reduces size
            if compressed.len() + 4 < data.len() {
                output.reserve(compressed.len() + 5);
                output.push(2); // LZ4 marker
                output.extend_from_slice(&(data.len() as u32).to_be_bytes());
                output.extend_from_slice(&compressed);
                Ok(output)
            } else {
                output.reserve(data.len() + 1);
                output.push(0); // Uncompressed marker
                output.extend_from_slice(data);
                Ok(output)
            }
        }
    }
}

/// Decompresses data based on the 1-byte header.
/// Header format: `[algorithm_id][data]`
/// - 0: Uncompressed
/// - 1: Zlib
/// - 2: LZ4
pub fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty data for decompression"));
    }

    let algorithm_id = data[0];
    let payload = &data[1..];

    match algorithm_id {
        0 => {
            // Uncompressed
            Ok(payload.to_vec())
        }
        1 => {
            // Zlib
            let mut decoder = ZlibDecoder::new(payload);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        2 => {
            // LZ4 - first 4 bytes are original size
            if payload.len() < 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "LZ4 payload too short"));
            }
            let original_size = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            let compressed_data = &payload[4..];
            let decompressed = lz4::block::decompress(compressed_data, Some(original_size as i32))?;
            Ok(decompressed)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unknown compression algorithm: {}", algorithm_id),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_none() {
        let data = b"Test data that will not be compressed";
        let compressed = compress(data, CompressionAlgorithm::None, 10).unwrap();
        assert_eq!(compressed[0], 0); // Uncompressed marker
        assert_eq!(&compressed[1..], data);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_zlib() {
        let data = b"Test data that should compress well because it has lots of repetition repetition repetition";
        let compressed = compress(data, CompressionAlgorithm::Zlib, 10).unwrap();
        assert_eq!(compressed[0], 1); // Zlib marker
        assert!(compressed.len() < data.len() + 1);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_lz4() {
        let data = b"Test data that should compress well because it has lots of repetition repetition repetition";
        let compressed = compress(data, CompressionAlgorithm::Lz4, 10).unwrap();
        assert_eq!(compressed[0], 2); // LZ4 marker
        assert!(compressed.len() < data.len() + 5);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_below_threshold() {
        let data = b"tiny";
        let compressed = compress(data, CompressionAlgorithm::Zlib, 100).unwrap();
        assert_eq!(compressed[0], 0); // Should not compress
        assert_eq!(&compressed[1..], data);
    }

    #[test]
    fn test_compression_ineffective() {
        // Random-ish data that won't compress well
        let data = b"a1b2c3d4e5f6g7h8i9j0";
        let compressed = compress(data, CompressionAlgorithm::Zlib, 5).unwrap();
        // Should fall back to uncompressed if compression doesn't help
        if compressed[0] == 0 {
            assert_eq!(&compressed[1..], data);
        }
    }

    #[test]
    fn test_decompression_unknown_algorithm() {
        let data = vec![99, 1, 2, 3]; // Invalid algorithm ID
        assert!(decompress(&data).is_err());
    }

    #[test]
    fn test_compress_with_buffer_reuse() {
        let data = b"Test data for buffer reuse";
        let buffer = Vec::with_capacity(100);
        let compressed = compress_with_buffer(data, CompressionAlgorithm::None, 10, buffer).unwrap();
        assert_eq!(compressed[0], 0);
        assert_eq!(&compressed[1..], data);
    }
}
