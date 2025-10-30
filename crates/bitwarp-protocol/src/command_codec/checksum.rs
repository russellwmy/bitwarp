//! CRC32 checksum utilities for data integrity verification.

use std::io;
use crc32fast::Hasher;

/// Appends a CRC32 checksum to the encoded packet data.
/// Returns a new vector with the checksum appended.
pub fn append_checksum(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let checksum = hasher.finalize();

    let mut result = Vec::with_capacity(data.len() + 4);
    result.extend_from_slice(data);
    result.extend_from_slice(&checksum.to_be_bytes());
    result
}

/// Appends a CRC32 checksum to the provided buffer in-place.
pub fn append_checksum_in_place(data: &mut Vec<u8>) {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let checksum = hasher.finalize();
    data.extend_from_slice(&checksum.to_be_bytes());
}

/// Validates and strips the CRC32 checksum from packet data.
/// Returns the data without checksum if valid, or an error if checksum fails.
pub fn validate_and_strip_checksum(data: &[u8]) -> io::Result<&[u8]> {
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Data too short for checksum"));
    }

    let (payload, checksum_bytes) = data.split_at(data.len() - 4);
    let received_checksum = u32::from_be_bytes([
        checksum_bytes[0],
        checksum_bytes[1],
        checksum_bytes[2],
        checksum_bytes[3],
    ]);

    let mut hasher = Hasher::new();
    hasher.update(payload);
    let computed_checksum = hasher.finalize();

    if received_checksum != computed_checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CRC32 checksum mismatch: expected {}, got {}",
                computed_checksum, received_checksum
            ),
        ));
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_append_and_validate() {
        let data = b"Hello, world!";
        let with_checksum = append_checksum(data);
        assert_eq!(with_checksum.len(), data.len() + 4);

        let validated = validate_and_strip_checksum(&with_checksum).unwrap();
        assert_eq!(validated, data);
    }

    #[test]
    fn test_checksum_validation_fails_on_corruption() {
        let data = b"Hello, world!";
        let mut with_checksum = append_checksum(data);

        // Corrupt the checksum
        let len = with_checksum.len();
        with_checksum[len - 1] ^= 0xFF;

        assert!(validate_and_strip_checksum(&with_checksum).is_err());
    }

    #[test]
    fn test_checksum_validation_rejects_short_data() {
        let data = b"Hi";
        assert!(validate_and_strip_checksum(data).is_err());
    }

    #[test]
    fn test_checksum_with_empty_data() {
        let data = b"";
        let with_checksum = append_checksum(data);
        assert_eq!(with_checksum.len(), 4);

        let validated = validate_and_strip_checksum(&with_checksum).unwrap();
        assert_eq!(validated, data);
    }

    #[test]
    fn test_append_checksum_in_place() {
        let data = b"Test data";
        let mut buffer = data.to_vec();
        append_checksum_in_place(&mut buffer);

        assert_eq!(buffer.len(), data.len() + 4);
        let validated = validate_and_strip_checksum(&buffer).unwrap();
        assert_eq!(validated, data);
    }
}
