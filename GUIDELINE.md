# Bitwarp Development Guidelines

## Project Overview

Bitwarp is a reliable UDP networking library inspired by ENet. These guidelines ensure consistency, performance, and reliability in protocol implementation and network operations.

## Core Principles

### Performance & Low Latency

- **Minimize allocations** - Use object pooling, Arc-based sharing, and buffer reuse
- **Zero-copy where possible** - Avoid unnecessary data copies
- **Batch operations** - Aggregate multiple commands into single UDP packets
- **Inline hot paths** - Use `#[inline]` for frequently called functions (packet encoding/decoding)
- **Cache-friendly data structures** - Consider memory layout for high-frequency access patterns
- **Profile before optimizing** - Measure with `cargo bench` and `criterion`

### Reliability & Correctness

- **Sequence number arithmetic** - Always use wrapping arithmetic for u16 sequence numbers
- **Proper packet drop detection** - Only drop packets that are behind the ACK window
- **Fragment timeout cleanup** - Prevent memory leaks from incomplete fragments
- **Integer overflow protection** - Validate calculations before casting to smaller types
- **MTU validation** - Ensure payloads fit within configured size limits
- **Comprehensive testing** - Test edge cases, wraparound, and boundary conditions

### Protocol Design

- **Command-based architecture** - Everything is a protocol command (ACK, Ping, Send, etc.)
- **Separation of concerns** - Protocol layer has no I/O, purely functional
- **Stateless where possible** - Minimize mutable state in protocol logic
- **Explicit state machines** - Use enums for connection lifecycle states
- **Version compatibility** - Design protocol changes to be backward compatible

## Architecture

### Layered Design

```text
bitwarp-host      → I/O, socket operations, session management
bitwarp-peer      → Per-peer state machine, command batching
bitwarp-protocol  → Pure protocol logic (no I/O)
bitwarp-core      → Configuration, errors, shared types
```

**Key principles:**

- **Protocol layer is pure** - No side effects, no I/O, fully testable
- **Clear boundaries** - Each layer has well-defined responsibilities
- **Dependency direction** - Always depend downward (host → peer → protocol → core)

### Module Organization

```rust
// Good: Clear separation
mod acknowledgment;  // ACK handling logic
mod congestion;      // RTT tracking, throttling
mod packet;          // Packet encoding/decoding
mod command;         // Protocol command types

// Bad: Mixed concerns
mod network;  // Too broad, unclear responsibility
```

## Code Quality

### Rust Best Practices

- **Follow Rust naming conventions** - snake_case for functions, PascalCase for types
- **Use Result for errors** - Never panic on user input or network errors
- **Use Option for optional values** - Avoid sentinel values
- **Pattern matching** - Prefer exhaustive matching over if-let chains
- **Explicit types** - Use type aliases for clarity (e.g., `type SequenceNumber = u16`)

### Error Handling

Use custom error types with clear variants:

```rust
#[derive(Debug, Clone)]
pub enum ErrorKind {
    MtuTooSmall,
    PayloadTooLargeToFragment,
    InvalidPacketFormat,
    ChecksumMismatch,
}
```

**Guidelines:**

- Log errors with `tracing::error!` or `tracing::warn!`
- Return errors, don't panic (except for internal logic bugs)
- Provide context in error messages
- Use `Result<T, Error>` consistently

### Dependencies

**Current dependencies:**

- `byteorder` - Binary serialization
- `crc32fast` - Checksums
- `lz4`, `flate2` - Compression (optional)
- `tracing` - Logging
- `crossbeam-channel` - Event channels
- `socket2` - Raw socket operations
- `dns-lookup` - Address resolution

**Adding new dependencies:**

1. Search crates.io for alternatives
2. Check maintenance status and download count
3. Prefer minimal, focused crates
4. Justify each addition (performance, compatibility, maintainability)
5. Use feature flags for optional dependencies

## Network Programming Best Practices

### UDP Packet Handling

```rust
// Good: Validate size before processing
if data.len() < MIN_PACKET_SIZE {
    return Err(ErrorKind::PacketTooSmall);
}

// Good: Handle truncated reads
let bytes_read = socket.recv_from(&mut buffer)?;
let packet = &buffer[..bytes_read];

// Bad: Assume full buffer is valid
let packet = &buffer;  // May contain garbage
```

### Sequence Number Arithmetic

**Always use wrapping arithmetic for u16:**

```rust
// Good: Correct wraparound handling
pub fn sequence_greater_than(s1: u16, s2: u16) -> bool {
    ((s1 > s2) && (s1 - s2 <= 32768)) ||
    ((s1 < s2) && (s2 - s1 > 32768))
}

// Bad: Simple comparison breaks at wraparound
if s1 > s2 { /* WRONG */ }
```

### Fragmentation

**Guidelines:**

- Calculate fragment count before casting to u8
- Check for integer overflow: `if total_fragments > u8::MAX { error }`
- Track incomplete fragments with timestamps
- Clean up stale fragments after timeout (5 seconds default)
- Validate MTU to prevent zero-sized payloads

```rust
// Good: Overflow protection
let total_fragments_usize = (data.len() + fragment_payload - 1) / fragment_payload;
if total_fragments_usize > u8::MAX as usize {
    return Err(ErrorKind::PayloadTooLargeToFragment);
}
let total_fragments = total_fragments_usize as u8;

// Bad: Silent truncation
let total_fragments = ((data.len() + fragment_payload - 1) / fragment_payload) as u8;
```

## Testing Strategy

### Test Coverage

- **Unit tests** - Each module has `#[cfg(test)] mod tests`
- **Integration tests** - End-to-end protocol tests in `tests/`
- **Edge cases** - Sequence wraparound, boundary conditions, timeouts
- **Property tests** - Use `quickcheck` for protocol invariants

### Test Organization

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_wraparound() {
        // Test near u16::MAX
    }

    #[test]
    fn test_dropped_packets_only_behind_ack() {
        // Test packet drop detection
    }

    #[test]
    fn test_fragment_timeout_cleanup() {
        // Test stale fragment removal
    }
}
```

### Test Naming

- Use descriptive names: `test_dropped_packets_only_behind_ack`
- Include "what" and "expected": `test_stale_fragment_cleanup`
- Group related tests with common prefix: `test_pmtu_*`

### Running Tests

```bash
cargo test --all                    # All tests
cargo test --all -- --nocapture     # With output
cargo test -p bitwarp-protocol      # Single crate
cargo clippy --all-targets          # Linting
```

## Performance Optimization

### Memory Management

- **Pool buffers** - Reuse send/receive buffers
- **Arc for shared data** - Avoid clones with `Arc<[u8]>`
- **Inline small functions** - Encoding/decoding hot paths
- **Stack allocate when possible** - Use arrays for fixed-size data

### Benchmarking

```rust
// Use criterion for benchmarks
#[bench]
fn bench_packet_encoding(b: &mut Bencher) {
    b.iter(|| {
        encode_packet(&test_packet)
    });
}
```

**Profile with:**

- `cargo bench` - Microbenchmarks
- `perf` or `flamegraph` - CPU profiling
- `dhat` or `heaptrack` - Memory profiling

### Hot Path Optimization

```rust
// Good: Minimize allocations
let mut buffer = self.buffer_pool.acquire();
encode_into(&mut buffer, &packet);
self.buffer_pool.release(buffer);

// Bad: Allocate every time
let buffer = Vec::new();
encode_into(&mut buffer, &packet);
```

## Logging & Debugging

### Tracing Levels

- `tracing::error!` - Protocol violations, network errors
- `tracing::warn!` - Recoverable issues (stale fragments, oversized commands)
- `tracing::info!` - Connection lifecycle events
- `tracing::debug!` - Detailed protocol state
- `tracing::trace!` - Hot path operations (fragmentation, encoding)

### Structured Logging

```rust
// Good: Include context
tracing::warn!(
    fragments = stale_count,
    timeout_secs = 5,
    "Cleaning up stale fragment buffers"
);

// Good: Performance metrics
tracing::trace!(
    payload_size = data.len(),
    fragments = total_fragments,
    fragment_size = fragment_payload,
    "Fragmenting payload"
);
```

## Documentation

### Doc Comments

- Use `///` for public APIs
- Include examples that compile
- Document edge cases and assumptions
- Explain non-obvious algorithms

```rust
/// Returns packets that are considered dropped (not ACKed beyond window).
///
/// A packet is considered dropped if it is more than REDUNDANT_PACKET_ACKS_SIZE (32)
/// sequence numbers behind the latest acknowledged sequence number.
///
/// # Implementation
///
/// Uses wrapping arithmetic to handle u16 sequence number wraparound correctly.
pub fn dropped_packets(&mut self) -> Vec<SentPacket> {
    // ...
}
```

### Internal Documentation

```rust
// Explain complex logic
// Binary search between pmtu_low and pmtu_high
// Probes are sent at intervals, replies adjust the bounds
let probe_size = (self.pmtu_low + self.pmtu_high) / 2;
```

## Security Considerations

### Input Validation

- **Validate all external input** - Packet sizes, sequence numbers, fragments
- **Bounds checking** - Array access, buffer writes
- **Avoid panics** - Use `checked_*` arithmetic or explicit bounds checks
- **Rate limiting** - Prevent DoS with bandwidth limits

### Safe Defaults

```rust
// Good: Safe defaults
impl Default for Config {
    fn default() -> Self {
        Self {
            max_packet_size: 32 * 1024,     // Reasonable limit
            use_checksums: false,            // Opt-in
            max_fragments: 255,              // Prevent excessive memory
            idle_connection_timeout: Duration::from_secs(30),
        }
    }
}
```

## CI/CD

### Required Checks

```yaml
- cargo fmt --check          # Code formatting
- cargo clippy --all-targets # Linting
- cargo test --all           # All tests
- cargo build --release      # Release build
```

### Recommended Checks

```yaml
- cargo audit                # Security vulnerabilities
- cargo deny check           # License compliance
- cargo bench                # Performance regression
```

## Versioning & Releases

### Semantic Versioning

- **MAJOR** - Breaking protocol changes
- **MINOR** - New features, backward compatible
- **PATCH** - Bug fixes

### Changelog

Document changes in each release:

- Fixed bugs (especially critical ones)
- New features
- Performance improvements
- Breaking changes (if any)

## Common Pitfalls

### ❌ Avoid

```rust
// Incorrect sequence comparison
if seq1 > seq2 { /* WRONG at wraparound */ }

// Unbounded fragment buffers
self.fragments.insert(seq, buffer);  // Memory leak

// Panicking on network errors
let data = buffer.get(0..size).unwrap();  // May panic

// Silent integer overflow
let count = (total / chunk_size) as u8;  // May truncate
```

### ✅ Correct

```rust
// Wraparound-aware comparison
if sequence_greater_than(seq1, seq2) { /* OK */ }

// Timeout-based cleanup
self.cleanup_stale_fragments(now);

// Graceful error handling
let data = buffer.get(0..size).ok_or(ErrorKind::InvalidSize)?;

// Overflow protection
let count_usize = total / chunk_size;
if count_usize > u8::MAX as usize {
    return Err(ErrorKind::TooManyFragments);
}
let count = count_usize as u8;
```

## File Organization

### What to Create

- Implementation files (`.rs`)
- Test files (`tests/*.rs`)
- Configuration (`Cargo.toml`)

### What NOT to Create (unless requested)

- Example files (`examples/*.rs`)
- Documentation files (`*.md`)
- Configuration files (`.github/`, `.vscode/`, etc.)

### Workspace Structure

```text
crates/
  bitwarp/           - Public API facade
  bitwarp-core/      - Core types (publish = false)
  bitwarp-protocol/  - Protocol logic (publish = false)
  bitwarp-peer/      - Peer state (publish = false)
  bitwarp-host/      - I/O layer (publish = false)
```

**Only `bitwarp` crate is published to crates.io**

## Summary

When contributing to Bitwarp:

1. **Test thoroughly** - Especially edge cases and sequence wraparound
2. **Profile performance** - Networking code must be fast
3. **Handle errors gracefully** - No panics on network errors
4. **Document assumptions** - Especially protocol invariants
5. **Keep layers separate** - Protocol has no I/O
6. **Use logging wisely** - Trace hot paths, warn on anomalies
7. **Validate inputs** - All external data must be validated
8. **Clean up resources** - Timeouts, buffer pools, stale state

**Goal:** Production-ready, high-performance, reliable UDP networking for real-time applications.
