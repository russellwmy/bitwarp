# Bitwarp

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)

A modern, high-performance reliable UDP networking library for Rust, inspired by [ENet](http://enet.bespin.org/).

Bitwarp provides flexible delivery guarantees, automatic fragmentation, congestion control, and multi-channel communication—ideal for games and real-time applications.

## Features

- **Multiple delivery modes** - Reliable, unreliable, ordered, sequenced, and unsequenced
- **Multi-channel support** - Up to 255 independent channels per connection
- **Automatic fragmentation** - Handles large packets transparently with timeout-based cleanup
- **PMTU discovery** - Adaptive MTU detection (enabled by default)
- **Congestion control** - RTT-based adaptive throttling
- **Bandwidth limiting** - Per-peer bandwidth throttling (optional)
- **Compression** - Optional LZ4 or Zlib compression
- **Data integrity** - Optional CRC32 checksums
- **Zero-copy design** - Efficient buffer management with Arc-based sharing
- **Command batching** - Multiple operations packed into single UDP packets

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
bitwarp = "0.1"
```

### Basic Example

```rust
use bitwarp::{Host, Packet, SocketEvent};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a host
    let mut host = Host::bind("127.0.0.1:9000")?;

    // Connect to a peer or send data
    let peer_addr = "127.0.0.1:8000".parse()?;
    host.send(Packet::reliable_unordered(peer_addr, b"Hello".to_vec()))?;

    // Poll for events
    loop {
        host.manual_poll(Instant::now());

        while let Some(event) = host.recv() {
            match event {
                SocketEvent::Connect(addr) => {
                    println!("Peer connected: {}", addr);
                }
                SocketEvent::Packet(packet) => {
                    println!("Received {} bytes on channel {}",
                        packet.payload().len(),
                        packet.channel_id());
                }
                SocketEvent::Disconnect(addr) => {
                    println!("Peer disconnected: {}", addr);
                }
                SocketEvent::Timeout(addr) => {
                    println!("Peer timeout: {}", addr);
                }
            }
        }
    }
}
```

## Delivery Guarantees

```rust
use bitwarp::Packet;

// Unreliable (fire-and-forget, lowest latency)
let pkt = Packet::unreliable(addr, data);

// Reliable (guaranteed delivery, unordered)
let pkt = Packet::reliable_unordered(addr, data);

// Reliable + Ordered (TCP-like)
let pkt = Packet::reliable_ordered(addr, data, None);

// Sequenced (only latest packet delivered)
let pkt = Packet::reliable_sequenced(addr, data, None);

// Unsequenced (prevents duplicates, allows reordering)
let pkt = Packet::unsequenced(addr, data);
```

## Multi-Channel Communication

Use channels to prioritize different traffic types independently:

```rust
use bitwarp::{Config, Host};

// Configure channel count
let mut config = Config::default();
config.channel_count = 4;
let mut host = Host::bind_with_config("0.0.0.0:7777", config)?;

// Send on different channels
host.send(Packet::reliable_on_channel(addr, player_input, 0))?;  // High priority
host.send(Packet::unreliable_on_channel(addr, world_state, 1))?; // State sync
host.send(Packet::reliable_on_channel(addr, chat_message, 2))?;  // Chat
```

## Configuration

```rust
use bitwarp::{Config, CompressionAlgorithm};
use std::time::Duration;

let mut config = Config::default();

// Connection settings
config.idle_connection_timeout = Duration::from_secs(30);
config.heartbeat_interval = Some(Duration::from_secs(5));

// Channels
config.channel_count = 8;

// Fragmentation (PMTU discovery enabled by default)
config.max_packet_size = 32 * 1024;  // 32 KB
config.use_pmtu_discovery = true;    // Adaptive MTU (default: true)
config.pmtu_min = 576;                // Minimum MTU
config.pmtu_max = 1400;               // Maximum MTU

// Bandwidth limiting (0 = unlimited)
config.outgoing_bandwidth_limit = 0;
config.incoming_bandwidth_limit = 0;

// Compression (optional)
config.compression = CompressionAlgorithm::None;  // None, Lz4, or Zlib
config.compression_threshold = 128;

// Checksums (optional)
config.use_checksums = false;

let host = Host::bind_with_config("0.0.0.0:7777", config)?;
```

## Examples

Run the included examples:

```bash
# Server
cargo run --example server -- 127.0.0.1:7777

# Client
cargo run --example client -- 127.0.0.1:7777
```

## Event Loop Integration

### Manual Polling (Game Loop)

```rust
use std::{thread, time::{Duration, Instant}};

let mut host = Host::bind_any()?;

loop {
    host.manual_poll(Instant::now());

    // Process events
    while let Some(event) = host.recv() {
        // Handle event
    }

    // Your game logic here

    thread::sleep(Duration::from_millis(16));  // 60 FPS
}
```

### Automatic Polling (Background Thread)

```rust
use std::thread;

let mut host = Host::bind_any()?;
let event_rx = host.get_event_receiver();

// Start background polling
thread::spawn(move || {
    host.start_polling();  // Polls every 1ms
});

// Main thread handles events
for event in event_rx.iter() {
    // Handle event
}
```

## Architecture

Bitwarp is organized into several focused crates:

```text
bitwarp (public API)
    ├── bitwarp-host      - Socket I/O and session management
    ├── bitwarp-peer      - Per-peer state and command batching
    ├── bitwarp-protocol  - Protocol logic, ACKs, fragmentation, congestion
    └── bitwarp-core      - Configuration and shared types
```

The protocol layer is purely functional (no I/O), making it easy to test and reason about.

## Best Practices

1. **Use unreliable packets** for high-frequency position updates
2. **Use reliable ordered** for critical game events
3. **Use channels** to separate different traffic types
4. **Enable PMTU discovery** for optimal bandwidth (default)
5. **Poll regularly** - call `manual_poll()` at least once per frame
6. **Clean up fragments** - call `cleanup_stale_fragments()` periodically in long-running apps

```rust
// In your main loop (recommended once per second)
let now = Instant::now();
for (_addr, peer) in host.peers_mut() {
    peer.cleanup_stale_fragments(now);
}
```

## Testing

```bash
cargo test --all                    # Run all tests
cargo clippy --all-targets          # Check for issues
cargo fmt --check                   # Check formatting
```

## Contributing

Contributions are welcome! Please ensure:

- All tests pass: `cargo test --all`
- Code is formatted: `cargo fmt`
- No clippy warnings: `cargo clippy --all-targets`

## License

MIT
