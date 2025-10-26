# Bitwarp

A high-performance, [ENet](http://enet.bespin.org/) inspired reliable UDP networking library for Rust, designed for games and real-time applications.

## Overview

Bitwarp provides a modular networking stack with configurable reliability, ordering guarantees, and advanced features like multi-channel communication and bandwidth throttling. The architecture separates protocol logic from I/O, making it testable and flexible.

## Architecture

```
bitwarp (facade)
    ├── bitwarp-host      - Host/session manager, UDP socket, events
    ├── bitwarp-peer      - Peer state machine, command batching
    ├── bitwarp-protocol  - Commands, packets, fragmentation, ACK, congestion
    └── bitwarp-core      - Config, errors, constants, transport trait
```

### Crates

- **`bitwarp`** - Convenient public API facade
- **`bitwarp-core`** - Foundation: config, errors, transport abstraction
- **`bitwarp-protocol`** - Protocol implementation: commands, packets, fragmentation, reliability
- **`bitwarp-peer`** - Peer lifecycle management with command queue batching
- **`bitwarp-host`** - High-level host managing multiple peer sessions over UDP

## Design Principles

### Separation of Concerns

- **Protocol layer** - Pure logic, no I/O, fully testable
- **Peer layer** - State machine for connection lifecycle
- **Host layer** - I/O management, socket operations, event dispatch

### ENet-Inspired

- Command-based protocol (everything is a command: ACK, Ping, Send, etc.)
- Command batching reduces UDP overhead
- Adaptive RTT-based congestion control
- Proper connection lifecycle with state machine

### Type Safety

- Strong typing prevents misuse
- Builder patterns for complex configurations
- Zero-cost abstractions where possible

## Features

### Reliability & Ordering

- **Reliable** - Guaranteed delivery with automatic retransmission
- **Unreliable** - Fire-and-forget for low-latency data
- **Ordered** - Packets delivered in send order
- **Sequenced** - Only latest packet delivered, old ones dropped
- **Unsequenced** - Prevents duplicates without requiring ordering (ENet-style)

### Advanced Features

- **Multi-channel** - Up to 255 independent channels per peer for traffic prioritization
- **Bandwidth throttling** - Per-peer outgoing/incoming bandwidth limits (opt-in)
- **Fragmentation** - Automatic splitting and reassembly of large packets
- **Congestion control** - RTT-based adaptive throttling
- **Graceful disconnect** - Proper connection lifecycle with PeerState machine
- **Compression** - Optional Zlib or LZ4 compression (opt-in, backward compatible)
- **CRC32 checksums** - Optional data integrity verification (opt-in, backward compatible)

### Performance

- **Zero-copy** where possible
- **Command batching** - Multiple operations aggregated into single UDP packets
- **Efficient ACKs** - Bitfield acknowledgments covering 32 packets
- **Send buffer pooling** - Host recycles send buffers to reduce allocations in hot paths

## Quick Start

```rust
use bitwarp::{Host, Packet, SocketEvent};

// Create host
let mut host = Host::bind_any()?;
let server_addr = host.local_addr()?;

// Send reliable packet on channel 0
host.send(Packet::reliable_unordered(server_addr, b"hello".to_vec()))?;

// Poll for events
host.manual_poll(std::time::Instant::now());

while let Some(event) = host.recv() {
    match event {
        SocketEvent::Connect(addr) => {
            println!("Peer connected: {}", addr);
        }
        SocketEvent::Packet(pkt) => {
            println!("Received on channel {}: {:?}", pkt.channel_id(), pkt.payload());
        }
        SocketEvent::Disconnect(addr) => {
            println!("Peer disconnected: {}", addr);
        }
        SocketEvent::Timeout(addr) => {
            println!("Peer timeout: {}", addr);
        }
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Examples

Runnable examples are included under the `bitwarp` crate:

- Echo server: `cargo run -p bitwarp --example server -- 127.0.0.1:7777`
- Client: `cargo run -p bitwarp --example client -- 127.0.0.1:7777`

Paths:

- `crates/bitwarp/examples/server.rs`
- `crates/bitwarp/examples/client.rs`

Tip: omit the address to use defaults (`127.0.0.1:9000`).

## Multi-Channel Communication

Channels allow prioritizing different types of traffic independently:

```rust
// Send high-priority command on channel 0
host.send(Packet::reliable_on_channel(addr, player_input, 0))?;

// Send low-priority state sync on channel 1
host.send(Packet::unreliable_on_channel(addr, world_state, 1))?;

// Send bulk data on channel 2
host.send(Packet::reliable_on_channel(addr, asset_data, 2))?;
```

Configure channel count (default: 1):

```rust
use bitwarp::Config;

let mut config = Config::default();
config.channel_count = 8;  // Support 8 channels per peer

let host = Host::bind_with_config("0.0.0.0:7777", config)?;
```

## Bandwidth Throttling

Limit bandwidth per peer (opt-in, backward compatible):

```rust
let mut config = Config::default();
config.outgoing_bandwidth_limit = 100_000;  // 100 KB/sec (0 = unlimited)
config.incoming_bandwidth_limit = 200_000;  // 200 KB/sec (0 = unlimited)

let host = Host::bind_with_config(addr, config)?;
```

When the limit is reached:

- Outgoing: packets are queued and sent in the next 1-second window.
- Incoming: excess packets are dropped for the remainder of the window.

Default is `0` (unlimited) for backward compatibility.

Adjust limits at runtime from the peer using a control command:

```rust
use bitwarp_protocol::command::ProtocolCommand;

// Apply new limits immediately on the remote
peer.enqueue_command(ProtocolCommand::BandwidthLimit { incoming: 200_000, outgoing: 100_000 });
```

## Compression

Enable optional packet compression (opt-in, backward compatible):

```rust
use bitwarp::{Config, CompressionAlgorithm};

let mut config = Config::default();
config.compression = CompressionAlgorithm::Lz4;  // or Zlib, or None (default)
config.compression_threshold = 128;  // Don't compress packets smaller than 128 bytes

let host = Host::bind_with_config(addr, config)?;
```

**Supported algorithms:**

- **None** - No compression (default, zero overhead)
- **Zlib** - Balanced speed and compression ratio
- **LZ4** - Fast compression, lower ratio, ideal for real-time

Compression is applied before checksums. Small packets (below threshold) are not compressed. If compression doesn't reduce size, the packet is sent uncompressed automatically.

**Use cases:**

- Large text-based payloads (JSON, XML)
- Repetitive data (player positions, state updates)
- Bandwidth-constrained environments

## CRC32 Checksums

Enable optional data integrity verification (opt-in, backward compatible):

```rust
let mut config = Config::default();
config.use_checksums = true;  // Enable CRC32 checksums (default: false)

let host = Host::bind_with_config(addr, config)?;
```

When enabled, a 4-byte CRC32 checksum is appended to every packet and validated on receipt. Corrupted packets are automatically rejected. Default is `false` for backward compatibility and minimal overhead.

**Use cases:**

- Unreliable networks (WiFi, cellular)
- Safety-critical applications
- Detecting hardware errors or memory corruption

## Handshake + PMTU Discovery

Bitwarp performs a 3‑way connection handshake carrying session IDs and MTU negotiation.

### Static Fragmentation (Default)

By default, fragmentation uses the static `Config.fragment_size` value (1200 bytes):

```rust
let mut config = Config::default();
config.fragment_size = 1200; // Safe default for most networks
let host = Host::bind_with_config(addr, config)?;
```

### Dynamic PMTU Discovery (Optional)

Enable automatic path MTU discovery to optimize fragment sizes per peer:

```rust
let mut config = Config::default();
config.use_pmtu_discovery = true;  // Enable PMTU discovery
config.pmtu_min = 576;              // Minimum probe size (default)
config.pmtu_max = 1400;             // Maximum probe size (default)
config.pmtu_interval_ms = 5000;    // Probe interval: 5 seconds (default)
config.pmtu_converge_threshold = 64; // Convergence threshold (default)

let host = Host::bind_with_config(addr, config)?;
```

**How it works:**

- Binary search algorithm probes between `pmtu_min` and `pmtu_max`
- Sends `PMTUProbe` commands at configured intervals
- Peer responds with `PMTUReply` for successful probes
- Updates per-peer `fragment_size` based on successful probes
- Handles timeouts by reducing upper bound
- Converges when search range is below threshold

**Benefits:**

- Optimizes bandwidth usage by finding largest usable MTU
- Adapts to network conditions automatically
- Per-peer tuning for heterogeneous networks

**Trade-offs:**

- Adds periodic probe overhead (minimal, configurable)
- Disabled by default for simplicity and backward compatibility

## Disconnect Handling

```rust
// Graceful disconnect
host.disconnect(peer_addr)?;

// Or detect disconnection via events
match host.recv() {
    Some(SocketEvent::Disconnect(addr)) => {
        // Peer gracefully disconnected
    }
    Some(SocketEvent::Timeout(addr)) => {
        // Peer timed out (idle_connection_timeout exceeded)
    }
    _ => {}
}
```

## Configuration

```rust
use std::time::Duration;
use bitwarp::Config;

let mut config = Config::default();

// Connection timeouts
config.idle_connection_timeout = Duration::from_secs(10);
config.heartbeat_interval = Some(Duration::from_secs(1));

// Fragmentation
config.max_packet_size = 32 * 1024;      // 32 KB max
config.fragment_size = 1200;             // 1200 bytes per fragment
config.max_fragments = 255;

// Reliability
config.max_packets_in_flight = 512;
config.rtt_smoothing_factor = 0.1;

// Channels & Bandwidth
config.channel_count = 4;                     // 4 channels per peer
config.outgoing_bandwidth_limit = 50_000;     // 50 KB/sec
config.incoming_bandwidth_limit = 100_000;    // 100 KB/sec

// Compression & Data Integrity
config.compression = CompressionAlgorithm::Lz4;  // Lz4, Zlib, or None (default)
config.compression_threshold = 128;              // Minimum size to compress (default: 128)
config.use_checksums = true;                     // Enable CRC32 checksums (default: false)

let host = Host::bind_with_config("0.0.0.0:7777", config)?;
```

## Packet Types

```rust
// Unreliable (fire-and-forget)
let pkt = Packet::unreliable(addr, data);
let pkt = Packet::unreliable_on_channel(addr, data, channel);

// Unsequenced (prevents duplicates, allows out-of-order)
let pkt = Packet::unsequenced(addr, data);

// Reliable (guaranteed delivery)
let pkt = Packet::reliable_unordered(addr, data);
let pkt = Packet::reliable_on_channel(addr, data, channel);

// Reliable + Ordered (TCP-like)
let pkt = Packet::reliable_ordered(addr, data, None);

// Reliable + Sequenced (latest only)
let pkt = Packet::reliable_sequenced(addr, data, None);
```

## Event Loop Patterns

### Manual Polling (Full Control)

```rust
let mut host = Host::bind_any()?;

loop {
    host.manual_poll(Instant::now());

    while let Some(event) = host.recv() {
        // Handle event
    }

    // Your game/app logic here
    thread::sleep(Duration::from_millis(16));
}
```

### Automatic Polling (Dedicated Thread)

```rust
let mut host = Host::bind_any()?;
let event_rx = host.get_event_receiver();
let packet_tx = host.get_packet_sender();

// Spawn polling thread
thread::spawn(move || {
    host.start_polling();  // Polls every 1ms
});

// Main thread handles events
for event in event_rx.iter() {
    match event {
        SocketEvent::Packet(pkt) => { /* ... */ }
        _ => {}
    }
}
```

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_bandwidth_throttling

# Check code
cargo clippy
cargo fmt --check
```

## Performance Tips

1. **Use unreliable packets** for high-frequency updates (player positions, etc.)
2. **Batch small messages** - protocol automatically batches commands
3. **Adjust fragment size** for your network's MTU (default: 1200 bytes)
4. **Use channels** to prioritize critical vs. bulk traffic
5. **Monitor bandwidth** with `peer.bandwidth_utilization()`

## License

MIT
