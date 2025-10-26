//! Simple echo server using Bitwarp.
//!
//! Run:
//! - cargo run -p bitwarp --example server
//! - cargo run -p bitwarp --example server -- 127.0.0.1:7777

use std::{
    env,
    net::SocketAddr,
    thread,
    time::{Duration, Instant},
};

use bitwarp::{Config, Host, Packet, SocketEvent};

fn parse_bind_addr() -> Option<SocketAddr> {
    let mut args = env::args().skip(1);
    args.next().and_then(|s| s.parse().ok())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic config; tweak here if you want to demo features quickly
    let mut config = Config::default();
    // Uncomment to try features:
    // config.compression = CompressionAlgorithm::Lz4;
    // config.use_checksums = true;
    // config.channel_count = 4;

    let bind_addr = parse_bind_addr().unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
    let mut host = Host::bind_with_config(bind_addr, config)?;
    let local = host.local_addr()?;
    println!("Bitwarp echo server listening on {}", local);
    println!("Send from client example to this address to see echoes.");

    loop {
        host.manual_poll(Instant::now());

        while let Some(event) = host.recv() {
            match event {
                SocketEvent::Connect(addr) => {
                    println!("[connect] {}", addr);
                }
                SocketEvent::Packet(pkt) => {
                    let text = String::from_utf8_lossy(pkt.payload());
                    println!(
                        "[packet] from={} channel={} delivery={:?} ordering={:?} payload=\"{}\"",
                        pkt.addr(),
                        pkt.channel_id(),
                        pkt.delivery_guarantee(),
                        pkt.order_guarantee(),
                        text
                    );

                    // Echo back using the same guarantees and channel id
                    let echo = Packet::new(
                        pkt.addr(),
                        pkt.payload_arc(),
                        pkt.delivery_guarantee(),
                        pkt.order_guarantee(),
                        pkt.channel_id(),
                    );
                    if let Err(e) = host.send(echo) {
                        eprintln!("failed to queue echo: {}", e);
                    }
                }
                SocketEvent::Disconnect(addr) => {
                    println!("[disconnect] {}", addr);
                }
                SocketEvent::Timeout(addr) => {
                    println!("[timeout] {}", addr);
                }
            }
        }

        thread::sleep(Duration::from_millis(10));
    }
}
