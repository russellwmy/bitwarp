//! Simple client that sends messages to a Bitwarp server and prints replies.
//!
//! Run the server first:
//! - cargo run -p bitwarp --example server -- 127.0.0.1:7777
//!
//! Then run the client:
//! - cargo run -p bitwarp --example client -- 127.0.0.1:7777
//! - cargo run -p bitwarp --example client -- 127.0.0.1:7777 10 200
//!   (sends 10 messages, 200ms apart)

use std::{
    env,
    net::SocketAddr,
    thread,
    time::{Duration, Instant},
};

use bitwarp::{Host, Packet, SocketEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Args: <server_addr> [count] [interval_ms]
    let mut args = env::args().skip(1);
    let server_addr: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:9000".to_string())
        .parse()?;
    let count: usize = args.next().unwrap_or_else(|| "5".into()).parse().unwrap_or(5);
    let interval_ms: u64 = args
        .next()
        .unwrap_or_else(|| "300".into())
        .parse()
        .unwrap_or(300);

    let mut host = Host::bind_any()?;
    let local = host.local_addr()?;
    println!(
        "Bitwarp client bound to {} -> sending {} messages to {} (every {}ms)",
        local, count, server_addr, interval_ms
    );

    for i in 0..count {
        let msg = format!("hello {} from {}", i, local);
        let pkt = Packet::reliable_unordered(server_addr, msg.clone().into_bytes());
        host.send(pkt)?;

        let start = Instant::now();
        let wait = Duration::from_millis(interval_ms);

        while start.elapsed() < wait {
            host.manual_poll(Instant::now());

            while let Some(event) = host.recv() {
                match event {
                    SocketEvent::Connect(addr) => {
                        println!("[connect] {}", addr);
                    }
                    SocketEvent::Packet(pkt) => {
                        let text = String::from_utf8_lossy(pkt.payload());
                        println!(
                            "[reply] from={} channel={} delivery={:?} ordering={:?} payload=\"{}\"",
                            pkt.addr(),
                            pkt.channel_id(),
                            pkt.delivery_guarantee(),
                            pkt.order_guarantee(),
                            text
                        );
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

    println!("done");
    Ok(())
}

