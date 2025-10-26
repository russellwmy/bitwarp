//! Transport abstraction for pluggable I/O.

use std::{io::Result, net::SocketAddr};

/// Low-level datagram socket abstraction.
///
/// This trait allows various transports (UDP, emulator, etc.) to be plugged
/// into the connection manager without coupling to a concrete implementation.
pub trait Socket {
    /// Sends a single packet to the socket.
    fn send_packet(&mut self, addr: &SocketAddr, payload: &[u8]) -> Result<usize>;

    /// Receives a single packet from the socket.
    fn receive_packet<'a>(&mut self, buffer: &'a mut [u8]) -> Result<(&'a [u8], SocketAddr)>;

    /// Returns the socket address that this socket was created from.
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Returns whether socket operates in blocking or non-blocking mode.
    fn is_blocking_mode(&self) -> bool;
}
