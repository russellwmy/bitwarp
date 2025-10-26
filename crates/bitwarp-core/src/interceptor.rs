//! Packet interception for custom processing.
//!
//! This module provides a trait for intercepting raw UDP packets before/after processing.
//! Useful for custom encryption, logging, packet inspection, and analytics.

use std::net::SocketAddr;

/// Trait for intercepting packets before/after processing.
///
/// Interceptors can inspect, modify, or drop packets at the raw UDP level.
/// This is useful for implementing custom encryption, logging, analytics, or packet inspection.
///
/// # Examples
/// ```
/// use std::net::SocketAddr;
/// use bitwarp_core::interceptor::Interceptor;
///
/// struct LoggingInterceptor;
///
/// impl Interceptor for LoggingInterceptor {
///     fn on_receive(&mut self, _addr: &SocketAddr, data: &mut [u8]) -> bool {
///         println!("Received {} bytes", data.len());
///         true // Continue processing
///     }
///
///     fn on_send(&mut self, _addr: &SocketAddr, data: &mut Vec<u8>) -> bool {
///         println!("Sending {} bytes", data.len());
///         true // Continue sending
///     }
/// }
/// ```
pub trait Interceptor: Send {
    /// Called when a packet is received from the network, before protocol processing.
    ///
    /// # Arguments
    /// * `addr` - The source address of the packet
    /// * `data` - The raw packet data (mutable, can be modified)
    ///
    /// # Returns
    /// * `true` - Continue processing the packet
    /// * `false` - Drop the packet (do not process)
    fn on_receive(&mut self, addr: &SocketAddr, data: &mut [u8]) -> bool;

    /// Called when a packet is about to be sent to the network, after protocol encoding.
    ///
    /// # Arguments
    /// * `addr` - The destination address of the packet
    /// * `data` - The raw packet data (mutable, can be modified or resized)
    ///
    /// # Returns
    /// * `true` - Continue sending the packet
    /// * `false` - Drop the packet (do not send)
    fn on_send(&mut self, addr: &SocketAddr, data: &mut Vec<u8>) -> bool;
}

/// No-op interceptor that passes all packets through unchanged.
///
/// This is the default interceptor when none is specified.
#[derive(Debug, Clone, Copy)]
pub struct NoOpInterceptor;

impl Interceptor for NoOpInterceptor {
    fn on_receive(&mut self, _addr: &SocketAddr, _data: &mut [u8]) -> bool {
        true
    }

    fn on_send(&mut self, _addr: &SocketAddr, _data: &mut Vec<u8>) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct CountingInterceptor {
        received: usize,
        sent: usize,
    }

    impl Interceptor for CountingInterceptor {
        fn on_receive(&mut self, _addr: &SocketAddr, _data: &mut [u8]) -> bool {
            self.received += 1;
            true
        }

        fn on_send(&mut self, _addr: &SocketAddr, _data: &mut Vec<u8>) -> bool {
            self.sent += 1;
            true
        }
    }

    #[test]
    fn test_counting_interceptor() {
        let mut interceptor = CountingInterceptor { received: 0, sent: 0 };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut data = vec![1, 2, 3];
        assert!(interceptor.on_receive(&addr, &mut data));
        assert_eq!(interceptor.received, 1);

        assert!(interceptor.on_send(&addr, &mut data));
        assert_eq!(interceptor.sent, 1);
    }

    struct DroppingInterceptor;

    impl Interceptor for DroppingInterceptor {
        fn on_receive(&mut self, _addr: &SocketAddr, _data: &mut [u8]) -> bool {
            false // Drop all received packets
        }

        fn on_send(&mut self, _addr: &SocketAddr, _data: &mut Vec<u8>) -> bool {
            false // Drop all sent packets
        }
    }

    #[test]
    fn test_dropping_interceptor() {
        let mut interceptor = DroppingInterceptor;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut data = vec![1, 2, 3];
        assert!(!interceptor.on_receive(&addr, &mut data));
        assert!(!interceptor.on_send(&addr, &mut data));
    }

    struct ModifyingInterceptor;

    impl Interceptor for ModifyingInterceptor {
        fn on_receive(&mut self, _addr: &SocketAddr, data: &mut [u8]) -> bool {
            // XOR decrypt
            for byte in data.iter_mut() {
                *byte ^= 0x55;
            }
            true
        }

        fn on_send(&mut self, _addr: &SocketAddr, data: &mut Vec<u8>) -> bool {
            // XOR encrypt
            for byte in data.iter_mut() {
                *byte ^= 0x55;
            }
            true
        }
    }

    #[test]
    fn test_modifying_interceptor() {
        let mut interceptor = ModifyingInterceptor;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut data = vec![0xAA, 0xBB, 0xCC];
        let original = data.clone();

        assert!(interceptor.on_send(&addr, &mut data));
        assert_ne!(data, original); // Should be modified

        assert!(interceptor.on_receive(&addr, &mut data));
        assert_eq!(data, original); // Should be decrypted back
    }

    #[test]
    fn test_noop_interceptor() {
        let mut interceptor = NoOpInterceptor;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let mut data = vec![1, 2, 3];
        let original = data.clone();

        assert!(interceptor.on_receive(&addr, &mut data));
        assert_eq!(data, original);

        assert!(interceptor.on_send(&addr, &mut data));
        assert_eq!(data, original);
    }
}
