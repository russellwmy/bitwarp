//! Utility functions for Bitwarp networking.
//!
//! This crate provides optional convenience utilities for working with Bitwarp:
//!
//! ## Address Utilities
//! Address utilities for DNS and IP operations:
//! - DNS resolution (hostname to IP)
//! - Reverse DNS lookup (IP to hostname)
//! - IP string parsing and formatting
//!
//! These utilities are provided as a separate crate to keep the core library dependency-free.

use std::{
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
};

/// Resolves a hostname to a socket address using DNS.
///
/// # Arguments
/// * `hostname` - The hostname to resolve (e.g., "example.com")
/// * `port` - The port number to use
///
/// # Returns
/// The first resolved socket address, or an error if resolution fails.
///
/// # Examples
/// ```no_run
/// use bitwarp_utilities::resolve_host;
///
/// let addr = resolve_host("localhost", 8080).unwrap();
/// assert_eq!(addr.port(), 8080);
/// ```
pub fn resolve_host(hostname: &str, port: u16) -> io::Result<SocketAddr> {
    let addr_str = format!("{}:{}", hostname, port);
    addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not resolve hostname"))
}

/// Performs reverse DNS lookup to get the hostname for an IP address.
///
/// # Arguments
/// * `addr` - The socket address to lookup
///
/// # Returns
/// The hostname if lookup succeeds, or an error if it fails.
///
/// # Examples
/// ```no_run
/// use bitwarp_utilities::reverse_lookup;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
/// let hostname = reverse_lookup(&ip).unwrap();
/// println!("Hostname: {}", hostname);
/// ```
pub fn reverse_lookup(addr: &IpAddr) -> io::Result<String> {
    // Rust's std library doesn't have built-in reverse DNS in a cross-platform way
    // We use dns_lookup crate which provides cross-platform reverse DNS lookup
    dns_lookup::lookup_addr(addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Parses an IP address string (without DNS resolution) to a socket address.
///
/// # Arguments
/// * `ip_str` - The IP address string (e.g., "192.168.1.1" or "::1")
/// * `port` - The port number to use
///
/// # Returns
/// A socket address if parsing succeeds, or an error if the string is invalid.
///
/// # Examples
/// ```
/// use bitwarp_utilities::parse_ip;
///
/// let addr = parse_ip("127.0.0.1", 8080).unwrap();
/// assert_eq!(addr.port(), 8080);
/// assert_eq!(addr.ip().to_string(), "127.0.0.1");
/// ```
pub fn parse_ip(ip_str: &str, port: u16) -> io::Result<SocketAddr> {
    let ip: IpAddr = ip_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid IP address: {}", e),
        )
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// Formats a socket address to an IP string (without reverse DNS lookup).
///
/// # Arguments
/// * `addr` - The socket address to format
///
/// # Returns
/// The IP address as a string (e.g., "192.168.1.1" or "::1").
///
/// # Examples
/// ```
/// use bitwarp_utilities::format_ip;
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
/// let ip_str = format_ip(&addr);
/// assert_eq!(ip_str, "127.0.0.1");
/// ```
pub fn format_ip(addr: &SocketAddr) -> String {
    addr.ip().to_string()
}

/// Formats an IP address to a string.
///
/// Convenience function for formatting an `IpAddr` directly.
///
/// # Arguments
/// * `ip` - The IP address to format
///
/// # Returns
/// The IP address as a string.
///
/// # Examples
/// ```
/// use bitwarp_utilities::format_ip_addr;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
/// let ip_str = format_ip_addr(&ip);
/// assert_eq!(ip_str, "192.168.1.1");
/// ```
pub fn format_ip_addr(ip: &IpAddr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_ipv4() {
        let addr = parse_ip("192.168.1.1", 8080).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_parse_ipv6() {
        let addr = parse_ip("::1", 8080).unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_parse_invalid_ip() {
        let result = parse_ip("not-an-ip", 8080);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let ip_str = format_ip(&addr);
        assert_eq!(ip_str, "127.0.0.1");
    }

    #[test]
    fn test_format_ipv6() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);
        let ip_str = format_ip(&addr);
        assert_eq!(ip_str, "::1");
    }

    #[test]
    fn test_format_ip_addr() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip_str = format_ip_addr(&ip);
        assert_eq!(ip_str, "192.168.1.1");
    }

    #[test]
    fn test_resolve_localhost() {
        // This should work on all platforms
        let addr = resolve_host("localhost", 8080).unwrap();
        assert_eq!(addr.port(), 8080);
        // Localhost can resolve to either 127.0.0.1 or ::1
        assert!(
            addr.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
                || addr.ip() == IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_resolve_with_ip_string() {
        // Resolving an IP string should also work (no actual DNS lookup needed)
        let addr = resolve_host("127.0.0.1", 8080).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_resolve_invalid_host() {
        // This hostname should not exist
        let result = resolve_host("this-hostname-should-not-exist-12345.invalid", 8080);
        assert!(result.is_err());
    }

    // Note: reverse_lookup tests are not included here because they require
    // a network connection and proper DNS setup, which may not be available
    // in all testing environments. Users can test this manually or in
    // integration tests.
}
