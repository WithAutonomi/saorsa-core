// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! # Address Types
//!
//! This module provides address types for the P2P network using IP:port combinations.

use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Network address represented as IP:port
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiAddr {
    /// The socket address (IP + port)
    pub socket_addr: SocketAddr,
}

impl MultiAddr {
    /// Create a new `MultiAddr` from a `SocketAddr`
    #[must_use]
    pub fn new(socket_addr: SocketAddr) -> Self {
        Self { socket_addr }
    }

    /// Create a `MultiAddr` from an IP address and port
    #[must_use]
    pub fn from_ip_port(ip: IpAddr, port: u16) -> Self {
        let socket_addr = SocketAddr::new(ip, port);
        Self::new(socket_addr)
    }

    /// Create a `MultiAddr` from IPv4 address and port
    #[must_use]
    pub fn from_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self::from_ip_port(IpAddr::V4(ip), port)
    }

    /// Create a `MultiAddr` from IPv6 address and port
    #[must_use]
    pub fn from_ipv6(ip: Ipv6Addr, port: u16) -> Self {
        Self::from_ip_port(IpAddr::V6(ip), port)
    }

    /// Get the IP address
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        self.socket_addr.ip()
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.socket_addr.port()
    }

    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        self.socket_addr.is_ipv4()
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        self.socket_addr.is_ipv6()
    }

    /// Check if this is a loopback address
    pub fn is_loopback(&self) -> bool {
        self.socket_addr.ip().is_loopback()
    }

    /// Check if this is a private/local address
    pub fn is_private(&self) -> bool {
        match self.socket_addr.ip() {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(ip) => {
                // Check for unique local addresses (fc00::/7)
                let octets = ip.octets();
                (octets[0] & 0xfe) == 0xfc
            }
        }
    }
}

impl Display for MultiAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.socket_addr)
    }
}

impl FromStr for MultiAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        // First try to parse as a socket address
        if let Ok(socket_addr) = SocketAddr::from_str(s) {
            return Ok(Self::new(socket_addr));
        }

        // Basic MultiAddr support: /ip4/<ip>/<proto>/<port> or /ip6/<ip>/<proto>/<port>
        // Supported protocols: tcp, udp, quic (all resolve to a SocketAddr)
        if s.starts_with("/ip4/") || s.starts_with("/ip6/") {
            let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
            // Expect: ["ip4"|"ip6", ip, "tcp"|"udp"|"quic", port]
            #[allow(clippy::collapsible_if)]
            if parts.len() >= 4
                && (parts[0] == "ip4" || parts[0] == "ip6")
                && matches!(parts[2], "tcp" | "udp" | "quic")
            {
                if let Ok(port) = parts[3].parse::<u16>() {
                    // Parse IP
                    let ip_str = parts[1];
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        let socket_addr = SocketAddr::new(ip, port);
                        return Ok(Self::new(socket_addr));
                    }
                }
            }
        }

        Err(anyhow!("Invalid address format: {}", s))
    }
}

impl From<SocketAddr> for MultiAddr {
    fn from(socket_addr: SocketAddr) -> Self {
        Self::new(socket_addr)
    }
}

impl From<&SocketAddr> for MultiAddr {
    fn from(socket_addr: &SocketAddr) -> Self {
        Self::new(*socket_addr)
    }
}

impl From<MultiAddr> for SocketAddr {
    fn from(addr: MultiAddr) -> Self {
        addr.socket_addr
    }
}

impl From<&MultiAddr> for SocketAddr {
    fn from(addr: &MultiAddr) -> Self {
        addr.socket_addr
    }
}

/// Serde helpers for serializing `MultiAddr` as a plain string.
///
/// Use with `#[serde(with = "crate::address::serde_as_string")]` on fields
/// of type `MultiAddr` to maintain wire-protocol compatibility with
/// code that expects a plain `"ip:port"` string.
pub mod serde_as_string {
    use super::MultiAddr;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(addr: &MultiAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MultiAddr, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<MultiAddr>().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_network_address_creation() {
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
        assert!(addr.is_ipv4());
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_network_address_from_string() {
        let addr = "127.0.0.1:8080".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_network_address_display() {
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        let display = addr.to_string();
        assert!(display.contains("192.168.1.1:9000"));
    }

    #[test]
    fn test_private_address_detection() {
        let private_addr = MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        assert!(private_addr.is_private());

        let public_addr = MultiAddr::from_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        assert!(!public_addr.is_private());
    }

    #[test]
    fn test_ipv6_address() {
        let addr = MultiAddr::from_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080);
        assert!(addr.is_ipv6());
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_multiaddr_tcp_parsing() {
        let addr = "/ip4/192.168.1.1/tcp/9000".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn test_multiaddr_udp_parsing() {
        let addr = "/ip4/127.0.0.1/udp/10000".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 10000);
    }

    #[test]
    fn test_multiaddr_quic_parsing() {
        let addr = "/ip4/10.0.0.1/quic/9000".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn test_multiaddr_ipv6_udp_parsing() {
        let addr = "/ip6/::1/udp/8080".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_serde_as_string_roundtrip() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            #[serde(with = "super::serde_as_string")]
            addr: MultiAddr,
        }

        let original = Wrapper {
            addr: MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000),
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("192.168.1.1:9000"));

        let recovered: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.addr.ip(), original.addr.ip());
        assert_eq!(recovered.addr.port(), original.addr.port());
    }
}
