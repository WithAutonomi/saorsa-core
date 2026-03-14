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

//! Transport Layer
//!
//! This module provides native saorsa-transport integration for the P2P Foundation.
//!
//! Use `saorsa_transport_adapter::P2PNetworkNode` directly for all networking needs.

// Native saorsa-transport integration with advanced NAT traversal and PQC support
pub mod saorsa_transport_adapter;

// DHT protocol handler for SharedTransport integration
pub mod dht_handler;

// Network binding and NAT traversal configuration (moved from messaging)
pub mod network_config;

pub use network_config::NetworkConfig;

use crate::validation::{Validate, ValidationContext, validate_message_size};
use crate::{P2PError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Transport protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TransportType {
    /// QUIC transport protocol with NAT traversal
    QUIC,
}

/// Transport selection strategy (simplified for QUIC-only)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[allow(dead_code)]
pub enum TransportSelection {
    /// Use QUIC transport (default and only option)
    #[default]
    QUIC,
}

/// Connection quality metrics
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectionQuality {
    /// Round-trip latency
    pub latency: Duration,
    /// Throughput in Mbps
    pub throughput_mbps: f64,
    /// Packet loss percentage
    pub packet_loss: f64,
    /// Jitter (latency variation)
    pub jitter: Duration,
    /// Connection establishment time
    pub connect_time: Duration,
}

/// Connection information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectionInfo {
    /// Transport type being used
    pub transport_type: TransportType,
    /// Local address
    pub local_addr: crate::MultiAddr,
    /// Remote address
    pub remote_addr: crate::MultiAddr,
    /// Whether connection is encrypted
    pub is_encrypted: bool,
    /// Cipher suite being used
    pub cipher_suite: String,
    /// Whether 0-RTT was used
    pub used_0rtt: bool,
    /// Connection establishment time
    pub established_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
}

/// Connection pool information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectionPoolInfo {
    /// Number of active connections
    pub active_connections: usize,
    /// Total connections ever created
    pub total_connections: usize,
    /// Bytes sent through pool
    pub bytes_sent: u64,
    /// Bytes received through pool
    pub bytes_received: u64,
}

/// Connection pool statistics
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConnectionPoolStats {
    /// Messages sent per connection
    pub messages_per_connection: HashMap<String, usize>,
    /// Bytes per connection
    pub bytes_per_connection: HashMap<String, u64>,
    /// Average latency per connection
    pub latency_per_connection: HashMap<String, Duration>,
}

/// Message received from transport
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TransportMessage {
    /// Sender peer ID
    pub sender: crate::PeerId,
    /// Message data
    pub data: Vec<u8>,
    /// Protocol identifier
    pub protocol: String,
    /// Timestamp when received
    pub received_at: Instant,
}

impl Validate for TransportMessage {
    fn validate(&self, ctx: &ValidationContext) -> Result<()> {
        // Validate message size
        validate_message_size(self.data.len(), ctx.max_message_size)?;

        // Validate protocol identifier
        if self.protocol.is_empty() || self.protocol.len() > 64 {
            return Err(P2PError::validation("Invalid protocol identifier"));
        }

        Ok(())
    }
}

/// Transport configuration options
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TransportOptions {
    /// Enable 0-RTT for QUIC
    pub enable_0rtt: bool,
    /// Force encryption
    pub require_encryption: bool,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive: Duration,
    /// Maximum message size
    pub max_message_size: usize,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::QUIC => write!(f, "quic"),
        }
    }
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            enable_0rtt: true,
            require_encryption: true,
            connect_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(60),
            max_message_size: 64 * 1024 * 1024, // 64MB
        }
    }
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(50),
            throughput_mbps: 100.0,
            packet_loss: 0.0,
            jitter: Duration::from_millis(5),
            connect_time: Duration::from_millis(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_type_display() {
        assert_eq!(format!("{}", TransportType::QUIC), "quic");
    }

    #[test]
    fn test_transport_type_serialization() {
        let quic_type = TransportType::QUIC;
        assert_eq!(quic_type, TransportType::QUIC);
    }

    #[test]
    fn test_transport_selection_variants() {
        let quic_selection = TransportSelection::QUIC;
        assert!(matches!(quic_selection, TransportSelection::QUIC));
    }

    #[test]
    fn test_transport_selection_default() {
        let default = TransportSelection::default();
        assert!(matches!(default, TransportSelection::QUIC));
    }

    #[test]
    fn test_transport_options_default() {
        let options = TransportOptions::default();

        assert!(options.enable_0rtt);
        assert!(options.require_encryption);
        assert_eq!(options.connect_timeout, Duration::from_secs(30));
        assert_eq!(options.keep_alive, Duration::from_secs(60));
        assert_eq!(options.max_message_size, 64 * 1024 * 1024);
    }

    #[test]
    fn test_connection_quality_default() {
        let quality = ConnectionQuality::default();

        assert_eq!(quality.latency, Duration::from_millis(50));
        assert_eq!(quality.throughput_mbps, 100.0);
        assert_eq!(quality.packet_loss, 0.0);
        assert_eq!(quality.jitter, Duration::from_millis(5));
        assert_eq!(quality.connect_time, Duration::from_millis(100));
    }

    #[test]
    fn test_transport_options_configuration() {
        let options = TransportOptions {
            enable_0rtt: false,
            require_encryption: false,
            connect_timeout: Duration::from_secs(10),
            keep_alive: Duration::from_secs(30),
            max_message_size: 1024,
        };

        assert!(!options.enable_0rtt);
        assert!(!options.require_encryption);
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.keep_alive, Duration::from_secs(30));
        assert_eq!(options.max_message_size, 1024);
    }

    #[test]
    fn test_transport_message_structure() {
        let message = TransportMessage {
            sender: crate::PeerId::from_name("test_peer"),
            data: vec![1, 2, 3, 4],
            protocol: "/p2p/test/1.0.0".to_string(),
            received_at: Instant::now(),
        };

        assert_eq!(message.sender, crate::PeerId::from_name("test_peer"));
        assert_eq!(message.data, vec![1, 2, 3, 4]);
        assert_eq!(message.protocol, "/p2p/test/1.0.0");
    }
}
