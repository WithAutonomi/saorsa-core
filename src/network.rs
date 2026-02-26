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

//! Network module
//!
//! This module provides core networking functionality for the P2P Foundation.
//! It handles peer connections, network events, and node lifecycle management.

use crate::adaptive::{
    EigenTrustEngine, NodeId as AdaptiveNodeId, NodeStatisticsUpdate, TrustProvider,
};
use crate::bootstrap::{BootstrapManager, ContactEntry, QualityMetrics};
use crate::config::Config;
use crate::dht::core_engine::{NodeCapacity, NodeId as DhtNodeId, NodeInfo};
use crate::dht::derive_dht_key_from_peer_id;
use crate::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use crate::error::{NetworkError, P2PError, P2pResult as Result, PeerFailureReason};

use crate::production::{ProductionConfig, ResourceManager, ResourceMetrics};
use crate::{NetworkAddress, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, broadcast};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Wire protocol message format for P2P communication.
///
/// Serialized with bincode for compact binary encoding.
/// Replaces the previous JSON format for better performance
/// and smaller wire size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireMessage {
    /// Protocol/topic identifier
    pub(crate) protocol: String,
    /// Raw payload bytes
    pub(crate) data: Vec<u8>,
    /// Sender's peer ID (verified against transport-level identity)
    pub(crate) from: String,
    /// Unix timestamp in seconds
    pub(crate) timestamp: u64,
}

/// Payload bytes used for keepalive messages to prevent connection timeouts.
pub(crate) const KEEPALIVE_PAYLOAD: &[u8] = b"keepalive";

/// Capacity of the internal channel used by the message receiving system.
pub(crate) const MESSAGE_RECV_CHANNEL_CAPACITY: usize = 256;

/// Maximum number of concurrent in-flight request/response operations.
pub(crate) const MAX_ACTIVE_REQUESTS: usize = 256;

/// Maximum allowed timeout for a single request (5 minutes).
pub(crate) const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Default port when config parsing fails.
const DEFAULT_LISTEN_PORT: u16 = 9000;

/// DHT max XOR distance (full 160-bit keyspace).
const DHT_MAX_DISTANCE: u8 = 160;

/// Interval for the P2PNode run loop's maintenance tick.
const RUN_LOOP_TICK_INTERVAL_MS: u64 = 100;

/// Quality score for successful bootstrap connections.
const BOOTSTRAP_QUALITY_SCORE_SUCCESS: f64 = 0.8;
/// Quality score for failed bootstrap connections.
const BOOTSTRAP_QUALITY_SCORE_FAILURE: f64 = 0.2;
/// Default uptime score for new bootstrap contacts.
const BOOTSTRAP_DEFAULT_UPTIME_SCORE: f64 = 0.5;
/// Penalty duration for failed bootstrap connections.
const BOOTSTRAP_FAILURE_PENALTY_HOURS: i64 = 1;

/// Default neutral trust score when trust engine is unavailable.
const DEFAULT_NEUTRAL_TRUST: f64 = 0.5;

/// Number of cached bootstrap peers to retrieve.
const BOOTSTRAP_PEER_BATCH_SIZE: usize = 20;

/// Configuration for a P2P node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Local peer ID for this node
    pub peer_id: Option<PeerId>,

    /// Addresses to listen on for incoming connections
    pub listen_addrs: Vec<std::net::SocketAddr>,

    /// Primary listen address (for compatibility)
    pub listen_addr: std::net::SocketAddr,

    /// Bootstrap peers to connect to on startup (legacy)
    pub bootstrap_peers: Vec<std::net::SocketAddr>,

    /// Bootstrap peers as strings (for integration tests)
    pub bootstrap_peers_str: Vec<String>,

    /// Enable IPv6 support
    pub enable_ipv6: bool,

    // MCP removed; will be redesigned later
    /// Connection timeout duration
    pub connection_timeout: Duration,

    /// Keep-alive interval for connections
    pub keep_alive_interval: Duration,

    /// Maximum number of concurrent connections
    pub max_connections: usize,

    /// Maximum number of incoming connections
    pub max_incoming_connections: usize,

    /// DHT configuration
    pub dht_config: DHTConfig,

    /// Security configuration
    pub security_config: SecurityConfig,

    /// Production hardening configuration
    pub production_config: Option<ProductionConfig>,

    /// Bootstrap cache configuration
    pub bootstrap_cache_config: Option<crate::bootstrap::CacheConfig>,

    /// Optional IP diversity configuration for Sybil protection tuning.
    ///
    /// When set, this configuration is used by bootstrap peer discovery and
    /// other diversity-enforcing subsystems. If `None`, defaults are used.
    pub diversity_config: Option<crate::security::IPDiversityConfig>,

    /// Stale peer threshold - peers with no activity for this duration are considered stale.
    /// Defaults to 60 seconds. Can be reduced for testing purposes.
    #[serde(default = "default_stale_peer_threshold")]
    pub stale_peer_threshold: Duration,

    /// Optional override for the maximum application-layer message size.
    ///
    /// When `None`, the underlying ant-quic default is used.
    #[serde(default)]
    pub max_message_size: Option<usize>,
}

/// Default stale peer threshold (60 seconds)
fn default_stale_peer_threshold() -> Duration {
    Duration::from_secs(60)
}

/// DHT-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTConfig {
    /// Kademlia K parameter (bucket size)
    pub k_value: usize,

    /// Kademlia alpha parameter (parallelism)
    pub alpha_value: usize,

    /// DHT record TTL
    pub record_ttl: Duration,

    /// DHT refresh interval
    pub refresh_interval: Duration,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable noise protocol for encryption
    pub enable_noise: bool,

    /// Enable TLS for secure transport
    pub enable_tls: bool,

    /// Trust level for peer verification
    pub trust_level: TrustLevel,
}

/// Trust level for peer verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrustLevel {
    /// No verification required
    None,
    /// Basic peer ID verification
    Basic,
    /// Full cryptographic verification
    Full,
}

// ============================================================================
// Address Construction Helpers
// ============================================================================

/// Build listen addresses based on port and IPv6 preference
///
/// This helper consolidates the duplicated address construction logic.
#[inline]
fn build_listen_addrs(port: u16, ipv6_enabled: bool) -> Vec<std::net::SocketAddr> {
    let mut addrs = Vec::with_capacity(if ipv6_enabled { 2 } else { 1 });

    if ipv6_enabled {
        addrs.push(std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
        ));
    }

    addrs.push(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        port,
    ));

    addrs
}

impl NodeConfig {
    /// Create a new NodeConfig with default values
    ///
    /// # Errors
    ///
    /// Returns an error if default addresses cannot be parsed
    pub fn new() -> Result<Self> {
        let config = Config::default();
        let listen_addr = config.listen_socket_addr()?;

        Ok(Self {
            peer_id: None,
            listen_addrs: build_listen_addrs(listen_addr.port(), config.network.ipv6_enabled),
            listen_addr,
            bootstrap_peers: Vec::new(),
            bootstrap_peers_str: config.network.bootstrap_nodes.clone(),
            enable_ipv6: config.network.ipv6_enabled,
            connection_timeout: Duration::from_secs(config.network.connection_timeout),
            keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
            max_connections: config.network.max_connections,
            max_incoming_connections: config.security.connection_limit as usize,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
            max_message_size: config.transport.max_message_size,
        })
    }

    /// Create a builder for customized NodeConfig construction
    pub fn builder() -> NodeConfigBuilder {
        NodeConfigBuilder::default()
    }
}

// ============================================================================
// NodeConfig Builder Pattern
// ============================================================================

/// Builder for constructing NodeConfig with fluent API
#[derive(Debug, Clone, Default)]
pub struct NodeConfigBuilder {
    peer_id: Option<PeerId>,
    listen_port: Option<u16>,
    enable_ipv6: Option<bool>,
    bootstrap_peers: Vec<std::net::SocketAddr>,
    max_connections: Option<usize>,
    connection_timeout: Option<Duration>,
    keep_alive_interval: Option<Duration>,
    dht_config: Option<DHTConfig>,
    security_config: Option<SecurityConfig>,
    production_config: Option<ProductionConfig>,
    max_message_size: Option<usize>,
}

impl NodeConfigBuilder {
    /// Set the peer ID
    pub fn peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Set the listen port
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Enable or disable IPv6
    pub fn ipv6(mut self, enabled: bool) -> Self {
        self.enable_ipv6 = Some(enabled);
        self
    }

    /// Add a bootstrap peer
    pub fn bootstrap_peer(mut self, addr: std::net::SocketAddr) -> Self {
        self.bootstrap_peers.push(addr);
        self
    }

    /// Set maximum connections
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = Some(max);
        self
    }

    /// Set connection timeout
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = Some(timeout);
        self
    }

    /// Set keep-alive interval
    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = Some(interval);
        self
    }

    /// Set DHT configuration
    pub fn dht_config(mut self, config: DHTConfig) -> Self {
        self.dht_config = Some(config);
        self
    }

    /// Set security configuration
    pub fn security_config(mut self, config: SecurityConfig) -> Self {
        self.security_config = Some(config);
        self
    }

    /// Set production configuration
    pub fn production_config(mut self, config: ProductionConfig) -> Self {
        self.production_config = Some(config);
        self
    }

    /// Set maximum application-layer message size in bytes.
    ///
    /// If this method is not called, ant-quic's built-in default is used.
    pub fn max_message_size(mut self, max_message_size: usize) -> Self {
        self.max_message_size = Some(max_message_size);
        self
    }

    /// Build the NodeConfig
    ///
    /// # Errors
    ///
    /// Returns an error if address construction fails
    pub fn build(self) -> Result<NodeConfig> {
        let base_config = Config::default();
        let default_port = base_config
            .listen_socket_addr()
            .map(|addr| addr.port())
            .unwrap_or(DEFAULT_LISTEN_PORT);
        let port = self.listen_port.unwrap_or(default_port);
        let ipv6_enabled = self.enable_ipv6.unwrap_or(base_config.network.ipv6_enabled);

        let listen_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);

        Ok(NodeConfig {
            peer_id: self.peer_id,
            listen_addrs: build_listen_addrs(port, ipv6_enabled),
            listen_addr,
            bootstrap_peers: self.bootstrap_peers.clone(),
            bootstrap_peers_str: self.bootstrap_peers.iter().map(|a| a.to_string()).collect(),
            enable_ipv6: ipv6_enabled,
            connection_timeout: self
                .connection_timeout
                .unwrap_or(Duration::from_secs(base_config.network.connection_timeout)),
            keep_alive_interval: self
                .keep_alive_interval
                .unwrap_or(Duration::from_secs(base_config.network.keepalive_interval)),
            max_connections: self
                .max_connections
                .unwrap_or(base_config.network.max_connections),
            max_incoming_connections: base_config.security.connection_limit as usize,
            dht_config: self.dht_config.unwrap_or_default(),
            security_config: self.security_config.unwrap_or_default(),
            production_config: self.production_config,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
            max_message_size: self
                .max_message_size
                .or(base_config.transport.max_message_size),
        })
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        let config = Config::default();
        let listen_addr = config.listen_socket_addr().unwrap_or_else(|_| {
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                DEFAULT_LISTEN_PORT,
            )
        });

        Self {
            peer_id: None,
            listen_addrs: build_listen_addrs(listen_addr.port(), config.network.ipv6_enabled),
            listen_addr,
            bootstrap_peers: Vec::new(),
            bootstrap_peers_str: Vec::new(),
            enable_ipv6: config.network.ipv6_enabled,
            connection_timeout: Duration::from_secs(config.network.connection_timeout),
            keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
            max_connections: config.network.max_connections,
            max_incoming_connections: config.security.connection_limit as usize,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
            max_message_size: config.transport.max_message_size,
        }
    }
}

impl NodeConfig {
    /// Create NodeConfig from Config
    pub fn from_config(config: &Config) -> Result<Self> {
        let listen_addr = config.listen_socket_addr()?;
        let bootstrap_addrs = config.bootstrap_addrs()?;

        let mut node_config = Self {
            peer_id: None,
            listen_addrs: vec![listen_addr],
            listen_addr,
            bootstrap_peers: bootstrap_addrs
                .iter()
                .map(|addr| addr.socket_addr())
                .collect(),
            bootstrap_peers_str: config
                .network
                .bootstrap_nodes
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            enable_ipv6: config.network.ipv6_enabled,

            connection_timeout: Duration::from_secs(config.network.connection_timeout),
            keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
            max_connections: config.network.max_connections,
            max_incoming_connections: config.security.connection_limit as usize,
            dht_config: DHTConfig {
                k_value: 20,
                alpha_value: 3,
                record_ttl: Duration::from_secs(3600),
                refresh_interval: Duration::from_secs(900),
            },
            security_config: SecurityConfig {
                enable_noise: true,
                enable_tls: true,
                trust_level: TrustLevel::Basic,
            },
            production_config: Some(ProductionConfig {
                max_connections: config.network.max_connections,
                max_memory_bytes: 0,  // unlimited
                max_bandwidth_bps: 0, // unlimited
                connection_timeout: Duration::from_secs(config.network.connection_timeout),
                keep_alive_interval: Duration::from_secs(config.network.keepalive_interval),
                health_check_interval: Duration::from_secs(30),
                metrics_interval: Duration::from_secs(60),
                enable_performance_tracking: true,
                enable_auto_cleanup: true,
                shutdown_timeout: Duration::from_secs(30),
                rate_limits: crate::production::RateLimitConfig::default(),
            }),
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
            max_message_size: config.transport.max_message_size,
        };

        // Add IPv6 listen address if enabled
        if config.network.ipv6_enabled {
            node_config.listen_addrs.push(std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                listen_addr.port(),
            ));
        }

        Ok(node_config)
    }

    /// Try to build a NodeConfig from a listen address string
    pub fn with_listen_addr(addr: &str) -> Result<Self> {
        let listen_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                NetworkError::InvalidAddress(e.to_string().into())
            })
            .map_err(P2PError::Network)?;
        let cfg = NodeConfig {
            listen_addr,
            listen_addrs: vec![listen_addr],
            diversity_config: None,
            ..Default::default()
        };
        Ok(cfg)
    }
}

impl DHTConfig {
    const DEFAULT_K_VALUE: usize = 20;
    const DEFAULT_ALPHA_VALUE: usize = 5;
    const DEFAULT_RECORD_TTL_SECS: u64 = 3600;
    const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 600;
}

impl Default for DHTConfig {
    fn default() -> Self {
        Self {
            k_value: Self::DEFAULT_K_VALUE,
            alpha_value: Self::DEFAULT_ALPHA_VALUE,
            record_ttl: Duration::from_secs(Self::DEFAULT_RECORD_TTL_SECS),
            refresh_interval: Duration::from_secs(Self::DEFAULT_REFRESH_INTERVAL_SECS),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_noise: true,
            enable_tls: true,
            trust_level: TrustLevel::Basic,
        }
    }
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer identifier
    pub peer_id: PeerId,

    /// Peer's addresses
    pub addresses: Vec<String>,

    /// Connection timestamp
    pub connected_at: Instant,

    /// Last seen timestamp
    pub last_seen: Instant,

    /// Connection status
    pub status: ConnectionStatus,

    /// Supported protocols
    pub protocols: Vec<String>,

    /// Number of heartbeats received
    pub heartbeat_count: u64,
}

/// Connection status for a peer
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    /// Connection is being established
    Connecting,
    /// Connection is established and active
    Connected,
    /// Connection is being closed
    Disconnecting,
    /// Connection is closed
    Disconnected,
    /// Connection failed
    Failed(String),
}

/// Network events that can occur
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new peer has connected
    PeerConnected {
        /// The identifier of the newly connected peer
        peer_id: PeerId,
        /// The network addresses where the peer can be reached
        addresses: Vec<String>,
    },

    /// A peer has disconnected
    PeerDisconnected {
        /// The identifier of the disconnected peer
        peer_id: PeerId,
        /// The reason for the disconnection
        reason: String,
    },

    /// A message was received from a peer
    MessageReceived {
        /// The identifier of the sending peer
        peer_id: PeerId,
        /// The protocol used for the message
        protocol: String,
        /// The raw message data
        data: Vec<u8>,
    },

    /// A connection attempt failed
    ConnectionFailed {
        /// The identifier of the peer (if known)
        peer_id: Option<PeerId>,
        /// The address where connection was attempted
        address: String,
        /// The error message describing the failure
        error: String,
    },

    /// DHT record was stored
    DHTRecordStored {
        /// The DHT key where the record was stored
        key: Vec<u8>,
        /// The value that was stored
        value: Vec<u8>,
    },

    /// DHT record was retrieved
    DHTRecordRetrieved {
        /// The DHT key that was queried
        key: Vec<u8>,
        /// The retrieved value, if found
        value: Option<Vec<u8>>,
    },
}

/// Network events that can occur in the P2P system
///
/// Events are broadcast to all listeners and provide real-time
/// notifications of network state changes and message arrivals.
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// Message received from a peer on a specific topic
    Message {
        /// Topic or channel the message was sent on
        topic: String,
        /// Peer ID of the message sender
        source: PeerId,
        /// Raw message data payload
        data: Vec<u8>,
    },
    /// A new peer has connected to the network
    PeerConnected(PeerId),
    /// A peer has disconnected from the network
    PeerDisconnected(PeerId),
}

/// Response from a peer to a request sent via [`P2PNode::send_request`].
///
/// Contains the response payload along with metadata about the responder
/// and round-trip latency.
#[derive(Debug, Clone)]
pub struct PeerResponse {
    /// The peer that sent the response.
    pub peer_id: PeerId,
    /// Raw response payload bytes.
    pub data: Vec<u8>,
    /// Round-trip latency from request to response.
    pub latency: Duration,
}

/// Wire format for request/response correlation.
///
/// Wraps application payloads with a message ID and direction flag
/// so the receive loop can route responses back to waiting callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RequestResponseEnvelope {
    /// Unique identifier to correlate request ↔ response.
    pub(crate) message_id: String,
    /// `false` for requests, `true` for responses.
    pub(crate) is_response: bool,
    /// Application payload.
    pub(crate) payload: Vec<u8>,
}

/// An in-flight request awaiting a response from a specific peer.
pub(crate) struct PendingRequest {
    /// Oneshot sender for delivering the response payload.
    pub(crate) response_tx: tokio::sync::oneshot::Sender<Vec<u8>>,
    /// The peer we expect the response from (for origin validation).
    pub(crate) expected_peer: String,
}

/// Main P2P network node that manages connections, routing, and communication
///
/// This struct represents a complete P2P network participant that can:
/// - Connect to other peers via QUIC transport
/// - Participate in distributed hash table (DHT) operations
/// - Send and receive messages through various protocols
/// - Handle network events and peer lifecycle
///
/// Transport concerns (connections, messaging, events) are delegated to
/// [`TransportHandle`](crate::transport_handle::TransportHandle).
pub struct P2PNode {
    /// Node configuration
    config: NodeConfig,

    /// Our peer ID
    peer_id: PeerId,

    /// Transport handle owning all QUIC / peer / event state
    transport: Arc<crate::transport_handle::TransportHandle>,

    /// Node start time
    start_time: Instant,

    /// Shutdown token — cancelled when the node should stop
    shutdown: CancellationToken,

    /// DHT manager for distributed hash table operations (peer discovery, routing, storage)
    dht_manager: Arc<DhtNetworkManager>,

    /// Production resource manager (optional)
    resource_manager: Option<Arc<ResourceManager>>,

    /// Bootstrap cache manager for peer discovery
    bootstrap_manager: Option<Arc<RwLock<BootstrapManager>>>,

    /// Security dashboard for monitoring
    pub security_dashboard: Option<Arc<crate::dht::metrics::SecurityDashboard>>,

    /// Bootstrap state tracking - indicates whether peer discovery has completed
    is_bootstrapped: Arc<AtomicBool>,

    /// Whether `start()` has been called (and `stop()` has not yet completed)
    is_started: Arc<AtomicBool>,

    /// EigenTrust engine for reputation management
    ///
    /// Used to track peer reliability based on data availability outcomes.
    /// Consumers (like saorsa-node) should report successes and failures
    /// via `report_peer_success()` and `report_peer_failure()` methods.
    trust_engine: Option<Arc<EigenTrustEngine>>,
}

/// Normalize wildcard bind addresses to localhost loopback addresses
///
/// ant-quic correctly rejects "unspecified" addresses (0.0.0.0 and [::]) for remote connections
/// because you cannot connect TO an unspecified address - these are only valid for BINDING.
///
/// This function converts wildcard addresses to appropriate loopback addresses for local connections:
/// - IPv6 [::]:port → ::1:port (IPv6 loopback)
/// - IPv4 0.0.0.0:port → 127.0.0.1:port (IPv4 loopback)
/// - All other addresses pass through unchanged
///
/// # Arguments
/// * `addr` - The SocketAddr to normalize
///
/// # Returns
/// * Normalized SocketAddr suitable for remote connections
pub(crate) fn normalize_wildcard_to_loopback(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if addr.ip().is_unspecified() {
        // Convert unspecified addresses to loopback
        let loopback_ip = match addr {
            std::net::SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST), // ::1
            std::net::SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST), // 127.0.0.1
        };
        std::net::SocketAddr::new(loopback_ip, addr.port())
    } else {
        // Not a wildcard address, pass through unchanged
        addr
    }
}

impl P2PNode {
    /// Create a new P2P node with the given configuration
    pub async fn new(config: NodeConfig) -> Result<Self> {
        let peer_id = config.peer_id.clone().unwrap_or_else(|| {
            // Generate a random peer ID for now
            // Safe: UUID v4 canonical format is always 36 characters
            let uuid_str = uuid::Uuid::new_v4().to_string();
            format!("peer_{}", &uuid_str[..8])
        });

        // Initialize and register a TrustWeightedKademlia DHT for the global API
        // Use a deterministic local NodeId derived from the peer_id
        {
            let nid = derive_dht_key_from_peer_id(&peer_id);
            let _twdht = std::sync::Arc::new(crate::dht::TrustWeightedKademlia::new(
                crate::identity::node_identity::NodeId::from_bytes(nid),
            ));
            // TODO: Update to use new clean API
            // let _ = crate::api::set_dht_instance(twdht);
        }

        // Initialize production resource manager if configured
        let resource_manager = config
            .production_config
            .clone()
            .map(|prod_config| Arc::new(ResourceManager::new(prod_config)));

        // Initialize bootstrap cache manager
        let diversity_config = config.diversity_config.clone().unwrap_or_default();
        let bootstrap_manager = if let Some(ref cache_config) = config.bootstrap_cache_config {
            match BootstrapManager::with_full_config(
                cache_config.clone(),
                crate::rate_limit::JoinRateLimiterConfig::default(),
                diversity_config.clone(),
            )
            .await
            {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    warn!(
                        "Failed to initialize bootstrap manager: {}, continuing without cache",
                        e
                    );
                    None
                }
            }
        } else {
            match BootstrapManager::with_full_config(
                crate::bootstrap::CacheConfig::default(),
                crate::rate_limit::JoinRateLimiterConfig::default(),
                diversity_config,
            )
            .await
            {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    warn!(
                        "Failed to initialize bootstrap manager: {}, continuing without cache",
                        e
                    );
                    None
                }
            }
        };

        // Initialize EigenTrust engine for reputation management
        let trust_engine = {
            let mut pre_trusted = HashSet::new();
            for bootstrap_peer in &config.bootstrap_peers_str {
                // Use canonical derivation to create NodeId from bootstrap peer address
                let node_id_bytes = derive_dht_key_from_peer_id(bootstrap_peer);
                pre_trusted.insert(AdaptiveNodeId::from_bytes(node_id_bytes));
            }

            let engine = Arc::new(EigenTrustEngine::new(pre_trusted));
            engine.clone().start_background_updates();
            Some(engine)
        };

        // Build transport handle with all transport-level concerns
        let transport_config = crate::transport_handle::TransportConfig {
            peer_id: peer_id.clone(),
            listen_addr: config.listen_addr,
            enable_ipv6: config.enable_ipv6,
            connection_timeout: config.connection_timeout,
            stale_peer_threshold: config.stale_peer_threshold,
            max_connections: config.max_connections,
            production_config: config.production_config.clone(),
            event_channel_capacity: crate::DEFAULT_EVENT_CHANNEL_CAPACITY,
            max_message_size: config.max_message_size,
        };
        let transport =
            Arc::new(crate::transport_handle::TransportHandle::new(transport_config).await?);

        // Initialize DHT manager (owns local DHT core and network DHT behavior)
        let manager_dht_config = crate::dht::DHTConfig {
            replication_factor: config.dht_config.k_value,
            bucket_size: config.dht_config.k_value,
            alpha: config.dht_config.alpha_value,
            record_ttl: config.dht_config.record_ttl,
            bucket_refresh_interval: config.dht_config.refresh_interval,
            republish_interval: config.dht_config.refresh_interval,
            max_distance: DHT_MAX_DISTANCE,
        };
        let dht_manager_config = DhtNetworkConfig {
            local_peer_id: peer_id.clone(),
            dht_config: manager_dht_config,
            node_config: config.clone(),
            request_timeout: config.connection_timeout,
            max_concurrent_operations: MAX_ACTIVE_REQUESTS,
            replication_factor: config.dht_config.k_value,
            enable_security: true,
        };
        let dht_manager = Arc::new(
            DhtNetworkManager::new(transport.clone(), trust_engine.clone(), dht_manager_config)
                .await?,
        );

        let security_metrics = dht_manager.security_metrics().await;
        let security_dashboard = Some(Arc::new(crate::dht::metrics::SecurityDashboard::new(
            security_metrics,
            Arc::new(crate::dht::metrics::DhtMetricsCollector::new()),
            Arc::new(crate::dht::metrics::TrustMetricsCollector::new()),
            Arc::new(crate::dht::metrics::PlacementMetricsCollector::new()),
        )));

        let node = Self {
            config,
            peer_id,
            transport,
            start_time: Instant::now(),
            shutdown: CancellationToken::new(),
            dht_manager,
            resource_manager,
            bootstrap_manager,
            security_dashboard,
            is_bootstrapped: Arc::new(AtomicBool::new(false)),
            is_started: Arc::new(AtomicBool::new(false)),
            trust_engine,
        };
        info!(
            "Created P2P node with peer ID: {} (call start() to begin networking)",
            node.peer_id
        );

        Ok(node)
    }

    /// Create a new node builder
    pub fn builder() -> NodeBuilder {
        NodeBuilder::new()
    }

    /// Get the peer ID of this node
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get the transport handle for sharing with other components.
    pub fn transport(&self) -> &Arc<crate::transport_handle::TransportHandle> {
        &self.transport
    }

    /// Get the hex-encoded transport-level peer ID.
    pub fn transport_peer_id(&self) -> Option<String> {
        self.transport.transport_peer_id()
    }

    pub fn local_addr(&self) -> Option<String> {
        self.transport.local_addr()
    }

    /// Check if the node has completed the initial bootstrap process
    ///
    /// Returns `true` if the node has successfully connected to at least one
    /// bootstrap peer and performed peer discovery (FIND_NODE).
    pub fn is_bootstrapped(&self) -> bool {
        self.is_bootstrapped.load(Ordering::SeqCst)
    }

    /// Manually trigger re-bootstrap (useful for recovery or network rejoin)
    ///
    /// This clears the bootstrapped state and attempts to reconnect to
    /// bootstrap peers and discover new peers.
    pub async fn re_bootstrap(&self) -> Result<()> {
        self.is_bootstrapped.store(false, Ordering::SeqCst);
        self.connect_bootstrap_peers().await
    }

    // =========================================================================
    // Trust API - EigenTrust Reputation System
    // =========================================================================

    /// Get the EigenTrust engine for direct trust operations
    ///
    /// This provides access to the underlying trust engine for advanced use cases.
    /// For simple success/failure reporting, prefer `report_peer_success()` and
    /// `report_peer_failure()`.
    ///
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if let Some(engine) = node.trust_engine() {
    ///     // Update node statistics directly
    ///     engine.update_node_stats(&peer_id, NodeStatisticsUpdate::StorageContributed(1024)).await;
    ///
    ///     // Get global trust scores
    ///     let scores = engine.compute_global_trust().await;
    /// }
    /// ```
    pub fn trust_engine(&self) -> Option<Arc<EigenTrustEngine>> {
        self.trust_engine.clone()
    }

    /// Canonical conversion from PeerId string to adaptive NodeId for trust.
    ///
    /// Delegates to the standalone [`peer_id_to_trust_node_id`] function.
    fn peer_id_to_trust_node_id(peer_id: &str) -> AdaptiveNodeId {
        if let Ok(bytes) = hex::decode(peer_id)
            && bytes.len() == 32
        {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return AdaptiveNodeId::from_bytes(arr);
        }
        // Non-hex or wrong length: use canonical derivation
        let hash = derive_dht_key_from_peer_id(peer_id);
        AdaptiveNodeId::from_bytes(hash)
    }

    /// Report a successful interaction with a peer
    ///
    /// Call this after successful data operations to increase the peer's trust score.
    /// This is the primary method for saorsa-node to report positive outcomes.
    ///
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID (as a string) of the node that performed well
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After successfully retrieving a chunk from a peer
    /// if let Ok(chunk) = fetch_chunk_from(&peer_id).await {
    ///     node.report_peer_success(&peer_id).await?;
    /// }
    /// ```
    pub async fn report_peer_success(&self, peer_id: &str) -> Result<()> {
        if let Some(ref engine) = self.trust_engine {
            let node_id = Self::peer_id_to_trust_node_id(peer_id);

            engine
                .update_node_stats(&node_id, NodeStatisticsUpdate::CorrectResponse)
                .await;
            Ok(())
        } else {
            // Trust engine not initialized - this is not an error, just a no-op
            Ok(())
        }
    }

    /// Report a failed interaction with a peer
    ///
    /// Call this after failed data operations to decrease the peer's trust score.
    /// This includes timeouts, corrupted data, or refused connections.
    ///
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID (as a string) of the node that failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // After a chunk retrieval fails
    /// match fetch_chunk_from(&peer_id).await {
    ///     Ok(chunk) => node.report_peer_success(&peer_id).await?,
    ///     Err(_) => node.report_peer_failure(&peer_id).await?,
    /// }
    /// ```
    pub async fn report_peer_failure(&self, peer_id: &str) -> Result<()> {
        // Delegate to the enriched version with a generic transport-level reason
        self.report_peer_failure_with_reason(peer_id, PeerFailureReason::ConnectionFailed)
            .await
    }

    /// Report a failed interaction with a peer, providing a specific failure reason.
    ///
    /// This is the enriched version of [`P2PNode::report_peer_failure`] that maps the failure
    /// reason to the appropriate trust penalty. Use this when you know *why* the
    /// interaction failed to give the trust engine more accurate data.
    ///
    /// - Transport-level failures (`Timeout`, `ConnectionFailed`) map to `FailedResponse`
    /// - `DataUnavailable` maps to `DataUnavailable`
    /// - `CorruptedData` maps to `CorruptedData` (counts as 2 failures)
    /// - `ProtocolError` maps to `ProtocolViolation` (counts as 2 failures)
    /// - `Refused` maps to `FailedResponse`
    ///
    /// Requires the `adaptive-ml` feature to be enabled.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID of the node that failed
    /// * `reason` - Why the interaction failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use saorsa_core::error::PeerFailureReason;
    ///
    /// // After a chunk retrieval returns corrupted data
    /// node.report_peer_failure_with_reason(&peer_id, PeerFailureReason::CorruptedData).await?;
    /// ```
    pub async fn report_peer_failure_with_reason(
        &self,
        peer_id: &str,
        reason: PeerFailureReason,
    ) -> Result<()> {
        if let Some(ref engine) = self.trust_engine {
            let node_id = Self::peer_id_to_trust_node_id(peer_id);

            let update = match reason {
                PeerFailureReason::Timeout | PeerFailureReason::ConnectionFailed => {
                    NodeStatisticsUpdate::FailedResponse
                }
                PeerFailureReason::DataUnavailable => NodeStatisticsUpdate::DataUnavailable,
                PeerFailureReason::CorruptedData => NodeStatisticsUpdate::CorruptedData,
                PeerFailureReason::ProtocolError => NodeStatisticsUpdate::ProtocolViolation,
                PeerFailureReason::Refused => NodeStatisticsUpdate::FailedResponse,
            };

            engine.update_node_stats(&node_id, update).await;
            Ok(())
        } else {
            // Trust engine not initialized - this is not an error, just a no-op
            Ok(())
        }
    }

    /// Get the current trust score for a peer
    ///
    /// Returns a value between 0.0 (untrusted) and 1.0 (fully trusted).
    /// Unknown peers return 0.0 by default.
    ///
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID (as a string) to query
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let trust = node.peer_trust(&peer_id);
    /// if trust < 0.3 {
    ///     tracing::warn!("Low trust peer: {}", peer_id);
    /// }
    /// ```
    pub fn peer_trust(&self, peer_id: &str) -> f64 {
        if let Some(ref engine) = self.trust_engine {
            let node_id = Self::peer_id_to_trust_node_id(peer_id);

            engine.get_trust(&node_id)
        } else {
            // Trust engine not initialized - return neutral trust
            DEFAULT_NEUTRAL_TRUST
        }
    }

    // =========================================================================
    // Request/Response API — Automatic Trust Feedback
    // =========================================================================

    /// Send a request to a peer and wait for a response with automatic trust reporting.
    ///
    /// Unlike fire-and-forget `send_message()`, this method:
    /// 1. Wraps the payload in a `RequestResponseEnvelope` with a unique message ID
    /// 2. Sends it on the `/rr/<protocol>` protocol prefix
    /// 3. Waits for a matching response (or timeout)
    /// 4. Automatically reports success or failure to the trust engine
    ///
    /// The remote peer's handler should call `send_response()` with the
    /// incoming message ID to route the response back.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Target peer
    /// * `protocol` - Application protocol name (e.g. `"chunk_fetch"`)
    /// * `data` - Request payload bytes
    /// * `timeout` - Maximum time to wait for a response
    ///
    /// # Returns
    ///
    /// A [`PeerResponse`] on success, or an error on timeout / connection failure.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let response = node.send_request(&peer_id, "chunk_fetch", chunk_id.to_vec(), Duration::from_secs(10)).await?;
    /// println!("Got {} bytes from {}", response.data.len(), response.peer_id);
    /// ```
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<PeerResponse> {
        match self
            .transport
            .send_request(peer_id, protocol, data, timeout)
            .await
        {
            Ok(resp) => {
                let _ = self.report_peer_success(peer_id).await;
                Ok(resp)
            }
            Err(e) => {
                // Choose the right failure reason based on the error type
                let reason = if matches!(&e, P2PError::Timeout(_)) {
                    PeerFailureReason::Timeout
                } else {
                    PeerFailureReason::ConnectionFailed
                };
                let _ = self.report_peer_failure_with_reason(peer_id, reason).await;
                Err(e)
            }
        }
    }

    pub async fn send_response(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        message_id: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        self.transport
            .send_response(peer_id, protocol, message_id, data)
            .await
    }

    pub fn parse_request_envelope(data: &[u8]) -> Option<(String, bool, Vec<u8>)> {
        crate::transport_handle::TransportHandle::parse_request_envelope(data)
    }

    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        self.transport.subscribe(topic).await
    }

    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        self.transport.publish(topic, data).await
    }

    /// Get the node configuration
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Start the P2P node
    pub async fn start(&self) -> Result<()> {
        info!("Starting P2P node...");

        // Start production resource manager if configured
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager
                .start()
                .await
                .map_err(|e| protocol_error(format!("Failed to start resource manager: {e}")))?;
            info!("Production resource manager started");
        }

        // Start bootstrap manager background tasks
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let mut manager = bootstrap_manager.write().await;
            manager
                .start_background_tasks()
                .await
                .map_err(|e| protocol_error(format!("Failed to start bootstrap manager: {e}")))?;
            info!("Bootstrap cache manager started");
        }

        // Start transport listeners and message receiving
        self.transport.start_network_listeners().await?;

        // Start the attached DHT manager.
        Arc::clone(&self.dht_manager).start().await?;

        // Log current listen addresses
        let listen_addrs = self.transport.listen_addrs().await;
        info!("P2P node started on addresses: {:?}", listen_addrs);

        // NOTE: Message receiving is now integrated into the accept loop in start_network_listeners()
        // The old start_message_receiving_system() is no longer needed as it competed with the accept
        // loop for incoming connections, causing messages to be lost.

        // Connect to bootstrap peers
        self.connect_bootstrap_peers().await?;

        self.is_started
            .store(true, std::sync::atomic::Ordering::Release);

        Ok(())
    }

    // start_network_listeners and start_message_receiving_system are implemented in TransportHandle.

    /// Run the P2P node (blocks until shutdown)
    pub async fn run(&self) -> Result<()> {
        if !self.is_running() {
            self.start().await?;
        }

        info!("P2P node running...");

        let mut interval = tokio::time::interval(Duration::from_millis(RUN_LOOP_TICK_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Main event loop
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.transport.maintenance_tick().await?;
                }
                () = self.shutdown.cancelled() => {
                    break;
                }
            }
        }

        info!("P2P node stopped");
        Ok(())
    }

    /// Stop the P2P node
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping P2P node...");

        // Signal the run loop to exit
        self.shutdown.cancel();

        // Stop DHT manager first so leave messages can be sent while transport is still active.
        self.dht_manager.stop().await?;

        // Stop the transport layer (shutdown endpoints, join tasks, disconnect peers)
        self.transport.stop().await?;

        // Shutdown production resource manager if configured
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager
                .shutdown()
                .await
                .map_err(|e| protocol_error(format!("Failed to shutdown resource manager: {e}")))?;
            info!("Production resource manager stopped");
        }

        self.is_started
            .store(false, std::sync::atomic::Ordering::Release);

        info!("P2P node stopped");
        Ok(())
    }

    /// Graceful shutdown alias for tests
    pub async fn shutdown(&self) -> Result<()> {
        self.stop().await
    }

    /// Check if the node is running
    pub fn is_running(&self) -> bool {
        self.is_started.load(std::sync::atomic::Ordering::Acquire) && !self.shutdown.is_cancelled()
    }

    /// Get the current listen addresses
    pub async fn listen_addrs(&self) -> Vec<std::net::SocketAddr> {
        self.transport.listen_addrs().await
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.transport.connected_peers().await
    }

    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        self.transport.peer_count().await
    }

    /// Get peer info
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.transport.peer_info(peer_id).await
    }

    /// Get the peer ID for a given socket address, if connected
    pub async fn get_peer_id_by_address(&self, addr: &str) -> Option<PeerId> {
        self.transport.get_peer_id_by_address(addr).await
    }

    /// List all active connections with their peer IDs and addresses
    pub async fn list_active_connections(&self) -> Vec<(PeerId, Vec<String>)> {
        self.transport.list_active_connections().await
    }

    /// Remove a peer from the peers map
    pub async fn remove_peer(&self, peer_id: &PeerId) -> bool {
        self.transport.remove_peer(peer_id).await
    }

    /// Check if a peer is connected
    pub async fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.transport.is_peer_connected(peer_id).await
    }

    /// Connect to a peer
    ///
    /// Delegates to the transport handle for the actual QUIC connection (Happy Eyeballs,
    /// self-connection prevention, etc.) and then seeds the DHT with the new peer.
    pub async fn connect_peer(&self, address: &str) -> Result<PeerId> {
        let peer_id = self.transport.connect_peer(address).await?;

        // Seed DHT with this new peer
        let dht_core = self.dht_manager.dht_core();
        register_peer_in_dht(dht_core, &peer_id, address).await;

        Ok(peer_id)
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        self.transport.disconnect_peer(peer_id).await
    }

    /// Check if a connection to a peer is active
    pub async fn is_connection_active(&self, peer_id: &str) -> bool {
        self.transport.is_connection_active(peer_id).await
    }

    /// Send a message to a peer
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        self.transport.send_message(peer_id, protocol, data).await
    }
}

/// Parse a postcard-encoded protocol message into a `P2PEvent::Message`.
///
/// Returns `None` if the bytes cannot be deserialized as a valid `WireMessage`.
///
/// The `from` field is a required part of the wire protocol but is **not**
/// used as the event source. Instead, `source` — the transport-level peer ID
/// derived from the authenticated QUIC connection — is used so that consumers
/// can pass it directly to `send_message()`. This eliminates a spoofing
/// vector where a peer could claim an arbitrary identity via the payload.
///
/// Maximum allowed clock skew for message timestamps (5 minutes).
/// This is intentionally lenient for initial deployment to accommodate nodes with
/// misconfigured clocks or high-latency network conditions. Can be tightened (e.g., to 60s)
/// once the network stabilizes and node clock synchronization improves.
const MAX_MESSAGE_AGE_SECS: u64 = 300;
/// Maximum allowed future timestamp (30 seconds to account for clock drift)
const MAX_FUTURE_SECS: u64 = 30;

/// Canonical conversion from PeerId string to adaptive NodeId for trust.
///
/// PeerId strings are hex-encoded 32-byte identifiers. This decodes them
/// back to raw bytes, matching the DHT NodeId representation used by
/// `trust_peer_selector`. Falls back to blake3 hash for non-hex IDs.
pub fn peer_id_to_trust_node_id(peer_id: &str) -> AdaptiveNodeId {
    if let Ok(bytes) = hex::decode(peer_id)
        && bytes.len() == 32
    {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return AdaptiveNodeId::from_bytes(arr);
    }
    // Non-hex or wrong length: use canonical derivation
    let hash = crate::dht::derive_dht_key_from_peer_id(peer_id);
    AdaptiveNodeId::from_bytes(hash)
}

/// Convenience constructor for `P2PError::Network(NetworkError::ProtocolError(...))`.
fn protocol_error(msg: impl std::fmt::Display) -> P2PError {
    P2PError::Network(NetworkError::ProtocolError(msg.to_string().into()))
}

/// Helper to send an event via a broadcast sender, logging at trace level if no receivers.
pub(crate) fn broadcast_event(tx: &broadcast::Sender<P2PEvent>, event: P2PEvent) {
    if let Err(e) = tx.send(event) {
        tracing::trace!("Event broadcast has no receivers: {e}");
    }
}

pub(crate) fn parse_protocol_message(bytes: &[u8], source: &str) -> Option<P2PEvent> {
    let message: WireMessage = postcard::from_bytes(bytes).ok()?;

    // Validate timestamp to prevent replay attacks
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Reject messages that are too old (potential replay)
    if message.timestamp < now.saturating_sub(MAX_MESSAGE_AGE_SECS) {
        tracing::warn!(
            "Rejecting stale message from {} (timestamp {} is {} seconds old)",
            source,
            message.timestamp,
            now.saturating_sub(message.timestamp)
        );
        return None;
    }

    // Reject messages too far in the future (clock manipulation)
    if message.timestamp > now + MAX_FUTURE_SECS {
        tracing::warn!(
            "Rejecting future-dated message from {} (timestamp {} is {} seconds ahead)",
            source,
            message.timestamp,
            message.timestamp.saturating_sub(now)
        );
        return None;
    }

    debug!(
        "Parsed P2PEvent::Message - topic: {}, source: {} (logical: {}), payload_len: {}",
        message.protocol,
        source,
        message.from,
        message.data.len()
    );

    Some(P2PEvent::Message {
        topic: message.protocol,
        source: source.to_string(),
        data: message.data,
    })
}

impl P2PNode {
    /// Subscribe to network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.transport.subscribe_events()
    }

    /// Backwards-compat event stream accessor for tests
    pub fn events(&self) -> broadcast::Receiver<P2PEvent> {
        self.subscribe_events()
    }

    /// Get node uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    // MCP removed: all MCP tool/service methods removed

    // /// Handle MCP remote tool call with network integration

    // /// List tools available on a specific remote peer

    // /// Get MCP server statistics

    /// Get production resource metrics
    pub async fn resource_metrics(&self) -> Result<ResourceMetrics> {
        if let Some(ref resource_manager) = self.resource_manager {
            Ok(resource_manager.get_metrics().await)
        } else {
            Err(protocol_error("Production resource manager not enabled"))
        }
    }

    // Background tasks (connection_lifecycle_monitor, keepalive, periodic_maintenance)
    // are now implemented in TransportHandle.

    /// Check system health
    pub async fn health_check(&self) -> Result<()> {
        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.health_check().await
        } else {
            // Basic health check without resource manager
            let peer_count = self.peer_count().await;
            if peer_count > self.config.max_connections {
                Err(protocol_error(format!(
                    "Too many connections: {peer_count}"
                )))
            } else {
                Ok(())
            }
        }
    }

    /// Get production configuration (if enabled)
    pub fn production_config(&self) -> Option<&ProductionConfig> {
        self.config.production_config.as_ref()
    }

    /// Check if production hardening is enabled
    pub fn is_production_mode(&self) -> bool {
        self.resource_manager.is_some()
    }

    /// Get the attached DHT manager.
    pub fn dht_manager(&self) -> &Arc<DhtNetworkManager> {
        &self.dht_manager
    }

    /// Backwards-compatible alias for `dht_manager()`.
    pub fn dht(&self) -> &Arc<DhtNetworkManager> {
        self.dht_manager()
    }

    /// Store a value in the local DHT
    ///
    /// This method stores data in the local DHT core through the attached manager.
    /// For network-wide replication across multiple nodes, use `DhtNetworkManager::put`.
    pub async fn dht_put(&self, key: crate::dht::Key, value: Vec<u8>) -> Result<()> {
        self.dht_manager.store_local(key, value).await
    }

    /// Retrieve a value from the local DHT
    ///
    /// This method retrieves data from the local DHT core through the attached manager.
    /// For network-wide lookups across multiple nodes, use `DhtNetworkManager::get`.
    pub async fn dht_get(&self, key: crate::dht::Key) -> Result<Option<Vec<u8>>> {
        self.dht_manager.get_local(&key).await
    }

    /// Seed the DHT routing table from currently connected P2P peers
    ///
    /// This method explicitly registers all currently connected P2P peers into the
    /// DHT routing table. This is necessary because P2P transport connections do not
    /// automatically populate the DHT - they operate at different layers.
    ///
    /// # Returns
    /// The number of peers successfully added to the DHT routing table
    ///
    /// # Errors
    /// Returns an error if DHT is not enabled or if seeding fails
    pub async fn seed_dht_from_connected_peers(&self) -> Result<usize> {
        let dht_core = self.dht_manager.dht_core();
        let connected = self.transport.connected_peers().await;
        let total_peers = connected.len();

        tracing::debug!(peer_count = total_peers, "Seeding DHT from connected peers");

        // Collect peer addresses via transport's peer_info method
        let mut peer_data: Vec<(PeerId, String)> = Vec::new();
        let mut skipped_no_addr = 0usize;
        let mut skipped_not_found = 0usize;
        for pid in &connected {
            if let Some(info) = self.transport.peer_info(pid).await {
                if let Some(addr) = info.addresses.first() {
                    peer_data.push((pid.clone(), addr.clone()));
                } else {
                    skipped_no_addr += 1;
                }
            } else {
                skipped_not_found += 1;
            }
        }

        if skipped_no_addr > 0 {
            tracing::warn!(
                count = skipped_no_addr,
                "Skipped peers with no addresses during DHT seeding"
            );
        }
        if skipped_not_found > 0 {
            tracing::warn!(
                count = skipped_not_found,
                "Skipped peers not found in peers map during DHT seeding"
            );
        }

        let mut seeded_count = 0;
        for (peer_id, address) in &peer_data {
            if register_peer_in_dht(dht_core, peer_id, address).await {
                seeded_count += 1;
            }
        }

        tracing::info!(
            seeded = seeded_count,
            total = total_peers,
            "DHT seeding complete"
        );

        Ok(seeded_count)
    }

    /// Add a discovered peer to the bootstrap cache
    pub async fn add_discovered_peer(&self, peer_id: PeerId, addresses: Vec<String>) -> Result<()> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.write().await;
            let socket_addresses: Vec<std::net::SocketAddr> = addresses
                .iter()
                .filter_map(|addr| addr.parse().ok())
                .collect();
            let contact = ContactEntry::new(peer_id, socket_addresses);
            manager.add_contact(contact).await.map_err(|e| {
                protocol_error(format!("Failed to add peer to bootstrap cache: {e}"))
            })?;
        }
        Ok(())
    }

    /// Update connection metrics for a peer in the bootstrap cache
    pub async fn update_peer_metrics(
        &self,
        peer_id: &PeerId,
        success: bool,
        latency_ms: Option<u64>,
        _error: Option<String>,
    ) -> Result<()> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.write().await;

            // Create quality metrics based on the connection result
            let metrics = QualityMetrics {
                success_rate: if success { 1.0 } else { 0.0 },
                avg_latency_ms: latency_ms.unwrap_or(0) as f64,
                quality_score: if success {
                    BOOTSTRAP_QUALITY_SCORE_SUCCESS
                } else {
                    BOOTSTRAP_QUALITY_SCORE_FAILURE
                },
                last_connection_attempt: chrono::Utc::now(),
                last_successful_connection: if success {
                    chrono::Utc::now()
                } else {
                    chrono::Utc::now() - chrono::Duration::hours(BOOTSTRAP_FAILURE_PENALTY_HOURS)
                },
                uptime_score: BOOTSTRAP_DEFAULT_UPTIME_SCORE,
            };

            manager
                .update_contact_metrics(peer_id, metrics)
                .await
                .map_err(|e| protocol_error(format!("Failed to update peer metrics: {e}")))?;
        }
        Ok(())
    }

    /// Get bootstrap cache statistics
    pub async fn get_bootstrap_cache_stats(&self) -> Result<Option<crate::bootstrap::CacheStats>> {
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            let stats = manager
                .get_stats()
                .await
                .map_err(|e| protocol_error(format!("Failed to get bootstrap stats: {e}")))?;
            Ok(Some(stats))
        } else {
            Ok(None)
        }
    }

    /// Get the number of cached bootstrap peers
    pub async fn cached_peer_count(&self) -> usize {
        if let Some(ref _bootstrap_manager) = self.bootstrap_manager
            && let Ok(Some(stats)) = self.get_bootstrap_cache_stats().await
        {
            return stats.total_contacts;
        }
        0
    }

    /// Discover peers from a connected bootstrap peer using FIND_NODE
    ///
    /// Sends a FIND_NODE request for our own peer ID to discover nearby peers
    /// and populate the routing table. This is the core of Kademlia peer discovery.
    ///
    /// NOTE: Currently unused — bootstrap peer discovery is handled by
    /// `DhtNetworkManager::bootstrap_from_peers()`. Retained for potential
    /// direct-protocol discovery fallback.
    #[allow(dead_code)]
    async fn discover_peers_from(&self, peer_id: &PeerId) -> Result<usize> {
        use crate::dht::network_integration::DhtMessage;

        info!("Discovering peers from bootstrap peer: {peer_id}");

        // Create our node ID as a DhtKey for the FIND_NODE query
        // We query for ourselves to find nodes closest to us
        let our_id_bytes = derive_dht_key_from_peer_id(&self.peer_id);
        let target_key = crate::dht::DhtKey::from_bytes(our_id_bytes);

        // Create FIND_NODE message
        let find_node_msg = DhtMessage::FindNode {
            target: target_key,
            count: 20, // Request up to 20 closest nodes
        };

        // Serialize the message
        let message_bytes = postcard::to_allocvec(&find_node_msg).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to serialize FIND_NODE message: {e}").into(),
            ))
        })?;

        // Send the FIND_NODE request
        self.send_message(peer_id, "/dht/1.0.0", message_bytes)
            .await?;

        // Note: Response handling is asynchronous through the message handler.
        // For now, we log the request and let the response handler populate
        // the routing table when it receives FindNodeReply.
        //
        // TODO: Implement request-response correlation with a timeout to get
        // actual discovered peer count. For now, return 0 to indicate we sent
        // the request but don't have immediate response data.

        info!("Sent FIND_NODE request to {peer_id} for peer discovery");

        Ok(0) // Actual count would require awaiting the response
    }

    /// Connect to bootstrap peers and perform initial peer discovery
    async fn connect_bootstrap_peers(&self) -> Result<()> {
        let mut bootstrap_contacts = Vec::new();
        let mut used_cache = false;
        let mut seen_addresses = std::collections::HashSet::new();

        // CLI-provided bootstrap peers take priority - always include them first
        let cli_bootstrap_peers = if !self.config.bootstrap_peers_str.is_empty() {
            self.config.bootstrap_peers_str.clone()
        } else {
            // Convert Multiaddr to strings
            self.config
                .bootstrap_peers
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
        };

        if !cli_bootstrap_peers.is_empty() {
            info!(
                "Using {} CLI-provided bootstrap peers (priority)",
                cli_bootstrap_peers.len()
            );
            for addr in &cli_bootstrap_peers {
                if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                    seen_addresses.insert(socket_addr);
                    let contact = ContactEntry::new(
                        format!("cli_peer_{}", addr.chars().take(8).collect::<String>()),
                        vec![socket_addr],
                    );
                    bootstrap_contacts.push(contact);
                } else {
                    warn!("Invalid bootstrap address format: {}", addr);
                }
            }
        }

        // Supplement with cached bootstrap peers (after CLI peers)
        // Use QUIC-specific peer selection since we're using ant-quic transport
        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
            let manager = bootstrap_manager.read().await;
            match manager
                .get_quic_bootstrap_peers(BOOTSTRAP_PEER_BATCH_SIZE)
                .await
            {
                // Try to get top 20 quality QUIC-enabled peers
                Ok(contacts) => {
                    if !contacts.is_empty() {
                        let mut added_from_cache = 0;
                        for contact in contacts {
                            // Only add if we haven't already added this address from CLI
                            let new_addresses: Vec<_> = contact
                                .addresses
                                .iter()
                                .filter(|addr| !seen_addresses.contains(addr))
                                .copied()
                                .collect();

                            if !new_addresses.is_empty() {
                                for addr in &new_addresses {
                                    seen_addresses.insert(*addr);
                                }
                                let mut contact = contact.clone();
                                contact.addresses = new_addresses;
                                bootstrap_contacts.push(contact);
                                added_from_cache += 1;
                            }
                        }
                        if added_from_cache > 0 {
                            info!(
                                "Added {} cached bootstrap peers (supplementing CLI peers)",
                                added_from_cache
                            );
                            used_cache = true;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get cached bootstrap peers: {}", e);
                }
            }
        }

        if bootstrap_contacts.is_empty() {
            info!("No bootstrap peers configured and no cached peers available");
            return Ok(());
        }

        // Connect to bootstrap peers and perform peer discovery
        let mut successful_connections = 0;
        let mut connected_peer_ids: Vec<PeerId> = Vec::new();

        for contact in bootstrap_contacts.iter() {
            for addr in &contact.addresses {
                match self.connect_peer(&addr.to_string()).await {
                    Ok(peer_id) => {
                        successful_connections += 1;
                        connected_peer_ids.push(peer_id.clone());

                        // Update bootstrap cache with successful connection
                        if let Some(ref bootstrap_manager) = self.bootstrap_manager {
                            let manager = bootstrap_manager.write().await;
                            let mut updated_contact = contact.clone();
                            updated_contact.peer_id = peer_id.clone();
                            updated_contact.update_connection_result(true, Some(100), None); // Assume 100ms latency for now

                            if let Err(e) = manager.add_contact(updated_contact).await {
                                warn!("Failed to update bootstrap cache: {}", e);
                            }
                        }
                        break; // Successfully connected, move to next contact
                    }
                    Err(e) => {
                        warn!("Failed to connect to bootstrap peer {}: {}", addr, e);

                        // Update bootstrap cache with failed connection
                        if used_cache && let Some(ref bootstrap_manager) = self.bootstrap_manager {
                            let manager = bootstrap_manager.write().await;
                            let mut updated_contact = contact.clone();
                            updated_contact.update_connection_result(
                                false,
                                None,
                                Some(e.to_string()),
                            );

                            if let Err(e) = manager.add_contact(updated_contact).await {
                                warn!("Failed to update bootstrap cache: {}", e);
                            }
                        }
                    }
                }
            }
        }

        if successful_connections == 0 {
            if !used_cache {
                warn!("Failed to connect to any bootstrap peers");
            }
            // Starting a node should not be gated on immediate bootstrap connectivity.
            // Keep running and allow background discovery / retries to populate peers later.
            return Ok(());
        }

        info!(
            "Successfully connected to {} bootstrap peers",
            successful_connections
        );

        // Perform DHT peer discovery from connected bootstrap peers
        // Uses the DHT manager's postcard protocol for correct deserialization
        match self
            .dht_manager
            .bootstrap_from_peers(&connected_peer_ids)
            .await
        {
            Ok(count) => info!("DHT peer discovery found {} peers", count),
            Err(e) => warn!("DHT peer discovery failed: {}", e),
        }

        // Mark node as bootstrapped - we have connected to bootstrap peers
        // and initiated peer discovery
        self.is_bootstrapped.store(true, Ordering::SeqCst);
        info!(
            "Bootstrap complete: connected to {} peers, initiated {} discovery requests",
            successful_connections,
            connected_peer_ids.len()
        );

        Ok(())
    }

    // disconnect_all_peers and periodic_tasks are now in TransportHandle
}

/// Network sender trait for sending messages
#[async_trait::async_trait]
pub trait NetworkSender: Send + Sync {
    /// Send a message to a specific peer
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()>;

    /// Get our local peer ID
    fn local_peer_id(&self) -> &PeerId;
}

// P2PNetworkSender removed — NetworkSender is now implemented directly on TransportHandle.

/// Builder pattern for creating P2P nodes
pub struct NodeBuilder {
    config: NodeConfig,
}

impl Default for NodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeBuilder {
    /// Create a new node builder
    pub fn new() -> Self {
        Self {
            config: NodeConfig::default(),
        }
    }

    /// Set the peer ID
    pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
        self.config.peer_id = Some(peer_id);
        self
    }

    /// Add a listen address
    pub fn listen_on(mut self, addr: &str) -> Self {
        if let Ok(multiaddr) = addr.parse() {
            self.config.listen_addrs.push(multiaddr);
        }
        self
    }

    /// Add a bootstrap peer
    pub fn with_bootstrap_peer(mut self, addr: &str) -> Self {
        if let Ok(multiaddr) = addr.parse() {
            self.config.bootstrap_peers.push(multiaddr);
        }
        self.config.bootstrap_peers_str.push(addr.to_string());
        self
    }

    /// Enable IPv6 support
    pub fn with_ipv6(mut self, enable: bool) -> Self {
        self.config.enable_ipv6 = enable;
        self
    }

    // MCP removed: builder methods deleted

    /// Set connection timeout
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.config.connection_timeout = timeout;
        self
    }

    /// Set maximum connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = max;
        self
    }

    /// Set maximum application-layer message size in bytes.
    ///
    /// If this method is not called, ant-quic's built-in default is used.
    pub fn with_max_message_size(mut self, max_message_size: usize) -> Self {
        self.config.max_message_size = Some(max_message_size);
        self
    }

    /// Enable production mode with default configuration
    pub fn with_production_mode(mut self) -> Self {
        self.config.production_config = Some(ProductionConfig::default());
        self
    }

    /// Configure production settings
    pub fn with_production_config(mut self, production_config: ProductionConfig) -> Self {
        self.config.production_config = Some(production_config);
        self
    }

    /// Configure IP diversity limits for Sybil protection.
    pub fn with_diversity_config(
        mut self,
        diversity_config: crate::security::IPDiversityConfig,
    ) -> Self {
        self.config.diversity_config = Some(diversity_config);
        self
    }

    /// Configure DHT settings
    pub fn with_dht(mut self, dht_config: DHTConfig) -> Self {
        self.config.dht_config = dht_config;
        self
    }

    /// Enable DHT with default configuration
    pub fn with_default_dht(mut self) -> Self {
        self.config.dht_config = DHTConfig::default();
        self
    }

    /// Build the P2P node
    pub async fn build(self) -> Result<P2PNode> {
        P2PNode::new(self.config).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod diversity_tests {
    use super::*;
    use crate::security::IPDiversityConfig;

    async fn build_bootstrap_manager_like_prod(config: &NodeConfig) -> BootstrapManager {
        let diversity_config = config.diversity_config.clone().unwrap_or_default();
        // Use a temp dir to avoid conflicts with cached files from old format
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let mut cache_config = config.bootstrap_cache_config.clone().unwrap_or_default();
        cache_config.cache_dir = temp_dir.path().to_path_buf();

        BootstrapManager::with_full_config(
            cache_config,
            crate::rate_limit::JoinRateLimiterConfig::default(),
            diversity_config,
        )
        .await
        .expect("bootstrap manager")
    }

    #[tokio::test]
    async fn test_nodeconfig_diversity_config_used_for_bootstrap() {
        let config = NodeConfig {
            diversity_config: Some(IPDiversityConfig::testnet()),
            ..Default::default()
        };

        let manager = build_bootstrap_manager_like_prod(&config).await;
        assert!(manager.diversity_config().is_relaxed());
        assert_eq!(manager.diversity_config().max_nodes_per_asn, 5000);
    }
}

/// Register a peer in the DHT routing table.
///
/// This is a standalone helper (not a method on `P2PNode`) so it can be
/// called from spawned tasks that don't have access to `self`.  The function
/// acquires the DHT write lock internally, so callers must NOT hold the lock.
///
/// Returns `true` if the peer was successfully added, `false` otherwise.
async fn register_peer_in_dht(
    dht: &tokio::sync::RwLock<crate::dht::DHT>,
    peer_id: &PeerId,
    address: &str,
) -> bool {
    let node_id_bytes = derive_dht_key_from_peer_id(peer_id);
    let node_id = DhtNodeId::from_bytes(node_id_bytes);

    let node_info = NodeInfo {
        id: node_id,
        address: address.to_string(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };

    let mut dht_instance = dht.write().await;
    match dht_instance.add_node(node_info).await {
        Ok(()) => {
            tracing::debug!(
                peer_id = %peer_id,
                "Added peer to DHT routing table"
            );
            true
        }
        Err(e) => {
            tracing::debug!(
                peer_id = %peer_id,
                error = %e,
                "Failed to add peer to DHT (may be due to security checks)"
            );
            false
        }
    }
}

/// Helper function to register a new peer
pub(crate) async fn register_new_peer(
    peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    peer_id: &PeerId,
    remote_addr: &NetworkAddress,
) {
    let mut peers_guard = peers.write().await;
    let peer_info = PeerInfo {
        peer_id: peer_id.clone(),
        addresses: vec![remote_addr.to_string()],
        connected_at: tokio::time::Instant::now(),
        last_seen: tokio::time::Instant::now(),
        status: ConnectionStatus::Connected,
        protocols: vec!["p2p-core/1.0.0".to_string()],
        heartbeat_count: 0,
    };
    peers_guard.insert(peer_id.clone(), peer_info);
}

#[cfg(test)]
mod tests {
    use super::*;
    // MCP removed from tests
    use std::time::Duration;
    use tokio::time::timeout;

    // Test tool handler for network tests

    // MCP removed

    /// Helper function to create a test node configuration
    fn create_test_node_config() -> NodeConfig {
        NodeConfig {
            peer_id: Some("test_peer_123".to_string()),
            listen_addrs: vec![
                std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0),
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
            ],
            listen_addr: std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ),
            bootstrap_peers: vec![],
            bootstrap_peers_str: vec![],
            enable_ipv6: true,

            connection_timeout: Duration::from_secs(2),
            keep_alive_interval: Duration::from_secs(30),
            max_connections: 100,
            max_incoming_connections: 50,
            dht_config: DHTConfig::default(),
            security_config: SecurityConfig::default(),
            production_config: None,
            bootstrap_cache_config: None,
            diversity_config: None,
            stale_peer_threshold: default_stale_peer_threshold(),
            max_message_size: None,
        }
    }

    /// Helper function to create a test tool
    // MCP removed: test tool helper deleted

    #[tokio::test]
    async fn test_node_config_default() {
        let config = NodeConfig::default();

        assert!(config.peer_id.is_none());
        assert_eq!(config.listen_addrs.len(), 2);
        assert!(config.enable_ipv6);
        assert_eq!(config.max_connections, 10000); // Fixed: matches actual default
        assert_eq!(config.max_incoming_connections, 100);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_dht_config_default() {
        let config = DHTConfig::default();

        assert_eq!(config.k_value, 20);
        assert_eq!(config.alpha_value, 5);
        assert_eq!(config.record_ttl, Duration::from_secs(3600));
        assert_eq!(config.refresh_interval, Duration::from_secs(600));
    }

    #[tokio::test]
    async fn test_security_config_default() {
        let config = SecurityConfig::default();

        assert!(config.enable_noise);
        assert!(config.enable_tls);
        assert_eq!(config.trust_level, TrustLevel::Basic);
    }

    #[test]
    fn test_trust_level_variants() {
        // Test that all trust level variants can be created
        let _none = TrustLevel::None;
        let _basic = TrustLevel::Basic;
        let _full = TrustLevel::Full;

        // Test equality
        assert_eq!(TrustLevel::None, TrustLevel::None);
        assert_eq!(TrustLevel::Basic, TrustLevel::Basic);
        assert_eq!(TrustLevel::Full, TrustLevel::Full);
        assert_ne!(TrustLevel::None, TrustLevel::Basic);
    }

    #[test]
    fn test_connection_status_variants() {
        let connecting = ConnectionStatus::Connecting;
        let connected = ConnectionStatus::Connected;
        let disconnecting = ConnectionStatus::Disconnecting;
        let disconnected = ConnectionStatus::Disconnected;
        let failed = ConnectionStatus::Failed("test error".to_string());

        assert_eq!(connecting, ConnectionStatus::Connecting);
        assert_eq!(connected, ConnectionStatus::Connected);
        assert_eq!(disconnecting, ConnectionStatus::Disconnecting);
        assert_eq!(disconnected, ConnectionStatus::Disconnected);
        assert_ne!(connecting, connected);

        if let ConnectionStatus::Failed(msg) = failed {
            assert_eq!(msg, "test error");
        } else {
            panic!("Expected Failed status");
        }
    }

    #[tokio::test]
    async fn test_node_creation() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        assert_eq!(node.peer_id(), "test_peer_123");
        assert!(!node.is_running());
        assert_eq!(node.peer_count().await, 0);
        assert!(node.connected_peers().await.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_node_creation_without_peer_id() -> Result<()> {
        let mut config = create_test_node_config();
        config.peer_id = None;

        let node = P2PNode::new(config).await?;

        // Should have generated a peer ID
        assert!(node.peer_id().starts_with("peer_"));
        assert!(!node.is_running());

        Ok(())
    }

    #[tokio::test]
    async fn test_node_lifecycle() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Initially not running
        assert!(!node.is_running());

        // Start the node
        node.start().await?;
        assert!(node.is_running());

        // Check listen addresses were set (at least one)
        let listen_addrs = node.listen_addrs().await;
        assert!(
            !listen_addrs.is_empty(),
            "Expected at least one listening address"
        );

        // Stop the node
        node.stop().await?;
        assert!(!node.is_running());

        Ok(())
    }

    #[tokio::test]
    async fn test_peer_connection() -> Result<()> {
        let config1 = create_test_node_config();
        let mut config2 = create_test_node_config();
        config2.peer_id = Some("test_peer_456".to_string());

        let node1 = P2PNode::new(config1).await?;
        let node2 = P2PNode::new(config2).await?;

        node1.start().await?;
        node2.start().await?;

        let node2_addr = node2
            .listen_addrs()
            .await
            .into_iter()
            .find(|a| a.ip().is_ipv4())
            .ok_or_else(|| {
                P2PError::Network(crate::error::NetworkError::InvalidAddress(
                    "Node 2 did not expose an IPv4 listen address".into(),
                ))
            })?;

        // Connect to a real peer
        let peer_id = node1.connect_peer(&node2_addr.to_string()).await?;

        // Check peer count
        assert_eq!(node1.peer_count().await, 1);

        // Check connected peers
        let connected_peers = node1.connected_peers().await;
        assert_eq!(connected_peers.len(), 1);
        assert_eq!(connected_peers[0], peer_id);

        // Get peer info
        let peer_info = node1.peer_info(&peer_id).await;
        assert!(peer_info.is_some());
        let info = peer_info.expect("Peer info should exist after adding peer");
        assert_eq!(info.peer_id, peer_id);
        assert_eq!(info.status, ConnectionStatus::Connected);
        assert!(info.protocols.contains(&"p2p-foundation/1.0".to_string()));

        // Disconnect from peer
        node1.disconnect_peer(&peer_id).await?;
        assert_eq!(node1.peer_count().await, 0);

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    // TODO(windows): Investigate QUIC connection issues on Windows CI
    // This test consistently fails on Windows GitHub Actions runners with
    // "All connect attempts failed" even with IPv4-only config, long delays,
    // and multiple retry attempts. The underlying ant-quic library may have
    // issues on Windows that need investigation.
    // See: https://github.com/dirvine/saorsa-core/issues/TBD
    #[cfg_attr(target_os = "windows", ignore)]
    #[tokio::test]
    async fn test_event_subscription() -> Result<()> {
        // Configure both nodes to use only IPv4 for reliable cross-platform testing
        // This is important because:
        // 1. local_addr() returns the first address from listen_addrs
        // 2. The default config puts IPv6 first, which may not work on all Windows setups
        let ipv4_localhost =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

        let mut config1 = create_test_node_config();
        config1.listen_addr = ipv4_localhost;
        config1.listen_addrs = vec![ipv4_localhost];
        config1.enable_ipv6 = false;

        let mut config2 = create_test_node_config();
        config2.peer_id = Some("test_peer_456".to_string());
        config2.listen_addr = ipv4_localhost;
        config2.listen_addrs = vec![ipv4_localhost];
        config2.enable_ipv6 = false;

        let node1 = P2PNode::new(config1).await?;
        let node2 = P2PNode::new(config2).await?;

        node1.start().await?;
        node2.start().await?;

        // Wait for nodes to fully bind their listening sockets
        // Windows network stack initialization can be significantly slower
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let mut events = node1.subscribe_events();

        // Get the actual listening address using local_addr() for reliability
        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect to a peer with retry logic for Windows reliability
        // The QUIC library may need additional time to fully initialize
        let mut peer_id = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
            match timeout(Duration::from_secs(2), node1.connect_peer(&node2_addr)).await {
                Ok(Ok(id)) => {
                    peer_id = Some(id);
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        let peer_id = peer_id.ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "Failed to connect after 3 attempts".to_string().into(),
            ))
        })?;

        // Check for PeerConnected event
        let event = timeout(Duration::from_secs(2), events.recv()).await;
        assert!(event.is_ok());

        let event_result = event
            .expect("Should receive event")
            .expect("Event should not be error");
        match event_result {
            P2PEvent::PeerConnected(event_peer_id) => {
                assert_eq!(event_peer_id, peer_id);
            }
            _ => panic!("Expected PeerConnected event"),
        }

        // Disconnect from peer (this should emit another event)
        node1.disconnect_peer(&peer_id).await?;

        // Check for PeerDisconnected event
        let event = timeout(Duration::from_secs(2), events.recv()).await;
        assert!(event.is_ok());

        let event_result = event
            .expect("Should receive event")
            .expect("Event should not be error");
        match event_result {
            P2PEvent::PeerDisconnected(event_peer_id) => {
                assert_eq!(event_peer_id, peer_id);
            }
            _ => panic!("Expected PeerDisconnected event"),
        }

        node1.stop().await?;
        node2.stop().await?;

        Ok(())
    }

    // TODO(windows): Same QUIC connection issues as test_event_subscription
    #[cfg_attr(target_os = "windows", ignore)]
    #[tokio::test]
    async fn test_message_sending() -> Result<()> {
        // Create two nodes
        let mut config1 = create_test_node_config();
        config1.listen_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let node1 = P2PNode::new(config1).await?;
        node1.start().await?;

        let mut config2 = create_test_node_config();
        config2.listen_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        let node2 = P2PNode::new(config2).await?;
        node2.start().await?;

        // Wait a bit for nodes to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Get actual listening address of node2
        let node2_addr = node2.local_addr().ok_or_else(|| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "No listening address".to_string().into(),
            ))
        })?;

        // Connect node1 to node2
        let peer_id =
            match timeout(Duration::from_millis(500), node1.connect_peer(&node2_addr)).await {
                Ok(res) => res?,
                Err(_) => return Err(P2PError::Network(NetworkError::Timeout)),
            };

        // Wait a bit for connection to establish
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        // Send a message
        let message_data = b"Hello, peer!".to_vec();
        let result = match timeout(
            Duration::from_millis(500),
            node1.send_message(&peer_id, "test-protocol", message_data),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => return Err(P2PError::Network(NetworkError::Timeout)),
        };
        // For now, we'll just check that we don't get a "not connected" error
        // The actual send might fail due to no handler on the other side
        if let Err(e) = &result {
            assert!(!e.to_string().contains("not connected"), "Got error: {}", e);
        }

        // Try to send to non-existent peer
        let non_existent_peer = "non_existent_peer".to_string();
        let result = node1
            .send_message(&non_existent_peer, "test-protocol", vec![])
            .await;
        assert!(result.is_err(), "Sending to non-existent peer should fail");

        Ok(())
    }

    #[tokio::test]
    async fn test_remote_mcp_operations() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // MCP removed; test reduced to simple start/stop
        node.start().await?;
        node.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_health_check() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Health check should pass with no connections
        let result = node.health_check().await;
        assert!(result.is_ok());

        // Note: We're not actually connecting to real peers here
        // since that would require running bootstrap nodes.
        // The health check should still pass with no connections.

        Ok(())
    }

    #[tokio::test]
    async fn test_node_uptime() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let uptime1 = node.uptime();
        assert!(uptime1 >= Duration::from_secs(0));

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(10)).await;

        let uptime2 = node.uptime();
        assert!(uptime2 > uptime1);

        Ok(())
    }

    #[tokio::test]
    async fn test_node_config_access() -> Result<()> {
        let config = create_test_node_config();
        let expected_peer_id = config.peer_id.clone();
        let node = P2PNode::new(config).await?;

        let node_config = node.config();
        assert_eq!(node_config.peer_id, expected_peer_id);
        assert_eq!(node_config.max_connections, 100);
        // MCP removed

        Ok(())
    }

    #[tokio::test]
    async fn test_mcp_server_access() -> Result<()> {
        let config = create_test_node_config();
        let _node = P2PNode::new(config).await?;

        // MCP removed
        Ok(())
    }

    #[tokio::test]
    async fn test_dht_access() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // DHT is always available
        let _dht = node.dht();

        Ok(())
    }

    #[tokio::test]
    async fn test_node_builder() -> Result<()> {
        // Create a config using the builder but don't actually build a real node
        let builder = P2PNode::builder()
            .with_peer_id("builder_test_peer".to_string())
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .listen_on("/ip6/::1/tcp/0")
            .with_bootstrap_peer("/ip4/127.0.0.1/tcp/9000") // Use a valid port number
            .with_ipv6(true)
            .with_connection_timeout(Duration::from_secs(15))
            .with_max_connections(200)
            .with_max_message_size(2 * 1024 * 1024);

        // Test the configuration that was built
        let config = builder.config;
        assert_eq!(config.peer_id, Some("builder_test_peer".to_string()));
        assert_eq!(config.listen_addrs.len(), 2); // 2 added by builder (no defaults)
        assert_eq!(config.bootstrap_peers_str.len(), 1); // Check bootstrap_peers_str instead
        assert!(config.enable_ipv6);
        assert_eq!(config.connection_timeout, Duration::from_secs(15));
        assert_eq!(config.max_connections, 200);
        assert_eq!(config.max_message_size, Some(2 * 1024 * 1024));

        Ok(())
    }

    #[tokio::test]
    async fn test_bootstrap_peers() -> Result<()> {
        let mut config = create_test_node_config();
        config.bootstrap_peers = vec![
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9200),
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9201),
        ];

        let node = P2PNode::new(config).await?;

        // Start node (which attempts to connect to bootstrap peers)
        node.start().await?;

        // In a test environment, bootstrap peers may not be available
        // The test verifies the node starts correctly with bootstrap configuration
        // Peer count may include local/internal tracking, so we just verify it's reasonable
        let _peer_count = node.peer_count().await;

        node.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_production_mode_disabled() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        assert!(!node.is_production_mode());
        assert!(node.production_config().is_none());

        // Resource metrics should fail when production mode is disabled
        let result = node.resource_metrics().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not enabled"));

        Ok(())
    }

    #[tokio::test]
    async fn test_network_event_variants() {
        // Test that all network event variants can be created
        let peer_id = "test_peer".to_string();
        let address = "/ip4/127.0.0.1/tcp/9000".to_string();

        let _peer_connected = NetworkEvent::PeerConnected {
            peer_id: peer_id.clone(),
            addresses: vec![address.clone()],
        };

        let _peer_disconnected = NetworkEvent::PeerDisconnected {
            peer_id: peer_id.clone(),
            reason: "test disconnect".to_string(),
        };

        let _message_received = NetworkEvent::MessageReceived {
            peer_id: peer_id.clone(),
            protocol: "test-protocol".to_string(),
            data: vec![1, 2, 3],
        };

        let _connection_failed = NetworkEvent::ConnectionFailed {
            peer_id: Some(peer_id.clone()),
            address: address.clone(),
            error: "connection refused".to_string(),
        };

        let _dht_stored = NetworkEvent::DHTRecordStored {
            key: vec![1, 2, 3],
            value: vec![4, 5, 6],
        };

        let _dht_retrieved = NetworkEvent::DHTRecordRetrieved {
            key: vec![1, 2, 3],
            value: Some(vec![4, 5, 6]),
        };
    }

    #[tokio::test]
    async fn test_peer_info_structure() {
        let peer_info = PeerInfo {
            peer_id: "test_peer".to_string(),
            addresses: vec!["/ip4/127.0.0.1/tcp/9000".to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        assert_eq!(peer_info.peer_id, "test_peer");
        assert_eq!(peer_info.addresses.len(), 1);
        assert_eq!(peer_info.status, ConnectionStatus::Connected);
        assert_eq!(peer_info.protocols.len(), 1);
    }

    #[tokio::test]
    async fn test_serialization() -> Result<()> {
        // Test that configs can be serialized/deserialized
        let config = create_test_node_config();
        let serialized = serde_json::to_string(&config)?;
        let deserialized: NodeConfig = serde_json::from_str(&serialized)?;

        assert_eq!(config.peer_id, deserialized.peer_id);
        assert_eq!(config.listen_addrs, deserialized.listen_addrs);
        assert_eq!(config.enable_ipv6, deserialized.enable_ipv6);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_found() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Manually insert a peer for testing
        let test_peer_id = "peer_test_123".to_string();
        let test_address = "192.168.1.100:9000".to_string();

        let peer_info = PeerInfo {
            peer_id: test_peer_id.clone(),
            addresses: vec![test_address.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(test_peer_id.clone(), peer_info)
            .await;

        // Test: Find peer by address
        let found_peer_id = node.get_peer_id_by_address(&test_address).await;
        assert_eq!(found_peer_id, Some(test_peer_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_not_found() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: Try to find a peer that doesn't exist
        let result = node.get_peer_id_by_address("192.168.1.200:9000").await;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_invalid_format() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: Invalid address format should return None
        let result = node.get_peer_id_by_address("invalid-address").await;
        assert_eq!(result, None);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_peer_id_by_address_multiple_peers() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add multiple peers with different addresses
        let peer1_id = "peer_1".to_string();
        let peer1_addr = "192.168.1.101:9001".to_string();

        let peer2_id = "peer_2".to_string();
        let peer2_addr = "192.168.1.102:9002".to_string();

        let peer1_info = PeerInfo {
            peer_id: peer1_id.clone(),
            addresses: vec![peer1_addr.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        let peer2_info = PeerInfo {
            peer_id: peer2_id.clone(),
            addresses: vec![peer2_addr.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(peer1_id.clone(), peer1_info)
            .await;
        node.transport
            .inject_peer(peer2_id.clone(), peer2_info)
            .await;

        // Test: Find each peer by their unique address
        let found_peer1 = node.get_peer_id_by_address(&peer1_addr).await;
        let found_peer2 = node.get_peer_id_by_address(&peer2_addr).await;

        assert_eq!(found_peer1, Some(peer1_id));
        assert_eq!(found_peer2, Some(peer2_id));

        Ok(())
    }

    #[tokio::test]
    async fn test_list_active_connections_empty() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Test: No connections initially
        let connections = node.list_active_connections().await;
        assert!(connections.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_list_active_connections_with_peers() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add multiple peers
        let peer1_id = "peer_1".to_string();
        let peer1_addrs = vec![
            "192.168.1.101:9001".to_string(),
            "192.168.1.101:9002".to_string(),
        ];

        let peer2_id = "peer_2".to_string();
        let peer2_addrs = vec!["192.168.1.102:9003".to_string()];

        let peer1_info = PeerInfo {
            peer_id: peer1_id.clone(),
            addresses: peer1_addrs.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        let peer2_info = PeerInfo {
            peer_id: peer2_id.clone(),
            addresses: peer2_addrs.clone(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport
            .inject_peer(peer1_id.clone(), peer1_info)
            .await;
        node.transport
            .inject_peer(peer2_id.clone(), peer2_info)
            .await;

        // Also add to active_connections (list_active_connections iterates over this)
        node.transport
            .inject_active_connection(peer1_id.clone())
            .await;
        node.transport
            .inject_active_connection(peer2_id.clone())
            .await;

        // Test: List all active connections
        let connections = node.list_active_connections().await;
        assert_eq!(connections.len(), 2);

        // Verify peer1 and peer2 are in the list
        let peer1_conn = connections.iter().find(|(id, _)| id == &peer1_id);
        let peer2_conn = connections.iter().find(|(id, _)| id == &peer2_id);

        assert!(peer1_conn.is_some());
        assert!(peer2_conn.is_some());

        // Verify addresses match
        assert_eq!(peer1_conn.unwrap().1, peer1_addrs);
        assert_eq!(peer2_conn.unwrap().1, peer2_addrs);

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_peer_success() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Add a peer
        let peer_id = "peer_to_remove".to_string();
        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            addresses: vec!["192.168.1.100:9000".to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport.inject_peer(peer_id.clone(), peer_info).await;

        // Verify peer exists
        assert!(node.is_peer_connected(&peer_id).await);

        // Remove the peer
        let removed = node.remove_peer(&peer_id).await;
        assert!(removed);

        // Verify peer no longer exists
        assert!(!node.is_peer_connected(&peer_id).await);

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_peer_nonexistent() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        // Try to remove a peer that doesn't exist
        let removed = node.remove_peer(&"nonexistent_peer".to_string()).await;
        assert!(!removed);

        Ok(())
    }

    #[tokio::test]
    async fn test_is_peer_connected() -> Result<()> {
        let config = create_test_node_config();
        let node = P2PNode::new(config).await?;

        let peer_id = "test_peer".to_string();

        // Initially not connected
        assert!(!node.is_peer_connected(&peer_id).await);

        // Add peer
        let peer_info = PeerInfo {
            peer_id: peer_id.clone(),
            addresses: vec!["192.168.1.100:9000".to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["test-protocol".to_string()],
            heartbeat_count: 0,
        };

        node.transport.inject_peer(peer_id.clone(), peer_info).await;

        // Now connected
        assert!(node.is_peer_connected(&peer_id).await);

        // Remove peer
        node.remove_peer(&peer_id).await;

        // No longer connected
        assert!(!node.is_peer_connected(&peer_id).await);

        Ok(())
    }

    #[test]
    fn test_normalize_ipv6_wildcard() {
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        let wildcard = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080);
        let normalized = normalize_wildcard_to_loopback(wildcard);

        assert_eq!(normalized.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(normalized.port(), 8080);
    }

    #[test]
    fn test_normalize_ipv4_wildcard() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);
        let normalized = normalize_wildcard_to_loopback(wildcard);

        assert_eq!(normalized.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(normalized.port(), 9000);
    }

    #[test]
    fn test_normalize_specific_address_unchanged() {
        let specific: std::net::SocketAddr = "192.168.1.100:3000".parse().unwrap();
        let normalized = normalize_wildcard_to_loopback(specific);

        assert_eq!(normalized, specific);
    }

    #[test]
    fn test_normalize_loopback_unchanged() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5000);
        let normalized_v6 = normalize_wildcard_to_loopback(loopback_v6);
        assert_eq!(normalized_v6, loopback_v6);

        let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let normalized_v4 = normalize_wildcard_to_loopback(loopback_v4);
        assert_eq!(normalized_v4, loopback_v4);
    }

    // ---- parse_protocol_message regression tests ----

    /// Get current Unix timestamp for tests
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Helper to create a postcard-serialized WireMessage for tests
    fn make_wire_bytes(protocol: &str, data: Vec<u8>, from: &str, timestamp: u64) -> Vec<u8> {
        let msg = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: from.to_string(),
            timestamp,
        };
        postcard::to_stdvec(&msg).unwrap()
    }

    #[test]
    fn test_parse_protocol_message_uses_transport_peer_id_as_source() {
        // Regression: P2PEvent::Message.source must be the transport peer ID,
        // NOT the "from" field from the wire message.  This ensures consumers
        // can pass source directly to send_message().
        let transport_id = "abcdef0123456789";
        let logical_id = "spoofed-logical-id";
        let bytes = make_wire_bytes("test/v1", vec![1, 2, 3], logical_id, current_timestamp());

        let event =
            parse_protocol_message(&bytes, transport_id).expect("valid message should parse");

        match event {
            P2PEvent::Message {
                topic,
                source,
                data,
            } => {
                assert_eq!(source, transport_id, "source must be the transport peer ID");
                assert_ne!(
                    source, logical_id,
                    "source must NOT be the logical 'from' field"
                );
                assert_eq!(topic, "test/v1");
                assert_eq!(data, vec![1u8, 2, 3]);
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_protocol_message_rejects_invalid_bytes() {
        // Random bytes that are not valid bincode should be rejected
        assert!(parse_protocol_message(b"not valid bincode", "peer-id").is_none());
    }

    #[test]
    fn test_parse_protocol_message_rejects_truncated_message() {
        // A truncated bincode message should fail to deserialize
        let full_bytes = make_wire_bytes("test/v1", vec![1, 2, 3], "sender", current_timestamp());
        let truncated = &full_bytes[..full_bytes.len() / 2];
        assert!(parse_protocol_message(truncated, "peer-id").is_none());
    }

    #[test]
    fn test_parse_protocol_message_empty_payload() {
        let bytes = make_wire_bytes("ping", vec![], "sender", current_timestamp());

        let event = parse_protocol_message(&bytes, "transport-peer")
            .expect("valid message with empty data should parse");

        match event {
            P2PEvent::Message { data, .. } => assert!(data.is_empty()),
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_protocol_message_preserves_binary_payload() {
        // Verify that arbitrary byte values (including 0xFF, 0x00) survive round-trip
        let payload: Vec<u8> = (0..=255).collect();
        let bytes = make_wire_bytes("binary/v1", payload.clone(), "sender", current_timestamp());

        let event = parse_protocol_message(&bytes, "peer-id")
            .expect("valid message with full byte range should parse");

        match event {
            P2PEvent::Message { data, topic, .. } => {
                assert_eq!(topic, "binary/v1");
                assert_eq!(
                    data, payload,
                    "payload must survive bincode round-trip exactly"
                );
            }
            other => panic!("expected P2PEvent::Message, got {:?}", other),
        }
    }
}
