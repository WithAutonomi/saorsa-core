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

//! DHT Network Manager
//!
//! This module provides the integration layer between the DHT system and the network layer,
//! enabling real P2P operations with Kademlia routing over transport protocols.

#![allow(missing_docs)]

use crate::{
    Multiaddr, P2PError, PeerId, Result,
    adaptive::EigenTrustEngine,
    dht::routing_maintenance::{MaintenanceConfig, MaintenanceScheduler, MaintenanceTask},
    dht::{DHTConfig, DhtCoreEngine, DhtKey, DhtNodeId, Key},
    error::{DhtError, NetworkError},
    network::NodeConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Semaphore, broadcast, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

/// Minimum concurrent operations for semaphore backpressure
const MIN_CONCURRENT_OPERATIONS: usize = 10;

/// Maximum candidate nodes queue size to prevent memory exhaustion attacks.
/// We keep this as a FIFO so the oldest (K-bucket-style) entries remain preferred
/// and simply drop newer candidates once the queue is full.
const MAX_CANDIDATE_NODES: usize = 200;

/// Maximum size for DHT PUT values (512 bytes) to prevent memory exhaustion DoS
const MAX_VALUE_SIZE: usize = 512;

/// Maximum size for incoming DHT messages (64 KB) to prevent memory exhaustion DoS
/// Messages larger than this are rejected before deserialization
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Number of closest nodes to return in DHT lookups (Kademlia K parameter)
const DHT_CLOSEST_NODES_COUNT: usize = 8;

/// Request timeout for DHT message handlers (30 seconds)
/// Prevents long-running handlers from starving the semaphore permit pool
/// SEC-001: DoS mitigation via timeout enforcement on concurrent operations
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Reliability score assigned to the local node in K-closest results.
/// The local node is always considered fully reliable for its own lookups.
const SELF_RELIABILITY_SCORE: f64 = 1.0;

/// DHT node representation for network operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNode {
    pub peer_id: String,
    pub address: String,
    pub distance: Option<Vec<u8>>,
    pub reliability: f64,
    /// Cached DHT key to avoid repeated SHA-256 hashing during distance comparisons.
    ///
    /// Lifecycle / invariants:
    /// - This cache is **lazily populated** via `ensure_cached_dht_key` the first time a
    ///   distance calculation requires it, not eagerly at node creation.
    /// - The field starts as `None` and may remain `None` until `ensure_cached_dht_key`
    ///   (or an equivalent helper) is called.
    /// - The value, once computed, is reused for all subsequent distance calculations and
    ///   is not expected to change for the lifetime of this `DHTNode`.
    /// - `#[serde(skip)]` means this cache is not serialized; after deserialization it will
    ///   again be `None` until `ensure_cached_dht_key` is invoked.
    ///
    /// Callers should treat this as an internal implementation detail and rely on
    /// `ensure_cached_dht_key` (or similar) rather than accessing `cached_dht_key` directly.
    /// PERF-001: Critical performance optimization - prevents O(N*log(N)*hash_cost) in sorts
    #[serde(skip)]
    pub cached_dht_key: Option<DhtKey>,
}

/// Alias for serialization compatibility
pub type SerializableDHTNode = DHTNode;

/// DHT Network Manager Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkConfig {
    /// Local peer configuration
    pub local_peer_id: PeerId,
    /// DHT configuration
    pub dht_config: DHTConfig,
    /// Network node configuration
    pub node_config: NodeConfig,
    /// Request timeout for DHT operations
    pub request_timeout: Duration,
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Replication factor (K value)
    pub replication_factor: usize,
    /// Enable enhanced security features
    pub enable_security: bool,
}

/// Bootstrap node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    /// Node's peer ID
    pub peer_id: PeerId,
    /// Network addresses
    pub addresses: Vec<Multiaddr>,
    /// Known DHT key (optional)
    pub dht_key: Option<Key>,
}

/// DHT network operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkOperation {
    /// Store a value in the DHT
    Put { key: Key, value: Vec<u8> },
    /// Retrieve a value from the DHT
    Get { key: Key },
    /// Find nodes closest to a key
    FindNode { key: Key },
    /// Find value or closest nodes
    FindValue { key: Key },
    /// Ping a node to check availability
    Ping,
    /// Join the DHT network
    Join,
    /// Leave the DHT network gracefully
    Leave,
}

/// Per-peer outcome from a DHT PUT replication attempt.
///
/// Captures whether each target peer successfully stored the value,
/// along with optional error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStoreOutcome {
    /// The peer that was targeted for replication.
    pub peer_id: PeerId,
    /// Whether the store operation succeeded on this peer.
    pub success: bool,
    /// Error description if the operation failed.
    pub error: Option<String>,
}

/// DHT network operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkResult {
    /// Successful PUT operation
    PutSuccess {
        key: Key,
        replicated_to: usize,
        /// Per-peer replication outcomes (empty for remote handlers).
        peer_outcomes: Vec<PeerStoreOutcome>,
    },
    /// Successful GET operation
    GetSuccess {
        key: Key,
        value: Vec<u8>,
        source: PeerId,
    },
    /// GET operation found no value
    GetNotFound {
        key: Key,
        /// Number of peers queried during the lookup.
        peers_queried: usize,
        /// Number of peers that returned errors during the lookup.
        peers_failed: usize,
        /// Last error encountered during the lookup, if any.
        last_error: Option<String>,
    },
    /// Nodes found for FIND_NODE or iterative lookup
    NodesFound {
        key: Key,
        nodes: Vec<SerializableDHTNode>,
    },
    /// Value found for FIND_VALUE
    ValueFound {
        key: Key,
        value: Vec<u8>,
        source: PeerId,
    },
    /// Ping response
    PongReceived {
        responder: PeerId,
        latency: Duration,
    },
    /// Join confirmation
    JoinSuccess {
        assigned_key: Key,
        bootstrap_peers: usize,
    },
    /// Leave confirmation
    LeaveSuccess,
    /// Operation failed
    Error { operation: String, error: String },
}

/// Returns the variant name of a [`DhtNetworkResult`] without exposing internal data.
fn dht_network_result_variant_name(result: &DhtNetworkResult) -> &'static str {
    match result {
        DhtNetworkResult::PutSuccess { .. } => "PutSuccess",
        DhtNetworkResult::GetSuccess { .. } => "GetSuccess",
        DhtNetworkResult::GetNotFound { .. } => "GetNotFound",
        DhtNetworkResult::NodesFound { .. } => "NodesFound",
        DhtNetworkResult::ValueFound { .. } => "ValueFound",
        DhtNetworkResult::PongReceived { .. } => "PongReceived",
        DhtNetworkResult::JoinSuccess { .. } => "JoinSuccess",
        DhtNetworkResult::LeaveSuccess => "LeaveSuccess",
        DhtNetworkResult::Error { .. } => "Error",
    }
}

/// DHT message envelope for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkMessage {
    /// Message ID for request/response correlation
    pub message_id: String,
    /// Source peer ID
    pub source: PeerId,
    /// Target peer ID (optional for broadcast)
    pub target: Option<PeerId>,
    /// Message type
    pub message_type: DhtMessageType,
    /// DHT operation payload (for requests)
    pub payload: DhtNetworkOperation,
    /// DHT operation result (for responses)
    pub result: Option<DhtNetworkResult>,
    /// Timestamp when message was created
    pub timestamp: u64,
    /// TTL for message forwarding
    pub ttl: u8,
    /// Hop count for routing
    pub hop_count: u8,
}

/// DHT message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageType {
    /// Request message
    Request,
    /// Response message
    Response,
    /// Broadcast message
    Broadcast,
    /// Error response
    Error,
}

/// Main DHT Network Manager
///
/// This manager handles DHT operations (peer discovery, routing, storage) but does
/// **not** own the transport lifecycle. The caller that supplies the
/// [`TransportHandle`](crate::transport_handle::TransportHandle) is responsible for
/// starting listeners and stopping the transport. For example, when `P2PNode` creates
/// the manager it starts transport listeners first, then starts this manager, and
/// stops transport after `DhtNetworkManager::stop()`.
pub struct DhtNetworkManager {
    /// DHT instance
    dht: Arc<RwLock<DhtCoreEngine>>,
    /// Transport handle for QUIC connections, peer registry, and message I/O
    transport: Arc<crate::transport_handle::TransportHandle>,
    /// EigenTrust engine for reputation management (optional)
    trust_engine: Option<Arc<EigenTrustEngine>>,
    /// Configuration
    config: DhtNetworkConfig,
    /// Active DHT operations
    active_operations: Arc<Mutex<HashMap<String, DhtOperationContext>>>,
    /// Network message broadcaster
    event_tx: broadcast::Sender<DhtNetworkEvent>,
    /// Known DHT peers
    dht_peers: Arc<RwLock<HashMap<PeerId, DhtPeerInfo>>>,
    /// Operation statistics
    stats: Arc<RwLock<DhtNetworkStats>>,
    /// Maintenance scheduler for periodic security and DHT tasks
    maintenance_scheduler: Arc<RwLock<MaintenanceScheduler>>,
    /// Semaphore for limiting concurrent message handlers (backpressure)
    message_handler_semaphore: Arc<Semaphore>,
    /// Cached local DHT key to avoid repeated SHA-256 hashing
    /// PERF-001: Eliminates redundant computation in message handlers
    local_dht_key: DhtKey,
    /// Transport-level peer ID (hex-encoded ant-quic PeerId).
    /// Used to filter out self-references during iterative DHT lookups,
    /// because FindNode responses use transport IDs, not app-level peer IDs.
    local_transport_peer_id: Option<String>,
    /// Hex-encoded local DHT key, cached to avoid repeated allocation in
    /// `is_local_peer_id` which runs in hot loops.
    local_dht_key_hex: String,
    /// Shutdown token for background tasks
    shutdown: CancellationToken,
    /// Handle for the maintenance task so it can be joined on stop
    maintenance_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Handle for the network event handler task
    event_handler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

/// DHT operation context
///
/// Uses oneshot channel for response delivery to eliminate TOCTOU races.
/// The sender is stored here; the receiver is held by wait_for_response().
#[allow(dead_code)]
struct DhtOperationContext {
    /// Operation type
    operation: DhtNetworkOperation,
    /// Target peer ID
    peer_id: PeerId,
    /// Start time
    started_at: Instant,
    /// Timeout
    timeout: Duration,
    /// Contacted nodes (for response source validation)
    contacted_nodes: Vec<PeerId>,
    /// Oneshot sender for delivering the response
    /// None if response already sent (channel consumed)
    response_tx: Option<oneshot::Sender<(PeerId, DhtNetworkResult)>>,
}

impl std::fmt::Debug for DhtOperationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtOperationContext")
            .field("operation", &self.operation)
            .field("peer_id", &self.peer_id)
            .field("started_at", &self.started_at)
            .field("timeout", &self.timeout)
            .field("contacted_nodes", &self.contacted_nodes)
            .field("response_tx", &self.response_tx.is_some())
            .finish()
    }
}

/// DHT peer information
#[derive(Debug, Clone)]
pub struct DhtPeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// DHT key/ID in the DHT address space
    pub dht_key: Key,
    /// Network addresses
    pub addresses: Vec<Multiaddr>,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Connection status
    pub is_connected: bool,
    /// Response latency statistics
    pub avg_latency: Duration,
    /// Reliability score (0.0 to 1.0)
    pub reliability_score: f64,
}

/// DHT network events
#[derive(Debug, Clone)]
pub enum DhtNetworkEvent {
    /// New DHT peer discovered
    PeerDiscovered { peer_id: PeerId, dht_key: Key },
    /// DHT peer disconnected
    PeerDisconnected { peer_id: PeerId },
    /// DHT operation completed
    OperationCompleted {
        operation: String,
        success: bool,
        duration: Duration,
    },
    /// DHT network status changed
    NetworkStatusChanged {
        connected_peers: usize,
        routing_table_size: usize,
    },
    /// Error occurred
    Error { error: String },
    /// Replication result for a PUT operation with per-peer details
    ReplicationResult {
        /// The key being replicated
        key: Key,
        /// Total number of peers targeted
        total_peers: usize,
        /// Number of peers that successfully stored the value
        successful_peers: usize,
        /// Per-peer outcomes
        outcomes: Vec<PeerStoreOutcome>,
    },
}

/// DHT network statistics
#[derive(Debug, Clone, Default)]
pub struct DhtNetworkStats {
    /// Total operations performed
    pub total_operations: u64,
    /// Successful operations
    pub successful_operations: u64,
    /// Failed operations
    pub failed_operations: u64,
    /// Average operation latency
    pub avg_operation_latency: Duration,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Connected DHT peers
    pub connected_peers: usize,
    /// Routing table size
    pub routing_table_size: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LookupRequestKind {
    Get,
    FindNode,
    FindValue,
}

impl DhtNetworkManager {
    fn init_dht_core(local_peer_id: &PeerId) -> Result<(Arc<RwLock<DhtCoreEngine>>, DhtKey)> {
        let dht_key = crate::dht::derive_dht_key_from_peer_id(local_peer_id);
        let node_id = DhtNodeId::from_bytes(dht_key);
        // Use LogOnly mode so nodes can join the routing table without prior validation.
        // Strict mode rejects every unknown node, making it impossible to bootstrap a
        // fresh network (chicken-and-egg: no node can be validated until it's in the RT).
        let dht_instance = DhtCoreEngine::new_with_validation_mode(
            node_id,
            crate::dht::routing_maintenance::close_group_validator::CloseGroupEnforcementMode::LogOnly,
        )
            .map_err(|e| P2PError::Dht(DhtError::StorageFailed(e.to_string().into())))?;
        dht_instance.start_maintenance_tasks();
        let dht = Arc::new(RwLock::new(dht_instance));
        Ok((dht, DhtKey::from_bytes(dht_key)))
    }

    fn new_from_components(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<EigenTrustEngine>>,
        config: DhtNetworkConfig,
    ) -> Result<Self> {
        let (dht, local_dht_key) = Self::init_dht_core(&config.local_peer_id)?;

        let (event_tx, _) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let maintenance_config = MaintenanceConfig::from(&config.dht_config);
        let maintenance_scheduler =
            Arc::new(RwLock::new(MaintenanceScheduler::new(maintenance_config)));
        let message_handler_semaphore = Arc::new(Semaphore::new(
            config
                .max_concurrent_operations
                .max(MIN_CONCURRENT_OPERATIONS),
        ));

        let local_transport_peer_id = transport.transport_peer_id();
        let local_dht_key_hex = hex::encode(local_dht_key.as_bytes());

        Ok(Self {
            dht,
            transport,
            trust_engine,
            config,
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            dht_peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DhtNetworkStats::default())),
            maintenance_scheduler,
            message_handler_semaphore,
            local_dht_key,
            local_transport_peer_id,
            local_dht_key_hex,
            shutdown: CancellationToken::new(),
            maintenance_handle: Arc::new(RwLock::new(None)),
            event_handler_handle: Arc::new(RwLock::new(None)),
        })
    }

    fn validate_put_value_size(value_len: usize, context: &str) -> Result<()> {
        if value_len > MAX_VALUE_SIZE {
            warn!(
                "Rejecting PUT with oversized value during {}: {} bytes (max: {} bytes)",
                context, value_len, MAX_VALUE_SIZE
            );
            return Err(P2PError::Validation(
                format!(
                    "Value size {} bytes exceeds maximum allowed size of {} bytes",
                    value_len, MAX_VALUE_SIZE
                )
                .into(),
            ));
        }
        Ok(())
    }

    async fn store_local_in_core(&self, key: Key, value: Vec<u8>, operation: &str) -> Result<()> {
        self.dht
            .write()
            .await
            .store(&DhtKey::from_bytes(key), value)
            .await
            .map_err(|e| {
                P2PError::Dht(crate::error::DhtError::StoreFailed(
                    format!("{operation} failed for key {}: {e}", hex::encode(key)).into(),
                ))
            })?;
        Ok(())
    }

    async fn retrieve_local_from_core(
        &self,
        key: &Key,
        operation: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.dht
            .read()
            .await
            .retrieve(&DhtKey::from_bytes(*key))
            .await
            .map_err(|e| {
                P2PError::Dht(crate::error::DhtError::StoreFailed(
                    format!("{operation} failed for key {}: {e}", hex::encode(key)).into(),
                ))
            })
    }

    async fn handle_lookup_request(
        &self,
        key: &Key,
        requester: &PeerId,
        kind: LookupRequestKind,
    ) -> Result<DhtNetworkResult> {
        if kind != LookupRequestKind::FindNode {
            match self.retrieve_local_from_core(key, "Lookup retrieve").await {
                Ok(Some(value)) => {
                    if kind == LookupRequestKind::Get {
                        return Ok(DhtNetworkResult::GetSuccess {
                            key: *key,
                            value,
                            source: self.config.local_peer_id.clone(),
                        });
                    }

                    return Ok(DhtNetworkResult::ValueFound {
                        key: *key,
                        value,
                        source: self.config.local_peer_id.clone(),
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Lookup retrieve failed for key {}: {e}", hex::encode(key));
                }
            }
        }

        if kind == LookupRequestKind::Get {
            trace!(
                "GET: value not found locally for key {}, returning closer nodes if available",
                hex::encode(key)
            );
        } else if kind == LookupRequestKind::FindValue {
            trace!(
                "FIND_VALUE: value not found locally for key {}, returning closer nodes if available",
                hex::encode(key)
            );
        } else {
            trace!(
                "FIND_NODE: resolving closer nodes for key {}",
                hex::encode(key)
            );
        }

        let candidate_nodes = self
            .find_closest_nodes_local(key, DHT_CLOSEST_NODES_COUNT)
            .await;
        let closer_nodes = Self::filter_response_nodes(candidate_nodes, requester);

        if closer_nodes.is_empty() {
            return Ok(DhtNetworkResult::GetNotFound {
                key: *key,
                peers_queried: 0,
                peers_failed: 0,
                last_error: None,
            });
        }

        Ok(DhtNetworkResult::NodesFound {
            key: *key,
            nodes: closer_nodes,
        })
    }

    /// Create a new DHT Network Manager using an existing transport handle.
    ///
    /// The caller is responsible for the transport lifecycle and must stop
    /// transport after stopping this manager.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<EigenTrustEngine>>,
        mut config: DhtNetworkConfig,
    ) -> Result<Self> {
        let local_transport_peer_id = transport.peer_id().clone();
        if config.local_peer_id.is_empty() {
            config.local_peer_id = local_transport_peer_id.clone();
        } else if config.local_peer_id != local_transport_peer_id {
            warn!(
                "DHT config peer_id ({}) differs from transport peer_id ({}); using config value",
                config.local_peer_id, local_transport_peer_id
            );
        }

        info!(
            "Creating attached DHT Network Manager for peer: {}",
            config.local_peer_id
        );
        let manager = Self::new_from_components(transport, trust_engine, config)?;

        info!("Attached DHT Network Manager created successfully");
        Ok(manager)
    }

    /// Start the DHT network manager.
    ///
    /// This manager does not manage the transport lifecycle. If transport listeners
    /// are already running, startup reconciles currently connected peers after event
    /// subscription is established.
    ///
    /// Note: This method requires `self` to be wrapped in an `Arc` so that
    /// background tasks can hold references to the manager.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        info!("Starting DHT Network Manager...");

        // Subscribe to transport events before DHT background work starts.
        self.start_network_event_handler(Arc::clone(self)).await?;

        // Reconcile peers that may have connected before event subscription.
        self.reconcile_connected_peers().await;

        // Start DHT maintenance tasks
        self.start_maintenance_tasks().await?;

        info!("DHT Network Manager started successfully");
        Ok(())
    }

    /// Perform DHT peer discovery from already-connected bootstrap peers.
    ///
    /// Sends FIND_NODE(self) to each peer using the DHT postcard protocol,
    /// then dials any newly-discovered candidates. Returns the total number
    /// of new peers discovered.
    pub async fn bootstrap_from_peers(&self, peers: &[PeerId]) -> Result<usize> {
        let key = *self.local_dht_key.as_bytes();
        let mut discovered = 0;
        for peer_id in peers {
            let op = DhtNetworkOperation::FindNode { key };
            match self.send_dht_request(peer_id, op).await {
                Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                    for node in &nodes {
                        self.dial_candidate(&node.peer_id, &node.address).await;
                        discovered += 1;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Bootstrap FIND_NODE to {} failed: {}", peer_id, e);
                }
            }
        }
        Ok(discovered)
    }

    /// Stop the DHT network manager.
    ///
    /// Sends leave messages to connected peers and shuts down DHT operations.
    /// The caller is responsible for stopping the transport after this returns.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DHT Network Manager...");

        // Send leave messages to connected peers before shutting down tasks
        self.leave_network().await?;

        // Signal all background tasks to stop
        self.shutdown.cancel();

        // Signal the DHT core engine's maintenance task to stop
        self.dht.read().await.signal_shutdown();

        // Join the maintenance task
        if let Some(handle) = self.maintenance_handle.write().await.take() {
            match handle.await {
                Ok(()) => debug!("Maintenance task stopped cleanly"),
                Err(e) if e.is_cancelled() => debug!("Maintenance task was cancelled"),
                Err(e) => warn!("Maintenance task panicked: {}", e),
            }
        }

        // Join the event handler task
        if let Some(handle) = self.event_handler_handle.write().await.take() {
            match handle.await {
                Ok(()) => debug!("Event handler task stopped cleanly"),
                Err(e) if e.is_cancelled() => debug!("Event handler task was cancelled"),
                Err(e) => warn!("Event handler task panicked: {}", e),
            }
        }

        info!("DHT Network Manager stopped");
        Ok(())
    }

    /// Put a value in the DHT.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn put(&self, key: Key, value: Vec<u8>) -> Result<DhtNetworkResult> {
        info!(
            "Putting value for key: {} ({} bytes)",
            hex::encode(key),
            value.len()
        );

        Self::validate_put_value_size(value.len(), "local put")?;

        let operation = DhtNetworkOperation::Put {
            key,
            value: value.clone(),
        };

        // Find closest nodes for replication using network lookup
        let closest_nodes = self
            .find_closest_nodes_network(&key, self.config.replication_factor)
            .await?;

        debug!(
            "find_closest_nodes returned {} nodes for key: {}",
            closest_nodes.len(),
            hex::encode(key)
        );
        for (i, node) in closest_nodes.iter().enumerate() {
            trace!("  Node {}: peer_id={}", i, node.peer_id);
        }

        if closest_nodes.is_empty() {
            warn!(
                "No nodes found for key: {}, storing locally only",
                hex::encode(key)
            );
            self.store_local_in_core(key, value, "Local PUT storage")
                .await?;

            return Ok(DhtNetworkResult::PutSuccess {
                key,
                replicated_to: 1,
                peer_outcomes: Vec::new(),
            });
        }

        self.store_local_in_core(key, value.clone(), "Local PUT storage")
            .await?;

        // Replicate to closest nodes in parallel for better performance
        let mut replicated_count = 1; // Local storage

        // Create parallel replication requests
        let replication_futures = closest_nodes.iter().map(|node| {
            let peer_id = node.peer_id.clone();
            let op = operation.clone();
            async move {
                debug!("Sending PUT to peer: {}", peer_id);
                (peer_id.clone(), self.send_dht_request(&peer_id, op).await)
            }
        });

        // Execute all replication requests in parallel
        let results = futures::future::join_all(replication_futures).await;

        let (remote_successes, peer_outcomes) = self.collect_replication_outcomes(results).await;
        replicated_count += remote_successes;

        // Emit replication result event
        let total_peers = peer_outcomes.len();
        let successful_peers = peer_outcomes.iter().filter(|o| o.success).count();
        let _ = self.event_tx.send(DhtNetworkEvent::ReplicationResult {
            key,
            total_peers,
            successful_peers,
            outcomes: peer_outcomes.clone(),
        });

        info!(
            "PUT operation completed: key={}, replicated_to={}/{}",
            hex::encode(key),
            replicated_count,
            closest_nodes.len().saturating_add(1)
        );

        Ok(DhtNetworkResult::PutSuccess {
            key,
            replicated_to: replicated_count,
            peer_outcomes,
        })
    }

    /// Store a value locally without network replication.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn store_local(&self, key: Key, value: Vec<u8>) -> Result<()> {
        self.store_local_in_core(key, value, "Local storage").await
    }

    /// Retrieve a value from local storage without network lookup.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn get_local(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.retrieve_local_from_core(key, "Local retrieve").await
    }

    /// Put a value in the DHT targeting a specific set of peers.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn put_with_targets(
        &self,
        key: Key,
        value: Vec<u8>,
        targets: &[PeerId],
    ) -> Result<DhtNetworkResult> {
        Self::validate_put_value_size(value.len(), "targeted put")?;

        let operation = DhtNetworkOperation::Put {
            key,
            value: value.clone(),
        };

        self.store_local(key, value.clone()).await?;

        let mut replicated_count = 1usize;
        let replication_futures = targets.iter().map(|peer_id| {
            let peer = peer_id.clone();
            let op = operation.clone();
            async move { (peer.clone(), self.send_dht_request(&peer, op).await) }
        });

        let results = futures::future::join_all(replication_futures).await;
        let (remote_successes, peer_outcomes) = self.collect_replication_outcomes(results).await;
        replicated_count += remote_successes;

        Ok(DhtNetworkResult::PutSuccess {
            key,
            replicated_to: replicated_count,
            peer_outcomes,
        })
    }

    /// Get a value from the DHT with iterative (recursive) lookup.
    ///
    /// This implements Kademlia-style iterative lookup to discover data beyond
    /// directly connected nodes by recursively querying closer nodes.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn get(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Getting value for key: {}", hex::encode(key));

        // Check local storage first
        match self
            .dht
            .read()
            .await
            .retrieve(&DhtKey::from_bytes(*key))
            .await
        {
            Ok(Some(value)) => {
                info!("Found value locally for key: {}", hex::encode(key));
                return Ok(DhtNetworkResult::GetSuccess {
                    key: *key,
                    value,
                    source: self.config.local_peer_id.clone(),
                });
            }
            Ok(None) => {
                debug!(
                    "Key {} not in local storage, proceeding with network lookup",
                    hex::encode(key)
                );
            }
            Err(e) => {
                warn!(
                    "Local retrieve failed for key {}: {e}, proceeding with network lookup",
                    hex::encode(key)
                );
            }
        }

        // Iterative lookup parameters
        const MAX_ITERATIONS: usize = 20;
        const ALPHA: usize = 3; // Parallel queries per iteration

        let mut queried_nodes = HashSet::new();
        let mut candidate_nodes = VecDeque::new();
        let mut queued_peer_ids: HashSet<String> = HashSet::new();
        let mut peers_failed: usize = 0;
        let mut last_error: Option<String> = None;

        // Never send an RPC to ourselves (we already checked local storage above).
        self.mark_self_queried(&mut queried_nodes);

        // Get initial candidates from local routing table and connected peers
        // IMPORTANT: Use find_closest_nodes_local to avoid making network requests
        // before the iterative lookup loop starts - we want to start with only nodes we know about
        let initial = self.find_closest_nodes_local(key, ALPHA * 2).await;

        for node in initial {
            queued_peer_ids.insert(node.peer_id.clone());
            candidate_nodes.push_back(node);
        }

        let mut previous_candidate_snapshot: Option<BTreeSet<String>> = None;

        // Iterative lookup loop
        for iteration in 0..MAX_ITERATIONS {
            if candidate_nodes.is_empty() {
                debug!("No more candidates after {} iterations", iteration);
                break;
            }

            // Build batch by draining nodes until we have ALPHA unqueried nodes
            // or exhaust the candidate queue. This prevents premature termination
            // when the first ALPHA drained nodes are all already queried.
            let mut batch = Vec::new();
            while batch.len() < ALPHA && !candidate_nodes.is_empty() {
                if let Some(node) = candidate_nodes.pop_front() {
                    queued_peer_ids.remove(&node.peer_id);
                    if !queried_nodes.contains(&node.peer_id) {
                        batch.push(node);
                    }
                }
                // If already queried, discard and continue draining
            }

            if batch.is_empty() {
                debug!(
                    "All candidates already queried after {} iterations",
                    iteration
                );
                break;
            }

            info!(
                "[ITERATIVE LOOKUP] {}: Iteration {}, querying {} nodes: {:?}",
                self.config.local_peer_id,
                iteration,
                batch.len(),
                batch
                    .iter()
                    .map(|n| format!("{}@{}", &n.peer_id[..8.min(n.peer_id.len())], &n.address))
                    .collect::<Vec<_>>()
            );

            // Query batch in parallel using FindValue operation
            // For each node, ensure we're connected before querying
            // ant-quic multiplexes streams on a single socket, so issuing ALPHA
            // parallel queries here does not consume extra listening ports.
            let query_futures: Vec<_> = batch
                .iter()
                .map(|node| {
                    let peer_id = node.peer_id.clone();
                    let address = node.address.clone();
                    let op = DhtNetworkOperation::FindValue { key: *key };
                    async move {
                        self.dial_candidate(&peer_id, &address).await;
                        (peer_id.clone(), self.send_dht_request(&peer_id, op).await)
                    }
                })
                .collect();

            let results = futures::future::join_all(query_futures).await;

            // Process results
            for (peer_id, result) in results {
                queried_nodes.insert(peer_id.clone());
                info!(
                    "[ITERATIVE LOOKUP] {}: Got result from {}: {:?}",
                    self.config.local_peer_id,
                    &peer_id[..8.min(peer_id.len())],
                    result.as_ref().map(std::mem::discriminant)
                );

                match result {
                    Ok(DhtNetworkResult::ValueFound { value, source, .. })
                    | Ok(DhtNetworkResult::GetSuccess { value, source, .. }) => {
                        self.record_peer_success(&peer_id).await;
                        // FOUND IT!
                        info!("Found value via iterative lookup from {}", source);

                        // Cache locally
                        let mut dht_guard = self.dht.write().await;
                        if let Err(e) = dht_guard
                            .store(&DhtKey::from_bytes(*key), value.clone())
                            .await
                        {
                            warn!("Failed to cache retrieved value: {}", e);
                        }

                        return Ok(DhtNetworkResult::GetSuccess {
                            key: *key,
                            value,
                            source,
                        });
                    }
                    Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                        self.record_peer_success(&peer_id).await;
                        // Got closer nodes - add them to candidates with bounds checking
                        info!(
                            "[ITERATIVE LOOKUP] {}: Peer {} returned {} closer nodes: {:?}",
                            self.config.local_peer_id,
                            &peer_id[..8.min(peer_id.len())],
                            nodes.len(),
                            nodes
                                .iter()
                                .map(|n| format!(
                                    "{}@{}",
                                    &n.peer_id[..8.min(n.peer_id.len())],
                                    &n.address
                                ))
                                .collect::<Vec<_>>()
                        );
                        for mut node in nodes {
                            Self::ensure_cached_dht_key(&mut node);
                            if queried_nodes.contains(&node.peer_id)
                                || queued_peer_ids.contains(&node.peer_id)
                                || self.is_local_peer_id(&node.peer_id)
                            {
                                continue;
                            }
                            if candidate_nodes.len() >= MAX_CANDIDATE_NODES {
                                trace!(
                                    "Candidate queue at capacity ({}), preserving oldest entries and dropping {}",
                                    MAX_CANDIDATE_NODES,
                                    &node.peer_id[..8.min(node.peer_id.len())]
                                );
                                continue;
                            }
                            queued_peer_ids.insert(node.peer_id.clone());
                            candidate_nodes.push_back(node);
                        }
                    }
                    Ok(DhtNetworkResult::GetNotFound { .. }) => {
                        self.record_peer_success(&peer_id).await;
                        // This peer doesn't have it, continue
                        debug!("Peer {} does not have value", peer_id);
                    }
                    Err(e) => {
                        debug!("Query to {} failed: {}", peer_id, e);
                        peers_failed += 1;
                        last_error = Some(e.to_string());
                        self.record_peer_failure(&peer_id).await;
                    }
                    Ok(other) => {
                        debug!("Unexpected result from {}: {:?}", peer_id, other);
                        peers_failed += 1;
                        last_error = Some(format!("Unexpected result: {:?}", other));
                        self.record_peer_failure(&peer_id).await;
                    }
                }
            }
            let snapshot: BTreeSet<String> = queued_peer_ids.iter().cloned().collect();
            if let Some(previous) = &previous_candidate_snapshot
                && !snapshot.is_empty()
                && *previous == snapshot
            {
                info!(
                    "[ITERATIVE LOOKUP] {}: Candidate set stagnated after {} iterations, stopping",
                    self.config.local_peer_id,
                    iteration + 1
                );
                break;
            }
            previous_candidate_snapshot = Some(snapshot);
        }

        // Not found after exhausting all paths
        info!(
            "Value not found for key {} after iterative lookup ({} nodes queried)",
            hex::encode(key),
            queried_nodes.len()
        );
        Ok(DhtNetworkResult::GetNotFound {
            key: *key,
            peers_queried: queried_nodes.len(),
            peers_failed,
            last_error,
        })
    }

    /// Backwards-compatible API that performs a full iterative lookup.
    pub async fn find_closest_nodes(&self, key: &Key, count: usize) -> Result<Vec<DHTNode>> {
        self.find_closest_nodes_network(key, count).await
    }

    /// Find nodes closest to a key using iterative network lookup
    pub async fn find_node(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Finding nodes closest to key: {}", hex::encode(key));

        let closest_nodes = self
            .find_closest_nodes_network(key, self.config.replication_factor * 2)
            .await?;
        let serializable_nodes: Vec<SerializableDHTNode> = closest_nodes.into_iter().collect();

        info!(
            "Found {} nodes closest to key: {}",
            serializable_nodes.len(),
            hex::encode(key)
        );
        Ok(DhtNetworkResult::NodesFound {
            key: *key,
            nodes: serializable_nodes,
        })
    }

    /// Ping a specific node
    pub async fn ping(&self, peer_id: &PeerId) -> Result<DhtNetworkResult> {
        info!("Pinging peer: {}", peer_id);

        let start_time = Instant::now();
        let operation = DhtNetworkOperation::Ping;

        match self.send_dht_request(peer_id, operation).await {
            Ok(DhtNetworkResult::PongReceived { responder, .. }) => {
                let latency = start_time.elapsed();
                info!("Received pong from {} in {:?}", responder, latency);
                Ok(DhtNetworkResult::PongReceived { responder, latency })
            }
            Ok(result) => {
                warn!("Unexpected ping result: {:?}", result);
                Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Unexpected ping response".to_string().into(),
                )))
            }
            Err(e) => {
                warn!("Ping failed to {}: {}", peer_id, e);
                Err(e)
            }
        }
    }

    /// Leave the DHT network gracefully
    async fn leave_network(&self) -> Result<()> {
        info!("Leaving DHT network...");

        let leave_operation = DhtNetworkOperation::Leave;
        let connected_peers: Vec<PeerId> = {
            let peers = self.dht_peers.read().await;
            peers.keys().cloned().collect()
        };

        // Send leave messages to all connected peers
        for peer_id in connected_peers {
            match self
                .send_dht_request(&peer_id, leave_operation.clone())
                .await
            {
                Ok(_) => {
                    debug!("Sent leave message to peer: {}", peer_id);
                }
                Err(e) => {
                    warn!("Failed to send leave message to {}: {}", peer_id, e);
                }
            }
        }

        info!("DHT network leave completed");
        Ok(())
    }

    // =========================================================================
    // FIND CLOSEST NODES API
    // =========================================================================
    //
    // Two functions for finding closest nodes to a key:
    //
    // 1. find_closest_nodes_local() - Instant address book check
    //    - Only checks local routing table + connected peers
    //    - No network requests, safe to call from request handlers
    //    - Returns nodes we already know about
    //
    // 2. find_closest_nodes_network() - Iterative network lookup
    //    - Starts with local knowledge, then queries the network
    //    - Asks known nodes for their closest nodes, then queries those
    //    - Continues until convergence (same answers or worse quality)
    //    - Full Kademlia-style iterative lookup
    // =========================================================================

    /// Find closest nodes to a key using ONLY local knowledge.
    ///
    /// This is an instant address book check - no network requests are made.
    /// Safe to call from request handlers without risk of deadlock.
    ///
    /// Returns nodes from:
    /// - Local routing table
    /// - Currently connected peers
    ///
    /// Results are sorted by XOR distance to the key.
    pub async fn find_closest_nodes_local(&self, key: &Key, count: usize) -> Vec<DHTNode> {
        debug!(
            "[LOCAL] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let mut seen_peer_ids: HashSet<String> = HashSet::new();
        let mut all_nodes: Vec<DHTNode> = Vec::new();

        // 1. Check local routing table
        {
            let dht_guard = self.dht.read().await;
            match dht_guard.find_nodes(&DhtKey::from_bytes(*key), count).await {
                Ok(nodes) => {
                    for node in nodes {
                        let id = node.id.to_string();
                        if self.is_local_peer_id(&id) {
                            continue;
                        }
                        if seen_peer_ids.insert(id.clone()) {
                            all_nodes.push(DHTNode {
                                peer_id: id,
                                address: node.address,
                                distance: None,
                                reliability: node.capacity.reliability_score,
                                cached_dht_key: Some(DhtKey::from_bytes(*node.id.as_bytes())),
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!("find_nodes failed for key {}: {e}", hex::encode(key));
                }
            }
        }

        // 2. Add connected peers
        {
            let peers = self.dht_peers.read().await;
            for (peer_id, peer_info) in peers.iter() {
                if !peer_info.is_connected {
                    continue;
                }
                if self.is_local_peer_id(peer_id) {
                    continue;
                }
                if !seen_peer_ids.insert(peer_id.clone()) {
                    continue;
                }
                let address = match peer_info.addresses.first() {
                    Some(a) => a.to_string(),
                    None => continue,
                };
                all_nodes.push(DHTNode {
                    peer_id: peer_id.clone(),
                    address,
                    distance: Some(peer_info.dht_key.to_vec()),
                    reliability: peer_info.reliability_score,
                    cached_dht_key: Some(DhtKey::from_bytes(peer_info.dht_key)),
                });
            }
        }

        // Sort by XOR distance and return closest
        all_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        all_nodes.into_iter().take(count).collect()
    }

    /// Find closest nodes to a key using iterative network lookup.
    ///
    /// This implements Kademlia-style iterative lookup:
    /// 1. Start with nodes from local address book
    /// 2. Query those nodes for their closest nodes to the key
    /// 3. Query the returned nodes, repeat
    /// 4. Stop when converged (same or worse answers)
    ///
    /// This makes network requests and should NOT be called from request handlers.
    pub async fn find_closest_nodes_network(
        &self,
        key: &Key,
        count: usize,
    ) -> Result<Vec<DHTNode>> {
        const MAX_ITERATIONS: usize = 20;
        const ALPHA: usize = 3; // Parallel queries per iteration

        debug!(
            "[NETWORK] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let mut queried_nodes: HashSet<String> = HashSet::new();
        let mut best_nodes: Vec<DHTNode> = Vec::new();
        let mut queued_peer_ids: HashSet<String> = HashSet::new();

        // Kademlia correctness: the local node must compete on distance in the
        // final K-closest result, but we must never send an RPC to ourselves.
        // Seed best_nodes with self and mark self as "queried" so the iterative
        // loop never tries to contact us.
        best_nodes.push(self.local_dht_node());
        self.mark_self_queried(&mut queried_nodes);

        // Start with local knowledge
        let initial = self.find_closest_nodes_local(key, count).await;
        let mut candidates: VecDeque<DHTNode> = VecDeque::new();
        for node in initial {
            queued_peer_ids.insert(node.peer_id.clone());
            candidates.push_back(node);
        }
        let mut previous_candidate_snapshot: Option<BTreeSet<String>> = None;

        for iteration in 0..MAX_ITERATIONS {
            if candidates.is_empty() {
                debug!(
                    "[NETWORK] No more candidates after {} iterations",
                    iteration
                );
                break;
            }

            // Select up to ALPHA unqueried nodes to query
            let mut batch: Vec<DHTNode> = Vec::new();
            while batch.len() < ALPHA && !candidates.is_empty() {
                if let Some(node) = candidates.pop_front() {
                    queued_peer_ids.remove(&node.peer_id);
                    if !queried_nodes.contains(&node.peer_id) {
                        batch.push(node);
                    }
                }
            }

            if batch.is_empty() {
                debug!(
                    "[NETWORK] All candidates queried after {} iterations",
                    iteration
                );
                break;
            }

            info!(
                "[NETWORK] Iteration {}: querying {} nodes",
                iteration,
                batch.len()
            );

            // Query nodes in parallel
            // ant-quic connection multiplexing lets us keep a single transport socket
            // while still querying multiple peers concurrently.
            let query_futures: Vec<_> = batch
                .iter()
                .map(|node| {
                    let peer_id = node.peer_id.clone();
                    let address = node.address.clone();
                    let op = DhtNetworkOperation::FindNode { key: *key };
                    async move {
                        self.dial_candidate(&peer_id, &address).await;
                        (peer_id.clone(), self.send_dht_request(&peer_id, op).await)
                    }
                })
                .collect();

            let results = futures::future::join_all(query_futures).await;

            let mut found_new_closer = false;
            for (peer_id, result) in results {
                queried_nodes.insert(peer_id.clone());

                match result {
                    Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                        self.record_peer_success(&peer_id).await;
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                        for mut node in nodes {
                            Self::ensure_cached_dht_key(&mut node);
                            if queried_nodes.contains(&node.peer_id)
                                || queued_peer_ids.contains(&node.peer_id)
                                || self.is_local_peer_id(&node.peer_id)
                            {
                                continue;
                            }
                            // A candidate is "dominated" only if we already have K
                            // best_nodes AND the candidate is no closer than the
                            // farthest node in our best set. best_nodes is sorted
                            // by distance at the end of each iteration, so .last()
                            // is the farthest.
                            let dominated = best_nodes.len() >= count
                                && best_nodes.last().is_some_and(|worst| {
                                    matches!(
                                        Self::compare_node_distance(&node, worst, key),
                                        std::cmp::Ordering::Equal | std::cmp::Ordering::Greater
                                    )
                                });
                            if !dominated {
                                if candidates.len() >= MAX_CANDIDATE_NODES {
                                    trace!(
                                        "[NETWORK] Candidate queue at capacity ({}), dropping {}",
                                        MAX_CANDIDATE_NODES,
                                        &node.peer_id[..8.min(node.peer_id.len())]
                                    );
                                    continue;
                                }
                                queued_peer_ids.insert(node.peer_id.clone());
                                candidates.push_back(node);
                                found_new_closer = true;
                            }
                        }
                    }
                    Ok(_) => {
                        self.record_peer_success(&peer_id).await;
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                    }
                    Err(e) => {
                        trace!("[NETWORK] Query to {} failed: {}", peer_id, e);
                        self.record_peer_failure(&peer_id).await;
                        // Don't add failed nodes to best_nodes - they can't be used for replication
                    }
                }
            }

            // Sort and truncate once per iteration instead of per result
            best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
            best_nodes.truncate(count);

            if !found_new_closer {
                info!("[NETWORK] Converged after {} iterations", iteration + 1);
                break;
            }

            let snapshot: BTreeSet<String> = queued_peer_ids.iter().cloned().collect();
            if let Some(previous) = &previous_candidate_snapshot
                && !snapshot.is_empty()
                && *previous == snapshot
            {
                info!(
                    "[NETWORK] {}: Candidate set stagnated after {} iterations, stopping",
                    self.config.local_peer_id,
                    iteration + 1
                );
                break;
            }
            previous_candidate_snapshot = Some(snapshot);
        }

        best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        best_nodes.truncate(count);

        info!(
            "[NETWORK] Found {} closest nodes: {:?}",
            best_nodes.len(),
            best_nodes
                .iter()
                .map(|n| &n.peer_id[..8.min(n.peer_id.len())])
                .collect::<Vec<_>>()
        );

        Ok(best_nodes)
    }

    /// Compare two nodes by their XOR distance to a target key
    ///
    /// PERF-001: Uses cached DHT keys to avoid repeated SHA-256 hashing.
    /// Falls back to parse_peer_id_to_key only if cached key is missing.
    ///
    /// If a peer ID cannot be decoded, it is placed at the end (treated as maximum distance).
    /// This prevents malformed peer IDs from being incorrectly treated as close to the target.
    fn compare_node_distance(a: &DHTNode, b: &DHTNode, key: &Key) -> std::cmp::Ordering {
        // Use cached keys if available, fallback to parsing if not
        let a_fallback;
        let a_key_ref = match a.cached_dht_key.as_ref() {
            Some(k) => Some(k),
            None => {
                a_fallback = Self::parse_peer_id_to_key(&a.peer_id);
                a_fallback.as_ref()
            }
        };
        let b_fallback;
        let b_key_ref = match b.cached_dht_key.as_ref() {
            Some(k) => Some(k),
            None => {
                b_fallback = Self::parse_peer_id_to_key(&b.peer_id);
                b_fallback.as_ref()
            }
        };

        match (a_key_ref, b_key_ref) {
            (Some(a_key), Some(b_key)) => {
                let target_key = DhtKey::from_bytes(*key);
                a_key
                    .distance(&target_key)
                    .cmp(&b_key.distance(&target_key))
            }
            // Invalid peer IDs sort to the end
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    }

    /// Return the K-closest candidate nodes, excluding the requester.
    ///
    /// Per Kademlia, a FindNode response should contain the K closest nodes
    /// the responder knows about — regardless of whether they are closer or
    /// farther than the responder itself. The requester is excluded because
    /// it already knows its own address.
    fn filter_response_nodes(
        candidate_nodes: Vec<DHTNode>,
        requester_peer_id: &PeerId,
    ) -> Vec<DHTNode> {
        candidate_nodes
            .into_iter()
            .filter(|node| node.peer_id != *requester_peer_id)
            .collect()
    }

    /// Build a `DHTNode` representing the local node for inclusion in
    /// K-closest results. The local node always participates in distance
    /// ranking but is never queried over the network.
    fn local_dht_node(&self) -> DHTNode {
        DHTNode {
            peer_id: self.config.local_peer_id.clone(),
            address: self.config.node_config.listen_addr.to_string(),
            distance: None,
            reliability: SELF_RELIABILITY_SCORE,
            cached_dht_key: Some(self.local_dht_key.clone()),
        }
    }

    /// Add both the app-level and transport-level local peer IDs to `queried`
    /// so that iterative lookups never send RPCs to the local node.
    fn mark_self_queried(&self, queried: &mut HashSet<String>) {
        queried.insert(self.config.local_peer_id.clone());
        if let Some(tid) = &self.local_transport_peer_id {
            queried.insert(tid.clone());
        }
    }

    /// Ensure a DHT node has a cached DHT key available for distance comparisons.
    fn ensure_cached_dht_key(node: &mut DHTNode) {
        if node.cached_dht_key.is_some() {
            return;
        }

        if let Some(distance) = node.distance.as_ref()
            && distance.len() == 32
        {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&distance[..32]);
            node.cached_dht_key = Some(DhtKey::from_bytes(key_bytes));
            return;
        }

        node.cached_dht_key = Self::parse_peer_id_to_key(&node.peer_id);
    }

    /// Parse a peer ID string to a DhtKey, returning None for invalid IDs.
    ///
    /// Uses the canonical `derive_dht_key_from_peer_id()` to ensure consistent
    /// DHT positioning across all nodes in the network.
    fn parse_peer_id_to_key(peer_id: &str) -> Option<DhtKey> {
        if peer_id.is_empty() {
            warn!("Empty peer ID");
            return None;
        }

        Some(DhtKey::from_bytes(crate::dht::derive_dht_key_from_peer_id(
            peer_id,
        )))
    }

    /// Convert peer addresses reported by the transport into multiaddresses the DHT understands.
    fn parse_peer_addresses(addresses: &[String]) -> Vec<Multiaddr> {
        addresses
            .iter()
            .filter_map(|addr| Self::multiaddr_from_address(addr))
            .collect()
    }

    /// Convert a human friendly socket string (possibly with a four-word suffix) into a Multiaddr.
    fn multiaddr_from_address(address: &str) -> Option<Multiaddr> {
        let clean_addr = address.split(" (").next().unwrap_or(address);
        match clean_addr.parse::<SocketAddr>() {
            Ok(socket_addr) => {
                let ip = socket_addr.ip();
                if ip.is_unspecified() {
                    warn!("Rejecting unspecified address: {clean_addr}");
                    return None;
                }
                if ip.is_loopback() {
                    trace!("Accepting loopback address (local/test): {clean_addr}");
                }
                Self::socket_addr_to_multiaddr(&socket_addr)
            }
            Err(e) => {
                warn!("Failed to parse '{clean_addr}' as SocketAddr: {e}");
                None
            }
        }
    }

    /// Render a SocketAddr as a Multiaddr, preserving IPv4/IPv6 protocol tags.
    fn socket_addr_to_multiaddr(socket_addr: &SocketAddr) -> Option<Multiaddr> {
        let ip_protocol = if socket_addr.ip().is_ipv4() {
            "ip4"
        } else {
            "ip6"
        };
        let multiaddr_string = format!(
            "/{}/{}/tcp/{}",
            ip_protocol,
            socket_addr.ip(),
            socket_addr.port()
        );
        match multiaddr_string.parse::<Multiaddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!(
                    "Failed to convert socket address {} to multiaddr: {}",
                    socket_addr, e
                );
                None
            }
        }
    }

    /// Process replication results from parallel PUT requests.
    ///
    /// Returns the number of successful replications and the per-peer outcomes.
    async fn collect_replication_outcomes(
        &self,
        results: Vec<(PeerId, Result<DhtNetworkResult>)>,
    ) -> (usize, Vec<PeerStoreOutcome>) {
        let mut successes = 0usize;
        let mut outcomes = Vec::with_capacity(results.len());
        for (peer_id, result) in results {
            match result {
                Ok(DhtNetworkResult::PutSuccess { .. }) => {
                    successes += 1;
                    self.record_peer_success(&peer_id).await;
                    debug!("Replicated to peer: {}", peer_id);
                    outcomes.push(PeerStoreOutcome {
                        peer_id,
                        success: true,
                        error: None,
                    });
                }
                Ok(other) => {
                    self.record_peer_failure(&peer_id).await;
                    let err_msg = format!(
                        "Unexpected result variant: {}",
                        dht_network_result_variant_name(&other)
                    );
                    debug!("Unexpected result from peer {}: {}", peer_id, err_msg);
                    outcomes.push(PeerStoreOutcome {
                        peer_id,
                        success: false,
                        error: Some(err_msg),
                    });
                }
                Err(e) => {
                    self.record_peer_failure(&peer_id).await;
                    let err_msg = e.to_string();
                    debug!("Failed to replicate to peer {}: {}", peer_id, err_msg);
                    outcomes.push(PeerStoreOutcome {
                        peer_id,
                        success: false,
                        error: Some(err_msg),
                    });
                }
            }
        }
        (successes, outcomes)
    }

    async fn record_peer_success(&self, peer_id: &str) {
        if let Some(ref engine) = self.trust_engine {
            let node_id = crate::network::peer_id_to_trust_node_id(peer_id);
            engine
                .update_node_stats(
                    &node_id,
                    crate::adaptive::NodeStatisticsUpdate::CorrectResponse,
                )
                .await;
        }
    }

    async fn record_peer_failure(&self, peer_id: &str) {
        if let Some(ref engine) = self.trust_engine {
            let node_id = crate::network::peer_id_to_trust_node_id(peer_id);
            engine
                .update_node_stats(
                    &node_id,
                    crate::adaptive::NodeStatisticsUpdate::FailedResponse,
                )
                .await;
        }
    }

    /// Remove expired operations from `active_operations`.
    ///
    /// Uses a 2x timeout multiplier as safety margin. Called at the start of
    /// `send_dht_request` to clean up orphaned entries from dropped futures.
    fn sweep_expired_operations(&self) {
        if let Ok(mut ops) = self.active_operations.lock() {
            let now = Instant::now();
            ops.retain(|id, ctx| {
                let expired = now.duration_since(ctx.started_at) > ctx.timeout * 2;
                if expired {
                    warn!(
                        "Sweeping expired DHT operation {id} (age {:?}, timeout {:?})",
                        now.duration_since(ctx.started_at),
                        ctx.timeout
                    );
                }
                !expired
            });
        }
    }

    /// Send a DHT request to a specific peer
    async fn send_dht_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
    ) -> Result<DhtNetworkResult> {
        // Sweep stale entries left by dropped futures before adding a new one
        self.sweep_expired_operations();

        let message_id = Uuid::new_v4().to_string();

        let message = DhtNetworkMessage {
            message_id: message_id.clone(),
            source: self.config.local_peer_id.clone(),
            target: Some(peer_id.clone()),
            message_type: DhtMessageType::Request,
            payload: operation,
            result: None, // Requests don't have results
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: 10,
            hop_count: 0,
        };

        // Serialize message
        let message_data = postcard::to_stdvec(&message)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Create oneshot channel for response delivery
        // This eliminates TOCTOU races - no polling, no shared mutable state
        let (response_tx, response_rx) = oneshot::channel();

        // Create operation context for tracking
        let operation_context = DhtOperationContext {
            operation: message.payload.clone(),
            peer_id: peer_id.clone(),
            started_at: Instant::now(),
            timeout: self.config.request_timeout,
            contacted_nodes: vec![peer_id.clone()],
            response_tx: Some(response_tx),
        };

        if let Ok(mut ops) = self.active_operations.lock() {
            ops.insert(message_id.clone(), operation_context);
        }

        // Send message via network layer
        info!(
            "[STEP 1] {} -> {}: Sending {:?} request (msg_id: {})",
            self.config.local_peer_id, peer_id, message.payload, message_id
        );
        let result = match self
            .transport
            .send_message(peer_id, "/dht/1.0.0", message_data)
            .await
        {
            Ok(_) => {
                info!(
                    "[STEP 2] {} -> {}: Message sent successfully, waiting for response...",
                    self.config.local_peer_id, peer_id
                );

                // Wait for response via oneshot channel with timeout
                let result = self.wait_for_response(&message_id, response_rx).await;
                match &result {
                    Ok(r) => info!(
                        "[STEP 6] {} <- {}: Got response: {:?}",
                        self.config.local_peer_id,
                        peer_id,
                        std::mem::discriminant(r)
                    ),
                    Err(e) => warn!(
                        "[STEP 6 FAILED] {} <- {}: Response error: {}",
                        self.config.local_peer_id, peer_id, e
                    ),
                }
                result
            }
            Err(e) => {
                warn!("[STEP 1 FAILED] Failed to send DHT request to {peer_id}: {e}");
                Err(e)
            }
        };

        // Explicit cleanup — no Drop guard, no tokio::spawn required
        if let Ok(mut ops) = self.active_operations.lock() {
            ops.remove(&message_id);
        }

        result
    }

    /// Check whether `peer_id` refers to this node in any of the three ID formats:
    /// 1. App-level peer ID (`"peer_xxxx"`)
    /// 2. Transport-level peer ID (hex-encoded ant-quic `PeerId` bytes)
    /// 3. DHT key (hex of SHA-256 of the transport peer ID)
    fn is_local_peer_id(&self, peer_id: &str) -> bool {
        peer_id == self.config.local_peer_id
            || self
                .local_transport_peer_id
                .as_ref()
                .is_some_and(|id| id == peer_id)
            || peer_id == self.local_dht_key_hex
    }

    /// Attempt to connect to a candidate peer with a timeout derived from the node config.
    ///
    /// All iterative lookups share the same ant-quic connection pool, so reusing the node's
    /// connection timeout keeps behavior consistent with the transport while still letting
    /// us parallelize lookups safely.
    async fn dial_candidate(&self, peer_id: &PeerId, address: &str) {
        if address.is_empty() {
            debug!("dial_candidate: peer {peer_id} missing address");
            return;
        }

        if self.transport.is_peer_connected(peer_id).await {
            debug!("dial_candidate: peer {peer_id} already connected");
            return;
        }

        let socket_addr = address.split(" (").next().unwrap_or(address);
        // Validate address before attempting connection
        if let Ok(parsed) = socket_addr.parse::<SocketAddr>()
            && parsed.ip().is_unspecified()
        {
            debug!("dial_candidate: rejecting unspecified address for {peer_id}: {socket_addr}");
            return;
        }
        let dial_timeout = self
            .transport
            .connection_timeout()
            .min(self.config.request_timeout);
        match tokio::time::timeout(dial_timeout, self.transport.connect_peer(socket_addr)).await {
            Ok(Ok(_)) => debug!("dial_candidate: connected to {peer_id} at {socket_addr}"),
            Ok(Err(e)) => {
                debug!("dial_candidate: failed to connect to {peer_id} at {socket_addr}: {e}")
            }
            Err(_) => {
                debug!(
                    "dial_candidate: timeout connecting to {peer_id} at {socket_addr} (>{:?})",
                    dial_timeout
                )
            }
        }
    }

    /// Wait for DHT network response via oneshot channel with timeout
    ///
    /// Uses oneshot channel instead of polling to eliminate TOCTOU races entirely.
    /// The channel is created in send_dht_request and the sender is stored in the
    /// operation context. When handle_dht_response receives a response, it sends
    /// through the channel. This function awaits on the receiver with timeout.
    ///
    /// Note: cleanup of `active_operations` is handled by explicit removal in the
    /// caller (`send_dht_request`), so this method does not remove entries itself.
    async fn wait_for_response(
        &self,
        _message_id: &str,
        response_rx: oneshot::Receiver<(PeerId, DhtNetworkResult)>,
    ) -> Result<DhtNetworkResult> {
        let response_timeout = self.config.request_timeout;

        // Wait for response with timeout - no polling, no TOCTOU race
        match tokio::time::timeout(response_timeout, response_rx).await {
            Ok(Ok((_source, result))) => Ok(result),
            Ok(Err(_recv_error)) => {
                // Channel closed without response (sender dropped)
                // This can happen if handle_dht_response rejected the response
                // or if the operation was cleaned up elsewhere
                Err(P2PError::Network(NetworkError::ProtocolError(
                    "Response channel closed unexpectedly".into(),
                )))
            }
            Err(_timeout) => Err(P2PError::Network(NetworkError::Timeout)),
        }
    }

    /// Handle incoming DHT network response (for real network integration)
    pub async fn handle_network_response(
        &self,
        message_id: &str,
        _response: DhtNetworkResult,
    ) -> Result<()> {
        // Store the response for the waiting request
        // In a real implementation, this would use a proper response queue/store

        debug!("Received DHT network response for message: {}", message_id);

        // For now, we'll complete the operation immediately
        // This method would be called by the network layer when a response is received

        Ok(())
    }

    /// Handle incoming DHT message
    pub async fn handle_dht_message(
        &self,
        data: &[u8],
        sender: &PeerId,
    ) -> Result<Option<Vec<u8>>> {
        // SEC: Reject oversized messages before deserialization to prevent memory exhaustion
        if data.len() > MAX_MESSAGE_SIZE {
            warn!(
                "Rejecting oversized DHT message from {sender}: {} bytes (max: {MAX_MESSAGE_SIZE})",
                data.len()
            );
            return Err(P2PError::Validation(
                format!(
                    "Message size {} bytes exceeds maximum allowed size of {MAX_MESSAGE_SIZE} bytes",
                    data.len()
                )
                .into(),
            ));
        }

        // Deserialize message
        let message: DhtNetworkMessage = postcard::from_bytes(data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        info!(
            "[STEP 3] {}: Received {:?} from {} (msg_id: {})",
            self.config.local_peer_id, message.message_type, sender, message.message_id
        );

        // Update peer info
        self.update_peer_info(sender.clone(), &message).await;

        match message.message_type {
            DhtMessageType::Request => {
                info!(
                    "[STEP 3a] {}: Processing {:?} request from {}",
                    self.config.local_peer_id, message.payload, sender
                );
                let result = self.handle_dht_request(&message).await?;
                info!(
                    "[STEP 4] {}: Sending response {:?} back to {} (msg_id: {})",
                    self.config.local_peer_id,
                    std::mem::discriminant(&result),
                    sender,
                    message.message_id
                );
                let response = self.create_response_message(&message, result)?;
                Ok(Some(postcard::to_stdvec(&response).map_err(|e| {
                    P2PError::Serialization(e.to_string().into())
                })?))
            }
            DhtMessageType::Response => {
                info!(
                    "[STEP 5] {}: Received response from {} (msg_id: {})",
                    self.config.local_peer_id, sender, message.message_id
                );
                self.handle_dht_response(&message, sender).await?;
                Ok(None)
            }
            DhtMessageType::Broadcast => {
                self.handle_dht_broadcast(&message).await?;
                Ok(None)
            }
            DhtMessageType::Error => {
                warn!("Received DHT error message: {:?}", message);
                Ok(None)
            }
        }
    }

    /// Handle DHT request message
    async fn handle_dht_request(&self, message: &DhtNetworkMessage) -> Result<DhtNetworkResult> {
        match &message.payload {
            DhtNetworkOperation::Put { key, value } => {
                trace!(
                    "  [DHT RECV] Handling PUT request for key: {} ({} bytes)",
                    hex::encode(key),
                    value.len()
                );

                Self::validate_put_value_size(value.len(), "remote put")?;
                self.store_local_in_core(*key, value.clone(), "Remote PUT storage")
                    .await?;
                Ok(DhtNetworkResult::PutSuccess {
                    key: *key,
                    replicated_to: 1,
                    peer_outcomes: Vec::new(),
                })
            }
            DhtNetworkOperation::Get { key } => {
                info!("Handling GET request for key: {}", hex::encode(key));
                self.handle_lookup_request(key, &message.source, LookupRequestKind::Get)
                    .await
            }
            DhtNetworkOperation::FindNode { key } => {
                info!("Handling FIND_NODE request for key: {}", hex::encode(key));
                self.handle_lookup_request(key, &message.source, LookupRequestKind::FindNode)
                    .await
            }
            DhtNetworkOperation::FindValue { key } => {
                info!(
                    "[STEP 3b] {}: Handling FIND_VALUE for key {}",
                    self.config.local_peer_id,
                    hex::encode(key)
                );
                self.handle_lookup_request(key, &message.source, LookupRequestKind::FindValue)
                    .await
            }
            DhtNetworkOperation::Ping => {
                info!("Handling PING request from: {}", message.source);
                Ok(DhtNetworkResult::PongReceived {
                    responder: self.config.local_peer_id.clone(),
                    latency: Duration::from_millis(0), // Local response
                })
            }
            DhtNetworkOperation::Join => {
                info!("Handling JOIN request from: {}", message.source);
                // Add the joining node to our routing table
                let dht_key = crate::dht::derive_dht_key_from_peer_id(&message.source);
                let _node = DHTNode {
                    peer_id: message.source.clone(),
                    address: String::new(),
                    distance: Some(dht_key.to_vec()),
                    reliability: 1.0,
                    cached_dht_key: Some(DhtKey::from_bytes(dht_key)),
                };

                // Node will be added to routing table through normal DHT operations
                debug!("Node {} joined the network", message.source);

                Ok(DhtNetworkResult::JoinSuccess {
                    assigned_key: dht_key,
                    bootstrap_peers: 1,
                })
            }
            DhtNetworkOperation::Leave => {
                info!("Handling LEAVE request from: {}", message.source);
                // Remove the leaving node from our routing table
                // TODO: Implement node removal from DHT routing table
                // let dht_guard = self.dht.write().await;
                // if let Err(e) = dht_guard.remove_node(&message.source).await {
                //     warn!("Failed to remove leaving node from routing table: {}", e);
                // }
                Ok(DhtNetworkResult::LeaveSuccess)
            }
        }
    }

    /// Send a DHT request directly to a peer.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
    ) -> Result<DhtNetworkResult> {
        self.send_dht_request(peer_id, operation).await
    }

    /// Handle DHT response message
    ///
    /// Delivers the response via oneshot channel to the waiting request coroutine.
    /// Uses oneshot channel instead of shared Vec to eliminate TOCTOU races.
    ///
    /// Security: Verifies that the transport-level sender matches the peer we
    /// contacted. The `sender` parameter is the transport peer ID provided by the
    /// network layer (from `handle_dht_message`), which is the same ID space used
    /// by `connect_peer` / `send_message`. This avoids the app-level vs transport-level
    /// ID mismatch that would occur if we compared against `message.source`.
    async fn handle_dht_response(
        &self,
        message: &DhtNetworkMessage,
        sender: &PeerId,
    ) -> Result<()> {
        let message_id = &message.message_id;
        debug!("Handling DHT response for message_id: {message_id}");

        // Get the result from the response message
        let result = match &message.result {
            Some(r) => r.clone(),
            None => {
                warn!("DHT response message {message_id} has no result field");
                return Ok(());
            }
        };

        // Find the active operation and send response via oneshot channel
        let Ok(mut ops) = self.active_operations.lock() else {
            warn!("active_operations mutex poisoned");
            return Ok(());
        };
        if let Some(context) = ops.get_mut(message_id) {
            // Security: Verify the transport-level sender is authorized.
            // We compare the `sender` (transport peer ID from the network layer) against
            // the peer IDs we originally contacted (also transport-level IDs).
            // This is correct because both `context.peer_id` and `sender` come from the
            // transport layer (connect_peer / P2PEvent), while `message.source` is the
            // remote node's app-level config ID — a different ID space.
            let source_authorized =
                context.peer_id == *sender || context.contacted_nodes.contains(sender);

            if !source_authorized {
                warn!(
                    "Rejecting DHT response for {message_id}: unauthorized sender {} \
                     (expected {} or one of {:?})",
                    sender, context.peer_id, context.contacted_nodes
                );
                return Ok(());
            }

            // Take the sender out of the context (can only send once)
            if let Some(tx) = context.response_tx.take() {
                info!(
                    "[STEP 5a] {}: Delivering response for msg_id {} to waiting request",
                    self.config.local_peer_id, message_id
                );
                // Send response - if receiver dropped (timeout), log it
                if tx.send((message.source.clone(), result)).is_err() {
                    warn!(
                        "[STEP 5a FAILED] {}: Response channel closed for msg_id {} (receiver timed out)",
                        self.config.local_peer_id, message_id
                    );
                }
            } else {
                debug!(
                    "Response already delivered for message_id: {message_id}, ignoring duplicate"
                );
            }
        } else {
            warn!(
                "[STEP 5 FAILED] {}: No active operation found for msg_id {} (may have timed out)",
                self.config.local_peer_id, message_id
            );
        }

        Ok(())
    }

    /// Handle DHT broadcast message
    async fn handle_dht_broadcast(&self, _message: &DhtNetworkMessage) -> Result<()> {
        // Handle broadcast messages (for network-wide announcements)
        debug!("DHT broadcast handling not fully implemented yet");
        Ok(())
    }

    /// Create response message
    fn create_response_message(
        &self,
        request: &DhtNetworkMessage,
        result: DhtNetworkResult,
    ) -> Result<DhtNetworkMessage> {
        // Create a minimal payload that echoes the original operation type
        // Each variant explicitly extracts its key to avoid silent fallbacks
        let payload = match &result {
            DhtNetworkResult::PutSuccess { key, .. } => DhtNetworkOperation::Put {
                key: *key,
                value: vec![],
            },
            DhtNetworkResult::GetSuccess { key, .. } => DhtNetworkOperation::Get { key: *key },
            DhtNetworkResult::GetNotFound { key, .. } => DhtNetworkOperation::Get { key: *key },
            DhtNetworkResult::NodesFound { key, .. } => DhtNetworkOperation::FindNode { key: *key },
            DhtNetworkResult::ValueFound { key, .. } => {
                DhtNetworkOperation::FindValue { key: *key }
            }
            DhtNetworkResult::PongReceived { .. } => DhtNetworkOperation::Ping,
            DhtNetworkResult::JoinSuccess { .. } => DhtNetworkOperation::Join,
            DhtNetworkResult::LeaveSuccess => DhtNetworkOperation::Leave,
            DhtNetworkResult::Error { .. } => {
                return Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Cannot create response for error result".to_string().into(),
                )));
            }
        };

        Ok(DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: self.config.local_peer_id.clone(),
            target: Some(request.source.clone()),
            message_type: DhtMessageType::Response,
            payload,
            result: Some(result),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count.saturating_add(1),
        })
    }

    /// Update peer information
    async fn update_peer_info(&self, peer_id: PeerId, _message: &DhtNetworkMessage) {
        let dht_key = crate::dht::derive_dht_key_from_peer_id(&peer_id);

        // Get peer addresses from transport layer
        let addresses = if let Some(peer_info) = self.transport.peer_info(&peer_id).await {
            Self::parse_peer_addresses(&peer_info.addresses)
        } else {
            warn!("peer_info unavailable for peer_id: {}", peer_id);
            Vec::new()
        };

        let mut peers = self.dht_peers.write().await;
        let peer_info = peers.entry(peer_id.clone()).or_insert_with(|| DhtPeerInfo {
            peer_id: peer_id.clone(),
            dht_key,
            addresses: addresses.clone(),
            last_seen: Instant::now(),
            is_connected: true,
            avg_latency: Duration::from_millis(50),
            reliability_score: 1.0,
        });

        peer_info.last_seen = Instant::now();
        peer_info.is_connected = true;
        // Update addresses if we have new ones
        if !addresses.is_empty() {
            peer_info.addresses = addresses;
        }

        debug!(
            "Updated peer info for {} with {} addresses",
            peer_id,
            peer_info.addresses.len()
        );
    }

    /// Reconcile already-connected peers into DHT bookkeeping/routing.
    async fn reconcile_connected_peers(&self) {
        let connected = self.transport.connected_peers().await;
        if connected.is_empty() {
            return;
        }

        info!(
            "Reconciling {} already-connected peers for DHT state",
            connected.len()
        );
        for peer_id in connected {
            self.handle_peer_connected(peer_id).await;
        }
    }

    /// Handle a connected peer event in an idempotent way.
    async fn handle_peer_connected(&self, peer_id: PeerId) {
        info!("DHT peer connected: {}", peer_id);
        let dht_key = crate::dht::derive_dht_key_from_peer_id(&peer_id);

        // Get peer addresses from transport layer
        let addresses = if let Some(peer_info) = self.transport.peer_info(&peer_id).await {
            Self::parse_peer_addresses(&peer_info.addresses)
        } else {
            warn!("peer_info unavailable for peer_id: {}", peer_id);
            Vec::new()
        };

        // Track peer and decide whether it should be promoted to routing table.
        let should_add_to_routing = {
            let mut peers = self.dht_peers.write().await;
            match peers.entry(peer_id.clone()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let peer_info = entry.get_mut();
                    let had_addresses = !peer_info.addresses.is_empty();
                    peer_info.last_seen = Instant::now();
                    peer_info.is_connected = true;
                    if !addresses.is_empty() {
                        peer_info.addresses = addresses.clone();
                    }
                    !addresses.is_empty() && !had_addresses
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(DhtPeerInfo {
                        peer_id: peer_id.clone(),
                        dht_key,
                        addresses: addresses.clone(),
                        last_seen: Instant::now(),
                        is_connected: true,
                        avg_latency: Duration::from_millis(50),
                        reliability_score: 1.0,
                    });
                    !addresses.is_empty()
                }
            }
        };

        // Skip peers with no addresses - they cannot be used for DHT routing.
        let address_str = match addresses.first() {
            Some(addr) => addr.to_string(),
            None => {
                warn!(
                    "Peer {} has no addresses, skipping DHT routing table addition",
                    peer_id
                );
                return;
            }
        };

        if !should_add_to_routing {
            debug!("Peer {} already tracked in DHT routing state", peer_id);
            return;
        }

        // Add to DHT routing table.
        {
            use crate::dht::core_engine::{NodeCapacity, NodeId, NodeInfo};

            let node_info = NodeInfo {
                id: NodeId::from_bytes(dht_key),
                address: address_str,
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            };

            if let Err(e) = self.dht.write().await.add_node(node_info).await {
                warn!("Failed to add peer {} to DHT routing table: {}", peer_id, e);
            } else {
                info!("Added peer {} to DHT routing table", peer_id);
            }
        }

        if self.event_tx.receiver_count() > 0 {
            let _ = self
                .event_tx
                .send(DhtNetworkEvent::PeerDiscovered { peer_id, dht_key });
        }
    }

    /// Start network event handler
    async fn start_network_event_handler(&self, self_arc: Arc<Self>) -> Result<()> {
        info!("Starting network event handler...");

        // Subscribe to network events from transport layer
        let mut events = self.transport.subscribe_events();

        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        info!("Network event handler shutting down");
                        break;
                    }
                    recv = events.recv() => {
                        match recv {
                            Ok(event) => match event {
                                crate::network::P2PEvent::PeerConnected(peer_id) => {
                                    self_arc.handle_peer_connected(peer_id).await;
                                }
                                crate::network::P2PEvent::PeerDisconnected(peer_id) => {
                                    info!("DHT peer disconnected: {}", peer_id);

                                    // Update peer status
                                    {
                                        let mut peers = self_arc.dht_peers.write().await;
                                        if let Some(peer_info) = peers.get_mut(&peer_id) {
                                            peer_info.is_connected = false;
                                        }
                                    }

                                    if self_arc.event_tx.receiver_count() > 0
                                        && let Err(e) = self_arc
                                            .event_tx
                                            .send(DhtNetworkEvent::PeerDisconnected { peer_id })
                                    {
                                        warn!("Failed to send PeerDisconnected event: {}", e);
                                    }
                                }
                                crate::network::P2PEvent::Message {
                                    topic,
                                    source,
                                    data,
                                } => {
                                    trace!(
                                        "  [EVENT] Message received: topic={}, source={}, {} bytes",
                                        topic,
                                        source,
                                        data.len()
                                    );
                                    if topic == "/dht/1.0.0" {
                                        trace!("  [EVENT] Processing DHT message from {}", source);
                                        // Process the DHT message with backpressure via semaphore
                                        let manager_clone = Arc::clone(&self_arc);
                                        let source_clone = source.clone();
                                        let semaphore = Arc::clone(&self_arc.message_handler_semaphore);
                                        tokio::spawn(async move {
                                            // Acquire permit for backpressure - limits concurrent handlers
                                            let _permit = match semaphore.acquire().await {
                                                Ok(permit) => permit,
                                                Err(_) => {
                                                    warn!("Message handler semaphore closed");
                                                    return;
                                                }
                                            };

                                            // SEC-001: Wrap handle_dht_message with timeout to prevent DoS via long-running handlers
                                            // This ensures permits are released even if a handler gets stuck
                                            match tokio::time::timeout(
                                                REQUEST_TIMEOUT,
                                                manager_clone.handle_dht_message(&data, &source_clone),
                                            )
                                            .await
                                            {
                                                Ok(Ok(Some(response))) => {
                                                    // Send response back to the source peer
                                                    if let Err(e) = manager_clone
                                                        .transport
                                                        .send_message(&source_clone, "/dht/1.0.0", response)
                                                        .await
                                                    {
                                                        warn!(
                                                            "Failed to send DHT response to {}: {}",
                                                            source_clone, e
                                                        );
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    // No response needed (e.g., for response messages)
                                                }
                                                Ok(Err(e)) => {
                                                    warn!(
                                                        "Failed to handle DHT message from {}: {}",
                                                        source_clone, e
                                                    );
                                                }
                                                Err(_) => {
                                                    // Timeout occurred - log warning and release permit
                                                    warn!(
                                                        "DHT message handler timed out after {:?} for peer {}: potential DoS attempt or slow processing",
                                                        REQUEST_TIMEOUT, source_clone
                                                    );
                                                }
                                            }
                                            // _permit dropped here, releasing semaphore slot
                                        });
                                    }
                                }
                            },
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!("Network event handler lagged, skipped {} events", skipped);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                info!("Network event channel closed, stopping event handler");
                                break;
                            }
                        }
                    }
                }
            }
        });

        *self.event_handler_handle.write().await = Some(handle);

        Ok(())
    }

    /// Start maintenance tasks using the MaintenanceScheduler
    async fn start_maintenance_tasks(&self) -> Result<()> {
        info!("Starting DHT maintenance tasks with scheduler...");

        // Start the scheduler
        {
            let mut scheduler = self.maintenance_scheduler.write().await;
            scheduler.start();
        }

        // Main scheduler loop
        let scheduler = Arc::clone(&self.maintenance_scheduler);
        let dht = Arc::clone(&self.dht);
        let dht_peers = Arc::clone(&self.dht_peers);
        let stats = Arc::clone(&self.stats);
        let event_tx = self.event_tx.clone();
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            let mut check_interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = check_interval.tick() => {}
                    () = shutdown.cancelled() => {
                        info!("DHT maintenance task shutting down");
                        break;
                    }
                }

                // Get due tasks from scheduler
                let due_tasks = {
                    let scheduler_guard = scheduler.read().await;
                    scheduler_guard.get_due_tasks()
                };

                for task in due_tasks {
                    // Mark task as started
                    {
                        let mut scheduler_guard = scheduler.write().await;
                        scheduler_guard.mark_started(task);
                    }

                    let task_result: std::result::Result<(), &'static str> = match task {
                        MaintenanceTask::BucketRefresh => {
                            debug!("Running BucketRefresh maintenance task");
                            // Refresh k-buckets by looking up random IDs in each bucket
                            // This helps discover new nodes and keep routing table fresh
                            Ok(())
                        }
                        MaintenanceTask::LivenessCheck => {
                            debug!("Running LivenessCheck maintenance task");
                            // Check liveness of nodes in routing table
                            let peers = dht_peers.read().await;
                            let stale_count = peers
                                .values()
                                .filter(|p| p.last_seen.elapsed() > Duration::from_secs(300))
                                .count();
                            if stale_count > 0 {
                                debug!(
                                    "Found {} stale peers that need liveness check",
                                    stale_count
                                );
                            }
                            Ok(())
                        }
                        MaintenanceTask::EvictionEvaluation => {
                            debug!("Running EvictionEvaluation maintenance task");
                            // Evaluate nodes for eviction based on:
                            // - Response rate
                            // - Trust scores
                            // - Consecutive failures
                            let peers = dht_peers.read().await;
                            let low_reliability =
                                peers.values().filter(|p| p.reliability_score < 0.3).count();
                            if low_reliability > 0 {
                                info!(
                                    "Found {} low-reliability peers for potential eviction",
                                    low_reliability
                                );
                            }
                            Ok(())
                        }
                        MaintenanceTask::CloseGroupValidation => {
                            debug!("Running CloseGroupValidation maintenance task");
                            // Validate close group membership and detect anomalies
                            // This helps detect Sybil attacks on close groups
                            Ok(())
                        }
                        MaintenanceTask::RecordRepublish => {
                            debug!("Running RecordRepublish maintenance task");
                            // Republish stored records to maintain replication factor
                            // Critical for data durability in presence of churn
                            let _dht_guard = dht.read().await;
                            // Would iterate through stored records and republish to K closest nodes
                            Ok(())
                        }
                    };

                    // Mark task completed or failed
                    {
                        let mut scheduler_guard = scheduler.write().await;
                        match task_result {
                            Ok(()) => {
                                scheduler_guard.mark_completed(task);
                                if event_tx.receiver_count() > 0 {
                                    let _ = event_tx.send(DhtNetworkEvent::OperationCompleted {
                                        operation: format!("{task:?}"),
                                        success: true,
                                        duration: Duration::from_millis(1),
                                    });
                                }
                            }
                            Err(_) => {
                                scheduler_guard.mark_failed(task);
                                if event_tx.receiver_count() > 0 {
                                    let _ = event_tx.send(DhtNetworkEvent::OperationCompleted {
                                        operation: format!("{task:?}"),
                                        success: false,
                                        duration: Duration::from_millis(1),
                                    });
                                }
                            }
                        }
                    }
                }

                // Update stats periodically
                let connected_peers = {
                    let peers = dht_peers.read().await;
                    peers.values().filter(|p| p.is_connected).count()
                };

                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.connected_peers = connected_peers;
                }
            }
        });

        *self.maintenance_handle.write().await = Some(handle);

        info!(
            "DHT maintenance scheduler started with {} task types",
            MaintenanceTask::all().len()
        );
        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> DhtNetworkStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to DHT network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<DhtNetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get connected DHT peers
    pub async fn get_connected_peers(&self) -> Vec<DhtPeerInfo> {
        let peers = self.dht_peers.read().await;
        peers.values().filter(|p| p.is_connected).cloned().collect()
    }

    /// Get DHT routing table size
    pub async fn get_routing_table_size(&self) -> usize {
        // TODO: Implement DHT stats
        // let dht_guard = self.dht.read().await;
        // let stats = dht_guard.stats().await;
        // stats.total_nodes
        0
    }

    /// Get this node's peer ID (the config name, e.g. "my_node")
    pub fn peer_id(&self) -> &PeerId {
        &self.config.local_peer_id
    }

    /// Get this node's transport-level peer ID (cryptographic hex ID).
    ///
    /// This is the ID used in P2P communication and stored in `dht_peers`.
    /// It differs from `peer_id()` which returns the human-readable config name.
    pub fn transport_peer_id(&self) -> Option<String> {
        self.transport.transport_peer_id()
    }

    /// Get the local listen address of this node's P2P network
    ///
    /// Returns the address other nodes can use to connect to this node.
    pub fn local_addr(&self) -> Option<String> {
        self.transport.local_addr()
    }

    /// Check if a key exists in local storage only (no network query)
    ///
    /// This is useful for testing to verify replication without triggering
    /// network lookups.
    pub async fn has_key_locally(&self, key: &Key) -> bool {
        match self
            .retrieve_local_from_core(key, "Local key existence check")
            .await
        {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!(
                    "has_key_locally retrieve failed for key {}: {e}",
                    hex::encode(key)
                );
                false
            }
        }
    }

    /// Get a value from local storage only (no network query)
    ///
    /// Returns the value if it exists in local storage, None otherwise.
    /// Unlike `get()`, this does NOT query remote nodes.
    /// Connect to a specific peer by address
    ///
    /// This is useful for manually building network topology in tests.
    pub async fn connect_to_peer(&self, address: &str) -> Result<PeerId> {
        self.transport.connect_peer(address).await
    }

    /// Get the transport handle for direct transport-level operations.
    pub fn transport(&self) -> &Arc<crate::transport_handle::TransportHandle> {
        &self.transport
    }

    /// Get the underlying DHT core engine for direct access.
    ///
    /// This is used by `P2PNode` for DHT seeding (registering transport-level peers
    /// into the DHT routing table).
    pub fn dht_core(&self) -> &Arc<RwLock<DhtCoreEngine>> {
        &self.dht
    }

    /// Get the optional trust engine used by this manager.
    pub fn trust_engine(&self) -> Option<Arc<EigenTrustEngine>> {
        self.trust_engine.clone()
    }

    /// Get the security metrics collector from the local DHT core.
    pub async fn security_metrics(&self) -> Arc<crate::dht::metrics::SecurityMetricsCollector> {
        self.dht.read().await.security_metrics()
    }
}

impl Default for DhtNetworkConfig {
    fn default() -> Self {
        Self {
            local_peer_id: "default_peer".to_string(),
            dht_config: DHTConfig::default(),
            node_config: NodeConfig::default(),
            request_timeout: Duration::from_secs(30),
            max_concurrent_operations: 100,
            replication_factor: 8, // K=8 replication
            enable_security: true,
        }
    }
}
