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
    P2PError, PeerId, Result,
    adaptive::TrustEngine,
    adaptive::trust::DEFAULT_NEUTRAL_TRUST,
    address::MultiAddr,
    dht::core_engine::NodeInfo,
    dht::{DhtCoreEngine, DhtKey, Key},
    error::{DhtError, IdentityError, NetworkError},
    network::NodeConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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

/// Maximum time to wait for the identity-exchange handshake after dialling
/// a peer. The actual timeout is `min(request_timeout, this)`.
const IDENTITY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// DHT node representation for network operations.
///
/// The `addresses` field stores one or more typed [`MultiAddr`] values.
/// Peers may be multi-homed or reachable via NAT traversal at several
/// endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNode {
    pub peer_id: PeerId,
    pub addresses: Vec<MultiAddr>,
    pub distance: Option<Vec<u8>>,
    pub reliability: f64,
}

/// Alias for serialization compatibility
pub type SerializableDHTNode = DHTNode;

/// DHT Network Manager Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkConfig {
    /// This node's peer ID
    pub peer_id: PeerId,
    /// Network node configuration (includes DHT settings via `NodeConfig.dht_config`)
    pub node_config: NodeConfig,
    /// Request timeout for DHT operations
    pub request_timeout: Duration,
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Enable enhanced security features
    pub enable_security: bool,
    /// Trust score below which a peer is blocked from DHT operations.
    /// Messages from blocked peers are silently dropped and they cannot
    /// be added to the routing table. Default: 0.0 (disabled).
    pub block_threshold: f64,
}

/// DHT network operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkOperation {
    /// Find nodes closest to a key
    FindNode { key: Key },
    /// Ping a node to check availability
    Ping,
    /// Join the DHT network
    Join,
    /// Leave the DHT network gracefully
    Leave,
}

/// DHT network operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkResult {
    /// Nodes found for FIND_NODE or iterative lookup
    NodesFound {
        key: Key,
        nodes: Vec<SerializableDHTNode>,
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
    /// The remote peer has blocked us — do not penalise their trust score
    PeerRejected,
    /// Operation failed
    Error { operation: String, error: String },
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
/// This manager handles DHT operations (peer discovery, routing) but does
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
    trust_engine: Option<Arc<TrustEngine>>,
    /// Configuration
    config: DhtNetworkConfig,
    /// Active DHT operations
    active_operations: Arc<Mutex<HashMap<String, DhtOperationContext>>>,
    /// Network message broadcaster
    event_tx: broadcast::Sender<DhtNetworkEvent>,
    /// Operation statistics
    stats: Arc<RwLock<DhtNetworkStats>>,
    /// Semaphore for limiting concurrent message handlers (backpressure)
    message_handler_semaphore: Arc<Semaphore>,
    /// Shutdown token for background tasks
    shutdown: CancellationToken,
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
    /// Target app-level peer ID (authentication identity, not transport channel)
    peer_id: PeerId,
    /// Start time
    started_at: Instant,
    /// Timeout
    timeout: Duration,
    /// Contacted app-level peer IDs (for response source validation)
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
    /// Connected transport peers (all authenticated peers, including Client-mode)
    pub connected_peers: usize,
    /// DHT routing table size (Node-mode peers only)
    pub routing_table_size: usize,
}

impl DhtNetworkManager {
    fn new_from_components(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<TrustEngine>>,
        config: DhtNetworkConfig,
    ) -> Result<Self> {
        let mut dht_instance = DhtCoreEngine::new(
            config.peer_id,
            config.node_config.dht_config.k_value,
            config.node_config.allow_loopback,
        )
        .map_err(|e| P2PError::Dht(DhtError::OperationFailed(e.to_string().into())))?;

        // Propagate IP diversity settings from the node config into the DHT
        // core engine so diversity overrides take effect on routing table
        // insertion, not just bootstrap discovery.
        if let Some(diversity) = &config.node_config.diversity_config {
            dht_instance.set_ip_diversity_config(diversity.clone());
        }

        let dht = Arc::new(RwLock::new(dht_instance));

        let (event_tx, _) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let message_handler_semaphore = Arc::new(Semaphore::new(
            config
                .max_concurrent_operations
                .max(MIN_CONCURRENT_OPERATIONS),
        ));

        Ok(Self {
            dht,
            transport,
            trust_engine,
            config,
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            stats: Arc::new(RwLock::new(DhtNetworkStats::default())),
            message_handler_semaphore,
            shutdown: CancellationToken::new(),
            event_handler_handle: Arc::new(RwLock::new(None)),
        })
    }

    /// Handle a FindNode request by returning the closest nodes from the local routing table.
    async fn handle_find_node_request(
        &self,
        key: &Key,
        requester: &PeerId,
    ) -> Result<DhtNetworkResult> {
        trace!(
            "FIND_NODE: resolving closer nodes for key {}",
            hex::encode(key)
        );

        let candidate_nodes = self
            .find_closest_nodes_local(key, DHT_CLOSEST_NODES_COUNT)
            .await;
        let closer_nodes = Self::filter_response_nodes(candidate_nodes, requester);

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
        trust_engine: Option<Arc<TrustEngine>>,
        mut config: DhtNetworkConfig,
    ) -> Result<Self> {
        let transport_app_peer_id = transport.peer_id();
        if config.peer_id == PeerId::from_bytes([0u8; 32]) {
            config.peer_id = transport_app_peer_id;
        } else if config.peer_id != transport_app_peer_id {
            warn!(
                "DHT config peer_id ({}) differs from transport peer_id ({}); using config value",
                config.peer_id.to_hex(),
                transport_app_peer_id.to_hex()
            );
        }

        info!(
            "Creating attached DHT Network Manager for peer: {}",
            config.peer_id.to_hex()
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

        info!("DHT Network Manager started successfully");
        Ok(())
    }

    /// Perform DHT peer discovery from already-connected bootstrap peers.
    ///
    /// Sends FIND_NODE(self) to each peer using the DHT postcard protocol,
    /// then dials any newly-discovered candidates. Returns the total number
    /// of new peers discovered.
    pub async fn bootstrap_from_peers(&self, peers: &[PeerId]) -> Result<usize> {
        let key = *self.config.peer_id.as_bytes();
        let mut seen = HashSet::new();
        for peer_id in peers {
            let op = DhtNetworkOperation::FindNode { key };
            match self.send_dht_request(peer_id, op, None).await {
                Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                    for node in &nodes {
                        if seen.insert(node.peer_id)
                            && let Some(addr) = Self::first_dialable_address(&node.addresses)
                        {
                            self.dial_candidate(&node.peer_id, &addr).await;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Bootstrap FIND_NODE to {} failed: {}", peer_id.to_hex(), e);
                }
            }
        }
        Ok(seen.len())
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

        // Signal background tasks to stop
        self.dht.read().await.signal_shutdown();

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

    /// Backwards-compatible API that performs a full iterative lookup.
    pub async fn find_closest_nodes(&self, key: &Key, count: usize) -> Result<Vec<DHTNode>> {
        self.find_closest_nodes_network(key, count).await
    }

    /// Find nodes closest to a key using iterative network lookup
    pub async fn find_node(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Finding nodes closest to key: {}", hex::encode(key));

        let closest_nodes = self
            .find_closest_nodes_network(key, DHT_CLOSEST_NODES_COUNT * 2)
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
        info!("Pinging peer: {}", peer_id.to_hex());

        let start_time = Instant::now();
        let operation = DhtNetworkOperation::Ping;

        match self.send_dht_request(peer_id, operation, None).await {
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
                warn!("Ping failed to {}: {}", peer_id.to_hex(), e);
                Err(e)
            }
        }
    }

    /// Leave the DHT network gracefully
    async fn leave_network(&self) -> Result<()> {
        // No-op: peers detect disconnection via transport-level connection loss.
        // Explicit leave messages added latency to shutdown without meaningful benefit.
        Ok(())
    }

    // =========================================================================
    // FIND CLOSEST NODES API
    // =========================================================================
    //
    // Two functions for finding closest nodes to a key:
    //
    // 1. find_closest_nodes_local() - Routing table lookup
    //    - Only checks the local Kademlia routing table
    //    - No network requests, safe to call from request handlers
    //    - Returns security-validated DHT participants only
    //
    // 2. find_closest_nodes_network() - Iterative network lookup
    //    - Starts with routing table knowledge, then queries the network
    //    - Asks known nodes for their closest nodes, then queries those
    //    - Continues until convergence (same answers or worse quality)
    //    - Full Kademlia-style iterative lookup
    // =========================================================================

    /// Find closest nodes to a key using ONLY the local routing table.
    ///
    /// No network requests are made — safe to call from request handlers.
    /// Only returns peers that passed the `is_dht_participant` security gate
    /// and were added to the Kademlia routing table.
    ///
    /// Results are sorted by XOR distance to the key.
    pub async fn find_closest_nodes_local(&self, key: &Key, count: usize) -> Vec<DHTNode> {
        debug!(
            "[LOCAL] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let dht_guard = self.dht.read().await;
        match dht_guard.find_nodes(&DhtKey::from_bytes(*key), count).await {
            Ok(nodes) => nodes
                .into_iter()
                .filter(|node| !self.is_local_peer_id(&node.id))
                .map(|node| DHTNode {
                    peer_id: node.id,
                    addresses: node.addresses,
                    distance: None,
                    reliability: SELF_RELIABILITY_SCORE,
                })
                .collect(),
            Err(e) => {
                warn!("find_nodes failed for key {}: {e}", hex::encode(key));
                Vec::new()
            }
        }
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

        let mut queried_nodes: HashSet<PeerId> = HashSet::new();
        let mut best_nodes: Vec<DHTNode> = Vec::new();
        let mut queued_peer_ids: HashSet<PeerId> = HashSet::new();

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
            if queued_peer_ids.insert(node.peer_id) {
                candidates.push_back(node);
            }
        }
        let mut previous_candidate_snapshot: Option<BTreeSet<PeerId>> = None;

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
            // saorsa-transport connection multiplexing lets us keep a single transport socket
            // while still querying multiple peers concurrently.
            let query_futures: Vec<_> = batch
                .iter()
                .map(|node| {
                    let peer_id = node.peer_id;
                    let address = Self::first_dialable_address(&node.addresses);
                    let op = DhtNetworkOperation::FindNode { key: *key };
                    async move {
                        if let Some(ref addr) = address {
                            self.dial_candidate(&peer_id, addr).await;
                        }
                        (
                            peer_id,
                            self.send_dht_request(&peer_id, op, address.as_ref()).await,
                        )
                    }
                })
                .collect();

            let results = futures::future::join_all(query_futures).await;

            let mut found_new_closer = false;
            for (peer_id, result) in results {
                queried_nodes.insert(peer_id);

                match result {
                    Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                        self.record_peer_success(&peer_id).await;
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                        for node in nodes {
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
                                        node.peer_id.to_hex()
                                    );
                                    continue;
                                }
                                queued_peer_ids.insert(node.peer_id);
                                candidates.push_back(node);
                                found_new_closer = true;
                            }
                        }
                    }
                    Ok(DhtNetworkResult::PeerRejected) => {
                        // Remote peer has us blocked — remove them from our routing
                        // table (no point retrying) but do NOT penalise their trust
                        // score; the rejection is an honest signal, not misbehaviour.
                        info!(
                            "[NETWORK] Peer {} rejected us (blocked) — removing from routing table",
                            peer_id.to_hex()
                        );
                        let mut dht = self.dht.write().await;
                        dht.remove_node_by_id(&peer_id).await;
                    }
                    Ok(_) => {
                        self.record_peer_success(&peer_id).await;
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                    }
                    Err(e) => {
                        trace!("[NETWORK] Query to {} failed: {}", peer_id.to_hex(), e);
                        self.record_peer_failure(&peer_id).await;
                        // Don't add failed nodes to best_nodes - they are unresponsive
                    }
                }
            }

            // Sort, deduplicate, and truncate once per iteration instead of per result
            best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
            best_nodes.dedup_by_key(|n| n.peer_id);
            best_nodes.truncate(count);

            if !found_new_closer {
                info!("[NETWORK] Converged after {} iterations", iteration + 1);
                break;
            }

            let snapshot: BTreeSet<PeerId> = queued_peer_ids.iter().cloned().collect();
            if let Some(previous) = &previous_candidate_snapshot
                && !snapshot.is_empty()
                && *previous == snapshot
            {
                info!(
                    "[NETWORK] {}: Candidate set stagnated after {} iterations, stopping",
                    self.config.peer_id.to_hex(),
                    iteration + 1
                );
                break;
            }
            previous_candidate_snapshot = Some(snapshot);
        }

        best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        best_nodes.dedup_by_key(|n| n.peer_id);
        best_nodes.truncate(count);

        info!(
            "[NETWORK] Found {} closest nodes: {:?}",
            best_nodes.len(),
            best_nodes
                .iter()
                .map(|n| {
                    let h = n.peer_id.to_hex();
                    h[..8.min(h.len())].to_string()
                })
                .collect::<Vec<_>>()
        );

        Ok(best_nodes)
    }

    /// Compare two nodes by their XOR distance to a target key.
    fn compare_node_distance(a: &DHTNode, b: &DHTNode, key: &Key) -> std::cmp::Ordering {
        let target_key = DhtKey::from_bytes(*key);
        a.peer_id
            .distance(&target_key)
            .cmp(&b.peer_id.distance(&target_key))
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
        let mut addresses: Vec<MultiAddr> = self.config.node_config.listen_addrs().to_vec();
        if addresses.is_empty() {
            addresses.push(MultiAddr::quic(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            )));
        }
        DHTNode {
            peer_id: self.config.peer_id,
            addresses,
            distance: None,
            reliability: SELF_RELIABILITY_SCORE,
        }
    }

    /// Add the local app-level peer ID to `queried` so that iterative lookups
    /// never send RPCs to the local node.
    fn mark_self_queried(&self, queried: &mut HashSet<PeerId>) {
        queried.insert(self.config.peer_id);
    }

    /// Return all dialable addresses from a list of [`MultiAddr`] values.
    ///
    /// Only QUIC addresses are considered dialable. Unspecified (`0.0.0.0`)
    /// addresses are rejected. Loopback addresses are accepted for local/test
    /// use.
    fn dialable_addresses(addresses: &[MultiAddr]) -> Vec<MultiAddr> {
        addresses
            .iter()
            .filter(|addr| {
                let Some(sa) = addr.dialable_socket_addr() else {
                    trace!("Skipping non-dialable address: {addr}");
                    return false;
                };
                if sa.ip().is_unspecified() {
                    warn!("Rejecting unspecified address: {addr}");
                    return false;
                }
                if sa.ip().is_loopback() {
                    trace!("Accepting loopback address (local/test): {addr}");
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Return the first dialable address from a list of [`MultiAddr`] values.
    fn first_dialable_address(addresses: &[MultiAddr]) -> Option<MultiAddr> {
        Self::dialable_addresses(addresses).into_iter().next()
    }

    async fn record_peer_success(&self, peer_id: &PeerId) {
        if let Some(ref engine) = self.trust_engine {
            engine
                .update_node_stats(
                    peer_id,
                    crate::adaptive::NodeStatisticsUpdate::CorrectResponse,
                )
                .await;
        }
    }

    async fn record_peer_failure(&self, peer_id: &PeerId) {
        if let Some(ref engine) = self.trust_engine {
            engine
                .update_node_stats(
                    peer_id,
                    crate::adaptive::NodeStatisticsUpdate::FailedResponse,
                )
                .await;

            // Immediately evict and disconnect if trust has crossed the block threshold
            if self.config.block_threshold > 0.0
                && engine.score(peer_id) < self.config.block_threshold
            {
                let mut dht = self.dht.write().await;
                dht.remove_node_by_id(peer_id).await;
                drop(dht); // Release write lock before disconnect
                let _ = self.transport.disconnect_peer(peer_id).await;
                tracing::info!(
                    peer = peer_id.to_hex(),
                    score = engine.score(peer_id),
                    threshold = self.config.block_threshold,
                    "Blocked peer — evicted from RT and disconnected"
                );
            }
        }
    }

    /// Check if a peer's trust score is below the block threshold.
    ///
    /// Returns `true` if the peer should be blocked (trust too low).
    /// Returns `false` if blocking is disabled (threshold == 0) or no trust engine.
    fn is_peer_blocked(&self, peer_id: &PeerId) -> bool {
        if self.config.block_threshold <= 0.0 {
            return false;
        }
        if let Some(ref engine) = self.trust_engine {
            engine.score(peer_id) < self.config.block_threshold
        } else {
            false
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

    /// Send a DHT request to a specific peer.
    ///
    /// When `address_hint` is provided (e.g. from a `DHTNode` in an iterative
    /// lookup), it is used directly for dialling without a routing-table lookup.
    async fn send_dht_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
        address_hint: Option<&MultiAddr>,
    ) -> Result<DhtNetworkResult> {
        // Fail fast for blocked peers — don't waste resources connecting/sending
        if self.is_peer_blocked(peer_id) {
            return Err(P2PError::Network(NetworkError::PeerBlocked(*peer_id)));
        }

        // Sweep stale entries left by dropped futures before adding a new one
        self.sweep_expired_operations();

        let message_id = Uuid::new_v4().to_string();

        let message = DhtNetworkMessage {
            message_id: message_id.clone(),
            source: self.config.peer_id,
            target: Some(*peer_id),
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

        // Only track app-level peer IDs. Transport IDs identify communication
        // channels, not peers — multiple peers may share one transport in the future.
        let contacted_nodes = vec![*peer_id];

        // Create operation context for tracking
        let operation_context = DhtOperationContext {
            operation: message.payload.clone(),
            peer_id: *peer_id,
            started_at: Instant::now(),
            timeout: self.config.request_timeout,
            contacted_nodes,
            response_tx: Some(response_tx),
        };

        if let Ok(mut ops) = self.active_operations.lock() {
            ops.insert(message_id.clone(), operation_context);
        }

        // Send message via network layer, reconnecting on demand if needed.
        let peer_hex = peer_id.to_hex();
        let local_hex = self.config.peer_id.to_hex();
        info!(
            "[STEP 1] {} -> {}: Sending {:?} request (msg_id: {})",
            local_hex, peer_hex, message.payload, message_id
        );

        // Ensure we have an open channel to the peer before sending.
        // A fresh dial establishes a QUIC connection but the app-level
        // `peer_to_channel` mapping is only populated after the asynchronous
        // identity-exchange handshake completes. Without waiting, the
        // subsequent `send_message` would fail with `PeerNotFound`.
        let resolved_address: Option<MultiAddr> = if self.transport.is_peer_connected(peer_id).await
        {
            None
        } else if let Some(hint) = address_hint {
            Some(hint.clone())
        } else {
            self.peer_addresses_for_dial(peer_id)
                .await
                .into_iter()
                .next()
        };
        if let Some(ref address) = resolved_address {
            info!(
                "[STEP 1b] {} -> {}: No open channel, dialling {}",
                local_hex, peer_hex, address
            );
            if let Some(channel_id) = self.dial_candidate(peer_id, address).await {
                let identity_timeout = self.config.request_timeout.min(IDENTITY_EXCHANGE_TIMEOUT);
                match self
                    .transport
                    .wait_for_peer_identity(&channel_id, identity_timeout)
                    .await
                {
                    Ok(authenticated) => {
                        if &authenticated != peer_id {
                            warn!(
                                "[STEP 1b] {} -> {}: identity MISMATCH — dialled {} but authenticated as {}. \
                                 Routing table entry may be stale.",
                                local_hex,
                                peer_hex,
                                address,
                                authenticated.to_hex()
                            );
                            if let Ok(mut ops) = self.active_operations.lock() {
                                ops.remove(&message_id);
                            }
                            return Err(P2PError::Identity(IdentityError::IdentityMismatch {
                                expected: peer_hex.into(),
                                actual: authenticated.to_hex().into(),
                            }));
                        }
                        debug!(
                            "[STEP 1b] {} -> {}: identity confirmed ({})",
                            local_hex,
                            peer_hex,
                            authenticated.to_hex()
                        );
                    }
                    Err(e) => {
                        warn!(
                            "[STEP 1b] {} -> {}: identity exchange failed, disconnecting channel: {}",
                            local_hex, peer_hex, e
                        );
                        self.transport.disconnect_channel(&channel_id).await;
                        if let Ok(mut ops) = self.active_operations.lock() {
                            ops.remove(&message_id);
                        }
                        return Err(P2PError::Network(NetworkError::ProtocolError(
                            format!("identity exchange with {} failed: {}", peer_hex, e).into(),
                        )));
                    }
                }
            } else {
                warn!(
                    "[STEP 1b] {} -> {}: dial failed to {}",
                    local_hex, peer_hex, address
                );
                if let Ok(mut ops) = self.active_operations.lock() {
                    ops.remove(&message_id);
                }
                return Err(P2PError::Network(NetworkError::PeerNotFound(
                    format!("failed to dial {} at {}", peer_hex, address).into(),
                )));
            }
        }

        let result = match self
            .transport
            .send_message(peer_id, "/dht/1.0.0", message_data)
            .await
        {
            Ok(_) => {
                info!(
                    "[STEP 2] {} -> {}: Message sent successfully, waiting for response...",
                    local_hex, peer_hex
                );

                // Wait for response via oneshot channel with timeout
                let result = self.wait_for_response(&message_id, response_rx).await;
                match &result {
                    Ok(r) => info!(
                        "[STEP 6] {} <- {}: Got response: {:?}",
                        local_hex,
                        peer_hex,
                        std::mem::discriminant(r)
                    ),
                    Err(e) => warn!(
                        "[STEP 6 FAILED] {} <- {}: Response error: {}",
                        local_hex, peer_hex, e
                    ),
                }
                result
            }
            Err(e) => {
                warn!(
                    "[STEP 1 FAILED] Failed to send DHT request to {}: {}",
                    peer_hex, e
                );
                Err(e)
            }
        };

        // Explicit cleanup — no Drop guard, no tokio::spawn required
        if let Ok(mut ops) = self.active_operations.lock() {
            ops.remove(&message_id);
        }

        result
    }

    /// Check whether `peer_id` refers to this node.
    fn is_local_peer_id(&self, peer_id: &PeerId) -> bool {
        *peer_id == self.config.peer_id
    }

    /// Resolve any peer identifier to a canonical app-level peer ID.
    ///
    /// For signed messages the event `source` is already the app-level peer ID
    /// (set by `parse_protocol_message`), so `is_known_app_peer_id` succeeds
    /// directly. For unsigned connections the channel ID itself is used as
    /// identity (e.g. in tests).
    async fn canonical_app_peer_id(&self, peer_id: &PeerId) -> Option<PeerId> {
        // Check if this is a known app-level peer ID
        if self.transport.is_known_app_peer_id(peer_id).await {
            return Some(*peer_id);
        }
        // Fallback: connected transport peer (unsigned connections)
        if self.transport.is_peer_connected(peer_id).await {
            return Some(*peer_id);
        }
        None
    }

    /// Attempt to connect to a candidate peer with a timeout derived from the node config.
    ///
    /// All iterative lookups share the same saorsa-transport connection pool, so reusing the node's
    /// connection timeout keeps behavior consistent with the transport while still letting
    /// us parallelize lookups safely.
    ///
    /// Returns the transport channel ID on a successful QUIC connection, or
    /// `None` when the dial fails or is skipped. Callers that need to send
    /// messages immediately should pass the channel ID to
    /// [`TransportHandle::wait_for_peer_identity`] before sending, because
    /// the app-level `peer_to_channel` mapping is only populated after the
    /// asynchronous identity-exchange handshake completes.
    async fn dial_candidate(&self, peer_id: &PeerId, address: &MultiAddr) -> Option<String> {
        if self.is_peer_blocked(peer_id) {
            return None;
        }

        let peer_hex = peer_id.to_hex();

        if self.transport.is_peer_connected(peer_id).await {
            debug!("dial_candidate: peer {} already connected", peer_hex);
            return None;
        }

        // Reject unspecified addresses before attempting the connection.
        if address.ip().is_some_and(|ip| ip.is_unspecified()) {
            debug!(
                "dial_candidate: rejecting unspecified address for {}: {}",
                peer_hex, address
            );
            return None;
        }
        let dial_timeout = self
            .transport
            .connection_timeout()
            .min(self.config.request_timeout);
        match tokio::time::timeout(dial_timeout, self.transport.connect_peer(address)).await {
            Ok(Ok(channel_id)) => {
                debug!(
                    "dial_candidate: connected to {} at {} (channel {})",
                    peer_hex, address, channel_id
                );
                Some(channel_id)
            }
            Ok(Err(e)) => {
                debug!(
                    "dial_candidate: failed to connect to {} at {}: {}",
                    peer_hex, address, e
                );
                self.record_peer_failure(peer_id).await;
                None
            }
            Err(_) => {
                debug!(
                    "dial_candidate: timeout connecting to {} at {} (>{:?})",
                    peer_hex, address, dial_timeout
                );
                self.record_peer_failure(peer_id).await;
                None
            }
        }
    }

    /// Look up connectable addresses for `peer_id`.
    ///
    /// Checks the DHT routing table first (source of truth for DHT peer
    /// addresses), then falls back to the transport layer for connected peers.
    /// Returns an empty vec when the peer is unknown or has no addresses.
    pub(crate) async fn peer_addresses_for_dial(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        // 1. Routing table — filter to dialable QUIC addresses (the table
        //    can hold unspecified or non-QUIC entries from peer announcements).
        let addrs = self.dht.read().await.get_node_addresses(peer_id).await;
        let filtered = Self::dialable_addresses(&addrs);
        if !filtered.is_empty() {
            return filtered;
        }

        // 2. Transport layer — for connected peers not yet in the routing table
        if let Some(info) = self.transport.peer_info(peer_id).await {
            return Self::dialable_addresses(&info.addresses);
        }

        Vec::new()
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

        // Deserialize message (needed before block check so we can send a rejection response)
        let message: DhtNetworkMessage = postcard::from_bytes(data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // SEC: Block peers whose trust score has fallen below threshold.
        // Send an explicit rejection so the remote peer knows not to penalise
        // our trust score (avoiding mutual-block loops from silent timeouts).
        if self.is_peer_blocked(sender) {
            info!("Rejecting message from blocked peer {}", sender.to_hex());
            let _ = self.transport.disconnect_peer(sender).await;
            let response =
                self.create_response_message(&message, DhtNetworkResult::PeerRejected)?;
            return Ok(Some(
                postcard::to_stdvec(&response)
                    .map_err(|e| P2PError::Serialization(e.to_string().into()))?,
            ));
        }

        debug!(
            "[STEP 3] {}: Received {:?} from {} (msg_id: {})",
            self.config.peer_id.to_hex(),
            message.message_type,
            sender,
            message.message_id
        );

        // Update peer info
        self.update_peer_info(*sender, &message).await;

        match message.message_type {
            DhtMessageType::Request => {
                debug!(
                    "[STEP 3a] {}: Processing {:?} request from {}",
                    self.config.peer_id.to_hex(),
                    message.payload,
                    sender
                );
                let result = self.handle_dht_request(&message, sender).await?;
                debug!(
                    "[STEP 4] {}: Sending response {:?} back to {} (msg_id: {})",
                    self.config.peer_id.to_hex(),
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
                debug!(
                    "[STEP 5] {}: Received response from {} (msg_id: {})",
                    self.config.peer_id.to_hex(),
                    sender,
                    message.message_id
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

    /// Handle DHT request message.
    ///
    /// `authenticated_sender` is the transport-authenticated peer ID, used
    /// instead of the self-reported `message.source` for any security-sensitive
    /// decisions (e.g. filtering nodes in lookup responses).
    async fn handle_dht_request(
        &self,
        message: &DhtNetworkMessage,
        authenticated_sender: &PeerId,
    ) -> Result<DhtNetworkResult> {
        match &message.payload {
            DhtNetworkOperation::FindNode { key } => {
                debug!("Handling FIND_NODE request for key: {}", hex::encode(key));
                self.handle_find_node_request(key, authenticated_sender)
                    .await
            }
            DhtNetworkOperation::Ping => {
                debug!("Handling PING request from: {}", authenticated_sender);
                Ok(DhtNetworkResult::PongReceived {
                    responder: self.config.peer_id,
                    latency: Duration::from_millis(0), // Local response
                })
            }
            DhtNetworkOperation::Join => {
                debug!("Handling JOIN request from: {}", authenticated_sender);
                let dht_key = *authenticated_sender.as_bytes();

                // Node will be added to routing table through normal DHT operations
                debug!("Node {} joined the network", authenticated_sender);

                Ok(DhtNetworkResult::JoinSuccess {
                    assigned_key: dht_key,
                    bootstrap_peers: 1,
                })
            }
            DhtNetworkOperation::Leave => {
                debug!("Handling LEAVE request from: {}", authenticated_sender);
                // Remove the leaving node from our routing table
                // TODO: Implement node removal from DHT routing table
                // let dht_guard = self.dht.write().await;
                // if let Err(e) = dht_guard.remove_node(authenticated_sender).await {
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
        self.send_dht_request(peer_id, operation, None).await
    }

    /// Handle DHT response message
    ///
    /// Delivers the response via oneshot channel to the waiting request coroutine.
    /// Uses oneshot channel instead of shared Vec to eliminate TOCTOU races.
    ///
    /// Security: Resolves the sender to an authenticated app-level peer ID and
    /// verifies it matches a contacted peer. Transport IDs identify channels,
    /// not peers, so they are never used for authorization.
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

        // Resolve sender to app-level identity. Transport IDs identify channels,
        // not peers, so unauthenticated senders are rejected outright.
        let Some(sender_app_id) = self.canonical_app_peer_id(sender).await else {
            warn!(
                "Rejecting DHT response for {message_id}: sender {} has no authenticated app identity",
                sender
            );
            return Ok(());
        };

        // Find the active operation and send response via oneshot channel
        let Ok(mut ops) = self.active_operations.lock() else {
            warn!("active_operations mutex poisoned");
            return Ok(());
        };
        if let Some(context) = ops.get_mut(message_id) {
            // Authenticate solely on app-level peer ID.
            let source_authorized = context.peer_id == sender_app_id
                || context.contacted_nodes.contains(&sender_app_id);

            if !source_authorized {
                warn!(
                    "Rejecting DHT response for {message_id}: sender app_id {} \
                     (transport={}) not in contacted peers (expected {} or one of {:?})",
                    sender_app_id.to_hex(),
                    sender,
                    context.peer_id.to_hex(),
                    context
                        .contacted_nodes
                        .iter()
                        .map(PeerId::to_hex)
                        .collect::<Vec<_>>()
                );
                return Ok(());
            }

            // Take the sender out of the context (can only send once)
            if let Some(tx) = context.response_tx.take() {
                debug!(
                    "[STEP 5a] {}: Delivering response for msg_id {} to waiting request",
                    self.config.peer_id.to_hex(),
                    message_id
                );
                // Send the transport-authenticated sender identity, not the
                // self-reported message.source which could be spoofed.
                if tx.send((sender_app_id, result)).is_err() {
                    warn!(
                        "[STEP 5a FAILED] {}: Response channel closed for msg_id {} (receiver timed out)",
                        self.config.peer_id.to_hex(),
                        message_id
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
                self.config.peer_id.to_hex(),
                message_id
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
            DhtNetworkResult::NodesFound { key, .. } => DhtNetworkOperation::FindNode { key: *key },
            DhtNetworkResult::PongReceived { .. } => DhtNetworkOperation::Ping,
            DhtNetworkResult::JoinSuccess { .. } => DhtNetworkOperation::Join,
            DhtNetworkResult::LeaveSuccess => DhtNetworkOperation::Leave,
            DhtNetworkResult::PeerRejected => request.payload.clone(),
            DhtNetworkResult::Error { .. } => {
                return Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Cannot create response for error result".to_string().into(),
                )));
            }
        };

        Ok(DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: self.config.peer_id,
            target: Some(request.source),
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

    /// Update routing-table liveness (and address) for a peer on successful
    /// message exchange.
    ///
    /// Standard Kademlia: any successful RPC proves liveness. We touch the
    /// routing table entry to move it to the tail of its k-bucket and refresh
    /// the stored address so that `FindNode` responses stay current when a peer
    /// reconnects from a different endpoint.
    async fn update_peer_info(&self, peer_id: PeerId, _message: &DhtNetworkMessage) {
        let Some(app_peer_id) = self.canonical_app_peer_id(&peer_id).await else {
            debug!(
                "Ignoring DHT peer update for unauthenticated transport peer {}",
                peer_id
            );
            return;
        };

        // Resolve current address from the transport layer so the routing
        // table stays up-to-date when a peer reconnects from a new endpoint.
        let current_address = self
            .transport
            .peer_info(&app_peer_id)
            .await
            .and_then(|info| Self::first_dialable_address(&info.addresses));

        let dht = self.dht.read().await;
        if dht.touch_node(&app_peer_id, current_address.as_ref()).await {
            trace!("Touched routing table entry for {}", app_peer_id.to_hex());
        }
    }

    /// Reconcile already-connected peers into DHT bookkeeping/routing.
    ///
    /// Looks up each peer's actual user agent from the transport layer.
    /// Peers whose user agent is not yet known (e.g. identity announce still
    /// in flight) are skipped — they will be handled by the normal
    /// `PeerConnected` event path once authentication completes.
    async fn reconcile_connected_peers(&self) {
        let connected = self.transport.connected_peers().await;
        if connected.is_empty() {
            return;
        }

        info!(
            "Reconciling {} already-connected peers for DHT state",
            connected.len()
        );
        let mut skipped = 0u32;
        for peer_id in connected {
            if let Some(ua) = self.transport.peer_user_agent(&peer_id).await {
                self.handle_peer_connected(peer_id, &ua).await;
            } else {
                skipped += 1;
                debug!(
                    "Skipping reconciliation for peer {} — user agent not yet known",
                    peer_id.to_hex()
                );
            }
        }
        if skipped > 0 {
            info!(
                "Skipped {} peers during reconciliation (user agent unknown, will arrive via PeerConnected)",
                skipped
            );
        }
    }

    /// Handle an authenticated peer connection event.
    ///
    /// The `node_id` is the authenticated app-level [`PeerId`] — no
    /// `canonical_app_peer_id()` lookup is needed because `PeerConnected`
    /// only fires after identity verification.
    async fn handle_peer_connected(&self, node_id: PeerId, user_agent: &str) {
        let app_peer_id_hex = node_id.to_hex();

        // Block peers whose trust score has fallen below threshold
        if self.is_peer_blocked(&node_id) {
            info!(
                "Rejecting blocked peer {} from DHT (trust below threshold)",
                app_peer_id_hex
            );
            return;
        }

        info!(
            "DHT peer connected: app_id={}, user_agent={}",
            app_peer_id_hex, user_agent
        );
        let dht_key = *node_id.as_bytes();

        // peer_info() resolves app-level IDs internally via peer_to_channel.
        // Collect all dialable addresses — peers may be multi-homed or
        // reachable via multiple NAT traversal endpoints.
        let addresses = if let Some(info) = self.transport.peer_info(&node_id).await {
            Self::dialable_addresses(&info.addresses)
        } else {
            warn!("peer_info unavailable for app_peer_id {}", app_peer_id_hex);
            Vec::new()
        };

        // Skip peers with no addresses — they cannot be used for DHT routing.
        if addresses.is_empty() {
            warn!(
                "Peer {} has no valid addresses, skipping DHT routing table addition",
                app_peer_id_hex
            );
            return;
        }

        // Only add full nodes to the DHT routing table. Ephemeral clients
        // (user_agent not starting with "node/") are excluded to prevent stale
        // addresses from polluting peer discovery after the client disconnects.
        if !crate::network::is_dht_participant(user_agent) {
            info!(
                "Skipping DHT routing table for ephemeral peer {} (user_agent={})",
                app_peer_id_hex, user_agent
            );
        } else {
            let node_info = NodeInfo {
                id: node_id,
                addresses,
                last_seen: SystemTime::now(),
            };

            let trust_fn = |peer_id: &PeerId| -> f64 {
                self.trust_engine
                    .as_ref()
                    .map(|engine| engine.score(peer_id))
                    .unwrap_or(DEFAULT_NEUTRAL_TRUST)
            };
            if let Err(e) = self.dht.write().await.add_node(node_info, &trust_fn).await {
                warn!(
                    "Failed to add peer {} to DHT routing table: {}",
                    app_peer_id_hex, e
                );
            } else {
                info!("Added peer {} to DHT routing table", app_peer_id_hex);
            }
        }

        // Record successful connection for trust scoring
        self.record_peer_success(&node_id).await;

        if self.event_tx.receiver_count() > 0 {
            let _ = self.event_tx.send(DhtNetworkEvent::PeerDiscovered {
                peer_id: node_id,
                dht_key,
            });
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
                                crate::network::P2PEvent::PeerConnected(peer_id, ref user_agent) => {
                                    // Disconnect blocked peers immediately
                                    if self_arc.is_peer_blocked(&peer_id) {
                                        info!(
                                            "Disconnecting blocked peer {}",
                                            peer_id.to_hex()
                                        );
                                        let _ = self_arc.transport.disconnect_peer(&peer_id).await;
                                        continue;
                                    }
                                    self_arc.handle_peer_connected(peer_id, user_agent).await;
                                }
                                crate::network::P2PEvent::PeerDisconnected(peer_id) => {
                                    // peer_id IS the authenticated app-level PeerId.
                                    // PeerDisconnected only fires when all channels for
                                    // this peer have closed — no multi-channel check needed.
                                    info!(
                                        "DHT peer fully disconnected: app_id={}",
                                        peer_id.to_hex()
                                    );

                                    if self_arc.event_tx.receiver_count() > 0
                                        && let Err(e) = self_arc
                                            .event_tx
                                            .send(DhtNetworkEvent::PeerDisconnected {
                                                peer_id,
                                            })
                                    {
                                        warn!(
                                            "Failed to send PeerDisconnected event: {}",
                                            e
                                        );
                                    }
                                }
                                crate::network::P2PEvent::Message {
                                    topic,
                                    source,
                                    data,
                                } => {
                                    trace!(
                                        "  [EVENT] Message received: topic={}, source={:?}, {} bytes",
                                        topic,
                                        source,
                                        data.len()
                                    );
                                    if topic == "/dht/1.0.0" {
                                        // DHT messages must be authenticated.
                                        let Some(source_peer) = source else {
                                            warn!("Ignoring unsigned DHT message");
                                            continue;
                                        };
                                        trace!("  [EVENT] Processing DHT message from {}", source_peer);
                                        // Process the DHT message with backpressure via semaphore
                                        let manager_clone = Arc::clone(&self_arc);
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
                                                manager_clone.handle_dht_message(&data, &source_peer),
                                            )
                                            .await
                                            {
                                                Ok(Ok(Some(response))) => {
                                                    // Send response back to the source peer
                                                    if let Err(e) = manager_clone
                                                        .transport
                                                        .send_message(&source_peer, "/dht/1.0.0", response)
                                                        .await
                                                    {
                                                        warn!(
                                                            "Failed to send DHT response to {}: {}",
                                                            source_peer, e
                                                        );
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    // No response needed (e.g., for response messages)
                                                }
                                                Ok(Err(e)) => {
                                                    warn!(
                                                        "Failed to handle DHT message from {}: {}",
                                                        source_peer, e
                                                    );
                                                }
                                                Err(_) => {
                                                    // Timeout occurred - log warning and release permit
                                                    warn!(
                                                        "DHT message handler timed out after {:?} for peer {}: potential DoS attempt or slow processing",
                                                        REQUEST_TIMEOUT, source_peer
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

    /// Get current statistics
    pub async fn get_stats(&self) -> DhtNetworkStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to DHT network events
    pub fn subscribe_events(&self) -> broadcast::Receiver<DhtNetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get currently connected peers from the transport layer.
    pub async fn get_connected_peers(&self) -> Vec<PeerId> {
        self.transport.connected_peers().await
    }

    /// Get DHT routing table size (Node-mode peers only).
    pub async fn get_routing_table_size(&self) -> usize {
        self.dht.read().await.routing_table_size().await
    }

    /// Check whether a peer is present in the DHT routing table.
    ///
    /// Only peers that passed the `is_dht_participant` gate are added
    /// to the routing table.
    pub async fn is_in_routing_table(&self, peer_id: &PeerId) -> bool {
        let dht_guard = self.dht.read().await;
        dht_guard.has_node(peer_id).await
    }

    /// Get this node's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.config.peer_id
    }

    /// Get the local listen address of this node's P2P network
    ///
    /// Returns the address other nodes can use to connect to this node.
    pub fn local_addr(&self) -> Option<MultiAddr> {
        self.transport.local_addr()
    }

    /// Connect to a specific peer by address.
    ///
    /// This is useful for manually building network topology in tests.
    pub async fn connect_to_peer(&self, address: &MultiAddr) -> Result<String> {
        self.transport.connect_peer(address).await
    }

    /// Get the transport handle for direct transport-level operations.
    pub fn transport(&self) -> &Arc<crate::transport_handle::TransportHandle> {
        &self.transport
    }

    /// Get the optional trust engine used by this manager.
    pub fn trust_engine(&self) -> Option<Arc<TrustEngine>> {
        self.trust_engine.clone()
    }
}

/// Default request timeout for DHT operations (seconds)
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default maximum concurrent DHT operations
const DEFAULT_MAX_CONCURRENT_OPS: usize = 100;

impl Default for DhtNetworkConfig {
    fn default() -> Self {
        Self {
            peer_id: PeerId::from_bytes([0u8; 32]),
            node_config: NodeConfig::default(),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_concurrent_operations: DEFAULT_MAX_CONCURRENT_OPS,
            enable_security: true,
            block_threshold: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_dialable_address_skips_non_ip_when_ip_address_exists() {
        let ble = MultiAddr::new(crate::address::TransportAddr::Ble {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            psm: 0x0025,
        });
        let quic = MultiAddr::quic("127.0.0.1:9000".parse().unwrap());

        let selected = DhtNetworkManager::first_dialable_address(&[ble, quic.clone()]);

        assert_eq!(
            selected,
            Some(quic),
            "address selection should prefer a dialable IP transport over a preceding non-IP entry"
        );
    }

    #[test]
    fn test_first_dialable_address_returns_none_for_all_non_dialable() {
        let ble = MultiAddr::new(crate::address::TransportAddr::Ble {
            mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            psm: 128,
        });
        let tcp = MultiAddr::tcp("10.0.0.1:80".parse().unwrap());
        let lora = MultiAddr::new(crate::address::TransportAddr::LoRa {
            dev_addr: [0xDE, 0xAD, 0xBE, 0xEF],
            freq_hz: 868_000_000,
        });

        assert_eq!(
            DhtNetworkManager::first_dialable_address(&[ble, tcp, lora]),
            None,
            "should return None when no QUIC address is present"
        );
    }

    #[test]
    fn test_first_dialable_address_rejects_unspecified_ip() {
        let unspecified = MultiAddr::quic("0.0.0.0:9000".parse().unwrap());

        assert_eq!(
            DhtNetworkManager::first_dialable_address(&[unspecified]),
            None,
            "should reject unspecified (0.0.0.0) addresses"
        );
    }

    #[test]
    fn test_first_dialable_address_returns_none_for_empty_slice() {
        assert_eq!(
            DhtNetworkManager::first_dialable_address(&[]),
            None,
            "should return None for empty address list"
        );
    }

    #[test]
    fn test_peer_rejected_round_trips_through_serialization() {
        let result = DhtNetworkResult::PeerRejected;
        let bytes = postcard::to_stdvec(&result).expect("serialization should succeed");
        let deserialized: DhtNetworkResult =
            postcard::from_bytes(&bytes).expect("deserialization should succeed");
        assert!(
            matches!(deserialized, DhtNetworkResult::PeerRejected),
            "round-tripped result should be PeerRejected, got: {deserialized:?}"
        );
    }

    #[test]
    fn test_peer_rejected_response_message_preserves_request_payload() {
        let request = DhtNetworkMessage {
            message_id: "test-123".to_string(),
            source: PeerId::random(),
            target: Some(PeerId::random()),
            message_type: DhtMessageType::Request,
            payload: DhtNetworkOperation::Ping,
            result: None,
            timestamp: 0,
            ttl: 10,
            hop_count: 0,
        };

        // Serialize & deserialize the full response message to verify
        // PeerRejected survives a wire round-trip inside a DhtNetworkMessage.
        let response = DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: PeerId::random(),
            target: Some(request.source),
            message_type: DhtMessageType::Response,
            payload: request.payload.clone(),
            result: Some(DhtNetworkResult::PeerRejected),
            timestamp: 0,
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count.saturating_add(1),
        };

        let bytes = postcard::to_stdvec(&response).expect("serialize response");
        let decoded: DhtNetworkMessage =
            postcard::from_bytes(&bytes).expect("deserialize response");

        assert!(
            matches!(decoded.result, Some(DhtNetworkResult::PeerRejected)),
            "response result should be PeerRejected"
        );
        assert!(
            matches!(decoded.payload, DhtNetworkOperation::Ping),
            "response should echo the request's Ping payload"
        );
    }
}
