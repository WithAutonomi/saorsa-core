//! DHT Core Engine with Kademlia routing
//!
//! Provides peer discovery and routing via a Kademlia DHT with k=8 buckets,
//! trust-weighted peer selection, and security-hardened maintenance tasks.

use crate::PeerId;
use crate::adaptive::EigenTrustEngine;
use crate::address::MultiAddr;
use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::network_integration::{DhtMessage, DhtResponse};
use crate::dht::routing_maintenance::close_group_validator::{
    CloseGroupEnforcementMode, CloseGroupFailure, CloseGroupValidator, CloseGroupValidatorConfig,
};
use crate::dht::routing_maintenance::{
    BucketRefreshManager, EvictionManager, EvictionReason, MaintenanceConfig,
};
use crate::dht::trust_peer_selector::{TrustAwarePeerSelector, TrustSelectionConfig};
use crate::security::IPDiversityConfig;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// DHT key type — now a direct alias for [`PeerId`].
///
/// Both types are `[u8; 32]` wrappers with identity conversions between them.
/// Using a single type eliminates keyspace mismatch bugs where BLAKE3-hashing
/// a PeerId into a second "DHT key" space caused nodes to land in wrong
/// Kademlia buckets.
pub type DhtKey = PeerId;

#[inline]
fn xor_distance_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = a[idx] ^ b[idx];
    }
    out
}

/// Node information for routing.
///
/// The `address` field stores a typed [`MultiAddr`] that is always valid.
/// For wire-protocol compatibility it serializes as a plain `"ip:port"` string
/// and deserializes from both `"ip:port"` and MultiAddr formats like
/// `/ip4/1.2.3.4/udp/9000`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: PeerId,
    #[serde(with = "crate::address::serde_as_string")]
    pub address: MultiAddr,
    pub last_seen: SystemTime,
    pub capacity: NodeCapacity,
}

impl NodeInfo {
    /// Get the socket address. Always succeeds because `MultiAddr`
    /// guarantees a valid `SocketAddr`.
    #[must_use]
    pub fn socket_addr(&self) -> SocketAddr {
        self.address.socket_addr
    }

    /// Get the IP address. Always succeeds because `MultiAddr`
    /// guarantees a valid IP.
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        self.address.ip()
    }
}

/// Node capacity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub bandwidth_available: u64,
    pub reliability_score: f64,
}

impl Default for NodeCapacity {
    fn default() -> Self {
        Self {
            bandwidth_available: 10_000_000, // 10MB/s
            reliability_score: 1.0,
        }
    }
}

/// K-bucket for Kademlia routing
struct KBucket {
    nodes: Vec<NodeInfo>,
    max_size: usize,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_size,
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // If the node is already in this bucket, replace it fully and move to
        // tail (most-recently-seen) per standard Kademlia protocol.
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push(node);
            return Ok(());
        }

        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
            Ok(())
        } else {
            Err(anyhow!(
                "K-bucket at capacity ({}/{})",
                self.nodes.len(),
                self.max_size
            ))
        }
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        self.nodes.retain(|n| &n.id != node_id);
    }

    /// Update `last_seen` (and optionally the address) for a node, then move
    /// it to the tail of the bucket (most recently seen) per Kademlia protocol.
    ///
    /// The `address` parameter accepts a string in either `"ip:port"` or
    /// MultiAddr format.  Invalid strings are silently ignored — the existing
    /// address is preserved.
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&str>) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) {
            self.nodes[pos].last_seen = SystemTime::now();
            if let Some(addr) = address
                && !addr.is_empty()
                && let Ok(parsed) = addr.parse::<MultiAddr>()
            {
                self.nodes[pos].address = parsed;
            }
            let node = self.nodes.remove(pos);
            self.nodes.push(node);
            true
        } else {
            false
        }
    }

    fn get_nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    fn find_node(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| &n.id == node_id)
    }
}

/// Kademlia routing table
pub struct KademliaRoutingTable {
    buckets: Vec<KBucket>,
    node_id: PeerId,
    _k_value: usize,
}

impl KademliaRoutingTable {
    fn new(node_id: PeerId, k_value: usize) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..KADEMLIA_BUCKET_COUNT {
            buckets.push(KBucket::new(k_value));
        }

        Self {
            buckets,
            node_id,
            _k_value: k_value,
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        let bucket_index = self.get_bucket_index(&node.id);
        self.buckets[bucket_index].add_node(node)
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].remove_node(node_id);
    }

    /// Update `last_seen` (and optionally address) for a node and move it to
    /// the tail of its k-bucket. Returns `true` if the node was found.
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&str>) -> bool {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].touch_node(node_id, address)
    }

    fn find_closest_nodes(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        // Optimization: Start from the bucket closest to the key and work outwards
        // This avoids collecting all nodes from all 256 buckets when we only need a few
        let target_bucket = self.get_bucket_index_for_key(key);

        let mut candidates: Vec<(NodeInfo, [u8; 32])> = Vec::with_capacity(count * 2);

        // Visit buckets in order of proximity to target, each exactly once.
        // Uses checked arithmetic so indices that would exceed [0, 255] are
        // skipped rather than clamped, preventing duplicate bucket visits.
        let bucket_iter = std::iter::once(target_bucket).chain(
            (1..KADEMLIA_BUCKET_COUNT).flat_map(move |offset| {
                let above = target_bucket
                    .checked_add(offset)
                    .filter(|&b| b < KADEMLIA_BUCKET_COUNT);
                let below = target_bucket.checked_sub(offset);
                above.into_iter().chain(below)
            }),
        );

        for bucket_idx in bucket_iter {
            for node in self.buckets[bucket_idx].get_nodes() {
                let distance = xor_distance_bytes(node.id.to_bytes(), key.as_bytes());
                candidates.push((node.clone(), distance));
            }

            // Early exit: if we have enough candidates, we can stop expanding
            if candidates.len() >= count * CANDIDATE_EXPANSION_FACTOR {
                break;
            }
        }

        // Sort by distance
        candidates.sort_by(|a, b| a.1.cmp(&b.1));

        // Return top `count` nodes
        candidates
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    fn get_bucket_index_for_key(&self, key: &DhtKey) -> usize {
        let distance = xor_distance_bytes(self.node_id.to_bytes(), key.as_bytes());

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return i;
            }
        }

        255 // Same key as node
    }

    /// Look up a node by its exact peer ID. O(K) scan of the target bucket.
    fn find_node_by_id(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].find_node(node_id)
    }

    /// Total number of nodes across all buckets.
    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.get_nodes().len()).sum()
    }

    /// Iterate over every node in the routing table.
    fn iter_nodes(&self) -> impl Iterator<Item = &NodeInfo> {
        self.buckets.iter().flat_map(|b| b.get_nodes().iter())
    }

    fn get_bucket_index(&self, node_id: &PeerId) -> usize {
        self.get_bucket_index_for_key(&DhtKey::from_bytes(*node_id.to_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Address parsing and subnet masking helpers for diversity checks
// ---------------------------------------------------------------------------

/// Accumulator for IPv4 subnet match counts during diversity scan.
#[derive(Default)]
struct Ipv4SubnetCounts {
    exact: usize,
    slash_24: usize,
    slash_16: usize,
}

/// Accumulator for IPv6 subnet match counts during diversity scan.
#[derive(Default)]
struct Ipv6SubnetCounts {
    slash_64: usize,
    slash_48: usize,
    slash_32: usize,
}

/// Zero out the host bits of an IPv4 address beyond `prefix_len`.
fn mask_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(bits & mask)
}

/// Zero out the host bits of an IPv6 address beyond `prefix_len`.
fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(bits & mask)
}

/// Default maximum nodes per geographic region. Matches
/// `GeographicRoutingConfig::max_nodes_per_region` default.
const GEO_DEFAULT_MAX_PER_REGION: usize = 50;

/// K parameter - number of closest nodes per bucket
const K: usize = 8;

/// Maximum node count for FindNode requests
/// Prevents amplification attacks by limiting response size
const MAX_FIND_NODE_COUNT: usize = 20;

/// Number of K-buckets in Kademlia routing table (one per bit in 256-bit key space)
const KADEMLIA_BUCKET_COUNT: usize = 256;

/// Candidate expansion factor for find_closest_nodes optimization
/// Collect 2x requested count before early exit to ensure good selection
const CANDIDATE_EXPANSION_FACTOR: usize = 2;

/// DHT routing table maintenance interval in seconds
/// Periodic refresh of buckets and eviction of stale nodes
const MAINTENANCE_INTERVAL_SECS: u64 = 60;

/// DHT request wrapper with request ID for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRequestWrapper {
    /// Unique request ID for response correlation
    pub id: String,
    /// The underlying DHT message
    pub message: DhtMessage,
}

/// DHT response wrapper with request ID for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtResponseWrapper {
    /// Request ID this response corresponds to
    pub id: String,
    /// The underlying DHT response
    pub response: DhtResponse,
}

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: PeerId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,

    // Security Components
    bucket_refresh_manager: Arc<RwLock<BucketRefreshManager>>,
    close_group_validator: Arc<RwLock<CloseGroupValidator>>,
    eviction_manager: Arc<RwLock<EvictionManager>>,

    /// IP diversity limits — checked against the live routing table on each
    /// `add_node` call rather than maintained as incremental counters.
    ip_diversity_config: IPDiversityConfig,
    /// Allow loopback addresses in the routing table.
    ///
    /// Set once at construction from `NodeConfig.allow_loopback` and never
    /// mutated — `NodeConfig` is the single source of truth. Kept separate
    /// from `IPDiversityConfig` to prevent duplication and drift.
    allow_loopback: bool,
    /// Maximum nodes per geographic region.
    geo_max_per_region: usize,

    // Trust-weighted peer selection
    /// Optional trust-aware peer selector for combining distance with trust scores
    trust_peer_selector: Option<TrustAwarePeerSelector<EigenTrustEngine>>,

    /// Shutdown token for background maintenance tasks
    shutdown: CancellationToken,
}

impl DhtCoreEngine {
    /// Create new DHT engine with specified node ID
    pub fn new(node_id: PeerId) -> Result<Self> {
        Self::new_with_validation_mode(node_id, CloseGroupEnforcementMode::Strict, false)
    }

    /// Create new DHT engine for testing (permissive validation)
    #[cfg(test)]
    pub fn new_for_tests(node_id: PeerId) -> Result<Self> {
        Self::new_with_validation_mode(node_id, CloseGroupEnforcementMode::LogOnly, false)
    }

    /// Override the IP diversity configuration.
    pub fn set_ip_diversity_config(&mut self, config: IPDiversityConfig) {
        self.ip_diversity_config = config;
    }

    /// Set whether loopback addresses are allowed in the routing table.
    /// Only available in test builds — production code sets this at construction.
    #[cfg(test)]
    pub fn set_allow_loopback(&mut self, allow: bool) {
        self.allow_loopback = allow;
    }

    /// Create new DHT engine with specified validation mode
    pub(crate) fn new_with_validation_mode(
        node_id: PeerId,
        enforcement_mode: CloseGroupEnforcementMode,
        allow_loopback: bool,
    ) -> Result<Self> {
        // Initialize security components
        let validator_config =
            CloseGroupValidatorConfig::default().with_enforcement_mode(enforcement_mode);
        let close_group_validator = Arc::new(RwLock::new(CloseGroupValidator::new(
            validator_config.clone(),
        )));

        let mut bucket_refresh_manager =
            BucketRefreshManager::new_with_validation(node_id, validator_config.clone());
        // Link validator to refresh manager
        bucket_refresh_manager.set_validator(close_group_validator.clone());
        let bucket_refresh_manager = Arc::new(RwLock::new(bucket_refresh_manager));

        let eviction_manager = Arc::new(RwLock::new(EvictionManager::new(
            MaintenanceConfig::default(),
        )));

        Ok(Self {
            node_id,
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, K))),
            bucket_refresh_manager,
            close_group_validator,
            eviction_manager,
            ip_diversity_config: IPDiversityConfig::default(),
            allow_loopback,
            geo_max_per_region: GEO_DEFAULT_MAX_PER_REGION,
            trust_peer_selector: None,
            shutdown: CancellationToken::new(),
        })
    }

    /// Get this node's ID
    #[must_use]
    pub fn node_id(&self) -> &PeerId {
        &self.node_id
    }

    /// Number of peers currently in the routing table.
    pub async fn routing_table_size(&self) -> usize {
        self.routing_table.read().await.node_count()
    }

    // ===== Trust-weighted peer selection methods =====

    /// Enable trust-weighted peer selection
    ///
    /// When enabled, peer selection for DHT operations will combine XOR distance
    /// with EigenTrust scores to prefer higher-trust nodes.
    ///
    /// # Arguments
    /// * `trust_engine` - The EigenTrust engine providing trust scores
    /// * `config` - Configuration for trust selection behavior
    pub fn enable_trust_selection(
        &mut self,
        trust_engine: Arc<EigenTrustEngine>,
        config: TrustSelectionConfig,
    ) {
        self.trust_peer_selector = Some(TrustAwarePeerSelector::new(trust_engine, config));
        tracing::info!("DHT trust-weighted peer selection enabled");
    }

    /// Disable trust-weighted peer selection
    ///
    /// Falls back to pure distance-based selection.
    pub fn disable_trust_selection(&mut self) {
        self.trust_peer_selector = None;
        tracing::info!("DHT trust-weighted peer selection disabled");
    }

    /// Check if trust-weighted peer selection is enabled
    #[must_use]
    pub fn has_trust_selection(&self) -> bool {
        self.trust_peer_selector.is_some()
    }

    /// Signal background maintenance tasks to stop
    pub fn signal_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Start background maintenance tasks for security and health
    pub fn start_maintenance_tasks(&self) {
        let routing_table = self.routing_table.clone();
        let refresh_manager = self.bucket_refresh_manager.clone();
        let eviction_manager = self.eviction_manager.clone();
        let close_group_validator = self.close_group_validator.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    () = shutdown.cancelled() => {
                        tracing::info!("DHT core maintenance task shutting down");
                        break;
                    }
                }

                // 1. Run Bucket Refresh Logic with Validation Integration
                {
                    let mut mgr = refresh_manager.write().await;

                    // Check for attack mode escalation based on validation failures
                    if mgr.should_trigger_attack_mode() {
                        if let Some(validator) = mgr.validator() {
                            validator.write().await.escalate_to_bft();
                            tracing::warn!(
                                "Escalating to BFT mode due to validation failures (rate: {:.2}%)",
                                mgr.overall_validation_rate() * 100.0
                            );
                        }
                    } else if let Some(validator) = mgr.validator() {
                        // De-escalate if validation rate recovers above 85%
                        if mgr.overall_validation_rate() > 0.85 {
                            validator.write().await.deescalate_from_bft();
                        }
                    }

                    // Get buckets needing refresh
                    let buckets = mgr.get_buckets_needing_refresh();
                    if !buckets.is_empty() {
                        // Get buckets that also need validation
                        let validation_buckets = mgr.get_buckets_needing_validation();
                        let mut total_validated = 0usize;
                        let mut total_evicted = 0usize;

                        for bucket in buckets {
                            // Record refresh (in a real impl, trigger network lookups first)
                            mgr.record_refresh_success(bucket, 0);

                            // Perform trust-based validation during refresh
                            if validation_buckets.contains(&bucket) {
                                // Get nodes that need validation from the refresh manager
                                let nodes_to_validate = mgr.get_nodes_in_bucket(bucket);

                                // Validate each node using trust-based validation
                                let validator = close_group_validator.read().await;
                                let mut evict_list = Vec::new();

                                for node_id in &nodes_to_validate {
                                    // Query trust score from eviction manager's trust cache
                                    // This cache is populated by EigenTrust updates via update_trust_score()
                                    let trust_score = {
                                        let evict_mgr = eviction_manager.read().await;
                                        evict_mgr.get_trust_score(node_id)
                                    };

                                    let (is_valid, failure_reason) =
                                        validator.validate_trust_only(node_id, trust_score);

                                    if !is_valid && let Some(reason) = failure_reason {
                                        tracing::info!(
                                            node_id = ?node_id,
                                            bucket = bucket,
                                            reason = ?reason,
                                            "Node failed validation during refresh"
                                        );
                                        evict_list
                                            .push((*node_id, EvictionReason::CloseGroupRejection));
                                    }
                                }
                                drop(validator);

                                total_validated += nodes_to_validate.len();

                                // Queue evictions
                                if !evict_list.is_empty() {
                                    let mut evict_mgr = eviction_manager.write().await;
                                    for (node_id, reason) in evict_list {
                                        evict_mgr.record_eviction(&node_id, reason);
                                        total_evicted += 1;
                                    }
                                }

                                // Record validation metrics
                                let nodes_count = nodes_to_validate.len();
                                mgr.record_validation_result(bucket, nodes_count, 0);

                                tracing::debug!(
                                    bucket = bucket,
                                    nodes_validated = nodes_count,
                                    "Bucket validation completed during refresh"
                                );
                            }
                        }

                        if total_validated > 0 || total_evicted > 0 {
                            tracing::info!(
                                total_validated = total_validated,
                                total_evicted = total_evicted,
                                "Refresh validation cycle completed"
                            );
                        }
                    }
                }

                // 2. Active Eviction Enforcement — remove candidates from both
                //    the eviction tracker and the routing table.
                {
                    let mut eviction_mgr = eviction_manager.write().await;
                    let candidates = eviction_mgr.get_eviction_candidates();
                    if !candidates.is_empty() {
                        let mut routing = routing_table.write().await;
                        for (node_id, reason) in candidates {
                            tracing::warn!("Evicting node {} for reason: {:?}", node_id, reason);
                            routing.remove_node(&node_id);
                            eviction_mgr.remove_node(&node_id);
                        }
                    }
                }

                // 4. Update Metrics
                // (Example: update churn rate)
                // metrics.update_churn(...)
            }
        });
    }

    /// Handle an incoming DHT request from the network
    ///
    /// Processes the request and returns a response wrapper ready to be sent back.
    pub async fn handle_request(&self, request_wrapper: DhtRequestWrapper) -> DhtResponseWrapper {
        let response = match request_wrapper.message {
            DhtMessage::FindNode { ref target, count } => {
                // Security: Cap count to prevent amplification attacks
                let capped_count = count.min(MAX_FIND_NODE_COUNT);
                let routing = self.routing_table.read().await;
                let nodes = routing.find_closest_nodes(target, capped_count);
                DhtResponse::FindNodeReply {
                    nodes,
                    distances: Vec::new(),
                }
            }
            DhtMessage::Ping { timestamp } => DhtResponse::Pong { timestamp },
            _ => DhtResponse::Error {
                code: crate::dht::network_integration::ErrorCode::InvalidMessage,
                message: "Unsupported message type".to_string(),
                retry_after: None,
            },
        };

        DhtResponseWrapper {
            id: request_wrapper.id,
            response,
        }
    }

    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes(key, count))
    }

    /// Join the DHT network.
    ///
    /// Bootstrap nodes go through the same close-group validation and
    /// IP/geographic diversity checks as every other `add_node` call, so a
    /// compromised bootstrap list cannot bypass security invariants.
    ///
    /// Returns an error if the list is non-empty but *every* node fails
    /// validation (the caller would be left with an empty routing table).
    pub async fn join_network(&mut self, bootstrap_nodes: Vec<NodeInfo>) -> Result<()> {
        let total = bootstrap_nodes.len();
        let mut added: usize = 0;
        for node in bootstrap_nodes {
            match self.add_node(node).await {
                Ok(()) => added += 1,
                Err(e) => tracing::warn!("Skipping bootstrap node that failed validation: {e}"),
            }
        }

        if total > 0 && added == 0 {
            return Err(anyhow!(
                "All {total} bootstrap nodes failed validation — cannot join network"
            ));
        }

        Ok(())
    }

    /// Leave the DHT network gracefully
    pub async fn leave_network(&mut self) -> Result<()> {
        Ok(())
    }

    /// Look up a node's address from the routing table by peer ID.
    ///
    /// Returns the stored address if the peer is in the routing table,
    /// `None` otherwise. O(K) scan of the target k-bucket.
    pub async fn get_node_address(&self, peer_id: &PeerId) -> Option<MultiAddr> {
        let routing = self.routing_table.read().await;
        routing.find_node_by_id(peer_id).map(|n| n.address.clone())
    }

    /// Record a successful interaction with a peer by updating its `last_seen`
    /// timestamp (and optionally its address) and moving it to the tail of its
    /// k-bucket (most recently seen).
    ///
    /// Standard Kademlia: any successful RPC implicitly proves liveness, so the
    /// routing table should reflect this without requiring dedicated pings.
    /// Passing the current address ensures stale addresses are replaced when a
    /// peer reconnects from a different endpoint.
    pub async fn touch_node(&self, node_id: &PeerId, address: Option<&str>) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address)
    }

    /// Handle node failure by removing it from the routing table.
    pub async fn handle_node_failure(&mut self, failed_node: PeerId) -> Result<()> {
        let mut routing = self.routing_table.write().await;
        routing.remove_node(&failed_node);
        Ok(())
    }

    /// Evict a node from the routing table with a specific reason.
    ///
    /// This is called when a node fails security validation or is detected
    /// as malicious through Sybil/collusion detection.
    pub async fn evict_node(&self, node_id: &PeerId, reason: EvictionReason) -> Result<()> {
        // 1. Remove from routing table
        {
            let mut routing = self.routing_table.write().await;
            routing.remove_node(node_id);
        }

        // 2. Log eviction for data integrity tracking
        // Note: Data health tracking handled elsewhere
        // Evicted nodes will be removed from routing table, which affects future lookups

        tracing::info!(
            node_id = %node_id,
            reason = ?reason,
            "Node evicted from DHT"
        );

        Ok(())
    }

    /// Evict a node due to close group validation failure.
    ///
    /// This is a specialized eviction for security-related failures.
    pub async fn evict_node_for_security(
        &self,
        node_id: &PeerId,
        failure_reason: CloseGroupFailure,
    ) -> Result<()> {
        let eviction_reason = match failure_reason {
            CloseGroupFailure::NotInCloseGroup => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::EvictedFromCloseGroup => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::InsufficientConfirmation => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::LowTrustScore => {
                EvictionReason::LowTrust("Security validation failed".to_string())
            }
            CloseGroupFailure::InsufficientGeographicDiversity => {
                EvictionReason::LowTrust("Geographic diversity violation".to_string())
            }
            CloseGroupFailure::SuspectedCollusion => {
                EvictionReason::LowTrust("Suspected collusion".to_string())
            }
            CloseGroupFailure::AttackModeTriggered => {
                EvictionReason::LowTrust("Attack mode triggered".to_string())
            }
        };

        self.evict_node(node_id, eviction_reason).await
    }

    /// Get eviction candidates from the refresh manager.
    ///
    /// Returns nodes that should be evicted based on validation failures.
    pub async fn get_eviction_candidates(&self) -> Vec<(PeerId, CloseGroupFailure)> {
        self.bucket_refresh_manager
            .read()
            .await
            .get_nodes_for_eviction()
            .await
    }

    /// Check if the system is currently in attack mode.
    #[must_use]
    pub async fn is_attack_mode(&self) -> bool {
        self.bucket_refresh_manager
            .read()
            .await
            .is_attack_mode()
            .await
    }

    /// Get the bucket refresh manager for external access
    pub fn bucket_refresh_manager(&self) -> Arc<RwLock<BucketRefreshManager>> {
        self.bucket_refresh_manager.clone()
    }

    /// Get the close group validator for external access
    pub fn close_group_validator(&self) -> Arc<RwLock<CloseGroupValidator>> {
        self.close_group_validator.clone()
    }

    /// Add a node to the DHT with security checks.
    ///
    /// Diversity limits (IP subnet and geographic region) are derived from the
    /// live routing table contents on every call, so counts are always accurate
    /// regardless of evictions, reconnections, or address changes.
    pub async fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // 1. Security Check: Close Group Validator
        {
            let validator = self.close_group_validator.read().await;
            if !validator.validate(&node.id) {
                tracing::warn!("Node failed close group validation: {:?}", node.id);
                return Err(anyhow::anyhow!("Node failed close group validation"));
            }
        }

        // MultiAddr guarantees a valid IP — no parsing can fail.
        let candidate_ip = node.ip();

        // 2. Security Check: IP + Geographic Diversity
        //
        // Counts are derived from the routing table in a single pass.
        // Nodes already present (reconnecting with the same ID) are
        // excluded from the count so they can update their address
        // without inflating limits.
        // 3. Add to routing table — single write lock for both the diversity
        //    check and the insertion to avoid a TOCTOU race where touch_node
        //    could change an address between a read-lock check and the write.
        let mut routing = self.routing_table.write().await;
        self.check_diversity(&routing, &node.id, candidate_ip)?;
        routing.add_node(node)?;

        Ok(())
    }

    /// Check IP subnet and geographic diversity against the live routing table.
    ///
    /// Single pass over all nodes — each node's address is parsed once.
    /// `candidate_id` is excluded from counting so that a reconnecting node
    /// doesn't block itself.  Loopback candidates are only accepted when
    /// `self.allow_loopback` is `true`; otherwise they are
    /// rejected outright.  Existing loopback nodes in the table are always
    /// excluded from `network_size` and subnet/region counts so they don't
    /// inflate the dynamic per-IP limit in devnet environments.
    fn check_diversity(
        &self,
        routing: &KademliaRoutingTable,
        candidate_id: &PeerId,
        candidate_ip: IpAddr,
    ) -> Result<()> {
        // Loopback addresses (127.0.0.0/8, ::1) are used in tests and local
        // development where many nodes share the same IP.  When
        // `allow_loopback` is enabled, diversity limits don't apply to them.
        // In production (allow_loopback = false), loopback addresses are
        // rejected outright — a peer advertising 127.0.0.1/::1 should never
        // enter the routing table.
        if candidate_ip.is_loopback() {
            if self.allow_loopback {
                return Ok(());
            }
            return Err(anyhow!(
                "IP diversity: loopback address {candidate_ip} rejected (allow_loopback=false)"
            ));
        }

        let candidate_region = GeographicRegion::from_ip(candidate_ip);
        let mut region_count: usize = 0;
        let mut network_size: usize = 0;

        // Protocol-specific subnet accumulators
        let mut v4_counts = Ipv4SubnetCounts::default();
        let mut v6_counts = Ipv6SubnetCounts::default();

        // Precompute candidate subnet masks
        let v4_masks = match candidate_ip {
            IpAddr::V4(v4) => Some((v4, mask_ipv4(v4, 24), mask_ipv4(v4, 16))),
            _ => None,
        };
        let v6_masks = match candidate_ip {
            IpAddr::V6(v6) => Some((mask_ipv6(v6, 64), mask_ipv6(v6, 48), mask_ipv6(v6, 32))),
            _ => None,
        };

        for node in routing.iter_nodes() {
            if node.id == *candidate_id {
                continue;
            }
            let existing_ip = node.ip();
            // Loopback nodes don't contribute to network_size or any counts
            if existing_ip.is_loopback() {
                continue;
            }
            network_size += 1;
            if GeographicRegion::from_ip(existing_ip) == candidate_region {
                region_count += 1;
            }
            // Count subnet matches for the candidate's address family
            match (existing_ip, v4_masks, v6_masks) {
                (IpAddr::V4(existing_v4), Some((v4, cand_24, cand_16)), _) => {
                    if existing_v4 == v4 {
                        v4_counts.exact += 1;
                    }
                    if mask_ipv4(existing_v4, 24) == cand_24 {
                        v4_counts.slash_24 += 1;
                    }
                    if mask_ipv4(existing_v4, 16) == cand_16 {
                        v4_counts.slash_16 += 1;
                    }
                }
                (IpAddr::V6(existing_v6), _, Some((cand_64, cand_48, cand_32))) => {
                    if mask_ipv6(existing_v6, 64) == cand_64 {
                        v6_counts.slash_64 += 1;
                    }
                    if mask_ipv6(existing_v6, 48) == cand_48 {
                        v6_counts.slash_48 += 1;
                    }
                    if mask_ipv6(existing_v6, 32) == cand_32 {
                        v6_counts.slash_32 += 1;
                    }
                }
                _ => {}
            }
        }

        // Enforce subnet limits
        let per_ip = self.dynamic_per_ip_limit(network_size);
        match candidate_ip {
            IpAddr::V4(v4) => {
                let cfg = &self.ip_diversity_config;
                let limit_32 = cfg
                    .max_nodes_per_ipv4_32
                    .map_or(per_ip, |cap| cap.min(per_ip));
                let limit_24 = cfg
                    .max_nodes_per_ipv4_24
                    .map_or(per_ip * 3, |cap| cap.min(per_ip * 3));
                let limit_16 = cfg
                    .max_nodes_per_ipv4_16
                    .map_or(per_ip * 10, |cap| cap.min(per_ip * 10));

                if v4_counts.exact >= limit_32 {
                    return Err(anyhow!(
                        "IP diversity: /32 limit ({limit_32}) exceeded for {v4}"
                    ));
                }
                if v4_counts.slash_24 >= limit_24 {
                    let cand_24 = mask_ipv4(v4, 24);
                    return Err(anyhow!(
                        "IP diversity: /24 limit ({limit_24}) exceeded for {cand_24}"
                    ));
                }
                if v4_counts.slash_16 >= limit_16 {
                    let cand_16 = mask_ipv4(v4, 16);
                    return Err(anyhow!(
                        "IP diversity: /16 limit ({limit_16}) exceeded for {cand_16}"
                    ));
                }
            }
            IpAddr::V6(_) => {
                let cfg = &self.ip_diversity_config;
                let limit_64 = std::cmp::min(cfg.max_nodes_per_64, per_ip * 3);
                let limit_48 = std::cmp::min(cfg.max_nodes_per_48, per_ip * 10);
                let limit_32 = std::cmp::min(cfg.max_nodes_per_32, per_ip * 30);

                if v6_counts.slash_64 >= limit_64 {
                    return Err(anyhow!("IP diversity: /64 limit ({limit_64}) exceeded"));
                }
                if v6_counts.slash_48 >= limit_48 {
                    return Err(anyhow!("IP diversity: /48 limit ({limit_48}) exceeded"));
                }
                if v6_counts.slash_32 >= limit_32 {
                    return Err(anyhow!("IP diversity: /32 limit ({limit_32}) exceeded"));
                }
            }
        }

        if region_count >= self.geo_max_per_region {
            return Err(anyhow!(
                "Geographic diversity: region {candidate_region:?} limit ({}) exceeded",
                self.geo_max_per_region
            ));
        }

        Ok(())
    }

    /// Dynamic per-IP limit: `min(cap, floor(network_size * fraction))`,
    /// clamped to at least 1.  `network_size` excludes loopback nodes so
    /// devnet environments don't inflate the limit for non-loopback IPs.
    fn dynamic_per_ip_limit(&self, network_size: usize) -> usize {
        let fraction =
            (network_size as f64 * self.ip_diversity_config.max_network_fraction).floor() as usize;
        std::cmp::min(
            self.ip_diversity_config.max_per_ip_cap,
            std::cmp::max(1, fraction),
        )
    }
}

// Manual Debug implementation to avoid cascade of Debug requirements
impl std::fmt::Debug for DhtCoreEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtCoreEngine")
            .field("node_id", &self.node_id)
            .field("routing_table", &"Arc<RwLock<KademliaRoutingTable>>")
            .field(
                "bucket_refresh_manager",
                &"Arc<RwLock<BucketRefreshManager>>",
            )
            .field("close_group_validator", &"Arc<RwLock<CloseGroupValidator>>")
            .field("eviction_manager", &"Arc<RwLock<EvictionManager>>")
            .field("ip_diversity_config", &self.ip_diversity_config)
            .field("geo_max_per_region", &self.geo_max_per_region)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_xor_distance() {
        let key1 = DhtKey::from_bytes([0u8; 32]);
        let key2 = DhtKey::from_bytes([255u8; 32]);

        let distance = key1.distance(&key2);
        assert_eq!(distance, [255u8; 32]);
    }

    /// Helper: create a NodeInfo with a deterministic PeerId derived from a
    /// single byte.  Keeps tests concise.
    fn make_node(byte: u8, address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes([byte; 32]),
            address: address.parse::<MultiAddr>().unwrap(),
            last_seen: SystemTime::now(),
            capacity: NodeCapacity::default(),
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::touch_node tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_touch_node_updates_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "1.2.3.4:9000");
        bucket.add_node(node).unwrap();

        // Touch with a new address
        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), Some("5.6.7.8:9000"));
        assert!(found);
        let expected: MultiAddr = "5.6.7.8:9000".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().address, expected);
    }

    #[test]
    fn test_touch_node_none_preserves_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "1.2.3.4:9000");
        bucket.add_node(node).unwrap();

        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), None);
        assert!(found);
        let expected: MultiAddr = "1.2.3.4:9000".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().address, expected);
    }

    #[test]
    fn test_touch_node_moves_to_tail() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket.add_node(make_node(1, "1.1.1.1:9000")).unwrap();
        bucket.add_node(make_node(2, "2.2.2.2:9000")).unwrap();
        bucket.add_node(make_node(3, "3.3.3.3:9000")).unwrap();

        // Touch the first node — it should move to the tail
        bucket.touch_node(&PeerId::from_bytes([1u8; 32]), None);
        let ids: Vec<u8> = bucket
            .get_nodes()
            .iter()
            .map(|n| n.id.to_bytes()[0])
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    #[test]
    fn test_touch_node_empty_string_preserves_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "1.2.3.4:9000");
        bucket.add_node(node).unwrap();

        // Touch with an empty string should NOT overwrite the valid address
        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), Some(""));
        assert!(found);
        let expected: MultiAddr = "1.2.3.4:9000".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().address, expected);
    }

    #[test]
    fn test_touch_node_missing_returns_false() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket.add_node(make_node(1, "1.1.1.1:9000")).unwrap();

        let found = bucket.touch_node(&PeerId::from_bytes([99u8; 32]), Some("9.9.9.9:9000"));
        assert!(!found);
    }

    // -----------------------------------------------------------------------
    // find_closest_nodes tests — boundary bucket indices
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_zero() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert nodes that land in different buckets.  XOR with [0;32]
        // means the bucket index is the leading-bit position of the node id.
        // Byte 0 = 0x80 → bucket 0, byte 0 = 0x40 → bucket 1, etc.
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 0x80; // bucket 0
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.1:9000".parse().unwrap(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[0] = 0x40; // bucket 1
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.2:9000".parse().unwrap(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        // Search for a key that targets bucket 0
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = 0x80;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        // Verify no duplicates by collecting IDs into a set
        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_255() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Bucket 255 requires the differing bit at position 255 (last bit
        // of last byte).  XOR distance with [0;32] is the id itself, so we
        // need id where only the very last bit is set.
        let mut id_bytes = [0u8; 32];
        id_bytes[31] = 0x01; // bucket 255
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.1:9000".parse().unwrap(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[31] = 0x02; // bucket 254
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.2:9000".parse().unwrap(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_returns_sorted_by_distance() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert 5 nodes at varying distances
        for i in 0..5u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = 0x80 >> i; // buckets 0,1,2,3,4
            table
                .add_node(NodeInfo {
                    id: PeerId::from_bytes(id_bytes),
                    address: format!("10.0.0.{}:9000", i + 1).parse().unwrap(),
                    last_seen: SystemTime::now(),
                    capacity: NodeCapacity::default(),
                })
                .unwrap();
        }

        let key = DhtKey::from_bytes([0u8; 32]);
        let results = table.find_closest_nodes(&key, 3);

        assert_eq!(results.len(), 3);
        // Results should be sorted by XOR distance to key
        for window in results.windows(2) {
            let d0 = xor_distance_bytes(window[0].id.to_bytes(), key.as_bytes());
            let d1 = xor_distance_bytes(window[1].id.to_bytes(), key.as_bytes());
            assert!(d0 <= d1, "Results not sorted by distance");
        }
    }

    #[test]
    fn test_find_closest_nodes_empty_table() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let table = KademliaRoutingTable::new(local_id, 8);

        let key = DhtKey::from_bytes([42u8; 32]);
        let results = table.find_closest_nodes(&key, 8);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // check_diversity loopback gating tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_loopback_rejected_when_allow_loopback_false() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // Default has allow_loopback = false
        assert!(!dht.allow_loopback);

        let loopback_node = make_node(1, "127.0.0.1:9000");
        let result = dht.add_node(loopback_node).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("loopback"),
            "expected loopback rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_loopback_v6_rejected_when_allow_loopback_false() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        assert!(!dht.allow_loopback);

        let loopback_node = make_node(2, "[::1]:9000");
        let result = dht.add_node(loopback_node).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("loopback"),
            "expected loopback rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_loopback_accepted_when_allow_loopback_true() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_allow_loopback(true);

        let loopback_node = make_node(1, "127.0.0.1:9000");
        let result = dht.add_node(loopback_node).await;
        assert!(result.is_ok(), "loopback should be accepted: {:?}", result);
    }

    #[tokio::test]
    async fn test_non_loopback_unaffected_by_allow_loopback_flag() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // allow_loopback = false should not affect normal addresses
        assert!(!dht.allow_loopback);

        let normal_node = make_node(1, "10.0.0.1:9000");
        let result = dht.add_node(normal_node).await;
        assert!(
            result.is_ok(),
            "non-loopback should be accepted: {:?}",
            result
        );
    }
}
