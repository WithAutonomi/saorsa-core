//! DHT Core Engine with Kademlia routing
//!
//! Provides peer discovery and routing via a Kademlia DHT with k=20 buckets,
//! trust-weighted peer selection, and security-hardened maintenance tasks.

use crate::PeerId;
use crate::address::MultiAddr;
use crate::dht::geographic_routing::GeographicRegion;
use crate::security::IPDiversityConfig;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};
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

/// Maximum addresses stored per node to prevent memory exhaustion.
/// A peer can legitimately have several addresses (multi-homed, NAT traversal),
/// but unbounded lists would be an abuse vector.
const MAX_ADDRESSES_PER_NODE: usize = 8;

/// Node information for routing.
///
/// The `addresses` field stores one or more typed [`MultiAddr`] values that are
/// always valid. Serializes each as a canonical `/`-delimited string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: PeerId,
    pub addresses: Vec<MultiAddr>,
    pub last_seen: SystemTime,
}

impl NodeInfo {
    /// Get the socket address from the first address. Returns `None` for
    /// non-IP transports or when no addresses are stored.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addresses.first().and_then(MultiAddr::socket_addr)
    }

    /// Get the IP address from the first address. Returns `None` for
    /// non-IP transports or when no addresses are stored.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.addresses.first().and_then(MultiAddr::ip)
    }

    /// Merge a new address into this node's address list.
    ///
    /// If the address is already present it is moved to the front (most
    /// recently seen). New addresses are prepended. The list is capped at
    /// [`MAX_ADDRESSES_PER_NODE`].
    pub fn merge_address(&mut self, addr: MultiAddr) {
        // Remove existing duplicate so the re-insert moves it to the front.
        self.addresses.retain(|a| a != &addr);
        self.addresses.insert(0, addr);
        self.addresses.truncate(MAX_ADDRESSES_PER_NODE);
    }
}

/// Result of attempting to add a node to a full k-bucket.
enum BucketInsertResult {
    /// Node was inserted (bucket had space or node was already present).
    Inserted,
    /// Bucket is full. Contains the ID of the least-recently-seen node
    /// that should be pinged. If it is unresponsive, call `evict_and_insert`
    /// to replace it with the pending node.
    BucketFull {
        /// The least-recently-seen node in the bucket.
        lrs_node_id: PeerId,
        /// The node that wants to be inserted.
        pending_node: NodeInfo,
    },
}

/// Maximum size of the replacement cache per bucket.
/// Nodes that could not be inserted because the bucket is full
/// are held here until an eviction creates a vacancy.
const REPLACEMENT_CACHE_SIZE: usize = 5;

/// K-bucket for Kademlia routing
struct KBucket {
    nodes: Vec<NodeInfo>,
    max_size: usize,
    /// Replacement cache: nodes that could not be inserted because the
    /// bucket was full. When a node is evicted, the most recently seen
    /// replacement is promoted. Standard Kademlia mechanism.
    replacement_cache: Vec<NodeInfo>,
    /// Timestamp of the last lookup that touched this bucket.
    /// Used for periodic refresh: buckets not looked up recently
    /// need a random-ID lookup to stay populated.
    last_lookup: Instant,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_size,
            replacement_cache: Vec::new(),
            last_lookup: Instant::now(),
        }
    }

    fn add_node(&mut self, mut node: NodeInfo) -> Result<BucketInsertResult> {
        // Reject nodes with no addresses — a node without reachable
        // addresses is useless in the routing table and would waste a slot.
        if node.addresses.is_empty() {
            return Err(anyhow!("NodeInfo has no addresses"));
        }

        // Cap addresses to prevent memory exhaustion from oversized lists
        // arriving via deserialization or direct construction.
        node.addresses.truncate(MAX_ADDRESSES_PER_NODE);

        // If the node is already in this bucket, replace it fully and move to
        // tail (most-recently-seen) per standard Kademlia protocol.
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push(node);
            return Ok(BucketInsertResult::Inserted);
        }

        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
            Ok(BucketInsertResult::Inserted)
        } else {
            // Bucket is full. Per Kademlia: the caller should ping the
            // least-recently-seen node (head of list). If it responds,
            // move it to tail and discard the new node. If it doesn't
            // respond, evict it and insert the new node.
            let lrs_id = self
                .nodes
                .first()
                .map(|n| n.id)
                .ok_or_else(|| anyhow!("K-bucket empty but at capacity"))?;

            Ok(BucketInsertResult::BucketFull {
                lrs_node_id: lrs_id,
                pending_node: node,
            })
        }
    }

    /// Evict a specific node and insert a replacement.
    /// Called after the least-recently-seen node fails to respond to a ping.
    fn evict_and_insert(&mut self, evict_id: &PeerId, new_node: NodeInfo) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == evict_id) {
            self.nodes.remove(pos);
            self.nodes.push(new_node);
            true
        } else {
            false
        }
    }

    /// Add a node to the replacement cache. If full, the oldest entry
    /// is dropped (FIFO). Used when a node cannot be inserted because
    /// the bucket is full and the LRS node responded to a ping.
    fn add_to_replacement_cache(&mut self, node: NodeInfo) {
        // Don't duplicate
        if self.replacement_cache.iter().any(|n| n.id == node.id) {
            return;
        }
        if self.replacement_cache.len() >= REPLACEMENT_CACHE_SIZE {
            self.replacement_cache.remove(0);
        }
        self.replacement_cache.push(node);
    }

    /// Promote the most recently seen replacement into the main bucket.
    /// Called when a node is removed from the bucket for any reason.
    fn promote_replacement(&mut self) -> bool {
        if self.nodes.len() < self.max_size {
            if let Some(replacement) = self.replacement_cache.pop() {
                self.nodes.push(replacement);
                return true;
            }
        }
        false
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        self.nodes.retain(|n| &n.id != node_id);
    }

    /// Update `last_seen` (and optionally merge an address) for a node, then
    /// move it to the tail of the bucket (most recently seen) per Kademlia
    /// protocol.
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) {
            self.nodes[pos].last_seen = SystemTime::now();
            if let Some(addr) = address {
                self.nodes[pos].merge_address(addr.clone());
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

    fn add_node(&mut self, node: NodeInfo) -> Result<BucketInsertResult> {
        let bucket_index = self.get_bucket_index(&node.id);
        self.buckets[bucket_index].add_node(node)
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].remove_node(node_id);
        // Promote a replacement from the cache if one exists
        self.buckets[bucket_index].promote_replacement();
    }

    /// Evict a node from the routing table and insert a new one in its place.
    fn evict_and_insert(&mut self, evict_id: &PeerId, new_node: NodeInfo) -> bool {
        let bucket_index = self.get_bucket_index(evict_id);
        self.buckets[bucket_index].evict_and_insert(evict_id, new_node)
    }

    /// Add a node to the replacement cache of the appropriate bucket.
    fn add_to_replacement_cache(&mut self, node: NodeInfo) {
        let bucket_index = self.get_bucket_index(&node.id);
        self.buckets[bucket_index].add_to_replacement_cache(node);
    }

    /// Update `last_seen` (and optionally merge an address) for a node and
    /// move it to the tail of its k-bucket. Returns `true` if the node was found.
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].touch_node(node_id, address)
    }

    fn find_closest_nodes(&mut self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        // Mark the target bucket as recently looked up for refresh scheduling
        let target_bucket = self.get_bucket_index_for_key(key);
        self.mark_bucket_lookup(target_bucket);

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

    /// Mark a bucket as recently looked up (for refresh scheduling).
    fn mark_bucket_lookup(&mut self, bucket_index: usize) {
        if let Some(bucket) = self.buckets.get_mut(bucket_index) {
            bucket.last_lookup = Instant::now();
        }
    }

    /// Return indices of buckets that haven't been looked up within `max_age`
    /// and have at least one node (empty buckets don't need refresh).
    fn stale_bucket_indices(&self, max_age: std::time::Duration) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.nodes.is_empty() && b.last_lookup.elapsed() > max_age)
            .map(|(i, _)| i)
            .collect()
    }

    /// Generate a random key that falls in the given bucket's range.
    /// Used for bucket refresh: perform a find_node with this key to
    /// discover peers in that distance range.
    fn random_key_in_bucket(&self, bucket_index: usize) -> DhtKey {
        let mut key_bytes = *self.node_id.to_bytes();
        // Flip the bit at `bucket_index` to ensure the key is in the bucket's range
        let byte_idx = bucket_index / 8;
        let bit_idx = 7 - (bucket_index % 8);
        key_bytes[byte_idx] ^= 1 << bit_idx;
        // Randomize remaining bits (after the prefix) for diversity
        for byte in key_bytes.iter_mut().skip(byte_idx + 1) {
            *byte = rand::random();
        }
        DhtKey::from_bytes(key_bytes)
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

/// Apply optional floor/ceiling overrides to a computed subnet limit.
/// Floor is applied first (raising the value), then ceiling (lowering it).
/// When both are set, ceiling wins if floor > ceiling.
fn clamp_limit(limit: usize, floor: Option<usize>, ceiling: Option<usize>) -> usize {
    let mut result = limit;
    if let Some(f) = floor {
        result = result.max(f);
    }
    if let Some(c) = ceiling {
        result = result.min(c);
    }
    result
}

/// Default maximum nodes per geographic region. Matches
/// `GeographicRoutingConfig::max_nodes_per_region` default.
const GEO_DEFAULT_MAX_PER_REGION: usize = 50;

/// K parameter — number of closest nodes per bucket.
///
/// Standard Kademlia (Maymounkov & Mazieres, 2002) and libp2p both use K=20.
/// Higher K improves routing table completeness and lookup convergence at the
/// cost of slightly more memory per bucket.
const K: usize = 20;

/// Number of K-buckets in Kademlia routing table (one per bit in 256-bit key space)
const KADEMLIA_BUCKET_COUNT: usize = 256;

/// Candidate expansion factor for find_closest_nodes optimization
/// Collect 2x requested count before early exit to ensure good selection
const CANDIDATE_EXPANSION_FACTOR: usize = 2;

/// Subnet diversity multiplier: /24 (IPv4) or /64 (IPv6) limit = per-IP * this.
const SUBNET_NARROW_MULTIPLIER: usize = 3;

/// Subnet diversity multiplier: /16 (IPv4) or /48 (IPv6) limit = per-IP * this.
const SUBNET_MEDIUM_MULTIPLIER: usize = 10;

/// Subnet diversity multiplier for IPv6 /32 (widest prefix tier).
const SUBNET_WIDE_MULTIPLIER: usize = 30;

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: PeerId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,

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

    /// Shutdown token for background maintenance tasks
    shutdown: CancellationToken,
}

impl DhtCoreEngine {
    /// Create new DHT engine for testing
    #[cfg(test)]
    pub fn new_for_tests(node_id: PeerId) -> Result<Self> {
        Self::new(node_id, false)
    }

    /// Create a new DHT core engine.
    pub(crate) fn new(node_id: PeerId, allow_loopback: bool) -> Result<Self> {
        Ok(Self {
            node_id,
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, K))),
            ip_diversity_config: IPDiversityConfig::default(),
            allow_loopback,
            geo_max_per_region: GEO_DEFAULT_MAX_PER_REGION,
            shutdown: CancellationToken::new(),
        })
    }

    /// Override the IP diversity configuration.
    pub fn set_ip_diversity_config(&mut self, config: IPDiversityConfig) {
        self.ip_diversity_config = config;
    }

    /// Set whether loopback addresses are allowed in the routing table.
    #[cfg(test)]
    pub fn set_allow_loopback(&mut self, allow: bool) {
        self.allow_loopback = allow;
    }

    /// Number of peers currently in the routing table.
    pub async fn routing_table_size(&self) -> usize {
        self.routing_table.read().await.node_count()
    }

    /// Remove a peer from the routing table by ID.
    pub async fn remove_node_by_id(&mut self, peer_id: &PeerId) {
        self.routing_table.write().await.remove_node(peer_id);
    }

    /// Signal background tasks to stop
    pub fn signal_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let mut routing = self.routing_table.write().await;
        Ok(routing.find_closest_nodes(key, count))
    }

    /// Look up a node's addresses from the routing table by peer ID.
    ///
    /// Returns the stored addresses if the peer is in the routing table,
    /// an empty vec otherwise. O(K) scan of the target k-bucket.
    pub async fn get_node_addresses(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        let routing = self.routing_table.read().await;
        routing
            .find_node_by_id(peer_id)
            .map(|n| n.addresses.clone())
            .unwrap_or_default()
    }

    /// Check whether a peer is present in the routing table.
    pub async fn has_node(&self, peer_id: &PeerId) -> bool {
        let routing = self.routing_table.read().await;
        routing.find_node_by_id(peer_id).is_some()
    }

    /// Record a successful interaction with a peer by updating its `last_seen`
    /// timestamp (and optionally its address) and moving it to the tail of its
    /// k-bucket (most recently seen).
    ///
    /// Standard Kademlia: any successful RPC implicitly proves liveness, so the
    /// routing table should reflect this without requiring dedicated pings.
    /// Passing the current address ensures stale addresses are replaced when a
    /// peer reconnects from a different endpoint.
    pub async fn touch_node(&self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address)
    }

    /// Add a node to the DHT with security checks.
    ///
    /// Diversity limits (IP subnet and geographic region) are derived from the
    /// live routing table contents on every call, so counts are always accurate
    /// regardless of evictions, reconnections, or address changes.
    /// Add a node to the DHT routing table with diversity checks.
    ///
    /// Returns `Ok(None)` if the node was inserted successfully, or
    /// `Ok(Some((lrs_id, pending_node)))` if the target bucket is full.
    /// In the latter case, the caller should ping `lrs_id` and either:
    /// - Call `evict_and_insert(lrs_id, pending_node)` if it is unresponsive
    /// - Call `add_to_replacement_cache(pending_node)` if it responds (alive)
    pub async fn add_node(
        &mut self,
        node: NodeInfo,
    ) -> Result<Option<(PeerId, NodeInfo)>> {
        // IP-based transports always have an IP; non-IP transports skip diversity.
        let candidate_ip = match node.ip() {
            Some(ip) => ip,
            None => {
                // Non-IP transports (Bluetooth, LoRa, etc.) bypass IP diversity.
                let mut routing = self.routing_table.write().await;
                return match routing.add_node(node)? {
                    BucketInsertResult::Inserted => Ok(None),
                    BucketInsertResult::BucketFull {
                        lrs_node_id,
                        pending_node,
                    } => Ok(Some((lrs_node_id, pending_node))),
                };
            }
        };

        // Security Check: IP + Geographic Diversity
        //
        // Counts are derived from the routing table in a single pass.
        // Nodes already present (reconnecting with the same ID) are
        // excluded from the count so they can update their address
        // without inflating limits.
        //
        // Single write lock for both the diversity check and the insertion
        // to avoid a TOCTOU race.
        let mut routing = self.routing_table.write().await;
        self.check_diversity(&routing, &node.id, candidate_ip)?;

        match routing.add_node(node)? {
            BucketInsertResult::Inserted => Ok(None),
            BucketInsertResult::BucketFull {
                lrs_node_id,
                pending_node,
            } => Ok(Some((lrs_node_id, pending_node))),
        }
    }

    /// Evict a node from the routing table and insert a new one.
    /// Called after a ping to the least-recently-seen node fails.
    pub async fn evict_and_insert(&self, evict_id: &PeerId, new_node: NodeInfo) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.evict_and_insert(evict_id, new_node)
    }

    /// Add a node to the replacement cache of the appropriate bucket.
    /// Called when the least-recently-seen node in a full bucket is alive.
    pub async fn add_to_replacement_cache(&self, node: NodeInfo) {
        let mut routing = self.routing_table.write().await;
        routing.add_to_replacement_cache(node);
    }

    /// Return bucket indices that haven't been looked up within `max_age`.
    /// Used by the periodic refresh task to determine which buckets need
    /// a random-key lookup.
    pub async fn stale_bucket_indices(&self, max_age: std::time::Duration) -> Vec<usize> {
        let routing = self.routing_table.read().await;
        routing.stale_bucket_indices(max_age)
    }

    /// Generate a random key in the given bucket's range and mark the
    /// bucket as recently looked up.
    pub async fn random_key_for_bucket_refresh(&self, bucket_index: usize) -> DhtKey {
        let mut routing = self.routing_table.write().await;
        routing.mark_bucket_lookup(bucket_index);
        routing.random_key_in_bucket(bucket_index)
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
            let Some(existing_ip) = node.ip() else {
                // Non-IP transports don't participate in IP diversity counting.
                continue;
            };
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
                let limit_32 = clamp_limit(
                    cfg.max_nodes_per_ipv4_32
                        .map_or(per_ip, |cap| cap.min(per_ip)),
                    cfg.ipv4_limit_floor,
                    cfg.ipv4_limit_ceiling,
                );
                let limit_24 = clamp_limit(
                    cfg.max_nodes_per_ipv4_24
                        .map_or(per_ip * SUBNET_NARROW_MULTIPLIER, |cap| {
                            cap.min(per_ip * SUBNET_NARROW_MULTIPLIER)
                        }),
                    cfg.ipv4_limit_floor,
                    cfg.ipv4_limit_ceiling,
                );
                let limit_16 = clamp_limit(
                    cfg.max_nodes_per_ipv4_16
                        .map_or(per_ip * SUBNET_MEDIUM_MULTIPLIER, |cap| {
                            cap.min(per_ip * SUBNET_MEDIUM_MULTIPLIER)
                        }),
                    cfg.ipv4_limit_floor,
                    cfg.ipv4_limit_ceiling,
                );

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
                let limit_64 = clamp_limit(
                    std::cmp::min(cfg.max_nodes_per_ipv6_64, per_ip * SUBNET_NARROW_MULTIPLIER),
                    cfg.ipv6_limit_floor,
                    cfg.ipv6_limit_ceiling,
                );
                let limit_48 = clamp_limit(
                    std::cmp::min(cfg.max_nodes_per_ipv6_48, per_ip * SUBNET_MEDIUM_MULTIPLIER),
                    cfg.ipv6_limit_floor,
                    cfg.ipv6_limit_ceiling,
                );
                let limit_32 = clamp_limit(
                    std::cmp::min(cfg.max_nodes_per_ipv6_32, per_ip * SUBNET_WIDE_MULTIPLIER),
                    cfg.ipv6_limit_floor,
                    cfg.ipv6_limit_ceiling,
                );

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
            addresses: vec![address.parse::<MultiAddr>().unwrap()],
            last_seen: SystemTime::now(),
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::touch_node tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_touch_node_merges_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        // Touch with a new address — should be prepended, old kept
        let new_addr: MultiAddr = "/ip4/5.6.7.8/udp/9000/quic".parse().unwrap();
        let old_addr: MultiAddr = "/ip4/1.2.3.4/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), Some(&new_addr));
        assert!(found);
        let addrs = &bucket.get_nodes().last().unwrap().addresses;
        assert_eq!(addrs[0], new_addr);
        assert_eq!(addrs[1], old_addr);
    }

    #[test]
    fn test_touch_node_none_preserves_addresses() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), None);
        assert!(found);
        let expected: MultiAddr = "/ip4/1.2.3.4/udp/9000/quic".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().addresses, vec![expected]);
    }

    #[test]
    fn test_touch_node_moves_to_tail() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(2, "/ip4/2.2.2.2/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(3, "/ip4/3.3.3.3/udp/9000/quic"))
            .unwrap();

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
    fn test_touch_node_missing_returns_false() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let new_addr: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node(&PeerId::from_bytes([99u8; 32]), Some(&new_addr));
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
                addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
                last_seen: SystemTime::now(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[0] = 0x40; // bucket 1
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
                last_seen: SystemTime::now(),
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
                addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
                last_seen: SystemTime::now(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[31] = 0x02; // bucket 254
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
                last_seen: SystemTime::now(),
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
                    addresses: vec![
                        format!("/ip4/10.0.0.{}/udp/9000/quic", i + 1)
                            .parse()
                            .unwrap(),
                    ],
                    last_seen: SystemTime::now(),
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
        let mut table = KademliaRoutingTable::new(local_id, 8);

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

        let loopback_node = make_node(1, "/ip4/127.0.0.1/udp/9000/quic");
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

        let loopback_node = make_node(2, "/ip6/::1/udp/9000/quic");
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

        let loopback_node = make_node(1, "/ip4/127.0.0.1/udp/9000/quic");
        let result = dht.add_node(loopback_node).await;
        assert!(result.is_ok(), "loopback should be accepted: {:?}", result);
    }

    #[tokio::test]
    async fn test_non_loopback_unaffected_by_allow_loopback_flag() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // allow_loopback = false should not affect normal addresses
        assert!(!dht.allow_loopback);

        let normal_node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let result = dht.add_node(normal_node).await;
        assert!(
            result.is_ok(),
            "non-loopback should be accepted: {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // IPv4 diversity: static floor overrides low dynamic limit
    // -----------------------------------------------------------------------

    /// When the network is small the dynamic per-IP formula yields 1, which
    /// would block additional same-IP nodes.  A configured `ipv4_limit_floor`
    /// must override the dynamic value so that bootstrap can proceed.
    #[tokio::test]
    async fn test_ipv4_static_floor_overrides_dynamic_limit() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Testnet-like config: floor of 100 guarantees at least that many
        // nodes per subnet regardless of how small the network is.
        let mut config = IPDiversityConfig::testnet();
        config.ipv4_limit_floor = Some(100);
        dht.set_ip_diversity_config(config);

        // Add multiple nodes from the same IP — the dynamic formula alone
        // would cap at 1, but the floor of 100 must allow these.
        for i in 1..=10u8 {
            let node = make_node(i, "/ip4/203.0.113.1/udp/9000/quic");
            let result = dht.add_node(node).await;
            assert!(
                result.is_ok(),
                "node {i} from same IP should be accepted with floor override: {:?}",
                result
            );
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::add_node address validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_node_rejects_empty_addresses() {
        let mut bucket = KBucket::new(8);
        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            last_seen: SystemTime::now(),
        };
        assert!(bucket.add_node(node).is_err());
    }

    #[test]
    fn test_add_node_truncates_excess_addresses() {
        let mut bucket = KBucket::new(8);

        // Build a NodeInfo with more addresses than the cap.
        let addresses: Vec<MultiAddr> = (1..=MAX_ADDRESSES_PER_NODE + 4)
            .map(|i| format!("/ip4/10.0.0.{}/udp/9000/quic", i).parse().unwrap())
            .collect();
        assert!(addresses.len() > MAX_ADDRESSES_PER_NODE);

        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses,
            last_seen: SystemTime::now(),
        };
        bucket.add_node(node).unwrap();

        let stored = &bucket.get_nodes()[0].addresses;
        assert_eq!(stored.len(), MAX_ADDRESSES_PER_NODE);
    }

    #[test]
    fn test_add_node_replace_also_truncates() {
        let mut bucket = KBucket::new(8);

        // Insert once with a single address.
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        assert_eq!(bucket.get_nodes()[0].addresses.len(), 1);

        // Replace with an oversized address list.
        let addresses: Vec<MultiAddr> = (1..=MAX_ADDRESSES_PER_NODE + 4)
            .map(|i| format!("/ip4/10.0.0.{}/udp/9000/quic", i).parse().unwrap())
            .collect();
        let replacement = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses,
            last_seen: SystemTime::now(),
        };
        bucket.add_node(replacement).unwrap();

        let stored = &bucket.get_nodes().last().unwrap().addresses;
        assert_eq!(stored.len(), MAX_ADDRESSES_PER_NODE);
    }
}
