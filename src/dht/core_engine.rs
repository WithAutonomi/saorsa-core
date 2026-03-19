//! DHT Core Engine with Kademlia routing
//!
//! Provides peer discovery and routing via a Kademlia DHT with k=8 buckets,
//! trust-weighted peer selection, and security-hardened maintenance tasks.

use crate::PeerId;
use crate::address::MultiAddr;
use crate::dht::geographic_routing::GeographicRegion;
use crate::security::IPDiversityConfig;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;
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
/// Serializes as a canonical `/`-delimited string via `serde_as_string`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: PeerId,
    #[serde(with = "crate::address::serde_as_string")]
    pub address: MultiAddr,
    pub last_seen: SystemTime,
    pub capacity: NodeCapacity,
}

impl NodeInfo {
    /// Get the socket address. Returns `None` for non-IP transports.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address.socket_addr()
    }

    /// Get the IP address. Returns `None` for non-IP transports.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
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
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) {
            self.nodes[pos].last_seen = SystemTime::now();
            if let Some(addr) = address {
                self.nodes[pos].address = addr.clone();
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

    /// Count nodes in this bucket that belong to `region`, excluding a specific
    /// peer (to avoid a reconnecting node blocking itself) and loopback nodes.
    fn count_region(&self, region: GeographicRegion, exclude_id: &PeerId) -> usize {
        self.nodes
            .iter()
            .filter(|n| n.id != *exclude_id)
            .filter(|n| {
                n.ip()
                    .is_some_and(|ip| !ip.is_loopback() && GeographicRegion::from_ip(ip) == region)
            })
            .count()
    }

    /// Find the same-region node in this bucket that is farthest from `our_node_id`
    /// by XOR distance. Used by swap logic to identify the eviction candidate.
    /// Excludes `exclude_id` (the candidate itself, for reconnection) and loopback nodes.
    fn farthest_same_region_node(
        &self,
        region: GeographicRegion,
        our_node_id: &PeerId,
        exclude_id: &PeerId,
    ) -> Option<(PeerId, [u8; 32])> {
        self.nodes
            .iter()
            .filter(|n| n.id != *exclude_id)
            .filter(|n| {
                n.ip()
                    .is_some_and(|ip| !ip.is_loopback() && GeographicRegion::from_ip(ip) == region)
            })
            .map(|n| {
                let dist = xor_distance_bytes(n.id.to_bytes(), our_node_id.to_bytes());
                (n.id, dist)
            })
            .max_by(|a, b| a.1.cmp(&b.1))
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
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
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

    /// Return the K nodes closest to `self.node_id` by XOR distance, sorted
    /// nearest-first. May span multiple buckets. Used for closest-K geo check.
    fn closest_k_nodes_to_self(&self) -> Vec<(PeerId, [u8; 32])> {
        let mut all: Vec<(PeerId, [u8; 32])> = self
            .iter_nodes()
            .map(|n| {
                let dist = xor_distance_bytes(n.id.to_bytes(), self.node_id.to_bytes());
                (n.id, dist)
            })
            .collect();
        all.sort_by(|a, b| a.1.cmp(&b.1));
        all.truncate(K);
        all
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

/// Default maximum nodes per geographic region (per-bucket and closest-K).
const GEO_DEFAULT_MAX_PER_REGION: usize = 3;

/// K parameter - number of closest nodes per bucket
const K: usize = 8;

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

/// Result of a per-bucket or closest-K geographic diversity check.
enum GeoCheckResult {
    /// Candidate is allowed (under the limit).
    Allowed,
    /// Candidate is closer than an existing same-region peer; evict that peer.
    SwapNeeded { evict_peer_id: PeerId },
    /// Candidate is rejected (at limit and not closer than any incumbent).
    Rejected { reason: String },
}

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

    /// Override the per-bucket / closest-K geographic region limit.
    #[cfg(test)]
    pub fn set_geo_max_per_region(&mut self, max: usize) {
        self.geo_max_per_region = max;
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
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes(key, count))
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
    pub async fn touch_node(&self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address)
    }

    /// Add a node to the DHT with security checks.
    ///
    /// Diversity limits (IP subnet and geographic region) are derived from the
    /// live routing table contents on every call, so counts are always accurate
    /// regardless of evictions, reconnections, or address changes.
    ///
    /// Geographic diversity is enforced per-bucket and across the K closest
    /// nodes to self. When a region is at its per-scope limit, a closer
    /// candidate can swap out the farthest same-region incumbent (1-for-1).
    pub async fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // IP-based transports always have an IP; non-IP transports skip diversity.
        let candidate_ip = match node.ip() {
            Some(ip) => ip,
            None => {
                // Non-IP transports (Bluetooth, LoRa, etc.) bypass IP diversity.
                let mut routing = self.routing_table.write().await;
                routing.add_node(node)?;
                return Ok(());
            }
        };

        // Single write lock for diversity check + insertion (avoids TOCTOU).
        let mut routing = self.routing_table.write().await;

        // IP subnet diversity (loopback gating handled inside).
        self.check_diversity(&routing, &node.id, candidate_ip)?;

        // Geographic diversity — skipped for loopback nodes.
        if !(self.allow_loopback && candidate_ip.is_loopback()) {
            let candidate_region = GeographicRegion::from_ip(candidate_ip);

            // Per-bucket check (cheaper: scans at most K=8 nodes).
            let bucket_result =
                self.check_geo_diversity_per_bucket(&routing, &node, candidate_region);

            if let GeoCheckResult::Rejected { reason } = &bucket_result {
                return Err(anyhow!("{reason}"));
            }

            // Closest-K check (scans all nodes, but only when bucket passed).
            let closest_k_result =
                self.check_geo_diversity_closest_k(&routing, &node, candidate_region);

            if let GeoCheckResult::Rejected { reason } = &closest_k_result {
                return Err(anyhow!("{reason}"));
            }

            // Collect eviction set (dedup if both target the same peer).
            let mut evictions: Vec<PeerId> = Vec::new();
            if let GeoCheckResult::SwapNeeded { evict_peer_id } = bucket_result {
                evictions.push(evict_peer_id);
            }
            if let GeoCheckResult::SwapNeeded { evict_peer_id } = closest_k_result
                && !evictions.contains(&evict_peer_id)
            {
                evictions.push(evict_peer_id);
            }

            for peer_id in &evictions {
                routing.remove_node(peer_id);
            }
        }

        routing.add_node(node)?;
        Ok(())
    }

    /// Check IP subnet diversity against the live routing table.
    ///
    /// Single pass over all nodes — each node's address is parsed once.
    /// `candidate_id` is excluded from counting so that a reconnecting node
    /// doesn't block itself.  Loopback candidates are only accepted when
    /// `self.allow_loopback` is `true`; otherwise they are
    /// rejected outright.  Existing loopback nodes in the table are always
    /// excluded from `network_size` and subnet counts so they don't
    /// inflate the dynamic per-IP limit in devnet environments.
    ///
    /// Geographic diversity is handled separately by per-bucket and closest-K
    /// checks in `add_node`.
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

    /// Per-bucket geographic diversity check.
    ///
    /// If the candidate's bucket already has `geo_max_per_region` nodes from
    /// the same region, the candidate can only enter if it is strictly closer
    /// to self than the farthest same-region incumbent (swap logic).
    fn check_geo_diversity_per_bucket(
        &self,
        routing: &KademliaRoutingTable,
        candidate: &NodeInfo,
        candidate_region: GeographicRegion,
    ) -> GeoCheckResult {
        let bucket_index = routing.get_bucket_index(&candidate.id);
        let bucket = &routing.buckets[bucket_index];
        let count = bucket.count_region(candidate_region, &candidate.id);

        if count < self.geo_max_per_region {
            return GeoCheckResult::Allowed;
        }

        // At limit — swap if candidate is closer than the farthest incumbent.
        let candidate_dist = xor_distance_bytes(candidate.id.to_bytes(), self.node_id.to_bytes());
        if let Some((farthest_id, farthest_dist)) =
            bucket.farthest_same_region_node(candidate_region, &self.node_id, &candidate.id)
            && candidate_dist < farthest_dist
        {
            return GeoCheckResult::SwapNeeded {
                evict_peer_id: farthest_id,
            };
        }

        GeoCheckResult::Rejected {
            reason: format!(
                "Geographic diversity: region {candidate_region:?} per-bucket limit ({}) exceeded in bucket {bucket_index}",
                self.geo_max_per_region
            ),
        }
    }

    /// Closest-K geographic diversity check.
    ///
    /// Considers only the K nodes closest to self by XOR distance. If the
    /// candidate would be part of that group and would push a region over the
    /// limit, it can swap out the farthest same-region node in the group.
    /// Candidates that would NOT be in the closest-K group bypass this check.
    fn check_geo_diversity_closest_k(
        &self,
        routing: &KademliaRoutingTable,
        candidate: &NodeInfo,
        candidate_region: GeographicRegion,
    ) -> GeoCheckResult {
        let closest_k = routing.closest_k_nodes_to_self();
        let candidate_dist = xor_distance_bytes(candidate.id.to_bytes(), self.node_id.to_bytes());

        // Would candidate be in the closest-K group?
        let would_be_in_k = if closest_k.len() < K {
            true
        } else {
            // Must be strictly closer than the current K-th node.
            closest_k
                .last()
                .is_none_or(|&(_, kth_dist)| candidate_dist < kth_dist)
        };

        if !would_be_in_k {
            return GeoCheckResult::Allowed;
        }

        // Build hypothetical closest-K including the candidate.
        let mut hypothetical = closest_k;
        hypothetical.push((candidate.id, candidate_dist));
        hypothetical.sort_by(|a, b| a.1.cmp(&b.1));
        hypothetical.truncate(K);

        // Count same-region nodes in the hypothetical group (excluding candidate).
        let region_count = hypothetical
            .iter()
            .filter(|(id, _)| *id != candidate.id)
            .filter(|&&(id, _)| {
                routing
                    .find_node_by_id(&id)
                    .and_then(|n| n.ip())
                    .is_some_and(|ip| {
                        !ip.is_loopback() && GeographicRegion::from_ip(ip) == candidate_region
                    })
            })
            .count();

        if region_count < self.geo_max_per_region {
            return GeoCheckResult::Allowed;
        }

        // Find farthest same-region node in the hypothetical group (excl. candidate).
        if let Some(&(farthest_id, farthest_dist)) = hypothetical
            .iter()
            .filter(|(id, _)| *id != candidate.id)
            .filter(|&&(id, _)| {
                routing
                    .find_node_by_id(&id)
                    .and_then(|n| n.ip())
                    .is_some_and(|ip| {
                        !ip.is_loopback() && GeographicRegion::from_ip(ip) == candidate_region
                    })
            })
            .max_by(|a, b| a.1.cmp(&b.1))
            && candidate_dist < farthest_dist
        {
            return GeoCheckResult::SwapNeeded {
                evict_peer_id: farthest_id,
            };
        }

        GeoCheckResult::Rejected {
            reason: format!(
                "Geographic diversity: region {candidate_region:?} closest-K limit ({}) exceeded",
                self.geo_max_per_region
            ),
        }
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
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        // Touch with a new address
        let new_addr: MultiAddr = "/ip4/5.6.7.8/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), Some(&new_addr));
        assert!(found);
        assert_eq!(bucket.get_nodes().last().unwrap().address, new_addr);
    }

    #[test]
    fn test_touch_node_none_preserves_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), None);
        assert!(found);
        let expected: MultiAddr = "/ip4/1.2.3.4/udp/9000/quic".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().address, expected);
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
                address: "/ip4/10.0.0.1/udp/9000/quic".parse().unwrap(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[0] = 0x40; // bucket 1
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "/ip4/10.0.0.2/udp/9000/quic".parse().unwrap(),
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
                address: "/ip4/10.0.0.1/udp/9000/quic".parse().unwrap(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[31] = 0x02; // bucket 254
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "/ip4/10.0.0.2/udp/9000/quic".parse().unwrap(),
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
                    address: format!("/ip4/10.0.0.{}/udp/9000/quic", i + 1)
                        .parse()
                        .unwrap(),
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
        // Raise geo limit so this IP-diversity test isn't affected by per-bucket geo.
        dht.set_geo_max_per_region(100);

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
    // Per-bucket geographic diversity tests
    // -----------------------------------------------------------------------

    /// Helper: create a NodeInfo with specific id bytes and address string.
    fn make_node_with_id(id_bytes: [u8; 32], address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes(id_bytes),
            address: address.parse::<MultiAddr>().unwrap(),
            last_seen: SystemTime::now(),
            capacity: NodeCapacity::default(),
        }
    }

    /// Build a PeerId that lands in bucket 0 when node_id is [0;32].
    /// `variant` is OR'd into byte[0] alongside the 0x80 bucket-0 marker.
    fn bucket0_id(variant: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 0x80 | variant;
        id
    }

    /// 3 same-region nodes in one bucket OK, 4th rejected (farther than all).
    #[tokio::test]
    async fn test_per_bucket_geo_limit_blocks_excess() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_ip_diversity_config(IPDiversityConfig {
            ipv4_limit_floor: Some(100),
            ..IPDiversityConfig::default()
        });

        // 3 Europe nodes in bucket 0 (distinct /16 subnets)
        for i in 1..=3u8 {
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 129 + i);
            dht.add_node(make_node_with_id(bucket0_id(i), &addr))
                .await
                .unwrap();
        }

        // 4th Europe node in bucket 0 — farther than all (0x84 > 0x83) → rejected
        let node = make_node_with_id(bucket0_id(4), "/ip4/134.1.1.1/udp/9000/quic");
        let result = dht.add_node(node).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("per-bucket limit"),
            "should be rejected by per-bucket geo check"
        );
    }

    /// 3 same-region in bucket A, 1 same-region in bucket B succeeds.
    #[tokio::test]
    async fn test_per_bucket_geo_allows_across_buckets() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_ip_diversity_config(IPDiversityConfig {
            ipv4_limit_floor: Some(100),
            ..IPDiversityConfig::default()
        });

        // 3 Europe nodes in bucket 0
        for i in 1..=3u8 {
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 129 + i);
            dht.add_node(make_node_with_id(bucket0_id(i), &addr))
                .await
                .unwrap();
        }

        // 1 Europe node in bucket 1 (byte[0]=0x40) — different bucket → per-bucket OK
        let mut id = [0u8; 32];
        id[0] = 0x40;
        let result = dht
            .add_node(make_node_with_id(id, "/ip4/133.1.1.1/udp/9000/quic"))
            .await;
        assert!(
            result.is_ok(),
            "Europe node in different bucket should succeed: {:?}",
            result
        );
    }

    /// 4th same-region node closer to self swaps out farthest in bucket.
    #[tokio::test]
    async fn test_per_bucket_swap_closer_replaces_farther() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_ip_diversity_config(IPDiversityConfig {
            ipv4_limit_floor: Some(100),
            ..IPDiversityConfig::default()
        });

        let eviction_target = PeerId::from_bytes(bucket0_id(3));

        // 3 Europe nodes in bucket 0: IDs 0x81, 0x82, 0x83 (farthest = 0x83)
        for i in 1..=3u8 {
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 129 + i);
            dht.add_node(make_node_with_id(bucket0_id(i), &addr))
                .await
                .unwrap();
        }

        // 4th: id 0x80 — closest to self in bucket 0 → swaps out 0x83
        let closer_id = bucket0_id(0);
        let result = dht
            .add_node(make_node_with_id(closer_id, "/ip4/133.1.1.1/udp/9000/quic"))
            .await;
        assert!(result.is_ok(), "closer node should swap in: {:?}", result);

        assert!(
            dht.get_node_address(&eviction_target).await.is_none(),
            "farthest Europe node should have been evicted"
        );
        assert!(
            dht.get_node_address(&PeerId::from_bytes(closer_id))
                .await
                .is_some(),
            "closer Europe node should be in table"
        );
    }

    /// 4th same-region node farther than all → rejected (no swap possible).
    #[tokio::test]
    async fn test_per_bucket_swap_rejected_when_farther() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_ip_diversity_config(IPDiversityConfig {
            ipv4_limit_floor: Some(100),
            ..IPDiversityConfig::default()
        });

        // 3 Europe nodes in bucket 0: IDs 0x81, 0x82, 0x83
        for i in 1..=3u8 {
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 129 + i);
            dht.add_node(make_node_with_id(bucket0_id(i), &addr))
                .await
                .unwrap();
        }

        // 4th: id 0x84 — farther than all → rejected
        let node = make_node_with_id(bucket0_id(4), "/ip4/134.1.1.1/udp/9000/quic");
        let result = dht.add_node(node).await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Closest-K geographic diversity tests
    // -----------------------------------------------------------------------

    /// K closest nodes have 3 same-region, 4th same-region (farther) rejected.
    #[tokio::test]
    async fn test_closest_k_geo_limit() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // 3 Europe nodes in different close buckets (each bucket has 1 → per-bucket OK)
        for (byte, addr) in [
            (0x01u8, "/ip4/130.1.1.1/udp/9000/quic"), // bucket 255
            (0x02, "/ip4/131.1.1.1/udp/9000/quic"),   // bucket 254
            (0x04, "/ip4/132.1.1.1/udp/9000/quic"),   // bucket 253
        ] {
            let mut id = [0u8; 32];
            id[31] = byte;
            dht.add_node(make_node_with_id(id, addr)).await.unwrap();
        }

        // 4th Europe node farther from self (0x08 > 0x04) → closest-K rejects
        let mut id = [0u8; 32];
        id[31] = 0x08;
        let result = dht
            .add_node(make_node_with_id(id, "/ip4/133.1.1.1/udp/9000/quic"))
            .await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("closest-K limit"),
            "should be rejected by closest-K geo check"
        );
    }

    /// Candidate closer than farthest same-region in K → swap.
    #[tokio::test]
    async fn test_closest_k_swap_closer_replaces_farther() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let eviction_target = PeerId::from_bytes({
            let mut id = [0u8; 32];
            id[31] = 0x08;
            id
        });

        // 3 Europe nodes: distances 0x02, 0x04, 0x08 (all different buckets)
        for (byte, addr) in [
            (0x02u8, "/ip4/130.1.1.1/udp/9000/quic"),
            (0x04, "/ip4/131.1.1.1/udp/9000/quic"),
            (0x08, "/ip4/132.1.1.1/udp/9000/quic"),
        ] {
            let mut id = [0u8; 32];
            id[31] = byte;
            dht.add_node(make_node_with_id(id, addr)).await.unwrap();
        }

        // 4th Europe node closer (0x01 < 0x08) → swap out farthest
        let mut id = [0u8; 32];
        id[31] = 0x01;
        let result = dht
            .add_node(make_node_with_id(id, "/ip4/133.1.1.1/udp/9000/quic"))
            .await;
        assert!(result.is_ok(), "closer node should swap in: {:?}", result);
        assert!(
            dht.get_node_address(&eviction_target).await.is_none(),
            "farthest same-region node should have been evicted"
        );
    }

    /// Candidate far from self, not in closest-K → geo check irrelevant.
    #[tokio::test]
    async fn test_closest_k_not_in_group_bypasses_check() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // 8 mixed-region nodes close to self (fill K=8). Interleave regions
        // so no single region exceeds the per-bucket or closest-K limit (3).
        for (byte, addr) in [
            (0x01u8, "/ip4/1.1.1.1/udp/9000/quic"), // NA, bucket 255
            (0x02, "/ip4/161.1.1.1/udp/9000/quic"), // AP, bucket 254
            (0x03, "/ip4/225.1.1.1/udp/9000/quic"), // SA, bucket 254
            (0x04, "/ip4/2.1.1.1/udp/9000/quic"),   // NA, bucket 253
            (0x05, "/ip4/162.1.1.1/udp/9000/quic"), // AP, bucket 253
            (0x06, "/ip4/226.1.1.1/udp/9000/quic"), // SA, bucket 253
            (0x07, "/ip4/3.1.1.1/udp/9000/quic"),   // NA, bucket 253
            (0x08, "/ip4/163.1.1.1/udp/9000/quic"), // AP, bucket 252
        ] {
            let mut id = [0u8; 32];
            id[31] = byte;
            dht.add_node(make_node_with_id(id, addr)).await.unwrap();
        }

        // 4 Europe nodes far from self (buckets 0-3) — not in closest-K
        for (i, &byte) in [0x80u8, 0x40, 0x20, 0x10].iter().enumerate() {
            let mut id = [0u8; 32];
            id[0] = byte;
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 130 + i as u8);
            let result = dht.add_node(make_node_with_id(id, &addr)).await;
            assert!(
                result.is_ok(),
                "far Europe node {i} should bypass closest-K: {:?}",
                result
            );
        }
    }

    /// Both per-bucket and closest-K trigger swap (same target, dedup).
    ///
    /// When all same-region nodes in K are in one bucket, both checks
    /// identify the same farthest peer. The dedup ensures single eviction.
    #[tokio::test]
    async fn test_both_checks_trigger_simultaneously() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // 4 non-EU close nodes (distances 0x01-0x05, mixed regions)
        for (byte, addr) in [
            (0x01u8, "/ip4/1.1.1.1/udp/9000/quic"), // NA, bucket 255
            (0x02, "/ip4/161.1.1.1/udp/9000/quic"), // AP, bucket 254
            (0x04, "/ip4/225.1.1.1/udp/9000/quic"), // SA, bucket 253
            (0x05, "/ip4/2.1.1.1/udp/9000/quic"),   // NA, bucket 253
        ] {
            let mut id = [0u8; 32];
            id[31] = byte;
            dht.add_node(make_node_with_id(id, addr)).await.unwrap();
        }

        // 3 EU in bucket 252: distances 0x09, 0x0A, 0x0B
        for (byte, addr) in [
            (0x09u8, "/ip4/130.1.1.1/udp/9000/quic"),
            (0x0A, "/ip4/131.1.1.1/udp/9000/quic"),
            (0x0B, "/ip4/132.1.1.1/udp/9000/quic"),
        ] {
            let mut id = [0u8; 32];
            id[31] = byte;
            dht.add_node(make_node_with_id(id, addr)).await.unwrap();
        }

        // 1 non-EU at 0x0C (SA, bucket 252) — will be K-th, displaced by candidate
        // so that the hypothetical K still has 3 EU from bucket 252.
        {
            let mut id = [0u8; 32];
            id[31] = 0x0C;
            dht.add_node(make_node_with_id(id, "/ip4/226.1.1.1/udp/9000/quic"))
                .await
                .unwrap();
        }

        // Candidate: 0x08 EU, bucket 252 — closer than farthest EU (0x0B).
        // Per-bucket: 3 EU → swap(0x0B). Closest-K: candidate displaces 0x0C
        // (non-EU) keeping 3 EU in K → swap(0x0B). Both target 0x0B (dedup).
        let evict_target = PeerId::from_bytes({
            let mut id = [0u8; 32];
            id[31] = 0x0B;
            id
        });
        let mut id = [0u8; 32];
        id[31] = 0x08;
        let result = dht
            .add_node(make_node_with_id(id, "/ip4/133.1.1.1/udp/9000/quic"))
            .await;
        assert!(result.is_ok(), "candidate should swap in: {:?}", result);
        assert!(
            dht.get_node_address(&evict_target).await.is_none(),
            "both checks should evict same peer (0x0B)"
        );
    }

    /// Same ID re-added passes without geo rejection (reconnecting node).
    #[tokio::test]
    async fn test_reconnecting_node_bypasses_geo() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_ip_diversity_config(IPDiversityConfig {
            ipv4_limit_floor: Some(100),
            ..IPDiversityConfig::default()
        });

        let reconnect_id = bucket0_id(2);

        // Fill bucket 0 with 3 Europe nodes at geo limit
        for i in 1..=3u8 {
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 129 + i);
            dht.add_node(make_node_with_id(bucket0_id(i), &addr))
                .await
                .unwrap();
        }

        // Re-add with same ID (reconnection) — count_region excludes own ID
        let result = dht
            .add_node(make_node_with_id(
                reconnect_id,
                "/ip4/131.2.2.2/udp/9000/quic",
            ))
            .await;
        assert!(
            result.is_ok(),
            "reconnecting node should bypass geo: {:?}",
            result
        );
    }

    /// Loopback nodes don't inflate geo counts.
    #[tokio::test]
    async fn test_loopback_excluded_from_geo_counting() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_allow_loopback(true);
        dht.set_ip_diversity_config(IPDiversityConfig {
            ipv4_limit_floor: Some(100),
            ..IPDiversityConfig::default()
        });

        // Add 5 loopback nodes in bucket 0 (127.0.0.1 → Europe by IP mapping)
        for i in 1..=5u8 {
            dht.add_node(make_node_with_id(
                bucket0_id(i),
                "/ip4/127.0.0.1/udp/9000/quic",
            ))
            .await
            .unwrap();
        }

        // 3 non-loopback Europe nodes in bucket 0 — loopback excluded from count
        for i in 6..=8u8 {
            let addr = format!("/ip4/{}.1.1.1/udp/9000/quic", 123 + i); // 129-131: Europe
            let result = dht.add_node(make_node_with_id(bucket0_id(i), &addr)).await;
            assert!(
                result.is_ok(),
                "non-loopback Europe node {i} should succeed: {:?}",
                result
            );
        }
    }
}
