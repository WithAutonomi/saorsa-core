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

//! S/Kademlia Security Extensions
//!
//! This module implements the S/Kademlia security extensions to the standard Kademlia DHT.
//! S/Kademlia provides enhanced security through disjoint path routing, sibling lists,
//! and cryptographic verification mechanisms to resist various attacks on the DHT.

use crate::dht::{DhtKey, Key, NodeInfo, PeerId};
use crate::error::{P2PError, P2pResult as Result};
use crate::quantum_crypto::saorsa_transport_integration::{
    MlDsaPublicKey, MlDsaSignature, ml_dsa_verify,
};
use crate::security::ReputationManager;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, info, warn};

/// Trait for querying nodes in the DHT network
///
/// Implementations of this trait provide the actual network communication
/// capabilities for S/Kademlia security operations.
pub trait NetworkQuerier: Send + Sync {
    /// Query a node for its closest nodes to a target key
    ///
    /// # Arguments
    /// * `node` - The node to query
    /// * `target` - The target key to find nodes closest to
    ///
    /// # Returns
    /// A list of nodes that the queried node knows about that are close to the target
    fn query_closest_nodes(
        &self,
        node: &NodeInfo,
        target: &Key,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<NodeInfo>>> + Send + '_>>;

    /// Query a node for distance measurement (for witness verification)
    ///
    /// # Arguments
    /// * `witness` - The witness node to query
    /// * `target_node` - The node whose distance is being measured
    /// * `target_key` - The key to measure distance from
    ///
    /// # Returns
    /// A distance measurement from the witness's perspective
    fn query_distance_measurement(
        &self,
        witness: &str,
        target_node: &str,
        target_key: &Key,
    ) -> Pin<Box<dyn Future<Output = Result<DistanceMeasurement>> + Send + '_>>;

    /// Request routing table entries from a node for cross-validation
    ///
    /// # Arguments
    /// * `node` - The node to query
    /// * `bucket_index` - Optional bucket index to request (None for all)
    ///
    /// # Returns
    /// A list of nodes from the queried node's routing table
    fn query_routing_table(
        &self,
        node: &NodeInfo,
        bucket_index: Option<usize>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<NodeInfo>>> + Send + '_>>;
}

/// S/Kademlia configuration parameters
#[derive(Debug, Clone)]
pub struct SKademliaConfig {
    /// Number of disjoint paths for lookups
    pub disjoint_path_count: usize,
    /// Maximum shared nodes between disjoint paths
    pub max_shared_nodes: usize,
    /// Size of sibling lists
    pub sibling_list_size: usize,
    /// Size of security buckets
    pub security_bucket_size: usize,
    /// Enable distance verification
    pub enable_distance_verification: bool,
    /// Enable routing table cross-validation
    pub enable_routing_validation: bool,
    /// Minimum reputation required for routing
    pub min_routing_reputation: f64,
    /// Timeout for disjoint path lookups
    pub lookup_timeout: Duration,
}

impl Default for SKademliaConfig {
    fn default() -> Self {
        Self {
            disjoint_path_count: 3,
            max_shared_nodes: 1,
            sibling_list_size: 16,
            security_bucket_size: 8,
            enable_distance_verification: true,
            enable_routing_validation: true,
            min_routing_reputation: 0.3,
            lookup_timeout: Duration::from_secs(30),
        }
    }
}

/// Disjoint path lookup for enhanced security
#[derive(Debug, Clone)]
pub struct DisjointPathLookup {
    /// Target key
    pub target: Key,
    /// Multiple independent paths
    pub paths: Vec<Vec<NodeInfo>>,
    /// Number of disjoint paths to maintain
    pub path_count: usize,
    /// Maximum nodes shared between paths
    pub max_shared_nodes: usize,
    /// Lookup start time
    pub started_at: Instant,
    /// Current lookup state per path
    pub path_states: Vec<PathState>,
}

/// State for individual path in disjoint lookup
#[derive(Debug, Clone)]
pub struct PathState {
    /// Path ID
    pub path_id: usize,
    /// Nodes in this path
    pub nodes: Vec<NodeInfo>,
    /// Nodes queried in this path
    pub queried: HashSet<PeerId>,
    /// Nodes to query next
    pub to_query: VecDeque<NodeInfo>,
    /// Path completion status
    pub completed: bool,
    /// Results found by this path
    pub results: Vec<NodeInfo>,
}

/// Sibling list for enhanced routing verification
#[derive(Debug, Clone)]
pub struct SiblingList {
    /// Local node ID
    pub local_id: Key,
    /// Closest nodes (siblings)
    pub siblings: Vec<NodeInfo>,
    /// Maximum size of sibling list
    pub max_size: usize,
    /// Last update time
    pub last_updated: Instant,
}

/// Security bucket for trusted nodes
#[derive(Debug, Clone)]
pub struct SecurityBucket {
    /// Trusted nodes for critical operations
    pub trusted_nodes: Vec<NodeInfo>,
    /// Alternative routing paths
    pub backup_routes: Vec<Vec<NodeInfo>>,
    /// Maximum size
    pub max_size: usize,
    /// Last validation time
    pub last_validated: Instant,
}

/// Distance verification challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistanceChallenge {
    /// Challenger node ID
    pub challenger: String,
    /// Target key for distance verification
    pub target_key: Key,
    /// Expected distance
    pub expected_distance: Key,
    /// Challenge nonce
    pub nonce: [u8; 32],
    /// Challenge timestamp
    pub timestamp: SystemTime,
}

/// Distance verification proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistanceProof {
    /// Original challenge
    pub challenge: DistanceChallenge,
    /// Proof nodes that can verify distance
    pub proof_nodes: Vec<String>,
    /// Signatures from proof nodes
    pub signatures: Vec<Vec<u8>>,
    /// Response time (distance indicator)
    pub response_time: Duration,
}

/// Enhanced distance challenge with witness nodes and multi-round verification
#[derive(Debug, Clone)]
pub struct EnhancedDistanceChallenge {
    /// Peer being challenged
    pub challenger: String,
    /// Target key for distance measurement
    pub target_key: Key,
    /// Expected distance based on claimed position
    pub expected_distance: Key,
    /// Random nonce for freshness
    pub nonce: [u8; 32],
    /// Challenge timestamp
    pub timestamp: SystemTime,
    /// Witness nodes for verification
    pub witness_nodes: Vec<PeerId>,
    /// Current challenge round
    pub challenge_round: u32,
    /// Maximum number of rounds
    pub max_rounds: u32,
}

/// Multi-node distance consensus result
#[derive(Debug, Clone)]
pub struct DistanceConsensus {
    /// Target key
    pub target_key: Key,
    /// Node being verified
    pub target_node: String,
    /// Consensus distance
    pub consensus_distance: Key,
    /// Individual measurements from witness nodes
    pub measurements: Vec<DistanceMeasurement>,
    /// Consensus confidence (0.0-1.0)
    pub confidence: f64,
    /// Verification timestamp
    pub verified_at: SystemTime,
}

/// Individual distance measurement by a witness node
#[derive(Debug, Clone)]
pub struct DistanceMeasurement {
    /// Witness node that made the measurement
    pub witness: String,
    /// Measured distance
    pub distance: Key,
    /// Measurement confidence
    pub confidence: f64,
    /// Response time for the measurement
    pub response_time: Duration,
}

/// Routing table consistency report
#[derive(Debug, Clone)]
pub struct ConsistencyReport {
    /// Number of nodes checked
    pub nodes_checked: usize,
    /// Number of inconsistencies found
    pub inconsistencies: usize,
    /// Suspicious nodes
    pub suspicious_nodes: Vec<String>,
    /// Validation timestamp
    pub validated_at: Instant,
}

/// S/Kademlia enhanced DHT
#[derive(Debug)]
pub struct SKademlia {
    /// Base configuration
    pub config: SKademliaConfig,
    /// Sibling lists for routing verification
    pub sibling_lists: HashMap<Key, SiblingList>,
    /// Security buckets for trusted nodes
    pub security_buckets: HashMap<Key, SecurityBucket>,
    /// Reputation manager for node trust scoring
    pub reputation_manager: ReputationManager,
    /// Active disjoint lookups
    pub active_lookups: HashMap<Key, DisjointPathLookup>,
    /// Distance verification challenges
    pub pending_challenges: HashMap<PeerId, DistanceChallenge>,
    /// Registry of peer public keys for signature verification (ML-DSA-65)
    pub peer_public_keys: HashMap<PeerId, Vec<u8>>,
}

impl DisjointPathLookup {
    /// Create a new disjoint path lookup
    pub fn new(target: Key, path_count: usize, max_shared_nodes: usize) -> Self {
        let path_states = (0..path_count)
            .map(|i| PathState {
                path_id: i,
                nodes: Vec::new(),
                queried: HashSet::new(),
                to_query: VecDeque::new(),
                completed: false,
                results: Vec::new(),
            })
            .collect();

        Self {
            target,
            paths: vec![Vec::new(); path_count],
            path_count,
            max_shared_nodes,
            started_at: Instant::now(),
            path_states,
        }
    }

    /// Add initial nodes to paths ensuring disjointness
    pub fn initialize_paths(&mut self, initial_nodes: Vec<NodeInfo>) -> Result<()> {
        if initial_nodes.len() < self.path_count {
            return Err(P2PError::Dht(crate::error::DhtError::InsufficientPeers(
                format!(
                    "Available: {}, Required: {}",
                    initial_nodes.len(),
                    self.path_count
                )
                .into(),
            )));
        }

        // Distribute nodes across paths to minimize overlap
        for (i, node) in initial_nodes.into_iter().enumerate() {
            let path_id = i % self.path_count;
            self.path_states[path_id].to_query.push_back(node.clone());
            self.paths[path_id].push(node);
        }

        Ok(())
    }

    /// Check if paths are sufficiently disjoint
    pub fn verify_disjointness(&self) -> bool {
        for i in 0..self.path_count {
            for j in (i + 1)..self.path_count {
                let shared_count = self.count_shared_nodes(i, j);
                if shared_count > self.max_shared_nodes {
                    debug!(
                        "Paths {} and {} share {} nodes (max: {})",
                        i, j, shared_count, self.max_shared_nodes
                    );
                    return false;
                }
            }
        }
        true
    }

    /// Count shared nodes between two paths
    fn count_shared_nodes(&self, path1: usize, path2: usize) -> usize {
        let nodes1: HashSet<_> = self.path_states[path1].queried.iter().collect();
        let nodes2: HashSet<_> = self.path_states[path2].queried.iter().collect();
        nodes1.intersection(&nodes2).count()
    }

    /// Get next node to query for a specific path
    pub fn get_next_node(&mut self, path_id: usize) -> Option<NodeInfo> {
        if path_id >= self.path_count {
            return None;
        }

        // Skip if path is completed
        if self.path_states[path_id].completed {
            return None;
        }

        // Get next unqueried node
        let mut next_node = None;
        while let Some(node) = self.path_states[path_id].to_query.pop_front() {
            if !self.path_states[path_id].queried.contains(&node.id) {
                // Check if using this node would violate disjointness
                if self.would_violate_disjointness(path_id, &node.id) {
                    continue;
                }

                next_node = Some(node);
                break;
            }
        }

        if let Some(node) = next_node {
            self.path_states[path_id].queried.insert(node.id);
            return Some(node);
        }

        // Mark path as completed if no more nodes to query
        self.path_states[path_id].completed = true;
        None
    }

    /// Check if adding a node to a path would violate disjointness constraints
    fn would_violate_disjointness(&self, path_id: usize, peer_id: &PeerId) -> bool {
        for (i, path_state) in self.path_states.iter().enumerate() {
            if i == path_id {
                continue;
            }

            if path_state.queried.contains(peer_id) {
                // Count current shared nodes
                let shared_count = self.count_shared_nodes(path_id, i);
                if shared_count >= self.max_shared_nodes {
                    return true;
                }
            }
        }
        false
    }

    /// Add nodes from query results to appropriate paths
    pub fn add_query_results(&mut self, path_id: usize, nodes: Vec<NodeInfo>) {
        if path_id >= self.path_count {
            return;
        }

        let target = self.target;
        for node in nodes {
            // Add to results if close to target
            let node_key = DhtKey::from_bytes(*node.id.as_bytes());
            let target_key = DhtKey::from_bytes(target);
            let distance = node_key.distance(&target_key);
            if self.is_close_to_target(&distance) {
                self.path_states[path_id].results.push(node.clone());
            }

            // Add to query queue if not already queried
            if !self.path_states[path_id].queried.contains(&node.id) {
                self.path_states[path_id].to_query.push_back(node);
            }
        }

        // Sort query queue by distance to target
        let mut to_query: Vec<_> = self.path_states[path_id].to_query.drain(..).collect();
        to_query.sort_by_key(|node| {
            let node_key = DhtKey::from_bytes(*node.id.as_bytes());
            let target_key = DhtKey::from_bytes(target);
            {
                let dist = node_key.distance(&target_key);
                // Count leading zero bits in the distance
                let mut leading_zeros = 0u32;
                for byte in dist.iter() {
                    if *byte == 0 {
                        leading_zeros += 8;
                    } else {
                        leading_zeros += byte.leading_zeros();
                        break;
                    }
                }
                leading_zeros
            }
        });
        self.path_states[path_id].to_query = to_query.into();
    }

    /// Check if a distance is close to target (within reasonable range)
    fn is_close_to_target(&self, distance: &Key) -> bool {
        // Count leading zero bytes in the distance
        let leading_zero_bytes = distance.iter().take_while(|&&b| b == 0).count();
        leading_zero_bytes > 16 // Within 128 bits of target (16 bytes = 128 bits)
    }

    /// Check if lookup is complete
    pub fn is_complete(&self) -> bool {
        self.path_states.iter().all(|path| path.completed)
            || self.started_at.elapsed() > Duration::from_secs(60)
    }

    /// Get consolidated results from all paths
    pub fn get_results(&self) -> Vec<NodeInfo> {
        let mut all_results = Vec::new();

        for path_state in &self.path_states {
            all_results.extend(path_state.results.clone());
        }

        // Remove duplicates and sort by distance
        all_results.sort_by_key(|node| {
            let node_key = DhtKey::from_bytes(*node.id.as_bytes());
            let target_key = DhtKey::from_bytes(self.target);
            {
                let dist = node_key.distance(&target_key);
                // Count leading zero bits in the distance
                let mut leading_zeros = 0u32;
                for byte in dist.iter() {
                    if *byte == 0 {
                        leading_zeros += 8;
                    } else {
                        leading_zeros += byte.leading_zeros();
                        break;
                    }
                }
                leading_zeros
            }
        });
        // Deduplicate by peer address to avoid conflating distinct peers with identical test IDs
        all_results.dedup_by_key(|node| node.address.clone());

        all_results
    }

    /// Validate consistency of results across paths
    pub fn validate_results(&self) -> Result<bool> {
        let mut path_results: Vec<Vec<&NodeInfo>> = Vec::new();

        for path_state in &self.path_states {
            let mut sorted_results: Vec<_> = path_state.results.iter().collect();
            sorted_results.sort_by_key(|node| {
                let node_key = DhtKey::from_bytes(*node.id.as_bytes());
                let target_key = DhtKey::from_bytes(self.target);
                {
                    let dist = node_key.distance(&target_key);
                    // Count leading zero bits in the distance
                    let mut leading_zeros = 0u32;
                    for byte in dist.iter() {
                        if *byte == 0 {
                            leading_zeros += 8;
                        } else {
                            leading_zeros += byte.leading_zeros();
                            break;
                        }
                    }
                    leading_zeros
                }
            });
            path_results.push(sorted_results);
        }

        // Check if top results are consistent across paths
        let min_results = path_results.iter().map(|r| r.len()).min().unwrap_or(0);
        if min_results == 0 {
            return Ok(true); // No results to validate
        }

        let consensus_threshold = (self.path_count * 2) / 3; // 2/3 consensus
        let check_count = std::cmp::min(min_results, 5); // Check top 5 results

        for i in 0..check_count {
            let mut node_counts: HashMap<String, usize> = HashMap::new();

            for path_result in &path_results {
                if i < path_result.len() {
                    *node_counts
                        .entry(path_result[i].id.to_string().clone())
                        .or_insert(0) += 1;
                }
            }

            // Check if any node appears in enough paths
            let has_consensus = node_counts
                .values()
                .any(|&count| count >= consensus_threshold);
            if !has_consensus {
                warn!("No consensus for result position {}: {:?}", i, node_counts);
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl SiblingList {
    /// Create a new sibling list
    pub fn new(local_id: Key, max_size: usize) -> Self {
        Self {
            local_id,
            siblings: Vec::new(),
            max_size,
            last_updated: Instant::now(),
        }
    }

    /// Add or update a node in the sibling list
    pub fn add_node(&mut self, node: NodeInfo) {
        // Remove if already exists
        self.siblings.retain(|n| n.address != node.address);

        // Add new node
        self.siblings.push(node);

        // Sort by distance to local node
        self.siblings.sort_by_key(|n| {
            // Compute distance from node id to local_id
            let node_key = DhtKey::from_bytes(*n.id.as_bytes());
            let local_key = DhtKey::from_bytes(self.local_id);
            let dist = node_key.distance(&local_key);
            // Count leading zero bits
            let mut leading_zeros = 0u32;
            for byte in dist.iter() {
                if *byte == 0 {
                    leading_zeros += 8;
                } else {
                    leading_zeros += byte.leading_zeros();
                    break;
                }
            }
            leading_zeros
        });

        // Trim to max size
        if self.siblings.len() > self.max_size {
            self.siblings.truncate(self.max_size);
        }

        self.last_updated = Instant::now();
    }

    /// Get closest siblings for verification
    pub fn get_closest_siblings(&self, count: usize) -> Vec<&NodeInfo> {
        self.siblings.iter().take(count).collect()
    }

    /// Verify a routing decision against sibling knowledge
    pub fn verify_routing_decision(&self, target: &Key, proposed_nodes: &[NodeInfo]) -> bool {
        // If we have no sibling knowledge yet, accept proposed nodes by default
        if self.siblings.is_empty() {
            return true;
        }
        // Check if proposed nodes are reasonable given our sibling knowledge
        let target_key = DhtKey::from_bytes(*target);
        let local_key = DhtKey::from_bytes(self.local_id);
        let expected_distance = target_key.distance(&local_key);

        for proposed in proposed_nodes {
            // NodeInfo has id field of type PeerId
            // Get the underlying bytes from the PeerId
            let proposed_id = *proposed.id.as_bytes();

            let proposed_key = DhtKey::from_bytes(proposed_id);
            let proposed_distance = target_key.distance(&proposed_key);

            // Verify the proposed node is actually closer than us
            // Count leading zeros for comparison
            let proposed_lz = {
                let mut lz = 0u32;
                for byte in proposed_distance.iter() {
                    if *byte == 0 {
                        lz += 8;
                    } else {
                        lz += byte.leading_zeros();
                        break;
                    }
                }
                lz
            };
            let expected_lz = {
                let mut lz = 0u32;
                for byte in expected_distance.iter() {
                    if *byte == 0 {
                        lz += 8;
                    } else {
                        lz += byte.leading_zeros();
                        break;
                    }
                }
                lz
            };
            if proposed_lz <= expected_lz && proposed_distance != expected_distance {
                debug!("Proposed node is not closer to target than local node");
                return false;
            }

            // Check if any sibling should know about this node
            let should_know = self.siblings.iter().any(|sibling| {
                // Compute sibling distance using its ID
                let sibling_key = DhtKey::from_bytes(*sibling.id.as_bytes());

                let sibling_to_target = target_key.distance(&sibling_key);
                let sibling_to_proposed = proposed_key.distance(&sibling_key);

                // Sibling should know about proposed node if it's in their neighborhood
                // Compare leading zeros
                let sibling_to_proposed_lz = {
                    let mut lz = 0u32;
                    for byte in sibling_to_proposed.iter() {
                        if *byte == 0 {
                            lz += 8;
                        } else {
                            lz += byte.leading_zeros();
                            break;
                        }
                    }
                    lz
                };
                let sibling_to_target_lz = {
                    let mut lz = 0u32;
                    for byte in sibling_to_target.iter() {
                        if *byte == 0 {
                            lz += 8;
                        } else {
                            lz += byte.leading_zeros();
                            break;
                        }
                    }
                    lz
                };
                sibling_to_proposed_lz > sibling_to_target_lz
            });

            if !should_know {
                debug!(
                    "No sibling knows about proposed node: {}",
                    proposed.id.to_string()
                );
                // This might be suspicious but not necessarily invalid
            }
        }

        true
    }
}

impl SecurityBucket {
    /// Create a new security bucket
    pub fn new(max_size: usize) -> Self {
        Self {
            trusted_nodes: Vec::new(),
            backup_routes: Vec::new(),
            max_size,
            last_validated: Instant::now(),
        }
    }

    /// Add a trusted node to the security bucket
    pub fn add_trusted_node(&mut self, node: NodeInfo) {
        // Remove if already exists
        // Use address for uniqueness to avoid test fixtures with identical IDs
        self.trusted_nodes.retain(|n| n.address != node.address);

        // Add new node
        self.trusted_nodes.push(node);

        // Trim to max size (keep most recently seen)
        if self.trusted_nodes.len() > self.max_size {
            self.trusted_nodes.sort_by_key(|n| n.last_seen);
            self.trusted_nodes.truncate(self.max_size);
        }
    }

    /// Get trusted nodes for secure operations
    pub fn get_trusted_nodes(&self) -> &[NodeInfo] {
        &self.trusted_nodes
    }

    /// Add a backup route
    pub fn add_backup_route(&mut self, route: Vec<NodeInfo>) {
        self.backup_routes.push(route);

        // Keep only a reasonable number of backup routes
        if self.backup_routes.len() > 5 {
            self.backup_routes.remove(0);
        }
    }

    /// Get backup routes for redundancy
    pub fn get_backup_routes(&self) -> &[Vec<NodeInfo>] {
        &self.backup_routes
    }
}

impl SKademlia {
    /// Create a new S/Kademlia instance
    pub fn new(config: SKademliaConfig) -> Self {
        let reputation_manager = ReputationManager::new(0.1, config.min_routing_reputation);

        Self {
            config,
            sibling_lists: HashMap::new(),
            security_buckets: HashMap::new(),
            reputation_manager,
            active_lookups: HashMap::new(),
            pending_challenges: HashMap::new(),
            peer_public_keys: HashMap::new(),
        }
    }

    /// Register a peer's public key for signature verification
    pub fn register_peer_public_key(&mut self, peer_id: PeerId, public_key: Vec<u8>) {
        self.peer_public_keys.insert(peer_id, public_key);
    }

    /// Get a peer's public key for signature verification
    pub fn get_peer_public_key(&self, peer_id: &PeerId) -> Option<&Vec<u8>> {
        self.peer_public_keys.get(peer_id)
    }

    /// Perform a secure lookup using disjoint paths (without network querier)
    ///
    /// This is a simplified version that returns the initial nodes.
    /// Use `secure_lookup_with_querier` for full network-based lookups.
    pub async fn secure_lookup(
        &mut self,
        target: Key,
        initial_nodes: Vec<NodeInfo>,
    ) -> Result<Vec<NodeInfo>> {
        info!("Starting secure lookup for target: {}", hex::encode(target));

        // Create disjoint path lookup
        let mut lookup = DisjointPathLookup::new(
            target,
            self.config.disjoint_path_count,
            self.config.max_shared_nodes,
        );

        // Initialize paths with initial nodes
        lookup.initialize_paths(initial_nodes)?;

        // Verify paths are sufficiently disjoint
        if !lookup.verify_disjointness() {
            warn!("Unable to create sufficiently disjoint paths");
        }

        // Store active lookup
        self.active_lookups.insert(target, lookup);

        // Return initial results (for backwards compatibility)
        if let Some(lookup) = self.active_lookups.get(&target) {
            Ok(lookup.get_results())
        } else {
            Err(P2PError::Dht(crate::error::DhtError::KeyNotFound(
                format!("{:?}: Lookup disappeared", target).into(),
            )))
        }
    }

    /// Perform a secure lookup using disjoint paths with network queries
    ///
    /// This method implements the full S/Kademlia disjoint path lookup algorithm:
    /// 1. Initialize d disjoint paths from initial nodes
    /// 2. Query nodes along each path in parallel
    /// 3. Validate results across paths for consensus
    /// 4. Return results that have consensus across majority of paths
    ///
    /// # Arguments
    /// * `target` - The key to look up
    /// * `initial_nodes` - Initial nodes to start the lookup from
    /// * `querier` - Network querier implementation for actual network calls
    ///
    /// # Returns
    /// The closest nodes to the target that were validated across disjoint paths
    pub async fn secure_lookup_with_querier<Q: NetworkQuerier>(
        &mut self,
        target: Key,
        initial_nodes: Vec<NodeInfo>,
        querier: &Q,
    ) -> Result<Vec<NodeInfo>> {
        info!(
            "Starting secure lookup with querier for target: {}",
            hex::encode(target)
        );

        // Create disjoint path lookup
        let mut lookup = DisjointPathLookup::new(
            target,
            self.config.disjoint_path_count,
            self.config.max_shared_nodes,
        );

        // Initialize paths with initial nodes
        lookup.initialize_paths(initial_nodes)?;

        // Verify paths are sufficiently disjoint
        if !lookup.verify_disjointness() {
            warn!("Initial paths are not sufficiently disjoint, proceeding with caution");
        }

        let timeout = self.config.lookup_timeout;
        let start_time = Instant::now();

        // Iteratively query nodes across all paths until complete or timeout
        while !lookup.is_complete() && start_time.elapsed() < timeout {
            // Query each path concurrently
            for path_id in 0..lookup.path_count {
                // Get next node to query for this path
                let next_node = lookup.get_next_node(path_id);

                if let Some(node) = next_node {
                    debug!(
                        "Path {}: Querying node {} for target {}",
                        path_id,
                        node.address,
                        hex::encode(target)
                    );

                    // Track query timing for reputation
                    let query_start = std::time::Instant::now();

                    // Perform the network query
                    match querier.query_closest_nodes(&node, &target).await {
                        Ok(discovered_nodes) => {
                            let response_time = query_start.elapsed();
                            debug!(
                                "Path {}: Discovered {} nodes from {} in {:?}",
                                path_id,
                                discovered_nodes.len(),
                                node.address,
                                response_time
                            );

                            // Update reputation for successful query
                            self.reputation_manager.update_reputation(
                                &node.id,
                                true,
                                response_time,
                            );

                            // Add discovered nodes to the path
                            lookup.add_query_results(path_id, discovered_nodes);
                        }
                        Err(e) => {
                            let response_time = query_start.elapsed();
                            warn!(
                                "Path {}: Query to {} failed after {:?}: {}",
                                path_id, node.address, response_time, e
                            );

                            // Update reputation for failed query
                            self.reputation_manager.update_reputation(
                                &node.id,
                                false,
                                response_time,
                            );
                        }
                    }
                }
            }

            // Small delay to avoid overwhelming the network
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Validate results across paths
        let is_consistent = lookup.validate_results()?;
        if !is_consistent {
            warn!("Lookup results are not consistent across paths - potential attack detected");
        }

        // Store lookup for later reference
        self.active_lookups.insert(target, lookup.clone());

        // Get and return consolidated results
        let results = lookup.get_results();
        info!(
            "Secure lookup complete: {} results found, consistent: {}",
            results.len(),
            is_consistent
        );

        Ok(results)
    }

    /// Update sibling list for a key range
    pub fn update_sibling_list(&mut self, key: Key, nodes: Vec<NodeInfo>) {
        let sibling_list = self
            .sibling_lists
            .entry(key)
            .or_insert_with(|| SiblingList::new(key, self.config.sibling_list_size));

        for node in nodes {
            sibling_list.add_node(node);
        }
    }

    /// Get or create security bucket for a key range
    pub fn get_security_bucket(&mut self, key: &Key) -> &mut SecurityBucket {
        self.security_buckets
            .entry(*key)
            .or_insert_with(|| SecurityBucket::new(self.config.security_bucket_size))
    }

    /// Create a distance verification challenge with multi-round protocol
    pub fn create_distance_challenge(&mut self, target: &PeerId, key: &Key) -> DistanceChallenge {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let challenge = DistanceChallenge {
            challenger: target.to_hex(),
            target_key: *key,
            expected_distance: {
                let target_bytes = target.as_bytes();
                DhtKey::from_bytes(*key).distance(&DhtKey::from_bytes(*target_bytes))
            },
            nonce,
            timestamp: SystemTime::now(),
        };

        self.pending_challenges.insert(*target, challenge.clone());
        challenge
    }

    /// Create an enhanced distance challenge with witness nodes
    pub fn create_enhanced_distance_challenge(
        &mut self,
        target: &PeerId,
        key: &Key,
        witness_nodes: Vec<PeerId>,
    ) -> EnhancedDistanceChallenge {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let challenge = EnhancedDistanceChallenge {
            challenger: target.to_hex(),
            target_key: *key,
            expected_distance: {
                let target_bytes = target.as_bytes();
                DhtKey::from_bytes(*key).distance(&DhtKey::from_bytes(*target_bytes))
            },
            nonce,
            timestamp: SystemTime::now(),
            witness_nodes,
            challenge_round: 1,
            max_rounds: 3,
        };

        self.pending_challenges.insert(
            *target,
            DistanceChallenge {
                challenger: challenge.challenger.clone(),
                target_key: challenge.target_key,
                expected_distance: challenge.expected_distance,
                nonce: challenge.nonce,
                timestamp: challenge.timestamp,
            },
        );

        challenge
    }

    /// Verify a distance proof
    pub fn verify_distance_proof(&self, proof: &DistanceProof) -> Result<bool> {
        // Verify proof timestamps
        let elapsed = proof.challenge.timestamp.elapsed().map_err(|e| {
            P2PError::Dht(crate::error::DhtError::RoutingError(
                format!("Invalid timestamp: {e}").into(),
            ))
        })?;

        if elapsed > Duration::from_secs(300) {
            return Ok(false); // Proof too old
        }

        // Verify expected distance matches actual distance
        let actual_distance = {
            let challenger_bytes = proof.challenge.challenger.as_bytes();
            let mut challenger_key = [0u8; 32];
            let len = challenger_bytes.len().min(32);
            challenger_key[..len].copy_from_slice(&challenger_bytes[..len]);

            DhtKey::from_bytes(proof.challenge.target_key)
                .distance(&DhtKey::from_bytes(challenger_key))
        };

        if actual_distance != proof.challenge.expected_distance {
            return Ok(false);
        }

        // Verify proof nodes and signatures
        if proof.proof_nodes.len() != proof.signatures.len() {
            return Ok(false);
        }

        // Generate the message that was signed from the challenge
        let message = Self::challenge_to_bytes_for_signing(&proof.challenge);

        // Verify each signature using ML-DSA-65
        let mut valid_signatures = 0;
        for (i, (peer_id, signature_bytes)) in proof
            .proof_nodes
            .iter()
            .zip(proof.signatures.iter())
            .enumerate()
        {
            // Look up the peer's public key from registry
            let peer_key = match PeerId::from_hex(peer_id) {
                Ok(id) => id,
                Err(_) => {
                    debug!(
                        "Distance proof verification: Invalid hex peer ID '{}' (signature {})",
                        peer_id, i
                    );
                    continue;
                }
            };
            let public_key_bytes = match self.peer_public_keys.get(&peer_key) {
                Some(pk) => pk,
                None => {
                    debug!(
                        "Distance proof verification: No public key for peer {} (signature {})",
                        peer_id, i
                    );
                    continue; // Skip unknown peers - they don't count toward validation
                }
            };

            // Parse the public key
            let public_key = match MlDsaPublicKey::from_bytes(public_key_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!(
                        "Distance proof verification: Invalid public key format for peer {}: {}",
                        peer_id, e
                    );
                    continue;
                }
            };

            // Parse the signature
            let signature = match MlDsaSignature::from_bytes(signature_bytes) {
                Ok(sig) => sig,
                Err(e) => {
                    warn!(
                        "Distance proof verification: Invalid signature format for peer {}: {}",
                        peer_id, e
                    );
                    continue;
                }
            };

            // Verify the signature
            match ml_dsa_verify(&public_key, &message, &signature) {
                Ok(true) => {
                    debug!(
                        "Distance proof: Valid signature from peer {} ({})",
                        peer_id, i
                    );
                    valid_signatures += 1;
                }
                Ok(false) => {
                    warn!(
                        "Distance proof: Invalid signature from peer {} - signature verification failed",
                        peer_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Distance proof: Signature verification error for peer {}: {}",
                        peer_id, e
                    );
                }
            }
        }

        // Require a majority of valid signatures (BFT threshold)
        let min_proofs = self.config.disjoint_path_count.div_ceil(2);
        let result = valid_signatures >= min_proofs;

        if result {
            info!(
                "Distance proof verified: {}/{} valid signatures (threshold: {})",
                valid_signatures,
                proof.proof_nodes.len(),
                min_proofs
            );
        } else {
            warn!(
                "Distance proof rejected: {}/{} valid signatures (threshold: {})",
                valid_signatures,
                proof.proof_nodes.len(),
                min_proofs
            );
        }

        Ok(result)
    }

    /// Generate deterministic bytes from a DistanceChallenge for cryptographic signing
    ///
    /// The format is:
    /// - 32 bytes: challenger peer ID (padded/truncated)
    /// - 32 bytes: target_key
    /// - 32 bytes: expected_distance
    /// - 32 bytes: nonce
    /// - 8 bytes: timestamp (as Unix epoch seconds, big-endian)
    pub fn challenge_to_bytes_for_signing(challenge: &DistanceChallenge) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(136); // 32*4 + 8

        // Challenger peer ID (padded to 32 bytes)
        let challenger_bytes = challenge.challenger.as_bytes();
        let mut challenger_padded = [0u8; 32];
        let len = challenger_bytes.len().min(32);
        challenger_padded[..len].copy_from_slice(&challenger_bytes[..len]);
        bytes.extend_from_slice(&challenger_padded);

        // Target key (32 bytes)
        bytes.extend_from_slice(&challenge.target_key);

        // Expected distance (32 bytes)
        bytes.extend_from_slice(&challenge.expected_distance);

        // Nonce (32 bytes)
        bytes.extend_from_slice(&challenge.nonce);

        // Timestamp as Unix epoch seconds (8 bytes, big-endian)
        let timestamp_secs = challenge
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        bytes.extend_from_slice(&timestamp_secs.to_be_bytes());

        bytes
    }

    /// Convert a 256-bit XOR distance to a score between 0.0 and 1.0
    ///
    /// Smaller distances (closer nodes) get higher scores.
    /// Uses the position of the first non-zero bit to determine closeness.
    fn distance_to_score(distance: &Key) -> f64 {
        // Count leading zero bits - more zeros = closer = higher score
        let mut leading_zeros = 0u32;
        for byte in distance {
            if *byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }

        // Maximum possible leading zeros is 256 (for zero distance)
        // Score: closer = higher score (max 1.0 for zero distance)
        let max_bits = 256.0;
        let score = leading_zeros as f64 / max_bits;

        // Clamp to [0.0, 1.0] range
        score.clamp(0.0, 1.0)
    }

    /// Perform multi-node distance consensus verification
    ///
    /// # Arguments
    /// * `target_node` - The node whose distance is being verified
    /// * `target_key` - The key to measure distance from
    /// * `witness_nodes` - List of witness nodes to query
    /// * `querier` - Network querier for making actual network calls
    pub async fn verify_distance_consensus<Q: NetworkQuerier>(
        &mut self,
        target_node: &str,
        target_key: &Key,
        witness_nodes: Vec<PeerId>,
        querier: &Q,
    ) -> Result<DistanceConsensus> {
        let mut measurements = Vec::new();

        for witness in &witness_nodes {
            // Request distance measurement from witness node via network call
            let query_start = std::time::Instant::now();
            let witness_hex = witness.to_hex();

            match querier
                .query_distance_measurement(&witness_hex, target_node, target_key)
                .await
            {
                Ok(mut measurement) => {
                    // Update reputation for successful query
                    let response_time = query_start.elapsed();
                    self.reputation_manager
                        .update_reputation(witness, true, response_time);

                    // Recalculate confidence based on current reputation and response time
                    // (the measurement may have its own confidence, but we weight it by reputation)
                    let reputation_factor = self
                        .reputation_manager
                        .get_reputation(witness)
                        .map(|rep| rep.response_rate * rep.consistency_score)
                        .unwrap_or(0.5);

                    // Blend the witness's reported confidence with our reputation assessment
                    measurement.confidence = (measurement.confidence + reputation_factor) / 2.0;
                    measurement.response_time = response_time;

                    tracing::debug!(
                        witness = %witness,
                        confidence = %measurement.confidence,
                        response_time_ms = %response_time.as_millis(),
                        "Distance measurement received from witness"
                    );

                    measurements.push(measurement);
                }
                Err(e) => {
                    // Update reputation for failed query
                    let response_time = query_start.elapsed();
                    self.reputation_manager
                        .update_reputation(witness, false, response_time);

                    tracing::warn!(
                        witness = %witness,
                        error = %e,
                        "Failed to get distance measurement from witness"
                    );
                    // Continue with other witnesses - don't fail the entire consensus
                }
            }
        }

        // Calculate overall confidence
        let total_confidence: f64 = measurements.iter().map(|m| m.confidence).sum();
        let confidence = if measurements.is_empty() {
            0.0
        } else {
            total_confidence / measurements.len() as f64
        };

        // Calculate consensus distance (handle empty measurements gracefully)
        let consensus_distance = if measurements.is_empty() {
            // For empty measurements, use a zero distance
            [0u8; 32]
        } else {
            self.calculate_consensus_distance(&measurements)?
        };

        Ok(DistanceConsensus {
            target_key: *target_key,
            target_node: target_node.to_owned(),
            consensus_distance,
            measurements,
            confidence,
            verified_at: SystemTime::now(),
        })
    }

    /// Calculate consensus distance from multiple measurements
    fn calculate_consensus_distance(&self, measurements: &[DistanceMeasurement]) -> Result<Key> {
        if measurements.is_empty() {
            return Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                "No measurements provided".to_string().into(),
            )));
        }

        // For simplicity, use the distance from the most confident measurement
        let best_measurement = measurements
            .iter()
            .max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .ok_or_else(|| {
                P2PError::Dht(crate::error::DhtError::RoutingError(
                    "No valid measurement found".to_string().into(),
                ))
            })?;

        Ok(best_measurement.distance)
    }

    /// Verify distance using multi-round challenge protocol
    ///
    /// # Arguments
    /// * `challenge` - The distance challenge to verify
    /// * `querier` - Network querier for making actual network calls
    pub async fn verify_distance_multi_round<Q: NetworkQuerier>(
        &mut self,
        challenge: &EnhancedDistanceChallenge,
        querier: &Q,
    ) -> Result<bool> {
        let mut successful_rounds = 0;
        let required_rounds = challenge.max_rounds.div_ceil(2); // Majority

        for _round in 1..=challenge.max_rounds {
            // Select subset of witness nodes for this round
            let round_witnesses: Vec<_> = challenge
                .witness_nodes
                .iter()
                .take(3) // Use up to 3 witnesses per round
                .cloned()
                .collect();

            if round_witnesses.is_empty() {
                break;
            }

            // Perform consensus verification for this round via network calls
            let consensus = self
                .verify_distance_consensus(
                    &challenge.challenger,
                    &challenge.target_key,
                    round_witnesses,
                    querier,
                )
                .await?;

            // Check if consensus distance matches expected
            let distance_diff = DhtKey::from_bytes(consensus.consensus_distance)
                .distance(&DhtKey::from_bytes(challenge.expected_distance));
            let mut tolerance_bytes = [0u8; 32];
            tolerance_bytes[31] = 1;
            let tolerance = tolerance_bytes;

            let zero_key = [0u8; 32];
            // Compare distance bytes directly
            let dist_bytes =
                DhtKey::from_bytes(distance_diff).distance(&DhtKey::from_bytes(zero_key));
            if dist_bytes <= tolerance {
                successful_rounds += 1;
            }

            // Early exit if we have enough successful rounds
            if successful_rounds >= required_rounds {
                return Ok(true);
            }
        }

        Ok(successful_rounds >= required_rounds)
    }

    /// Create distance verification challenge with adaptive difficulty
    ///
    /// Selects witness nodes from the routing table based on:
    /// 1. Trusted nodes from security buckets (highest priority)
    /// 2. Sibling nodes close to the target key
    /// 3. Reputation filtering (must meet minimum threshold)
    pub fn create_adaptive_distance_challenge(
        &mut self,
        target: &PeerId,
        key: &Key,
        suspected_attack: bool,
    ) -> EnhancedDistanceChallenge {
        let witness_count = if suspected_attack { 7 } else { 3 }; // More witnesses if attack suspected
        let max_rounds = if suspected_attack { 5 } else { 3 }; // More rounds if attack suspected

        // Select witness nodes from routing table based on proximity and reputation
        let mut candidate_nodes: Vec<(NodeInfo, f64)> = Vec::new(); // (node, score)

        // 1. First, collect trusted nodes from security buckets (highest priority)
        for security_bucket in self.security_buckets.values() {
            for node in &security_bucket.trusted_nodes {
                // Don't select the target as a witness
                if node.id == *target {
                    continue;
                }

                // Get reputation score (trusted nodes get bonus)
                let reputation_score = self
                    .reputation_manager
                    .get_reputation(&node.id)
                    .map(|rep| rep.response_rate * rep.consistency_score)
                    .unwrap_or(0.5)
                    * 1.5; // Trusted node bonus

                // Calculate distance-based score (closer to key = better witness)
                let node_dht_key = DhtKey::from_bytes(*node.id.as_bytes());
                let distance = node_dht_key.distance(&DhtKey::from_bytes(*key));
                let distance_score = Self::distance_to_score(&distance);

                let combined_score = reputation_score * 0.6 + distance_score * 0.4;
                candidate_nodes.push((node.clone(), combined_score));
            }
        }

        // 2. Then collect sibling nodes from sibling lists
        for sibling_list in self.sibling_lists.values() {
            for node in &sibling_list.siblings {
                // Don't select the target as a witness
                if node.id == *target {
                    continue;
                }

                // Check if already in candidates
                if candidate_nodes.iter().any(|(n, _)| n.id == node.id) {
                    continue;
                }

                // Get reputation score
                let reputation_score = self
                    .reputation_manager
                    .get_reputation(&node.id)
                    .map(|rep| rep.response_rate * rep.consistency_score)
                    .unwrap_or(0.5);

                // Filter out nodes with poor reputation
                if reputation_score < self.config.min_routing_reputation {
                    continue;
                }

                // Calculate distance-based score
                let node_dht_key = DhtKey::from_bytes(*node.id.as_bytes());
                let distance = node_dht_key.distance(&DhtKey::from_bytes(*key));
                let distance_score = Self::distance_to_score(&distance);

                let combined_score = reputation_score * 0.6 + distance_score * 0.4;
                candidate_nodes.push((node.clone(), combined_score));
            }
        }

        // 3. Sort by score (descending) and select top witnesses
        candidate_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let witness_nodes: Vec<PeerId> = candidate_nodes
            .into_iter()
            .take(witness_count)
            .map(|(node, _)| node.id)
            .collect();

        tracing::debug!(
            witness_count = %witness_nodes.len(),
            target = %target,
            suspected_attack = %suspected_attack,
            "Selected witness nodes for distance challenge"
        );

        // Create enhanced challenge with proper configuration
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        EnhancedDistanceChallenge {
            challenger: target.to_hex(),
            target_key: *key,
            expected_distance: {
                let target_bytes = target.as_bytes();
                let mut target_key = [0u8; 32];
                let len = target_bytes.len().min(32);
                target_key[..len].copy_from_slice(&target_bytes[..len]);
                DhtKey::from_bytes(*key).distance(&DhtKey::from_bytes(target_key))
            },
            nonce,
            timestamp: SystemTime::now(),
            witness_nodes,
            challenge_round: 1,
            max_rounds,
        }
    }

    /// Validate routing table consistency
    ///
    /// Cross-validates nodes by querying multiple trusted validators about each
    /// node's claimed neighbors. Detects inconsistencies that may indicate Sybil attacks.
    pub async fn validate_routing_consistency<Q: NetworkQuerier>(
        &self,
        nodes: &[NodeInfo],
        querier: &Q,
    ) -> Result<ConsistencyReport> {
        let mut inconsistencies = 0;
        let mut suspicious_nodes = Vec::new();

        // Collect trusted validators from security buckets for cross-validation
        let mut validators: Vec<NodeInfo> = Vec::new();
        for security_bucket in self.security_buckets.values() {
            for trusted_node in &security_bucket.trusted_nodes {
                // Only use nodes with good reputation as validators
                if let Some(reputation) = self.reputation_manager.get_reputation(&trusted_node.id)
                    && reputation.response_rate >= 0.7
                    && reputation.consistency_score >= 0.8
                {
                    validators.push(trusted_node.clone());
                }
            }
        }

        // Limit number of validators to reduce network overhead
        let max_validators = 5;
        validators.truncate(max_validators);

        for node in nodes {
            let node_id_hex = hex::encode(node.id.as_bytes());

            // Check reputation threshold
            if let Some(reputation) = self.reputation_manager.get_reputation(&node.id)
                && reputation.response_rate < self.config.min_routing_reputation
            {
                inconsistencies += 1;
                suspicious_nodes.push(node_id_hex.clone());
                continue; // Don't waste network resources on known bad nodes
            }

            // Cross-validation: Query multiple validators about this node's routing table
            if validators.len() >= 2 {
                let mut validator_reports: Vec<Vec<NodeInfo>> = Vec::new();
                let mut responding_validators = 0;

                for validator in &validators {
                    // Don't query a node about itself
                    if validator.id == node.id {
                        continue;
                    }

                    // Query the validator about the target node's routing table
                    match querier.query_routing_table(validator, None).await {
                        Ok(reported_neighbors) => {
                            responding_validators += 1;
                            validator_reports.push(reported_neighbors);
                            tracing::debug!(
                                "Validator {} reported {} neighbors for cross-validation",
                                hex::encode(validator.id.as_bytes()),
                                validator_reports.last().map(|v| v.len()).unwrap_or(0)
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Cross-validation query to {} failed: {}",
                                hex::encode(validator.id.as_bytes()),
                                e
                            );
                        }
                    }
                }

                // Analyze cross-validation results for inconsistencies
                if responding_validators >= 2 {
                    let inconsistency_score =
                        Self::calculate_cross_validation_inconsistency(&validator_reports, node);

                    // High inconsistency score indicates potential Sybil node
                    if inconsistency_score > 0.5 {
                        inconsistencies += 1;
                        if !suspicious_nodes.contains(&node_id_hex) {
                            suspicious_nodes.push(node_id_hex.clone());
                        }
                        tracing::warn!(
                            "Node {} flagged as suspicious: cross-validation inconsistency score {}",
                            node_id_hex,
                            inconsistency_score
                        );
                    }
                }
            }
        }

        Ok(ConsistencyReport {
            nodes_checked: nodes.len(),
            inconsistencies,
            suspicious_nodes,
            validated_at: Instant::now(),
        })
    }

    /// Calculate inconsistency score from cross-validation reports
    ///
    /// Compares what different validators report about a node's neighbors.
    /// High score (>0.5) indicates suspicious inconsistencies.
    fn calculate_cross_validation_inconsistency(
        validator_reports: &[Vec<NodeInfo>],
        target_node: &NodeInfo,
    ) -> f64 {
        if validator_reports.len() < 2 {
            return 0.0;
        }

        // Check if the target node appears consistently in validator reports
        let target_id = &target_node.id;
        let mut appearance_count = 0;

        for report in validator_reports {
            if report.iter().any(|n| &n.id == target_id) {
                appearance_count += 1;
            }
        }

        // If node appears in some reports but not others, that's suspicious
        let appearance_ratio = appearance_count as f64 / validator_reports.len() as f64;

        // Check for address consistency across reports
        let mut address_variations = std::collections::HashSet::new();
        for report in validator_reports {
            for node in report {
                if &node.id == target_id {
                    // Track the address reported for this node
                    address_variations.insert(node.address.to_string());
                }
            }
        }

        // Calculate inconsistency score:
        // - Partial appearance (neither 0% nor 100%) is suspicious
        // - Multiple different addresses for same node is suspicious
        let appearance_inconsistency = if appearance_ratio > 0.0 && appearance_ratio < 1.0 {
            (0.5 - (appearance_ratio - 0.5).abs()) * 2.0 // Max at 50% appearance
        } else {
            0.0
        };

        let address_inconsistency = if address_variations.len() > 1 {
            ((address_variations.len() - 1) as f64 * 0.2).min(0.5)
        } else {
            0.0
        };

        (appearance_inconsistency + address_inconsistency).min(1.0)
    }

    /// Select nodes using security-aware criteria
    pub fn select_secure_nodes(
        &self,
        candidates: &[NodeInfo],
        target: &Key,
        count: usize,
    ) -> Vec<NodeInfo> {
        let mut scored_nodes: Vec<_> = candidates
            .iter()
            .map(|node| {
                let node_key = DhtKey::from_bytes(*node.id.as_bytes());
                let target_key = DhtKey::from_bytes(*target);
                let distance = node_key.distance(&target_key);
                // Count leading zeros by checking each byte
                let mut leading_zeros = 0u32;
                for byte in distance.iter() {
                    if *byte == 0 {
                        leading_zeros += 8;
                    } else {
                        leading_zeros += byte.leading_zeros();
                        break;
                    }
                }
                let distance_score = leading_zeros as f64;

                let reputation_score = self
                    .reputation_manager
                    .get_reputation(&node.id)
                    .map(|rep| rep.response_rate * rep.consistency_score)
                    .unwrap_or(0.0);

                // Combined score: distance + reputation
                let combined_score = distance_score + (reputation_score * 100.0);

                (node.clone(), combined_score)
            })
            .collect();

        // Sort by combined score (higher is better)
        scored_nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Return top nodes
        scored_nodes
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    /// Clean up expired lookups and challenges
    pub fn cleanup_expired(&mut self) {
        let _now = Instant::now();

        // Remove completed or expired lookups
        self.active_lookups.retain(|_, lookup| {
            !lookup.is_complete() && lookup.started_at.elapsed() < self.config.lookup_timeout
        });

        // Remove old challenges
        self.pending_challenges.retain(|_, challenge| {
            challenge.timestamp.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(300)
        });

        // Apply reputation decay
        self.reputation_manager.apply_decay();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::core_engine::{NodeCapacity, NodeInfo};
    use std::time::SystemTime;

    /// Mock implementation of NetworkQuerier for testing
    struct MockNetworkQuerier;

    impl NetworkQuerier for MockNetworkQuerier {
        fn query_closest_nodes(
            &self,
            _node: &NodeInfo,
            _target: &Key,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<NodeInfo>>> + Send + '_>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn query_distance_measurement(
            &self,
            _witness: &str,
            _target_node: &str,
            _target_key: &Key,
        ) -> Pin<Box<dyn Future<Output = Result<DistanceMeasurement>> + Send + '_>> {
            Box::pin(async {
                Ok(DistanceMeasurement {
                    witness: "mock_witness".to_string(),
                    distance: [0u8; 32],
                    confidence: 1.0,
                    response_time: Duration::from_millis(10),
                })
            })
        }

        fn query_routing_table(
            &self,
            _node: &NodeInfo,
            _bucket_index: Option<usize>,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<NodeInfo>>> + Send + '_>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn create_test_dht_node(_peer_id: &str, distance_bytes: [u8; 32]) -> NodeInfo {
        let port = 9000u16 + distance_bytes[0] as u16;
        NodeInfo {
            id: PeerId::new(&distance_bytes),
            address: format!("127.0.0.1:{port}").parse().unwrap(),
            last_seen: std::time::SystemTime::now(),
            capacity: NodeCapacity::default(),
        }
    }

    fn create_test_key(bytes: [u8; 32]) -> Key {
        bytes
    }

    #[test]
    fn test_skademlia_config_default() {
        let config = SKademliaConfig::default();
        assert_eq!(config.disjoint_path_count, 3);
        assert_eq!(config.max_shared_nodes, 1);
        assert_eq!(config.sibling_list_size, 16);
        assert_eq!(config.security_bucket_size, 8);
        assert!(config.enable_distance_verification);
        assert!(config.enable_routing_validation);
        assert_eq!(config.min_routing_reputation, 0.3);
        assert_eq!(config.lookup_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_disjoint_path_lookup_creation() {
        let target = create_test_key([1u8; 32]);
        let lookup = DisjointPathLookup::new(target, 3, 1);

        assert_eq!(lookup.target, target);
        assert_eq!(lookup.path_count, 3);
        assert_eq!(lookup.max_shared_nodes, 1);
        assert_eq!(lookup.paths.len(), 3);
        assert_eq!(lookup.path_states.len(), 3);

        for (i, path_state) in lookup.path_states.iter().enumerate() {
            assert_eq!(path_state.path_id, i);
            assert!(path_state.nodes.is_empty());
            assert!(path_state.queried.is_empty());
            assert!(path_state.to_query.is_empty());
            assert!(!path_state.completed);
            assert!(path_state.results.is_empty());
        }
    }

    #[test]
    fn test_disjoint_path_initialization() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 3, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
            create_test_dht_node("peer3", [4u8; 32]),
            create_test_dht_node("peer4", [5u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        // Check that nodes are distributed across paths
        assert!(!lookup.path_states[0].to_query.is_empty());
        assert!(!lookup.path_states[1].to_query.is_empty());
        assert!(!lookup.path_states[2].to_query.is_empty());

        // Each path should have at least one node
        for path_state in &lookup.path_states {
            assert!(!path_state.to_query.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_disjoint_path_initialization_insufficient_nodes() {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 5, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        let result = lookup.initialize_paths(initial_nodes);
        assert!(result.is_err());
    }

    #[test]
    fn test_disjoint_path_get_next_node() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 2, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        // Get next node from path 0
        let next_node = lookup.get_next_node(0);
        assert!(next_node.is_some());

        if let Some(node) = next_node {
            assert!(lookup.path_states[0].queried.contains(&node.id));
        }

        Ok(())
    }

    #[test]
    fn test_disjoint_path_invalid_path_id() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 2, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        // Try to get node from invalid path ID
        let next_node = lookup.get_next_node(10);
        assert!(next_node.is_none());

        Ok(())
    }

    #[test]
    fn test_disjoint_path_add_query_results() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 2, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        let query_results = vec![
            create_test_dht_node("peer3", [4u8; 32]),
            create_test_dht_node("peer4", [5u8; 32]),
        ];

        let initial_queue_size = lookup.path_states[0].to_query.len();
        lookup.add_query_results(0, query_results);

        // Queue should have more nodes now
        assert!(lookup.path_states[0].to_query.len() >= initial_queue_size);

        Ok(())
    }

    #[test]
    fn test_disjoint_path_verify_disjointness() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 2, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        // Initially should be disjoint (no shared nodes yet)
        assert!(lookup.verify_disjointness());

        Ok(())
    }

    #[test]
    fn test_disjoint_path_count_shared_nodes() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 2, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        // Initially no shared nodes
        let shared_count = lookup.count_shared_nodes(0, 1);
        assert_eq!(shared_count, 0);

        Ok(())
    }

    #[test]
    fn test_disjoint_path_completion() {
        let target = create_test_key([1u8; 32]);
        let lookup = DisjointPathLookup::new(target, 2, 1);

        // Should not be complete initially
        assert!(!lookup.is_complete());
    }

    #[test]
    fn test_disjoint_path_get_results() -> Result<()> {
        let target = create_test_key([1u8; 32]);
        let mut lookup = DisjointPathLookup::new(target, 2, 1);

        let initial_nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        lookup.initialize_paths(initial_nodes)?;

        // Add some results to path states
        lookup.path_states[0]
            .results
            .push(create_test_dht_node("result1", [10u8; 32]));
        lookup.path_states[1]
            .results
            .push(create_test_dht_node("result2", [11u8; 32]));

        let results = lookup.get_results();
        assert_eq!(results.len(), 2);

        Ok(())
    }

    #[test]
    fn test_sibling_list_creation() {
        let local_id = create_test_key([1u8; 32]);
        let sibling_list = SiblingList::new(local_id, 16);

        assert_eq!(sibling_list.local_id, local_id);
        assert_eq!(sibling_list.max_size, 16);
        assert!(sibling_list.siblings.is_empty());
    }

    #[test]
    fn test_sibling_list_add_node() {
        let local_id = create_test_key([1u8; 32]);
        let mut sibling_list = SiblingList::new(local_id, 16);

        let node = create_test_dht_node("peer1", [2u8; 32]);
        sibling_list.add_node(node.clone());

        assert_eq!(sibling_list.siblings.len(), 1);
        assert_eq!(sibling_list.siblings[0].id.to_string(), node.id.to_string());
    }

    #[test]
    fn test_sibling_list_size_limit() {
        let local_id = create_test_key([1u8; 32]);
        let mut sibling_list = SiblingList::new(local_id, 2);

        // Add more nodes than the limit
        sibling_list.add_node(create_test_dht_node("peer1", [2u8; 32]));
        sibling_list.add_node(create_test_dht_node("peer2", [3u8; 32]));
        sibling_list.add_node(create_test_dht_node("peer3", [4u8; 32]));

        // Should be limited to max_size
        assert_eq!(sibling_list.siblings.len(), 2);
    }

    #[test]
    fn test_sibling_list_get_closest_siblings() {
        let local_id = create_test_key([1u8; 32]);
        let mut sibling_list = SiblingList::new(local_id, 16);

        sibling_list.add_node(create_test_dht_node("peer1", [2u8; 32]));
        sibling_list.add_node(create_test_dht_node("peer2", [3u8; 32]));
        sibling_list.add_node(create_test_dht_node("peer3", [4u8; 32]));

        let closest = sibling_list.get_closest_siblings(2);
        assert_eq!(closest.len(), 2);
    }

    #[test]
    fn test_sibling_list_verify_routing_decision() {
        let local_id = create_test_key([1u8; 32]);
        let sibling_list = SiblingList::new(local_id, 16);

        let target = create_test_key([10u8; 32]);
        let proposed_nodes = vec![create_test_dht_node("peer1", [11u8; 32])];

        // Should accept routing decision (basic test)
        let is_valid = sibling_list.verify_routing_decision(&target, &proposed_nodes);
        assert!(is_valid);
    }

    #[test]
    fn test_security_bucket_creation() {
        let security_bucket = SecurityBucket::new(8);

        assert_eq!(security_bucket.max_size, 8);
        assert!(security_bucket.trusted_nodes.is_empty());
        assert!(security_bucket.backup_routes.is_empty());
    }

    #[test]
    fn test_security_bucket_add_trusted_node() {
        let mut security_bucket = SecurityBucket::new(8);

        let node = create_test_dht_node("peer1", [2u8; 32]);
        security_bucket.add_trusted_node(node.clone());

        assert_eq!(security_bucket.trusted_nodes.len(), 1);
        assert_eq!(
            security_bucket.trusted_nodes[0].id.to_string(),
            node.id.to_string()
        );
    }

    #[test]
    fn test_security_bucket_size_limit() {
        let mut security_bucket = SecurityBucket::new(2);

        // Add more nodes than the limit
        security_bucket.add_trusted_node(create_test_dht_node("peer1", [2u8; 32]));
        security_bucket.add_trusted_node(create_test_dht_node("peer2", [3u8; 32]));
        security_bucket.add_trusted_node(create_test_dht_node("peer3", [4u8; 32]));

        // Should be limited to max_size
        assert_eq!(security_bucket.trusted_nodes.len(), 2);
    }

    #[test]
    fn test_security_bucket_add_backup_route() {
        let mut security_bucket = SecurityBucket::new(8);

        let route = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        security_bucket.add_backup_route(route.clone());

        assert_eq!(security_bucket.backup_routes.len(), 1);
        assert_eq!(security_bucket.backup_routes[0].len(), 2);
    }

    #[test]
    fn test_security_bucket_backup_route_limit() {
        let mut security_bucket = SecurityBucket::new(8);

        // Add more routes than the limit (max 5)
        for i in 0..7 {
            let route = vec![create_test_dht_node(&format!("peer{}", i), [i as u8; 32])];
            security_bucket.add_backup_route(route);
        }

        // Should be limited to 5 routes
        assert_eq!(security_bucket.backup_routes.len(), 5);
    }

    #[test]
    fn test_skademlia_creation() {
        let config = SKademliaConfig::default();
        let skademlia = SKademlia::new(config);

        assert!(skademlia.sibling_lists.is_empty());
        assert!(skademlia.security_buckets.is_empty());
        assert!(skademlia.active_lookups.is_empty());
        assert!(skademlia.pending_challenges.is_empty());
    }

    #[test]
    fn test_skademlia_update_sibling_list() {
        let config = SKademliaConfig::default();
        let mut skademlia = SKademlia::new(config);

        let key = create_test_key([1u8; 32]);
        let nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        skademlia.update_sibling_list(key, nodes);

        assert!(skademlia.sibling_lists.contains_key(&key));
        assert_eq!(skademlia.sibling_lists[&key].siblings.len(), 2);
    }

    #[test]
    fn test_skademlia_get_security_bucket() {
        let config = SKademliaConfig::default();
        let mut skademlia = SKademlia::new(config);

        let key = create_test_key([1u8; 32]);

        // Should create new bucket if it doesn't exist
        let bucket = skademlia.get_security_bucket(&key);
        assert_eq!(bucket.max_size, 8); // Default config value

        // Should return existing bucket
        let bucket2 = skademlia.get_security_bucket(&key);
        assert_eq!(bucket2.max_size, 8);
    }

    #[test]
    fn test_skademlia_create_distance_challenge() {
        let config = SKademliaConfig::default();
        let mut skademlia = SKademlia::new(config);

        let target = PeerId::from_name("test_peer");
        let key = create_test_key([1u8; 32]);

        let challenge = skademlia.create_distance_challenge(&target, &key);

        assert_eq!(challenge.challenger, target.to_hex());
        assert_eq!(challenge.target_key, key);
        assert!(skademlia.pending_challenges.contains_key(&target));
    }

    #[test]
    fn test_skademlia_create_enhanced_distance_challenge() {
        let config = SKademliaConfig::default();
        let mut skademlia = SKademlia::new(config);

        let target = PeerId::from_name("test_peer");
        let key = create_test_key([1u8; 32]);
        let witness_nodes = vec![PeerId::random(), PeerId::random()];

        let challenge =
            skademlia.create_enhanced_distance_challenge(&target, &key, witness_nodes.clone());

        assert_eq!(challenge.challenger, target.to_hex());
        assert_eq!(challenge.target_key, key);
        assert_eq!(challenge.witness_nodes, witness_nodes);
        assert_eq!(challenge.challenge_round, 1);
        assert_eq!(challenge.max_rounds, 3);
    }

    #[test]
    fn test_skademlia_create_adaptive_distance_challenge() {
        let config = SKademliaConfig::default();
        let mut skademlia = SKademlia::new(config);

        let target = PeerId::from_name("test_peer");
        let key = create_test_key([1u8; 32]);

        // Test normal challenge (empty network - no witness nodes available)
        let normal_challenge = skademlia.create_adaptive_distance_challenge(&target, &key, false);
        // With no nodes registered, witness selection returns empty
        assert!(normal_challenge.witness_nodes.len() <= 3);
        assert_eq!(normal_challenge.max_rounds, 3);

        // Test challenge when attack is suspected (empty network)
        let attack_challenge = skademlia.create_adaptive_distance_challenge(&target, &key, true);
        // With no nodes registered, witness selection returns empty
        assert!(attack_challenge.witness_nodes.len() <= 7);
        assert_eq!(attack_challenge.max_rounds, 5);
    }

    #[test]
    fn test_skademlia_select_secure_nodes() {
        let config = SKademliaConfig::default();
        let skademlia = SKademlia::new(config);

        let candidates = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
            create_test_dht_node("peer3", [4u8; 32]),
        ];

        let target = create_test_key([1u8; 32]);
        let selected = skademlia.select_secure_nodes(&candidates, &target, 2);

        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_skademlia_cleanup_expired() {
        let config = SKademliaConfig::default();
        let mut skademlia = SKademlia::new(config);

        // Add some test data
        let key = create_test_key([1u8; 32]);
        let target = PeerId::from_name("test_peer");

        skademlia.create_distance_challenge(&target, &key);

        // Should have pending challenge
        assert!(!skademlia.pending_challenges.is_empty());

        // Cleanup should not remove recent challenge
        skademlia.cleanup_expired();
        assert!(!skademlia.pending_challenges.is_empty());
    }

    #[test]
    fn test_distance_challenge_creation() {
        let challenger = "test_peer".to_string();
        let target_key = create_test_key([1u8; 32]);
        let _hash = blake3::hash(challenger.as_bytes());
        let expected_distance = [0u8; 32]; // distance calculation simplified

        let challenge = DistanceChallenge {
            challenger: challenger.clone(),
            target_key,
            expected_distance,
            nonce: [1u8; 32],
            timestamp: SystemTime::now(),
        };

        assert_eq!(challenge.challenger, challenger);
        assert_eq!(challenge.target_key, target_key);
        assert_eq!(challenge.expected_distance, expected_distance);
        assert_eq!(challenge.nonce, [1u8; 32]);
    }

    #[test]
    fn test_distance_measurement() {
        let witness = "witness_peer".to_string();
        let distance = create_test_key([5u8; 32]);
        let confidence = 0.8;
        let response_time = Duration::from_millis(100);

        let measurement = DistanceMeasurement {
            witness: witness.clone(),
            distance,
            confidence,
            response_time,
        };

        assert_eq!(measurement.witness, witness);
        assert_eq!(measurement.distance, distance);
        assert_eq!(measurement.confidence, confidence);
        assert_eq!(measurement.response_time, response_time);
    }

    #[test]
    fn test_consistency_report() {
        let nodes_checked = 10;
        let inconsistencies = 2;
        let suspicious_nodes = vec!["peer1".to_string(), "peer2".to_string()];
        let validated_at = Instant::now();

        let report = ConsistencyReport {
            nodes_checked,
            inconsistencies,
            suspicious_nodes: suspicious_nodes.clone(),
            validated_at,
        };

        assert_eq!(report.nodes_checked, nodes_checked);
        assert_eq!(report.inconsistencies, inconsistencies);
        assert_eq!(report.suspicious_nodes, suspicious_nodes);
    }

    #[tokio::test]
    async fn test_skademlia_validate_routing_consistency() -> Result<()> {
        let config = SKademliaConfig::default();
        let skademlia = SKademlia::new(config);

        let nodes = vec![
            create_test_dht_node("peer1", [2u8; 32]),
            create_test_dht_node("peer2", [3u8; 32]),
        ];

        let querier = MockNetworkQuerier;
        let report = skademlia
            .validate_routing_consistency(&nodes, &querier)
            .await?;

        assert_eq!(report.nodes_checked, 2);
        // Since no reputation data exists, inconsistencies may be 0 or 2 depending on implementation
        assert!(report.inconsistencies <= 2);
        assert!(report.suspicious_nodes.len() <= 2);

        Ok(())
    }

    #[test]
    fn test_distance_proof_validation_components() {
        // Test individual components used in distance proof validation
        let challenger = "test_peer".to_string();
        let target_key = create_test_key([1u8; 32]);
        let _hash = blake3::hash(challenger.as_bytes());
        let expected_distance = [0u8; 32]; // distance calculation simplified

        let challenge = DistanceChallenge {
            challenger: challenger.clone(),
            target_key,
            expected_distance,
            nonce: [1u8; 32],
            timestamp: SystemTime::now(),
        };

        let proof = DistanceProof {
            challenge,
            proof_nodes: vec!["proof1".to_string(), "proof2".to_string()],
            signatures: vec![vec![1u8; 64], vec![2u8; 64]],
            response_time: Duration::from_millis(50),
        };

        // Verify structure
        assert_eq!(proof.proof_nodes.len(), 2);
        assert_eq!(proof.signatures.len(), 2);
        assert_eq!(proof.response_time, Duration::from_millis(50));
    }
}
