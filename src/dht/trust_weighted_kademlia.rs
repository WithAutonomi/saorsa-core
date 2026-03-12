//! Trust-weighted Kademlia DHT with EigenTrust integration
//!
//! Implements XOR-based Kademlia with trust bias for routing, eviction, and peer selection.
//! Includes capacity signaling and EigenTrust computation for peer discovery.
//!
//! ## Security Properties
//!
//! Trust scores influence node selection **only within distance magnitude buckets**, preserving
//! Kademlia's distance-first routing properties. This prevents trust manipulation attacks from
//! compromising routing correctness:
//!
//! - **Distance always takes precedence**: Nodes are first grouped by distance magnitude
//!   (leading zero count), ensuring closer nodes are always preferred
//! - **Trust acts as tiebreaker**: Within magnitude buckets (nodes at similar distances),
//!   higher-trust nodes are selected
//! - **No routing centralization**: Even maximum trust cannot override distance ordering,
//!   preventing concentration of traffic to high-trust nodes at wrong distances
//! - **Sybil resistance**: Creating many nodes with artificial trust doesn't help unless
//!   those nodes happen to be at the correct distance to the target
//!
//! The magnitude bucketing approach (factor of 2 granularity) maintains Kademlia's O(log n)
//! convergence properties while allowing trust to meaningfully reduce timeouts and improve
//! reliability among similarly-distant nodes.

use crate::identity::node_identity::PeerId;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// DHT key type (256-bit)
pub type Key = [u8; 32];

// PeerId is imported from identity::node_identity

/// Contact information for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub peer: PeerId,
    pub address: String,
    pub rtt_est: Duration,
    pub last_seen: SystemTime,
    pub trust_score: f32,
}

/// Capacity gossip message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityGossip {
    pub peer: PeerId,
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub epoch: u64,
}

/// Interaction outcome for trust recording
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Ok,
    Timeout,
    BadData,
    Refused,
}

/// Trust-weighted Kademlia DHT implementation
pub struct TrustWeightedKademlia {
    /// Local node ID
    local_id: PeerId,
    /// Kademlia routing table (160 buckets for 160-bit prefix)
    routing_table: Arc<RwLock<[KBucket; 160]>>,
    /// Trust matrix for EigenTrust computation
    trust_matrix: Arc<RwLock<HashMap<PeerId, HashMap<PeerId, f32>>>>,
    /// Recent interactions for trust computation
    interactions: Arc<RwLock<VecDeque<(PeerId, Outcome, SystemTime)>>>,
    /// EigenTrust scores
    eigen_trust_scores: Arc<RwLock<HashMap<PeerId, f32>>>,
    /// Kademlia parameters
    k: usize, // bucket size
    _alpha: usize, // parallelism factor
}

/// Kademlia bucket with trust-weighted ordering
#[derive(Debug, Clone)]
struct KBucket {
    contacts: Vec<Contact>,
    _max_size: usize,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            contacts: Vec::new(),
            _max_size: max_size,
        }
    }

    /// Add or update contact with trust bias
    fn _add_contact(&mut self, contact: Contact) {
        // Remove existing contact if present
        self.contacts.retain(|c| c.peer != contact.peer);

        // Insert in trust-biased order
        let insert_pos = self
            .contacts
            .iter()
            .position(|c| c.trust_score < contact.trust_score)
            .unwrap_or(self.contacts.len());

        self.contacts.insert(insert_pos, contact);

        // Evict least trusted if bucket is full
        if self.contacts.len() > self._max_size {
            self.contacts.pop();
        }
    }

    /// Get contacts sorted by trust bias
    fn _get_contacts(&self, count: usize) -> Vec<Contact> {
        self.contacts.iter().take(count).cloned().collect()
    }
}

impl TrustWeightedKademlia {
    /// Create new DHT instance
    pub fn new(local_id: PeerId) -> Self {
        let routing_table = Arc::new(RwLock::new(
            array_init::array_init(|_| KBucket::new(20)), // k=20
        ));

        Self {
            local_id,
            routing_table,
            trust_matrix: Arc::new(RwLock::new(HashMap::new())),
            interactions: Arc::new(RwLock::new(VecDeque::new())),
            eigen_trust_scores: Arc::new(RwLock::new(HashMap::new())),
            k: 20,
            _alpha: 3,
        }
    }

    /// Record interaction outcome for trust computation
    pub async fn record_interaction(&self, peer: PeerId, outcome: Outcome) {
        let mut interactions = self.interactions.write().await;
        interactions.push_back((peer, outcome, SystemTime::now()));

        // Keep only recent interactions (last 1000)
        while interactions.len() > 1000 {
            interactions.pop_front();
        }

        // Update trust matrix
        self.update_trust_matrix(peer, outcome).await;
    }

    /// Update trust matrix based on interaction
    async fn update_trust_matrix(&self, peer: PeerId, outcome: Outcome) {
        let mut trust_matrix = self.trust_matrix.write().await;

        // Simple trust update: good outcomes increase trust, bad decrease
        let trust_delta = match outcome {
            Outcome::Ok => 0.1,
            Outcome::Timeout => -0.2,
            Outcome::BadData => -0.3,
            Outcome::Refused => -0.1,
        };

        let local_trust = trust_matrix
            .entry(self.local_id)
            .or_insert_with(HashMap::new);
        let current_trust = local_trust.get(&peer).copied().unwrap_or(0.5);
        let new_trust = (current_trust + trust_delta).clamp(0.0, 1.0);
        local_trust.insert(peer, new_trust);
    }

    /// Compute EigenTrust scores using power iteration
    pub async fn eigen_trust_epoch(&self) {
        let trust_matrix = self.trust_matrix.read().await;
        let mut scores = HashMap::new();

        // Initialize with uniform trust
        let all_peers: HashSet<_> = trust_matrix.keys().collect();
        for peer in &all_peers {
            scores.insert(**peer, 1.0 / all_peers.len() as f32);
        }

        // Power iteration (simplified)
        for _ in 0..10 {
            let mut new_scores = HashMap::new();

            for peer in &all_peers {
                let mut score = 0.0;
                let mut total_weight = 0.0;

                for (rater, ratings) in &*trust_matrix {
                    if let Some(rating) = ratings.get(peer) {
                        let rater_score = scores.get(rater).copied().unwrap_or(0.5);
                        score += rater_score * rating;
                        total_weight += rater_score;
                    }
                }

                new_scores.insert(
                    **peer,
                    if total_weight > 0.0 {
                        score / total_weight
                    } else {
                        0.5
                    },
                );
            }

            scores = new_scores;
        }

        // Update EigenTrust scores
        let mut eigen_trust_scores = self.eigen_trust_scores.write().await;
        *eigen_trust_scores = scores;
    }

    /// Find k closest nodes to target with trust bias
    ///
    /// Uses distance bucketing: nodes are grouped by "distance magnitude" (number of
    /// leading zero bits in XOR distance). Within each magnitude group, nodes are
    /// sorted by trust (descending) then RTT (ascending).
    ///
    /// This preserves Kademlia's convergence properties while preferring trusted nodes
    /// among those at similar distances. Since distance magnitude groups nodes by
    /// powers of 2, nodes within the same bucket are "close enough" from a routing
    /// perspective, allowing trust to meaningfully influence selection.
    async fn find_closest_nodes(&self, target: &PeerId, k: usize) -> Vec<Contact> {
        let routing_table = self.routing_table.read().await;
        let eigen_trust_scores = self.eigen_trust_scores.read().await;

        let mut candidates = Vec::new();

        // Collect candidates from all buckets
        for bucket in &*routing_table {
            for contact in &bucket.contacts {
                candidates.push(contact.clone());
            }
        }

        // Sort by (distance_magnitude ASC, trust DESC, RTT ASC)
        candidates.sort_by(|a, b| {
            let a_distance = self.xor_distance(&a.peer, target);
            let b_distance = self.xor_distance(&b.peer, target);

            // Use distance magnitude (inverted leading zeros) for coarse grouping
            // Nodes within same magnitude are at similar distances (within factor of 2)
            let a_magnitude = Self::distance_magnitude(&a_distance);
            let b_magnitude = Self::distance_magnitude(&b_distance);

            let a_trust = eigen_trust_scores.get(&a.peer).copied().unwrap_or(0.5);
            let b_trust = eigen_trust_scores.get(&b.peer).copied().unwrap_or(0.5);

            // Sort: closer first (smaller magnitude), then higher trust, then lower RTT
            a_magnitude
                .cmp(&b_magnitude)
                .then_with(|| {
                    b_trust
                        .partial_cmp(&a_trust)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.rtt_est.cmp(&b.rtt_est))
        });

        candidates.into_iter().take(k).collect()
    }

    /// Calculate distance magnitude as inverted leading zeros count
    ///
    /// Returns a value where smaller = closer to target.
    /// Nodes with the same magnitude are within a factor of 2 in actual distance,
    /// making them effectively equivalent from a Kademlia routing perspective.
    ///
    /// # Returns
    /// - `0`: Self-lookup (all bits zero - edge case)
    /// - `1-256`: Distance magnitude where 1 = furthest, 256 = closest non-zero
    ///
    /// # Edge Cases
    /// - All-zero distance (self-lookup): returns 0
    /// - All-ones distance (maximum): returns 256
    ///
    /// # Security Note
    /// Trust scores only influence selection within magnitude buckets, preserving
    /// Kademlia's distance-first routing properties. This prevents trust score
    /// manipulation from compromising routing correctness.
    fn distance_magnitude(distance: &[u8; 32]) -> u16 {
        let mut leading_zeros = 0u16;
        for byte in distance {
            if *byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros() as u16;
                break;
            }
        }
        // Invert: max 256 bits, so 256 - leading_zeros gives smaller = closer
        256u16.saturating_sub(leading_zeros)
    }

    /// Calculate XOR distance between two node IDs
    fn xor_distance(&self, a: &PeerId, b: &PeerId) -> [u8; 32] {
        let mut result = [0u8; 32];
        let a_bytes = a.to_bytes();
        let b_bytes = b.to_bytes();

        for (i, out) in result.iter_mut().enumerate() {
            *out = a_bytes[i] ^ b_bytes[i];
        }
        result
    }

    /// Update routing table with new contact
    async fn _update_routing_table(&self, contact: Contact) {
        let bucket_index = self._bucket_index(&contact.peer);
        let mut routing_table = self.routing_table.write().await;
        routing_table[bucket_index]._add_contact(contact);
    }
}

// PeerId::to_bytes() is already implemented in identity/node_identity.rs

impl TrustWeightedKademlia {
    fn _bucket_index(&self, peer: &PeerId) -> usize {
        // Calculate bucket index based on XOR distance from local node
        let distance = self.xor_distance(&self.local_id, peer);

        // Find the highest bit set in the distance
        for (i, &byte) in distance.iter().enumerate() {
            if byte != 0 {
                return i * 8 + (7 - byte.leading_zeros() as usize);
            }
        }

        0 // Fallback for identical nodes
    }
}

/// DHT trait implementation
#[async_trait::async_trait]
impl super::Dht for TrustWeightedKademlia {
    async fn find_node(&self, target: super::PeerId) -> Result<Vec<super::Contact>> {
        let closest = self.find_closest_nodes(&target, self.k).await;
        let converted: Vec<super::Contact> = closest
            .into_iter()
            .map(|contact| super::Contact {
                peer: contact.peer,
                address: contact.address,
            })
            .collect();
        Ok(converted)
    }
}

/// Global trust recording function
pub async fn record_interaction(_peer: PeerId, _outcome: Outcome) {
    // This would need to be implemented with a global DHT instance
    // For now, this is a placeholder
}

/// Global EigenTrust computation
pub async fn eigen_trust_epoch() {
    // This would need to be implemented with a global DHT instance
    // For now, this is a placeholder
}
