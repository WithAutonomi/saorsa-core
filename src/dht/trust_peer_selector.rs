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

//! Trust-aware peer selection for DHT operations
//!
//! This module provides peer selection that combines XOR distance (Kademlia)
//! with EigenTrust scores to prefer higher-trust nodes while maintaining
//! network coverage.
//!
//! ## Scoring Formula
//!
//! The combined score for peer selection is:
//! ```text
//! score = distance_score * (α + (1-α) * trust)
//! ```
//!
//! Where:
//! - `distance_score` = 1.0 / (1.0 + normalized_distance)
//! - `trust` = EigenTrust score (0.0-1.0)
//! - `α` = minimum trust weight (ensures untrusted nodes still considered)
//!
//! ## Features
//!
//! - Weighted scoring combining distance and trust
//! - Configurable trust emphasis for different operations
//! - Graceful fallback when trust engine unavailable
//! - Never panics - all operations return safe defaults

use crate::PeerId;
use crate::adaptive::TrustProvider;
use crate::dht::core_engine::{DhtKey, NodeInfo};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Dampening factor for normalizing XOR distance to a 0-1 score.
/// This value (1e30) is chosen to map the u128 distance range to reasonable
/// f64 values for score calculation.
const DISTANCE_DAMPENING_FACTOR: f64 = 1e30;

/// Configuration for trust-weighted peer selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSelectionConfig {
    /// Minimum weight given to trust factor (0.0-1.0)
    /// Higher values = more emphasis on trust vs distance
    /// Default: 0.3 (30% minimum weight for trust factor)
    pub trust_weight: f64,

    /// Minimum trust score to consider a node
    /// Nodes below this are deprioritized but not necessarily excluded
    /// Default: 0.1
    pub min_trust_threshold: f64,

    /// Whether to completely exclude nodes below threshold
    /// If false, low-trust nodes are deprioritized but can still be selected
    /// Default: false
    pub exclude_untrusted: bool,
}

impl Default for TrustSelectionConfig {
    fn default() -> Self {
        Self {
            trust_weight: 0.3,
            min_trust_threshold: 0.1,
            exclude_untrusted: false,
        }
    }
}

/// Peer selector that combines XOR distance with trust scores
///
/// This selector wraps a trust provider and uses it to score peers
/// for DHT operations. When no trust provider is available, it falls
/// back to pure distance-based selection.
pub struct TrustAwarePeerSelector<T: TrustProvider> {
    trust_provider: Arc<T>,
    config: TrustSelectionConfig,
}

impl<T: TrustProvider> TrustAwarePeerSelector<T> {
    /// Create a new trust-aware peer selector
    pub fn new(trust_provider: Arc<T>, config: TrustSelectionConfig) -> Self {
        Self {
            trust_provider,
            config,
        }
    }

    /// Select best peers for a lookup operation
    ///
    /// Returns up to `count` peers, sorted by combined distance/trust score.
    /// Higher scores are better (closer and more trusted).
    pub fn select_peers(
        &self,
        key: &DhtKey,
        candidates: &[NodeInfo],
        count: usize,
    ) -> Vec<NodeInfo> {
        self.select_peers_with_config(key, candidates, count, &self.config)
    }

    /// Internal peer selection with specified config
    fn select_peers_with_config(
        &self,
        key: &DhtKey,
        candidates: &[NodeInfo],
        count: usize,
        config: &TrustSelectionConfig,
    ) -> Vec<NodeInfo> {
        if candidates.is_empty() {
            return vec![];
        }

        // Score each candidate, filtering NaN during collection for efficiency
        let mut scored: Vec<(NodeInfo, f64)> = candidates
            .iter()
            .filter_map(|node| {
                let trust = self.get_trust_for_node(&node.id);

                // Apply exclusion filter if configured
                if config.exclude_untrusted && trust < config.min_trust_threshold {
                    return None;
                }

                let score = self.compute_score(key, node, trust, config);
                // Filter NaN during collection rather than after
                if score.is_nan() {
                    return None;
                }
                Some((node.clone(), score))
            })
            .collect();

        // Sort by score descending (higher is better)
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));

        // Take top `count` peers
        scored
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    /// Compute combined score for a node
    ///
    /// Formula: distance_score * (α + (1-α) * trust)
    /// - distance_score: inversely proportional to XOR distance
    /// - α (trust_weight): minimum multiplier ensuring untrusted nodes get some score
    /// - trust: EigenTrust score from provider
    fn compute_score(
        &self,
        key: &DhtKey,
        node: &NodeInfo,
        trust: f64,
        config: &TrustSelectionConfig,
    ) -> f64 {
        // Calculate XOR distance
        let distance = xor_distance(key, &node.id);

        // Convert distance to score (closer = higher score)
        // Use exponential dampening to handle the full u128 range
        let distance_score = 1.0 / (1.0 + (distance as f64) / DISTANCE_DAMPENING_FACTOR);

        // Combine with trust score
        // Formula ensures even trust=0 nodes get α * distance_score
        let alpha = config.trust_weight;
        let trust_factor = alpha + (1.0 - alpha) * trust;

        distance_score * trust_factor
    }

    /// Get trust score for a DHT node ID.
    fn get_trust_for_node(&self, node_id: &PeerId) -> f64 {
        self.trust_provider.get_trust(node_id)
    }

    /// Get the current configuration
    pub fn config(&self) -> &TrustSelectionConfig {
        &self.config
    }
}

/// Calculate XOR distance between a key and a node ID
///
/// Returns the distance as a u128 (using first 16 bytes for comparison).
/// This is sufficient for relative ordering since XOR distance is metric.
fn xor_distance(key: &DhtKey, node_id: &PeerId) -> u128 {
    let key_bytes = key.as_bytes();
    let node_bytes = node_id.as_bytes();

    let mut distance: u128 = 0;
    for i in 0..16 {
        distance = (distance << 8) | ((key_bytes[i] ^ node_bytes[i]) as u128);
    }
    distance
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::MockTrustProvider;
    use std::time::SystemTime;

    fn make_node(id_byte: u8) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes([id_byte; 32]),
            address: format!("127.0.0.1:{}", 9000 + id_byte as u16)
                .parse()
                .unwrap(),
            last_seen: SystemTime::now(),
            capacity: crate::dht::core_engine::NodeCapacity::default(),
        }
    }

    #[test]
    fn test_xor_distance() {
        let key = DhtKey::from_bytes([0u8; 32]);
        let node_same = PeerId::from_bytes([0u8; 32]);
        let node_far = PeerId::from_bytes([255u8; 32]);

        assert_eq!(xor_distance(&key, &node_same), 0);
        assert!(xor_distance(&key, &node_far) > 0);
    }

    #[test]
    fn test_select_peers_empty_candidates() {
        let trust = Arc::new(MockTrustProvider::new());
        let selector = TrustAwarePeerSelector::new(trust, TrustSelectionConfig::default());

        let key = DhtKey::from_bytes([42u8; 32]);
        let result = selector.select_peers(&key, &[], 5);

        assert!(result.is_empty());
    }

    #[test]
    fn test_select_peers_prefers_closer_nodes() {
        let trust = Arc::new(MockTrustProvider::new());
        let selector = TrustAwarePeerSelector::new(trust, TrustSelectionConfig::default());

        let key = DhtKey::from_bytes([0u8; 32]);
        let candidates = vec![
            make_node(100), // Further from key
            make_node(1),   // Closer to key
            make_node(50),  // Medium distance
        ];

        let result = selector.select_peers(&key, &candidates, 3);

        assert_eq!(result.len(), 3);
        // Closest node should be first (node with id_byte=1)
        assert_eq!(result.first().unwrap().id.as_bytes()[0], 1);
    }

    #[test]
    fn test_select_peers_with_count_limit() {
        let trust = Arc::new(MockTrustProvider::new());
        let selector = TrustAwarePeerSelector::new(trust, TrustSelectionConfig::default());

        let key = DhtKey::from_bytes([0u8; 32]);
        let candidates: Vec<NodeInfo> = (1..=10).map(make_node).collect();

        let result = selector.select_peers(&key, &candidates, 3);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_default_config_includes_untrusted() {
        let trust = Arc::new(MockTrustProvider::new());
        let selector = TrustAwarePeerSelector::new(trust, TrustSelectionConfig::default());

        let key = DhtKey::from_bytes([0u8; 32]);
        let candidates = vec![make_node(1), make_node(2), make_node(3)];

        // Default config doesn't exclude untrusted
        let result = selector.select_peers(&key, &candidates, 3);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_default_config_values() {
        let config = TrustSelectionConfig::default();
        assert!((config.trust_weight - 0.3).abs() < f64::EPSILON);
        assert!((config.min_trust_threshold - 0.1).abs() < f64::EPSILON);
        assert!(!config.exclude_untrusted);
    }
}
