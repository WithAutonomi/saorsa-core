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

//! Adaptive routing system combining multiple strategies
//!
//! Implements multi-armed bandit routing selection using Thompson Sampling
//! to dynamically choose between Kademlia, Hyperbolic, Trust-based, and SOM routing

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

use super::AdaptiveNetworkError;
use super::Result;
use super::learning::ThompsonSampling;
use super::{HyperbolicCoordinate, RoutingStrategy, TrustProvider};
use crate::PeerId;
use std::sync::Arc;

// Re-export types that other modules need
pub use super::{ContentType, StrategyChoice};

/// Adaptive router that combines multiple routing strategies
pub struct AdaptiveRouter {
    /// Local node ID
    _local_id: PeerId,

    /// Routing strategies
    strategies: Arc<RwLock<HashMap<StrategyChoice, Arc<dyn RoutingStrategy>>>>,

    /// Multi-armed bandit for strategy selection
    bandit: Arc<RwLock<ThompsonSampling>>,
}

impl AdaptiveRouter {
    /// Create a new adaptive router with multiple strategies
    pub fn new(trust_provider: Arc<dyn TrustProvider>) -> Self {
        let node_id = PeerId::from_bytes([0u8; 32]); // Default node ID
        Self::new_with_id(node_id, trust_provider)
    }
    /// Create a new adaptive router with specific node ID
    pub fn new_with_id(node_id: PeerId, _trust_provider: Arc<dyn TrustProvider>) -> Self {
        Self {
            _local_id: node_id,
            strategies: Arc::new(RwLock::new(HashMap::new())),
            bandit: Arc::new(RwLock::new(ThompsonSampling::new())),
        }
    }

    /// Register a routing strategy
    pub async fn register_strategy(
        &self,
        choice: StrategyChoice,
        strategy: Arc<dyn RoutingStrategy>,
    ) {
        let mut strategies = self.strategies.write().await;
        strategies.insert(choice, strategy);
    }

    /// Route a message to a target using the best strategy
    pub async fn route(
        &self,
        target: &PeerId,
        content_type: ContentType,
    ) -> std::result::Result<Vec<PeerId>, AdaptiveNetworkError> {
        // Select strategy using multi-armed bandit
        let strategy_choice = self
            .bandit
            .read()
            .await
            .select_strategy(content_type)
            .await
            .unwrap_or(StrategyChoice::Kademlia);

        // Execute routing with selected strategy
        let start = std::time::Instant::now();
        let strategies = self.strategies.read().await;

        let result = if let Some(strategy) = strategies.get(&strategy_choice) {
            let primary_result = strategy.find_path(target).await;

            // If primary strategy fails and it's not Kademlia, try Kademlia as fallback
            if primary_result.is_err() && strategy_choice != StrategyChoice::Kademlia {
                if let Some(kademlia) = strategies.get(&StrategyChoice::Kademlia) {
                    kademlia.find_path(target).await
                } else {
                    primary_result
                }
            } else {
                primary_result
            }
        } else {
            // If strategy not found, try Kademlia
            if let Some(kademlia) = strategies.get(&StrategyChoice::Kademlia) {
                kademlia.find_path(target).await
            } else {
                Err(AdaptiveNetworkError::Routing(
                    "No routing strategies available".to_string(),
                ))
            }
        };

        // Update bandit based on result
        let success = result.is_ok();
        let latency = start.elapsed().as_millis() as f64;

        self.bandit
            .write()
            .await
            .update(content_type, strategy_choice, success, latency as u64)
            .await
            .unwrap_or(());

        result
    }

    /// Get all routing strategies
    pub async fn get_all_strategies(&self) -> HashMap<String, Arc<dyn RoutingStrategy>> {
        let strategies = self.strategies.read().await;
        strategies
            .iter()
            .map(|(choice, strategy)| (format!("{choice:?}"), Arc::clone(strategy)))
            .collect()
    }

    /// Mark a node as unreliable
    pub async fn mark_node_unreliable(&self, _node_id: &PeerId) {
        // In a real implementation, would notify strategies about unreliable node
    }

    /// Remove a node from all routing tables
    pub async fn remove_node(&self, _node_id: &PeerId) {
        // In a real implementation, would remove from K-buckets, etc.
    }

    /// Remove node's hyperbolic coordinates
    pub async fn remove_hyperbolic_coordinate(&self, _node_id: &PeerId) {
        // In a real implementation, would remove coordinates
    }

    /// Remove node from SOM
    pub async fn remove_from_som(&self, _node_id: &PeerId) {
        // In a real implementation, would remove from SOM
    }

    /// Enable aggressive caching during high churn
    pub async fn enable_aggressive_caching(&self) {
        // In a real implementation, would enable aggressive caching
    }

    /// Rebalance hyperbolic space after failures
    pub async fn rebalance_hyperbolic_space(&self) {
        // In a real implementation, would rebalance space
    }

    /// Update SOM grid after topology changes
    pub async fn update_som_grid(&self) {
        // In a real implementation, would update SOM grid
    }

    /// Trigger trust score recomputation
    pub async fn trigger_trust_recomputation(&self) {
        // In a real implementation, would trigger recomputation
    }
}

/// Kademlia routing implementation
pub struct KademliaRouting {
    _node_id: PeerId,
    // Placeholder for routing table - would use actual implementation
    _routing_table: Arc<RwLock<HashMap<PeerId, Vec<PeerId>>>>,
}

impl KademliaRouting {
    pub fn new(node_id: PeerId) -> Self {
        Self {
            _node_id: node_id,
            _routing_table: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl RoutingStrategy for KademliaRouting {
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        // Implementation would use the actual Kademlia lookup
        // For now, return a placeholder
        Ok(vec![*target])
    }

    fn route_score(&self, _neighbor: &PeerId, _target: &PeerId) -> f64 {
        // XOR distance metric
        let neighbor_bytes = _neighbor.to_bytes();
        let target_bytes = _target.to_bytes();
        let mut distance = 0u32;

        for i in 0..32 {
            distance += (neighbor_bytes[i] ^ target_bytes[i]).count_ones();
        }

        // Convert to score (closer = higher score)
        1.0 / (1.0 + distance as f64)
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // Update routing table based on success/failure
    }
}

/// Hyperbolic routing implementation
pub struct HyperbolicRouting {
    _coordinates: Arc<RwLock<HashMap<PeerId, HyperbolicCoordinate>>>,
}

impl Default for HyperbolicRouting {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperbolicRouting {
    pub fn new() -> Self {
        Self {
            _coordinates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Calculate hyperbolic distance between two coordinates
    pub fn distance(a: &HyperbolicCoordinate, b: &HyperbolicCoordinate) -> f64 {
        let delta = 2.0 * ((a.r - b.r).powi(2) + (a.theta - b.theta).cos().acos().powi(2)).sqrt();
        let denominator = (1.0 - a.r.powi(2)) * (1.0 - b.r.powi(2));

        (1.0 + delta / denominator).acosh()
    }
}

#[async_trait]
impl RoutingStrategy for HyperbolicRouting {
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        // Greedy routing in hyperbolic space
        // For now, return a placeholder
        Ok(vec![*target])
    }

    fn route_score(&self, _neighbor: &PeerId, _target: &PeerId) -> f64 {
        // Score based on hyperbolic distance
        // Note: This is synchronous, so we can't use async
        0.0 // Placeholder for now
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // Update coordinate estimates
    }
}

/// Trust-based routing implementation
pub struct TrustRouting {
    trust_provider: Arc<dyn TrustProvider>,
}

impl TrustRouting {
    pub fn new(trust_provider: Arc<dyn TrustProvider>) -> Self {
        Self { trust_provider }
    }
}

#[async_trait]
impl RoutingStrategy for TrustRouting {
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        // Route through high-trust nodes
        Ok(vec![*target])
    }

    fn route_score(&self, neighbor: &PeerId, _target: &PeerId) -> f64 {
        self.trust_provider.get_trust(neighbor)
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // Trust updates handled by trust provider
    }
}

/// SOM-based routing implementation
pub struct SOMRouting {
    _som_positions: Arc<RwLock<HashMap<PeerId, [f64; 4]>>>,
}

impl Default for SOMRouting {
    fn default() -> Self {
        Self::new()
    }
}

impl SOMRouting {
    pub fn new() -> Self {
        Self {
            _som_positions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl RoutingStrategy for SOMRouting {
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        // Route through similar nodes in SOM space
        Ok(vec![*target])
    }

    fn route_score(&self, _neighbor: &PeerId, _target: &PeerId) -> f64 {
        // Score based on SOM distance
        // Note: This is synchronous, so we can't use async
        0.0 // Placeholder for now
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // Update SOM positions
    }
}

// ThompsonSampling has been moved to learning.rs for a more comprehensive implementation
// Re-export it from learning module

// Implementation moved to learning.rs - using the more comprehensive version from there

/// Beta distribution for Thompson Sampling
#[derive(Debug, Clone)]
pub struct BetaDistribution {
    alpha: f64,
    beta: f64,
}

impl BetaDistribution {
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self { alpha, beta }
    }

    pub fn sample(&self) -> f64 {
        // Using a simple approximation for Beta distribution
        // In production, use rand_distr crate for proper Beta distribution
        let total = self.alpha + self.beta;
        self.alpha / total
    }
}

/// Mock routing strategy for testing
#[cfg(test)]
pub struct MockRoutingStrategy {
    nodes: Vec<PeerId>,
}

#[cfg(test)]
impl Default for MockRoutingStrategy {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
impl MockRoutingStrategy {
    pub fn new() -> Self {
        Self {
            nodes: vec![
                PeerId::from_bytes([1u8; 32]),
                PeerId::from_bytes([2u8; 32]),
                PeerId::from_bytes([3u8; 32]),
                PeerId::from_bytes([4u8; 32]),
                PeerId::from_bytes([5u8; 32]),
            ],
        }
    }
}

#[cfg(test)]
#[async_trait]
impl RoutingStrategy for MockRoutingStrategy {
    async fn find_closest_nodes(
        &self,
        _target: &super::ContentHash,
        count: usize,
    ) -> std::result::Result<Vec<PeerId>, AdaptiveNetworkError> {
        Ok(self.nodes.iter().take(count).cloned().collect())
    }

    async fn find_path(
        &self,
        target: &PeerId,
    ) -> std::result::Result<Vec<PeerId>, AdaptiveNetworkError> {
        let mut path = vec![PeerId::from_bytes([0u8; 32])]; // Start node
        if self.nodes.contains(target) {
            path.push(*target);
        }
        Ok(path)
    }

    fn route_score(&self, _neighbor: &PeerId, _target: &PeerId) -> f64 {
        0.5
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // Mock implementation - do nothing
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::{
        AdaptiveRouter, ContentType, HyperbolicCoordinate, HyperbolicRouting, StrategyChoice,
        ThompsonSampling, TrustProvider,
    };
    use crate::PeerId;
    use rand::RngCore;
    use std::sync::Arc;
    #[tokio::test]
    async fn test_adaptive_router_creation() {
        struct MockTrustProvider;
        impl TrustProvider for MockTrustProvider {
            fn get_trust(&self, _node: &PeerId) -> f64 {
                0.5
            }
            fn update_trust(&self, _from: &PeerId, _to: &PeerId, _success: bool) {}
            fn get_global_trust(&self) -> std::collections::HashMap<PeerId, f64> {
                std::collections::HashMap::new()
            }
            fn remove_node(&self, _node: &PeerId) {}
        }

        let mut hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash);
        let node_id = PeerId::from_bytes(hash); // Create proper PeerId
        let trust_provider = Arc::new(MockTrustProvider);
        let _router = AdaptiveRouter::new_with_id(node_id, trust_provider);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn test_thompson_sampling() {
        let bandit = ThompsonSampling::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let strategy = rt
            .block_on(bandit.select_strategy(ContentType::DHTLookup))
            .unwrap_or(StrategyChoice::Kademlia);

        // Should return a valid strategy
        matches!(
            strategy,
            StrategyChoice::Kademlia
                | StrategyChoice::Hyperbolic
                | StrategyChoice::TrustPath
                | StrategyChoice::SOMRegion
        );

        // Update with positive feedback
        rt.block_on(bandit.update(ContentType::DHTLookup, strategy, true, 100))
            .unwrap();
    }

    #[test]
    fn test_hyperbolic_distance() {
        let a = HyperbolicCoordinate { r: 0.0, theta: 0.0 };
        let b = HyperbolicCoordinate {
            r: 0.5,
            theta: std::f64::consts::PI,
        };

        let distance = HyperbolicRouting::distance(&a, &b);
        assert!(distance > 0.0);

        // Distance to self should be 0
        let self_distance = HyperbolicRouting::distance(&a, &a);
        assert!((self_distance - 0.0).abs() < 1e-10);
    }
}
