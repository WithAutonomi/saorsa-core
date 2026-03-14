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

//! Adaptive P2P Network Implementation
//!
//! This module implements the adaptive P2P network architecture described in the
//! network documentation, combining multiple distributed systems technologies:
//! - Secure Kademlia (S/Kademlia) as the foundational DHT layer
//! - Hyperbolic geometry routing for efficient greedy routing
//! - Self-Organizing Maps (SOM) for content and capability clustering
//! - EigenTrust++ for decentralized reputation management
//! - Adaptive GossipSub for scalable message propagation
//! - Machine learning systems for routing optimization, caching, and churn prediction

#![allow(missing_docs)]

use crate::PeerId;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod beta_distribution;
pub mod churn;
pub mod churn_prediction;
pub mod coordinator;
pub mod coordinator_extensions;
pub mod dht_integration;
pub mod eviction;
pub mod gossip;
pub mod hyperbolic;
pub mod learning;
pub mod monitoring;
pub mod multi_armed_bandit;
pub mod q_learning_cache;
pub mod routing;
pub mod security;
pub mod trust;

// Re-export commonly used types
pub use crate::identity::NodeIdentity;
pub use churn::{ChurnConfig, ChurnHandler, NodeMonitor, NodeState};
pub use coordinator::{NetworkConfig, NetworkCoordinator};
pub use dht_integration::{
    AdaptiveDHT, AdaptiveDhtConfig, AdaptiveDhtDependencies, KademliaRoutingStrategy,
};
pub use eviction::{
    AdaptiveStrategy, CacheState, EvictionStrategy, EvictionStrategyType, FIFOStrategy,
    LFUStrategy, LRUStrategy,
};
pub use gossip::AdaptiveGossipSub;
pub use hyperbolic::{HyperbolicRoutingStrategy, HyperbolicSpace};
pub use learning::{ChurnPredictor, QLearnCacheManager, ThompsonSampling};
pub use monitoring::{
    Alert, AlertManager, DashboardData, MonitoringConfig, MonitoringSystem, NetworkHealth,
};
pub use multi_armed_bandit::{
    MABConfig, MABRoutingStrategy, MultiArmedBandit, RouteDecision, RouteId,
};
pub use q_learning_cache::{
    AccessInfo, CacheAction, CacheStatistics, QLearnCacheManager as QLearningCacheManager,
    QLearningConfig, StateVector,
};
pub use routing::AdaptiveRouter;
pub use security::{
    BlacklistManager, EclipseDetector, RateLimiter, SecurityAuditor, SecurityConfig,
    SecurityManager,
};
pub use trust::{
    EigenTrustEngine, MockTrustProvider, NodeStatistics, NodeStatisticsUpdate,
    TrustBasedRoutingStrategy, TrustRoutingConfig,
};

/// Result type for adaptive network operations
pub type Result<T> = std::result::Result<T, AdaptiveNetworkError>;

/// Core error type for the adaptive network
#[derive(Debug, thiserror::Error)]
pub enum AdaptiveNetworkError {
    #[error("Routing error: {0}")]
    Routing(String),

    #[error("Trust calculation error: {0}")]
    Trust(String),

    #[error("Learning system error: {0}")]
    Learning(String),

    #[error("Gossip error: {0}")]
    Gossip(String),

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for AdaptiveNetworkError {
    fn from(e: anyhow::Error) -> Self {
        AdaptiveNetworkError::Network(std::io::Error::other(e.to_string()))
    }
}

impl From<crate::error::P2PError> for AdaptiveNetworkError {
    fn from(e: crate::error::P2PError) -> Self {
        AdaptiveNetworkError::Network(std::io::Error::other(e.to_string()))
    }
}

/// Content hash type used throughout the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Create from bytes
    pub fn from(data: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        if data.len() >= 32 {
            hash.copy_from_slice(&data[..32]);
        } else {
            let hashed = blake3::hash(data);
            hash.copy_from_slice(hashed.as_bytes());
        }
        Self(hash)
    }
}

/// Network message type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message ID
    pub id: String,
    /// Sender node ID
    pub sender: PeerId,
    /// Message content
    pub content: Vec<u8>,
    /// Message type
    pub msg_type: ContentType,
    /// Timestamp (Unix timestamp in seconds)
    pub timestamp: u64,
}

/// Node descriptor containing all information about a peer
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    pub id: PeerId,
    // PQC-only: ML-DSA public key
    pub public_key: crate::quantum_crypto::saorsa_transport_integration::MlDsaPublicKey,
    pub addresses: Vec<crate::address::MultiAddr>,
    pub hyperbolic: Option<HyperbolicCoordinate>,
    pub som_position: Option<[f64; 4]>,
    pub trust: f64,
    pub capabilities: NodeCapabilities,
}

/// Hyperbolic coordinate in Poincaré disk model
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HyperbolicCoordinate {
    pub r: f64,     // Radial coordinate [0, 1)
    pub theta: f64, // Angular coordinate [0, 2π)
}

/// Node capabilities for resource discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub compute: u64,   // Benchmark score
    pub bandwidth: u64, // Mbps available
}

/// Core trait for adaptive P2P network nodes (peer phonebook only)
#[async_trait]
pub trait AdaptiveNetworkNode: Send + Sync {
    /// Join the network using bootstrap nodes
    async fn join(&mut self, bootstrap: Vec<NodeDescriptor>) -> Result<()>;

    /// Publish a message to a gossip topic
    async fn publish(&self, topic: &str, message: Vec<u8>) -> Result<()>;

    /// Subscribe to a gossip topic
    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<Box<dyn futures::Stream<Item = Vec<u8>> + Send>>;

    /// Get current node information
    async fn node_info(&self) -> Result<NodeDescriptor>;

    /// Get network statistics
    async fn network_stats(&self) -> Result<NetworkStats>;

    /// Gracefully shutdown the node
    async fn shutdown(self) -> Result<()>;
}

/// Network statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub connected_peers: usize,
    pub routing_success_rate: f64,
    pub average_trust_score: f64,
    pub cache_hit_rate: f64,
    pub churn_rate: f64,
}

/// Routing strategy trait for different routing algorithms
#[async_trait]
pub trait RoutingStrategy: Send + Sync {
    /// Find a path to the target node
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>>;

    /// Calculate routing score for a neighbor towards a target
    fn route_score(&self, neighbor: &PeerId, target: &PeerId) -> f64;

    /// Update routing metrics based on success/failure
    fn update_metrics(&self, path: &[PeerId], success: bool);

    /// Find closest nodes to a content hash
    async fn find_closest_nodes(
        &self,
        content_hash: &ContentHash,
        _count: usize,
    ) -> Result<Vec<PeerId>> {
        // Default implementation uses node ID from content hash
        let target = PeerId::from_bytes(content_hash.0);
        self.find_path(&target).await
    }
}

/// Trust provider trait for reputation queries
///
/// Provides a unified interface for trust scoring and management.
/// Implementations should maintain a global trust vector that can be
/// queried for individual nodes or in aggregate.
pub trait TrustProvider: Send + Sync {
    /// Get trust score for a node (0.0 = untrusted, 1.0 = fully trusted)
    fn get_trust(&self, node: &PeerId) -> f64;

    /// Update trust based on interaction outcome
    fn update_trust(&self, from: &PeerId, to: &PeerId, success: bool);

    /// Get global trust vector for all known nodes
    fn get_global_trust(&self) -> std::collections::HashMap<PeerId, f64>;

    /// Remove a node from the trust system
    fn remove_node(&self, node: &PeerId);

    // Note: get_trust_score was removed as redundant alias for get_trust
}

/// Learning system trait for adaptive behavior
#[async_trait]
pub trait LearningSystem: Send + Sync {
    /// Select optimal strategy based on context
    async fn select_strategy(&self, context: &LearningContext) -> StrategyChoice;

    /// Update learning model with outcome
    async fn update(
        &mut self,
        context: &LearningContext,
        choice: &StrategyChoice,
        outcome: &Outcome,
    );

    /// Get current model performance metrics
    async fn metrics(&self) -> LearningMetrics;
}

/// Context for learning decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningContext {
    pub content_type: ContentType,
    pub network_conditions: NetworkConditions,
    pub historical_performance: Vec<f64>,
}

/// Content type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentType {
    DHTLookup,
    ComputeRequest,
    RealtimeMessage,
    DiscoveryProbe,
}

/// Current network conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConditions {
    pub connected_peers: usize,
    pub avg_latency_ms: f64,
    pub churn_rate: f64,
}

/// Strategy choice made by learning system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StrategyChoice {
    Kademlia,
    Hyperbolic,
    TrustPath,
    SOMRegion,
}

/// Outcome of a strategy choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub success: bool,
    pub latency_ms: u64,
    pub hops: usize,
}

/// Learning system performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningMetrics {
    pub total_decisions: u64,
    pub success_rate: f64,
    pub avg_latency_ms: f64,
    pub strategy_performance: std::collections::HashMap<StrategyChoice, f64>,
}

#[cfg(test)]
mod timestamp_tests;

#[cfg(test)]
mod coordinator_extensions_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash_serialization() {
        let hash = ContentHash([42u8; 32]);
        let serialized = postcard::to_stdvec(&hash).unwrap();
        let deserialized: ContentHash = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_hyperbolic_coordinate_bounds() {
        let coord = HyperbolicCoordinate {
            r: 0.5,
            theta: std::f64::consts::PI,
        };
        assert!(coord.r >= 0.0 && coord.r < 1.0);
        assert!(coord.theta >= 0.0 && coord.theta < 2.0 * std::f64::consts::PI);
    }
}
