//! Distributed Hash Table implementations
//!
//! This module provides the DHT as a **peer phonebook**: routing table,
//! peer discovery, liveness, and trust-weighted selection. Data storage
//! and replication are handled by the application layer (saorsa-node).

pub mod capacity_signaling;
pub mod core_engine;
pub mod telemetry;
pub mod trust_weighted_dht;
pub mod trust_weighted_kademlia;

// Re-export the main DHT trait and types
pub use trust_weighted_dht::{Contact, Dht, Key, Outcome, eigen_trust_epoch, record_interaction};

// Re-export PeerId from trust_weighted_dht
pub use trust_weighted_dht::PeerId;

// Re-export the trust-weighted implementation
pub use trust_weighted_kademlia::TrustWeightedKademlia;

// Re-export capacity signaling
pub use capacity_signaling::{CapacityGossip, CapacityHistogram, CapacityManager, CapacityStats};

// Re-export telemetry
pub use telemetry::{DhtTelemetry, OperationStats, OperationType, TelemetryStats};

// Re-export existing DHT components
pub use core_engine::{
    DhtCoreEngine, DhtKey, DhtRequestWrapper, DhtResponseWrapper, NodeCapacity, NodeInfo,
};

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DHT configuration parameters (peer phonebook only — no data storage)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTConfig {
    /// Maximum nodes per k-bucket
    pub bucket_size: usize,
    /// Concurrency parameter for parallel lookups
    pub alpha: usize,
    /// Refresh interval for buckets
    pub bucket_refresh_interval: Duration,
    /// Maximum distance for considering nodes "close"
    pub max_distance: u8,
}

impl Default for DHTConfig {
    fn default() -> Self {
        Self {
            bucket_size: 20,
            alpha: 3,
            bucket_refresh_interval: Duration::from_secs(3600),
            max_distance: 160,
        }
    }
}

pub mod geographic_network_integration;
pub mod geographic_routing;
pub mod geographic_routing_table;
pub mod latency_aware_selection;
pub mod network_integration;
pub mod skademlia;

/// IPv6-based DHT identity for security parity
pub mod ipv6_identity;

/// IPv4-based DHT identity for security parity
pub mod ipv4_identity;

/// Node age verification for anti-Sybil protection
pub mod node_age_verifier;

/// Sybil attack detection for DHT protection
pub mod sybil_detector;

/// Authenticated sibling broadcast for eclipse attack prevention
pub mod authenticated_sibling_broadcast;

/// Routing table maintenance and node validation
pub mod routing_maintenance;

/// Comprehensive metrics for security, DHT health, and trust
pub mod metrics;

/// Trust-aware peer selection combining XOR distance with EigenTrust scores
pub mod trust_peer_selector;

// Re-export trust peer selector types
pub use trust_peer_selector::{TrustAwarePeerSelector, TrustSelectionConfig};

// Re-export routing maintenance types for convenience
pub use routing_maintenance::{
    BucketRefreshManager, EvictionManager, EvictionReason, MaintenanceConfig, MaintenanceScheduler,
    MaintenanceTask, NodeLivenessState, NodeValidationResult, RefreshTier, ValidationFailure,
};

// Re-export security coordinator types
pub use routing_maintenance::{
    CloseGroupEviction, CloseGroupEvictionTracker, EvictionRecord, SecurityCoordinator,
    SecurityCoordinatorConfig,
};

// Re-export close group validator types
pub use routing_maintenance::close_group_validator::{
    AttackIndicators, CloseGroupFailure, CloseGroupHistory, CloseGroupResponse,
    CloseGroupValidationResult, CloseGroupValidator, CloseGroupValidatorConfig,
};

// Re-export sybil detector types for DHT protection
pub use sybil_detector::{
    BehaviorProfile, JoinRecord, SybilDetector, SybilDetectorConfig, SybilEvidence, SybilGroup,
};

// Re-export authenticated sibling broadcast types
pub use authenticated_sibling_broadcast::{
    AuthenticatedSiblingBroadcast, BroadcastValidationFailure, BroadcastValidationResult,
    MembershipProof, MembershipProofType, SiblingBroadcastBuilder, SiblingBroadcastConfig,
    SiblingBroadcastValidator, SignedSiblingEntry,
};

// Re-export comprehensive metrics types for security, DHT health, and trust
pub use metrics::{
    DhtHealthMetrics, DhtMetricsAggregator, DhtMetricsCollector, MetricsSummary, SecurityMetrics,
    SecurityMetricsCollector, TrustMetrics, TrustMetricsCollector,
};

#[cfg(test)]
mod security_tests;
