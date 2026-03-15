//! Distributed Hash Table implementations
//!
//! This module provides the DHT as a **peer phonebook**: routing table,
//! peer discovery, liveness, and trust-weighted selection. Data storage
//! and replication are handled by the application layer (saorsa-node).

pub mod core_engine;
pub mod geographic_routing;
pub mod network_integration;
pub mod routing_maintenance;

// Re-export core engine types
pub use core_engine::{DhtCoreEngine, DhtKey};

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DHT key type (256-bit)
pub type Key = [u8; 32];

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

#[cfg(test)]
mod security_tests;
