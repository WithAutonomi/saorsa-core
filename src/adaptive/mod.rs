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

//! Adaptive P2P Network — Trust & Reputation
//!
//! Provides EigenTrust++ for decentralized reputation management.

#![allow(missing_docs)]

use crate::PeerId;

pub mod trust;

// Re-export essential trust types
pub use trust::{EigenTrustEngine, NodeStatisticsUpdate};

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

/// Trust provider trait for reputation queries
///
/// Provides a unified interface for trust scoring and management.
/// Implementations should maintain a global trust vector that can be
/// queried for individual nodes or in aggregate.
pub trait TrustProvider: Send + Sync {
    /// Get trust score for a node (0.0 = untrusted, 1.0 = fully trusted)
    fn get_trust(&self, node: &PeerId) -> f64;

    /// Update trust based on interaction outcome
    #[allow(dead_code)]
    fn update_trust(&self, from: &PeerId, to: &PeerId, success: bool);

    /// Get global trust vector for all known nodes
    #[allow(dead_code)]
    fn get_global_trust(&self) -> std::collections::HashMap<PeerId, f64>;

    /// Remove a node from the trust system
    #[allow(dead_code)]
    fn remove_node(&self, node: &PeerId);
}
