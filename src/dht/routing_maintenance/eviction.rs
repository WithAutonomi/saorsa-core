//! Reputation-based node eviction
//!
//! Manages eviction decisions based on:
//! - Consecutive communication failures
//! - Low trust scores (EigenTrust integration)
//! - Failed validation checks
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;

use crate::PeerId;

use super::config::MaintenanceConfig;
use super::liveness::NodeLivenessState;

/// Reasons why a node might be evicted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionReason {
    /// Too many consecutive communication failures
    ConsecutiveFailures(u32),
    /// Trust score fell below minimum threshold
    LowTrust(String), // String representation of f64 for Eq
    /// Close group consensus: node is no longer valid
    CloseGroupRejection,
}

/// Manages eviction decisions for nodes
pub struct EvictionManager {
    /// Configuration for eviction thresholds
    config: MaintenanceConfig,
    /// Liveness state for each tracked node
    liveness_states: HashMap<PeerId, NodeLivenessState>,
    /// Trust scores (from EigenTrust integration)
    trust_scores: HashMap<PeerId, f64>,
    /// Nodes explicitly marked for eviction with reason
    marked_for_eviction: HashMap<PeerId, EvictionReason>,
}

impl EvictionManager {
    /// Create a new eviction manager
    #[must_use]
    pub fn new(config: MaintenanceConfig) -> Self {
        Self {
            config,
            liveness_states: HashMap::new(),
            trust_scores: HashMap::new(),
            marked_for_eviction: HashMap::new(),
        }
    }

    /// Mark a node for eviction with a specific reason
    pub fn record_eviction(&mut self, node_id: &PeerId, reason: EvictionReason) {
        self.marked_for_eviction.insert(*node_id, reason);
    }

    /// Get trust score for a node
    #[must_use]
    pub fn get_trust_score(&self, node_id: &PeerId) -> Option<f64> {
        self.trust_scores.get(node_id).copied()
    }

    /// Get the eviction reason if any
    #[must_use]
    pub fn get_eviction_reason(&self, node_id: &PeerId) -> Option<EvictionReason> {
        // Check explicitly marked nodes first (highest priority)
        if let Some(reason) = self.marked_for_eviction.get(node_id) {
            return Some(reason.clone());
        }

        // Check consecutive failures (most common)
        if let Some(state) = self
            .liveness_states
            .get(node_id)
            .filter(|s| s.should_evict(&self.config))
        {
            return Some(EvictionReason::ConsecutiveFailures(
                state.consecutive_failures,
            ));
        }

        // Check trust score
        if let Some(&score) = self
            .trust_scores
            .get(node_id)
            .filter(|&&s| s < self.config.min_trust_threshold)
        {
            return Some(EvictionReason::LowTrust(format!("{:.4}", score)));
        }

        None
    }

    /// Get list of all nodes that should be evicted
    #[must_use]
    pub fn get_eviction_candidates(&self) -> Vec<(PeerId, EvictionReason)> {
        let mut candidates = Vec::new();

        // Check explicitly marked nodes first (highest priority)
        for (node_id, reason) in &self.marked_for_eviction {
            candidates.push((*node_id, reason.clone()));
        }

        // Check all nodes in liveness states
        for node_id in self.liveness_states.keys() {
            if self.marked_for_eviction.contains_key(node_id) {
                continue;
            }
            if let Some(reason) = self.get_eviction_reason(node_id) {
                candidates.push((*node_id, reason));
            }
        }

        // Also check nodes only in trust scores
        for node_id in self.trust_scores.keys() {
            if self.marked_for_eviction.contains_key(node_id)
                || self.liveness_states.contains_key(node_id)
            {
                continue;
            }
            if let Some(reason) = self.get_eviction_reason(node_id) {
                candidates.push((*node_id, reason));
            }
        }

        candidates
    }

    /// Remove a node from tracking (after eviction)
    pub fn remove_node(&mut self, node_id: &PeerId) {
        self.liveness_states.remove(node_id);
        self.trust_scores.remove(node_id);
        self.marked_for_eviction.remove(node_id);
    }
}

/// Test-only methods
#[cfg(test)]
impl EvictionManager {
    pub fn with_trust(config: MaintenanceConfig, trust_scores: HashMap<PeerId, f64>) -> Self {
        Self {
            config,
            liveness_states: HashMap::new(),
            trust_scores,
            marked_for_eviction: HashMap::new(),
        }
    }

    pub fn record_failure(&mut self, node_id: &PeerId) {
        let state = self.liveness_states.entry(*node_id).or_default();
        state.record_failure();
    }

    pub fn record_success(&mut self, node_id: &PeerId) {
        let state = self.liveness_states.entry(*node_id).or_default();
        state.record_success();
    }

    pub fn update_trust_score(&mut self, node_id: &PeerId, score: f64) {
        self.trust_scores.insert(*node_id, score);
    }

    pub fn get_consecutive_failures(&self, node_id: &PeerId) -> u32 {
        self.liveness_states
            .get(node_id)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    pub fn should_evict(&self, node_id: &PeerId) -> bool {
        self.liveness_states
            .get(node_id)
            .map(|s| s.should_evict(&self.config))
            .unwrap_or(false)
    }

    pub fn should_evict_for_trust(&self, node_id: &PeerId) -> bool {
        self.trust_scores
            .get(node_id)
            .map(|&score| score < self.config.min_trust_threshold)
            .unwrap_or(false)
    }

    pub fn get_liveness_state(&self, node_id: &PeerId) -> Option<&NodeLivenessState> {
        self.liveness_states.get(node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_evict_after_consecutive_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.record_failure(&node_id);
        assert!(!manager.should_evict(&node_id));

        manager.record_failure(&node_id);
        assert!(manager.should_evict(&node_id));
    }

    #[test]
    fn test_evict_for_low_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let node_id = make_node_id();
        let mut trust_scores = HashMap::new();
        trust_scores.insert(node_id, 0.10);

        let manager = EvictionManager::with_trust(config, trust_scores);
        assert!(manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_no_evict_for_good_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let node_id = make_node_id();
        let mut trust_scores = HashMap::new();
        trust_scores.insert(node_id, 0.50);

        let manager = EvictionManager::with_trust(config, trust_scores);
        assert!(!manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.record_failure(&node_id);
        manager.record_success(&node_id);

        assert_eq!(manager.get_consecutive_failures(&node_id), 0);
    }

    #[test]
    fn test_eviction_reason_consecutive_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        for _ in 0..3 {
            manager.record_failure(&node_id);
        }

        let reason = manager.get_eviction_reason(&node_id);
        assert!(matches!(
            reason,
            Some(EvictionReason::ConsecutiveFailures(3))
        ));
    }

    #[test]
    fn test_eviction_reason_low_trust() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            max_consecutive_failures: 10,
            ..Default::default()
        };
        let node_id = make_node_id();
        let mut trust_scores = HashMap::new();
        trust_scores.insert(node_id, 0.05);

        let manager = EvictionManager::with_trust(config, trust_scores);
        let reason = manager.get_eviction_reason(&node_id);
        assert!(matches!(reason, Some(EvictionReason::LowTrust(_))));
    }

    #[test]
    fn test_get_eviction_candidates() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let failing_node = make_node_id();
        for _ in 0..3 {
            manager.record_failure(&failing_node);
        }

        let low_trust_node = make_node_id();
        manager.update_trust_score(&low_trust_node, 0.05);

        let good_node = make_node_id();
        manager.record_success(&good_node);
        manager.update_trust_score(&good_node, 0.90);

        let candidates = manager.get_eviction_candidates();
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn test_remove_node() {
        let config = MaintenanceConfig::default();
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        manager.record_failure(&node_id);
        manager.update_trust_score(&node_id, 0.5);

        manager.remove_node(&node_id);

        assert_eq!(manager.get_consecutive_failures(&node_id), 0);
        assert!(manager.get_liveness_state(&node_id).is_none());
        assert!(!manager.should_evict_for_trust(&node_id));
    }

    #[test]
    fn test_update_trust_score() {
        let config = MaintenanceConfig {
            min_trust_threshold: 0.15,
            ..Default::default()
        };
        let mut manager = EvictionManager::new(config);

        let node_id = make_node_id();
        assert!(!manager.should_evict_for_trust(&node_id));

        manager.update_trust_score(&node_id, 0.05);
        assert!(manager.should_evict_for_trust(&node_id));

        manager.update_trust_score(&node_id, 0.50);
        assert!(!manager.should_evict_for_trust(&node_id));
    }
}
