//! Node liveness tracking and eviction logic
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use super::config::MaintenanceConfig;

/// Tracks liveness state for a single node
#[derive(Debug, Clone)]
pub struct NodeLivenessState {
    /// Number of consecutive failed communication attempts
    pub consecutive_failures: u32,
}

impl Default for NodeLivenessState {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeLivenessState {
    /// Create a new liveness state for a node
    #[must_use]
    pub fn new() -> Self {
        Self {
            consecutive_failures: 0,
        }
    }

    /// Check if this node should be evicted based on consecutive failures
    #[must_use]
    pub fn should_evict(&self, config: &MaintenanceConfig) -> bool {
        self.consecutive_failures >= config.max_consecutive_failures
    }
}

/// Test-only methods
#[cfg(test)]
impl NodeLivenessState {
    /// Record a failed communication attempt
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    /// Record a successful communication
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_state_new() {
        let state = NodeLivenessState::new();
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn test_liveness_state_tracks_failures() {
        let mut state = NodeLivenessState::new();
        state.record_failure();
        state.record_failure();
        assert_eq!(state.consecutive_failures, 2);
    }

    #[test]
    fn test_liveness_state_resets_on_success() {
        let mut state = NodeLivenessState::new();
        state.record_failure();
        state.record_failure();
        assert_eq!(state.consecutive_failures, 2);

        state.record_success();
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn test_should_evict_after_max_failures() {
        let config = MaintenanceConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let mut state = NodeLivenessState::new();

        state.record_failure();
        state.record_failure();
        assert!(!state.should_evict(&config));

        state.record_failure();
        assert!(state.should_evict(&config));
    }

    #[test]
    fn test_success_resets_consecutive_but_not_eviction() {
        let config = MaintenanceConfig::default();
        let mut state = NodeLivenessState::new();

        for _ in 0..2 {
            state.record_failure();
        }
        assert_eq!(state.consecutive_failures, 2);
        assert!(!state.should_evict(&config));

        state.record_success();
        assert_eq!(state.consecutive_failures, 0);

        state.record_failure();
        assert!(!state.should_evict(&config));
    }
}
