//! Routing table maintenance and node validation
//!
//! This module provides:
//! - Periodic routing table refresh with liveness checking
//! - Ill-behaving node removal from routing table
//! - Node validity verification via close group consensus
//! - Close group validation with hybrid trust/BFT approach
//! - Security coordination integrating Sybil detection
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

pub mod close_group_validator;
pub mod config;
pub mod eviction;
pub mod liveness;
pub mod refresh;
pub mod scheduler;
pub mod security_coordinator;
pub mod validator;

// Re-export main types
pub use close_group_validator::{
    AttackIndicators, CloseGroupFailure, CloseGroupHistory, CloseGroupResponse,
    CloseGroupValidationResult, CloseGroupValidator, CloseGroupValidatorConfig,
};
pub use config::MaintenanceConfig;
pub use eviction::{EvictionManager, EvictionReason};
pub use liveness::NodeLivenessState;
pub use refresh::{BucketRefreshManager, BucketRefreshState, RefreshTier};
pub use scheduler::{MaintenanceScheduler, MaintenanceTask, ScheduledTask, TaskStats};
pub use security_coordinator::{
    CloseGroupEviction, CloseGroupEvictionTracker, EvictionRecord, SecurityCoordinator,
    SecurityCoordinatorConfig,
};
pub use validator::{
    NodeValidationResult, ValidationFailure, WitnessResponse, WitnessSelectionCriteria,
};

/// Lightweight data integrity metrics snapshot used by the security dashboard.
#[derive(Debug, Clone, Default)]
pub struct DataIntegrityMetrics {
    pub healthy_keys: u64,
    pub degraded_keys: u64,
    pub critical_keys: u64,
}

impl DataIntegrityMetrics {
    pub fn health_ratio(&self) -> f64 {
        let total = self.healthy_keys + self.degraded_keys + self.critical_keys;
        if total == 0 {
            1.0
        } else {
            self.healthy_keys as f64 / total as f64
        }
    }
}
