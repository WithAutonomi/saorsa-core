//! Routing table maintenance and node validation
//!
//! This module provides:
//! - Periodic routing table refresh with liveness checking
//! - Ill-behaving node removal from routing table
//! - Node validity verification via close group consensus
//! - Close group validation with hybrid trust/BFT approach
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

pub mod close_group_validator;
pub mod config;
pub mod eviction;
pub mod liveness;
pub mod refresh;
pub mod scheduler;

// Re-export main types
pub use config::MaintenanceConfig;
pub use eviction::{EvictionManager, EvictionReason};
pub use refresh::BucketRefreshManager;
pub use scheduler::{MaintenanceScheduler, MaintenanceTask};
