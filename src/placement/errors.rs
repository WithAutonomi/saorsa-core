// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Error types for the placement system
//!
//! Comprehensive error handling for placement operations with detailed
//! error categories, severity levels, and recovery guidance.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::PeerId;

/// Result type for placement operations
pub type PlacementResult<T> = Result<T, PlacementError>;

/// Comprehensive error types for placement operations
#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum PlacementError {
    /// Insufficient nodes available for placement
    #[error("Insufficient nodes: required {required}, available {available}")]
    InsufficientNodes { required: usize, available: usize },

    /// Invalid replication factor
    #[error("Invalid replication factor: {0}")]
    InvalidReplicationFactor(u8),

    /// Invalid configuration parameter
    #[error("Invalid configuration - {field}: {reason}")]
    InvalidConfiguration { field: String, reason: String },

    /// Invalid metrics value
    #[error("Invalid metrics - {field}: {value} ({reason})")]
    InvalidMetrics {
        field: String,
        value: f64,
        reason: String,
    },

    /// Invalid weight value for node
    #[error("Invalid weight for node {node_id:?}: {weight} ({reason})")]
    InvalidWeight {
        node_id: PeerId,
        weight: f64,
        reason: String,
    },

    /// Node metadata not found
    #[error("Node metadata not found: {0:?}")]
    NodeMetadataNotFound(PeerId),

    /// Placement timeout exceeded
    #[error("Placement operation timed out")]
    PlacementTimeout,

    /// Diversity constraint violation
    #[error("Diversity violation - {constraint}: {details}")]
    DiversityViolation {
        constraint: String,
        nodes: Vec<PeerId>,
        details: String,
    },

    /// Byzantine fault tolerance violation
    #[error("Byzantine tolerance violation: required {required} nodes, available {available}")]
    ByzantineToleranceViolation { required: usize, available: usize },

    /// Capacity constraint violation
    #[error("Capacity constraint violated for node {node_id:?}: {details}")]
    CapacityViolation { node_id: PeerId, details: String },

    /// Performance constraint violation
    #[error(
        "Performance constraint violated for node {node_id:?}: {metric} = {value} (min: {minimum})"
    )]
    PerformanceViolation {
        node_id: PeerId,
        metric: String,
        value: f64,
        minimum: f64,
    },

    /// Geographic constraint violation
    #[error("Geographic constraint violated: {details}")]
    GeographicViolation { details: String },

    /// Network topology error
    #[error("Network topology error: {0}")]
    NetworkTopology(String),

    /// Trust system error
    #[error("Trust system error: {0}")]
    TrustSystem(String),

    /// Performance monitoring error
    #[error("Performance monitoring error: {0}")]
    PerformanceMonitoring(String),

    /// Strategy execution error
    #[error("Strategy execution error: {0}")]
    StrategyExecution(String),

    /// Node selection algorithm error
    #[error("Node selection failed: {0}")]
    NodeSelection(String),

    /// Sampling algorithm error
    #[error("Sampling algorithm error: {0}")]
    SamplingError(String),

    /// Validation error
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// Reliability too low
    #[error("Estimated reliability {estimated} below minimum {minimum}")]
    ReliabilityTooLow { estimated: f64, minimum: f64 },

    /// Resource exhaustion
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Concurrent modification
    #[error("Concurrent modification detected: {0}")]
    ConcurrentModification(String),

    /// Internal consistency error
    #[error("Internal consistency error: {0}")]
    InternalConsistency(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// DHT operation error
    #[error("DHT operation failed: {0}")]
    DhtOperation(String),

    /// External dependency error
    #[error("External dependency error: {0}")]
    ExternalDependency(String),

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl PlacementError {
    /// Get error severity level (1-5, where 5 is most severe)
    pub fn severity(&self) -> u8 {
        match self {
            PlacementError::InsufficientNodes { .. } => 5,
            PlacementError::InvalidReplicationFactor(_) => 4,
            PlacementError::InvalidConfiguration { .. } => 4,
            PlacementError::PlacementTimeout => 3,
            PlacementError::ByzantineToleranceViolation { .. } => 5,
            PlacementError::DiversityViolation { .. } => 2,
            PlacementError::CapacityViolation { .. } => 3,
            PlacementError::PerformanceViolation { .. } => 2,
            PlacementError::GeographicViolation { .. } => 2,
            PlacementError::NetworkTopology(_) => 3,
            PlacementError::TrustSystem(_) => 3,
            PlacementError::PerformanceMonitoring(_) => 2,
            PlacementError::StrategyExecution(_) => 4,
            PlacementError::NodeSelection(_) => 4,
            PlacementError::SamplingError(_) => 3,
            PlacementError::ValidationFailed(_) => 3,
            PlacementError::ReliabilityTooLow { .. } => 4,
            PlacementError::ResourceExhausted(_) => 3,
            PlacementError::ConcurrentModification(_) => 2,
            PlacementError::InternalConsistency(_) => 5,
            PlacementError::Serialization(_) => 2,
            PlacementError::DhtOperation(_) => 3,
            PlacementError::ExternalDependency(_) => 3,
            PlacementError::InvalidMetrics { .. } => 2,
            PlacementError::InvalidWeight { .. } => 2,
            PlacementError::NodeMetadataNotFound(_) => 3,
            PlacementError::Unknown(_) => 1,
        }
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            PlacementError::InsufficientNodes { .. } => false,
            PlacementError::InvalidReplicationFactor(_) => false,
            PlacementError::InvalidConfiguration { .. } => false,
            PlacementError::PlacementTimeout => true,
            PlacementError::ByzantineToleranceViolation { .. } => false,
            PlacementError::DiversityViolation { .. } => true,
            PlacementError::CapacityViolation { .. } => true,
            PlacementError::PerformanceViolation { .. } => true,
            PlacementError::GeographicViolation { .. } => true,
            PlacementError::NetworkTopology(_) => true,
            PlacementError::TrustSystem(_) => true,
            PlacementError::PerformanceMonitoring(_) => true,
            PlacementError::StrategyExecution(_) => true,
            PlacementError::NodeSelection(_) => true,
            PlacementError::SamplingError(_) => true,
            PlacementError::ValidationFailed(_) => false,
            PlacementError::ReliabilityTooLow { .. } => true,
            PlacementError::ResourceExhausted(_) => true,
            PlacementError::ConcurrentModification(_) => true,
            PlacementError::InternalConsistency(_) => false,
            PlacementError::Serialization(_) => false,
            PlacementError::DhtOperation(_) => true,
            PlacementError::ExternalDependency(_) => true,
            PlacementError::InvalidMetrics { .. } => false,
            PlacementError::InvalidWeight { .. } => false,
            PlacementError::NodeMetadataNotFound(_) => true,
            PlacementError::Unknown(_) => false,
        }
    }

    /// Get suggested retry delay
    pub fn retry_delay(&self) -> Option<Duration> {
        if !self.is_retryable() {
            return None;
        }

        Some(match self {
            PlacementError::PlacementTimeout => Duration::from_secs(5),
            PlacementError::NetworkTopology(_) => Duration::from_secs(2),
            PlacementError::TrustSystem(_) => Duration::from_secs(1),
            PlacementError::PerformanceMonitoring(_) => Duration::from_secs(1),
            PlacementError::ResourceExhausted(_) => Duration::from_secs(10),
            PlacementError::ConcurrentModification(_) => Duration::from_millis(100),
            PlacementError::DhtOperation(_) => Duration::from_secs(3),
            PlacementError::ExternalDependency(_) => Duration::from_secs(5),
            _ => Duration::from_secs(1),
        })
    }

    /// Get error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            PlacementError::InsufficientNodes { .. } | PlacementError::NodeMetadataNotFound(_) => {
                ErrorCategory::NodeAvailability
            }

            PlacementError::InvalidReplicationFactor(_)
            | PlacementError::InvalidConfiguration { .. }
            | PlacementError::InvalidMetrics { .. }
            | PlacementError::InvalidWeight { .. } => ErrorCategory::Configuration,

            PlacementError::DiversityViolation { .. }
            | PlacementError::GeographicViolation { .. }
            | PlacementError::ByzantineToleranceViolation { .. } => ErrorCategory::Constraints,

            PlacementError::CapacityViolation { .. }
            | PlacementError::PerformanceViolation { .. }
            | PlacementError::ReliabilityTooLow { .. } => ErrorCategory::Performance,

            PlacementError::NetworkTopology(_) | PlacementError::DhtOperation(_) => {
                ErrorCategory::Network
            }

            PlacementError::TrustSystem(_) => ErrorCategory::Trust,

            PlacementError::StrategyExecution(_)
            | PlacementError::NodeSelection(_)
            | PlacementError::SamplingError(_) => ErrorCategory::Algorithm,

            PlacementError::PlacementTimeout | PlacementError::ResourceExhausted(_) => {
                ErrorCategory::Resource
            }

            PlacementError::ValidationFailed(_) | PlacementError::InternalConsistency(_) => {
                ErrorCategory::Validation
            }

            PlacementError::Serialization(_) => ErrorCategory::Serialization,

            PlacementError::ConcurrentModification(_) => ErrorCategory::Concurrency,

            PlacementError::PerformanceMonitoring(_) | PlacementError::ExternalDependency(_) => {
                ErrorCategory::External
            }

            PlacementError::Unknown(_) => ErrorCategory::Unknown,
        }
    }

    /// Get recovery suggestion
    pub fn recovery_suggestion(&self) -> &'static str {
        match self {
            PlacementError::InsufficientNodes { .. } => {
                "Add more nodes to the network or reduce replication factor"
            }
            PlacementError::InvalidReplicationFactor(_) => {
                "Use a valid replication factor within configured bounds"
            }
            PlacementError::InvalidConfiguration { .. } => {
                "Fix configuration parameters and restart"
            }
            PlacementError::PlacementTimeout => {
                "Increase placement timeout or optimize network performance"
            }
            PlacementError::ByzantineToleranceViolation { .. } => {
                "Add more nodes or reduce Byzantine fault tolerance requirements"
            }
            PlacementError::DiversityViolation { .. } => {
                "Relax diversity constraints or add nodes in different regions"
            }
            PlacementError::CapacityViolation { .. } => {
                "Add nodes with more capacity or reduce storage requirements"
            }
            PlacementError::PerformanceViolation { .. } => {
                "Improve node performance or relax performance constraints"
            }
            PlacementError::ReliabilityTooLow { .. } => {
                "Improve node reliability or increase replication factor"
            }
            PlacementError::ResourceExhausted(_) => {
                "Wait for resources to become available or add more capacity"
            }
            PlacementError::ConcurrentModification(_) => "Retry the operation with updated state",
            _ => "Check logs for details and consider retrying",
        }
    }

    /// Convert to user-friendly message
    pub fn user_message(&self) -> String {
        match self {
            PlacementError::InsufficientNodes {
                required,
                available,
            } => {
                format!(
                    "Not enough nodes available for placement. Need {} but only {} available.",
                    required, available
                )
            }
            PlacementError::PlacementTimeout => {
                "Placement took too long to complete. The network may be busy.".to_string()
            }
            PlacementError::DiversityViolation { constraint, .. } => {
                format!("Placement violates {} diversity requirement.", constraint)
            }
            PlacementError::ReliabilityTooLow { estimated, minimum } => {
                format!(
                    "Estimated reliability {:.1}% is below minimum {:.1}%.",
                    estimated * 100.0,
                    minimum * 100.0
                )
            }
            _ => "Placement operation failed. Please try again.".to_string(),
        }
    }
}

/// Error categories for grouping and handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Node availability issues
    NodeAvailability,
    /// Configuration problems
    Configuration,
    /// Constraint violations
    Constraints,
    /// Performance issues
    Performance,
    /// Network problems
    Network,
    /// Trust system issues
    Trust,
    /// Algorithm failures
    Algorithm,
    /// Resource problems
    Resource,
    /// Validation failures
    Validation,
    /// Serialization issues
    Serialization,
    /// System component failures
    System,
    /// Concurrency issues
    Concurrency,
    /// External dependency failures
    External,
    /// Unknown/unclassified errors
    Unknown,
}

impl ErrorCategory {
    /// Get category priority (higher = more important)
    pub fn priority(&self) -> u8 {
        match self {
            ErrorCategory::Configuration => 10,
            ErrorCategory::NodeAvailability => 9,
            ErrorCategory::Constraints => 8,
            ErrorCategory::Performance => 7,
            ErrorCategory::Algorithm => 6,
            ErrorCategory::Network => 5,
            ErrorCategory::Resource => 4,
            ErrorCategory::Trust => 3,
            ErrorCategory::Validation => 2,
            ErrorCategory::System => 2,
            ErrorCategory::Serialization => 1,
            ErrorCategory::Concurrency => 1,
            ErrorCategory::External => 1,
            ErrorCategory::Unknown => 0,
        }
    }

    /// Get category name
    pub fn name(&self) -> &'static str {
        match self {
            ErrorCategory::NodeAvailability => "Node Availability",
            ErrorCategory::Configuration => "Configuration",
            ErrorCategory::Constraints => "Constraints",
            ErrorCategory::Performance => "Performance",
            ErrorCategory::Network => "Network",
            ErrorCategory::Trust => "Trust",
            ErrorCategory::Algorithm => "Algorithm",
            ErrorCategory::Resource => "Resource",
            ErrorCategory::Validation => "Validation",
            ErrorCategory::Serialization => "Serialization",
            ErrorCategory::System => "System",
            ErrorCategory::Concurrency => "Concurrency",
            ErrorCategory::External => "External",
            ErrorCategory::Unknown => "Unknown",
        }
    }
}

/// Error context for debugging and monitoring
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Operation that failed
    pub operation: String,
    /// Component that generated the error
    pub component: String,
    /// Additional context data
    pub context: std::collections::HashMap<String, String>,
    /// Timestamp when error occurred
    pub timestamp: u64,
}

impl ErrorContext {
    /// Create new error context
    pub fn new(operation: impl Into<String>, component: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            component: component.into(),
            context: std::collections::HashMap::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add context data
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

/// Extension trait for adding context to placement results
pub trait PlacementResultExt<T> {
    /// Add error context
    fn with_context(self, context: ErrorContext) -> PlacementResult<T>;

    /// Add simple context
    fn context(self, operation: &str, component: &str) -> PlacementResult<T>;
}

impl<T> PlacementResultExt<T> for PlacementResult<T> {
    fn with_context(self, _context: ErrorContext) -> PlacementResult<T> {
        // For now, just pass through the result
        // In the future, we could wrap errors with context
        self
    }

    fn context(self, _operation: &str, _component: &str) -> PlacementResult<T> {
        // For now, just pass through the result
        // In the future, we could wrap errors with context
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_severity() {
        let error = PlacementError::InsufficientNodes {
            required: 5,
            available: 3,
        };
        assert_eq!(error.severity(), 5);

        let error = PlacementError::DiversityViolation {
            constraint: "geographic".to_string(),
            nodes: vec![],
            details: "too close".to_string(),
        };
        assert_eq!(error.severity(), 2);
    }

    #[test]
    fn test_error_retryability() {
        let error = PlacementError::PlacementTimeout;
        assert!(error.is_retryable());
        assert_eq!(error.retry_delay(), Some(Duration::from_secs(5)));

        let error = PlacementError::InvalidReplicationFactor(0);
        assert!(!error.is_retryable());
        assert_eq!(error.retry_delay(), None);
    }

    #[test]
    fn test_error_categories() {
        let error = PlacementError::InsufficientNodes {
            required: 5,
            available: 3,
        };
        assert_eq!(error.category(), ErrorCategory::NodeAvailability);

        let error = PlacementError::DiversityViolation {
            constraint: "geographic".to_string(),
            nodes: vec![],
            details: "too close".to_string(),
        };
        assert_eq!(error.category(), ErrorCategory::Constraints);
    }

    #[test]
    fn test_error_messages() {
        let error = PlacementError::InsufficientNodes {
            required: 5,
            available: 3,
        };
        let message = error.user_message();
        assert!(message.contains("Not enough nodes"));
        assert!(message.contains("5"));
        assert!(message.contains("3"));
    }

    #[test]
    fn test_category_priority() {
        assert!(ErrorCategory::Configuration.priority() > ErrorCategory::Performance.priority());
        assert!(ErrorCategory::NodeAvailability.priority() > ErrorCategory::Network.priority());
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("select_nodes", "placement_engine")
            .with_context("replication_factor", "8")
            .with_context("available_nodes", "5");

        assert_eq!(context.operation, "select_nodes");
        assert_eq!(context.component, "placement_engine");
        assert_eq!(
            context.context.get("replication_factor"),
            Some(&"8".to_string())
        );
        assert_eq!(
            context.context.get("available_nodes"),
            Some(&"5".to_string())
        );
    }
}
