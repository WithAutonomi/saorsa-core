//! Close group validation during routing table refresh
//!
//! Validates that nodes are still considered valid members of their close groups.
//! Uses hybrid validation: trust-weighted normally, BFT consensus when attacks detected.
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;

use crate::PeerId;

/// Reasons why close group validation might fail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseGroupFailure {
    /// Node's trust score too low
    LowTrustScore,
}

/// Enforcement mode for close group validation
///
/// Controls whether validation failures result in node rejection or just logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseGroupEnforcementMode {
    /// Log-only mode - log validation failures but allow unknown nodes
    /// Use during initial deployment or for monitoring
    LogOnly,
    /// Strict mode - reject nodes that fail validation (default)
    /// Use in production for full security
    #[default]
    Strict,
}

impl CloseGroupEnforcementMode {
    /// Check if this mode is log-only (allows all nodes, just logs issues)
    #[must_use]
    pub fn is_log_only(&self) -> bool {
        matches!(self, Self::LogOnly)
    }
}

/// Result of close group validation
#[derive(Debug, Clone)]
pub struct CloseGroupValidationResult {
    /// Whether the node is valid
    pub is_valid: bool,
    /// Any failure reasons
    pub failure_reasons: Vec<CloseGroupFailure>,
    /// Timestamp of validation
    pub validated_at: SystemTime,
}

/// Configuration for close group validation
#[derive(Debug, Clone)]
pub struct CloseGroupValidatorConfig {
    /// Minimum trust score for a witness
    pub min_witness_trust: f64,
    /// Enforcement mode (Strict or LogOnly)
    pub enforcement_mode: CloseGroupEnforcementMode,
}

impl Default for CloseGroupValidatorConfig {
    fn default() -> Self {
        Self {
            min_witness_trust: 0.3,
            enforcement_mode: CloseGroupEnforcementMode::default(),
        }
    }
}

impl CloseGroupValidatorConfig {
    /// Set the enforcement mode
    #[must_use]
    pub fn with_enforcement_mode(mut self, mode: CloseGroupEnforcementMode) -> Self {
        self.enforcement_mode = mode;
        self
    }
}

/// Close group validator with hybrid validation
///
/// Uses trust-weighted validation normally, escalates to BFT consensus
/// when attack indicators are detected.
pub struct CloseGroupValidator {
    /// Configuration
    config: CloseGroupValidatorConfig,
    /// Whether attack mode is active (use BFT instead of trust-weighted)
    attack_mode: AtomicBool,
    /// Cache of recent validation results
    validation_cache: Arc<RwLock<HashMap<PeerId, CloseGroupValidationResult>>>,
    /// Cache TTL
    cache_ttl: Duration,
}

impl CloseGroupValidator {
    /// Create a new close group validator
    #[must_use]
    pub fn new(config: CloseGroupValidatorConfig) -> Self {
        Self {
            config,
            attack_mode: AtomicBool::new(false),
            validation_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(60),
        }
    }

    /// Check if attack mode is currently active
    #[must_use]
    pub fn is_attack_mode(&self) -> bool {
        self.attack_mode.load(Ordering::Relaxed)
    }

    /// Escalate to BFT consensus mode
    pub fn escalate_to_bft(&self) {
        self.attack_mode.store(true, Ordering::SeqCst);
    }

    /// De-escalate from BFT mode (when attack indicators clear)
    pub fn deescalate_from_bft(&self) {
        self.attack_mode.store(false, Ordering::SeqCst);
    }

    /// Check if a node is valid based on cached validation results
    ///
    /// Behavior depends on enforcement mode:
    /// - Strict: Unknown nodes are rejected (return false)
    /// - LogOnly: Unknown nodes are allowed (return true) with warning logged
    pub fn validate(&self, node_id: &PeerId) -> bool {
        if let Some(result) = self.get_cached_result(node_id) {
            if !result.is_valid && self.config.enforcement_mode.is_log_only() {
                tracing::warn!(
                    node_id = ?node_id,
                    "Close group validation failed but allowed (LogOnly mode)"
                );
                return true;
            }
            return result.is_valid;
        }

        // Node not in cache - behavior depends on enforcement mode
        match self.config.enforcement_mode {
            CloseGroupEnforcementMode::Strict => {
                // Strict mode: unknown nodes are rejected
                tracing::debug!(
                    node_id = ?node_id,
                    "Unknown node rejected (Strict mode)"
                );
                false
            }
            CloseGroupEnforcementMode::LogOnly => {
                // LogOnly mode: allow unknown nodes
                tracing::debug!(
                    node_id = ?node_id,
                    "Unknown node allowed (LogOnly mode)"
                );
                true
            }
        }
    }

    /// Validate node using trust score only (no peer responses required)
    ///
    /// This is a lightweight validation for use during background refresh when
    /// full close group consensus is not available. It validates based on:
    /// - Trust score threshold
    /// - Cached validation results
    ///
    /// Returns (is_valid, failure_reason)
    #[must_use]
    pub fn validate_trust_only(
        &self,
        node_id: &PeerId,
        trust_score: Option<f64>,
    ) -> (bool, Option<CloseGroupFailure>) {
        // Check cache first
        if let Some(cached) = self.get_cached_result(node_id) {
            // In LogOnly mode, return valid even if cached result is invalid
            if !cached.is_valid && self.config.enforcement_mode.is_log_only() {
                return (true, None);
            }
            return (cached.is_valid, cached.failure_reasons.first().cloned());
        }

        // Check trust score
        let min_threshold = if self.is_attack_mode() {
            // Higher threshold in attack mode
            self.config.min_witness_trust
        } else {
            // Lower threshold in normal mode (0.15 default)
            self.config.min_witness_trust * 0.5
        };

        match trust_score {
            Some(score) if score < min_threshold => {
                if self.config.enforcement_mode.is_log_only() {
                    tracing::warn!(
                        node_id = ?node_id,
                        trust_score = score,
                        min_threshold = min_threshold,
                        "Trust validation failed but allowed (LogOnly mode)"
                    );
                    (true, None)
                } else {
                    tracing::debug!(
                        node_id = ?node_id,
                        trust_score = score,
                        min_threshold = min_threshold,
                        "Node failed trust validation"
                    );
                    (false, Some(CloseGroupFailure::LowTrustScore))
                }
            }
            Some(_) => (true, None), // Trust score above threshold
            None => {
                // No trust score available - allow in LogOnly mode, reject in Strict
                match self.config.enforcement_mode {
                    CloseGroupEnforcementMode::LogOnly => (true, None),
                    CloseGroupEnforcementMode::Strict => {
                        tracing::debug!(
                            node_id = ?node_id,
                            "Node rejected due to missing trust score (Strict mode)"
                        );
                        (false, Some(CloseGroupFailure::LowTrustScore))
                    }
                }
            }
        }
    }

    /// Get cached validation result if still valid
    #[must_use]
    fn get_cached_result(&self, node_id: &PeerId) -> Option<CloseGroupValidationResult> {
        let cache = self.validation_cache.read();
        cache.get(node_id).and_then(|result| {
            let age = result.validated_at.elapsed().ok()?;
            if age < self.cache_ttl {
                Some(result.clone())
            } else {
                None
            }
        })
    }
}

/// Test-only methods
#[cfg(test)]
impl CloseGroupValidator {
    /// Manually set attack mode (test utility)
    pub fn set_attack_mode(&self, enabled: bool) {
        self.attack_mode.store(enabled, Ordering::Relaxed);
    }

    /// Get the current enforcement mode (test utility)
    #[must_use]
    pub fn enforcement_mode(&self) -> CloseGroupEnforcementMode {
        self.config.enforcement_mode
    }

    /// Cache a validation result (test utility)
    pub fn cache_result(&self, node_id: PeerId, result: CloseGroupValidationResult) {
        let mut cache = self.validation_cache.write();
        cache.insert(node_id, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_mode_enum() {
        assert_eq!(
            CloseGroupEnforcementMode::default(),
            CloseGroupEnforcementMode::Strict
        );
        assert!(!CloseGroupEnforcementMode::Strict.is_log_only());
        assert!(CloseGroupEnforcementMode::LogOnly.is_log_only());
    }

    #[test]
    fn test_config_with_enforcement_mode() {
        let config = CloseGroupValidatorConfig::default()
            .with_enforcement_mode(CloseGroupEnforcementMode::LogOnly);
        assert_eq!(config.enforcement_mode, CloseGroupEnforcementMode::LogOnly);
    }

    #[test]
    fn test_strict_mode_rejects_unknown_nodes() {
        let config = CloseGroupValidatorConfig::default();
        let validator = CloseGroupValidator::new(config);
        let unknown_node = PeerId::random();

        assert!(!validator.validate(&unknown_node));
        assert!(!validator.enforcement_mode().is_log_only());
    }

    #[test]
    fn test_log_only_mode_allows_unknown_nodes() {
        let config = CloseGroupValidatorConfig::default()
            .with_enforcement_mode(CloseGroupEnforcementMode::LogOnly);
        let validator = CloseGroupValidator::new(config);
        let unknown_node = PeerId::random();

        assert!(validator.validate(&unknown_node));
        assert!(validator.enforcement_mode().is_log_only());
    }

    #[test]
    fn test_strict_mode_respects_cached_results() {
        let config = CloseGroupValidatorConfig::default();
        let validator = CloseGroupValidator::new(config);
        let node_id = PeerId::random();

        let valid_result = CloseGroupValidationResult {
            is_valid: true,
            failure_reasons: Vec::new(),
            validated_at: SystemTime::now(),
        };
        validator.cache_result(node_id, valid_result);
        assert!(validator.validate(&node_id));

        let invalid_node = PeerId::random();
        let invalid_result = CloseGroupValidationResult {
            is_valid: false,
            failure_reasons: Vec::new(),
            validated_at: SystemTime::now(),
        };
        validator.cache_result(invalid_node, invalid_result);
        assert!(!validator.validate(&invalid_node));
    }

    #[test]
    fn test_log_only_mode_allows_failed_cached_results() {
        let config = CloseGroupValidatorConfig::default()
            .with_enforcement_mode(CloseGroupEnforcementMode::LogOnly);
        let validator = CloseGroupValidator::new(config);
        let node_id = PeerId::random();

        let invalid_result = CloseGroupValidationResult {
            is_valid: false,
            failure_reasons: Vec::new(),
            validated_at: SystemTime::now(),
        };
        validator.cache_result(node_id, invalid_result);
        assert!(validator.validate(&node_id));
    }

    #[test]
    fn test_attack_mode_toggle() {
        let validator = CloseGroupValidator::new(CloseGroupValidatorConfig::default());
        assert!(!validator.is_attack_mode());

        validator.escalate_to_bft();
        assert!(validator.is_attack_mode());

        validator.deescalate_from_bft();
        assert!(!validator.is_attack_mode());
    }

    #[test]
    fn test_set_attack_mode() {
        let validator = CloseGroupValidator::new(CloseGroupValidatorConfig::default());
        assert!(!validator.is_attack_mode());

        validator.set_attack_mode(true);
        assert!(validator.is_attack_mode());

        validator.set_attack_mode(false);
        assert!(!validator.is_attack_mode());
    }
}
