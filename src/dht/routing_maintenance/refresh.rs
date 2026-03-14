//! Bucket refresh logic for Kademlia routing table
//!
//! Handles periodic refresh of k-buckets by:
//! - Generating keys that land in specific buckets
//! - Performing lookups to find nodes for sparse buckets
//! - Tracking bucket refresh timestamps
//! - Validating nodes via close group consensus
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use crate::PeerId;

use super::close_group_validator::{CloseGroupValidator, CloseGroupValidatorConfig};

/// Tier classification for bucket refresh intervals
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTier {
    /// Background tier: sparse buckets (refresh every 60min default)
    Background,
}

impl RefreshTier {
    /// Get the default refresh interval for this tier
    #[must_use]
    pub fn default_interval(&self) -> Duration {
        match self {
            RefreshTier::Background => Duration::from_secs(3600),
        }
    }
}

/// Tracks the state of bucket refresh operations
#[derive(Debug, Clone)]
pub struct BucketRefreshState {
    /// Last time this bucket was refreshed
    pub last_refresh: Instant,
    /// Number of nodes currently in this bucket
    pub node_count: usize,
    /// Current tier for this bucket
    pub tier: RefreshTier,
    /// Number of successful refreshes
    pub success_count: u64,
    /// Number of nodes that passed validation
    pub validated_nodes: u64,
    /// Number of nodes that failed validation
    pub validation_failures: u64,
    /// Last validation timestamp
    pub last_validation: Option<Instant>,
    /// Tracked node IDs for validation
    pub tracked_nodes: Vec<PeerId>,
}

impl Default for BucketRefreshState {
    fn default() -> Self {
        Self::new()
    }
}

impl BucketRefreshState {
    /// Create a new bucket refresh state
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_refresh: Instant::now(),
            node_count: 0,
            tier: RefreshTier::Background,
            success_count: 0,
            validated_nodes: 0,
            validation_failures: 0,
            last_validation: None,
            tracked_nodes: Vec::new(),
        }
    }

    /// Check if this bucket needs a refresh
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.last_refresh.elapsed() > self.tier.default_interval()
    }

    /// Record a successful refresh
    pub fn record_success(&mut self, node_count: usize) {
        self.last_refresh = Instant::now();
        self.node_count = node_count;
        self.success_count += 1;
    }

    /// Check if this bucket needs validation based on validation age
    #[must_use]
    pub fn needs_validation(&self, max_age: Duration) -> bool {
        match self.last_validation {
            Some(last) => last.elapsed() > max_age,
            None => true, // Never validated
        }
    }
}

/// Manages refresh operations for all buckets
pub struct BucketRefreshManager {
    /// State for each bucket (indexed 0-255)
    bucket_states: HashMap<usize, BucketRefreshState>,
    /// Optional close group validator for hybrid validation
    validator: Option<Arc<RwLock<CloseGroupValidator>>>,
    /// Total validation failures across all buckets (for attack detection)
    total_validation_failures: u64,
    /// Validation age threshold (default 5 minutes)
    validation_age_threshold: Duration,
}

impl BucketRefreshManager {
    /// Create a new bucket refresh manager with validation enabled
    #[must_use]
    pub fn new_with_validation(_local_id: PeerId, config: CloseGroupValidatorConfig) -> Self {
        let validator = CloseGroupValidator::new(config);
        Self {
            bucket_states: HashMap::new(),
            validator: Some(Arc::new(RwLock::new(validator))),
            total_validation_failures: 0,
            validation_age_threshold: Duration::from_secs(300),
        }
    }

    /// Set the close group validator
    pub fn set_validator(&mut self, validator: Arc<RwLock<CloseGroupValidator>>) {
        self.validator = Some(validator);
    }

    /// Get a reference to the validator if available
    #[must_use]
    pub fn validator(&self) -> Option<&Arc<RwLock<CloseGroupValidator>>> {
        self.validator.as_ref()
    }

    /// Get or create state for a bucket
    pub fn get_or_create_state(&mut self, bucket_idx: usize) -> &mut BucketRefreshState {
        self.bucket_states.entry(bucket_idx).or_default()
    }

    /// Record successful refresh for a bucket
    pub fn record_refresh_success(&mut self, bucket_idx: usize, node_count: usize) {
        let state = self.get_or_create_state(bucket_idx);
        state.record_success(node_count);
    }

    /// Get list of buckets needing refresh, sorted by priority
    #[must_use]
    pub fn get_buckets_needing_refresh(&self) -> Vec<usize> {
        self.bucket_states
            .iter()
            .filter(|(_, state)| state.needs_refresh())
            .map(|(&idx, _)| idx)
            .collect()
    }

    /// Get overall validation rate across all buckets
    #[must_use]
    pub fn overall_validation_rate(&self) -> f64 {
        let (total_passed, total_failed) =
            self.bucket_states
                .values()
                .fold((0u64, 0u64), |acc, state| {
                    (
                        acc.0 + state.validated_nodes,
                        acc.1 + state.validation_failures,
                    )
                });
        let total = total_passed + total_failed;
        if total == 0 {
            1.0
        } else {
            total_passed as f64 / total as f64
        }
    }

    /// Check if attack mode should be triggered based on validation failures
    #[must_use]
    pub fn should_trigger_attack_mode(&self) -> bool {
        self.overall_validation_rate() < 0.7 || self.total_validation_failures > 10
    }

    /// Get list of buckets needing validation
    #[must_use]
    pub fn get_buckets_needing_validation(&self) -> Vec<usize> {
        let threshold = self.validation_age_threshold;
        self.bucket_states
            .iter()
            .filter(|(_, state)| state.needs_validation(threshold) && state.node_count > 0)
            .map(|(&idx, _)| idx)
            .collect()
    }

    /// Get nodes tracked in a specific bucket for validation
    #[must_use]
    pub fn get_nodes_in_bucket(&self, bucket_idx: usize) -> Vec<PeerId> {
        self.bucket_states
            .get(&bucket_idx)
            .map(|state| state.tracked_nodes.clone())
            .unwrap_or_default()
    }

    /// Record a validation result for a bucket (with count of validated and failed)
    pub fn record_validation_result(
        &mut self,
        bucket_idx: usize,
        _validated_count: usize,
        _failed_count: usize,
    ) {
        if let Some(state) = self.bucket_states.get_mut(&bucket_idx) {
            state.last_validation = Some(Instant::now());
        }
    }
}

/// Test-only constructor
#[cfg(test)]
impl BucketRefreshManager {
    pub fn new(_local_id: PeerId) -> Self {
        Self {
            bucket_states: HashMap::new(),
            validator: None,
            total_validation_failures: 0,
            validation_age_threshold: Duration::from_secs(300),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::DhtKey;

    /// Test helper: create a BucketRefreshManager with key generation support
    struct TestRefreshManager {
        inner: BucketRefreshManager,
        local_id: PeerId,
    }

    impl TestRefreshManager {
        fn new(local_id: PeerId) -> Self {
            Self {
                inner: BucketRefreshManager::new(local_id),
                local_id,
            }
        }

        fn generate_key_for_bucket(&self, bucket_idx: usize) -> Option<DhtKey> {
            if bucket_idx >= 256 {
                return None;
            }

            let mut key_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_bytes);

            let our_id = self.local_id.as_bytes();
            let byte_idx = bucket_idx / 8;
            let bit_idx = 7 - (bucket_idx % 8);

            for (i, byte) in key_bytes.iter_mut().enumerate().take(byte_idx) {
                *byte = our_id[i];
            }

            key_bytes[byte_idx] = our_id[byte_idx] ^ (1 << bit_idx);
            Some(DhtKey::from_bytes(key_bytes))
        }

        fn bucket_index(&self, key: &DhtKey) -> usize {
            let our_bytes = self.local_id.as_bytes();
            let key_bytes = key.as_bytes();

            for (byte_idx, (&a, &b)) in our_bytes.iter().zip(key_bytes.iter()).enumerate() {
                let xor = a ^ b;
                if xor != 0 {
                    let leading_zeros = xor.leading_zeros() as usize;
                    return byte_idx * 8 + leading_zeros;
                }
            }
            255
        }
    }

    #[test]
    fn test_refresh_tier_default_intervals() {
        assert_eq!(
            RefreshTier::Background.default_interval(),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_bucket_refresh_state_new() {
        let state = BucketRefreshState::new();
        assert_eq!(state.node_count, 0);
        assert_eq!(state.tier, RefreshTier::Background);
        assert_eq!(state.success_count, 0);
    }

    #[test]
    fn test_bucket_refresh_state_needs_refresh() {
        let state = BucketRefreshState::new();
        assert!(!state.needs_refresh());
    }

    #[test]
    fn test_bucket_refresh_state_record_success() {
        let mut state = BucketRefreshState::new();
        state.record_success(5);

        assert_eq!(state.node_count, 5);
        assert_eq!(state.success_count, 1);
    }

    #[test]
    fn test_generate_key_for_bucket_lands_in_correct_bucket() {
        let local_id = PeerId::random();
        let manager = TestRefreshManager::new(local_id);

        for bucket_idx in [0, 10, 100, 200, 255] {
            let key = manager.generate_key_for_bucket(bucket_idx).unwrap();
            let actual_bucket = manager.bucket_index(&key);
            assert_eq!(
                actual_bucket, bucket_idx,
                "Key for bucket {} landed in bucket {}",
                bucket_idx, actual_bucket
            );
        }
    }

    #[test]
    fn test_generate_key_produces_different_keys() {
        let local_id = PeerId::random();
        let manager = TestRefreshManager::new(local_id);

        let key1 = manager.generate_key_for_bucket(100).unwrap();
        let key2 = manager.generate_key_for_bucket(100).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_key_invalid_bucket() {
        let local_id = PeerId::random();
        let manager = TestRefreshManager::new(local_id);

        assert!(manager.generate_key_for_bucket(256).is_none());
        assert!(manager.generate_key_for_bucket(1000).is_none());
    }

    #[test]
    fn test_initialize_buckets() {
        let local_id = PeerId::random();
        let mut manager = BucketRefreshManager::new(local_id);

        for i in 0..256 {
            manager.get_or_create_state(i);
        }

        assert!(manager.bucket_states.get(&0).is_some());
        assert!(manager.bucket_states.get(&255).is_some());
        assert!(manager.bucket_states.get(&256).is_none());
    }

    #[test]
    fn test_record_refresh_success() {
        let local_id = PeerId::random();
        let mut manager = BucketRefreshManager::new(local_id);

        manager.record_refresh_success(10, 8);

        let state = manager.bucket_states.get(&10).unwrap();
        assert_eq!(state.node_count, 8);
        assert_eq!(state.success_count, 1);
    }
}
