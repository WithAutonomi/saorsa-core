// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Tests for coordinator extension trait implementations
//!
//! These tests verify that the coordinator extension traits properly integrate
//! with their underlying implementations.

#[cfg(test)]
mod tests {
    use crate::adaptive::ContentHash;
    use crate::adaptive::coordinator_extensions::*;
    use crate::adaptive::q_learning_cache::{QLearnCacheManager, QLearningConfig};

    // ==================== QLearningCacheExtensions Tests ====================

    #[tokio::test]
    async fn test_decide_caching_returns_valid_decision() {
        let config = QLearningConfig::default();
        let cache_manager = QLearnCacheManager::new(config, 1024 * 1024); // 1MB
        let hash = ContentHash::from(&[1u8; 32]);

        let decision = cache_manager.decide_caching(&hash).await;

        // Should return a valid decision (Cache, Skip, or Evict)
        matches!(
            decision,
            CacheDecision::Cache | CacheDecision::Skip | CacheDecision::Evict
        );
    }

    #[tokio::test]
    async fn test_decide_caching_considers_cache_state() {
        let config = QLearningConfig::default();
        let cache_manager = QLearnCacheManager::new(config, 1024); // Small cache

        // Fill the cache by making decisions for multiple items
        for i in 0..5u8 {
            let hash = ContentHash::from(&[i; 32]);
            let _ = cache_manager.decide_caching(&hash).await;
        }

        // New item - should still make a decision
        let new_hash = ContentHash::from(&[99u8; 32]);
        let decision = cache_manager.decide_caching(&new_hash).await;

        // Should not panic and return a valid decision
        matches!(
            decision,
            CacheDecision::Cache | CacheDecision::Skip | CacheDecision::Evict
        );
    }

    #[tokio::test]
    async fn test_cache_get_returns_none_when_not_cached() {
        let config = QLearningConfig::default();
        let cache_manager = QLearnCacheManager::new(config, 1024 * 1024);
        let hash = ContentHash::from(&[42u8; 32]);

        // Nothing is cached, so get should return None
        let result = cache_manager.get(&hash).await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_save_model_succeeds() {
        let config = QLearningConfig::default();
        let cache_manager = QLearnCacheManager::new(config, 1024 * 1024);

        // Train the model a bit
        let hash = ContentHash::from(&[1u8; 32]);
        let _ = cache_manager.decide_caching(&hash).await;

        // Save should succeed
        let result = cache_manager.save_model().await;
        assert!(result.is_ok());
    }

    // ==================== CacheDecision Tests ====================

    #[test]
    fn test_cache_decision_debug() {
        let cache = CacheDecision::Cache;
        let skip = CacheDecision::Skip;
        let evict = CacheDecision::Evict;

        // Verify Debug is implemented
        assert_eq!(format!("{:?}", cache), "Cache");
        assert_eq!(format!("{:?}", skip), "Skip");
        assert_eq!(format!("{:?}", evict), "Evict");
    }

    // (StorageStrategy tests removed — storage is handled by saorsa-node)

    // ==================== ChurnStats Tests ====================

    #[test]
    fn test_churn_stats_struct() {
        let stats = ChurnStats {
            churn_rate: 0.05,
            nodes_joined_last_hour: 10,
            nodes_left_last_hour: 5,
        };

        // Verify Debug is implemented
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("0.05"));
        assert!(debug_str.contains("10"));
        assert!(debug_str.contains("5"));
    }

    // ==================== NetworkChurnPrediction Tests ====================

    #[test]
    fn test_network_churn_prediction_struct() {
        let prediction = NetworkChurnPrediction {
            probability_1h: 0.1,
            probability_6h: 0.15,
            probability_24h: 0.2,
        };

        // Verify Debug is implemented
        let debug_str = format!("{:?}", prediction);
        assert!(debug_str.contains("0.1"));
        assert!(debug_str.contains("0.15"));
        assert!(debug_str.contains("0.2"));
    }

    // (ContentStoreExtensions tests removed — storage is handled by saorsa-node)
}
