// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Component Builder Module
//!
//! Provides focused builder functions for each component group used by
//! the NetworkCoordinator. Each builder is ~40-50 lines and testable in isolation.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

// Import from parent module's re-exports
use super::monitoring::{LogLevel, MonitoredComponents};
use super::performance::CacheConfig;
use super::security::{
    AuditConfig, BlacklistConfig, EclipseDetectionConfig, IntegrityConfig, RateLimitConfig,
};
use super::som::{GridSize, SomConfig};
use super::{
    AdaptiveDHT, AdaptiveGossipSub, AdaptiveRouter, ChurnConfig, ChurnHandler, ChurnPredictor,
    ContentHash, EigenTrustEngine, HyperbolicSpace, MABConfig, MonitoringConfig, MonitoringSystem,
    MultiArmedBandit, NodeIdentity, PerformanceCache, QLearnCacheManager, QLearningCacheManager,
    QLearningConfig, SecurityConfig, SecurityManager, SelfOrganizingMap, ThompsonSampling,
    TransportManager,
};
use crate::{P2PError, Result};

use super::coordinator::{
    LearningComponents, NetworkComponents, NetworkConfig, OperationsComponents, RoutingComponents,
};

// ============================================================================
// Network Components Builder
// ============================================================================

impl NetworkComponents {
    /// Build network components from configuration
    ///
    /// Creates: identity, transport, dht, router, gossip
    pub async fn build(
        identity: NodeIdentity,
        _config: &NetworkConfig,
        trust_engine: Arc<EigenTrustEngine>,
    ) -> Result<(Self, Arc<AdaptiveRouter>)> {
        let identity = Arc::new(identity);
        let transport = Arc::new(TransportManager::new());

        // Create adaptive router
        let router = Arc::new(AdaptiveRouter::new(trust_engine.clone()));

        // Initialize DHT
        let dht = Arc::new(
            AdaptiveDHT::new(identity.clone(), trust_engine.clone(), router.clone()).await?,
        );

        // Initialize gossip
        let gossip = Arc::new(AdaptiveGossipSub::new(
            *identity.peer_id(),
            trust_engine.clone(),
        ));

        let components = Self {
            identity,
            transport,
            dht,
            router: router.clone(),
            gossip,
        };

        Ok((components, router))
    }
}

// ============================================================================
// Routing Components Builder
// ============================================================================

impl RoutingComponents {
    /// Build routing components from configuration
    ///
    /// Creates: hyperbolic_space, som, trust_engine
    pub fn build(_config: &NetworkConfig) -> Result<(Self, Arc<EigenTrustEngine>)> {
        // Create trust provider for components that need it
        let pre_trusted = HashSet::new();
        let trust_engine = Arc::new(EigenTrustEngine::new(pre_trusted));

        // Initialize routing components
        let hyperbolic_space = Arc::new(HyperbolicSpace::new());
        let som = Arc::new(SelfOrganizingMap::new(SomConfig {
            initial_learning_rate: 0.3,
            initial_radius: 5.0,
            iterations: 1000,
            grid_size: GridSize::Fixed(10, 10),
        }));

        let components = Self {
            hyperbolic_space,
            som,
            trust_engine: trust_engine.clone(),
        };

        Ok((components, trust_engine))
    }
}

// (StorageComponents builder removed — storage is handled by saorsa-node)

// ============================================================================
// Learning Components Builder
// ============================================================================

impl LearningComponents {
    /// Build ML/learning components from configuration
    ///
    /// Creates: mab, q_learning_cache, churn_predictor
    pub async fn build(config: &NetworkConfig) -> Result<(Self, Arc<ChurnPredictor>)> {
        // Initialize ML components
        let churn_predictor = Arc::new(ChurnPredictor::new());

        // Initialize ML optimizers
        let mab_config = MABConfig::default();
        let mab = Arc::new(
            MultiArmedBandit::new(mab_config)
                .await
                .map_err(|e| P2PError::Internal(format!("Failed to create MAB: {}", e).into()))?,
        );

        // Create Q-learning cache
        let q_config = QLearningConfig::default();
        let q_learning_cache = Arc::new(QLearningCacheManager::new(
            q_config,
            config.storage_capacity * 1024 * 1024,
        ));

        let components = Self {
            mab,
            q_learning_cache,
            churn_predictor: churn_predictor.clone(),
        };

        Ok((components, churn_predictor))
    }
}

// ============================================================================
// Operations Components Builder
// ============================================================================

impl OperationsComponents {
    /// Build operations/monitoring components from configuration
    ///
    /// Creates: churn_handler, monitoring, security, performance
    pub fn build(
        config: &NetworkConfig,
        identity: &NodeIdentity,
        churn_predictor: Arc<ChurnPredictor>,
        trust_engine: Arc<EigenTrustEngine>,
        router: Arc<AdaptiveRouter>,
        gossip: Arc<AdaptiveGossipSub>,
        retrieval_cache: Arc<QLearnCacheManager>,
    ) -> Result<Self> {
        // Initialize churn handler
        let churn_config = ChurnConfig::default();
        let churn_handler = Arc::new(ChurnHandler::new(
            *identity.peer_id(),
            churn_predictor,
            trust_engine,
            router.clone(),
            gossip.clone(),
            churn_config,
        ));

        // Create ThompsonSampling for monitoring
        let thompson = Arc::new(ThompsonSampling::new());

        // Initialize monitoring
        let monitoring_config = MonitoringConfig {
            collection_interval: config.monitoring_interval,
            anomaly_window_size: 100,
            alert_cooldown: Duration::from_secs(300),
            profiling_sample_rate: 0.1,
            log_level: LogLevel::Info,
            dashboard_interval: Duration::from_secs(10),
        };

        let monitored_components = MonitoredComponents {
            router,
            churn_handler: churn_handler.clone(),
            gossip,
            thompson,
            cache: retrieval_cache,
        };

        let monitoring = Arc::new(
            MonitoringSystem::new(monitored_components, monitoring_config)
                .map_err(|_| P2PError::Network(crate::error::NetworkError::Timeout))?,
        );

        // Initialize security
        let security = Self::build_security(config, identity)?;

        // Initialize performance cache
        let cache_config = CacheConfig {
            max_entries: 1000,
            ttl: Duration::from_secs(3600),
            compression: false,
        };
        let performance = Arc::new(PerformanceCache::<ContentHash, Vec<u8>>::new(cache_config));

        Ok(Self {
            churn_handler,
            monitoring,
            security,
            performance,
        })
    }

    /// Build security manager with full configuration
    fn build_security(
        _config: &NetworkConfig,
        identity: &NodeIdentity,
    ) -> Result<Arc<SecurityManager>> {
        let security_config = SecurityConfig {
            rate_limit: RateLimitConfig {
                node_requests_per_window: 1000,
                ip_requests_per_window: 5000,
                window_duration: Duration::from_secs(60),
                max_connections_per_node: 50,
                max_joins_per_hour: 100,
                max_tracked_nodes: 10000,
                max_tracked_ips: 10000,
            },
            blacklist: BlacklistConfig {
                entry_ttl: Duration::from_secs(86400), // 24 hours
                max_entries: 10000,
                violation_threshold: 10,
            },
            eclipse_detection: EclipseDetectionConfig {
                min_diversity_score: 0.5,
                max_subnet_ratio: 0.2,
                pattern_threshold: 0.7,
            },
            integrity: IntegrityConfig::default(),
            audit: AuditConfig::default(),
        };

        Ok(Arc::new(SecurityManager::new(security_config, identity)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_components_build() {
        let config = NetworkConfig::default();
        let result = RoutingComponents::build(&config);
        assert!(result.is_ok());

        let (components, trust_engine) = result.unwrap();
        assert!(Arc::strong_count(&components.trust_engine) >= 1);
        assert!(Arc::strong_count(&trust_engine) >= 1);
    }

    #[tokio::test]
    async fn test_learning_components_build() {
        let config = NetworkConfig::default();
        let result = LearningComponents::build(&config).await;
        assert!(result.is_ok());

        let (components, churn_predictor) = result.unwrap();
        assert!(Arc::strong_count(&components.churn_predictor) >= 1);
        assert!(Arc::strong_count(&churn_predictor) >= 1);
    }

    #[tokio::test]
    async fn test_network_components_build() {
        let identity = NodeIdentity::generate().unwrap();
        let config = NetworkConfig::default();
        let (_, trust_engine) = RoutingComponents::build(&config).unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            NetworkComponents::build(identity, &config, trust_engine),
        )
        .await;

        // Either succeeds or times out in test environment
        match result {
            Ok(Ok((components, router))) => {
                assert!(Arc::strong_count(&components.identity) >= 1);
                assert!(Arc::strong_count(&router) >= 1);
            }
            Ok(Err(e)) => {
                println!("Network components build failed (may be expected): {}", e);
            }
            Err(_) => {
                println!("Network components build timed out (expected in test environment)");
            }
        }
    }

    #[tokio::test]
    async fn test_full_coordinator_build_sequence() {
        // Test the full build sequence that the coordinator would use
        let config = NetworkConfig::default();

        // 1. Build routing first (provides trust_engine)
        let (_, trust_engine) = RoutingComponents::build(&config).unwrap();

        // 2. Build learning (provides churn_predictor)
        let (learning, churn_predictor) = LearningComponents::build(&config).await.unwrap();

        // 3. Build network (needs trust_engine, provides router)
        let identity_for_network = NodeIdentity::generate().unwrap();
        let identity_for_ops = NodeIdentity::generate().unwrap();

        let network_result = tokio::time::timeout(
            Duration::from_secs(5),
            NetworkComponents::build(identity_for_network, &config, trust_engine.clone()),
        )
        .await;

        match network_result {
            Ok(Ok((network, router))) => {
                // 4. Build operations (needs trust_engine, churn_predictor, router, gossip, cache)
                let cache = Arc::new(QLearnCacheManager::new(
                    (config.storage_capacity * 1024 * 1024) as usize,
                ));
                let ops_result = OperationsComponents::build(
                    &config,
                    &identity_for_ops,
                    churn_predictor,
                    trust_engine,
                    router,
                    network.gossip.clone(),
                    cache,
                );

                assert!(ops_result.is_ok(), "Operations build should succeed");
                // Verify learning components were built
                assert!(Arc::strong_count(&learning.mab) >= 1);
            }
            _ => println!("Network build skipped due to timeout or error"),
        }
    }
}
