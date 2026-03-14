//! Adaptive integration tests aligned with current APIs

use saorsa_core::PeerId;
use saorsa_core::adaptive::q_learning_cache::{ActionType, StateVector};
use saorsa_core::adaptive::*;
use std::sync::Arc;

#[tokio::test]
async fn test_q_learning_manager_updates_q_values() -> anyhow::Result<()> {
    let cfg = QLearningConfig {
        learning_rate: 0.5,
        discount_factor: 0.9,
        epsilon: 0.0,
        buffer_size: 128,
        batch_size: 8,
        ..Default::default()
    };

    let manager = QLearningCacheManager::new(cfg, 10 * 1024 * 1024);

    let s1 = StateVector::from_metrics(0.2, 2.0, 30, 2048);
    let s2 = StateVector::from_metrics(0.3, 4.0, 10, 4096);

    let before = manager.get_q_value(&s1, ActionType::Cache).await;
    assert_eq!(before, 0.0);

    manager
        .update_q_value(&s1, ActionType::Cache, 1.0, &s2, false)
        .await?;

    let after = manager.get_q_value(&s1, ActionType::Cache).await;
    assert!(after > before);
    Ok(())
}

#[tokio::test]
async fn test_security_manager_validate_join() -> anyhow::Result<()> {
    let identity = saorsa_core::identity::NodeIdentity::generate()?;
    let sm = SecurityManager::new(SecurityConfig::default(), &identity);

    let desc = NodeDescriptor {
        id: saorsa_core::identity::node_identity::peer_id_from_public_key(identity.public_key()),
        public_key: identity.public_key().clone(),
        addresses: vec!["127.0.0.1:0".parse().unwrap()],
        hyperbolic: None,
        som_position: None,
        trust: 0.5,
        capabilities: NodeCapabilities {
            compute: 1,
            bandwidth: 1,
        },
    };

    sm.validate_node_join(&desc).await?;
    sm.check_rate_limit(&desc.id, None).await?;
    Ok(())
}

#[tokio::test]
async fn test_adaptive_router_routes_with_registered_strategy() -> anyhow::Result<()> {
    let trust = Arc::new(MockTrustProvider::new());
    let _hyper = Arc::new(HyperbolicSpace::new());
    let router = AdaptiveRouter::new(trust);

    struct DirectStrategy;
    #[async_trait::async_trait]
    impl RoutingStrategy for DirectStrategy {
        async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
            Ok(vec![*target])
        }
        fn route_score(&self, _from: &PeerId, _to: &PeerId) -> f64 {
            1.0
        }
        fn update_metrics(&self, _path: &[PeerId], _success: bool) {}
    }

    router
        .register_strategy(StrategyChoice::Kademlia, Arc::new(DirectStrategy))
        .await;

    let target = PeerId::from_bytes([1u8; 32]);
    let path = router.route(&target, ContentType::DHTLookup).await?;
    assert_eq!(path.len(), 1);
    assert_eq!(path[0], target);
    Ok(())
}
