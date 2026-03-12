//! Simple integration tests for adaptive network components
//! Tests only the publicly exported adaptive features

use saorsa_core::PeerId;
use saorsa_core::adaptive::{
    ContentHash,
    eviction::{CacheState, EvictionStrategy, LFUStrategy, LRUStrategy},
    learning::{ChurnPredictor, QLearnCacheManager, ThompsonSampling},
    multi_armed_bandit::{MABConfig, MultiArmedBandit},
    q_learning_cache::{AccessInfo, StateVector},
    security::{SecurityConfig, SecurityManager},
};
use saorsa_core::identity::NodeIdentity;
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

#[tokio::test]
async fn test_thompson_sampling_basic() -> anyhow::Result<()> {
    println!("Testing Thompson Sampling basic functionality...");

    let ts = ThompsonSampling::new();

    // Test that we can create a Thompson Sampling instance
    println!("✓ Thompson Sampling instance created successfully");

    // Test metrics exist (should start with 0 decisions)
    let metrics = ts.get_metrics().await;
    println!(
        "Initial metrics: total_decisions={}",
        metrics.total_decisions
    );
    assert_eq!(metrics.total_decisions, 0, "Should start with 0 decisions");

    Ok(())
}

#[tokio::test]
async fn test_multi_armed_bandit_basic() -> anyhow::Result<()> {
    println!("Testing Multi-Armed Bandit basic functionality...");

    let temp_dir = TempDir::new()?;
    let config = MABConfig {
        epsilon: 0.1,
        min_samples: 5,
        decay_factor: 0.95,
        storage_path: Some(temp_dir.path().to_path_buf()),
        persist_interval: Duration::from_secs(60),
        max_stats_age: Duration::from_secs(3600),
    };

    let mab = MultiArmedBandit::new(config).await?;
    println!("✓ Multi-Armed Bandit instance created successfully");

    // Test metrics exist
    let metrics = mab.get_metrics().await;
    println!(
        "Initial metrics: total_decisions={}",
        metrics.total_decisions
    );
    assert_eq!(metrics.total_decisions, 0, "Should start with 0 decisions");

    // Test persistence works
    mab.persist().await?;
    println!("✓ Persistence works");

    Ok(())
}

#[tokio::test]
async fn test_security_manager_basic() -> anyhow::Result<()> {
    println!("Testing Security Manager basic functionality...");

    let config = SecurityConfig::default();
    let identity = NodeIdentity::generate()?;
    let security = SecurityManager::new(config, &identity);

    println!("✓ Security Manager instance created successfully");

    // Test we can get metrics
    let metrics = security.get_metrics().await;
    println!(
        "Security metrics: blacklisted_nodes={}, audit_entries={}",
        metrics.blacklisted_nodes, metrics.audit_entries
    );

    Ok(())
}

#[tokio::test]
async fn test_eviction_strategies_basic() -> anyhow::Result<()> {
    println!("Testing Eviction Strategies basic functionality...");

    // Create test cache state
    let cache_state = CacheState {
        current_size: 800,
        max_size: 1000,
        item_count: 5,
        avg_access_frequency: 10.0,
    };

    // Create access info for test content
    let mut access_info = HashMap::new();
    let content_hashes = vec![
        ContentHash([1u8; 32]),
        ContentHash([2u8; 32]),
        ContentHash([3u8; 32]),
    ];

    for (i, hash) in content_hashes.iter().enumerate() {
        access_info.insert(
            *hash,
            AccessInfo {
                count: (i + 1) as u64 * 10,
                last_access_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
                    - (i as u64 * 60),
                size: 100,
            },
        );
    }

    // Test LRU strategy
    let mut lru = LRUStrategy::new();
    println!("Testing LRU Strategy: {}", lru.name());

    // Simulate accesses in order
    for hash in &content_hashes {
        lru.on_insert(hash);
    }

    let lru_victim = lru.select_victim(&cache_state, &access_info);
    println!("LRU selected victim: {:?}", lru_victim);

    // Test LFU strategy
    let mut lfu = LFUStrategy::new();
    println!("Testing LFU Strategy: {}", lfu.name());

    for hash in &content_hashes {
        lfu.on_insert(hash);
        // Simulate different access frequencies
        for _ in 0..((hash.0[0] % 5) + 1) {
            lfu.on_access(hash);
        }
    }

    let lfu_victim = lfu.select_victim(&cache_state, &access_info);
    println!("LFU selected victim: {:?}", lfu_victim);

    assert!(
        lru_victim.is_some() || lfu_victim.is_some(),
        "At least one strategy should select a victim"
    );

    Ok(())
}

#[tokio::test]
async fn test_q_learning_cache_basic() -> anyhow::Result<()> {
    println!("Testing Q-Learning Cache Manager basic functionality...");

    let manager = QLearnCacheManager::new(1024); // 1KB cache for testing

    // Test content insertion and retrieval
    let content_hash = ContentHash([1u8; 32]);
    let test_content = vec![1u8; 100]; // 100 bytes

    // Insert content
    let success = manager.insert(content_hash, test_content.clone()).await;
    println!("Inserted content: {}", success);

    // Test retrieval
    if let Some(data) = manager.get(&content_hash).await {
        println!("Cache hit: size = {}", data.len());
        assert_eq!(
            data, test_content,
            "Retrieved data should match inserted data"
        );
    } else {
        println!("Cache miss");
    }

    // Get cache statistics
    let stats = manager.get_stats_async().await;
    println!(
        "Cache stats: hits={}, misses={}, size={}, items={}",
        stats.hits, stats.misses, stats.size_bytes, stats.item_count
    );

    Ok(())
}

#[tokio::test]
async fn test_churn_predictor_basic() -> anyhow::Result<()> {
    println!("Testing Churn Predictor basic functionality...");

    let predictor = ChurnPredictor::new();
    println!("✓ Churn Predictor instance created successfully");

    // Test basic functionality exists
    let node_id = PeerId::from_bytes([1u8; 32]);
    let should_replicate = predictor.should_replicate(&node_id).await;
    println!("Should replicate from new node: {}", should_replicate);

    Ok(())
}

#[tokio::test]
async fn test_state_vector_basic() -> anyhow::Result<()> {
    println!("Testing State Vector basic functionality...");

    let test_cases = [
        (0.5, 10.0, 300, 1024 * 50),   // 50% util, 10/hr freq, 5min recency, 50KB
        (0.9, 100.0, 60, 1024 * 1024), // 90% util, 100/hr freq, 1min recency, 1MB
        (0.1, 1.0, 86400, 500),        // 10% util, 1/hr freq, 1day recency, 500B
    ];

    for (i, (utilization, frequency, recency_seconds, content_size)) in
        test_cases.iter().enumerate()
    {
        let state =
            StateVector::from_metrics(*utilization, *frequency, *recency_seconds, *content_size);

        println!(
            "Test case {}: util={:.1}%, freq={:.1}/hr, recency={}s, size={}B",
            i + 1,
            utilization * 100.0,
            frequency,
            recency_seconds,
            content_size
        );
        println!(
            "  Discretized: util_bucket={}, freq_bucket={}, recency_bucket={}, size_bucket={}",
            state.utilization_bucket,
            state.frequency_bucket,
            state.recency_bucket,
            state.content_size_bucket
        );

        // Validate buckets are within expected ranges
        assert!(
            state.utilization_bucket <= 10,
            "Utilization bucket should be <= 10"
        );
        assert!(
            state.frequency_bucket <= 5,
            "Frequency bucket should be <= 5"
        );
        assert!(state.recency_bucket <= 5, "Recency bucket should be <= 5");
        assert!(
            state.content_size_bucket <= 4,
            "Content size bucket should be <= 4"
        );
    }

    let state_space = StateVector::state_space_size();
    println!("Total state space size: {}", state_space);
    assert!(state_space > 0, "State space should be positive");

    Ok(())
}

#[tokio::test]
async fn test_adaptive_system_creation() -> anyhow::Result<()> {
    println!("\n=== Testing Adaptive System Component Creation ===\n");

    // Test that we can create all the main adaptive components
    let thompson = ThompsonSampling::new();
    println!("✓ Thompson Sampling created");

    let temp_dir = TempDir::new()?;
    let mab_config = MABConfig {
        epsilon: 0.1,
        min_samples: 5,
        decay_factor: 0.95,
        storage_path: Some(temp_dir.path().to_path_buf()),
        persist_interval: Duration::from_secs(60),
        max_stats_age: Duration::from_secs(3600),
    };
    let mab = MultiArmedBandit::new(mab_config).await?;
    println!("✓ Multi-Armed Bandit created");

    let cache_manager = QLearnCacheManager::new(2048);
    println!("✓ Q-Learning Cache Manager created");

    let identity = NodeIdentity::generate()?;
    let security = SecurityManager::new(SecurityConfig::default(), &identity);
    println!("✓ Security Manager created");

    let _predictor = ChurnPredictor::new();
    println!("✓ Churn Predictor created");

    // Verify metrics are accessible
    let ts_metrics = thompson.get_metrics().await;
    let mab_metrics = mab.get_metrics().await;
    let cache_stats = cache_manager.get_stats_async().await;
    let security_metrics = security.get_metrics().await;

    println!("Initial metrics:");
    println!(
        "  Thompson Sampling decisions: {}",
        ts_metrics.total_decisions
    );
    println!("  MAB decisions: {}", mab_metrics.total_decisions);
    println!(
        "  Cache hits: {}, misses: {}",
        cache_stats.hits, cache_stats.misses
    );
    println!(
        "  Security audit entries: {}",
        security_metrics.audit_entries
    );

    // Verify all systems start in expected state
    assert_eq!(
        ts_metrics.total_decisions, 0,
        "Thompson should start with 0 decisions"
    );
    assert_eq!(
        mab_metrics.total_decisions, 0,
        "MAB should start with 0 decisions"
    );
    assert_eq!(cache_stats.hits, 0, "Cache should start with 0 hits");
    assert_eq!(cache_stats.misses, 0, "Cache should start with 0 misses");

    println!("\n=== Adaptive System Component Creation Test Passed ===\n");

    Ok(())
}
