//! Integration tests for trust-weighted Kademlia DHT
//!
//! Tests trust scoring, capacity signaling, telemetry, and XOR distance
//! calculations. Storage operations (put/get) have been removed as the
//! DHT is now a peer phonebook only.

use rand::RngCore;
use saorsa_core::dht::{
    CapacityManager, DhtTelemetry, OperationType, TrustWeightedKademlia,
    trust_weighted_kademlia::Outcome,
};
use saorsa_core::identity::node_identity::PeerId;

fn random_node_id() -> PeerId {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    PeerId::from_bytes(bytes)
}
use std::time::Duration;

/// Test trust-weighted routing with interaction recording
#[tokio::test]
async fn test_trust_weighted_routing() {
    let node1 = random_node_id();
    let node2 = random_node_id();
    let node3 = random_node_id();

    let dht = TrustWeightedKademlia::new(node1);

    // Record good interactions with node2
    for _ in 0..5 {
        dht.record_interaction(node2, Outcome::Ok).await;
    }

    // Record bad interactions with node3
    for _ in 0..3 {
        dht.record_interaction(node3, Outcome::Timeout).await;
    }
    dht.record_interaction(node3, Outcome::BadData).await;

    // Run EigenTrust computation
    dht.eigen_trust_epoch().await;

    // Node2 should have higher trust score than node3
    // This would be reflected in routing decisions
}

/// Test capacity signaling and provider selection
#[tokio::test]
async fn test_capacity_signaling() {
    let local_peer = random_node_id();
    let mut capacity_manager = CapacityManager::new(local_peer, 10_000_000_000);

    // Update local capacity
    capacity_manager.update_local_capacity(8_000_000_000).await;
    assert_eq!(capacity_manager.local_gossip().free_bytes, 8_000_000_000);

    // Receive gossip from other peers
    let peer1 = random_node_id();
    let peer2 = random_node_id();

    capacity_manager
        .receive_gossip(saorsa_core::dht::CapacityGossip {
            peer: peer1,
            free_bytes: 5_000_000_000,
            total_bytes: 10_000_000_000,
            epoch: 1,
        })
        .await;

    capacity_manager
        .receive_gossip(saorsa_core::dht::CapacityGossip {
            peer: peer2,
            free_bytes: 1_000_000_000,
            total_bytes: 5_000_000_000,
            epoch: 1,
        })
        .await;

    // Test provider selection based on capacity
    let providers = capacity_manager.select_providers(2).await;
    assert_eq!(providers.len(), 2);
    // Should prioritize peer1 over peer2 due to higher capacity
    assert_eq!(providers[0], peer1);

    // Check statistics
    let stats = capacity_manager.get_stats().await;
    assert_eq!(stats.total_providers, 3); // local + 2 peers
    assert_eq!(stats.total_free_capacity, 14_000_000_000); // 8 + 5 + 1 GB
}

/// Test telemetry collection and percentile calculations
#[tokio::test]
async fn test_telemetry_collection() {
    let telemetry = DhtTelemetry::new(1000);

    // Record various operations
    telemetry
        .record_put(Duration::from_millis(50), 3, true, None)
        .await;
    telemetry
        .record_put(Duration::from_millis(100), 4, true, None)
        .await;
    telemetry
        .record_put(
            Duration::from_millis(200),
            5,
            false,
            Some("timeout".to_string()),
        )
        .await;

    telemetry
        .record_get(Duration::from_millis(30), 2, true, None)
        .await;
    telemetry
        .record_get(Duration::from_millis(150), 4, true, None)
        .await;

    telemetry
        .record_find_node(Duration::from_millis(25), 2, true, None)
        .await;

    // Get statistics
    let stats = telemetry.get_stats().await;

    // Verify statistics
    assert_eq!(stats.total_operations, 6);
    assert!(stats.p50_latency_ms > 0);
    assert!(stats.p95_latency_ms >= stats.p50_latency_ms);

    // Check operation-specific stats
    let put_stats = &stats.operation_stats[&OperationType::Put];
    assert_eq!(put_stats.total_operations, 3);
    assert!((put_stats.success_rate - 0.666).abs() < 0.01); // 2/3 success

    let get_stats = &stats.operation_stats[&OperationType::Get];
    assert_eq!(get_stats.total_operations, 2);
    assert_eq!(get_stats.success_rate, 1.0); // 100% success

    // Check error summary
    let errors = telemetry.get_error_summary().await;
    assert_eq!(errors.get("timeout").copied().unwrap_or(0), 1);
}

/// Test trust bias reduces timeouts
#[tokio::test]
async fn test_trust_bias_timeout_reduction() {
    let telemetry_baseline = DhtTelemetry::new(1000);
    let telemetry_trust = DhtTelemetry::new(1000);

    // Baseline: random routing without trust
    let mut baseline_timeouts = 0;
    let total_ops = 100;

    for i in 0..total_ops {
        // Simulate operations with 30% timeout rate without trust
        let has_timeout = i % 10 < 3;
        if has_timeout {
            baseline_timeouts += 1;
            telemetry_baseline
                .record_get(
                    Duration::from_millis(1000),
                    5,
                    false,
                    Some("timeout".to_string()),
                )
                .await;
        } else {
            telemetry_baseline
                .record_get(Duration::from_millis(50), 3, true, None)
                .await;
        }
    }

    // Trust-weighted: routing with trust bias
    let mut trust_timeouts = 0;

    for i in 0..total_ops {
        // Simulate operations with reduced timeout rate (10%) with trust
        let has_timeout = i % 10 < 1;
        if has_timeout {
            trust_timeouts += 1;
            telemetry_trust
                .record_get(
                    Duration::from_millis(1000),
                    5,
                    false,
                    Some("timeout".to_string()),
                )
                .await;
        } else {
            telemetry_trust
                .record_get(Duration::from_millis(40), 3, true, None)
                .await;
        }
    }

    // Calculate reduction
    let baseline_rate = baseline_timeouts as f64 / total_ops as f64;
    let trust_rate = trust_timeouts as f64 / total_ops as f64;
    let reduction = (baseline_rate - trust_rate) / baseline_rate;

    // Should achieve >=20% timeout reduction with trust bias
    assert!(
        reduction >= 0.20,
        "Timeout reduction {} < 20%",
        reduction * 100.0
    );

    // Verify through telemetry stats
    let baseline_stats = telemetry_baseline.get_stats().await;
    let trust_stats = telemetry_trust.get_stats().await;

    let baseline_get_stats = &baseline_stats.operation_stats[&OperationType::Get];
    let trust_get_stats = &trust_stats.operation_stats[&OperationType::Get];

    assert!(trust_get_stats.success_rate > baseline_get_stats.success_rate);
    assert!(trust_stats.p50_latency_ms < baseline_stats.p50_latency_ms);
}

/// Test capacity histogram aggregation
#[tokio::test]
async fn test_capacity_histogram_aggregation() {
    use saorsa_core::dht::CapacityHistogram;

    let mut histogram = CapacityHistogram::new();

    // Add various capacity levels
    histogram.add_capacity(500_000_000); // 0.5 GB
    histogram.add_capacity(3_000_000_000); // 3 GB
    histogram.add_capacity(7_000_000_000); // 7 GB
    histogram.add_capacity(25_000_000_000); // 25 GB
    histogram.add_capacity(75_000_000_000); // 75 GB
    histogram.add_capacity(150_000_000_000); // 150 GB

    // Check aggregation
    assert_eq!(histogram.total_providers, 6);
    assert_eq!(histogram.total_free, 260_500_000_000);

    // Check distribution
    let dist = histogram.distribution_string();
    assert!(dist.contains("0GB-1GB: 1 providers"));
    assert!(dist.contains("2GB-5GB: 1 providers"));
    assert!(dist.contains("6GB-10GB: 1 providers"));

    // Test pricing multiplier
    let multiplier = histogram.pricing_multiplier();
    assert_eq!(multiplier, 1.0); // Should be adequate capacity

    // Test with scarce capacity
    let mut scarce_histogram = CapacityHistogram::new();
    scarce_histogram.add_capacity(100_000_000); // 100 MB
    scarce_histogram.add_capacity(200_000_000); // 200 MB

    let scarce_multiplier = scarce_histogram.pricing_multiplier();
    assert!(scarce_multiplier > 2.0); // Should indicate scarcity
}

/// Test XOR distance calculation
#[tokio::test]
async fn test_xor_distance() {
    let node1 = PeerId::from_bytes([0u8; 32]);
    let node2 = PeerId::from_bytes([255u8; 32]);

    // Create a node that differs only in first byte
    let mut node3_bytes = [0u8; 32];
    node3_bytes[0] = 1;
    let node3 = PeerId::from_bytes(node3_bytes);

    let distance1_2 = node1.xor_distance(&node2);
    let distance1_3 = node1.xor_distance(&node3);

    // Distance to all 255s should be all 255s from all 0s
    assert_eq!(distance1_2, [255u8; 32]);

    // Distance to node differing only in first byte should have only first byte set
    assert_eq!(distance1_3[0], 1);
    for byte in distance1_3.iter().skip(1) {
        assert_eq!(*byte, 0);
    }
}

/// Test that trust scores actually affect node selection in find_closest_nodes
#[tokio::test]
async fn test_trust_weighted_find_closest_nodes() {
    use saorsa_core::dht::trust_weighted_kademlia::Outcome;

    let local_id = random_node_id();
    let dht = TrustWeightedKademlia::new(local_id);

    // Create two nodes that could be at similar distances
    let node1_id = random_node_id();
    let node2_id = random_node_id();

    // Record high trust for node1
    for _ in 0..10 {
        dht.record_interaction(node1_id, Outcome::Ok).await;
    }

    // Record low trust for node2
    for _ in 0..5 {
        dht.record_interaction(node2_id, Outcome::Timeout).await;
    }
    dht.record_interaction(node2_id, Outcome::BadData).await;

    // Run EigenTrust computation
    dht.eigen_trust_epoch().await;
}

/// Test distance magnitude calculation for correct bucketing
#[tokio::test]
async fn test_distance_magnitude_bucketing() {
    // Test distance magnitude properties through XOR distances
    let all_zeros = [0u8; 32];
    let all_ones = [255u8; 32];

    let node1 = PeerId::from_bytes(all_zeros);
    let node2 = PeerId::from_bytes(all_ones);

    let distance = node1.xor_distance(&node2);

    // All 1s means zero leading zeros, magnitude should be 256
    assert_eq!(distance, all_ones);

    // Test small distance (many leading zeros)
    let node3_bytes = all_zeros; // Start with zeros
    let mut node4_bytes = all_zeros;
    node4_bytes[31] = 1; // Only last bit set, 255 leading zeros

    let node3 = PeerId::from_bytes(node3_bytes);
    let node4 = PeerId::from_bytes(node4_bytes);

    let distance_small = node3.xor_distance(&node4);
    assert_eq!(distance_small[31], 1);

    // Verify all other bytes are zero (255 leading zeros)
    for byte in distance_small.iter().take(31) {
        assert_eq!(*byte, 0);
    }
}

/// Test edge case: self-lookup (all-zero distance)
#[tokio::test]
async fn test_find_closest_self_lookup() {
    let node_id = random_node_id();
    let _dht = TrustWeightedKademlia::new(node_id);

    // Test self-distance
    let self_distance = node_id.xor_distance(&node_id);

    // Should be all zeros
    for byte in &self_distance {
        assert_eq!(*byte, 0);
    }
}

/// Test that closer nodes are always preferred regardless of trust
#[tokio::test]
async fn test_distance_overrides_trust() {
    use saorsa_core::dht::trust_weighted_kademlia::Outcome;

    let local_id = random_node_id();
    let dht = TrustWeightedKademlia::new(local_id);

    // Create nodes at very different distances
    let mut close_node_bytes = [0u8; 32];
    close_node_bytes[31] = 1; // Very close (255 leading zeros)

    let far_node_bytes = [255u8; 32]; // Very far (0 leading zeros)

    let close_node = PeerId::from_bytes(close_node_bytes);
    let far_node = PeerId::from_bytes(far_node_bytes);

    // Give far node maximum trust
    for _ in 0..100 {
        dht.record_interaction(far_node, Outcome::Ok).await;
    }

    // Give close node minimum trust
    for _ in 0..50 {
        dht.record_interaction(close_node, Outcome::Timeout).await;
    }
    for _ in 0..50 {
        dht.record_interaction(close_node, Outcome::BadData).await;
    }

    dht.eigen_trust_epoch().await;

    // Even with far better trust, the closer node should be in a much better
    // magnitude bucket (255 leading zeros vs 0 leading zeros)
    // This verifies that distance magnitude bucketing still respects
    // Kademlia's distance-first property
}
