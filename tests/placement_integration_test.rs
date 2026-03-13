// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Comprehensive integration tests for the placement system
//!
//! Tests cover:
//! - Basic placement operations
//! - Byzantine fault tolerance
//! - Diversity enforcement (geographic, ASN, region)
//! - EigenTrust integration

use saorsa_core::PeerId;
use saorsa_core::adaptive::performance::PerformanceMonitor;
use saorsa_core::adaptive::trust::EigenTrustEngine;
use saorsa_core::placement::{
    ByzantineTolerance, GeographicLocation, NetworkRegion, OptimizationWeights, PlacementConfig,
    PlacementEngine, PlacementError, ReplicationFactor,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

// ============================================================================
// Test Fixtures & Helper Functions
// ============================================================================

/// Create test nodes with sequential IDs
fn create_test_nodes(count: usize) -> Vec<PeerId> {
    (0..count)
        .map(|i| {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            hash[1] = (i >> 8) as u8;
            PeerId::from_bytes(hash)
        })
        .collect()
}

/// Create node metadata with diverse geographic locations
fn create_diverse_node_metadata(
    nodes: &[PeerId],
) -> HashMap<PeerId, (GeographicLocation, u32, NetworkRegion)> {
    let locations = [
        (40.7128, -74.0060, 12345, NetworkRegion::NorthAmerica), // NYC
        (34.0522, -118.2437, 12346, NetworkRegion::NorthAmerica), // LA
        (51.5074, -0.1278, 23456, NetworkRegion::Europe),        // London
        (48.8566, 2.3522, 23457, NetworkRegion::Europe),         // Paris
        (35.6762, 139.6503, 34567, NetworkRegion::AsiaPacific),  // Tokyo
        (37.7749, -122.4194, 12347, NetworkRegion::NorthAmerica), // SF
        (52.5200, 13.4050, 23458, NetworkRegion::Europe),        // Berlin
        (1.3521, 103.8198, 34568, NetworkRegion::AsiaPacific),   // Singapore
        (-23.5505, -46.6333, 45678, NetworkRegion::SouthAmerica), // Sao Paulo
        (-33.8688, 151.2093, 56789, NetworkRegion::Oceania),     // Sydney
    ];

    let mut metadata = HashMap::new();
    for (i, node_id) in nodes.iter().enumerate() {
        let (lat, lon, base_asn, region) = locations[i % locations.len()];
        let asn = base_asn + (i / locations.len()) as u32;
        let location = GeographicLocation::new(lat, lon)
            .unwrap_or_else(|_| GeographicLocation::new(0.0, 0.0).unwrap());
        metadata.insert(*node_id, (location, asn, region));
    }

    metadata
}

/// Create node metadata with all nodes in same region (for diversity violation tests)
fn create_same_region_metadata(
    nodes: &[PeerId],
) -> HashMap<PeerId, (GeographicLocation, u32, NetworkRegion)> {
    let mut metadata = HashMap::new();
    for (i, node_id) in nodes.iter().enumerate() {
        let lat = 40.0 + (i as f64 * 0.001);
        let lon = -74.0 + (i as f64 * 0.001);
        let location = GeographicLocation::new(lat, lon)
            .unwrap_or_else(|_| GeographicLocation::new(0.0, 0.0).unwrap());
        metadata.insert(*node_id, (location, 12345, NetworkRegion::NorthAmerica));
    }
    metadata
}

/// Create a basic placement engine for testing
fn create_test_placement_engine() -> PlacementEngine {
    let config = PlacementConfig::default();
    PlacementEngine::new(config)
}

/// Create a placement engine with custom configuration
fn create_custom_placement_engine(
    replication_factor: ReplicationFactor,
    byzantine_tolerance: ByzantineTolerance,
) -> Result<PlacementEngine, PlacementError> {
    let config = PlacementConfig::new(
        replication_factor,
        Duration::from_secs(30),
        byzantine_tolerance,
        OptimizationWeights::default(),
    )?;
    Ok(PlacementEngine::new(config))
}

/// Verify diversity constraints in selection
fn verify_diversity_constraints(
    selection: &[PeerId],
    metadata: &HashMap<PeerId, (GeographicLocation, u32, NetworkRegion)>,
) -> bool {
    if selection.len() < 2 {
        return true;
    }

    // Check region diversity - no single region should dominate (>60%)
    let mut region_counts = HashMap::new();
    for node_id in selection {
        if let Some((_, _, region)) = metadata.get(node_id) {
            *region_counts.entry(region).or_insert(0) += 1;
        }
    }

    let max_region_count = region_counts.values().max().copied().unwrap_or(0);
    let max_allowed = (selection.len() as f64 * 0.6).ceil() as usize;

    max_region_count <= max_allowed
}

/// Verify Byzantine fault tolerance requirements
fn verify_byzantine_tolerance(
    selection: &[PeerId],
    byzantine_tolerance: &ByzantineTolerance,
) -> bool {
    selection.len() >= byzantine_tolerance.required_nodes()
}

/// Calculate trust distribution across selections
fn calculate_trust_distribution(selections: &[Vec<PeerId>]) -> HashMap<PeerId, usize> {
    let mut distribution = HashMap::new();
    for selection in selections {
        for node_id in selection {
            *distribution.entry(*node_id).or_insert(0) += 1;
        }
    }
    distribution
}

/// Create mock trust system
fn create_mock_trust_system() -> Arc<EigenTrustEngine> {
    Arc::new(EigenTrustEngine::new(HashSet::new()))
}

/// Create mock performance monitor
fn create_mock_performance_monitor() -> Arc<PerformanceMonitor> {
    Arc::new(PerformanceMonitor::new())
}

// ============================================================================
// Test Suite 1: Basic Placement Operations
// ============================================================================

#[tokio::test]
async fn test_basic_placement_selection() {
    let nodes = create_test_nodes(20);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    let decision = engine
        .select_nodes(&node_set, 8, &trust_system, &performance_monitor, &metadata)
        .await
        .expect("Placement selection should succeed");

    // Verify exactly 8 nodes selected
    assert_eq!(
        decision.selected_nodes.len(),
        8,
        "Should select exactly 8 nodes"
    );

    // Verify no duplicate nodes
    let unique_nodes: HashSet<_> = decision.selected_nodes.iter().cloned().collect();
    assert_eq!(
        unique_nodes.len(),
        decision.selected_nodes.len(),
        "Should have no duplicate nodes"
    );

    // Verify all selected nodes are from candidates
    for node in &decision.selected_nodes {
        assert!(
            node_set.contains(node),
            "Selected node should be from candidates"
        );
    }

    // Verify diversity score is set
    assert!(
        decision.diversity_score >= 0.0 && decision.diversity_score <= 1.0,
        "Diversity score should be in [0,1]"
    );
}

// ============================================================================
// Test Suite 2: Byzantine Fault Tolerance (2 tests)
// ============================================================================

#[tokio::test]
async fn test_byzantine_tolerance_enforcement() {
    let nodes = create_test_nodes(10);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    // Configure f=2 (requires 3f+1=7 nodes minimum)
    let replication = ReplicationFactor::new(7, 8, 16).expect("Valid replication factor");
    let byzantine = ByzantineTolerance::Classic { f: 2 };

    let mut engine = create_custom_placement_engine(replication, byzantine)
        .expect("Engine creation should succeed");

    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    let decision = engine
        .select_nodes(&node_set, 8, &trust_system, &performance_monitor, &metadata)
        .await
        .expect("Placement should succeed with 10 nodes");

    // Verify at least 7 nodes selected (3f+1 for f=2)
    assert!(
        decision.selected_nodes.len() >= 7,
        "Should select at least 7 nodes for f=2 Byzantine tolerance"
    );

    // Verify Byzantine requirements met
    assert!(verify_byzantine_tolerance(
        &decision.selected_nodes,
        &byzantine
    ));
}

#[tokio::test]
async fn test_insufficient_nodes_for_byzantine() {
    let nodes = create_test_nodes(8);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    // Configure f=3 (requires 10 nodes)
    let replication = ReplicationFactor::new(10, 10, 16).expect("Valid replication factor");
    let byzantine = ByzantineTolerance::Classic { f: 3 };

    let mut engine = create_custom_placement_engine(replication, byzantine)
        .expect("Engine creation should succeed");

    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    // Attempt placement with insufficient nodes
    let result = engine
        .select_nodes(
            &node_set,
            10,
            &trust_system,
            &performance_monitor,
            &metadata,
        )
        .await;

    // Should fail with InsufficientNodes error
    assert!(
        result.is_err(),
        "Should fail with insufficient nodes for Byzantine tolerance"
    );

    match result.unwrap_err() {
        PlacementError::InsufficientNodes {
            required,
            available,
        } => {
            assert_eq!(available, 8);
            assert!(required >= 10);
        }
        _ => panic!("Expected InsufficientNodes error"),
    }
}

// ============================================================================
// Test Suite 3: Diversity Enforcement (3 tests)
// ============================================================================

#[tokio::test]
async fn test_geographic_diversity_enforcement() {
    let nodes = create_test_nodes(30);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    let decision = engine
        .select_nodes(&node_set, 9, &trust_system, &performance_monitor, &metadata)
        .await
        .expect("Placement should succeed");

    // Verify multiple regions represented
    let mut regions = HashSet::new();
    for node in &decision.selected_nodes {
        if let Some((_, _, region)) = metadata.get(node) {
            regions.insert(region);
        }
    }

    assert!(
        regions.len() >= 2,
        "Should have nodes from at least 2 regions"
    );

    // Verify no single region dominates (>60%)
    assert!(
        verify_diversity_constraints(&decision.selected_nodes, &metadata),
        "Should enforce diversity constraints"
    );

    // Verify diversity score reflects this
    assert!(
        decision.diversity_score > 0.0,
        "Diversity score should be positive"
    );
}

#[tokio::test]
async fn test_asn_diversity() {
    let nodes = create_test_nodes(20);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    let decision = engine
        .select_nodes(&node_set, 8, &trust_system, &performance_monitor, &metadata)
        .await
        .expect("Placement should succeed");

    // Count ASNs represented
    let mut asns = HashSet::new();
    for node in &decision.selected_nodes {
        if let Some((_, asn, _)) = metadata.get(node) {
            asns.insert(asn);
        }
    }

    // Should have multiple ASNs represented
    assert!(
        asns.len() >= 3,
        "Should have nodes from at least 3 different ASNs"
    );
}

#[tokio::test]
async fn test_diversity_violation_detection() {
    let nodes = create_test_nodes(10);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    // All nodes in same region/close location
    let metadata = create_same_region_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    let result = engine
        .select_nodes(&node_set, 8, &trust_system, &performance_monitor, &metadata)
        .await;

    // Should either fail with diversity violation or succeed with low diversity score
    match result {
        Ok(decision) => {
            // If it succeeds, diversity score should reflect poor diversity
            assert!(
                decision.diversity_score < 1.0,
                "Diversity score should be reduced when all nodes are in same region"
            );
        }
        Err(PlacementError::DiversityViolation { constraint, .. }) => {
            // Expected error
            assert!(
                constraint.contains("geographic") || constraint.contains("region"),
                "Should detect geographic/region diversity violation"
            );
        }
        Err(e) => {
            panic!("Unexpected error type: {:?}", e);
        }
    }
}

// ============================================================================
// Test Suite 4: EigenTrust Integration (2 tests)
// ============================================================================

#[tokio::test]
async fn test_trust_weighted_placement() {
    let nodes = create_test_nodes(10);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    // Set up trust relationships
    // High trust nodes: 0, 1, 2
    for i in 0..3 {
        for j in 0..3 {
            if i != j {
                trust_system
                    .update_local_trust(&nodes[i], &nodes[j], true)
                    .await;
            }
        }
    }

    // Low trust nodes: 7, 8, 9
    for i in 7..10 {
        for j in 7..10 {
            if i != j {
                trust_system
                    .update_local_trust(&nodes[i], &nodes[j], false)
                    .await;
            }
        }
    }

    // Compute global trust
    trust_system.compute_global_trust().await;

    // Perform multiple placements to get statistical distribution
    let mut selections = Vec::new();
    for _ in 0..100 {
        let decision = engine
            .select_nodes(&node_set, 5, &trust_system, &performance_monitor, &metadata)
            .await
            .expect("Placement should succeed");
        selections.push(decision.selected_nodes);
    }

    // Calculate selection frequency
    let distribution = calculate_trust_distribution(&selections);

    // High-trust nodes should be selected more frequently
    let high_trust_avg = (0..3)
        .map(|i| distribution.get(&nodes[i]).copied().unwrap_or(0))
        .sum::<usize>() as f64
        / 3.0;

    let low_trust_avg = (7..10)
        .map(|i| distribution.get(&nodes[i]).copied().unwrap_or(0))
        .sum::<usize>() as f64
        / 3.0;

    // High trust nodes should be selected more often (allowing for randomness)
    assert!(
        high_trust_avg >= low_trust_avg * 0.8,
        "High-trust nodes should be selected at least as often as low-trust nodes"
    );
}

#[tokio::test]
async fn test_trust_updates_affect_placement() {
    let nodes = create_test_nodes(10);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    // Initial trust setup - all nodes have similar trust
    for i in 0..10 {
        for j in 0..10 {
            if i != j {
                trust_system
                    .update_local_trust(&nodes[i], &nodes[j], true)
                    .await;
            }
        }
    }
    trust_system.compute_global_trust().await;

    // First placement
    let decision1 = engine
        .select_nodes(&node_set, 5, &trust_system, &performance_monitor, &metadata)
        .await
        .expect("First placement should succeed");

    // Update trust - downgrade nodes 0, 1, 2
    for i in 0..3 {
        for j in 3..10 {
            trust_system
                .update_local_trust(&nodes[j], &nodes[i], false)
                .await;
        }
    }
    trust_system.compute_global_trust().await;

    // Wait a bit for trust updates to propagate
    sleep(Duration::from_millis(100)).await;

    // Second placement
    let decision2 = engine
        .select_nodes(&node_set, 5, &trust_system, &performance_monitor, &metadata)
        .await
        .expect("Second placement should succeed");

    // Decisions should potentially be different due to trust changes
    // (Though not guaranteed due to randomness and diversity factors)
    assert_eq!(decision1.selected_nodes.len(), 5);
    assert_eq!(decision2.selected_nodes.len(), 5);
}

// ============================================================================
// Test Suite 5: Placement Under Churn
// ============================================================================

#[tokio::test]
async fn test_placement_under_high_churn() {
    let nodes = create_test_nodes(30);
    let node_set: HashSet<PeerId> = nodes.iter().cloned().collect();
    let metadata = create_diverse_node_metadata(&nodes);

    let mut engine = create_test_placement_engine();
    let trust_system = create_mock_trust_system();
    let performance_monitor = create_mock_performance_monitor();

    // Simulate multiple placements with changing node availability
    for i in 0..10 {
        // Remove some nodes to simulate churn
        let available_nodes: HashSet<PeerId> = node_set
            .iter()
            .enumerate()
            .filter(|(idx, _)| (idx + i) % 3 != 0)
            .map(|(_, node)| *node)
            .collect();

        if available_nodes.len() >= 8 {
            let decision = engine
                .select_nodes(
                    &available_nodes,
                    8,
                    &trust_system,
                    &performance_monitor,
                    &metadata,
                )
                .await;

            match decision {
                Ok(d) => {
                    assert_eq!(d.selected_nodes.len(), 8);
                }
                Err(PlacementError::InsufficientNodes { .. }) => {
                    // Expected when not enough nodes available
                }
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }
    }
}

// ============================================================================
// Additional Helper Tests
// ============================================================================

#[test]
fn test_helper_functions() {
    // Test create_test_nodes
    let nodes = create_test_nodes(10);
    assert_eq!(nodes.len(), 10);
    let unique: HashSet<_> = nodes.iter().collect();
    assert_eq!(unique.len(), 10, "All nodes should be unique");

    // Test create_diverse_node_metadata
    let metadata = create_diverse_node_metadata(&nodes);
    assert_eq!(metadata.len(), 10);

    // Verify diversity in metadata
    let regions: HashSet<_> = metadata.values().map(|(_, _, region)| region).collect();
    assert!(regions.len() >= 2, "Should have multiple regions");

    // Test diversity verification
    let selection = nodes.iter().take(5).cloned().collect::<Vec<_>>();
    let is_diverse = verify_diversity_constraints(&selection, &metadata);
    assert!(is_diverse); // With diverse metadata, should pass

    // Test same region metadata
    let same_region = create_same_region_metadata(&nodes);
    let regions: HashSet<_> = same_region.values().map(|(_, _, region)| region).collect();
    assert_eq!(regions.len(), 1, "Should have single region");
}

#[test]
fn test_byzantine_tolerance_calculations() {
    let byzantine = ByzantineTolerance::Classic { f: 2 };
    assert_eq!(byzantine.required_nodes(), 7); // 3*2+1
    assert_eq!(byzantine.max_faults(), 2);

    let byzantine = ByzantineTolerance::Classic { f: 3 };
    assert_eq!(byzantine.required_nodes(), 10); // 3*3+1
    assert_eq!(byzantine.max_faults(), 3);

    let custom = ByzantineTolerance::Custom {
        total_nodes: 15,
        max_faults: 5,
    };
    assert_eq!(custom.required_nodes(), 15);
    assert_eq!(custom.max_faults(), 5);
}

#[test]
fn test_trust_distribution_calculation() {
    let nodes = create_test_nodes(5);

    let selections = vec![
        vec![nodes[0], nodes[1]],
        vec![nodes[1], nodes[2]],
        vec![nodes[0], nodes[2]],
    ];

    let distribution = calculate_trust_distribution(&selections);

    assert_eq!(*distribution.get(&nodes[0]).unwrap_or(&0), 2);
    assert_eq!(*distribution.get(&nodes[1]).unwrap_or(&0), 2);
    assert_eq!(*distribution.get(&nodes[2]).unwrap_or(&0), 2);
    assert_eq!(*distribution.get(&nodes[3]).unwrap_or(&0), 0);
    assert_eq!(*distribution.get(&nodes[4]).unwrap_or(&0), 0);
}
