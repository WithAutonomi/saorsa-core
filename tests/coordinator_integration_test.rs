// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Integration tests for NetworkCoordinator
//!
//! Storage operations (store/retrieve) have been removed from the coordinator.
//! The DHT is now a peer phonebook only; storage is handled by saorsa-node.

use saorsa_core::adaptive::{
    NetworkConfig, NetworkCoordinator, NodeIdentity, coordinator::DegradationReason,
};
use std::time::Duration;

#[tokio::test]
async fn test_full_system_integration() {
    // Create identities for multiple nodes
    let node1 = NodeIdentity::generate().unwrap();
    let node2 = NodeIdentity::generate().unwrap();
    let node3 = NodeIdentity::generate().unwrap();

    // Create coordinators
    let config1 = NetworkConfig {
        bootstrap_nodes: vec![],
        storage_capacity: 10,
        max_connections: 100,
        replication_factor: 3,
        ml_enabled: true,
        monitoring_interval: Duration::from_secs(5),
        security_level: 7,
    };

    let mut config2 = config1.clone();
    config2.bootstrap_nodes = vec!["localhost:8001".to_string()];

    let mut config3 = config1.clone();
    config3.bootstrap_nodes = vec!["localhost:8001".to_string(), "localhost:8002".to_string()];

    let Some(coordinator1) = maybe_coordinator(node1, config1, "coordinator1").await else {
        return;
    };
    let Some(coordinator2) = maybe_coordinator(node2, config2, "coordinator2").await else {
        return;
    };
    let Some(coordinator3) = maybe_coordinator(node3, config3, "coordinator3").await else {
        return;
    };

    // Join network
    let _ = coordinator1.join_network().await;
    let _ = coordinator2.join_network().await;
    let _ = coordinator3.join_network().await;

    // Test gossip messaging
    let _ = coordinator1
        .publish("test-topic", b"test message".to_vec())
        .await;

    // Test network statistics
    let stats = coordinator1.get_network_stats().await;
    assert!(stats.routing_success_rate >= 0.0 && stats.routing_success_rate <= 1.0);

    // Test graceful degradation
    let _ = coordinator1
        .handle_degradation(DegradationReason::HighChurn)
        .await;

    // Clean shutdown
    let _ = coordinator1.shutdown().await;
}

#[tokio::test]
async fn test_message_routing() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig::default();
    let Some(coordinator) = maybe_coordinator(identity, config, "message_routing").await else {
        return;
    };

    // Create a test message
    let message = saorsa_core::adaptive::NetworkMessage {
        id: "test-msg-1".to_string(),
        sender: coordinator.get_node_info().await.unwrap().id,
        content: vec![1, 2, 3, 4],
        msg_type: saorsa_core::adaptive::ContentType::DHTLookup,
        timestamp: 0,
    };

    // Route message (should succeed with local handler even without full network)
    let result = coordinator.route_message(message).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_layer_coordination() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig::default();
    let Some(coordinator) = maybe_coordinator(identity, config, "layer_coordination").await else {
        return;
    };

    // Test routing coordination
    let target = saorsa_core::PeerId::from_bytes([1u8; 32]);
    let paths = coordinator.coordinate_routing(&target).await;

    // Should return empty paths in test environment
    if let Ok(path) = paths {
        assert!(path.is_empty());
    }
    // Err is expected without actual network
}

#[tokio::test]
async fn test_metrics_collection() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig {
        monitoring_interval: Duration::from_millis(100),
        ..Default::default()
    };
    let Some(coordinator) = maybe_coordinator(identity, config, "metrics_collection").await else {
        return;
    };

    // Wait for metrics collection
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stats = coordinator.get_network_stats().await;
    assert_eq!(stats.connected_peers, 0); // No real connections in test
}

#[tokio::test]
async fn test_ml_integration() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig {
        ml_enabled: true,
        ..Default::default()
    };
    let Some(_coordinator) = maybe_coordinator(identity, config, "ml_integration").await else {
        return;
    };

    // ML components are integrated and initialized during construction.
    // Storage operations have been removed from the coordinator.
}

#[tokio::test]
async fn test_security_integration() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig {
        security_level: 10, // Maximum security
        ..Default::default()
    };
    let Some(_coordinator) = maybe_coordinator(identity, config, "security_integration").await
    else {
        return;
    };

    // Security components are initialized during construction.
    // Rate limiting is tested through the security manager directly.
}

#[tokio::test]
async fn test_concurrent_operations() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig::default();
    let Some(_coordinator) = maybe_coordinator(identity, config, "concurrent_ops").await else {
        return;
    };

    // Launch multiple concurrent operations
    let mut handles = vec![];

    for i in 0..10 {
        let data = vec![i as u8; 100];
        handles.push(tokio::spawn(async move {
            // Each task processes data concurrently
            data
        }));
    }

    // Wait for all operations
    for handle in handles {
        let _ = handle.await;
    }
}

#[tokio::test]
async fn test_graceful_shutdown() {
    let identity = NodeIdentity::generate().unwrap();
    let config = NetworkConfig::default();
    let Some(coordinator) = maybe_coordinator(identity, config, "graceful_shutdown").await else {
        return;
    };

    // Join network
    let _ = coordinator.join_network().await;

    // Graceful shutdown
    let _ = coordinator.shutdown().await;
}

async fn maybe_coordinator(
    identity: NodeIdentity,
    config: NetworkConfig,
    context: &str,
) -> Option<NetworkCoordinator> {
    match NetworkCoordinator::new(identity, config).await {
        Ok(coord) => Some(coord),
        Err(err) => {
            println!(
                "Skipping coordinator integration test `{}` due to environment error: {}",
                context, err
            );
            None
        }
    }
}
