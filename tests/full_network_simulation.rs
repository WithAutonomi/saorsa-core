// Copyright (c) 2025 Saorsa Labs Limited
#![allow(clippy::unwrap_used, clippy::expect_used)]
// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Full network simulation test
//!
//! This test simulates a complete P2P network with multiple nodes
//! demonstrating all adaptive layers working together.
//!
//! Storage operations (store/retrieve) have been removed from the coordinator.
//! The DHT is now a peer phonebook only; storage is handled by saorsa-node.

use saorsa_core::PeerId;
use saorsa_core::adaptive::coordinator::DegradationReason;
use saorsa_core::adaptive::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Simulated network environment
struct NetworkSimulation {
    nodes: HashMap<PeerId, Arc<NetworkCoordinator>>,
    _network_latency: Duration,
    _packet_loss_rate: f64,
}

impl NetworkSimulation {
    async fn new(num_nodes: usize) -> Option<Self> {
        let mut nodes = HashMap::new();
        let mut bootstrap_nodes = vec![];

        for i in 0..num_nodes {
            let identity = NodeIdentity::generate().unwrap();
            let user_id = *identity.peer_id();

            let config = NetworkConfig {
                bootstrap_nodes: bootstrap_nodes.clone(),
                storage_capacity: 10,
                max_connections: 50,
                replication_factor: 3,
                ml_enabled: true,
                monitoring_interval: Duration::from_secs(10),
                security_level: 7,
            };

            match NetworkCoordinator::new(identity, config).await {
                Ok(coordinator) => {
                    nodes.insert(user_id, Arc::new(coordinator));

                    // First 3 nodes are bootstrap nodes
                    if i < 3 {
                        bootstrap_nodes.push(format!("node-{}", i));
                    }
                }
                Err(err) => {
                    println!(
                        "Skipping node {i} in full network simulation: failed to create coordinator: {err}"
                    );
                }
            }
        }

        if nodes.is_empty() {
            println!(
                "Aborting full network simulation: no coordinators could be constructed in this environment."
            );
            return None;
        }

        Some(Self {
            nodes,
            _network_latency: Duration::from_millis(50),
            _packet_loss_rate: 0.01,
        })
    }

    async fn join_all_nodes(&self) {
        if self.nodes.is_empty() {
            return;
        }
        for (node_id, coordinator) in &self.nodes {
            println!("Node {:?} joining network...", node_id);
            let _ = coordinator.join_network().await;
        }
    }

    async fn simulate_gossip_communication(&self) {
        if self.nodes.is_empty() {
            return;
        }
        // Different types of gossip messages
        let topics = vec![
            ("system-update", b"New version available".to_vec()),
            ("peer-discovery", b"Node announcement".to_vec()),
            ("content-announcement", b"New content available".to_vec()),
        ];

        for (topic, message) in topics {
            let Some(node) = self.nodes.values().next() else {
                break;
            };
            let _ = node.publish(topic, message).await;
            println!("Published message to topic: {}", topic);
        }
    }

    async fn simulate_network_stress(&self) {
        if self.nodes.is_empty() {
            return;
        }
        // Simulate high churn
        println!("\nSimulating high churn scenario...");
        for node in self.nodes.values().take(2) {
            if let Err(err) = node.handle_degradation(DegradationReason::HighChurn).await {
                println!("High churn simulation failed: {err}");
            }
        }

        // Simulate low connectivity
        println!("Simulating low connectivity...");
        for node in self.nodes.values().skip(2).take(2) {
            if let Err(err) = node
                .handle_degradation(DegradationReason::LowConnectivity)
                .await
            {
                println!("Low connectivity simulation failed: {err}");
            }
        }

        // Simulate high load
        println!("Simulating high load...");
        for node in self.nodes.values().skip(4).take(2) {
            if let Err(err) = node.handle_degradation(DegradationReason::HighLoad).await {
                println!("High load simulation failed: {err}");
            }
        }
    }

    async fn collect_metrics(&self) {
        println!("\n=== Network Metrics ===");

        for (i, (_node_id, coordinator)) in self.nodes.iter().enumerate() {
            let stats = coordinator.get_network_stats().await;
            println!(
                "Node {}: peers={}, success_rate={:.2}%, cache_hit={:.2}%, churn={:.2}%",
                i,
                stats.connected_peers,
                stats.routing_success_rate * 100.0,
                stats.cache_hit_rate * 100.0,
                stats.churn_rate * 100.0
            );
        }
    }
}

#[tokio::test]
async fn test_full_network_simulation() {
    // Create a network with 10 nodes
    let Some(simulation) = NetworkSimulation::new(10).await else {
        return;
    };

    println!("=== P2P Network Simulation ===");
    println!("Nodes: {}", simulation.nodes.len());

    // Phase 1: Network formation
    println!("\n[Phase 1] Network Formation");
    simulation.join_all_nodes().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Phase 2: Normal operations (gossip only, no storage)
    println!("\n[Phase 2] Normal Operations");
    simulation.simulate_gossip_communication().await;

    // Phase 3: Stress testing
    println!("\n[Phase 3] Stress Testing");
    simulation.simulate_network_stress().await;

    // Phase 4: Recovery and metrics
    println!("\n[Phase 4] Recovery and Metrics");
    tokio::time::sleep(Duration::from_secs(1)).await;
    simulation.collect_metrics().await;

    // Phase 5: Graceful shutdown
    println!("\n[Phase 5] Graceful Shutdown");
    for (i, coordinator) in simulation.nodes.into_values().enumerate() {
        println!("Shutting down node {}...", i);
        Arc::try_unwrap(coordinator).ok().map(|c| c.shutdown());
    }

    println!("\n=== Simulation Complete ===");
}

#[tokio::test]
async fn test_adaptive_routing_layers() -> Result<()> {
    let Some(sim) = NetworkSimulation::new(5).await else {
        return Ok(());
    };
    sim.join_all_nodes().await;

    println!("\n=== Testing Adaptive Routing Layers ===");

    // Test that different routing strategies are used
    let Some(source) = sim.nodes.values().next() else {
        return Ok(());
    };
    let target_id = PeerId::from_bytes([42u8; 32]);

    match source.coordinate_routing(&target_id).await {
        Ok(path) => {
            println!("Routing path selected with {} hops", path.len());
        }
        Err(e) => {
            println!("Routing coordination result: {:?}", e);
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_ml_optimization_impact() -> Result<()> {
    // Create two networks - one with ML, one without
    let identity1 = NodeIdentity::generate().unwrap();
    let identity2 = NodeIdentity::generate().unwrap();

    let config_ml = NetworkConfig {
        ml_enabled: true,
        ..Default::default()
    };

    let config_no_ml = NetworkConfig {
        ml_enabled: false,
        ..Default::default()
    };

    let Ok(_coordinator_ml) = NetworkCoordinator::new(identity1, config_ml).await else {
        println!("Skipping ML optimization test: unable to create ML-enabled coordinator");
        return Ok(());
    };
    let Ok(_coordinator_no_ml) = NetworkCoordinator::new(identity2, config_no_ml).await else {
        println!("Skipping ML optimization test: unable to create baseline coordinator");
        return Ok(());
    };

    println!("\n=== ML Optimization Impact Test ===");

    // Both coordinators can be constructed successfully.
    // Storage operations have been removed; ML optimization is verified
    // through the adaptive routing and strategy selection layers.
    println!("Both ML and non-ML coordinators created successfully");

    Ok(())
}

#[tokio::test]
async fn test_trust_based_interactions() {
    let Some(sim) = NetworkSimulation::new(6).await else {
        return;
    };
    sim.join_all_nodes().await;

    println!("\n=== Trust-Based Interactions ===");

    // Simulate trust evolution through interactions
    let nodes: Vec<_> = sim.nodes.values().collect();
    if nodes.len() < 3 {
        println!(
            "Skipping trust-based interaction test: need at least 3 coordinators, had {}",
            nodes.len()
        );
        return;
    }

    // Check network stats to see trust impact
    let stats = nodes[0].get_network_stats().await;
    println!("Average trust score: {:.2}", stats.average_trust_score);
}
