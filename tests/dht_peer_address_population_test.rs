// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! DHT Peer Address Population Test
//!
//! This test verifies that the DHT manager correctly populates peer addresses
//! from the P2P layer when nodes connect and communicate.
//!
//! ## Problem Statement
//!
//! The DHT layer needs to know the network addresses of peers for routing and
//! replication. These addresses should be automatically populated from the P2P
//! connection layer, but we need to verify this happens correctly.
//!
//! ## Test Coverage
//!
//! 1. **Direct Connection Address Propagation**: Verifies that when two nodes
//!    connect directly, both nodes populate each other's addresses in their
//!    DHT peer info.
//!
//! 2. **Find Closest Nodes Returns Addresses**: Verifies that when querying
//!    for closest nodes, the returned nodes have non-empty address fields.
//!
//! 3. **Address Consistency Between Layers**: Verifies that addresses stored
//!    in the DHT layer match the addresses from the P2P layer.
//!
//! ## Authentication Requirement
//!
//! Peers must exchange signed messages to be recognized as authenticated peers.
//! The DHT layer only tracks authenticated peers (identified by their ML-DSA-65
//! node IDs), not raw transport-level channel IDs.

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use saorsa_core::identity::node_identity::NodeIdentity;
use saorsa_core::network::NodeConfig;
use saorsa_core::transport_handle::{TransportConfig, TransportHandle};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

const NODE_STARTUP_DELAY: Duration = Duration::from_millis(500);
const AUTH_PROPAGATION_DELAY: Duration = Duration::from_millis(500);

/// Helper to create a unique 32-byte key from a string
fn key_from_str(s: &str) -> Key {
    let bytes = s.as_bytes();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Creates a DhtNetworkConfig and TransportHandle for testing with automatic port allocation.
///
/// Returns the transport handle, config, and the generated node identity (needed for
/// determining the app-level peer ID that other nodes will see after authentication).
async fn create_test_dht_config(
    _name: &str,
) -> Result<(Arc<TransportHandle>, DhtNetworkConfig, Arc<NodeIdentity>)> {
    let identity = Arc::new(
        NodeIdentity::generate().map_err(|e| anyhow::anyhow!("identity generation failed: {e}"))?,
    );

    let node_config = NodeConfig::builder()
        .listen_port(0) // Random port
        .ipv6(false)
        .allow_loopback(true)
        .build()?;

    let transport = Arc::new(
        TransportHandle::new(TransportConfig::from_node_config(
            &node_config,
            saorsa_core::DEFAULT_EVENT_CHANNEL_CAPACITY,
            identity.clone(),
        ))
        .await?,
    );

    let config = DhtNetworkConfig {
        peer_id: *identity.peer_id(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(10),
        max_concurrent_operations: 10,
        enable_security: false,
    };

    Ok((transport, config, identity))
}

/// Creates and starts a DhtNetworkManager for testing.
///
/// Returns the manager and the node identity (needed for determining the
/// app-level peer ID that remote nodes will use to identify this node).
async fn create_test_manager(name: &str) -> Result<(Arc<DhtNetworkManager>, Arc<NodeIdentity>)> {
    let (transport, config, identity) = create_test_dht_config(name).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
    manager.start().await?;
    sleep(NODE_STARTUP_DELAY).await;
    Ok((manager, identity))
}

/// Perform bidirectional authentication between two managers.
///
/// Both sides send an automatic identity announce on connect, so we just
/// need to connect and wait for the announces to propagate.
///
/// Returns the channel ID from the initial connection.
async fn authenticate_bidirectional(manager_a: &DhtNetworkManager, addr_b: &str) -> Result<String> {
    let channel_id_b = manager_a.connect_to_peer(addr_b).await?;
    // Auto identity announce handles bidirectional authentication.
    sleep(AUTH_PROPAGATION_DELAY).await;
    Ok(channel_id_b)
}

// =============================================================================
// TEST 1: Direct Connection Address Propagation
// =============================================================================

/// Test that when two nodes connect and authenticate, both populate each other's
/// addresses in their DHT peer info.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B
/// ```
///
/// ## Expected Behavior
/// - After bidirectional authentication, Node A's get_connected_peers() should show Node B
/// - After bidirectional authentication, Node B's get_connected_peers() should show Node A
/// - Peers are identified by app-level node IDs (ML-DSA-65), not channel IDs
/// - Addresses should be valid network addresses (not empty strings)
#[tokio::test]
async fn test_direct_connection_address_propagation() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Direct Connection Address Propagation ===");

    // Create two nodes (each with its own ML-DSA-65 identity)
    let (manager_a, identity_a) = create_test_manager("address_test_a").await?;
    let (manager_b, identity_b) = create_test_manager("address_test_b").await?;

    let a_node_id = *identity_a.peer_id();
    let b_node_id = *identity_b.peer_id();
    info!(
        "Created nodes A (node_id={}) and B (node_id={})",
        a_node_id, b_node_id
    );

    // Get Node B's listen address
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;

    // Connect and authenticate bidirectionally
    info!("Connecting and authenticating A ←→ B");
    authenticate_bidirectional(&manager_a, &addr_b).await?;

    // Check Node A's view of Node B via transport layer (source of truth for addresses)
    info!("Checking Node A's view of connected peers...");
    let peers_from_a = manager_a.get_connected_peers().await;
    info!("Node A sees {} connected peers", peers_from_a.len());

    assert!(
        peers_from_a.contains(&b_node_id),
        "Node B not in Node A's connected peers"
    );

    let b_info = manager_a
        .transport()
        .peer_info(&b_node_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("Node A has no transport info for Node B"))?;
    info!(
        "Node A sees peer B with {} addresses",
        b_info.addresses.len()
    );
    for (i, addr) in b_info.addresses.iter().enumerate() {
        info!("  Address {}: {}", i, addr);
    }
    assert!(
        !b_info.addresses.is_empty(),
        "Address propagation failed: Node A has no addresses for Node B"
    );
    info!("Node A successfully populated addresses for Node B");

    // Check Node B's view of Node A via transport layer
    info!("Checking Node B's view of connected peers...");
    let peers_from_b = manager_b.get_connected_peers().await;
    info!("Node B sees {} connected peers", peers_from_b.len());

    assert!(
        peers_from_b.contains(&a_node_id),
        "Node A not in Node B's connected peers"
    );

    let a_info = manager_b
        .transport()
        .peer_info(&a_node_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("Node B has no transport info for Node A"))?;
    info!(
        "Node B sees peer A with {} addresses",
        a_info.addresses.len()
    );
    for (i, addr) in a_info.addresses.iter().enumerate() {
        info!("  Address {}: {}", i, addr);
    }
    assert!(
        !a_info.addresses.is_empty(),
        "Address propagation failed: Node B has no addresses for Node A"
    );
    info!("Node B successfully populated addresses for Node A");

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;

    info!("TEST PASSED: Both nodes correctly populated peer addresses!");
    Ok(())
}

// =============================================================================
// TEST 2: Find Closest Nodes Returns Addresses
// =============================================================================

/// Test that find_closest_nodes returns nodes with populated address fields.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B ←→ Node C
/// (Chain topology)
/// ```
///
/// ## Expected Behavior
/// - When Node B calls find_closest_nodes(), the returned nodes should have addresses
/// - Addresses should be usable for making connections
#[tokio::test]
async fn test_find_closest_nodes_returns_addresses() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Find Closest Nodes Returns Addresses ===");

    // Create three nodes (each with its own ML-DSA-65 identity)
    let (manager_a, _identity_a) = create_test_manager("find_nodes_a").await?;
    let (manager_b, _identity_b) = create_test_manager("find_nodes_b").await?;
    let (manager_c, _identity_c) = create_test_manager("find_nodes_c").await?;

    info!("Created nodes A, B, and C");

    // Get listen addresses
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;
    let addr_c = manager_c
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node C has no listen address"))?;

    // Connect and authenticate A ←→ B
    info!("Connecting and authenticating A ←→ B");
    authenticate_bidirectional(&manager_a, &addr_b).await?;

    // Connect and authenticate B ←→ C
    info!("Connecting and authenticating B ←→ C");
    authenticate_bidirectional(&manager_b, &addr_c).await?;

    // Node B calls find_closest_nodes for a test key
    let test_key = key_from_str("test_find_nodes_key");
    info!(
        "Node B finding closest nodes to key: {}",
        hex::encode(test_key)
    );

    let closest_nodes = manager_b.find_closest_nodes_local(&test_key, 5).await;

    info!("find_closest_nodes returned {} nodes", closest_nodes.len());

    if closest_nodes.is_empty() {
        warn!("TEST FAILED: find_closest_nodes returned ZERO nodes");
        return Err(anyhow::anyhow!("No nodes returned from find_closest_nodes"));
    }

    // Check each returned node for addresses
    let mut nodes_with_addresses = 0;
    let mut nodes_without_addresses = 0;

    for (i, node) in closest_nodes.iter().enumerate() {
        debug!("Node {}: peer_id={}", i, node.peer_id);
        debug!("  address: '{}'", node.address);
        debug!("  reliability: {}", node.reliability);

        let addr_str = node.address.to_string();
        if addr_str == "0.0.0.0:0" {
            warn!("  Node {} has EMPTY address field", i);
            nodes_without_addresses += 1;
        } else {
            debug!("  Node {} has address: {}", i, node.address);
            nodes_with_addresses += 1;
        }
    }

    info!(
        "Address population results: {} with addresses, {} without",
        nodes_with_addresses, nodes_without_addresses
    );

    if nodes_without_addresses > 0 {
        warn!(
            "TEST FAILED: {}/{} nodes returned by find_closest_nodes have NO addresses.\n\
            \n\
            Expected behavior:\n\
            - find_closest_nodes should return nodes with populated address fields\n\
            - These addresses should be usable for connecting to the nodes\n\
            \n\
            Actual behavior:\n\
            - {} nodes have empty address fields\n\
            \n\
            Implementation needed:\n\
            - Ensure DHTNode.address is populated from peer connection info\n\
            - Address should be the socket address or multiaddr of the peer",
            nodes_without_addresses,
            closest_nodes.len(),
            nodes_without_addresses
        );
        return Err(anyhow::anyhow!(
            "{} nodes missing addresses",
            nodes_without_addresses
        ));
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;
    let _ = manager_c.stop().await;

    info!("TEST PASSED: All returned nodes have populated addresses!");
    Ok(())
}

// =============================================================================
// TEST 3: Address Consistency Between P2P and DHT Layers
// =============================================================================

/// Test that addresses in DHT peer info match addresses from the P2P layer.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B
/// ```
///
/// ## Expected Behavior
/// - When Node A authenticates Node B:
///   - P2P layer stores peer info with addresses (keyed by app-level node ID)
///   - DHT layer should have matching addresses
/// - Addresses should be consistent between both layers
#[tokio::test]
async fn test_address_consistency_with_p2p_layer() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Address Consistency Between P2P and DHT Layers ===");

    // Create two nodes (each with its own ML-DSA-65 identity)
    let (manager_a, _identity_a) = create_test_manager("consistency_a").await?;
    let (manager_b, identity_b) = create_test_manager("consistency_b").await?;

    let b_peer_id = *identity_b.peer_id();
    info!("Created nodes A and B (B's node_id={})", b_peer_id);

    // Connect and authenticate bidirectionally
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;

    info!("Connecting and authenticating A ←→ B");
    authenticate_bidirectional(&manager_a, &addr_b).await?;

    // Query P2P layer for peer B's info (using B's app-level node ID)
    info!(
        "Querying P2P layer for peer B's info (node_id={})...",
        b_peer_id
    );
    let p2p_peer_info = manager_a.transport().peer_info(&b_peer_id).await;

    let p2p_addresses = match p2p_peer_info {
        Some(info) => {
            info!(
                "P2P layer has {} addresses for peer B",
                info.addresses.len()
            );
            for (i, addr) in info.addresses.iter().enumerate() {
                info!("  P2P Address {}: {}", i, addr);
            }
            info.addresses
        }
        None => {
            warn!("P2P layer has NO peer info for peer B!");
            return Err(anyhow::anyhow!("P2P layer missing peer info"));
        }
    };

    // Verify peer B is in the routing table with a valid address.
    // The routing table is now the single source of truth for DHT peer addresses.
    info!("Checking routing table for peer B's address...");
    assert!(
        manager_a.is_in_routing_table(&b_peer_id).await,
        "Peer B should be in Node A's routing table"
    );

    // Verify the routing table address is consistent with the P2P layer
    let closest = manager_a
        .find_closest_nodes_local(b_peer_id.as_bytes(), 8)
        .await;
    let rt_node = closest.iter().find(|n| n.peer_id == b_peer_id);
    match rt_node {
        Some(node) => {
            info!("Routing table address for peer B: {}", node.address);
            // The routing table address should match one of the P2P addresses
            let rt_addr_str = node.address.to_string();
            let match_found = p2p_addresses.iter().any(|p2p_addr| {
                p2p_addr == &rt_addr_str
                    || p2p_addr.contains(&rt_addr_str)
                    || rt_addr_str.contains(p2p_addr)
            });
            assert!(
                match_found,
                "Routing table address {} does not match any P2P address: {:?}",
                node.address, p2p_addresses
            );
        }
        None => {
            panic!(
                "Peer B not found in closest nodes result — address consistency cannot be verified"
            );
        }
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;

    info!("TEST PASSED: Addresses are consistent between P2P and DHT layers!");
    Ok(())
}
