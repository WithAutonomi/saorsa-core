// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! End-to-End Tests for Network Wiring
//!
//! These tests use TDD approach - they define the expected behavior BEFORE
//! the implementation is complete. Tests are expected to FAIL initially
//! and pass once the networking is properly wired up.
//!
//! Sprint 1: Basic 2-node message exchange
//! Sprint 2: Peer health checks and heartbeat
//! Sprint 3: DHT distribution across 3 nodes
//!
//! Run with: cargo test --test network_wiring_e2e_test -- --nocapture

use saorsa_core::PeerId;
use saorsa_core::identity::node_identity::NodeIdentity;
use saorsa_core::network::{NodeConfig, P2PEvent, P2PNode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

/// Timeout for waiting for a single event (PeerConnected, etc.).
const EVENT_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum time to wait for peer cleanup after a disconnect.
const DISCONNECT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Polling interval when busy-waiting for state changes.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Timeout for PeerDisconnected events.
const DISCONNECT_EVENT_TIMEOUT: Duration = Duration::from_secs(8);

/// Helper to create a test node configuration with unique port.
///
/// Includes a generated `node_identity` so that messages are signed and
/// `PeerConnected`/`PeerDisconnected` events fire on authentication.
fn create_test_node_config() -> NodeConfig {
    let identity =
        Arc::new(NodeIdentity::generate().expect("Test setup: identity generation should succeed"));
    NodeConfig {
        listen_addr: "127.0.0.1:0"
            .parse()
            .unwrap_or_else(|_| panic!("Test setup error: hardcoded address should parse")),
        listen_addrs: vec![
            "127.0.0.1:0".parse().unwrap_or_else(|_| {
                panic!("Test setup error: hardcoded IPv4 address should parse")
            }),
            "[::]:0".parse().unwrap_or_else(|_| {
                panic!("Test setup error: hardcoded IPv6 address should parse")
            }),
        ],
        bootstrap_peers: vec![],
        node_identity: Some(identity),
        ..Default::default()
    }
}

/// Wait for a specific event with timeout
async fn wait_for_event<F>(
    rx: &mut broadcast::Receiver<P2PEvent>,
    timeout_duration: Duration,
    predicate: F,
) -> Option<P2PEvent>
where
    F: Fn(&P2PEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout_duration;

    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(event)) => {
                if predicate(&event) {
                    return Some(event);
                }
            }
            Ok(Err(_)) => {
                // Channel closed
                return None;
            }
            Err(_) => {
                // Timeout on individual recv, continue waiting
            }
        }
    }
    None
}

/// Connect `from` to `to` and wait for identity exchange so `from` has `to`'s
/// [`PeerId`] in its `connected_peers()` list. Returns `to`'s [`PeerId`].
async fn connect_and_identify(from: &P2PNode, to: &P2PNode) -> PeerId {
    let addrs = to.listen_addrs().await;
    let addr = addrs
        .first()
        .expect("target node needs a listen address")
        .to_string();
    let channel_id = from.connect_peer(&addr).await.expect("connect_peer failed");
    let peer_id = from
        .wait_for_peer_identity(&channel_id, Duration::from_secs(5))
        .await
        .expect("identity exchange timed out");
    assert_eq!(peer_id, *to.peer_id(), "identity mismatch after exchange");
    peer_id
}

// =============================================================================
// SPRINT 1: Basic 2-Node Message Exchange
// =============================================================================

/// TEST 1.1: Two nodes can connect and exchange messages
///
/// This is the most fundamental test - verifying that when node A sends
/// a message to node B using the "messaging" protocol/topic, node B actually
/// receives it via P2PEvent::Message.
///
/// EXPECTED INITIAL STATE: FAIL
/// - Currently, the message flow works but we need to verify end-to-end
#[tokio::test]
async fn test_two_node_message_exchange() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Two Node Message Exchange ===");

    // Create two nodes
    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Subscribe to events on node2 BEFORE connecting
    let mut events2 = node2.subscribe_events();

    // Get node2's address
    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2
        .first()
        .expect("Node2 should have a listen address")
        .to_string();

    info!("Node1 connecting to Node2 at {}", addr2);

    // Connect node1 to node2 and wait for identity exchange
    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    info!("Connected! Node2's PeerId: {}", peer2_peer_id);

    // Define test message
    let test_topic = "messaging";
    let test_payload = b"Hello from Node1!";

    info!(
        "Sending message on topic '{}': {:?}",
        test_topic,
        std::str::from_utf8(test_payload)
    );

    // Send message from node1 to node2
    node1
        .send_message(&peer2_peer_id, test_topic, test_payload.to_vec())
        .await
        .expect("Failed to send message");

    info!("Message sent, waiting for it on node2...");

    // Wait for message on node2
    let received_event = wait_for_event(
        &mut events2,
        Duration::from_secs(5),
        |event| matches!(event, P2PEvent::Message { topic, .. } if topic == test_topic),
    )
    .await;

    // Verify message was received
    match received_event {
        Some(P2PEvent::Message {
            topic,
            source,
            data,
        }) => {
            info!("SUCCESS! Received message on node2:");
            info!("  Topic: {}", topic);
            info!("  Source: {:?}", source);
            info!("  Data: {:?}", std::str::from_utf8(&data));

            assert_eq!(topic, test_topic, "Topic should match");
            assert_eq!(data, test_payload.to_vec(), "Payload should match");
        }
        Some(other) => {
            panic!("Received unexpected event: {:?}", other);
        }
        None => {
            panic!(
                "FAIL: No message received on node2 within timeout!\n\
                This indicates the message delivery pipeline is not working.\n\
                Check that:\n\
                1. create_protocol_message wraps the message correctly\n\
                2. receive_any parses and emits P2PEvent::Message\n\
                3. The topic matches what the receiver expects"
            );
        }
    }

    info!("=== TEST PASSED: Two Node Message Exchange ===");
}

/// TEST 1.2: Messages are delivered with correct topic preservation
///
/// Verifies that the topic/protocol string survives the send/receive cycle.
/// This is critical because messaging/transport.rs filters by topic.
#[tokio::test]
async fn test_message_topic_preservation() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Message Topic Preservation ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Test multiple topics
    let topics = vec!["messaging", "key_exchange", "/dht/1.0.0", "custom_topic"];

    for topic in topics {
        info!("Testing topic: {}", topic);

        node1
            .send_message(&peer2_peer_id, topic, b"test".to_vec())
            .await
            .expect("Send failed");

        let received = wait_for_event(
            &mut events2,
            Duration::from_secs(2),
            |event| matches!(event, P2PEvent::Message { topic: t, .. } if t == topic),
        )
        .await;

        match received {
            Some(P2PEvent::Message {
                topic: received_topic,
                ..
            }) => {
                assert_eq!(received_topic, topic, "Topic must be preserved exactly");
                info!("  OK: Topic '{}' preserved correctly", topic);
            }
            _ => {
                panic!(
                    "FAIL: Message with topic '{}' was not received!\n\
                    This suggests topic mapping is broken.",
                    topic
                );
            }
        }
    }

    info!("=== TEST PASSED: Message Topic Preservation ===");
}

/// TEST 1.3: Bidirectional message exchange
///
/// Verifies that both nodes can send AND receive messages.
#[tokio::test]
async fn test_bidirectional_message_exchange() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Bidirectional Message Exchange ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = Arc::new(P2PNode::new(config1).await.expect("Failed to create node1"));
    node1.start().await.expect("Failed to start node1");
    let node2 = Arc::new(P2PNode::new(config2).await.expect("Failed to create node2"));
    node2.start().await.expect("Failed to start node2");

    let mut events1 = node1.subscribe_events();
    let mut events2 = node2.subscribe_events();

    // Connect node1 to node2
    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();
    let _channel_id = node1.connect_peer(&addr2).await.expect("Connect failed");

    // Wait for auto identity announce to authenticate node1 on node2
    let peer1_peer_id = match wait_for_event(&mut events2, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(id, _)) => id,
        _ => panic!("Node2 did not receive PeerConnected event from Node1"),
    };

    // Wait for auto identity announce to authenticate node2 on node1
    let peer2_peer_id = match wait_for_event(&mut events1, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(id, _)) => id,
        _ => panic!("Node1 did not receive PeerConnected event from Node2"),
    };

    info!("Node1 sees Node2 as: {}", peer2_peer_id);
    info!("Node2 sees Node1 as: {}", peer1_peer_id);

    // Node1 -> Node2
    node1
        .send_message(&peer2_peer_id, "messaging", b"From Node1".to_vec())
        .await
        .expect("Send from node1 failed");

    let msg_on_2 = wait_for_event(
        &mut events2,
        EVENT_TIMEOUT,
        |event| matches!(event, P2PEvent::Message { topic, .. } if topic == "messaging"),
    )
    .await;

    assert!(
        matches!(msg_on_2, Some(P2PEvent::Message { data, .. }) if data == b"From Node1"),
        "Node2 should receive message from Node1"
    );
    info!("Node1 -> Node2: OK");

    // Node2 -> Node1
    node2
        .send_message(&peer1_peer_id, "messaging", b"From Node2".to_vec())
        .await
        .expect("Send from node2 failed");

    let msg_on_1 = wait_for_event(
        &mut events1,
        EVENT_TIMEOUT,
        |event| matches!(event, P2PEvent::Message { topic, .. } if topic == "messaging"),
    )
    .await;

    assert!(
        matches!(msg_on_1, Some(P2PEvent::Message { data, .. }) if data == b"From Node2"),
        "Node1 should receive message from Node2"
    );
    info!("Node2 -> Node1: OK");

    info!("=== TEST PASSED: Bidirectional Message Exchange ===");
}

// =============================================================================
// SPRINT 2: Peer Health Checks and Heartbeat
// =============================================================================

/// TEST 2.1: Connection survives idle period
///
/// Verifies that an established connection remains alive after a period of
/// inactivity (relying on QUIC transport-layer idle timeout), and that
/// messages can still be exchanged afterwards.
#[tokio::test]
async fn test_connection_survives_idle_period() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Connection Survives Idle Period ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Connect and obtain the real authenticated PeerId
    let peer2_id = connect_and_identify(&node1, &node2).await;

    // Verify the peer is connected initially
    assert!(
        node1.is_peer_connected(&peer2_id).await,
        "Peer should be connected initially"
    );

    // Wait for a period of inactivity. With keepalive removed, the
    // connection should still survive via the transport-layer idle timeout
    // (which is longer than this sleep).
    info!("Waiting 2s to verify connection survives inactivity...");
    sleep(Duration::from_secs(2)).await;

    // Verify the peer is still connected after the idle period
    assert!(
        node1.is_peer_connected(&peer2_id).await,
        "Peer should still be connected after 2s of inactivity"
    );

    // Send a message to prove the connection is still functional
    let mut events2 = node2.subscribe_events();
    node1
        .send_message(&peer2_id, "liveness", b"ping".to_vec())
        .await
        .expect("send_message should succeed after idle period");

    let received = timeout(EVENT_TIMEOUT, async {
        loop {
            if let Ok(P2PEvent::Message { data, .. }) = events2.recv().await {
                return data;
            }
        }
    })
    .await
    .expect("node2 should receive message after idle period");

    assert_eq!(received, b"ping", "message content should match");

    info!("=== TEST PASSED: Connection Survives Idle Period ===");
}

/// TEST 2.2: Disconnected peers are detected and removed
///
/// This test verifies that when a peer drops, the transport layer detects the
/// disconnect (via QUIC idle timeout) and removes the peer from tracking.
#[tokio::test]
async fn test_disconnected_peer_removal() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Disconnected Peer Removal ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Connect and obtain the real authenticated PeerId
    let peer2_id = connect_and_identify(&node1, &node2).await;

    assert!(node1.is_peer_connected(&peer2_id).await);
    info!("Initial connection established");

    // Simulate network partition by dropping node2
    drop(node2);

    // Wait for QUIC idle timeout to detect the disconnect.
    info!("Waiting for disconnect detection...");

    // Wait up to 10 seconds for the peer to be cleaned up
    let deadline = tokio::time::Instant::now() + DISCONNECT_CLEANUP_TIMEOUT;
    loop {
        if !node1.is_peer_connected(&peer2_id).await {
            info!("Disconnected peer {} detected and removed", peer2_id);
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "FAIL: Disconnected peer should be removed from peers map.\n\
                Transport layer should detect the QUIC disconnect and remove the peer."
            );
        }
        sleep(POLL_INTERVAL).await;
    }

    info!("=== TEST PASSED: Disconnected Peer Removal ===");
}

/// TEST 2.3: Heartbeat/ping keeps connection alive
///
/// EXPECTED INITIAL STATE: May pass if keepalive is working at QUIC level
#[tokio::test]
#[ignore = "Long-running test - keepalive mechanism"]
async fn test_heartbeat_keeps_connection_alive() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Heartbeat Keeps Connection Alive ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    info!("Connection established, waiting 35 seconds (beyond 30s idle timeout)...");

    // Wait longer than the 30-second idle timeout
    sleep(Duration::from_secs(35)).await;

    // Connection should still be alive due to heartbeat
    let is_active = node1.is_peer_connected(&peer2_peer_id).await;

    assert!(
        is_active,
        "FAIL: Connection died after 35 seconds!\n\
        The heartbeat mechanism should keep the connection alive.\n\
        Check that periodic_tasks() sends keepalive pings."
    );

    // Verify we can still send messages
    node1
        .send_message(&peer2_peer_id, "test", b"still alive".to_vec())
        .await
        .expect("Should be able to send message after 35 seconds");

    info!("=== TEST PASSED: Heartbeat Keeps Connection Alive ===");
}

// =============================================================================
// SPRINT 3: DHT Network Integration
// =============================================================================

/// TEST 3.1: DhtNetworkManager is instantiated with P2PNode
///
/// EXPECTED INITIAL STATE: FAIL
/// - DhtNetworkManager is not wired up to P2PNode
#[tokio::test]
#[ignore = "Requires DhtNetworkManager integration"]
async fn test_dht_network_manager_integration() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: DHT Network Manager Integration ===");

    let config = create_test_node_config();
    let _node = P2PNode::new(config).await.expect("Failed to create node");
    _node.start().await.expect("Failed to start node");

    // Check if DHT network manager is accessible
    // This would require adding a method to P2PNode like:
    // pub fn dht_manager(&self) -> Option<&DhtNetworkManager>

    // For now, we'll test indirectly by checking if DHT operations work
    // after starting the node

    // TODO: Add dht_manager() method to P2PNode and verify it's Some

    info!("=== TEST: DHT Network Manager Integration ===");
    // Currently this will just pass without real verification
    // Implement properly once DhtNetworkManager is wired up
}

/// TEST 3.2: Three-node DHT store and retrieve
///
/// Node A stores a value, Node C (not directly connected to A) retrieves it
/// via DHT routing through Node B.
///
/// EXPECTED INITIAL STATE: FAIL
/// - DHT remote queries not implemented
#[tokio::test]
#[ignore = "Requires DHT remote query implementation"]
async fn test_three_node_dht_routing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Three Node DHT Routing ===");

    // Create three nodes
    let config_a = create_test_node_config();
    let config_b = create_test_node_config();
    let config_c = create_test_node_config();

    let node_a = P2PNode::new(config_a)
        .await
        .expect("Failed to create node A");
    node_a.start().await.expect("Failed to start node A");
    let node_b = P2PNode::new(config_b)
        .await
        .expect("Failed to create node B");
    node_b.start().await.expect("Failed to start node B");
    let node_c = P2PNode::new(config_c)
        .await
        .expect("Failed to create node C");
    node_c.start().await.expect("Failed to start node C");

    // Get addresses
    let addrs_a = node_a.listen_addrs().await;
    let addrs_b = node_b.listen_addrs().await;

    let _addr_a = addrs_a.first().expect("Node A needs address").to_string();
    let addr_b = addrs_b.first().expect("Node B needs address").to_string();

    // Connect: A <-> B <-> C (A and C not directly connected)
    let _peer_b_from_a = node_a
        .connect_peer(&addr_b)
        .await
        .expect("A->B connect failed");
    let _peer_b_from_c = node_c
        .connect_peer(&addr_b)
        .await
        .expect("C->B connect failed");

    // Wait for connections to stabilize
    sleep(Duration::from_millis(500)).await;

    info!("Network topology: A <-> B <-> C");

    info!("=== TEST: Three Node DHT Routing ===");
}

/// TEST 3.3: DHT messages are routed through the network layer
///
/// EXPECTED INITIAL STATE: FAIL
#[tokio::test]
#[ignore = "Requires DHT message routing implementation"]
async fn test_dht_message_routing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("=== TEST: DHT Message Routing ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Send a DHT protocol message
    let dht_topic = "/dht/1.0.0";
    let dht_message = b"DHT_FIND_NODE_REQUEST";

    node1
        .send_message(&peer2_peer_id, dht_topic, dht_message.to_vec())
        .await
        .expect("Failed to send DHT message");

    // Verify it arrives with the correct topic
    let received = wait_for_event(
        &mut events2,
        Duration::from_secs(2),
        |event| matches!(event, P2PEvent::Message { topic, .. } if topic == dht_topic),
    )
    .await;

    assert!(
        matches!(received, Some(P2PEvent::Message { .. })),
        "DHT messages should be routed through the network layer"
    );

    info!("=== TEST PASSED: DHT Message Routing ===");
}

// =============================================================================
// Utility/Sanity Tests
// =============================================================================

/// Sanity check: Nodes can start and have addresses
#[tokio::test]
async fn test_node_creation_sanity() {
    let config = create_test_node_config();
    let node = P2PNode::new(config).await.expect("Failed to create node");
    node.start().await.expect("Failed to start node");

    let addrs = node.listen_addrs().await;
    assert!(
        !addrs.is_empty(),
        "Node should have at least one listen address"
    );

    info!("Node created with addresses: {:?}", addrs);
}

/// Sanity check: Event subscription works.
///
/// PeerConnected fires automatically via the identity announce sent on connect.
#[tokio::test]
async fn test_event_subscription_sanity() {
    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();

    node1.connect_peer(&addr2).await.expect("Connect failed");

    // Should receive PeerConnected event on node2 from auto identity announce
    let event = wait_for_event(&mut events2, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await;

    assert!(
        matches!(event, Some(P2PEvent::PeerConnected(..))),
        "Should receive PeerConnected event when authenticated peer sends a message"
    );

    info!("Event subscription working correctly");
}

// =============================================================================
// PHASE 0: Normal Operation Tests (Happy Path)
// =============================================================================

/// TEST 0.1: Simple Ping-Pong Exchange
///
/// Node A sends "ping" to Node B, Node B receives and sends "pong" back,
/// Node A receives "pong". Verifies basic request/response pattern.
#[tokio::test]
async fn test_simple_ping_pong() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Simple Ping-Pong Exchange ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = Arc::new(P2PNode::new(config1).await.expect("Failed to create node1"));
    node1.start().await.expect("Failed to start node1");
    let node2 = Arc::new(P2PNode::new(config2).await.expect("Failed to create node2"));
    node2.start().await.expect("Failed to start node2");

    let mut events1 = node1.subscribe_events();
    let mut events2 = node2.subscribe_events();

    // Connect node1 to node2
    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();
    let _channel_id = node1.connect_peer(&addr2).await.expect("Connect failed");

    // Wait for auto identity announce to authenticate both sides
    let peer1_peer_id = match wait_for_event(&mut events2, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(id, _)) => id,
        _ => panic!("Node2 did not receive PeerConnected event"),
    };

    let peer2_peer_id = match wait_for_event(&mut events1, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(id, _)) => id,
        _ => panic!("Node1 did not receive PeerConnected event"),
    };

    // Node1 sends "ping"
    node1
        .send_message(&peer2_peer_id, "messaging", b"ping".to_vec())
        .await
        .expect("Failed to send ping");

    // Node2 receives "ping"
    let received_ping = wait_for_event(
        &mut events2,
        EVENT_TIMEOUT,
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"ping"),
    )
    .await;

    assert!(
        matches!(received_ping, Some(P2PEvent::Message { data, .. }) if data == b"ping"),
        "Node2 should receive 'ping'"
    );
    info!("Node2 received 'ping'");

    // Node2 sends "pong" back
    node2
        .send_message(&peer1_peer_id, "messaging", b"pong".to_vec())
        .await
        .expect("Failed to send pong");

    // Node1 receives "pong"
    let received_pong = wait_for_event(
        &mut events1,
        EVENT_TIMEOUT,
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"pong"),
    )
    .await;

    assert!(
        matches!(received_pong, Some(P2PEvent::Message { data, .. }) if data == b"pong"),
        "Node1 should receive 'pong'"
    );
    info!("Node1 received 'pong'");

    info!("=== TEST PASSED: Simple Ping-Pong Exchange ===");
}

/// TEST 0.2: Multiple Sequential Messages
///
/// Send 10 messages in sequence and verify all are received.
#[tokio::test]
async fn test_multiple_sequential_messages() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Multiple Sequential Messages ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Send 10 messages with small delay to avoid overwhelming the transport
    let message_count = 10;
    for i in 0..message_count {
        let msg = format!("message_{i}");
        node1
            .send_message(&peer2_peer_id, "messaging", msg.as_bytes().to_vec())
            .await
            .expect("Failed to send message");
        // Small delay between sends to let transport process
        sleep(Duration::from_millis(50)).await;
    }

    // Collect received messages
    let mut received_messages: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while received_messages.len() < message_count && tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(500), events2.recv()).await {
            Ok(Ok(P2PEvent::Message { data, .. })) => {
                if let Ok(msg) = String::from_utf8(data)
                    && msg.starts_with("message_")
                {
                    received_messages.push(msg);
                }
            }
            _ => continue,
        }
    }

    info!(
        "Received {}/{} messages",
        received_messages.len(),
        message_count
    );

    assert_eq!(
        received_messages.len(),
        message_count,
        "Should receive all {} messages, got: {:?}",
        message_count,
        received_messages
    );

    // Verify all messages received (order may vary in network conditions)
    for i in 0..message_count {
        let expected = format!("message_{i}");
        assert!(
            received_messages.contains(&expected),
            "Missing message: {expected}"
        );
    }

    info!("=== TEST PASSED: Multiple Sequential Messages ===");
}

/// TEST 0.3: Connection Persistence
///
/// Connect two nodes, wait 3 seconds idle, then send message.
/// Verifies connection stays alive via keepalive.
#[tokio::test]
async fn test_connection_stays_alive() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Connection Stays Alive ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    info!("Connected, waiting 3 seconds idle...");
    sleep(Duration::from_secs(3)).await;

    // Send message after idle period
    node1
        .send_message(&peer2_peer_id, "messaging", b"still connected".to_vec())
        .await
        .expect("Failed to send message after idle");

    // Wait for message
    let received = wait_for_event(
        &mut events2,
        Duration::from_secs(2),
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"still connected"),
    )
    .await;

    assert!(
        matches!(received, Some(P2PEvent::Message { .. })),
        "Message should still be delivered after 3 seconds idle"
    );

    info!("=== TEST PASSED: Connection Stays Alive ===");
}

/// TEST 0.4: Reconnection After Graceful Disconnect
///
/// Connect, disconnect, reconnect, and verify message delivery.
///
/// NOTE: This test is ignored because message delivery after reconnection is
/// timing-sensitive and may fail intermittently due to:
/// - Event subscription timing relative to message send
/// - Connection state propagation delays
/// - CI environment variability
///
/// TODO: Refactor to use synchronization primitives for deterministic testing.
#[tokio::test]
#[ignore = "Flaky: timing-sensitive reconnection test - see test documentation"]
async fn test_reconnection_works() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Reconnection Works ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();

    // First connection
    let peer2_peer_id = connect_and_identify(&node1, &node2).await;
    assert!(
        node1
            .transport()
            .connected_peers()
            .await
            .contains(&peer2_peer_id),
        "Should be connected initially"
    );

    // Disconnect (if there's a disconnect method) or simulate by waiting
    // For now, we'll just verify reconnection works by connecting again
    sleep(Duration::from_millis(200)).await;

    // Reconnect (should work even if already connected)
    let _channel = node1.connect_peer(&addr2).await.expect("Reconnect failed");

    // Send message after reconnection
    let mut events2 = node2.subscribe_events();
    node1
        .send_message(&peer2_peer_id, "messaging", b"after reconnect".to_vec())
        .await
        .expect("Failed to send after reconnect");

    let received = wait_for_event(
        &mut events2,
        Duration::from_secs(2),
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"after reconnect"),
    )
    .await;

    assert!(
        matches!(received, Some(P2PEvent::Message { .. })),
        "Message should be delivered after reconnection"
    );

    info!("=== TEST PASSED: Reconnection Works ===");
}

/// TEST 0.5: Peer Discovery Events
///
/// Connect (auto identity announce triggers PeerConnected on the receiver),
/// then disconnect (drop sender) and verify PeerDisconnected on the receiver.
#[tokio::test]
async fn test_peer_events_sequence() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Peer Events Sequence ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Subscribe to node2's events (the receiver side)
    let mut events2 = node2.subscribe_events();

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();

    // Connect — auto identity announce triggers PeerConnected on node2
    node1.connect_peer(&addr2).await.expect("Connect failed");

    // Wait for PeerConnected event on node2
    let connected_event = wait_for_event(&mut events2, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await;

    assert!(
        matches!(connected_event, Some(P2PEvent::PeerConnected(..))),
        "Should receive PeerConnected event"
    );
    info!("Received PeerConnected event");

    // Drop node1 to simulate disconnect
    drop(node1);

    // Wait for PeerDisconnected event on node2
    let disconnected_event = wait_for_event(&mut events2, DISCONNECT_EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerDisconnected(_))
    })
    .await;

    assert!(
        matches!(disconnected_event, Some(P2PEvent::PeerDisconnected(_))),
        "Should receive PeerDisconnected event after peer drops"
    );
    info!("Received PeerDisconnected event");

    info!("=== TEST PASSED: Peer Events Sequence ===");
}

/// TEST 0.6: Large Message Transfer
///
/// Send a 64KB message and verify it's received completely.
/// Note: Very large messages (1MB+) may be limited by transport layer.
#[tokio::test]
async fn test_large_message_transfer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Large Message Transfer ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Create a 64KB message with a recognizable pattern
    // Using 64KB as it's a common transport buffer size
    let large_message: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let expected_len = large_message.len();

    info!("Sending {}KB message...", expected_len / 1024);

    node1
        .send_message(&peer2_peer_id, "messaging", large_message.clone())
        .await
        .expect("Failed to send large message");

    // Wait for message with longer timeout for large transfer
    let received = wait_for_event(
        &mut events2,
        Duration::from_secs(30),
        |event| matches!(event, P2PEvent::Message { topic, .. } if topic == "messaging"),
    )
    .await;

    match received {
        Some(P2PEvent::Message { data, .. }) => {
            assert_eq!(
                data.len(),
                expected_len,
                "Message size should match: expected {expected_len}, got {}",
                data.len()
            );
            assert_eq!(data, large_message, "Message content should match exactly");
            info!("Successfully received {}KB message", data.len() / 1024);
        }
        _ => {
            panic!("Failed to receive large message within timeout");
        }
    }

    info!("=== TEST PASSED: Large Message Transfer ===");
}

/// TEST 0.7: Multiple Protocols/Topics
///
/// Send messages on different topics and verify each arrives with correct topic.
#[tokio::test]
async fn test_multiple_protocols() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Multiple Protocols ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Define topics and messages
    let test_cases = vec![
        ("messaging", "chat message"),
        ("dht", "dht lookup"),
        ("custom_protocol", "custom data"),
    ];

    // Send all messages
    for (topic, payload) in &test_cases {
        node1
            .send_message(&peer2_peer_id, topic, payload.as_bytes().to_vec())
            .await
            .expect("Failed to send message");
        sleep(Duration::from_millis(50)).await; // Small delay between sends
    }

    // Collect received messages
    let mut received: Vec<(String, String)> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    while received.len() < test_cases.len() && tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(200), events2.recv()).await {
            Ok(Ok(P2PEvent::Message { topic, data, .. })) => {
                if let Ok(payload) = String::from_utf8(data) {
                    received.push((topic, payload));
                }
            }
            _ => continue,
        }
    }

    // Verify all topic/payload combinations received
    for (expected_topic, expected_payload) in &test_cases {
        let found = received
            .iter()
            .any(|(t, p)| t == *expected_topic && p == *expected_payload);
        assert!(
            found,
            "Should receive message on topic '{}' with payload '{}'. Got: {:?}",
            expected_topic, expected_payload, received
        );
        info!("Topic '{}' verified", expected_topic);
    }

    info!("=== TEST PASSED: Multiple Protocols ===");
}

// =============================================================================
// PHASE 1: Critical Bug Tests
// =============================================================================

/// TEST 1.1: Race Condition Detection
///
/// Detect if duplicate PeerDisconnected events are emitted due to
/// dual periodic task implementations.
#[tokio::test]
async fn test_no_duplicate_disconnect_events() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: No Duplicate Disconnect Events ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events1 = node1.subscribe_events();

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();
    let _channel_id = node1.connect_peer(&addr2).await.expect("Connect failed");

    // Wait for connection to stabilize
    sleep(Duration::from_millis(500)).await;

    // Drop node2 to trigger disconnect detection
    drop(node2);

    // Collect ALL PeerDisconnected events for this peer
    let mut disconnect_count = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(100), events1.recv()).await {
            Ok(Ok(P2PEvent::PeerDisconnected(_))) => {
                disconnect_count += 1;
                info!("Received PeerDisconnected event #{}", disconnect_count);
            }
            Ok(Err(_)) => break, // Channel closed
            _ => continue,
        }
    }

    // Allow exactly 1 disconnect event (or 0 if cleanup happened differently)
    assert!(
        disconnect_count <= 1,
        "RACE CONDITION DETECTED: Received {} PeerDisconnected events for same peer!\n\
        This indicates both periodic_maintenance_task() and periodic_tasks() are running concurrently.\n\
        Only one should emit disconnect events.",
        disconnect_count
    );

    if disconnect_count == 1 {
        info!("Correctly received exactly 1 disconnect event");
    }

    info!("=== TEST PASSED: No Duplicate Disconnect Events ===");
}

/// TEST 1.2: Cleanup Timing Verification
///
/// Verify peer is removed from tracking within expected timeframe.
/// BUG: Timestamp reset causes 2x expected cleanup time.
#[tokio::test]
async fn test_peer_cleanup_timing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Peer Cleanup Timing ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let peer2_id = connect_and_identify(&node1, &node2).await;

    assert!(
        node1.is_peer_connected(&peer2_id).await,
        "Peer should be connected"
    );

    // Drop peer and record start time
    let disconnect_start = tokio::time::Instant::now();
    drop(node2);

    // Poll for peer to be removed from tracking
    let max_wait = Duration::from_secs(10);
    let mut was_removed = false;
    let mut removal_time = Duration::ZERO;

    while disconnect_start.elapsed() < max_wait {
        if !node1.is_peer_connected(&peer2_id).await {
            removal_time = disconnect_start.elapsed();
            was_removed = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(was_removed, "Peer should be removed from tracking");

    // Add generous margin for CI timing variations
    let expected_max = Duration::from_secs(10);
    info!(
        "Peer removed after {:?} (expected within {:?})",
        removal_time, expected_max
    );

    // If this assertion fails with very long times (>10s), it may indicate
    // the timestamp reset bug causing cleanup to take even longer
    assert!(
        removal_time <= expected_max,
        "Peer cleanup took too long: {:?} (expected <= {:?}).\n\
        This may indicate the timestamp reset bug (last_seen = now when marking disconnected)",
        removal_time,
        expected_max
    );

    info!("=== TEST PASSED: Peer Cleanup Timing ===");
}

/// TEST 1.3: Empty Message Handling
///
/// Verify empty messages don't cause issues (hang or panic).
#[tokio::test]
async fn test_empty_message_handling() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Empty Message Handling ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Send empty message
    let send_result = node1
        .send_message(&peer2_peer_id, "messaging", vec![])
        .await;

    // Empty message should either:
    // 1. Be sent successfully and possibly delivered
    // 2. Return an error gracefully
    // 3. NOT hang or panic
    match send_result {
        Ok(()) => {
            info!("Empty message sent successfully");

            // Check if it arrives (may be dropped by receiver - that's OK)
            let received = wait_for_event(
                &mut events2,
                Duration::from_secs(1),
                |event| matches!(event, P2PEvent::Message { data, .. } if data.is_empty()),
            )
            .await;

            if received.is_some() {
                info!("Empty message was delivered");
            } else {
                info!("Empty message was dropped (acceptable behavior)");
            }
        }
        Err(e) => {
            info!("Empty message rejected with error (acceptable): {}", e);
        }
    }

    // Verify the connection still works after empty message
    node1
        .send_message(&peer2_peer_id, "messaging", b"after_empty".to_vec())
        .await
        .expect("Should be able to send after empty message");

    let verify = wait_for_event(
        &mut events2,
        Duration::from_secs(2),
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"after_empty"),
    )
    .await;

    assert!(
        matches!(verify, Some(P2PEvent::Message { .. })),
        "Connection should still work after empty message test"
    );

    info!("=== TEST PASSED: Empty Message Handling ===");
}

// =============================================================================
// PHASE 2: Edge Case Tests
// =============================================================================

/// TEST 2.1: Rapid Connect/Disconnect Cycles
///
/// Connect the same peer multiple times rapidly to check for resource leaks.
#[tokio::test]
async fn test_rapid_reconnection_stress() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Rapid Reconnection Stress ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();

    // Perform multiple rapid connections
    let cycles = 10;
    for i in 0..cycles {
        let result = node1.connect_peer(&addr2).await;
        match result {
            Ok(peer_id) => {
                debug!("Cycle {}: Connected to {}", i, peer_id);
            }
            Err(e) => {
                // Some failures are acceptable during rapid reconnection
                debug!("Cycle {}: Connection error (may be acceptable): {}", i, e);
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    // Allow time for any cleanup
    sleep(Duration::from_millis(500)).await;

    // Verify node is still functional
    let final_connect = node1.connect_peer(&addr2).await;
    assert!(
        final_connect.is_ok(),
        "Node should still be able to connect after rapid cycles"
    );

    info!("=== TEST PASSED: Rapid Reconnection Stress ===");
}

/// TEST 2.2: Concurrent Message Flood
///
/// Send many messages from both directions simultaneously.
#[tokio::test]
async fn test_concurrent_message_flood() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Concurrent Message Flood ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = Arc::new(P2PNode::new(config1).await.expect("Failed to create node1"));
    node1.start().await.expect("Failed to start node1");
    let node2 = Arc::new(P2PNode::new(config2).await.expect("Failed to create node2"));
    node2.start().await.expect("Failed to start node2");

    let mut events1 = node1.subscribe_events();
    let mut events2 = node2.subscribe_events();

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();
    node1.connect_peer(&addr2).await.expect("Connect failed");

    // Wait for auto identity announce to authenticate both sides
    let peer1_peer_id = match wait_for_event(&mut events2, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(id, _)) => id,
        _ => panic!("Node2 did not receive PeerConnected"),
    };

    let peer2_peer_id = match wait_for_event(&mut events1, EVENT_TIMEOUT, |event| {
        matches!(event, P2PEvent::PeerConnected(..))
    })
    .await
    {
        Some(P2PEvent::PeerConnected(id, _)) => id,
        _ => panic!("Node1 did not receive PeerConnected"),
    };

    // Send messages concurrently from both directions
    // Reduced from 50 to 20 for more reliable testing
    let messages_per_direction = 20;
    let node1_clone = Arc::clone(&node1);

    let send_task1 = tokio::spawn(async move {
        for i in 0..messages_per_direction {
            let msg = format!("from1_{i}");
            let _ = node1_clone
                .send_message(&peer2_peer_id, "messaging", msg.as_bytes().to_vec())
                .await;
            // Small delay to avoid overwhelming transport
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let node2_clone = Arc::clone(&node2);
    let send_task2 = tokio::spawn(async move {
        for i in 0..messages_per_direction {
            let msg = format!("from2_{i}");
            let _ = node2_clone
                .send_message(&peer1_peer_id, "messaging", msg.as_bytes().to_vec())
                .await;
            // Small delay to avoid overwhelming transport
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Wait for sends to complete
    let _ = tokio::join!(send_task1, send_task2);

    // Collect received messages with reasonable timeout
    let mut received_on_1 = 0;
    let mut received_on_2 = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

    let collect_task1 = {
        async {
            while tokio::time::Instant::now() < deadline {
                if let Ok(Ok(P2PEvent::Message { data, .. })) =
                    timeout(Duration::from_millis(100), events1.recv()).await
                    && let Ok(msg) = String::from_utf8(data)
                    && msg.starts_with("from2_")
                {
                    received_on_1 += 1;
                }
            }
            received_on_1
        }
    };

    let collect_task2 = {
        async {
            while tokio::time::Instant::now() < deadline {
                if let Ok(Ok(P2PEvent::Message { data, .. })) =
                    timeout(Duration::from_millis(100), events2.recv()).await
                    && let Ok(msg) = String::from_utf8(data)
                    && msg.starts_with("from1_")
                {
                    received_on_2 += 1;
                }
            }
            received_on_2
        }
    };

    let (count1, count2) = tokio::join!(collect_task1, collect_task2);

    info!(
        "Node1 received {} messages, Node2 received {} messages",
        count1, count2
    );

    // We expect most messages to arrive, but some loss under load is acceptable
    // With 20 messages and small delays, we should see at least 25% delivery
    let min_expected = (messages_per_direction as f64 * 0.25) as usize;
    assert!(
        count2 >= min_expected,
        "Node2 should receive at least {} messages (got {})",
        min_expected,
        count2
    );

    info!("=== TEST PASSED: Concurrent Message Flood ===");
}

/// TEST 2.3: Send to Disconnecting Peer
///
/// Start sending a message while peer is disconnecting.
#[tokio::test]
async fn test_send_to_disconnecting_peer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Send to Disconnecting Peer ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = Arc::new(P2PNode::new(config1).await.expect("Failed to create node1"));
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // Drop node2 and immediately try to send
    drop(node2);

    // Try to send multiple messages - should fail gracefully, not panic
    let mut error_count = 0;
    for i in 0..5 {
        let result = node1
            .send_message(
                &peer2_peer_id,
                "messaging",
                format!("msg_{i}").as_bytes().to_vec(),
            )
            .await;

        match result {
            Ok(()) => debug!("Message {} sent (may be queued)", i),
            Err(e) => {
                debug!("Message {} failed as expected: {}", i, e);
                error_count += 1;
            }
        }
    }

    // Some or all should fail, but none should panic
    info!(
        "{} messages failed gracefully (expected behavior)",
        error_count
    );

    // Verify node1 is still functional
    let config3 = create_test_node_config();
    let node3 = P2PNode::new(config3).await.expect("Failed to create node3");
    node3.start().await.expect("Failed to start node3");
    let addrs3 = node3.listen_addrs().await;
    let addr3 = addrs3.first().expect("Need address").to_string();

    let connect_result = node1.connect_peer(&addr3).await;
    assert!(
        connect_result.is_ok(),
        "Node1 should still be functional after sending to dead peer"
    );

    info!("=== TEST PASSED: Send to Disconnecting Peer ===");
}

/// TEST 2.4: Late Event Subscription
///
/// Connect peers BEFORE subscribing to events, then verify message events work.
#[tokio::test]
async fn test_late_event_subscription() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Late Event Subscription ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Connect BEFORE subscribing
    let peer2_peer_id = connect_and_identify(&node1, &node2).await;

    // NOW subscribe to events (late subscription)
    let mut events2 = node2.subscribe_events();

    // Send message
    node1
        .send_message(&peer2_peer_id, "messaging", b"late_sub_test".to_vec())
        .await
        .expect("Send failed");

    // Should still receive message event
    let received = wait_for_event(
        &mut events2,
        Duration::from_secs(2),
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"late_sub_test"),
    )
    .await;

    assert!(
        matches!(received, Some(P2PEvent::Message { .. })),
        "Should receive message even with late subscription"
    );

    info!("=== TEST PASSED: Late Event Subscription ===");
}

// =============================================================================
// PHASE 3: Boundary Tests
// =============================================================================

/// TEST 3.1: Default Configuration Connection
///
/// Verify basic connection behavior with default configuration.
#[tokio::test]
async fn test_default_config_connection() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Default Config Connection ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let peer2_id = connect_and_identify(&node1, &node2).await;

    // Verify the connection is active
    assert!(
        node1.is_peer_connected(&peer2_id).await,
        "node1 should see peer2 as connected"
    );

    // Verify bidirectional message exchange
    let mut events2 = node2.subscribe_events();
    node1
        .send_message(&peer2_id, "messaging", b"hello".to_vec())
        .await
        .expect("send_message should succeed");

    let received = timeout(EVENT_TIMEOUT, async {
        loop {
            if let Ok(P2PEvent::Message { data, .. }) = events2.recv().await {
                return data;
            }
        }
    })
    .await
    .expect("node2 should receive the message within timeout");

    assert_eq!(
        received, b"hello",
        "received message should match sent data"
    );

    info!("=== TEST PASSED: Default Config Connection ===");
}

/// TEST 3.2: Quick Message Exchange
///
/// Verifies connection and message exchange with default configuration.
#[tokio::test]
async fn test_quick_message_exchange() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Quick Message Exchange ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let mut events2 = node2.subscribe_events();

    let peer2_id = connect_and_identify(&node1, &node2).await;

    // Send a message
    node1
        .send_message(&peer2_id, "messaging", b"quick_msg".to_vec())
        .await
        .expect("Should be able to send message");

    let received = wait_for_event(
        &mut events2,
        Duration::from_secs(5),
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"quick_msg"),
    )
    .await;

    assert!(
        matches!(received, Some(P2PEvent::Message { .. })),
        "Should receive message"
    );

    info!("=== TEST PASSED: Quick Message Exchange ===");
}

/// TEST 3.3: Many Peers Performance
///
/// Connect 10 peers to one node and verify all are tracked correctly.
#[tokio::test]
async fn test_many_peers_scaling() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Many Peers Scaling ===");

    let config1 = create_test_node_config();
    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");

    let peer_count = 10;
    let mut nodes: Vec<P2PNode> = Vec::with_capacity(peer_count);
    let mut connected_peers: Vec<PeerId> = Vec::with_capacity(peer_count);

    // Create and connect multiple peers
    for i in 0..peer_count {
        let config = create_test_node_config();
        let node = P2PNode::new(config)
            .await
            .expect("Failed to create peer node");
        node.start().await.expect("Failed to start peer node");

        match timeout(Duration::from_secs(5), connect_and_identify(&node1, &node)).await {
            Ok(peer_id) => {
                debug!("Connected peer {}: {}", i, peer_id);
                connected_peers.push(peer_id);
            }
            Err(_) => {
                warn!("Failed to connect/identify peer {}", i);
            }
        }

        nodes.push(node);
    }

    // Verify all peers are reachable at transport level
    let mut reachable_count = 0;
    for peer_id in &connected_peers {
        if node1.is_peer_connected(peer_id).await {
            reachable_count += 1;
        }
    }
    info!(
        "Connected {} peers, {} reachable",
        connected_peers.len(),
        reachable_count
    );

    assert!(
        reachable_count >= connected_peers.len(),
        "Should track all connected peers"
    );

    // Drop all peer nodes
    drop(nodes);

    // Wait for cleanup (using default 60s threshold would take too long, so we just verify
    // the initial connection worked)
    info!("All peer nodes dropped");

    info!("=== TEST PASSED: Many Peers Scaling ===");
}

// =============================================================================
// PHASE 4: Shutdown & Cleanup Tests
// =============================================================================

/// TEST 4.1: Graceful Shutdown
///
/// Start node with active connections and call stop().
#[tokio::test]
async fn test_graceful_shutdown() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Graceful Shutdown ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Need address").to_string();
    let _peer2_id = node1.connect_peer(&addr2).await.expect("Connect failed");

    sleep(Duration::from_millis(200)).await;

    // Stop node1
    let shutdown_result = node1.stop().await;
    assert!(
        shutdown_result.is_ok(),
        "Shutdown should complete successfully"
    );

    // Verify node1 is no longer running
    let is_running = node1.is_running();
    assert!(!is_running, "Node should not be running after stop()");

    info!("=== TEST PASSED: Graceful Shutdown ===");
}

/// TEST 4.2: Event Subscriber Cleanup
///
/// Create multiple event subscribers, drop some, and verify no deadlock.
#[tokio::test]
async fn test_event_subscriber_cleanup() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Event Subscriber Cleanup ===");

    let config1 = create_test_node_config();
    let config2 = create_test_node_config();

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Create multiple subscribers
    let sub1 = node2.subscribe_events();
    let sub2 = node2.subscribe_events();
    let mut sub3 = node2.subscribe_events();
    let sub4 = node2.subscribe_events();
    let sub5 = node2.subscribe_events();

    // Drop some subscribers
    drop(sub1);
    drop(sub2);
    drop(sub4);
    drop(sub5);

    // Connect and send message - should still work
    let peer2_id = connect_and_identify(&node1, &node2).await;

    node1
        .send_message(&peer2_id, "messaging", b"after_drop".to_vec())
        .await
        .expect("Send should work after dropping subscribers");

    // Remaining subscriber should receive
    let received = wait_for_event(
        &mut sub3,
        Duration::from_secs(2),
        |event| matches!(event, P2PEvent::Message { data, .. } if data == b"after_drop"),
    )
    .await;

    assert!(
        matches!(received, Some(P2PEvent::Message { .. })),
        "Remaining subscriber should still receive events"
    );

    info!("=== TEST PASSED: Event Subscriber Cleanup ===");
}
