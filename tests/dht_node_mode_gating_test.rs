// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

#![allow(clippy::unwrap_used, clippy::expect_used)]
//! DHT Node-Mode Gating Integration Test
//!
//! Verifies that `NodeMode` controls DHT routing table membership:
//!
//! - **Node** peers are added to the DHT routing table.
//! - **Client** peers are tracked as connected but excluded from the
//!   routing table to prevent stale-address pollution.

use saorsa_core::identity::node_identity::NodeIdentity;
use saorsa_core::network::{NodeConfig, NodeMode, P2PEvent, P2PNode};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::info;

/// Maximum time to wait for a single `PeerConnected` event.
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Small pause to let the DHT manager process the event after transport fires it.
const DHT_SETTLE_DELAY: Duration = Duration::from_millis(500);

/// Create a [`NodeConfig`] with a fresh identity and the given [`NodeMode`].
fn test_config(mode: NodeMode) -> NodeConfig {
    let identity =
        Arc::new(NodeIdentity::generate().expect("Test setup: identity generation should succeed"));
    NodeConfig {
        listen_addr: "127.0.0.1:0"
            .parse()
            .expect("Test setup: hardcoded address should parse"),
        listen_addrs: vec![
            "127.0.0.1:0"
                .parse()
                .expect("Test setup: hardcoded address should parse"),
        ],
        bootstrap_peers: vec![],
        node_identity: Some(identity),
        mode,
        allow_loopback: true,
        ..Default::default()
    }
}

/// Wait for the next `PeerConnected` event from any peer.
async fn wait_for_peer_connected(
    rx: &mut broadcast::Receiver<P2PEvent>,
    timeout_duration: Duration,
) -> Option<P2PEvent> {
    let deadline = tokio::time::Instant::now() + timeout_duration;
    while tokio::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(100), rx.recv()).await {
            Ok(Ok(event @ P2PEvent::PeerConnected(..))) => return Some(event),
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return None,
            Err(_) => {}
        }
    }
    None
}

/// Connect `from` to `to` and wait for identity exchange.
async fn connect_and_wait(from: &P2PNode, to: &P2PNode) {
    let addrs = to.listen_addrs().await;
    let addr = addrs
        .first()
        .expect("target node needs a listen address")
        .to_string();
    let channel_id = from.connect_peer(&addr).await.expect("connect_peer failed");
    from.wait_for_peer_identity(&channel_id, EVENT_TIMEOUT)
        .await
        .expect("identity exchange timed out");
}

/// A Node-mode peer must be added to the observer's DHT routing table.
/// A Client-mode peer must be tracked as connected but excluded from the
/// routing table.
#[tokio::test]
async fn test_node_mode_dht_routing_table_gating() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Node-mode DHT routing table gating ===");

    // --- Set up three nodes ------------------------------------------------
    // observer: a Node-mode peer that we inspect for routing table state
    // node_peer: a Node-mode peer that should appear in the routing table
    // client_peer: a Client-mode peer that should NOT appear in the routing table
    let observer = P2PNode::new(test_config(NodeMode::Node))
        .await
        .expect("observer node creation failed");
    let node_peer = P2PNode::new(test_config(NodeMode::Node))
        .await
        .expect("node peer creation failed");
    let client_peer = P2PNode::new(test_config(NodeMode::Client))
        .await
        .expect("client peer creation failed");

    observer.start().await.expect("observer start failed");
    node_peer.start().await.expect("node_peer start failed");
    client_peer.start().await.expect("client_peer start failed");

    let mut observer_events = observer.subscribe_events();

    // --- Connect both peers to the observer --------------------------------
    connect_and_wait(&node_peer, &observer).await;
    connect_and_wait(&client_peer, &observer).await;

    // Collect both PeerConnected events (order may vary due to scheduling).
    let event1 = wait_for_peer_connected(&mut observer_events, EVENT_TIMEOUT)
        .await
        .expect("observer should receive first PeerConnected event");
    let event2 = wait_for_peer_connected(&mut observer_events, EVENT_TIMEOUT)
        .await
        .expect("observer should receive second PeerConnected event");

    // Extract (PeerId, user_agent) from each event.
    let extract = |e: P2PEvent| match e {
        P2PEvent::PeerConnected(id, ua) => (id, ua),
        _ => panic!("unexpected event variant"),
    };
    let (id1, ua1) = extract(event1);
    let (id2, ua2) = extract(event2);

    // Assign based on user agent prefix, not arrival order.
    let (node_peer_id, node_ua, client_peer_id, client_ua) = if ua1.starts_with("node/") {
        (id1, ua1, id2, ua2)
    } else {
        (id2, ua2, id1, ua1)
    };

    assert!(
        node_ua.starts_with("node/"),
        "Node peer should advertise node/ user agent, got: {node_ua}"
    );
    assert!(
        client_ua.starts_with("client/"),
        "Client peer should advertise client/ user agent, got: {client_ua}"
    );

    // Allow DHT manager time to process the events.
    tokio::time::sleep(DHT_SETTLE_DELAY).await;

    // --- Assert routing table membership -----------------------------------
    let dht = observer.dht_manager();

    assert!(
        dht.is_in_routing_table(&node_peer_id).await,
        "Node-mode peer should be present in the DHT routing table"
    );
    assert!(
        !dht.is_in_routing_table(&client_peer_id).await,
        "Client-mode peer should NOT be present in the DHT routing table"
    );

    // Both should still be tracked as connected via the transport layer.
    let connected = dht.get_connected_peers().await;
    assert!(
        connected.contains(&node_peer_id),
        "Node peer should be in connected peers"
    );
    assert!(
        connected.contains(&client_peer_id),
        "Client peer should be in connected peers"
    );

    info!("=== PASS: Node-mode DHT routing table gating ===");

    // --- Cleanup -----------------------------------------------------------
    observer.stop().await.expect("observer stop failed");
    node_peer.stop().await.expect("node_peer stop failed");
    client_peer.stop().await.expect("client_peer stop failed");
}
