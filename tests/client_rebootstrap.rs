// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Regression tests for client-mode routing-table repair (V2-1036).
//!
//! Two failure modes are covered, both previously unrecoverable at runtime
//! (only a process restart re-dialed the configured bootstrap peers):
//!
//! 1. `bootstrap_from_peers` skipped ALL gossiped-peer dials in client mode.
//!    Routing-table admission is connection-driven (`handle_peer_connected`),
//!    so a client with a starved table rediscovered the same peers every
//!    cycle, dialed none of them, and stayed starved forever.
//! 2. `maybe_rebootstrap` seeded only from currently connected peers and gave
//!    up when there were none, never falling back to the configured
//!    bootstrap peers that initial startup uses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{MultiAddr, NodeConfig, NodeMode, P2PNode};
use std::time::Duration;
use tokio::time::timeout;

fn node_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("node config should be valid")
}

fn client_config(bootstrap: Option<MultiAddr>) -> NodeConfig {
    let mut builder = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .mode(NodeMode::Client);
    if let Some(addr) = bootstrap {
        builder = builder.bootstrap_peer(addr);
    }
    builder.build().expect("client config should be valid")
}

async fn started_node() -> P2PNode {
    let node = P2PNode::new(node_config()).await.unwrap();
    node.start().await.unwrap();
    node
}

fn ipv4_listen_addr(addrs: Vec<MultiAddr>) -> MultiAddr {
    addrs
        .into_iter()
        .find(|a| a.is_ipv4())
        .expect("node should have an IPv4 listen address")
}

/// Poll the routing table until it reaches `want` entries or `wait` elapses.
/// Returns the final observed size either way.
async fn wait_for_routing_table(node: &P2PNode, want: usize, wait: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let size = node.dht_manager().get_routing_table_size().await;
        if size >= want || tokio::time::Instant::now() >= deadline {
            return size;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A client whose routing table is below the auto-re-bootstrap threshold must
/// dial gossiped peers during `bootstrap_from_peers` so admission (which is
/// connection-driven) can actually repair the table. Before the fix the
/// client skipped every dial and the table stayed at 1 forever.
#[tokio::test]
async fn starved_client_dials_gossiped_peers_to_repair_routing_table() {
    // Hub-and-spoke mesh: c and d dial hub b, so b's routing table knows
    // both and FIND_NODE against b gossips them.
    let node_b = started_node().await;
    let node_c = started_node().await;
    let node_d = started_node().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let b_addr = ipv4_listen_addr(node_b.listen_addrs().await);
    for spoke in [&node_c, &node_d] {
        timeout(Duration::from_secs(5), spoke.connect_peer(&b_addr))
            .await
            .expect("spoke connect should not time out")
            .expect("spoke connect should succeed");
    }
    let hub_table = wait_for_routing_table(&node_b, 2, Duration::from_secs(10)).await;
    assert!(
        hub_table >= 2,
        "hub should admit both spokes, got {hub_table}"
    );

    // Client connects to the hub only: routing table = 1, below threshold.
    let client = P2PNode::new(client_config(None)).await.unwrap();
    client.start().await.unwrap();
    timeout(Duration::from_secs(5), client.connect_peer(&b_addr))
        .await
        .expect("client connect should not time out")
        .expect("client connect should succeed");
    let before = wait_for_routing_table(&client, 1, Duration::from_secs(10)).await;
    assert!(before >= 1, "client should admit the hub, got {before}");

    // Drive the repair path directly (the maintenance driver would do the
    // same on its next cycle).
    let seeds: Vec<_> = client.connected_peers().await;
    assert!(!seeds.is_empty(), "client should be connected to the hub");
    client
        .dht_manager()
        .bootstrap_from_peers(&seeds)
        .await
        .expect("bootstrap_from_peers should succeed");

    // Admission runs on the async peer-connected path; poll briefly.
    let after = wait_for_routing_table(&client, before + 1, Duration::from_secs(10)).await;
    assert!(
        after > before,
        "client routing table should grow after repair dials (before={before}, after={after})"
    );
}

/// A client that has lost every connection must fall back to re-dialing its
/// configured bootstrap peers during `maybe_rebootstrap`. Before the fix it
/// returned early on "no connected peers" and could only recover via a
/// process restart.
#[tokio::test]
async fn isolated_client_rebootstraps_from_configured_peers() {
    let node_b = started_node().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let b_addr = ipv4_listen_addr(node_b.listen_addrs().await);

    let client = P2PNode::new(client_config(Some(b_addr))).await.unwrap();
    client.start().await.unwrap();
    let before = wait_for_routing_table(&client, 1, Duration::from_secs(10)).await;
    assert!(
        before >= 1,
        "client should bootstrap to the node, got {before}"
    );

    // Sever every connection — the state the reporter's daemon was stuck in.
    for peer in client.connected_peers().await {
        client.disconnect_peer(&peer).await.ok();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !client.connected_peers().await.is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        client.connected_peers().await.is_empty(),
        "disconnect should leave the client with no connections"
    );

    // The repair must reconnect using the configured bootstrap peers.
    client.dht_manager().maybe_rebootstrap().await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while client.connected_peers().await.is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !client.connected_peers().await.is_empty(),
        "maybe_rebootstrap should have re-dialed the configured bootstrap peer"
    );
}
