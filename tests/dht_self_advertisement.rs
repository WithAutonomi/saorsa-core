// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Regression tests for the addresses a node publishes about itself in the DHT.
//!
//! These tests guard against the failure mode where a node tells other peers
//! "you can reach me at <unspecified-or-zero-port>", which is silently filtered
//! out by every consumer's `dialable_addresses()` check and makes the node
//! invisible to DHT-based peer discovery.
//!
//! Concretely, the production path is:
//!
//! 1. Peer A queries the DHT for peer B.
//! 2. The DHT response contains B's self-entry, built by
//!    `DhtNetworkManager::local_dht_node()`.
//! 3. A's `dialable_addresses()` filter rejects any unspecified IP
//!    (`0.0.0.0`, `[::]`) and any non-QUIC entry. Port 0 is also undialable.
//! 4. If every address in B's self-entry is filtered out, A cannot reach B
//!    via the DHT — it can only reach B via static bootstrap config or a
//!    pre-existing in-memory connection.
//!
//! These tests assert (3) succeeds against (2) using the public
//! `find_closest_nodes_local_with_self()` API, which is the same code path the
//! DHT response handler invokes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use saorsa_core::{Key, MultiAddr, NodeConfig, P2PNode};
use std::time::Duration;

/// How many results to ask for from the local closest-nodes query. Any value
/// >= 1 is fine; we only care that the local self-entry is included.
const QUERY_COUNT: usize = 8;

/// Brief delay after `start()` to let the listener bind. The two_node_messaging
/// integration tests use the same value.
const POST_START_DELAY: Duration = Duration::from_millis(50);

/// Build a node config that mirrors a typical production deployment as
/// closely as possible while still being runnable inside a unit test:
///
/// - `local: false` — use `Public` listen mode (binds to `0.0.0.0` /
///   `[::]`), which is what `cargo run --release -- --listen 0.0.0.0:10000`
///   does.
/// - `port: 0` — let the OS pick an ephemeral port. This matches ant-node's
///   default `--port 0`.
/// - `ipv6: false` — IPv4-only is sufficient for the assertion and avoids
///   IPv6-disabled CI environments.
fn production_like_config() -> NodeConfig {
    NodeConfig::builder()
        .local(false)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Returns the entry for `peer_id` from a list of `DHTNode`s, or panics with a
/// descriptive message. We assert this entry exists separately from the
/// dialability assertions so a missing self-entry is reported clearly.
fn extract_self_entry(
    nodes: &[saorsa_core::DHTNode],
    peer_id: &saorsa_core::PeerId,
) -> saorsa_core::DHTNode {
    nodes
        .iter()
        .find(|n| n.peer_id == *peer_id)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "find_closest_nodes_local_with_self did not return the local node \
                 (peer_id={peer_id:?}); this means local_dht_node() was not invoked"
            )
        })
}

/// Returns true if the given `MultiAddr` would survive `dialable_addresses()`'s
/// filter — i.e. it is a QUIC address with a specified IP and a non-zero port.
///
/// Mirrors the rejection rules in
/// `saorsa-core/src/dht_network_manager.rs::dialable_addresses`.
fn is_dialable(addr: &MultiAddr) -> bool {
    let Some(sa) = addr.dialable_socket_addr() else {
        return false; // not QUIC
    };
    if sa.ip().is_unspecified() {
        return false; // 0.0.0.0 / [::]
    }
    if sa.port() == 0 {
        return false; // OS-assigned placeholder, never dialable
    }
    true
}

/// **PRIMARY REGRESSION TEST FOR THE NAT TRAVERSAL ROOT CAUSE.**
///
/// A freshly-started node must publish at least one dialable address about
/// itself in `local_dht_node()`. If this test fails, peers performing DHT
/// FIND_NODE for this node will receive *zero* usable addresses and will be
/// unable to connect — manifesting as "sporadic NAT traversal" in production.
///
/// On the broken codebase this test fails because `local_dht_node()` reads
/// from `NodeConfig::listen_addrs()` (a static `(port, ipv6, local)`
/// derivation that returns wildcards in `Public` mode and zero ports for
/// `--port 0`) instead of from the runtime-bound listener addresses or the
/// transport's observed external address.
#[tokio::test]
async fn published_self_entry_contains_a_dialable_address() {
    let node = P2PNode::new(production_like_config())
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    let peer_id = *node.peer_id();
    let key: Key = [0u8; 32];

    let nodes = node
        .dht_manager()
        .find_closest_nodes_local_with_self(&key, QUERY_COUNT)
        .await;

    let self_entry = extract_self_entry(&nodes, &peer_id);

    assert!(
        !self_entry.addresses.is_empty(),
        "local DHT self-entry has no addresses at all — peers will see this node \
         as having zero contact information"
    );

    let dialable: Vec<&MultiAddr> = self_entry
        .addresses
        .iter()
        .filter(|a| is_dialable(a))
        .collect();

    assert!(
        !dialable.is_empty(),
        "local DHT self-entry has {} address(es) but NONE are dialable: {:?}\n\
         \n\
         This is the root cause of sporadic NAT traversal failure: every address \
         in the self-entry will be filtered out by dialable_addresses() on the \
         receiving peer, so DHT-based peer discovery for this node always returns \
         no contactable address.\n\
         \n\
         Fix: DhtNetworkManager::local_dht_node() must read from the runtime \
         listen_addrs RwLock and/or the transport's get_observed_external_address() \
         instead of NodeConfig::listen_addrs() (which is a pure derivation that \
         returns 0.0.0.0:<port> in Public mode and zero ports for --port 0).",
        self_entry.addresses.len(),
        self_entry.addresses,
    );

    node.stop().await.expect("node.stop() should succeed");
}

/// The runtime `listen_addrs` read from the transport's RwLock should match
/// the addresses published in the DHT self-entry. If they diverge, the DHT is
/// advertising stale or incorrect contact information.
///
/// This test catches the case where someone "fixes" `local_dht_node()` by
/// reading from the static `NodeConfig` instead of from the live transport
/// state, which would produce a result that's still wrong but in a different
/// way (e.g. the configured port instead of the bound port).
#[tokio::test]
async fn published_self_entry_matches_runtime_listen_addrs() {
    let node = P2PNode::new(production_like_config())
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    // What the transport actually bound to (real ports, possibly real IPs).
    let runtime_addrs = node.listen_addrs().await;

    // What the node tells the rest of the network about itself.
    let nodes = node
        .dht_manager()
        .find_closest_nodes_local_with_self(&[0u8; 32], QUERY_COUNT)
        .await;
    let self_entry = extract_self_entry(&nodes, node.peer_id());

    // The published ports must be the actually-bound ports — not 0, and not
    // some statically configured value that might differ from what the OS
    // chose.
    let runtime_ports: Vec<u16> = runtime_addrs
        .iter()
        .filter_map(MultiAddr::port)
        .filter(|p| *p != 0)
        .collect();

    assert!(
        !runtime_ports.is_empty(),
        "transport.listen_addrs() returned no non-zero ports — the listener \
         did not bind successfully"
    );

    let published_ports: Vec<u16> = self_entry
        .addresses
        .iter()
        .filter_map(MultiAddr::port)
        .collect();

    for port in &runtime_ports {
        assert!(
            published_ports.contains(port),
            "published self-entry does not include the actually-bound port {port}; \
             runtime ports = {runtime_ports:?}, published ports = {published_ports:?}\n\
             \n\
             local_dht_node() is reading from the static NodeConfig instead of \
             from the runtime transport state — peers will dial the wrong port."
        );
    }

    node.stop().await.expect("node.stop() should succeed");
}

/// A node configured with `local: true` (loopback mode) should publish
/// loopback addresses with the *actual bound port*, not port 0.
///
/// This is a weaker variant of the primary test that catches the same bug via
/// a different config path: even in `Local` listen mode (where the wildcard-IP
/// problem does not apply), `NodeConfig::listen_addrs()` still returns the
/// configured port — which is 0 — instead of the OS-assigned ephemeral port.
#[tokio::test]
async fn published_self_entry_uses_bound_port_in_local_mode() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid");

    let node = P2PNode::new(config)
        .await
        .expect("P2PNode::new should succeed");
    node.start().await.expect("node.start() should succeed");
    tokio::time::sleep(POST_START_DELAY).await;

    let nodes = node
        .dht_manager()
        .find_closest_nodes_local_with_self(&[0u8; 32], QUERY_COUNT)
        .await;
    let self_entry = extract_self_entry(&nodes, node.peer_id());

    let zero_port_addrs: Vec<&MultiAddr> = self_entry
        .addresses
        .iter()
        .filter(|a| a.port() == Some(0))
        .collect();

    assert!(
        zero_port_addrs.is_empty(),
        "local DHT self-entry contains {} address(es) with port 0: {:?}\n\
         \n\
         Port 0 is the placeholder the kernel uses for 'pick any port'; it is \
         never a valid destination. Publishing it to the DHT means peers will \
         try to dial port 0 and fail. The fix is the same as the primary \
         regression test: read from the runtime transport state, not from \
         NodeConfig::listen_addrs().",
        zero_port_addrs.len(),
        zero_port_addrs,
    );

    node.stop().await.expect("node.stop() should succeed");
}
