// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use super::*;
use crate::P2PNode;

async fn test_node() -> P2PNode {
    P2PNode::new(
        NodeConfig::builder()
            .local(true)
            .port(0)
            .ipv6(false)
            .build()
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn listening_node() -> (P2PNode, MultiAddr) {
    let node = test_node().await;
    node.dht_manager()
        .transport
        .start_network_listeners()
        .await
        .unwrap();
    node.dht_manager().start().await.unwrap();
    let address = node
        .listen_addrs()
        .await
        .into_iter()
        .find(MultiAddr::is_ipv4)
        .unwrap();
    (node, address)
}

async fn seed_peer(manager: &DhtNetworkManager, owner: PeerId, address: &MultiAddr) {
    manager
        .dht
        .write()
        .await
        .add_node_no_trust(NodeInfo {
            id: owner,
            addresses: vec![address.clone()],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        })
        .await
        .unwrap();
}

fn lookup_node(peer_id: PeerId, address: &MultiAddr) -> DHTNode {
    DHTNode {
        peer_id,
        addresses: vec![address.clone()],
        address_types: vec![AddressType::Direct],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    }
}

fn peer_ids(nodes: &[DHTNode]) -> Vec<PeerId> {
    let mut ids: Vec<_> = nodes.iter().map(|node| node.peer_id).collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn closer_peers_match_a_find_node_answer() {
    let (requester, _) = listening_node().await;
    let (responder, responder_address) = listening_node().await;
    let (known, known_address) = listening_node().await;
    seed_peer(responder.dht_manager(), *known.peer_id(), &known_address).await;
    let responder_node = lookup_node(*responder.peer_id(), &responder_address);
    let key = *known.peer_id().as_bytes();

    requester
        .dht_manager()
        .connect_lookup_peer(&responder_node)
        .await
        .unwrap();
    assert!(
        requester
            .dht_manager()
            .is_lookup_candidate_dialable(&responder_node)
            .await
    );
    let answered = requester
        .dht_manager()
        .find_node_on_peer(&responder_node, &key)
        .await
        .unwrap();
    let payload = responder
        .dht_manager()
        .encode_closer_peers(&key, requester.peer_id())
        .await
        .unwrap();
    let decoded = requester
        .dht_manager()
        .decode_closer_peers(
            responder.peer_id(),
            &key,
            &payload,
            Some(&responder_address),
        )
        .await
        .unwrap();

    assert!(peer_ids(&answered).contains(known.peer_id()));
    assert_eq!(peer_ids(&decoded), peer_ids(&answered));
    for node in [&requester, &responder, &known] {
        node.stop().await.unwrap();
    }
}

#[tokio::test]
async fn closer_peers_exclude_the_requester() {
    let responder = test_node().await;
    let requester = PeerId::from_bytes([7; 32]);
    seed_peer(
        responder.dht_manager(),
        requester,
        &"/ip4/127.0.0.1/udp/9/quic".parse().unwrap(),
    )
    .await;
    let payload = responder
        .dht_manager()
        .encode_closer_peers(requester.as_bytes(), &requester)
        .await
        .unwrap();
    let (body, _): (CloserPeers, _) = postcard::take_from_bytes(&payload[1..]).unwrap();
    assert!(body.nodes.iter().all(|node| node.peer_id != requester));
}

#[tokio::test]
async fn closer_peers_reject_another_key_or_format() {
    let node = test_node().await;
    let key = [1; 32];
    let responder = PeerId::from_bytes([2; 32]);
    let payload = node
        .dht_manager()
        .encode_closer_peers(&key, &PeerId::from_bytes([3; 32]))
        .await
        .unwrap();

    let other_key = node
        .dht_manager()
        .decode_closer_peers(&responder, &[9; 32], &payload, None)
        .await;
    assert!(other_key.is_err());

    let mut other_format = payload;
    other_format[0] = CLOSER_PEERS_FORMAT.wrapping_add(1);
    let other_format = node
        .dht_manager()
        .decode_closer_peers(&responder, &key, &other_format, None)
        .await;
    assert!(other_format.is_err());

    let empty = node
        .dht_manager()
        .decode_closer_peers(&responder, &key, &[], None)
        .await;
    assert!(empty.is_err());
}
