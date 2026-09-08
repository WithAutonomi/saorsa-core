// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use super::*;
use crate::{P2PNode, WebRtcCertificateHash, WebRtcDirectAddr};

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

fn browser_address(owner: PeerId) -> MultiAddr {
    MultiAddr::webrtc_direct(
        WebRtcDirectAddr::new(
            "203.0.113.7:42768".parse().unwrap(),
            WebRtcCertificateHash::new([0x55; 32]),
        )
        .unwrap(),
    )
    .with_peer_id(owner)
}

fn quic_record(address: &str) -> TransportAddressRecord {
    TransportAddressRecord::from_multiaddr(&address.parse().unwrap(), KnownReachability::Direct)
        .unwrap()
        .unwrap()
}

async fn seed_peer(manager: &DhtNetworkManager, owner: PeerId, address: &str) {
    manager
        .dht
        .write()
        .await
        .add_node_no_trust(NodeInfo {
            id: owner,
            addresses: vec![address.parse().unwrap()],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        })
        .await
        .unwrap();
}

async fn peer_view(manager: &DhtNetworkManager, owner: PeerId) -> DHTNode {
    manager
        .find_closest_nodes_local(owner.as_bytes(), 1)
        .await
        .remove(0)
}

fn message(owner: PeerId, operation: DhtNetworkOperation) -> DhtNetworkMessage {
    DhtNetworkMessage {
        message_id: "address-v2-regression".into(),
        source: owner,
        target: None,
        message_type: DhtMessageType::Request,
        payload: operation,
        result: None,
        timestamp: 1,
        ttl: 10,
        hop_count: 0,
    }
}

fn response(sender: PeerId, owner: PeerId, seq: u64) -> DhtNetworkMessage {
    let mut response = message(sender, DhtNetworkOperation::FindNodeV2 { key: [0; 32] });
    response.message_type = DhtMessageType::Response;
    response.result = Some(DhtNetworkResult::NodesFoundV2 {
        key: [0; 32],
        nodes: vec![TransportDhtNode {
            peer_id: owner,
            records: vec![
                TransportAddressRecord::from_multiaddr(
                    &browser_address(owner),
                    KnownReachability::Unverified,
                )
                .unwrap()
                .unwrap(),
            ],
            publish_seq: seq,
            reliability: 1.0,
        }],
    });
    response
}

fn track_request(
    manager: &DhtNetworkManager,
    peer_id: PeerId,
    operation: DhtNetworkOperation,
) -> oneshot::Receiver<DhtResponseEnvelope> {
    let (tx, rx) = oneshot::channel();
    manager.active_operations.lock().unwrap().insert(
        "address-v2-regression".into(),
        DhtOperationContext {
            operation,
            peer_id,
            started_at: Instant::now(),
            timeout: Duration::from_secs(2),
            contacted_nodes: vec![peer_id],
            response_tx: Some(tx),
        },
    );
    rx
}

#[tokio::test]
async fn unauthenticated_v2_response_cannot_populate_address_cache() {
    let node = test_node().await;
    let owner = PeerId::from_bytes([0x22; 32]);
    let sender = PeerId::from_bytes([0x33; 32]);
    let _rx = track_request(
        node.dht_manager(),
        sender,
        DhtNetworkOperation::FindNodeV2 { key: [0; 32] },
    );
    node.dht_manager()
        .handle_dht_response(&response(sender, owner, u64::MAX), &sender, None)
        .await
        .unwrap();
    assert!(
        node.dht_manager()
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn authenticated_v2_response_requires_a_live_matching_request() {
    let receiver = test_node().await;
    let sender = test_node().await;
    receiver.start().await.unwrap();
    sender.start().await.unwrap();
    let address = sender
        .listen_addrs()
        .await
        .into_iter()
        .find(MultiAddr::is_ipv4)
        .unwrap();
    let channel = receiver.connect_peer(&address).await.unwrap();
    receiver
        .wait_for_peer_identity(&channel, Duration::from_secs(2))
        .await
        .unwrap();
    let manager = receiver.dht_manager();
    let sender_id = *sender.peer_id();
    let owner = PeerId::from_bytes([0x22; 32]);
    let wire_response = response(sender_id, owner, 10);
    assert_eq!(
        manager.canonical_app_peer_id(&sender_id).await,
        Some(sender_id)
    );

    // An authenticated peer still cannot send an unsolicited record.
    manager
        .handle_dht_response(&wire_response, &sender_id, None)
        .await
        .unwrap();
    assert!(
        manager
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );

    // Neither another peer's request nor the wrong operation/key authorizes
    // a response. Rejection must leave the waiter available for a valid reply.
    for (expected_peer, operation) in [
        (owner, DhtNetworkOperation::FindNodeV2 { key: [0; 32] }),
        (sender_id, DhtNetworkOperation::Ping),
        (sender_id, DhtNetworkOperation::FindNodeV2 { key: [1; 32] }),
    ] {
        let mut rx = track_request(manager, expected_peer, operation);
        manager
            .handle_dht_response(&wire_response, &sender_id, None)
            .await
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(
            manager
                .supplemental_addresses_for_peer(&owner)
                .await
                .is_empty()
        );
    }

    let operation = DhtNetworkOperation::FindNodeV2 { key: [0; 32] };
    drop(track_request(manager, sender_id, operation.clone()));
    manager
        .handle_dht_response(&wire_response, &sender_id, None)
        .await
        .unwrap();
    assert!(
        manager
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );

    let rx = track_request(manager, sender_id, operation);
    manager
        .handle_dht_response(&wire_response, &sender_id, None)
        .await
        .unwrap();
    assert!(matches!(
        rx.await.unwrap().result,
        DhtNetworkResult::NodesFound { .. }
    ));
    assert!(
        manager
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );

    // A duplicate must not advance the accepted publication sequence.
    manager
        .handle_dht_response(&response(sender_id, owner, u64::MAX), &sender_id, None)
        .await
        .unwrap();
    assert!(
        !manager
            .transport_address_sets
            .read()
            .await
            .contains_key(&owner)
    );
    receiver.stop().await.unwrap();
    sender.stop().await.unwrap();
}

#[tokio::test]
async fn rejected_v2_publish_preserves_both_views_and_allows_correction() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let good = quic_record("/ip4/8.8.8.8/udp/9000/quic");
    assert!(
        manager
            .apply_transport_address_set(&owner, 10, vec![good.clone()], None)
            .await
    );
    for invalid in [
        quic_record("/ip4/0.0.0.0/udp/9000/quic"),
        quic_record("/ip4/8.8.8.8/udp/0/quic"),
        TransportAddressRecord {
            transport: KnownTransport::Quic.id(),
            reachability: 2,
            address: vec![255],
        },
    ] {
        assert!(
            !manager
                .apply_transport_address_set(&owner, 11, vec![invalid], None)
                .await
        );
        let legacy = peer_view(manager, owner).await;
        assert_eq!(dht_node_publish_seq(&legacy), 10);
        assert_eq!(
            manager.transport_dht_node(legacy).await.records,
            vec![good.clone()]
        );
    }
    let corrected = quic_record("/ip4/9.9.9.9/udp/9000/quic");
    assert!(
        manager
            .apply_transport_address_set(&owner, 11, vec![corrected.clone()], None)
            .await
    );
    for seq in [0, 10, 11] {
        assert!(
            !manager
                .apply_transport_address_set(&owner, seq, vec![good.clone()], None)
                .await
        );
    }
    let legacy = peer_view(manager, owner).await;
    assert_eq!(dht_node_publish_seq(&legacy), 11);
    assert_eq!(
        legacy.addresses,
        vec![corrected.decode_known().unwrap().unwrap()]
    );
    assert_eq!(
        manager.transport_dht_node(legacy).await.records,
        vec![corrected]
    );
}

#[tokio::test]
async fn supplemental_replacements_preserve_native_addresses_and_reject_empty_sets() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let quic = quic_record("/ip4/8.8.8.8/udp/9000/quic");
    let browser = TransportAddressRecord::from_multiaddr(
        &browser_address(owner),
        KnownReachability::Unverified,
    )
    .unwrap()
    .unwrap();
    assert!(
        manager
            .apply_transport_address_set(&owner, 10, vec![quic.clone(), browser.clone()], None)
            .await
    );
    let stale = peer_view(manager, owner).await;
    assert!(
        manager
            .apply_transport_address_set(&owner, 11, vec![browser.clone()], None)
            .await
    );
    manager.merge_trusted_gossiped_typed_addresses(&stale).await;
    let native = peer_view(manager, owner).await;
    assert_eq!(native.addresses, stale.addresses);
    assert_eq!(dht_node_publish_seq(&native), 10);
    assert_eq!(
        manager.transport_dht_node(native).await.records,
        vec![browser.clone()]
    );
    assert!(
        !manager
            .apply_transport_address_set(&owner, u64::MAX, Vec::new(), None)
            .await
    );
    assert_eq!(manager.transport_address_sets.read().await[&owner].seq, 11);
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );
    // A real nonempty replacement still removes omitted supplemental records.
    assert!(
        manager
            .apply_transport_address_set(&owner, 12, vec![quic], None)
            .await
    );
    assert!(
        manager
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );
    assert_eq!(dht_node_publish_seq(&peer_view(manager, owner).await), 12);
}

#[tokio::test]
async fn unsigned_v2_gossip_cannot_replace_owner_proven_native_or_future_records() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    let quic = quic_record("/ip4/8.8.8.8/udp/9000/quic");
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    assert!(
        manager
            .apply_transport_address_set(&owner, 10, vec![quic.clone()], None)
            .await
    );
    let last_seen = manager.dht.read().await.all_nodes().await[0]
        .last_seen
        .load();
    assert!(
        manager
            .normalize_v2_nodes(
                vec![TransportDhtNode {
                    peer_id: owner,
                    records: Vec::new(),
                    publish_seq: u64::MAX,
                    reliability: 1.0
                }],
                None
            )
            .await
            .is_empty()
    );
    assert_eq!(manager.transport_address_sets.read().await[&owner].seq, 10);
    let opaque = TransportAddressRecord {
        transport: 900,
        reachability: 901,
        address: vec![1, 2, 3],
    };
    manager
        .normalize_v2_nodes(
            vec![TransportDhtNode {
                peer_id: owner,
                records: vec![opaque.clone()],
                publish_seq: 11,
                reliability: 1.0,
            }],
            None,
        )
        .await;
    let native = peer_view(manager, owner).await;
    assert_eq!(
        native.addresses,
        vec![quic.decode_known().unwrap().unwrap()]
    );
    assert_eq!(dht_node_publish_seq(&native), 10);
    assert_eq!(
        manager.transport_dht_node(native).await.records,
        vec![quic.clone()]
    );
    assert_eq!(
        manager.dht.read().await.all_nodes().await[0]
            .last_seen
            .load(),
        last_seen
    );
    assert!(
        manager
            .apply_transport_address_set(&owner, 12, vec![quic], None)
            .await
    );
}

#[tokio::test]
async fn v2_filters_loopback_in_both_ip_representations_and_transports() {
    let node = P2PNode::new(NodeConfig::builder().port(0).ipv6(false).build().unwrap())
        .await
        .unwrap();
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let lan_source = "/ip4/192.168.1.2/udp/9000/quic".parse().unwrap();
    for (seq, socket) in [(10, "127.0.0.1:9000"), (12, "[::ffff:127.0.0.1]:9000")] {
        assert!(
            manager
                .apply_transport_address_set(
                    &owner,
                    seq,
                    vec![quic_record("/ip4/8.8.8.8/udp/9000/quic")],
                    None
                )
                .await
        );
        let socket: SocketAddr = socket.parse().unwrap();
        let addresses = [
            MultiAddr::quic(socket),
            MultiAddr::webrtc_direct(
                WebRtcDirectAddr::new(socket, WebRtcCertificateHash::new([1; 32])).unwrap(),
            )
            .with_peer_id(owner),
        ];
        let records = addresses
            .iter()
            .map(|address| {
                TransportAddressRecord::from_multiaddr(address, KnownReachability::Direct)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        assert!(
            !manager
                .apply_transport_address_set(&owner, seq + 1, records, Some(&lan_source))
                .await
        );
        let native = peer_view(manager, owner).await;
        assert_eq!(
            native.addresses,
            vec!["/ip4/8.8.8.8/udp/9000/quic".parse::<MultiAddr>().unwrap()]
        );
        assert_eq!(dht_node_publish_seq(&native), seq);
        assert_eq!(
            manager.transport_dht_node(native).await.records,
            vec![quic_record("/ip4/8.8.8.8/udp/9000/quic")]
        );
    }
}

#[tokio::test]
async fn concurrent_legacy_and_v2_publications_keep_the_newest_complete_set() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let quic = quic_record("/ip4/9.9.9.9/udp/9000/quic");
    let browser = TransportAddressRecord::from_multiaddr(
        &browser_address(owner),
        KnownReachability::Unverified,
    )
    .unwrap()
    .unwrap();
    let legacy = message(
        owner,
        DhtNetworkOperation::PublishAddressSet {
            seq: 12,
            addresses: vec![(quic.decode_known().unwrap().unwrap(), AddressType::Direct)],
        },
    );
    let (_, legacy_result) = tokio::join!(
        manager.apply_transport_address_set(&owner, 11, vec![browser.clone()], None),
        manager.handle_dht_request(&legacy, &owner, None),
    );
    legacy_result.unwrap();
    assert_eq!(
        manager
            .transport_dht_node(peer_view(manager, owner).await)
            .await
            .records,
        vec![quic]
    );
    assert!(
        manager
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );

    let (_, legacy_result) = tokio::join!(
        manager.apply_transport_address_set(&owner, 13, vec![browser.clone()], None),
        manager.handle_dht_request(&legacy, &owner, None),
    );
    legacy_result.unwrap();
    let native = peer_view(manager, owner).await;
    assert_eq!(
        native.addresses,
        vec!["/ip4/9.9.9.9/udp/9000/quic".parse::<MultiAddr>().unwrap()]
    );
    assert_eq!(dht_node_publish_seq(&native), 12);
    assert_eq!(
        manager.transport_dht_node(native).await.records,
        vec![browser]
    );
}

#[tokio::test]
async fn v2_completes_an_identical_legacy_projection_at_the_same_sequence() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let quic = quic_record("/ip4/8.8.8.8/udp/9000/quic");
    let legacy = message(
        owner,
        DhtNetworkOperation::PublishAddressSet {
            seq: 10,
            addresses: vec![(quic.decode_known().unwrap().unwrap(), AddressType::Direct)],
        },
    );
    manager
        .handle_dht_request(&legacy, &owner, None)
        .await
        .unwrap();
    assert!(
        !manager
            .apply_transport_address_set(
                &owner,
                10,
                vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
                None
            )
            .await
    );
    let browser = TransportAddressRecord::from_multiaddr(
        &browser_address(owner),
        KnownReachability::Unverified,
    )
    .unwrap()
    .unwrap();
    let records = vec![quic, browser];
    assert!(
        manager
            .apply_transport_address_set(&owner, 10, records.clone(), None)
            .await
    );
    assert_eq!(
        manager
            .transport_dht_node(peer_view(manager, owner).await)
            .await
            .records,
        records
    );
}

#[tokio::test]
async fn v2_lookup_bounds_the_full_envelope_and_preserves_complete_closest_records() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let mut expected = Vec::new();
    for (id, ip) in [(0x22, "8.8.8.8"), (0x33, "9.9.9.9"), (0x44, "1.1.1.1")] {
        let owner = PeerId::from_bytes([id; 32]);
        seed_peer(manager, owner, &format!("/ip4/{ip}/udp/9000/quic")).await;
        let mut records = vec![quic_record(&format!("/ip4/{ip}/udp/9000/quic"))];
        records.extend((0..15).map(|i| TransportAddressRecord {
            transport: 900 + i,
            reachability: 901,
            address: vec![1; 2048],
        }));
        let publish = message(
            owner,
            DhtNetworkOperation::PublishAddressSetV2 {
                seq: 10,
                records: records.clone(),
            },
        );
        let bytes = postcard::to_stdvec(&publish).unwrap();
        assert!(bytes.len() < MAX_MESSAGE_SIZE);
        manager
            .handle_dht_message(&bytes, &owner, None)
            .await
            .unwrap();
        expected.push((owner, records));
    }
    let requester = PeerId::from_bytes([0x77; 32]);
    // The same records fit differently when the request has a larger echoed ID.
    for (id_len, expected_count) in [(32, 2), (10_000, 1)] {
        let mut request = message(requester, DhtNetworkOperation::FindNodeV2 { key: [0; 32] });
        request.message_id = "x".repeat(id_len);
        let bytes = manager
            .handle_dht_message(&postcard::to_stdvec(&request).unwrap(), &requester, None)
            .await
            .unwrap()
            .unwrap();
        assert!(bytes.len() <= MAX_MESSAGE_SIZE);
        let response: DhtNetworkMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(response.message_id, request.message_id);
        let Some(DhtNetworkResult::NodesFoundV2 { nodes, .. }) = response.result else {
            panic!("expected V2 lookup response");
        };
        assert_eq!(nodes.len(), expected_count);
        for (actual, (owner, records)) in nodes.iter().zip(&expected) {
            assert_eq!(actual.peer_id, *owner);
            assert_eq!(actual.publish_seq, 10);
            assert_eq!(actual.records, *records);
        }
    }
}

#[tokio::test]
async fn v2_response_rejects_an_envelope_that_cannot_fit_even_without_nodes() {
    let node = test_node().await;
    let owner = PeerId::from_bytes([0x22; 32]);
    let mut response = response(owner, owner, 10);
    response.message_id = "x".repeat(MAX_MESSAGE_SIZE);
    assert!(DhtNetworkManager::encode_response_message(response).is_err());

    let request = message(owner, DhtNetworkOperation::FindNodeV2 { key: [0; 32] });
    let empty = node
        .dht_manager()
        .create_response_message(
            &request,
            DhtNetworkResult::NodesFoundV2 {
                key: [0; 32],
                nodes: Vec::new(),
            },
        )
        .unwrap();
    let expected = postcard::to_stdvec(&empty).unwrap();
    assert_eq!(
        DhtNetworkManager::encode_response_message(empty).unwrap(),
        expected
    );
}

#[tokio::test]
async fn supplemental_self_addresses_bind_missing_peer_ids_before_deduplication() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let address = MultiAddr::webrtc_direct(
        WebRtcDirectAddr::new(
            "203.0.113.7:42768".parse().unwrap(),
            WebRtcCertificateHash::new([0x55; 32]),
        )
        .unwrap(),
    );
    let bound = address.clone().with_peer_id(*node.peer_id());
    let other_peer = address.clone().with_peer_id(PeerId::from_bytes([0x22; 32]));
    manager
        .set_supplemental_self_addresses(vec![address, bound.clone(), other_peer])
        .await;
    assert_eq!(
        manager
            .supplemental_addresses_for_peer(node.peer_id())
            .await,
        vec![bound.clone()]
    );
    let records = manager.complete_transport_address_records(&[]).await;
    assert_eq!(records.len(), 1);
    let (received, _) = manager
        .validate_transport_address_records(node.peer_id(), records, None)
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].decode_known().unwrap(), Some(bound));
}

#[tokio::test]
async fn empty_publication_is_not_sent_or_acknowledged() {
    let publisher = test_node().await;
    let receiver = test_node().await;
    publisher.start().await.unwrap();
    receiver.start().await.unwrap();
    let address = receiver
        .listen_addrs()
        .await
        .into_iter()
        .find(MultiAddr::is_ipv4)
        .unwrap();
    let peer = DHTNode {
        peer_id: *receiver.peer_id(),
        addresses: vec![address],
        address_types: vec![AddressType::Direct],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    let confirmed = publisher
        .dht_manager()
        .publish_address_records_to_peers(Vec::new(), &[peer])
        .await;
    assert!(confirmed.is_empty());
    assert!(
        receiver
            .dht_manager()
            .transport_address_sets
            .read()
            .await
            .is_empty()
    );
    publisher.stop().await.unwrap();
    receiver.stop().await.unwrap();
}

#[tokio::test]
async fn signed_gossip_survives_forwarding_and_unsigned_downgrade_attempts() {
    use crate::identity::NodeIdentity;
    let receiver = test_node().await;
    let forwarder = test_node().await;
    receiver.start().await.unwrap();
    forwarder.start().await.unwrap();
    let address = forwarder
        .listen_addrs()
        .await
        .into_iter()
        .find(MultiAddr::is_ipv4)
        .unwrap();
    let channel = receiver.connect_peer(&address).await.unwrap();
    receiver
        .wait_for_peer_identity(&channel, Duration::from_secs(2))
        .await
        .unwrap();
    let manager = receiver.dht_manager();
    let sender = *forwarder.peer_id();
    let identity = NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let native = quic_record("/ip4/9.9.9.9/udp/9000/quic");
    let mut browser = TransportAddressRecord::from_multiaddr(
        &browser_address(owner),
        KnownReachability::Unverified,
    )
    .unwrap()
    .unwrap();
    // Verify and forward the original even though local policy normalizes this tag.
    browser.reachability = KnownReachability::Direct.id();
    let opaque = TransportAddressRecord {
        transport: 900,
        reachability: 901,
        address: vec![1, 2, 3],
    };
    let proof = SignedAddressRecord::sign(
        &identity,
        20,
        DhtNetworkManager::address_time(),
        vec![native.clone(), browser.clone(), opaque],
    )
    .unwrap();
    let last_seen = manager
        .dht
        .read()
        .await
        .all_nodes()
        .await
        .into_iter()
        .find(|node| node.id == owner)
        .unwrap()
        .last_seen
        .load();
    let operation = DhtNetworkOperation::FindNodeSigned { key: [0; 32] };
    let mut wire = message(sender, operation.clone());
    wire.message_type = DhtMessageType::Response;
    wire.result = Some(DhtNetworkResult::NodesFoundSigned {
        key: [0; 32],
        nodes: vec![SignedTransportDhtNode {
            // A responder cannot substitute its own view for fields inside the proof.
            node: TransportDhtNode {
                peer_id: owner,
                records: vec![],
                publish_seq: u64::MAX,
                reliability: 1.0,
            },
            proof: Some(proof.clone()),
        }],
    });
    // Neither an unsolicited proof nor a mismatched live lookup may mutate caches.
    manager
        .handle_dht_response(&wire, &sender, None)
        .await
        .unwrap();
    assert!(
        !manager
            .transport_address_sets
            .read()
            .await
            .contains_key(&owner)
    );
    let rx = track_request(manager, sender, operation);
    let mut wrong_key = wire.clone();
    if let Some(DhtNetworkResult::NodesFoundSigned { key, .. }) = &mut wrong_key.result {
        *key = [1; 32];
    }
    manager
        .handle_dht_response(&wrong_key, &sender, None)
        .await
        .unwrap();
    assert!(
        !manager
            .transport_address_sets
            .read()
            .await
            .contains_key(&owner)
    );
    manager
        .handle_dht_response(&wire, &sender, None)
        .await
        .unwrap();
    let DhtNetworkResult::NodesFound { nodes, .. } = rx.await.unwrap().result else {
        panic!("nodes")
    };
    assert_eq!(dht_node_publish_seq(&nodes[0]), 20);
    assert_eq!(
        nodes[0].addresses,
        vec![native.decode_known().unwrap().unwrap()]
    );
    assert_eq!(
        manager
            .signed_address_record_for_peer(&owner)
            .await
            .unwrap()
            .encode()
            .unwrap(),
        proof.encode().unwrap()
    );
    assert_eq!(
        manager.supplemental_address_records_for_peer(&owner).await[0].1,
        KnownReachability::Unverified
    );
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .all_nodes()
            .await
            .into_iter()
            .find(|node| node.id == owner)
            .unwrap()
            .last_seen
            .load(),
        last_seen
    );

    // Both legacy wire versions carry only hints when forwarded by somebody else.
    for version in [1, 2] {
        let operation = if version == 1 {
            DhtNetworkOperation::FindNode { key: [0; 32] }
        } else {
            DhtNetworkOperation::FindNodeV2 { key: [0; 32] }
        };
        let rx = track_request(manager, sender, operation.clone());
        let mut forged = message(sender, operation);
        forged.message_type = DhtMessageType::Response;
        forged.result = Some(if version == 1 {
            DhtNetworkResult::NodesFound {
                key: [0; 32],
                nodes: vec![DHTNode {
                    peer_id: owner,
                    addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                    address_types: vec![AddressType::Direct],
                    distance: encode_publish_seq_distance(u64::MAX),
                    reliability: 1.0,
                    address_authority: None,
                }],
            }
        } else {
            DhtNetworkResult::NodesFoundV2 {
                key: [0; 32],
                nodes: vec![TransportDhtNode {
                    peer_id: owner,
                    records: vec![quic_record("/ip4/1.1.1.1/udp/9000/quic")],
                    publish_seq: u64::MAX,
                    reliability: 1.0,
                }],
            }
        });
        manager
            .handle_dht_response(&forged, &sender, None)
            .await
            .unwrap();
        let DhtNetworkResult::NodesFound { nodes, .. } = rx.await.unwrap().result else {
            panic!("nodes")
        };
        assert_eq!(
            nodes[0].addresses,
            vec![native.decode_known().unwrap().unwrap()]
        );
        assert_eq!(dht_node_publish_seq(&nodes[0]), 20);
        assert_eq!(manager.transport_address_sets.read().await[&owner].seq, 20);
    }
    let stale = SignedAddressRecord::sign(
        &identity,
        19,
        DhtNetworkManager::address_time(),
        vec![quic_record("/ip4/1.1.1.1/udp/9000/quic")],
    )
    .unwrap();
    assert!(
        !manager
            .apply_signed_address_set(
                stale.verify(DhtNetworkManager::address_time()).unwrap(),
                None
            )
            .await
    );
    let corrected = SignedAddressRecord::sign(
        &identity,
        21,
        DhtNetworkManager::address_time(),
        vec![native],
    )
    .unwrap();
    assert!(
        manager
            .apply_signed_address_set(
                corrected.verify(DhtNetworkManager::address_time()).unwrap(),
                None
            )
            .await
    );
    receiver.stop().await.unwrap();
    forwarder.stop().await.unwrap();
}

#[tokio::test]
async fn signed_discovery_precedes_admission_and_defers_to_newer_direct_publication() {
    let receiver = test_node().await;
    let manager = receiver.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let record = quic_record("/ip4/9.9.9.9/udp/9000/quic");
    let signed = SignedAddressRecord::sign(
        &identity,
        20,
        DhtNetworkManager::address_time(),
        vec![record.clone()],
    )
    .unwrap();
    assert!(
        manager
            .apply_signed_address_set(
                signed.verify(DhtNetworkManager::address_time()).unwrap(),
                None
            )
            .await
    );
    let hint = DHTNode {
        peer_id: owner,
        addresses: vec![],
        address_types: vec![],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    let view = manager.protect_owner_view(hint.clone()).await;
    assert_eq!(
        view.addresses,
        vec![record.decode_known().unwrap().unwrap()]
    );
    assert_eq!(dht_node_publish_seq(&view), 20);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let direct: MultiAddr = "/ip4/1.1.1.1/udp/9000/quic".parse().unwrap();
    assert!(
        manager
            .dht
            .write()
            .await
            .replace_node_addresses(&owner, vec![(direct.clone(), AddressType::Direct)], 21)
            .await
    );
    assert!(
        manager
            .signed_address_record_for_peer(&owner)
            .await
            .is_none()
    );
    let view = manager.protect_owner_view(hint).await;
    assert_eq!(view.addresses, vec![direct]);
    assert_eq!(dht_node_publish_seq(&view), 21);
    assert!(matches!(
        view.address_authority,
        Some(AddressAuthority::AuthenticatedOwner(21))
    ));
}

#[tokio::test]
async fn signed_envelope_keeps_full_close_group_and_enforces_topic_and_collection_bounds() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let proof = SignedAddressRecord::sign(
        &identity,
        1,
        DhtNetworkManager::address_time(),
        vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
    )
    .unwrap();
    let entry = SignedTransportDhtNode {
        node: TransportDhtNode {
            peer_id: *identity.peer_id(),
            records: vec![],
            publish_seq: 1,
            reliability: 1.0,
        },
        proof: Some(proof),
    };
    let mut response = message(
        *identity.peer_id(),
        DhtNetworkOperation::FindNodeSigned { key: [0; 32] },
    );
    response.message_type = DhtMessageType::Response;
    response.result = Some(DhtNetworkResult::NodesFoundSigned {
        key: [0; 32],
        nodes: vec![entry.clone(); 20],
    });
    let encoded = DhtNetworkManager::encode_response_message(response.clone()).unwrap();
    assert!(encoded.len() > MAX_MESSAGE_SIZE);
    assert!(encoded.len() < MAX_SIGNED_MESSAGE_SIZE);
    let decoded: DhtNetworkMessage = postcard::from_bytes(&encoded).unwrap();
    assert!(
        matches!(decoded.result, Some(DhtNetworkResult::NodesFoundSigned { nodes, .. }) if nodes.len() == 20)
    );
    assert!(
        manager
            .handle_dht_message(&encoded, identity.peer_id(), None)
            .await
            .is_err()
    );
    assert!(
        manager
            .handle_dht_message_on_topic(&encoded, identity.peer_id(), None, DHT_SIGNED_TOPIC)
            .await
            .is_ok()
    );
    response.payload = DhtNetworkOperation::FindNode { key: [0; 32] };
    assert!(
        manager
            .handle_dht_message_on_topic(
                &postcard::to_stdvec(&response).unwrap(),
                identity.peer_id(),
                None,
                DHT_SIGNED_TOPIC
            )
            .await
            .is_err()
    );
    response.result = Some(DhtNetworkResult::NodesFoundSigned {
        key: [0; 32],
        nodes: vec![entry; MAX_SIGNED_LOOKUP_NODES + 1],
    });
    assert!(
        postcard::from_bytes::<DhtNetworkMessage>(&postcard::to_stdvec(&response).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn unchanged_local_proofs_are_reused_and_renewed_before_expiry() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let records = vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")];
    let first = manager
        .local_signed_address_record(records.clone())
        .await
        .unwrap();
    assert_eq!(
        manager
            .local_signed_address_record(records.clone())
            .await
            .unwrap(),
        first
    );
    let now = DhtNetworkManager::address_time();
    let old = SignedAddressRecord::sign(
        manager.transport.node_identity(),
        1,
        now - crate::signed_address::ADDRESS_RECORD_REFRESH_SECS,
        records.clone(),
    )
    .unwrap();
    *manager.local_signed_addresses.write().await = Some(old.verify(now).unwrap());
    let renewed = manager.local_signed_address_record(records).await.unwrap();
    let verified = renewed.verify(now).unwrap();
    assert!(verified.sequence() > 1);
    assert!(!verified.needs_refresh(now));
    assert!(
        manager
            .local_signed_address_record(Vec::new())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn capable_peers_exchange_signed_publications_and_receive_acknowledgements() {
    let publisher = test_node().await;
    let receiver = test_node().await;
    publisher.start().await.unwrap();
    receiver.start().await.unwrap();
    let address = receiver
        .listen_addrs()
        .await
        .into_iter()
        .find(MultiAddr::is_ipv4)
        .unwrap();
    let channel = publisher.connect_peer(&address).await.unwrap();
    publisher
        .wait_for_peer_identity(&channel, Duration::from_secs(2))
        .await
        .unwrap();
    let target = DHTNode {
        peer_id: *receiver.peer_id(),
        addresses: vec![address],
        address_types: vec![AddressType::Direct],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    let records = vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")];
    let confirmed = publisher
        .dht_manager()
        .publish_address_records_to_peers(records, &[target])
        .await;
    assert_eq!(confirmed, vec![*receiver.peer_id()]);
    assert!(
        receiver
            .dht_manager()
            .signed_address_record_for_peer(publisher.peer_id())
            .await
            .is_some()
    );
    publisher.stop().await.unwrap();
    receiver.stop().await.unwrap();
}
