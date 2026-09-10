// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.

use super::*;
use crate::{P2PEvent, P2PNode, WebRtcCertificateHash, WebRtcDirectAddr};

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

fn response(
    sender: PeerId,
    identity: &crate::identity::NodeIdentity,
    seq: u64,
) -> DhtNetworkMessage {
    let mut response = message(sender, DhtNetworkOperation::FindNodeV2 { key: [0; 32] });
    response.message_type = DhtMessageType::Response;
    let records = vec![
        TransportAddressRecord::from_multiaddr(
            &browser_address(*identity.peer_id()),
            KnownReachability::Unverified,
        )
        .unwrap()
        .unwrap(),
    ];
    response.result = Some(DhtNetworkResult::NodesFoundV2 {
        key: [0; 32],
        nodes: vec![TransportDhtNode {
            record: SignedAddressRecord::sign(identity, seq, records).unwrap(),
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
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let sender = PeerId::from_bytes([0x33; 32]);
    let _rx = track_request(
        node.dht_manager(),
        sender,
        DhtNetworkOperation::FindNodeV2 { key: [0; 32] },
    );
    node.dht_manager()
        .handle_dht_response(&response(sender, &identity, u64::MAX), &sender, None)
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
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let wire_response = response(sender_id, &identity, 10);
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

    let mut rx = track_request(manager, sender_id, operation);
    let mut downgraded = wire_response.clone();
    downgraded.payload = DhtNetworkOperation::FindNode { key: [0; 32] };
    downgraded.result = Some(DhtNetworkResult::NodesFound {
        key: [0; 32],
        nodes: Vec::new(),
    });
    manager
        .handle_dht_response(&downgraded, &sender_id, None)
        .await
        .unwrap();
    assert!(matches!(
        rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    manager
        .handle_dht_response(&wire_response, &sender_id, None)
        .await
        .unwrap();
    assert!(matches!(
        rx.await.unwrap().result,
        DhtNetworkResult::NodesFound { .. }
    ));
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );
    manager
        .handle_dht_response(&response(sender_id, &identity, u64::MAX), &sender_id, None)
        .await
        .unwrap();
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .seq,
        10
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
            manager
                .dht
                .read()
                .await
                .transport_address_set(&owner)
                .await
                .unwrap()
                .records,
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
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .records,
        vec![corrected]
    );
}

#[tokio::test]
async fn supplemental_replacements_remove_native_addresses_and_reject_empty_sets() {
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
    assert!(native.addresses.is_empty());
    assert_eq!(dht_node_publish_seq(&native), 11);
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .records,
        vec![browser.clone()]
    );
    assert!(
        !manager
            .apply_transport_address_set(&owner, u64::MAX, Vec::new(), None)
            .await
    );
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .seq,
        11
    );
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

#[test]
fn v2_wire_records_and_publications_require_an_owner_signature() {
    let unsigned = serde_json::json!({
        "peer_id": PeerId::from_bytes([0x22; 32]), "records": [], "publish_seq": u64::MAX, "reliability": 1.0
    });
    assert!(serde_json::from_value::<TransportDhtNode>(unsigned).is_err());
    let unsigned = serde_json::json!({"PublishAddressSetV2": {"seq": 1, "records": []}});
    assert!(serde_json::from_value::<DhtNetworkOperation>(unsigned).is_err());
    // V1 discriminants remain unchanged; V2 replaces the unpublished format.
    assert_eq!(
        postcard::to_stdvec(&DhtNetworkOperation::Ping).unwrap(),
        vec![1]
    );
    assert_eq!(
        postcard::to_stdvec(&DhtNetworkOperation::FindNodeV2 { key: [0; 32] }).unwrap()[0],
        5
    );
}

#[tokio::test]
async fn v2_lookup_omits_peers_without_current_owner_proofs() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let requester = PeerId::from_bytes([0x33; 32]);
    let DhtNetworkResult::NodesFoundV2 { nodes, .. } = manager
        .handle_find_node_v2_request(&[0; 32], &requester)
        .await
        .unwrap()
    else {
        panic!("V2 response");
    };
    assert!(nodes.is_empty());
    let proof = SignedAddressRecord::sign(
        &identity,
        10,
        vec![quic_record("/ip4/8.8.8.8/udp/9000/quic")],
    )
    .unwrap();
    manager
        .apply_signed_address_set(proof.verify().unwrap(), None, false)
        .await;
    let DhtNetworkResult::NodesFoundV2 { nodes, .. } = manager
        .handle_find_node_v2_request(&[0; 32], &requester)
        .await
        .unwrap()
    else {
        panic!("V2 response");
    };
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].record, proof);
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
            manager
                .dht
                .read()
                .await
                .transport_address_set(&owner)
                .await
                .unwrap()
                .records,
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
    assert!(peer_view(manager, owner).await.addresses.is_empty());
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );

    let (_, legacy_result) = tokio::join!(
        manager.apply_transport_address_set(&owner, 13, vec![browser.clone()], None),
        manager.handle_dht_request(&legacy, &owner, None),
    );
    legacy_result.unwrap();
    let native = peer_view(manager, owner).await;
    assert!(native.addresses.is_empty());
    assert_eq!(dht_node_publish_seq(&native), 13);
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .records,
        vec![browser]
    );
}

#[tokio::test]
async fn v2_overwrites_a_conflicting_legacy_projection_at_the_same_sequence() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let owner = PeerId::from_bytes([0x22; 32]);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let legacy = message(
        owner,
        DhtNetworkOperation::PublishAddressSet {
            seq: 10,
            addresses: vec![(
                "/ip4/8.8.8.8/udp/9000/quic".parse().unwrap(),
                AddressType::Direct,
            )],
        },
    );
    manager
        .handle_dht_request(&legacy, &owner, None)
        .await
        .unwrap();
    let quic = quic_record("/ip4/9.9.9.9/udp/9000/quic");
    assert!(
        manager
            .apply_transport_address_set(&owner, 10, vec![quic.clone()], None)
            .await
    );
    assert_eq!(
        peer_view(manager, owner).await.addresses,
        vec![quic.decode_known().unwrap().unwrap()]
    );
    manager
        .handle_dht_request(&legacy, &owner, None)
        .await
        .unwrap();
    assert_eq!(
        peer_view(manager, owner).await.addresses,
        vec![quic.decode_known().unwrap().unwrap()]
    );
}

#[tokio::test]
async fn v2_lookup_bounds_the_full_envelope_and_preserves_complete_closest_records() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let mut expected = Vec::new();
    for id in 1..=20u8 {
        let identity = crate::identity::NodeIdentity::from_seed(&[id; 32]).unwrap();
        let owner = *identity.peer_id();
        let address = format!("/ip4/{id}.1.1.1/udp/9000/quic");
        seed_peer(manager, owner, &address).await;
        let mut records = vec![quic_record(&address)];
        records.extend((0..15).map(|i| TransportAddressRecord {
            transport: 900 + i,
            reachability: 901,
            address: vec![1; 2048],
        }));
        let record = SignedAddressRecord::sign(&identity, 10, records).unwrap();
        let publish = message(
            owner,
            DhtNetworkOperation::PublishAddressSetV2 {
                record: record.clone(),
            },
        );
        manager
            .handle_dht_message_on_topic(
                &postcard::to_stdvec(&publish).unwrap(),
                &owner,
                None,
                DHT_V2_TOPIC,
            )
            .await
            .unwrap();
        expected.push((owner, record));
    }
    expected.sort_by_key(|(owner, _)| *owner.as_bytes());
    let requester = PeerId::from_bytes([0x77; 32]);
    for id_len in [32, 300_000] {
        let mut request = message(requester, DhtNetworkOperation::FindNodeV2 { key: [0; 32] });
        request.message_id = "x".repeat(id_len);
        let bytes = manager
            .handle_dht_message_on_topic(
                &postcard::to_stdvec(&request).unwrap(),
                &requester,
                None,
                DHT_V2_TOPIC,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(bytes.len() <= MAX_V2_MESSAGE_SIZE);
        let response: DhtNetworkMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(response.message_id, request.message_id);
        let Some(DhtNetworkResult::NodesFoundV2 { nodes, .. }) = response.result else {
            panic!("V2 response");
        };
        if id_len == 32 {
            assert_eq!(nodes.len(), 20);
        } else {
            assert!(!nodes.is_empty() && nodes.len() < 20);
        }
        for (actual, (_, record)) in nodes.iter().zip(&expected) {
            assert_eq!(actual.record, *record);
        }
    }
}

#[tokio::test]
async fn v2_response_rejects_an_envelope_that_cannot_fit_even_without_nodes() {
    let node = test_node().await;
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let mut response = response(owner, &identity, 10);
    response.message_id = "x".repeat(MAX_V2_MESSAGE_SIZE);
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
    let sent = publisher
        .dht_manager()
        .publish_address_records_to_peers(Vec::new(), &[peer])
        .await;
    assert!(sent.is_empty());
    assert!(
        receiver
            .dht_manager()
            .dht
            .read()
            .await
            .transport_address_set(publisher.peer_id())
            .await
            .is_none()
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
    let proof =
        SignedAddressRecord::sign(&identity, 20, vec![native.clone(), browser.clone(), opaque])
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
    let operation = DhtNetworkOperation::FindNodeV2 { key: [0; 32] };
    let mut wire = message(sender, operation.clone());
    wire.message_type = DhtMessageType::Response;
    wire.result = Some(DhtNetworkResult::NodesFoundV2 {
        key: [0; 32],
        nodes: vec![TransportDhtNode {
            record: proof.clone(),
            reliability: 1.0,
        }],
    });
    // Neither an unsolicited proof nor a mismatched live lookup may mutate caches.
    manager
        .handle_dht_response(&wire, &sender, None)
        .await
        .unwrap();
    assert!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .is_none()
    );
    let rx = track_request(manager, sender, operation);
    let mut wrong_key = wire.clone();
    if let Some(DhtNetworkResult::NodesFoundV2 { key, .. }) = &mut wrong_key.result {
        *key = [1; 32];
    }
    manager
        .handle_dht_response(&wrong_key, &sender, None)
        .await
        .unwrap();
    assert!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .is_none()
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

    // V1 fallback carries only hints when forwarded by somebody else.
    let operation = DhtNetworkOperation::FindNode { key: [0; 32] };
    let rx = track_request(manager, sender, operation.clone());
    let mut forged = message(sender, operation);
    forged.message_type = DhtMessageType::Response;
    forged.result = Some(DhtNetworkResult::NodesFound {
        key: [0; 32],
        nodes: vec![DHTNode {
            peer_id: owner,
            addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
            address_types: vec![AddressType::Direct],
            distance: encode_publish_seq_distance(u64::MAX),
            reliability: 1.0,
            address_authority: None,
        }],
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
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .seq,
        20
    );
    let stale = SignedAddressRecord::sign(
        &identity,
        19,
        vec![quic_record("/ip4/1.1.1.1/udp/9000/quic")],
    )
    .unwrap();
    assert!(
        !manager
            .apply_signed_address_set(stale.verify().unwrap(), None, false)
            .await
    );
    let corrected = SignedAddressRecord::sign(&identity, 21, vec![native]).unwrap();
    assert!(
        manager
            .apply_signed_address_set(corrected.verify().unwrap(), None, false)
            .await
    );
    receiver.stop().await.unwrap();
    forwarder.stop().await.unwrap();
}

#[tokio::test]
async fn signed_discovery_precedes_admission_and_blocks_newer_v1_publication() {
    let receiver = test_node().await;
    let manager = receiver.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let record = quic_record("/ip4/9.9.9.9/udp/9000/quic");
    let signed = SignedAddressRecord::sign(&identity, 20, vec![record.clone()]).unwrap();
    assert!(
        !manager
            .apply_signed_address_set(signed.verify().unwrap(), None, false)
            .await
    );
    let request = message(
        owner,
        DhtNetworkOperation::PublishAddressSetV2 {
            record: signed.clone(),
        },
    );
    assert!(matches!(
        manager
            .handle_dht_request(&request, &owner, None)
            .await
            .unwrap(),
        DhtNetworkResult::PeerRejected
    ));
    let view = manager
        .normalize_v2_nodes(
            vec![TransportDhtNode {
                record: signed.clone(),
                reliability: 1.0,
            }],
            None,
        )
        .await
        .remove(0);
    assert_eq!(
        view.addresses,
        vec![record.decode_known().unwrap().unwrap()]
    );
    assert_eq!(dht_node_publish_seq(&view), 20);
    assert!(
        manager
            .signed_address_record_for_peer(&owner)
            .await
            .is_none()
    );
    assert!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .is_none()
    );
    assert!(!manager.dht.read().await.has_node(&owner).await);
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    manager.merge_trusted_gossiped_typed_addresses(&view).await;
    assert_eq!(
        manager.signed_address_record_for_peer(&owner).await,
        Some(signed)
    );
    let hint = view;
    let direct: MultiAddr = "/ip4/1.1.1.1/udp/9000/quic".parse().unwrap();
    assert!(
        !manager
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
            .is_some()
    );
    let view = manager.protect_owner_view(hint).await;
    assert_eq!(
        view.addresses,
        vec![record.decode_known().unwrap().unwrap()]
    );
    assert_eq!(dht_node_publish_seq(&view), 20);
    assert!(matches!(
        view.address_authority,
        Some(AddressAuthority::Signed(_))
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
        vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
    )
    .unwrap();
    let entry = TransportDhtNode {
        record: proof,
        reliability: 1.0,
    };
    let mut response = message(
        *identity.peer_id(),
        DhtNetworkOperation::FindNodeV2 { key: [0; 32] },
    );
    response.message_type = DhtMessageType::Response;
    response.result = Some(DhtNetworkResult::NodesFoundV2 {
        key: [0; 32],
        nodes: vec![entry.clone(); 20],
    });
    let encoded = DhtNetworkManager::encode_response_message(response.clone()).unwrap();
    assert!(encoded.len() > MAX_MESSAGE_SIZE);
    assert!(encoded.len() < MAX_V2_MESSAGE_SIZE);
    let decoded: DhtNetworkMessage = postcard::from_bytes(&encoded).unwrap();
    assert!(
        matches!(decoded.result, Some(DhtNetworkResult::NodesFoundV2 { nodes, .. }) if nodes.len() == 20)
    );
    assert!(
        manager
            .handle_dht_message(&encoded, identity.peer_id(), None)
            .await
            .is_err()
    );
    assert!(
        manager
            .handle_dht_message_on_topic(&encoded, identity.peer_id(), None, DHT_V2_TOPIC)
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
                DHT_V2_TOPIC
            )
            .await
            .is_err()
    );
    response.result = Some(DhtNetworkResult::NodesFoundV2 {
        key: [0; 32],
        nodes: vec![entry; MAX_V2_LOOKUP_NODES + 1],
    });
    assert!(
        postcard::from_bytes::<DhtNetworkMessage>(&postcard::to_stdvec(&response).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn unchanged_local_proofs_are_reused_until_addresses_change() {
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
    let old =
        SignedAddressRecord::sign(manager.transport.node_identity(), 1, records.clone()).unwrap();
    *manager.local_signed_addresses.write().await = Some(old.verify().unwrap());
    assert_eq!(
        manager.local_signed_address_record(records).await.unwrap(),
        old
    );
    let changed = manager
        .local_signed_address_record(vec![quic_record("/ip4/1.1.1.1/udp/9001/quic")])
        .await
        .unwrap();
    assert!(changed.verify().unwrap().sequence() > 1);
    assert_ne!(changed, old);
    assert!(
        manager
            .local_signed_address_record(Vec::new())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn peers_without_capability_tokens_exchange_both_publication_versions() {
    let publisher = test_node().await;
    let receiver = test_node().await;
    for node in [&publisher, &receiver] {
        node.dht_manager()
            .transport
            .start_network_listeners()
            .await
            .unwrap();
        node.dht_manager().start().await.unwrap();
    }
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
    let mut received = receiver.dht_manager().transport.subscribe_events();
    assert_eq!(
        publisher
            .dht_manager()
            .transport
            .peer_user_agent(receiver.peer_id())
            .await
            .unwrap(),
        crate::network::user_agent_for_mode(NodeMode::Node)
    );
    let records = vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")];
    let sent = publisher
        .dht_manager()
        .publish_address_records_to_peers(records, &[target])
        .await;
    assert_eq!(sent, vec![*receiver.peer_id()]);
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut versions = HashSet::new();
        while versions.len() < 2 {
            let P2PEvent::Message { data, topic, .. } = received.recv().await.unwrap() else {
                continue;
            };
            if topic != DHT_V1_TOPIC && topic != DHT_V2_TOPIC {
                continue;
            }
            let wire: DhtNetworkMessage = postcard::from_bytes(&data).unwrap();
            match wire.payload {
                DhtNetworkOperation::PublishAddressSet { .. } => {
                    versions.insert(false);
                }
                DhtNetworkOperation::PublishAddressSetV2 { .. } => {
                    versions.insert(true);
                }
                _ => {}
            }
        }
        // A completed send does not imply that the receiver has applied it yet.
        while receiver
            .dht_manager()
            .signed_address_record_for_peer(publisher.peer_id())
            .await
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    publisher.stop().await.unwrap();
    receiver.stop().await.unwrap();
}

#[tokio::test]
async fn address_publications_complete_without_replies_or_response_tracking() {
    let publisher = test_node().await;
    let receiver = test_node().await;
    let manager = publisher.dht_manager();
    manager.transport.start_network_listeners().await.unwrap();
    manager.start().await.unwrap();
    // Only the transport runs on the receiver: neither version gets a reply.
    let mut received = receiver.dht_manager().transport.subscribe_events();
    receiver
        .dht_manager()
        .transport
        .start_network_listeners()
        .await
        .unwrap();
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
        address_types: vec![AddressType::Lan],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    let trust = manager.trust_engine.as_ref().unwrap();
    let before = trust.score(receiver.peer_id());
    // Duplicate recipients still receive only one message per version.
    let sent = tokio::time::timeout(
        Duration::from_secs(2),
        manager.publish_address_records_to_peers(
            vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
            &[target.clone(), target],
        ),
    )
    .await
    .unwrap();
    assert_eq!(sent, vec![*receiver.peer_id()]);
    assert_eq!(
        manager
            .transport
            .traffic
            .publish_addr_tx_count
            .load(Ordering::Relaxed),
        2
    );
    assert!(manager.active_operations.lock().unwrap().is_empty());
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut versions = HashSet::new();
        while versions.len() < 2 {
            let P2PEvent::Message { data, topic, .. } = received.recv().await.unwrap() else {
                continue;
            };
            if topic != DHT_V1_TOPIC && topic != DHT_V2_TOPIC {
                continue;
            }
            let request: DhtNetworkMessage = postcard::from_bytes(&data).unwrap();
            match request.payload {
                DhtNetworkOperation::PublishAddressSet { .. } => {
                    assert_eq!(topic, DHT_V1_TOPIC);
                    assert!(versions.insert(false));
                }
                DhtNetworkOperation::PublishAddressSetV2 { .. } => {
                    assert_eq!(topic, DHT_V2_TOPIC);
                    assert!(versions.insert(true));
                }
                _ => panic!("unexpected DHT request"),
            }
            // Older receivers may still send an ACK. It must remain unsolicited
            // and cannot create tracking state or affect trust after this send.
            let ack = receiver
                .dht_manager()
                .create_response_message(&request, DhtNetworkResult::PublishAddressAck)
                .unwrap();
            manager
                .handle_dht_response(&ack, receiver.peer_id(), None)
                .await
                .unwrap();
        }
    })
    .await
    .unwrap();
    assert!(manager.active_operations.lock().unwrap().is_empty());
    assert_eq!(trust.score(receiver.peer_id()), before);
    publisher.stop().await.unwrap();
    receiver.stop().await.unwrap();
}

#[tokio::test]
async fn address_publication_connection_failure_is_scored_once_without_retry() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let peer = PeerId::from_bytes([0x33; 32]);
    // No dialable addresses makes the connection attempt fail immediately.
    let target = DHTNode {
        peer_id: peer,
        addresses: vec![],
        address_types: vec![],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    let sent = tokio::time::timeout(
        Duration::from_secs(2),
        manager.publish_address_records_to_peers(
            vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
            &[target.clone(), target],
        ),
    )
    .await
    .unwrap();
    assert!(sent.is_empty());
    assert!(manager.active_operations.lock().unwrap().is_empty());
    assert_eq!(
        manager
            .transport
            .traffic
            .publish_addr_tx_count
            .load(Ordering::Relaxed),
        0
    );
    let trust = manager.trust_engine.as_ref().unwrap();
    let reference = PeerId::from_bytes([0x44; 32]);
    trust.update_node_stats(&reference, NodeStatisticsUpdate::FailedResponse);
    assert!((trust.score(&peer) - trust.score(&reference)).abs() < 1e-5);
}

#[tokio::test]
async fn address_publication_send_failures_count_once_and_local_errors_do_not_count() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let trust = manager.trust_engine.as_ref().unwrap();
    let reference = PeerId::from_bytes([0x44; 32]);
    trust.update_node_stats(&reference, NodeStatisticsUpdate::FailedResponse);
    for (index, (v1_fails, v2_fails)) in [(true, false), (false, true), (true, true)]
        .into_iter()
        .enumerate()
    {
        let peer = PeerId::from_bytes([index as u8; 32]);
        let result = |fails| {
            if fails {
                Err(P2PError::Transport(
                    crate::error::TransportError::SendFailed {
                        kind: crate::error::SendFailureKind::WriteProgressTimeout,
                        reason: "test send failure".into(),
                    },
                ))
            } else {
                Ok(())
            }
        };
        manager
            .record_address_publication_send_outcomes(&peer, &result(v1_fails), &result(v2_fails))
            .await;
        assert!((trust.score(&peer) - trust.score(&reference)).abs() < 1e-5);
    }
    let peer = PeerId::from_bytes([0x55; 32]);
    manager
        .record_address_publication_send_outcomes(
            &peer,
            &Err(P2PError::Network(NetworkError::ProtocolError(
                "local signing failure".into(),
            ))),
            &Err(P2PError::Transport(
                crate::error::TransportError::StreamError("local serialization failure".into()),
            )),
        )
        .await;
    assert_eq!(trust.score(&peer), DEFAULT_NEUTRAL_TRUST);
}

#[tokio::test]
async fn v2_publication_checks_signature_and_authenticated_owner_before_mutation() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let proof = SignedAddressRecord::sign(
        &identity,
        10,
        vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
    )
    .unwrap();
    let request = message(
        owner,
        DhtNetworkOperation::PublishAddressSetV2 {
            record: proof.clone(),
        },
    );
    assert!(
        manager
            .handle_dht_request(&request, &PeerId::from_bytes([7; 32]), None)
            .await
            .is_err()
    );
    let mut forged = serde_json::to_value(&proof).unwrap();
    forged["sequence"] = serde_json::json!(u64::MAX);
    let invalid = message(
        owner,
        DhtNetworkOperation::PublishAddressSetV2 {
            record: serde_json::from_value(forged).unwrap(),
        },
    );
    assert!(
        manager
            .handle_dht_request(&invalid, &owner, None)
            .await
            .is_err()
    );
    assert!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .is_none()
    );
    // Invalid V2 does not suppress V1; the subsequent valid V2 still wins
    // even over this much larger V1 sequence.
    assert!(
        manager
            .dht
            .read()
            .await
            .replace_node_addresses(
                &owner,
                vec![(
                    "/ip4/1.1.1.1/udp/9000/quic".parse().unwrap(),
                    AddressType::Direct
                )],
                u64::MAX,
            )
            .await
    );
    manager
        .handle_dht_request(&request, &owner, None)
        .await
        .unwrap();
    assert_eq!(
        manager
            .dht
            .read()
            .await
            .transport_address_set(&owner)
            .await
            .unwrap()
            .seq,
        10
    );
    assert_eq!(
        peer_view(manager, owner).await.addresses,
        vec!["/ip4/9.9.9.9/udp/9000/quic".parse::<MultiAddr>().unwrap()]
    );
}

#[tokio::test]
async fn routing_publication_forwards_signed_transports_but_native_dials_only_quic() {
    let node = test_node().await;
    let manager = node.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let quic: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
    let browser = browser_address(owner);
    let records = vec![
        quic_record("/ip4/9.9.9.9/udp/9000/quic"),
        TransportAddressRecord::from_multiaddr(&browser, KnownReachability::Unverified)
            .unwrap()
            .unwrap(),
    ];
    let signed = SignedAddressRecord::sign(&identity, 10, records.clone()).unwrap();
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    let publication = message(
        owner,
        DhtNetworkOperation::PublishAddressSetV2 {
            record: signed.clone(),
        },
    );
    manager
        .handle_dht_request(&publication, &owner, None)
        .await
        .unwrap();
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser.clone()]
    );
    assert_eq!(
        manager.peer_addresses_for_dial_typed(&owner).await,
        vec![(quic.clone(), AddressType::Direct)]
    );
    let mixed = vec![
        (browser.clone(), AddressType::Direct),
        (quic, AddressType::Direct),
    ];
    let plan = manager.contextual_dial_plan(&mixed).await;
    assert_eq!(plan.len(), 1);
    assert!(plan[0].0.is_quic());
    let browser_only = DHTNode {
        peer_id: owner,
        addresses: vec![browser.clone()],
        address_types: vec![AddressType::Direct],
        distance: None,
        reliability: 1.0,
        address_authority: None,
    };
    let mut query = NativeFindNodeQuery::new(manager, None);
    assert!(!query.is_candidate_eligible(&browser_only).await.unwrap());
    assert!(manager.transport.connect_peer(&browser).await.is_err());

    // A client receives the unchanged signed QUIC + WebRTC record and can
    // verify/decode it using the same portable types exposed on WASM.
    let result = manager
        .handle_find_node_v2_request(owner.as_bytes(), node.peer_id())
        .await
        .unwrap();
    let encoded = postcard::to_stdvec(&result).unwrap();
    let DhtNetworkResult::NodesFoundV2 { nodes, .. } = postcard::from_bytes(&encoded).unwrap()
    else {
        panic!("expected a V2 lookup response");
    };
    let forwarded = nodes
        .into_iter()
        .find(|entry| entry.record == signed)
        .unwrap();
    let verified = forwarded.record.verify().unwrap();
    assert_eq!(verified.records(), records);
    assert_eq!(verified.records()[1].decode_known().unwrap(), Some(browser));

    // All address metadata follows routing membership, with no separate eviction.
    manager.dht.write().await.remove_node_by_id(&owner).await;
    assert!(
        manager
            .supplemental_addresses_for_peer(&owner)
            .await
            .is_empty()
    );
    assert!(
        manager
            .signed_address_record_for_peer(&owner)
            .await
            .is_none()
    );
    seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
    assert!(
        manager
            .signed_address_record_for_peer(&owner)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn publication_order_always_prefers_newest_v2_over_v1() {
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let receiver = test_node().await;
        let manager = receiver.dht_manager();
        let identity = crate::identity::NodeIdentity::generate().unwrap();
        let owner = *identity.peer_id();
        seed_peer(manager, owner, "/ip4/8.8.8.8/udp/9000/quic").await;
        let old_quic = quic_record("/ip4/9.9.9.9/udp/9000/quic");
        let new_quic: MultiAddr = "/ip4/1.1.1.1/udp/9001/quic".parse().unwrap();
        let browser = TransportAddressRecord::from_multiaddr(
            &browser_address(owner),
            KnownReachability::Unverified,
        )
        .unwrap()
        .unwrap();
        let old = SignedAddressRecord::sign(&identity, 10, vec![old_quic.clone()]).unwrap();
        let latest = SignedAddressRecord::sign(&identity, 11, vec![old_quic, browser]).unwrap();
        let publications = [
            message(
                owner,
                DhtNetworkOperation::PublishAddressSetV2 { record: old },
            ),
            message(
                owner,
                DhtNetworkOperation::PublishAddressSet {
                    seq: 12,
                    addresses: vec![(new_quic.clone(), AddressType::Direct)],
                },
            ),
            message(
                owner,
                DhtNetworkOperation::PublishAddressSetV2 {
                    record: latest.clone(),
                },
            ),
        ];
        for index in order {
            manager
                .handle_dht_request(&publications[index], &owner, None)
                .await
                .unwrap();
        }
        let native = peer_view(manager, owner).await;
        assert_eq!(
            native.addresses,
            vec!["/ip4/9.9.9.9/udp/9000/quic".parse::<MultiAddr>().unwrap()],
            "order {order:?}"
        );
        assert_eq!(dht_node_publish_seq(&native), 11);
        assert_eq!(
            manager.supplemental_addresses_for_peer(&owner).await,
            vec![browser_address(owner)]
        );
        assert_eq!(
            manager.signed_address_record_for_peer(&owner).await,
            Some(latest.clone())
        );
        let forwarded = manager
            .handle_find_node_v2_request(owner.as_bytes(), manager.peer_id())
            .await
            .unwrap();
        let DhtNetworkResult::NodesFoundV2 { nodes, .. } = forwarded else {
            panic!("V2 response")
        };
        assert!(nodes.iter().any(|node| node.record == latest));
        let view = manager
            .normalize_v2_nodes(
                vec![TransportDhtNode {
                    record: latest.clone(),
                    reliability: 1.0,
                }],
                None,
            )
            .await
            .remove(0);
        assert_eq!(view.addresses, native.addresses);
        let authority = view.address_authority.unwrap();
        assert_eq!(authority.quic_sequence(), 11);
        assert_eq!(authority.publication().unwrap().signed(), &latest);

        // Only a newer V2 replacement can withdraw the supplemental address.
        let replacement =
            SignedAddressRecord::sign(&identity, 13, vec![quic_record(&new_quic.to_string())])
                .unwrap();
        assert!(
            manager
                .apply_signed_address_set(replacement.verify().unwrap(), None, true)
                .await
        );
        assert!(
            !manager
                .apply_signed_address_set(latest.verify().unwrap(), None, true)
                .await
        );
        assert!(
            manager
                .supplemental_addresses_for_peer(&owner)
                .await
                .is_empty()
        );
        assert_eq!(
            manager.signed_address_record_for_peer(&owner).await,
            Some(replacement)
        );
    }
}

#[tokio::test]
async fn authenticated_v1_lookup_reply_cannot_change_a_v2_owner_view() {
    let receiver = test_node().await;
    let publisher = test_node().await;
    receiver.start().await.unwrap();
    publisher.start().await.unwrap();
    let address = publisher
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
    let owner = *publisher.peer_id();
    let identity = publisher.dht_manager().transport.node_identity();
    let record = SignedAddressRecord::sign(
        identity,
        10,
        vec![
            quic_record("/ip4/9.9.9.9/udp/9000/quic"),
            TransportAddressRecord::from_multiaddr(
                &browser_address(owner),
                KnownReachability::Unverified,
            )
            .unwrap()
            .unwrap(),
        ],
    )
    .unwrap();
    assert!(
        manager
            .apply_signed_address_set(record.verify().unwrap(), None, true)
            .await
    );
    let operation = DhtNetworkOperation::FindNode { key: [0; 32] };
    let rx = track_request(manager, owner, operation.clone());
    let mut reply = message(owner, operation);
    reply.message_type = DhtMessageType::Response;
    let new_quic: MultiAddr = "/ip4/1.1.1.1/udp/9001/quic".parse().unwrap();
    reply.result = Some(DhtNetworkResult::NodesFound {
        key: [0; 32],
        nodes: vec![DHTNode {
            peer_id: owner,
            addresses: vec![new_quic.clone()],
            address_types: vec![AddressType::Direct],
            distance: encode_publish_seq_distance(12),
            reliability: 1.0,
            address_authority: None,
        }],
    });
    manager
        .handle_dht_response(&reply, &owner, None)
        .await
        .unwrap();
    let DhtNetworkResult::NodesFound { nodes, .. } = rx.await.unwrap().result else {
        panic!("V1 response")
    };
    let expected: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
    assert_eq!(nodes[0].addresses, vec![expected.clone()]);
    assert_eq!(peer_view(manager, owner).await.addresses, vec![expected]);
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );
    assert_eq!(
        manager.signed_address_record_for_peer(&owner).await,
        Some(record)
    );
    // Invalid or non-QUIC V1 self-reports must not advance either view.
    for address in [
        "/ip4/0.0.0.0/udp/9000/quic".parse().unwrap(),
        nodes[0].addresses[0]
            .clone()
            .with_peer_id(*receiver.peer_id()),
        browser_address(owner),
    ] {
        let mut invalid = nodes[0].clone();
        invalid.addresses = vec![address];
        assert!(
            manager
                .apply_native_self_report(&invalid, 14, None)
                .await
                .is_none()
        );
    }
    assert_eq!(dht_node_publish_seq(&peer_view(manager, owner).await), 10);
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );
    receiver.stop().await.unwrap();
    publisher.stop().await.unwrap();
}

#[tokio::test]
async fn supplemental_only_v2_removes_native_contacts_and_rejects_delayed_quic() {
    let receiver = test_node().await;
    let manager = receiver.dht_manager();
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let initial: MultiAddr = "/ip4/8.8.8.8/udp/9000/quic".parse().unwrap();
    seed_peer(manager, owner, &initial.to_string()).await;
    let publication = SignedAddressRecord::sign(
        &identity,
        13,
        vec![
            TransportAddressRecord::from_multiaddr(
                &browser_address(owner),
                KnownReachability::Unverified,
            )
            .unwrap()
            .unwrap(),
        ],
    )
    .unwrap();
    let view = manager
        .normalize_v2_nodes(
            vec![TransportDhtNode {
                record: publication.clone(),
                reliability: 1.0,
            }],
            None,
        )
        .await
        .remove(0);
    assert!(view.addresses.is_empty());
    let mut combined = view.clone();
    combined.merge_from(view);
    assert!(combined.addresses.is_empty());
    let quic = quic_record("/ip4/9.9.9.9/udp/9001/quic");
    let delayed = SignedAddressRecord::sign(&identity, 12, vec![quic.clone()]).unwrap();
    assert!(
        !manager
            .apply_signed_address_set(delayed.verify().unwrap(), None, true)
            .await
    );
    assert!(peer_view(manager, owner).await.addresses.is_empty());
    assert_eq!(
        manager.signed_address_record_for_peer(&owner).await,
        Some(publication)
    );
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );
}

#[test]
fn paired_lookup_keeps_legacy_subjects_and_prefers_v2_in_either_arrival_order() {
    let identity = crate::identity::NodeIdentity::generate().unwrap();
    let owner = *identity.peer_id();
    let proof = SignedAddressRecord::sign(
        &identity,
        1,
        vec![quic_record("/ip4/9.9.9.9/udp/9000/quic")],
    )
    .unwrap()
    .verify()
    .unwrap();
    let mut legacy = proof.peer_record(1.0);
    legacy.addresses = vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()];
    legacy.address_authority = Some(AddressAuthority::AuthenticatedOwner(u64::MAX));
    let mut legacy_only = legacy.clone();
    legacy_only.peer_id = PeerId::from_bytes([0x33; 32]);
    legacy_only.address_authority = None;
    let reply = |nodes| {
        Ok(DhtResponseEnvelope {
            result: DhtNetworkResult::NodesFound {
                key: [0; 32],
                nodes,
            },
            transport_source: None,
        })
    };
    for v2_first in [false, true] {
        let mut replies = vec![
            reply(vec![legacy.clone(), legacy_only.clone()]),
            reply(vec![proof.peer_record(1.0)]),
        ];
        if v2_first {
            replies.reverse();
        }
        let result = DhtNetworkManager::merge_find_node_responses([0; 32], replies).unwrap();
        let DhtNetworkResult::NodesFound { nodes, .. } = result.result else {
            panic!("lookup response")
        };
        assert_eq!(nodes.len(), 2);
        assert_eq!(
            nodes
                .iter()
                .find(|node| node.peer_id == owner)
                .unwrap()
                .addresses,
            proof.peer_record(1.0).addresses
        );
        assert!(nodes.iter().any(|node| node.peer_id == legacy_only.peer_id));
    }
    // An empty V2 reply does not erase legacy-only subjects.
    let result = DhtNetworkManager::merge_find_node_responses(
        [0; 32],
        vec![reply(vec![legacy_only]), reply(vec![])],
    )
    .unwrap();
    assert!(
        matches!(result.result, DhtNetworkResult::NodesFound { nodes, .. } if nodes.len() == 1)
    );
}

#[tokio::test]
async fn both_lookup_versions_are_sent_and_one_unsupported_version_does_not_penalize_peer() {
    for supported_v2 in [false, true] {
        let requester = test_node().await;
        let responder = test_node().await;
        requester
            .dht_manager()
            .transport
            .start_network_listeners()
            .await
            .unwrap();
        requester.dht_manager().start().await.unwrap();
        // Run a transport-only responder that deliberately understands one version.
        let remote = responder.dht_manager();
        let mut events = remote.transport.subscribe_events();
        remote.transport.start_network_listeners().await.unwrap();
        let address = responder
            .listen_addrs()
            .await
            .into_iter()
            .find(MultiAddr::is_ipv4)
            .unwrap();
        let channel = requester.connect_peer(&address).await.unwrap();
        requester
            .wait_for_peer_identity(&channel, Duration::from_secs(2))
            .await
            .unwrap();
        let manager = requester.dht_manager();
        let trust = manager.trust_engine.as_ref().unwrap();
        let score = trust.score(responder.peer_id());
        let serve = async {
            let mut received = HashSet::new();
            while received.len() < 2 {
                let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let P2PEvent::Message {
                    topic,
                    data,
                    source: Some(source),
                    ..
                } = event
                else {
                    continue;
                };
                if topic != DHT_V1_TOPIC && topic != DHT_V2_TOPIC {
                    continue;
                }
                let request: DhtNetworkMessage = postcard::from_bytes(&data).unwrap();
                let (v2, key) = match request.payload {
                    DhtNetworkOperation::FindNode { key } => (false, key),
                    DhtNetworkOperation::FindNodeV2 { key } => (true, key),
                    _ => continue,
                };
                received.insert(v2);
                if v2 != supported_v2 {
                    continue;
                }
                let result = if v2 {
                    DhtNetworkResult::NodesFoundV2 { key, nodes: vec![] }
                } else {
                    DhtNetworkResult::NodesFound { key, nodes: vec![] }
                };
                let response = remote.create_response_message(&request, result).unwrap();
                remote
                    .transport
                    .send_message(&source, &topic, postcard::to_stdvec(&response).unwrap())
                    .await
                    .unwrap();
            }
            received
        };
        let target = DHTNode {
            peer_id: *responder.peer_id(),
            addresses: vec![address],
            address_types: vec![AddressType::Lan],
            distance: None,
            reliability: 1.0,
            address_authority: None,
        };
        let targets = [target];
        let (responses, received) =
            tokio::join!(manager.query_find_node_batch(&targets, [0; 32]), serve);
        let response = responses
            .into_iter()
            .find(|(peer, _)| peer == responder.peer_id())
            .unwrap()
            .1;
        assert_eq!(received, HashSet::from([false, true]));
        assert!(matches!(
            response.unwrap().result,
            DhtNetworkResult::NodesFound { .. }
        ));
        assert_eq!(trust.score(responder.peer_id()), score);
        assert!(manager.active_operations.lock().unwrap().values().all(|operation| {
            !matches!(operation.operation, DhtNetworkOperation::FindNode { key } | DhtNetworkOperation::FindNodeV2 { key } if key == [0; 32])
        }));
        requester.stop().await.unwrap();
        responder.stop().await.unwrap();
    }
}
