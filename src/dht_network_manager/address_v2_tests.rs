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
    assert_eq!(
        manager.supplemental_addresses_for_peer(&owner).await,
        vec![browser_address(owner)]
    );

    // A duplicate must not advance the accepted publication sequence.
    manager
        .handle_dht_response(&response(sender_id, owner, u64::MAX), &sender_id, None)
        .await
        .unwrap();
    assert_eq!(
        manager
            .transport_address_sets
            .read()
            .await
            .get(&owner)
            .unwrap()
            .seq,
        10
    );
    receiver.stop().await.unwrap();
    sender.stop().await.unwrap();
}
