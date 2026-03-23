use crate::PeerId;
use crate::dht::core_engine::{DhtCoreEngine, NodeInfo};
use crate::security::IPDiversityConfig;
use std::time::SystemTime;

/// Helper: create a NodeInfo with a specific PeerId (from byte array) and address.
fn make_node_with_id(id_bytes: [u8; 32], addr: &str) -> NodeInfo {
    NodeInfo {
        id: PeerId::from_bytes(id_bytes),
        addresses: vec![addr.parse().unwrap()],
        last_seen: SystemTime::now(),
    }
}

/// Build a deterministic peer ID that lands in bucket 0 when self=[0;32].
///
/// All returned IDs have `id[0] = 0x80` (so XOR with [0;32] has its first
/// set bit at position 0 -> bucket 0). `seq` is written to `id[31]` for
/// uniqueness within the bucket.
fn bucket0_id(seq: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0x80;
    id[31] = seq;
    id
}

// -----------------------------------------------------------------------
// IPv6 diversity -- per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv6() -> anyhow::Result<()> {
    // With self=[0;32], all nodes land in bucket 0.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Subnet limit = K/4 = 20/4 = 5. Add 5 nodes in same /64 — all should succeed.
    for i in 1..=5u8 {
        let node = make_node_with_id(bucket0_id(i), &format!("/ip6/2001:db8::{i}/udp/9000/quic"));
        engine.add_node_no_trust(node).await?;
    }

    // Sixth node in same /64 should fail (exceeds /64 limit of 5).
    let node6 = make_node_with_id(bucket0_id(6), "/ip6/2001:db8::6/udp/9000/quic");
    let result = engine.add_node_no_trust(node6).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 diversity -- per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv4() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    let node1 = make_node_with_id(bucket0_id(1), "/ip4/192.168.1.1/udp/9000/quic");
    engine.add_node_no_trust(node1).await?;

    // Second same-IP node should succeed (exact-IP limit = 2).
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/192.168.1.1/udp/9001/quic");
    engine.add_node_no_trust(node2).await?;

    // Third same-IP node should fail (exceeds exact-IP limit of 2).
    let node3 = make_node_with_id(bucket0_id(3), "/ip4/192.168.1.1/udp/9002/quic");
    let result = engine.add_node_no_trust(node3).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 /24 subnet limit -- per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_subnet_24_limit() -> anyhow::Result<()> {
    // Subnet limit = K/4 = 20/4 = 5.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Five nodes on different IPs but same /24, all in bucket 0.
    for i in 1..=5u8 {
        engine
            .add_node_no_trust(make_node_with_id(
                bucket0_id(i),
                &format!("/ip4/192.168.1.{i}/udp/9000/quic"),
            ))
            .await?;
    }

    // Sixth should fail (/24 limit = 5).
    let node6 = make_node_with_id(bucket0_id(6), "/ip4/192.168.1.6/udp/9000/quic");
    let result = engine.add_node_no_trust(node6).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// Mixed IPv4 + IPv6 enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_mixed_ipv4_ipv6_enforcement() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // IPv4 node
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;

    // IPv6 node -- different address family, should succeed
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(2),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;

    // Second IPv4 on same IP should succeed (exact-IP limit = 2)
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(3),
            "/ip4/192.168.1.1/udp/9001/quic",
        ))
        .await?;

    // Third IPv4 on same IP should fail (exceeds exact-IP limit of 2)
    let result_v4 = engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(4),
            "/ip4/192.168.1.1/udp/9002/quic",
        ))
        .await;
    assert!(result_v4.is_err());

    // IPv6 nodes in same /64 should succeed up to the /64 limit (K/4 = 5).
    // We already added one IPv6 node above (bucket0_id(2)), so add 4 more.
    for i in 5..=8u8 {
        engine
            .add_node_no_trust(make_node_with_id(
                bucket0_id(i),
                &format!("/ip6/2001:db8::{i}/udp/9000/quic"),
            ))
            .await?;
    }

    // Sixth IPv6 in same /64 should fail (exceeds /64 limit of 5)
    let result_v6 = engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(9),
            "/ip6/2001:db8::9/udp/9000/quic",
        ))
        .await;
    assert!(result_v6.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 floor override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_ip_override_raises_limit() -> anyhow::Result<()> {
    // Default exact-IP limit is 2.
    // Setting max_per_ip = 3 should allow 3 nodes on the same IP.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_ip: Some(3),
        max_per_subnet: Some(usize::MAX),
        ..IPDiversityConfig::default()
    });

    for i in 1..=3u8 {
        let node = make_node_with_id(
            bucket0_id(i),
            &format!("/ip4/192.168.1.1/udp/{}/quic", 9000 + u16::from(i)),
        );
        engine.add_node_no_trust(node).await?;
    }

    // Fourth node should fail (max_per_ip = 3)
    let node4 = make_node_with_id(bucket0_id(4), "/ip4/192.168.1.1/udp/9003/quic");
    let result = engine.add_node_no_trust(node4).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 ceiling override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_subnet_override_lowers_limit() -> anyhow::Result<()> {
    // Setting max_per_subnet = 1 caps /24 limit at 1.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_subnet: Some(1),
        ..IPDiversityConfig::default()
    });

    let node1 = make_node_with_id(bucket0_id(1), "/ip4/10.0.1.1/udp/9000/quic");
    engine.add_node_no_trust(node1).await?;

    // Different IP but same /24 -- should fail because /24 limit = 1
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/10.0.1.2/udp/9000/quic");
    let result = engine.add_node_no_trust(node2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 floor override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_subnet_override_raises_limit() -> anyhow::Result<()> {
    // Default subnet limit is K/4 = 20/4 = 5. Setting max_per_subnet = 8
    // should allow 8 nodes in the same /64 subnet.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_subnet: Some(8),
        ..IPDiversityConfig::default()
    });

    for i in 1..=8u8 {
        let node = make_node_with_id(bucket0_id(i), &format!("/ip6/2001:db8::{i}/udp/9000/quic"));
        engine.add_node_no_trust(node).await?;
    }

    // Ninth node should fail
    let node9 = make_node_with_id(bucket0_id(9), "/ip6/2001:db8::9/udp/9000/quic");
    let result = engine.add_node_no_trust(node9).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 ceiling override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_subnet_override_lowers_limit() -> anyhow::Result<()> {
    // Default subnet limit is K/4 = 20/4 = 5. Setting max_per_subnet = 1 lowers it.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_subnet: Some(1),
        ..IPDiversityConfig::default()
    });

    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;

    // Second should fail because /64 limit is now 1
    let node2 = make_node_with_id(bucket0_id(2), "/ip6/2001:db8::2/udp/9000/quic");
    let result = engine.add_node_no_trust(node2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// No overrides -- defaults enforced
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_no_override_uses_defaults() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;

    // Second same-IP should succeed (exact-IP limit = 2)
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(2),
            "/ip4/192.168.1.1/udp/9001/quic",
        ))
        .await?;

    // Third same-IP should fail (exceeds exact-IP limit of 2)
    let node3 = make_node_with_id(bucket0_id(3), "/ip4/192.168.1.1/udp/9002/quic");
    let result = engine.add_node_no_trust(node3).await;
    assert!(result.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// Trust-aware swap-closer protection
// -----------------------------------------------------------------------

/// A well-trusted peer (score >= 0.7) should keep its routing table slot
/// even when a closer same-IP candidate arrives that would normally evict it.
#[tokio::test]
async fn test_trust_protects_peer_from_swap() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::default());

    // Two peers in bucket 0, same IP (exact-IP limit = 2).
    let mut id_far = [0u8; 32];
    id_far[0] = 0xFF; // farthest from self=[0;32]
    engine
        .add_node_no_trust(make_node_with_id(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
        .await?;

    let mut id_mid = [0u8; 32];
    id_mid[0] = 0xFE;
    engine
        .add_node_no_trust(make_node_with_id(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
        .await?;

    // A closer candidate with the same IP tries to join.
    // The farthest peer (id_far) has trust 0.8 — above TRUST_PROTECTION_THRESHOLD.
    let mut id_close = [0u8; 32];
    id_close[0] = 0x80; // closer to self than id_far/id_mid
    let far_peer = PeerId::from_bytes(id_far);

    let trust_fn = |peer_id: &PeerId| -> f64 {
        if *peer_id == far_peer {
            0.8 // trusted — above threshold
        } else {
            0.5 // neutral
        }
    };

    let result = engine
        .add_node(
            make_node_with_id(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
            &trust_fn,
        )
        .await;

    // Should be REJECTED: the only swap candidate (farthest) is trust-protected
    assert!(result.is_err());
    assert!(engine.has_node(&far_peer).await);

    Ok(())
}

/// An untrusted peer (score < 0.7) should be swapped out when a closer
/// same-IP candidate arrives, preserving the original distance-based behavior.
#[tokio::test]
async fn test_untrusted_peer_can_be_swapped() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::default());

    let mut id_far = [0u8; 32];
    id_far[0] = 0xFF;
    engine
        .add_node_no_trust(make_node_with_id(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
        .await?;

    let mut id_mid = [0u8; 32];
    id_mid[0] = 0xFE;
    engine
        .add_node_no_trust(make_node_with_id(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
        .await?;

    let mut id_close = [0u8; 32];
    id_close[0] = 0x80;
    let far_peer = PeerId::from_bytes(id_far);

    let trust_fn = |peer_id: &PeerId| -> f64 {
        if *peer_id == far_peer {
            0.3 // low trust — below threshold
        } else {
            0.5
        }
    };

    let result = engine
        .add_node(
            make_node_with_id(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
            &trust_fn,
        )
        .await;

    // Should succeed — far peer is not trust-protected and gets swapped out
    assert!(result.is_ok());
    assert!(engine.has_node(&PeerId::from_bytes(id_close)).await);
    assert!(!engine.has_node(&far_peer).await);

    Ok(())
}
