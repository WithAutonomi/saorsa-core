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
/// set bit at position 0 → bucket 0). `seq` is written to `id[31]` for
/// uniqueness within the bucket.
fn bucket0_id(seq: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0x80;
    id[31] = seq;
    id
}

// -----------------------------------------------------------------------
// IPv6 diversity — per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv6() -> anyhow::Result<()> {
    // With self=[0;32], both nodes land in bucket 0.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    // Disable geo limits so only IP diversity matters.
    engine.set_geo_max_per_region(usize::MAX);

    let node1 = make_node_with_id(bucket0_id(1), "/ip6/2001:db8::1/udp/9000/quic");
    engine.add_node(node1).await?;

    // Second node in same /64 should fail (default per-IP=1 → /64 limit=1*3=3,
    // but static max_nodes_per_ipv6_64=1 is the binding constraint).
    let node2 = make_node_with_id(bucket0_id(2), "/ip6/2001:db8::2/udp/9000/quic");
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 diversity — per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv4() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_geo_max_per_region(usize::MAX);

    let node1 = make_node_with_id(bucket0_id(1), "/ip4/192.168.1.1/udp/9000/quic");
    engine.add_node(node1).await?;

    // Same IP, same bucket → per-bucket /32 limit (1) exceeded.
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/192.168.1.1/udp/9000/quic");
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 /24 subnet limit — per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_subnet_24_limit() -> anyhow::Result<()> {
    // Default /24 limit = per_ip * 3 = 1*3 = 3.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_geo_max_per_region(usize::MAX);

    // Three nodes on different IPs but same /24, all in bucket 0.
    engine
        .add_node(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node(make_node_with_id(
            bucket0_id(2),
            "/ip4/192.168.1.2/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node(make_node_with_id(
            bucket0_id(3),
            "/ip4/192.168.1.3/udp/9000/quic",
        ))
        .await?;

    // Fourth should fail (/24 limit = 3).
    let node4 = make_node_with_id(bucket0_id(4), "/ip4/192.168.1.4/udp/9000/quic");
    let result = engine.add_node(node4).await;
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
    engine.set_geo_max_per_region(usize::MAX);

    // IPv4 node
    engine
        .add_node(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;

    // IPv6 node — different address family, should succeed
    engine
        .add_node(make_node_with_id(
            bucket0_id(2),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;

    // Second IPv4 on same IP should fail
    let result_v4 = engine
        .add_node(make_node_with_id(
            bucket0_id(3),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await;
    assert!(result_v4.is_err());

    // Second IPv6 in same /64 should also fail
    let result_v6 = engine
        .add_node(make_node_with_id(
            bucket0_id(4),
            "/ip6/2001:db8::2/udp/9000/quic",
        ))
        .await;
    assert!(result_v6.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// Geographic diversity — different regions (deterministic IDs)
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_geographic_diversity_allows_different_regions() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // All nodes in bucket 0, each from a different region
    engine
        .add_node(make_node_with_id(
            bucket0_id(1),
            "/ip4/10.0.1.1/udp/9000/quic",
        ))
        .await?; // NorthAmerica
    engine
        .add_node(make_node_with_id(
            bucket0_id(2),
            "/ip4/130.45.10.1/udp/9000/quic",
        ))
        .await?; // Europe
    engine
        .add_node(make_node_with_id(
            bucket0_id(3),
            "/ip4/170.20.30.1/udp/9000/quic",
        ))
        .await?; // AsiaPacific
    engine
        .add_node(make_node_with_id(
            bucket0_id(4),
            "/ip4/225.1.1.1/udp/9000/quic",
        ))
        .await?; // SouthAmerica

    Ok(())
}

// -----------------------------------------------------------------------
// Geographic diversity — counting region nodes
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_geographic_diversity_counts_region_nodes() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // 3 Europe nodes (different /24 subnets to avoid IP diversity limits)
    engine
        .add_node(make_node_with_id(
            bucket0_id(1),
            "/ip4/130.10.1.1/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node(make_node_with_id(
            bucket0_id(2),
            "/ip4/130.20.1.1/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node(make_node_with_id(
            bucket0_id(3),
            "/ip4/131.30.1.1/udp/9000/quic",
        ))
        .await?;

    // All should succeed since geo_max_per_region=3
    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 floor override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_floor_override_raises_limit() -> anyhow::Result<()> {
    // Default dynamic limit for a small network is 1 per /32.
    // Setting ipv4_limit_floor = 3 should allow 3 nodes on the same IP.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        ipv4_limit_floor: Some(3),
        ..IPDiversityConfig::default()
    });
    engine.set_geo_max_per_region(usize::MAX);

    for i in 1..=3u8 {
        let node = make_node_with_id(
            bucket0_id(i),
            &format!("/ip4/192.168.1.1/udp/{}/quic", 9000 + u16::from(i)),
        );
        engine.add_node(node).await?;
    }

    // Fourth node should fail (floor is 3, so limit is 3)
    let node4 = make_node_with_id(bucket0_id(4), "/ip4/192.168.1.1/udp/9003/quic");
    let result = engine.add_node(node4).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 ceiling override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_ceiling_override_lowers_limit() -> anyhow::Result<()> {
    // With a large per-IP cap, ceiling = 1 caps all subnet limits at 1.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        ipv4_limit_ceiling: Some(1),
        max_per_ip_cap: 100,
        max_network_fraction: 1.0,
        ..IPDiversityConfig::default()
    });
    engine.set_geo_max_per_region(usize::MAX);

    let node1 = make_node_with_id(bucket0_id(1), "/ip4/10.0.1.1/udp/9000/quic");
    engine.add_node(node1).await?;

    // Different IP but same /24 — should fail because ceiling=1 applies to /24
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/10.0.1.2/udp/9000/quic");
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 floor override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_floor_override_raises_limit() -> anyhow::Result<()> {
    // Default IPv6 /64 limit is 1. Setting ipv6_limit_floor = 5 should allow
    // 5 nodes in the same /64 subnet.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        ipv6_limit_floor: Some(5),
        ..IPDiversityConfig::default()
    });
    // Disable geo limits — this test only exercises IP diversity, and 5
    // same-region nodes would hit geo_max_per_region=3 first.
    engine.set_geo_max_per_region(usize::MAX);

    for i in 1..=5u8 {
        let node = make_node_with_id(bucket0_id(i), &format!("/ip6/2001:db8::{i}/udp/9000/quic"));
        engine.add_node(node).await?;
    }

    // Sixth node should fail
    let node6 = make_node_with_id(bucket0_id(6), "/ip6/2001:db8::6/udp/9000/quic");
    let result = engine.add_node(node6).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 ceiling override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_ceiling_override_lowers_limit() -> anyhow::Result<()> {
    // With permissive IPv6 config, setting ipv6_limit_ceiling = 2 caps at 2.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_nodes_per_ipv6_64: usize::MAX,
        max_nodes_per_ipv6_48: usize::MAX,
        max_nodes_per_ipv6_32: usize::MAX,
        max_per_ip_cap: 100,
        max_network_fraction: 1.0,
        ipv6_limit_ceiling: Some(2),
        ..IPDiversityConfig::default()
    });
    engine.set_geo_max_per_region(usize::MAX);

    engine
        .add_node(make_node_with_id(
            bucket0_id(1),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node(make_node_with_id(
            bucket0_id(2),
            "/ip6/2001:db8::2/udp/9000/quic",
        ))
        .await?;

    // Third should fail due to ceiling
    let node3 = make_node_with_id(bucket0_id(3), "/ip6/2001:db8::3/udp/9000/quic");
    let result = engine.add_node(node3).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// No overrides — dynamic behavior preserved
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_no_override_preserves_dynamic_behavior() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_geo_max_per_region(usize::MAX);

    engine
        .add_node(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;

    // Same IP should fail (dynamic limit = 1)
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/192.168.1.1/udp/9001/quic");
    let result = engine.add_node(node2).await;
    assert!(result.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// Per-bucket geographic diversity tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_geo_per_bucket_rejects_fourth_same_region() -> anyhow::Result<()> {
    // With self=[0;32], IDs starting with 0x80 all land in bucket 0.
    // Default geo_max_per_region=3. Fourth same-region peer should be rejected.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    // Use permissive IP config so only geo limits matter
    engine.set_ip_diversity_config(IPDiversityConfig::permissive());

    // Three Europe peers (130.x = Europe) in bucket 0, each closer to self
    // than the next so that swap-closer can't help a fourth peer.
    let mut id1 = [0u8; 32];
    id1[0] = 0x80;
    id1[31] = 0x01; // distance: [0x80, 0..0, 0x01] — closest
    let mut id2 = [0u8; 32];
    id2[0] = 0x80;
    id2[31] = 0x02;
    let mut id3 = [0u8; 32];
    id3[0] = 0x80;
    id3[31] = 0x03;

    engine
        .add_node(make_node_with_id(id1, "/ip4/130.10.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id2, "/ip4/130.20.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id3, "/ip4/130.30.1.1/udp/9000/quic"))
        .await?;

    // Fourth Europe peer, FARTHER from self than all three → cannot swap → rejected
    let mut id4 = [0u8; 32];
    id4[0] = 0xFF; // distance: [0xFF, 0..0] — farthest in bucket 0
    let result = engine
        .add_node(make_node_with_id(id4, "/ip4/130.40.1.1/udp/9000/quic"))
        .await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Geographic diversity"),
        "expected geo diversity rejection"
    );

    Ok(())
}

#[tokio::test]
async fn test_geo_per_bucket_allows_different_regions() -> anyhow::Result<()> {
    // Even with 8 peers in bucket 0, if they're from different regions
    // the per-bucket geo limit should not block any of them.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::permissive());

    let regions = [
        "/ip4/10.0.1.1/udp/9000/quic",  // NorthAmerica
        "/ip4/130.0.1.1/udp/9000/quic", // Europe
        "/ip4/170.0.1.1/udp/9000/quic", // AsiaPacific
        "/ip4/225.0.1.1/udp/9000/quic", // SouthAmerica
        "/ip4/240.0.1.1/udp/9000/quic", // Africa
        "/ip4/248.0.1.1/udp/9000/quic", // Oceania
        "/ip4/200.0.1.1/udp/9000/quic", // NorthAmerica (second)
        "/ip4/131.0.1.1/udp/9000/quic", // Europe (second)
    ];

    for (i, addr) in regions.iter().enumerate() {
        let mut id = [0u8; 32];
        id[0] = 0x80;
        id[31] = (i as u8) + 1;
        engine.add_node(make_node_with_id(id, addr)).await?;
    }

    // All 8 should succeed — diverse regions
    assert_eq!(engine.routing_table_size().await, 8);

    Ok(())
}

#[tokio::test]
async fn test_geo_swap_closer_peer_replaces_farther() -> anyhow::Result<()> {
    // When a closer same-region peer arrives and the bucket is at the geo
    // limit, the farthest same-region peer should be swapped out.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::permissive());

    // Three Europe peers in bucket 0, all far from self
    let mut id_far1 = [0u8; 32];
    id_far1[0] = 0xFD;
    let mut id_far2 = [0u8; 32];
    id_far2[0] = 0xFE;
    let mut id_far3 = [0u8; 32];
    id_far3[0] = 0xFF; // farthest

    engine
        .add_node(make_node_with_id(id_far1, "/ip4/130.10.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id_far2, "/ip4/130.20.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id_far3, "/ip4/130.30.1.1/udp/9000/quic"))
        .await?;

    // Add a CLOSER Europe peer — should swap out id_far3 (0xFF, farthest)
    let mut id_close = [0u8; 32];
    id_close[0] = 0x80; // distance [0x80, 0..0] — closer than all three
    engine
        .add_node(make_node_with_id(id_close, "/ip4/130.40.1.1/udp/9000/quic"))
        .await?;

    // Verify swap: id_close present, id_far3 evicted
    assert!(engine.has_node(&PeerId::from_bytes(id_close)).await);
    assert!(
        !engine.has_node(&PeerId::from_bytes(id_far3)).await,
        "farthest same-region peer should have been swapped out"
    );
    // Other two remain
    assert!(engine.has_node(&PeerId::from_bytes(id_far1)).await);
    assert!(engine.has_node(&PeerId::from_bytes(id_far2)).await);

    Ok(())
}

#[tokio::test]
async fn test_geo_close_group_limit_enforced() -> anyhow::Result<()> {
    // The K closest nodes to self should also respect the per-region geo limit.
    // Place 3 Europe peers as the closest, then try to add a 4th Europe peer
    // that's farther — should be rejected by close-group check.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::permissive());

    // These three are the closest to self (small XOR distances), each in
    // its own bucket — all Europe.
    let mut id1 = [0u8; 32];
    id1[31] = 0x01; // bucket 255, distance=1
    let mut id2 = [0u8; 32];
    id2[31] = 0x02; // bucket 254, distance=2
    let mut id3 = [0u8; 32];
    id3[31] = 0x04; // bucket 253, distance=4

    engine
        .add_node(make_node_with_id(id1, "/ip4/130.10.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id2, "/ip4/130.20.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id3, "/ip4/130.30.1.1/udp/9000/quic"))
        .await?;

    // 4th Europe peer, farther than all three in the close group
    let mut id4 = [0u8; 32];
    id4[31] = 0x08; // bucket 252, distance=8
    let result = engine
        .add_node(make_node_with_id(id4, "/ip4/130.40.1.1/udp/9000/quic"))
        .await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("close-group limit"),
        "expected close-group geo rejection"
    );

    Ok(())
}

#[tokio::test]
async fn test_geo_close_group_swap_closer_peer() -> anyhow::Result<()> {
    // When a CLOSER Europe peer arrives and the close group is at the limit,
    // it should swap out the farthest Europe peer from the close group.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::permissive());

    // 3 Europe peers: distances 2, 4, 8 (all close to self)
    let mut id_e1 = [0u8; 32];
    id_e1[31] = 0x02; // distance 2
    let mut id_e2 = [0u8; 32];
    id_e2[31] = 0x04; // distance 4
    let mut id_e3 = [0u8; 32];
    id_e3[31] = 0x08; // distance 8 — farthest Europe in close group

    engine
        .add_node(make_node_with_id(id_e1, "/ip4/130.10.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id_e2, "/ip4/130.20.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node(make_node_with_id(id_e3, "/ip4/130.30.1.1/udp/9000/quic"))
        .await?;

    // Add a 4th Europe peer at distance 3 — closer than id_e3 (distance 8)
    // Should swap out id_e3
    let mut id_closer = [0u8; 32];
    id_closer[31] = 0x03; // distance 3
    engine
        .add_node(make_node_with_id(
            id_closer,
            "/ip4/130.40.1.1/udp/9000/quic",
        ))
        .await?;

    assert!(engine.has_node(&PeerId::from_bytes(id_closer)).await);
    assert!(
        !engine.has_node(&PeerId::from_bytes(id_e3)).await,
        "farthest Europe peer in close group should have been swapped out"
    );
    assert!(engine.has_node(&PeerId::from_bytes(id_e1)).await);
    assert!(engine.has_node(&PeerId::from_bytes(id_e2)).await);

    Ok(())
}

#[tokio::test]
async fn test_geo_different_region_bypasses_limit() -> anyhow::Result<()> {
    // After filling a bucket with 3 Europe peers, a NorthAmerica peer
    // should be accepted without issue.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::permissive());

    for i in 1..=3u8 {
        let mut id = [0u8; 32];
        id[0] = 0x80;
        id[31] = i;
        engine
            .add_node(make_node_with_id(
                id,
                &format!("/ip4/130.{}.1.1/udp/9000/quic", i * 10),
            ))
            .await?;
    }

    // NorthAmerica peer in same bucket — different region, should pass
    let mut id_na = [0u8; 32];
    id_na[0] = 0x80;
    id_na[31] = 0x04;
    engine
        .add_node(make_node_with_id(id_na, "/ip4/10.0.1.1/udp/9000/quic"))
        .await?;

    assert!(engine.has_node(&PeerId::from_bytes(id_na)).await);
    Ok(())
}
