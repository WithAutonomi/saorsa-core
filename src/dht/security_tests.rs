use crate::PeerId;
use crate::dht::core_engine::{DhtCoreEngine, NodeInfo};
use crate::security::IPDiversityConfig;
use std::time::SystemTime;

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv6() -> anyhow::Result<()> {
    // 1. Initialize Engine
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // 2. Create Node 1 (IPv6)
    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::1/udp/9000/quic".parse().unwrap()], // /64 subnet 2001:db8::
        last_seen: SystemTime::now(),
    };

    // 3. Create Node 2 (Same /64 subnet)
    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::2/udp/9000/quic".parse().unwrap()], // Same /64
        last_seen: SystemTime::now(),
    };

    // 4. Add Node 1 - Should Succeed
    engine.add_node(node1).await?;

    // 5. Add Node 2 - Should Fail (Default limit is 1 per /64)
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv4() -> anyhow::Result<()> {
    // Verify IPv4 addresses are now checked (security fix - IPv4 no longer bypasses)
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // First node should succeed
    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node1).await?;

    // Second node on same IP should fail (default limit is 1 per IP for small networks)
    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()], // Same IP
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

#[tokio::test]
async fn test_ipv4_subnet_24_limit() -> anyhow::Result<()> {
    // Test /24 subnet limit (default: 3x per-IP limit)
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // Add nodes on different IPs but same /24 subnet
    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.2/udp/9000/quic".parse().unwrap()], // Different IP, same /24
        last_seen: SystemTime::now(),
    };
    engine.add_node(node2).await?;

    let node3 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.3/udp/9000/quic".parse().unwrap()], // Different IP, same /24
        last_seen: SystemTime::now(),
    };
    engine.add_node(node3).await?;

    // Fourth node should fail (default /24 limit is 3)
    let node4 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.4/udp/9000/quic".parse().unwrap()], // Different IP, same /24
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node4).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

#[tokio::test]
async fn test_mixed_ipv4_ipv6_enforcement() -> anyhow::Result<()> {
    // Test that both IPv4 and IPv6 are enforced in the same engine
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // Add IPv4 node
    let node_v4 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node_v4).await?;

    // Add IPv6 node (should succeed - different address family)
    let node_v6 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node_v6).await?;

    // Second IPv4 on same IP should fail
    let node_v4_2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result_v4 = engine.add_node(node_v4_2).await;
    assert!(result_v4.is_err());

    // Second IPv6 on same /64 should also fail
    let node_v6_2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::2/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result_v6 = engine.add_node(node_v6_2).await;
    assert!(result_v6.is_err());

    Ok(())
}

#[tokio::test]
async fn test_geographic_diversity_allows_different_regions() -> anyhow::Result<()> {
    // Test that nodes from different geographic regions can be added
    // This verifies the geographic diversity enforcement doesn't block legitimate diversity
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // Add node from North America (192.x.x.x range)
    let node_na = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()], // NorthAmerica
        last_seen: SystemTime::now(),
    };
    engine.add_node(node_na).await?;

    // Add node from Europe (127-159 range)
    let node_eu = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/130.45.10.1/udp/9000/quic".parse().unwrap()], // Europe
        last_seen: SystemTime::now(),
    };
    engine.add_node(node_eu).await?;

    // Add node from Asia Pacific (160-191 range)
    let node_ap = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/170.20.30.1/udp/9000/quic".parse().unwrap()], // AsiaPacific
        last_seen: SystemTime::now(),
    };
    engine.add_node(node_ap).await?;

    // Add node from South America (224-239 range)
    let node_sa = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/225.1.1.1/udp/9000/quic".parse().unwrap()], // SouthAmerica
        last_seen: SystemTime::now(),
    };
    engine.add_node(node_sa).await?;

    // All different regions should succeed
    Ok(())
}

#[tokio::test]
async fn test_geographic_diversity_counts_region_nodes() -> anyhow::Result<()> {
    // Test that multiple nodes from the same region are tracked correctly
    // We use different /24 subnets to avoid IP diversity rejection
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // Add 3 nodes from Europe (different /24 subnets to avoid IP diversity limits)
    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/130.10.1.1/udp/9000/quic".parse().unwrap()], // Europe
        last_seen: SystemTime::now(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/130.20.1.1/udp/9000/quic".parse().unwrap()], // Europe, different /24
        last_seen: SystemTime::now(),
    };
    engine.add_node(node2).await?;

    let node3 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/131.30.1.1/udp/9000/quic".parse().unwrap()], // Europe, different /16
        last_seen: SystemTime::now(),
    };
    engine.add_node(node3).await?;

    // All should succeed since geographic limit is 50 and we're only adding 3
    Ok(())
}

#[tokio::test]
async fn test_ipv4_floor_override_raises_limit() -> anyhow::Result<()> {
    // Default dynamic limit for a small network is 1 per /32.
    // Setting ipv4_limit_floor = 3 should allow 3 nodes on the same IP.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        ipv4_limit_floor: Some(3),
        ..IPDiversityConfig::default()
    });

    for i in 0..3u8 {
        let node = NodeInfo {
            id: PeerId::random(),
            addresses: vec![
                format!("/ip4/192.168.1.1/udp/{}/quic", 9000 + u16::from(i))
                    .parse()
                    .unwrap(),
            ],
            last_seen: SystemTime::now(),
        };
        engine.add_node(node).await?;
    }

    // Fourth node should fail (floor is 3, so limit is 3)
    let node4 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9003/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node4).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

#[tokio::test]
async fn test_ipv4_ceiling_override_lowers_limit() -> anyhow::Result<()> {
    // With a large network, dynamic per-IP would be high.
    // Setting ipv4_limit_ceiling = 1 should cap all subnet limits at 1.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        ipv4_limit_ceiling: Some(1),
        // Raise the dynamic limit so ceiling actually constrains it
        max_per_ip_cap: 100,
        max_network_fraction: 1.0,
        ..IPDiversityConfig::default()
    });

    // First node on 10.0.1.1
    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/10.0.1.1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node1).await?;

    // Second node on different IP but same /24 — should fail because ceiling=1
    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/10.0.1.2/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

#[tokio::test]
async fn test_ipv6_floor_override_raises_limit() -> anyhow::Result<()> {
    // Default IPv6 /64 limit is 1. Setting ipv6_limit_floor = 5 should allow
    // 5 nodes in the same /64 subnet.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        ipv6_limit_floor: Some(5),
        ..IPDiversityConfig::default()
    });
    // Disable geo limits — this test only exercises IP diversity.
    engine.set_geo_max_per_region(usize::MAX);

    for i in 1..=5u128 {
        let node = NodeInfo {
            id: PeerId::random(),
            addresses: vec![format!("/ip6/2001:db8::{i}/udp/9000/quic").parse().unwrap()],
            last_seen: SystemTime::now(),
        };
        engine.add_node(node).await?;
    }

    // Sixth node should fail
    let node6 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::6/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node6).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

#[tokio::test]
async fn test_ipv6_ceiling_override_lowers_limit() -> anyhow::Result<()> {
    // With permissive IPv6 config (max_nodes_per_ipv6_64 = usize::MAX),
    // setting ipv6_limit_ceiling = 2 should cap at 2.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_nodes_per_ipv6_64: usize::MAX,
        max_nodes_per_ipv6_48: usize::MAX,
        max_nodes_per_ipv6_32: usize::MAX,
        max_per_ip_cap: 100,
        max_network_fraction: 1.0,
        ipv6_limit_ceiling: Some(2),
        ..IPDiversityConfig::default()
    });

    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::2/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node2).await?;

    // Third should fail due to ceiling
    let node3 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip6/2001:db8::3/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node3).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

#[tokio::test]
async fn test_no_override_preserves_dynamic_behavior() -> anyhow::Result<()> {
    // When no overrides are set, behavior should be identical to before.
    // Default dynamic limit for small network = 1 per /32, 3 per /24.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    let node1 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9000/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    engine.add_node(node1).await?;

    // Same IP should fail (dynamic limit = 1)
    let node2 = NodeInfo {
        id: PeerId::random(),
        addresses: vec!["/ip4/192.168.1.1/udp/9001/quic".parse().unwrap()],
        last_seen: SystemTime::now(),
    };
    let result = engine.add_node(node2).await;
    assert!(result.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// Per-bucket geographic diversity tests
// -----------------------------------------------------------------------

/// Helper: create a NodeInfo with a specific PeerId (from byte array) and address.
fn make_node_with_id(id_bytes: [u8; 32], addr: &str) -> NodeInfo {
    NodeInfo {
        id: PeerId::from_bytes(id_bytes),
        addresses: vec![addr.parse().unwrap()],
        last_seen: SystemTime::now(),
    }
}

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
