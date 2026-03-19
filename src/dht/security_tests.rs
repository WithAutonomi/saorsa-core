use crate::PeerId;
use crate::dht::core_engine::{DhtCoreEngine, NodeCapacity, NodeInfo};
use crate::security::IPDiversityConfig;
use std::time::SystemTime;

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv6() -> anyhow::Result<()> {
    // 1. Initialize Engine
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::random())?;

    // 2. Create Node 1 (IPv6)
    let node1 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::1/udp/9000/quic".parse().unwrap(), // /64 subnet 2001:db8::
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };

    // 3. Create Node 2 (Same /64 subnet)
    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::2/udp/9000/quic".parse().unwrap(), // Same /64
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    // Second node on same IP should fail (default limit is 1 per IP for small networks)
    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(), // Same IP
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.2/udp/9000/quic".parse().unwrap(), // Different IP, same /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node2).await?;

    let node3 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.3/udp/9000/quic".parse().unwrap(), // Different IP, same /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node3).await?;

    // Fourth node should fail (default /24 limit is 3)
    let node4 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.4/udp/9000/quic".parse().unwrap(), // Different IP, same /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_v4).await?;

    // Add IPv6 node (should succeed - different address family)
    let node_v6 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_v6).await?;

    // Second IPv4 on same IP should fail
    let node_v4_2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    let result_v4 = engine.add_node(node_v4_2).await;
    assert!(result_v4.is_err());

    // Second IPv6 on same /64 should also fail
    let node_v6_2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::2/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(), // NorthAmerica
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_na).await?;

    // Add node from Europe (127-159 range)
    let node_eu = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/130.45.10.1/udp/9000/quic".parse().unwrap(), // Europe
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_eu).await?;

    // Add node from Asia Pacific (160-191 range)
    let node_ap = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/170.20.30.1/udp/9000/quic".parse().unwrap(), // AsiaPacific
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node_ap).await?;

    // Add node from South America (224-239 range)
    let node_sa = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/225.1.1.1/udp/9000/quic".parse().unwrap(), // SouthAmerica
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/130.10.1.1/udp/9000/quic".parse().unwrap(), // Europe
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/130.20.1.1/udp/9000/quic".parse().unwrap(), // Europe, different /24
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node2).await?;

    let node3 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/131.30.1.1/udp/9000/quic".parse().unwrap(), // Europe, different /16
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node3).await?;

    // All should succeed: random PeerIds almost certainly land in different
    // buckets (256 buckets), so each bucket has at most 1 Europe node (limit=3).
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
            address: format!("/ip4/192.168.1.1/udp/{}/quic", 9000 + u16::from(i))
                .parse()
                .unwrap(),
            last_seen: SystemTime::now(),
            capacity: NodeCapacity::default(),
        };
        engine.add_node(node).await?;
    }

    // Fourth node should fail (floor is 3, so limit is 3)
    let node4 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.1/udp/9003/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/10.0.1.1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    // Second node on different IP but same /24 — should fail because ceiling=1
    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/10.0.1.2/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
    // Raise geo limit — this test exercises IP diversity, not geographic limits.
    // IPv6 maps to GeographicRegion::Unknown, so 5 nodes would hit the
    // per-region limit (3) before reaching the IP diversity limit.
    engine.set_geo_max_per_region(100);

    for i in 1..=5u128 {
        let node = NodeInfo {
            id: PeerId::random(),
            address: format!("/ip6/2001:db8::{i}/udp/9000/quic").parse().unwrap(),
            last_seen: SystemTime::now(),
            capacity: NodeCapacity::default(),
        };
        engine.add_node(node).await?;
    }

    // Sixth node should fail
    let node6 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::6/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip6/2001:db8::1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::2/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node2).await?;

    // Third should fail due to ceiling
    let node3 = NodeInfo {
        id: PeerId::random(),
        address: "/ip6/2001:db8::3/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
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
        address: "/ip4/192.168.1.1/udp/9000/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    engine.add_node(node1).await?;

    // Same IP should fail (dynamic limit = 1)
    let node2 = NodeInfo {
        id: PeerId::random(),
        address: "/ip4/192.168.1.1/udp/9001/quic".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    };
    let result = engine.add_node(node2).await;
    assert!(result.is_err());

    Ok(())
}
