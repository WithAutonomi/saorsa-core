// Copyright 2024 Saorsa Labs Limited
//
// Diagnostic test to identify DHT connectivity issues
// This test runs step-by-step with timeouts to pinpoint where things fail.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use saorsa_core::dht::DHTConfig;
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use saorsa_core::identity::node_identity::NodeIdentity;
use saorsa_core::network::NodeConfig;
use saorsa_core::transport_handle::{TransportConfig, TransportHandle};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

async fn create_node_with_transport(
    _name: &str,
) -> saorsa_core::Result<(Arc<TransportHandle>, DhtNetworkConfig)> {
    let identity = Arc::new(NodeIdentity::generate().unwrap());
    let node_config = NodeConfig::builder()
        .listen_port(0)
        .ipv6(false)
        .allow_loopback(true)
        .build()
        .expect("Failed to build NodeConfig");

    let transport = Arc::new(
        TransportHandle::new(TransportConfig::from_node_config(
            &node_config,
            saorsa_core::DEFAULT_EVENT_CHANNEL_CAPACITY,
            identity.clone(),
        ))
        .await?,
    );

    let config = DhtNetworkConfig {
        peer_id: *identity.peer_id(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(5),
        max_concurrent_operations: 10,
        enable_security: false,
    };

    Ok((transport, config))
}

/// Step 1: Can we create a single DhtNetworkManager?
#[tokio::test]
async fn step1_create_single_manager() -> Result<()> {
    println!("STEP 1: Creating single DhtNetworkManager...");

    let result = timeout(Duration::from_secs(10), async {
        let (transport, config) = create_node_with_transport("diag_node_1").await?;
        transport.start_network_listeners().await?;
        DhtNetworkManager::new(transport, None, config).await
    })
    .await;

    match result {
        Ok(Ok(manager)) => {
            println!("  ✓ Manager created successfully");
            println!("  Local addr: {:?}", manager.local_addr());
            println!("  Peer ID: {}", manager.peer_id());
            Ok(())
        }
        Ok(Err(e)) => {
            println!("  ✗ Manager creation failed: {}", e);
            Err(e.into())
        }
        Err(_) => {
            println!("  ✗ Manager creation timed out after 10s");
            Err(anyhow::anyhow!("Timeout"))
        }
    }
}

/// Step 2: Can we start a manager?
#[tokio::test]
async fn step2_start_manager() -> Result<()> {
    println!("STEP 2: Starting DhtNetworkManager...");

    let manager = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_2").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    println!("  Manager created");

    let start_result = timeout(Duration::from_secs(10), manager.start()).await;

    match start_result {
        Ok(Ok(())) => {
            println!("  ✓ Manager started successfully");
            println!("  Local addr after start: {:?}", manager.local_addr());
            let _ = manager.stop().await;
            Ok(())
        }
        Ok(Err(e)) => {
            println!("  ✗ Manager start failed: {}", e);
            Err(e.into())
        }
        Err(_) => {
            println!("  ✗ Manager start timed out after 10s");
            Err(anyhow::anyhow!("Timeout"))
        }
    }
}

/// Step 3: Can we create and start two managers?
#[tokio::test]
async fn step3_two_managers() -> Result<()> {
    println!("STEP 3: Creating two managers...");

    let manager1 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_3a").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    println!("  Manager 1 created");

    let manager2 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_3b").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    println!("  Manager 2 created");

    timeout(Duration::from_secs(10), manager1.start()).await??;
    println!("  Manager 1 started at {:?}", manager1.local_addr());

    timeout(Duration::from_secs(10), manager2.start()).await??;
    println!("  Manager 2 started at {:?}", manager2.local_addr());

    println!("  ✓ Both managers started");

    let _ = manager1.stop().await;
    let _ = manager2.stop().await;
    Ok(())
}

/// Step 4: Can two managers connect?
#[tokio::test]
async fn step4_connect_managers() -> Result<()> {
    println!("STEP 4: Connecting two managers...");

    let manager1 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_4a").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );
    let manager2 = Arc::new(
        timeout(Duration::from_secs(10), async {
            let (transport, config) = create_node_with_transport("diag_node_4b").await?;
            transport.start_network_listeners().await?;
            DhtNetworkManager::new(transport, None, config).await
        })
        .await??,
    );

    timeout(Duration::from_secs(10), manager1.start()).await??;
    timeout(Duration::from_secs(10), manager2.start()).await??;

    let addr1 = manager1
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("No addr for manager1"))?;
    println!("  Manager 1 listening at: {}", addr1);
    println!("  Attempting connection from manager2 -> manager1...");

    let peer_id = timeout(Duration::from_secs(15), manager2.connect_to_peer(&addr1))
        .await
        .map_err(|_| anyhow::anyhow!("Connection timed out after 15s"))??;
    println!("  Connected! Peer ID: {}", peer_id);

    // Wait briefly for the connection to be fully established on both sides
    tokio::time::sleep(Duration::from_millis(500)).await;

    let peers2 = manager2.get_connected_peers().await;
    assert!(
        !peers2.is_empty(),
        "Manager 2 should have at least one connected peer"
    );

    let _ = manager1.stop().await;
    let _ = manager2.stop().await;
    Ok(())
}
