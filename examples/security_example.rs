// Copyright 2024 Saorsa Labs Limited
//
#![allow(clippy::unwrap_used, clippy::expect_used)]
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

//! Example of using the security module in the adaptive P2P network

use anyhow::Result;
use saorsa_core::PeerId;
use saorsa_core::adaptive::*;
use saorsa_core::quantum_crypto::saorsa_transport_integration::MlDsaPublicKey;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a node identity
    let identity = NodeIdentity::generate()?;
    println!("Generated node identity: {:?}", identity.peer_id());

    // Configure security settings
    let mut security_config = SecurityConfig::default();
    security_config.rate_limit.node_requests_per_window = 10;
    security_config.rate_limit.window_duration = Duration::from_secs(60);
    security_config.blacklist.max_entries = 1000;
    security_config.eclipse_detection.min_diversity_score = 0.6;

    // Create security manager
    let security_manager = SecurityManager::new(security_config, &identity);

    // Example: Validate a node join request
    let new_node = NodeDescriptor {
        id: PeerId::from_bytes([1u8; 32]),
        public_key: MlDsaPublicKey::from_bytes(&[0u8; 1952]).unwrap(),
        addresses: vec!["192.168.1.10:8000".parse().unwrap()],
        hyperbolic: None,
        som_position: None,
        trust: 0.5,
        capabilities: NodeCapabilities {
            compute: 100,
            bandwidth: 100,
        },
    };

    match security_manager.validate_node_join(&new_node).await {
        Ok(()) => println!("Node join validated successfully"),
        Err(e) => println!("Node join validation failed: {}", e),
    }

    // Example: Check rate limits
    let peer_id = PeerId::from_bytes([2u8; 32]);
    for i in 0..12 {
        if security_manager
            .check_rate_limit(&peer_id, None)
            .await
            .is_ok()
        {
            println!("Request {} allowed", i + 1);
        } else {
            println!("Request {} rate limited!", i + 1);
        }
    }

    // Example: Verify data integrity
    let data = b"Important network data";
    let hash = blake3::hash(data);
    if security_manager
        .verify_message_integrity(data, hash.as_bytes(), None)
        .await
        .is_ok()
    {
        println!("Data integrity verified");
    } else {
        println!("Data integrity check failed!");
    }

    // Example: Check for eclipse attacks
    let routing_table = vec![
        PeerId::from_bytes([10u8; 32]),
        PeerId::from_bytes([20u8; 32]),
        PeerId::from_bytes([30u8; 32]),
        PeerId::from_bytes([40u8; 32]),
        PeerId::from_bytes([50u8; 32]),
    ];

    match security_manager.detect_eclipse_attack(&routing_table).await {
        Ok(()) => println!("No eclipse attack detected"),
        Err(e) => println!("Eclipse attack warning: {}", e),
    }

    // Security metrics have been removed; security enforcement logic remains active
    println!("\nSecurity enforcement active (metrics removed)");

    Ok(())
}
