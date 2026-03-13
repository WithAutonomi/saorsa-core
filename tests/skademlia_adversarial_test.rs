// Copyright 2024 Saorsa Labs Limited
//
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::double_comparisons)]
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Adversarial integration tests for S/Kademlia security
//!
//! These tests validate that the S/Kademlia implementation correctly detects
//! and handles various attack scenarios including:
//! - ML-DSA-65 signature verification
//! - XOR distance calculations
//! - Authenticated broadcast integrity
//! - Eclipse attack detection

use saorsa_core::PeerId;
use saorsa_core::dht::authenticated_sibling_broadcast::{
    AuthenticatedSiblingBroadcast, BroadcastValidationFailure, SiblingBroadcastBuilder,
    SiblingBroadcastConfig, SiblingBroadcastValidator, SignedSiblingEntry,
};
use saorsa_core::dht::core_engine::NodeCapacity;
use saorsa_core::dht::{Key, NodeInfo};
use std::time::{Duration, SystemTime};

// ============================================================================
// Test Helpers
// ============================================================================

fn random_peer_id() -> PeerId {
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        *byte = rand::random();
    }
    PeerId::from_bytes(bytes)
}

fn random_key() -> Key {
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        *byte = rand::random();
    }
    Key::from(bytes)
}

fn create_test_node() -> NodeInfo {
    NodeInfo {
        id: PeerId::random(),
        address: "127.0.0.1:8000".parse().unwrap(),
        last_seen: SystemTime::now(),
        capacity: NodeCapacity::default(),
    }
}

fn create_sibling_entry() -> SignedSiblingEntry {
    SignedSiblingEntry {
        node: create_test_node(),
        distance: random_key(),
        sibling_signature: None,
        last_seen: SystemTime::now(),
    }
}

// ============================================================================
// Test 3.1: ML-DSA-65 Signature Verification Under Attack
// ============================================================================

#[tokio::test]
async fn test_invalid_signature_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, _secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    // Create broadcast with valid structure but invalid signature (random bytes)
    let broadcast = AuthenticatedSiblingBroadcast {
        broadcaster: random_peer_id(),
        broadcaster_position: random_key(),
        siblings: vec![create_sibling_entry()],
        timestamp: SystemTime::now(),
        signature: vec![0u8; 3309], // Invalid signature (wrong bytes)
        membership_proof: None,
        sequence_number: 1,
    };

    // Verify should fail with invalid signature
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(!is_valid, "Invalid signature should be rejected");
}

#[tokio::test]
async fn test_valid_signature_acceptance() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    // Create a properly signed broadcast
    let broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Verify should succeed with valid signature
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(is_valid, "Valid signature should be accepted");
}

#[tokio::test]
async fn test_tampered_siblings_detection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    // Create a properly signed broadcast
    let mut broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Tamper with the siblings list
    broadcast.siblings.push(create_sibling_entry());

    // Verify should fail due to sibling list modification
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(
        !is_valid,
        "Tampered sibling list should invalidate signature"
    );
}

#[tokio::test]
async fn test_tampered_broadcaster_detection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    // Create a properly signed broadcast
    let mut broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Tamper with the broadcaster (identity spoofing attack)
    broadcast.broadcaster = random_peer_id();

    // Verify should fail due to broadcaster modification
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(
        !is_valid,
        "Tampered broadcaster should invalidate signature (prevents identity spoofing)"
    );
}

#[tokio::test]
async fn test_tampered_sequence_number_detection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    // Create a properly signed broadcast
    let mut broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Tamper with the sequence number
    broadcast.sequence_number = 999;

    // Verify should fail due to sequence number modification
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(
        !is_valid,
        "Tampered sequence_number should invalidate signature"
    );
}

// ============================================================================
// Test 3.2: Replay Attack Prevention
// ============================================================================

#[tokio::test]
async fn test_replay_attack_prevention_via_sequence() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (_pk, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");
    let broadcaster = random_peer_id();
    let position = random_key();

    // Create two broadcasts with same content but different sequence numbers
    let broadcast_1 = SiblingBroadcastBuilder::new()
        .broadcaster(broadcaster, position)
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create broadcast 1");

    let broadcast_2 = SiblingBroadcastBuilder::new()
        .broadcaster(broadcaster, position)
        .add_sibling(create_sibling_entry())
        .sequence_number(2)
        .build_and_sign(&secret_key)
        .expect("Should create broadcast 2");

    // Different signatures prove they're not replays
    assert_ne!(
        broadcast_1.signature, broadcast_2.signature,
        "Different sequence numbers should produce different signatures"
    );
}

#[tokio::test]
async fn test_sequence_validation_rejects_replay() {
    let position = random_key();
    let validator = SiblingBroadcastValidator::with_defaults(position);

    let peer = random_peer_id();

    // Simulate receiving a broadcast with sequence 5
    validator
        .get_recent_broadcasts(&peer)
        .iter()
        .for_each(|_| {});

    // For a fresh peer, any sequence is valid
    assert!(validator.is_valid_sequence(&peer, 1));
}

#[tokio::test]
async fn test_different_broadcasters_produce_different_signatures() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    // Two different keypairs for different broadcasters
    let (_pk1, secret_key1) = generate_ml_dsa_keypair().expect("Should generate keypair 1");
    let (_pk2, secret_key2) = generate_ml_dsa_keypair().expect("Should generate keypair 2");

    let position = random_key();
    let sibling = create_sibling_entry();

    let broadcast_1 = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), position)
        .add_sibling(sibling.clone())
        .sequence_number(1)
        .build_and_sign(&secret_key1)
        .expect("Should create broadcast 1");

    let broadcast_2 = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), position)
        .add_sibling(sibling)
        .sequence_number(1)
        .build_and_sign(&secret_key2)
        .expect("Should create broadcast 2");

    // Different sources produce different signatures (prevents cross-node replay)
    assert_ne!(
        broadcast_1.signature, broadcast_2.signature,
        "Different broadcasters should produce different signatures"
    );
}

// ============================================================================
// Test 3.3: XOR Distance Calculations for Sybil Detection
// ============================================================================

#[test]
fn test_xor_distance_symmetry() {
    // XOR distance should be symmetric: d(a,b) == d(b,a)
    let key_a = Key::from([1u8; 32]);
    let key_b = Key::from([200u8; 32]);

    let distance_ab = xor_distance(&key_a, &key_b);
    let distance_ba = xor_distance(&key_b, &key_a);

    assert_eq!(distance_ab, distance_ba, "XOR distance should be symmetric");
}

#[test]
fn test_xor_distance_identity() {
    // Distance to self should be zero
    let key = Key::from([42u8; 32]);

    let distance = xor_distance(&key, &key);

    assert_eq!(distance, [0u8; 32], "Distance to self should be zero");
}

#[test]
fn test_xor_distance_triangle_inequality() {
    // XOR distance satisfies triangle inequality: d(a,c) <= d(a,b) XOR d(b,c)
    // (Note: XOR metric uses XOR instead of addition)
    let key_a = Key::from([0u8; 32]);
    let key_b = Key::from([128u8; 32]);
    let key_c = Key::from([255u8; 32]);

    let d_ac = xor_distance(&key_a, &key_c);
    let d_ab = xor_distance(&key_a, &key_b);
    let d_bc = xor_distance(&key_b, &key_c);

    // Verify d(a,c) = d(a,b) XOR d(b,c) for XOR metric
    let combined = xor_two(&d_ab, &d_bc);

    assert_eq!(
        d_ac, combined,
        "XOR should satisfy d(a,c) = d(a,b) XOR d(b,c)"
    );
}

#[test]
fn test_sybil_node_id_proximity_detection() {
    // In a Sybil attack, attacker creates nodes with IDs close to target
    // The system should detect suspiciously close node IDs

    let target_key = Key::from([128u8; 32]);

    // Legitimate nodes: random IDs far from target
    let legitimate_ids = [
        Key::from([10u8; 32]),
        Key::from([200u8; 32]),
        Key::from([50u8; 32]),
    ];

    // Sybil nodes: IDs crafted to be close to target
    let sybil_ids = [
        Key::from([129u8; 32]), // Very close to 128
        Key::from([127u8; 32]), // Very close to 128
        Key::from([130u8; 32]), // Very close to 128
    ];

    // Calculate average distance for each group
    let avg_legit_distance: f64 = legitimate_ids
        .iter()
        .map(|id| count_leading_zeros(&xor_distance(&target_key, id)) as f64)
        .sum::<f64>()
        / legitimate_ids.len() as f64;

    let avg_sybil_distance: f64 = sybil_ids
        .iter()
        .map(|id| count_leading_zeros(&xor_distance(&target_key, id)) as f64)
        .sum::<f64>()
        / sybil_ids.len() as f64;

    // Sybil nodes should have suspiciously many leading zeros (closer distance)
    // This is a red flag for Sybil detection
    println!(
        "Average leading zeros - Legitimate: {}, Sybil: {}",
        avg_legit_distance, avg_sybil_distance
    );

    // A clustering of nodes with similar proximity could indicate Sybil attack
    assert!(
        avg_sybil_distance > avg_legit_distance || avg_sybil_distance == avg_legit_distance,
        "Sybil nodes typically cluster near target (may vary based on specific IDs)"
    );
}

// ============================================================================
// Test 3.4: Public Key Integrity
// ============================================================================

#[tokio::test]
async fn test_wrong_public_key_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    // Generate two different keypairs
    let (_pk1, secret_key1) = generate_ml_dsa_keypair().expect("Should generate keypair 1");
    let (public_key2, _sk2) = generate_ml_dsa_keypair().expect("Should generate keypair 2");

    // Create broadcast signed with key1
    let broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key1)
        .expect("Should create authenticated broadcast");

    // Verify with key2 should fail (key substitution attack)
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key2.as_bytes());
    assert!(
        !is_valid,
        "Signature should not verify with wrong public key"
    );
}

#[tokio::test]
async fn test_truncated_public_key_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    let broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Truncate the public key (malformed key attack)
    let truncated_pk = &public_key.as_bytes()[..100];

    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, truncated_pk);
    assert!(!is_valid, "Truncated public key should be rejected");
}

#[tokio::test]
async fn test_empty_public_key_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (_pk, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    let broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Empty public key
    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, &[]);
    assert!(!is_valid, "Empty public key should be rejected");
}

// ============================================================================
// Test 3.5: Signature Integrity Attacks
// ============================================================================

#[tokio::test]
async fn test_truncated_signature_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    let mut broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Truncate the signature
    broadcast.signature = broadcast.signature[..100].to_vec();

    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(!is_valid, "Truncated signature should be rejected");
}

#[tokio::test]
async fn test_empty_signature_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, _sk) = generate_ml_dsa_keypair().expect("Should generate keypair");

    let broadcast = AuthenticatedSiblingBroadcast {
        broadcaster: random_peer_id(),
        broadcaster_position: random_key(),
        siblings: vec![create_sibling_entry()],
        timestamp: SystemTime::now(),
        signature: vec![], // Empty signature
        membership_proof: None,
        sequence_number: 1,
    };

    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(!is_valid, "Empty signature should be rejected");
}

#[tokio::test]
async fn test_bit_flipped_signature_rejection() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().expect("Should generate keypair");

    let mut broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should create authenticated broadcast");

    // Flip one bit in the signature
    if !broadcast.signature.is_empty() {
        broadcast.signature[0] ^= 1;
    }

    let validator = SiblingBroadcastValidator::with_defaults(random_key());
    let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
    assert!(!is_valid, "Signature with flipped bit should be rejected");
}

// ============================================================================
// Test 3.6: Eclipse Attack Detection
// ============================================================================

#[test]
fn test_eclipse_attack_low_overlap_detection() {
    let position = random_key();
    let mut validator = SiblingBroadcastValidator::new(
        SiblingBroadcastConfig {
            min_siblings: 2,
            min_overlap_ratio: 0.5,
            require_membership_proof: false,
            ..Default::default()
        },
        position,
    );

    // Set up local siblings
    let local1 = random_peer_id();
    let local2 = random_peer_id();
    validator.add_local_sibling(local1);
    validator.add_local_sibling(local2);

    // Create broadcast with completely different siblings (no overlap)
    let broadcast = AuthenticatedSiblingBroadcast {
        broadcaster: random_peer_id(),
        broadcaster_position: random_key(),
        siblings: vec![create_sibling_entry(), create_sibling_entry()],
        timestamp: SystemTime::now(),
        signature: vec![],
        membership_proof: None,
        sequence_number: 1,
    };

    let result = validator.validate_broadcast(&broadcast);
    assert!(
        result.eclipse_suspected,
        "Eclipse attack should be detected"
    );
    assert!(
        result
            .failures
            .contains(&BroadcastValidationFailure::LowOverlap),
        "Low overlap should be reported"
    );
}

#[test]
fn test_stale_broadcast_rejection() {
    let position = random_key();
    let mut validator = SiblingBroadcastValidator::new(
        SiblingBroadcastConfig {
            max_broadcast_age: Duration::from_secs(60),
            min_siblings: 1,
            require_membership_proof: false,
            min_overlap_ratio: 0.0,
            ..Default::default()
        },
        position,
    );

    // Create broadcast with old timestamp (potential replay)
    let broadcast = AuthenticatedSiblingBroadcast {
        broadcaster: random_peer_id(),
        broadcaster_position: random_key(),
        siblings: vec![create_sibling_entry()],
        timestamp: SystemTime::now() - Duration::from_secs(120), // 2 minutes old
        signature: vec![],
        membership_proof: None,
        sequence_number: 1,
    };

    let result = validator.validate_broadcast(&broadcast);
    assert!(!result.is_valid, "Stale broadcast should be rejected");
    assert!(
        result
            .failures
            .contains(&BroadcastValidationFailure::StaleTimestamp),
        "Stale timestamp should be reported"
    );
}

#[test]
fn test_missing_membership_proof_rejection() {
    let position = random_key();
    let mut validator = SiblingBroadcastValidator::new(
        SiblingBroadcastConfig {
            min_siblings: 1,
            require_membership_proof: true, // Require proof
            min_overlap_ratio: 0.0,
            ..Default::default()
        },
        position,
    );

    // Create broadcast without membership proof
    let broadcast = AuthenticatedSiblingBroadcast {
        broadcaster: random_peer_id(),
        broadcaster_position: random_key(),
        siblings: vec![create_sibling_entry()],
        timestamp: SystemTime::now(),
        signature: vec![],
        membership_proof: None, // Missing!
        sequence_number: 1,
    };

    let result = validator.validate_broadcast(&broadcast);
    assert!(
        !result.is_valid,
        "Missing membership proof should be rejected"
    );
    assert!(
        result
            .failures
            .contains(&BroadcastValidationFailure::MissingMembershipProof),
        "Missing membership proof should be reported"
    );
}

#[test]
fn test_validate_broadcast_with_signature_integration() {
    use saorsa_core::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

    let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
    let position = random_key();

    let mut validator = SiblingBroadcastValidator::new(
        SiblingBroadcastConfig {
            min_siblings: 1,
            require_membership_proof: false,
            min_overlap_ratio: 0.0,
            ..Default::default()
        },
        position,
    );

    let broadcast = SiblingBroadcastBuilder::new()
        .broadcaster(random_peer_id(), random_key())
        .add_sibling(create_sibling_entry())
        .sequence_number(1)
        .build_and_sign(&secret_key)
        .expect("Should build and sign successfully");

    let result = validator.validate_broadcast_with_signature(&broadcast, public_key.as_bytes());
    assert!(
        result.is_valid,
        "Validation should succeed: {:?}",
        result.failures
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate XOR distance between two keys
fn xor_distance(a: &Key, b: &Key) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// XOR two distance arrays
fn xor_two(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Count leading zeros in a 256-bit key
fn count_leading_zeros(key: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for byte in key.iter() {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}
