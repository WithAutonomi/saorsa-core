//! Authenticated Sibling Broadcast for eclipse attack prevention
//!
//! This module provides authenticated sibling list broadcasts with:
//! - ML-DSA-65 signature verification
//! - Timestamp freshness checking
//! - Membership proof validation
//! - Cross-validation against local sibling list
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dht::{Key, NodeInfo, PeerId};

/// Configuration for sibling broadcast validation
#[derive(Debug, Clone)]
pub struct SiblingBroadcastConfig {
    /// Maximum age for a broadcast to be considered fresh (default 5 minutes)
    pub max_broadcast_age: Duration,
    /// Minimum overlap ratio with local siblings to accept (default 0.5)
    pub min_overlap_ratio: f64,
    /// Minimum number of siblings in a valid broadcast
    pub min_siblings: usize,
    /// Maximum number of siblings in a valid broadcast
    pub max_siblings: usize,
    /// Whether to require membership proofs
    pub require_membership_proof: bool,
}

impl Default for SiblingBroadcastConfig {
    fn default() -> Self {
        Self {
            max_broadcast_age: Duration::from_secs(300), // 5 minutes
            min_overlap_ratio: 0.5,
            min_siblings: 4,
            max_siblings: 32,
            require_membership_proof: true,
        }
    }
}

/// A signed sibling entry in a broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSiblingEntry {
    /// The sibling node info
    pub node: NodeInfo,
    /// Distance from broadcaster
    pub distance: Key,
    /// Signature from the sibling confirming membership
    pub sibling_signature: Option<Vec<u8>>,
    /// When the sibling was last seen
    pub last_seen: SystemTime,
}

/// Proof of membership in the sibling group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    /// Proof type
    pub proof_type: MembershipProofType,
    /// Proof data (signatures, paths, etc.)
    pub proof_data: Vec<u8>,
    /// Peer validators that vouch for membership
    pub witnesses: Vec<PeerId>,
    /// Validator signatures
    pub witness_signatures: Vec<Vec<u8>>,
}

/// Types of membership proofs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MembershipProofType {
    /// Signatures from existing siblings
    SiblingSignatures,
    /// Path through DHT to verify position
    DhtPath,
    /// Combined proof using multiple methods
    Combined,
}

/// An authenticated sibling list broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedSiblingBroadcast {
    /// The node broadcasting its sibling list
    pub broadcaster: PeerId,
    /// The broadcaster's claimed position in the DHT
    pub broadcaster_position: Key,
    /// Signed sibling entries
    pub siblings: Vec<SignedSiblingEntry>,
    /// Broadcast timestamp
    pub timestamp: SystemTime,
    /// ML-DSA-65 signature of the broadcast
    pub signature: Vec<u8>,
    /// Optional membership proof
    pub membership_proof: Option<MembershipProof>,
    /// Sequence number for ordering
    pub sequence_number: u64,
}

impl AuthenticatedSiblingBroadcast {
    /// Serialize the broadcast to bytes for signing/verification
    ///
    /// Creates a deterministic byte representation of all significant fields
    /// (excluding the signature itself) for cryptographic operations.
    #[must_use]
    pub fn to_bytes_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256); // Pre-allocate reasonable size

        // Broadcaster identity (PeerId is 32 bytes)
        bytes.extend_from_slice(self.broadcaster.to_bytes());

        // Broadcaster position (Key is [u8; 32])
        bytes.extend_from_slice(&self.broadcaster_position);

        // Sequence number (8 bytes, little endian)
        bytes.extend_from_slice(&self.sequence_number.to_le_bytes());

        // Timestamp as milliseconds since UNIX_EPOCH (8 bytes, little endian)
        let millis = self
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        bytes.extend_from_slice(&millis.to_le_bytes());

        // Number of siblings (for length prefix)
        bytes.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());

        // Siblings (deterministic order - already in vector order)
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling.node.id.as_bytes());
            bytes.extend_from_slice(&sibling.distance);
            // Last seen timestamp
            let sibling_millis = sibling
                .last_seen
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            bytes.extend_from_slice(&sibling_millis.to_le_bytes());
        }

        // Membership proof if present
        if let Some(proof) = &self.membership_proof {
            bytes.push(1); // Proof present marker
            bytes.push(match proof.proof_type {
                MembershipProofType::SiblingSignatures => 0,
                MembershipProofType::DhtPath => 1,
                MembershipProofType::Combined => 2,
            });
            bytes.extend_from_slice(&(proof.proof_data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&proof.proof_data);
            bytes.extend_from_slice(&(proof.witnesses.len() as u32).to_le_bytes());
            for witness in &proof.witnesses {
                bytes.extend_from_slice(witness.to_bytes());
            }
        } else {
            bytes.push(0); // No proof marker
        }

        bytes
    }
}

/// Result of validating a sibling broadcast
#[derive(Debug, Clone)]
pub struct BroadcastValidationResult {
    /// Whether the broadcast is valid
    pub is_valid: bool,
    /// Overlap ratio with local siblings
    pub overlap_ratio: f64,
    /// Number of valid sibling entries
    pub valid_siblings: usize,
    /// Failure reasons if invalid
    pub failures: Vec<BroadcastValidationFailure>,
    /// Whether eclipse attack is suspected
    pub eclipse_suspected: bool,
}

/// Types of validation failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastValidationFailure {
    /// Broadcast signature is invalid
    InvalidSignature,
    /// Broadcast timestamp is too old
    StaleTimestamp,
    /// Too few siblings in broadcast
    TooFewSiblings,
    /// Too many siblings in broadcast
    TooManySiblings,
    /// Low overlap with local sibling list (potential eclipse)
    LowOverlap,
    /// Invalid membership proof
    InvalidMembershipProof,
    /// Missing required membership proof
    MissingMembershipProof,
    /// Sibling signature verification failed
    InvalidSiblingSignature,
    /// Inconsistent distances in sibling list
    InconsistentDistances,
    /// Duplicate entries in sibling list
    DuplicateEntries,
}

/// Validator for authenticated sibling broadcasts
pub struct SiblingBroadcastValidator {
    /// Configuration
    config: SiblingBroadcastConfig,
    /// Local sibling list for comparison
    local_siblings: HashSet<PeerId>,
    /// Local node position (stored for future distance-based validation)
    _local_position: Key,
    /// History of recent broadcasts for consistency checking
    recent_broadcasts: std::collections::VecDeque<(PeerId, u64, SystemTime)>,
}

impl SiblingBroadcastValidator {
    /// Create a new validator
    #[must_use]
    pub fn new(config: SiblingBroadcastConfig, local_position: Key) -> Self {
        Self {
            config,
            local_siblings: HashSet::new(),
            _local_position: local_position,
            recent_broadcasts: std::collections::VecDeque::new(),
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults(local_position: Key) -> Self {
        Self::new(SiblingBroadcastConfig::default(), local_position)
    }

    /// Update local sibling list
    pub fn update_local_siblings(&mut self, siblings: HashSet<PeerId>) {
        self.local_siblings = siblings;
    }

    /// Add a sibling to the local list
    pub fn add_local_sibling(&mut self, peer_id: PeerId) {
        self.local_siblings.insert(peer_id);
    }

    /// Remove a sibling from the local list
    pub fn remove_local_sibling(&mut self, peer_id: &PeerId) {
        self.local_siblings.remove(peer_id);
    }

    /// Validate an authenticated sibling broadcast
    #[must_use]
    pub fn validate_broadcast(
        &mut self,
        broadcast: &AuthenticatedSiblingBroadcast,
    ) -> BroadcastValidationResult {
        let mut failures = Vec::new();
        let mut is_valid = true;

        // Check timestamp freshness
        if let Ok(elapsed) = SystemTime::now().duration_since(broadcast.timestamp) {
            if elapsed > self.config.max_broadcast_age {
                failures.push(BroadcastValidationFailure::StaleTimestamp);
                is_valid = false;
            }
        } else {
            // Future timestamp is suspicious
            failures.push(BroadcastValidationFailure::StaleTimestamp);
            is_valid = false;
        }

        // Check sibling count bounds
        if broadcast.siblings.len() < self.config.min_siblings {
            failures.push(BroadcastValidationFailure::TooFewSiblings);
            is_valid = false;
        }
        if broadcast.siblings.len() > self.config.max_siblings {
            failures.push(BroadcastValidationFailure::TooManySiblings);
            is_valid = false;
        }

        // Check for duplicate entries
        let unique_siblings: HashSet<_> = broadcast.siblings.iter().map(|s| s.node.id).collect();
        if unique_siblings.len() != broadcast.siblings.len() {
            failures.push(BroadcastValidationFailure::DuplicateEntries);
            is_valid = false;
        }

        // Check membership proof if required
        if self.config.require_membership_proof && broadcast.membership_proof.is_none() {
            failures.push(BroadcastValidationFailure::MissingMembershipProof);
            is_valid = false;
        }

        // Validate membership proof if present
        if broadcast
            .membership_proof
            .as_ref()
            .is_some_and(|proof| !self.validate_membership_proof(proof, &broadcast.broadcaster))
        {
            failures.push(BroadcastValidationFailure::InvalidMembershipProof);
            is_valid = false;
        }

        // Calculate overlap with local siblings
        let broadcast_peer_ids: HashSet<PeerId> =
            broadcast.siblings.iter().map(|s| s.node.id).collect();

        let overlap_count = self
            .local_siblings
            .intersection(&broadcast_peer_ids)
            .count();

        let overlap_ratio = if self.local_siblings.is_empty() {
            1.0 // If we have no local siblings, accept the broadcast
        } else {
            overlap_count as f64 / self.local_siblings.len() as f64
        };

        // Check for low overlap (potential eclipse attack)
        let eclipse_suspected = overlap_ratio < self.config.min_overlap_ratio;
        if eclipse_suspected && !self.local_siblings.is_empty() {
            failures.push(BroadcastValidationFailure::LowOverlap);
            is_valid = false;
        }

        // Track this broadcast
        self.recent_broadcasts.push_back((
            broadcast.broadcaster,
            broadcast.sequence_number,
            broadcast.timestamp,
        ));

        // Keep only recent broadcasts (last 100)
        while self.recent_broadcasts.len() > 100 {
            self.recent_broadcasts.pop_front();
        }

        BroadcastValidationResult {
            is_valid,
            overlap_ratio,
            valid_siblings: broadcast.siblings.len(),
            failures,
            eclipse_suspected,
        }
    }

    /// Validate a membership proof
    fn validate_membership_proof(&self, proof: &MembershipProof, _broadcaster: &PeerId) -> bool {
        match proof.proof_type {
            MembershipProofType::SiblingSignatures => {
                // Need at least 2 sibling signatures
                proof.witnesses.len() >= 2 && proof.witness_signatures.len() >= 2
            }
            MembershipProofType::DhtPath => {
                // Need valid path data
                !proof.proof_data.is_empty()
            }
            MembershipProofType::Combined => {
                // Combined requires both witnesses and proof data
                !proof.witnesses.is_empty() && !proof.proof_data.is_empty()
            }
        }
    }

    /// Verify ML-DSA-65 signature of a broadcast
    ///
    /// Verifies that the broadcast was signed by the holder of the secret key
    /// corresponding to the provided public key.
    ///
    /// # Arguments
    /// * `broadcast` - The broadcast to verify
    /// * `public_key_bytes` - The ML-DSA-65 public key bytes (1952 bytes)
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    pub fn verify_signature(
        &self,
        broadcast: &AuthenticatedSiblingBroadcast,
        public_key_bytes: &[u8],
    ) -> bool {
        use crate::quantum_crypto::saorsa_transport_integration::{
            MlDsaPublicKey, MlDsaSignature, ml_dsa_verify,
        };

        // Parse public key from bytes
        let public_key = match MlDsaPublicKey::from_bytes(public_key_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // Empty signature is invalid
        if broadcast.signature.is_empty() {
            return false;
        }

        // Parse signature from bytes
        let signature = match MlDsaSignature::from_bytes(&broadcast.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // Create deterministic message from broadcast contents
        let message = broadcast.to_bytes_for_signing();

        // Verify using ML-DSA-65
        ml_dsa_verify(&public_key, &message, &signature).unwrap_or_default()
    }

    /// Validate an authenticated sibling broadcast with signature verification
    ///
    /// This performs all standard validation plus verifies the ML-DSA-65 signature.
    /// Use this method when you have the broadcaster's public key available for
    /// full cryptographic verification.
    ///
    /// # Arguments
    /// * `broadcast` - The broadcast to validate
    /// * `broadcaster_public_key` - The broadcaster's ML-DSA-65 public key bytes (1952 bytes)
    ///
    /// # Returns
    /// `BroadcastValidationResult` with `InvalidSignature` failure if signature verification fails
    #[must_use]
    pub fn validate_broadcast_with_signature(
        &mut self,
        broadcast: &AuthenticatedSiblingBroadcast,
        broadcaster_public_key: &[u8],
    ) -> BroadcastValidationResult {
        // First verify the ML-DSA-65 signature
        if !self.verify_signature(broadcast, broadcaster_public_key) {
            return BroadcastValidationResult {
                is_valid: false,
                overlap_ratio: 0.0,
                valid_siblings: 0,
                failures: vec![BroadcastValidationFailure::InvalidSignature],
                eclipse_suspected: false,
            };
        }

        // Then perform standard validation
        self.validate_broadcast(broadcast)
    }

    /// Get recent broadcasts from a specific peer
    #[must_use]
    pub fn get_recent_broadcasts(&self, peer: &PeerId) -> Vec<(u64, SystemTime)> {
        self.recent_broadcasts
            .iter()
            .filter(|(p, _, _)| p == peer)
            .map(|(_, seq, time)| (*seq, *time))
            .collect()
    }

    /// Check if a sequence number is valid (not replayed)
    #[must_use]
    pub fn is_valid_sequence(&self, peer: &PeerId, sequence: u64) -> bool {
        let recent = self.get_recent_broadcasts(peer);
        if recent.is_empty() {
            return true;
        }
        // Sequence should be greater than the most recent
        recent.iter().all(|(seq, _)| sequence > *seq)
    }

    /// Calculate eclipse risk score based on recent broadcasts
    #[must_use]
    pub fn calculate_eclipse_risk(&self) -> f64 {
        if self.recent_broadcasts.is_empty() {
            return 0.0;
        }

        // Count broadcasts with low overlap
        // This is a simplified metric - in production would be more sophisticated
        0.0 // Placeholder - would analyze recent validation results
    }
}

/// Builder for authenticated sibling broadcasts
pub struct SiblingBroadcastBuilder {
    broadcaster: Option<PeerId>,
    broadcaster_position: Option<Key>,
    siblings: Vec<SignedSiblingEntry>,
    membership_proof: Option<MembershipProof>,
    sequence_number: u64,
}

impl Default for SiblingBroadcastBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SiblingBroadcastBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            broadcaster: None,
            broadcaster_position: None,
            siblings: Vec::new(),
            membership_proof: None,
            sequence_number: 0,
        }
    }

    /// Set the broadcaster
    #[must_use]
    pub fn broadcaster(mut self, peer_id: PeerId, position: Key) -> Self {
        self.broadcaster = Some(peer_id);
        self.broadcaster_position = Some(position);
        self
    }

    /// Add a sibling
    #[must_use]
    pub fn add_sibling(mut self, entry: SignedSiblingEntry) -> Self {
        self.siblings.push(entry);
        self
    }

    /// Set the membership proof
    #[must_use]
    pub fn membership_proof(mut self, proof: MembershipProof) -> Self {
        self.membership_proof = Some(proof);
        self
    }

    /// Set the sequence number
    #[must_use]
    pub fn sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number = seq;
        self
    }

    /// Build the broadcast (without signature - must be signed separately)
    pub fn build(self) -> Result<AuthenticatedSiblingBroadcast, &'static str> {
        let broadcaster = self.broadcaster.ok_or("Broadcaster is required")?;
        let broadcaster_position = self
            .broadcaster_position
            .ok_or("Broadcaster position is required")?;

        Ok(AuthenticatedSiblingBroadcast {
            broadcaster,
            broadcaster_position,
            siblings: self.siblings,
            timestamp: SystemTime::now(),
            signature: Vec::new(), // Must be signed after building
            membership_proof: self.membership_proof,
            sequence_number: self.sequence_number,
        })
    }

    /// Build and sign the broadcast with ML-DSA-65
    ///
    /// This is the recommended way to create a signed broadcast.
    ///
    /// # Arguments
    /// * `secret_key` - The ML-DSA-65 secret key to sign with
    ///
    /// # Returns
    /// A signed `AuthenticatedSiblingBroadcast` or an error
    ///
    /// # Errors
    /// Returns an error if:
    /// - Required fields (broadcaster, position) are missing
    /// - Signing fails
    pub fn build_and_sign(
        self,
        secret_key: &crate::quantum_crypto::saorsa_transport_integration::MlDsaSecretKey,
    ) -> Result<AuthenticatedSiblingBroadcast, &'static str> {
        use crate::quantum_crypto::saorsa_transport_integration::ml_dsa_sign;

        // Build the unsigned broadcast
        let mut broadcast = self.build()?;

        // Create the message to sign
        let message = broadcast.to_bytes_for_signing();

        // Sign with ML-DSA-65
        let signature = ml_dsa_sign(secret_key, &message).map_err(|_| "Signing failed")?;

        // Attach signature to broadcast
        broadcast.signature = signature.as_bytes().to_vec();

        Ok(broadcast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerId;
    use crate::dht::core_engine::NodeCapacity;
    use rand::Rng;

    fn random_peer_id() -> PeerId {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        PeerId::from_bytes(bytes)
    }

    fn random_key() -> Key {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        Key::from(bytes)
    }

    fn random_node_id() -> PeerId {
        PeerId::random()
    }

    fn create_test_node() -> NodeInfo {
        NodeInfo {
            id: random_node_id(),
            address: "127.0.0.1:8000".parse().unwrap(),
            last_seen: SystemTime::now(),
            capacity: NodeCapacity::default(),
        }
    }

    #[test]
    fn test_validator_creation() {
        let position = random_key();
        let validator = SiblingBroadcastValidator::with_defaults(position);
        assert!(validator.local_siblings.is_empty());
    }

    #[test]
    fn test_update_local_siblings() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::with_defaults(position);

        let peer1 = random_peer_id();
        let peer2 = random_peer_id();

        let siblings: HashSet<_> = [peer1, peer2].into_iter().collect();
        validator.update_local_siblings(siblings);

        assert_eq!(validator.local_siblings.len(), 2);
    }

    #[test]
    fn test_add_remove_sibling() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::with_defaults(position);

        let peer = random_peer_id();
        validator.add_local_sibling(peer);
        assert!(validator.local_siblings.contains(&peer));

        validator.remove_local_sibling(&peer);
        assert!(!validator.local_siblings.contains(&peer));
    }

    #[test]
    fn test_stale_broadcast_rejected() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::new(
            SiblingBroadcastConfig {
                max_broadcast_age: Duration::from_secs(60),
                require_membership_proof: false,
                ..Default::default()
            },
            position,
        );

        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![],
            timestamp: SystemTime::now() - Duration::from_secs(120), // 2 minutes old
            signature: vec![],
            membership_proof: None,
            sequence_number: 1,
        };

        let result = validator.validate_broadcast(&broadcast);
        assert!(!result.is_valid);
        assert!(
            result
                .failures
                .contains(&BroadcastValidationFailure::StaleTimestamp)
        );
    }

    #[test]
    fn test_too_few_siblings_rejected() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::new(
            SiblingBroadcastConfig {
                min_siblings: 4,
                require_membership_proof: false,
                ..Default::default()
            },
            position,
        );

        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![], // No siblings
            timestamp: SystemTime::now(),
            signature: vec![],
            membership_proof: None,
            sequence_number: 1,
        };

        let result = validator.validate_broadcast(&broadcast);
        assert!(!result.is_valid);
        assert!(
            result
                .failures
                .contains(&BroadcastValidationFailure::TooFewSiblings)
        );
    }

    #[test]
    fn test_low_overlap_detected() {
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

        // Create broadcast with different siblings (no overlap)
        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![
                SignedSiblingEntry {
                    node: create_test_node(),
                    distance: random_key(),
                    sibling_signature: None,
                    last_seen: SystemTime::now(),
                },
                SignedSiblingEntry {
                    node: create_test_node(),
                    distance: random_key(),
                    sibling_signature: None,
                    last_seen: SystemTime::now(),
                },
            ],
            timestamp: SystemTime::now(),
            signature: vec![],
            membership_proof: None,
            sequence_number: 1,
        };

        let result = validator.validate_broadcast(&broadcast);
        assert!(result.eclipse_suspected);
        assert!(
            result
                .failures
                .contains(&BroadcastValidationFailure::LowOverlap)
        );
    }

    #[test]
    fn test_missing_membership_proof() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::new(
            SiblingBroadcastConfig {
                min_siblings: 1,
                require_membership_proof: true,
                ..Default::default()
            },
            position,
        );

        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![SignedSiblingEntry {
                node: create_test_node(),
                distance: random_key(),
                sibling_signature: None,
                last_seen: SystemTime::now(),
            }],
            timestamp: SystemTime::now(),
            signature: vec![],
            membership_proof: None, // Missing!
            sequence_number: 1,
        };

        let result = validator.validate_broadcast(&broadcast);
        assert!(!result.is_valid);
        assert!(
            result
                .failures
                .contains(&BroadcastValidationFailure::MissingMembershipProof)
        );
    }

    #[test]
    fn test_valid_broadcast() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::new(
            SiblingBroadcastConfig {
                min_siblings: 2,
                require_membership_proof: false,
                min_overlap_ratio: 0.0, // Don't require overlap for this test
                ..Default::default()
            },
            position,
        );

        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![
                SignedSiblingEntry {
                    node: create_test_node(),
                    distance: random_key(),
                    sibling_signature: None,
                    last_seen: SystemTime::now(),
                },
                SignedSiblingEntry {
                    node: create_test_node(),
                    distance: random_key(),
                    sibling_signature: None,
                    last_seen: SystemTime::now(),
                },
            ],
            timestamp: SystemTime::now(),
            signature: vec![],
            membership_proof: None,
            sequence_number: 1,
        };

        let result = validator.validate_broadcast(&broadcast);
        assert!(result.is_valid);
        assert_eq!(result.valid_siblings, 2);
    }

    #[test]
    fn test_builder() {
        let broadcaster = random_peer_id();
        let position = random_key();

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        let broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(broadcaster, position)
            .add_sibling(sibling)
            .sequence_number(42)
            .build()
            .expect("Should build successfully");

        assert_eq!(broadcast.broadcaster, broadcaster);
        assert_eq!(broadcast.sequence_number, 42);
        assert_eq!(broadcast.siblings.len(), 1);
    }

    #[test]
    fn test_sequence_validation() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::with_defaults(position);

        let peer = random_peer_id();

        // First broadcast with seq 1
        validator
            .recent_broadcasts
            .push_back((peer, 1, SystemTime::now()));

        // Seq 2 should be valid
        assert!(validator.is_valid_sequence(&peer, 2));

        // Seq 1 should be invalid (replay)
        assert!(!validator.is_valid_sequence(&peer, 1));

        // Seq 0 should be invalid
        assert!(!validator.is_valid_sequence(&peer, 0));
    }

    #[test]
    fn test_duplicate_entries_rejected() {
        let position = random_key();
        let mut validator = SiblingBroadcastValidator::new(
            SiblingBroadcastConfig {
                min_siblings: 2,
                require_membership_proof: false,
                min_overlap_ratio: 0.0,
                ..Default::default()
            },
            position,
        );

        let node = create_test_node();

        // Same node twice
        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![
                SignedSiblingEntry {
                    node: node.clone(),
                    distance: random_key(),
                    sibling_signature: None,
                    last_seen: SystemTime::now(),
                },
                SignedSiblingEntry {
                    node, // Duplicate!
                    distance: random_key(),
                    sibling_signature: None,
                    last_seen: SystemTime::now(),
                },
            ],
            timestamp: SystemTime::now(),
            signature: vec![],
            membership_proof: None,
            sequence_number: 1,
        };

        let result = validator.validate_broadcast(&broadcast);
        assert!(!result.is_valid);
        assert!(
            result
                .failures
                .contains(&BroadcastValidationFailure::DuplicateEntries)
        );
    }

    // ==========================================================================
    // ML-DSA-65 Signature Verification Tests
    // ==========================================================================

    #[test]
    fn test_build_and_sign_creates_valid_signature() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
        let broadcaster = random_peer_id();
        let position = random_key();

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        let broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(broadcaster, position)
            .add_sibling(sibling)
            .sequence_number(1)
            .build_and_sign(&secret_key)
            .expect("Should build and sign successfully");

        // Signature should not be empty
        assert!(!broadcast.signature.is_empty());
        assert_eq!(broadcast.broadcaster, broadcaster);

        // Verify the signature is valid
        let validator = SiblingBroadcastValidator::with_defaults(random_key());
        let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_verify_signature_rejects_wrong_key() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

        // Generate two different keypairs
        let (_public_key1, secret_key1) = generate_ml_dsa_keypair().unwrap();
        let (public_key2, _secret_key2) = generate_ml_dsa_keypair().unwrap();

        let broadcaster = random_peer_id();
        let position = random_key();

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        // Sign with key1
        let broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(broadcaster, position)
            .add_sibling(sibling)
            .sequence_number(1)
            .build_and_sign(&secret_key1)
            .expect("Should build and sign successfully");

        // Try to verify with key2 - should fail
        let validator = SiblingBroadcastValidator::with_defaults(random_key());
        let is_valid = validator.verify_signature(&broadcast, public_key2.as_bytes());
        assert!(!is_valid, "Signature should be invalid with wrong key");
    }

    #[test]
    fn test_verify_signature_rejects_tampered_data() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

        let (public_key, secret_key) = generate_ml_dsa_keypair().unwrap();
        let broadcaster = random_peer_id();
        let position = random_key();

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        let mut broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(broadcaster, position)
            .add_sibling(sibling)
            .sequence_number(1)
            .build_and_sign(&secret_key)
            .expect("Should build and sign successfully");

        // Tamper with the sequence number
        broadcast.sequence_number = 999;

        // Verification should fail
        let validator = SiblingBroadcastValidator::with_defaults(random_key());
        let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
        assert!(!is_valid, "Signature should be invalid after tampering");
    }

    #[test]
    fn test_verify_signature_rejects_empty_signature() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

        let (public_key, _secret_key) = generate_ml_dsa_keypair().unwrap();

        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster: random_peer_id(),
            broadcaster_position: random_key(),
            siblings: vec![SignedSiblingEntry {
                node: create_test_node(),
                distance: random_key(),
                sibling_signature: None,
                last_seen: SystemTime::now(),
            }],
            timestamp: SystemTime::now(),
            signature: vec![], // Empty signature
            membership_proof: None,
            sequence_number: 1,
        };

        let validator = SiblingBroadcastValidator::with_defaults(random_key());
        let is_valid = validator.verify_signature(&broadcast, public_key.as_bytes());
        assert!(!is_valid, "Empty signature should be rejected");
    }

    #[test]
    fn test_verify_signature_rejects_invalid_public_key() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

        let (_public_key, secret_key) = generate_ml_dsa_keypair().unwrap();

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        let broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(random_peer_id(), random_key())
            .add_sibling(sibling)
            .sequence_number(1)
            .build_and_sign(&secret_key)
            .expect("Should build and sign successfully");

        // Try to verify with garbage public key
        let validator = SiblingBroadcastValidator::with_defaults(random_key());
        let is_valid = validator.verify_signature(&broadcast, &[0u8; 32]);
        assert!(!is_valid, "Invalid public key should be rejected");
    }

    #[test]
    fn test_validate_broadcast_with_signature_success() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

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

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        let broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(random_peer_id(), random_key())
            .add_sibling(sibling)
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

    #[test]
    fn test_validate_broadcast_with_signature_rejects_invalid() {
        use crate::quantum_crypto::saorsa_transport_integration::generate_ml_dsa_keypair;

        let (_public_key1, secret_key1) = generate_ml_dsa_keypair().unwrap();
        let (public_key2, _secret_key2) = generate_ml_dsa_keypair().unwrap();
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

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: SystemTime::now(),
        };

        // Sign with key1
        let broadcast = SiblingBroadcastBuilder::new()
            .broadcaster(random_peer_id(), random_key())
            .add_sibling(sibling)
            .sequence_number(1)
            .build_and_sign(&secret_key1)
            .expect("Should build and sign successfully");

        // Validate with key2 - should fail with InvalidSignature
        let result =
            validator.validate_broadcast_with_signature(&broadcast, public_key2.as_bytes());
        assert!(!result.is_valid);
        assert!(
            result
                .failures
                .contains(&BroadcastValidationFailure::InvalidSignature)
        );
    }

    #[test]
    fn test_to_bytes_for_signing_deterministic() {
        let broadcaster = random_peer_id();
        let position = random_key();
        let timestamp = SystemTime::now();

        let sibling = SignedSiblingEntry {
            node: create_test_node(),
            distance: random_key(),
            sibling_signature: None,
            last_seen: timestamp,
        };

        let broadcast = AuthenticatedSiblingBroadcast {
            broadcaster,
            broadcaster_position: position,
            siblings: vec![sibling.clone()],
            timestamp,
            signature: vec![1, 2, 3], // Different signature
            membership_proof: None,
            sequence_number: 42,
        };

        let broadcast2 = AuthenticatedSiblingBroadcast {
            broadcaster,
            broadcaster_position: position,
            siblings: vec![sibling],
            timestamp,
            signature: vec![4, 5, 6], // Different signature
            membership_proof: None,
            sequence_number: 42,
        };

        // to_bytes_for_signing should not include signature
        let bytes1 = broadcast.to_bytes_for_signing();
        let bytes2 = broadcast2.to_bytes_for_signing();

        assert_eq!(
            bytes1, bytes2,
            "Serialization should be deterministic and exclude signature"
        );
    }
}
