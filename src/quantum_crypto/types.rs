// Copyright 2024 Saorsa Labs Limited
//
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

//! Core types for quantum-resistant cryptography

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::SystemTime;

/// Peer identifier derived from quantum-resistant public key
///
/// Unique identifier for peers in the quantum-resistant P2P network.
/// Generated from a cryptographic hash of the peer's ML-DSA public key
/// to ensure uniqueness and prevent spoofing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub Vec<u8>);

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Unique identifier for threshold cryptography groups
///
/// 256-bit identifier for groups participating in threshold signature
/// schemes, distributed key generation, and quantum-resistant consensus.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Participant identifier within threshold cryptography groups
///
/// Numeric identifier for individual participants in threshold schemes.
/// Limited to u16 range to support groups up to 65,535 participants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub u16);

impl std::fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session identifier for cryptographic operations
///
/// 256-bit identifier for temporary cryptographic sessions including
/// key exchange, signature ceremonies, and secure communications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub [u8; 32]);

/// Complete quantum-resistant peer identity
///
/// Contains all cryptographic material needed for secure quantum-resistant
/// communication including post-quantum signatures and key exchange.
///
/// NOTE: This now uses saorsa-transport PQC types exclusively
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumPeerIdentity {
    /// Unique identifier for the peer
    pub peer_id: PeerId,

    /// ML-DSA (FIPS 204) public key for post-quantum digital signatures
    /// Use saorsa-transport::crypto::pqc::types::MlDsaPublicKey
    pub ml_dsa_public_key: Vec<u8>, // Serialized saorsa-transport MlDsaPublicKey

    /// ML-KEM (FIPS 203) public key for quantum-safe key exchange  
    /// Use saorsa-transport::crypto::pqc::types::MlKemPublicKey
    pub ml_kem_public_key: Vec<u8>, // Serialized saorsa-transport MlKemPublicKey

    /// Optional FROST public key for threshold operations
    pub frost_public_key: Option<FrostPublicKey>,

    /// Supported cryptographic capabilities
    pub capabilities: crate::quantum_crypto::CryptoCapabilities,

    /// Identity creation timestamp
    pub created_at: SystemTime,
}

/// FROST public key for threshold signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostPublicKey(pub Vec<u8>);

/// FROST group public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostGroupPublicKey(pub Vec<u8>);

/// FROST key share for a participant
#[derive(Clone)]
pub struct FrostKeyShare {
    pub participant_id: ParticipantId,
    pub share: Vec<u8>,
}

impl fmt::Debug for FrostKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrostKeyShare")
            .field("participant_id", &self.participant_id)
            .field("share", &"***")
            .finish()
    }
}

/// FROST commitment for verifiable secret sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostCommitment(pub Vec<u8>);

/// Ed25519 private key for testing (sensitive data)
#[derive(Clone)]
pub struct Ed25519PrivateKey(pub [u8; 64]);

impl serde::Serialize for Ed25519PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(
                "Ed25519PrivateKey must be 64 bytes",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Ed25519PrivateKey(arr))
    }
}

impl fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PrivateKey")
            .field("key", &"***")
            .finish()
    }
}

/// FROST signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostSignature(pub Vec<u8>);

/// Quantum-safe secure session
#[derive(Debug)]
pub struct SecureSession {
    /// Session identifier
    pub session_id: SessionId,

    /// Symmetric encryption key (derived from ML-KEM)
    pub encryption_key: [u8; 32],

    /// Message authentication key
    pub mac_key: [u8; 32],

    /// Remote peer identity
    pub peer_identity: QuantumPeerIdentity,

    /// Session establishment time
    pub established_at: SystemTime,

    /// Session state
    pub state: SessionState,

    /// Whether this is a threshold-capable session
    pub is_threshold_capable: bool,
}

/// Session state
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Handshake in progress
    Handshaking,

    /// Session established and active
    Active,

    /// Session closed
    Closed,
}

/// Handshake parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeParameters {
    pub kem_algorithm: crate::quantum_crypto::KemAlgorithm,
    pub signature_algorithm: crate::quantum_crypto::SignatureAlgorithm,
    pub protocol_version: crate::quantum_crypto::ProtocolVersion,
}

/// Key derivation info
pub struct KeyDerivationInfo {
    pub purpose: KeyPurpose,
    pub session_id: SessionId,
    pub additional_data: Vec<u8>,
}

/// Key purpose for derivation
#[derive(Debug, Clone, Copy)]
pub enum KeyPurpose {
    Encryption,
    Authentication,
    KeyWrapping,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_display() {
        let peer_id = PeerId(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        assert_eq!(format!("{}", peer_id), "123456789abcdef0");
    }

    #[test]
    fn test_sensitive_debug() -> Result<(), Box<dyn std::error::Error>> {
        // Test with Ed25519PrivateKey since ML-DSA types are now from saorsa-transport
        let private_key = Ed25519PrivateKey([0x42; 64]);
        let debug_str: String = format!("{:?}", private_key);
        assert!(!debug_str.contains("0x42"));
        assert!(debug_str.contains("***"));
        Ok(())
    }
}
