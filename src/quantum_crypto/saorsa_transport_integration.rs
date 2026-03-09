// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration with saorsa-transport's post-quantum cryptography
//!
//! This module provides integration with saorsa-transport 0.8.1's post-quantum
//! cryptography features, making them available to saorsa-core applications.

use anyhow::Result;
use once_cell::sync::Lazy;

// Re-export saorsa-transport PQC module and types for applications
pub use saorsa_transport::crypto::pqc;

// Re-export key saorsa-transport PQC types from types module
// Note: saorsa-transport 0.14+ is pure PQC only (no hybrid mode)
pub use saorsa_transport::crypto::pqc::types::{
    MlDsaPublicKey,
    MlDsaSecretKey,
    MlDsaSignature,
    MlKemCiphertext,
    MlKemPublicKey,
    MlKemSecretKey,
    // Error and result types
    PqcError,
    PqcResult,
    SharedSecret as PqcSharedSecret,
};

// Re-export config types and algorithm implementations
pub use saorsa_transport::crypto::pqc::{
    MlDsa65,
    MlKem768,
    // Additional enums and types
    NamedGroup,
    // Memory pool types for performance
    PoolConfig,
    PqcConfig,
    PqcConfigBuilder,
    PqcMemoryPool,
    SignatureScheme,
};

// Re-export PQC traits for advanced users
pub use saorsa_transport::crypto::pqc::{MlDsaOperations, MlKemOperations, PqcProvider};

static ML_DSA: Lazy<MlDsa65> = Lazy::new(MlDsa65::new);

static ML_KEM: Lazy<MlKem768> = Lazy::new(MlKem768::new);

/// Create a default PQC configuration with quantum-resistant algorithms enabled
/// Note: saorsa-transport 0.14+ is pure PQC - no hybrid mode available
pub fn create_default_pqc_config() -> Result<PqcConfig> {
    let config = PqcConfigBuilder::new()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC config: {}", e))?;

    Ok(config)
}

/// Create a PQC-only configuration (no classical algorithms)
/// Note: This is now the only mode in saorsa-transport 0.14+ (pure PQC)
pub fn create_pqc_only_config() -> Result<PqcConfig> {
    let config = PqcConfigBuilder::new()
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build PQC-only config: {}", e))?;

    Ok(config)
}

/// Generate ML-DSA-65 key pair using saorsa-transport's implementation
pub fn generate_ml_dsa_keypair() -> Result<(MlDsaPublicKey, MlDsaSecretKey)> {
    let (public_key, secret_key) = ML_DSA
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-DSA keypair: {}", e))?;
    Ok((public_key, secret_key))
}

/// Generate ML-KEM-768 key pair using saorsa-transport's implementation
pub fn generate_ml_kem_keypair() -> Result<(MlKemPublicKey, MlKemSecretKey)> {
    let (public_key, secret_key) = ML_KEM
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;
    Ok((public_key, secret_key))
}

/// Sign a message using ML-DSA-65 with saorsa-transport's implementation
pub fn ml_dsa_sign(secret_key: &MlDsaSecretKey, message: &[u8]) -> Result<MlDsaSignature> {
    ML_DSA
        .sign(secret_key, message)
        .map_err(|e| anyhow::anyhow!("Failed to sign with ML-DSA: {}", e))
}

/// Verify a signature using ML-DSA-65 with saorsa-transport's implementation
pub fn ml_dsa_verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool> {
    match ML_DSA.verify(public_key, message, signature) {
        Ok(is_valid) => Ok(is_valid),
        Err(e) => Err(anyhow::anyhow!("ML-DSA verification failed: {}", e)),
    }
}

/// Encapsulate a shared secret using ML-KEM-768 with saorsa-transport's implementation
pub fn ml_kem_encapsulate(
    public_key: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, PqcSharedSecret)> {
    ML_KEM
        .encapsulate(public_key)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with ML-KEM: {}", e))
}

/// Decapsulate a shared secret using ML-KEM-768 with saorsa-transport's implementation
pub fn ml_kem_decapsulate(
    secret_key: &MlKemSecretKey,
    ciphertext: &MlKemCiphertext,
) -> Result<PqcSharedSecret> {
    ML_KEM
        .decapsulate(secret_key, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate with ML-KEM: {}", e))
}

/// Create a PQC memory pool for performance optimization
pub fn create_pqc_memory_pool(config: PoolConfig) -> Result<PqcMemoryPool> {
    Ok(PqcMemoryPool::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_config_creation() {
        let config = create_default_pqc_config();
        assert!(config.is_ok(), "Should create default PQC config");

        let pqc_only_config = create_pqc_only_config();
        assert!(pqc_only_config.is_ok(), "Should create PQC-only config");
    }

    #[test]
    fn test_ml_dsa_roundtrip() {
        let keypair = generate_ml_dsa_keypair();
        assert!(keypair.is_ok(), "Should generate ML-DSA keypair");

        let (public_key, secret_key) = keypair.unwrap();
        let message = b"test message for ML-DSA";

        let signature = ml_dsa_sign(&secret_key, message);
        assert!(signature.is_ok(), "Should sign message with ML-DSA");

        let sig = signature.unwrap();
        let verification = ml_dsa_verify(&public_key, message, &sig);
        assert!(verification.is_ok(), "Should verify ML-DSA signature");
        assert!(verification.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_ml_kem_roundtrip() {
        let keypair = generate_ml_kem_keypair();
        assert!(keypair.is_ok(), "Should generate ML-KEM keypair");

        let (public_key, secret_key) = keypair.unwrap();

        let encapsulation = ml_kem_encapsulate(&public_key);
        assert!(encapsulation.is_ok(), "Should encapsulate with ML-KEM");

        let (ciphertext, shared_secret1) = encapsulation.unwrap();

        let decapsulation = ml_kem_decapsulate(&secret_key, &ciphertext);
        assert!(decapsulation.is_ok(), "Should decapsulate with ML-KEM");

        let shared_secret2 = decapsulation.unwrap();
        assert_eq!(
            shared_secret1.0, shared_secret2.0,
            "Shared secrets should match"
        );
    }

    #[test]
    fn test_pqc_memory_pool_creation() {
        let pool_config = PoolConfig::default();
        let pool = create_pqc_memory_pool(pool_config);
        assert!(pool.is_ok(), "Should create PQC memory pool");
    }
}
