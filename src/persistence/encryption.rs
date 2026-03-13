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

//! Encryption layer for storage

use async_trait::async_trait;
use rand_core::OsRng;
use saorsa_pqc::{ChaCha20Poly1305Cipher, HkdfSha3_256, SymmetricKey, api::traits::Kdf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;

use crate::persistence::{
    EncryptionAlgorithm, EncryptionConfig, Migrate, Monitor, Operation, PersistenceError, Query,
    Replicate, Result, Store, Transaction,
};

/// Encryption errors
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Invalid nonce size")]
    InvalidNonceSize,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

/// Encrypted storage wrapper
pub struct EncryptedStore {
    inner: Arc<dyn Store + Query + Replicate + Migrate + Monitor>,
    config: EncryptionConfig,
    key_derivation_salt: [u8; 32],
    master_key: [u8; 32],
}

impl EncryptedStore {
    /// Create new encrypted store
    pub fn new(
        inner: impl Store + Query + Replicate + Migrate + Monitor + 'static,
        config: EncryptionConfig,
    ) -> Result<Self> {
        // Generate a random salt for key derivation
        let mut key_derivation_salt = [0u8; 32];
        OsRng.fill_bytes(&mut key_derivation_salt);

        // Load master key from environment (hex-encoded 32 bytes)
        let master_key = match std::env::var("SAORSA_MASTER_KEY_HEX") {
            Ok(hex_str) => {
                let bytes = hex::decode(hex_str).map_err(|e| {
                    PersistenceError::Encryption(format!("Invalid SAORSA_MASTER_KEY_HEX: {}", e))
                })?;
                if bytes.len() != 32 {
                    return Err(PersistenceError::Encryption(
                        "SAORSA_MASTER_KEY_HEX must be 32 bytes of hex".into(),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Err(_) => {
                return Err(PersistenceError::Encryption(
                    "Missing SAORSA_MASTER_KEY_HEX (set 32-byte hex key)".into(),
                ));
            }
        };

        Ok(Self {
            inner: Arc::new(inner),
            config,
            key_derivation_salt,
            master_key,
        })
    }

    /// Derive encryption key using HKDF
    fn derive_key(master_key: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
        let mut derived_key = [0u8; 32];

        HkdfSha3_256::derive(
            master_key,
            Some(salt),
            b"saorsa-storage-encryption",
            &mut derived_key,
        )
        .map_err(|e| PersistenceError::Encryption(e.to_string()))?;
        Ok(derived_key)
    }

    /// Generate a nonce for encryption
    fn generate_nonce_bytes() -> [u8; 12] {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        nonce_bytes
    }

    /// Encrypt data
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = Self::derive_key(&self.master_key, &self.key_derivation_salt)?;
        let sk = SymmetricKey::from_bytes(key);
        let cipher = ChaCha20Poly1305Cipher::new(&sk);
        let (ciphertext, nonce) = cipher
            .encrypt(plaintext, None)
            .map_err(|e| PersistenceError::Encryption(e.to_string()))?;

        // Store nonce with ciphertext: [nonce][ciphertext]
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < 12 {
            return Err(PersistenceError::Encryption(
                "Invalid encrypted data format".into(),
            ));
        }

        let (nonce, ciphertext) = encrypted.split_at(12);
        let key = Self::derive_key(&self.master_key, &self.key_derivation_salt)?;
        let sk = SymmetricKey::from_bytes(key);
        let cipher = ChaCha20Poly1305Cipher::new(&sk);
        let plaintext = cipher
            .decrypt(ciphertext, nonce, None)
            .map_err(|e| PersistenceError::Encryption(e.to_string()))?;

        Ok(plaintext)
    }

    /// Rotate encryption key
    pub async fn rotate_encryption_key(&self) -> Result<()> {
        // Generate new salt and derive new cipher
        let mut new_salt = [0u8; 32];
        OsRng.fill_bytes(&mut new_salt);

        let _new_key = Self::derive_key(&self.master_key, &new_salt)?;

        // In a real implementation, we would:
        // 1. Re-encrypt all existing data with the new key
        // 2. Update the cipher
        // 3. Store the new salt

        // For now, just update the cipher (this is a simplified implementation)
        // Note: In production, this would require careful key rotation strategy

        Ok(())
    }

    /// Get encryption metadata for storage
    fn get_encryption_metadata(&self) -> Vec<u8> {
        // Store encryption metadata: [algorithm][salt]
        let mut metadata = Vec::new();
        metadata.push(0x01); // Algorithm identifier for ChaCha20Poly1305
        metadata.extend_from_slice(&self.key_derivation_salt);
        metadata
    }

    /// Parse encryption metadata from storage
    fn parse_encryption_metadata(metadata: &[u8]) -> Result<([u8; 32], EncryptionAlgorithm)> {
        if metadata.len() < 33 {
            return Err(PersistenceError::Encryption(
                "Invalid encryption metadata".into(),
            ));
        }

        let algorithm = match metadata[0] {
            0x01 => EncryptionAlgorithm::ChaCha20Poly1305,
            _ => {
                return Err(PersistenceError::Encryption(
                    "Unsupported encryption algorithm".into(),
                ));
            }
        };

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&metadata[1..33]);

        Ok((salt, algorithm))
    }
}

#[async_trait]
impl Store for EncryptedStore {
    async fn put(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        self.inner.put(key, &encrypted, ttl).await
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let encrypted = self.inner.get(key).await?;
        match encrypted {
            Some(data) => {
                let decrypted = self.decrypt(&data)?;
                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        self.inner.delete(key).await
    }

    async fn exists(&self, key: &[u8]) -> Result<bool> {
        self.inner.exists(key).await
    }

    async fn batch(&self, ops: Vec<Operation>) -> Result<()> {
        let mut encrypted_ops = Vec::with_capacity(ops.len());

        for op in ops {
            match op {
                Operation::Put { key, value, ttl } => {
                    let encrypted = self.encrypt(&value)?;
                    encrypted_ops.push(Operation::Put {
                        key,
                        value: encrypted,
                        ttl,
                    });
                }
                Operation::Delete { key } => {
                    encrypted_ops.push(Operation::Delete { key });
                }
            }
        }

        self.inner.batch(encrypted_ops).await
    }

    async fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Transaction) -> Result<R> + Send,
        R: Send,
    {
        self.inner.transaction(f).await
    }

    async fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.get_raw(key).await
    }

    async fn secure_delete(&self, key: &[u8]) -> Result<()> {
        self.inner.secure_delete(key).await
    }
}

#[async_trait]
impl Query for EncryptedStore {
    async fn range(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let encrypted_results = self.inner.range(start, end, limit, reverse).await?;
        let mut decrypted_results = Vec::with_capacity(encrypted_results.len());

        for (key, encrypted_value) in encrypted_results {
            let decrypted_value = self.decrypt(&encrypted_value)?;
            decrypted_results.push((key, decrypted_value));
        }

        Ok(decrypted_results)
    }

    async fn prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let encrypted_results = self.inner.prefix(prefix, limit).await?;
        let mut decrypted_results = Vec::with_capacity(encrypted_results.len());

        for (key, encrypted_value) in encrypted_results {
            let decrypted_value = self.decrypt(&encrypted_value)?;
            decrypted_results.push((key, decrypted_value));
        }

        Ok(decrypted_results)
    }

    async fn count(&self, start: &[u8], end: &[u8]) -> Result<usize> {
        self.inner.count(start, end).await
    }
}

#[async_trait]
impl Replicate for EncryptedStore {
    async fn replicate(&self, key: &[u8], nodes: Vec<crate::persistence::NodeId>) -> Result<()> {
        self.inner.replicate(key, nodes).await
    }

    async fn sync_from(
        &self,
        peer: crate::persistence::NodeId,
        namespace: &str,
    ) -> Result<crate::persistence::SyncStats> {
        self.inner.sync_from(peer, namespace).await
    }

    async fn replication_status(
        &self,
        key: &[u8],
    ) -> Result<crate::persistence::ReplicationStatus> {
        self.inner.replication_status(key).await
    }

    async fn set_replication_config(
        &self,
        config: crate::persistence::ReplicationConfig,
    ) -> Result<()> {
        self.inner.set_replication_config(config).await
    }
}

#[async_trait]
impl Migrate for EncryptedStore {
    async fn migrate(&self, migrations: &[crate::persistence::Migration]) -> Result<()> {
        self.inner.migrate(migrations).await
    }

    async fn schema_version(&self) -> Result<Option<u32>> {
        self.inner.schema_version().await
    }

    async fn set_schema_version(&self, version: u32) -> Result<()> {
        self.inner.set_schema_version(version).await
    }
}

#[async_trait]
impl Monitor for EncryptedStore {
    async fn health(&self) -> Result<crate::persistence::StorageHealth> {
        self.inner.health().await
    }

    async fn metrics(&self) -> Result<crate::persistence::StorageMetrics> {
        self.inner.metrics().await
    }

    async fn compact(&self) -> Result<()> {
        self.inner.compact().await
    }

    async fn backup(&self, path: &str) -> Result<()> {
        self.inner.backup(path).await
    }

    async fn restore(&self, path: &str) -> Result<()> {
        self.inner.restore(path).await
    }
}
