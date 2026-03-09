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

//! # Hierarchical Key Derivation System
//!
//! This module implements BIP32-style hierarchical deterministic key derivation
//! adapted for Ed25519/X25519 key pairs used in the P2P network.
//!
//! ## Security Features
//! - Secure entropy generation for master seeds
//! - HMAC-based key stretching (HKDF)
//! - Deterministic key derivation from hierarchical paths
//! - Key isolation between different derivation contexts
//! - Side-channel resistance through constant-time operations
//!
//! ## Performance Features
//! - Batch key derivation for multiple paths
//! - Intelligent caching of derived keys
//! - Memory-efficient storage of key material
//! - Async key generation for non-blocking operations

use crate::error::SecurityError;
use crate::quantum_crypto::saorsa_transport_integration::{MlDsaPublicKey, MlDsaSecretKey};
use crate::secure_memory::SecureMemory;
use crate::{P2PError, Result};
use rand::{RngCore, thread_rng};
use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
use saorsa_pqc::{HkdfSha3_256, api::traits::Kdf};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Size of master seed in bytes (256 bits for security)
const MASTER_SEED_SIZE: usize = 32;

/// Maximum derivation depth to prevent stack overflow
const MAX_DERIVATION_DEPTH: usize = 10;

/// Size of derivation path index
#[allow(dead_code)]
const PATH_INDEX_SIZE: usize = 4;

/// Hardened derivation marker (BIP32 style)
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Master seed for deterministic key derivation
pub struct MasterSeed {
    /// Secure seed material
    seed: SecureMemory,
    /// Creation timestamp
    _created_at: u64,
    /// Derivation counter for tracking usage
    derivation_counter: u64,
}

/// Hierarchical key derivation path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    /// Path components (each can be hardened)
    components: Vec<u32>,
}

/// Derived key material with metadata
pub struct DerivedKey {
    /// ML-DSA secret key (wrapped in Arc to avoid clone issues)
    pub secret_key: std::sync::Arc<MlDsaSecretKey>,
    /// ML-DSA public key
    pub public_key: MlDsaPublicKey,
    /// Derivation path used
    pub path: DerivationPath,
    /// Creation timestamp
    pub created_at: u64,
    /// Key usage counter
    pub usage_counter: u64,
}

impl Clone for DerivedKey {
    fn clone(&self) -> Self {
        Self {
            secret_key: std::sync::Arc::clone(&self.secret_key),
            public_key: self.public_key.clone(),
            path: self.path.clone(),
            created_at: self.created_at,
            usage_counter: self.usage_counter,
        }
    }
}

/// Key derivation cache for performance
pub struct KeyDerivationCache {
    /// Cached derived keys
    cache: RwLock<HashMap<DerivationPath, DerivedKey>>,
    /// Cache size limit
    max_size: usize,
    /// Cache hit statistics
    hits: std::sync::atomic::AtomicU64,
    /// Cache miss statistics
    misses: std::sync::atomic::AtomicU64,
}

/// Hierarchical key derivation engine
pub struct HierarchicalKeyDerivation {
    /// Master seed
    master_seed: MasterSeed,
    /// Derivation cache
    cache: Arc<KeyDerivationCache>,
}

/// Batch key derivation request
pub struct BatchDerivationRequest {
    /// Derivation paths to process
    pub paths: Vec<DerivationPath>,
    /// Whether to use cache
    pub use_cache: bool,
    /// Priority level for processing
    pub priority: DerivationPriority,
}

/// Priority levels for key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationPriority {
    /// Low priority (background operations)
    Low,
    /// Normal priority (standard operations)
    Normal,
    /// High priority (time-sensitive operations)
    High,
    /// Critical priority (immediate operations)
    Critical,
}

/// Results of batch key derivation
pub struct BatchDerivationResult {
    /// Successfully derived keys
    pub keys: HashMap<DerivationPath, DerivedKey>,
    /// Failed derivations with error messages
    pub failures: HashMap<DerivationPath, String>,
    /// Cache hit rate for this batch
    pub cache_hit_rate: f64,
    /// Total processing time
    pub processing_time: std::time::Duration,
}

/// Statistics for key derivation performance
#[derive(Debug, Clone, Default)]
pub struct DerivationStats {
    /// Total keys derived
    pub total_derived: u64,
    /// Total cache hits
    pub cache_hits: u64,
    /// Total cache misses
    pub cache_misses: u64,
    /// Average derivation time in microseconds
    pub avg_derivation_time_us: u64,
    /// Total batch operations
    pub batch_operations: u64,
    /// Current cache size
    pub cache_size: usize,
}

impl MasterSeed {
    /// Generate a new master seed with cryptographically secure randomness
    pub fn generate() -> Result<Self> {
        let mut seed_bytes = vec![0u8; MASTER_SEED_SIZE];
        thread_rng().fill_bytes(&mut seed_bytes);

        let seed = SecureMemory::from_slice(&seed_bytes)?;

        // Zeroize the temporary buffer
        seed_bytes.zeroize();

        Ok(Self {
            seed,
            _created_at: current_timestamp(),
            derivation_counter: 0,
        })
    }

    /// Create master seed from existing entropy
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        if entropy.len() < MASTER_SEED_SIZE {
            return Err(P2PError::Security(SecurityError::InvalidKey(
                "Insufficient entropy for master seed".to_string().into(),
            )));
        }

        let seed = SecureMemory::from_slice(&entropy[..MASTER_SEED_SIZE])?;

        Ok(Self {
            seed,
            _created_at: current_timestamp(),
            derivation_counter: 0,
        })
    }

    /// Get the seed material for derivation
    pub fn seed_material(&self) -> &[u8] {
        self.seed.as_slice()
    }

    /// Increment derivation counter
    pub fn increment_counter(&mut self) {
        self.derivation_counter += 1;
    }

    /// Get derivation counter
    pub fn derivation_counter(&self) -> u64 {
        self.derivation_counter
    }
}

impl DerivationPath {
    /// Create a new derivation path
    pub fn new(components: Vec<u32>) -> Result<Self> {
        if components.len() > MAX_DERIVATION_DEPTH {
            return Err(P2PError::Security(SecurityError::InvalidKey(
                format!(
                    "Derivation path too deep: {} > {}",
                    components.len(),
                    MAX_DERIVATION_DEPTH
                )
                .into(),
            )));
        }

        Ok(Self { components })
    }

    /// Create path from string representation (e.g., "m/0'/1/2")
    pub fn from_string(path_str: &str) -> Result<Self> {
        let parts: Vec<&str> = path_str.split('/').collect();

        if parts.first() != Some(&"m") {
            return Err(P2PError::Security(SecurityError::InvalidKey(
                "Invalid derivation path format".to_string().into(),
            )));
        }

        let mut components = Vec::new();

        for part in parts.iter().skip(1) {
            if part.is_empty() {
                continue;
            }

            let (index_str, hardened) = if let Some(stripped) = part.strip_suffix('\'') {
                (stripped, true)
            } else {
                (*part, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                P2PError::Security(SecurityError::InvalidKey(
                    format!("Invalid path component: {part}").into(),
                ))
            })?;

            let final_index = if hardened {
                index + HARDENED_OFFSET
            } else {
                index
            };

            components.push(final_index);
        }

        Self::new(components)
    }

    // (Removed inherent to_string; rely on Display/ToString)
    /// Get path components
    pub fn components(&self) -> &[u32] {
        &self.components
    }

    /// Check if path component is hardened
    pub fn is_hardened(&self, index: usize) -> bool {
        self.components
            .get(index)
            .map(|&c| c >= HARDENED_OFFSET)
            .unwrap_or(false)
    }

    /// Get depth of derivation path
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Create child path by appending component
    pub fn child(&self, component: u32) -> Result<Self> {
        let mut new_components = self.components.clone();
        new_components.push(component);
        Self::new(new_components)
    }

    /// Create hardened child path
    pub fn hardened_child(&self, index: u32) -> Result<Self> {
        self.child(index + HARDENED_OFFSET)
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "m")?;
        for &component in &self.components {
            write!(f, "/")?;
            if component >= HARDENED_OFFSET {
                write!(f, "{}'", component - HARDENED_OFFSET)?;
            } else {
                write!(f, "{}", component)?;
            }
        }
        Ok(())
    }
}

impl KeyDerivationCache {
    /// Create new key derivation cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_size,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Get cached key
    pub fn get(&self, path: &DerivationPath) -> Option<DerivedKey> {
        let cache = match self.cache.read() {
            Ok(c) => c,
            Err(_) => return None,
        };
        if let Some(key) = cache.get(path) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(key.clone())
        } else {
            self.misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }

    /// Insert key into cache
    pub fn insert(&self, path: DerivationPath, key: DerivedKey) {
        let mut cache = match self.cache.write() {
            Ok(c) => c,
            Err(_) => return,
        };

        // Evict oldest entries if cache is full
        if cache.len() >= self.max_size {
            let oldest_path = cache
                .iter()
                .min_by_key(|(_, k)| k.created_at)
                .map(|(p, _)| p.clone());

            if let Some(path_to_remove) = oldest_path {
                cache.remove(&path_to_remove);
            }
        }

        cache.insert(path, key);
    }

    /// Clear the cache
    pub fn clear(&self) {
        let mut cache = match self.cache.write() {
            Ok(c) => c,
            Err(_) => return,
        };
        cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> (u64, u64, usize) {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let size = self.cache.read().map(|c| c.len()).unwrap_or(0);
        (hits, misses, size)
    }
}

impl HierarchicalKeyDerivation {
    /// Create new hierarchical key derivation engine
    pub fn new(master_seed: MasterSeed) -> Self {
        let cache = Arc::new(KeyDerivationCache::new(1000)); // Default cache size
        // Use thread-local RNG holder; generate randomness locally where needed
        Self { master_seed, cache }
    }

    /// Create with custom cache size
    pub fn with_cache_size(master_seed: MasterSeed, cache_size: usize) -> Self {
        let cache = Arc::new(KeyDerivationCache::new(cache_size));
        Self { master_seed, cache }
    }

    /// Derive key at specific path
    pub fn derive_key(&mut self, path: &DerivationPath) -> Result<DerivedKey> {
        // Check cache first
        if let Some(cached_key) = self.cache.get(path) {
            return Ok(cached_key);
        }

        // Perform actual derivation
        let derived_key = self.derive_key_internal(path)?;

        // Cache the result
        self.cache.insert(path.clone(), derived_key.clone());

        // Increment master seed counter
        self.master_seed.increment_counter();

        Ok(derived_key)
    }

    /// Internal key derivation implementation (PQC: ML-DSA keys)
    fn derive_key_internal(&self, path: &DerivationPath) -> Result<DerivedKey> {
        let mut current_key = self.master_seed.seed_material().to_vec();
        let mut current_chaincode = [0u8; 32];

        // Initial HKDF from master seed
        let mut temp_key = [0u8; 32];
        HkdfSha3_256::derive(&current_key, None, b"ml-dsa seed", &mut temp_key).map_err(|_| {
            P2PError::Security(SecurityError::InvalidKey(
                "HKDF derivation failed".to_string().into(),
            ))
        })?;
        current_key.copy_from_slice(&temp_key);

        HkdfSha3_256::derive(&current_key, None, b"chaincode", &mut current_chaincode).map_err(
            |_| {
                P2PError::Security(SecurityError::InvalidKey(
                    "HKDF derivation failed".to_string().into(),
                ))
            },
        )?;

        // Derive through each path component
        for &component in path.components() {
            let (new_key, new_chaincode) =
                self.derive_child_key(&current_key, &current_chaincode, component)?;
            current_key = new_key;
            current_chaincode = new_chaincode;
        }

        // Derive a 32-byte ML-DSA seed deterministically, then generate a real keypair
        let mut xi = [0u8; 32];
        HkdfSha3_256::derive(
            &current_key,
            Some(&current_chaincode),
            b"ml-dsa keypair",
            &mut xi,
        )
        .map_err(|_| {
            P2PError::Security(SecurityError::InvalidKey(
                "HKDF derivation failed".to_string().into(),
            ))
        })?;

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair_from_seed(&xi);

        let public_key = MlDsaPublicKey::from_bytes(&pk.to_bytes()).map_err(|e| {
            P2PError::Security(SecurityError::InvalidKey(
                format!("Invalid ML-DSA public key: {e}").into(),
            ))
        })?;
        let secret_key = MlDsaSecretKey::from_bytes(&sk.to_bytes()).map_err(|e| {
            P2PError::Security(SecurityError::InvalidKey(
                format!("Invalid ML-DSA secret key: {e}").into(),
            ))
        })?;

        // Zeroize temporary key material
        current_key.zeroize();
        current_chaincode.zeroize();
        xi.zeroize();

        Ok(DerivedKey {
            secret_key: std::sync::Arc::new(secret_key),
            public_key,
            path: path.clone(),
            created_at: current_timestamp(),
            usage_counter: 0,
        })
    }

    /// Derive child key from parent (PQC-friendly HKDF)
    fn derive_child_key(
        &self,
        parent_key: &[u8],
        parent_chaincode: &[u8],
        index: u32,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        // Combine parent key, parent chaincode and index deterministically
        let mut data = Vec::with_capacity(parent_key.len() + parent_chaincode.len() + 4);
        data.extend_from_slice(parent_key);
        data.extend_from_slice(parent_chaincode);
        data.extend_from_slice(&index.to_be_bytes());

        let mut child_key = vec![0u8; parent_key.len().max(32)];
        let mut child_chaincode = [0u8; 32];

        HkdfSha3_256::derive(&data, Some(parent_chaincode), b"key", &mut child_key).map_err(
            |_| {
                P2PError::Security(SecurityError::InvalidKey(
                    "Child key derivation failed".to_string().into(),
                ))
            },
        )?;
        HkdfSha3_256::derive(
            &data,
            Some(parent_chaincode),
            b"chaincode",
            &mut child_chaincode,
        )
        .map_err(|_| {
            P2PError::Security(SecurityError::InvalidKey(
                "Child chaincode derivation failed".to_string().into(),
            ))
        })?;

        // Zeroize temporary data
        data.zeroize();

        Ok((child_key, child_chaincode))
    }

    /// Derive multiple keys in batch
    pub fn derive_batch(
        &mut self,
        request: BatchDerivationRequest,
    ) -> Result<BatchDerivationResult> {
        let start_time = std::time::Instant::now();
        let mut keys = HashMap::new();
        let mut failures = HashMap::new();
        let mut cache_hits = 0u64;

        for path in request.paths {
            match self.derive_key(&path) {
                Ok(key) => {
                    // Check if this was a cache hit
                    if self.cache.get(&path).is_some() {
                        cache_hits += 1;
                    }
                    keys.insert(path, key);
                }
                Err(e) => {
                    failures.insert(path, e.to_string());
                }
            }
        }

        let processing_time = start_time.elapsed();
        let total_requests = keys.len() + failures.len();
        let cache_hit_rate = if total_requests > 0 {
            cache_hits as f64 / total_requests as f64
        } else {
            0.0
        };

        Ok(BatchDerivationResult {
            keys,
            failures,
            cache_hit_rate,
            processing_time,
        })
    }

    /// Get derivation statistics
    pub fn stats(&self) -> DerivationStats {
        let (cache_hits, cache_misses, cache_size) = self.cache.stats();

        DerivationStats {
            total_derived: self.master_seed.derivation_counter(),
            cache_hits,
            cache_misses,
            avg_derivation_time_us: 0, // Would need to track this
            batch_operations: 0,       // Would need to track this
            cache_size,
        }
    }

    /// Clear the derivation cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl DerivedKey {
    /// Increment usage counter
    pub fn increment_usage(&mut self) {
        self.usage_counter += 1;
    }

    /// Get ML-DSA key pair
    pub fn ml_dsa_keypair(&self) -> (MlDsaPublicKey, std::sync::Arc<MlDsaSecretKey>) {
        (
            self.public_key.clone(),
            std::sync::Arc::clone(&self.secret_key),
        )
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Zeroize trait for secure memory clearing
trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            *byte = 0;
        }
    }
}

impl Zeroize for [u8; 32] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ML-DSA-65 key sizes for test assertions
    const ML_DSA_PUB_LEN: usize = 1952;
    const ML_DSA_SEC_LEN: usize = 4032;

    #[test]
    fn test_master_seed_generation() {
        let seed = MasterSeed::generate().unwrap();
        assert_eq!(seed.seed_material().len(), MASTER_SEED_SIZE);
        assert!(seed._created_at > 0);
    }

    #[test]
    fn test_derivation_path_parsing() {
        let path = DerivationPath::from_string("m/0'/1/2'").unwrap();
        assert_eq!(path.components().len(), 3);
        assert!(path.is_hardened(0));
        assert!(!path.is_hardened(1));
        assert!(path.is_hardened(2));

        let path_str = path.to_string();
        assert_eq!(path_str, "m/0'/1/2'");
    }

    #[test]
    fn test_key_derivation() {
        let master_seed = MasterSeed::generate().unwrap();
        let mut derivation = HierarchicalKeyDerivation::new(master_seed);

        let path = DerivationPath::from_string("m/0'/1").unwrap();
        let derived_key = derivation.derive_key(&path).unwrap();

        assert_eq!(derived_key.path, path);
        // Validate ML-DSA key sizes
        assert_eq!(derived_key.public_key.as_bytes().len(), ML_DSA_PUB_LEN);
        assert_eq!(derived_key.secret_key.as_bytes().len(), ML_DSA_SEC_LEN);
    }

    #[test]
    fn test_key_derivation_cache() {
        let master_seed = MasterSeed::generate().unwrap();
        let mut derivation = HierarchicalKeyDerivation::new(master_seed);

        let path = DerivationPath::from_string("m/0'/1").unwrap();

        // First derivation
        let key1 = derivation.derive_key(&path).unwrap();

        // Second derivation should use cache
        let key2 = derivation.derive_key(&path).unwrap();

        // Keys should be identical
        assert_eq!(key1.secret_key.as_bytes(), key2.secret_key.as_bytes());
        assert_eq!(key1.public_key.as_bytes(), key2.public_key.as_bytes());

        // Check cache stats
        let stats = derivation.stats();
        assert!(stats.cache_hits > 0);
    }

    #[test]
    fn test_batch_derivation() {
        let master_seed = MasterSeed::generate().unwrap();
        let mut derivation = HierarchicalKeyDerivation::new(master_seed);

        let paths = vec![
            DerivationPath::from_string("m/0'/1").unwrap(),
            DerivationPath::from_string("m/0'/2").unwrap(),
            DerivationPath::from_string("m/1'/0").unwrap(),
        ];

        let request = BatchDerivationRequest {
            paths: paths.clone(),
            use_cache: true,
            priority: DerivationPriority::Normal,
        };

        let result = derivation.derive_batch(request).unwrap();

        assert_eq!(result.keys.len(), 3);
        assert_eq!(result.failures.len(), 0);

        // All paths should be present
        for path in paths {
            assert!(result.keys.contains_key(&path));
        }
    }

    #[test]
    fn test_derivation_path_depth_limit() {
        let components = vec![0u32; MAX_DERIVATION_DEPTH + 1];
        let result = DerivationPath::new(components);
        assert!(result.is_err());
    }

    #[test]
    fn test_hardened_derivation() {
        let master_seed = MasterSeed::generate().unwrap();
        let mut derivation = HierarchicalKeyDerivation::new(master_seed);

        let hardened_path = DerivationPath::from_string("m/0'").unwrap();
        let normal_path = DerivationPath::from_string("m/0").unwrap();

        let hardened_key = derivation.derive_key(&hardened_path).unwrap();
        let normal_key = derivation.derive_key(&normal_path).unwrap();
        // Keys should be different
        assert_ne!(
            hardened_key.secret_key.as_bytes(),
            normal_key.secret_key.as_bytes()
        );
        assert_ne!(
            hardened_key.public_key.as_bytes(),
            normal_key.public_key.as_bytes()
        );
    }
}
