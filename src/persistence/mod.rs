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

//! Persistence layer for durable, encrypted, and replicated storage
//!
//! This module provides the core persistence functionality for the P2P network,
//! including storage backends, encryption, replication, and migration support.

pub mod backend;
pub mod encryption;
pub mod metrics;
pub mod migration;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Persistence layer errors
#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Corruption detected: {0}")]
    Corruption(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Replication failed: {0}")]
    Replication(String),

    #[error("Transaction aborted: {0}")]
    Transaction(String),

    #[error("Migration failed: {0}")]
    Migration(String),

    #[error("Storage full")]
    StorageFull,

    #[error("Key not found")]
    NotFound,

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, PersistenceError>;

/// Node identifier for replication
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeId(String);

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        NodeId(s.to_string())
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        NodeId(s)
    }
}

/// Storage operation for batch processing
#[derive(Debug, Clone)]
pub enum Operation {
    /// Put a key-value pair
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
        ttl: Option<Duration>,
    },
    /// Delete a key
    Delete { key: Vec<u8> },
}

/// Transaction handle for atomic operations
pub struct Transaction {
    operations: Vec<Operation>,
}

impl Transaction {
    /// Create a new transaction
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Add a put operation to the transaction
    pub fn put(&mut self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()> {
        self.operations.push(Operation::Put {
            key: key.to_vec(),
            value: value.to_vec(),
            ttl,
        });
        Ok(())
    }

    /// Add a delete operation to the transaction
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.operations
            .push(Operation::Delete { key: key.to_vec() });
        Ok(())
    }

    /// Get pending operations
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
}

/// Core storage trait for key-value operations
#[async_trait]
pub trait Store: Send + Sync {
    /// Put a key-value pair with optional TTL
    async fn put(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> Result<()>;

    /// Get a value by key
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Delete a key
    async fn delete(&self, key: &[u8]) -> Result<()>;

    /// Check if key exists
    async fn exists(&self, key: &[u8]) -> Result<bool>;

    /// Batch operations for efficiency
    async fn batch(&self, ops: Vec<Operation>) -> Result<()>;

    /// Transaction support
    async fn transaction<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Transaction) -> Result<R> + Send,
        R: Send;

    /// Get raw value without decryption (for debugging)
    async fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(key).await
    }

    /// Secure delete with overwriting
    async fn secure_delete(&self, key: &[u8]) -> Result<()> {
        // Overwrite with random data before deletion
        let random_data = vec![0u8; 32]; // Should use actual random data
        self.put(key, &random_data, Some(Duration::from_secs(0)))
            .await?;
        self.delete(key).await
    }
}

/// Query trait for range and prefix operations
#[async_trait]
pub trait Query: Store {
    /// Range query with pagination
    async fn range(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Prefix scan
    async fn prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Count keys in range
    async fn count(&self, start: &[u8], end: &[u8]) -> Result<usize>;
}

/// Replication status for a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    /// Number of replicas
    pub replica_count: usize,

    /// List of nodes holding replicas
    pub replica_nodes: Vec<NodeId>,

    /// Last sync time
    pub last_sync: SystemTime,

    /// Whether write quorum was met
    pub write_quorum_met: bool,

    /// Replication lag in milliseconds
    pub lag_ms: u64,
}

impl ReplicationStatus {
    /// Check if replication is healthy
    pub fn is_healthy(&self) -> bool {
        self.replica_count >= 3 && self.lag_ms < 1000
    }
}

/// Sync statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStats {
    /// Number of keys synced
    pub keys_synced: usize,

    /// Bytes transferred
    pub bytes_transferred: u64,

    /// Duration of sync
    pub duration: Duration,

    /// Errors encountered
    pub errors: Vec<String>,
}

/// Consistency level for operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    /// Wait for all replicas
    All,

    /// Wait for quorum (N/2 + 1)
    Quorum,

    /// Wait for one replica
    One,

    /// Fire and forget
    None,
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConflictResolver {
    /// Last write wins
    LastWriteWins,

    /// First write wins
    FirstWriteWins,

    /// Custom resolver function
    Custom,
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Number of replicas (default: 8)
    pub replication_factor: usize,

    /// Write consistency level
    pub write_consistency: ConsistencyLevel,

    /// Read consistency level  
    pub read_consistency: ConsistencyLevel,

    /// Conflict resolution
    pub conflict_resolver: ConflictResolver,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            replication_factor: 8,
            write_consistency: ConsistencyLevel::Quorum,
            read_consistency: ConsistencyLevel::One,
            conflict_resolver: ConflictResolver::LastWriteWins,
        }
    }
}

/// Replication trait for distributed storage
#[async_trait]
pub trait Replicate: Store {
    /// Replicate to peer nodes
    async fn replicate(&self, key: &[u8], nodes: Vec<NodeId>) -> Result<()>;

    /// Sync from peer
    async fn sync_from(&self, peer: NodeId, namespace: &str) -> Result<SyncStats>;

    /// Get replication status
    async fn replication_status(&self, key: &[u8]) -> Result<ReplicationStatus>;

    /// Set replication configuration
    async fn set_replication_config(&self, config: ReplicationConfig) -> Result<()>;
}

/// Key derivation function for encryption
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyDerivationFunction {
    /// Argon2 (recommended)
    Argon2,

    /// PBKDF2
    Pbkdf2,

    /// Scrypt
    Scrypt,
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// ChaCha20-Poly1305 (saorsa-pqc symmetric)
    ChaCha20Poly1305,
    /// No encryption (testing only)
    None,
}

/// Key rotation policy
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyRotationPolicy {
    /// Rotate after N days
    Days(u32),

    /// Rotate after N operations
    Operations(u64),

    /// Never rotate
    Never,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Master key derivation
    pub kdf: KeyDerivationFunction,

    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,

    /// Key rotation policy
    pub rotation: KeyRotationPolicy,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            kdf: KeyDerivationFunction::Argon2,
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            rotation: KeyRotationPolicy::Days(90),
        }
    }
}

/// Storage backend type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BackendType {
    /// RocksDB - high performance LSM tree
    RocksDb,

    /// SQLite - embedded SQL database
    Sqlite,

    /// Memory - in-memory storage
    Memory,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type
    pub backend: BackendType,

    /// Storage path
    pub path: Option<String>,

    /// Maximum storage size in bytes
    pub max_size: Option<u64>,

    /// Cache size in MB
    pub cache_size_mb: usize,

    /// Encryption configuration
    pub encryption: EncryptionConfig,

    /// Replication configuration
    pub replication: ReplicationConfig,

    /// Enable compression
    pub compression: bool,

    /// Sync policy
    pub sync_policy: SyncPolicy,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: BackendType::RocksDb,
            path: None,
            max_size: None,
            cache_size_mb: 128,
            encryption: EncryptionConfig::default(),
            replication: ReplicationConfig::default(),
            compression: true,
            sync_policy: SyncPolicy::default(),
        }
    }
}

/// Sync policy for durability
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SyncPolicy {
    /// Sync on every write (slowest, most durable)
    Always,

    /// Sync periodically
    Periodic(Duration),

    /// Never sync (fastest, least durable)
    Never,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        SyncPolicy::Periodic(Duration::from_secs(1))
    }
}

/// Migration for schema changes
pub struct Migration {
    /// Version number
    pub version: u32,

    /// Description
    pub description: String,

    /// Upgrade function
    pub up: fn(&dyn Store) -> Result<()>,

    /// Downgrade function
    pub down: fn(&dyn Store) -> Result<()>,
}

/// Migrate trait for schema evolution
#[async_trait]
pub trait Migrate: Store {
    /// Apply migrations
    async fn migrate(&self, migrations: &[Migration]) -> Result<()>;

    /// Get current schema version
    async fn schema_version(&self) -> Result<Option<u32>>;

    /// Set schema version
    async fn set_schema_version(&self, version: u32) -> Result<()>;
}

/// Health status
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Everything is working
    Healthy,

    /// Some issues but operational
    Degraded,

    /// Not operational
    Unhealthy,
}

/// Storage health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHealth {
    /// Overall status
    pub status: HealthStatus,

    /// Storage used in bytes
    pub storage_used: u64,

    /// Storage available in bytes
    pub storage_available: u64,

    /// Whether replication is healthy
    pub replication_healthy: bool,

    /// Last compaction time
    pub last_compaction: Option<SystemTime>,

    /// Error count
    pub error_count: u64,

    /// Performance metrics
    pub metrics: StorageMetrics,
}

/// Storage performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// Read operations per second
    pub read_ops_per_sec: f64,

    /// Write operations per second
    pub write_ops_per_sec: f64,

    /// Average read latency in microseconds
    pub read_latency_us: u64,

    /// Average write latency in microseconds
    pub write_latency_us: u64,

    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,

    /// Compaction backlog
    pub compaction_backlog: u64,
}

/// Monitor trait for health and metrics
#[async_trait]
pub trait Monitor: Store {
    /// Get storage health
    async fn health(&self) -> Result<StorageHealth>;

    /// Get performance metrics
    async fn metrics(&self) -> Result<StorageMetrics>;

    /// Trigger manual compaction
    async fn compact(&self) -> Result<()>;

    /// Create backup
    async fn backup(&self, path: &str) -> Result<()>;

    /// Restore from backup
    async fn restore(&self, path: &str) -> Result<()>;
}

/// Factory for creating storage instances
pub struct StorageFactory;

impl StorageFactory {
    /// Create a new storage instance with configuration
    pub async fn create(
        config: StorageConfig,
    ) -> Result<Arc<dyn Store + Query + Replicate + Migrate + Monitor>> {
        match config.backend {
            BackendType::RocksDb => backend::rocksdb::create_rocksdb_store(config).await,
            BackendType::Sqlite => backend::sqlite::create_sqlite_store(config).await,
            BackendType::Memory => backend::memory::create_memory_store(config).await,
        }
    }

    /// Create a test storage instance (memory backend)
    pub async fn create_test() -> Result<Arc<dyn Store + Query + Replicate + Migrate + Monitor>> {
        let config = StorageConfig {
            backend: BackendType::Memory,
            encryption: EncryptionConfig {
                algorithm: EncryptionAlgorithm::None,
                ..Default::default()
            },
            ..Default::default()
        };
        Self::create(config).await
    }
}

/// Re-export commonly used types
pub use backend::{MemoryStore, RocksDbStore, SqliteStore};
pub use encryption::EncryptedStore;
