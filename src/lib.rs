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

// Enforce no unwrap/expect/panic in production code only (tests can use them)
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![cfg_attr(not(test), warn(clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::panic))]
// Allow unused_async as many functions are async for API consistency
#![allow(clippy::unused_async)]

//! # Saorsa Core
//!
//! A next-generation peer-to-peer networking foundation built in Rust.
//!
//! ## Features
//!
//! - QUIC-based transport with NAT traversal
//! - IPv4-first with simple addressing
//! - Kademlia DHT for distributed routing
//! - Post-quantum cryptography (ML-DSA-65, ML-KEM-768)
//!
//! ## Example
//!
//! ```rust,ignore
//! use saorsa_core::{P2PNode, NodeConfig, MultiAddr};
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let addr = "127.0.0.1:9000".parse::<MultiAddr>()?;
//!     let node = P2PNode::builder()
//!         .listen_on(addr)
//!         .with_mcp_server()
//!         .build()
//!         .await?;
//!
//!     node.run().await?;
//!     Ok(())
//! }
//! ```

#![allow(missing_docs)]
#![allow(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

/// Key derivation and hashing utilities
pub mod fwid;

/// Prelude module for convenient imports
///
/// Use `use saorsa_core::prelude::*;` to import commonly used types.
pub mod prelude;

/// Network address types
pub mod address;

/// Network core functionality
pub mod network;

/// Distributed Hash Table implementation
pub mod dht;

/// DHT Network Integration Manager
pub mod dht_network_manager;

/// Transport handle: shared QUIC + peer + event state
pub mod transport_handle;

/// Transport layer (QUIC, TCP)
pub mod transport;

/// Authentication system for multi-writer records
pub mod auth;

/// Async event bus for watches and state changes
pub mod events;
/// MLS verifier adapter and proof format
pub mod mls;
/// Shared simple structs
pub mod types;

/// Telemetry for metrics and health signals
pub mod telemetry;

// MCP removed; will be redesigned later

/// Security and cryptography
pub mod security;

/// BGP-based GeoIP provider using open-source routing data
pub mod bgp_geo_provider;

/// User identity and privacy system
pub mod identity;

/// Threshold cryptography for group operations
pub mod threshold;

/// Quantum-resistant cryptography
pub mod quantum_crypto;

/// Utility functions and types
pub mod utils;

/// Validation framework for input sanitization and rate limiting
pub mod validation;

/// Unified rate limiting engine
pub mod rate_limit;

/// Production hardening features
pub mod production;

/// Bootstrap cache for decentralized peer discovery
pub mod bootstrap;

/// Error types
pub mod error;

/// Peer record system for DHT-based peer discovery
pub mod peer_record;

/// Monotonic counter system for replay attack prevention
pub mod monotonic_counter;

/// Secure memory management for cryptographic operations
pub mod secure_memory;

/// Hierarchical key derivation system
pub mod key_derivation;

/// Encrypted key storage with Argon2id and ChaCha20-Poly1305
pub mod encrypted_key_storage;

/// Persistent state management with crash recovery
pub mod persistent_state;

/// Adaptive P2P network implementation
pub mod adaptive;

/// Configuration management system
pub mod config;
pub mod control;

/// Health check system for monitoring and metrics
pub mod health;

/// Geographic-aware networking enhancements for P2P routing optimization
pub mod geographic_enhanced_network;

/// Placement Loop & Storage Orchestration System
pub mod placement;

/// Auto-upgrade system for cross-platform binary updates
pub mod upgrade;

// Re-export main types
pub use address::{AddressBook, MultiAddr};

// New spec-compliant API exports
pub use auth::{
    DelegatedWriteAuth, MlsWriteAuth, PubKey, Sig, SingleWriteAuth, ThresholdWriteAuth, WriteAuth,
};
pub use bootstrap::{BootstrapConfig, BootstrapManager, BootstrapStats};
pub use dht::Key;
pub use dht_network_manager::{
    DhtNetworkConfig, DhtNetworkEvent, DhtNetworkManager, DhtNetworkOperation, DhtNetworkResult,
};
pub use encrypted_key_storage::{
    Argon2Config, DerivationPriority as KeyDerivationPriority, EncryptedKeyStorageManager,
    KeyMetadata, PasswordValidation, SecurityLevel, StorageStats,
};
pub use error::{P2PError, P2pResult as Result, PeerFailureReason};
pub use events::{Subscription, TopologyEvent, device_subscribe, dht_watch, subscribe_topology};
pub use fwid::Key as FwKey;
pub use health::{
    ComponentChecker, ComponentHealth, HealthEndpoints, HealthManager, HealthResponse,
    HealthServer, HealthStatus, PrometheusExporter,
};
pub use key_derivation::{
    BatchDerivationRequest, BatchDerivationResult, DerivationPath, DerivationPriority,
    DerivationStats, DerivedKey, HierarchicalKeyDerivation, MasterSeed,
};
pub use monotonic_counter::{
    BatchUpdateRequest, BatchUpdateResult, CounterStats, MonotonicCounterSystem, PeerCounter,
    SequenceValidationResult,
};
pub use network::{
    ConnectionStatus, NetworkSender, NodeBuilder, NodeConfig, NodeMode, P2PEvent, P2PNode,
    PeerInfo, PeerResponse, is_dht_participant, user_agent_for_mode,
};
pub use transport_handle::TransportHandle;
// Trust system exports for saorsa-node integration
pub use adaptive::{EigenTrustEngine, NodeStatistics, NodeStatisticsUpdate, TrustProvider};
pub use telemetry::{Metrics, StreamClass, record_lookup, record_timeout, telemetry};
// Back-compat exports for tests
pub use config::Config;
pub use network::P2PNode as Node;
pub use peer_record::{EndpointId, NatType, PeerDHTRecord, PeerEndpoint, SignatureCache};
pub use persistent_state::{
    FlushStrategy, IntegrityReport, PersistentStateManager, RecoveryMode, RecoveryStats,
    StateChangeEvent, StateConfig, TransactionType, WalEntry,
};
pub use production::{ProductionConfig, ResourceManager, ResourceMetrics};
pub use secure_memory::{
    PoolStats, SecureMemory, SecureMemoryPool, SecureString, SecureVec, allocate_secure,
    secure_string_with_capacity, secure_vec_with_capacity,
};
pub use validation::{
    RateLimitConfig, RateLimiter, Sanitize, Validate, ValidationContext, ValidationError,
    sanitize_string, validate_dht_key, validate_dht_value, validate_file_path,
    validate_message_size, validate_network_address, validate_peer_id,
};

// Join rate limiting for Sybil protection
pub use rate_limit::{
    JoinRateLimitError, JoinRateLimiter, JoinRateLimiterConfig, extract_ipv4_subnet_8,
    extract_ipv4_subnet_16, extract_ipv4_subnet_24, extract_ipv6_subnet_32, extract_ipv6_subnet_48,
    extract_ipv6_subnet_64,
};

// Security and anti-Sybil exports (includes testnet configurations)
pub use dht::node_age_verifier::{
    AgeVerificationResult, NodeAgeCategory, NodeAgeConfig, NodeAgeRecord, NodeAgeStats,
    NodeAgeVerifier, OperationType,
};
pub use security::{
    DiversityStats, GeoInfo, GeoProvider, IPAnalysis, IPDiversityConfig, IPDiversityEnforcer,
    IPv4NodeID, IPv6NodeID, NodeReputation, ReputationManager, StubGeoProvider,
};

// Enhanced identity removed

// Threshold exports
pub use threshold::{
    GroupMetadata, ParticipantInfo, ThresholdGroup, ThresholdGroupManager, ThresholdSignature,
};

// Post-quantum cryptography exports (using saorsa-transport types exclusively)
pub use quantum_crypto::{
    CryptoCapabilities,
    KemAlgorithm,
    NegotiatedAlgorithms,
    ProtocolVersion,
    // Core types and errors (compatibility layer only)
    QuantumCryptoError,
    SignatureAlgorithm,
    // Functions (compatibility layer only)
    negotiate_algorithms,
};

// Saorsa-PQC exports (primary post-quantum crypto types)
pub use quantum_crypto::{
    // Symmetric encryption (quantum-resistant)
    ChaCha20Poly1305Cipher,
    // Encrypted message types
    EncryptedMessage,
    // Algorithm implementations
    MlDsa65,
    MlDsaOperations,
    // Use saorsa-transport types for better trait implementations
    MlDsaPublicKey as AntMlDsaPublicKey,
    MlDsaSecretKey as AntMlDsaSecretKey,
    MlDsaSignature as AntMlDsaSignature,
    MlKem768,
    MlKemCiphertext,
    // Core traits for operations
    MlKemOperations,
    // Key types
    MlKemPublicKey,
    MlKemSecretKey,
    // Errors and results
    PqcError,
    SaorsaPqcResult,
    SharedSecret,
    SymmetricEncryptedMessage,
    SymmetricError,
    SymmetricKey,
    // Configuration functions
    create_default_pqc_config,
    create_pqc_only_config,
    // Library initialization
    saorsa_pqc_init,
};

// Session and identity types
pub use quantum_crypto::types::{
    // FROST threshold signatures
    FrostCommitment,
    FrostGroupPublicKey,
    FrostKeyShare,
    FrostPublicKey,
    FrostSignature,
    // Session and group management types
    GroupId,
    HandshakeParameters,
    ParticipantId,
    PeerId as QuantumPeerId,
    QuantumPeerIdentity,
    SecureSession,
    SessionId,
    SessionState,
};

// Placement system exports
pub use crate::placement::{
    DataPointer, DhtRecord, DiversityEnforcer, GeographicLocation, GroupBeacon, NetworkRegion,
    NodeAd, PlacementConfig, PlacementDecision, PlacementEngine, PlacementMetrics, RegisterPointer,
    WeightedPlacementStrategy,
};

// Canonical peer identity type — 32-byte BLAKE3 hash of ML-DSA-65 public key.
pub use identity::peer_id::{PEER_ID_BYTE_LEN, PeerId, PeerIdParseError};

/// Saorsa Core version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default capacity for broadcast and mpsc event channels throughout the system.
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1000;

// Upgrade system exports
pub use upgrade::{
    ApplierConfig, ApplyResult, BackupMetadata, DownloadProgress, Downloader, DownloaderConfig,
    PinnedKey, Platform as UpgradePlatform, PlatformBinary, Release, ReleaseChannel,
    RollbackManager, SignatureVerifier, StagedUpdate, StagedUpdateManager, UpdateConfig,
    UpdateConfigBuilder, UpdateInfo, UpdateManager, UpdateManifest, UpdatePolicy, UpgradeError,
    UpgradeEvent, create_applier,
};
