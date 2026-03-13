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

//! Prelude module for convenient imports
//!
//! This module provides a single import for the most commonly used types
//! throughout the codebase.
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_core::prelude::*;
//! ```

// ============================================================================
// Core Types & Results
// ============================================================================

/// Core error type and result alias
pub use crate::error::{P2PError, P2pResult as Result};

/// Network address types
pub use crate::address::{AddressBook, MultiAddr};

// ============================================================================
// Network & Node Types
// ============================================================================

/// Node configuration and management
pub use crate::network::{
    ConnectionStatus, NodeConfig, NodeConfigBuilder, P2PEvent, P2PNode, PeerInfo,
};

/// Bootstrap management
pub use crate::bootstrap::{BootstrapConfig, BootstrapManager, BootstrapStats};

/// DHT types
pub use crate::dht::Key;

// ============================================================================
// Identity & Authentication
// ============================================================================

/// Write authorization types
pub use crate::auth::{
    DelegatedWriteAuth, MlsWriteAuth, PubKey, Sig, SingleWriteAuth, ThresholdWriteAuth, WriteAuth,
};

/// Peer record types
pub use crate::peer_record::{EndpointId, NatType, PeerDHTRecord, PeerEndpoint, SignatureCache};

// ============================================================================
// Post-Quantum Cryptography
// ============================================================================

/// Core PQC types from saorsa-pqc
pub use crate::quantum_crypto::{
    // Symmetric encryption
    ChaCha20Poly1305Cipher,
    EncryptedMessage,
    // ML-DSA (signatures)
    MlDsa65,
    MlDsaOperations,
    MlDsaPublicKey as AntMlDsaPublicKey,
    MlDsaSecretKey as AntMlDsaSecretKey,
    MlDsaSignature as AntMlDsaSignature,
    // ML-KEM (key encapsulation)
    MlKem768,
    MlKemCiphertext,
    MlKemOperations,
    MlKemPublicKey,
    MlKemSecretKey,
    // Errors
    PqcError,
    QuantumCryptoError,
    SaorsaPqcResult,
    SharedSecret,
    SymmetricEncryptedMessage,
    SymmetricError,
    SymmetricKey,
    // Configuration
    create_default_pqc_config,
    create_pqc_only_config,
    saorsa_pqc_init,
};

/// PQC capability negotiation
pub use crate::quantum_crypto::{
    CryptoCapabilities, KemAlgorithm, NegotiatedAlgorithms, ProtocolVersion, SignatureAlgorithm,
    negotiate_algorithms,
};

// ============================================================================
// Security & Sybil Protection
// ============================================================================

/// IP diversity and anti-Sybil
pub use crate::security::{
    DiversityStats, GeoInfo, GeoProvider, IPAnalysis, IPDiversityConfig, IPDiversityEnforcer,
    IPv4NodeID, IPv6NodeID, NodeReputation, ReputationManager, StubGeoProvider,
};

/// Node age verification
pub use crate::dht::node_age_verifier::{
    AgeVerificationResult, NodeAgeCategory, NodeAgeConfig, NodeAgeRecord, NodeAgeStats,
    NodeAgeVerifier, OperationType,
};

// ============================================================================
// State Management
// ============================================================================

/// Secure memory management
pub use crate::secure_memory::{
    PoolStats, SecureMemory, SecureMemoryPool, SecureString, SecureVec, allocate_secure,
    secure_string_with_capacity, secure_vec_with_capacity,
};

// ============================================================================
// Validation & Rate Limiting
// ============================================================================

/// Input validation
pub use crate::validation::{
    RateLimitConfig, RateLimiter, Sanitize, Validate, ValidationContext, ValidationError,
    sanitize_string, validate_dht_key, validate_dht_value, validate_file_path,
    validate_message_size, validate_network_address, validate_peer_id,
};

/// Join rate limiting
pub use crate::rate_limit::{
    JoinRateLimitError, JoinRateLimiter, JoinRateLimiterConfig, extract_ipv4_subnet_8,
    extract_ipv4_subnet_16, extract_ipv4_subnet_24, extract_ipv6_subnet_32, extract_ipv6_subnet_48,
    extract_ipv6_subnet_64,
};

// ============================================================================
// Adaptive Networking
// ============================================================================

pub use crate::PeerId;
/// Adaptive network types
pub use crate::adaptive::{
    // Traits
    AdaptiveNetworkNode,
    // Core types
    ContentHash,
    // Learning context
    ContentType,
    HyperbolicCoordinate,
    LearningContext,
    LearningMetrics,
    LearningSystem,
    NetworkConditions,
    NetworkMessage,
    NetworkStats,
    NodeCapabilities,
    NodeDescriptor,
    Outcome,
    RoutingStrategy,
    StrategyChoice,
    TrustProvider,
};

// ============================================================================
// Telemetry & Health
// ============================================================================

/// Metrics and telemetry
pub use crate::telemetry::{Metrics, StreamClass, record_lookup, record_timeout, telemetry};

/// Health monitoring
pub use crate::health::{
    ComponentChecker, ComponentHealth, HealthEndpoints, HealthManager, HealthResponse,
    HealthServer, HealthStatus, PrometheusExporter,
};

// ============================================================================
// Events & Subscriptions
// ============================================================================

/// Event system
pub use crate::events::{
    Subscription, TopologyEvent, device_subscribe, dht_watch, subscribe_topology,
};
