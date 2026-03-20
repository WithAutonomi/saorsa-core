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

//! Security module
//!
//! This module provides cryptographic functionality and Sybil protection for the P2P network.
//! It implements IPv6-based node ID generation and IP diversity enforcement to prevent
//! large-scale Sybil attacks while maintaining network openness.

use crate::quantum_crypto::saorsa_transport_integration::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ml_dsa_sign, ml_dsa_verify,
};
use anyhow::{Result, anyhow};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::sync::Arc;

/// Maximum subnet tracking entries before evicting oldest (prevents memory DoS)
const MAX_SUBNET_TRACKING: usize = 50_000;

// ============================================================================
// Generic IP Address Trait
// ============================================================================

/// Trait for IP addresses that can be used in node ID generation
#[allow(dead_code)]
pub trait NodeIpAddress: Debug + Clone + Send + Sync + 'static {
    /// Get the octets of this IP address for hashing
    fn octets_vec(&self) -> Vec<u8>;
}

impl NodeIpAddress for Ipv6Addr {
    fn octets_vec(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

impl NodeIpAddress for Ipv4Addr {
    fn octets_vec(&self) -> Vec<u8> {
        self.octets().to_vec()
    }
}

// ============================================================================
// Generic IP-Based Node Identity
// ============================================================================

/// Generic IP-based node identity that binds node ID to network location
///
/// This struct provides a unified implementation for both IPv4 and IPv6
/// node identities, reducing code duplication while maintaining type safety.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct GenericIpNodeID<A: NodeIpAddress> {
    /// Derived node ID (BLAKE3 of ip_addr + public_key + salt + timestamp)
    pub node_id: Vec<u8>,
    /// IP address this node ID is bound to
    pub ip_addr: A,
    /// ML-DSA public key for signatures
    pub public_key: Vec<u8>,
    /// Signature proving ownership of the IP address and keys
    pub signature: Vec<u8>,
    /// Timestamp when this ID was generated (seconds since epoch)
    pub timestamp_secs: u64,
    /// Salt used in node ID generation (for freshness)
    pub salt: Vec<u8>,
}

#[allow(dead_code)]
impl<A: NodeIpAddress> GenericIpNodeID<A> {
    /// ML-DSA-65 signature length
    const SIGNATURE_LENGTH: usize = 3309;

    /// Generate a new IP-based node ID
    pub fn generate(ip_addr: A, secret: &MlDsaSecretKey, public: &MlDsaPublicKey) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut salt = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rng, &mut salt);

        let timestamp = SystemTime::now();
        let timestamp_secs = timestamp.duration_since(UNIX_EPOCH)?.as_secs();
        let public_key = public.as_bytes().to_vec();
        let ip_octets = ip_addr.octets_vec();

        // Generate node ID: BLAKE3(ip_address || public_key || salt || timestamp)
        let node_id = Self::compute_node_id(&ip_octets, &public_key, &salt, timestamp_secs);

        // Create signature proving ownership
        let message_to_sign = Self::build_message(&ip_octets, &public_key, &salt, timestamp_secs);
        let sig = ml_dsa_sign(secret, &message_to_sign)
            .map_err(|e| anyhow!("ML-DSA sign failed: {:?}", e))?;
        let signature = sig.0.to_vec();

        Ok(Self {
            node_id,
            ip_addr,
            public_key,
            signature,
            timestamp_secs,
            salt,
        })
    }

    /// Verify that this node ID is valid and properly signed
    pub fn verify(&self) -> Result<bool> {
        let ip_octets = self.ip_addr.octets_vec();

        // Reconstruct and verify node ID
        let expected_node_id = Self::compute_node_id(
            &ip_octets,
            &self.public_key,
            &self.salt,
            self.timestamp_secs,
        );

        if expected_node_id != self.node_id {
            return Ok(false);
        }

        // Verify signature
        let public_key = MlDsaPublicKey::from_bytes(&self.public_key)
            .map_err(|e| anyhow!("Invalid ML-DSA public key: {:?}", e))?;

        if self.signature.len() != Self::SIGNATURE_LENGTH {
            return Ok(false);
        }

        let mut sig_bytes = [0u8; 3309];
        sig_bytes.copy_from_slice(&self.signature);
        let signature = MlDsaSignature(Box::new(sig_bytes));

        let message_to_verify = Self::build_message(
            &ip_octets,
            &self.public_key,
            &self.salt,
            self.timestamp_secs,
        );

        let ok = ml_dsa_verify(&public_key, &message_to_verify, &signature)
            .map_err(|e| anyhow!("ML-DSA verify error: {:?}", e))?;
        Ok(ok)
    }

    /// Get the age of this node ID in seconds
    pub fn age_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.timestamp_secs)
    }

    /// Check if the node ID has expired (older than max_age)
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.age_secs() > max_age.as_secs()
    }

    // Internal helpers

    #[inline]
    fn compute_node_id(
        ip_octets: &[u8],
        public_key: &[u8],
        salt: &[u8],
        timestamp_secs: u64,
    ) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ip_octets);
        hasher.update(public_key);
        hasher.update(salt);
        hasher.update(&timestamp_secs.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    }

    #[inline]
    fn build_message(
        ip_octets: &[u8],
        public_key: &[u8],
        salt: &[u8],
        timestamp_secs: u64,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(ip_octets.len() + public_key.len() + salt.len() + 8);
        message.extend_from_slice(ip_octets);
        message.extend_from_slice(public_key);
        message.extend_from_slice(salt);
        message.extend_from_slice(&timestamp_secs.to_le_bytes());
        message
    }
}

// ============================================================================
// Backward-Compatible Type Aliases and Wrappers
// ============================================================================

/// IPv6-based node identity that binds node ID to actual network location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct IPv6NodeID {
    /// Derived node ID (BLAKE3 of ipv6_addr + public_key + salt)
    pub node_id: Vec<u8>,
    /// IPv6 address this node ID is bound to
    pub ipv6_addr: Ipv6Addr,
    /// ML-DSA public key for signatures
    pub public_key: Vec<u8>,
    /// Signature proving ownership of the IPv6 address and keys
    pub signature: Vec<u8>,
    /// Timestamp when this ID was generated (seconds since epoch)
    pub timestamp_secs: u64,
    /// Salt used in node ID generation (for freshness)
    pub salt: Vec<u8>,
}

/// Configuration for IP diversity enforcement at multiple subnet levels.
///
/// Limits are applied **per-bucket** and **per-close-group** (the K closest
/// nodes to self), matching how geographic diversity is enforced.  When a
/// candidate would exceed a limit, it may still be admitted via swap-closer
/// logic: if the candidate is closer (XOR distance) to self than the
/// farthest same-subnet peer in the scope, that farther peer is evicted.
///
/// The dynamic per-IP formula uses the *global* network size for stability,
/// but counting happens within each scope independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPDiversityConfig {
    // === IPv6 subnet limits ===
    /// Maximum nodes per /64 subnet within a single k-bucket or
    /// close group (default: 1).
    pub max_nodes_per_ipv6_64: usize,
    /// Maximum nodes per /48 allocation within a single k-bucket or
    /// close group (default: 3).
    pub max_nodes_per_ipv6_48: usize,
    /// Maximum nodes per /32 region within a single k-bucket or
    /// close group (default: 10).
    pub max_nodes_per_ipv6_32: usize,

    // === IPv4 subnet limits ===
    /// Optional cap for nodes per single IPv4 address (/32) within a
    /// single k-bucket or close group.  When `None` (default), the
    /// dynamic per-IP limit is used alone.  When `Some(n)`, the
    /// effective limit is `min(n, dynamic_per_ip)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes_per_ipv4_32: Option<usize>,
    /// Optional cap for nodes per /24 subnet (Class C) within a single
    /// k-bucket or close group.  When `None` (default),
    /// `dynamic_per_ip * 3` is used alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes_per_ipv4_24: Option<usize>,
    /// Optional cap for nodes per /16 subnet (Class B) within a single
    /// k-bucket or close group.  When `None` (default),
    /// `dynamic_per_ip * 10` is used alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes_per_ipv4_16: Option<usize>,

    // === Per-protocol limit overrides ===
    /// Optional floor for all IPv4 subnet limits (per-bucket / per-close-group).
    /// When set, the effective limit at every IPv4 prefix level (/32, /24, /16)
    /// will be at least this value, overriding the dynamic calculation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_limit_floor: Option<usize>,
    /// Optional ceiling for all IPv4 subnet limits (per-bucket / per-close-group).
    /// When set, the effective limit at every IPv4 prefix level will be at most
    /// this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_limit_ceiling: Option<usize>,
    /// Optional floor for all IPv6 subnet limits (per-bucket / per-close-group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_limit_floor: Option<usize>,
    /// Optional ceiling for all IPv6 subnet limits (per-bucket / per-close-group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_limit_ceiling: Option<usize>,

    // === Network-relative limits ===
    /// Absolute maximum nodes allowed per single IP (default: 50).
    /// Used in the global dynamic per-IP formula.
    pub max_per_ip_cap: usize,
    /// Maximum fraction of global network any single IP can represent
    /// (default: 0.005 = 0.5%).  Used in the dynamic per-IP formula.
    pub max_network_fraction: f64,

    // === ASN and GeoIP ===
    /// Maximum nodes per AS number (default: 20)
    pub max_nodes_per_asn: usize,
    /// Enable GeoIP-based diversity checks
    pub enable_geolocation_check: bool,
    /// Minimum number of different countries required
    pub min_geographic_diversity: usize,
}

/// Analysis of an IPv6 address for diversity enforcement
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IPAnalysis {
    /// Whether the original address is a loopback address (::1 or
    /// an IPv4-mapped loopback like ::ffff:127.0.0.1).
    #[serde(default)]
    pub is_loopback: bool,
    /// /64 subnet (host allocation)
    pub subnet_64: Ipv6Addr,
    /// /48 subnet (site allocation)
    pub subnet_48: Ipv6Addr,
    /// /32 subnet (ISP allocation)
    pub subnet_32: Ipv6Addr,
    /// Autonomous System Number (if available)
    pub asn: Option<u32>,
    /// Country code from GeoIP lookup
    pub country: Option<String>,
    /// Whether this is a known hosting/VPS provider
    pub is_hosting_provider: bool,
    /// Whether this is a known VPN provider
    pub is_vpn_provider: bool,
    /// Historical reputation score for this IP range
    pub reputation_score: f64,
}

/// Analysis of an IPv4 address for diversity enforcement
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct IPv4Analysis {
    /// The exact IPv4 address
    pub ip_addr: Ipv4Addr,
    /// /24 subnet (Class C equivalent)
    pub subnet_24: Ipv4Addr,
    /// /16 subnet (Class B equivalent)
    pub subnet_16: Ipv4Addr,
    /// /8 subnet (Class A equivalent)
    pub subnet_8: Ipv4Addr,
    /// Autonomous System Number (if available)
    pub asn: Option<u32>,
    /// Country code from GeoIP lookup
    pub country: Option<String>,
    /// Whether this is a known hosting/VPS provider
    pub is_hosting_provider: bool,
    /// Whether this is a known VPN provider
    pub is_vpn_provider: bool,
    /// Historical reputation score for this IP range
    pub reputation_score: f64,
}

/// Unified IP analysis that handles both IPv4 and IPv6 addresses
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum UnifiedIPAnalysis {
    /// IPv4 address analysis
    IPv4(IPv4Analysis),
    /// IPv6 address analysis
    IPv6(IPAnalysis),
}

impl Default for IPDiversityConfig {
    fn default() -> Self {
        Self {
            // IPv6 limits
            max_nodes_per_ipv6_64: 1,
            max_nodes_per_ipv6_48: 3,
            max_nodes_per_ipv6_32: 10,
            // IPv4 limits — None = purely dynamic (no static cap)
            max_nodes_per_ipv4_32: None,
            max_nodes_per_ipv4_24: None,
            max_nodes_per_ipv4_16: None,
            // Per-protocol overrides — None = no override
            ipv4_limit_floor: None,
            ipv4_limit_ceiling: None,
            ipv6_limit_floor: None,
            ipv6_limit_ceiling: None,
            // Network-relative limits
            max_per_ip_cap: 50,          // Hard cap of 50 nodes per IP
            max_network_fraction: 0.005, // 0.5% of network max
            // ASN and GeoIP
            max_nodes_per_asn: 20,
            enable_geolocation_check: true,
            min_geographic_diversity: 3,
        }
    }
}

impl IPDiversityConfig {
    /// Create a testnet configuration with relaxed diversity requirements.
    ///
    /// This is useful for testing environments like Digital Ocean where all nodes
    /// share the same ASN (AS14061). The relaxed limits allow many nodes from the
    /// same provider while still maintaining some diversity tracking.
    ///
    /// # Warning
    ///
    /// This configuration should NEVER be used in production as it significantly
    /// weakens Sybil attack protection.
    #[must_use]
    pub fn testnet() -> Self {
        Self {
            // IPv6 relaxed limits
            max_nodes_per_ipv6_64: 100,  // Allow many nodes per /64 subnet
            max_nodes_per_ipv6_48: 500,  // Allow many nodes per /48 allocation
            max_nodes_per_ipv6_32: 1000, // Allow many nodes per /32 region
            // IPv4 — guaranteed minimums prevent bootstrap deadlock when
            // many nodes share few public IPs (e.g. 10 nodes per VM).
            // Without these, the dynamic per-IP formula starts at 1 for
            // small networks and never grows past the number of unique IPs.
            max_nodes_per_ipv4_32: Some(100),
            max_nodes_per_ipv4_24: Some(500),
            max_nodes_per_ipv4_16: Some(1000),
            // Floors ensure small testnets (< 100 nodes) aren't bottlenecked
            // by the dynamic per-IP formula, which yields 1 for tiny networks.
            ipv4_limit_floor: Some(5),
            ipv4_limit_ceiling: None,
            ipv6_limit_floor: Some(5),
            ipv6_limit_ceiling: None,
            // Network-relative limits (relaxed for testnet)
            max_per_ip_cap: 100,       // Higher cap for testing
            max_network_fraction: 0.1, // Allow 10% of network from one IP (relaxed from 0.5%)
            // ASN and GeoIP
            max_nodes_per_asn: 5000, // Allow many nodes from same ASN (e.g., Digital Ocean)
            enable_geolocation_check: false, // Disable geo checks for testing
            min_geographic_diversity: 1, // Single region is acceptable for testing
        }
    }

    /// Create a permissive configuration that effectively disables diversity checks.
    ///
    /// This is useful for local development and unit testing where all nodes
    /// run on localhost or the same machine.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            // IPv6 - effectively disabled
            max_nodes_per_ipv6_64: usize::MAX,
            max_nodes_per_ipv6_48: usize::MAX,
            max_nodes_per_ipv6_32: usize::MAX,
            // IPv4 — no static caps
            max_nodes_per_ipv4_32: None,
            max_nodes_per_ipv4_24: None,
            max_nodes_per_ipv4_16: None,
            // Per-protocol overrides — None = no override
            ipv4_limit_floor: None,
            ipv4_limit_ceiling: None,
            ipv6_limit_floor: None,
            ipv6_limit_ceiling: None,
            // Network-relative - effectively disabled
            max_per_ip_cap: usize::MAX,
            max_network_fraction: 1.0, // Allow 100% of network
            // ASN and GeoIP
            max_nodes_per_asn: usize::MAX,
            enable_geolocation_check: false,
            min_geographic_diversity: 0,
        }
    }

    /// Check if this is a testnet or permissive configuration.
    #[must_use]
    pub fn is_relaxed(&self) -> bool {
        self.max_nodes_per_asn > 100 || !self.enable_geolocation_check
    }
}

#[allow(dead_code)]
impl IPv6NodeID {
    /// Generate a new IPv6-based node ID
    ///
    /// Delegates to `GenericIpNodeID` for the core generation logic.
    pub fn generate(
        ipv6_addr: Ipv6Addr,
        secret: &MlDsaSecretKey,
        public: &MlDsaPublicKey,
    ) -> Result<Self> {
        let generic = GenericIpNodeID::generate(ipv6_addr, secret, public)?;
        Ok(Self::from_generic(generic))
    }

    /// Verify that this node ID is valid and properly signed
    pub fn verify(&self) -> Result<bool> {
        self.to_generic().verify()
    }

    /// Extract /64 subnet from IPv6 address
    pub fn extract_subnet_64(&self) -> Ipv6Addr {
        let octets = self.ipv6_addr.octets();
        let mut subnet = [0u8; 16];
        subnet[..8].copy_from_slice(&octets[..8]);
        Ipv6Addr::from(subnet)
    }

    /// Extract /48 subnet from IPv6 address
    pub fn extract_subnet_48(&self) -> Ipv6Addr {
        let octets = self.ipv6_addr.octets();
        let mut subnet = [0u8; 16];
        subnet[..6].copy_from_slice(&octets[..6]);
        Ipv6Addr::from(subnet)
    }

    /// Extract /32 subnet from IPv6 address
    pub fn extract_subnet_32(&self) -> Ipv6Addr {
        let octets = self.ipv6_addr.octets();
        let mut subnet = [0u8; 16];
        subnet[..4].copy_from_slice(&octets[..4]);
        Ipv6Addr::from(subnet)
    }

    // Conversion helpers for delegation

    fn from_generic(g: GenericIpNodeID<Ipv6Addr>) -> Self {
        Self {
            node_id: g.node_id,
            ipv6_addr: g.ip_addr,
            public_key: g.public_key,
            signature: g.signature,
            timestamp_secs: g.timestamp_secs,
            salt: g.salt,
        }
    }

    fn to_generic(&self) -> GenericIpNodeID<Ipv6Addr> {
        GenericIpNodeID {
            node_id: self.node_id.clone(),
            ip_addr: self.ipv6_addr,
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
            timestamp_secs: self.timestamp_secs,
            salt: self.salt.clone(),
        }
    }
}

/// IPv4-based node identity that binds node ID to actual network location
/// Mirrors IPv6NodeID for security parity on IPv4 networks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct IPv4NodeID {
    /// Derived node ID (BLAKE3 of ipv4_addr + public_key + salt + timestamp)
    pub node_id: Vec<u8>,
    /// IPv4 address this node ID is bound to
    pub ipv4_addr: Ipv4Addr,
    /// ML-DSA public key for signatures
    pub public_key: Vec<u8>,
    /// Signature proving ownership of the IPv4 address and keys
    pub signature: Vec<u8>,
    /// Timestamp when this ID was generated (seconds since epoch)
    pub timestamp_secs: u64,
    /// Salt used in node ID generation (for freshness)
    pub salt: Vec<u8>,
}

#[allow(dead_code)]
impl IPv4NodeID {
    /// Generate a new IPv4-based node ID
    ///
    /// Delegates to `GenericIpNodeID` for the core generation logic.
    pub fn generate(
        ipv4_addr: Ipv4Addr,
        secret: &MlDsaSecretKey,
        public: &MlDsaPublicKey,
    ) -> Result<Self> {
        let generic = GenericIpNodeID::generate(ipv4_addr, secret, public)?;
        Ok(Self::from_generic(generic))
    }

    /// Verify that this node ID is valid and properly signed
    pub fn verify(&self) -> Result<bool> {
        self.to_generic().verify()
    }

    /// Extract /24 subnet from IPv4 address (Class C / most ISP allocations)
    pub fn extract_subnet_24(&self) -> Ipv4Addr {
        let octets = self.ipv4_addr.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], 0)
    }

    /// Extract /16 subnet from IPv4 address (Class B / large ISP allocations)
    pub fn extract_subnet_16(&self) -> Ipv4Addr {
        let octets = self.ipv4_addr.octets();
        Ipv4Addr::new(octets[0], octets[1], 0, 0)
    }

    /// Extract /8 subnet from IPv4 address (Class A / regional allocations)
    pub fn extract_subnet_8(&self) -> Ipv4Addr {
        let octets = self.ipv4_addr.octets();
        Ipv4Addr::new(octets[0], 0, 0, 0)
    }

    /// Get the age of this node ID in seconds
    pub fn age_secs(&self) -> u64 {
        self.to_generic().age_secs()
    }

    /// Check if the node ID has expired (older than max_age)
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.to_generic().is_expired(max_age)
    }

    // Conversion helpers for delegation

    fn from_generic(g: GenericIpNodeID<Ipv4Addr>) -> Self {
        Self {
            node_id: g.node_id,
            ipv4_addr: g.ip_addr,
            public_key: g.public_key,
            signature: g.signature,
            timestamp_secs: g.timestamp_secs,
            salt: g.salt,
        }
    }

    fn to_generic(&self) -> GenericIpNodeID<Ipv4Addr> {
        GenericIpNodeID {
            node_id: self.node_id.clone(),
            ip_addr: self.ipv4_addr,
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
            timestamp_secs: self.timestamp_secs,
            salt: self.salt.clone(),
        }
    }
}

/// IP diversity enforcement system
#[derive(Debug)]
pub struct IPDiversityEnforcer {
    config: IPDiversityConfig,
    /// Allow loopback addresses (127.0.0.1, ::1) to bypass diversity checks.
    ///
    /// This flag is intentionally separate from `IPDiversityConfig` so that it
    /// has a single source of truth in the owning component (`NodeConfig`,
    /// `BootstrapManager`, etc.) rather than being copied into every config.
    allow_loopback: bool,
    // IPv6 tracking (LRU caches with max 50k entries to prevent memory DoS)
    subnet_64_counts: LruCache<Ipv6Addr, usize>,
    subnet_48_counts: LruCache<Ipv6Addr, usize>,
    subnet_32_counts: LruCache<Ipv6Addr, usize>,
    // IPv4 tracking (LRU caches with max 50k entries to prevent memory DoS)
    #[allow(dead_code)]
    ipv4_32_counts: LruCache<Ipv4Addr, usize>, // Per exact IP
    #[allow(dead_code)]
    ipv4_24_counts: LruCache<Ipv4Addr, usize>, // Per /24 subnet
    #[allow(dead_code)]
    ipv4_16_counts: LruCache<Ipv4Addr, usize>, // Per /16 subnet
    // Shared tracking (LRU caches with max 50k entries to prevent memory DoS)
    asn_counts: LruCache<u32, usize>,
    country_counts: LruCache<String, usize>,
    geo_provider: Option<Arc<dyn GeoProvider + Send + Sync>>,
    // Network size for dynamic limits
    #[allow(dead_code)]
    network_size: usize,
}

#[allow(dead_code)]
impl IPDiversityEnforcer {
    /// Create a new IP diversity enforcer with loopback disabled.
    pub fn new(config: IPDiversityConfig) -> Self {
        Self::with_loopback(config, false)
    }

    /// Create a new IP diversity enforcer with explicit loopback setting.
    ///
    /// `allow_loopback` should come from the single source of truth
    /// (e.g. `NodeConfig.allow_loopback`), not from the diversity config.
    pub fn with_loopback(config: IPDiversityConfig, allow_loopback: bool) -> Self {
        let cache_size = NonZeroUsize::new(MAX_SUBNET_TRACKING).unwrap_or(NonZeroUsize::MIN);
        Self {
            config,
            allow_loopback,
            // IPv6 (LRU caches with bounded size)
            subnet_64_counts: LruCache::new(cache_size),
            subnet_48_counts: LruCache::new(cache_size),
            subnet_32_counts: LruCache::new(cache_size),
            // IPv4 (LRU caches with bounded size)
            ipv4_32_counts: LruCache::new(cache_size),
            ipv4_24_counts: LruCache::new(cache_size),
            ipv4_16_counts: LruCache::new(cache_size),
            // Shared (LRU caches with bounded size)
            asn_counts: LruCache::new(cache_size),
            country_counts: LruCache::new(cache_size),
            geo_provider: None,
            network_size: 0,
        }
    }

    /// Create a new IP diversity enforcer with a GeoIP/ASN provider
    pub fn with_geo_provider(
        config: IPDiversityConfig,
        provider: Arc<dyn GeoProvider + Send + Sync>,
    ) -> Self {
        let mut s = Self::new(config);
        s.geo_provider = Some(provider);
        s
    }

    /// Analyze an IPv6 address for diversity enforcement
    pub fn analyze_ip(&self, ipv6_addr: Ipv6Addr) -> Result<IPAnalysis> {
        let subnet_64 = Self::extract_subnet_prefix(ipv6_addr, 64);
        let subnet_48 = Self::extract_subnet_prefix(ipv6_addr, 48);
        let subnet_32 = Self::extract_subnet_prefix(ipv6_addr, 32);

        // GeoIP/ASN lookup via provider if available
        let (asn, country, is_hosting_provider, is_vpn_provider) =
            if let Some(p) = &self.geo_provider {
                let info = p.lookup(ipv6_addr);
                (
                    info.asn,
                    info.country,
                    info.is_hosting_provider,
                    info.is_vpn_provider,
                )
            } else {
                (None, None, false, false)
            };

        // Default reputation for new IPs
        let reputation_score = 0.5;

        // Detect loopback: native ::1 or IPv4-mapped 127.0.0.0/8.
        let is_loopback = ipv6_addr.is_loopback()
            || ipv6_addr
                .to_ipv4_mapped()
                .is_some_and(|v4| v4.is_loopback());

        Ok(IPAnalysis {
            is_loopback,
            subnet_64,
            subnet_48,
            subnet_32,
            asn,
            country,
            is_hosting_provider,
            is_vpn_provider,
            reputation_score,
        })
    }

    /// Check if a new node can be accepted based on IP diversity constraints
    pub fn can_accept_node(&self, ip_analysis: &IPAnalysis) -> bool {
        // Loopback addresses bypass diversity checks only when explicitly allowed.
        if ip_analysis.is_loopback && self.allow_loopback {
            return true;
        }

        // Determine limits based on hosting provider status
        let (limit_64, limit_48, limit_32, limit_asn) =
            if ip_analysis.is_hosting_provider || ip_analysis.is_vpn_provider {
                // Stricter limits for hosting providers (halved)
                (
                    std::cmp::max(1, self.config.max_nodes_per_ipv6_64 / 2),
                    std::cmp::max(1, self.config.max_nodes_per_ipv6_48 / 2),
                    std::cmp::max(1, self.config.max_nodes_per_ipv6_32 / 2),
                    std::cmp::max(1, self.config.max_nodes_per_asn / 2),
                )
            } else {
                // Regular limits for normal nodes
                (
                    self.config.max_nodes_per_ipv6_64,
                    self.config.max_nodes_per_ipv6_48,
                    self.config.max_nodes_per_ipv6_32,
                    self.config.max_nodes_per_asn,
                )
            };

        // Check /64 subnet limit (use peek() for read-only access)
        if let Some(&count) = self.subnet_64_counts.peek(&ip_analysis.subnet_64)
            && count >= limit_64
        {
            return false;
        }

        // Check /48 subnet limit (use peek() for read-only access)
        if let Some(&count) = self.subnet_48_counts.peek(&ip_analysis.subnet_48)
            && count >= limit_48
        {
            return false;
        }

        // Check /32 subnet limit (use peek() for read-only access)
        if let Some(&count) = self.subnet_32_counts.peek(&ip_analysis.subnet_32)
            && count >= limit_32
        {
            return false;
        }

        // Check ASN limit (use peek() for read-only access)
        if let Some(asn) = ip_analysis.asn
            && let Some(&count) = self.asn_counts.peek(&asn)
            && count >= limit_asn
        {
            return false;
        }

        true
    }

    /// Add a node to the diversity tracking
    pub fn add_node(&mut self, ip_analysis: &IPAnalysis) -> Result<()> {
        if !self.can_accept_node(ip_analysis) {
            return Err(anyhow!("IP diversity limits exceeded"));
        }

        // Update counts (optimized: single hash lookup per cache)
        let count_64 = self
            .subnet_64_counts
            .get(&ip_analysis.subnet_64)
            .copied()
            .unwrap_or(0)
            + 1;
        self.subnet_64_counts.put(ip_analysis.subnet_64, count_64);

        let count_48 = self
            .subnet_48_counts
            .get(&ip_analysis.subnet_48)
            .copied()
            .unwrap_or(0)
            + 1;
        self.subnet_48_counts.put(ip_analysis.subnet_48, count_48);

        let count_32 = self
            .subnet_32_counts
            .get(&ip_analysis.subnet_32)
            .copied()
            .unwrap_or(0)
            + 1;
        self.subnet_32_counts.put(ip_analysis.subnet_32, count_32);

        if let Some(asn) = ip_analysis.asn {
            let count = self.asn_counts.get(&asn).copied().unwrap_or(0) + 1;
            self.asn_counts.put(asn, count);
        }

        if let Some(ref country) = ip_analysis.country {
            let count = self.country_counts.get(country).copied().unwrap_or(0) + 1;
            self.country_counts.put(country.clone(), count);
        }

        Ok(())
    }

    /// Remove a node from diversity tracking
    pub fn remove_node(&mut self, ip_analysis: &IPAnalysis) {
        // Optimized: pop removes and returns value in single hash operation
        if let Some(count) = self.subnet_64_counts.pop(&ip_analysis.subnet_64) {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.subnet_64_counts.put(ip_analysis.subnet_64, new_count);
            }
        }

        if let Some(count) = self.subnet_48_counts.pop(&ip_analysis.subnet_48) {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.subnet_48_counts.put(ip_analysis.subnet_48, new_count);
            }
        }

        if let Some(count) = self.subnet_32_counts.pop(&ip_analysis.subnet_32) {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.subnet_32_counts.put(ip_analysis.subnet_32, new_count);
            }
        }

        if let Some(asn) = ip_analysis.asn
            && let Some(count) = self.asn_counts.pop(&asn)
        {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.asn_counts.put(asn, new_count);
            }
        }

        if let Some(ref country) = ip_analysis.country
            && let Some(count) = self.country_counts.pop(country)
        {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.country_counts.put(country.clone(), new_count);
            }
        }
    }

    /// Extract network prefix of specified length from IPv6 address
    pub fn extract_subnet_prefix(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
        let octets = addr.octets();
        let mut subnet = [0u8; 16];

        let bytes_to_copy = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        // Copy full bytes
        if bytes_to_copy < 16 {
            subnet[..bytes_to_copy].copy_from_slice(&octets[..bytes_to_copy]);
        } else {
            subnet.copy_from_slice(&octets);
        }

        // Handle partial byte
        if remaining_bits > 0 && bytes_to_copy < 16 {
            let mask = 0xFF << (8 - remaining_bits);
            subnet[bytes_to_copy] = octets[bytes_to_copy] & mask;
        }

        Ipv6Addr::from(subnet)
    }

    /// Get diversity statistics
    pub fn get_diversity_stats(&self) -> DiversityStats {
        // LRU cache API: use iter() instead of values()
        let max_nodes_per_ipv6_64 = self
            .subnet_64_counts
            .iter()
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);
        let max_nodes_per_ipv6_48 = self
            .subnet_48_counts
            .iter()
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);
        let max_nodes_per_ipv6_32 = self
            .subnet_32_counts
            .iter()
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);
        let max_nodes_per_ipv4_32 = self
            .ipv4_32_counts
            .iter()
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);
        let max_nodes_per_ipv4_24 = self
            .ipv4_24_counts
            .iter()
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);
        let max_nodes_per_ipv4_16 = self
            .ipv4_16_counts
            .iter()
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);

        DiversityStats {
            total_64_subnets: self.subnet_64_counts.len(),
            total_48_subnets: self.subnet_48_counts.len(),
            total_32_subnets: self.subnet_32_counts.len(),
            total_asns: self.asn_counts.len(),
            total_countries: self.country_counts.len(),
            max_nodes_per_ipv6_64,
            max_nodes_per_ipv6_48,
            max_nodes_per_ipv6_32,
            // IPv4 stats
            total_ipv4_32: self.ipv4_32_counts.len(),
            total_ipv4_24_subnets: self.ipv4_24_counts.len(),
            total_ipv4_16_subnets: self.ipv4_16_counts.len(),
            max_nodes_per_ipv4_32,
            max_nodes_per_ipv4_24,
            max_nodes_per_ipv4_16,
        }
    }

    // === IPv4 Methods (new) ===

    /// Set the current network size for dynamic limit calculation
    pub fn set_network_size(&mut self, size: usize) {
        self.network_size = size;
    }

    /// Get the current network size
    pub fn get_network_size(&self) -> usize {
        self.network_size
    }

    /// Calculate the dynamic per-IP limit: min(cap, floor(network_size * fraction))
    /// Formula: min(50, floor(network_size * 0.005))
    pub fn get_per_ip_limit(&self) -> usize {
        let fraction_limit =
            (self.network_size as f64 * self.config.max_network_fraction).floor() as usize;
        std::cmp::min(self.config.max_per_ip_cap, std::cmp::max(1, fraction_limit))
    }

    /// Extract /24 subnet from IPv4 address
    fn extract_ipv4_subnet_24(addr: Ipv4Addr) -> Ipv4Addr {
        let octets = addr.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], 0)
    }

    /// Extract /16 subnet from IPv4 address
    fn extract_ipv4_subnet_16(addr: Ipv4Addr) -> Ipv4Addr {
        let octets = addr.octets();
        Ipv4Addr::new(octets[0], octets[1], 0, 0)
    }

    /// Extract /8 subnet from IPv4 address
    fn extract_ipv4_subnet_8(addr: Ipv4Addr) -> Ipv4Addr {
        let octets = addr.octets();
        Ipv4Addr::new(octets[0], 0, 0, 0)
    }

    /// Analyze an IPv4 address for diversity enforcement
    pub fn analyze_ipv4(&self, ipv4_addr: Ipv4Addr) -> Result<IPv4Analysis> {
        let subnet_24 = Self::extract_ipv4_subnet_24(ipv4_addr);
        let subnet_16 = Self::extract_ipv4_subnet_16(ipv4_addr);
        let subnet_8 = Self::extract_ipv4_subnet_8(ipv4_addr);

        // For IPv4, we don't have GeoIP lookup yet (would need IPv4 support in GeoProvider)
        // Using defaults for now
        let asn = None;
        let country = None;
        let is_hosting_provider = false;
        let is_vpn_provider = false;
        let reputation_score = 0.5;

        Ok(IPv4Analysis {
            ip_addr: ipv4_addr,
            subnet_24,
            subnet_16,
            subnet_8,
            asn,
            country,
            is_hosting_provider,
            is_vpn_provider,
            reputation_score,
        })
    }

    /// Analyze any IP address (IPv4 or IPv6) for diversity enforcement
    pub fn analyze_unified(&self, addr: std::net::IpAddr) -> Result<UnifiedIPAnalysis> {
        match addr {
            std::net::IpAddr::V4(ipv4) => {
                let analysis = self.analyze_ipv4(ipv4)?;
                Ok(UnifiedIPAnalysis::IPv4(analysis))
            }
            std::net::IpAddr::V6(ipv6) => {
                let analysis = self.analyze_ip(ipv6)?;
                Ok(UnifiedIPAnalysis::IPv6(analysis))
            }
        }
    }

    /// Check if a node can be accepted based on unified IP diversity constraints
    pub fn can_accept_unified(&self, analysis: &UnifiedIPAnalysis) -> bool {
        match analysis {
            UnifiedIPAnalysis::IPv4(ipv4_analysis) => self.can_accept_ipv4(ipv4_analysis),
            UnifiedIPAnalysis::IPv6(ipv6_analysis) => self.can_accept_node(ipv6_analysis),
        }
    }

    /// Check if an IPv4 node can be accepted based on diversity constraints
    fn can_accept_ipv4(&self, analysis: &IPv4Analysis) -> bool {
        // Loopback addresses bypass diversity checks only when explicitly allowed.
        if analysis.ip_addr.is_loopback() && self.allow_loopback {
            return true;
        }

        // Get dynamic per-IP limit
        let per_ip_limit = self.get_per_ip_limit();

        // Determine multipliers for subnet limits
        let limit_32 = self
            .config
            .max_nodes_per_ipv4_32
            .map_or(per_ip_limit, |floor| floor.max(per_ip_limit));
        let limit_24 = self
            .config
            .max_nodes_per_ipv4_24
            .map_or(per_ip_limit * 3, |floor| floor.max(per_ip_limit * 3));
        let limit_16 = self
            .config
            .max_nodes_per_ipv4_16
            .map_or(per_ip_limit * 10, |floor| floor.max(per_ip_limit * 10));

        // Apply stricter limits for hosting/VPN providers
        let (limit_32, limit_24, limit_16) =
            if analysis.is_hosting_provider || analysis.is_vpn_provider {
                (
                    std::cmp::max(1, limit_32 / 2),
                    std::cmp::max(1, limit_24 / 2),
                    std::cmp::max(1, limit_16 / 2),
                )
            } else {
                (limit_32, limit_24, limit_16)
            };

        // Check /32 (exact IP) limit (use peek() for read-only access)
        if let Some(&count) = self.ipv4_32_counts.peek(&analysis.ip_addr)
            && count >= limit_32
        {
            return false;
        }

        // Check /24 subnet limit (use peek() for read-only access)
        if let Some(&count) = self.ipv4_24_counts.peek(&analysis.subnet_24)
            && count >= limit_24
        {
            return false;
        }

        // Check /16 subnet limit (use peek() for read-only access)
        if let Some(&count) = self.ipv4_16_counts.peek(&analysis.subnet_16)
            && count >= limit_16
        {
            return false;
        }

        // Check ASN limit (shared with IPv6, use peek() for read-only access)
        if let Some(asn) = analysis.asn
            && let Some(&count) = self.asn_counts.peek(&asn)
            && count >= self.config.max_nodes_per_asn
        {
            return false;
        }

        true
    }

    /// Add a unified node to the diversity tracking
    pub fn add_unified(&mut self, analysis: &UnifiedIPAnalysis) -> Result<()> {
        match analysis {
            UnifiedIPAnalysis::IPv4(ipv4_analysis) => self.add_ipv4(ipv4_analysis),
            UnifiedIPAnalysis::IPv6(ipv6_analysis) => self.add_node(ipv6_analysis),
        }
    }

    /// Add an IPv4 node to diversity tracking
    fn add_ipv4(&mut self, analysis: &IPv4Analysis) -> Result<()> {
        if !self.can_accept_ipv4(analysis) {
            return Err(anyhow!("IPv4 diversity limits exceeded"));
        }

        // Update counts (optimized: single hash lookup per cache)
        let count_32 = self
            .ipv4_32_counts
            .get(&analysis.ip_addr)
            .copied()
            .unwrap_or(0)
            + 1;
        self.ipv4_32_counts.put(analysis.ip_addr, count_32);

        let count_24 = self
            .ipv4_24_counts
            .get(&analysis.subnet_24)
            .copied()
            .unwrap_or(0)
            + 1;
        self.ipv4_24_counts.put(analysis.subnet_24, count_24);

        let count_16 = self
            .ipv4_16_counts
            .get(&analysis.subnet_16)
            .copied()
            .unwrap_or(0)
            + 1;
        self.ipv4_16_counts.put(analysis.subnet_16, count_16);

        if let Some(asn) = analysis.asn {
            let count = self.asn_counts.get(&asn).copied().unwrap_or(0) + 1;
            self.asn_counts.put(asn, count);
        }

        if let Some(ref country) = analysis.country {
            let count = self.country_counts.get(country).copied().unwrap_or(0) + 1;
            self.country_counts.put(country.clone(), count);
        }

        Ok(())
    }

    /// Remove a unified node from diversity tracking
    pub fn remove_unified(&mut self, analysis: &UnifiedIPAnalysis) {
        match analysis {
            UnifiedIPAnalysis::IPv4(ipv4_analysis) => self.remove_ipv4(ipv4_analysis),
            UnifiedIPAnalysis::IPv6(ipv6_analysis) => self.remove_node(ipv6_analysis),
        }
    }

    /// Remove an IPv4 node from diversity tracking
    fn remove_ipv4(&mut self, analysis: &IPv4Analysis) {
        // Optimized: pop removes and returns value in single hash operation
        if let Some(count) = self.ipv4_32_counts.pop(&analysis.ip_addr) {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.ipv4_32_counts.put(analysis.ip_addr, new_count);
            }
        }

        if let Some(count) = self.ipv4_24_counts.pop(&analysis.subnet_24) {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.ipv4_24_counts.put(analysis.subnet_24, new_count);
            }
        }

        if let Some(count) = self.ipv4_16_counts.pop(&analysis.subnet_16) {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.ipv4_16_counts.put(analysis.subnet_16, new_count);
            }
        }

        if let Some(asn) = analysis.asn
            && let Some(count) = self.asn_counts.pop(&asn)
        {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.asn_counts.put(asn, new_count);
            }
        }

        if let Some(ref country) = analysis.country
            && let Some(count) = self.country_counts.pop(country)
        {
            let new_count = count.saturating_sub(1);
            if new_count > 0 {
                self.country_counts.put(country.clone(), new_count);
            }
        }
    }
}

#[cfg(test)]
impl IPDiversityEnforcer {
    #[allow(dead_code)]
    pub fn config(&self) -> &IPDiversityConfig {
        &self.config
    }
}

/// GeoIP/ASN provider trait
pub trait GeoProvider: std::fmt::Debug {
    fn lookup(&self, ip: Ipv6Addr) -> GeoInfo;
}

/// Geo information
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub asn: Option<u32>,
    pub country: Option<String>,
    pub is_hosting_provider: bool,
    pub is_vpn_provider: bool,
}

/// A simple in-memory caching wrapper for a GeoProvider
#[derive(Debug)]
#[allow(dead_code)]
pub struct CachedGeoProvider<P: GeoProvider> {
    inner: P,
    cache: parking_lot::RwLock<HashMap<Ipv6Addr, GeoInfo>>,
}

#[allow(dead_code)]
impl<P: GeoProvider> CachedGeoProvider<P> {
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cache: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}

impl<P: GeoProvider> GeoProvider for CachedGeoProvider<P> {
    fn lookup(&self, ip: Ipv6Addr) -> GeoInfo {
        if let Some(info) = self.cache.read().get(&ip).cloned() {
            return info;
        }
        let info = self.inner.lookup(ip);
        self.cache.write().insert(ip, info.clone());
        info
    }
}

/// Stub provider returning no ASN/GeoIP info
#[derive(Debug)]
#[allow(dead_code)]
pub struct StubGeoProvider;
impl GeoProvider for StubGeoProvider {
    fn lookup(&self, _ip: Ipv6Addr) -> GeoInfo {
        GeoInfo {
            asn: None,
            country: None,
            is_hosting_provider: false,
            is_vpn_provider: false,
        }
    }
}

/// Diversity statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DiversityStats {
    // === IPv6 stats ===
    /// Number of unique /64 subnets represented
    pub total_64_subnets: usize,
    /// Number of unique /48 subnets represented
    pub total_48_subnets: usize,
    /// Number of unique /32 subnets represented
    pub total_32_subnets: usize,
    /// Maximum nodes in any single /64 subnet
    pub max_nodes_per_ipv6_64: usize,
    /// Maximum nodes in any single /48 subnet
    pub max_nodes_per_ipv6_48: usize,
    /// Maximum nodes in any single /32 subnet
    pub max_nodes_per_ipv6_32: usize,

    // === IPv4 stats (new) ===
    /// Number of unique IPv4 addresses (/32)
    pub total_ipv4_32: usize,
    /// Number of unique /24 subnets represented
    pub total_ipv4_24_subnets: usize,
    /// Number of unique /16 subnets represented
    pub total_ipv4_16_subnets: usize,
    /// Maximum nodes from any single IPv4 address
    pub max_nodes_per_ipv4_32: usize,
    /// Maximum nodes in any single /24 subnet
    pub max_nodes_per_ipv4_24: usize,
    /// Maximum nodes in any single /16 subnet
    pub max_nodes_per_ipv4_16: usize,

    // === Shared stats ===
    /// Number of unique ASNs represented
    pub total_asns: usize,
    /// Number of unique countries represented
    pub total_countries: usize,
}

// Ed25519 compatibility removed

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum_crypto::generate_ml_dsa_keypair;

    fn create_test_keypair() -> (MlDsaPublicKey, MlDsaSecretKey) {
        generate_ml_dsa_keypair().expect("Failed to generate test keypair")
    }

    fn create_test_ipv6() -> Ipv6Addr {
        Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        )
    }

    fn create_test_diversity_config() -> IPDiversityConfig {
        IPDiversityConfig {
            // IPv6 limits
            max_nodes_per_ipv6_64: 1,
            max_nodes_per_ipv6_48: 3,
            max_nodes_per_ipv6_32: 10,
            // IPv4 limits — None = purely dynamic
            max_nodes_per_ipv4_32: None,
            max_nodes_per_ipv4_24: None,
            max_nodes_per_ipv4_16: None,
            ipv4_limit_floor: None,
            ipv4_limit_ceiling: None,
            ipv6_limit_floor: None,
            ipv6_limit_ceiling: None,
            // Network-relative limits
            max_per_ip_cap: 50,
            max_network_fraction: 0.005,
            // ASN and GeoIP
            max_nodes_per_asn: 20,
            enable_geolocation_check: true,
            min_geographic_diversity: 3,
        }
    }

    #[test]
    fn test_ipv6_node_id_generation() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv6_addr = create_test_ipv6();

        let node_id = IPv6NodeID::generate(ipv6_addr, &secret_key, &public_key)?;

        assert_eq!(node_id.ipv6_addr, ipv6_addr);
        assert_eq!(node_id.public_key.len(), 1952); // ML-DSA-65 public key size
        assert_eq!(node_id.signature.len(), 3309); // ML-DSA-65 signature size
        assert_eq!(node_id.node_id.len(), 32); // BLAKE3 output
        assert_eq!(node_id.salt.len(), 16);
        assert!(node_id.timestamp_secs > 0);

        Ok(())
    }

    #[test]
    fn test_ipv6_node_id_verification() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv6_addr = create_test_ipv6();

        let node_id = IPv6NodeID::generate(ipv6_addr, &secret_key, &public_key)?;
        let is_valid = node_id.verify()?;

        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_ipv6_node_id_verification_fails_with_wrong_data() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv6_addr = create_test_ipv6();

        let mut node_id = IPv6NodeID::generate(ipv6_addr, &secret_key, &public_key)?;

        // Tamper with the node ID
        node_id.node_id[0] ^= 0xFF;
        let is_valid = node_id.verify()?;
        assert!(!is_valid);

        // Test with wrong signature length
        let mut node_id2 = IPv6NodeID::generate(ipv6_addr, &secret_key, &public_key)?;
        node_id2.signature = vec![0u8; 32]; // Wrong length (should be 3309 for ML-DSA)
        let is_valid2 = node_id2.verify()?;
        assert!(!is_valid2);

        // Test with wrong public key length
        let mut node_id3 = IPv6NodeID::generate(ipv6_addr, &secret_key, &public_key)?;
        node_id3.public_key = vec![0u8; 16]; // Wrong length (should be 1952 for ML-DSA-65)
        let is_valid3 = node_id3.verify()?;
        assert!(!is_valid3);

        Ok(())
    }

    #[test]
    fn test_ipv6_subnet_extraction() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv6_addr = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
        );

        let node_id = IPv6NodeID::generate(ipv6_addr, &secret_key, &public_key)?;

        // Test /64 subnet extraction
        let subnet_64 = node_id.extract_subnet_64();
        let expected_64 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1234, 0, 0, 0, 0);
        assert_eq!(subnet_64, expected_64);

        // Test /48 subnet extraction
        let subnet_48 = node_id.extract_subnet_48();
        let expected_48 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0, 0, 0);
        assert_eq!(subnet_48, expected_48);

        // Test /32 subnet extraction
        let subnet_32 = node_id.extract_subnet_32();
        let expected_32 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        assert_eq!(subnet_32, expected_32);

        Ok(())
    }

    // =========== IPv4 Node ID Tests ===========

    fn create_test_ipv4() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 100)
    }

    #[test]
    fn test_ipv4_node_id_generation() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv4_addr = create_test_ipv4();

        let node_id = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;

        assert_eq!(node_id.ipv4_addr, ipv4_addr);
        assert_eq!(node_id.public_key.len(), 1952); // ML-DSA-65 public key size
        assert_eq!(node_id.signature.len(), 3309); // ML-DSA-65 signature size
        assert_eq!(node_id.node_id.len(), 32); // BLAKE3 output
        assert_eq!(node_id.salt.len(), 16);
        assert!(node_id.timestamp_secs > 0);

        Ok(())
    }

    #[test]
    fn test_ipv4_node_id_verification() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv4_addr = create_test_ipv4();

        let node_id = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;
        let is_valid = node_id.verify()?;

        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_ipv4_node_id_verification_fails_with_wrong_data() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv4_addr = create_test_ipv4();

        let mut node_id = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;

        // Tamper with the node ID
        node_id.node_id[0] ^= 0xFF;
        let is_valid = node_id.verify()?;
        assert!(!is_valid);

        // Test with wrong signature length
        let mut node_id2 = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;
        node_id2.signature = vec![0u8; 32]; // Wrong length (should be 3309 for ML-DSA)
        let is_valid2 = node_id2.verify()?;
        assert!(!is_valid2);

        // Test with wrong public key length
        let mut node_id3 = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;
        node_id3.public_key = vec![0u8; 16]; // Wrong length (should be 1952 for ML-DSA-65)
        let is_valid3 = node_id3.verify()?;
        assert!(!is_valid3);

        Ok(())
    }

    #[test]
    fn test_ipv4_subnet_extraction() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv4_addr = Ipv4Addr::new(192, 168, 42, 100);

        let node_id = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;

        // Test /24 subnet extraction
        let subnet_24 = node_id.extract_subnet_24();
        let expected_24 = Ipv4Addr::new(192, 168, 42, 0);
        assert_eq!(subnet_24, expected_24);

        // Test /16 subnet extraction
        let subnet_16 = node_id.extract_subnet_16();
        let expected_16 = Ipv4Addr::new(192, 168, 0, 0);
        assert_eq!(subnet_16, expected_16);

        // Test /8 subnet extraction
        let subnet_8 = node_id.extract_subnet_8();
        let expected_8 = Ipv4Addr::new(192, 0, 0, 0);
        assert_eq!(subnet_8, expected_8);

        Ok(())
    }

    #[test]
    fn test_ipv4_node_id_age() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let ipv4_addr = create_test_ipv4();

        let node_id = IPv4NodeID::generate(ipv4_addr, &secret_key, &public_key)?;

        // Age should be very small (just created)
        assert!(node_id.age_secs() < 5);

        // Not expired with a 1 hour max age
        assert!(!node_id.is_expired(Duration::from_secs(3600)));

        // A freshly created node with 0 age is NOT expired (0 > 0 is false)
        // This is correct behavior - a 0-second-old node is not older than 0 seconds
        assert!(!node_id.is_expired(Duration::from_secs(0)));

        Ok(())
    }

    #[test]
    fn test_ipv4_different_addresses_different_node_ids() -> Result<()> {
        let (public_key, secret_key) = create_test_keypair();
        let addr1 = Ipv4Addr::new(192, 168, 1, 1);
        let addr2 = Ipv4Addr::new(192, 168, 1, 2);

        let node_id1 = IPv4NodeID::generate(addr1, &secret_key, &public_key)?;
        let node_id2 = IPv4NodeID::generate(addr2, &secret_key, &public_key)?;

        // Different addresses should produce different node IDs
        assert_ne!(node_id1.node_id, node_id2.node_id);

        // Both should verify successfully
        assert!(node_id1.verify()?);
        assert!(node_id2.verify()?);

        Ok(())
    }

    // =========== End IPv4 Tests ===========

    #[test]
    fn test_ip_diversity_config_default() {
        let config = IPDiversityConfig::default();

        assert_eq!(config.max_nodes_per_ipv6_64, 1);
        assert_eq!(config.max_nodes_per_ipv6_48, 3);
        assert_eq!(config.max_nodes_per_ipv6_32, 10);
        assert_eq!(config.max_nodes_per_asn, 20);
        assert!(config.enable_geolocation_check);
        assert_eq!(config.min_geographic_diversity, 3);
    }

    #[test]
    fn test_ip_diversity_enforcer_creation() {
        let config = create_test_diversity_config();
        let enforcer = IPDiversityEnforcer::with_loopback(config.clone(), true);

        assert_eq!(
            enforcer.config.max_nodes_per_ipv6_64,
            config.max_nodes_per_ipv6_64
        );
        assert_eq!(enforcer.subnet_64_counts.len(), 0);
        assert_eq!(enforcer.subnet_48_counts.len(), 0);
        assert_eq!(enforcer.subnet_32_counts.len(), 0);
    }

    #[test]
    fn test_ip_analysis() -> Result<()> {
        let config = create_test_diversity_config();
        let enforcer = IPDiversityEnforcer::new(config);

        let ipv6_addr = create_test_ipv6();
        let analysis = enforcer.analyze_ip(ipv6_addr)?;

        assert_eq!(
            analysis.subnet_64,
            IPDiversityEnforcer::extract_subnet_prefix(ipv6_addr, 64)
        );
        assert_eq!(
            analysis.subnet_48,
            IPDiversityEnforcer::extract_subnet_prefix(ipv6_addr, 48)
        );
        assert_eq!(
            analysis.subnet_32,
            IPDiversityEnforcer::extract_subnet_prefix(ipv6_addr, 32)
        );
        assert!(analysis.asn.is_none()); // Not implemented in test
        assert!(analysis.country.is_none()); // Not implemented in test
        assert!(!analysis.is_hosting_provider);
        assert!(!analysis.is_vpn_provider);
        assert_eq!(analysis.reputation_score, 0.5);

        Ok(())
    }

    #[test]
    fn test_can_accept_node_basic() -> Result<()> {
        let config = create_test_diversity_config();
        let enforcer = IPDiversityEnforcer::new(config);

        let ipv6_addr = create_test_ipv6();
        let analysis = enforcer.analyze_ip(ipv6_addr)?;

        // Should accept first node
        assert!(enforcer.can_accept_node(&analysis));

        Ok(())
    }

    #[test]
    fn test_add_and_remove_node() -> Result<()> {
        let config = create_test_diversity_config();
        let mut enforcer = IPDiversityEnforcer::new(config);

        let ipv6_addr = create_test_ipv6();
        let analysis = enforcer.analyze_ip(ipv6_addr)?;

        // Add node
        enforcer.add_node(&analysis)?;
        assert_eq!(enforcer.subnet_64_counts.get(&analysis.subnet_64), Some(&1));
        assert_eq!(enforcer.subnet_48_counts.get(&analysis.subnet_48), Some(&1));
        assert_eq!(enforcer.subnet_32_counts.get(&analysis.subnet_32), Some(&1));

        // Remove node
        enforcer.remove_node(&analysis);
        assert_eq!(enforcer.subnet_64_counts.get(&analysis.subnet_64), None);
        assert_eq!(enforcer.subnet_48_counts.get(&analysis.subnet_48), None);
        assert_eq!(enforcer.subnet_32_counts.get(&analysis.subnet_32), None);

        Ok(())
    }

    #[test]
    fn test_diversity_limits_enforcement() -> Result<()> {
        let config = create_test_diversity_config();
        let mut enforcer = IPDiversityEnforcer::new(config);

        let ipv6_addr1 = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
        );
        let ipv6_addr2 = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7335,
        ); // Same /64

        let analysis1 = enforcer.analyze_ip(ipv6_addr1)?;
        let analysis2 = enforcer.analyze_ip(ipv6_addr2)?;

        // First node should be accepted
        assert!(enforcer.can_accept_node(&analysis1));
        enforcer.add_node(&analysis1)?;

        // Second node in same /64 should be rejected (max_nodes_per_ipv6_64 = 1)
        assert!(!enforcer.can_accept_node(&analysis2));

        // But adding should fail
        let result = enforcer.add_node(&analysis2);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("IP diversity limits exceeded")
        );

        Ok(())
    }

    #[test]
    fn test_hosting_provider_stricter_limits() -> Result<()> {
        let config = IPDiversityConfig {
            max_nodes_per_ipv6_64: 4, // Set higher limit for regular nodes
            max_nodes_per_ipv6_48: 8,
            ..create_test_diversity_config()
        };
        let mut enforcer = IPDiversityEnforcer::new(config);

        let ipv6_addr = create_test_ipv6();
        let mut analysis = enforcer.analyze_ip(ipv6_addr)?;
        analysis.is_hosting_provider = true;

        // Should accept first hosting provider node
        assert!(enforcer.can_accept_node(&analysis));
        enforcer.add_node(&analysis)?;

        // Add second hosting provider node in same /64 (should be accepted with limit=2)
        let ipv6_addr2 = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7335,
        );
        let mut analysis2 = enforcer.analyze_ip(ipv6_addr2)?;
        analysis2.is_hosting_provider = true;
        analysis2.subnet_64 = analysis.subnet_64; // Force same subnet

        assert!(enforcer.can_accept_node(&analysis2));
        enforcer.add_node(&analysis2)?;

        // Should reject third hosting provider node in same /64 (exceeds limit=2)
        let ipv6_addr3 = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7336,
        );
        let mut analysis3 = enforcer.analyze_ip(ipv6_addr3)?;
        analysis3.is_hosting_provider = true;
        analysis3.subnet_64 = analysis.subnet_64; // Force same subnet

        assert!(!enforcer.can_accept_node(&analysis3));

        Ok(())
    }

    #[test]
    fn test_diversity_stats() -> Result<()> {
        let config = create_test_diversity_config();
        let mut enforcer = IPDiversityEnforcer::new(config);

        // Add some nodes with different subnets
        let addresses = [
            Ipv6Addr::new(
                0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
            ),
            Ipv6Addr::new(
                0x2001, 0xdb8, 0x85a4, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
            ), // Different /48
            Ipv6Addr::new(
                0x2002, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
            ), // Different /32
        ];

        for addr in addresses {
            let analysis = enforcer.analyze_ip(addr)?;
            enforcer.add_node(&analysis)?;
        }

        let stats = enforcer.get_diversity_stats();
        assert_eq!(stats.total_64_subnets, 3);
        assert_eq!(stats.total_48_subnets, 3);
        assert_eq!(stats.total_32_subnets, 2); // Two /32 prefixes
        assert_eq!(stats.max_nodes_per_ipv6_64, 1);
        assert_eq!(stats.max_nodes_per_ipv6_48, 1);
        assert_eq!(stats.max_nodes_per_ipv6_32, 2); // 2001:db8 has 2 nodes

        Ok(())
    }

    #[test]
    fn test_extract_subnet_prefix() {
        let addr = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x7334,
        );

        // Test /64 prefix
        let prefix_64 = IPDiversityEnforcer::extract_subnet_prefix(addr, 64);
        let expected_64 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1234, 0, 0, 0, 0);
        assert_eq!(prefix_64, expected_64);

        // Test /48 prefix
        let prefix_48 = IPDiversityEnforcer::extract_subnet_prefix(addr, 48);
        let expected_48 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0, 0, 0);
        assert_eq!(prefix_48, expected_48);

        // Test /32 prefix
        let prefix_32 = IPDiversityEnforcer::extract_subnet_prefix(addr, 32);
        let expected_32 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        assert_eq!(prefix_32, expected_32);

        // Test /56 prefix (partial byte)
        let prefix_56 = IPDiversityEnforcer::extract_subnet_prefix(addr, 56);
        let expected_56 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1200, 0, 0, 0, 0);
        assert_eq!(prefix_56, expected_56);

        // Test /128 prefix (full address)
        let prefix_128 = IPDiversityEnforcer::extract_subnet_prefix(addr, 128);
        assert_eq!(prefix_128, addr);
    }

    #[test]
    fn test_security_types_keypair() {
        let (public_key, secret_key) =
            generate_ml_dsa_keypair().expect("Failed to generate keypair");

        let public_key_bytes = public_key.as_bytes();
        assert_eq!(public_key_bytes.len(), 1952); // ML-DSA-65 public key size

        let message = b"test message";
        let signature = ml_dsa_sign(&secret_key, message).expect("Failed to sign message");
        assert_eq!(signature.as_bytes().len(), 3309); // ML-DSA-65 signature size

        // Verify the signature
        assert!(ml_dsa_verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_ip_analysis_structure() {
        let analysis = IPAnalysis {
            is_loopback: false,
            subnet_64: Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1234, 0, 0, 0, 0),
            subnet_48: Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0, 0, 0, 0, 0),
            subnet_32: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            asn: Some(64512),
            country: Some("US".to_string()),
            is_hosting_provider: true,
            is_vpn_provider: false,
            reputation_score: 0.75,
        };

        assert_eq!(analysis.asn, Some(64512));
        assert_eq!(analysis.country, Some("US".to_string()));
        assert!(analysis.is_hosting_provider);
        assert!(!analysis.is_vpn_provider);
        assert_eq!(analysis.reputation_score, 0.75);
    }

    #[test]
    fn test_diversity_stats_structure() {
        let stats = DiversityStats {
            // IPv6 stats
            total_64_subnets: 100,
            total_48_subnets: 50,
            total_32_subnets: 25,
            max_nodes_per_ipv6_64: 1,
            max_nodes_per_ipv6_48: 3,
            max_nodes_per_ipv6_32: 10,
            // IPv4 stats
            total_ipv4_32: 80,
            total_ipv4_24_subnets: 40,
            total_ipv4_16_subnets: 20,
            max_nodes_per_ipv4_32: 1,
            max_nodes_per_ipv4_24: 3,
            max_nodes_per_ipv4_16: 10,
            // Shared stats
            total_asns: 15,
            total_countries: 8,
        };

        // IPv6 assertions
        assert_eq!(stats.total_64_subnets, 100);
        assert_eq!(stats.total_48_subnets, 50);
        assert_eq!(stats.total_32_subnets, 25);
        assert_eq!(stats.max_nodes_per_ipv6_64, 1);
        assert_eq!(stats.max_nodes_per_ipv6_48, 3);
        assert_eq!(stats.max_nodes_per_ipv6_32, 10);
        // IPv4 assertions
        assert_eq!(stats.total_ipv4_32, 80);
        assert_eq!(stats.total_ipv4_24_subnets, 40);
        assert_eq!(stats.total_ipv4_16_subnets, 20);
        assert_eq!(stats.max_nodes_per_ipv4_32, 1);
        assert_eq!(stats.max_nodes_per_ipv4_24, 3);
        assert_eq!(stats.max_nodes_per_ipv4_16, 10);
        // Shared assertions
        assert_eq!(stats.total_asns, 15);
        assert_eq!(stats.total_countries, 8);
    }

    #[test]
    fn test_multiple_same_subnet_nodes() -> Result<()> {
        let config = IPDiversityConfig {
            max_nodes_per_ipv6_64: 3, // Allow more nodes in same /64
            max_nodes_per_ipv6_48: 5,
            max_nodes_per_ipv6_32: 10,
            ..create_test_diversity_config()
        };
        let mut enforcer = IPDiversityEnforcer::new(config);

        let _base_addr = Ipv6Addr::new(
            0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 0x0000,
        );

        // Add 3 nodes in same /64 subnet
        for i in 1..=3 {
            let addr = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, i);
            let analysis = enforcer.analyze_ip(addr)?;
            assert!(enforcer.can_accept_node(&analysis));
            enforcer.add_node(&analysis)?;
        }

        // 4th node should be rejected
        let addr4 = Ipv6Addr::new(0x2001, 0xdb8, 0x85a3, 0x1234, 0x5678, 0x8a2e, 0x0370, 4);
        let analysis4 = enforcer.analyze_ip(addr4)?;
        assert!(!enforcer.can_accept_node(&analysis4));

        let stats = enforcer.get_diversity_stats();
        assert_eq!(stats.total_64_subnets, 1);
        assert_eq!(stats.max_nodes_per_ipv6_64, 3);

        Ok(())
    }

    #[test]
    fn test_asn_and_country_tracking() -> Result<()> {
        let config = create_test_diversity_config();
        let mut enforcer = IPDiversityEnforcer::new(config);

        // Create analysis with ASN and country
        let ipv6_addr = create_test_ipv6();
        let mut analysis = enforcer.analyze_ip(ipv6_addr)?;
        analysis.asn = Some(64512);
        analysis.country = Some("US".to_string());

        enforcer.add_node(&analysis)?;

        assert_eq!(enforcer.asn_counts.get(&64512), Some(&1));
        assert_eq!(enforcer.country_counts.get("US"), Some(&1));

        // Remove and check cleanup
        enforcer.remove_node(&analysis);
        assert!(!enforcer.asn_counts.contains(&64512));
        assert!(!enforcer.country_counts.contains("US"));

        Ok(())
    }
}
