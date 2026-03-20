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
//! It implements IP-based node ID generation and IP diversity enforcement to prevent
//! large-scale Sybil attacks while maintaining network openness.

use crate::quantum_crypto::saorsa_transport_integration::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, ml_dsa_sign, ml_dsa_verify,
};
use anyhow::{Result, anyhow};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum subnet tracking entries before evicting oldest (prevents memory DoS)
const BOOTSTRAP_MAX_TRACKED_SUBNETS: usize = 50_000;

/// Default subnet limit for `BootstrapIpLimiter` (/64 IPv6, /24 IPv4).
/// Used when `IPDiversityConfig::max_per_subnet` is `None`.
const BOOTSTRAP_DEFAULT_SUBNET_LIMIT: usize = 2;

/// Default exact-IP limit for `BootstrapIpLimiter`.
/// Used when `IPDiversityConfig::max_per_ip` is `None`.
const BOOTSTRAP_DEFAULT_IP_LIMIT: usize = 2;

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

/// Configuration for IP diversity enforcement at two tiers: exact IP and subnet.
///
/// Limits are applied **per-bucket** and **per-close-group** (the K closest
/// nodes to self), matching how geographic diversity is enforced.  When a
/// candidate would exceed a limit, it may still be admitted via swap-closer
/// logic: if the candidate is closer (XOR distance) to self than the
/// farthest same-subnet peer in the scope, that farther peer is evicted.
///
/// By default every limit is `None`, meaning the K-based defaults from
/// `DhtCoreEngine` apply (fractions of the bucket size K).  Setting an
/// explicit `Some(n)` overrides the K-based default for that tier.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IPDiversityConfig {
    /// Override for max nodes sharing an exact IP address per bucket/close-group.
    /// When `None`, uses the default of 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_ip: Option<usize>,

    /// Override for max nodes in the same subnet (/24 IPv4, /64 IPv6).
    /// When `None`, uses the K-based default (~25% of bucket size).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_subnet: Option<usize>,
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
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(usize::MAX),
        }
    }

    /// Create a permissive configuration that effectively disables diversity checks.
    ///
    /// This is useful for local development and unit testing where all nodes
    /// run on localhost or the same machine.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(usize::MAX),
        }
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
///
/// Tracks per-IP and per-subnet counts to prevent Sybil attacks.
/// Uses simple 2-tier limits: exact IP and subnet (/24 IPv4, /64 IPv6).
#[derive(Debug)]
pub struct BootstrapIpLimiter {
    config: IPDiversityConfig,
    /// Allow loopback addresses (127.0.0.1, ::1) to bypass diversity checks.
    ///
    /// This flag is intentionally separate from `IPDiversityConfig` so that it
    /// has a single source of truth in the owning component (`NodeConfig`,
    /// `BootstrapManager`, etc.) rather than being copied into every config.
    allow_loopback: bool,
    /// Count of nodes per exact IP address
    ip_counts: LruCache<IpAddr, usize>,
    /// Count of nodes per subnet (/24 IPv4, /64 IPv6)
    subnet_counts: LruCache<IpAddr, usize>,
}

impl BootstrapIpLimiter {
    /// Create a new IP diversity enforcer with loopback disabled.
    #[allow(dead_code)]
    pub fn new(config: IPDiversityConfig) -> Self {
        Self::with_loopback(config, false)
    }

    /// Create a new IP diversity enforcer with explicit loopback setting.
    ///
    /// `allow_loopback` should come from the single source of truth
    /// (e.g. `NodeConfig.allow_loopback`), not from the diversity config.
    pub fn with_loopback(config: IPDiversityConfig, allow_loopback: bool) -> Self {
        let cache_size =
            NonZeroUsize::new(BOOTSTRAP_MAX_TRACKED_SUBNETS).unwrap_or(NonZeroUsize::MIN);
        Self {
            config,
            allow_loopback,
            ip_counts: LruCache::new(cache_size),
            subnet_counts: LruCache::new(cache_size),
        }
    }

    /// Mask an IP to its subnet prefix (/24 for IPv4, /64 for IPv6).
    fn subnet_key(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
            }
            IpAddr::V6(v6) => {
                let mut o = v6.octets();
                // Zero out bytes 8-15 (host portion of /64)
                for b in &mut o[8..] {
                    *b = 0;
                }
                IpAddr::V6(Ipv6Addr::from(o))
            }
        }
    }

    /// Check if a new node with the given IP can be accepted under diversity limits.
    pub fn can_accept(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() && self.allow_loopback {
            return true;
        }

        let ip_limit = self.config.max_per_ip.unwrap_or(BOOTSTRAP_DEFAULT_IP_LIMIT);
        let subnet_limit = self
            .config
            .max_per_subnet
            .unwrap_or(BOOTSTRAP_DEFAULT_SUBNET_LIMIT);

        // Check exact IP limit
        if let Some(&count) = self.ip_counts.peek(&ip)
            && count >= ip_limit
        {
            return false;
        }

        // Check subnet limit
        let subnet = Self::subnet_key(ip);
        if let Some(&count) = self.subnet_counts.peek(&subnet)
            && count >= subnet_limit
        {
            return false;
        }

        true
    }

    /// Track a new node's IP address in the diversity enforcer.
    ///
    /// Returns an error if the IP would exceed diversity limits.
    pub fn track(&mut self, ip: IpAddr) -> Result<()> {
        if !self.can_accept(ip) {
            return Err(anyhow!("IP diversity limits exceeded"));
        }

        let count = self.ip_counts.get(&ip).copied().unwrap_or(0) + 1;
        self.ip_counts.put(ip, count);

        let subnet = Self::subnet_key(ip);
        let count = self.subnet_counts.get(&subnet).copied().unwrap_or(0) + 1;
        self.subnet_counts.put(subnet, count);

        Ok(())
    }

    /// Remove a tracked IP address from the diversity enforcer.
    #[allow(dead_code)]
    pub fn untrack(&mut self, ip: IpAddr) {
        if let Some(count) = self.ip_counts.pop(&ip) {
            let new = count.saturating_sub(1);
            if new > 0 {
                self.ip_counts.put(ip, new);
            }
        }

        let subnet = Self::subnet_key(ip);
        if let Some(count) = self.subnet_counts.pop(&subnet) {
            let new = count.saturating_sub(1);
            if new > 0 {
                self.subnet_counts.put(subnet, new);
            }
        }
    }
}

#[cfg(test)]
impl BootstrapIpLimiter {
    #[allow(dead_code)]
    pub fn config(&self) -> &IPDiversityConfig {
        &self.config
    }
}

/// GeoIP/ASN provider trait
#[allow(dead_code)]
pub trait GeoProvider: std::fmt::Debug {
    fn lookup(&self, ip: Ipv6Addr) -> GeoInfo;
}

/// Geo information
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

        assert!(config.max_per_ip.is_none());
        assert!(config.max_per_subnet.is_none());
    }

    #[test]
    fn test_bootstrap_ip_limiter_creation() {
        let config = IPDiversityConfig {
            max_per_ip: None,
            max_per_subnet: Some(1),
        };
        let enforcer = BootstrapIpLimiter::with_loopback(config.clone(), true);

        assert_eq!(enforcer.config.max_per_subnet, config.max_per_subnet);
    }

    #[test]
    fn test_can_accept_basic() {
        let config = IPDiversityConfig::default();
        let enforcer = BootstrapIpLimiter::new(config);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(enforcer.can_accept(ip));
    }

    #[test]
    fn test_ip_limit_enforcement() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(usize::MAX),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // First node should be accepted
        assert!(enforcer.can_accept(ip));
        enforcer.track(ip).unwrap();

        // Second node with same IP should be rejected
        assert!(!enforcer.can_accept(ip));
        assert!(enforcer.track(ip).is_err());
    }

    #[test]
    fn test_subnet_limit_enforcement_ipv4() {
        let config = IPDiversityConfig {
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(2),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Two IPs in same /24 subnet
        let ip1: IpAddr = "10.0.1.1".parse().unwrap();
        let ip2: IpAddr = "10.0.1.2".parse().unwrap();
        let ip3: IpAddr = "10.0.1.3".parse().unwrap();

        enforcer.track(ip1).unwrap();
        enforcer.track(ip2).unwrap();

        // Third in same /24 should be rejected
        assert!(!enforcer.can_accept(ip3));
        assert!(enforcer.track(ip3).is_err());

        // Different /24 should still be accepted
        let ip_other: IpAddr = "10.0.2.1".parse().unwrap();
        assert!(enforcer.can_accept(ip_other));
    }

    #[test]
    fn test_subnet_limit_enforcement_ipv6() {
        let config = IPDiversityConfig {
            max_per_ip: Some(usize::MAX),
            max_per_subnet: Some(1),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        // Two IPs in same /64 subnet
        let ip1: IpAddr = "2001:db8:85a3:1234::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:85a3:1234::2".parse().unwrap();

        enforcer.track(ip1).unwrap();

        // Second in same /64 should be rejected
        assert!(!enforcer.can_accept(ip2));

        // Different /64 should be accepted
        let ip_other: IpAddr = "2001:db8:85a3:5678::1".parse().unwrap();
        assert!(enforcer.can_accept(ip_other));
    }

    #[test]
    fn test_track_and_untrack() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(usize::MAX),
        };
        let mut enforcer = BootstrapIpLimiter::new(config);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Track
        enforcer.track(ip).unwrap();
        assert!(!enforcer.can_accept(ip));

        // Untrack
        enforcer.untrack(ip);
        assert!(enforcer.can_accept(ip));

        // Can track again after untrack
        enforcer.track(ip).unwrap();
        assert!(!enforcer.can_accept(ip));
    }

    #[test]
    fn test_loopback_bypass() {
        let config = IPDiversityConfig {
            max_per_ip: Some(1),
            max_per_subnet: Some(1),
        };

        // With loopback enabled
        let enforcer = BootstrapIpLimiter::with_loopback(config.clone(), true);
        let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
        let loopback_v6: IpAddr = "::1".parse().unwrap();
        assert!(enforcer.can_accept(loopback_v4));
        assert!(enforcer.can_accept(loopback_v6));

        // With loopback disabled (default)
        let mut enforcer_no_lb = BootstrapIpLimiter::new(config);
        enforcer_no_lb.track(loopback_v4).unwrap();
        // After tracking once, should be rejected (limit=1)
        assert!(!enforcer_no_lb.can_accept(loopback_v4));
    }

    #[test]
    fn test_subnet_key_ipv4() {
        let ip: IpAddr = "192.168.42.100".parse().unwrap();
        let subnet = BootstrapIpLimiter::subnet_key(ip);
        let expected: IpAddr = "192.168.42.0".parse().unwrap();
        assert_eq!(subnet, expected);
    }

    #[test]
    fn test_subnet_key_ipv6() {
        let ip: IpAddr = "2001:db8:85a3:1234:5678:8a2e:0370:7334".parse().unwrap();
        let subnet = BootstrapIpLimiter::subnet_key(ip);
        let expected: IpAddr = "2001:db8:85a3:1234::".parse().unwrap();
        assert_eq!(subnet, expected);
    }

    #[test]
    fn test_default_limits_are_two() {
        let config = IPDiversityConfig::default();
        let mut enforcer = BootstrapIpLimiter::new(config);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();

        // Default IP limit is 2, so two tracks should succeed
        enforcer.track(ip1).unwrap();
        enforcer.track(ip1).unwrap();

        // Third should fail
        assert!(!enforcer.can_accept(ip1));
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
}
