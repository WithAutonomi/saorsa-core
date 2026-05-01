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
//! IP diversity configuration and helpers used by the DHT routing-table
//! Sybil defenses.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

/// Max nodes sharing an exact IP address per bucket/close-group.
/// Used by `DhtCoreEngine` when `IPDiversityConfig::max_per_ip` is `None`.
pub const IP_EXACT_LIMIT: usize = 2;

/// Canonicalize an IP address: map IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to
/// its IPv4 equivalent so that diversity limits are enforced uniformly
/// regardless of which address family the transport layer reports.
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// Compute the subnet diversity limit from the active K value.
/// At least 1 node per subnet is always permitted.
pub const fn ip_subnet_limit(k: usize) -> usize {
    if k / 4 > 0 { k / 4 } else { 1 }
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

    /// Override for max nodes in the same subnet (/24 IPv4, /48 IPv6).
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
    /// Currently identical to [`permissive`](Self::permissive) but kept as a
    /// separate constructor so testnet limits can diverge independently (e.g.
    /// allowing same-subnet but limiting per-IP) without changing local-dev
    /// callers.
    ///
    /// # Warning
    ///
    /// This configuration should NEVER be used in production as it significantly
    /// weakens Sybil attack protection.
    #[must_use]
    pub fn testnet() -> Self {
        Self::permissive()
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

    /// Validate IP diversity parameter safety constraints.
    ///
    /// Returns `Err` if any explicit limit is less than 1.
    pub fn validate(&self) -> Result<()> {
        if let Some(limit) = self.max_per_ip
            && limit < 1
        {
            anyhow::bail!("max_per_ip must be >= 1 (got {limit})");
        }
        if let Some(limit) = self.max_per_subnet
            && limit < 1
        {
            anyhow::bail!("max_per_subnet must be >= 1 (got {limit})");
        }
        Ok(())
    }
}

/// GeoIP/ASN provider trait.
///
/// Used by `BgpGeoProvider` in the transport layer; kept here so it can be
/// shared across crates without a circular dependency.
#[allow(dead_code)]
pub trait GeoProvider: std::fmt::Debug {
    /// Look up geo/ASN information for an IP address.
    fn lookup(&self, ip: Ipv6Addr) -> GeoInfo;
}

/// Geo information for a peer's IP address.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GeoInfo {
    /// Autonomous System Number
    pub asn: Option<u32>,
    /// Country code
    pub country: Option<String>,
    /// Whether the IP belongs to a known hosting provider
    pub is_hosting_provider: bool,
    /// Whether the IP belongs to a known VPN provider
    pub is_vpn_provider: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_diversity_config_default() {
        let config = IPDiversityConfig::default();
        assert!(config.max_per_ip.is_none());
        assert!(config.max_per_subnet.is_none());
    }

    #[test]
    fn test_canonicalize_ipv4_mapped() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let canonical = canonicalize_ip(mapped);
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn test_canonicalize_native_ipv6_unchanged() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonicalize_ip(v6), v6);
    }

    #[test]
    fn test_ip_subnet_limit() {
        assert_eq!(ip_subnet_limit(20), 5);
        assert_eq!(ip_subnet_limit(8), 2);
        assert_eq!(ip_subnet_limit(1), 1);
        assert_eq!(ip_subnet_limit(0), 1);
    }
}
