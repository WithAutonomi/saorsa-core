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

//! Geographic-Aware DHT Routing Core Components
//!
//! Provides region-based routing optimization for improved P2P network performance
//! across different geographic areas with latency and reliability considerations.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Geographic regions for DHT routing optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeographicRegion {
    NorthAmerica,
    Europe,
    AsiaPacific,
    SouthAmerica,
    Africa,
    Oceania,
    Unknown,
}

impl GeographicRegion {
    /// Determine geographic region from IP address
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                // Basic IP range mapping for major regions
                let octets = ipv4.octets();
                match octets[0] {
                    // North America (simplified ranges)
                    1..=99 => GeographicRegion::NorthAmerica,
                    100..=126 => GeographicRegion::NorthAmerica,
                    // Europe (including DigitalOcean European infrastructure)
                    127..=159 => GeographicRegion::Europe,
                    // Asia Pacific
                    160..=191 => GeographicRegion::AsiaPacific,
                    // More North America
                    192..=223 => GeographicRegion::NorthAmerica,
                    // Rest mapped to regions
                    224..=239 => GeographicRegion::SouthAmerica,
                    240..=247 => GeographicRegion::Africa,
                    248..=251 => GeographicRegion::Oceania,
                    _ => GeographicRegion::Unknown,
                }
            }
            IpAddr::V6(_) => {
                // IPv6 region detection would be more complex
                // For now, default to Unknown and rely on explicit configuration
                GeographicRegion::Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_geographic_region_from_ip() {
        // Test DigitalOcean IP (159.89.81.21)
        let digitalocean_ip = IpAddr::V4(Ipv4Addr::new(159, 89, 81, 21));
        assert_eq!(
            GeographicRegion::from_ip(digitalocean_ip),
            GeographicRegion::Europe
        );

        // Test other regions
        let na_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(
            GeographicRegion::from_ip(na_ip),
            GeographicRegion::NorthAmerica
        );
    }
}
