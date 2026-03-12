//! Routing maintenance configuration
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::time::Duration;

use crate::dht::DHTConfig;

/// Configuration for routing table maintenance (peer phonebook only)
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// How often to refresh buckets (from DHTConfig.bucket_refresh_interval)
    pub bucket_refresh_interval: Duration,
    /// Ping timeout for liveness checks
    pub ping_timeout: Duration,
    /// Max consecutive failures before eviction
    pub max_consecutive_failures: u32,
    /// Minimum trust threshold for eviction (0.0-1.0)
    pub min_trust_threshold: f64,
    /// Byzantine fault tolerance parameter (f in 3f+1)
    /// Default: 2 (tolerate 2 Byzantine faults, need 5 witnesses)
    pub bft_fault_tolerance: usize,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            bucket_refresh_interval: Duration::from_secs(3600),
            ping_timeout: Duration::from_secs(5),
            max_consecutive_failures: 3,
            min_trust_threshold: 0.15,
            bft_fault_tolerance: 2,
        }
    }
}

impl MaintenanceConfig {
    /// Calculate required confirmations for BFT consensus
    /// For f Byzantine faults, need 2f+1 confirmations
    #[must_use]
    pub fn required_confirmations(&self) -> usize {
        2 * self.bft_fault_tolerance + 1
    }

    /// Calculate minimum witnesses needed (3f+1)
    #[must_use]
    pub fn minimum_witnesses(&self) -> usize {
        3 * self.bft_fault_tolerance + 1
    }
}

impl From<&DHTConfig> for MaintenanceConfig {
    fn from(dht_config: &DHTConfig) -> Self {
        Self {
            bucket_refresh_interval: dht_config.bucket_refresh_interval,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maintenance_config_has_sane_defaults() {
        let config = MaintenanceConfig::default();
        assert!(config.ping_timeout <= Duration::from_secs(10));
        assert!(config.max_consecutive_failures >= 3);
        assert!(config.min_trust_threshold > 0.0);
        assert!(config.min_trust_threshold < 1.0);
        assert_eq!(config.bft_fault_tolerance, 2);
    }

    #[test]
    fn test_maintenance_config_from_dht_config() {
        let dht_config = DHTConfig {
            bucket_refresh_interval: Duration::from_secs(1800),
            ..Default::default()
        };
        let maintenance_config = MaintenanceConfig::from(&dht_config);
        assert_eq!(
            maintenance_config.bucket_refresh_interval,
            Duration::from_secs(1800)
        );
        // Other fields should use defaults
        assert_eq!(maintenance_config.ping_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_bft_threshold_calculation() {
        // For f=2 Byzantine faults, need 2f+1 = 5 confirmations
        let config = MaintenanceConfig {
            bft_fault_tolerance: 2,
            ..Default::default()
        };
        assert_eq!(config.required_confirmations(), 5);

        // For f=1, need 3 confirmations
        let config_f1 = MaintenanceConfig {
            bft_fault_tolerance: 1,
            ..Default::default()
        };
        assert_eq!(config_f1.required_confirmations(), 3);
    }

    #[test]
    fn test_minimum_witnesses_calculation() {
        // For f=2, minimum witnesses is 3f+1 = 7
        let config = MaintenanceConfig {
            bft_fault_tolerance: 2,
            ..Default::default()
        };
        assert_eq!(config.minimum_witnesses(), 7);
    }
}
