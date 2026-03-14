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
    /// Max consecutive failures before eviction
    pub max_consecutive_failures: u32,
    /// Minimum trust threshold for eviction (0.0-1.0)
    pub min_trust_threshold: f64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            bucket_refresh_interval: Duration::from_secs(3600),
            max_consecutive_failures: 3,
            min_trust_threshold: 0.15,
        }
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
        assert!(config.max_consecutive_failures >= 3);
        assert!(config.min_trust_threshold > 0.0);
        assert!(config.min_trust_threshold < 1.0);
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
    }
}
