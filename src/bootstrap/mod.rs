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

//! Bootstrap Cache System
//!
//! Provides decentralized peer discovery through local caching of known contacts.
//! Uses saorsa-transport's BootstrapCache internally with additional Sybil protection
//! via rate limiting and IP diversity enforcement.

pub mod manager;

// Re-export the primary BootstrapManager (wraps saorsa-transport)
pub use manager::BootstrapManager;
pub use manager::{BootstrapConfig, BootstrapStats};

use crate::error::BootstrapError;
use crate::{P2PError, Result};
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::path::PathBuf;

/// Default directory for storing bootstrap cache files
pub const DEFAULT_CACHE_DIR: &str = ".cache/saorsa";

/// Convert an IP address to IPv6
///
/// IPv4 addresses are converted to IPv6-mapped format (::ffff:a.b.c.d)
/// IPv6 addresses are returned as-is
pub fn ip_to_ipv6(ip: &IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
        IpAddr::V6(ipv6) => *ipv6,
    }
}

/// Get the home cache directory
pub fn home_cache_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            P2PError::Bootstrap(BootstrapError::CacheError(
                "Unable to determine home directory".to_string().into(),
            ))
        })?;

    let cache_dir = PathBuf::from(home).join(DEFAULT_CACHE_DIR);

    // Ensure cache directory exists
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        P2PError::Bootstrap(BootstrapError::CacheError(
            format!("Failed to create cache directory: {e}").into(),
        ))
    })?;

    Ok(cache_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NodeConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bootstrap_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = BootstrapConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            max_peers: 1000,
            ..BootstrapConfig::default()
        };
        let node_config = NodeConfig::default();

        let manager = BootstrapManager::with_node_config(config, &node_config).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_home_cache_dir() {
        let result = home_cache_dir();
        assert!(result.is_ok());

        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.is_dir());
    }
}
