// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Business metrics for P2P network operations

use crate::Result;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of operation history entries to retain
const MAX_OPERATION_HISTORY: usize = 1000;

/// Window (in seconds) for computing recent operation statistics
const RECENT_OPERATIONS_WINDOW_SECS: u64 = 300;

/// Window (in seconds) for computing operations-per-second rate
const OPS_RATE_WINDOW_SECS: u64 = 60;

/// Business metrics for DHT peer-phonebook operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessMetrics {
    pub active_peers: u64,
    pub operations_per_second: f64,
    pub dht_success_rate: f64,
    pub network_growth_rate: f64,
    pub average_response_time_ms: f64,
    pub timestamp: u64,
}

impl BusinessMetrics {
    pub fn new() -> Self {
        Self {
            active_peers: 0,
            operations_per_second: 0.0,
            dht_success_rate: 1.0,
            network_growth_rate: 0.0,
            average_response_time_ms: 0.0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl Default for BusinessMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks DHT operation outcome for success-rate and latency calculations.
///
/// Fields: `(timestamp_secs, success, latency_ms)`
type OperationRecord = (u64, bool, u64);

/// Business metrics collector with thread-safe operations
pub struct BusinessMetricsCollector {
    metrics: Arc<RwLock<BusinessMetrics>>,
    operation_history: Arc<RwLock<Vec<OperationRecord>>>,
}

impl BusinessMetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(BusinessMetrics::new())),
            operation_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn record_peer_connected(&self) -> Result<()> {
        let mut metrics = self.metrics.write().map_err(|e| {
            crate::P2PError::Internal(format!("Failed to acquire metrics lock: {}", e).into())
        })?;
        metrics.active_peers += 1;
        Ok(())
    }

    pub fn record_peer_disconnected(&self) -> Result<()> {
        let mut metrics = self.metrics.write().map_err(|e| {
            crate::P2PError::Internal(format!("Failed to acquire metrics lock: {}", e).into())
        })?;
        if metrics.active_peers > 0 {
            metrics.active_peers -= 1;
        }
        Ok(())
    }

    /// Record the outcome of a DHT peer-lookup operation.
    pub fn record_dht_operation(&self, success: bool, latency_ms: u64) -> Result<()> {
        {
            let mut history = self.operation_history.write().map_err(|e| {
                crate::P2PError::Internal(format!("Failed to acquire history lock: {}", e).into())
            })?;
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            history.push((timestamp, success, latency_ms));

            if history.len() > MAX_OPERATION_HISTORY {
                history.remove(0);
            }
        }

        self.update_rates()?;
        Ok(())
    }

    pub fn get_metrics(&self) -> Result<BusinessMetrics> {
        let metrics = self.metrics.read().map_err(|e| {
            crate::P2PError::Internal(format!("Failed to acquire metrics lock: {}", e).into())
        })?;
        Ok(metrics.clone())
    }

    fn update_rates(&self) -> Result<()> {
        let history = self.operation_history.read().map_err(|e| {
            crate::P2PError::Internal(format!("Failed to acquire history lock: {}", e).into())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let recent_operations: Vec<_> = history
            .iter()
            .filter(|(timestamp, _, _)| now - timestamp < RECENT_OPERATIONS_WINDOW_SECS)
            .collect();

        if recent_operations.is_empty() {
            return Ok(());
        }

        let mut metrics = self.metrics.write().map_err(|e| {
            crate::P2PError::Internal(format!("Failed to acquire metrics lock: {}", e).into())
        })?;

        let successful = recent_operations
            .iter()
            .filter(|(_, success, _)| *success)
            .count();
        metrics.dht_success_rate = successful as f64 / recent_operations.len() as f64;

        let total_latency: u64 = recent_operations
            .iter()
            .map(|(_, _, latency)| *latency)
            .sum();
        metrics.average_response_time_ms = total_latency as f64 / recent_operations.len() as f64;

        let ops_in_last_minute = recent_operations
            .iter()
            .filter(|(timestamp, _, _)| now - timestamp < OPS_RATE_WINDOW_SECS)
            .count();
        metrics.operations_per_second = ops_in_last_minute as f64 / OPS_RATE_WINDOW_SECS as f64;

        metrics.timestamp = now;
        Ok(())
    }

    pub fn to_prometheus(&self) -> Result<String> {
        let metrics = self.get_metrics()?;
        let mut output = String::new();

        output.push_str("# HELP p2p_active_peers Number of currently connected peers\n");
        output.push_str("# TYPE p2p_active_peers gauge\n");
        output.push_str(&format!("p2p_active_peers {}\n\n", metrics.active_peers));

        output.push_str("# HELP p2p_dht_success_rate DHT operation success rate (0.0 to 1.0)\n");
        output.push_str("# TYPE p2p_dht_success_rate gauge\n");
        output.push_str(&format!(
            "p2p_dht_success_rate {}\n\n",
            metrics.dht_success_rate
        ));

        output.push_str("# HELP p2p_operations_per_second Network operations per second\n");
        output.push_str("# TYPE p2p_operations_per_second gauge\n");
        output.push_str(&format!(
            "p2p_operations_per_second {}\n\n",
            metrics.operations_per_second
        ));

        output.push_str(
            "# HELP p2p_average_response_time_ms Average response time in milliseconds\n",
        );
        output.push_str("# TYPE p2p_average_response_time_ms gauge\n");
        output.push_str(&format!(
            "p2p_average_response_time_ms {}\n\n",
            metrics.average_response_time_ms
        ));

        output.push_str("# HELP p2p_network_growth_rate Network growth rate in peers per hour\n");
        output.push_str("# TYPE p2p_network_growth_rate gauge\n");
        output.push_str(&format!(
            "p2p_network_growth_rate {}\n\n",
            metrics.network_growth_rate
        ));

        Ok(output)
    }
}

impl Default for BusinessMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_business_metrics_creation() {
        let collector = BusinessMetricsCollector::new();
        let metrics = collector.get_metrics().unwrap();
        assert_eq!(metrics.active_peers, 0);
        assert!((metrics.dht_success_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_peer_tracking() {
        let collector = BusinessMetricsCollector::new();

        collector.record_peer_connected().unwrap();
        collector.record_peer_connected().unwrap();

        let metrics = collector.get_metrics().unwrap();
        assert_eq!(metrics.active_peers, 2);

        collector.record_peer_disconnected().unwrap();
        let metrics = collector.get_metrics().unwrap();
        assert_eq!(metrics.active_peers, 1);
    }

    #[test]
    fn test_dht_operation_tracking() {
        let collector = BusinessMetricsCollector::new();

        collector.record_dht_operation(true, 10).unwrap();
        collector.record_dht_operation(true, 20).unwrap();
        collector.record_dht_operation(false, 50).unwrap();

        let metrics = collector.get_metrics().unwrap();
        // 2 out of 3 succeeded
        assert!((metrics.dht_success_rate - 2.0 / 3.0).abs() < 0.01);
        // Average latency: (10 + 20 + 50) / 3 ≈ 26.67
        assert!((metrics.average_response_time_ms - 80.0 / 3.0).abs() < 0.01);
        assert!(metrics.operations_per_second > 0.0);
    }

    #[test]
    fn test_prometheus_export() {
        let collector = BusinessMetricsCollector::new();
        collector.record_peer_connected().unwrap();

        let prometheus = collector.to_prometheus().unwrap();
        assert!(prometheus.contains("p2p_active_peers 1"));
        assert!(prometheus.contains("p2p_dht_success_rate"));
        assert!(!prometheus.contains("p2p_storage"));
        assert!(!prometheus.contains("p2p_total_data"));
    }
}
