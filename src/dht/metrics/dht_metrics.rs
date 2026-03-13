// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! DHT health metrics for routing and operations
//!
//! Tracks metrics for:
//! - Routing table health and k-bucket status
//! - Lookup latency (P50, P95, P99)
//! - Operation success rates
//! - Bucket refresh and liveness checks

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

/// DHT health metrics data structure
#[derive(Debug, Clone, Default)]
pub struct DhtHealthMetrics {
    // Routing table metrics
    /// Number of nodes in routing table
    pub routing_table_size: u64,
    /// Number of non-empty k-buckets
    pub buckets_filled: u64,
    /// Average bucket fullness (0-1)
    pub bucket_fullness: f64,

    // Latency metrics
    /// P50 lookup latency in milliseconds
    pub lookup_latency_p50_ms: f64,
    /// P95 lookup latency in milliseconds
    pub lookup_latency_p95_ms: f64,
    /// P99 lookup latency in milliseconds
    pub lookup_latency_p99_ms: f64,
    /// Average number of hops per lookup
    pub lookup_hops_avg: f64,

    // Operation metrics
    /// Total DHT operations
    pub operations_total: u64,
    /// Successful DHT operations
    pub operations_success_total: u64,
    /// Failed DHT operations
    pub operations_failed_total: u64,
    /// Operation success rate (0-1)
    pub success_rate: f64,

    // Refresh metrics
    /// Total bucket refresh operations
    pub bucket_refresh_total: u64,
    /// Total node liveness checks
    pub liveness_checks_total: u64,
    /// Failed node liveness checks
    pub liveness_failures_total: u64,
}

/// Latency sample for percentile calculations
#[derive(Debug, Clone)]
struct LatencySample {
    duration_ms: f64,
    hops: u64,
}

/// Thread-safe DHT health metrics collector
pub struct DhtMetricsCollector {
    // Routing table metrics
    routing_table_size: AtomicU64,
    buckets_filled: AtomicU64,
    bucket_fullness: AtomicU64, // Stored as millipercent

    // Latency samples (rolling window)
    latency_samples: Arc<RwLock<VecDeque<LatencySample>>>,
    max_samples: usize,

    // Operation counters
    operations_total: AtomicU64,
    operations_success_total: AtomicU64,
    operations_failed_total: AtomicU64,

    // Refresh counters
    bucket_refresh_total: AtomicU64,
    liveness_checks_total: AtomicU64,
    liveness_failures_total: AtomicU64,
}

impl DhtMetricsCollector {
    /// Create a new DHT metrics collector
    pub fn new() -> Self {
        Self::with_max_samples(10000)
    }

    /// Create a new DHT metrics collector with custom sample limit
    pub fn with_max_samples(max_samples: usize) -> Self {
        Self {
            routing_table_size: AtomicU64::new(0),
            buckets_filled: AtomicU64::new(0),
            bucket_fullness: AtomicU64::new(0),
            latency_samples: Arc::new(RwLock::new(VecDeque::new())),
            max_samples,
            operations_total: AtomicU64::new(0),
            operations_success_total: AtomicU64::new(0),
            operations_failed_total: AtomicU64::new(0),
            bucket_refresh_total: AtomicU64::new(0),
            liveness_checks_total: AtomicU64::new(0),
            liveness_failures_total: AtomicU64::new(0),
        }
    }

    /// Update routing table size
    pub fn set_routing_table_size(&self, size: u64) {
        self.routing_table_size.store(size, Ordering::Relaxed);
    }

    /// Update number of filled buckets
    pub fn set_buckets_filled(&self, count: u64) {
        self.buckets_filled.store(count, Ordering::Relaxed);
    }

    /// Update bucket fullness (0.0 - 1.0)
    pub fn set_bucket_fullness(&self, fullness: f64) {
        let millipercent = (fullness.clamp(0.0, 1.0) * 1000.0) as u64;
        self.bucket_fullness.store(millipercent, Ordering::Relaxed);
    }

    /// Record a lookup operation with latency and hops
    pub async fn record_lookup(&self, duration: Duration, hops: u64, success: bool) {
        // Record latency sample
        let sample = LatencySample {
            duration_ms: duration.as_secs_f64() * 1000.0,
            hops,
        };

        let mut samples = self.latency_samples.write().await;
        samples.push_back(sample);

        // Maintain rolling window
        while samples.len() > self.max_samples {
            samples.pop_front();
        }
        drop(samples);

        // Update operation counters
        self.operations_total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.operations_success_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.operations_failed_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a bucket refresh operation
    pub fn record_bucket_refresh(&self) {
        self.bucket_refresh_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a liveness check result
    pub fn record_liveness_check(&self, success: bool) {
        self.liveness_checks_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.liveness_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Calculate percentile from samples
    fn calculate_percentile(sorted_values: &[f64], percentile: f64) -> f64 {
        if sorted_values.is_empty() {
            return 0.0;
        }

        let index = (percentile / 100.0 * (sorted_values.len() - 1) as f64).ceil() as usize;
        sorted_values[index.min(sorted_values.len() - 1)]
    }

    /// Get current metrics snapshot
    pub async fn get_metrics(&self) -> DhtHealthMetrics {
        // Calculate latency percentiles
        let samples = self.latency_samples.read().await;
        let (p50, p95, p99, avg_hops) = if samples.is_empty() {
            (0.0, 0.0, 0.0, 0.0)
        } else {
            let mut latencies: Vec<f64> = samples.iter().map(|s| s.duration_ms).collect();
            latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let p50 = Self::calculate_percentile(&latencies, 50.0);
            let p95 = Self::calculate_percentile(&latencies, 95.0);
            let p99 = Self::calculate_percentile(&latencies, 99.0);

            let avg_hops =
                samples.iter().map(|s| s.hops as f64).sum::<f64>() / samples.len() as f64;

            (p50, p95, p99, avg_hops)
        };
        drop(samples);

        // Calculate success rate
        let total = self.operations_total.load(Ordering::Relaxed);
        let success = self.operations_success_total.load(Ordering::Relaxed);
        let success_rate = if total > 0 {
            success as f64 / total as f64
        } else {
            1.0 // Default to 1.0 when no operations recorded
        };

        DhtHealthMetrics {
            routing_table_size: self.routing_table_size.load(Ordering::Relaxed),
            buckets_filled: self.buckets_filled.load(Ordering::Relaxed),
            bucket_fullness: self.bucket_fullness.load(Ordering::Relaxed) as f64 / 1000.0,
            lookup_latency_p50_ms: p50,
            lookup_latency_p95_ms: p95,
            lookup_latency_p99_ms: p99,
            lookup_hops_avg: avg_hops,
            operations_total: total,
            operations_success_total: success,
            operations_failed_total: self.operations_failed_total.load(Ordering::Relaxed),
            success_rate,
            bucket_refresh_total: self.bucket_refresh_total.load(Ordering::Relaxed),
            liveness_checks_total: self.liveness_checks_total.load(Ordering::Relaxed),
            liveness_failures_total: self.liveness_failures_total.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters and samples
    pub async fn reset(&self) {
        self.routing_table_size.store(0, Ordering::Relaxed);
        self.buckets_filled.store(0, Ordering::Relaxed);
        self.bucket_fullness.store(0, Ordering::Relaxed);
        self.operations_total.store(0, Ordering::Relaxed);
        self.operations_success_total.store(0, Ordering::Relaxed);
        self.operations_failed_total.store(0, Ordering::Relaxed);
        self.bucket_refresh_total.store(0, Ordering::Relaxed);
        self.liveness_checks_total.store(0, Ordering::Relaxed);
        self.liveness_failures_total.store(0, Ordering::Relaxed);
        self.latency_samples.write().await.clear();
    }
}

impl Default for DhtMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dht_metrics_creation() {
        let collector = DhtMetricsCollector::new();
        let metrics = collector.get_metrics().await;

        assert_eq!(metrics.routing_table_size, 0);
        assert!((metrics.success_rate - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_routing_table_updates() {
        let collector = DhtMetricsCollector::new();

        collector.set_routing_table_size(150);
        collector.set_buckets_filled(45);
        collector.set_bucket_fullness(0.75);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.routing_table_size, 150);
        assert_eq!(metrics.buckets_filled, 45);
        assert!((metrics.bucket_fullness - 0.75).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_latency_tracking() {
        let collector = DhtMetricsCollector::new();

        // Add some lookup samples
        for i in 0u64..100 {
            let duration = Duration::from_millis(10 + (i % 50));
            let hops = 3 + (i % 3);
            collector.record_lookup(duration, hops, true).await;
        }

        let metrics = collector.get_metrics().await;
        assert!(metrics.lookup_latency_p50_ms > 0.0);
        assert!(metrics.lookup_latency_p95_ms >= metrics.lookup_latency_p50_ms);
        assert!(metrics.lookup_latency_p99_ms >= metrics.lookup_latency_p95_ms);
        assert!(metrics.lookup_hops_avg >= 3.0);
    }

    #[tokio::test]
    async fn test_operation_success_rate() {
        let collector = DhtMetricsCollector::new();

        // Record 7 successes and 3 failures
        for i in 0..10 {
            let success = i < 7;
            collector
                .record_lookup(Duration::from_millis(10), 3, success)
                .await;
        }

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.operations_total, 10);
        assert_eq!(metrics.operations_success_total, 7);
        assert_eq!(metrics.operations_failed_total, 3);
        assert!((metrics.success_rate - 0.7).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_liveness_checks() {
        let collector = DhtMetricsCollector::new();

        collector.record_liveness_check(true);
        collector.record_liveness_check(true);
        collector.record_liveness_check(false);
        collector.record_liveness_check(true);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.liveness_checks_total, 4);
        assert_eq!(metrics.liveness_failures_total, 1);
    }

    #[tokio::test]
    async fn test_bucket_refresh() {
        let collector = DhtMetricsCollector::new();

        collector.record_bucket_refresh();
        collector.record_bucket_refresh();
        collector.record_bucket_refresh();

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.bucket_refresh_total, 3);
    }

    #[tokio::test]
    async fn test_rolling_window() {
        let collector = DhtMetricsCollector::with_max_samples(100);

        // Add more samples than the window size
        for i in 0..200 {
            let duration = Duration::from_millis(10 + i as u64);
            collector.record_lookup(duration, 3, true).await;
        }

        let samples = collector.latency_samples.read().await;
        assert_eq!(samples.len(), 100);
    }

    #[tokio::test]
    async fn test_reset() {
        let collector = DhtMetricsCollector::new();

        collector.set_routing_table_size(100);
        collector
            .record_lookup(Duration::from_millis(50), 3, true)
            .await;
        collector.record_bucket_refresh();

        collector.reset().await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.routing_table_size, 0);
        assert_eq!(metrics.operations_total, 0);
        assert_eq!(metrics.bucket_refresh_total, 0);
    }

    #[tokio::test]
    async fn test_default_success_rate() {
        let collector = DhtMetricsCollector::new();
        let metrics = collector.get_metrics().await;

        // Default should be 1.0 when no operations recorded
        assert!((metrics.success_rate - 1.0).abs() < 0.01);
    }
}
