// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Placement metrics for peer distribution and load management
//!
//! Tracks metrics for:
//! - Geographic diversity
//! - Load balancing
//! - Audits

use std::sync::atomic::{AtomicU64, Ordering};

/// Placement metrics data structure
#[derive(Debug, Clone, Default)]
pub struct PlacementMetrics {
    // Geographic diversity metrics
    /// Geographic diversity score (0-1)
    pub geographic_diversity: f64,
    /// Number of geographic regions with nodes
    pub regions_covered: u64,

    // Load balancing metrics
    /// Load balance score (0-1, higher is better)
    pub load_balance_score: f64,
    /// Number of overloaded nodes
    pub overloaded_nodes: u64,
    /// Total rebalance operations performed
    pub rebalance_operations_total: u64,

    // Audit metrics
    /// Total audits performed
    pub audits_total: u64,
    /// Total audit failures
    pub audit_failures_total: u64,
}

/// Thread-safe placement metrics collector
pub struct PlacementMetricsCollector {
    // Geographic diversity (stored as millipercent)
    geographic_diversity: AtomicU64,
    regions_covered: AtomicU64,

    // Load balancing
    load_balance_score: AtomicU64, // Stored as millipercent
    overloaded_nodes: AtomicU64,
    rebalance_operations_total: AtomicU64,

    // Audit metrics
    audits_total: AtomicU64,
    audit_failures_total: AtomicU64,
}

impl PlacementMetricsCollector {
    /// Create a new placement metrics collector
    pub fn new() -> Self {
        Self {
            geographic_diversity: AtomicU64::new(1000), // Default 1.0
            regions_covered: AtomicU64::new(0),
            load_balance_score: AtomicU64::new(1000), // Default 1.0 (perfect balance)
            overloaded_nodes: AtomicU64::new(0),
            rebalance_operations_total: AtomicU64::new(0),
            audits_total: AtomicU64::new(0),
            audit_failures_total: AtomicU64::new(0),
        }
    }

    /// Update geographic diversity score (0.0 - 1.0)
    pub fn set_geographic_diversity(&self, diversity: f64) {
        let millipercent = (diversity.clamp(0.0, 1.0) * 1000.0) as u64;
        self.geographic_diversity
            .store(millipercent, Ordering::Relaxed);
    }

    /// Update regions covered count
    pub fn set_regions_covered(&self, count: u64) {
        self.regions_covered.store(count, Ordering::Relaxed);
    }

    /// Update load balance score (0.0 - 1.0)
    pub fn set_load_balance_score(&self, score: f64) {
        let millipercent = (score.clamp(0.0, 1.0) * 1000.0) as u64;
        self.load_balance_score
            .store(millipercent, Ordering::Relaxed);
    }

    /// Update overloaded node count
    pub fn set_overloaded_nodes(&self, count: u64) {
        self.overloaded_nodes.store(count, Ordering::Relaxed);
    }

    /// Record a rebalance operation
    pub fn record_rebalance(&self) {
        self.rebalance_operations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an audit result
    pub fn record_audit(&self, success: bool) {
        self.audits_total.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.audit_failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Calculate load balance score from node loads
    /// Lower variance = better balance = higher score
    pub fn calculate_load_balance(&self, loads: &[f64]) -> f64 {
        if loads.is_empty() || loads.len() == 1 {
            return 1.0; // Perfect balance with 0 or 1 nodes
        }

        let n = loads.len() as f64;
        let mean = loads.iter().sum::<f64>() / n;

        if mean == 0.0 {
            return 1.0; // No load = perfect balance
        }

        // Calculate coefficient of variation (CV)
        let variance = loads.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean;

        // Convert CV to score: CV=0 -> score=1.0, CV=1 -> score=0.5
        // Higher CV means more imbalance
        let score = 1.0 / (1.0 + cv);

        // Update the metric
        self.set_load_balance_score(score);

        // Count overloaded nodes (load > 0.8)
        let overloaded = loads.iter().filter(|&&l| l > 0.8).count() as u64;
        self.set_overloaded_nodes(overloaded);

        score
    }

    /// Get current metrics snapshot
    pub async fn get_metrics(&self) -> PlacementMetrics {
        PlacementMetrics {
            geographic_diversity: self.geographic_diversity.load(Ordering::Relaxed) as f64 / 1000.0,
            regions_covered: self.regions_covered.load(Ordering::Relaxed),
            load_balance_score: self.load_balance_score.load(Ordering::Relaxed) as f64 / 1000.0,
            overloaded_nodes: self.overloaded_nodes.load(Ordering::Relaxed),
            rebalance_operations_total: self.rebalance_operations_total.load(Ordering::Relaxed),
            audits_total: self.audits_total.load(Ordering::Relaxed),
            audit_failures_total: self.audit_failures_total.load(Ordering::Relaxed),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.geographic_diversity.store(1000, Ordering::Relaxed);
        self.regions_covered.store(0, Ordering::Relaxed);
        self.load_balance_score.store(1000, Ordering::Relaxed);
        self.overloaded_nodes.store(0, Ordering::Relaxed);
        self.rebalance_operations_total.store(0, Ordering::Relaxed);
        self.audits_total.store(0, Ordering::Relaxed);
        self.audit_failures_total.store(0, Ordering::Relaxed);
    }
}

impl Default for PlacementMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_placement_metrics_creation() {
        let collector = PlacementMetricsCollector::new();
        let metrics = collector.get_metrics().await;

        assert!((metrics.geographic_diversity - 1.0).abs() < 0.01);
        assert!((metrics.load_balance_score - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_geographic_diversity() {
        let collector = PlacementMetricsCollector::new();

        collector.set_geographic_diversity(0.75);
        collector.set_regions_covered(5);

        let metrics = collector.get_metrics().await;
        assert!((metrics.geographic_diversity - 0.75).abs() < 0.01);
        assert_eq!(metrics.regions_covered, 5);
    }

    #[tokio::test]
    async fn test_load_balance_calculation() {
        let collector = PlacementMetricsCollector::new();

        // Perfect balance: all nodes have same load
        let perfect_loads = vec![0.5, 0.5, 0.5, 0.5];
        let score = collector.calculate_load_balance(&perfect_loads);
        assert!((score - 1.0).abs() < 0.01);

        // Imbalanced: varying loads
        let imbalanced_loads = vec![0.1, 0.3, 0.6, 0.9];
        let score = collector.calculate_load_balance(&imbalanced_loads);
        assert!(score < 1.0);
        assert!(score > 0.0);
    }

    #[tokio::test]
    async fn test_overloaded_nodes_detection() {
        let collector = PlacementMetricsCollector::new();

        // 2 nodes above 0.8 threshold
        let loads = vec![0.5, 0.6, 0.85, 0.95];
        collector.calculate_load_balance(&loads);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.overloaded_nodes, 2);
    }

    #[tokio::test]
    async fn test_rebalance_operations() {
        let collector = PlacementMetricsCollector::new();

        collector.record_rebalance();
        collector.record_rebalance();
        collector.record_rebalance();

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.rebalance_operations_total, 3);
    }

    #[tokio::test]
    async fn test_audit_tracking() {
        let collector = PlacementMetricsCollector::new();

        collector.record_audit(true);
        collector.record_audit(true);
        collector.record_audit(false);
        collector.record_audit(true);

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.audits_total, 4);
        assert_eq!(metrics.audit_failures_total, 1);
    }

    #[tokio::test]
    async fn test_reset() {
        let collector = PlacementMetricsCollector::new();

        collector.set_geographic_diversity(0.5);
        collector.record_audit(false);
        collector.record_rebalance();

        collector.reset();

        let metrics = collector.get_metrics().await;
        assert!((metrics.geographic_diversity - 1.0).abs() < 0.01);
        assert_eq!(metrics.audits_total, 0);
        assert_eq!(metrics.rebalance_operations_total, 0);
    }

    #[tokio::test]
    async fn test_empty_load_balance() {
        let collector = PlacementMetricsCollector::new();

        // Empty loads
        let score = collector.calculate_load_balance(&[]);
        assert!((score - 1.0).abs() < 0.01);

        // Single node
        let score = collector.calculate_load_balance(&[0.5]);
        assert!((score - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_zero_load_balance() {
        let collector = PlacementMetricsCollector::new();

        // All nodes have zero load
        let loads = vec![0.0, 0.0, 0.0];
        let score = collector.calculate_load_balance(&loads);
        assert!((score - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_diversity_clamping() {
        let collector = PlacementMetricsCollector::new();

        // Test upper bound clamping
        collector.set_geographic_diversity(1.5);
        let metrics = collector.get_metrics().await;
        assert!((metrics.geographic_diversity - 1.0).abs() < 0.01);

        // Test lower bound clamping
        collector.set_geographic_diversity(-0.5);
        let metrics = collector.get_metrics().await;
        assert!((metrics.geographic_diversity - 0.0).abs() < 0.01);
    }
}
