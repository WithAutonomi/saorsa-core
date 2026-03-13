// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Comprehensive DHT metrics for security, health, and trust monitoring
//!
//! This module provides production-ready metrics for monitoring:
//! - Security: Attack detection, Sybil/Eclipse indicators, collusion patterns
//! - DHT Health: Routing table, latency, churn
//! - Trust: EigenTrust scores, witness validation, reputation

pub mod dht_metrics;
pub mod security_dashboard;
pub mod security_metrics;
pub mod trust_metrics;

// Re-export main types
pub use dht_metrics::{DhtHealthMetrics, DhtMetricsCollector};
pub use security_dashboard::{
    AlertCategory, AlertSeverity, AlertThresholds, ComponentHealth, ComponentStatus,
    DashboardSnapshot, SecurityAlert, SecurityDashboard, SystemStatus,
};
pub use security_metrics::{SecurityMetrics, SecurityMetricsCollector};
pub use trust_metrics::{TrustMetrics, TrustMetricsCollector};

use std::fmt::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Unified metrics aggregator for all DHT-related metrics
pub struct DhtMetricsAggregator {
    security: Arc<SecurityMetricsCollector>,
    dht_health: Arc<DhtMetricsCollector>,
    trust: Arc<TrustMetricsCollector>,
}

impl DhtMetricsAggregator {
    /// Create a new metrics aggregator
    pub fn new() -> Self {
        Self {
            security: Arc::new(SecurityMetricsCollector::new()),
            dht_health: Arc::new(DhtMetricsCollector::new()),
            trust: Arc::new(TrustMetricsCollector::new()),
        }
    }

    /// Get the security metrics collector
    pub fn security(&self) -> &Arc<SecurityMetricsCollector> {
        &self.security
    }

    /// Get the DHT health metrics collector
    pub fn dht_health(&self) -> &Arc<DhtMetricsCollector> {
        &self.dht_health
    }

    /// Get the trust metrics collector
    pub fn trust(&self) -> &Arc<TrustMetricsCollector> {
        &self.trust
    }

    /// Export all metrics in Prometheus format
    pub async fn export_prometheus(&self) -> Result<String, std::fmt::Error> {
        let mut output = String::with_capacity(16384);

        // Security metrics
        let security = self.security.get_metrics().await;
        self.write_security_metrics(&mut output, &security)?;

        // DHT health metrics
        let dht_health = self.dht_health.get_metrics().await;
        self.write_dht_health_metrics(&mut output, &dht_health)?;

        // Trust metrics
        let trust = self.trust.get_metrics().await;
        self.write_trust_metrics(&mut output, &trust)?;

        // Add timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        writeln!(
            &mut output,
            "\n# HELP dht_metrics_last_scrape_timestamp Unix timestamp of last scrape\n# TYPE dht_metrics_last_scrape_timestamp gauge\ndht_metrics_last_scrape_timestamp {}",
            timestamp
        )?;

        Ok(output)
    }

    fn write_security_metrics(
        &self,
        output: &mut String,
        metrics: &SecurityMetrics,
    ) -> std::fmt::Result {
        writeln!(output, "# Security Metrics")?;

        // Attack detection metrics
        writeln!(
            output,
            "\n# HELP dht_security_eclipse_score Current eclipse attack risk score (0-1)\n# TYPE dht_security_eclipse_score gauge\ndht_security_eclipse_score {}",
            metrics.eclipse_score
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_sybil_score Current Sybil attack risk score (0-1)\n# TYPE dht_security_sybil_score gauge\ndht_security_sybil_score {}",
            metrics.sybil_score
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_collusion_score Current collusion risk score (0-1)\n# TYPE dht_security_collusion_score gauge\ndht_security_collusion_score {}",
            metrics.collusion_score
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_routing_manipulation_score Routing manipulation risk score (0-1)\n# TYPE dht_security_routing_manipulation_score gauge\ndht_security_routing_manipulation_score {}",
            metrics.routing_manipulation_score
        )?;

        // Attack event counters
        writeln!(
            output,
            "\n# HELP dht_security_eclipse_attempts_total Total eclipse attack attempts detected\n# TYPE dht_security_eclipse_attempts_total counter\ndht_security_eclipse_attempts_total {}",
            metrics.eclipse_attempts_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_sybil_nodes_detected_total Total Sybil nodes detected\n# TYPE dht_security_sybil_nodes_detected_total counter\ndht_security_sybil_nodes_detected_total {}",
            metrics.sybil_nodes_detected_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_collusion_groups_detected_total Total collusion groups detected\n# TYPE dht_security_collusion_groups_detected_total counter\ndht_security_collusion_groups_detected_total {}",
            metrics.collusion_groups_detected_total
        )?;

        // BFT mode metrics
        writeln!(
            output,
            "\n# HELP dht_security_bft_mode_active BFT consensus mode active (1=active, 0=trust-weighted)\n# TYPE dht_security_bft_mode_active gauge\ndht_security_bft_mode_active {}",
            if metrics.bft_mode_active { 1 } else { 0 }
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_bft_escalations_total Total BFT mode escalations\n# TYPE dht_security_bft_escalations_total counter\ndht_security_bft_escalations_total {}",
            metrics.bft_escalations_total
        )?;

        // Sibling broadcast metrics
        writeln!(
            output,
            "\n# HELP dht_security_sibling_broadcasts_validated_total Total sibling broadcasts validated\n# TYPE dht_security_sibling_broadcasts_validated_total counter\ndht_security_sibling_broadcasts_validated_total {}",
            metrics.sibling_broadcasts_validated_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_sibling_broadcasts_rejected_total Total sibling broadcasts rejected\n# TYPE dht_security_sibling_broadcasts_rejected_total counter\ndht_security_sibling_broadcasts_rejected_total {}",
            metrics.sibling_broadcasts_rejected_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_sibling_overlap_ratio Average sibling list overlap ratio\n# TYPE dht_security_sibling_overlap_ratio gauge\ndht_security_sibling_overlap_ratio {}",
            metrics.sibling_overlap_ratio
        )?;

        // Close group validation metrics
        writeln!(
            output,
            "\n# HELP dht_security_close_group_validations_total Total close group validations\n# TYPE dht_security_close_group_validations_total counter\ndht_security_close_group_validations_total {}",
            metrics.close_group_validations_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_close_group_consensus_failures_total Total close group consensus failures\n# TYPE dht_security_close_group_consensus_failures_total counter\ndht_security_close_group_consensus_failures_total {}",
            metrics.close_group_consensus_failures_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_witness_validations_total Total witness validations performed\n# TYPE dht_security_witness_validations_total counter\ndht_security_witness_validations_total {}",
            metrics.witness_validations_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_witness_failures_total Total witness validation failures\n# TYPE dht_security_witness_failures_total counter\ndht_security_witness_failures_total {}",
            metrics.witness_failures_total
        )?;

        // Node eviction metrics
        writeln!(
            output,
            "\n# HELP dht_security_nodes_evicted_total Total nodes evicted from routing table\n# TYPE dht_security_nodes_evicted_total counter\ndht_security_nodes_evicted_total {}",
            metrics.nodes_evicted_total
        )?;

        for (reason, count) in &metrics.eviction_by_reason {
            writeln!(
                output,
                "dht_security_nodes_evicted_by_reason{{reason=\"{}\"}} {}",
                reason, count
            )?;
        }

        // Churn metrics
        writeln!(
            output,
            "\n# HELP dht_security_churn_rate_5m Node churn rate over 5 minutes (percentage)\n# TYPE dht_security_churn_rate_5m gauge\ndht_security_churn_rate_5m {}",
            metrics.churn_rate_5m
        )?;

        writeln!(
            output,
            "\n# HELP dht_security_high_churn_alerts_total Total high churn alerts triggered\n# TYPE dht_security_high_churn_alerts_total counter\ndht_security_high_churn_alerts_total {}",
            metrics.high_churn_alerts_total
        )?;

        Ok(())
    }

    fn write_dht_health_metrics(
        &self,
        output: &mut String,
        metrics: &DhtHealthMetrics,
    ) -> std::fmt::Result {
        writeln!(output, "\n# DHT Health Metrics")?;

        // Routing table metrics
        writeln!(
            output,
            "\n# HELP dht_routing_table_size Number of nodes in routing table\n# TYPE dht_routing_table_size gauge\ndht_routing_table_size {}",
            metrics.routing_table_size
        )?;

        writeln!(
            output,
            "\n# HELP dht_routing_table_buckets_filled Number of non-empty k-buckets\n# TYPE dht_routing_table_buckets_filled gauge\ndht_routing_table_buckets_filled {}",
            metrics.buckets_filled
        )?;

        writeln!(
            output,
            "\n# HELP dht_routing_table_bucket_fullness Average bucket fullness (0-1)\n# TYPE dht_routing_table_bucket_fullness gauge\ndht_routing_table_bucket_fullness {}",
            metrics.bucket_fullness
        )?;

        // Latency metrics
        writeln!(
            output,
            "\n# HELP dht_lookup_latency_p50_ms P50 lookup latency in milliseconds\n# TYPE dht_lookup_latency_p50_ms gauge\ndht_lookup_latency_p50_ms {}",
            metrics.lookup_latency_p50_ms
        )?;

        writeln!(
            output,
            "\n# HELP dht_lookup_latency_p95_ms P95 lookup latency in milliseconds\n# TYPE dht_lookup_latency_p95_ms gauge\ndht_lookup_latency_p95_ms {}",
            metrics.lookup_latency_p95_ms
        )?;

        writeln!(
            output,
            "\n# HELP dht_lookup_latency_p99_ms P99 lookup latency in milliseconds\n# TYPE dht_lookup_latency_p99_ms gauge\ndht_lookup_latency_p99_ms {}",
            metrics.lookup_latency_p99_ms
        )?;

        writeln!(
            output,
            "\n# HELP dht_lookup_hops_avg Average number of hops per lookup\n# TYPE dht_lookup_hops_avg gauge\ndht_lookup_hops_avg {}",
            metrics.lookup_hops_avg
        )?;

        // Operation metrics
        writeln!(
            output,
            "\n# HELP dht_operations_total Total DHT operations\n# TYPE dht_operations_total counter\ndht_operations_total {}",
            metrics.operations_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_operations_success_total Successful DHT operations\n# TYPE dht_operations_success_total counter\ndht_operations_success_total {}",
            metrics.operations_success_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_operations_failed_total Failed DHT operations\n# TYPE dht_operations_failed_total counter\ndht_operations_failed_total {}",
            metrics.operations_failed_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_success_rate DHT operation success rate (0-1)\n# TYPE dht_success_rate gauge\ndht_success_rate {}",
            metrics.success_rate
        )?;

        // Refresh metrics
        writeln!(
            output,
            "\n# HELP dht_bucket_refresh_total Total bucket refresh operations\n# TYPE dht_bucket_refresh_total counter\ndht_bucket_refresh_total {}",
            metrics.bucket_refresh_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_liveness_checks_total Total node liveness checks\n# TYPE dht_liveness_checks_total counter\ndht_liveness_checks_total {}",
            metrics.liveness_checks_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_liveness_failures_total Failed node liveness checks\n# TYPE dht_liveness_failures_total counter\ndht_liveness_failures_total {}",
            metrics.liveness_failures_total
        )?;

        Ok(())
    }

    fn write_trust_metrics(&self, output: &mut String, metrics: &TrustMetrics) -> std::fmt::Result {
        writeln!(output, "\n# Trust Metrics")?;

        // EigenTrust metrics
        writeln!(
            output,
            "\n# HELP dht_trust_eigentrust_avg Average EigenTrust score across all peers\n# TYPE dht_trust_eigentrust_avg gauge\ndht_trust_eigentrust_avg {}",
            metrics.eigentrust_avg
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_eigentrust_min Minimum EigenTrust score\n# TYPE dht_trust_eigentrust_min gauge\ndht_trust_eigentrust_min {}",
            metrics.eigentrust_min
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_eigentrust_max Maximum EigenTrust score\n# TYPE dht_trust_eigentrust_max gauge\ndht_trust_eigentrust_max {}",
            metrics.eigentrust_max
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_eigentrust_epochs_total Total EigenTrust epochs processed\n# TYPE dht_trust_eigentrust_epochs_total counter\ndht_trust_eigentrust_epochs_total {}",
            metrics.eigentrust_epochs_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_low_trust_nodes Number of nodes below trust threshold\n# TYPE dht_trust_low_trust_nodes gauge\ndht_trust_low_trust_nodes {}",
            metrics.low_trust_nodes
        )?;

        // Witness validation metrics
        writeln!(
            output,
            "\n# HELP dht_trust_witness_receipts_issued_total Total witness receipts issued\n# TYPE dht_trust_witness_receipts_issued_total counter\ndht_trust_witness_receipts_issued_total {}",
            metrics.witness_receipts_issued_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_witness_receipts_verified_total Total witness receipts verified\n# TYPE dht_trust_witness_receipts_verified_total counter\ndht_trust_witness_receipts_verified_total {}",
            metrics.witness_receipts_verified_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_witness_receipts_rejected_total Total witness receipts rejected\n# TYPE dht_trust_witness_receipts_rejected_total counter\ndht_trust_witness_receipts_rejected_total {}",
            metrics.witness_receipts_rejected_total
        )?;

        // Interaction tracking metrics
        writeln!(
            output,
            "\n# HELP dht_trust_interactions_recorded_total Total peer interactions recorded\n# TYPE dht_trust_interactions_recorded_total counter\ndht_trust_interactions_recorded_total {}",
            metrics.interactions_recorded_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_positive_interactions_total Total positive interactions\n# TYPE dht_trust_positive_interactions_total counter\ndht_trust_positive_interactions_total {}",
            metrics.positive_interactions_total
        )?;

        writeln!(
            output,
            "\n# HELP dht_trust_negative_interactions_total Total negative interactions\n# TYPE dht_trust_negative_interactions_total counter\ndht_trust_negative_interactions_total {}",
            metrics.negative_interactions_total
        )?;

        // Trust distribution
        for (bucket, count) in &metrics.trust_distribution {
            writeln!(
                output,
                "dht_trust_distribution{{bucket=\"{}\"}} {}",
                bucket, count
            )?;
        }

        Ok(())
    }

    /// Get aggregated summary metrics
    pub async fn get_summary(&self) -> MetricsSummary {
        let security = self.security.get_metrics().await;
        let dht_health = self.dht_health.get_metrics().await;
        let trust = self.trust.get_metrics().await;

        MetricsSummary {
            overall_health_score: Self::calculate_health_score(&security, &dht_health, &trust),
            security_score: Self::calculate_security_score(&security),
            dht_health_score: dht_health.success_rate,
            trust_score: trust.eigentrust_avg,
            active_alerts: Self::count_active_alerts(&security, &dht_health),
        }
    }

    fn calculate_health_score(
        security: &SecurityMetrics,
        dht_health: &DhtHealthMetrics,
        trust: &TrustMetrics,
    ) -> f64 {
        // Weighted average of component scores
        let security_score =
            1.0 - (security.eclipse_score + security.sybil_score + security.collusion_score) / 3.0;
        let dht_score = dht_health.success_rate;
        let trust_score = trust.eigentrust_avg;

        (security_score * 0.4 + dht_score * 0.35 + trust_score * 0.25).clamp(0.0, 1.0)
    }

    fn calculate_security_score(security: &SecurityMetrics) -> f64 {
        1.0 - (security.eclipse_score * 0.3
            + security.sybil_score * 0.3
            + security.collusion_score * 0.2
            + security.routing_manipulation_score * 0.2)
            .clamp(0.0, 1.0)
    }

    fn count_active_alerts(security: &SecurityMetrics, dht_health: &DhtHealthMetrics) -> usize {
        let mut alerts = 0;

        // Security alerts
        if security.eclipse_score > 0.5 {
            alerts += 1;
        }
        if security.sybil_score > 0.5 {
            alerts += 1;
        }
        if security.collusion_score > 0.5 {
            alerts += 1;
        }
        if security.churn_rate_5m > 0.3 {
            alerts += 1;
        }
        if security.bft_mode_active {
            alerts += 1;
        }

        // DHT health alerts
        if dht_health.success_rate < 0.9 {
            alerts += 1;
        }

        alerts
    }
}

impl Default for DhtMetricsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of all metrics for quick health assessment
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    /// Overall system health score (0-1)
    pub overall_health_score: f64,
    /// Security score (0-1, higher is better)
    pub security_score: f64,
    /// DHT health score (0-1)
    pub dht_health_score: f64,
    /// Trust score (0-1)
    pub trust_score: f64,
    /// Number of active alerts
    pub active_alerts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_aggregator_creation() {
        let aggregator = DhtMetricsAggregator::new();
        let summary = aggregator.get_summary().await;

        assert!(summary.overall_health_score >= 0.0);
        assert!(summary.overall_health_score <= 1.0);
    }

    #[tokio::test]
    async fn test_prometheus_export() {
        let aggregator = DhtMetricsAggregator::new();
        let output = aggregator.export_prometheus().await.unwrap();

        // Verify Prometheus format
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
        assert!(output.contains("dht_security_eclipse_score"));
        assert!(output.contains("dht_routing_table_size"));
        assert!(output.contains("dht_trust_eigentrust_avg"));
    }
}
