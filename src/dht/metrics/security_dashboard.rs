//! Unified Security Dashboard for production monitoring
//!
//! Provides:
//! - Real-time security status aggregation
//! - Alert thresholds and recommendations
//! - Integration with SecurityCoordinator and DataIntegrityMonitor
//! - Production-ready health check endpoints
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::RwLock;

use super::{
    DhtHealthMetrics, DhtMetricsCollector, SecurityMetrics, SecurityMetricsCollector, TrustMetrics,
    TrustMetricsCollector,
};
use crate::dht::routing_maintenance::DataIntegrityMetrics;

/// Overall system health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemStatus {
    /// All systems operational, no issues detected
    Healthy,
    /// Minor issues detected, monitoring recommended
    Degraded,
    /// Significant issues requiring attention
    Warning,
    /// Critical issues, immediate action required
    Critical,
    /// System is in emergency mode (BFT active)
    Emergency,
}

impl SystemStatus {
    /// Get numeric severity level (0-4)
    pub fn severity(&self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Degraded => 1,
            Self::Warning => 2,
            Self::Critical => 3,
            Self::Emergency => 4,
        }
    }

    /// Get status name for display
    pub fn name(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }
}

/// Alert severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Security alert
#[derive(Debug, Clone)]
pub struct SecurityAlert {
    /// Alert identifier
    pub id: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert category
    pub category: AlertCategory,
    /// Human-readable message
    pub message: String,
    /// Recommended action
    pub recommendation: String,
    /// When the alert was triggered
    pub triggered_at: SystemTime,
    /// Metric value that triggered the alert
    pub metric_value: f64,
    /// Threshold that was exceeded
    pub threshold: f64,
}

/// Alert category for grouping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertCategory {
    SecurityAttack,
    TrustDegradation,
    DataIntegrity,
    NetworkHealth,
    Capacity,
    Performance,
}

impl AlertCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SecurityAttack => "security_attack",
            Self::TrustDegradation => "trust_degradation",
            Self::DataIntegrity => "data_integrity",
            Self::NetworkHealth => "network_health",
            Self::Capacity => "capacity",
            Self::Performance => "performance",
        }
    }
}

/// Alert thresholds configuration
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    /// Eclipse attack score threshold (0-1)
    pub eclipse_warning: f64,
    pub eclipse_critical: f64,

    /// Sybil attack score threshold (0-1)
    pub sybil_warning: f64,
    pub sybil_critical: f64,

    /// Collusion score threshold (0-1)
    pub collusion_warning: f64,
    pub collusion_critical: f64,

    /// Churn rate threshold (percentage)
    pub churn_warning: f64,
    pub churn_critical: f64,

    /// Trust score threshold (0-1)
    pub trust_warning: f64,
    pub trust_critical: f64,

    /// Success rate threshold (0-1)
    pub success_rate_warning: f64,
    pub success_rate_critical: f64,

    /// Data health threshold (0-1)
    pub data_health_warning: f64,
    pub data_health_critical: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            eclipse_warning: 0.3,
            eclipse_critical: 0.6,
            sybil_warning: 0.3,
            sybil_critical: 0.6,
            collusion_warning: 0.3,
            collusion_critical: 0.6,
            churn_warning: 0.2,
            churn_critical: 0.4,
            trust_warning: 0.5,
            trust_critical: 0.3,
            success_rate_warning: 0.95,
            success_rate_critical: 0.85,
            data_health_warning: 0.8,
            data_health_critical: 0.6,
        }
    }
}

/// Comprehensive dashboard snapshot
#[derive(Debug, Clone)]
pub struct DashboardSnapshot {
    /// Overall system status
    pub status: SystemStatus,
    /// Overall health score (0-1)
    pub health_score: f64,
    /// Security score (0-1)
    pub security_score: f64,
    /// Data integrity score (0-1)
    pub data_integrity_score: f64,
    /// Network health score (0-1)
    pub network_health_score: f64,
    /// Trust score (0-1)
    pub trust_score: f64,
    /// Active alerts
    pub alerts: Vec<SecurityAlert>,
    /// Alert counts by category
    pub alert_counts: HashMap<AlertCategory, usize>,
    /// Alert counts by severity
    pub severity_counts: HashMap<AlertSeverity, usize>,
    /// Component statuses
    pub components: ComponentStatus,
    /// Snapshot timestamp
    pub timestamp: SystemTime,
    /// Time since last check
    pub check_latency: Duration,
}

/// Individual component health status
#[derive(Debug, Clone)]
pub struct ComponentStatus {
    /// Security coordinator status
    pub security_coordinator: ComponentHealth,
    /// Data integrity monitor status
    pub data_integrity: ComponentHealth,
    /// Trust system status
    pub trust_system: ComponentHealth,
    /// Routing table status
    pub routing_table: ComponentHealth,
    /// Geographic diversity status
    pub geographic_diversity: ComponentHealth,
}

/// Health of a single component
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    /// Component name
    pub name: &'static str,
    /// Whether the component is operational
    pub operational: bool,
    /// Health score (0-1)
    pub health_score: f64,
    /// Status message
    pub message: String,
    /// Last check time
    pub last_check: SystemTime,
}

/// Unified Security Dashboard
pub struct SecurityDashboard {
    /// Security metrics collector
    security_collector: Arc<SecurityMetricsCollector>,
    /// DHT health metrics collector
    dht_collector: Arc<DhtMetricsCollector>,
    /// Trust metrics collector
    trust_collector: Arc<TrustMetricsCollector>,
    /// Alert thresholds
    thresholds: AlertThresholds,
    /// Cached snapshot
    cached_snapshot: RwLock<Option<(DashboardSnapshot, Instant)>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Data integrity metrics (optional, injected from DataIntegrityMonitor)
    data_integrity_metrics: RwLock<Option<DataIntegrityMetrics>>,
    /// BFT mode status
    bft_mode_active: RwLock<bool>,
}

impl SecurityDashboard {
    /// Create a new security dashboard
    pub fn new(
        security_collector: Arc<SecurityMetricsCollector>,
        dht_collector: Arc<DhtMetricsCollector>,
        trust_collector: Arc<TrustMetricsCollector>,
    ) -> Self {
        Self {
            security_collector,
            dht_collector,
            trust_collector,
            thresholds: AlertThresholds::default(),
            cached_snapshot: RwLock::new(None),
            cache_ttl: Duration::from_secs(5),
            data_integrity_metrics: RwLock::new(None),
            bft_mode_active: RwLock::new(false),
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(mut self, thresholds: AlertThresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Update data integrity metrics
    pub async fn update_data_integrity(&self, metrics: DataIntegrityMetrics) {
        let mut guard = self.data_integrity_metrics.write().await;
        *guard = Some(metrics);
    }

    /// Update BFT mode status
    pub async fn set_bft_mode(&self, active: bool) {
        let mut guard = self.bft_mode_active.write().await;
        *guard = active;
    }

    /// Get current dashboard snapshot (with caching)
    pub async fn get_snapshot(&self) -> DashboardSnapshot {
        // Check cache
        {
            let cache = self.cached_snapshot.read().await;
            if let Some((snapshot, created_at)) = &*cache
                && created_at.elapsed() < self.cache_ttl
            {
                return snapshot.clone();
            }
        }

        // Generate fresh snapshot
        let snapshot = self.generate_snapshot().await;

        // Update cache
        {
            let mut cache = self.cached_snapshot.write().await;
            *cache = Some((snapshot.clone(), Instant::now()));
        }

        snapshot
    }

    /// Force refresh snapshot (bypasses cache)
    pub async fn refresh(&self) -> DashboardSnapshot {
        let snapshot = self.generate_snapshot().await;

        let mut cache = self.cached_snapshot.write().await;
        *cache = Some((snapshot.clone(), Instant::now()));

        snapshot
    }

    /// Generate a fresh dashboard snapshot
    async fn generate_snapshot(&self) -> DashboardSnapshot {
        let start = Instant::now();
        let now = SystemTime::now();

        // Collect all metrics
        let security = self.security_collector.get_metrics().await;
        let dht_health = self.dht_collector.get_metrics().await;
        let trust = self.trust_collector.get_metrics().await;
        let data_integrity = self.data_integrity_metrics.read().await.clone();
        let bft_active = *self.bft_mode_active.read().await;

        // Generate alerts
        let alerts = self.generate_alerts(&security, &dht_health, &trust, bft_active);

        // Calculate scores
        let security_score = self.calculate_security_score(&security);
        let data_integrity_score = self.calculate_data_integrity_score(data_integrity.as_ref());
        let network_health_score = self.calculate_network_health_score(&dht_health);
        let trust_score = trust.eigentrust_avg;

        // Calculate overall health
        let health_score = self.calculate_overall_health(
            security_score,
            data_integrity_score,
            network_health_score,
            trust_score,
        );

        // Determine system status
        let status = self.determine_status(&alerts, bft_active, health_score);

        // Count alerts
        let mut alert_counts: HashMap<AlertCategory, usize> = HashMap::new();
        let mut severity_counts: HashMap<AlertSeverity, usize> = HashMap::new();
        for alert in &alerts {
            *alert_counts.entry(alert.category).or_default() += 1;
            *severity_counts.entry(alert.severity).or_default() += 1;
        }

        // Generate component statuses
        let components = self.generate_component_status(
            &security,
            &dht_health,
            &trust,
            data_integrity.as_ref(),
            now,
        );

        DashboardSnapshot {
            status,
            health_score,
            security_score,
            data_integrity_score,
            network_health_score,
            trust_score,
            alerts,
            alert_counts,
            severity_counts,
            components,
            timestamp: now,
            check_latency: start.elapsed(),
        }
    }

    /// Generate alerts based on current metrics
    fn generate_alerts(
        &self,
        security: &SecurityMetrics,
        dht_health: &DhtHealthMetrics,
        trust: &TrustMetrics,
        bft_active: bool,
    ) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        let now = SystemTime::now();

        // Security alerts
        self.check_security_alerts(security, &mut alerts, now);

        // BFT mode alert
        if bft_active {
            alerts.push(SecurityAlert {
                id: "bft_mode_active".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::SecurityAttack,
                message: "BFT consensus mode is active due to detected threats".to_string(),
                recommendation: "Monitor for attack patterns and investigate root cause"
                    .to_string(),
                triggered_at: now,
                metric_value: 1.0,
                threshold: 0.0,
            });
        }

        // Network health alerts
        self.check_network_alerts(dht_health, &mut alerts, now);

        // Trust alerts
        self.check_trust_alerts(trust, &mut alerts, now);

        alerts
    }

    fn check_security_alerts(
        &self,
        security: &SecurityMetrics,
        alerts: &mut Vec<SecurityAlert>,
        now: SystemTime,
    ) {
        // Eclipse attack
        if security.eclipse_score >= self.thresholds.eclipse_critical {
            alerts.push(SecurityAlert {
                id: "eclipse_critical".to_string(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::SecurityAttack,
                message: format!(
                    "Critical eclipse attack risk detected: {:.1}%",
                    security.eclipse_score * 100.0
                ),
                recommendation: "Increase peer diversity and verify routing table integrity"
                    .to_string(),
                triggered_at: now,
                metric_value: security.eclipse_score,
                threshold: self.thresholds.eclipse_critical,
            });
        } else if security.eclipse_score >= self.thresholds.eclipse_warning {
            alerts.push(SecurityAlert {
                id: "eclipse_warning".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::SecurityAttack,
                message: format!(
                    "Elevated eclipse attack risk: {:.1}%",
                    security.eclipse_score * 100.0
                ),
                recommendation: "Monitor peer diversity and routing patterns".to_string(),
                triggered_at: now,
                metric_value: security.eclipse_score,
                threshold: self.thresholds.eclipse_warning,
            });
        }

        // Sybil attack
        if security.sybil_score >= self.thresholds.sybil_critical {
            alerts.push(SecurityAlert {
                id: "sybil_critical".to_string(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::SecurityAttack,
                message: format!(
                    "Critical Sybil attack detected: {:.1}%",
                    security.sybil_score * 100.0
                ),
                recommendation: "Activate BFT mode and increase node validation requirements"
                    .to_string(),
                triggered_at: now,
                metric_value: security.sybil_score,
                threshold: self.thresholds.sybil_critical,
            });
        } else if security.sybil_score >= self.thresholds.sybil_warning {
            alerts.push(SecurityAlert {
                id: "sybil_warning".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::SecurityAttack,
                message: format!(
                    "Potential Sybil nodes detected: {:.1}%",
                    security.sybil_score * 100.0
                ),
                recommendation: "Investigate node clusters and join patterns".to_string(),
                triggered_at: now,
                metric_value: security.sybil_score,
                threshold: self.thresholds.sybil_warning,
            });
        }

        // Collusion detection
        if security.collusion_score >= self.thresholds.collusion_critical {
            alerts.push(SecurityAlert {
                id: "collusion_critical".to_string(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::SecurityAttack,
                message: format!(
                    "Critical collusion pattern detected: {:.1}%",
                    security.collusion_score * 100.0
                ),
                recommendation: "Switch to BFT consensus and isolate suspected node groups"
                    .to_string(),
                triggered_at: now,
                metric_value: security.collusion_score,
                threshold: self.thresholds.collusion_critical,
            });
        } else if security.collusion_score >= self.thresholds.collusion_warning {
            alerts.push(SecurityAlert {
                id: "collusion_warning".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::SecurityAttack,
                message: format!(
                    "Suspicious voting patterns detected: {:.1}%",
                    security.collusion_score * 100.0
                ),
                recommendation: "Monitor witness group behavior and trust scores".to_string(),
                triggered_at: now,
                metric_value: security.collusion_score,
                threshold: self.thresholds.collusion_warning,
            });
        }

        // High churn
        if security.churn_rate_5m >= self.thresholds.churn_critical {
            alerts.push(SecurityAlert {
                id: "churn_critical".to_string(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::NetworkHealth,
                message: format!(
                    "Abnormally high network churn: {:.1}%",
                    security.churn_rate_5m * 100.0
                ),
                recommendation: "Investigate network stability and potential attack patterns"
                    .to_string(),
                triggered_at: now,
                metric_value: security.churn_rate_5m,
                threshold: self.thresholds.churn_critical,
            });
        } else if security.churn_rate_5m >= self.thresholds.churn_warning {
            alerts.push(SecurityAlert {
                id: "churn_warning".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::NetworkHealth,
                message: format!(
                    "Elevated network churn: {:.1}%",
                    security.churn_rate_5m * 100.0
                ),
                recommendation: "Monitor for network instability".to_string(),
                triggered_at: now,
                metric_value: security.churn_rate_5m,
                threshold: self.thresholds.churn_warning,
            });
        }
    }

    fn check_network_alerts(
        &self,
        dht_health: &DhtHealthMetrics,
        alerts: &mut Vec<SecurityAlert>,
        now: SystemTime,
    ) {
        // Success rate
        if dht_health.success_rate < self.thresholds.success_rate_critical {
            alerts.push(SecurityAlert {
                id: "success_rate_critical".to_string(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::Performance,
                message: format!(
                    "Critical DHT operation success rate: {:.1}%",
                    dht_health.success_rate * 100.0
                ),
                recommendation: "Investigate network connectivity and node health".to_string(),
                triggered_at: now,
                metric_value: dht_health.success_rate,
                threshold: self.thresholds.success_rate_critical,
            });
        } else if dht_health.success_rate < self.thresholds.success_rate_warning {
            alerts.push(SecurityAlert {
                id: "success_rate_warning".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::Performance,
                message: format!(
                    "Degraded DHT operation success rate: {:.1}%",
                    dht_health.success_rate * 100.0
                ),
                recommendation: "Check for timeout issues and routing problems".to_string(),
                triggered_at: now,
                metric_value: dht_health.success_rate,
                threshold: self.thresholds.success_rate_warning,
            });
        }
    }

    fn check_trust_alerts(
        &self,
        trust: &TrustMetrics,
        alerts: &mut Vec<SecurityAlert>,
        now: SystemTime,
    ) {
        // Low average trust
        if trust.eigentrust_avg < self.thresholds.trust_critical {
            alerts.push(SecurityAlert {
                id: "trust_critical".to_string(),
                severity: AlertSeverity::Critical,
                category: AlertCategory::TrustDegradation,
                message: format!(
                    "Critical average trust score: {:.2}",
                    trust.eigentrust_avg
                ),
                recommendation:
                    "Review recent node behavior and consider network health assessment".to_string(),
                triggered_at: now,
                metric_value: trust.eigentrust_avg,
                threshold: self.thresholds.trust_critical,
            });
        } else if trust.eigentrust_avg < self.thresholds.trust_warning {
            alerts.push(SecurityAlert {
                id: "trust_warning".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::TrustDegradation,
                message: format!("Low average trust score: {:.2}", trust.eigentrust_avg),
                recommendation: "Monitor peer interactions and reputation trends".to_string(),
                triggered_at: now,
                metric_value: trust.eigentrust_avg,
                threshold: self.thresholds.trust_warning,
            });
        }

        // Many low trust nodes
        if trust.low_trust_nodes > 10 {
            alerts.push(SecurityAlert {
                id: "low_trust_nodes".to_string(),
                severity: AlertSeverity::Warning,
                category: AlertCategory::TrustDegradation,
                message: format!("{} nodes are below trust threshold", trust.low_trust_nodes),
                recommendation: "Investigate causes and consider eviction for persistent offenders"
                    .to_string(),
                triggered_at: now,
                metric_value: trust.low_trust_nodes as f64,
                threshold: 10.0,
            });
        }
    }

    /// Calculate security score
    fn calculate_security_score(&self, security: &SecurityMetrics) -> f64 {
        let attack_score = 1.0
            - (security.eclipse_score * 0.3
                + security.sybil_score * 0.3
                + security.collusion_score * 0.25
                + security.routing_manipulation_score * 0.15);

        attack_score.clamp(0.0, 1.0)
    }

    /// Calculate data integrity score
    fn calculate_data_integrity_score(&self, data_integrity: Option<&DataIntegrityMetrics>) -> f64 {
        if let Some(di) = data_integrity {
            di.health_ratio().clamp(0.0, 1.0)
        } else {
            // No data integrity monitor available; assume healthy
            1.0
        }
    }

    /// Calculate network health score
    fn calculate_network_health_score(&self, dht_health: &DhtHealthMetrics) -> f64 {
        let success = dht_health.success_rate;
        let routing = (dht_health.routing_table_size as f64 / 160.0).min(1.0); // Normalize by max k-buckets

        (success * 0.6 + routing * 0.4).clamp(0.0, 1.0)
    }

    /// Calculate overall health score
    fn calculate_overall_health(
        &self,
        security: f64,
        data_integrity: f64,
        network_health: f64,
        trust: f64,
    ) -> f64 {
        // Security has highest weight since attacks are critical
        (security * 0.35 + data_integrity * 0.25 + network_health * 0.20 + trust * 0.20)
            .clamp(0.0, 1.0)
    }

    /// Determine overall system status
    fn determine_status(
        &self,
        alerts: &[SecurityAlert],
        bft_active: bool,
        health_score: f64,
    ) -> SystemStatus {
        // Emergency if BFT is active
        if bft_active {
            return SystemStatus::Emergency;
        }

        // Check for critical alerts
        if alerts
            .iter()
            .any(|a| a.severity == AlertSeverity::Emergency)
        {
            return SystemStatus::Emergency;
        }
        if alerts.iter().any(|a| a.severity == AlertSeverity::Critical) {
            return SystemStatus::Critical;
        }
        if alerts.iter().any(|a| a.severity == AlertSeverity::Warning) {
            return SystemStatus::Warning;
        }

        // Check overall health
        if health_score >= 0.9 {
            SystemStatus::Healthy
        } else if health_score >= 0.7 {
            SystemStatus::Degraded
        } else if health_score >= 0.5 {
            SystemStatus::Warning
        } else {
            SystemStatus::Critical
        }
    }

    /// Generate component status
    fn generate_component_status(
        &self,
        security: &SecurityMetrics,
        dht_health: &DhtHealthMetrics,
        trust: &TrustMetrics,
        data_integrity: Option<&DataIntegrityMetrics>,
        now: SystemTime,
    ) -> ComponentStatus {
        ComponentStatus {
            security_coordinator: ComponentHealth {
                name: "Security Coordinator",
                operational: true,
                health_score: self.calculate_security_score(security),
                message: if security.bft_mode_active {
                    "BFT mode active".to_string()
                } else {
                    "Normal operation".to_string()
                },
                last_check: now,
            },
            data_integrity: ComponentHealth {
                name: "Data Integrity Monitor",
                operational: data_integrity.is_some(),
                health_score: data_integrity.map(|d| d.health_ratio()).unwrap_or(0.0),
                message: if let Some(di) = data_integrity {
                    format!(
                        "{} healthy, {} degraded, {} critical",
                        di.healthy_keys, di.degraded_keys, di.critical_keys
                    )
                } else {
                    "Not initialized".to_string()
                },
                last_check: now,
            },
            trust_system: ComponentHealth {
                name: "EigenTrust System",
                operational: true,
                health_score: trust.eigentrust_avg,
                message: format!(
                    "Avg trust: {:.2}, {} low-trust nodes",
                    trust.eigentrust_avg, trust.low_trust_nodes
                ),
                last_check: now,
            },
            routing_table: ComponentHealth {
                name: "Routing Table",
                operational: dht_health.routing_table_size > 0,
                health_score: dht_health.bucket_fullness,
                message: format!(
                    "{} nodes, {} buckets filled",
                    dht_health.routing_table_size, dht_health.buckets_filled
                ),
                last_check: now,
            },
            geographic_diversity: ComponentHealth {
                name: "Geographic Diversity",
                operational: dht_health.routing_table_size > 0,
                health_score: dht_health.bucket_fullness,
                message: format!(
                    "{} nodes across {} buckets",
                    dht_health.routing_table_size, dht_health.buckets_filled
                ),
                last_check: now,
            },
        }
    }

    /// Export dashboard in JSON format
    pub async fn export_json(&self) -> String {
        let snapshot = self.get_snapshot().await;

        format!(
            r#"{{
  "status": "{}",
  "health_score": {:.4},
  "security_score": {:.4},
  "data_integrity_score": {:.4},
  "network_health_score": {:.4},
  "trust_score": {:.4},
  "alert_count": {},
  "critical_alerts": {},
  "timestamp": "{}",
  "check_latency_ms": {}
}}"#,
            snapshot.status.name(),
            snapshot.health_score,
            snapshot.security_score,
            snapshot.data_integrity_score,
            snapshot.network_health_score,
            snapshot.trust_score,
            snapshot.alerts.len(),
            snapshot
                .alerts
                .iter()
                .filter(|a| a.severity == AlertSeverity::Critical)
                .count(),
            chrono_format(&snapshot.timestamp),
            snapshot.check_latency.as_millis(),
        )
    }

    /// Get alerts filtered by severity
    pub async fn get_alerts_by_severity(&self, min_severity: AlertSeverity) -> Vec<SecurityAlert> {
        let snapshot = self.get_snapshot().await;
        snapshot
            .alerts
            .into_iter()
            .filter(|a| a.severity >= min_severity)
            .collect()
    }

    /// Check if system is healthy
    pub async fn is_healthy(&self) -> bool {
        let snapshot = self.get_snapshot().await;
        matches!(
            snapshot.status,
            SystemStatus::Healthy | SystemStatus::Degraded
        )
    }
}

// Helper for timestamp formatting
fn chrono_format(time: &SystemTime) -> String {
    let duration = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_status_severity() {
        assert_eq!(SystemStatus::Healthy.severity(), 0);
        assert_eq!(SystemStatus::Degraded.severity(), 1);
        assert_eq!(SystemStatus::Warning.severity(), 2);
        assert_eq!(SystemStatus::Critical.severity(), 3);
        assert_eq!(SystemStatus::Emergency.severity(), 4);
    }

    #[test]
    fn test_alert_thresholds_default() {
        let thresholds = AlertThresholds::default();
        assert!(thresholds.eclipse_critical > thresholds.eclipse_warning);
        assert!(thresholds.sybil_critical > thresholds.sybil_warning);
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Info < AlertSeverity::Warning);
        assert!(AlertSeverity::Warning < AlertSeverity::Critical);
        assert!(AlertSeverity::Critical < AlertSeverity::Emergency);
    }

    #[tokio::test]
    async fn test_dashboard_creation() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.get_snapshot().await;

        assert!(snapshot.health_score >= 0.0 && snapshot.health_score <= 1.0);
        assert!(snapshot.security_score >= 0.0 && snapshot.security_score <= 1.0);
    }

    #[tokio::test]
    async fn test_dashboard_caching() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard =
            SecurityDashboard::new(security, dht, trust).with_cache_ttl(Duration::from_secs(60));

        let snapshot1 = dashboard.get_snapshot().await;
        let snapshot2 = dashboard.get_snapshot().await;

        // Timestamps should be same due to caching
        assert_eq!(snapshot1.timestamp, snapshot2.timestamp);
    }

    #[tokio::test]
    async fn test_dashboard_json_export() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);
        let json = dashboard.export_json().await;

        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"health_score\":"));
        assert!(json.contains("\"alert_count\":"));
    }

    #[tokio::test]
    async fn test_bft_mode_triggers_emergency() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);

        // Set BFT mode active
        dashboard.set_bft_mode(true).await;

        let snapshot = dashboard.refresh().await;
        assert_eq!(snapshot.status, SystemStatus::Emergency);
    }

    #[test]
    fn test_alert_category_names() {
        assert_eq!(AlertCategory::SecurityAttack.name(), "security_attack");
        assert_eq!(AlertCategory::TrustDegradation.name(), "trust_degradation");
        assert_eq!(AlertCategory::DataIntegrity.name(), "data_integrity");
        assert_eq!(AlertCategory::NetworkHealth.name(), "network_health");
        assert_eq!(AlertCategory::Capacity.name(), "capacity");
        assert_eq!(AlertCategory::Performance.name(), "performance");
    }

    #[tokio::test]
    async fn test_health_check() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);
        let is_healthy = dashboard.is_healthy().await;

        // Default state should be healthy or degraded
        assert!(is_healthy);
    }

    // ==========================================
    // Phase 5 TDD Tests: Alert Triggering
    // ==========================================

    #[tokio::test]
    async fn test_eclipse_attack_triggers_warning_alert() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set eclipse attack score (warning level: 0.3)
        security.set_eclipse_score(0.35);

        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Should have eclipse warning alert
        let eclipse_alerts: Vec<_> = snapshot
            .alerts
            .iter()
            .filter(|a| a.id.contains("eclipse"))
            .collect();

        assert!(
            !eclipse_alerts.is_empty(),
            "Should have eclipse alert when score >= 0.3"
        );
        assert!(
            eclipse_alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Warning)
        );
    }

    #[tokio::test]
    async fn test_eclipse_attack_triggers_critical_alert() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set eclipse attack score (critical level: 0.6)
        security.set_eclipse_score(0.7);

        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Should have critical eclipse alert
        let critical_alerts: Vec<_> = snapshot
            .alerts
            .iter()
            .filter(|a| a.id == "eclipse_critical")
            .collect();

        assert!(
            !critical_alerts.is_empty(),
            "Should have critical eclipse alert when score >= 0.6"
        );
        assert_eq!(critical_alerts[0].severity, AlertSeverity::Critical);
    }

    #[tokio::test]
    async fn test_sybil_attack_triggers_alerts() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set sybil attack score (critical level: 0.6)
        security.set_sybil_score(0.65);

        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Should have sybil critical alert
        let sybil_alerts: Vec<_> = snapshot
            .alerts
            .iter()
            .filter(|a| a.id.contains("sybil"))
            .collect();

        assert!(
            !sybil_alerts.is_empty(),
            "Should have sybil alert when score >= 0.6"
        );
        assert!(
            sybil_alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical)
        );
    }

    #[tokio::test]
    async fn test_collusion_attack_triggers_alerts() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set collusion score (warning level: 0.3)
        security.set_collusion_score(0.4);

        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Should have collusion warning alert
        let collusion_alerts: Vec<_> = snapshot
            .alerts
            .iter()
            .filter(|a| a.id.contains("collusion"))
            .collect();

        assert!(
            !collusion_alerts.is_empty(),
            "Should have collusion alert when score >= 0.3"
        );
    }

    #[tokio::test]
    async fn test_get_alerts_by_severity_filtering() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set BFT mode to generate a Warning alert
        let dashboard = SecurityDashboard::new(security, dht, trust);
        dashboard.set_bft_mode(true).await;

        // Get only critical or higher alerts
        let critical_alerts = dashboard
            .get_alerts_by_severity(AlertSeverity::Critical)
            .await;

        // All returned alerts should be critical or higher
        for alert in &critical_alerts {
            assert!(
                alert.severity >= AlertSeverity::Critical,
                "Filtered alerts should only include severity >= Critical"
            );
        }
    }

    #[tokio::test]
    async fn test_security_score_calculation() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Clean state should have high security score
        let dashboard = SecurityDashboard::new(security.clone(), dht, trust);
        let snapshot = dashboard.refresh().await;

        // With no attacks, security score should be high (close to 1.0)
        assert!(
            snapshot.security_score >= 0.9,
            "Clean state should have security score >= 0.9, got {}",
            snapshot.security_score
        );

        // Set attack scores
        security.set_eclipse_score(0.5);
        security.set_sybil_score(0.5);
        security.set_collusion_score(0.5);

        let snapshot2 = dashboard.refresh().await;

        // Security score should be lower after attacks
        assert!(
            snapshot2.security_score < snapshot.security_score,
            "Security score should decrease after attack indicators"
        );
    }

    #[tokio::test]
    async fn test_alert_count_by_category() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set multiple attack scores
        security.set_eclipse_score(0.7);
        security.set_sybil_score(0.7);

        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Should have alert counts populated
        let security_attack_count = snapshot
            .alert_counts
            .get(&AlertCategory::SecurityAttack)
            .copied()
            .unwrap_or(0);

        assert!(
            security_attack_count >= 2,
            "Should have at least 2 security attack alerts"
        );
    }

    #[tokio::test]
    async fn test_component_status_generation() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // All components should be present
        assert_eq!(
            snapshot.components.security_coordinator.name,
            "Security Coordinator"
        );
        assert_eq!(
            snapshot.components.data_integrity.name,
            "Data Integrity Monitor"
        );
        assert_eq!(snapshot.components.trust_system.name, "EigenTrust System");
        assert_eq!(snapshot.components.routing_table.name, "Routing Table");
        assert_eq!(
            snapshot.components.geographic_diversity.name,
            "Geographic Diversity"
        );
    }

    #[tokio::test]
    async fn test_overall_health_calculation() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Health score should be weighted average of components
        // health = security * 0.35 + data_integrity * 0.25 + network_health * 0.20 + trust * 0.20
        assert!(
            snapshot.health_score >= 0.0 && snapshot.health_score <= 1.0,
            "Health score should be between 0 and 1"
        );
    }

    #[tokio::test]
    async fn test_status_determination_by_health_score() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        let dashboard = SecurityDashboard::new(security, dht, trust);
        let snapshot = dashboard.refresh().await;

        // Status should be consistent with health score
        match snapshot.status {
            SystemStatus::Healthy => {
                assert!(
                    snapshot.health_score >= 0.9,
                    "Healthy status requires health >= 0.9"
                );
            }
            SystemStatus::Degraded => {
                assert!(
                    snapshot.health_score >= 0.7 && snapshot.health_score < 0.9,
                    "Degraded status requires 0.7 <= health < 0.9"
                );
            }
            SystemStatus::Warning => {
                // Warning can be triggered by alerts OR health score
            }
            SystemStatus::Critical => {
                // Critical can be triggered by alerts OR health score
            }
            SystemStatus::Emergency => {
                // Emergency is triggered by BFT mode or emergency alerts
            }
        }
    }

    #[tokio::test]
    async fn test_custom_alert_thresholds() {
        let security = Arc::new(SecurityMetricsCollector::new());
        let dht = Arc::new(DhtMetricsCollector::new());
        let trust = Arc::new(TrustMetricsCollector::new());
        // Set attack score at 0.25 (below default warning of 0.3)
        security.set_eclipse_score(0.25);

        // With default thresholds, no alert
        let dashboard_default =
            SecurityDashboard::new(security.clone(), dht.clone(), trust.clone());
        let snapshot1 = dashboard_default.refresh().await;

        let default_eclipse_alerts: Vec<_> = snapshot1
            .alerts
            .iter()
            .filter(|a| a.id.contains("eclipse"))
            .collect();

        assert!(
            default_eclipse_alerts.is_empty(),
            "Should have no eclipse alert with default thresholds"
        );

        // With custom lower thresholds, should trigger alert
        let custom_thresholds = AlertThresholds {
            eclipse_warning: 0.2, // Lower threshold
            eclipse_critical: 0.5,
            ..Default::default()
        };

        let dashboard_custom =
            SecurityDashboard::new(security, dht, trust).with_thresholds(custom_thresholds);
        let snapshot2 = dashboard_custom.refresh().await;

        let custom_eclipse_alerts: Vec<_> = snapshot2
            .alerts
            .iter()
            .filter(|a| a.id.contains("eclipse"))
            .collect();

        assert!(
            !custom_eclipse_alerts.is_empty(),
            "Should have eclipse alert with lowered threshold"
        );
    }
}
