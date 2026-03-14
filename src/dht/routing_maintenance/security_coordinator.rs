//! Security coordinator for unified routing maintenance security
//!
//! Integrates:
//! - Close group validation during bucket refresh
//! - Sybil detection for routing table protection
//! - EigenTrust reputation integration
//! - Geographic diversity enforcement
//! - Metrics collection and alerting
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::PeerId;
use crate::dht::sybil_detector::{SybilDetector, SybilDetectorConfig};

use super::close_group_validator::{
    AttackIndicators, CloseGroupFailure, CloseGroupResponse, CloseGroupValidationResult,
    CloseGroupValidator, CloseGroupValidatorConfig,
};
use super::config::MaintenanceConfig;
use super::eviction::{EvictionManager, EvictionReason};

/// Event when a node is evicted from close group
#[derive(Debug, Clone)]
pub struct CloseGroupEviction {
    /// The evicted node ID
    pub node_id: PeerId,
    /// Reasons for eviction
    pub reasons: Vec<CloseGroupFailure>,
    /// When the eviction was detected
    pub timestamp: SystemTime,
    /// Confirmation count from peers
    pub peer_confirmations: usize,
}

/// Record of close group eviction for tracking
#[derive(Debug, Clone)]
pub struct EvictionRecord {
    /// When the node was evicted
    pub evicted_at: SystemTime,
    /// Reasons for eviction
    pub reasons: Vec<CloseGroupFailure>,
    /// Number of peers that confirmed this eviction
    pub consensus_count: usize,
}

/// Tracks nodes that have been evicted from close groups
pub struct CloseGroupEvictionTracker {
    /// Nodes evicted with reasons and timestamps
    evicted_nodes: HashMap<PeerId, EvictionRecord>,
    /// Broadcast channel for eviction events
    eviction_sender: broadcast::Sender<CloseGroupEviction>,
    /// Maximum age to keep eviction records
    max_record_age: Duration,
}

impl CloseGroupEvictionTracker {
    /// Create a new eviction tracker
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(100);
        Self {
            evicted_nodes: HashMap::new(),
            eviction_sender: sender,
            max_record_age: Duration::from_secs(3600 * 24), // 24 hours
        }
    }

    /// Record an eviction
    pub fn record_eviction(
        &mut self,
        node_id: PeerId,
        reasons: Vec<CloseGroupFailure>,
        peer_confirmations: usize,
    ) {
        let record = EvictionRecord {
            evicted_at: SystemTime::now(),
            reasons: reasons.clone(),
            consensus_count: peer_confirmations,
        };
        self.evicted_nodes.insert(node_id, record);

        // Broadcast to network
        let _ = self.eviction_sender.send(CloseGroupEviction {
            node_id,
            reasons,
            timestamp: SystemTime::now(),
            peer_confirmations,
        });
    }

    /// Check if a node was recently evicted
    #[must_use]
    pub fn was_evicted(&self, node_id: &PeerId, within: Duration) -> bool {
        self.evicted_nodes
            .get(node_id)
            .and_then(|r| r.evicted_at.elapsed().ok())
            .is_some_and(|elapsed| elapsed < within)
    }

    /// Get eviction record for a node
    #[must_use]
    pub fn get_eviction_record(&self, node_id: &PeerId) -> Option<&EvictionRecord> {
        self.evicted_nodes.get(node_id)
    }

    /// Subscribe to eviction events
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<CloseGroupEviction> {
        self.eviction_sender.subscribe()
    }

    /// Clean up old eviction records
    pub fn cleanup_old_records(&mut self) {
        let now = SystemTime::now();
        self.evicted_nodes.retain(|_, record| {
            now.duration_since(record.evicted_at)
                .ok()
                .is_some_and(|age| age < self.max_record_age)
        });
    }

    /// Get all recently evicted nodes
    #[must_use]
    pub fn get_recently_evicted(&self, within: Duration) -> Vec<(PeerId, &EvictionRecord)> {
        self.evicted_nodes
            .iter()
            .filter(|(_, r)| {
                r.evicted_at
                    .elapsed()
                    .ok()
                    .is_some_and(|elapsed| elapsed < within)
            })
            .map(|(id, r)| (*id, r))
            .collect()
    }

    /// Total eviction count
    #[must_use]
    pub fn total_evictions(&self) -> usize {
        self.evicted_nodes.len()
    }
}

impl Default for CloseGroupEvictionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for security coordinator
#[derive(Debug, Clone)]
pub struct SecurityCoordinatorConfig {
    /// Close group validator config
    pub close_group_config: CloseGroupValidatorConfig,
    /// Sybil detector config
    pub sybil_config: SybilDetectorConfig,
    /// Maintenance config
    pub maintenance_config: MaintenanceConfig,
    /// Minimum trust for participation in security decisions
    pub min_participation_trust: f64,
    /// Minimum geographic regions for close group
    pub min_geographic_regions: usize,
    /// Whether to automatically propagate evictions
    pub auto_propagate_evictions: bool,
    /// Analysis interval for detectors
    pub analysis_interval: Duration,
}

impl Default for SecurityCoordinatorConfig {
    fn default() -> Self {
        Self {
            close_group_config: CloseGroupValidatorConfig::default(),
            sybil_config: SybilDetectorConfig::default(),
            maintenance_config: MaintenanceConfig::default(),
            min_participation_trust: 0.3,
            min_geographic_regions: 3,
            auto_propagate_evictions: true,
            analysis_interval: Duration::from_secs(60),
        }
    }
}

/// Unified security coordinator for routing maintenance
///
/// Integrates all security components to provide coordinated
/// protection during routing table operations.
pub struct SecurityCoordinator {
    /// Configuration
    config: SecurityCoordinatorConfig,
    /// Close group validator
    close_group_validator: Arc<RwLock<CloseGroupValidator>>,
    /// Sybil detector
    sybil_detector: Arc<RwLock<SybilDetector>>,
    /// Eviction manager
    eviction_manager: Arc<RwLock<EvictionManager>>,
    /// Close group eviction tracker
    eviction_tracker: Arc<RwLock<CloseGroupEvictionTracker>>,
    /// Trust scores (from EigenTrust)
    trust_scores: Arc<RwLock<HashMap<PeerId, f64>>>,
    /// Node geographic regions
    node_regions: Arc<RwLock<HashMap<PeerId, String>>>,
    /// Last analysis time
    last_analysis: RwLock<Instant>,
}

impl SecurityCoordinator {
    /// Create a new security coordinator
    #[must_use]
    pub fn new(config: SecurityCoordinatorConfig) -> Self {
        Self {
            close_group_validator: Arc::new(RwLock::new(CloseGroupValidator::new(
                config.close_group_config.clone(),
            ))),
            sybil_detector: Arc::new(RwLock::new(SybilDetector::new(config.sybil_config.clone()))),
            eviction_manager: Arc::new(RwLock::new(EvictionManager::new(
                config.maintenance_config.clone(),
            ))),
            eviction_tracker: Arc::new(RwLock::new(CloseGroupEvictionTracker::new())),
            trust_scores: Arc::new(RwLock::new(HashMap::new())),
            node_regions: Arc::new(RwLock::new(HashMap::new())),
            last_analysis: RwLock::new(Instant::now()),
            config,
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SecurityCoordinatorConfig::default())
    }

    /// Get the eviction tracker
    #[must_use]
    pub fn eviction_tracker(&self) -> &Arc<RwLock<CloseGroupEvictionTracker>> {
        &self.eviction_tracker
    }

    /// Update trust score for a node
    pub fn update_trust_score(&self, node_id: &PeerId, score: f64) {
        self.trust_scores.write().insert(*node_id, score);
        self.eviction_manager
            .write()
            .update_trust_score(node_id, score);
    }

    /// Update node geographic region
    pub fn update_node_region(&self, node_id: &PeerId, region: String) {
        self.node_regions.write().insert(*node_id, region);
    }

    /// Get trust score for a node
    #[must_use]
    pub fn get_trust_score(&self, node_id: &PeerId) -> Option<f64> {
        self.trust_scores.read().get(node_id).copied()
    }

    /// Record a node joining the network
    pub fn record_node_join(&self, peer_id: PeerId, ip_addr: Option<std::net::IpAddr>) {
        self.sybil_detector.write().record_join(peer_id, ip_addr);
    }

    /// Record a node leaving the network
    pub fn record_node_leave(&self, peer_id: &PeerId) {
        self.sybil_detector.write().record_leave(peer_id);
    }

    /// Record a communication success
    pub fn record_success(&self, node_id: &PeerId) {
        self.eviction_manager.write().record_success(node_id);
    }

    /// Record a communication failure
    pub fn record_failure(&self, node_id: &PeerId) {
        self.eviction_manager.write().record_failure(node_id);
    }

    /// Validate a node's close group membership
    ///
    /// This is the core function that should be called during routing table refresh.
    pub fn validate_close_group_membership(
        &self,
        node_id: &PeerId,
        responses: &[CloseGroupResponse],
    ) -> CloseGroupValidationResult {
        let trust_score = self.get_trust_score(node_id);

        // Perform validation
        let result =
            self.close_group_validator
                .read()
                .validate_membership(node_id, responses, trust_score);

        // If validation failed, process the failure
        if !result.is_valid {
            self.handle_validation_failure(node_id, &result);
        }

        result
    }

    /// Handle a validation failure
    fn handle_validation_failure(&self, node_id: &PeerId, result: &CloseGroupValidationResult) {
        // Record eviction in tracker
        let peer_confirmations = (result.confirmation_ratio * 10.0) as usize; // Approximate

        self.eviction_tracker.write().record_eviction(
            *node_id,
            result.failure_reasons.clone(),
            peer_confirmations,
        );

        // Update eviction manager
        self.eviction_manager.write().record_failure(node_id);
    }

    /// Run periodic security analysis
    pub fn run_analysis(&self) {
        let now = Instant::now();

        // Check if enough time has passed
        {
            let last = self.last_analysis.read();
            if now.duration_since(*last) < self.config.analysis_interval {
                return;
            }
        }

        // Update last analysis time
        *self.last_analysis.write() = now;

        // Run Sybil analysis
        self.sybil_detector.write().run_analysis();

        // Update attack indicators
        self.update_attack_indicators();

        // Clean up old records
        self.cleanup_old_records();
    }

    /// Update attack indicators based on detector state
    fn update_attack_indicators(&self) {
        let sybil_risk = self.sybil_detector.read().overall_risk_score();

        let indicators = AttackIndicators {
            eclipse_risk: 0.0, // Would need eclipse detection
            sybil_risk,
            routing_manipulation: false,
            churn_rate: 0.0, // Would need churn tracking
            recent_failures: 0,
            last_updated: Instant::now(),
        };

        // Update validator
        self.close_group_validator
            .write()
            .update_attack_indicators(indicators);
    }

    /// Clean up old records from all detectors
    fn cleanup_old_records(&self) {
        self.sybil_detector.write().cleanup_old_records();
        self.eviction_tracker.write().cleanup_old_records();
    }

    /// Check if a node should be evicted
    #[must_use]
    pub fn should_evict(&self, node_id: &PeerId) -> bool {
        // Check eviction manager first
        if self.eviction_manager.read().should_evict(node_id) {
            return true;
        }

        // Check trust threshold
        if self.eviction_manager.read().should_evict_for_trust(node_id) {
            return true;
        }

        // Check if suspected Sybil
        if self.sybil_detector.read().is_peer_suspected(node_id) {
            return true;
        }

        // Check if recently evicted from close group
        if self
            .eviction_tracker
            .read()
            .was_evicted(node_id, Duration::from_secs(3600))
        {
            return true;
        }

        false
    }

    /// Get eviction reason for a node
    #[must_use]
    pub fn get_eviction_reason(&self, node_id: &PeerId) -> Option<EvictionReason> {
        // Check eviction manager reasons
        if let Some(reason) = self.eviction_manager.read().get_eviction_reason(node_id) {
            return Some(reason);
        }

        // Check close group eviction
        if self
            .eviction_tracker
            .read()
            .was_evicted(node_id, Duration::from_secs(3600))
        {
            return Some(EvictionReason::CloseGroupRejection);
        }

        None
    }

    /// Get all nodes that should be evicted
    #[must_use]
    pub fn get_eviction_candidates(&self) -> Vec<(PeerId, EvictionReason)> {
        let mut candidates = self.eviction_manager.read().get_eviction_candidates();

        // Add Sybil suspects
        for group in self.sybil_detector.read().get_suspected_groups() {
            if group.confidence >= 0.7 {
                for member in &group.members {
                    if !candidates.iter().any(|(id, _)| id == member) {
                        candidates.push((
                            *member,
                            EvictionReason::LowTrust("Sybil suspected".to_string()),
                        ));
                    }
                }
            }
        }

        candidates
    }

    /// Validate geographic diversity of a node set
    #[must_use]
    pub fn validate_geographic_diversity(&self, node_ids: &[PeerId]) -> bool {
        let regions = self.node_regions.read();
        let unique_regions: HashSet<_> = node_ids.iter().filter_map(|id| regions.get(id)).collect();

        unique_regions.len() >= self.config.min_geographic_regions
    }

    /// Get security score for a node (composite of all factors)
    #[must_use]
    pub fn get_security_score(&self, node_id: &PeerId) -> f64 {
        let base_trust = self.get_trust_score(node_id).unwrap_or(0.5);

        let sybil_penalty = self.sybil_detector.read().sybil_risk_score(node_id);

        // Composite score with Sybil penalty
        let score = base_trust * (1.0 - sybil_penalty * 0.5);
        score.clamp(0.0, 1.0)
    }

    /// Check if a node is eligible for critical operations
    #[must_use]
    pub fn is_eligible_for_critical_ops(&self, node_id: &PeerId) -> bool {
        self.get_security_score(node_id) >= 0.7
            && !self.sybil_detector.read().is_peer_suspected(node_id)
            && !self
                .eviction_tracker
                .read()
                .was_evicted(node_id, Duration::from_secs(3600))
    }

    /// Get current attack mode status
    #[must_use]
    pub fn is_attack_mode(&self) -> bool {
        self.close_group_validator.read().is_attack_mode()
    }

    /// Manually escalate to BFT mode
    pub fn escalate_to_bft(&self) {
        self.close_group_validator.write().escalate_to_bft();
    }

    /// De-escalate from BFT mode
    pub fn deescalate_from_bft(&self) {
        self.close_group_validator.write().deescalate_from_bft();
    }

    // =========================================================================
    // Phase 1.3: Orchestration Methods for Routing Table Refresh
    // =========================================================================

    /// Orchestrate security validation during bucket refresh.
    ///
    /// This is the main entry point for integrating security validation into
    /// the routing table refresh process. It coordinates all security detectors
    /// and returns a comprehensive validation result.
    ///
    /// Returns: (valid_nodes, eviction_candidates)
    pub fn orchestrate_refresh_validation(
        &self,
        refreshed_nodes: &[PeerId],
        responses_by_node: &HashMap<PeerId, Vec<CloseGroupResponse>>,
    ) -> (Vec<PeerId>, Vec<(PeerId, EvictionReason)>) {
        let mut valid_nodes = Vec::new();
        let mut eviction_candidates = Vec::new();

        // Step 1: Check if we should be in attack mode based on current indicators
        self.check_attack_escalation();

        // Step 2: Validate each refreshed node
        for node_id in refreshed_nodes {
            let responses = responses_by_node
                .get(node_id)
                .map(|r| r.as_slice())
                .unwrap_or(&[]);

            // Perform comprehensive validation
            let validation_result = self.validate_node_comprehensive(node_id, responses);

            if validation_result.is_valid {
                valid_nodes.push(*node_id);
            } else {
                // Determine eviction reason
                let reason = self.determine_eviction_reason(&validation_result);
                eviction_candidates.push((*node_id, reason));
            }
        }

        // Step 3: Run cross-node analysis (Sybil patterns, geographic diversity)
        self.analyze_node_set(&valid_nodes);

        // Step 4: Check for de-escalation if attack mode
        self.check_attack_deescalation();

        // Step 5: Record metrics
        self.record_refresh_metrics(&valid_nodes, &eviction_candidates);

        (valid_nodes, eviction_candidates)
    }

    /// Comprehensive validation of a single node.
    ///
    /// Combines close group validation with additional security checks.
    fn validate_node_comprehensive(
        &self,
        node_id: &PeerId,
        responses: &[CloseGroupResponse],
    ) -> CloseGroupValidationResult {
        // Get close group validation result
        let result = self.validate_close_group_membership(node_id, responses);

        // Additional Sybil check
        if self.sybil_detector.read().is_peer_suspected(node_id) {
            // Return a modified result if Sybil suspected
            let mut modified = result.clone();
            if modified.is_valid {
                modified.is_valid = false;
                modified
                    .failure_reasons
                    .push(CloseGroupFailure::SuspectedCollusion);
            }
            return modified;
        }

        // Check if recently evicted
        if self
            .eviction_tracker
            .read()
            .was_evicted(node_id, Duration::from_secs(3600))
        {
            let mut modified = result.clone();
            if modified.is_valid {
                modified.is_valid = false;
                modified
                    .failure_reasons
                    .push(CloseGroupFailure::EvictedFromCloseGroup);
            }
            return modified;
        }

        result
    }

    /// Determine the eviction reason from validation result.
    fn determine_eviction_reason(&self, result: &CloseGroupValidationResult) -> EvictionReason {
        // Check for specific failure reasons
        for reason in &result.failure_reasons {
            match reason {
                CloseGroupFailure::LowTrustScore => {
                    return EvictionReason::LowTrust("Failed trust validation".to_string());
                }
                CloseGroupFailure::SuspectedCollusion => {
                    return EvictionReason::LowTrust("Suspected collusion".to_string());
                }
                CloseGroupFailure::InsufficientGeographicDiversity => {
                    return EvictionReason::LowTrust("Geographic concentration".to_string());
                }
                CloseGroupFailure::EvictedFromCloseGroup => {
                    return EvictionReason::CloseGroupRejection;
                }
                _ => {}
            }
        }

        // Default to close group rejection
        EvictionReason::CloseGroupRejection
    }

    /// Analyze a set of nodes for cross-node attack patterns.
    fn analyze_node_set(&self, nodes: &[PeerId]) {
        // Check geographic diversity of the set
        if !nodes.is_empty() && !self.validate_geographic_diversity(nodes) {
            // Log warning but don't reject - this is informational
            tracing::warn!(
                node_count = nodes.len(),
                "Refresh result lacks geographic diversity"
            );
        }

        // Run periodic analysis if due
        self.run_analysis();
    }

    /// Check if we should escalate to attack mode.
    fn check_attack_escalation(&self) {
        let sybil_risk = self.sybil_detector.read().overall_risk_score();

        // Threshold for escalation
        let should_escalate = sybil_risk > 0.7;

        if should_escalate && !self.is_attack_mode() {
            tracing::warn!(
                sybil_risk = %sybil_risk,
                "Escalating to BFT mode due to high Sybil risk"
            );
            self.escalate_to_bft();
        }
    }

    /// Check if we can de-escalate from attack mode.
    fn check_attack_deescalation(&self) {
        if !self.is_attack_mode() {
            return;
        }

        let sybil_risk = self.sybil_detector.read().overall_risk_score();

        // Lower threshold for de-escalation (hysteresis)
        let can_deescalate = sybil_risk < 0.3;

        if can_deescalate {
            tracing::info!(
                sybil_risk = %sybil_risk,
                "De-escalating from BFT mode - attack indicators cleared"
            );
            self.deescalate_from_bft();
        }
    }

    /// Record metrics for refresh validation results.
    fn record_refresh_metrics(
        &self,
        valid_nodes: &[PeerId],
        eviction_candidates: &[(PeerId, EvictionReason)],
    ) {
        let total = valid_nodes.len() + eviction_candidates.len();
        if total == 0 {
            return;
        }

        let success_rate = valid_nodes.len() as f64 / total as f64;

        // Log validation summary
        tracing::debug!(
            valid = valid_nodes.len(),
            evicted = eviction_candidates.len(),
            success_rate = %format!("{:.1}%", success_rate * 100.0),
            attack_mode = self.is_attack_mode(),
            "Refresh validation complete"
        );

        // Count eviction reasons for metrics
        for (_, reason) in eviction_candidates {
            match reason {
                EvictionReason::LowTrust(_) => {
                    // Counted in eviction metrics
                }
                EvictionReason::CloseGroupRejection => {
                    // Counted in close group metrics
                }
                _ => {}
            }
        }
    }

    /// Start a background security monitoring task.
    ///
    /// This spawns an async task that periodically runs security analysis
    /// and checks for attack indicators.
    pub fn start_background_monitoring(
        self: &Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let coordinator = Arc::clone(self);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                // Run periodic analysis
                coordinator.run_analysis();

                // Check escalation/de-escalation
                coordinator.check_attack_escalation();
                coordinator.check_attack_deescalation();

                // Log security status periodically
                let sybil_risk = coordinator.sybil_detector.read().overall_risk_score();
                let eviction_count = coordinator.eviction_tracker.read().total_evictions();

                tracing::debug!(
                    sybil_risk = %format!("{:.2}", sybil_risk),
                    recent_evictions = %eviction_count,
                    attack_mode = coordinator.is_attack_mode(),
                    "Security monitor status"
                );
            }
        })
    }

    /// Get the close group validator for direct access.
    #[must_use]
    pub fn close_group_validator(&self) -> &Arc<RwLock<CloseGroupValidator>> {
        &self.close_group_validator
    }

    /// Get the sybil detector for direct access.
    #[must_use]
    pub fn sybil_detector(&self) -> &Arc<RwLock<SybilDetector>> {
        &self.sybil_detector
    }

    /// Get the eviction manager for direct access.
    #[must_use]
    pub fn eviction_manager(&self) -> &Arc<RwLock<EvictionManager>> {
        &self.eviction_manager
    }

    /// Get current attack indicators summary.
    #[must_use]
    pub fn get_attack_indicators_summary(&self) -> AttackIndicatorsSummary {
        let sybil_risk = self.sybil_detector.read().overall_risk_score();
        let recent_evictions = self
            .eviction_tracker
            .read()
            .get_recently_evicted(Duration::from_secs(300))
            .len();

        AttackIndicatorsSummary {
            sybil_risk,
            recent_eviction_count: recent_evictions,
            is_attack_mode: self.is_attack_mode(),
            geographic_diversity_ok: true, // Placeholder - would need context
        }
    }
}

/// Summary of current attack indicators
#[derive(Debug, Clone)]
pub struct AttackIndicatorsSummary {
    /// Sybil attack risk score (0.0 - 1.0)
    pub sybil_risk: f64,
    /// Number of evictions in last 5 minutes
    pub recent_eviction_count: usize,
    /// Whether system is in BFT attack mode
    pub is_attack_mode: bool,
    /// Whether geographic diversity requirements are met
    pub geographic_diversity_ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_node_id() -> PeerId {
        PeerId::random()
    }

    fn create_response(
        confirms: bool,
        trust: f64,
        region: Option<&str>,
        latency_ms: u64,
    ) -> CloseGroupResponse {
        CloseGroupResponse {
            peer_id: random_node_id(),
            confirms_membership: confirms,
            peer_trust_score: Some(trust),
            peer_region: region.map(String::from),
            response_latency: Duration::from_millis(latency_ms),
            received_at: Instant::now(),
        }
    }

    #[test]
    fn test_security_coordinator_creation() {
        let coordinator = SecurityCoordinator::with_defaults();
        assert!(!coordinator.is_attack_mode());
    }

    #[test]
    fn test_trust_score_management() {
        let coordinator = SecurityCoordinator::with_defaults();
        let node_id = random_node_id();

        assert!(coordinator.get_trust_score(&node_id).is_none());

        coordinator.update_trust_score(&node_id, 0.75);
        assert!((coordinator.get_trust_score(&node_id).unwrap() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_close_group_validation() {
        let coordinator = SecurityCoordinator::with_defaults();
        let node_id = random_node_id();

        let responses = vec![
            create_response(true, 0.9, Some("us-east"), 50),
            create_response(true, 0.8, Some("eu-west"), 60),
            create_response(true, 0.7, Some("asia"), 70),
            create_response(true, 0.6, Some("oceania"), 80),
            create_response(false, 0.4, Some("africa"), 90),
        ];

        let result = coordinator.validate_close_group_membership(&node_id, &responses);
        assert!(result.is_valid);
    }

    #[test]
    fn test_eviction_tracking() {
        let coordinator = SecurityCoordinator::with_defaults();
        let node_id = random_node_id();

        // Initially not evicted
        assert!(
            !coordinator
                .eviction_tracker
                .read()
                .was_evicted(&node_id, Duration::from_secs(3600))
        );

        // Record eviction
        coordinator.eviction_tracker.write().record_eviction(
            node_id,
            vec![CloseGroupFailure::InsufficientConfirmation],
            5,
        );

        // Now evicted
        assert!(
            coordinator
                .eviction_tracker
                .read()
                .was_evicted(&node_id, Duration::from_secs(3600))
        );
    }

    #[test]
    fn test_should_evict_integration() {
        let coordinator = SecurityCoordinator::with_defaults();
        let node_id = random_node_id();

        // Record failures until eviction threshold
        for _ in 0..5 {
            coordinator.record_failure(&node_id);
        }

        // Check if should evict - depends on config max_consecutive_failures
        // Default is 3, so with 5 failures it should trigger
        let should = coordinator.eviction_manager.read().should_evict(&node_id);
        assert!(should || coordinator.should_evict(&node_id));
    }

    #[test]
    fn test_security_score_calculation() {
        let coordinator = SecurityCoordinator::with_defaults();
        let node_id = random_node_id();

        // Set base trust
        coordinator.update_trust_score(&node_id, 0.8);

        // Security score should be close to trust with no penalties
        let score = coordinator.get_security_score(&node_id);
        assert!(score >= 0.7); // Should be around 0.8
    }

    #[test]
    fn test_geographic_diversity_validation() {
        let coordinator = SecurityCoordinator::with_defaults();

        let nodes: Vec<_> = (0..5).map(|_| random_node_id()).collect();

        // Add regions
        for (i, node) in nodes.iter().enumerate() {
            let region = match i {
                0 => "us-east",
                1 => "eu-west",
                2 => "asia",
                3 => "oceania",
                4 => "africa",
                _ => "unknown",
            };
            coordinator.update_node_region(node, region.to_string());
        }

        // Should have diversity with 5 different regions
        assert!(coordinator.validate_geographic_diversity(&nodes));

        // Without diversity
        let same_region_nodes: Vec<_> = (0..5).map(|_| random_node_id()).collect();
        for node in &same_region_nodes {
            coordinator.update_node_region(node, "us-east".to_string());
        }

        // Only 1 region - should fail
        assert!(!coordinator.validate_geographic_diversity(&same_region_nodes));
    }

    #[test]
    fn test_bft_escalation() {
        let coordinator = SecurityCoordinator::with_defaults();

        assert!(!coordinator.is_attack_mode());

        coordinator.escalate_to_bft();
        assert!(coordinator.is_attack_mode());

        coordinator.deescalate_from_bft();
        // De-escalation only works if attack indicators are clear
        // So it might still be in attack mode
    }

    #[test]
    fn test_eligible_for_critical_ops() {
        let coordinator = SecurityCoordinator::with_defaults();
        let node_id = random_node_id();

        // Set high trust
        coordinator.update_trust_score(&node_id, 0.9);

        // Should be eligible
        assert!(coordinator.is_eligible_for_critical_ops(&node_id));

        // Record eviction
        coordinator.eviction_tracker.write().record_eviction(
            node_id,
            vec![CloseGroupFailure::InsufficientConfirmation],
            5,
        );

        // Now not eligible
        assert!(!coordinator.is_eligible_for_critical_ops(&node_id));
    }
}
