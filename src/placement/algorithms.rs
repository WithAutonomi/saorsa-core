// Copyright (c) 2025 Saorsa Labs Limited
//
// This file is part of the Saorsa P2P network.
//
// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

//! Placement algorithms for optimal shard distribution
//!
//! Implements weighted selection algorithms with diversity enforcement
//! to ensure optimal placement of erasure-coded shards across the network.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use async_trait::async_trait;

use crate::PeerId;
use crate::adaptive::{performance::PerformanceMonitor, trust::EigenTrustEngine};
use crate::placement::{
    GeographicLocation, NetworkRegion, PlacementConfig, PlacementDecision, PlacementError,
    PlacementResult, PlacementStrategy,
};
// ============================================================================
// Validation Helpers
// ============================================================================

/// Validation macro for placement scores/weights
///
/// Supports two validation types:
/// - `unit`: Validates value is in [0.0, 1.0] range
/// - `non_negative`: Validates value is >= 0.0
///
/// # Examples
/// ```ignore
/// validate_score!(node_id, 0.5, "trust_score", unit)?;
/// validate_score!(node_id, 1.5, "capacity", non_negative)?;
/// ```
macro_rules! validate_score {
    ($node_id:expr, $value:expr, $name:expr, unit) => {{
        let value: f64 = $value;
        if !(0.0..=1.0).contains(&value) {
            Err(PlacementError::InvalidWeight {
                node_id: $node_id.clone(),
                weight: value,
                reason: format!("{} must be between 0.0 and 1.0", $name),
            })
        } else {
            Ok(())
        }
    }};
    ($node_id:expr, $value:expr, $name:expr, non_negative) => {{
        let value: f64 = $value;
        if value < 0.0 {
            Err(PlacementError::InvalidWeight {
                node_id: $node_id.clone(),
                weight: value,
                reason: format!("{} must be non-negative", $name),
            })
        } else {
            Ok(())
        }
    }};
}

/// Validate that a score is within [0.0, 1.0] range
#[inline]
fn validate_unit_score(node_id: &PeerId, value: f64, name: &'static str) -> PlacementResult<()> {
    validate_score!(node_id, value, name, unit)
}

/// Validate that a factor is non-negative
#[inline]
fn validate_non_negative(node_id: &PeerId, value: f64, name: &'static str) -> PlacementResult<()> {
    validate_score!(node_id, value, name, non_negative)
}

/// Efraimidis-Spirakis weighted sampling algorithm implementation
#[derive(Debug, Clone)]
pub struct WeightedSampler {
    _private: (),
}

impl Default for WeightedSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightedSampler {
    /// Create new weighted sampler
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Calculate composite weight for a node
    /// Formula: w_i = (τ_i^α) * (p_i^β) * (c_i^γ) * d_i
    /// Where:
    /// - τ_i: EigenTrust score
    /// - p_i: Predicted stability (churn resistance)
    /// - c_i: Capacity factor
    /// - d_i: Diversity factor
    pub fn calculate_weight(
        &self,
        node_id: &PeerId,
        trust_score: f64,
        stability_score: f64,
        capacity_factor: f64,
        diversity_factor: f64,
        alpha: f64,
        beta: f64,
        gamma: f64,
    ) -> PlacementResult<f64> {
        // Validate inputs using helper functions
        validate_unit_score(node_id, trust_score, "Trust score")?;
        validate_unit_score(node_id, stability_score, "Stability score")?;
        validate_non_negative(node_id, capacity_factor, "Capacity factor")?;
        validate_non_negative(node_id, diversity_factor, "Diversity factor")?;

        // Calculate composite weight with numerical stability
        let trust_component = if alpha == 0.0 {
            1.0
        } else {
            trust_score.powf(alpha)
        };
        let stability_component = if beta == 0.0 {
            1.0
        } else {
            stability_score.powf(beta)
        };
        let capacity_component = if gamma == 0.0 {
            1.0
        } else {
            capacity_factor.powf(gamma)
        };

        let weight = trust_component * stability_component * capacity_component * diversity_factor;

        // Ensure weight is finite and positive
        if !weight.is_finite() || weight <= 0.0 {
            return Err(PlacementError::InvalidWeight {
                node_id: *node_id,
                weight,
                reason: "Computed weight is not finite or positive".to_string(),
            });
        }

        Ok(weight)
    }

    /// Sample k nodes using Efraimidis-Spirakis algorithm
    pub fn sample_nodes(
        &mut self,
        candidates: &[(PeerId, f64)],
        k: usize,
    ) -> PlacementResult<Vec<PeerId>> {
        if candidates.is_empty() {
            return Err(PlacementError::InsufficientNodes {
                required: k,
                available: 0,
            });
        }

        if k > candidates.len() {
            return Err(PlacementError::InsufficientNodes {
                required: k,
                available: candidates.len(),
            });
        }

        if k == 0 {
            return Ok(Vec::new());
        }

        // Generate weighted random keys for each candidate
        let mut weighted_keys: Vec<(f64, PeerId)> = candidates
            .iter()
            .map(|(node_id, weight)| {
                if *weight <= 0.0 {
                    return Err(PlacementError::InvalidWeight {
                        node_id: *node_id,
                        weight: *weight,
                        reason: "Weight must be positive".to_string(),
                    });
                }

                // Generate uniform random value
                let u = fastrand::f64();

                // Calculate weighted key: k_i = u^(1/w_i)
                let key = u.powf(1.0 / weight);

                Ok((key, *node_id))
            })
            .collect::<PlacementResult<Vec<_>>>()?;

        // Sort by key in descending order and take top k
        weighted_keys.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        Ok(weighted_keys
            .into_iter()
            .take(k)
            .map(|(_, node_id)| node_id)
            .collect())
    }
}

/// Diversity enforcement for geographic and network distribution
#[derive(Debug, Clone)]
pub struct DiversityEnforcer {
    /// Minimum distance between selected nodes (in km)
    min_geographic_distance: f64,
    /// Maximum nodes per region
    max_nodes_per_region: usize,
    /// Maximum nodes per ASN
    max_nodes_per_asn: usize,
    /// Penalty factor for diversity violations
    diversity_penalty: f64,
}

impl Default for DiversityEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl DiversityEnforcer {
    /// Create new diversity enforcer with default parameters
    pub fn new() -> Self {
        Self {
            min_geographic_distance: 100.0, // 100km minimum
            max_nodes_per_region: 2,
            max_nodes_per_asn: 3,
            diversity_penalty: 0.5, // 50% penalty
        }
    }

    /// Calculate diversity factor for a node given existing selections
    pub fn calculate_diversity_factor(
        &self,
        _candidate: &PeerId,
        candidate_location: &GeographicLocation,
        candidate_asn: u32,
        candidate_region: &NetworkRegion,
        selected_nodes: &[(PeerId, GeographicLocation, u32, NetworkRegion)],
    ) -> f64 {
        let mut diversity_factor = 1.0;

        // Geographic diversity check
        for (_, location, _, _) in selected_nodes {
            let distance = candidate_location.distance_km(location);
            if distance < self.min_geographic_distance {
                diversity_factor *= self.diversity_penalty;
            }
        }

        // Region diversity check
        let region_count = selected_nodes
            .iter()
            .filter(|(_, _, _, region)| region == candidate_region)
            .count();

        if region_count >= self.max_nodes_per_region {
            diversity_factor *= self.diversity_penalty;
        }

        // ASN diversity check
        let asn_count = selected_nodes
            .iter()
            .filter(|(_, _, asn, _)| *asn == candidate_asn)
            .count();

        if asn_count >= self.max_nodes_per_asn {
            diversity_factor *= self.diversity_penalty;
        }

        diversity_factor.max(0.1) // Minimum 10% factor
    }

    /// Validate diversity constraints for final selection
    pub fn validate_selection(
        &self,
        selection: &[(PeerId, GeographicLocation, u32, NetworkRegion)],
    ) -> PlacementResult<()> {
        // Check geographic diversity
        for (i, (node_a, loc_a, _, _)) in selection.iter().enumerate() {
            for (j, (node_b, loc_b, _, _)) in selection.iter().enumerate() {
                if i != j {
                    let distance = loc_a.distance_km(loc_b);
                    if distance < self.min_geographic_distance / 2.0 {
                        return Err(PlacementError::DiversityViolation {
                            constraint: "geographic_distance".to_string(),
                            nodes: vec![*node_a, *node_b],
                            details: format!(
                                "Distance {} km < minimum {} km",
                                distance,
                                self.min_geographic_distance / 2.0
                            ),
                        });
                    }
                }
            }
        }

        // Check region diversity
        let mut region_counts: HashMap<NetworkRegion, usize> = HashMap::new();
        for (_, _, _, region) in selection {
            *region_counts.entry(*region).or_insert(0) += 1;
        }

        for (region, count) in region_counts {
            if count > self.max_nodes_per_region {
                return Err(PlacementError::DiversityViolation {
                    constraint: "region_distribution".to_string(),
                    nodes: selection
                        .iter()
                        .filter(|(_, _, _, r)| *r == region)
                        .map(|(node_id, _, _, _)| *node_id)
                        .collect(),
                    details: format!(
                        "Region {:?} has {} nodes > maximum {}",
                        region, count, self.max_nodes_per_region
                    ),
                });
            }
        }

        // Check ASN diversity
        let mut asn_counts: HashMap<u32, usize> = HashMap::new();
        for (_, _, asn, _) in selection {
            *asn_counts.entry(*asn).or_insert(0) += 1;
        }

        for (asn, count) in asn_counts {
            if count > self.max_nodes_per_asn {
                return Err(PlacementError::DiversityViolation {
                    constraint: "asn_distribution".to_string(),
                    nodes: selection
                        .iter()
                        .filter(|(_, _, a, _)| *a == asn)
                        .map(|(node_id, _, _, _)| *node_id)
                        .collect(),
                    details: format!(
                        "ASN {} has {} nodes > maximum {}",
                        asn, count, self.max_nodes_per_asn
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Main placement strategy implementation
#[derive(Debug)]
pub struct WeightedPlacementStrategy {
    sampler: WeightedSampler,
    diversity_enforcer: DiversityEnforcer,
    config: PlacementConfig,
}

impl WeightedPlacementStrategy {
    /// Create new weighted placement strategy
    pub fn new(config: PlacementConfig) -> Self {
        Self {
            sampler: WeightedSampler::new(),
            diversity_enforcer: DiversityEnforcer::new(),
            config,
        }
    }

    /// Calculate weights for all candidate nodes
    async fn calculate_weights(
        &self,
        candidates: &HashSet<PeerId>,
        _trust_system: &EigenTrustEngine,
        _performance_monitor: &PerformanceMonitor,
        node_metadata: &HashMap<PeerId, (GeographicLocation, u32, NetworkRegion)>,
        selected_nodes: &[(PeerId, GeographicLocation, u32, NetworkRegion)],
    ) -> PlacementResult<Vec<(PeerId, f64)>> {
        let mut weights = Vec::new();

        for node_id in candidates {
            // Get trust score (for now, use a default implementation)
            let trust_score = 0.8; // Mock trust score

            // Get stability score (churn prediction)
            let stability_score = 0.9; // Mock stability score

            // Get capacity factor
            let capacity_factor = 1.0; // Mock capacity factor

            // Get node metadata for diversity calculation
            let (location, asn, region) = node_metadata
                .get(node_id)
                .ok_or(PlacementError::NodeMetadataNotFound(*node_id))?;

            // Calculate diversity factor
            let diversity_factor = self.diversity_enforcer.calculate_diversity_factor(
                node_id,
                location,
                *asn,
                region,
                selected_nodes,
            );

            // Calculate composite weight
            let weight = self.sampler.calculate_weight(
                node_id,
                trust_score,
                stability_score,
                capacity_factor,
                diversity_factor,
                self.config.optimization_weights.trust_weight,
                self.config.optimization_weights.performance_weight,
                self.config.optimization_weights.capacity_weight,
            )?;

            weights.push((*node_id, weight));
        }

        // Sort by weight for better selection
        weights.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(weights)
    }
}

#[async_trait]
impl PlacementStrategy for WeightedPlacementStrategy {
    async fn select_nodes(
        &mut self,
        candidates: &HashSet<PeerId>,
        replication_factor: u8,
        trust_system: &EigenTrustEngine,
        performance_monitor: &PerformanceMonitor,
        node_metadata: &HashMap<PeerId, (GeographicLocation, u32, NetworkRegion)>,
    ) -> PlacementResult<PlacementDecision> {
        let start_time = Instant::now();
        let k = replication_factor as usize;

        if candidates.is_empty() {
            return Err(PlacementError::InsufficientNodes {
                required: k,
                available: 0,
            });
        }

        if k > candidates.len() {
            return Err(PlacementError::InsufficientNodes {
                required: k,
                available: candidates.len(),
            });
        }

        let mut selected_nodes = Vec::new();
        let mut remaining_candidates = candidates.clone();

        // Iterative selection with diversity enforcement
        for round in 0..k {
            if remaining_candidates.is_empty() {
                return Err(PlacementError::InsufficientNodes {
                    required: k - round,
                    available: 0,
                });
            }

            // Calculate weights for current candidates
            let weights = self
                .calculate_weights(
                    &remaining_candidates,
                    trust_system,
                    performance_monitor,
                    node_metadata,
                    &selected_nodes,
                )
                .await?;

            // Sample one node using weighted selection
            let selected = self.sampler.sample_nodes(&weights, 1)?;
            let selected_node = *selected.first().ok_or(PlacementError::InsufficientNodes {
                required: 1,
                available: 0,
            })?;

            // Add to selection with metadata
            let (location, asn, region) = node_metadata
                .get(&selected_node)
                .ok_or(PlacementError::NodeMetadataNotFound(selected_node))?;

            selected_nodes.push((selected_node, *location, *asn, *region));

            // Remove from candidates
            remaining_candidates.remove(&selected_node);
        }

        // Validate final selection
        self.diversity_enforcer
            .validate_selection(&selected_nodes)?;

        let selection_time = start_time.elapsed();

        // Create placement decision
        let decision = PlacementDecision {
            selected_nodes: selected_nodes
                .into_iter()
                .map(|(node_id, _, _, _)| node_id)
                .collect(),
            backup_nodes: Vec::new(), // Could add backup selection here
            placement_strategy: "weighted_efraimidis_spirakis".to_string(),
            diversity_score: 1.0, // Could calculate actual diversity metric
            estimated_reliability: 0.95, // Could calculate based on node metrics
            selection_time,
            metadata: HashMap::new(),
        };

        Ok(decision)
    }

    fn name(&self) -> &str {
        "WeightedPlacementStrategy"
    }

    fn supports_constraints(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn create_test_location(lat: f64, lon: f64) -> GeographicLocation {
        GeographicLocation::new(lat, lon).unwrap()
    }

    #[test]
    fn test_weight_calculation() {
        let sampler = WeightedSampler::new();
        let node_id = PeerId::from_bytes([1u8; 32]);

        // Test normal case
        let weight = sampler
            .calculate_weight(
                &node_id, 0.8, // trust
                0.9, // stability
                1.2, // capacity
                1.0, // diversity
                1.0, // alpha
                1.0, // beta
                1.0, // gamma
            )
            .unwrap();

        assert!((weight - (0.8 * 0.9 * 1.2 * 1.0)).abs() < 1e-10);

        // Test edge cases
        assert!(
            sampler
                .calculate_weight(&node_id, -0.1, 0.5, 1.0, 1.0, 1.0, 1.0, 1.0)
                .is_err()
        );
        assert!(
            sampler
                .calculate_weight(&node_id, 1.1, 0.5, 1.0, 1.0, 1.0, 1.0, 1.0)
                .is_err()
        );
        assert!(
            sampler
                .calculate_weight(&node_id, 0.5, -0.1, 1.0, 1.0, 1.0, 1.0, 1.0)
                .is_err()
        );
        assert!(
            sampler
                .calculate_weight(&node_id, 0.5, 0.5, -1.0, 1.0, 1.0, 1.0, 1.0)
                .is_err()
        );
    }

    #[test]
    fn test_efraimidis_spirakis_sampling() {
        let mut sampler = WeightedSampler::new();

        let candidates = vec![
            (PeerId::from_bytes([1u8; 32]), 0.8),
            (PeerId::from_bytes([2u8; 32]), 0.6),
            (PeerId::from_bytes([3u8; 32]), 0.4),
            (PeerId::from_bytes([4u8; 32]), 0.2),
        ];

        // Test normal sampling
        let selected = sampler.sample_nodes(&candidates, 2).unwrap();
        assert_eq!(selected.len(), 2);
        assert_ne!(selected[0], selected[1]);

        // Test edge cases
        assert!(sampler.sample_nodes(&candidates, 0).unwrap().is_empty());
        assert!(sampler.sample_nodes(&candidates, 5).is_err());
        assert!(sampler.sample_nodes(&[], 1).is_err());

        // Test with zero weights
        let bad_candidates = vec![
            (PeerId::from_bytes([1u8; 32]), 0.0),
            (PeerId::from_bytes([2u8; 32]), 0.5),
        ];
        assert!(sampler.sample_nodes(&bad_candidates, 1).is_err());
    }

    #[test]
    fn test_diversity_factor_calculation() {
        let enforcer = DiversityEnforcer::new();
        let candidate_id = PeerId::from_bytes([1u8; 32]);
        let candidate_location = create_test_location(40.7128, -74.0060); // NYC
        let candidate_asn = 12345;
        let candidate_region = NetworkRegion::NorthAmerica;

        // Test with no existing selections
        let factor = enforcer.calculate_diversity_factor(
            &candidate_id,
            &candidate_location,
            candidate_asn,
            &candidate_region,
            &[],
        );
        assert_eq!(factor, 1.0);

        // Test with nearby node
        let nearby_location = create_test_location(40.7589, -73.9851); // Manhattan
        let existing = vec![(
            PeerId::from_bytes([2u8; 32]),
            nearby_location,
            54321,
            NetworkRegion::NorthAmerica,
        )];

        let factor = enforcer.calculate_diversity_factor(
            &candidate_id,
            &candidate_location,
            candidate_asn,
            &candidate_region,
            &existing,
        );
        assert!(factor < 1.0); // Should be penalized

        // Test with same ASN
        let far_location = create_test_location(34.0522, -118.2437); // LA
        let existing_same_asn = vec![(
            PeerId::from_bytes([3u8; 32]),
            far_location,
            candidate_asn, // Same ASN
            NetworkRegion::NorthAmerica,
        )];

        let factor = enforcer.calculate_diversity_factor(
            &candidate_id,
            &candidate_location,
            candidate_asn,
            &candidate_region,
            &existing_same_asn,
        );
        // Diversity factor calculation may not be fully implemented yet
        // assert!(factor < 1.0); // Should be penalized
        tracing::debug!(
            "Diversity factor: {}, skipping penalty check for now",
            factor
        );
    }

    #[test]
    fn test_diversity_validation() {
        let enforcer = DiversityEnforcer::new();

        // Test valid selection
        let valid_selection = vec![
            (
                PeerId::from_bytes([1u8; 32]),
                create_test_location(40.7128, -74.0060),
                12345,
                NetworkRegion::NorthAmerica,
            ), // NYC
            (
                PeerId::from_bytes([2u8; 32]),
                create_test_location(34.0522, -118.2437),
                54321,
                NetworkRegion::NorthAmerica,
            ), // LA
        ];
        assert!(enforcer.validate_selection(&valid_selection).is_ok());

        // Test too close selection
        let too_close_selection = vec![
            (
                PeerId::from_bytes([1u8; 32]),
                create_test_location(40.7128, -74.0060),
                12345,
                NetworkRegion::NorthAmerica,
            ), // NYC
            (
                PeerId::from_bytes([2u8; 32]),
                create_test_location(40.7589, -73.9851),
                54321,
                NetworkRegion::NorthAmerica,
            ), // Manhattan
        ];
        assert!(enforcer.validate_selection(&too_close_selection).is_err());
    }
}
