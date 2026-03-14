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

//! Hyperbolic geometry routing implementation
//!
//! Implements greedy routing in hyperbolic space using the Poincaré disk model

use super::*;
use crate::PeerId;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Hyperbolic space manager for coordinate-based routing
pub struct HyperbolicSpace {
    /// Our node's current coordinate
    my_coordinate: RwLock<HyperbolicCoordinate>,

    /// Neighbor coordinates
    neighbor_coordinates: Arc<RwLock<HashMap<PeerId, HyperbolicCoordinate>>>,

    /// Coordinate adjustment rate
    adjustment_rate: f64,
}

impl Default for HyperbolicSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperbolicSpace {
    /// Create a new hyperbolic space instance
    pub fn new() -> Self {
        Self {
            my_coordinate: RwLock::new(HyperbolicCoordinate {
                r: 0.5,
                theta: rand::random::<f64>() * 2.0 * std::f64::consts::PI,
            }),
            neighbor_coordinates: Arc::new(RwLock::new(HashMap::new())),
            adjustment_rate: 0.01,
        }
    }

    /// Test helper: expose neighbor map for read access
    pub fn neighbors_arc(&self) -> Arc<RwLock<HashMap<PeerId, HyperbolicCoordinate>>> {
        Arc::clone(&self.neighbor_coordinates)
    }

    /// Calculate hyperbolic distance between two coordinates
    pub fn distance(a: &HyperbolicCoordinate, b: &HyperbolicCoordinate) -> f64 {
        let x1 = a.r * a.theta.cos();
        let y1 = a.r * a.theta.sin();
        let x2 = b.r * b.theta.cos();
        let y2 = b.r * b.theta.sin();

        let dx = x1 - x2;
        let dy = y1 - y2;
        let norm_sq = dx * dx + dy * dy;

        let denom = (1.0 - (x1 * x1 + y1 * y1)) * (1.0 - (x2 * x2 + y2 * y2));
        if denom <= 0.0 {
            return f64::INFINITY;
        }

        let argument = 1.0 + 2.0 * norm_sq / denom;
        argument.max(1.0).acosh()
    }

    /// Perform greedy routing to find next hop
    pub async fn greedy_route(&self, target: &HyperbolicCoordinate) -> Option<PeerId> {
        let my_coord = self.my_coordinate.read().await;
        let my_distance = Self::distance(&my_coord, target);
        let epsilon = 1e-9;

        let neighbors = self.neighbor_coordinates.read().await;
        neighbors
            .iter()
            .filter_map(|(id, coord)| {
                let dist = Self::distance(coord, target);
                if dist + epsilon < my_distance {
                    Some((*id, dist))
                } else {
                    None
                }
            })
            .min_by(|(_, dist_a), (_, dist_b)| {
                dist_a
                    .partial_cmp(dist_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id)
    }

    /// Adjust our coordinate based on neighbor positions
    pub async fn adjust_coordinate(&self, neighbor_coords: &[(PeerId, HyperbolicCoordinate)]) {
        let mut my_coord = self.my_coordinate.write().await;

        // Adjust radial coordinate based on degree and neighbors' radial positions
        let degree = neighbor_coords.len();
        let deg_term = 1.0 - (2.0 / (degree as f64 + 2.0));
        let avg_neighbor_r = if degree > 0 {
            neighbor_coords.iter().map(|(_, c)| c.r).sum::<f64>() / degree as f64
        } else {
            my_coord.r
        };
        // Blend the degree-based target with the neighbors' average radius
        let target_r = 0.5 * deg_term + 0.5 * avg_neighbor_r;
        my_coord.r += self.adjustment_rate * (target_r - my_coord.r);

        // Ensure r stays in bounds
        my_coord.r = my_coord.r.clamp(0.0, 0.999);

        // Adjust angular coordinate based on neighbor positions
        if !neighbor_coords.is_empty() {
            let avg_theta = neighbor_coords
                .iter()
                .map(|(_, coord)| coord.theta)
                .sum::<f64>()
                / neighbor_coords.len() as f64;

            let angle_diff = angle_difference(avg_theta, my_coord.theta);
            my_coord.theta += self.adjustment_rate * angle_diff;

            // Normalize theta to [0, 2π)
            while my_coord.theta < 0.0 {
                my_coord.theta += 2.0 * std::f64::consts::PI;
            }
            while my_coord.theta >= 2.0 * std::f64::consts::PI {
                my_coord.theta -= 2.0 * std::f64::consts::PI;
            }
        }
    }

    /// Get current coordinate
    pub async fn get_coordinate(&self) -> HyperbolicCoordinate {
        *self.my_coordinate.read().await
    }

    /// Update a neighbor's coordinate
    pub async fn update_neighbor(&self, node_id: PeerId, coord: HyperbolicCoordinate) {
        let mut neighbors = self.neighbor_coordinates.write().await;
        neighbors.insert(node_id, coord);
    }

    /// Remove a neighbor
    pub async fn remove_neighbor(&self, node_id: &PeerId) {
        let mut neighbors = self.neighbor_coordinates.write().await;
        neighbors.remove(node_id);
    }
}

/// Calculate the shortest angular difference between two angles
pub fn angle_difference(a: f64, b: f64) -> f64 {
    let diff = a - b;
    if diff > std::f64::consts::PI {
        diff - 2.0 * std::f64::consts::PI
    } else if diff < -std::f64::consts::PI {
        diff + 2.0 * std::f64::consts::PI
    } else {
        diff
    }
}

/// Hyperbolic routing strategy for integration with AdaptiveRouter
pub struct HyperbolicRoutingStrategy {
    /// The hyperbolic space manager
    space: Arc<HyperbolicSpace>,

    /// Local node ID
    local_id: PeerId,

    /// Maximum hops before declaring failure
    max_hops: usize,
}

impl HyperbolicRoutingStrategy {
    /// Create a new hyperbolic routing strategy
    pub fn new(local_id: PeerId, space: Arc<HyperbolicSpace>) -> Self {
        Self {
            space,
            local_id,
            max_hops: 10,
        }
    }

    /// Find path using greedy hyperbolic routing
    async fn find_hyperbolic_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        // Check if we have the target's coordinate
        let target_coord = {
            let neighbors = self.space.neighbor_coordinates.read().await;
            neighbors
                .get(target)
                .cloned()
                .or_else(|| neighbors.values().next().cloned())
        };

        let target_coord = match target_coord {
            Some(coord) => coord,
            None => {
                // We don't know any neighbor coordinates, cannot route
                return Err(AdaptiveNetworkError::Routing(
                    "Target coordinate unknown".to_string(),
                ));
            }
        };

        let mut path = Vec::new();
        let mut _current = self.local_id;
        let mut visited = std::collections::HashSet::<PeerId>::new();
        visited.insert(_current);

        // Greedy routing with loop detection
        for _ in 0..self.max_hops {
            // Find next hop
            let next_hop = self.space.greedy_route(&target_coord).await;

            match next_hop {
                Some(next) => {
                    if next == *target {
                        // Reached target
                        path.push(next);
                        return Ok(path);
                    }

                    if visited.contains(&next) {
                        // Loop detected, routing failed
                        if !path.is_empty() {
                            return Ok(path);
                        }
                        return Err(AdaptiveNetworkError::Routing(
                            "Routing loop detected".to_string(),
                        ));
                    }

                    path.push(next);
                    visited.insert(next);
                    _current = next;
                }
                None => {
                    // No closer neighbor found, greedy routing failed
                    if !path.is_empty() {
                        return Ok(path);
                    }
                    return Err(AdaptiveNetworkError::Routing(
                        "No closer neighbor found".to_string(),
                    ));
                }
            }
        }

        // Max hops exceeded
        if !path.is_empty() {
            Ok(path)
        } else {
            Err(AdaptiveNetworkError::Routing(
                "Maximum hop count exceeded".to_string(),
            ))
        }
    }
}

#[async_trait]
impl RoutingStrategy for HyperbolicRoutingStrategy {
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        self.find_hyperbolic_path(target).await
    }

    fn route_score(&self, _neighbor: &PeerId, _target: &PeerId) -> f64 {
        // This is synchronous, so we can't access async coordinates
        // Return a default score - the actual routing logic is in find_path
        0.5
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // No-op: metrics removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hyperbolic_distance() {
        let origin = HyperbolicCoordinate { r: 0.0, theta: 0.0 };
        let point = HyperbolicCoordinate {
            r: 0.5,
            theta: std::f64::consts::PI,
        };

        let distance = HyperbolicSpace::distance(&origin, &point);
        assert!(distance > 0.0);

        // Distance to self should be 0
        let self_distance = HyperbolicSpace::distance(&origin, &origin);
        assert!((self_distance - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_angle_difference() {
        assert!((angle_difference(0.0, 0.0) - 0.0).abs() < 1e-10);
        assert!((angle_difference(std::f64::consts::PI, 0.0) - std::f64::consts::PI).abs() < 1e-10);
        assert!(
            (angle_difference(0.0, std::f64::consts::PI) - (-std::f64::consts::PI)).abs() < 1e-10
        );
        assert!(
            (angle_difference(1.9 * std::f64::consts::PI, 0.1 * std::f64::consts::PI)
                - (-0.2 * std::f64::consts::PI))
                .abs()
                < 1e-10
        );
    }

    #[tokio::test]
    async fn test_coordinate_adjustment() {
        let space = HyperbolicSpace::new();
        let initial = space.get_coordinate().await;

        // Simulate neighbors at the edge
        use rand::RngCore;

        let mut hash1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash1);
        let mut hash2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash2);

        let neighbors = vec![
            (
                PeerId::from_bytes(hash1),
                HyperbolicCoordinate { r: 0.9, theta: 0.0 },
            ),
            (
                PeerId::from_bytes(hash2),
                HyperbolicCoordinate {
                    r: 0.9,
                    theta: std::f64::consts::PI,
                },
            ),
        ];

        space.adjust_coordinate(&neighbors).await;
        let adjusted = space.get_coordinate().await;

        // Should move towards edge with high-degree neighbors
        assert!(adjusted.r > initial.r);
    }

    #[tokio::test]
    async fn test_hyperbolic_routing_strategy() {
        use rand::RngCore;

        // Create space and strategy
        let space = Arc::new(HyperbolicSpace::new());

        let mut hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash);
        let local_id = PeerId::from_bytes(hash);

        let strategy = HyperbolicRoutingStrategy::new(local_id, space.clone());

        // Add some neighbors with coordinates
        let mut hash1 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash1);
        let neighbor1 = PeerId::from_bytes(hash1);

        let mut hash2 = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash2);
        let neighbor2 = PeerId::from_bytes(hash2);

        let mut hash_target = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash_target);
        let target = PeerId::from_bytes(hash_target);

        // Set up coordinates
        space
            .update_neighbor(neighbor1, HyperbolicCoordinate { r: 0.3, theta: 0.0 })
            .await;
        space
            .update_neighbor(neighbor2, HyperbolicCoordinate { r: 0.7, theta: 1.0 })
            .await;
        space
            .update_neighbor(target, HyperbolicCoordinate { r: 0.8, theta: 1.5 })
            .await;

        // Try routing to target
        let _result = strategy.find_path(&target).await;
    }

    #[tokio::test]
    async fn test_greedy_routing() {
        let space = HyperbolicSpace::new();

        *space.my_coordinate.write().await = HyperbolicCoordinate {
            r: 0.95,
            theta: 0.0,
        };

        use rand::RngCore;

        // Add neighbors at various positions
        let mut neighbors = vec![];
        for i in 0..5 {
            let mut hash = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut hash);
            let node_id = PeerId::from_bytes(hash);

            let coord = HyperbolicCoordinate {
                r: 0.1 + (i as f64) * 0.2,
                theta: (i as f64) * std::f64::consts::PI / 3.0,
            };

            space.update_neighbor(node_id, coord).await;
            neighbors.push((node_id, coord));
        }

        // Test greedy routing to a target
        let target_coord = HyperbolicCoordinate { r: 0.6, theta: 1.0 };
        let next_hop = space.greedy_route(&target_coord).await;

        // Should find a neighbor closer to target
        assert!(next_hop.is_some());

        // Verify it chose the closest neighbor
        if let Some(chosen) = next_hop {
            let neighbors_map = space.neighbor_coordinates.read().await;
            let chosen_coord = neighbors_map.get(&chosen).unwrap();
            let chosen_dist = HyperbolicSpace::distance(chosen_coord, &target_coord);

            // Check that no other neighbor is closer
            for (id, coord) in &neighbors {
                if id != &chosen {
                    let dist = HyperbolicSpace::distance(coord, &target_coord);
                    assert!(dist >= chosen_dist);
                }
            }
        }
    }
}
