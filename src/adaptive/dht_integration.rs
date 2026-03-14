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

//! DHT Integration for Adaptive Network
//!
//! This module bridges the existing DHT implementation with the adaptive
//! network, providing trust-weighted routing and integration with other adaptive
//! components.

use super::*;
use crate::P2PNode;
use crate::PeerId;
use crate::address::MultiAddr;
use crate::dht::geographic_network_integration::GeographicNetworkIntegration;
use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::{DhtCoreEngine, DhtKey, Key as DhtKeyBytes};
use crate::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use async_trait::async_trait;

use std::collections::HashMap;
use std::f64::consts::PI;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Weighting for adaptive DHT node selection.
#[derive(Debug, Clone)]
pub struct AdaptiveDhtWeights {
    pub trust: f64,
    pub geo: f64,
    pub churn: f64,
    pub hyperbolic: f64,
    pub proximity: f64,
}

impl AdaptiveDhtWeights {
    const MIN_WEIGHT: f64 = 0.05;

    fn enforce_all_layers(&self) -> Self {
        let mut weights = Self {
            trust: self.trust.max(Self::MIN_WEIGHT),
            geo: self.geo.max(Self::MIN_WEIGHT),
            churn: self.churn.max(Self::MIN_WEIGHT),
            hyperbolic: self.hyperbolic.max(Self::MIN_WEIGHT),
            proximity: self.proximity.max(Self::MIN_WEIGHT),
        };
        let total =
            weights.trust + weights.geo + weights.churn + weights.hyperbolic + weights.proximity;
        if total > 0.0 {
            weights.trust /= total;
            weights.geo /= total;
            weights.churn /= total;
            weights.hyperbolic /= total;
            weights.proximity /= total;
        }
        weights
    }
}

impl Default for AdaptiveDhtWeights {
    fn default() -> Self {
        Self {
            trust: 0.25,
            geo: 0.2,
            churn: 0.15,
            hyperbolic: 0.2,
            proximity: 0.2,
        }
    }
}

/// Default number of closest nodes for DHT lookups (Kademlia K parameter).
const DEFAULT_CLOSEST_NODES_COUNT: usize = 8;

/// Adaptive DHT configuration used for layer-aware selection.
#[derive(Debug, Clone)]
pub struct AdaptiveDhtConfig {
    pub local_region: GeographicRegion,
    /// How many closest nodes to return from lookups.
    pub closest_nodes_count: usize,
    pub candidate_multiplier: usize,
    pub max_per_region: usize,
    pub min_trust_threshold: f64,
    pub max_churn_probability: f64,
    pub weights: AdaptiveDhtWeights,
}

impl AdaptiveDhtConfig {
    fn candidate_count(&self) -> usize {
        let base = self.closest_nodes_count.max(1);
        let multiplier = self.candidate_multiplier.max(1);
        base.saturating_mul(multiplier)
    }

    fn enforced_weights(&self) -> AdaptiveDhtWeights {
        self.weights.enforce_all_layers()
    }
}

impl Default for AdaptiveDhtConfig {
    fn default() -> Self {
        Self {
            local_region: GeographicRegion::Unknown,
            closest_nodes_count: DEFAULT_CLOSEST_NODES_COUNT,
            candidate_multiplier: 3,
            max_per_region: 3,
            min_trust_threshold: 0.2,
            max_churn_probability: 0.85,
            weights: AdaptiveDhtWeights::default(),
        }
    }
}

/// Dependencies required for AdaptiveDHT.
#[derive(Clone)]
pub struct AdaptiveDhtDependencies {
    pub identity: Arc<NodeIdentity>,
    pub trust_provider: Arc<dyn TrustProvider>,
    pub hyperbolic_space: Arc<HyperbolicSpace>,
    pub churn_predictor: Arc<ChurnPredictor>,
}

impl AdaptiveDhtDependencies {
    pub fn new(
        identity: Arc<NodeIdentity>,
        trust_provider: Arc<dyn TrustProvider>,
        hyperbolic_space: Arc<HyperbolicSpace>,
        churn_predictor: Arc<ChurnPredictor>,
    ) -> Self {
        Self {
            identity,
            trust_provider,
            hyperbolic_space,
            churn_predictor,
        }
    }

    pub fn with_defaults(
        identity: Arc<NodeIdentity>,
        trust_provider: Arc<dyn TrustProvider>,
    ) -> Self {
        let hyperbolic_space = Arc::new(HyperbolicSpace::new());
        let churn_predictor = Arc::new(ChurnPredictor::new());
        Self {
            identity,
            trust_provider,
            hyperbolic_space,
            churn_predictor,
        }
    }
}

enum AdaptiveDhtBackend {
    Local { dht: Arc<RwLock<DhtCoreEngine>> },
    Network { manager: Arc<DhtNetworkManager> },
}

/// Adaptive DHT that integrates S/Kademlia with trust scoring
pub struct AdaptiveDHT {
    backend: AdaptiveDhtBackend,
    config: AdaptiveDhtConfig,
    trust_provider: Arc<dyn TrustProvider>,
    hyperbolic_space: Arc<HyperbolicSpace>,
    churn_predictor: Arc<ChurnPredictor>,
    geo_integration: Arc<GeographicNetworkIntegration>,
    identity: Arc<NodeIdentity>,
}

#[derive(Debug, Clone)]
struct LayerScores {
    trust: f64,
    geo: f64,
    churn: f64,
    hyperbolic: f64,
    proximity: f64,
}

#[derive(Debug, Clone)]
struct ScoredCandidate {
    peer_id: PeerId,
    address: Option<MultiAddr>,
    region: GeographicRegion,
    scores: LayerScores,
    composite: f64,
}

#[derive(Debug, Clone)]
struct CandidateNode {
    peer_id: PeerId,
    address: MultiAddr,
}

impl AdaptiveDHT {
    /// Create new adaptive DHT instance (local-only backend)
    pub async fn new(
        identity: Arc<NodeIdentity>,
        trust_provider: Arc<dyn TrustProvider>,
    ) -> Result<Self> {
        let dependencies = AdaptiveDhtDependencies::with_defaults(identity, trust_provider);
        Self::new_with_dependencies(AdaptiveDhtConfig::default(), dependencies).await
    }

    /// Create new adaptive DHT instance with explicit dependencies (local backend).
    pub async fn new_with_dependencies(
        config: AdaptiveDhtConfig,
        dependencies: AdaptiveDhtDependencies,
    ) -> Result<Self> {
        let local_key = Self::node_id_to_key(&dependencies.identity.peer_id().clone());
        let node_id = PeerId::from_bytes(local_key);
        let base_dht = Arc::new(RwLock::new(
            DhtCoreEngine::new(node_id).map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        ));
        let geo_integration = Arc::new(
            GeographicNetworkIntegration::new(config.local_region)
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        );

        Ok(Self {
            backend: AdaptiveDhtBackend::Local { dht: base_dht },
            config,
            trust_provider: dependencies.trust_provider,
            hyperbolic_space: dependencies.hyperbolic_space,
            churn_predictor: dependencies.churn_predictor,
            geo_integration,
            identity: dependencies.identity,
        })
    }

    /// Attach AdaptiveDHT to an existing P2P node using a network backend.
    pub async fn attach_to_node(
        node: Arc<P2PNode>,
        network_config: DhtNetworkConfig,
        config: AdaptiveDhtConfig,
        dependencies: AdaptiveDhtDependencies,
    ) -> Result<Self> {
        let manager = Arc::new(
            DhtNetworkManager::new(
                node.transport().clone(),
                node.trust_engine(),
                network_config,
            )
            .await
            .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        );
        manager
            .start()
            .await
            .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?;

        let geo_integration = Arc::new(
            GeographicNetworkIntegration::new(config.local_region)
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        );

        Ok(Self {
            backend: AdaptiveDhtBackend::Network { manager },
            config,
            trust_provider: dependencies.trust_provider,
            hyperbolic_space: dependencies.hyperbolic_space,
            churn_predictor: dependencies.churn_predictor,
            geo_integration,
            identity: dependencies.identity,
        })
    }

    /// Convert adaptive PeerId to DHT key
    fn node_id_to_key(node_id: &PeerId) -> DhtKeyBytes {
        node_id.0
    }

    fn key_to_node_id(key: &DhtKeyBytes) -> PeerId {
        PeerId::from_bytes(*key)
    }

    fn xor_distance_score(a: &PeerId, b: &PeerId) -> f64 {
        let mut distance = 0u32;
        for i in 0..32 {
            distance += (a.0[i] ^ b.0[i]).count_ones();
        }
        1.0 / (1.0 + distance as f64)
    }

    fn derive_hyperbolic_coordinate(node_id: &PeerId) -> HyperbolicCoordinate {
        let hash = blake3::hash(node_id.to_bytes());
        let bytes = hash.as_bytes();
        let r_seed = u16::from_le_bytes([bytes[0], bytes[1]]) as f64 / u16::MAX as f64;
        let theta_seed = u16::from_le_bytes([bytes[2], bytes[3]]) as f64 / u16::MAX as f64;
        HyperbolicCoordinate {
            r: (r_seed * 0.999).clamp(0.0, 0.999),
            theta: (theta_seed * 2.0 * PI).clamp(0.0, 2.0 * PI),
        }
    }

    async fn hyperbolic_score(&self, node_id: &PeerId, target_id: &PeerId) -> f64 {
        let node_coord = {
            let neighbors = self.hyperbolic_space.neighbors_arc();
            let guard = neighbors.read().await;
            guard.get(node_id).cloned()
        };

        let target_coord = {
            let neighbors = self.hyperbolic_space.neighbors_arc();
            let guard = neighbors.read().await;
            guard.get(target_id).cloned()
        };

        let node_coord = match node_coord {
            Some(coord) => coord,
            None => {
                let coord = Self::derive_hyperbolic_coordinate(node_id);
                self.hyperbolic_space.update_neighbor(*node_id, coord).await;
                coord
            }
        };

        let target_coord = match target_coord {
            Some(coord) => coord,
            None => {
                let coord = Self::derive_hyperbolic_coordinate(target_id);
                self.hyperbolic_space
                    .update_neighbor(*target_id, coord)
                    .await;
                coord
            }
        };

        let distance = HyperbolicSpace::distance(&node_coord, &target_coord);
        if distance.is_finite() {
            1.0 / (1.0 + distance)
        } else {
            0.0
        }
    }

    async fn detect_region(&self, address: &Option<MultiAddr>) -> GeographicRegion {
        if let Some(addr) = address {
            self.geo_integration.detect_region(addr).await
        } else {
            GeographicRegion::Unknown
        }
    }

    async fn score_candidates(
        &self,
        key: &DhtKeyBytes,
        candidates: Vec<CandidateNode>,
    ) -> Result<Vec<ScoredCandidate>> {
        let target_id = Self::key_to_node_id(key);
        let weights = self.config.enforced_weights();

        let mut scored = Vec::with_capacity(candidates.len());

        for candidate in candidates {
            let node_id = &candidate.peer_id;
            let address = Some(candidate.address.clone());
            let region = self.detect_region(&address).await;
            let trust = self.trust_provider.get_trust(node_id).clamp(0.0, 1.0);

            let prediction = self.churn_predictor.predict(node_id).await;
            let churn_risk = (prediction.probability_1h * 0.6
                + prediction.probability_6h * 0.3
                + prediction.probability_24h * 0.1)
                .clamp(0.0, 1.0);
            let churn_score =
                (1.0 - churn_risk) * (0.5 + 0.5 * prediction.confidence.clamp(0.0, 1.0));

            let hyperbolic_score = self.hyperbolic_score(node_id, &target_id).await;

            let proximity_score = Self::xor_distance_score(node_id, &target_id);
            let geo_score = self
                .config
                .local_region
                .preference_score(&region)
                .clamp(0.0, 1.0);

            let scores = LayerScores {
                trust,
                geo: geo_score,
                churn: churn_score.clamp(0.0, 1.0),
                hyperbolic: hyperbolic_score.clamp(0.0, 1.0),
                proximity: proximity_score.clamp(0.0, 1.0),
            };

            let mut composite = scores.trust * weights.trust
                + scores.geo * weights.geo
                + scores.churn * weights.churn
                + scores.hyperbolic * weights.hyperbolic
                + scores.proximity * weights.proximity;

            if trust < self.config.min_trust_threshold {
                composite *= 0.5;
            }
            if churn_risk > self.config.max_churn_probability {
                composite *= 0.7;
            }

            scored.push(ScoredCandidate {
                peer_id: candidate.peer_id,
                address,
                region,
                scores,
                composite,
            });
        }

        Ok(scored)
    }

    fn select_diverse_candidates(
        &self,
        mut scored: Vec<ScoredCandidate>,
        count: usize,
    ) -> Vec<ScoredCandidate> {
        scored.sort_by(|a, b| {
            b.composite
                .partial_cmp(&a.composite)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut selected = Vec::with_capacity(count);
        let mut region_counts: HashMap<GeographicRegion, usize> = HashMap::new();

        for candidate in &scored {
            if selected.len() >= count {
                break;
            }
            let region_count = region_counts.get(&candidate.region).copied().unwrap_or(0);
            if region_count < self.config.max_per_region {
                selected.push(candidate.clone());
                region_counts.insert(candidate.region, region_count + 1);
            }
        }

        if selected.len() < count {
            for candidate in scored {
                if selected.len() >= count {
                    break;
                }
                if selected
                    .iter()
                    .any(|selected| selected.peer_id == candidate.peer_id)
                {
                    continue;
                }
                selected.push(candidate);
            }
        }

        selected
    }

    async fn candidate_nodes(&self, key: &DhtKeyBytes, count: usize) -> Result<Vec<CandidateNode>> {
        match &self.backend {
            AdaptiveDhtBackend::Local { dht } => {
                let dht_guard = dht.read().await;
                let nodes = dht_guard
                    .find_nodes(&DhtKey::from_bytes(*key), count)
                    .await
                    .unwrap_or_default();
                Ok(nodes
                    .into_iter()
                    .map(|node| CandidateNode {
                        peer_id: node.id,
                        address: node.address,
                    })
                    .collect())
            }
            AdaptiveDhtBackend::Network { manager } => manager
                .find_closest_nodes(key, count)
                .await
                .map(|nodes| {
                    nodes
                        .into_iter()
                        .map(|node| CandidateNode {
                            peer_id: node.peer_id,
                            address: node.address,
                        })
                        .collect()
                })
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string())),
        }
    }

    async fn select_targets(
        &self,
        key: &DhtKeyBytes,
        count: usize,
    ) -> Result<Vec<ScoredCandidate>> {
        let candidate_count = self.config.candidate_count().max(count);
        let candidates = self.candidate_nodes(key, candidate_count).await?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let scored = self.score_candidates(key, candidates).await?;
        Ok(self.select_diverse_candidates(scored, count))
    }

    /// Find nodes close to a key using trust-weighted selection
    pub async fn find_closest_nodes(
        &self,
        target: &PeerId,
        count: usize,
    ) -> Result<Vec<NodeDescriptor>> {
        let dht_key = target.0;
        let selected = self.select_targets(&dht_key, count).await?;

        let public_key = self.identity.public_key().clone();

        let nodes = selected
            .into_iter()
            .map(|candidate| {
                let node_id = candidate.peer_id;
                NodeDescriptor {
                    id: node_id,
                    public_key: public_key.clone(),
                    addresses: candidate.address.into_iter().collect(),
                    hyperbolic: Some(Self::derive_hyperbolic_coordinate(&node_id)),
                    som_position: None,
                    trust: candidate.scores.trust,
                    capabilities: NodeCapabilities {
                        compute: (candidate.scores.trust * 1000.0) as u64,
                        bandwidth: (candidate.scores.churn * 1000.0) as u64,
                    },
                }
            })
            .collect();

        Ok(nodes)
    }

    /// Update routing table with new node information
    pub async fn update_routing(&self, node: NodeDescriptor) -> Result<()> {
        if node.addresses.is_empty() {
            return Err(AdaptiveNetworkError::Other(
                "No valid addresses".to_string(),
            ));
        }

        Ok(())
    }
}

/// Implement Kademlia routing strategy for adaptive router
pub struct KademliaRoutingStrategy {
    dht: Arc<AdaptiveDHT>,
}

impl KademliaRoutingStrategy {
    pub fn new(dht: Arc<AdaptiveDHT>) -> Self {
        Self { dht }
    }
}

#[async_trait]
impl RoutingStrategy for KademliaRoutingStrategy {
    async fn find_path(&self, target: &PeerId) -> Result<Vec<PeerId>> {
        let nodes = self.dht.find_closest_nodes(target, 3).await?;
        Ok(nodes.into_iter().map(|n| n.id).collect())
    }

    fn route_score(&self, neighbor: &PeerId, target: &PeerId) -> f64 {
        AdaptiveDHT::xor_distance_score(neighbor, target)
    }

    fn update_metrics(&self, _path: &[PeerId], _success: bool) {
        // No-op: metrics removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_adaptive_dht_creation() {
        struct MockTrustProvider;
        impl TrustProvider for MockTrustProvider {
            fn get_trust(&self, _node: &PeerId) -> f64 {
                0.5
            }
            fn update_trust(&self, _from: &PeerId, _to: &PeerId, _success: bool) {}
            fn get_global_trust(&self) -> HashMap<PeerId, f64> {
                HashMap::new()
            }
            fn remove_node(&self, _node: &PeerId) {}
        }

        let identity = Arc::new(NodeIdentity::generate().unwrap());
        let trust_provider = Arc::new(MockTrustProvider);

        let _dht = AdaptiveDHT::new(identity, trust_provider).await.unwrap();
    }

    #[tokio::test]
    async fn test_node_id_to_key_conversion() {
        use rand::RngCore;

        let mut hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash);
        let node_id = PeerId::from_bytes(hash);

        let key = AdaptiveDHT::node_id_to_key(&node_id);

        assert_eq!(key.len(), 32);
    }
}
