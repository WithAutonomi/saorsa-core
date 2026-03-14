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

use super::som::NodeFeatures;
use super::*;
use crate::P2PNode;
use crate::PeerId;
use crate::address::MultiAddr;
use crate::dht::geographic_network_integration::GeographicNetworkIntegration;
use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::{DHT, DHTConfig, DhtKey, Key as DhtKeyBytes};
use crate::dht_network_manager::{
    DhtNetworkConfig, DhtNetworkManager, DhtNetworkOperation, DhtNetworkResult,
};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
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
    pub som: f64,
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
            som: self.som.max(Self::MIN_WEIGHT),
            proximity: self.proximity.max(Self::MIN_WEIGHT),
        };
        let total = weights.trust
            + weights.geo
            + weights.churn
            + weights.hyperbolic
            + weights.som
            + weights.proximity;
        if total > 0.0 {
            weights.trust /= total;
            weights.geo /= total;
            weights.churn /= total;
            weights.hyperbolic /= total;
            weights.som /= total;
            weights.proximity /= total;
        }
        weights
    }
}

impl Default for AdaptiveDhtWeights {
    fn default() -> Self {
        Self {
            trust: 0.2,
            geo: 0.15,
            churn: 0.15,
            hyperbolic: 0.2,
            som: 0.15,
            proximity: 0.15,
        }
    }
}

/// Adaptive DHT configuration used for layer-aware selection.
#[derive(Debug, Clone)]
pub struct AdaptiveDhtConfig {
    pub local_region: GeographicRegion,
    pub replication_factor: usize,
    pub candidate_multiplier: usize,
    pub max_per_region: usize,
    pub min_trust_threshold: f64,
    pub max_churn_probability: f64,
    pub weights: AdaptiveDhtWeights,
}

impl AdaptiveDhtConfig {
    fn effective_replication_factor(&self, dht_config: &DHTConfig) -> usize {
        if self.replication_factor > 0 {
            self.replication_factor
        } else {
            dht_config.replication_factor
        }
    }

    fn candidate_count(&self, dht_config: &DHTConfig) -> usize {
        let base = self.effective_replication_factor(dht_config).max(1);
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
            replication_factor: DHTConfig::default().replication_factor,
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
    pub router: Arc<AdaptiveRouter>,
    pub hyperbolic_space: Arc<HyperbolicSpace>,
    pub som: Arc<SelfOrganizingMap>,
    pub churn_predictor: Arc<ChurnPredictor>,
}

impl AdaptiveDhtDependencies {
    pub fn new(
        identity: Arc<NodeIdentity>,
        trust_provider: Arc<dyn TrustProvider>,
        router: Arc<AdaptiveRouter>,
        hyperbolic_space: Arc<HyperbolicSpace>,
        som: Arc<SelfOrganizingMap>,
        churn_predictor: Arc<ChurnPredictor>,
    ) -> Self {
        Self {
            identity,
            trust_provider,
            router,
            hyperbolic_space,
            som,
            churn_predictor,
        }
    }

    pub fn with_defaults(
        identity: Arc<NodeIdentity>,
        trust_provider: Arc<dyn TrustProvider>,
        router: Arc<AdaptiveRouter>,
    ) -> Self {
        let hyperbolic_space = Arc::new(HyperbolicSpace::new());
        let som = Arc::new(SelfOrganizingMap::new(super::som::SomConfig {
            initial_learning_rate: 0.3,
            initial_radius: 5.0,
            iterations: 1000,
            grid_size: super::som::GridSize::Fixed(10, 10),
        }));
        let churn_predictor = Arc::new(ChurnPredictor::new());
        Self {
            identity,
            trust_provider,
            router,
            hyperbolic_space,
            som,
            churn_predictor,
        }
    }
}

enum AdaptiveDhtBackend {
    Local { dht: Arc<RwLock<DHT>> },
    Network { manager: Arc<DhtNetworkManager> },
}

/// Adaptive DHT that integrates S/Kademlia with trust scoring
pub struct AdaptiveDHT {
    backend: AdaptiveDhtBackend,
    dht_config: DHTConfig,
    config: AdaptiveDhtConfig,
    trust_provider: Arc<dyn TrustProvider>,
    /// Router for adaptive path selection. Used by pub(crate) DHT methods
    /// reserved for future internal use (put, get, etc.).
    router: Arc<AdaptiveRouter>,
    hyperbolic_space: Arc<HyperbolicSpace>,
    som: Arc<SelfOrganizingMap>,
    churn_predictor: Arc<ChurnPredictor>,
    geo_integration: Arc<GeographicNetworkIntegration>,
    identity: Arc<NodeIdentity>,
    metrics: Arc<RwLock<DHTMetrics>>,
}

/// DHT performance metrics
#[derive(Debug, Default, Clone)]
pub struct DHTMetrics {
    pub lookups_total: u64,
    pub lookups_successful: u64,
    pub stores_total: u64,
    pub stores_successful: u64,
    pub average_lookup_hops: f64,
    pub trust_rejections: u64,
}

#[derive(Debug, Clone)]
struct LayerScores {
    trust: f64,
    geo: f64,
    churn: f64,
    hyperbolic: f64,
    som: f64,
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
    reliability: f64,
}

impl AdaptiveDHT {
    /// Create new adaptive DHT instance (local-only backend)
    pub async fn new(
        dht_config: DHTConfig,
        identity: Arc<NodeIdentity>,
        trust_provider: Arc<dyn TrustProvider>,
        router: Arc<AdaptiveRouter>,
    ) -> Result<Self> {
        let dependencies = AdaptiveDhtDependencies::with_defaults(identity, trust_provider, router);
        Self::new_with_dependencies(dht_config, AdaptiveDhtConfig::default(), dependencies).await
    }

    /// Create new adaptive DHT instance with explicit dependencies (local backend).
    pub async fn new_with_dependencies(
        dht_config: DHTConfig,
        config: AdaptiveDhtConfig,
        dependencies: AdaptiveDhtDependencies,
    ) -> Result<Self> {
        let local_key = Self::node_id_to_key(&dependencies.identity.peer_id().clone());
        let node_id = PeerId::from_bytes(local_key);
        let base_dht = Arc::new(RwLock::new(
            DHT::new(node_id).map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        ));
        let geo_integration = Arc::new(
            GeographicNetworkIntegration::new(config.local_region)
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        );

        Ok(Self {
            backend: AdaptiveDhtBackend::Local { dht: base_dht },
            dht_config,
            config,
            trust_provider: dependencies.trust_provider,
            router: dependencies.router,
            hyperbolic_space: dependencies.hyperbolic_space,
            som: dependencies.som,
            churn_predictor: dependencies.churn_predictor,
            geo_integration,
            identity: dependencies.identity,
            metrics: Arc::new(RwLock::new(DHTMetrics::default())),
        })
    }

    /// Attach AdaptiveDHT to an existing P2P node using a network backend.
    pub async fn attach_to_node(
        node: Arc<P2PNode>,
        network_config: DhtNetworkConfig,
        config: AdaptiveDhtConfig,
        dependencies: AdaptiveDhtDependencies,
    ) -> Result<Self> {
        let dht_config = network_config.dht_config.clone();
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
            dht_config,
            config,
            trust_provider: dependencies.trust_provider,
            router: dependencies.router,
            hyperbolic_space: dependencies.hyperbolic_space,
            som: dependencies.som,
            churn_predictor: dependencies.churn_predictor,
            geo_integration,
            identity: dependencies.identity,
            metrics: Arc::new(RwLock::new(DHTMetrics::default())),
        })
    }

    /// Create an AdaptiveDHT that reuses an existing node's DHT network manager.
    ///
    /// Unlike `attach_to_node`, this does not create a second `DhtNetworkManager`.
    /// The node's existing manager is shared, so all DHT operations benefit from
    /// the adaptive scoring layer without duplicating network state.
    pub fn with_existing_manager(
        manager: Arc<DhtNetworkManager>,
        dht_config: DHTConfig,
        config: AdaptiveDhtConfig,
        dependencies: AdaptiveDhtDependencies,
    ) -> Result<Self> {
        let geo_integration = Arc::new(
            GeographicNetworkIntegration::new(config.local_region)
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))?,
        );

        Ok(Self {
            backend: AdaptiveDhtBackend::Network { manager },
            dht_config,
            config,
            trust_provider: dependencies.trust_provider,
            router: dependencies.router,
            hyperbolic_space: dependencies.hyperbolic_space,
            som: dependencies.som,
            churn_predictor: dependencies.churn_predictor,
            geo_integration,
            identity: dependencies.identity,
            metrics: Arc::new(RwLock::new(DHTMetrics::default())),
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

    fn content_vector_from_hash(hash: &[u8; 32]) -> Vec<f64> {
        let mut vector = Vec::with_capacity(128);
        for i in 0..128 {
            let value = hash[i % 32] as f64 / 255.0;
            vector.push(value);
        }
        vector
    }

    fn content_features_from_key(key: &DhtKeyBytes) -> NodeFeatures {
        NodeFeatures {
            content_vector: Self::content_vector_from_hash(key),
            compute_capability: 500.0,
            network_latency: 50.0,
            storage_available: 500.0,
        }
    }

    fn node_features_from_candidate(
        node_id: &PeerId,
        reliability: f64,
        region: GeographicRegion,
    ) -> NodeFeatures {
        let mut vector = Self::content_vector_from_hash(node_id.to_bytes());
        for (idx, value) in vector.iter_mut().enumerate() {
            let modifier = ((idx as f64 * 0.01) + reliability).sin().abs();
            *value = (*value * 0.7 + modifier * 0.3).clamp(0.0, 1.0);
        }
        let (min_latency, max_latency) = region.expected_latency_range();
        let avg_latency = (min_latency + max_latency) / 2;
        let avg_latency_ms = avg_latency.as_millis() as f64;
        NodeFeatures {
            content_vector: vector,
            compute_capability: (reliability * 1000.0).clamp(0.0, 1000.0),
            network_latency: avg_latency_ms.max(10.0),
            storage_available: (200.0 + reliability * 800.0).clamp(50.0, 1000.0),
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
        let target_features = Self::content_features_from_key(key);
        let target_bmu = self.som.find_best_matching_unit(&target_features);
        let (grid_w, grid_h) = self.som.get_grid_dimensions();
        let max_grid_distance = if grid_w > 1 || grid_h > 1 {
            let dx = (grid_w.saturating_sub(1)) as f64;
            let dy = (grid_h.saturating_sub(1)) as f64;
            (dx * dx + dy * dy).sqrt()
        } else {
            1.0
        };

        let mut scored = Vec::with_capacity(candidates.len());
        let mut trust_rejections = 0u64;

        for candidate in candidates {
            let node_id = &candidate.peer_id;
            let address = Some(candidate.address.clone());
            let region = self.detect_region(&address).await;
            let trust = self.trust_provider.get_trust(node_id).clamp(0.0, 1.0);
            if trust < self.config.min_trust_threshold {
                trust_rejections += 1;
            }

            let prediction = self.churn_predictor.predict(node_id).await;
            let churn_risk = (prediction.probability_1h * 0.6
                + prediction.probability_6h * 0.3
                + prediction.probability_24h * 0.1)
                .clamp(0.0, 1.0);
            let churn_score =
                (1.0 - churn_risk) * (0.5 + 0.5 * prediction.confidence.clamp(0.0, 1.0));

            let hyperbolic_score = self.hyperbolic_score(node_id, &target_id).await;

            let node_features =
                Self::node_features_from_candidate(node_id, candidate.reliability, region);
            let node_bmu = self.som.find_best_matching_unit(&node_features);
            let som_distance = {
                let dx = node_bmu.0 as f64 - target_bmu.0 as f64;
                let dy = node_bmu.1 as f64 - target_bmu.1 as f64;
                (dx * dx + dy * dy).sqrt()
            };
            let som_score = (1.0 - (som_distance / max_grid_distance).min(1.0)).clamp(0.0, 1.0);

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
                som: som_score,
                proximity: proximity_score.clamp(0.0, 1.0),
            };

            let mut composite = scores.trust * weights.trust
                + scores.geo * weights.geo
                + scores.churn * weights.churn
                + scores.hyperbolic * weights.hyperbolic
                + scores.som * weights.som
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

        if trust_rejections > 0 {
            let mut metrics = self.metrics.write().await;
            metrics.trust_rejections = metrics.trust_rejections.saturating_add(trust_rejections);
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
                        reliability: node.capacity.reliability_score,
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
                            reliability: node.reliability,
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
        let candidate_count = self.config.candidate_count(&self.dht_config).max(count);
        let candidates = self.candidate_nodes(key, candidate_count).await?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let scored = self.score_candidates(key, candidates).await?;
        Ok(self.select_diverse_candidates(scored, count))
    }

    /// Store value in the DHT with adaptive replication.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub(crate) async fn put(&self, key: DhtKeyBytes, value: Vec<u8>) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        metrics.stores_total += 1;
        drop(metrics);

        let target_id = Self::key_to_node_id(&key);
        let _ = self.router.route(&target_id, ContentType::DHTLookup).await;

        let replication_factor = self.config.effective_replication_factor(&self.dht_config);
        let selected = self.select_targets(&key, replication_factor).await?;

        let result = match &self.backend {
            AdaptiveDhtBackend::Local { dht } => dht
                .write()
                .await
                .store(&DhtKey::from_bytes(key), value)
                .await
                .map(|_| DhtNetworkResult::PutSuccess {
                    key,
                    replicated_to: 1,
                    peer_outcomes: Vec::new(),
                })
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string())),
            AdaptiveDhtBackend::Network { manager } => {
                if selected.is_empty() {
                    manager
                        .put(key, value)
                        .await
                        .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))
                } else {
                    let targets: Vec<crate::PeerId> = selected.iter().map(|c| c.peer_id).collect();
                    manager
                        .put_with_targets(key, value, &targets)
                        .await
                        .map_err(|e| AdaptiveNetworkError::Other(e.to_string()))
                }
            }
        };

        let mut metrics = self.metrics.write().await;
        match result {
            Ok(_) => {
                metrics.stores_successful += 1;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Retrieve value from the DHT using adaptive routing.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub(crate) async fn get(&self, key: DhtKeyBytes) -> Result<Option<Vec<u8>>> {
        let mut metrics = self.metrics.write().await;
        metrics.lookups_total += 1;
        drop(metrics);

        let target_id = Self::key_to_node_id(&key);
        let _ = self
            .router
            .route(&target_id, ContentType::DataRetrieval)
            .await;

        let replication_factor = self.config.effective_replication_factor(&self.dht_config);

        let mut attempted_hops = 0usize;

        let result = match &self.backend {
            AdaptiveDhtBackend::Local { dht } => dht
                .read()
                .await
                .retrieve(&DhtKey::from_bytes(key))
                .await
                .map_err(|e| AdaptiveNetworkError::Other(e.to_string())),
            AdaptiveDhtBackend::Network { manager } => {
                if let Ok(Some(value)) = manager.get_local(&key).await {
                    return Ok(Some(value));
                }

                let selected = self.select_targets(&key, replication_factor).await?;
                if selected.is_empty() {
                    return Ok(None);
                }

                let mut futures = FuturesUnordered::new();
                for candidate in selected {
                    let op = DhtNetworkOperation::Get { key };
                    let manager = Arc::clone(manager);
                    let peer_id = candidate.peer_id;
                    attempted_hops += 1;
                    futures.push(async move {
                        let result = manager.send_request(&peer_id, op).await;
                        (peer_id, result)
                    });
                }

                while let Some((_peer_id, result)) = futures.next().await {
                    match result {
                        Ok(DhtNetworkResult::GetSuccess { value, .. })
                        | Ok(DhtNetworkResult::ValueFound { value, .. }) => {
                            let _ = manager.store_local(key, value.clone()).await;
                            return Ok(Some(value));
                        }
                        Ok(DhtNetworkResult::GetNotFound { .. }) => continue,
                        Ok(_) => continue,
                        Err(_) => continue,
                    }
                }

                Ok(None)
            }
        };

        let mut metrics = self.metrics.write().await;
        let total = metrics.lookups_total as f64;
        if total > 0.0 {
            let hops = attempted_hops as f64;
            metrics.average_lookup_hops =
                (metrics.average_lookup_hops * (total - 1.0) + hops) / total;
        }
        if matches!(&result, Ok(Some(_))) {
            metrics.lookups_successful += 1;
        }

        result
    }

    /// Store value in the DHT using content-addressed key derivation.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub(crate) async fn store(&self, key: Vec<u8>, value: Vec<u8>) -> Result<ContentHash> {
        let dht_key = if key.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&key[..32]);
            bytes
        } else {
            *blake3::hash(&key).as_bytes()
        };

        self.put(dht_key, value.clone()).await?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&dht_key);
        hasher.update(&value);
        let hash = hasher.finalize();

        Ok(ContentHash(*hash.as_bytes()))
    }

    /// Retrieve value from DHT using a content hash key.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub(crate) async fn retrieve(&self, hash: &ContentHash) -> Result<Vec<u8>> {
        match self.get(hash.0).await? {
            Some(value) => Ok(value),
            None => Err(AdaptiveNetworkError::Other("Record not found".to_string())),
        }
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
                    som_position: Some([
                        candidate.scores.som,
                        candidate.scores.trust,
                        candidate.scores.geo,
                        candidate.scores.churn,
                    ]),
                    trust: candidate.scores.trust,
                    capabilities: NodeCapabilities {
                        storage: (candidate.scores.geo * 1000.0) as u64,
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

    /// Get current DHT metrics
    pub async fn get_metrics(&self) -> DHTMetrics {
        self.metrics.read().await.clone()
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
        // Metrics updated in AdaptiveDHT
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

        let config = DHTConfig::default();
        let identity = Arc::new(NodeIdentity::generate().unwrap());
        let trust_provider = Arc::new(MockTrustProvider);
        let router = Arc::new(AdaptiveRouter::new_with_id(
            *identity.peer_id(),
            trust_provider.clone(),
        ));

        let dht = AdaptiveDHT::new(config, identity, trust_provider, router)
            .await
            .unwrap();
        let metrics = dht.get_metrics().await;

        assert_eq!(metrics.lookups_total, 0);
        assert_eq!(metrics.stores_total, 0);
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
