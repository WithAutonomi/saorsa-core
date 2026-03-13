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

//! Churn handling system
//!
//! This module implements churn detection mechanisms:
//! - Node failure detection with 30-second heartbeat timeout
//! - Routing table repair and maintenance
//! - Trust score updates for unexpected departures
//! - Topology rebalancing for network health
//! - Graceful degradation under high churn

use crate::PeerId;
use crate::adaptive::{
    TrustProvider,
    gossip::{AdaptiveGossipSub, GossipMessage},
    learning::ChurnPredictor,
    routing::AdaptiveRouter,
};
use anyhow::Result;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Churn detection and recovery system
pub struct ChurnHandler {
    /// Local node ID
    node_id: PeerId,

    /// Churn predictor for proactive measures
    predictor: Arc<ChurnPredictor>,

    /// Node monitoring system
    node_monitor: Arc<NodeMonitor>,

    /// Trust provider for reputation updates
    trust_provider: Arc<dyn TrustProvider>,

    /// Routing system
    router: Arc<AdaptiveRouter>,

    /// Gossip system for announcements
    gossip: Arc<AdaptiveGossipSub>,

    /// Configuration
    config: ChurnConfig,

    /// Churn statistics
    stats: Arc<RwLock<ChurnStats>>,
}

/// Configuration for churn handling
#[derive(Debug, Clone)]
pub struct ChurnConfig {
    /// Heartbeat timeout (default: 30 seconds)
    pub heartbeat_timeout: Duration,

    /// Gossip absence timeout (default: 5 minutes)
    pub gossip_timeout: Duration,

    /// Prediction threshold for proactive measures (default: 0.7)
    pub prediction_threshold: f64,

    /// Monitoring interval (default: 30 seconds)
    pub monitoring_interval: Duration,

    /// Maximum acceptable churn rate (default: 30%)
    pub max_churn_rate: f64,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            heartbeat_timeout: Duration::from_secs(30),
            gossip_timeout: Duration::from_secs(300),
            prediction_threshold: 0.7,
            monitoring_interval: Duration::from_secs(30),
            max_churn_rate: 0.3,
        }
    }
}

/// Node monitoring system
pub struct NodeMonitor {
    /// Node status tracking
    node_status: Arc<RwLock<HashMap<PeerId, NodeStatus>>>,

    /// Heartbeat tracking
    heartbeats: Arc<RwLock<HashMap<PeerId, Instant>>>,

    /// Configuration
    config: ChurnConfig,
}

/// Status of a monitored node
#[derive(Debug, Clone)]
pub struct NodeStatus {
    /// Node identifier
    pub node_id: PeerId,

    /// Last seen timestamp
    pub last_seen: Instant,

    /// Last heartbeat received
    pub last_heartbeat: Option<Instant>,

    /// Last gossip activity
    pub last_gossip: Option<Instant>,

    /// Current status
    pub status: NodeState,

    /// Reliability score (0.0-1.0)
    pub reliability: f64,
}

/// Node state in the network
#[derive(Debug, Clone, PartialEq)]
pub enum NodeState {
    /// Node is active and healthy
    Active,

    /// Node is suspicious (missed heartbeats)
    Suspicious,

    /// Node is departing (predicted or announced)
    Departing,

    /// Node has failed
    Failed,
}

/// Churn handling statistics
#[derive(Debug, Default, Clone)]
pub struct ChurnStats {
    /// Total nodes monitored
    pub total_nodes: u64,

    /// Active nodes
    pub active_nodes: u64,

    /// Failed nodes
    pub failed_nodes: u64,

    /// Suspicious nodes
    pub suspicious_nodes: u64,

    /// Current churn rate
    pub churn_rate: f64,

    /// Successful recoveries
    pub successful_recoveries: u64,

    /// Failed recoveries
    pub failed_recoveries: u64,

    /// Average detection time
    pub avg_detection_time_ms: f64,
}

impl ChurnHandler {
    /// Create a new churn handler
    pub fn new(
        node_id: PeerId,
        predictor: Arc<ChurnPredictor>,
        trust_provider: Arc<dyn TrustProvider>,
        router: Arc<AdaptiveRouter>,
        gossip: Arc<AdaptiveGossipSub>,
        config: ChurnConfig,
    ) -> Self {
        let node_monitor = Arc::new(NodeMonitor::new(config.clone()));

        Self {
            node_id,
            predictor,
            node_monitor,
            trust_provider,
            router,
            gossip,
            config,
            stats: Arc::new(RwLock::new(ChurnStats::default())),
        }
    }

    /// Start monitoring network for churn
    pub async fn start_monitoring(&self) {
        let monitoring_interval = self.config.monitoring_interval;
        let handler = self.clone_for_task();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(monitoring_interval);

            loop {
                interval.tick().await;

                if let Err(_e) = handler.monitor_cycle().await {
                    // log::error!("Churn monitoring error: {}", e);
                }
            }
        });
    }

    /// Perform one monitoring cycle
    async fn monitor_cycle(&self) -> Result<()> {
        let nodes = self.node_monitor.get_all_nodes().await;
        let mut stats = self.stats.write().await;

        stats.total_nodes = nodes.len() as u64;
        stats.active_nodes = 0;
        stats.suspicious_nodes = 0;
        stats.failed_nodes = 0;

        for node_id in nodes {
            let node_status = self.node_monitor.get_node_status(&node_id).await;

            match node_status.status {
                NodeState::Active => {
                    stats.active_nodes += 1;

                    // Check churn prediction
                    let prediction = self.predictor.predict(&node_id).await;

                    if prediction.probability_1h > self.config.prediction_threshold {
                        self.handle_imminent_departure(&node_id).await?;
                    }
                }
                NodeState::Suspicious => {
                    stats.suspicious_nodes += 1;

                    // Check if node should be marked as failed
                    if node_status.last_seen.elapsed() > self.config.heartbeat_timeout {
                        self.handle_node_failure(&node_id).await?;
                    }
                }
                NodeState::Failed => {
                    stats.failed_nodes += 1;
                }
                _ => {}
            }
        }

        // Calculate churn rate
        if stats.total_nodes > 0 {
            stats.churn_rate = stats.failed_nodes as f64 / stats.total_nodes as f64;
        }

        // Check if network is experiencing high churn
        if stats.churn_rate > self.config.max_churn_rate {
            self.handle_high_churn().await?;
        }

        Ok(())
    }

    /// Handle imminent node departure (predicted)
    async fn handle_imminent_departure(&self, node_id: &PeerId) -> Result<()> {
        // log::info!("Handling imminent departure for node {:?}", node_id);

        // 1. Mark node as departing
        self.node_monitor
            .update_node_state(node_id, NodeState::Departing)
            .await;

        // 2. Reroute ongoing connections
        self.router.mark_node_unreliable(node_id).await;

        // 3. Notify network via gossip
        let message = GossipMessage {
            topic: "node_departing".to_string(),
            data: postcard::to_stdvec(&node_id)
                .map_err(|e| anyhow::anyhow!("Serialization error: {}", e))?,
            from: self.node_id,
            seqno: 0, // Will be set by gossip subsystem
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        self.gossip.publish("node_departing", message).await?;

        Ok(())
    }

    /// Handle confirmed node failure
    async fn handle_node_failure(&self, node_id: &PeerId) -> Result<()> {
        let start_time = Instant::now();

        // 1. Mark node as failed
        self.node_monitor
            .update_node_state(node_id, NodeState::Failed)
            .await;

        // 2. Remove from all routing structures
        self.remove_from_routing_tables(node_id).await?;

        // 3. Update trust scores
        self.penalize_unexpected_departure(node_id).await;

        // 4. Trigger topology rebalancing
        self.trigger_topology_rebalance().await?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.failed_nodes += 1;
        let detection_time = start_time.elapsed().as_millis() as f64;
        stats.avg_detection_time_ms =
            (stats.avg_detection_time_ms * (stats.failed_nodes - 1) as f64 + detection_time)
                / stats.failed_nodes as f64;

        Ok(())
    }

    /// Handle high churn conditions
    async fn handle_high_churn(&self) -> Result<()> {
        // 1. Reduce gossip fanout to conserve bandwidth
        self.gossip.reduce_fanout(0.75).await;

        // 2. Enable aggressive caching
        self.router.enable_aggressive_caching().await;

        // 3. Notify applications of degraded conditions
        let churn_rate = self.stats.read().await.churn_rate;
        let message = GossipMessage {
            topic: "high_churn_alert".to_string(),
            data: postcard::to_stdvec(&churn_rate)
                .map_err(|e| anyhow::anyhow!("Serialization error: {}", e))?,
            from: self.node_id,
            seqno: 0, // Will be set by gossip subsystem
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        self.gossip.publish("high_churn_alert", message).await?;

        Ok(())
    }

    /// Remove failed node from routing tables
    async fn remove_from_routing_tables(&self, node_id: &PeerId) -> Result<()> {
        // Remove from Kademlia routing table
        self.router.remove_node(node_id).await;

        // Remove from hyperbolic space
        self.router.remove_hyperbolic_coordinate(node_id).await;

        // Remove from SOM
        self.router.remove_from_som(node_id).await;

        // Remove from trust system
        self.trust_provider.remove_node(node_id);

        Ok(())
    }

    /// Penalize node for unexpected departure
    async fn penalize_unexpected_departure(&self, node_id: &PeerId) {
        self.trust_provider.update_trust(
            &PeerId::from_bytes([0u8; 32]), // System node
            node_id,
            false, // Negative interaction
        );
    }

    /// Trigger topology rebalancing after failures
    async fn trigger_topology_rebalance(&self) -> Result<()> {
        // Adjust hyperbolic coordinates
        self.router.rebalance_hyperbolic_space().await;

        // Update SOM grid if needed
        self.router.update_som_grid().await;

        // Recompute trust scores
        self.router.trigger_trust_recomputation().await;

        Ok(())
    }

    /// Handle heartbeat from a node
    pub async fn handle_heartbeat(&self, node_id: &PeerId) -> Result<()> {
        self.node_monitor.record_heartbeat(node_id).await;
        Ok(())
    }

    /// Handle gossip activity from a node
    pub async fn handle_gossip_activity(&self, node_id: &PeerId) -> Result<()> {
        self.node_monitor.record_gossip_activity(node_id).await;
        Ok(())
    }

    /// Get churn statistics
    pub async fn get_stats(&self) -> ChurnStats {
        self.stats.read().await.clone()
    }

    /// Clone for spawning tasks
    fn clone_for_task(&self) -> Self {
        Self {
            node_id: self.node_id,
            predictor: self.predictor.clone(),
            node_monitor: self.node_monitor.clone(),
            trust_provider: self.trust_provider.clone(),
            router: self.router.clone(),
            gossip: self.gossip.clone(),
            config: self.config.clone(),
            stats: self.stats.clone(),
        }
    }
}

impl NodeMonitor {
    /// Create a new node monitor
    pub fn new(config: ChurnConfig) -> Self {
        Self {
            node_status: Arc::new(RwLock::new(HashMap::new())),
            heartbeats: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get all monitored nodes
    pub async fn get_all_nodes(&self) -> Vec<PeerId> {
        self.node_status.read().await.keys().cloned().collect()
    }

    /// Get node status
    pub async fn get_node_status(&self, node_id: &PeerId) -> NodeStatus {
        self.node_status
            .read()
            .await
            .get(node_id)
            .cloned()
            .unwrap_or(NodeStatus {
                node_id: *node_id,
                last_seen: Instant::now(),
                last_heartbeat: None,
                last_gossip: None,
                status: NodeState::Failed,
                reliability: 0.0,
            })
    }

    /// Update node state
    pub async fn update_node_state(&self, node_id: &PeerId, state: NodeState) {
        if let Some(status) = self.node_status.write().await.get_mut(node_id) {
            status.status = state;
        }
    }

    /// Record heartbeat from node
    pub async fn record_heartbeat(&self, node_id: &PeerId) {
        let now = Instant::now();
        self.heartbeats.write().await.insert(*node_id, now);

        let mut status_map = self.node_status.write().await;
        let status = status_map.entry(*node_id).or_insert_with(|| NodeStatus {
            node_id: *node_id,
            last_seen: now,
            last_heartbeat: None,
            last_gossip: None,
            status: NodeState::Active,
            reliability: 1.0,
        });
        status.last_heartbeat = Some(now);
        status.last_seen = now;
        status.status = NodeState::Active;
    }

    /// Record gossip activity
    pub async fn record_gossip_activity(&self, node_id: &PeerId) {
        let now = Instant::now();

        if let Some(status) = self.node_status.write().await.get_mut(node_id) {
            status.last_gossip = Some(now);
            status.last_seen = now;
        }
    }

    /// Check if node is alive
    pub async fn is_alive(&self, node_id: &PeerId) -> bool {
        if let Some(last_heartbeat) = self.heartbeats.read().await.get(node_id) {
            last_heartbeat.elapsed() < self.config.heartbeat_timeout
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::trust::MockTrustProvider;
    use rand::RngCore;

    async fn create_test_churn_handler() -> ChurnHandler {
        let predictor = Arc::new(ChurnPredictor::new());
        let trust_provider = Arc::new(MockTrustProvider::new());
        let router = Arc::new(AdaptiveRouter::new(trust_provider.clone()));
        // Create a test PeerId
        use crate::peer_record::PeerId;
        let mut hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut hash);
        let node_id = PeerId::from_bytes(hash);

        let gossip = Arc::new(AdaptiveGossipSub::new(node_id, trust_provider.clone()));

        // Create default ChurnConfig
        let config = ChurnConfig {
            heartbeat_timeout: Duration::from_secs(30),
            gossip_timeout: Duration::from_secs(300),
            monitoring_interval: Duration::from_secs(5),
            prediction_threshold: 0.7,
            max_churn_rate: 0.2,
        };

        ChurnHandler::new(node_id, predictor, trust_provider, router, gossip, config)
    }

    #[tokio::test]
    async fn test_node_monitoring() {
        let handler = create_test_churn_handler().await;
        let node_id = PeerId::from_bytes([1u8; 32]);

        // Record heartbeat
        handler.node_monitor.record_heartbeat(&node_id).await;

        // Check node is alive
        assert!(handler.node_monitor.is_alive(&node_id).await);

        // Check status
        let status = handler.node_monitor.get_node_status(&node_id).await;
        assert_eq!(status.status, NodeState::Active);
        assert!(status.last_heartbeat.is_some());
    }

    #[tokio::test]
    async fn test_failure_detection() {
        let mut handler = create_test_churn_handler().await;
        // Short timeout for testing
        handler.config.heartbeat_timeout = Duration::from_millis(100);
        // Ensure NodeMonitor uses the same short timeout
        if let Some(nm) = Arc::get_mut(&mut handler.node_monitor) {
            nm.config.heartbeat_timeout = Duration::from_millis(100);
        }
        let node_id = PeerId::from_bytes([1u8; 32]);

        // Record initial heartbeat
        handler.handle_heartbeat(&node_id).await.unwrap();

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Node should no longer be alive
        assert!(!handler.node_monitor.is_alive(&node_id).await);
    }

    #[tokio::test]
    async fn test_proactive_departure_handling() {
        let handler = create_test_churn_handler().await;
        let node_id = PeerId::from_bytes([1u8; 32]);

        // Add node with high churn probability
        // Ensure node is tracked as active first
        handler.node_monitor.record_heartbeat(&node_id).await;
        handler
            .predictor
            .update_node_features(
                &node_id,
                vec![
                    0.1, // Low online duration
                    0.9, // High response time
                    0.1, // Low resource contribution
                    0.1, // Low message frequency
                    0.0, // Time of day
                    0.0, // Day of week
                    0.1, // Low historical reliability
                    0.0, 0.0, 0.0,
                ],
            )
            .await
            .unwrap();

        // Handle imminent departure
        handler.handle_imminent_departure(&node_id).await.unwrap();

        // Check node marked as departing
        let status = handler.node_monitor.get_node_status(&node_id).await;
        assert_eq!(status.status, NodeState::Departing);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_churn_rate_calculation() {
        let mut handler = create_test_churn_handler().await;
        // Avoid triggering high-churn handling which can slow tests
        handler.config.max_churn_rate = 1.0;

        // Add some nodes
        for i in 0..10 {
            let node_id = PeerId::from_bytes([i; 32]);
            handler.handle_heartbeat(&node_id).await.unwrap();
        }

        // Mark some as failed
        for i in 0..3 {
            let node_id = PeerId::from_bytes([i; 32]);
            handler
                .node_monitor
                .update_node_state(&node_id, NodeState::Failed)
                .await;
        }

        // Run monitoring cycle with a strict timeout to avoid hangs
        let res =
            tokio::time::timeout(std::time::Duration::from_secs(30), handler.monitor_cycle()).await;
        assert!(res.is_ok(), "monitor_cycle timed out");
        res.unwrap().unwrap();

        // Check stats
        let stats = handler.get_stats().await;
        assert_eq!(stats.total_nodes, 10);
        assert_eq!(stats.failed_nodes, 3);
        assert!((stats.churn_rate - 0.3).abs() < 0.01); // 30% churn rate
    }
}
