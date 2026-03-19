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

//! AdaptiveDHT — the trust boundary for all DHT operations.
//!
//! `AdaptiveDHT` is the **sole component** that creates and owns the [`TrustEngine`].
//! All DHT operations flow through it, and all trust signals originate from it.
//!
//! Internal DHT operations (iterative lookups) record trust via the `TrustEngine`
//! reference passed to `DhtNetworkManager`. External callers report additional
//! trust signals through [`AdaptiveDHT::report_trust_event`].

use crate::PeerId;
use crate::adaptive::trust::{NodeStatisticsUpdate, TrustEngine};
use crate::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};

use crate::error::P2pResult as Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Default trust score threshold below which a peer is evicted and blocked
const DEFAULT_BLOCK_THRESHOLD: f64 = 0.15;

/// Configuration for the AdaptiveDHT layer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptiveDhtConfig {
    /// Trust score below which a peer is evicted from the routing table
    /// and blocked from sending DHT messages or being re-added to the RT.
    /// Eviction is immediate when a peer's score crosses this threshold.
    /// Default: 0.15
    pub block_threshold: f64,
}

impl Default for AdaptiveDhtConfig {
    fn default() -> Self {
        Self {
            block_threshold: DEFAULT_BLOCK_THRESHOLD,
        }
    }
}

impl AdaptiveDhtConfig {
    /// Validate that all config values are within acceptable ranges.
    ///
    /// Returns `Err` if `block_threshold` is outside `[0.0, 1.0]` or is NaN.
    pub fn validate(&self) -> crate::error::P2pResult<()> {
        if !(0.0..=1.0).contains(&self.block_threshold) || self.block_threshold.is_nan() {
            return Err(crate::error::P2PError::Validation(
                format!(
                    "block_threshold must be in [0.0, 1.0], got {}",
                    self.block_threshold
                )
                .into(),
            ));
        }
        Ok(())
    }
}

/// Trust-relevant events observable by the saorsa-core network layer.
///
/// Each variant maps to an internal [`NodeStatisticsUpdate`] with appropriate severity.
/// Only events that saorsa-core can directly observe are included here.
/// Application-level events (data verification, storage checks) belong in
/// the consuming application and should be added when that layer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustEvent {
    // === Positive signals ===
    /// Peer provided a correct response to a request
    SuccessfulResponse,
    /// Peer connection was established and authenticated
    SuccessfulConnection,

    // === Negative signals ===
    /// Could not establish a connection to the peer
    ConnectionFailed,
    /// Connection attempt timed out
    ConnectionTimeout,
}

impl TrustEvent {
    /// Convert a TrustEvent to the internal NodeStatisticsUpdate
    fn to_stats_update(self) -> NodeStatisticsUpdate {
        match self {
            TrustEvent::SuccessfulResponse | TrustEvent::SuccessfulConnection => {
                NodeStatisticsUpdate::CorrectResponse
            }
            TrustEvent::ConnectionFailed | TrustEvent::ConnectionTimeout => {
                NodeStatisticsUpdate::FailedResponse
            }
        }
    }
}

/// AdaptiveDHT — the trust boundary for all DHT operations.
///
/// Owns the `TrustEngine` and `DhtNetworkManager`. All DHT operations
/// should go through this component. Application-level trust signals
/// are reported via [`report_trust_event`](Self::report_trust_event).
pub struct AdaptiveDHT {
    /// The underlying DHT network manager (handles raw DHT operations)
    dht_manager: Arc<DhtNetworkManager>,

    /// The trust engine — sole authority on peer trust scores
    trust_engine: Arc<TrustEngine>,

    /// Configuration for trust-weighted behavior
    config: AdaptiveDhtConfig,
}

impl AdaptiveDHT {
    /// Create a new AdaptiveDHT instance.
    ///
    /// This creates the `TrustEngine` and the `DhtNetworkManager` with the
    /// trust engine injected. Call [`start`](Self::start) to begin DHT
    /// operations. Trust scores are computed live — peers are evicted
    /// immediately when their score crosses the block threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if `block_threshold` is not in `[0.0, 1.0]` or if
    /// the underlying `DhtNetworkManager` fails to initialise.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        mut dht_config: DhtNetworkConfig,
        adaptive_config: AdaptiveDhtConfig,
    ) -> Result<Self> {
        adaptive_config.validate()?;

        dht_config.block_threshold = adaptive_config.block_threshold;

        let trust_engine = Arc::new(TrustEngine::new());

        let dht_manager = Arc::new(
            DhtNetworkManager::new(transport, Some(trust_engine.clone()), dht_config).await?,
        );

        Ok(Self {
            dht_manager,
            trust_engine,
            config: adaptive_config,
        })
    }

    // =========================================================================
    // Trust API — the only place where external callers record trust events
    // =========================================================================

    /// Report a trust event for a peer.
    ///
    /// Records a network-observable outcome (connection success/failure)
    /// that the DHT layer did not record automatically. See [`TrustEvent`]
    /// for the supported variants.
    pub async fn report_trust_event(&self, peer_id: &PeerId, event: TrustEvent) {
        self.trust_engine
            .update_node_stats(peer_id, event.to_stats_update())
            .await;
    }

    /// Get the current trust score for a peer (synchronous).
    ///
    /// Returns `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers.
    pub fn peer_trust(&self, peer_id: &PeerId) -> f64 {
        self.trust_engine.score(peer_id)
    }

    /// Get a reference to the underlying trust engine for advanced use cases.
    pub fn trust_engine(&self) -> &Arc<TrustEngine> {
        &self.trust_engine
    }

    /// Get the adaptive DHT configuration.
    pub fn config(&self) -> &AdaptiveDhtConfig {
        &self.config
    }

    // =========================================================================
    // DHT operations — delegates to DhtNetworkManager
    // =========================================================================

    /// Get the underlying DHT network manager.
    ///
    /// All DHT operations are accessible through this reference.
    /// The DHT manager records trust internally for per-peer outcomes
    /// during iterative lookups.
    pub fn dht_manager(&self) -> &Arc<DhtNetworkManager> {
        &self.dht_manager
    }

    /// Start the DHT manager.
    ///
    /// Trust scores are computed live — no background tasks needed.
    /// Peers are evicted from the routing table immediately when their
    /// trust drops below the block threshold.
    pub async fn start(&self) -> Result<()> {
        Arc::clone(&self.dht_manager).start().await
    }

    /// Stop the DHT manager gracefully.
    pub async fn stop(&self) -> Result<()> {
        self.dht_manager.stop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::trust::DEFAULT_NEUTRAL_TRUST;

    #[test]
    fn test_trust_event_mapping() {
        // Positive events map to CorrectResponse
        assert!(matches!(
            TrustEvent::SuccessfulResponse.to_stats_update(),
            NodeStatisticsUpdate::CorrectResponse
        ));
        assert!(matches!(
            TrustEvent::SuccessfulConnection.to_stats_update(),
            NodeStatisticsUpdate::CorrectResponse
        ));

        // Failure events map to FailedResponse
        assert!(matches!(
            TrustEvent::ConnectionFailed.to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
        assert!(matches!(
            TrustEvent::ConnectionTimeout.to_stats_update(),
            NodeStatisticsUpdate::FailedResponse
        ));
    }

    #[test]
    fn test_adaptive_dht_config_defaults() {
        let config = AdaptiveDhtConfig::default();
        assert!((config.block_threshold - DEFAULT_BLOCK_THRESHOLD).abs() < f64::EPSILON);
    }

    #[test]
    fn test_block_threshold_validation_rejects_invalid() {
        for &bad in &[-0.1, 1.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let config = AdaptiveDhtConfig {
                block_threshold: bad,
            };
            assert!(
                config.validate().is_err(),
                "block_threshold {bad} should fail validation"
            );
        }
    }

    #[test]
    fn test_block_threshold_validation_accepts_valid() {
        for &good in &[0.0, 0.15, 0.5, 1.0] {
            let config = AdaptiveDhtConfig {
                block_threshold: good,
            };
            assert!(
                config.validate().is_ok(),
                "block_threshold {good} should pass validation"
            );
        }
    }

    // =========================================================================
    // Integration tests: full trust signal flow
    // =========================================================================

    /// Test: trust events flow through to TrustEngine and change scores immediately
    #[tokio::test]
    async fn test_trust_events_affect_scores() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        // Unknown peer starts at neutral trust
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);

        // Record successes — score should rise above neutral
        for _ in 0..10 {
            engine
                .update_node_stats(&peer, TrustEvent::SuccessfulResponse.to_stats_update())
                .await;
        }

        assert!(engine.score(&peer) > DEFAULT_NEUTRAL_TRUST);
    }

    /// Test: failures reduce trust below block threshold
    #[tokio::test]
    async fn test_failures_reduce_trust_below_block_threshold() {
        let engine = Arc::new(TrustEngine::new());
        let bad_peer = PeerId::random();

        // Record only failures — score should be 0.0 immediately
        for _ in 0..20 {
            engine
                .update_node_stats(&bad_peer, TrustEvent::ConnectionFailed.to_stats_update())
                .await;
        }

        let trust = engine.score(&bad_peer);
        assert!(
            trust < DEFAULT_BLOCK_THRESHOLD,
            "Bad peer trust {trust} should be below block threshold {DEFAULT_BLOCK_THRESHOLD}"
        );
    }

    /// Test: TrustEngine scores are bounded 0.0-1.0
    #[tokio::test]
    async fn test_trust_scores_bounded() {
        let engine = Arc::new(TrustEngine::new());
        let peer = PeerId::random();

        for _ in 0..100 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(score >= 0.0, "Score must be >= 0.0, got {score}");
        assert!(score <= 1.0, "Score must be <= 1.0, got {score}");
    }

    /// Test: all TrustEvent variants produce valid stats updates
    #[test]
    fn test_all_trust_events_produce_valid_updates() {
        let events = [
            TrustEvent::SuccessfulResponse,
            TrustEvent::SuccessfulConnection,
            TrustEvent::ConnectionFailed,
            TrustEvent::ConnectionTimeout,
        ];

        for event in events {
            // Should not panic
            let _update = event.to_stats_update();
        }
    }

    // =========================================================================
    // End-to-end: peer lifecycle from trusted to blocked to unblocked
    // =========================================================================

    /// Full lifecycle: good peer → fails → blocked → time passes → unblocked
    #[tokio::test]
    async fn test_peer_lifecycle_block_and_recovery() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Phase 1: Peer starts at neutral
        assert!(
            engine.score(&peer) >= DEFAULT_BLOCK_THRESHOLD,
            "New peer should not be blocked"
        );

        // Phase 2: Some successes — peer is trusted
        for _ in 0..20 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        let good_score = engine.score(&peer);
        assert!(
            good_score > DEFAULT_NEUTRAL_TRUST,
            "Trusted peer: {good_score}"
        );

        // Phase 3: Peer starts failing — score drops
        for _ in 0..200 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }
        let bad_score = engine.score(&peer);
        assert!(
            bad_score < DEFAULT_BLOCK_THRESHOLD,
            "After many failures, peer should be blocked: {bad_score}"
        );

        // Phase 4: Time passes (3+ days) — score decays back toward neutral
        let three_days = std::time::Duration::from_secs(3 * 24 * 3600);
        engine.simulate_elapsed(&peer, three_days).await;
        let recovered_score = engine.score(&peer);
        assert!(
            recovered_score >= DEFAULT_BLOCK_THRESHOLD,
            "After 3 days idle, peer should be unblocked: {recovered_score}"
        );
    }

    /// Verify the block threshold works as a binary gate
    #[tokio::test]
    async fn test_block_threshold_is_binary() {
        let engine = TrustEngine::new();
        let threshold = DEFAULT_BLOCK_THRESHOLD;

        let peer_above = PeerId::random();
        let peer_below = PeerId::random();

        // Peer with some successes — above threshold
        for _ in 0..5 {
            engine
                .update_node_stats(&peer_above, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        assert!(
            engine.score(&peer_above) >= threshold,
            "Peer with successes should be above threshold"
        );

        // Peer with only failures — below threshold
        for _ in 0..50 {
            engine
                .update_node_stats(&peer_below, NodeStatisticsUpdate::FailedResponse)
                .await;
        }
        assert!(
            engine.score(&peer_below) < threshold,
            "Peer with only failures should be below threshold"
        );

        // Unknown peer — at neutral, which is above threshold
        let unknown = PeerId::random();
        assert!(
            engine.score(&unknown) >= threshold,
            "Unknown peer at neutral should not be blocked"
        );
    }

    /// Verify that a single failure doesn't immediately block a peer
    #[tokio::test]
    async fn test_single_failure_does_not_block() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
            .await;

        // A single failure from neutral (0.5) should give ~0.45, still above 0.15
        assert!(
            engine.score(&peer) >= DEFAULT_BLOCK_THRESHOLD,
            "One failure from neutral should not block: {}",
            engine.score(&peer)
        );
    }

    /// Verify that a previously-trusted peer needs many failures to get blocked
    #[tokio::test]
    async fn test_trusted_peer_resilient_to_occasional_failures() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Build up trust
        for _ in 0..50 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        let trusted_score = engine.score(&peer);

        // A few failures shouldn't block
        for _ in 0..3 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }

        assert!(
            engine.score(&peer) >= DEFAULT_BLOCK_THRESHOLD,
            "3 failures after 50 successes should not block: {}",
            engine.score(&peer)
        );
        assert!(
            engine.score(&peer) < trusted_score,
            "Score should have decreased"
        );
    }

    /// Verify removing a peer resets their state completely
    #[tokio::test]
    async fn test_removed_peer_starts_fresh() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Block the peer
        for _ in 0..100 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }
        assert!(engine.score(&peer) < DEFAULT_BLOCK_THRESHOLD);

        // Remove and check — should be back to neutral
        engine.remove_node(&peer).await;
        assert!(
            (engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON,
            "Removed peer should return to neutral"
        );
    }
}
