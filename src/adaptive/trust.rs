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

//! Local trust scoring based on direct peer interactions.
//!
//! Scores use an exponential moving average (EMA) that blends each new
//! observation and decays toward neutral when idle. No background task
//! needed — decay is applied lazily on each read or write.
//!
//! Future: full EigenTrust with peer-to-peer trust gossip.

use crate::PeerId;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Default trust score for unknown peers
pub const DEFAULT_NEUTRAL_TRUST: f64 = 0.5;

/// Minimum trust score a peer can reach
const MIN_TRUST_SCORE: f64 = 0.0;

/// Maximum trust score a peer can reach
const MAX_TRUST_SCORE: f64 = 1.0;

/// EMA weight for each new observation (higher = faster response to events)
const EMA_WEIGHT: f64 = 0.1;

/// Decay constant (per-second).
///
/// Tuned so that the worst possible score (0.0) takes 3 days of idle time
/// to decay back above the block threshold (0.15).
///
/// Derivation: 0.15 = 0.5 - 0.5 * e^(-λ * 259200)  →  λ = -ln(0.7) / 259200
const DECAY_LAMBDA: f64 = 1.3761e-6;

/// Per-node trust state
#[derive(Debug, Clone)]
struct PeerTrust {
    /// Current trust score (between MIN and MAX)
    score: f64,
    /// When the score was last updated (for decay calculation)
    last_updated: Instant,
}

impl PeerTrust {
    fn new() -> Self {
        Self {
            score: DEFAULT_NEUTRAL_TRUST,
            last_updated: Instant::now(),
        }
    }

    /// Apply time-based decay toward neutral, then clamp to bounds.
    ///
    /// Uses exponential decay: `score = neutral + (score - neutral) * e^(-λt)`
    /// This smoothly pulls the score back toward 0.5 over time.
    fn apply_decay(&mut self) {
        let elapsed_secs = self.last_updated.elapsed().as_secs_f64();
        self.apply_decay_secs(elapsed_secs);
    }

    /// Apply decay for an explicit number of elapsed seconds.
    ///
    /// Factored out so tests can call this directly without manipulating
    /// `Instant` (which can overflow on Windows if uptime < the duration).
    fn apply_decay_secs(&mut self, elapsed_secs: f64) {
        if elapsed_secs > 0.0 {
            let decay_factor = (-DECAY_LAMBDA * elapsed_secs).exp();
            self.score =
                DEFAULT_NEUTRAL_TRUST + (self.score - DEFAULT_NEUTRAL_TRUST) * decay_factor;
            self.score = self.score.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE);
            self.last_updated = Instant::now();
        }
    }

    /// Apply a new observation via EMA, after first applying decay.
    fn record(&mut self, observation: f64) {
        self.apply_decay();
        self.score = (1.0 - EMA_WEIGHT) * self.score + EMA_WEIGHT * observation;
        self.score = self.score.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE);
        self.last_updated = Instant::now();
    }

    /// Get the current score with decay applied (does not mutate).
    fn decayed_score(&self) -> f64 {
        Self::decay_score(self.score, self.last_updated.elapsed().as_secs_f64())
    }

    /// Pure function: compute what a score would be after `elapsed_secs` of decay.
    fn decay_score(score: f64, elapsed_secs: f64) -> f64 {
        if elapsed_secs > 0.0 {
            let decay_factor = (-DECAY_LAMBDA * elapsed_secs).exp();
            let decayed = DEFAULT_NEUTRAL_TRUST + (score - DEFAULT_NEUTRAL_TRUST) * decay_factor;
            decayed.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE)
        } else {
            score
        }
    }
}

/// Observation value for a successful interaction
const SUCCESS_OBSERVATION: f64 = 1.0;

/// Observation value for a failed interaction
const FAILURE_OBSERVATION: f64 = 0.0;

/// Statistics update type for recording peer interaction outcomes
#[derive(Debug, Clone)]
pub enum NodeStatisticsUpdate {
    /// Peer provided a correct response
    CorrectResponse,
    /// Peer failed to provide a response
    FailedResponse,
}

/// Serializable trust snapshot for persistence across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSnapshot {
    /// Peer trust scores with timestamps.
    /// The timestamp is seconds since UNIX epoch when the score was last updated.
    pub peers: HashMap<PeerId, TrustRecord>,
}

/// A single peer's trust record for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRecord {
    /// Trust score [0.0, 1.0]
    pub score: f64,
    /// When the score was last updated (seconds since UNIX epoch)
    pub last_updated_epoch_secs: u64,
}

/// Local trust engine based on direct peer observations.
///
/// Scores are an exponential moving average of success/failure observations
/// that decays toward neutral (0.5) when idle. Bounded by `MIN_TRUST_SCORE`
/// and `MAX_TRUST_SCORE`.
///
/// This is the **sole authority** on peer trust scores in the system.
#[derive(Debug)]
pub struct TrustEngine {
    /// Per-node trust state
    peers: Arc<RwLock<HashMap<PeerId, PeerTrust>>>,
}

impl TrustEngine {
    /// Create a new TrustEngine
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a peer interaction outcome
    pub async fn update_node_stats(&self, node_id: &PeerId, update: NodeStatisticsUpdate) {
        let mut peers = self.peers.write();
        let entry = peers.entry(*node_id).or_insert_with(PeerTrust::new);

        let observation = match update {
            NodeStatisticsUpdate::CorrectResponse => SUCCESS_OBSERVATION,
            NodeStatisticsUpdate::FailedResponse => FAILURE_OBSERVATION,
        };

        entry.record(observation);
    }

    /// Get current trust score for a peer (synchronous).
    ///
    /// Applies time decay lazily — no background task needed.
    /// Returns `DEFAULT_NEUTRAL_TRUST` (0.5) for unknown peers.
    ///
    /// Uses `parking_lot::RwLock` so this never falls back to a stale
    /// neutral value during write contention — it briefly blocks until
    /// the writer releases.
    pub fn score(&self, node_id: &PeerId) -> f64 {
        let peers = self.peers.read();
        peers
            .get(node_id)
            .map(|p| p.decayed_score())
            .unwrap_or(DEFAULT_NEUTRAL_TRUST)
    }

    /// Remove a peer from the trust system entirely
    pub async fn remove_node(&self, node_id: &PeerId) {
        let mut peers = self.peers.write();
        peers.remove(node_id);
    }

    /// Export current trust state as a serializable snapshot.
    ///
    /// Applies decay to all scores before exporting so the snapshot
    /// reflects the current effective scores.
    pub async fn export_snapshot(&self) -> TrustSnapshot {
        let peers_guard = self.peers.read();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let peers = peers_guard
            .iter()
            .map(|(peer_id, peer_trust)| {
                let record = TrustRecord {
                    score: peer_trust.decayed_score(),
                    last_updated_epoch_secs: now_epoch,
                };
                (*peer_id, record)
            })
            .collect();

        TrustSnapshot { peers }
    }

    /// Import trust state from a persisted snapshot.
    ///
    /// Scores are restored as-is with `last_updated` set to now.  Decay does
    /// not run while our node is offline — we can't observe peer behavior
    /// during downtime, so penalising peers for our absence would be wrong.
    /// Decay resumes naturally from the moment the node restarts.
    pub async fn import_snapshot(&self, snapshot: &TrustSnapshot) {
        let mut peers_guard = self.peers.write();

        for (peer_id, record) in &snapshot.peers {
            // Guard against NaN/Infinity from corrupted or malicious snapshots —
            // non-finite values would propagate through all EMA/decay calculations.
            let score = if record.score.is_finite() {
                record.score.clamp(MIN_TRUST_SCORE, MAX_TRUST_SCORE)
            } else {
                DEFAULT_NEUTRAL_TRUST
            };
            let peer_trust = PeerTrust {
                score,
                last_updated: Instant::now(),
            };
            peers_guard.insert(*peer_id, peer_trust);
        }
    }

    /// Simulate time passing for a peer (test only).
    ///
    /// Applies decay as if `elapsed` time had passed since the last update.
    /// Uses `apply_decay_secs` directly to avoid `Instant` subtraction,
    /// which panics on Windows when system uptime < `elapsed`.
    #[cfg(test)]
    pub async fn simulate_elapsed(&self, node_id: &PeerId, elapsed: std::time::Duration) {
        let mut peers = self.peers.write();
        if let Some(trust) = peers.get_mut(node_id) {
            trust.apply_decay_secs(elapsed.as_secs_f64());
        }
    }
}

impl Default for TrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unknown_peer_returns_neutral() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_successes_increase_score() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        for _ in 0..50 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(
            score > DEFAULT_NEUTRAL_TRUST,
            "Score {score} should be above neutral"
        );
        assert!(score <= MAX_TRUST_SCORE, "Score {score} should be <= max");
    }

    #[tokio::test]
    async fn test_failures_decrease_score() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        for _ in 0..50 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }

        let score = engine.score(&peer);
        assert!(
            score < DEFAULT_NEUTRAL_TRUST,
            "Score {score} should be below neutral"
        );
        assert!(score >= MIN_TRUST_SCORE, "Score {score} should be >= min");
    }

    #[tokio::test]
    async fn test_scores_clamped_to_bounds() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // Many successes — should not exceed MAX
        for _ in 0..1000 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        let score = engine.score(&peer);
        assert!(score >= MIN_TRUST_SCORE, "Score {score} below min");
        assert!(score <= MAX_TRUST_SCORE, "Score {score} above max");

        // Many failures — should not go below MIN
        for _ in 0..2000 {
            engine
                .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
                .await;
        }
        let score = engine.score(&peer);
        assert!(score >= MIN_TRUST_SCORE, "Score {score} below min");
        assert!(score <= MAX_TRUST_SCORE, "Score {score} above max");
    }

    #[tokio::test]
    async fn test_remove_node_resets_to_neutral() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
            .await;
        assert!(engine.score(&peer) < DEFAULT_NEUTRAL_TRUST);

        engine.remove_node(&peer).await;
        assert!((engine.score(&peer) - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_ema_blends_observations() {
        let engine = TrustEngine::new();
        let peer = PeerId::random();

        // First failure moves score below neutral
        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::FailedResponse)
            .await;
        let after_fail = engine.score(&peer);
        assert!(after_fail < DEFAULT_NEUTRAL_TRUST);

        // A success moves it back up (but not all the way to neutral)
        engine
            .update_node_stats(&peer, NodeStatisticsUpdate::CorrectResponse)
            .await;
        let after_success = engine.score(&peer);
        assert!(after_success > after_fail, "Success should increase score");
    }

    /// 3 days of idle time from worst score (0.0) should cross the block threshold (0.15).
    ///
    /// Uses the pure `decay_score` function to avoid `Instant` subtraction,
    /// which panics on Windows if system uptime < the simulated duration.
    #[test]
    fn test_worst_score_unblocks_after_3_days() {
        let three_days_secs = (3 * 24 * 3600) as f64;
        let score = PeerTrust::decay_score(MIN_TRUST_SCORE, three_days_secs);

        assert!(
            score >= 0.15,
            "After 3 days, score {score} should be >= block threshold 0.15",
        );
    }

    /// Just under 3 days should NOT be enough to unblock
    #[test]
    fn test_worst_score_still_blocked_before_3_days() {
        let just_under_3_days = (3 * 24 * 3600 - 3600) as f64; // 3 days minus 1 hour
        let score = PeerTrust::decay_score(MIN_TRUST_SCORE, just_under_3_days);

        assert!(
            score < 0.15,
            "Before 3 days, score {score} should still be < block threshold 0.15",
        );
    }

    #[test]
    fn test_decay_from_high_score_moves_down() {
        let one_week_secs = (7 * 24 * 3600) as f64;
        let score = PeerTrust::decay_score(0.95, one_week_secs);

        assert!(score < 0.95, "Score should have decayed from 0.95");
        assert!(
            score > DEFAULT_NEUTRAL_TRUST,
            "Score should still be above neutral after 1 week"
        );
    }

    #[test]
    fn test_decay_from_low_score_moves_up() {
        let one_week_secs = (7 * 24 * 3600) as f64;
        let score = PeerTrust::decay_score(0.1, one_week_secs);

        assert!(score > 0.1, "Low score should decay upward toward neutral");
    }

    #[tokio::test]
    async fn test_export_import_roundtrip() {
        let engine = TrustEngine::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        // Build up some trust
        for _ in 0..20 {
            engine
                .update_node_stats(&peer1, NodeStatisticsUpdate::CorrectResponse)
                .await;
        }
        for _ in 0..10 {
            engine
                .update_node_stats(&peer2, NodeStatisticsUpdate::FailedResponse)
                .await;
        }

        let score1_before = engine.score(&peer1);
        let score2_before = engine.score(&peer2);

        // Export
        let snapshot = engine.export_snapshot().await;
        assert_eq!(snapshot.peers.len(), 2);

        // Import into fresh engine
        let engine2 = TrustEngine::new();
        engine2.import_snapshot(&snapshot).await;

        let score1_after = engine2.score(&peer1);
        let score2_after = engine2.score(&peer2);

        // Scores should be approximately equal (small time drift from test execution)
        assert!(
            (score1_before - score1_after).abs() < 0.01,
            "peer1 score drifted: before={score1_before}, after={score1_after}"
        );
        assert!(
            (score2_before - score2_after).abs() < 0.01,
            "peer2 score drifted: before={score2_before}, after={score2_after}"
        );
    }

    #[tokio::test]
    async fn test_import_preserves_scores_without_decay() {
        // Create a snapshot with a timestamp 1 day in the past.
        // Scores should be restored as-is — no decay for offline time.
        let peer = PeerId::random();
        let one_day_secs: u64 = 86_400;
        let one_day_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - one_day_secs;

        let snapshot = TrustSnapshot {
            peers: HashMap::from([(
                peer,
                TrustRecord {
                    score: 0.9,
                    last_updated_epoch_secs: one_day_ago,
                },
            )]),
        };

        let engine = TrustEngine::new();
        engine.import_snapshot(&snapshot).await;

        let score = engine.score(&peer);
        // Score should be restored at 0.9 — offline time doesn't decay
        assert!(
            (score - 0.9).abs() < 0.01,
            "Score {score} should be ~0.9 (no offline decay)"
        );
    }

    #[tokio::test]
    async fn test_import_nan_score_falls_back_to_neutral() {
        let peer = PeerId::random();
        let snapshot = TrustSnapshot {
            peers: HashMap::from([(
                peer,
                TrustRecord {
                    score: f64::NAN,
                    last_updated_epoch_secs: 1_000_000,
                },
            )]),
        };

        let engine = TrustEngine::new();
        engine.import_snapshot(&snapshot).await;

        let score = engine.score(&peer);
        assert!(
            score.is_finite(),
            "NaN score should have been replaced with a finite value"
        );
        assert!(
            (score - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON,
            "NaN score should fall back to neutral, got {score}"
        );
    }

    #[tokio::test]
    async fn test_import_infinity_score_falls_back_to_neutral() {
        let peer = PeerId::random();
        let snapshot = TrustSnapshot {
            peers: HashMap::from([(
                peer,
                TrustRecord {
                    score: f64::INFINITY,
                    last_updated_epoch_secs: 1_000_000,
                },
            )]),
        };

        let engine = TrustEngine::new();
        engine.import_snapshot(&snapshot).await;

        let score = engine.score(&peer);
        assert!(
            score.is_finite(),
            "Infinity score should have been replaced with a finite value"
        );
        assert!(
            (score - DEFAULT_NEUTRAL_TRUST).abs() < f64::EPSILON,
            "Infinity score should fall back to neutral, got {score}"
        );
    }
}
