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

//! Close group cache for persisting trusted peers across restarts.
//!
//! Stores the node's close group peers with their addresses and trust scores
//! in a single JSON file. Loaded on startup to warm the routing table with
//! trusted peers, preserving close group consistency across restarts.

use crate::PeerId;
use crate::adaptive::trust::TrustRecord;
use crate::address::MultiAddr;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

/// Filename used for the close group cache inside the configured directory.
const CACHE_FILENAME: &str = "close_group_cache.json";

/// Maximum tolerated wall-clock skew for a cache timestamp in the future.
/// Larger offsets are treated as invalid so a corrupt clock cannot make a
/// cache appear fresh indefinitely.
const MAX_FUTURE_TIMESTAMP_SKEW: Duration = Duration::from_secs(5 * 60);

/// A peer in the persisted close group cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCloseGroupPeer {
    /// Peer identity
    pub peer_id: PeerId,
    /// Known addresses for this peer
    pub addresses: Vec<MultiAddr>,
    /// Trust score at time of save
    pub trust: TrustRecord,
}

/// Persisted close group snapshot with trust scores.
///
/// Saved periodically during normal operation, after initial bootstrap,
/// and on shutdown. Loaded on startup to reconnect to the same trusted
/// close group peers, preserving close group consistency across restarts.
/// Stale snapshots are skipped as Priority-0 bootstrap material according
/// to the node's configured maximum cache age.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseGroupCache {
    /// Close group peers with their trust scores
    pub peers: Vec<CachedCloseGroupPeer>,
    /// When this snapshot was saved (seconds since UNIX epoch)
    pub saved_at_epoch_secs: u64,
}

impl CloseGroupCache {
    /// Return whether this snapshot is older than `max_age` relative to
    /// `now_epoch_secs`.
    ///
    /// `None` disables the maximum-age check, but timestamps materially in the
    /// future are always rejected. Small offsets are tolerated for clock skew.
    #[must_use]
    pub fn is_stale(&self, now_epoch_secs: u64, max_age: Option<Duration>) -> bool {
        let future_skew = self.saved_at_epoch_secs.saturating_sub(now_epoch_secs);
        if future_skew > MAX_FUTURE_TIMESTAMP_SKEW.as_secs() {
            return true;
        }

        max_age.is_some_and(|max_age| {
            now_epoch_secs.saturating_sub(self.saved_at_epoch_secs) > max_age.as_secs()
        })
    }

    /// Save the cache to `{dir}/close_group_cache.json`.
    ///
    /// Uses [`tempfile::NamedTempFile::persist`] for atomicity: the temp file
    /// has a unique name (safe under concurrent saves) and `persist` is an
    /// atomic rename on Unix and a replace-then-rename on Windows.
    pub async fn save_to_dir(&self, dir: &Path) -> anyhow::Result<()> {
        // Ensure the directory exists (first run or after cache dir deletion).
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            anyhow::anyhow!(
                "failed to create close group cache directory {}: {e}",
                dir.display()
            )
        })?;

        let path = dir.join(CACHE_FILENAME);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize close group cache: {e}"))?;

        // Spawn blocking because NamedTempFile I/O is synchronous.
        let dir_owned = dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut tmp = tempfile::NamedTempFile::new_in(&dir_owned).map_err(|e| {
                anyhow::anyhow!("failed to create temp file in {}: {e}", dir_owned.display())
            })?;
            tmp.write_all(json.as_bytes())
                .map_err(|e| anyhow::anyhow!("failed to write close group cache: {e}"))?;
            tmp.persist(&path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to persist close group cache to {}: {e}",
                    path.display()
                )
            })?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("close group cache save task panicked: {e}"))?
    }

    /// Load the cache from `{dir}/close_group_cache.json`.
    ///
    /// Returns `None` if the file doesn't exist (fresh start).
    pub async fn load_from_dir(dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = dir.join(CACHE_FILENAME);
        match tokio::fs::read_to_string(&path).await {
            Ok(json) => {
                let cache: Self = serde_json::from_str(&json)
                    .map_err(|e| anyhow::anyhow!("failed to deserialize close group cache: {e}"))?;
                Ok(Some(cache))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!(
                "failed to read close group cache from {}: {e}",
                path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::trust::TrustRecord;

    #[tokio::test]
    async fn test_save_load_roundtrip() {
        let cache = CloseGroupCache {
            peers: vec![
                CachedCloseGroupPeer {
                    peer_id: PeerId::random(),
                    addresses: vec!["/ip4/10.0.1.1/udp/9000/quic".parse().unwrap()],
                    trust: TrustRecord {
                        score: 0.8,
                        last_updated_epoch_secs: 1_234_567_890,
                    },
                },
                CachedCloseGroupPeer {
                    peer_id: PeerId::random(),
                    addresses: vec!["/ip4/10.0.2.1/udp/9000/quic".parse().unwrap()],
                    trust: TrustRecord {
                        score: 0.6,
                        last_updated_epoch_secs: 1_234_567_890,
                    },
                },
            ],
            saved_at_epoch_secs: 1_234_567_890,
        };

        let dir = tempfile::tempdir().unwrap();

        cache.save_to_dir(dir.path()).await.unwrap();
        let loaded = CloseGroupCache::load_from_dir(dir.path())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.peers.len(), 2);
        assert_eq!(loaded.peers[0].peer_id, cache.peers[0].peer_id);
        assert!((loaded.peers[0].trust.score - 0.8).abs() < f64::EPSILON);
        assert_eq!(loaded.saved_at_epoch_secs, 1_234_567_890);
    }

    #[tokio::test]
    async fn test_load_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = CloseGroupCache::load_from_dir(dir.path()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_empty_cache() {
        let populated = CloseGroupCache {
            peers: vec![CachedCloseGroupPeer {
                peer_id: PeerId::random(),
                addresses: vec!["/ip4/10.0.1.1/udp/9000/quic".parse().unwrap()],
                trust: TrustRecord {
                    score: 0.8,
                    last_updated_epoch_secs: 1,
                },
            }],
            saved_at_epoch_secs: 1,
        };
        let empty = CloseGroupCache {
            peers: vec![],
            saved_at_epoch_secs: 2,
        };

        let dir = tempfile::tempdir().unwrap();

        populated.save_to_dir(dir.path()).await.unwrap();
        empty.save_to_dir(dir.path()).await.unwrap();
        let loaded = CloseGroupCache::load_from_dir(dir.path())
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.peers.is_empty());
        assert_eq!(loaded.saved_at_epoch_secs, 2);
    }

    #[test]
    fn cache_staleness_respects_age_limit_and_rejects_future_timestamp() {
        let now = 10_000;
        let max_age = Duration::from_secs(3_600);
        let mut cache = CloseGroupCache {
            peers: vec![],
            saved_at_epoch_secs: now,
        };

        assert!(!cache.is_stale(now, Some(max_age)));
        cache.saved_at_epoch_secs = now - 3_600;
        assert!(!cache.is_stale(now, Some(max_age)));
        cache.saved_at_epoch_secs = now - 3_601;
        assert!(cache.is_stale(now, Some(max_age)));
        assert!(!cache.is_stale(now, None));

        cache.saved_at_epoch_secs = now + 60;
        assert!(!cache.is_stale(now, Some(max_age)));
        cache.saved_at_epoch_secs = now + MAX_FUTURE_TIMESTAMP_SKEW.as_secs();
        assert!(!cache.is_stale(now, Some(max_age)));
        cache.saved_at_epoch_secs = now + MAX_FUTURE_TIMESTAMP_SKEW.as_secs() + 1;
        assert!(cache.is_stale(now, Some(max_age)));
        assert!(cache.is_stale(now, None));
    }

    #[tokio::test]
    async fn stale_age_survives_save_load_roundtrip() {
        let now = 10_000;
        let cache = CloseGroupCache {
            peers: vec![],
            saved_at_epoch_secs: now - 7_200,
        };
        let dir = tempfile::tempdir().unwrap();

        cache.save_to_dir(dir.path()).await.unwrap();
        let loaded = CloseGroupCache::load_from_dir(dir.path())
            .await
            .unwrap()
            .unwrap();

        assert!(loaded.is_stale(now, Some(Duration::from_secs(3_600))));
    }
}
