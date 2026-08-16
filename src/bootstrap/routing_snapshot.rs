// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! The whole routing table, persisted across a restart.
//!
//! [`CloseGroupCache`](super::cache::CloseGroupCache) persists the `k` peers
//! nearest to self, which is the right shape for reconnecting to a close group
//! and the wrong shape for reconstructing a routing table: the peers that
//! answer "is anyone closer to this key than me?" for a *distant* key are
//! exactly the ones a close group leaves out. For a key `K` sharing `c` leading
//! bits with self, every peer in bucket `c` is strictly closer to `K` than self
//! is, so a node that kept those peers answers correctly and a node whose
//! bucket `c` is empty cannot, however many neighbours it has.
//!
//! Restored peers are **dial candidates only**. They are dialled and
//! identity-verified through the ordinary path before they can enter the
//! routing table, and the snapshot carries no trust scores, because a file on
//! disk must not grant routing-table membership or above-neutral trust.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::PeerId;
use crate::address::MultiAddr;

/// Filename for the routing snapshot.
///
/// Distinct from `close_group_cache.json`, which is still written alongside it,
/// so an older binary never reads a whole-table snapshot as a close group.
pub(crate) const ROUTING_SNAPSHOT_FILENAME: &str = "routing_snapshot.json";

/// Schema version. An unrecognised version is discarded, never coerced.
const SCHEMA_VERSION: u32 = 1;

/// Maximum age of a snapshot that is still worth dialling.
///
/// Deliberately not the close-group cache's one hour. That bound exists for
/// trust scores on `k` neighbours; this file answers which parts of the id
/// space the node knew about, which does not rot on the same timescale. A
/// maintenance window or a host move must not cost a node its table, and a
/// snapshot of departed peers already costs nothing beyond failed dials.
const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Tolerated wall-clock skew for a timestamp in the future, so a clock jump
/// cannot make a snapshot look fresh indefinitely.
const MAX_FUTURE_TIMESTAMP_SKEW: Duration = Duration::from_secs(5 * 60);

/// Largest snapshot file that will be read. A full table is ~25 KB; anything
/// past this is not a snapshot this node wrote.
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024;

/// Hard caps applied when writing and after parsing, so a corrupt or hostile
/// file cannot turn into an unbounded dial set.
const MAX_SNAPSHOT_PEERS: usize = 1024;
const MAX_ADDRESSES_PER_PEER: usize = 8;

/// A peer recorded in a snapshot: identity and addresses, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SnapshotPeer {
    /// Peer identity, re-verified on dial before it can enter the routing table.
    pub peer_id: PeerId,
    /// Addresses last known to reach this peer.
    pub addresses: Vec<MultiAddr>,
}

/// Why a snapshot on disk was not used.
///
/// A node that silently cold-starts looks identical to one that never had a
/// snapshot, so every rejection is reportable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SnapshotRejection {
    /// The schema version is not one this build understands.
    #[error("unknown schema version {found} (this build writes {expected})")]
    UnknownSchemaVersion {
        /// Version found in the file.
        found: u32,
        /// Version this build writes.
        expected: u32,
    },
    /// The snapshot was written by a different node. Bucket indices are
    /// relative to the owner, so another node's snapshot is meaningless here.
    #[error("written by a different node")]
    ForeignOwner,
    /// Older than [`MAX_AGE`], or dated implausibly far in the future.
    #[error("stale or implausibly future-dated")]
    Stale,
    /// The file exists but could not be used.
    #[error("unusable snapshot file: {0}")]
    Unreadable(String),
}

/// A persisted routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RoutingSnapshot {
    /// Schema version of this file.
    pub schema_version: u32,
    /// Node that wrote it. Bucket indices are relative to this id.
    pub owner: PeerId,
    /// When it was written (seconds since UNIX epoch).
    pub saved_at_epoch_secs: u64,
    /// Every routing-table peer at the time of writing, across all buckets.
    pub peers: Vec<SnapshotPeer>,
}

impl RoutingSnapshot {
    /// Build a snapshot of the current routing table, capped.
    pub fn new(owner: PeerId, saved_at_epoch_secs: u64, mut peers: Vec<SnapshotPeer>) -> Self {
        peers.truncate(MAX_SNAPSHOT_PEERS);
        for peer in &mut peers {
            peer.addresses.truncate(MAX_ADDRESSES_PER_PEER);
        }
        Self {
            schema_version: SCHEMA_VERSION,
            owner,
            saved_at_epoch_secs,
            peers,
        }
    }

    /// The peers this node may dial, or why the snapshot was not used.
    ///
    /// # Errors
    ///
    /// Returns the first binding that failed, so the caller can log why.
    pub fn peers_for(
        &self,
        expected_owner: &PeerId,
        now_epoch_secs: u64,
    ) -> Result<&[SnapshotPeer], SnapshotRejection> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(SnapshotRejection::UnknownSchemaVersion {
                found: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        if self.owner != *expected_owner {
            return Err(SnapshotRejection::ForeignOwner);
        }
        if self.is_stale(now_epoch_secs) {
            return Err(SnapshotRejection::Stale);
        }
        Ok(&self.peers)
    }

    /// Older than [`MAX_AGE`], or dated implausibly far in the future.
    fn is_stale(&self, now_epoch_secs: u64) -> bool {
        let future_skew = self.saved_at_epoch_secs.saturating_sub(now_epoch_secs);
        if future_skew > MAX_FUTURE_TIMESTAMP_SKEW.as_secs() {
            return true;
        }
        now_epoch_secs.saturating_sub(self.saved_at_epoch_secs) > MAX_AGE.as_secs()
    }

    /// Write the snapshot to `{dir}/routing_snapshot.json`.
    ///
    /// Written to a temporary file in the same directory and persisted by
    /// rename, so a crash mid-write leaves either the previous snapshot or
    /// none, never a half-written one.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created, or the file cannot
    /// be serialized, written, or persisted.
    pub async fn save_to_dir(&self, dir: &Path) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            anyhow::anyhow!(
                "failed to create routing snapshot directory {}: {e}",
                dir.display()
            )
        })?;

        let path = dir.join(ROUTING_SNAPSHOT_FILENAME);
        let json = serde_json::to_vec(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize routing snapshot: {e}"))?;

        let dir_owned = dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut tmp = tempfile::NamedTempFile::new_in(&dir_owned).map_err(|e| {
                anyhow::anyhow!("failed to create temp file in {}: {e}", dir_owned.display())
            })?;
            tmp.write_all(&json)
                .map_err(|e| anyhow::anyhow!("failed to write routing snapshot: {e}"))?;
            tmp.persist(&path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to persist routing snapshot to {}: {e}",
                    path.display()
                )
            })?;
            Ok(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("routing snapshot save task panicked: {e}"))?
    }

    /// Read the snapshot from `{dir}/routing_snapshot.json`.
    ///
    /// Returns `Ok(None)` when there is no snapshot. A file that exists but is
    /// oversized, not a regular file, a symlink, or unparseable is reported
    /// rather than treated as absence, because the two need different operator
    /// responses.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotRejection::Unreadable`] with the underlying reason.
    pub async fn load_from_dir(dir: &Path) -> Result<Option<Self>, SnapshotRejection> {
        let path = dir.join(ROUTING_SNAPSHOT_FILENAME);

        // Open once and check the handle, not the path: checking the path and
        // then reading it again is two different files if anything replaces it
        // in between. The read is separately capped, so the size check cannot
        // be sidestepped by a file that grows after it is opened.
        let file = match open_snapshot_file(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SnapshotRejection::Unreadable(e.to_string())),
        };
        let metadata = file
            .metadata()
            .await
            .map_err(|e| SnapshotRejection::Unreadable(e.to_string()))?;
        if !metadata.is_file() {
            return Err(SnapshotRejection::Unreadable("not a regular file".into()));
        }
        if metadata.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotRejection::Unreadable(format!(
                "{} bytes exceeds the {MAX_SNAPSHOT_BYTES} byte limit",
                metadata.len()
            )));
        }

        let mut bytes = Vec::new();
        let mut bounded = tokio::io::AsyncReadExt::take(file, MAX_SNAPSHOT_BYTES + 1);
        tokio::io::AsyncReadExt::read_to_end(&mut bounded, &mut bytes)
            .await
            .map_err(|e| SnapshotRejection::Unreadable(e.to_string()))?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotRejection::Unreadable(format!(
                "exceeds the {MAX_SNAPSHOT_BYTES} byte limit while reading"
            )));
        }
        let mut snapshot: Self = serde_json::from_slice(&bytes)
            .map_err(|e| SnapshotRejection::Unreadable(e.to_string()))?;

        // Re-apply the write-side caps: the bound has to hold for a file this
        // process did not write.
        snapshot.peers.truncate(MAX_SNAPSHOT_PEERS);
        for peer in &mut snapshot.peers {
            peer.addresses.truncate(MAX_ADDRESSES_PER_PEER);
        }
        Ok(Some(snapshot))
    }
}

/// Open the snapshot for reading without following a symlink and without
/// blocking on a special file.
///
/// A plain `open` of a FIFO placed at this fixed path blocks until a writer
/// appears, which would stall bootstrap before the regular-file check on the
/// handle could reject it. `O_NONBLOCK` makes that open return immediately and
/// is inert for regular files, and `O_NOFOLLOW` refuses a symlink outright:
/// this node only ever writes a regular file here, by rename.
#[cfg(unix)]
async fn open_snapshot_file(path: &Path) -> std::io::Result<tokio::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("snapshot open task panicked: {e}")))??;
    Ok(tokio::fs::File::from_std(file))
}

/// Non-Unix fallback: a plain open, with the non-regular-file rejection still
/// enforced on the opened handle by the caller.
#[cfg(not(unix))]
async fn open_snapshot_file(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::File::open(path).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn peer() -> SnapshotPeer {
        SnapshotPeer {
            peer_id: PeerId::random(),
            addresses: vec!["/ip4/10.0.1.1/udp/9000/quic".parse().unwrap()],
        }
    }

    fn snapshot(owner: PeerId, saved_at: u64, count: usize) -> RoutingSnapshot {
        RoutingSnapshot::new(owner, saved_at, (0..count).map(|_| peer()).collect())
    }

    #[tokio::test]
    async fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let owner = PeerId::random();
        let original = snapshot(owner, 1_000, 130);

        original.save_to_dir(dir.path()).await.unwrap();
        let loaded = RoutingSnapshot::load_from_dir(dir.path())
            .await
            .unwrap()
            .expect("snapshot present");

        assert_eq!(loaded.peers, original.peers);
        assert_eq!(loaded.peers_for(&owner, 1_000).unwrap().len(), 130);
    }

    #[tokio::test]
    async fn a_missing_snapshot_is_absence_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            RoutingSnapshot::load_from_dir(dir.path())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_truncated_file_is_reported_not_silently_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let owner = PeerId::random();
        snapshot(owner, 1_000, 4)
            .save_to_dir(dir.path())
            .await
            .unwrap();

        let path = dir.path().join(ROUTING_SNAPSHOT_FILENAME);
        let json = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &json[..json.len() / 2]).unwrap();

        assert!(matches!(
            RoutingSnapshot::load_from_dir(dir.path()).await,
            Err(SnapshotRejection::Unreadable(_))
        ));
    }

    #[tokio::test]
    async fn an_oversized_file_is_refused_without_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ROUTING_SNAPSHOT_FILENAME);
        std::fs::write(&path, vec![b'x'; (MAX_SNAPSHOT_BYTES + 1) as usize]).unwrap();

        assert!(matches!(
            RoutingSnapshot::load_from_dir(dir.path()).await,
            Err(SnapshotRejection::Unreadable(_))
        ));
    }

    #[tokio::test]
    async fn a_file_with_too_many_peers_is_capped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let owner = PeerId::random();
        // Build past the cap by hand: `new` caps on the write side.
        let oversized = RoutingSnapshot {
            schema_version: SCHEMA_VERSION,
            owner,
            saved_at_epoch_secs: 1_000,
            peers: (0..MAX_SNAPSHOT_PEERS + 50).map(|_| peer()).collect(),
        };
        let path = dir.path().join(ROUTING_SNAPSHOT_FILENAME);
        std::fs::write(&path, serde_json::to_vec(&oversized).unwrap()).unwrap();

        let loaded = RoutingSnapshot::load_from_dir(dir.path())
            .await
            .unwrap()
            .expect("snapshot present");
        assert_eq!(loaded.peers.len(), MAX_SNAPSHOT_PEERS);
    }

    /// Regression test: a plain blocking open of a FIFO at the snapshot path
    /// hangs until a writer appears, so bootstrap never reached the
    /// regular-file rejection.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_at_the_snapshot_path_is_refused_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ROUTING_SNAPSHOT_FILENAME);
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            RoutingSnapshot::load_from_dir(dir.path()),
        )
        .await
        .expect("loading must not block on a FIFO");
        assert!(matches!(result, Err(SnapshotRejection::Unreadable(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_at_the_snapshot_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let owner = PeerId::random();
        let target = dir.path().join("elsewhere.json");
        std::fs::write(
            &target,
            serde_json::to_vec(&snapshot(owner, 1_000, 4)).unwrap(),
        )
        .unwrap();
        let path = dir.path().join(ROUTING_SNAPSHOT_FILENAME);
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(matches!(
            RoutingSnapshot::load_from_dir(dir.path()).await,
            Err(SnapshotRejection::Unreadable(_))
        ));
    }

    #[test]
    fn another_nodes_snapshot_is_refused() {
        let owner = PeerId::random();
        let someone_else = PeerId::random();
        assert_eq!(
            snapshot(owner, 1_000, 4).peers_for(&someone_else, 1_000),
            Err(SnapshotRejection::ForeignOwner)
        );
    }

    #[test]
    fn an_unknown_schema_version_is_refused_rather_than_guessed_at() {
        let owner = PeerId::random();
        let mut snap = snapshot(owner, 1_000, 4);
        snap.schema_version = SCHEMA_VERSION + 1;
        assert!(matches!(
            snap.peers_for(&owner, 1_000),
            Err(SnapshotRejection::UnknownSchemaVersion { .. })
        ));
    }

    #[test]
    fn staleness_is_bounded_on_both_sides_of_now() {
        let owner = PeerId::random();
        let saved_at = 1_000_000;
        let snap = snapshot(owner, saved_at, 4);

        // Fresh, and still usable well past the close-group cache's one hour.
        assert!(snap.peers_for(&owner, saved_at).is_ok());
        assert!(snap.peers_for(&owner, saved_at + 6 * 60 * 60).is_ok());
        // Older than the maximum age.
        assert_eq!(
            snap.peers_for(&owner, saved_at + MAX_AGE.as_secs() + 1),
            Err(SnapshotRejection::Stale)
        );
        // Dated further in the future than tolerated skew.
        assert_eq!(
            snap.peers_for(&owner, saved_at - MAX_FUTURE_TIMESTAMP_SKEW.as_secs() - 1),
            Err(SnapshotRejection::Stale)
        );
    }
}
