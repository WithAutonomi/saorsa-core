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

//! Routing snapshot: the whole routing table, persisted across a restart.
//!
//! # Why the close-group cache is not enough
//!
//! [`CloseGroupCache`](super::cache::CloseGroupCache) persists the `k` peers
//! nearest to self. That is the right shape for reconnecting to a close group,
//! and the wrong shape for reconstructing a routing table, because it drops
//! every peer that is not a neighbour — which is precisely the population a
//! node consults to answer "is anyone closer to this key than me?".
//!
//! The consequence is combinatorial, not statistical. For a key `K`, write
//! `c = CPL(self, K)` for the number of leading bits they share. Any peer `p`
//! with `CPL(p, self) == c` agrees with self on bits `[0, c)` and differs at
//! bit `c`; `K` agrees with self on `[0, c)` and also differs at bit `c`;
//! therefore `p` agrees with `K` at bit `c`, giving `CPL(p, K) >= c + 1`.
//! **Every peer in bucket `c` is strictly closer to `K` than self is.**
//!
//! So a node holding `w` peers in bucket `c` can always answer "no, I am not
//! among the `w` closest to `K`" — and a node whose bucket `c` is empty cannot,
//! however many neighbours it has. A snapshot must therefore preserve peers
//! across *every* bucket, not the nearest `k` overall. Preserving up to the
//! bucket capacity is what makes the restored table answer as the original did,
//! for every key, at every width.
//!
//! # What a snapshot is, and is not
//!
//! Restored peers are **dial candidates**. They are not inserted into the
//! routing table, are not trusted, and confer no authority until they have been
//! dialled and identity-verified through the ordinary path — routing-table
//! membership is an authorization fact for callers above this crate, and a file
//! on disk must never be able to grant it.
//!
//! For the same reason a snapshot records **no trust scores**. The close-group
//! cache does carry them, and imports them into the `TrustEngine` before its
//! peers are dialled, which is defensible for a set of `k` neighbours a node has
//! already vetted. It is not defensible for a whole-table file: pre-dial trust
//! restoration would let a file on disk decide that hundreds of unverified peers
//! start above neutral. A snapshot answers "where were my peers", never "how
//! much did I trust them" — trust is re-earned from live behaviour.
//!
//! # Bindings
//!
//! A snapshot is accepted only when every binding holds:
//!
//! - **Schema version.** An unknown version is discarded rather than guessed at.
//! - **Owner.** Bucket indices are relative to the owning node's id, so another
//!   node's snapshot is not merely stale, it is *meaningless* — it describes a
//!   different partition of the id space. This is the binding that matters most.
//! - **Network fingerprint.** Derived from the configured bootstrap set, so a
//!   snapshot does not follow a node between networks. Bootstrap lists do change
//!   legitimately; the cost of a mismatch is one cold start, which is exactly
//!   today's behaviour, so failing closed here is cheap.
//! - **Integrity.** A checksum over the payload, so a truncated or bit-flipped
//!   file is rejected instead of partially believed.
//! - **Age.** Reuses the close-group cache's rules, including rejecting
//!   timestamps far in the future so a broken clock cannot make a snapshot look
//!   fresh forever.
//!
//! None of these is a defence against an attacker who can write to the node's
//! data directory: such an attacker owns the node. They defend against the
//! accidents that actually happen — copied directories, cloned images, rolled
//! back filesystems, half-written files, and a snapshot outliving the network it
//! was taken on.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::PeerId;
use crate::address::MultiAddr;

/// A peer recorded in a routing snapshot.
///
/// Identity and addresses only. See the module docs for why no trust score is
/// carried: this file must not be able to promote unverified peers above
/// neutral before they have been dialled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPeer {
    /// Peer identity, re-verified on dial before it can enter the routing table.
    pub peer_id: PeerId,
    /// Addresses last known to reach this peer.
    pub addresses: Vec<MultiAddr>,
}

/// Filename for the routing snapshot.
///
/// Deliberately distinct from `close_group_cache.json`: an older binary must
/// never read this file and mistake a whole-table snapshot for a close group.
/// The two are written side by side so a downgrade keeps working.
pub const ROUTING_SNAPSHOT_FILENAME: &str = "routing_snapshot.json";

/// Schema version for [`RoutingSnapshot`].
///
/// Bump on any change to the payload's meaning. An unrecognised version is
/// discarded, never coerced.
pub const ROUTING_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Maximum tolerated wall-clock skew for a snapshot timestamp in the future.
const MAX_FUTURE_TIMESTAMP_SKEW: Duration = Duration::from_secs(5 * 60);

/// Why a snapshot on disk was not used.
///
/// Every variant is a reason an operator may need to see: a node that silently
/// cold-starts every time looks identical to one with no snapshot at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRejection {
    /// The schema version is not one this build understands.
    UnknownSchemaVersion {
        /// Version found in the file.
        found: u32,
        /// Version this build writes.
        expected: u32,
    },
    /// The snapshot was written by a different node.
    ForeignOwner,
    /// The snapshot was taken on a different network.
    ForeignNetwork,
    /// The checksum does not match the payload.
    CorruptChecksum,
    /// The snapshot is older than the configured maximum age, or its timestamp
    /// is implausibly far in the future.
    Stale,
    /// The file could not be parsed at all.
    Unreadable,
}

impl std::fmt::Display for SnapshotRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion { found, expected } => {
                write!(
                    f,
                    "unknown schema version {found} (this build writes {expected})"
                )
            }
            Self::ForeignOwner => write!(f, "written by a different node"),
            Self::ForeignNetwork => write!(f, "taken on a different network"),
            Self::CorruptChecksum => write!(f, "checksum mismatch"),
            Self::Stale => write!(f, "stale or implausibly future-dated"),
            Self::Unreadable => write!(f, "unparseable"),
        }
    }
}

/// The checksummed body of a snapshot.
///
/// Split from the envelope so the checksum covers exactly the bytes whose
/// integrity is being asserted, and so adding an envelope field later cannot
/// silently change what was signed for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSnapshotPayload {
    /// Schema version of this payload.
    pub schema_version: u32,
    /// Node that wrote the snapshot. Bucket indices are relative to this id.
    pub owner: PeerId,
    /// Fingerprint of the network the snapshot was taken on.
    pub network_fingerprint: String,
    /// When the snapshot was written (seconds since UNIX epoch).
    pub saved_at_epoch_secs: u64,
    /// Every routing-table peer at the time of writing, across all buckets.
    pub peers: Vec<SnapshotPeer>,
}

/// A persisted routing table, with the bindings needed to use it safely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSnapshot {
    /// The checksummed body.
    pub payload: RoutingSnapshotPayload,
    /// Hex-encoded BLAKE3 of the canonical payload encoding.
    pub checksum: String,
}

/// Derive a network fingerprint from the configured bootstrap addresses.
///
/// Order-independent, so reordering the configured list is not a change of
/// network. An empty list yields a well-known fingerprint so that a node with no
/// configured bootstrap peers still round-trips its own snapshot.
#[must_use]
pub fn network_fingerprint(bootstrap_peers: &[MultiAddr]) -> String {
    let mut rendered: Vec<String> = bootstrap_peers.iter().map(ToString::to_string).collect();
    rendered.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"saorsa-routing-snapshot-network-v1");
    for entry in &rendered {
        hasher.update(entry.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize().as_bytes())
}

impl RoutingSnapshotPayload {
    /// Canonical checksum over this payload.
    ///
    /// Computed from the serialized form so it covers every field without a
    /// hand-maintained list that could drift as fields are added.
    fn checksum(&self) -> anyhow::Result<String> {
        let encoded = serde_json::to_vec(self)
            .map_err(|e| anyhow::anyhow!("failed to encode routing snapshot payload: {e}"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"saorsa-routing-snapshot-payload-v1");
        hasher.update(&encoded);
        Ok(hex::encode(hasher.finalize().as_bytes()))
    }
}

impl RoutingSnapshot {
    /// Build a snapshot from the current routing table.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cannot be encoded for checksumming.
    pub fn new(
        owner: PeerId,
        network_fingerprint: String,
        saved_at_epoch_secs: u64,
        peers: Vec<SnapshotPeer>,
    ) -> anyhow::Result<Self> {
        let payload = RoutingSnapshotPayload {
            schema_version: ROUTING_SNAPSHOT_SCHEMA_VERSION,
            owner,
            network_fingerprint,
            saved_at_epoch_secs,
            peers,
        };
        let checksum = payload.checksum()?;
        Ok(Self { payload, checksum })
    }

    /// Number of peers carried.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.payload.peers.len()
    }

    /// Check every binding, returning the peers only if all of them hold.
    ///
    /// Checked cheapest-first, and integrity before meaning: there is no point
    /// interpreting fields from a file that failed its checksum.
    ///
    /// # Errors
    ///
    /// Returns the first binding that failed, so the caller can log why a
    /// snapshot was discarded rather than reporting a bare absence.
    pub fn validate(
        &self,
        expected_owner: &PeerId,
        expected_network: &str,
        now_epoch_secs: u64,
        max_age: Option<Duration>,
    ) -> Result<&[SnapshotPeer], SnapshotRejection> {
        if self.payload.schema_version != ROUTING_SNAPSHOT_SCHEMA_VERSION {
            return Err(SnapshotRejection::UnknownSchemaVersion {
                found: self.payload.schema_version,
                expected: ROUTING_SNAPSHOT_SCHEMA_VERSION,
            });
        }
        let Ok(expected_checksum) = self.payload.checksum() else {
            return Err(SnapshotRejection::CorruptChecksum);
        };
        if expected_checksum != self.checksum {
            return Err(SnapshotRejection::CorruptChecksum);
        }
        if self.payload.owner != *expected_owner {
            return Err(SnapshotRejection::ForeignOwner);
        }
        if self.payload.network_fingerprint != expected_network {
            return Err(SnapshotRejection::ForeignNetwork);
        }
        if self.is_stale(now_epoch_secs, max_age) {
            return Err(SnapshotRejection::Stale);
        }
        Ok(&self.payload.peers)
    }

    /// Whether the snapshot is older than `max_age`, or dated implausibly far
    /// in the future.
    ///
    /// `None` disables the maximum-age check; a future timestamp beyond the
    /// tolerated skew is always rejected, so a broken clock cannot make a
    /// snapshot look fresh indefinitely.
    #[must_use]
    pub fn is_stale(&self, now_epoch_secs: u64, max_age: Option<Duration>) -> bool {
        let future_skew = self
            .payload
            .saved_at_epoch_secs
            .saturating_sub(now_epoch_secs);
        if future_skew > MAX_FUTURE_TIMESTAMP_SKEW.as_secs() {
            return true;
        }
        max_age.is_some_and(|max_age| {
            now_epoch_secs.saturating_sub(self.payload.saved_at_epoch_secs) > max_age.as_secs()
        })
    }

    /// Write the snapshot to `{dir}/routing_snapshot.json`.
    ///
    /// Atomic: written to a uniquely-named temporary file in the same directory
    /// and persisted by rename, so a crash mid-write leaves either the previous
    /// snapshot or none — never a half-written one. The checksum makes a
    /// half-written file detectable even if the platform's rename is not atomic.
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
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("failed to serialize routing snapshot: {e}"))?;

        let dir_owned = dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let mut tmp = tempfile::NamedTempFile::new_in(&dir_owned).map_err(|e| {
                anyhow::anyhow!("failed to create temp file in {}: {e}", dir_owned.display())
            })?;
            tmp.write_all(json.as_bytes())
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
    /// Returns `Ok(None)` when there is no snapshot, and
    /// `Err(SnapshotRejection::Unreadable)` when there is one that cannot be
    /// parsed — a corrupt file is a fact worth logging, not an absence.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotRejection::Unreadable`] for an unreadable or
    /// unparseable file.
    pub async fn load_from_dir(dir: &Path) -> Result<Option<Self>, SnapshotRejection> {
        let path = dir.join(ROUTING_SNAPSHOT_FILENAME);
        match tokio::fs::read_to_string(&path).await {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(snapshot) => Ok(Some(snapshot)),
                Err(_) => Err(SnapshotRejection::Unreadable),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SnapshotRejection::Unreadable),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn peer() -> SnapshotPeer {
        SnapshotPeer {
            peer_id: PeerId::random(),
            addresses: vec!["/ip4/10.0.1.1/udp/9000/quic".parse().unwrap()],
        }
    }

    fn snapshot(owner: PeerId, network: &str, saved_at: u64, count: usize) -> RoutingSnapshot {
        let peers = (0..count).map(|_| peer()).collect();
        RoutingSnapshot::new(owner, network.to_string(), saved_at, peers).unwrap()
    }

    #[tokio::test]
    async fn round_trips_through_disk() {
        let owner = PeerId::random();
        let snap = snapshot(owner, "net-a", NOW, 40);
        let dir = tempfile::tempdir().unwrap();

        snap.save_to_dir(dir.path()).await.unwrap();
        let loaded = RoutingSnapshot::load_from_dir(dir.path())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.peer_count(), 40);
        let peers = loaded.validate(&owner, "net-a", NOW, None).unwrap();
        assert_eq!(peers.len(), 40);
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
        // Truncation must be distinguishable from "no snapshot": a node that
        // cold-starts every time because its file is corrupt looks exactly like
        // one that never had a snapshot.
        let dir = tempfile::tempdir().unwrap();
        let snap = snapshot(PeerId::random(), "net-a", NOW, 8);
        snap.save_to_dir(dir.path()).await.unwrap();

        let path = dir.path().join(ROUTING_SNAPSHOT_FILENAME);
        let json = tokio::fs::read_to_string(&path).await.unwrap();
        let truncated = &json[..json.len() / 2];
        tokio::fs::write(&path, truncated).await.unwrap();

        assert_eq!(
            RoutingSnapshot::load_from_dir(dir.path())
                .await
                .unwrap_err(),
            SnapshotRejection::Unreadable
        );
    }

    #[test]
    fn a_bit_flip_that_keeps_the_json_valid_fails_the_checksum() {
        // The case a parser cannot catch: still-valid JSON, wrong contents.
        let owner = PeerId::random();
        let mut snap = snapshot(owner, "net-a", NOW, 4);
        snap.payload.saved_at_epoch_secs = NOW - 1;

        assert_eq!(
            snap.validate(&owner, "net-a", NOW, None).unwrap_err(),
            SnapshotRejection::CorruptChecksum
        );
    }

    #[test]
    fn another_nodes_snapshot_is_refused() {
        // Bucket indices are relative to the owner, so a foreign snapshot is
        // not stale data — it describes a different partition of the id space.
        let snap = snapshot(PeerId::random(), "net-a", NOW, 4);
        assert_eq!(
            snap.validate(&PeerId::random(), "net-a", NOW, None)
                .unwrap_err(),
            SnapshotRejection::ForeignOwner
        );
    }

    #[test]
    fn a_snapshot_from_another_network_is_refused() {
        let owner = PeerId::random();
        let snap = snapshot(owner, "net-a", NOW, 4);
        assert_eq!(
            snap.validate(&owner, "net-b", NOW, None).unwrap_err(),
            SnapshotRejection::ForeignNetwork
        );
    }

    #[test]
    fn an_unknown_schema_version_is_refused_rather_than_guessed_at() {
        let owner = PeerId::random();
        let mut snap = snapshot(owner, "net-a", NOW, 4);
        snap.payload.schema_version = ROUTING_SNAPSHOT_SCHEMA_VERSION + 1;
        snap.checksum = snap.payload.checksum().unwrap();

        assert_eq!(
            snap.validate(&owner, "net-a", NOW, None).unwrap_err(),
            SnapshotRejection::UnknownSchemaVersion {
                found: ROUTING_SNAPSHOT_SCHEMA_VERSION + 1,
                expected: ROUTING_SNAPSHOT_SCHEMA_VERSION,
            }
        );
    }

    #[test]
    fn staleness_is_bounded_on_both_sides_of_now() {
        let owner = PeerId::random();

        let old = snapshot(owner, "net-a", NOW - 7200, 4);
        assert_eq!(
            old.validate(&owner, "net-a", NOW, Some(Duration::from_secs(3600)))
                .unwrap_err(),
            SnapshotRejection::Stale
        );
        assert!(old.validate(&owner, "net-a", NOW, None).is_ok());

        // A clock that jumped forward must not mint an evergreen snapshot.
        let future = snapshot(owner, "net-a", NOW + 86_400, 4);
        assert_eq!(
            future.validate(&owner, "net-a", NOW, None).unwrap_err(),
            SnapshotRejection::Stale
        );

        // Small skew is tolerated.
        let skewed = snapshot(owner, "net-a", NOW + 60, 4);
        assert!(skewed.validate(&owner, "net-a", NOW, None).is_ok());
    }

    #[test]
    fn the_network_fingerprint_ignores_ordering_but_not_membership() {
        let a: MultiAddr = "/ip4/10.0.1.1/udp/9000/quic".parse().unwrap();
        let b: MultiAddr = "/ip4/10.0.2.1/udp/9000/quic".parse().unwrap();
        let c: MultiAddr = "/ip4/10.0.3.1/udp/9000/quic".parse().unwrap();

        assert_eq!(
            network_fingerprint(&[a.clone(), b.clone()]),
            network_fingerprint(&[b.clone(), a.clone()]),
            "reordering the configured list is not a change of network"
        );
        assert_ne!(
            network_fingerprint(&[a.clone(), b.clone()]),
            network_fingerprint(&[a, b, c]),
            "a different bootstrap set is a different network"
        );
        assert_eq!(
            network_fingerprint(&[]),
            network_fingerprint(&[]),
            "no configured peers still round-trips"
        );
    }

    #[tokio::test]
    async fn a_copied_snapshot_does_not_transplant_between_nodes() {
        // The accident this actually guards: a data directory copied to a new
        // host, or a cloned VM image, where the identity differs.
        let dir = tempfile::tempdir().unwrap();
        snapshot(PeerId::random(), "net-a", NOW, 30)
            .save_to_dir(dir.path())
            .await
            .unwrap();

        let loaded = RoutingSnapshot::load_from_dir(dir.path())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded
                .validate(&PeerId::random(), "net-a", NOW, None)
                .unwrap_err(),
            SnapshotRejection::ForeignOwner
        );
    }
}
