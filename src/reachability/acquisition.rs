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

//! Proactive MASQUE relay acquisition coordinator.
//!
//! Every non-client node calls [`RelayAcquisition::acquire`] after bootstrap
//! to establish a relay from a close-group peer. The walker is unaware of
//! whether the local node is public or private — if a candidate's Direct
//! address is unreachable (private peer), the QUIC dial fails and the walk
//! advances to the next-closest peer. "Is this candidate public?" is
//! inferred ambiently from the dial attempt.
//!
//! 1. The caller supplies a pre-filtered list of [`RelayCandidate`]s sorted
//!    by XOR distance (closest first). Filtering — selecting peers whose
//!    own DHT record contains at least one `Direct` address that is not on
//!    the local node's WAN IP — is the caller's responsibility, not the
//!    coordinator's. See
//!    [`DhtNetworkManager::first_direct_dialable_for_relay`](crate::dht_network_manager::DhtNetworkManager::first_direct_dialable_for_relay)
//!    for the canonical filter.
//! 2. [`RelayAcquisition::acquire`] tries each candidate in order. On
//!    `AtCapacity` or `Unreachable` it walks to the next candidate. On the
//!    first success it returns.
//! 3. If every candidate fails, the coordinator returns
//!    [`RelayAcquisitionError::AllCandidatesExhausted`]; the caller can
//!    then publish direct-only addresses and retry after a backoff.
//!
//! ## Separation of concerns
//!
//! The coordinator depends on a [`RelaySessionEstablisher`] trait rather than
//! a concrete transport type. This keeps the XOR-walk logic testable with a
//! mock establisher and decouples the relay-acquisition subsystem from the
//! saorsa-transport API surface. A production implementation of the trait
//! wraps saorsa-transport's `NatTraversalEndpoint::setup_proactive_relay()`.

use std::net::SocketAddr;

use async_trait::async_trait;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{MultiAddr, PeerId};

/// A single candidate the acquisition coordinator will try.
///
/// Callers build one of these per public peer they wish to attempt as a
/// relayer, passing the list (sorted by XOR distance, closest first) to
/// [`RelayAcquisition::acquire`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidate {
    /// The candidate peer's identity. Recorded on success so the monitor can
    /// watch for this peer dropping out of the K closest set.
    pub peer_id: PeerId,
    /// One of the candidate's advertised `Direct` addresses. The coordinator
    /// extracts a dialable socket from this and asks the establisher to open
    /// a MASQUE session against it.
    pub direct_address: MultiAddr,
}

impl RelayCandidate {
    /// Convenience constructor.
    pub fn new(peer_id: PeerId, direct_address: MultiAddr) -> Self {
        Self {
            peer_id,
            direct_address,
        }
    }
}

/// Successful outcome of a relay acquisition pass.
///
/// On success the node must:
///
/// 1. Remember `relayer` so the monitor can rebind if that peer drops out of
///    the K closest set.
/// 2. Publish `allocated_public_addr` (tagged `AddressType::Relay`) as its
///    contact address in the DHT self-record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredRelay {
    /// Peer ID of the node running the MASQUE relay we are now using.
    pub relayer: PeerId,
    /// The public socket address the relay allocated for inbound traffic to
    /// us. This is what the private peer publishes as its contact address.
    pub allocated_public_addr: SocketAddr,
}

/// Per-candidate establishment error returned by a [`RelaySessionEstablisher`].
///
/// Both variants are treated as "walk to the next candidate" by the
/// coordinator; they differ only in the diagnostic detail they carry.
#[derive(Debug, Clone, Error)]
pub enum RelaySessionEstablishError {
    /// The relay refused because its relay-client slots are full. See the
    /// saorsa-transport `NatTraversalError::RelayAtCapacity` variant and
    /// ADR-014's 2-client-per-public-peer cap.
    #[error("relay at client capacity: {0}")]
    AtCapacity(String),
    /// The relay could not be reached at all (timeout, refused, protocol
    /// error). Network-level failure.
    #[error("relay unreachable: {0}")]
    Unreachable(String),
}

/// Terminal outcome when every candidate in the input has been tried.
///
/// Per-candidate failures are logged but not returned; the coordinator only
/// surfaces aggregate outcomes.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RelayAcquisitionError {
    /// The caller supplied an empty candidate list. Typically indicates that
    /// the routing table does not yet contain any peers with a verified
    /// `Direct` address — the caller should retry after discovery completes.
    #[error("no candidate relays available")]
    NoCandidates,
    /// Every candidate in the supplied list was tried and each failed. The
    /// caller may refresh the candidate set (new DHT state may expose new
    /// candidates) and retry.
    #[error("all candidate relays exhausted without success")]
    AllCandidatesExhausted,
}

/// Establishes a proactive MASQUE relay session against a candidate relay.
///
/// A production implementation of this trait wraps saorsa-transport's
/// `NatTraversalEndpoint::setup_proactive_relay()`, which establishes the
/// MASQUE `CONNECT-UDP` session, rebinds the local Quinn endpoint onto the
/// tunnel, and returns the allocated public address. Test implementations
/// return canned results to exercise the coordinator's walk logic.
#[async_trait]
pub trait RelaySessionEstablisher: Send + Sync + 'static {
    /// Attempt to establish a proactive relay session with the peer reachable
    /// at `relay_addr`.
    ///
    /// - Returns `Ok(allocated_public_addr)` when the MASQUE session is
    ///   established and the local endpoint has been rebound onto the tunnel.
    ///   The returned socket address is the relay-allocated public address
    ///   the caller should publish.
    /// - Returns `Err(AtCapacity(_))` when the relay refused because its
    ///   client slots are full.
    /// - Returns `Err(Unreachable(_))` for any network-level failure.
    async fn establish(
        &self,
        relay_addr: SocketAddr,
    ) -> Result<SocketAddr, RelaySessionEstablishError>;
}

/// XOR-closest relay acquisition coordinator.
///
/// See the module-level documentation for the design rationale. Construct
/// with [`RelayAcquisition::new`], then call [`RelayAcquisition::acquire`]
/// once per classification round.
pub struct RelayAcquisition<E: RelaySessionEstablisher> {
    establisher: E,
}

impl<E: RelaySessionEstablisher> RelayAcquisition<E> {
    /// Construct a coordinator wrapping the supplied establisher.
    pub fn new(establisher: E) -> Self {
        Self { establisher }
    }

    /// Walk `candidates` in order, trying each until one accepts.
    ///
    /// Per-candidate failures (no dialable address, `AtCapacity`, `Unreachable`)
    /// are logged at `debug`/`warn` and the walk continues. The first success
    /// returns immediately with the chosen relayer's peer ID and allocated
    /// public address.
    ///
    /// Returns [`RelayAcquisitionError::NoCandidates`] if `candidates` is
    /// empty; [`RelayAcquisitionError::AllCandidatesExhausted`] if every
    /// candidate failed.
    pub async fn acquire(
        &self,
        candidates: Vec<RelayCandidate>,
    ) -> Result<AcquiredRelay, RelayAcquisitionError> {
        if candidates.is_empty() {
            debug!("relay acquisition called with empty candidate list");
            return Err(RelayAcquisitionError::NoCandidates);
        }

        let candidate_count = candidates.len();
        debug!(
            candidates = candidate_count,
            "starting proactive relay acquisition walk"
        );

        for (index, candidate) in candidates.into_iter().enumerate() {
            let Some(socket) = candidate.direct_address.dialable_socket_addr() else {
                warn!(
                    relayer = ?candidate.peer_id,
                    address = %candidate.direct_address,
                    "candidate has no dialable socket address, skipping"
                );
                continue;
            };

            match self.establisher.establish(socket).await {
                Ok(allocated) => {
                    info!(
                        relayer = ?candidate.peer_id,
                        allocated = %allocated,
                        index = index,
                        "acquired proactive relay session"
                    );
                    return Ok(AcquiredRelay {
                        relayer: candidate.peer_id,
                        allocated_public_addr: allocated,
                    });
                }
                Err(RelaySessionEstablishError::AtCapacity(reason)) => {
                    debug!(
                        relayer = ?candidate.peer_id,
                        reason = %reason,
                        index = index,
                        "candidate relay at capacity, walking to next"
                    );
                }
                Err(RelaySessionEstablishError::Unreachable(reason)) => {
                    debug!(
                        relayer = ?candidate.peer_id,
                        reason = %reason,
                        index = index,
                        "candidate relay unreachable, walking to next"
                    );
                }
            }
        }

        warn!(
            candidates = candidate_count,
            "all candidate relays exhausted without success"
        );
        Err(RelayAcquisitionError::AllCandidatesExhausted)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn peer_id(seed: u8) -> PeerId {
        PeerId::from_bytes([seed; 32])
    }

    fn dialable_addr(port: u16) -> MultiAddr {
        MultiAddr::from_ipv4(Ipv4Addr::new(192, 0, 2, 1), port)
    }

    fn candidate(seed: u8, port: u16) -> RelayCandidate {
        RelayCandidate::new(peer_id(seed), dialable_addr(port))
    }

    /// Scripted establisher: returns one outcome per call, in order. The
    /// `calls` atomic tracks the number of invocations so tests can verify
    /// the coordinator walked exactly as far as expected and no further.
    struct ScriptedEstablisher {
        outcomes: std::sync::Mutex<Vec<Result<SocketAddr, RelaySessionEstablishError>>>,
        calls: Arc<AtomicUsize>,
    }

    impl ScriptedEstablisher {
        fn new(outcomes: Vec<Result<SocketAddr, RelaySessionEstablishError>>) -> Self {
            Self {
                outcomes: std::sync::Mutex::new(outcomes),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl RelaySessionEstablisher for ScriptedEstablisher {
        async fn establish(
            &self,
            _relay_addr: SocketAddr,
        ) -> Result<SocketAddr, RelaySessionEstablishError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut guard = self.outcomes.lock().expect("mutex poisoned in test");
            if guard.is_empty() {
                panic!("scripted establisher ran out of outcomes");
            }
            guard.remove(0)
        }
    }

    fn allocated(port: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), port)
    }

    #[tokio::test]
    async fn empty_candidate_list_returns_no_candidates_error() {
        let establisher = ScriptedEstablisher::new(Vec::new());
        let coordinator = RelayAcquisition::new(establisher);
        let result = coordinator.acquire(Vec::new()).await;
        assert_eq!(result.unwrap_err(), RelayAcquisitionError::NoCandidates);
    }

    #[tokio::test]
    async fn first_candidate_success_returns_immediately() {
        let establisher = ScriptedEstablisher::new(vec![Ok(allocated(9000))]);
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let candidates = vec![candidate(1, 10000), candidate(2, 10001)];
        let result = coordinator
            .acquire(candidates)
            .await
            .expect("should succeed");
        assert_eq!(result.relayer, peer_id(1));
        assert_eq!(result.allocated_public_addr, allocated(9000));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "should stop on first success, not walk further"
        );
    }

    #[tokio::test]
    async fn at_capacity_walks_to_next_candidate() {
        let establisher = ScriptedEstablisher::new(vec![
            Err(RelaySessionEstablishError::AtCapacity("full".to_string())),
            Ok(allocated(9001)),
        ]);
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let candidates = vec![candidate(1, 10000), candidate(2, 10001)];
        let result = coordinator
            .acquire(candidates)
            .await
            .expect("should succeed");
        assert_eq!(result.relayer, peer_id(2));
        assert_eq!(result.allocated_public_addr, allocated(9001));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unreachable_walks_to_next_candidate() {
        let establisher = ScriptedEstablisher::new(vec![
            Err(RelaySessionEstablishError::Unreachable(
                "timeout".to_string(),
            )),
            Ok(allocated(9002)),
        ]);
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let candidates = vec![candidate(1, 10000), candidate(2, 10001)];
        let result = coordinator
            .acquire(candidates)
            .await
            .expect("should succeed");
        assert_eq!(result.relayer, peer_id(2));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn all_at_capacity_returns_exhausted() {
        let establisher = ScriptedEstablisher::new(vec![
            Err(RelaySessionEstablishError::AtCapacity("full".to_string())),
            Err(RelaySessionEstablishError::AtCapacity("full".to_string())),
            Err(RelaySessionEstablishError::AtCapacity("full".to_string())),
        ]);
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let candidates = vec![
            candidate(1, 10000),
            candidate(2, 10001),
            candidate(3, 10002),
        ];
        let result = coordinator.acquire(candidates).await;
        assert_eq!(
            result.unwrap_err(),
            RelayAcquisitionError::AllCandidatesExhausted
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "should have tried every candidate exactly once"
        );
    }

    #[tokio::test]
    async fn all_unreachable_returns_exhausted() {
        let establisher = ScriptedEstablisher::new(vec![
            Err(RelaySessionEstablishError::Unreachable("a".to_string())),
            Err(RelaySessionEstablishError::Unreachable("b".to_string())),
        ]);
        let coordinator = RelayAcquisition::new(establisher);
        let candidates = vec![candidate(1, 10000), candidate(2, 10001)];
        let result = coordinator.acquire(candidates).await;
        assert_eq!(
            result.unwrap_err(),
            RelayAcquisitionError::AllCandidatesExhausted
        );
    }

    #[tokio::test]
    async fn mixed_errors_then_success() {
        let establisher = ScriptedEstablisher::new(vec![
            Err(RelaySessionEstablishError::Unreachable("dead".to_string())),
            Err(RelaySessionEstablishError::AtCapacity("full".to_string())),
            Ok(allocated(9003)),
        ]);
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let candidates = vec![
            candidate(1, 10000),
            candidate(2, 10001),
            candidate(3, 10002),
        ];
        let result = coordinator
            .acquire(candidates)
            .await
            .expect("should succeed");
        assert_eq!(result.relayer, peer_id(3));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn candidate_with_non_dialable_address_is_skipped() {
        // TCP is not dialable per the current MultiAddr::dialable_socket_addr()
        // policy (QUIC only). The first candidate has a TCP address and should
        // be skipped without invoking the establisher.
        let tcp_addr = MultiAddr::tcp(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            80,
        ));
        let skipped = RelayCandidate::new(peer_id(1), tcp_addr);
        let ok = candidate(2, 10001);
        let establisher = ScriptedEstablisher::new(vec![Ok(allocated(9004))]);
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let result = coordinator
            .acquire(vec![skipped, ok])
            .await
            .expect("should succeed");
        assert_eq!(result.relayer, peer_id(2));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "TCP candidate must be skipped without invoking the establisher"
        );
    }

    #[tokio::test]
    async fn all_candidates_non_dialable_returns_exhausted() {
        let tcp_addr = MultiAddr::tcp(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            80,
        ));
        let c1 = RelayCandidate::new(peer_id(1), tcp_addr.clone());
        let c2 = RelayCandidate::new(peer_id(2), tcp_addr);
        let establisher = ScriptedEstablisher::new(Vec::new());
        let calls = establisher.calls.clone();
        let coordinator = RelayAcquisition::new(establisher);
        let result = coordinator.acquire(vec![c1, c2]).await;
        assert_eq!(
            result.unwrap_err(),
            RelayAcquisitionError::AllCandidatesExhausted
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "establisher must not be called when no candidate has a dialable address"
        );
    }
}
