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

//! Relay acquisition driver.
//!
//! Owns every state transition for this node's MASQUE relay: the initial
//! acquisition at startup, the backoff retry when no candidate accepts,
//! the republish-then-reacquire sequence when an existing relay is lost,
//! and the K-closest-eviction watcher that forces a rebind when the
//! chosen relayer drops out of the close group.
//!
//! ## State machine
//!
//! The driver runs as a single tokio task and cycles through three states:
//!
//! 1. **Acquiring**: call [`run_relay_acquisition`]. On success, run
//!    third-party relay canaries before publishing. Only a canary-verified
//!    relay is written to the full typed self-record (relay-allocated
//!    address tagged [`AddressType::Relay`] first, then one best non-relay
//!    address per IP family), stored as the current relayer, and held. A
//!    canary-rejected relayer is excluded from subsequent acquisition attempts
//!    until a relay verifies or non-close witness coverage drops below
//!    quorum. On failure, publish the direct-only address set so the node
//!    remains as reachable as possible, arm the exponential backoff timer,
//!    and enter the **Backoff** state.
//! 2. **Holding**: subscribe to `KClosestPeersChanged` events, republish
//!    when a pinned external address is promoted to
//!    [`AddressType::Direct`], and poll
//!    [`TransportHandle::is_relay_healthy`] every
//!    [`HEALTH_POLL_INTERVAL`]. On relayer-evicted or unhealthy-tunnel,
//!    transition to **Lost**; on shutdown, exit the driver.
//! 3. **Lost**: run the `republish-direct-only → reacquire` sequence.
//!    The republish MUST happen **before** the acquisition walk starts,
//!    so the network stops dialing the dead relay address during the
//!    1–10 s acquisition window. After republishing, loop back to
//!    **Acquiring**.
//! 4. **Backoff**: wait for the current backoff window or a
//!    `KClosestPeersChanged` event (whichever comes first), republishing
//!    if a pinned external is promoted to [`AddressType::Direct`] while
//!    waiting, then loop back to **Acquiring**. Successful acquisition
//!    resets the backoff.
//!
//! Clients ([`NodeMode::Client`](crate::network::NodeMode::Client)) do
//! not spawn the driver at all — they are outbound-only and do not need
//! a relay.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::dht::AddressType;
use crate::dht_network_manager::{DhtNetworkEvent, DhtNetworkManager};
use crate::reachability::canary::{RelayCanaryVerdict, verify_relay_with_canaries};
use crate::reachability::session::{RelayAcquisitionOutcome, run_relay_acquisition};
use crate::self_address::build_self_address_set;
use crate::transport_handle::TransportHandle;
use crate::{MultiAddr, PeerId};

/// How often to poll the transport for tunnel health while holding a relay.
///
/// 5 seconds fits inside the 10–30 s failover-window budget and keeps the
/// wake rate low (the poll is non-blocking and only reads an atomic
/// counter inside saorsa-transport).
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Initial delay before the first retry after a failed acquisition walk.
const BACKOFF_INITIAL: Duration = Duration::from_secs(30);

/// Upper bound on the backoff delay. Retries beyond this cap continue to
/// fire every [`BACKOFF_MAX`] until the routing table expands or the
/// retry succeeds.
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// Multiplicative factor applied after each failed retry.
const BACKOFF_FACTOR: u32 = 2;

/// Spawn the relay acquisition driver as a background task.
///
/// The task runs until `shutdown` is cancelled. On spawn, it performs the
/// initial acquisition attempt and then enters the state machine described
/// in the module docs.
///
/// `relayer_peer_id` and `relay_address` are shared with the owning
/// [`P2PNode`](crate::network::P2PNode); the driver writes to them to
/// reflect the current relay state.
pub(crate) fn spawn_acquisition_driver(
    dht: Arc<DhtNetworkManager>,
    transport: Arc<TransportHandle>,
    relayer_peer_id: Arc<RwLock<Option<PeerId>>>,
    relay_address: Arc<RwLock<Option<SocketAddr>>>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut driver = AcquisitionDriver {
            dht,
            transport,
            relayer_peer_id,
            relay_address,
            shutdown,
            current_backoff: BACKOFF_INITIAL,
            last_published_typed_set: None,
            canary_rejected_relayers: HashSet::new(),
        };
        driver.run().await;
    });
}

/// The driver's owned state, factored out of `spawn_acquisition_driver`
/// so the state-transition methods can share it without threading
/// individual arguments through each step.
struct AcquisitionDriver {
    dht: Arc<DhtNetworkManager>,
    transport: Arc<TransportHandle>,
    relayer_peer_id: Arc<RwLock<Option<PeerId>>>,
    relay_address: Arc<RwLock<Option<SocketAddr>>>,
    shutdown: CancellationToken,
    current_backoff: Duration,
    last_published_typed_set: Option<PublishedTypedSet>,
    canary_rejected_relayers: HashSet<PeerId>,
}

#[derive(Clone, Debug, PartialEq)]
struct PublishedTypedSet {
    typed_addresses: Vec<(MultiAddr, AddressType)>,
    peers: Vec<PeerId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanaryRejectionEvent {
    Verified,
    Rejected(PeerId),
    InsufficientWitnesses,
    AcquisitionFailed,
}

fn apply_canary_rejection_event(
    rejected_relayers: &mut HashSet<PeerId>,
    event: CanaryRejectionEvent,
) {
    match event {
        CanaryRejectionEvent::Verified | CanaryRejectionEvent::InsufficientWitnesses => {
            rejected_relayers.clear();
        }
        CanaryRejectionEvent::Rejected(relayer) => {
            rejected_relayers.insert(relayer);
        }
        CanaryRejectionEvent::AcquisitionFailed => {}
    }
}

impl AcquisitionDriver {
    async fn run(&mut self) {
        info!("relay acquisition driver starting");
        loop {
            if self.shutdown.is_cancelled() {
                debug!("relay acquisition driver: shutdown, exiting");
                return;
            }

            let outcome = run_relay_acquisition(
                self.dht.as_ref(),
                &self.transport,
                &self.canary_rejected_relayers,
            )
            .await;
            match outcome {
                RelayAcquisitionOutcome::Acquired(relay) => {
                    match verify_relay_with_canaries(
                        &self.dht,
                        relay.relayer,
                        relay.allocated_public_addr,
                    )
                    .await
                    {
                        RelayCanaryVerdict::Verified {
                            successes,
                            attempts,
                        } => {
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::Verified,
                            );
                            self.current_backoff = BACKOFF_INITIAL;
                            *self.relayer_peer_id.write().await = Some(relay.relayer);
                            *self.relay_address.write().await = Some(relay.allocated_public_addr);
                            self.transport
                                .set_relay_address(relay.allocated_public_addr);
                            self.force_publish_typed_set(Some(relay.allocated_public_addr))
                                .await;
                            info!(
                                relayer = ?relay.relayer,
                                allocated = %relay.allocated_public_addr,
                                successes,
                                attempts,
                                "driver: relay canary verified and published"
                            );
                            // Hold the relay until an eviction or tunnel-death
                            // event forces us back into the acquisition loop.
                            if self.hold_until_lost().await {
                                // shutdown
                                return;
                            }
                            // Fall through: hold_until_lost() returned false, the
                            // relay is considered lost, we need to republish
                            // direct-only BEFORE re-trying acquisition.
                            self.lose_relay_and_republish().await;
                        }
                        RelayCanaryVerdict::Rejected {
                            successes,
                            attempts,
                        } => {
                            warn!(
                                relayer = ?relay.relayer,
                                allocated = %relay.allocated_public_addr,
                                successes,
                                attempts,
                                "driver: relay failed canary quorum, entering backoff before trying next candidate"
                            );
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::Rejected(relay.relayer),
                            );
                            self.clear_unpublished_relay_state().await;
                            self.publish_typed_set(None).await;
                            if self.wait_backoff_or_event().await {
                                return; // shutdown
                            }
                            self.advance_backoff();
                        }
                        RelayCanaryVerdict::InsufficientWitnesses {
                            available,
                            required,
                        } => {
                            warn!(
                                relayer = ?relay.relayer,
                                allocated = %relay.allocated_public_addr,
                                available,
                                required,
                                "driver: insufficient relay canary witnesses, entering backoff without publishing relay"
                            );
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::InsufficientWitnesses,
                            );
                            self.clear_unpublished_relay_state().await;
                            self.publish_typed_set(None).await;
                            if self.wait_backoff_or_event().await {
                                return; // shutdown
                            }
                            self.advance_backoff();
                        }
                    }
                }
                RelayAcquisitionOutcome::Failed(reason) => {
                    apply_canary_rejection_event(
                        &mut self.canary_rejected_relayers,
                        CanaryRejectionEvent::AcquisitionFailed,
                    );
                    warn!(
                        reason,
                        rejected_relayers = self.canary_rejected_relayers.len(),
                        "driver: acquisition failed, entering backoff"
                    );
                    *self.relayer_peer_id.write().await = None;
                    *self.relay_address.write().await = None;
                    self.transport.clear_relay_address();
                    self.publish_typed_set(None).await;
                    if self.wait_backoff_or_event().await {
                        return; // shutdown
                    }
                    self.advance_backoff();
                }
            }
        }
    }

    /// Publish this node's current typed address set to K-closest peers.
    ///
    /// Each address's [`AddressType`] is computed independently from the
    /// passive per-address reachability proof (see
    /// [`TransportHandle::is_external_proven`]): an address is tagged
    /// [`AddressType::Direct`] only after at least
    /// `MIN_DISTINCT_OBSERVERS_FOR_DIRECT` source-disjoint inbounds have
    /// been attributed to it; otherwise it is tagged
    /// [`AddressType::Unverified`] (so dialers know they may time out).
    ///
    /// When `relay` is `Some`, the relay-allocated socket is emitted
    /// first, tagged [`AddressType::Relay`].
    ///
    /// Per-address (not global) tagging matters for two cases the previous
    /// global-flag approach got wrong:
    ///
    /// 1. A v4 inbound proves nothing about a v6 external; the classifier
    ///    only credits same-family externals, and the tag is computed
    ///    per address from that per-address proof.
    /// 2. On a multi-NAT host, one external being proven Direct does not
    ///    promote unrelated externals.
    ///
    /// Quietly drops the publish when there are no dialable addresses to
    /// advertise — a fully wildcard-bound node cannot meaningfully tell
    /// peers how to reach it.
    async fn publish_typed_set(&mut self, relay: Option<SocketAddr>) {
        self.publish_typed_set_with_policy(relay, false).await;
    }

    async fn force_publish_typed_set(&mut self, relay: Option<SocketAddr>) {
        self.publish_typed_set_with_policy(relay, true).await;
    }

    /// Clear core advertisement state for a relay that never passed canary.
    ///
    /// This prevents DHT publication. Core also ignores peer ADD_ADDRESS relay
    /// hints, so unverified relays cannot enter DHT gossip through the legacy
    /// transport bridge. A future saorsa-transport API still needs to defer
    /// outbound ADD_ADDRESS and tear down rejected MASQUE sessions for a fully
    /// airtight transport-layer gate. Tracked in
    /// <https://github.com/WithAutonomi/saorsa-core/issues/138>.
    async fn clear_unpublished_relay_state(&mut self) {
        *self.relayer_peer_id.write().await = None;
        *self.relay_address.write().await = None;
        self.transport.clear_relay_address();
    }

    async fn publish_typed_set_with_policy(&mut self, relay: Option<SocketAddr>, force: bool) {
        let listen = self.transport.listen_addrs().await;
        let observed = self.transport.non_relay_external_addresses();

        debug!(
            relay = ?relay,
            observed = ?observed,
            listen = ?listen,
            "driver: preparing typed self address set"
        );

        let self_addresses = build_self_address_set(observed, listen, relay, |sa| {
            self.transport.is_external_proven(sa)
        });

        if self_addresses.is_empty() {
            debug!("driver: publish skipped, no dialable self addresses");
            return;
        }

        let typed = self_addresses.into_typed_vec();

        let own_key = *self.dht.peer_id().to_bytes();
        let all_peers = self
            .dht
            .find_closest_nodes_local(&own_key, self.dht.k_value())
            .await;
        let peers = all_peers.iter().map(|node| node.peer_id).collect();
        let publish_snapshot = PublishedTypedSet {
            typed_addresses: typed.clone(),
            peers,
        };
        if !force && self.last_published_typed_set.as_ref() == Some(&publish_snapshot) {
            debug!(
                peers = all_peers.len(),
                typed_addresses = ?typed,
                relay = ?relay,
                "driver: publish skipped, typed self address set unchanged"
            );
            return;
        }

        debug!(
            peers = all_peers.len(),
            typed_addresses = ?typed,
            relay = ?relay,
            "driver: publishing typed self address set"
        );
        trace!(
            peers = all_peers.len(),
            addrs = typed.len(),
            relay = ?relay,
            "driver: publishing typed address set to all routing table peers"
        );
        self.dht
            .publish_address_set_to_peers(typed, &all_peers)
            .await;
        self.last_published_typed_set = Some(publish_snapshot);
    }

    /// Hold the acquired relay until an eviction or death event forces a
    /// rebind. Returns `true` on shutdown (caller should exit), `false`
    /// when the relay is considered lost and a republish+reacquire is
    /// needed.
    async fn hold_until_lost(&mut self) -> bool {
        let mut events = self.dht.subscribe_events();
        let mut health = tokio::time::interval(HEALTH_POLL_INTERVAL);
        health.tick().await; // drop the immediate first tick

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => {
                    return true;
                }
                // Event-driven relay-death signal: the transport layer
                // emits `RelayLost` the moment its health monitor (or the
                // MASQUE tunnel reader task, via the graceful-close
                // watcher) observes the tunnel is gone.  Acting on it
                // immediately closes the staleness window that the 5 s
                // `health.tick()` path would otherwise leave open — the
                // window during which peers continue to dial the dead
                // relay address returned by DHT lookups.
                lost = self.transport.recv_relay_lost() => {
                    match lost {
                        Some(addr) => {
                            info!(
                                relay = %addr,
                                "driver: RelayLost event received, rebinding"
                            );
                            return false;
                        }
                        None => {
                            // Channel closed — transport is shutting
                            // down. Treat as shutdown.
                            return true;
                        }
                    }
                }
                promoted = self.transport.recv_direct_address_promoted() => {
                    match promoted {
                        Some(addr) => {
                            let relay = *self.relay_address.read().await;
                            info!(
                                address = %addr,
                                relay = ?relay,
                                "driver: direct address promoted, republishing typed self address set"
                            );
                            self.publish_typed_set(relay).await;
                        }
                        None => {
                            // Channel closed — transport is shutting down.
                            return true;
                        }
                    }
                }
                updated = self.transport.recv_self_address_updated() => {
                    match updated {
                        Some(addr) => {
                            let relay = *self.relay_address.read().await;
                            debug!(
                                address = %addr,
                                relay = ?relay,
                                "driver: self address updated, refreshing typed self address set"
                            );
                            self.publish_typed_set(relay).await;
                        }
                        None => {
                            // Channel closed — transport is shutting down.
                            return true;
                        }
                    }
                }
                event = events.recv() => {
                    match event {
                        Ok(DhtNetworkEvent::KClosestPeersChanged { ref new, .. }) => {
                            if self.relayer_evicted_from_k_closest(new).await {
                                info!("driver: relayer evicted from K-closest, rebinding");
                                return false;
                            }
                        }
                        Ok(_) => continue,
                        // `RecvError::Lagged` is recoverable — the broadcast
                        // channel dropped events we did not consume fast
                        // enough, but we are still subscribed. `Closed` is
                        // terminal (the DHT manager is dropping); treat it
                        // the same as shutdown.
                        Err(RecvError::Closed) => return true,
                        Err(_) => continue,
                    }
                }
                _ = health.tick() => {
                    if !self.transport.is_relay_healthy() {
                        info!("driver: relay tunnel unhealthy, rebinding");
                        return false;
                    }
                }
            }
        }
    }

    /// Returns `true` if the currently-chosen relayer is no longer in the
    /// new K-closest set.
    async fn relayer_evicted_from_k_closest(&self, new_k_closest: &[PeerId]) -> bool {
        let guard = self.relayer_peer_id.read().await;
        let Some(relayer) = guard.as_ref() else {
            return false;
        };
        !new_k_closest.contains(relayer)
    }

    /// Transition out of the Holding state: republish direct-only and
    /// clear relayer state, BEFORE the acquisition walk retries. The
    /// pre-retry publish is critical — without it, other peers would
    /// continue dialing the dead relay address during the 1–10 s
    /// acquisition walk.
    async fn lose_relay_and_republish(&mut self) {
        *self.relayer_peer_id.write().await = None;
        *self.relay_address.write().await = None;
        self.transport.clear_relay_address();
        self.force_publish_typed_set(None).await;
    }

    /// Wait out the current backoff window, or short-circuit on a
    /// `KClosestPeersChanged` event (new peers may offer fresh candidates).
    /// Returns `true` on shutdown.
    async fn wait_backoff_or_event(&mut self) -> bool {
        let mut events = self.dht.subscribe_events();
        let sleep = tokio::time::sleep(self.current_backoff);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return true,
                _ = &mut sleep => {
                    trace!(window = ?self.current_backoff, "driver: backoff window expired");
                    return false;
                }
                promoted = self.transport.recv_direct_address_promoted() => {
                    match promoted {
                        Some(addr) => {
                            info!(
                                address = %addr,
                                "driver: direct address promoted during relay backoff, republishing typed self address set"
                            );
                            self.publish_typed_set(None).await;
                        }
                        None => {
                            // Channel closed — transport is shutting down.
                            return true;
                        }
                    }
                }
                updated = self.transport.recv_self_address_updated() => {
                    match updated {
                        Some(addr) => {
                            debug!(
                                address = %addr,
                                "driver: self address updated during relay backoff, refreshing typed self address set"
                            );
                            self.publish_typed_set(None).await;
                        }
                        None => {
                            // Channel closed — transport is shutting down.
                            return true;
                        }
                    }
                }
                event = events.recv() => {
                    match event {
                        Ok(DhtNetworkEvent::KClosestPeersChanged { .. }) => {
                            debug!("driver: K-closest changed, retrying early");
                            return false;
                        }
                        Ok(_) => continue,
                        Err(RecvError::Closed) => return true,
                        Err(_) => continue,
                    }
                }
            }
        }
    }

    /// Move the backoff window one step closer to [`BACKOFF_MAX`].
    fn advance_backoff(&mut self) {
        let next = self.current_backoff.saturating_mul(BACKOFF_FACTOR);
        self.current_backoff = next.min(BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REJECTED_RELAYER_SEED: u8 = 7;
    const SECOND_RELAYER_SEED: u8 = 8;
    const PEER_ID_BYTES: usize = 32;

    fn peer_id(seed: u8) -> PeerId {
        PeerId::from_bytes([seed; PEER_ID_BYTES])
    }

    #[test]
    fn acquisition_failure_preserves_canary_rejected_relayers() {
        let rejected_relayer = peer_id(REJECTED_RELAYER_SEED);
        let mut rejected_relayers = HashSet::from([rejected_relayer]);

        apply_canary_rejection_event(
            &mut rejected_relayers,
            CanaryRejectionEvent::AcquisitionFailed,
        );

        assert!(rejected_relayers.contains(&rejected_relayer));
    }

    #[test]
    fn verified_relay_clears_canary_rejected_relayers() {
        let mut rejected_relayers =
            HashSet::from([peer_id(REJECTED_RELAYER_SEED), peer_id(SECOND_RELAYER_SEED)]);

        apply_canary_rejection_event(&mut rejected_relayers, CanaryRejectionEvent::Verified);

        assert!(rejected_relayers.is_empty());
    }

    #[test]
    fn insufficient_witnesses_clear_canary_rejected_relayers() {
        let mut rejected_relayers =
            HashSet::from([peer_id(REJECTED_RELAYER_SEED), peer_id(SECOND_RELAYER_SEED)]);

        apply_canary_rejection_event(
            &mut rejected_relayers,
            CanaryRejectionEvent::InsufficientWitnesses,
        );

        assert!(rejected_relayers.is_empty());
    }

    #[test]
    fn canary_rejection_adds_relayer_to_exclusion_set() {
        let relayer = peer_id(REJECTED_RELAYER_SEED);
        let mut rejected_relayers = HashSet::new();

        apply_canary_rejection_event(
            &mut rejected_relayers,
            CanaryRejectionEvent::Rejected(relayer),
        );

        assert!(rejected_relayers.contains(&relayer));
    }
}
