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

//! Relay acquisition driver.
//!
//! Owns every state transition for this node's MASQUE relay: the initial
//! acquisition at startup, the backoff retry when no candidate accepts,
//! the republish-then-reacquire sequence when an existing relay is lost,
//! and the health checks that retain a verified relay until there is positive
//! evidence that it is no longer usable.
//!
//! ## State machine
//!
//! The driver runs as a single tokio task and cycles through five states:
//!
//! 1. **Starting**: publish a newer relay-free address set before the first
//!    acquisition walk. This withdraws any relay allocation left in DHT
//!    replicas by a previous process incarnation before peers can dial it.
//! 2. **Acquiring**: call [`run_relay_acquisition`]. On success, run
//!    third-party relay canaries before publishing. Only a canary-verified
//!    relay is written to the full typed self-record (relay-allocated
//!    address tagged [`AddressType::Relay`] first, then one best non-relay
//!    address per IP family), stored as the current relayer, and held. A
//!    canary-rejected relayer is excluded from subsequent acquisition attempts
//!    until a relay verifies or non-close witness coverage drops below
//!    quorum. On failure, publish the direct-only address set so the node
//!    remains as reachable as possible, arm the exponential backoff timer,
//!    and enter the **Backoff** state.
//! 3. **Holding**: republish when a pinned external address is promoted to
//!    [`AddressType::Direct`], and poll
//!    [`TransportHandle::is_relay_healthy`] every
//!    [`HEALTH_POLL_INTERVAL`]. The driver also repeats the independent
//!    third-party canary quorum every [`RELAY_REVALIDATION_INTERVAL`]. The
//!    maintenance cadence is deliberately much slower than local health
//!    polling: admission already proved external reachability, while each
//!    maintenance round creates six network operations (three witness requests
//!    and three fresh relay dials). K-closest churn does not invalidate an
//!    already verified relay. On an unhealthy tunnel or failed revalidation,
//!    transition to **Lost**; on shutdown, exit.
//! 4. **Lost**: run the `republish-direct-only → reacquire` sequence.
//!    The republish MUST happen **before** the acquisition walk starts,
//!    so the network stops dialing the dead relay address during the
//!    1–10 s acquisition window. After republishing, loop back to
//!    **Acquiring**.
//! 5. **Backoff**: wait for the current backoff window or a
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
use crate::reachability::canary::{
    RelayCanaryPolicy, RelayCanaryVerdict, verify_relay_with_canaries,
};
use crate::reachability::session::{RelayAcquisitionOutcome, run_relay_acquisition};
use crate::self_address::build_self_address_set;
use crate::transport_handle::TransportHandle;
use crate::{MultiAddr, PeerId};
use saorsa_transport::nat_traversal_api::PreparedRelay;

/// How often to poll the transport for tunnel health while holding a relay.
///
/// 5 seconds fits inside the 10–30 s failover-window budget and keeps the
/// wake rate low.
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How often an established relay must again pass a third-party canary quorum.
///
/// Local task health only proves that this process still has a tunnel. A
/// relay-server forwarding regression or expired public allocation can leave
/// that tunnel locally alive but externally unreachable, so retain a periodic
/// external check. Two hours avoids turning a large fleet into a continuous
/// source of witness dials and one-shot PQC handshakes.
const RELAY_REVALIDATION_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);

/// Maximum deterministic per-peer offset added before the first maintenance
/// canary. Spreading the first round across a full interval avoids a fleet-wide
/// probe burst after a rolling deployment.
const RELAY_REVALIDATION_JITTER_MAX: Duration = RELAY_REVALIDATION_INTERVAL;

/// Retry interval for authoritative address publications that were not
/// acknowledged by every current close peer.
const PUBLISH_RETRY_INTERVAL: Duration = Duration::from_secs(15);

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
    target_peers: HashSet<PeerId>,
    pending_peers: HashSet<PeerId>,
}

fn pending_publication_targets(
    previous: Option<&PublishedTypedSet>,
    typed_addresses: &[(MultiAddr, AddressType)],
    target_peers: &HashSet<PeerId>,
    force: bool,
) -> HashSet<PeerId> {
    let Some(previous) = previous
        .filter(|previous| !force && previous.typed_addresses.as_slice() == typed_addresses)
    else {
        return target_peers.clone();
    };

    let mut pending: HashSet<_> = previous
        .pending_peers
        .intersection(target_peers)
        .copied()
        .collect();
    pending.extend(target_peers.difference(&previous.target_peers).copied());
    pending
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanaryRejectionEvent {
    Verified,
    Rejected(PeerId),
    InsufficientWitnesses,
    AcquisitionFailed,
}

/// Update the per-acquisition canary exclusion set in response to an outcome.
///
/// Exclusions accumulate only across a contiguous run of canary `Rejected`
/// verdicts, so the next acquisition walk skips a relay that just failed its
/// proof and advances to the next candidate. Every other outcome resets the
/// set:
/// - `Verified`: a relay was published; prior rejections are no longer relevant.
/// - `InsufficientWitnesses`: the relay was never disproven, only unverifiable.
/// - `AcquisitionFailed`: no candidate could be acquired at all. Preserving the
///   set here would be a trap — if the only close Direct candidate is the
///   excluded relayer, acquisition fails every round and the node stays
///   permanently relay-less. Clearing lets it retry; backoff rate-limits the
///   retries and a still-unreachable relay is simply re-excluded next round.
fn apply_canary_rejection_event(
    rejected_relayers: &mut HashSet<PeerId>,
    event: CanaryRejectionEvent,
) {
    match event {
        CanaryRejectionEvent::Verified
        | CanaryRejectionEvent::InsufficientWitnesses
        | CanaryRejectionEvent::AcquisitionFailed => {
            rejected_relayers.clear();
        }
        CanaryRejectionEvent::Rejected(relayer) => {
            rejected_relayers.insert(relayer);
        }
    }
}

impl AcquisitionDriver {
    async fn run(&mut self) {
        info!("relay acquisition driver starting");

        // A process restart invalidates every relay allocation owned by the
        // previous process, while DHT replicas can still retain its last
        // sequenced self-record. Publish a newer relay-free full replacement
        // before attempting to acquire another relay. Without this startup
        // tombstone, peers can keep dialing an allocation whose tunnel died
        // with the old process.
        self.transport.clear_relay_address();
        self.force_publish_typed_set(None).await;

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
                    let relay_addr = relay.allocation.public_addr();
                    match verify_relay_with_canaries(
                        &self.dht,
                        relay.relayer,
                        relay_addr,
                        RelayCanaryPolicy::Admission,
                    )
                    .await
                    {
                        RelayCanaryVerdict::Verified {
                            successes,
                            attempts,
                        } => {
                            if let Err(error) = self
                                .transport
                                .publish_proactive_relay_session(relay.allocation)
                                .await
                            {
                                warn!(
                                    relayer = ?relay.relayer,
                                    allocated = %relay_addr,
                                    %error,
                                    "driver: failed to commit canary-verified relay"
                                );
                                apply_canary_rejection_event(
                                    &mut self.canary_rejected_relayers,
                                    CanaryRejectionEvent::AcquisitionFailed,
                                );
                                self.clear_unpublished_relay_state(relay.allocation).await;
                                self.publish_typed_set(None).await;
                                if self.wait_backoff_or_event().await {
                                    return;
                                }
                                self.advance_backoff();
                                continue;
                            }
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::Verified,
                            );
                            self.current_backoff = BACKOFF_INITIAL;
                            *self.relayer_peer_id.write().await = Some(relay.relayer);
                            *self.relay_address.write().await = Some(relay_addr);
                            self.transport.set_relay_address(relay_addr);
                            self.force_publish_typed_set(Some(relay_addr)).await;
                            info!(
                                relayer = ?relay.relayer,
                                allocated = %relay_addr,
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
                            self.lose_relay_and_republish(relay.allocation).await;
                        }
                        RelayCanaryVerdict::Rejected {
                            successes,
                            attempts,
                        } => {
                            warn!(
                                relayer = ?relay.relayer,
                                allocated = %relay_addr,
                                successes,
                                attempts,
                                "driver: relay failed canary quorum, entering backoff before trying next candidate"
                            );
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::Rejected(relay.relayer),
                            );
                            self.clear_unpublished_relay_state(relay.allocation).await;
                            self.publish_typed_set(None).await;
                            if self.wait_backoff_or_event().await {
                                return; // shutdown
                            }
                            self.advance_backoff();
                        }
                        RelayCanaryVerdict::Inconclusive {
                            successes,
                            failures,
                            unavailable,
                        } => {
                            warn!(
                                relayer = ?relay.relayer,
                                allocated = %relay_addr,
                                successes,
                                failures,
                                unavailable,
                                "driver: relay canary evidence inconclusive, entering backoff without publishing relay"
                            );
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::InsufficientWitnesses,
                            );
                            self.clear_unpublished_relay_state(relay.allocation).await;
                            self.publish_typed_set(None).await;
                            if self.wait_backoff_or_event().await {
                                return; // shutdown
                            }
                            self.advance_backoff();
                        }
                    }
                }
                RelayAcquisitionOutcome::Failed(reason) => {
                    warn!(
                        reason,
                        rejected_relayers = self.canary_rejected_relayers.len(),
                        "driver: acquisition failed, clearing canary exclusions and entering backoff"
                    );
                    apply_canary_rejection_event(
                        &mut self.canary_rejected_relayers,
                        CanaryRejectionEvent::AcquisitionFailed,
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

    /// Tear down and clear a relay allocation that never passed canary.
    async fn clear_unpublished_relay_state(&mut self, allocation: PreparedRelay) {
        let relay_public_addr = allocation.public_addr();
        if let Err(error) = self
            .transport
            .abort_proactive_relay_session(allocation)
            .await
        {
            warn!(
                relay_addr = %relay_public_addr,
                %error,
                "driver: failed to abort unpublished relay"
            );
        }
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

        if self_addresses.is_empty() && !force {
            debug!("driver: publish skipped, no dialable self addresses");
            return;
        }

        let typed = self_addresses.into_typed_vec();
        if typed.is_empty() {
            info!(
                "driver: publishing empty authoritative address set to withdraw stale relay state"
            );
        }

        let own_key = *self.dht.peer_id().to_bytes();
        let all_peers = self
            .dht
            .find_closest_nodes_local(&own_key, self.dht.k_value())
            .await;
        let target_peers: HashSet<PeerId> = all_peers
            .iter()
            .map(|node| node.peer_id)
            .filter(|peer| peer != self.dht.peer_id())
            .collect();
        let mut pending_peers = pending_publication_targets(
            self.last_published_typed_set.as_ref(),
            &typed,
            &target_peers,
            force,
        );
        if pending_peers.is_empty() {
            debug!(
                peers = all_peers.len(),
                typed_addresses = ?typed,
                relay = ?relay,
                "driver: publish skipped, typed self address set unchanged"
            );
            self.last_published_typed_set = Some(PublishedTypedSet {
                typed_addresses: typed,
                target_peers,
                pending_peers,
            });
            return;
        }

        let peers_to_publish: Vec<_> = all_peers
            .into_iter()
            .filter(|peer| pending_peers.contains(&peer.peer_id))
            .collect();

        debug!(
            peers = peers_to_publish.len(),
            typed_addresses = ?typed,
            relay = ?relay,
            "driver: publishing typed self address set"
        );
        trace!(
            peers = peers_to_publish.len(),
            addrs = typed.len(),
            relay = ?relay,
            "driver: publishing typed address set to all routing table peers"
        );
        let confirmed = self
            .dht
            .publish_address_set_to_peers(typed.clone(), &peers_to_publish)
            .await;
        for peer in confirmed {
            pending_peers.remove(&peer);
        }
        let missing = pending_peers.len();
        if missing > 0 {
            debug!(
                missing,
                targets = target_peers.len(),
                relay = ?relay,
                "driver: address publication incomplete; unacknowledged peers will be retried"
            );
        }
        self.last_published_typed_set = Some(PublishedTypedSet {
            typed_addresses: typed,
            target_peers,
            pending_peers,
        });
    }

    /// Hold the acquired relay until positive failure evidence forces a rebind.
    ///
    /// Returns `true` on shutdown (caller should exit), `false` when the relay
    /// is considered lost and a republish+reacquire is needed.
    async fn hold_until_lost(&mut self) -> bool {
        let mut events = self.dht.subscribe_events();
        let mut health = tokio::time::interval(HEALTH_POLL_INTERVAL);
        health.tick().await; // drop the immediate first tick
        let first_revalidation =
            tokio::time::Instant::now() + relay_revalidation_initial_delay(self.dht.peer_id());
        let revalidation = tokio::time::sleep_until(first_revalidation);
        tokio::pin!(revalidation);

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
                        Ok(DhtNetworkEvent::KClosestPeersChanged {
                            added,
                            removed,
                            ..
                        }) => {
                            let relay = *self.relay_address.read().await;
                            self.publish_typed_set(relay).await;
                            debug!(
                                added = added.len(),
                                removed = removed.len(),
                                "driver: K-closest changed; published current relay state only to new targets"
                            );
                        }
                        Ok(_) => continue,
                        // `RecvError::Lagged` is recoverable — the broadcast
                        // channel dropped events we did not consume fast
                        // enough, but we are still subscribed. `Closed` is
                        // terminal (the DHT manager is dropping); treat it
                        // the same as shutdown.
                        Err(RecvError::Closed) => return true,
                        Err(RecvError::Lagged(skipped)) => {
                            self.last_published_typed_set = None;
                            let relay = *self.relay_address.read().await;
                            self.publish_typed_set(relay).await;
                            debug!(
                                skipped,
                                "driver: refreshed publication after lagging DHT events"
                            );
                        }
                    }
                }
                _ = health.tick() => {
                    if !self.transport.is_relay_healthy().await {
                        info!("driver: relay tunnel unhealthy, rebinding");
                        return false;
                    }
                    // Also retries any peers that did not acknowledge the
                    // latest full address-set publication.
                    let relay = *self.relay_address.read().await;
                    self.publish_typed_set(relay).await;
                }
                _ = &mut revalidation => {
                    let relayer = *self.relayer_peer_id.read().await;
                    let relay = *self.relay_address.read().await;
                    let (Some(relayer), Some(relay)) = (relayer, relay) else {
                        warn!("driver: relay state disappeared before revalidation");
                        return false;
                    };
                    let verdict = verify_relay_with_canaries(
                        &self.dht,
                        relayer,
                        relay,
                        RelayCanaryPolicy::Maintenance,
                    )
                    .await;
                    let retry_delay = match verdict {
                        RelayCanaryVerdict::Verified { successes, attempts } => {
                            info!(
                                relayer = %relayer.to_hex(),
                                relay = %relay,
                                successes,
                                attempts,
                                "driver: established relay passed periodic canary revalidation"
                            );
                            RELAY_REVALIDATION_INTERVAL
                        }
                        RelayCanaryVerdict::Rejected { successes, attempts } => {
                            warn!(
                                relayer = %relayer.to_hex(),
                                relay = %relay,
                                successes,
                                attempts,
                                "driver: established relay failed periodic canary revalidation; withdrawing"
                            );
                            apply_canary_rejection_event(
                                &mut self.canary_rejected_relayers,
                                CanaryRejectionEvent::Rejected(relayer),
                            );
                            return false;
                        }
                        RelayCanaryVerdict::Inconclusive {
                            successes,
                            failures,
                            unavailable,
                        } => {
                            info!(
                                relayer = %relayer.to_hex(),
                                relay = %relay,
                                successes,
                                failures,
                                unavailable,
                                "driver: established relay canary evidence inconclusive; retaining relay until the next scheduled check"
                            );
                            // Missing witnesses and transient request failures
                            // are not evidence that the established relay is
                            // bad. Retain it and wait for the ordinary cadence;
                            // retrying a three-witness round after 15 seconds
                            // amplified partial outages into sustained dial
                            // storms.
                            RELAY_REVALIDATION_INTERVAL
                        }
                    };
                    revalidation
                        .as_mut()
                        .reset(tokio::time::Instant::now() + retry_delay);
                }
            }
        }
    }

    /// Transition out of the Holding state: republish direct-only and
    /// clear relayer state, BEFORE the acquisition walk retries. The
    /// pre-retry publish is critical — without it, other peers would
    /// continue dialing the dead relay address during the 1–10 s
    /// acquisition walk.
    async fn lose_relay_and_republish(&mut self, allocation: PreparedRelay) {
        let relay_public_addr = self.relay_address.write().await.take();
        *self.relayer_peer_id.write().await = None;
        self.transport.clear_relay_address();

        // Withdrawal and transport teardown start together. Peers are told to
        // stop using the allocation without waiting for local QUIC/MASQUE
        // shutdown, while teardown does not wait on DHT acknowledgements.
        let transport = Arc::clone(&self.transport);
        let teardown = async move { transport.abort_proactive_relay_session(allocation).await };
        let (teardown_result, ()) = tokio::join!(teardown, self.force_publish_typed_set(None));
        if let Err(error) = teardown_result {
            warn!(
                relay_addr = ?relay_public_addr,
                %error,
                "driver: failed to tear down lost or evicted relay"
            );
        }
    }

    /// Wait out the current backoff window, or short-circuit on a
    /// `KClosestPeersChanged` event (new peers may offer fresh candidates).
    /// Returns `true` on shutdown.
    async fn wait_backoff_or_event(&mut self) -> bool {
        let mut events = self.dht.subscribe_events();
        let sleep = tokio::time::sleep(self.current_backoff);
        tokio::pin!(sleep);
        let mut publish_retry = tokio::time::interval(PUBLISH_RETRY_INTERVAL);
        publish_retry.tick().await;

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return true,
                _ = &mut sleep => {
                    trace!(window = ?self.current_backoff, "driver: backoff window expired");
                    return false;
                }
                _ = publish_retry.tick() => {
                    self.publish_typed_set(None).await;
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
                            self.last_published_typed_set = None;
                            debug!("driver: K-closest changed, retrying early");
                            return false;
                        }
                        Ok(_) => continue,
                        Err(RecvError::Closed) => return true,
                        Err(RecvError::Lagged(skipped)) => {
                            self.last_published_typed_set = None;
                            self.publish_typed_set(None).await;
                            debug!(
                                skipped,
                                "driver: refreshed publication after lagging DHT events during backoff"
                            );
                        }
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

fn relay_revalidation_initial_delay(peer_id: &PeerId) -> Duration {
    let mut prefix = [0u8; std::mem::size_of::<u64>()];
    prefix.copy_from_slice(&peer_id.to_bytes()[..std::mem::size_of::<u64>()]);
    let jitter_bound = RELAY_REVALIDATION_JITTER_MAX.as_secs().saturating_add(1);
    let jitter = u64::from_be_bytes(prefix) % jitter_bound;
    RELAY_REVALIDATION_INTERVAL.saturating_add(Duration::from_secs(jitter))
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
    fn publication_targets_only_retry_pending_and_new_peers() {
        let departed = peer_id(1);
        let retained = peer_id(2);
        let joined = peer_id(3);
        let previous = PublishedTypedSet {
            typed_addresses: Vec::new(),
            target_peers: HashSet::from([departed, retained]),
            pending_peers: HashSet::from([departed]),
        };
        let current = HashSet::from([retained, joined]);

        assert_eq!(
            pending_publication_targets(Some(&previous), &[], &current, false),
            HashSet::from([joined])
        );
    }

    #[test]
    fn invalidated_publication_retries_rejoined_peer_id() {
        let peer = peer_id(1);
        let current = HashSet::from([peer]);

        assert_eq!(
            pending_publication_targets(None, &[], &current, false),
            current
        );
    }

    #[test]
    fn changed_or_forced_publication_targets_every_current_peer() {
        let first = peer_id(1);
        let second = peer_id(2);
        let previous = PublishedTypedSet {
            typed_addresses: Vec::new(),
            target_peers: HashSet::from([first, second]),
            pending_peers: HashSet::new(),
        };
        let current = HashSet::from([first, second]);
        let changed = [(
            MultiAddr::from_ipv4(std::net::Ipv4Addr::new(203, 0, 113, 7), 9000),
            AddressType::Direct,
        )];

        assert_eq!(
            pending_publication_targets(Some(&previous), &changed, &current, false),
            current
        );
        assert_eq!(
            pending_publication_targets(Some(&previous), &[], &current, true),
            current
        );
    }

    #[test]
    fn acquisition_failure_clears_canary_rejected_relayers() {
        // A failed acquisition must reset exclusions: if the only close Direct
        // candidate is the excluded relayer, preserving the set would fail
        // acquisition every round and leave the node permanently relay-less.
        let mut rejected_relayers =
            HashSet::from([peer_id(REJECTED_RELAYER_SEED), peer_id(SECOND_RELAYER_SEED)]);

        apply_canary_rejection_event(
            &mut rejected_relayers,
            CanaryRejectionEvent::AcquisitionFailed,
        );

        assert!(rejected_relayers.is_empty());
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

    #[test]
    fn relay_revalidation_delay_is_bounded_and_peer_stable() {
        let peer = peer_id(REJECTED_RELAYER_SEED);
        let delay = relay_revalidation_initial_delay(&peer);

        assert_eq!(delay, relay_revalidation_initial_delay(&peer));
        assert!(delay >= RELAY_REVALIDATION_INTERVAL);
        assert!(delay <= RELAY_REVALIDATION_INTERVAL.saturating_add(RELAY_REVALIDATION_JITTER_MAX));
    }
}
