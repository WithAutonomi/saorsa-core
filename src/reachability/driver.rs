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
//! 1. **Acquiring**: call [`run_relay_acquisition`]. On success, publish
//!    the full typed self-record (relay-allocated address tagged
//!    [`AddressType::Relay`] first, then one best non-relay address per
//!    IP family) to K-closest peers, store the relayer peer ID, and enter
//!    the **Holding** state. Relay serving stays permanently enabled. On
//!    failure, publish the direct-only address set so the node remains as
//!    reachable as possible, arm the exponential backoff timer, and enter
//!    the **Backoff** state.
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
use crate::reachability::session::{RelayAcquisitionOutcome, run_relay_acquisition};
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
}

impl AcquisitionDriver {
    async fn run(&mut self) {
        info!("relay acquisition driver starting");
        loop {
            if self.shutdown.is_cancelled() {
                debug!("relay acquisition driver: shutdown, exiting");
                return;
            }

            let outcome = run_relay_acquisition(self.dht.as_ref(), &self.transport).await;
            match outcome {
                RelayAcquisitionOutcome::Acquired(relay) => {
                    self.current_backoff = BACKOFF_INITIAL;
                    *self.relayer_peer_id.write().await = Some(relay.relayer);
                    *self.relay_address.write().await = Some(relay.allocated_public_addr);
                    self.transport
                        .set_relay_address(relay.allocated_public_addr);
                    self.publish_typed_set(Some(relay.allocated_public_addr))
                        .await;
                    info!(
                        relayer = ?relay.relayer,
                        allocated = %relay.allocated_public_addr,
                        "driver: relay acquired and published"
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
                RelayAcquisitionOutcome::Failed(reason) => {
                    warn!(reason, "driver: acquisition failed, entering backoff");
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
    async fn publish_typed_set(&self, relay: Option<SocketAddr>) {
        let listen = self.transport.listen_addrs().await;
        let observed = self.transport.non_relay_external_addresses();

        debug!(
            relay = ?relay,
            observed = ?observed,
            listen = ?listen,
            "driver: preparing typed self address set"
        );

        let typed = build_typed_self_address_set(observed, listen, relay, |sa| {
            self.transport.is_external_proven(sa)
        });

        if typed.is_empty() {
            debug!("driver: publish skipped, no dialable self addresses");
            return;
        }

        let own_key = *self.dht.peer_id().to_bytes();
        let all_peers = self
            .dht
            .find_closest_nodes_local(&own_key, self.dht.k_value())
            .await;
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
    }

    /// Hold the acquired relay until an eviction or death event forces a
    /// rebind. Returns `true` on shutdown (caller should exit), `false`
    /// when the relay is considered lost and a republish+reacquire is
    /// needed.
    async fn hold_until_lost(&self) -> bool {
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
                            info!(
                                address = %addr,
                                relay = ?relay,
                                "driver: self address updated, republishing typed self address set"
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
    async fn lose_relay_and_republish(&self) {
        *self.relayer_peer_id.write().await = None;
        *self.relay_address.write().await = None;
        self.transport.clear_relay_address();
        self.publish_typed_set(None).await;
    }

    /// Wait out the current backoff window, or short-circuit on a
    /// `KClosestPeersChanged` event (new peers may offer fresh candidates).
    /// Returns `true` on shutdown.
    async fn wait_backoff_or_event(&self) -> bool {
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
                            info!(
                                address = %addr,
                                "driver: self address updated during relay backoff, republishing typed self address set"
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

fn build_typed_self_address_set<F>(
    observed: impl IntoIterator<Item = SocketAddr>,
    listen: impl IntoIterator<Item = MultiAddr>,
    relay: Option<SocketAddr>,
    mut is_external_proven: F,
) -> Vec<(MultiAddr, AddressType)>
where
    F: FnMut(SocketAddr) -> bool,
{
    let mut typed: Vec<(MultiAddr, AddressType)> = Vec::new();
    let mut non_relay: Vec<FamilyAddressChoice> = Vec::new();
    // Normalize addresses before dedup so IPv4-mapped IPv6
    // (::ffff:a.b.c.d) and plain IPv4 (a.b.c.d) are treated as equal.
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    if let Some(relay_addr) = relay {
        let normalized = saorsa_transport::shared::normalize_socket_addr(relay_addr);
        debug!(
            address = %normalized,
            "driver: adding relay self address to publish set"
        );
        typed.push((MultiAddr::quic(normalized), AddressType::Relay));
        seen.insert(normalized);
    }

    // Prefer observed (post-NAT) addresses for the direct tier since
    // those are what peers actually see from the outside. Listen
    // addresses are emitted alongside them with the same per-address
    // tagging.
    for sa in observed {
        record_non_relay_self_address(
            sa,
            AddressSource::Observed,
            &mut seen,
            &mut non_relay,
            &mut is_external_proven,
        );
    }
    for addr in listen {
        let Some(sa) = addr.dialable_socket_addr() else {
            trace!(
                address = %addr,
                "driver: skipping non-dialable listen address"
            );
            continue;
        };
        record_non_relay_self_address(
            sa,
            AddressSource::Listen,
            &mut seen,
            &mut non_relay,
            &mut is_external_proven,
        );
    }

    for choice in non_relay {
        typed.push((choice.address, choice.tag));
    }

    typed
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressSource {
    Observed,
    Listen,
}

impl AddressSource {
    fn label(self) -> &'static str {
        match self {
            AddressSource::Observed => "observed",
            AddressSource::Listen => "listen",
        }
    }

    /// Observed externals are the most recent post-NAT signal we have, so a
    /// new observation in the same tier supersedes the previous one (matches
    /// NAT rebinding and mobile handoff behavior). Listen addresses are
    /// static, so they should never displace an observed same-tier choice.
    fn replace_same_tier(self) -> bool {
        matches!(self, AddressSource::Observed)
    }
}

fn record_non_relay_self_address<F>(
    socket_addr: SocketAddr,
    source: AddressSource,
    seen: &mut HashSet<SocketAddr>,
    non_relay: &mut Vec<FamilyAddressChoice>,
    is_external_proven: &mut F,
) where
    F: FnMut(SocketAddr) -> bool,
{
    if socket_addr.ip().is_unspecified() {
        debug!(
            address = %socket_addr,
            source = source.label(),
            "driver: skipping unspecified self address"
        );
        return;
    }
    let normalized = saorsa_transport::shared::normalize_socket_addr(socket_addr);
    let tag = if is_external_proven(normalized) {
        AddressType::Direct
    } else {
        AddressType::Unverified
    };
    if seen.insert(normalized) {
        debug!(
            address = %normalized,
            tag = ?tag,
            source = source.label(),
            "driver: adding self address to candidate publish set"
        );
        record_non_relay_choice(non_relay, normalized, tag, source.replace_same_tier());
    } else {
        trace!(
            address = %normalized,
            tag = ?tag,
            source = source.label(),
            "driver: deduped self address"
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Debug)]
struct FamilyAddressChoice {
    family: IpFamily,
    address: MultiAddr,
    tag: AddressType,
}

fn record_non_relay_choice(
    choices: &mut Vec<FamilyAddressChoice>,
    socket_addr: SocketAddr,
    tag: AddressType,
    replace_same_tier: bool,
) {
    // Callers normalize before reaching this helper, so IPv4-mapped IPv6 is
    // already represented as plain IPv4 and cannot be mis-bucketed as V6.
    let family = if socket_addr.ip().is_ipv4() {
        IpFamily::V4
    } else {
        IpFamily::V6
    };

    let address = MultiAddr::quic(socket_addr);
    let Some(existing) = choices.iter_mut().find(|choice| choice.family == family) else {
        choices.push(FamilyAddressChoice {
            family,
            address,
            tag,
        });
        return;
    };

    if tag.priority() < existing.tag.priority()
        || (replace_same_tier && tag.priority() == existing.tag.priority())
    {
        trace!(
            family = ?family,
            old_tag = ?existing.tag,
            new_tag = ?tag,
            "driver: replacing self address candidate for IP family"
        );
        existing.address = address;
        existing.tag = tag;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> MultiAddr {
        s.parse().unwrap()
    }

    #[test]
    fn publish_set_keeps_relay_primary_and_unverified_fallback() {
        let typed = build_typed_self_address_set(
            [sock("203.0.113.10:10004")],
            Vec::<MultiAddr>::new(),
            Some(sock("198.51.100.1:45000")),
            |_| false,
        );

        assert_eq!(
            typed,
            vec![
                (addr("/ip4/198.51.100.1/udp/45000/quic"), AddressType::Relay),
                (
                    addr("/ip4/203.0.113.10/udp/10004/quic"),
                    AddressType::Unverified,
                ),
            ]
        );
    }

    #[test]
    fn publish_set_keeps_relay_primary_and_direct_fallback() {
        let proven = sock("203.0.113.10:10004");
        let typed = build_typed_self_address_set(
            [proven],
            Vec::<MultiAddr>::new(),
            Some(sock("198.51.100.1:45000")),
            |sa| sa == proven,
        );

        assert_eq!(
            typed,
            vec![
                (addr("/ip4/198.51.100.1/udp/45000/quic"), AddressType::Relay),
                (
                    addr("/ip4/203.0.113.10/udp/10004/quic"),
                    AddressType::Direct,
                ),
            ]
        );
    }

    #[test]
    fn publish_set_without_relay_prefers_direct_over_unverified() {
        let proven = sock("203.0.113.10:10004");
        let typed = build_typed_self_address_set(
            [proven, sock("203.0.113.11:10004")],
            Vec::<MultiAddr>::new(),
            None,
            |sa| sa == proven,
        );

        assert_eq!(
            typed,
            vec![(
                addr("/ip4/203.0.113.10/udp/10004/quic"),
                AddressType::Direct,
            )]
        );
    }

    #[test]
    fn publish_set_keeps_unverified_for_family_without_direct() {
        let proven_v4 = sock("203.0.113.10:10004");
        let unverified_v6 = sock("[2001:db8::10]:10004");
        let typed = build_typed_self_address_set(
            [proven_v4, unverified_v6],
            Vec::<MultiAddr>::new(),
            Some(sock("198.51.100.1:45000")),
            |sa| sa == proven_v4,
        );

        assert_eq!(
            typed,
            vec![
                (addr("/ip4/198.51.100.1/udp/45000/quic"), AddressType::Relay),
                (
                    addr("/ip4/203.0.113.10/udp/10004/quic"),
                    AddressType::Direct,
                ),
                (
                    addr("/ip6/2001:db8::10/udp/10004/quic"),
                    AddressType::Unverified,
                ),
            ]
        );
    }

    #[test]
    fn publish_set_keeps_one_best_non_relay_per_family() {
        let older_v4 = sock("203.0.113.10:10004");
        let newer_v4 = sock("203.0.113.11:10004");
        let typed = build_typed_self_address_set(
            [older_v4, newer_v4],
            Vec::<MultiAddr>::new(),
            None,
            |sa| sa == older_v4 || sa == newer_v4,
        );

        assert_eq!(
            typed,
            vec![(
                addr("/ip4/203.0.113.11/udp/10004/quic"),
                AddressType::Direct,
            )]
        );
    }

    #[test]
    fn publish_set_without_relay_publishes_unverified_when_no_direct() {
        let typed = build_typed_self_address_set(
            [sock("203.0.113.11:10004")],
            Vec::<MultiAddr>::new(),
            None,
            |_| false,
        );

        assert_eq!(
            typed,
            vec![(
                addr("/ip4/203.0.113.11/udp/10004/quic"),
                AddressType::Unverified,
            )]
        );
    }

    #[test]
    fn publish_set_dedupes_listen_address_after_observed_address() {
        let typed = build_typed_self_address_set(
            [sock("203.0.113.10:10004")],
            [addr("/ip4/203.0.113.10/udp/10004/quic")],
            None,
            |_| false,
        );

        assert_eq!(
            typed,
            vec![(
                addr("/ip4/203.0.113.10/udp/10004/quic"),
                AddressType::Unverified,
            )]
        );
    }
}
