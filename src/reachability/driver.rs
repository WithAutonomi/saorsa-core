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
//!    the full typed self-record (direct addresses + relay-allocated
//!    address tagged [`AddressType::Relay`]) to K-closest peers, store
//!    the relayer peer ID, and enter the **Holding** state. Relay
//!    serving stays permanently enabled. On failure, publish the
//!    direct-only address set so the node remains as reachable as
//!    possible, arm the exponential backoff timer, and enter the
//!    **Backoff** state.
//! 2. **Holding**: subscribe to `KClosestPeersChanged` events and poll
//!    [`TransportHandle::is_relay_healthy`] every
//!    [`HEALTH_POLL_INTERVAL`]. On relayer-evicted, unhealthy-tunnel,
//!    or shutdown, transition to **Lost**.
//! 3. **Lost**: run the `republish-direct-only → reacquire` sequence.
//!    The republish MUST happen **before** the acquisition walk starts,
//!    so the network stops dialing the dead relay address during the
//!    1–10 s acquisition window. After republishing, loop back to
//!    **Acquiring**.
//! 4. **Backoff**: wait for the current backoff window or a
//!    `KClosestPeersChanged` event (whichever comes first), then loop
//!    back to **Acquiring**. Successful acquisition resets the backoff.
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
use crate::dht_network_manager::{DhtNetworkEvent, DhtNetworkManager, is_lan_or_loopback_socket};
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
    /// The direct tier's [`AddressType`] depends on the passive
    /// reachability classifier (see
    /// [`TransportHandle::direct_reachability_observed`]): when at least
    /// one unsolicited inbound handshake has completed, observed external
    /// addresses are tagged [`AddressType::Direct`]; otherwise they are
    /// tagged [`AddressType::Unverified`] so dialers know they may time
    /// out. When `relay` is `Some`, the relay-allocated socket is appended
    /// tagged [`AddressType::Relay`].
    ///
    /// When a relay has been acquired, unverified-only addresses are
    /// suppressed — the relay address is the authoritative contact and
    /// publishing undialable direct entries alongside it just adds
    /// timeout cost for dialers.
    ///
    /// Quietly drops the publish when there are no dialable addresses to
    /// advertise — a fully wildcard-bound node cannot meaningfully tell
    /// peers how to reach it.
    async fn publish_typed_set(&self, relay: Option<SocketAddr>) {
        let listen = self.transport.listen_addrs().await;
        let observed = self.transport.direct_external_addresses();
        let direct_verified = self.transport.direct_reachability_observed();

        // Choose the tag for observed/listen addresses:
        //   - classifier has proven reachability → Direct
        //   - no proof yet, no relay either      → Unverified (cold-start;
        //                                          dialers eat the risk)
        //   - no proof yet, but relay is held    → suppress (relay is
        //                                          authoritative; don't
        //                                          waste dialers on
        //                                          unverified direct)
        let direct_tag: Option<AddressType> = if direct_verified {
            Some(AddressType::Direct)
        } else if relay.is_none() {
            Some(AddressType::Unverified)
        } else {
            None
        };

        let mut typed: Vec<(MultiAddr, AddressType)> = Vec::new();
        // Normalize addresses before dedup so IPv4-mapped IPv6
        // (::ffff:a.b.c.d) and plain IPv4 (a.b.c.d) are treated as
        // equal, preventing the same address from appearing twice with
        // different representations.
        let mut seen: HashSet<SocketAddr> = HashSet::new();

        // Prefer observed (post-NAT) addresses for the direct tier since
        // those are what peers actually see from the outside. LAN-scoped
        // observations and listen sockets are tagged separately and only
        // published to peers on the same WAN by `publish_address_set_to_peers`.
        if !observed.is_empty() {
            for sa in observed {
                if sa.ip().is_unspecified() {
                    continue;
                }
                let normalized = saorsa_transport::shared::normalize_socket_addr(sa);
                let addr_type = if is_lan_or_loopback_socket(&normalized) {
                    Some(AddressType::Lan)
                } else {
                    direct_tag
                };
                if let Some(tag) = addr_type
                    && seen.insert(normalized)
                {
                    typed.push((MultiAddr::quic(normalized), tag));
                }
            }
        }
        for addr in listen {
            let Some(sa) = addr.dialable_socket_addr() else {
                continue;
            };
            if sa.ip().is_unspecified() {
                continue;
            }
            let normalized = saorsa_transport::shared::normalize_socket_addr(sa);
            let addr_type = if is_lan_or_loopback_socket(&normalized) {
                Some(AddressType::Lan)
            } else {
                direct_tag
            };
            if let Some(tag) = addr_type
                && seen.insert(normalized)
            {
                typed.push((MultiAddr::quic(normalized), tag));
            }
        }

        if let Some(relay_addr) = relay {
            let normalized = saorsa_transport::shared::normalize_socket_addr(relay_addr);
            typed.push((MultiAddr::quic(normalized), AddressType::Relay));
        }

        if typed.is_empty() {
            debug!("driver: publish skipped, no dialable self addresses");
            return;
        }

        let own_key = *self.dht.peer_id().to_bytes();
        let all_peers = self
            .dht
            .find_closest_nodes_local(&own_key, self.dht.k_value())
            .await;
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
