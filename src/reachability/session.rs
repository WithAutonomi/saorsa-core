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

//! Unconditional MASQUE relay acquisition.
//!
//! Every non-client node tries to acquire a MASQUE relay from an XOR-closest
//! peer after bootstrap. There is no dial-back probe and no public/private
//! classification: the "is this candidate public?" question is answered
//! ambiently by the dial attempt itself. A candidate whose Direct address is
//! unreachable will simply fail to accept the CONNECT-UDP request, and the
//! walker moves to the next-closest peer.
//!
//! The acquisition walk is a thin wrapper around the reusable
//! [`RelayAcquisition`] coordinator: build a filtered candidate list from
//! the routing table, hand it off, and return the outcome.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tracing::{debug, info, warn};

use crate::dht_network_manager::DhtNetworkManager;
use crate::reachability::acquisition::{AcquiredRelay, RelayAcquisition, RelayCandidate};
use crate::transport_handle::TransportHandle;

/// Upper bound on the random startup jitter applied before the first
/// acquisition attempt.
///
/// Decorrelates bootstrap-time acquisition stampedes: when many private
/// nodes come online simultaneously, this prevents them all from hammering
/// the same 2–3 close public peers in lock-step and tripping per-relay
/// capacity limits. 2 seconds is short enough to be imperceptible to users
/// but wide enough to spread load at the tens-of-milliseconds resolution
/// that matters for QUIC dial handling.
const STARTUP_JITTER_UPPER_MS: u64 = 2000;

/// Outcome of a single relay acquisition attempt.
#[derive(Debug, Clone)]
pub(crate) enum RelayAcquisitionOutcome {
    /// A MASQUE relay session was successfully established.
    ///
    /// The caller (acquisition driver) is responsible for:
    ///
    /// 1. Storing the relayer peer ID for the K-closest eviction monitor.
    /// 2. Publishing the full typed self-record (direct addresses +
    ///    relay-allocated address tagged [`AddressType::Relay`]) to K
    ///    closest peers.
    /// 3. Disabling local relay serving so this node does not form a
    ///    relay loop by accepting reservations while its own traffic
    ///    tunnels through someone else.
    Acquired(AcquiredRelay),
    /// Acquisition did not succeed. The driver should publish the
    /// direct-only address set (so the network still has some way to
    /// reach this node) and arm a backoff retry.
    ///
    /// `reason` is a human-readable diagnostic for logs / metrics — no
    /// programmatic consumer switches on its contents.
    Failed(String),
}

/// Run a single unconditional relay-acquisition attempt.
///
/// Walks the XOR-closest peers in the local routing table, filters to
/// those advertising at least one `Direct` address, and tries each in
/// order via the [`RelayAcquisition`] coordinator until one accepts a
/// MASQUE CONNECT-UDP reservation.
///
/// The "is this candidate public?" check is implicit: a private candidate's
/// Direct address is unreachable from outside its NAT, so the QUIC dial
/// fails and the walker advances to the next candidate.
///
/// A small randomized startup jitter is applied before the first dial to
/// prevent correlated bootstrap-time stampedes against the same close-group
/// peers.
pub(crate) async fn run_relay_acquisition(
    dht: &DhtNetworkManager,
    transport: &Arc<TransportHandle>,
) -> RelayAcquisitionOutcome {
    let jitter_ms = rand::thread_rng().gen_range(0..STARTUP_JITTER_UPPER_MS);
    if jitter_ms > 0 {
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
    }

    let own_key = *dht.peer_id().to_bytes();
    let closest = dht.find_closest_nodes_local(&own_key, dht.k_value()).await;
    let own_wan_ips = DhtNetworkManager::own_direct_wan_ips_from_transport(transport);

    let candidates: Vec<RelayCandidate> = closest
        .iter()
        .filter_map(|node| {
            let direct =
                DhtNetworkManager::first_direct_dialable_excluding_wan(node, &own_wan_ips)?;
            Some(RelayCandidate::new(node.peer_id, direct))
        })
        .collect();

    if candidates.is_empty() {
        warn!("relay acquisition: no direct-addressable candidates in routing table");
        return RelayAcquisitionOutcome::Failed(
            "no direct-addressable candidates in routing table".to_string(),
        );
    }

    debug!(
        candidate_count = candidates.len(),
        "relay acquisition: starting XOR-closest walk"
    );

    let coordinator = RelayAcquisition::new(Arc::clone(transport));
    match coordinator.acquire(candidates).await {
        Ok(relay) => {
            info!(
                relayer = ?relay.relayer,
                allocated = %relay.allocated_public_addr,
                "relay acquisition: session established"
            );
            RelayAcquisitionOutcome::Acquired(relay)
        }
        Err(e) => {
            warn!(error = %e, "relay acquisition: all candidates failed");
            RelayAcquisitionOutcome::Failed(e.to_string())
        }
    }
}
