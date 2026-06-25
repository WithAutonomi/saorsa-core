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

//! DHT Network Manager
//!
//! This module provides the integration layer between the DHT system and the network layer,
//! enabling real P2P operations with Kademlia routing over transport protocols.

#![allow(missing_docs)]

use crate::{
    P2PError, PeerId, Result,
    adaptive::trust::DEFAULT_NEUTRAL_TRUST,
    adaptive::{AdaptiveDhtConfig, NodeStatisticsUpdate, TrustEngine},
    address::{MultiAddr, is_lan_ip},
    dht::core_engine::{AddressType, AtomicInstant, BucketRefreshCandidate, NodeInfo},
    dht::{AdmissionResult, DhtCoreEngine, DhtKey, Key, RoutingTableEvent},
    error::{DhtError, IdentityError, NetworkError},
    network::{NodeConfig, NodeMode},
    security::canonicalize_ip,
    self_address::build_self_address_set,
};
use anyhow::Context as _;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Semaphore, broadcast, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

/// Minimum concurrent operations for semaphore backpressure
const MIN_CONCURRENT_OPERATIONS: usize = 10;

/// Maximum candidate nodes queue size to prevent memory exhaustion attacks.
/// Candidates are sorted by XOR distance to the lookup target (closest first).
/// When at capacity, a closer newcomer evicts the farthest existing candidate.
const MAX_CANDIDATE_NODES: usize = 200;

/// Maximum size for incoming DHT messages (64 KB) to prevent memory exhaustion DoS
/// Messages larger than this are rejected before deserialization
const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Request timeout for DHT message handlers (10 seconds)
/// Prevents long-running handlers from starving the semaphore permit pool
/// SEC-001: DoS mitigation via timeout enforcement on concurrent operations
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Reliability score assigned to the local node in K-closest results.
/// The local node is always considered fully reliable for its own lookups.
const SELF_RELIABILITY_SCORE: f64 = 1.0;

/// Maximum time to wait for the identity-exchange handshake after dialling
/// a known peer. The actual timeout is `min(request_timeout, this)`.
///
/// Identity exchange is two RTTs over a freshly-handshaken QUIC connection
/// plus an ML-DSA-65 signature verification. Covers a reasonable range of
/// loopback and WAN links — LAN completes in <1 s, a congested
/// cross-region link fits in the 5 s budget with retransmits.
///
/// Used for every post-bootstrap dial: `send_dht_request` against a peer
/// the routing table already knows about, and the reconnect-on-send path
/// in `network.rs::wait_for_peer_identity`. Bootstrap dials use a tighter
/// budget (`BOOTSTRAP_IDENTITY_TIMEOUT_SECS`) on the assumption that the
/// peer is unverified and should not be allowed to head-of-line block
/// convergence.
///
/// Tightened from 15 s to 5 s: the old budget let dead channels hold
/// up bootstrap convergence for 15 s each. On a devnet with serialised
/// bootstraps this turned a ~6 s startup into ~40 s for the last node.
/// `wait_for_peer_identity` additionally short-circuits on channel
/// close so most failures surface in microseconds regardless of the
/// timeout.
pub(crate) const IDENTITY_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Wall-clock budget for a single stale-peer revalidation probe.
///
/// The probe is `ping_peer`, which will dial and run identity exchange
/// from cold when no authenticated channel is currently open — the
/// common case for a peer that has been silent for `LIVE_THRESHOLD`
/// (15 min) and may have lost its transport channel to a NAT rebind,
/// idle timeout, or transient network blip. We must therefore budget
/// for the full identity-exchange handshake before the ping reply is
/// even possible:
///
/// ```text
///   IDENTITY_EXCHANGE_TIMEOUT  (up to 5 s)   — fresh handshake from cold
/// + STALE_REVALIDATION_PING_RTT (1 s)        — ping round-trip over the
///                                              freshly-authenticated channel
/// = STALE_REVALIDATION_BUDGET   (6 s)
/// ```
///
/// Capping at 1 s — the original budget — silently false-evicted
/// healthy peers whose channel had to be re-established, because the
/// outer timeout fired mid-handshake. The strict identity-confirmation
/// check in [`DhtNetworkManager::ping_with_identity_confirmation`]
/// makes that especially harmful: even if the wire ping somehow
/// succeeded, `is_known_app_peer_id` would still be `false` until
/// identity exchange completed.
///
/// `wait_for_peer_identity` short-circuits on transport-level channel
/// close, so genuinely-broken peers (the case that motivated the
/// strict check) usually surface their failure in microseconds and
/// don't pay the full 6 s. The budget is the worst-case ceiling, not
/// the typical path.
const STALE_REVALIDATION_PING_RTT: Duration = Duration::from_secs(1);
// Use `saturating_add` rather than re-deriving from `as_secs()`: the latter
// truncates any sub-second component, so a future tweak that adds millis or
// nanos to either input would silently shrink the budget below the documented
// "identity exchange + ping RTT" invariant. `saturating_add` is `const fn`,
// preserves every nanosecond, and only saturates at `Duration::MAX` (~584 Gyr)
// — well outside any realistic input range here.
const STALE_REVALIDATION_BUDGET: Duration =
    IDENTITY_EXCHANGE_TIMEOUT.saturating_add(STALE_REVALIDATION_PING_RTT);

/// Buffer size for the broadcast channel that
/// [`DhtNetworkManager::ensure_peer_channel`] uses to fan a single
/// dial's outcome out to tasks that joined in flight. The owner
/// removes the coordinator entry immediately before broadcasting,
/// so subscribers can only accumulate during the narrow dial window
/// (milliseconds) — a small buffer is enough to absorb them without
/// lagging.
const PENDING_DIAL_BROADCAST_CAPACITY: usize = 16;

/// Broadcast buffer for active FIND_NODE peer-failure signals.
///
/// Only active lookup probes subscribe, and each message is a single
/// [`PeerId`]. A larger buffer than the dial coordinator keeps a short burst
/// of failing peers from lagging sibling lookups during upload/download storms.
const LOOKUP_FAILURE_BROADCAST_CAPACITY: usize = 1024;

/// Maximum concurrent stale revalidation passes across all buckets.
const MAX_CONCURRENT_REVALIDATIONS: usize = 8;

/// Maximum concurrent pings within a single stale revalidation pass.
const MAX_CONCURRENT_REVALIDATION_PINGS: usize = 4;

/// Minimum self-lookup interval (randomized between min and max).
const SELF_LOOKUP_INTERVAL_MIN: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum self-lookup interval.
const SELF_LOOKUP_INTERVAL_MAX: Duration = Duration::from_secs(600); // 10 minutes

/// Minimum periodic refresh cadence for k-buckets (randomized between min and
/// max). Jittering this interval prevents 1000s of nodes that started in
/// lockstep from all firing their bucket-refresh FIND_NODEs in the same second.
const BUCKET_REFRESH_INTERVAL_MIN: Duration = Duration::from_secs(450); // 7.5 minutes

/// Maximum periodic refresh cadence for k-buckets.
const BUCKET_REFRESH_INTERVAL_MAX: Duration = Duration::from_secs(750); // 12.5 minutes

/// Maximum k-buckets refreshed during a single bucket-refresh pass.
///
/// A large production routing table has 256 buckets to maintain. Without a
/// per-pass budget, the refresh task can spend the whole interval running
/// iterative network lookups back-to-back. With the current 7.5-12.5 minute
/// interval, refreshing two buckets per pass gives an approximate once-per-day
/// full-table maintenance cadence while keeping background lookup pressure low.
const MAX_BUCKET_REFRESH_LOOKUPS_PER_PASS: usize = 2;

/// Maximum concurrent bucket-refresh lookups.
///
/// This is intentionally scoped to bucket refresh so periodic self-lookup and
/// foreground/user lookup behaviour remain unchanged. Automatic re-bootstrap is
/// intentionally exempt: it is gated separately by [`REBOOTSTRAP_COOLDOWN`] and
/// only runs when the routing table has fallen below
/// [`AUTO_REBOOTSTRAP_THRESHOLD`].
const MAX_CONCURRENT_BUCKET_REFRESH_LOOKUPS: usize = 1;

/// Random jitter applied to bucket-refresh debt ordering.
///
/// Kept small so the oldest/debtiest buckets still dominate, while same-age
/// buckets do not refresh in lockstep across nodes.
const BUCKET_REFRESH_SELECTION_JITTER: Duration = Duration::from_secs(60);

/// Routing table size below which automatic re-bootstrap is triggered.
const AUTO_REBOOTSTRAP_THRESHOLD: usize = 3;

/// Maximum time to wait for a background task to stop during shutdown before
/// aborting it. Defense in depth against tasks that fail to respond to the
/// shutdown cancellation token.
const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum time between consecutive auto re-bootstrap attempts.
const REBOOTSTRAP_COOLDOWN: Duration = Duration::from_secs(300); // 5 minutes

/// Duration a dial failure is remembered before it may be retried.
///
/// 30 minutes is the sweet spot: long enough to absorb the common
/// causes of transient direct-dial failure (short-lived NAT rebinds,
/// bootstrap hiccups, routing churn) without permanently banning an
/// address that was temporarily unreachable. Combined with the
/// per-peer bounded dial cap, this prevents retry storms against stale
/// Unverified/Direct entries published by NATed peers.
const DIAL_FAILURE_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

/// Number of *distinct* failed relay-session `SocketAddr`s at a single
/// relay-server IP (with no intervening success at that IP, within the
/// [`DIAL_FAILURE_CACHE_TTL`] window) that trips IP-level suppression in
/// [`DialFailureCache`].
///
/// When a relay server goes down it orphans every MASQUE session address
/// it ever allocated; those records keep circulating in FIND_NODE
/// responses, each a distinct `ip:port` the per-`SocketAddr` tier can only
/// suppress after it fails its own dial. Once this many distinct sessions
/// at one IP have failed, every *remaining* session at that IP is
/// suppressed without an individual dial. A success at the IP clears the
/// suppression immediately, so a recovered relay is re-admitted promptly.
///
/// Conservative on purpose: a threshold (not a single failure) plus
/// success-clears-immediately guards against suppressing a live IP because
/// one peer behind a shared NAT IP churned.
const DIAL_FAILURE_IP_SUPPRESS_THRESHOLD: usize = 4;

/// How long a freshly re-attested (re-published) relay address bypasses
/// IP-level suppression (ADR-011 self-heal).
///
/// When a peer reclaims its previous stable relay port and re-attests it via a
/// newer `PublishAddressSet`, that exact `ip:port` should be retried promptly
/// even if its relay IP is still IP-suppressed by *other* dead sessions —
/// otherwise the self-healed record waits out the full
/// [`DIAL_FAILURE_CACHE_TTL`]. The exemption is scoped to the single re-attested
/// socket (never the whole IP), and kept short so it only bridges the gap to the
/// next dial attempt rather than masking a genuinely dead relay IP for long.
const DIAL_FAILURE_PUBLISH_EXEMPTION_TTL: Duration = Duration::from_secs(2 * 60);

/// Trust-score log reason for a failed pre-request dial.
const TRUST_REASON_DHT_DIAL_FAILED: &str = "dht_dial_failed";

/// Trust-score log reason for a failed post-dial identity exchange.
const TRUST_REASON_DHT_IDENTITY_EXCHANGE_FAILED: &str = "dht_identity_exchange_failed";

/// Trust-score log reason for a sent DHT request that failed or timed out.
const TRUST_REASON_DHT_REQUEST_FAILED: &str = "dht_request_failed";

/// Worst-case number of addresses
/// [`DhtNetworkManager::select_dial_candidates_with_context`] returns for a
/// single peer: one Relay plus at most one best WAN and one best LAN address
/// per IP family (V4 and V6). Used to size the result vector so the hot path
/// does not reallocate.
const MAX_DIAL_PLAN_SIZE: usize = 5;

#[derive(Debug, Default)]
pub(crate) struct DialAddressContext {
    local_wan_ips: HashSet<IpAddr>,
    local_lan_ips: Vec<IpAddr>,
    allow_loopback: bool,
}

impl DialAddressContext {
    fn from_parts(
        local_external_addresses: impl IntoIterator<Item = SocketAddr>,
        local_listen_addresses: impl IntoIterator<Item = MultiAddr>,
        allow_loopback: bool,
    ) -> Self {
        let mut local_wan_ips = HashSet::new();
        let mut local_lan_ips = Vec::new();

        for addr in local_external_addresses {
            Self::record_local_ip(addr.ip(), &mut local_wan_ips, &mut local_lan_ips);
        }
        for addr in local_listen_addresses {
            if let Some(ip) = addr.ip() {
                Self::record_local_ip(ip, &mut local_wan_ips, &mut local_lan_ips);
            }
        }

        Self {
            local_wan_ips,
            local_lan_ips,
            allow_loopback,
        }
    }

    fn record_local_ip(ip: IpAddr, wan_ips: &mut HashSet<IpAddr>, lan_ips: &mut Vec<IpAddr>) {
        let ip = canonicalize_ip(ip);
        if is_lan_ip(ip) {
            if !lan_ips.contains(&ip) {
                lan_ips.push(ip);
            }
        } else {
            wan_ips.insert(ip);
        }
    }

    fn peer_shares_wan(&self, typed: &[(MultiAddr, AddressType)]) -> bool {
        !self.local_wan_ips.is_empty()
            && typed.iter().any(|(addr, ty)| {
                let ty = AddressType::for_advertised_address(addr, *ty);
                !matches!(ty, AddressType::Relay | AddressType::Lan)
                    && addr.ip().is_some_and(|ip| self.ip_shares_local_wan(ip))
            })
    }

    fn address_shares_local_wan(&self, addr: &MultiAddr) -> bool {
        addr.ip().is_some_and(|ip| self.ip_shares_local_wan(ip))
    }

    fn ip_shares_local_wan(&self, ip: IpAddr) -> bool {
        let ip = canonicalize_ip(ip);
        !is_lan_ip(ip) && self.local_wan_ips.contains(&ip)
    }

    fn lan_match_score(&self, ip: IpAddr) -> u8 {
        let ip = canonicalize_ip(ip);
        if !is_lan_ip(ip) {
            return 4;
        }
        if ip.is_loopback() {
            return if self.allow_loopback { 0 } else { 4 };
        }
        if self.local_lan_ips.contains(&ip) {
            return 0;
        }
        if self
            .local_lan_ips
            .iter()
            .any(|local| same_lan_prefix(*local, ip))
        {
            return 1;
        }
        3
    }
}

fn same_lan_prefix(a: IpAddr, b: IpAddr) -> bool {
    match (canonicalize_ip(a), canonicalize_ip(b)) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let a_octets = a.octets();
            let b_octets = b.octets();
            is_lan_ip(IpAddr::V4(a))
                && is_lan_ip(IpAddr::V4(b))
                && a_octets[0] == b_octets[0]
                && a_octets[1] == b_octets[1]
                && a_octets[2] == b_octets[2]
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let a_octets = a.octets();
            let b_octets = b.octets();
            is_lan_ip(IpAddr::V6(a))
                && is_lan_ip(IpAddr::V6(b))
                && a_octets[0..8]
                    .iter()
                    .zip(b_octets[0..8].iter())
                    .all(|(a, b)| a == b)
        }
        _ => false,
    }
}

/// Duration an identity-exchange *timeout* is remembered before the
/// peer may be re-dialed. Used for the `IdentityFailed` outcome —
/// QUIC handshake completed but the app-level identity announce
/// never arrived. See [`IDENTITY_MISMATCH_CACHE_TTL`] for the
/// authenticated-as-different-peer outcome.
///
/// Distinct from [`DIAL_FAILURE_CACHE_TTL`]: that cache is keyed by
/// [`SocketAddr`] (per-address dial failure). This one is keyed by
/// [`PeerId`] — a peer whose QUIC handshake completes but whose
/// app-level identity exchange repeatedly times out is poisoning every
/// iterative DHT lookup that names it as a candidate, regardless of
/// which of its advertised addresses we tried.
///
/// 5 minutes is a deliberate compromise:
///
/// * Long enough to suppress the in-session retry storm we observed in
///   the field (one peer dialed 6× in ~80 s during a single download,
///   each attempt eating the full 5 s identity-exchange timeout).
/// * Short enough that a peer that is genuinely recovering — e.g. an
///   operator restarting the binary onto a fixed protocol version —
///   re-enters our dial set within a coffee break, not a workday.
const IDENTITY_FAILURE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Duration an identity *mismatch* is remembered before the peer
/// may be re-dialed. Used for the `IdentityMismatch` outcome — the
/// address authenticated, but as a different peer than the routing
/// table claimed.
///
/// Longer than [`IDENTITY_FAILURE_CACHE_TTL`] (and matching
/// [`DIAL_FAILURE_CACHE_TTL`]) because a mismatch is more
/// "permanent" than a timeout: it almost always reflects stale
/// routing info that authenticated neighbours keep gossiping back
/// in FIND_NODE responses, and the underlying situation (a different
/// peer occupies the address we expected) rarely fixes itself within
/// a session. 30 minutes keeps us from paying the 5 s identity
/// timeout against the same stale entry on every iterative lookup
/// while still allowing recovery (e.g., NAT churn returning the
/// address to the original peer) within a single browsing session.
const IDENTITY_MISMATCH_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

/// DHT node representation for network operations.
///
/// The `addresses` field stores one or more typed [`MultiAddr`] values.
/// Peers may be multi-homed or reachable via NAT traversal at several
/// endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTNode {
    pub peer_id: PeerId,
    pub addresses: Vec<MultiAddr>,
    /// Type tag for each address, parallel to `addresses` by index.
    ///
    /// Defaults to empty on deserialization (legacy records or wire data from
    /// nodes that predate ADR-014). When empty, callers treat all addresses
    /// as [`AddressType::Unverified`] — a legacy peer never asserted
    /// reachability for its published sockets, so the conservative default
    /// is "publisher did not claim direct-dialability." This excludes the
    /// entries from `first_direct_dialable` (relay-candidate selection)
    /// while keeping them in the general dial priority queue as a
    /// last-resort cold-start fallback.
    ///
    /// Populated when constructing from DHT routing-table entries so
    /// consumers (e.g., saorsa-node) can inspect the address types of
    /// peers returned by `find_closest_nodes_local()`.
    #[serde(default)]
    pub address_types: Vec<AddressType>,
    /// Optional per-record metadata. In current DHT responses this may carry
    /// a marker-encoded `PublishAddressSet` sequence so newer nodes can prefer
    /// fresher address records without changing the wire shape for older nodes.
    pub distance: Option<Vec<u8>>,
    pub reliability: f64,
}

/// Witnessed close-group selection result for a target key.
///
/// `initial_closest` is the client's initial pure-XOR K lookup. Each
/// `responder_views` entry is that responder's closest-K node view after making
/// the response self-inclusive. The DHT layer owns lookup/transcript hygiene;
/// downstream protocol users own quorum, fallback, and payment policy.
#[derive(Debug, Clone)]
pub struct WitnessedCloseGroup {
    /// Target key the group was built for.
    pub target: Key,
    /// Requested close-group size.
    pub k: usize,
    /// Initial K closest responders from the client lookup, ordered by XOR.
    pub initial_closest: Vec<DHTNode>,
    /// Self-inclusive closest-K node view for each responder that replied.
    pub responder_views: Vec<ResponderView>,
}

/// One responder's self-inclusive closest-K view.
#[derive(Debug, Clone)]
pub struct ResponderView {
    /// The peer that supplied this view.
    pub responder: PeerId,
    /// Nodes in the responder's self-inclusive closest-K view.
    pub closest: Vec<DHTNode>,
}

impl DHTNode {
    /// Pair each address with its type tag.
    ///
    /// Local-scope IP addresses are always returned as [`AddressType::Lan`],
    /// even if the sender advertised a stronger tag. Other untagged entries
    /// (legacy records that predate ADR-014, or any position past the end of
    /// `address_types`) default to [`AddressType::Unverified`]. A legacy
    /// publisher never asserted reachability for these sockets, so we refuse
    /// to let them stand in for a verified `Direct` tag.
    ///
    /// The returned vec preserves the storage order from `addresses`;
    /// callers that need Relay-first ordering should pass the result to
    /// [`DhtNetworkManager::dialable_addresses_typed`] or use
    /// [`Self::addresses_by_priority`] for a pre-sorted `Vec<MultiAddr>`.
    pub fn typed_addresses(&self) -> Vec<(MultiAddr, AddressType)> {
        self.addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let advertised = self
                    .address_types
                    .get(i)
                    .copied()
                    .unwrap_or(AddressType::Unverified);
                let ty = AddressType::for_advertised_address(addr, advertised);
                (addr.clone(), ty)
            })
            .collect()
    }

    /// Addresses sorted by [`AddressType`] priority: Relay first, then
    /// Direct, Unverified, and Lan. Within each tier the original insertion
    /// order is preserved (stable sort).
    ///
    /// Use this instead of raw `addresses` whenever the caller needs to
    /// dial or pass addresses to a consumer that will try them in order
    /// (e.g., `send_message`, `reconnect_and_send`).
    pub fn addresses_by_priority(&self) -> Vec<MultiAddr> {
        let mut typed = self.typed_addresses();
        typed.sort_by_key(|(_, ty)| ty.priority());
        typed.into_iter().map(|(addr, _)| addr).collect()
    }

    /// Merge another `DHTNode`'s typed addresses into this one.
    ///
    /// Each incoming `(addr, ty)` pair is added if the address is not
    /// already present; if it is present, the type is upgraded when the
    /// incoming tag has strictly higher priority (e.g. an existing
    /// `Unverified` is promoted to `Relay` when a Relay-tagged duplicate
    /// arrives). The final list is sorted by [`AddressType::priority`]
    /// and capped at the incoming node's entry count plus the existing
    /// entries — no arbitrary truncation.
    ///
    /// Intended for the iterative FIND_NODE path in
    /// [`DhtNetworkManager::find_closest_nodes_network`]: different
    /// responders may have different views of the same peer (one saw
    /// only a connection-observed listen port, another received the
    /// peer's `PublishAddressSet` with a Relay entry), and merging all
    /// of them gives the caller the union — so `select_dial_candidates`
    /// can pick the best tier rather than being locked into whichever
    /// response happened to arrive first.
    pub fn merge_from(&mut self, other: DHTNode) {
        // Pad own address_types to match addresses length (defensive
        // against legacy entries with trailing untagged addresses).
        while self.address_types.len() < self.addresses.len() {
            self.address_types.push(AddressType::Unverified);
        }
        for (i, addr) in self.addresses.iter().enumerate() {
            self.address_types[i] =
                AddressType::for_advertised_address(addr, self.address_types[i]);
        }

        for (addr, ty) in other.typed_addresses() {
            if let Some(pos) = self.addresses.iter().position(|a| a == &addr) {
                // Already present — upgrade tag if incoming has strictly
                // higher priority (lower numeric value).
                if ty.priority() < self.address_types[pos].priority() {
                    self.address_types[pos] = ty;
                }
            } else {
                self.addresses.push(addr);
                self.address_types.push(ty);
            }
        }

        // Re-sort by priority so Relay comes first.
        let mut pairs: Vec<(MultiAddr, AddressType)> = self
            .addresses
            .drain(..)
            .zip(self.address_types.drain(..))
            .collect();
        pairs.sort_by_key(|(_, ty)| ty.priority());
        for (addr, ty) in pairs {
            self.addresses.push(addr);
            self.address_types.push(ty);
        }

        // Prefer the higher reliability score — the duplicate responder
        // may be more authoritative (e.g. closer to the peer in XOR).
        if other.reliability > self.reliability {
            self.reliability = other.reliability;
        }
        let publish_seq = dht_node_publish_seq(self).max(dht_node_publish_seq(&other));
        if publish_seq != 0 {
            self.distance = encode_publish_seq_distance(publish_seq);
        }
    }
}

const PUBLISH_SEQ_DISTANCE_MARKER: &[u8; 8] = b"PUBSEQ01";

fn encode_publish_seq_distance(seq: u64) -> Option<Vec<u8>> {
    if seq == 0 {
        return None;
    }
    let mut encoded = Vec::with_capacity(PUBLISH_SEQ_DISTANCE_MARKER.len() + 8);
    encoded.extend_from_slice(PUBLISH_SEQ_DISTANCE_MARKER);
    encoded.extend_from_slice(&seq.to_be_bytes());
    Some(encoded)
}

fn dht_node_publish_seq(node: &DHTNode) -> u64 {
    let Some(distance) = node.distance.as_deref() else {
        return 0;
    };
    if distance.len() != PUBLISH_SEQ_DISTANCE_MARKER.len() + 8
        || &distance[..PUBLISH_SEQ_DISTANCE_MARKER.len()] != PUBLISH_SEQ_DISTANCE_MARKER
    {
        return 0;
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&distance[PUBLISH_SEQ_DISTANCE_MARKER.len()..]);
    u64::from_be_bytes(bytes)
}

/// Alias for serialization compatibility
pub type SerializableDHTNode = DHTNode;

/// DHT Network Manager Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkConfig {
    /// This node's peer ID
    pub peer_id: PeerId,
    /// Network node configuration (includes DHT settings via `NodeConfig.dht_config`)
    pub node_config: NodeConfig,
    /// Request timeout for DHT operations
    pub request_timeout: Duration,
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Enable enhanced security features
    pub enable_security: bool,
    /// Trust score below which a peer is eligible for swap-out from the
    /// routing table when a better candidate is available.
    /// Default: [`AdaptiveDhtConfig::default`].
    pub swap_threshold: f64,
    /// Trust score below which automatic lookup/dial paths avoid a peer, and
    /// K-closest peers are evicted into temporary quarantine when the routing
    /// table can keep at least K peers.
    /// Default: [`AdaptiveDhtConfig::default`].
    pub quarantine_threshold: f64,
    /// Trust score required before a new peer can enter the routing table,
    /// and before a quarantined peer can be admitted again.
    /// Default: [`AdaptiveDhtConfig::default`].
    pub quarantine_readmit_threshold: f64,
}

/// DHT network operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkOperation {
    /// Find nodes closest to a key
    FindNode { key: Key },
    /// Ping a node to check availability
    Ping,
    /// Join the DHT network
    Join,
    /// Leave the DHT network gracefully
    Leave,
    /// Publish the sender's complete, typed address set. Full-replace
    /// semantics: the sender is authoritative about its own reachable
    /// addresses, and the receiver drops any address the sender omits.
    ///
    /// `seq` is a per-sender monotonic Unix-nanosecond timestamp; receivers
    /// discard messages whose `seq` is lower than the last seen from this
    /// sender. This closes the "relay-lost → relay-acquired" reorder race
    /// without a dedicated counter, and recovers across sender restarts
    /// because wall-clock time advances across reboots.
    PublishAddressSet {
        seq: u64,
        addresses: Vec<(crate::MultiAddr, AddressType)>,
    },
}

/// DHT network operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtNetworkResult {
    /// Nodes found for FIND_NODE or iterative lookup
    NodesFound {
        key: Key,
        nodes: Vec<SerializableDHTNode>,
    },
    /// Ping response
    PongReceived {
        responder: PeerId,
        latency: Duration,
    },
    /// Join confirmation
    JoinSuccess {
        assigned_key: Key,
        bootstrap_peers: usize,
    },
    /// Leave confirmation
    LeaveSuccess,
    /// The remote peer has rejected us — do not penalise their trust score
    PeerRejected,
    /// Acknowledgement of a `PublishAddressSet` request
    PublishAddressAck,
    /// Operation failed
    Error { operation: String, error: String },
}

/// DHT message envelope for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtNetworkMessage {
    /// Message ID for request/response correlation
    pub message_id: String,
    /// Source peer ID
    pub source: PeerId,
    /// Target peer ID (optional for broadcast)
    pub target: Option<PeerId>,
    /// Message type
    pub message_type: DhtMessageType,
    /// DHT operation payload (for requests)
    pub payload: DhtNetworkOperation,
    /// DHT operation result (for responses)
    pub result: Option<DhtNetworkResult>,
    /// Timestamp when message was created
    pub timestamp: u64,
    /// TTL for message forwarding
    pub ttl: u8,
    /// Hop count for routing
    pub hop_count: u8,
}

/// DHT message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessageType {
    /// Request message
    Request,
    /// Response message
    Response,
    /// Broadcast message
    Broadcast,
    /// Error response
    Error,
}

/// Main DHT Network Manager
///
/// This manager handles DHT operations (peer discovery, routing) but does
/// **not** own the transport lifecycle. The caller that supplies the
/// [`TransportHandle`](crate::transport_handle::TransportHandle) is responsible for
/// starting listeners and stopping the transport. For example, when `P2PNode` creates
/// the manager it starts transport listeners first, then starts this manager, and
/// stops transport after `DhtNetworkManager::stop()`.
pub struct DhtNetworkManager {
    /// DHT instance
    dht: Arc<RwLock<DhtCoreEngine>>,
    /// Transport handle for QUIC connections, peer registry, and message I/O
    transport: Arc<crate::transport_handle::TransportHandle>,
    /// EigenTrust engine for reputation management (optional)
    trust_engine: Option<Arc<TrustEngine>>,
    /// Configuration
    config: DhtNetworkConfig,
    /// Active DHT operations
    active_operations: Arc<Mutex<HashMap<String, DhtOperationContext>>>,
    /// Network message broadcaster
    event_tx: broadcast::Sender<DhtNetworkEvent>,
    /// Operation statistics
    stats: Arc<RwLock<DhtNetworkStats>>,
    /// Semaphore for limiting concurrent message handlers (backpressure)
    message_handler_semaphore: Arc<Semaphore>,
    /// Global semaphore limiting concurrent stale revalidation passes.
    /// Prevents a flood of revalidation attempts from consuming excessive
    /// resources when many buckets have stale peers simultaneously.
    revalidation_semaphore: Arc<Semaphore>,
    /// Per-bucket revalidation state: tracks active revalidation to prevent
    /// concurrent revalidation passes on the same bucket.
    /// Uses `parking_lot::Mutex` (not tokio) because it is never held across
    /// `.await` and its `Drop`-based guard cleanup requires synchronous locking.
    bucket_revalidation_active: Arc<parking_lot::Mutex<HashSet<usize>>>,
    /// Semaphore for limiting concurrent bucket-refresh lookups.
    ///
    /// Self-lookups and foreground/payment/user lookup calls do not use this
    /// semaphore.
    bucket_refresh_lookup_semaphore: Arc<Semaphore>,
    /// Shutdown token for background tasks
    shutdown: CancellationToken,
    /// Handle for the network event handler task
    event_handler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Handle for the periodic self-lookup background task
    self_lookup_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Handle for the periodic bucket refresh background task
    bucket_refresh_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Timestamp of the last automatic re-bootstrap attempt, guarded by a
    /// cooldown to avoid hammering bootstrap peers during transient churn.
    last_rebootstrap: tokio::sync::Mutex<Option<Instant>>,
    /// TTL-indexed cache of recently failed dial targets. Consulted by
    /// [`Self::dial_addresses`] so planned addresses that failed within
    /// the last [`DIAL_FAILURE_CACHE_TTL`] count toward the two-address
    /// dial cap without actually being re-dialed.
    dial_failure_cache: Arc<DialFailureCache>,
    /// TTL-indexed cache of peer IDs whose app-level identity exchange
    /// recently failed (timeout) or mismatched (authenticated as a
    /// different peer). Consulted by [`Self::ensure_peer_channel`] to
    /// short-circuit the dial cascade for known-broken peers before
    /// paying the [`IDENTITY_EXCHANGE_TIMEOUT`] (5 s) again — the
    /// in-session counterpart to the `last_seen`/revalidation gating
    /// that closes the cross-session eviction loop.
    identity_failure_cache: Arc<IdentityFailureCache>,
    /// In-flight dial+identity-exchange coordinator keyed by app-level
    /// `PeerId`. Collapses concurrent [`Self::ensure_peer_channel`]
    /// calls for the same peer onto a single dial so the identity
    /// handshake runs once — not once per caller racing through the
    /// window where `peer_to_channel` has not yet been populated.
    pending_peer_dials: Arc<DashMap<PeerId, broadcast::Sender<PendingDialOutcome>>>,
    /// Active FIND_NODE failure broadcaster. When one lookup observes that a
    /// peer failed while it was being queried, every other active lookup that
    /// is waiting on the same peer can stop spending an alpha slot on it.
    lookup_failures: Arc<LookupFailureCoordinator>,
}

/// Outcome of a shared dial+identity-exchange attempt, broadcast to
/// every task that joined the in-flight dial via
/// [`DhtNetworkManager::ensure_peer_channel`].
///
/// `Clone` is required because `broadcast::Sender::send` hands each
/// subscriber its own copy; that rules out embedding a [`P2PError`]
/// directly (the error type is not `Clone`). Instead we carry just
/// enough to reconstruct a representative error in
/// [`PendingDialOutcome::into_result`].
#[derive(Clone, Debug)]
enum PendingDialOutcome {
    /// QUIC handshake completed and identity exchange authenticated
    /// the remote as the expected peer.
    Connected,
    /// Every candidate address failed to dial.
    DialFailed { candidates_count: usize },
    /// The dial succeeded but identity exchange failed or timed out —
    /// the owning task has already torn down the transport channel.
    IdentityFailed { err: String },
    /// The dial succeeded but the authenticated identity disagreed
    /// with the expected `peer_id` (stale routing entry).
    IdentityMismatch { actual: PeerId },
}

impl PendingDialOutcome {
    /// Translate a shared outcome into the caller-facing [`Result`].
    ///
    /// Side effects (disconnect, trust-score penalty) are performed
    /// once by the owning task before it broadcasts the outcome, so
    /// subscribers only need to reconstruct the error.
    fn into_result(self, peer_id: &PeerId) -> Result<()> {
        let peer_hex = peer_id.to_hex();
        match self {
            Self::Connected => Ok(()),
            Self::DialFailed { candidates_count } => {
                Err(P2PError::Network(NetworkError::PeerNotFound(
                    format!(
                        "failed to dial {} at any of {} candidate address(es)",
                        peer_hex, candidates_count
                    )
                    .into(),
                )))
            }
            Self::IdentityFailed { err } => Err(P2PError::Network(NetworkError::ProtocolError(
                format!("identity exchange with {} failed: {}", peer_hex, err).into(),
            ))),
            Self::IdentityMismatch { actual } => {
                Err(P2PError::Identity(IdentityError::IdentityMismatch {
                    expected: peer_hex.into(),
                    actual: actual.to_hex().into(),
                }))
            }
        }
    }
}

/// TTL-indexed cache of [`SocketAddr`]s that recently failed to dial.
///
/// Entries are keyed by the `SocketAddr` the dialer actually attempts
/// (i.e. [`MultiAddr::dialable_socket_addr`]) so the cache hits across
/// every `AddressType` that resolves to the same endpoint.
///
/// Backed by [`DashMap`] for sharded, lock-free-in-the-common-case
/// access. A single iterative lookup may invoke `dial_addresses`
/// concurrently on several peers (alpha=3 probes plus parallel RPC
/// paths), and each invocation does two independent cache queries —
/// so the sharded map removes the single-mutex bottleneck that a
/// `Mutex<HashMap>` would impose on those paths.
///
/// Lookups perform lazy expiry: stale entries are removed on access
/// rather than by a background sweeper. A 30-minute TTL keeps the
/// hot-set small enough that lazy eviction is sufficient, even on
/// long-lived nodes.
///
/// # IP-level tier
///
/// Alongside the per-`SocketAddr` tier above, a second index keyed by
/// relay-server [`IpAddr`] collapses the dead-orphaned-session pattern: a
/// downed relay server orphans *every* MASQUE session address it ever
/// allocated, and each is a distinct `ip:port` that the per-`SocketAddr`
/// tier can only suppress after it fails its own dial. The IP tier records
/// the set of *distinct* failed relay sessions per IP and, once that set
/// reaches [`DIAL_FAILURE_IP_SUPPRESS_THRESHOLD`] within the TTL,
/// suppresses *all* remaining sessions at that IP without dialing them.
///
/// The IP tier is fed only by `AddressType::Relay` failures and only
/// suppresses relay-kind dials, so a genuinely-distinct Direct peer behind
/// a shared NAT IP is never suppressed by relay churn at that IP. Any
/// successful dial at an IP clears its IP-level suppression immediately
/// (see [`Self::clear`]) — the primary guard against a transient
/// false-positive on a shared or recovered IP.
#[derive(Debug, Default)]
struct DialFailureCache {
    /// Per-`SocketAddr` failure timestamps (the original tier).
    entries: DashMap<SocketAddr, Instant>,
    /// Per relay-server `IpAddr`: the distinct relay-session `SocketAddr`s
    /// that have failed, each with its own record time for lazy TTL
    /// expiry. Keyed on `SocketAddr` so re-dialing the *same* dead session
    /// cannot inflate the distinct count. Only `AddressType::Relay`
    /// failures populate this map.
    ip_failures: DashMap<IpAddr, HashMap<SocketAddr, Instant>>,
    /// `(publisher PeerId, relay SocketAddr)` pairs freshly re-attested by the
    /// peer that owns the address, via an applied `PublishAddressSet`, each with
    /// the time it was re-attested. While fresh (within
    /// [`DIAL_FAILURE_PUBLISH_EXEMPTION_TTL`]) a dial **to that peer** at that
    /// exact socket bypasses IP-level suppression so ADR-011 self-heal can retry
    /// it promptly — without lifting suppression for other dead sessions on the
    /// same relay IP, and without granting a bypass to any *other* peer that
    /// happens to be dialed at the same socket.
    exempt: DashMap<(PeerId, SocketAddr), Instant>,
}

impl DialFailureCache {
    fn new() -> Self {
        Self::default()
    }

    /// Canonicalize a cache key so an IPv4-mapped IPv6 socket
    /// (`[::ffff:a.b.c.d]:p`) and its bare IPv4 form (`a.b.c.d:p`) resolve to
    /// the **same** entry — matching how the rest of the dial path
    /// canonicalizes endpoint identity (see [`canonicalize_ip`]). Without
    /// this, a failure recorded under one form would neither suppress nor be
    /// cleared by the other for the same physical endpoint.
    fn canon_key(addr: SocketAddr) -> SocketAddr {
        SocketAddr::new(canonicalize_ip(addr.ip()), addr.port())
    }

    /// Whether `addr` (already canonicalized) has a live per-`SocketAddr`
    /// failure. Prunes the entry lazily if it has expired.
    fn per_addr_failed(&self, addr: &SocketAddr) -> bool {
        match self.entries.entry(*addr) {
            DashEntry::Occupied(entry) => {
                if entry.get().elapsed() < DIAL_FAILURE_CACHE_TTL {
                    true
                } else {
                    entry.remove();
                    false
                }
            }
            DashEntry::Vacant(_) => false,
        }
    }

    /// Returns true if `addr` should be skipped because it failed a dial
    /// within the last [`DIAL_FAILURE_CACHE_TTL`] (per-`SocketAddr` tier),
    /// or — for `AddressType::Relay` dials only — because its relay-server
    /// IP is currently suppressed by the IP tier. Expired entries in both
    /// tiers are removed as a side effect of the lookup so the cache stays
    /// bounded without a dedicated sweeper.
    ///
    /// Peer-agnostic check used by tests and the test-only dial-plan helper.
    /// Production dial paths use [`Self::is_failed_for_dial`] instead, so a
    /// freshly re-attested address can bypass IP suppression for its owner.
    #[cfg(test)]
    fn is_failed(&self, addr: &SocketAddr, ty: AddressType) -> bool {
        let addr = Self::canon_key(*addr);
        self.per_addr_failed(&addr)
            || (ty == AddressType::Relay && self.ip_is_suppressed(&addr.ip()))
    }

    /// Like [`Self::is_failed`], but for a dial to a known `peer`: a relay
    /// socket that `peer` itself just re-attested via a fresh
    /// `PublishAddressSet` bypasses IP-level suppression (ADR-011 self-heal).
    ///
    /// An individual per-address failure still suppresses (checked first), and
    /// the exemption is keyed by `(peer, socket)` so it never lets a *different*
    /// peer dialed at the same socket skip suppression. Stale exemptions are
    /// pruned on read; a fresh one is left in place so repeated checks (the
    /// dial-plan predicate and the dial itself) stay consistent across the
    /// window.
    fn is_failed_for_dial(&self, peer: &PeerId, addr: &SocketAddr, ty: AddressType) -> bool {
        let addr = Self::canon_key(*addr);
        if self.per_addr_failed(&addr) {
            return true;
        }
        if ty != AddressType::Relay || !self.ip_is_suppressed(&addr.ip()) {
            return false;
        }
        !self.has_fresh_publish_exemption(peer, &addr)
    }

    /// Whether `peer` holds a fresh publish exemption for the (already
    /// canonicalized) relay `addr`. Prunes a stale exemption on read.
    fn has_fresh_publish_exemption(&self, peer: &PeerId, addr: &SocketAddr) -> bool {
        match self.exempt.entry((*peer, *addr)) {
            DashEntry::Occupied(entry) => {
                if entry.get().elapsed() < DIAL_FAILURE_PUBLISH_EXEMPTION_TTL {
                    true
                } else {
                    entry.remove();
                    false
                }
            }
            DashEntry::Vacant(_) => false,
        }
    }

    /// Returns true if `ip` has at least
    /// [`DIAL_FAILURE_IP_SUPPRESS_THRESHOLD`] distinct relay sessions that
    /// failed within the TTL. Expired sessions are pruned on access, and
    /// an IP whose set empties is removed entirely, so the IP tier stays
    /// bounded by the same lazy-expiry discipline as the per-addr tier.
    ///
    /// Holds the shard write lock across the prune and the count, so a
    /// concurrent [`Self::record_failure`] or [`Self::clear`] cannot race
    /// the threshold decision.
    fn ip_is_suppressed(&self, ip: &IpAddr) -> bool {
        match self.ip_failures.entry(*ip) {
            DashEntry::Occupied(mut entry) => {
                let sessions = entry.get_mut();
                sessions.retain(|_, recorded| recorded.elapsed() < DIAL_FAILURE_CACHE_TTL);
                if sessions.is_empty() {
                    entry.remove();
                    false
                } else {
                    sessions.len() >= DIAL_FAILURE_IP_SUPPRESS_THRESHOLD
                }
            }
            DashEntry::Vacant(_) => false,
        }
    }

    /// Record a failed dial of `addr`. Always updates the per-`SocketAddr`
    /// tier; additionally registers the session against its relay-server IP
    /// when `ty` is [`AddressType::Relay`], so enough distinct dead
    /// sessions at one IP trip IP-level suppression.
    fn record_failure(&self, addr: SocketAddr, ty: AddressType) {
        let addr = Self::canon_key(addr);
        let now = Instant::now();
        self.entries.insert(addr, now);
        // No need to clear any publish exemption here: `is_failed_for_dial`
        // checks the per-address failure first, so a fresh failure suppresses
        // the socket regardless of an outstanding exemption (which expires on
        // its own short TTL).
        if ty == AddressType::Relay {
            let mut sessions = self.ip_failures.entry(addr.ip()).or_default();
            let newly_distinct = sessions.insert(addr, now).is_none();
            let count = sessions.len();
            drop(sessions);
            // Log once — when a newly-distinct failed session first brings the
            // IP to the suppression threshold — so traces can tell a single
            // skipped address apart from a fully suppressed relay IP. (The
            // count may include not-yet-expired entries; `ip_is_suppressed`
            // prunes on read, so this is best-effort observability.)
            if newly_distinct && count == DIAL_FAILURE_IP_SUPPRESS_THRESHOLD {
                debug!(
                    "DialFailureCache: relay IP {} reached the suppression threshold \
                     ({} distinct failed sessions, no intervening success); suppressing \
                     all further relay dials to this IP for up to {:?}",
                    addr.ip(),
                    DIAL_FAILURE_IP_SUPPRESS_THRESHOLD,
                    DIAL_FAILURE_CACHE_TTL
                );
            }
        }
    }

    /// Clear the cached failure for `addr` after a successful dial so
    /// the next retry is not suppressed by a stale entry. Cheap when
    /// the address is absent (typical success path).
    ///
    /// Also drops the entire IP-level failure set for `addr.ip()`: a
    /// success at an IP proves the relay server (or a live peer behind a
    /// shared IP) is reachable, so any IP-level suppression must lift
    /// immediately. Type-agnostic on purpose — a Direct success behind a
    /// shared NAT IP re-admits relay sessions there too.
    fn clear(&self, addr: &SocketAddr) {
        let addr = Self::canon_key(*addr);
        self.entries.remove(&addr);
        self.ip_failures.remove(&addr.ip());
    }

    /// Mark `addr` as freshly re-attested by `peer` (its owner) via an applied
    /// `PublishAddressSet` (ADR-011 self-heal).
    ///
    /// Clears the address's own per-address failure and grants `(peer, addr)` a
    /// short exemption from IP-level suppression (see
    /// [`DIAL_FAILURE_PUBLISH_EXEMPTION_TTL`]) so the exact reclaimed stable port
    /// is retried promptly rather than waiting out the IP-tier TTL. Deliberately
    /// does NOT touch the IP-level failure set: a re-publish proves the owner
    /// re-attested this address, not that *this* node can reach the relay IP, so
    /// other dead sessions on the same IP stay suppressed. Keying the exemption
    /// by peer means only a dial *to `peer`* benefits — a different peer dialed
    /// at the same socket is unaffected. Stale exemptions are pruned here to keep
    /// the map bounded.
    fn note_republished(&self, peer: &PeerId, addr: &SocketAddr) {
        let addr = Self::canon_key(*addr);
        self.entries.remove(&addr);
        self.exempt
            .retain(|_, at| at.elapsed() < DIAL_FAILURE_PUBLISH_EXEMPTION_TTL);
        self.exempt.insert((*peer, addr), Instant::now());
    }
}

/// ADR-011 self-heal: when a newer authoritative `PublishAddressSet` from
/// `publisher` is applied, clear any stale dial-failure suppression for its
/// freshly published socket addresses. A recovered address — for example a relay
/// that now hands a reconnecting peer back its previous stable port — is
/// otherwise kept suppressed for up to [`DIAL_FAILURE_CACHE_TTL`] even though the
/// owner has just re-attested it. The exemption it grants is keyed by
/// `(publisher, socket)` so only a dial *to that publisher* benefits. Returns the
/// number of addresses cleared; a no-op when the publish was not applied (stale
/// or duplicate sequence).
fn clear_dial_failures_for_published(
    cache: &DialFailureCache,
    publisher: &PeerId,
    applied: bool,
    addresses: &[(crate::MultiAddr, AddressType)],
) -> usize {
    if !applied {
        return 0;
    }
    let mut cleared = 0;
    for (addr, _ty) in addresses {
        if let Some(socket_addr) = addr.dialable_socket_addr() {
            // Clears this address's own failure and grants (publisher, socket) a
            // short exemption from IP suppression — but never lifts IP-level relay
            // suppression for other sessions (that needs a real dial success).
            cache.note_republished(publisher, &socket_addr);
            cleared += 1;
        }
    }
    cleared
}

/// TTL-indexed cache of [`PeerId`]s whose identity exchange recently
/// failed (timeout) or mismatched (authenticated as a different peer).
///
/// Distinct from [`DialFailureCache`] which only suppresses re-dials of
/// individual unreachable [`SocketAddr`]s. This cache fires before the
/// dial coordinator in [`DhtNetworkManager::ensure_peer_channel`] and
/// short-circuits the entire `peer → address-list → dial → 5 s
/// wait_for_peer_identity` cascade when we already learned that
/// app-level identity exchange with this peer is currently broken
/// (e.g., older-protocol nodes whose QUIC handshake completes but whose
/// identity announce never arrives) or that the peer at any of the
/// candidate addresses authenticates as someone else.
///
/// The stored value is an *expiry* [`Instant`] — the wall-clock
/// moment at which the entry stops suppressing re-dials. Storing the
/// expiry (rather than the recording time) lets each outcome carry
/// its own TTL: see [`IDENTITY_FAILURE_CACHE_TTL`] (5 min, timeout)
/// vs [`IDENTITY_MISMATCH_CACHE_TTL`] (30 min, mismatch).
///
/// Backed by [`DashMap`] for sharded, lock-free-in-the-common-case
/// access — every iterative DHT lookup invokes this on the hot path,
/// so a single mutex would bottleneck. Lookups perform lazy expiry:
/// stale entries are removed on access rather than by a sweeper.
#[derive(Debug, Default)]
struct IdentityFailureCache {
    /// `peer_id → expires_at` (wall-clock instant at which the
    /// suppression lifts).
    entries: DashMap<PeerId, Instant>,
}

impl IdentityFailureCache {
    fn new() -> Self {
        Self::default()
    }

    /// Returns true if `peer_id` is currently within an active
    /// suppression window. Expired entries are removed as a side
    /// effect of the lookup so the cache stays bounded without a
    /// dedicated sweeper.
    ///
    /// The `DashMap::entry` API holds a single shard write lock across
    /// the expiry-check and the `remove`, so a concurrent
    /// [`Self::record_failure`] / [`Self::record_mismatch`] cannot
    /// slip a fresh entry in between the check and the eviction.
    /// Atomicity is guaranteed locally here rather than inferred from
    /// the external `pending_peer_dials` coordinator — future
    /// call-site changes can't reintroduce the race.
    fn is_failed(&self, peer_id: &PeerId) -> bool {
        match self.entries.entry(*peer_id) {
            DashEntry::Occupied(entry) => {
                if Instant::now() < *entry.get() {
                    true
                } else {
                    entry.remove();
                    false
                }
            }
            DashEntry::Vacant(_) => false,
        }
    }

    /// Record an `IdentityFailed` outcome — QUIC handshake completed
    /// but identity exchange timed out. Suppressed for
    /// [`IDENTITY_FAILURE_CACHE_TTL`].
    fn record_failure(&self, peer_id: PeerId) {
        self.entries
            .insert(peer_id, Instant::now() + IDENTITY_FAILURE_CACHE_TTL);
    }

    /// Record an `IdentityMismatch` outcome — the peer at the dialed
    /// address authenticated, but as a different peer than expected.
    /// Suppressed for [`IDENTITY_MISMATCH_CACHE_TTL`] (longer than a
    /// timeout because mismatches reflect stale routing info that
    /// rarely fixes itself within a session).
    fn record_mismatch(&self, peer_id: PeerId) {
        self.entries
            .insert(peer_id, Instant::now() + IDENTITY_MISMATCH_CACHE_TTL);
    }

    /// Clear the cached failure for `peer_id` after a successful
    /// identity exchange so the next dial is not suppressed by a stale
    /// entry. Cheap when the peer is absent (typical success path).
    fn clear(&self, peer_id: &PeerId) {
        self.entries.remove(peer_id);
    }
}

/// DHT operation context
///
/// Uses oneshot channel for response delivery to eliminate TOCTOU races.
/// The sender is stored here; the receiver is held by wait_for_response().
struct DhtOperationContext {
    /// Operation type
    operation: DhtNetworkOperation,
    /// Target app-level peer ID (authentication identity, not transport channel)
    peer_id: PeerId,
    /// Start time
    started_at: Instant,
    /// Timeout
    timeout: Duration,
    /// Contacted app-level peer IDs (for response source validation)
    contacted_nodes: Vec<PeerId>,
    /// Oneshot sender for delivering the response
    /// None if response already sent (channel consumed)
    response_tx: Option<oneshot::Sender<DhtResponseEnvelope>>,
}

impl std::fmt::Debug for DhtOperationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtOperationContext")
            .field("operation", &self.operation)
            .field("peer_id", &self.peer_id)
            .field("started_at", &self.started_at)
            .field("timeout", &self.timeout)
            .field("contacted_nodes", &self.contacted_nodes)
            .field("response_tx", &self.response_tx.is_some())
            .finish()
    }
}

#[derive(Debug)]
struct DhtResponseEnvelope {
    result: DhtNetworkResult,
    transport_source: Option<MultiAddr>,
}

/// DHT network events
#[derive(Debug, Clone)]
pub enum DhtNetworkEvent {
    /// New DHT peer discovered
    PeerDiscovered { peer_id: PeerId, dht_key: Key },
    /// DHT peer disconnected
    PeerDisconnected { peer_id: PeerId },
    /// The K-closest peers to this node's own address have changed.
    ///
    /// Emitted after routing table mutations (peer added, removed, or evicted)
    /// when the set of K-closest peers differs from the previous snapshot.
    /// Callers implementing replication can use this to detect close-group
    /// topology changes and trigger neighbor-sync or responsibility
    /// recomputation.
    KClosestPeersChanged {
        /// K-closest peer IDs before the mutation.
        old: Vec<PeerId>,
        /// K-closest peer IDs after the mutation.
        new: Vec<PeerId>,
    },
    /// New peer added to the routing table.
    PeerAdded { peer_id: PeerId },
    /// Peer removed from the routing table (swap-out, eviction, or departure).
    PeerRemoved { peer_id: PeerId },
    /// Routing table populated after bootstrap peer discovery.
    ///
    /// Emitted when the DHT routing table is populated with peers from the
    /// bootstrap process. This is an intermediate milestone — the node has
    /// outbound connectivity and can issue DHT queries, but it has **not**
    /// yet classified its own reachability or acquired a relay if private.
    ///
    /// For the "fully addressable" signal, wait for [`Self::BootstrapComplete`].
    RoutingTableReady { num_peers: usize },
    /// Bootstrap fully complete: node is classified and addressable.
    ///
    /// Emitted after the ADR-014 reachability classifier has run and, if
    /// needed, a relay has been acquired. When a consumer sees this event
    /// the node's published DHT self-record is accurate (either a verified
    /// Direct address or a relay-allocated address).
    BootstrapComplete { num_peers: usize },
    /// DHT operation completed
    OperationCompleted {
        operation: String,
        success: bool,
        duration: Duration,
    },
    /// DHT network status changed
    NetworkStatusChanged {
        connected_peers: usize,
        routing_table_size: usize,
    },
    /// Error occurred
    Error { error: String },
}

/// DHT network statistics
#[derive(Debug, Clone, Default)]
pub struct DhtNetworkStats {
    /// Total operations performed
    pub total_operations: u64,
    /// Successful operations
    pub successful_operations: u64,
    /// Failed operations
    pub failed_operations: u64,
    /// Average operation latency
    pub avg_operation_latency: Duration,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Connected transport peers (all authenticated peers, including Client-mode)
    pub connected_peers: usize,
    /// DHT routing table size (Node-mode peers only)
    pub routing_table_size: usize,
}

/// RAII guard that removes a bucket index from the per-bucket revalidation set
/// on drop, ensuring the slot is released even if the revalidation panics or
/// returns early.
struct BucketRevalidationGuard {
    active: Arc<parking_lot::Mutex<HashSet<usize>>>,
    bucket_idx: usize,
}

impl Drop for BucketRevalidationGuard {
    fn drop(&mut self) {
        self.active.lock().remove(&self.bucket_idx);
    }
}

/// Quorum parameters for the iterative FIND_NODE aggregator.
///
/// Among the closest-XOR responders that reported a given subject, a
/// consensus of `QUORUM_THRESHOLD` out of the top `QUORUM_TOP_N`
/// agreeing responders wins outright. A single close-XOR adversary
/// cannot poison the lookup so long as two of its XOR neighbours are
/// honest and agree.
const QUORUM_TOP_N: usize = 3;
const QUORUM_THRESHOLD: usize = 2;

/// All reports collected for a single subject peer during an iterative
/// FIND_NODE lookup, keyed by responder peer_id. Grows as responses
/// arrive and feeds [`compute_winner`].
type SubjectReports = HashMap<PeerId, DHTNode>;

#[derive(Debug, Default)]
struct FindNodeLookupTranscript {
    responder_views: HashMap<PeerId, Vec<DHTNode>>,
}

impl FindNodeLookupTranscript {
    fn record_responder_view(&mut self, responder: PeerId, closest: Vec<DHTNode>) {
        self.responder_views.insert(responder, closest);
    }

    fn take_responder_view(&mut self, responder: &PeerId) -> Option<Vec<DHTNode>> {
        self.responder_views.remove(responder)
    }
}

#[derive(Debug)]
struct FindNodeLookupOutcome {
    closest_nodes: Vec<DHTNode>,
    transcript: FindNodeLookupTranscript,
}

#[derive(Debug)]
struct LookupFailureCoordinator {
    tx: broadcast::Sender<PeerId>,
}

impl LookupFailureCoordinator {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(LOOKUP_FAILURE_BROADCAST_CAPACITY);
        Self { tx }
    }

    fn subscribe(&self) -> broadcast::Receiver<PeerId> {
        self.tx.subscribe()
    }

    fn notify_failed(&self, peer_id: PeerId) {
        // No active subscribers is the common case. `send` only fails when
        // receiver_count == 0, so ignore the returned peer id.
        let _ = self.tx.send(peer_id);
    }
}

/// Per-lookup state for peers in an iterative FIND_NODE query.
///
/// Mirrors rust-libp2p's closest-peer iterator model: peers move from
/// "not contacted" (absence from the map) to `Waiting`, then to a final
/// outcome. Final states are not selected again by the same lookup, so a
/// failed or abandoned alpha probe cannot be reintroduced by later gossip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupPeerState {
    Waiting,
    Succeeded,
    Failed,
    Unresponsive,
}

#[derive(Debug, Default)]
struct LookupPeerStates {
    states: HashMap<PeerId, LookupPeerState>,
}

impl LookupPeerStates {
    fn mark_waiting(&mut self, peer_id: PeerId) {
        self.states.insert(peer_id, LookupPeerState::Waiting);
    }

    fn mark_succeeded(&mut self, peer_id: PeerId) {
        self.states.insert(peer_id, LookupPeerState::Succeeded);
    }

    fn mark_failed(&mut self, peer_id: PeerId) {
        self.states.insert(peer_id, LookupPeerState::Failed);
    }

    fn mark_unresponsive(&mut self, peer_id: PeerId) {
        self.states.insert(peer_id, LookupPeerState::Unresponsive);
    }

    fn is_contactable(&self, peer_id: &PeerId) -> bool {
        !self.states.contains_key(peer_id)
    }

    fn state(&self, peer_id: &PeerId) -> Option<LookupPeerState> {
        self.states.get(peer_id).copied()
    }
}

/// Best (lowest-numeric) [`AddressType::priority`] across a node's
/// address tags. `u8::MAX` when the address list is empty.
///
/// Used as the fallback tie-breaker in [`compute_winner`]: when no
/// quorum exists and two responders are at the same XOR distance,
/// the one whose best tag tier is stronger wins.
fn best_tier_priority(node: &DHTNode) -> u8 {
    node.typed_addresses()
        .iter()
        .map(|(_, t)| t.priority())
        .min()
        .unwrap_or(u8::MAX)
}

/// Canonical signature of a report's address set, used to group
/// responders that agree. Independent of insertion order — addresses
/// are sorted by their string form, and each tag is reduced to its
/// priority byte so [`AddressType`] does not need a [`Hash`] impl.
fn report_signature(node: &DHTNode) -> Vec<(MultiAddr, u8)> {
    let mut sig: Vec<(MultiAddr, u8)> = node
        .typed_addresses()
        .into_iter()
        .map(|(addr, t)| (addr, t.priority()))
        .collect();
    sig.sort_by_key(|a| a.0.to_string());
    sig
}

/// Compute the current winning report for a subject peer given all
/// reports received so far from different responders.
///
/// Rules (applied in order):
///
///   1. **Self-report** — if the subject peer itself responded, its
///      report is authoritative.
///   2. **Newest publish** — any report carrying the highest non-zero
///      `PublishAddressSet` sequence wins. That sequence originated from
///      the subject peer's authenticated publish path and lets a newer
///      direct-only or re-relayed record displace stale relay gossip.
///   3. **Quorum** — among the top `QUORUM_TOP_N` closest-XOR
///      responders, if `QUORUM_THRESHOLD`+ agree on the address set
///      (same [`report_signature`]), their consensus wins. One close
///      adversary cannot poison the result when 2+ honest neighbours
///      agree.
///   4. **Fallback** — the closest-XOR responder wins. On an XOR tie
///      the one whose best tag tier is stronger breaks it.
///
/// Returns `None` only when `reports` is empty.
fn compute_winner<'a>(
    subject_id: &PeerId,
    reports: &'a SubjectReports,
) -> Option<(PeerId, &'a DHTNode)> {
    if reports.is_empty() {
        return None;
    }

    // Rule 1: self-report locks in.
    if let Some(node) = reports.get(subject_id) {
        return Some((*subject_id, node));
    }

    // Sort all responders by XOR distance to subject (primary), then by
    // best-tier-priority (secondary, for stable tie-break).
    let mut by_dist: Vec<(PeerId, &DHTNode, Key, u8)> = reports
        .iter()
        .map(|(rid, node)| {
            (
                *rid,
                node,
                rid.xor_distance(subject_id),
                best_tier_priority(node),
            )
        })
        .collect();
    by_dist.sort_by(|a, b| a.2.cmp(&b.2).then(a.3.cmp(&b.3)));

    // Rule 2: newest authoritative publish sequence wins. This keeps stale
    // third-party relay records from beating a newer direct-only or re-relayed
    // self-record during an iterative lookup.
    if let Some((rid, node, _, _)) = by_dist
        .iter()
        .filter(|(_, node, _, _)| dht_node_publish_seq(node) != 0)
        .max_by(|a, b| {
            dht_node_publish_seq(a.1)
                .cmp(&dht_node_publish_seq(b.1))
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| b.3.cmp(&a.3))
        })
    {
        return Some((*rid, *node));
    }

    // Rule 3: quorum among top-N.
    let top_n = &by_dist[..by_dist.len().min(QUORUM_TOP_N)];
    if top_n.len() >= QUORUM_THRESHOLD {
        let mut buckets: HashMap<Vec<(MultiAddr, u8)>, Vec<PeerId>> = HashMap::new();
        for (rid, node, _, _) in top_n {
            buckets
                .entry(report_signature(node))
                .or_default()
                .push(*rid);
        }
        if let Some(group) = buckets.values().find(|g| g.len() >= QUORUM_THRESHOLD)
            && let Some(winner_rid) = group
                .iter()
                .copied()
                .min_by_key(|rid| rid.xor_distance(subject_id))
        {
            // Pick the XOR-closest consensus member as the representative.
            // All consensus reports have the same address set by
            // construction, so any pick is behaviourally equivalent;
            // choosing closest makes the result deterministic.
            return reports.get(&winner_rid).map(|node| (winner_rid, node));
        }
    }

    // Rule 4: fallback — closest-XOR (then strongest-tier) responder.
    let (rid, node, _, _) = by_dist.first()?;
    Some((*rid, *node))
}

fn prefer_lookup_record(candidate: &DHTNode, existing: &DHTNode) -> bool {
    let candidate_seq = dht_node_publish_seq(candidate);
    let existing_seq = dht_node_publish_seq(existing);
    candidate_seq > existing_seq
        || (candidate_seq == existing_seq
            && best_tier_priority(candidate) < best_tier_priority(existing))
}

/// Refresh final lookup results with the per-subject winners observed during
/// the lookup.
///
/// `best_nodes` is built from the candidate that was queried at the time it
/// entered an alpha batch. Later responses in the same lookup may carry a
/// fresher sequence-bearing self-record for that same peer. Before returning
/// results to callers, replace every returned peer with the current
/// [`compute_winner`] output so a stale candidate copy cannot leak out to
/// clients that discovered the peer purely through this lookup.
fn apply_lookup_report_winners(
    best_nodes: Vec<DHTNode>,
    subject_reports: &HashMap<PeerId, SubjectReports>,
    key: &Key,
    count: usize,
) -> Vec<DHTNode> {
    let mut by_peer: HashMap<PeerId, DHTNode> = HashMap::new();

    for node in best_nodes {
        let node = subject_reports
            .get(&node.peer_id)
            .and_then(|reports| compute_winner(&node.peer_id, reports))
            .map(|(_, winner)| winner.clone())
            .unwrap_or(node);

        match by_peer.entry(node.peer_id) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if prefer_lookup_record(&node, entry.get()) {
                    *entry.get_mut() = node;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(node);
            }
        }
    }

    let mut refreshed: Vec<DHTNode> = by_peer.into_values().collect();
    refreshed.sort_by(|a, b| DhtNetworkManager::compare_node_distance(a, b, key));
    refreshed.truncate(count);
    refreshed
}

fn merge_witnessed_node(nodes: &mut HashMap<PeerId, DHTNode>, node: DHTNode) {
    match nodes.entry(node.peer_id) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.get_mut().merge_from(node);
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(node);
        }
    }
}

fn compare_peer_distance(a: &PeerId, b: &PeerId, key: &Key) -> std::cmp::Ordering {
    let target_key = DhtKey::from_bytes(*key);
    a.distance(&target_key)
        .cmp(&b.distance(&target_key))
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

fn sort_dedup_witnessed_nodes(mut nodes: Vec<DHTNode>, key: &Key, count: usize) -> Vec<DHTNode> {
    let mut by_peer: HashMap<PeerId, DHTNode> = HashMap::new();
    for node in nodes.drain(..) {
        merge_witnessed_node(&mut by_peer, node);
    }

    let mut deduped: Vec<DHTNode> = by_peer.into_values().collect();
    deduped.sort_by(|a, b| compare_peer_distance(&a.peer_id, &b.peer_id, key));
    deduped.truncate(count);
    deduped
}

fn self_inclusive_responder_view(
    responder: PeerId,
    closest: Vec<DHTNode>,
    known_nodes: &HashMap<PeerId, DHTNode>,
    key: &Key,
    count: usize,
) -> Vec<DHTNode> {
    let mut view_nodes: HashMap<PeerId, DHTNode> = HashMap::new();
    for node in closest {
        merge_witnessed_node(&mut view_nodes, node);
    }

    if let Some(responder_node) = known_nodes.get(&responder) {
        merge_witnessed_node(&mut view_nodes, responder_node.clone());
    }

    let mut nodes: Vec<DHTNode> = view_nodes.into_values().collect();
    nodes.sort_by(|a, b| compare_peer_distance(&a.peer_id, &b.peer_id, key));
    nodes.truncate(count);
    nodes
}

fn build_witnessed_close_group(
    key: &Key,
    count: usize,
    view_count: usize,
    initial_closest: Vec<DHTNode>,
    responder_node_views: Vec<(PeerId, Vec<DHTNode>)>,
) -> WitnessedCloseGroup {
    let initial_closest = sort_dedup_witnessed_nodes(initial_closest, key, count);

    let mut known_nodes: HashMap<PeerId, DHTNode> = HashMap::new();
    for node in &initial_closest {
        merge_witnessed_node(&mut known_nodes, node.clone());
    }
    for (_, closest) in &responder_node_views {
        for node in closest {
            merge_witnessed_node(&mut known_nodes, node.clone());
        }
    }

    let mut responder_views = Vec::with_capacity(responder_node_views.len());

    for (responder, closest) in responder_node_views {
        let closest =
            self_inclusive_responder_view(responder, closest, &known_nodes, key, view_count);
        responder_views.push(ResponderView { responder, closest });
    }

    responder_views.sort_by(|a, b| compare_peer_distance(&a.responder, &b.responder, key));

    WitnessedCloseGroup {
        target: *key,
        k: count,
        initial_closest,
        responder_views,
    }
}

fn split_witnessed_transcript_views(
    initial_closest: &[DHTNode],
    transcript: &mut FindNodeLookupTranscript,
) -> (Vec<(PeerId, Vec<DHTNode>)>, Vec<DHTNode>) {
    let mut responder_node_views = Vec::with_capacity(initial_closest.len());
    let mut missing_responders = Vec::new();

    for node in initial_closest {
        match transcript.take_responder_view(&node.peer_id) {
            Some(view) => responder_node_views.push((node.peer_id, view)),
            None => missing_responders.push(node.clone()),
        }
    }

    (responder_node_views, missing_responders)
}

impl DhtNetworkManager {
    fn new_from_components(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<TrustEngine>>,
        config: DhtNetworkConfig,
    ) -> Result<Self> {
        let mut dht_instance = DhtCoreEngine::new(
            config.peer_id,
            config.node_config.dht_config.k_value,
            config.node_config.allow_loopback,
            config.swap_threshold,
        )
        .map_err(|e| P2PError::Dht(DhtError::OperationFailed(e.to_string().into())))?;
        dht_instance
            .set_trust_quarantine_thresholds(
                config.quarantine_threshold,
                config.quarantine_readmit_threshold,
            )
            .map_err(|e| P2PError::Dht(DhtError::OperationFailed(e.to_string().into())))?;

        // Propagate IP diversity settings from the node config into the DHT
        // core engine so diversity overrides take effect on routing table
        // insertion, not just bootstrap discovery.
        if let Some(diversity) = &config.node_config.diversity_config {
            dht_instance.set_ip_diversity_config(diversity.clone());
        }

        let dht = Arc::new(RwLock::new(dht_instance));

        let (event_tx, _) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let message_handler_semaphore = Arc::new(Semaphore::new(
            config
                .max_concurrent_operations
                .max(MIN_CONCURRENT_OPERATIONS),
        ));

        Ok(Self {
            dht,
            transport,
            trust_engine,
            config,
            active_operations: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            stats: Arc::new(RwLock::new(DhtNetworkStats::default())),
            message_handler_semaphore,
            revalidation_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REVALIDATIONS)),
            bucket_revalidation_active: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            bucket_refresh_lookup_semaphore: Arc::new(Semaphore::new(
                MAX_CONCURRENT_BUCKET_REFRESH_LOOKUPS,
            )),
            shutdown: CancellationToken::new(),
            event_handler_handle: Arc::new(RwLock::new(None)),
            self_lookup_handle: Arc::new(RwLock::new(None)),
            bucket_refresh_handle: Arc::new(RwLock::new(None)),
            last_rebootstrap: tokio::sync::Mutex::new(None),
            dial_failure_cache: Arc::new(DialFailureCache::new()),
            identity_failure_cache: Arc::new(IdentityFailureCache::new()),
            pending_peer_dials: Arc::new(DashMap::new()),
            lookup_failures: Arc::new(LookupFailureCoordinator::new()),
        })
    }

    /// Kademlia K parameter — bucket size and lookup count.
    /// Get the configured Kademlia K value (bucket size / close group size).
    pub fn k_value(&self) -> usize {
        self.config.node_config.dht_config.k_value
    }

    /// Handle a FindNode request by returning the closest nodes from the local routing table.
    async fn handle_find_node_request(
        &self,
        key: &Key,
        requester: &PeerId,
    ) -> Result<DhtNetworkResult> {
        trace!(
            "FIND_NODE: resolving closer nodes for key {}",
            hex::encode(key)
        );

        let candidate_nodes = self.find_closest_nodes_local(key, self.k_value()).await;
        let closer_nodes = Self::filter_response_nodes(candidate_nodes, requester);

        // Log addresses being returned in FIND_NODE response
        for node in &closer_nodes {
            let addrs: Vec<String> = node.addresses.iter().map(|a| format!("{}", a)).collect();
            debug!(
                "FIND_NODE response: peer={} addresses={:?}",
                node.peer_id.to_hex(),
                addrs
            );
        }

        Ok(DhtNetworkResult::NodesFound {
            key: *key,
            nodes: closer_nodes,
        })
    }

    /// Create a new DHT Network Manager using an existing transport handle.
    ///
    /// The caller is responsible for the transport lifecycle and must stop
    /// transport after stopping this manager.
    pub async fn new(
        transport: Arc<crate::transport_handle::TransportHandle>,
        trust_engine: Option<Arc<TrustEngine>>,
        mut config: DhtNetworkConfig,
    ) -> Result<Self> {
        let transport_app_peer_id = transport.peer_id();
        if config.peer_id == PeerId::from_bytes([0u8; 32]) {
            config.peer_id = transport_app_peer_id;
        } else if config.peer_id != transport_app_peer_id {
            warn!(
                "DHT config peer_id ({}) differs from transport peer_id ({}); using config value",
                config.peer_id.to_hex(),
                transport_app_peer_id.to_hex()
            );
        }

        info!(
            "Creating attached DHT Network Manager for peer: {}",
            config.peer_id.to_hex()
        );
        let manager = Self::new_from_components(transport, trust_engine, config)?;

        info!("Attached DHT Network Manager created successfully");
        Ok(manager)
    }

    /// Start the DHT network manager.
    ///
    /// This manager does not manage the transport lifecycle. If transport listeners
    /// are already running, startup reconciles currently connected peers after event
    /// subscription is established.
    ///
    /// Note: This method requires `self` to be wrapped in an `Arc` so that
    /// background tasks can hold references to the manager.
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        info!("Starting DHT Network Manager...");

        // Subscribe to transport events before DHT background work starts.
        self.start_network_event_handler(Arc::clone(self)).await?;

        // Reconcile peers that may have connected before event subscription.
        self.reconcile_connected_peers().await;

        // Spawn periodic maintenance background tasks.
        self.spawn_self_lookup_task().await;
        self.spawn_bucket_refresh_task().await;

        info!("DHT Network Manager started successfully");
        Ok(())
    }

    /// Spawn the periodic self-lookup background task.
    ///
    /// Runs an iterative FIND_NODE(self) at a randomised interval between
    /// [`SELF_LOOKUP_INTERVAL_MIN`] and [`SELF_LOOKUP_INTERVAL_MAX`] to keep
    /// the close neighbourhood fresh and discover newly joined peers.
    async fn spawn_self_lookup_task(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let shutdown = self.shutdown.clone();
        let handle_slot = Arc::clone(&self.self_lookup_handle);

        let handle = tokio::spawn(async move {
            loop {
                let interval =
                    Self::randomised_interval(SELF_LOOKUP_INTERVAL_MIN, SELF_LOOKUP_INTERVAL_MAX);

                tokio::select! {
                    () = tokio::time::sleep(interval) => {}
                    () = shutdown.cancelled() => break,
                }

                // Wrap the work in a select so shutdown cancels in-progress
                // operations rather than waiting for them to complete. Without
                // this, iterative DHT lookups under active traffic can block
                // for minutes, preventing the task from noticing shutdown.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = async {
                        if let Err(e) = this.trigger_self_lookup().await {
                            warn!("Periodic self-lookup failed: {e}");
                        }
                        this.revalidate_stale_k_closest().await;
                        this.maybe_rebootstrap().await;
                    } => {}
                }
            }
        });
        *handle_slot.write().await = Some(handle);
    }

    /// Spawn the periodic bucket refresh background task.
    ///
    /// At a randomised interval between [`BUCKET_REFRESH_INTERVAL_MIN`] and
    /// [`BUCKET_REFRESH_INTERVAL_MAX`], selects the highest-debt buckets and
    /// performs a FIND_NODE lookup for a random key in each selected bucket's
    /// range. This keeps bucket refresh continuous while the per-pass budget
    /// limits background lookup volume.
    async fn spawn_bucket_refresh_task(self: &Arc<Self>) {
        let this = Arc::clone(self);
        let shutdown = self.shutdown.clone();
        let handle_slot = Arc::clone(&self.bucket_refresh_handle);

        let handle = tokio::spawn(async move {
            loop {
                let interval = Self::randomised_interval(
                    BUCKET_REFRESH_INTERVAL_MIN,
                    BUCKET_REFRESH_INTERVAL_MAX,
                );

                tokio::select! {
                    () = tokio::time::sleep(interval) => {}
                    () = shutdown.cancelled() => break,
                }

                // Wrap the work in a select so shutdown cancels in-progress
                // lookups rather than waiting for all buckets to be refreshed.
                let shutdown_ref = &shutdown;
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = async {
                        match Arc::clone(&this.bucket_refresh_lookup_semaphore).try_acquire_owned()
                        {
                            Ok(_maintenance_lookup_permit) => {
                                let refresh_candidates = this
                                    .dht
                                    .read()
                                    .await
                                    .bucket_refresh_candidates()
                                    .await;

                                let candidate_count = refresh_candidates.len();
                                let refresh_indices =
                                    Self::select_bucket_refresh_indices(refresh_candidates);
                                let refresh_count = refresh_indices.len();
                                debug!(
                                    "Bucket refresh: {candidate_count} candidate buckets, refreshing {refresh_count}"
                                );

                                let k = this.k_value();

                                for bucket_idx in refresh_indices {
                                    if shutdown_ref.is_cancelled() {
                                        break;
                                    }
                                    let random_key = {
                                        let dht = this.dht.read().await;
                                        dht.generate_random_key_for_bucket(bucket_idx)
                                    };
                                    let Some(key) = random_key else {
                                        this.mark_bucket_probe_finished(bucket_idx).await;
                                        continue;
                                    };

                                    let key_bytes: Key = *key.as_bytes();
                                    let lookup_result =
                                        this.find_closest_nodes_network(&key_bytes, k).await;
                                    this.mark_bucket_probe_finished(bucket_idx).await;
                                    match lookup_result {
                                        Ok(nodes) => {
                                            trace!(
                                                "Bucket refresh[{bucket_idx}]: discovered {} peers",
                                                nodes.len()
                                            );
                                            for dht_node in nodes {
                                                if dht_node.peer_id == this.config.peer_id {
                                                    continue;
                                                }
                                                if this
                                                    .should_avoid_automatic_peer(&dht_node.peer_id)
                                                    .await
                                                {
                                                    trace!(
                                                        "Bucket refresh[{bucket_idx}]: skipping quarantined peer {}",
                                                        dht_node.peer_id.to_hex()
                                                    );
                                                    continue;
                                                }
                                                this.dial_addresses(
                                                    &dht_node.peer_id,
                                                    &dht_node.typed_addresses(),
                                                )
                                                .await;
                                            }
                                        }
                                        Err(e) => {
                                            debug!("Bucket refresh[{bucket_idx}] lookup failed: {e}");
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                debug!(
                                    "Bucket refresh skipped: bucket refresh lookup already running"
                                );
                            }
                        }

                        this.maybe_rebootstrap().await;
                    } => {}
                }
            }
        });
        *handle_slot.write().await = Some(handle);
    }

    async fn mark_bucket_probe_finished(&self, bucket_idx: usize) {
        let marked = {
            let dht = self.dht.read().await;
            dht.mark_bucket_probe_finished(bucket_idx).await
        };
        if !marked {
            warn!(
                "Bucket refresh[{bucket_idx}]: probe-finished mark skipped for out-of-range bucket"
            );
        }
    }

    /// Trigger an immediate self-lookup to refresh the close neighborhood.
    ///
    /// Performs an iterative FIND_NODE for this node's own key and attempts to
    /// admit any newly discovered peers into the routing table.
    pub async fn trigger_self_lookup(&self) -> Result<()> {
        let self_id = self.config.peer_id;
        let self_key: Key = *self_id.as_bytes();
        let k = self.k_value();

        match self.find_closest_nodes_network(&self_key, k).await {
            Ok(nodes) => {
                debug!("Self-lookup discovered {} peers", nodes.len());
                for dht_node in nodes {
                    if dht_node.peer_id == self_id {
                        continue;
                    }
                    if self.should_avoid_automatic_peer(&dht_node.peer_id).await {
                        trace!(
                            "Self-lookup skipping quarantined peer {}",
                            dht_node.peer_id.to_hex()
                        );
                        continue;
                    }
                    // Dial if not already connected — try every advertised
                    // address, not just the first, so a stale NAT binding on
                    // one entry doesn't kill the dial.
                    self.dial_addresses(&dht_node.peer_id, &dht_node.typed_addresses())
                        .await;
                }
                Ok(())
            }
            Err(e) => {
                debug!("Self-lookup failed: {e}");
                Err(e)
            }
        }
    }

    /// Trigger automatic re-bootstrap if the routing table has fallen below
    /// [`AUTO_REBOOTSTRAP_THRESHOLD`] and the cooldown has elapsed.
    ///
    /// Uses currently connected peers as bootstrap seeds. The cooldown prevents
    /// hammering bootstrap nodes during transient network partitions. This is
    /// deliberately not guarded by `bucket_refresh_lookup_semaphore`: once the
    /// routing table is below the recovery threshold, bootstrap repair should
    /// not be skipped just because a best-effort bucket refresh is running.
    async fn maybe_rebootstrap(&self) {
        let rt_size = self.get_routing_table_size().await;
        if rt_size >= AUTO_REBOOTSTRAP_THRESHOLD {
            return;
        }

        // Enforce cooldown to avoid bootstrap storms.
        {
            let mut guard = self.last_rebootstrap.lock().await;
            if let Some(last) = *guard
                && last.elapsed() < REBOOTSTRAP_COOLDOWN
            {
                trace!(
                    "Auto re-bootstrap skipped: cooldown ({:?} remaining)",
                    REBOOTSTRAP_COOLDOWN.saturating_sub(last.elapsed())
                );
                return;
            }
            *guard = Some(Instant::now());
        }

        info!(
            "Auto re-bootstrap: routing table size ({rt_size}) below threshold ({})",
            AUTO_REBOOTSTRAP_THRESHOLD
        );

        // Collect currently connected peers to use as bootstrap seeds.
        let connected = self.transport.connected_peers().await;
        if connected.is_empty() {
            debug!("Auto re-bootstrap: no connected peers to bootstrap from");
            return;
        }

        match self.bootstrap_from_peers(&connected).await {
            Ok(discovered) => {
                info!("Auto re-bootstrap discovered {discovered} peers");
            }
            Err(e) => {
                warn!("Auto re-bootstrap failed: {e}");
            }
        }
    }

    /// Compute a randomised duration between `min` and `max`.
    ///
    /// Uses [`PeerId::random()`] as a cheap entropy source to avoid the `gen`
    /// keyword reserved in Rust edition 2024. This is not cryptographically
    /// secure but sufficient for jittering maintenance timers.
    fn randomised_interval(min: Duration, max: Duration) -> Duration {
        let range_secs = max.as_secs().saturating_sub(min.as_secs());
        if range_secs == 0 {
            return min;
        }
        let random_bytes = PeerId::random();
        let bytes = random_bytes.to_bytes();
        let random_value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let jitter = Duration::from_secs(random_value % (range_secs + 1));
        min + jitter
    }

    fn select_bucket_refresh_indices(candidates: Vec<BucketRefreshCandidate>) -> Vec<usize> {
        let jitter_bound_millis = BUCKET_REFRESH_SELECTION_JITTER.as_millis() as u64;
        let mut rng = rand::thread_rng();
        let mut scored: Vec<(u128, u128, u128, usize)> = candidates
            .into_iter()
            .map(|candidate| {
                let jitter = if jitter_bound_millis == 0 {
                    0
                } else {
                    rng.gen_range(0..=jitter_bound_millis) as u128
                };
                (
                    candidate.refresh_debt.as_millis().saturating_add(jitter),
                    candidate.live_peer_age.as_millis(),
                    candidate.probe_age.as_millis(),
                    candidate.index,
                )
            })
            .collect();
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.3.cmp(&b.3))
        });
        scored.truncate(MAX_BUCKET_REFRESH_LOOKUPS_PER_PASS);
        scored.into_iter().map(|(_, _, _, index)| index).collect()
    }

    /// Perform DHT peer discovery from already-connected bootstrap peers.
    ///
    /// Sends FIND_NODE(self) to each peer using the DHT postcard protocol,
    /// then dials any newly-discovered candidates. Returns the total number
    /// of new peers discovered.
    pub async fn bootstrap_from_peers(&self, peers: &[PeerId]) -> Result<usize> {
        let key = *self.config.peer_id.as_bytes();
        let mut seen = HashSet::new();
        // Collect peers that are worth dialing so the dial step can be skipped
        // entirely for clients. Node-mode dials are issued serially below.
        let mut to_dial: Vec<(PeerId, Vec<(MultiAddr, AddressType)>)> = Vec::new();
        for peer_id in peers {
            if self.should_avoid_automatic_peer(peer_id).await {
                trace!("Bootstrap skipping quarantined peer {}", peer_id.to_hex());
                continue;
            }
            let op = DhtNetworkOperation::FindNode { key };
            match self
                .send_dht_request_with_response_context(peer_id, op, None)
                .await
            {
                Ok(DhtResponseEnvelope {
                    result: DhtNetworkResult::NodesFound { nodes, .. },
                    transport_source,
                    ..
                }) => {
                    for node in &nodes {
                        let trusted_node = self
                            .gossiped_node_with_trusted_addresses(
                                node.clone(),
                                transport_source.as_ref(),
                            )
                            .await;
                        let typed = trusted_node.typed_addresses();
                        let dialable_count =
                            typed.iter().filter(|(a, _)| Self::is_dialable(a)).count();
                        debug!(
                            "DHT bootstrap: peer={} num_addresses={} dialable={}",
                            trusted_node.peer_id.to_hex(),
                            trusted_node.addresses.len(),
                            dialable_count
                        );
                        // Ingest the responder's typed view of this peer so
                        // later relay acquisition / dial paths can see Direct
                        // and Relay tags without having to rely on the peer
                        // landing in our own K-closest PublishAddressSet
                        // fan-out. No-op when the peer isn't already in the
                        // routing table; upgrade-only on existing entries.
                        self.merge_trusted_gossiped_typed_addresses(&trusted_node)
                            .await;
                        if self
                            .should_avoid_automatic_peer(&trusted_node.peer_id)
                            .await
                        {
                            trace!(
                                "DHT bootstrap: skipping quarantined gossiped peer {}",
                                trusted_node.peer_id.to_hex()
                            );
                            continue;
                        }
                        if seen.insert(trusted_node.peer_id) && dialable_count > 0 {
                            to_dial.push((trusted_node.peer_id, typed));
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Bootstrap FIND_NODE to {} failed: {}", peer_id.to_hex(), e);
                }
            }
        }

        // Client-mode nodes don't serve the DHT, so they don't need a live
        // QUIC channel to every gossiped peer. Iterative lookups will dial on
        // demand when the client needs to reach one, which is enough for its
        // own requests — matching the rationale for skipping post-bootstrap
        // self-lookups in `P2PNode::start()`.
        if matches!(self.config.node_config.mode, NodeMode::Client) {
            debug!(
                "DHT bootstrap: client mode — skipping {} gossiped-peer dial(s)",
                to_dial.len()
            );
        } else {
            for (peer_id, typed) in to_dial {
                self.dial_addresses(&peer_id, &typed).await;
            }
        }

        // Emit RoutingTableReady — routing table is populated but the node has
        // not yet classified its reachability (ADR-014). The full
        // BootstrapComplete event is emitted later by P2PNode::start() after
        // the classifier run.
        let rt_size = self.get_routing_table_size().await;
        if self.event_tx.receiver_count() > 0 {
            let _ = self
                .event_tx
                .send(DhtNetworkEvent::RoutingTableReady { num_peers: rt_size });
        }
        info!("Routing table ready: {rt_size} peers (reachability classification pending)");

        Ok(seen.len())
    }

    /// Stop the DHT network manager.
    ///
    /// Sends leave messages to connected peers and shuts down DHT operations.
    /// The caller is responsible for stopping the transport after this returns.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DHT Network Manager...");

        // Send leave messages to connected peers before shutting down tasks
        self.leave_network().await?;

        // Signal all background tasks to stop
        self.shutdown.cancel();

        // Signal background tasks to stop
        self.dht.read().await.signal_shutdown();

        // Join all background tasks with a timeout. The tasks check
        // `shutdown.cancelled()` but may be mid-operation when cancel fires.
        // The select-wrapped work blocks (added to fix shutdown hangs under
        // active traffic) should make tasks exit promptly, but as defense in
        // depth we abort any task that exceeds `TASK_SHUTDOWN_TIMEOUT`.
        async fn join_task(name: &str, slot: &RwLock<Option<tokio::task::JoinHandle<()>>>) {
            if let Some(mut handle) = slot.write().await.take() {
                match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, &mut handle).await {
                    Ok(Ok(())) => debug!("{name} task stopped cleanly"),
                    Ok(Err(e)) if e.is_cancelled() => debug!("{name} task was cancelled"),
                    Ok(Err(e)) => warn!("{name} task panicked: {e}"),
                    Err(_) => {
                        warn!(
                            "{name} task did not stop within {}s, aborting",
                            TASK_SHUTDOWN_TIMEOUT.as_secs()
                        );
                        handle.abort();
                    }
                }
            }
        }
        join_task("event handler", &self.event_handler_handle).await;
        join_task("self-lookup", &self.self_lookup_handle).await;
        join_task("bucket refresh", &self.bucket_refresh_handle).await;

        info!("DHT Network Manager stopped");
        Ok(())
    }

    /// Backwards-compatible API that performs a full iterative lookup.
    pub async fn find_closest_nodes(&self, key: &Key, count: usize) -> Result<Vec<DHTNode>> {
        self.find_closest_nodes_network(key, count).await
    }

    /// Find a quorum-witnessed close group for a target key.
    ///
    /// This is a specialised close-group authority API. It does not change
    /// regular FIND_NODE semantics:
    ///
    /// 1. Perform the normal iterative pure-XOR lookup and keep the closest K
    ///    remote responders.
    /// 2. Reuse each initial responder's closest-K view from the iterative
    ///    lookup transcript when available; query only responders whose view
    ///    was not captured during convergence.
    /// 3. Make each responder view self-inclusive, so a responder that belongs
    ///    in its own local close group recognises itself even though standard
    ///    FIND_NODE responses omit the responder.
    /// 4. Return the trusted, self-inclusive closest-K view for each responder.
    ///    Callers decide quorum, fallback, and payment policy from that
    ///    transcript.
    ///
    /// The returned [`WitnessedCloseGroup`] is a validated DHT transcript. It
    /// can be inconclusive when some initial responders do not provide views;
    /// callers that require a complete or quorum-backed close group should
    /// evaluate that before performing irreversible work such as payment.
    pub async fn find_witnessed_close_group(
        &self,
        key: &Key,
        count: usize,
    ) -> Result<WitnessedCloseGroup> {
        self.find_witnessed_close_group_with_view_count(key, count, count)
            .await
    }

    /// Find a witnessed close-group transcript with independently sized
    /// responder views.
    ///
    /// `count` controls the initial pure-XOR responder set. `view_count`
    /// controls how many closest nodes each responder view may contribute to
    /// the transcript.
    pub async fn find_witnessed_close_group_with_view_count(
        &self,
        key: &Key,
        count: usize,
        view_count: usize,
    ) -> Result<WitnessedCloseGroup> {
        if count == 0 {
            return Err(P2PError::InvalidInput(
                "witnessed close group count must be greater than zero".to_string(),
            ));
        }
        if view_count == 0 {
            return Err(P2PError::InvalidInput(
                "witnessed close group view count must be greater than zero".to_string(),
            ));
        }

        let initial_lookup_count = count.saturating_add(1);
        let FindNodeLookupOutcome {
            closest_nodes,
            mut transcript,
        } = self
            .find_closest_nodes_network_with_transcript(key, initial_lookup_count, Some(view_count))
            .await?;
        let initial_closest: Vec<DHTNode> = sort_dedup_witnessed_nodes(
            closest_nodes
                .into_iter()
                .filter(|node| !self.is_local_peer_id(&node.peer_id))
                .collect(),
            key,
            count,
        );

        if initial_closest.len() < count {
            return Err(P2PError::Dht(DhtError::InsufficientPeers(
                format!(
                    "witnessed close group initial lookup found {} peers, need {count} for key {}",
                    initial_closest.len(),
                    hex::encode(key)
                )
                .into(),
            )));
        }

        let (mut responder_node_views, missing_responders) =
            split_witnessed_transcript_views(&initial_closest, &mut transcript);
        for (_, nodes) in &responder_node_views {
            for node in nodes {
                self.merge_trusted_gossiped_typed_addresses(node).await;
            }
        }
        if !missing_responders.is_empty() {
            debug!(
                "Witnessed close group re-querying {} responder(s) without transcript views for key {}",
                missing_responders.len(),
                hex::encode(key)
            );
        }

        let mut query_stream: FuturesUnordered<_> = missing_responders
            .iter()
            .map(|node| {
                let peer_id = node.peer_id;
                let typed = node.typed_addresses();
                let lookup_key = *key;
                let failure_rx = self.lookup_failures.subscribe();
                async move {
                    self.send_find_node_lookup_request(peer_id, typed, lookup_key, failure_rx)
                        .await
                }
            })
            .collect();

        while let Some((responder, result)) = query_stream.next().await {
            match result {
                Ok(DhtResponseEnvelope {
                    result: DhtNetworkResult::NodesFound { nodes, .. },
                    transport_source,
                    ..
                }) => {
                    let (_, trusted_nodes) = self
                        .trusted_find_node_response_nodes(
                            nodes,
                            transport_source.as_ref(),
                            key,
                            0,
                            view_count,
                        )
                        .await;
                    for node in &trusted_nodes {
                        self.merge_trusted_gossiped_typed_addresses(node).await;
                    }

                    responder_node_views.push((responder, trusted_nodes));
                }
                Ok(other) => {
                    warn!(
                        "Witnessed close-group FIND_NODE from {} returned unexpected result: {:?}",
                        responder.to_hex(),
                        other
                    );
                }
                Err(e) => {
                    warn!(
                        "Witnessed close-group FIND_NODE from {} failed for key {}: {}",
                        responder.to_hex(),
                        hex::encode(key),
                        e
                    );
                }
            }
        }

        let witnessed = build_witnessed_close_group(
            key,
            count,
            view_count,
            initial_closest,
            responder_node_views,
        );

        if witnessed.responder_views.len() < witnessed.initial_closest.len() {
            warn!(
                "Witnessed close group transcript incomplete for key {}: responders={}/{}",
                hex::encode(key),
                witnessed.responder_views.len(),
                witnessed.initial_closest.len()
            );
        }

        Ok(witnessed)
    }

    /// Find nodes closest to a key using iterative network lookup
    pub async fn find_node(&self, key: &Key) -> Result<DhtNetworkResult> {
        info!("Finding nodes closest to key: {}", hex::encode(key));

        let closest_nodes = self.find_closest_nodes_network(key, self.k_value()).await?;
        let serializable_nodes: Vec<SerializableDHTNode> = closest_nodes.into_iter().collect();

        info!(
            "Found {} nodes closest to key: {}",
            serializable_nodes.len(),
            hex::encode(key)
        );
        Ok(DhtNetworkResult::NodesFound {
            key: *key,
            nodes: serializable_nodes,
        })
    }

    /// Ping a specific node
    pub async fn ping(&self, peer_id: &PeerId) -> Result<DhtNetworkResult> {
        info!("Pinging peer: {}", peer_id.to_hex());

        let start_time = Instant::now();
        let operation = DhtNetworkOperation::Ping;

        match self.send_dht_request(peer_id, operation, None).await {
            Ok(DhtNetworkResult::PongReceived { responder, .. }) => {
                let latency = start_time.elapsed();
                info!("Received pong from {} in {:?}", responder, latency);
                Ok(DhtNetworkResult::PongReceived { responder, latency })
            }
            Ok(result) => {
                warn!("Unexpected ping result: {:?}", result);
                Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Unexpected ping response".to_string().into(),
                )))
            }
            Err(e) => {
                warn!("Ping failed to {}: {}", peer_id.to_hex(), e);
                Err(e)
            }
        }
    }

    /// Leave the DHT network gracefully
    async fn leave_network(&self) -> Result<()> {
        // No-op: peers detect disconnection via transport-level connection loss.
        // Explicit leave messages added latency to shutdown without meaningful benefit.
        Ok(())
    }

    // =========================================================================
    // FIND CLOSEST NODES API
    // =========================================================================
    //
    // Two functions for finding closest nodes to a key:
    //
    // 1. find_closest_nodes_local() - Routing table lookup
    //    - Only checks the local Kademlia routing table
    //    - No network requests, safe to call from request handlers
    //    - Returns security-validated DHT participants only
    //
    // 2. find_closest_nodes_network() - Iterative network lookup
    //    - Starts with routing table knowledge, then queries the network
    //    - Asks known nodes for their closest nodes, then queries those
    //    - Continues until convergence (same answers or worse quality)
    //    - Full Kademlia-style iterative lookup
    // =========================================================================

    /// Find closest nodes to a key using ONLY the local routing table.
    ///
    /// No network requests are made — safe to call from request handlers.
    /// Only returns peers that passed the `is_dht_participant` security gate,
    /// were added to the Kademlia routing table, and are not locally
    /// quarantined by trust policy.
    ///
    /// Results are sorted by XOR distance to the key.
    pub async fn find_closest_nodes_local(&self, key: &Key, count: usize) -> Vec<DHTNode> {
        debug!(
            "[LOCAL] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let dht_guard = self.dht.read().await;
        let dht_key = DhtKey::from_bytes(*key);
        let local_peer_id = self.config.peer_id;
        let trust_score = |peer_id: &PeerId| self.peer_trust_score(peer_id);
        match dht_guard
            .find_nodes_with_publish_seq_filtered(&dht_key, count, |node| {
                if node.id == local_peer_id {
                    return false;
                }
                let score = trust_score(&node.id);
                !dht_guard.should_avoid_for_lookup(&node.id, score)
            })
            .await
        {
            Ok(nodes) => Self::lookup_results_from_routing_nodes(nodes, count),
            Err(e) => {
                warn!("find_nodes failed for key {}: {e}", hex::encode(key));
                Vec::new()
            }
        }
    }

    fn lookup_results_from_routing_nodes(
        nodes: Vec<(NodeInfo, u64)>,
        count: usize,
    ) -> Vec<DHTNode> {
        nodes
            .into_iter()
            .take(count)
            .map(|(node, publish_seq)| DHTNode {
                peer_id: node.id,
                address_types: node.address_types,
                addresses: node.addresses,
                distance: encode_publish_seq_distance(publish_seq),
                // Keep the legacy wire value stable. Trust is local policy
                // used for filtering and should not change DHTNode wire
                // semantics for older nodes.
                reliability: SELF_RELIABILITY_SCORE,
            })
            .collect()
    }

    /// Find closest nodes to a key using the local routing table, including
    /// the local node itself in the candidate set.
    ///
    /// This is the self-inclusive variant of [`find_closest_nodes_local`] and
    /// corresponds to `SelfInclusiveRT(N)` in replication designs — the local
    /// routing table plus the local node. It allows callers to compute
    /// `IsResponsible(self, K)` by checking whether self appears in the
    /// top-N results.
    ///
    /// Results are sorted by XOR distance to the key and truncated to `count`.
    pub async fn find_closest_nodes_local_with_self(
        &self,
        key: &Key,
        count: usize,
    ) -> Vec<DHTNode> {
        // Get `count` routing-table peers, append self, sort, and truncate
        // back to `count`. Self may displace the farthest peer.
        let mut nodes = self.find_closest_nodes_local(key, count).await;

        nodes.push(self.local_dht_node().await);

        let key_peer = PeerId::from_bytes(*key);
        nodes.sort_by(|a, b| {
            let da = a.peer_id.xor_distance(&key_peer);
            let db = b.peer_id.xor_distance(&key_peer);
            da.cmp(&db)
        });
        nodes.truncate(count);
        nodes
    }

    /// Self-inclusive local lookup ordered by XOR distance.
    ///
    /// This mirrors [`find_closest_nodes_local_with_self`]: it includes the
    /// local node in the candidate set so a caller can compute
    /// `IsResponsible(self, K)`, orders by XOR distance, and truncates to
    /// `count`.
    pub async fn find_closest_nodes_local_by_distance_with_self(
        &self,
        key: &Key,
        count: usize,
    ) -> Vec<DHTNode> {
        let mut nodes = self.find_closest_nodes_local(key, count).await;

        nodes.push(self.local_dht_node().await);

        nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        nodes.truncate(count);
        nodes
    }

    /// Find closest nodes to a key using iterative network lookup.
    ///
    /// This implements Kademlia-style iterative lookup:
    /// 1. Start with nodes from local address book
    /// 2. Query those nodes for their closest nodes to the key
    /// 3. Query the returned nodes, repeat
    /// 4. Stop when converged (same or worse answers)
    ///
    /// This makes network requests and should NOT be called from request handlers.
    pub async fn find_closest_nodes_network(
        &self,
        key: &Key,
        count: usize,
    ) -> Result<Vec<DHTNode>> {
        Ok(self
            .find_closest_nodes_network_with_transcript(key, count, None)
            .await?
            .closest_nodes)
    }

    async fn find_closest_nodes_network_with_transcript(
        &self,
        key: &Key,
        count: usize,
        transcript_view_count: Option<usize>,
    ) -> Result<FindNodeLookupOutcome> {
        const MAX_ITERATIONS: usize = 20;
        const ALPHA: usize = 3; // Parallel queries per iteration

        debug!(
            "[NETWORK] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let target_key = DhtKey::from_bytes(*key);
        let mut peer_states = LookupPeerStates::default();
        let mut best_nodes: Vec<DHTNode> = Vec::new();

        // Kademlia correctness: the local node must compete on distance in the
        // final K-closest result, but we must never send an RPC to ourselves.
        // Seed best_nodes with self and mark self as "queried" so the iterative
        // loop never tries to contact us.
        best_nodes.push(self.local_dht_node().await);
        self.mark_self_queried(&mut peer_states);

        // Candidates sorted by XOR distance to target (closest first).
        // Composite key (distance, peer_id) ensures uniqueness when two peers
        // share the same distance.
        let mut candidates: BTreeMap<(Key, PeerId), DHTNode> = BTreeMap::new();
        // All reports collected per subject peer across the lookup,
        // keyed by responder. `compute_winner` consults this every time
        // a new report arrives so a quorum that emerges only after the
        // third close-XOR responder has replied can supersede a
        // previously-stored single-source pick.
        let mut subject_reports: HashMap<PeerId, SubjectReports> = HashMap::new();
        let mut transcript = FindNodeLookupTranscript::default();

        // Start with local knowledge
        let initial = self.find_closest_nodes_local(key, count).await;
        for node in initial {
            if self.should_avoid_automatic_peer(&node.peer_id).await {
                trace!(
                    "[NETWORK] Skipping {}: peer is below trust quarantine/admission threshold",
                    node.peer_id.to_hex()
                );
                continue;
            }
            if peer_states.is_contactable(&node.peer_id) {
                if self.lookup_candidate_dial_plan_is_exhausted(&node).await {
                    // Cache exhaustion is a transient, address-view-local
                    // decision — not a terminal peer failure. Skip this view
                    // but leave the peer contactable so a later responder can
                    // still revive it with a usable (e.g. Direct) address.
                    continue;
                }
                let dist = node.peer_id.distance(&target_key);
                candidates.entry((dist, node.peer_id)).or_insert(node);
            }
        }

        // Snapshot of the top-K peer IDs from the previous iteration.
        // Stagnation = the entire top-K set is unchanged AND no unqueried
        // candidate is closer than the current worst member of top-K.
        let mut previous_top_k: Vec<PeerId> = Vec::new();

        for iteration in 0..MAX_ITERATIONS {
            if candidates.is_empty() {
                debug!(
                    "[NETWORK] No more candidates after {} iterations",
                    iteration
                );
                break;
            }

            // Select up to ALPHA closest unqueried nodes to query.
            // BTreeMap is sorted by (distance, peer_id), so first_entry()
            // always yields the closest candidate.
            let mut batch: Vec<DHTNode> = Vec::new();
            while batch.len() < ALPHA {
                let Some(entry) = candidates.first_entry() else {
                    break;
                };
                let node = entry.remove();
                if !peer_states.is_contactable(&node.peer_id) {
                    continue;
                }
                if self.should_avoid_automatic_peer(&node.peer_id).await {
                    peer_states.mark_failed(node.peer_id);
                    trace!(
                        "[NETWORK] Skipping {}: peer is below trust quarantine/admission threshold",
                        node.peer_id.to_hex()
                    );
                    continue;
                }
                if self.lookup_candidate_dial_plan_is_exhausted(&node).await {
                    // Transient skip, not a terminal failure: keep the peer
                    // contactable so a better address from a later responder
                    // can re-admit it (it may have become exhausted only
                    // because of a coarse relay-IP suppression).
                    trace!(
                        "[NETWORK] Skipping {} this round: all dial candidates currently in the failure cache (peer left contactable)",
                        node.peer_id.to_hex()
                    );
                    continue;
                }
                peer_states.mark_waiting(node.peer_id);
                batch.push(node);
            }

            if batch.is_empty() {
                debug!(
                    "[NETWORK] All candidates queried after {} iterations",
                    iteration
                );
                break;
            }

            info!(
                "[NETWORK] Iteration {}: querying {} nodes",
                iteration,
                batch.len()
            );

            // Query nodes in parallel.
            //
            // saorsa-transport connection multiplexing lets us keep a single
            // transport socket while still querying multiple peers
            // concurrently.
            //
            // We drive the α queries through `FuturesUnordered` so we can
            // advance the lookup as soon as there's *something* to work
            // with. Waiting for every query (`join_all`) lets a single dead
            // peer — whose dial cascade can take 20–30s — block the whole
            // iteration; instead, once the first response arrives, we bound
            // the wait on the stragglers to `ITERATION_GRACE_TIMEOUT_SECS`
            // and move on with whatever responses came in by then. Any
            // still-pending queries are dropped (and their futures cancelled)
            // when the stream goes out of scope.
            let query_stream: FuturesUnordered<_> = batch
                .iter()
                .map(|node| {
                    let peer_id = node.peer_id;
                    let typed = node.typed_addresses();
                    let lookup_key = *key;
                    let failure_rx = self.lookup_failures.subscribe();
                    async move {
                        self.send_find_node_lookup_request(peer_id, typed, lookup_key, failure_rx)
                            .await
                    }
                })
                .collect();

            let results = Self::collect_iteration_results(query_stream).await;
            let responded: HashSet<PeerId> = results.iter().map(|(peer_id, _)| *peer_id).collect();

            // Queries still pending after the grace window are dropped. Treat
            // them like libp2p's `Unresponsive`: they free alpha capacity and
            // are skipped for the rest of this lookup, preventing later gossip
            // from reintroducing the same abandoned probe.
            for node in &batch {
                if !responded.contains(&node.peer_id)
                    && peer_states.state(&node.peer_id) == Some(LookupPeerState::Waiting)
                {
                    peer_states.mark_unresponsive(node.peer_id);
                }
            }

            for (peer_id, result) in results {
                match result {
                    Ok(DhtResponseEnvelope {
                        result: DhtNetworkResult::NodesFound { nodes, .. },
                        transport_source,
                        ..
                    }) => {
                        peer_states.mark_succeeded(peer_id);
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }

                        let (candidate_nodes, responder_view) = self
                            .trusted_find_node_response_nodes(
                                nodes,
                                transport_source.as_ref(),
                                key,
                                self.k_value(),
                                transcript_view_count.unwrap_or(0),
                            )
                            .await;
                        if transcript_view_count.is_some() {
                            transcript.record_responder_view(peer_id, responder_view);
                        }

                        for node in candidate_nodes {
                            if !peer_states.is_contactable(&node.peer_id) {
                                continue;
                            }
                            if self.should_avoid_automatic_peer(&node.peer_id).await {
                                peer_states.mark_failed(node.peer_id);
                                trace!(
                                    "[NETWORK] Skipping gossiped {}: peer is below trust quarantine/admission threshold",
                                    node.peer_id.to_hex()
                                );
                                continue;
                            }
                            if self.lookup_candidate_dial_plan_is_exhausted(&node).await {
                                // Transient skip, not a terminal failure: a
                                // single responder's stale/suppressed (e.g.
                                // relay-only) view of this peer must not poison
                                // it for the rest of the lookup. Leave it
                                // contactable so another responder's usable
                                // (e.g. Direct) address can still win.
                                trace!(
                                    "[NETWORK] Skipping gossiped {} this round: all dial candidates currently in the failure cache (peer left contactable)",
                                    node.peer_id.to_hex()
                                );
                                continue;
                            }
                            // Ingest the responder's typed view into our
                            // routing table (upgrade-only on existing
                            // entries) so `Direct` and `Relay` tags
                            // propagate beyond the publisher's K-closest
                            // PublishAddressSet fan-out. Without this, a
                            // peer that isn't in any open node's top-K
                            // never learns which of its neighbours expose
                            // a dialable Direct address and fails relay
                            // acquisition.
                            self.merge_trusted_gossiped_typed_addresses(&node).await;
                            let subject_id = node.peer_id;
                            let dist = subject_id.distance(&target_key);
                            let cand_key = (dist, subject_id);

                            // Accumulate the report, then recompute the
                            // winner across all responders that have
                            // reported this subject so far. The winner
                            // may change as later responses arrive — e.g.
                            // a quorum that only forms after the third
                            // close-XOR responder replies supersedes the
                            // first single-source pick.
                            let reports = subject_reports.entry(subject_id).or_default();
                            reports.insert(peer_id, node);

                            let winner_node = match compute_winner(&subject_id, reports) {
                                Some((_, node)) => node.clone(),
                                None => continue,
                            };

                            // Already present at the same cand_key? Replace
                            // in place — no capacity change.
                            if let std::collections::btree_map::Entry::Occupied(mut e) =
                                candidates.entry(cand_key)
                            {
                                e.insert(winner_node);
                                continue;
                            }

                            if candidates.len() >= MAX_CANDIDATE_NODES {
                                // At capacity — evict the farthest candidate if the
                                // new one is closer, otherwise drop the new one.
                                let farthest_key = candidates.keys().next_back().copied();
                                match farthest_key {
                                    Some(fk) if cand_key < fk => {
                                        candidates.remove(&fk);
                                        subject_reports.remove(&fk.1);
                                    }
                                    _ => {
                                        trace!(
                                            "[NETWORK] Candidate queue at capacity ({}), dropping {}",
                                            MAX_CANDIDATE_NODES,
                                            subject_id.to_hex()
                                        );
                                        continue;
                                    }
                                }
                            }
                            candidates.insert(cand_key, winner_node);
                        }
                    }
                    Ok(DhtResponseEnvelope {
                        result: DhtNetworkResult::PeerRejected,
                        ..
                    }) => {
                        peer_states.mark_failed(peer_id);
                        // Remote peer rejected us (e.g. older node with blocking) —
                        // remove them from our routing table (no point retrying) but
                        // do NOT penalise their trust score; the rejection is an
                        // honest signal, not misbehaviour.
                        info!(
                            "[NETWORK] Peer {} rejected us — removing from routing table",
                            peer_id.to_hex()
                        );
                        let mut dht = self.dht.write().await;
                        let rt_events = dht.remove_node_by_id(&peer_id).await;
                        drop(dht);
                        self.broadcast_routing_events_with_quarantine(rt_events)
                            .await;
                        let _ = self.transport.disconnect_peer(&peer_id).await;
                    }
                    Ok(_) => {
                        peer_states.mark_succeeded(peer_id);
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                    }
                    Err(e) => {
                        peer_states.mark_failed(peer_id);
                        trace!("[NETWORK] Query to {} failed: {}", peer_id.to_hex(), e);
                        // Trust failure is recorded inside send_dht_request —
                        // no additional recording needed here.
                    }
                }
            }

            // Sort, deduplicate, and truncate once per iteration instead of per result
            best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
            best_nodes.dedup_by_key(|n| n.peer_id);
            best_nodes.truncate(count);

            // Stagnation: compare the entire top-K set, not just closest distance.
            let current_top_k: Vec<PeerId> = best_nodes.iter().map(|n| n.peer_id).collect();
            if current_top_k == previous_top_k {
                // If we haven't filled K slots yet, any remaining candidate
                // could improve the result — keep going.
                if best_nodes.len() < count && !candidates.is_empty() {
                    previous_top_k = current_top_k;
                    continue;
                }
                // Top-K didn't change, but don't stop if a queued candidate is
                // closer than the farthest member of top-K — it could still
                // improve the result once queried.
                let has_promising_candidate = best_nodes.last().is_some_and(|worst| {
                    let worst_dist = worst.peer_id.distance(&target_key);
                    candidates
                        .keys()
                        .next()
                        .is_some_and(|(dist, _)| *dist < worst_dist)
                });
                if !has_promising_candidate {
                    info!(
                        "[NETWORK] {}: Top-K converged after {} iterations",
                        self.config.peer_id.to_hex(),
                        iteration + 1
                    );
                    break;
                }
            }
            previous_top_k = current_top_k;
        }

        best_nodes = apply_lookup_report_winners(best_nodes, &subject_reports, key, count);

        info!(
            "[NETWORK] Found {} closest nodes: {:?}",
            best_nodes.len(),
            best_nodes
                .iter()
                .map(|n| {
                    let h = n.peer_id.to_hex();
                    h[..8.min(h.len())].to_string()
                })
                .collect::<Vec<_>>()
        );

        Ok(FindNodeLookupOutcome {
            closest_nodes: best_nodes,
            transcript,
        })
    }

    /// Send one iterative FIND_NODE probe, aborting early if another active
    /// lookup reports the same peer as failed.
    ///
    /// This is the closest analogue to libp2p feeding a dial/connection
    /// failure into every active query that is waiting on that peer. The
    /// actual request owns the failure notification: externally-cancelled
    /// probes return an error but do not rebroadcast, avoiding feedback loops.
    async fn send_find_node_lookup_request(
        &self,
        peer_id: PeerId,
        typed: Vec<(MultiAddr, AddressType)>,
        key: Key,
        failure_rx: broadcast::Receiver<PeerId>,
    ) -> (PeerId, Result<DhtResponseEnvelope>) {
        let request = async {
            // Pass the same typed candidate list to both ensure_peer_channel
            // and send_dht_request so the request path doesn't pay a redundant
            // routing-table read. Trying every dialable address protects
            // against stale NAT bindings, single-IP-family failures, and
            // recently-relayed peers whose direct address is no longer reachable.
            //
            // Going through ensure_peer_channel registers the in-flight dial in
            // the peer-dial coordinator, so concurrent iterative lookups that
            // happen to batch the same peer join this dial rather than racing it.
            self.ensure_peer_channel(&peer_id, &typed).await?;
            self.send_dht_request_with_response_context(
                &peer_id,
                DhtNetworkOperation::FindNode { key },
                Some(&typed),
            )
            .await
        };
        tokio::pin!(request);

        let external_failure = Self::wait_for_lookup_failure_signal(peer_id, failure_rx);
        tokio::pin!(external_failure);

        let result = tokio::select! {
            biased;

            result = &mut request => {
                if result.is_err() {
                    self.notify_lookup_peer_failed(peer_id);
                }
                result
            }
            () = &mut external_failure => {
                Err(Self::active_lookup_peer_failed_error(&peer_id))
            }
        };

        (peer_id, result)
    }

    /// Wait until the active-lookup failure bus reports `peer_id`.
    async fn wait_for_lookup_failure_signal(peer_id: PeerId, mut rx: broadcast::Receiver<PeerId>) {
        loop {
            match rx.recv().await {
                Ok(failed_peer) if failed_peer == peer_id => return,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // The skipped window may have contained this peer. Treat
                    // lag as a conservative failure signal so lookup storms do
                    // not leave waiters spending their full request timeout.
                    return;
                }
                Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
            }
        }
    }

    fn notify_lookup_peer_failed(&self, peer_id: PeerId) {
        self.lookup_failures.notify_failed(peer_id);
    }

    fn active_lookup_peer_failed_error(peer_id: &PeerId) -> P2PError {
        P2PError::Network(NetworkError::PeerNotFound(
            format!(
                "peer {} failed in another active FIND_NODE lookup",
                peer_id.to_hex()
            )
            .into(),
        ))
    }

    /// Compare two nodes by their XOR distance to a target key.
    fn compare_node_distance(a: &DHTNode, b: &DHTNode, key: &Key) -> std::cmp::Ordering {
        let target_key = DhtKey::from_bytes(*key);
        a.peer_id
            .distance(&target_key)
            .cmp(&b.peer_id.distance(&target_key))
    }

    async fn trusted_find_node_response_nodes(
        &self,
        mut nodes: Vec<SerializableDHTNode>,
        transport_source: Option<&MultiAddr>,
        key: &Key,
        candidate_limit: usize,
        transcript_limit: usize,
    ) -> (Vec<DHTNode>, Vec<DHTNode>) {
        let processing_limit = candidate_limit.max(transcript_limit);
        nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        nodes.truncate(processing_limit);

        let mut candidate_nodes = Vec::with_capacity(candidate_limit.min(nodes.len()));
        let mut transcript_nodes = Vec::with_capacity(transcript_limit.min(nodes.len()));

        for (index, node) in nodes.into_iter().enumerate() {
            let node = self
                .gossiped_node_with_trusted_addresses(node, transport_source)
                .await;
            if self.is_local_peer_id(&node.peer_id) {
                continue;
            }

            let is_candidate_node = index < candidate_limit;
            let is_transcript_node = index < transcript_limit;
            match (is_candidate_node, is_transcript_node) {
                (true, true) => {
                    candidate_nodes.push(node.clone());
                    transcript_nodes.push(node);
                }
                (true, false) => candidate_nodes.push(node),
                (false, true) => transcript_nodes.push(node),
                (false, false) => {}
            }
        }

        (candidate_nodes, transcript_nodes)
    }

    /// Drain an iteration's α queries with a bounded wait after first response.
    ///
    /// Waits for the first query to complete, then grants the remaining
    /// queries up to `ITERATION_GRACE_TIMEOUT_SECS` to finish before giving
    /// up on them and returning whatever has arrived. Any still-pending
    /// futures are dropped (and cancelled) when the stream is returned.
    async fn collect_iteration_results<S>(
        mut stream: S,
    ) -> Vec<(PeerId, Result<DhtResponseEnvelope>)>
    where
        S: futures::Stream<Item = (PeerId, Result<DhtResponseEnvelope>)> + Unpin,
    {
        let mut results = Vec::new();

        // Block for the first response — if nothing arrives the iteration
        // has no new information to work with, so we do need to wait here.
        let Some(first) = stream.next().await else {
            return results;
        };
        results.push(first);

        // Bounded drain: accept whichever stragglers finish within the
        // grace window, then move on. `timeout` cancels the inner future
        // on expiry, which drops the remaining query futures.
        let grace = Duration::from_secs(ITERATION_GRACE_TIMEOUT_SECS);
        let _ = tokio::time::timeout(grace, async {
            while let Some(next) = stream.next().await {
                results.push(next);
            }
        })
        .await;

        results
    }

    /// Return the K-closest candidate nodes, excluding the requester.
    ///
    /// Per Kademlia, a FindNode response should contain the K closest nodes
    /// the responder knows about — regardless of whether they are closer or
    /// farther than the responder itself. The requester is excluded because
    /// it already knows its own address.
    fn filter_response_nodes(
        candidate_nodes: Vec<DHTNode>,
        requester_peer_id: &PeerId,
    ) -> Vec<DHTNode> {
        candidate_nodes
            .into_iter()
            .filter(|node| node.peer_id != *requester_peer_id)
            .collect()
    }

    /// Build a `DHTNode` representing the local node for inclusion in
    /// K-closest results. The local node always participates in distance
    /// ranking but is never queried over the network.
    ///
    /// The published address list uses the same shared self-address
    /// invariants as the reachability driver's `PublishAddressSet` fan-out:
    /// relay first when present, then at most one best WAN address per IP
    /// family and one LAN address per IP family. WAN addresses are tagged as
    /// Direct only when the passive classifier has proven that exact external
    /// socket; local-scope addresses are tagged Lan. Wildcard and zero-port
    /// listen addresses are dropped rather than published as undialable
    /// placeholders.
    ///
    /// If neither source produces an address, the returned `DHTNode` has an
    /// empty `addresses` vec. That is intentional: it tells consumers "I
    /// don't know how to be reached yet" rather than guessing a bind-side
    /// wildcard address that peers cannot route to.
    async fn local_dht_node(&self) -> DHTNode {
        let observed = self.transport.non_relay_external_addresses();
        let listen = self.transport.listen_addrs().await;
        let relay = self.transport.relay_external_address();
        let (addresses, address_types) = build_self_address_set(observed, listen, relay, |sa| {
            self.transport.is_external_proven(sa)
        })
        .into_parallel_vecs();

        DHTNode {
            peer_id: self.config.peer_id,
            addresses,
            address_types,
            distance: None,
            reliability: SELF_RELIABILITY_SCORE,
        }
    }

    /// Add the local app-level peer ID to the per-lookup state map so that
    /// iterative lookups never send RPCs to the local node.
    fn mark_self_queried(&self, peer_states: &mut LookupPeerStates) {
        peer_states.mark_succeeded(self.config.peer_id);
    }

    /// Return the first dialable `Direct`-tagged address from a [`DHTNode`].
    ///
    /// Used by the relay-acquisition walker: to set up a new MASQUE relay
    /// session against a candidate, we must dial the candidate's actual
    /// listening socket (its Direct address). A `Relay`-tagged address is a
    /// tunnel-allocated socket that already fronts its own target; using it
    /// to request a new relay reservation would be a "relay through a
    /// relay" which MASQUE CONNECT-UDP does not support.
    ///
    /// Walks the parallel `addresses` / `address_types` vecs, returning
    /// the first address whose type is [`AddressType::Direct`] and whose
    /// socket is dialable (QUIC, non-unspecified, not port zero). Returns
    /// `None` when no such address exists — the caller should skip this
    /// candidate and walk to the next-closest peer.
    ///
    /// Untagged entries fall through as `Unverified`, not `Direct` — a
    /// legacy record with no `address_types` is NOT a valid relay
    /// candidate because its publisher never asserted reachability. This
    /// closes the "NAT-through-NAT relay chain" failure mode where a
    /// node's observed-but-unverified ephemeral port would be treated as
    /// a dialable Direct candidate.
    fn first_direct_dialable_with_filter(
        node: &DHTNode,
        accept: impl Fn(&MultiAddr) -> bool,
    ) -> Option<MultiAddr> {
        for (i, addr) in node.addresses.iter().enumerate() {
            let advertised = node
                .address_types
                .get(i)
                .copied()
                .unwrap_or(AddressType::Unverified);
            let addr_type = AddressType::for_advertised_address(addr, advertised);
            if addr_type != AddressType::Direct {
                continue;
            }
            let Some(sa) = addr.dialable_socket_addr() else {
                continue;
            };
            if sa.ip().is_unspecified() {
                continue;
            }
            if !accept(addr) {
                continue;
            }
            return Some(addr.clone());
        }
        None
    }

    pub(crate) fn first_direct_dialable(node: &DHTNode) -> Option<MultiAddr> {
        Self::first_direct_dialable_with_filter(node, |_| true)
    }

    /// Return the first `Direct` relay-candidate address that is not on this
    /// node's own WAN.
    ///
    /// Same-WAN and same-machine peers must not be selected as relayers: they
    /// do not provide a distinct public route. Local-scope addresses are
    /// already canonicalized to [`AddressType::Lan`] by
    /// [`Self::first_direct_dialable_with_filter`].
    pub(crate) fn first_direct_dialable_for_relay(
        node: &DHTNode,
        context: &DialAddressContext,
    ) -> Option<MultiAddr> {
        if context.local_wan_ips.is_empty() {
            return Self::first_direct_dialable(node);
        }
        Self::first_direct_dialable_with_filter(node, |addr| {
            !context.address_shares_local_wan(addr)
        })
    }

    /// Predicate: is this address dialable (QUIC, non-unspecified)?
    ///
    /// Centralised so the typed dial path and the transport-bridge sites
    /// (which only have bare `MultiAddr` lists from the transport layer's
    /// peer info) emit the same trace/warn output for rejected addresses.
    /// Loopback is accepted — the actual loopback gate lives in
    /// [`crate::dht::core_engine::DhtCoreEngine::replace_node_addresses`]
    /// and the per-node `allow_loopback` config.
    fn is_dialable(addr: &MultiAddr) -> bool {
        let Some(sa) = addr.dialable_socket_addr() else {
            trace!("Skipping non-dialable address: {addr}");
            return false;
        };
        if sa.ip().is_unspecified() {
            warn!("Rejecting unspecified address: {addr}");
            return false;
        }
        if sa.ip().is_loopback() {
            trace!("Accepting loopback address (local/test): {addr}");
        }
        true
    }

    /// Try dialing the bounded per-family plan chosen by
    /// [`Self::select_dial_candidates`]. Returns the transport channel ID on
    /// the first success, `None` if every attempted dial failed.
    ///
    /// The caller hands in typed pairs from a `DHTNode` (via
    /// [`DHTNode::typed_addresses`]) or a candidate list returned by
    /// [`Self::peer_addresses_for_dial_typed`]. Ordering of the input slice
    /// does not matter for correctness — the selector picks deterministically
    /// by [`AddressType`].
    ///
    /// Addresses that failed a dial within the last
    /// [`DIAL_FAILURE_CACHE_TTL`] are **not re-dialed**, but they still
    /// consume one of the plan slots — a fully cached plan therefore
    /// returns `None` without trying anything further down the priority
    /// list. This stops a peer that republishes the same broken Direct /
    /// Unverified / Lan set on every DHT query from causing a dial retry
    /// every time we encounter them.
    ///
    /// Bails out early when the peer is already connected — the caller
    /// would otherwise be paying N redundant `is_peer_connected` reads
    /// (one per address) only to learn the dial is unnecessary.
    async fn dial_addresses(
        &self,
        peer_id: &PeerId,
        typed_addresses: &[(MultiAddr, AddressType)],
    ) -> Option<String> {
        if self.transport.is_peer_connected(peer_id).await {
            trace!(
                "dial_addresses: peer {} already connected, skipping dial",
                peer_id.to_hex()
            );
            return None;
        }
        let plan = self.contextual_dial_plan(typed_addresses).await;
        if plan.is_empty() {
            debug!(
                "dial_addresses: no dialable addresses for {}",
                peer_id.to_hex()
            );
            return None;
        }
        let mut attempted = 0usize;
        let mut skipped_cached = 0usize;
        for (addr, ty) in &plan {
            attempted += 1;
            let Some(socket_addr) = addr.dialable_socket_addr() else {
                continue;
            };
            if self
                .dial_failure_cache
                .is_failed_for_dial(peer_id, &socket_addr, *ty)
            {
                skipped_cached += 1;
                trace!(
                    "dial_addresses: skipping recently failed address {} ({:?}) for {}",
                    addr,
                    ty,
                    peer_id.to_hex()
                );
                continue;
            }
            match self.dial_candidate(peer_id, addr, *ty).await {
                Some(channel_id) => {
                    self.dial_failure_cache.clear(&socket_addr);
                    return Some(channel_id);
                }
                None => {
                    self.dial_failure_cache.record_failure(socket_addr, *ty);
                }
            }
        }
        debug!(
            "dial_addresses: all {} attempted address(es) failed for {} ({} skipped from failure cache)",
            attempted,
            peer_id.to_hex(),
            skipped_cached
        );
        None
    }

    /// Return true when a FIND_NODE candidate has no useful dial attempt left
    /// right now because every address in the dial plan is cooling down in the
    /// shared failed-address cache.
    ///
    /// Already-connected peers are still queryable even if their advertised
    /// addresses are cached as failed, because the request path can reuse the
    /// open channel without dialing.
    async fn lookup_candidate_dial_plan_is_exhausted(&self, node: &DHTNode) -> bool {
        let typed = node.typed_addresses();
        if !self
            .dial_plan_fully_failed_in_cache_for_local(&node.peer_id, &typed)
            .await
        {
            return false;
        }

        !self.transport.is_peer_connected(&node.peer_id).await
    }

    #[cfg(test)]
    fn dial_plan_fully_failed_in_cache(
        cache: &DialFailureCache,
        typed_addresses: &[(MultiAddr, AddressType)],
    ) -> bool {
        let plan = Self::select_dial_candidates(typed_addresses);
        !plan.is_empty()
            && plan.iter().all(|(addr, ty)| {
                addr.dialable_socket_addr()
                    .is_some_and(|socket_addr| cache.is_failed(&socket_addr, *ty))
            })
    }

    pub(crate) async fn local_dial_address_context(&self) -> DialAddressContext {
        let external = self.transport.non_relay_external_addresses();
        let listen = self.transport.listen_addrs().await;
        DialAddressContext::from_parts(external, listen, self.config.node_config.allow_loopback)
    }

    async fn filter_lan_addresses_for_store(
        &self,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        transport_source: Option<&MultiAddr>,
    ) -> Vec<(MultiAddr, AddressType)> {
        let context = self.local_dial_address_context().await;
        Self::filter_lan_addresses_for_store_with_context(
            typed_addresses,
            transport_source,
            &context,
        )
    }

    fn filter_lan_addresses_for_store_with_context(
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        transport_source: Option<&MultiAddr>,
        context: &DialAddressContext,
    ) -> Vec<(MultiAddr, AddressType)> {
        let canonical: Vec<_> = typed_addresses
            .into_iter()
            .map(|(addr, ty)| {
                let ty = AddressType::for_advertised_address(&addr, ty);
                (addr, ty)
            })
            .collect();

        let arrived_over_lan = transport_source
            .and_then(MultiAddr::ip)
            .is_some_and(is_lan_ip);
        if arrived_over_lan || context.peer_shares_wan(&canonical) {
            return canonical;
        }

        canonical
            .into_iter()
            .filter(|(_, ty)| *ty != AddressType::Lan)
            .collect()
    }

    async fn contextual_dial_plan(
        &self,
        typed_addresses: &[(MultiAddr, AddressType)],
    ) -> Vec<(MultiAddr, AddressType)> {
        let context = self.local_dial_address_context().await;
        Self::select_dial_candidates_with_context(typed_addresses, &context)
    }

    async fn dial_plan_fully_failed_in_cache_for_local(
        &self,
        peer: &PeerId,
        typed_addresses: &[(MultiAddr, AddressType)],
    ) -> bool {
        let plan = self.contextual_dial_plan(typed_addresses).await;
        !plan.is_empty()
            && plan.iter().all(|(addr, ty)| {
                addr.dialable_socket_addr().is_some_and(|socket_addr| {
                    self.dial_failure_cache
                        .is_failed_for_dial(peer, &socket_addr, *ty)
                })
            })
    }

    async fn record_peer_failure(&self, peer_id: &PeerId, reason: &'static str) {
        if let Some(ref engine) = self.trust_engine {
            engine.update_node_stats_with_reason(
                peer_id,
                NodeStatisticsUpdate::FailedResponse,
                reason,
            );
        }
        self.enforce_trust_quarantine(peer_id).await;
    }

    pub(crate) async fn enforce_trust_quarantine(&self, peer_id: &PeerId) -> bool {
        let Some(ref engine) = self.trust_engine else {
            return false;
        };
        let trust_score = engine.score(peer_id);
        let rt_events = self.enforce_close_group_trust_gate().await;
        if rt_events.is_empty() {
            return false;
        }
        info!(
            "Evicted quarantined close-group peer(s) after trust update for {} with trust {:.3}",
            peer_id.to_hex(),
            trust_score
        );
        self.broadcast_routing_events(&rt_events);
        true
    }

    fn peer_trust_score(&self, peer_id: &PeerId) -> f64 {
        self.trust_engine
            .as_ref()
            .map(|engine| engine.score(peer_id))
            .unwrap_or(DEFAULT_NEUTRAL_TRUST)
    }

    async fn should_avoid_automatic_peer(&self, peer_id: &PeerId) -> bool {
        let trust_score = self.peer_trust_score(peer_id);
        let dht = self.dht.read().await;
        dht.should_avoid_automatic_candidate(peer_id, trust_score)
            .await
    }

    /// Ensure an identity-authenticated channel to `peer_id` exists,
    /// collapsing concurrent calls for the same peer onto a single
    /// dial + identity-exchange sequence.
    ///
    /// Without this dedup every task that enters the window between
    /// the QUIC handshake completing and the peer's first signed
    /// identity message arriving sees `is_peer_connected` return
    /// `false` and kicks off its own
    /// `dial_addresses → connect_peer` cascade. Those redundant
    /// dials spawn duplicate reader tasks on the shared QUIC
    /// connection and, in practice, trip the remote's
    /// simultaneous-open detector into closing the channel with
    /// `b"duplicate"` — which tears down the working connection.
    ///
    /// The first task to arrive for a given `peer_id` becomes the
    /// dial owner: it runs the dial, awaits identity exchange,
    /// performs any cleanup (channel disconnect, trust penalty),
    /// then broadcasts the outcome to every subscriber before
    /// removing the coordinator entry. Subsequent tasks that race in
    /// while the dial is in flight subscribe to the owner's
    /// broadcast and translate the shared outcome back into a
    /// caller-facing [`P2PError`] — they do not duplicate the
    /// owner's side effects.
    async fn ensure_peer_channel(
        &self,
        peer_id: &PeerId,
        candidates: &[(MultiAddr, AddressType)],
    ) -> Result<()> {
        // Fast path: identity exchange already completed for this peer.
        if self.transport.is_peer_connected(peer_id).await {
            return Ok(());
        }

        let local_hex = self.config.peer_id.to_hex();
        let peer_hex = peer_id.to_hex();

        // Try to claim the coordinator slot. If another task is
        // already dialing this peer, the Occupied branch returns us
        // a subscription to their outcome; only the Vacant branch
        // runs the actual dial. Doing the check via the `entry` API
        // prevents the contains/insert TOCTOU that would otherwise
        // let two tasks both see "no existing dial" and start their
        // own cascades in parallel.
        //
        // The identity-failure cache check lives **inside** the Vacant
        // branch — not before the entry call — so that subscribers
        // to an in-flight dial (Occupied branch) still receive its
        // genuine outcome rather than being short-circuited by a
        // stale cache entry from a prior attempt that the in-flight
        // dial may already be on track to invalidate.
        let tx = match self.pending_peer_dials.entry(*peer_id) {
            DashEntry::Occupied(entry) => {
                let mut rx = entry.get().subscribe();
                drop(entry);
                debug!(
                    "[STEP 1b] {} -> {}: joining in-flight dial",
                    local_hex, peer_hex
                );
                return match rx.recv().await {
                    Ok(outcome) => outcome.into_result(peer_id),
                    Err(_) => Err(P2PError::Network(NetworkError::PeerNotFound(
                        format!(
                            "in-flight dial to {} dropped before producing a result",
                            peer_hex
                        )
                        .into(),
                    ))),
                };
            }
            DashEntry::Vacant(entry) => {
                if self.identity_failure_cache.is_failed(peer_id) {
                    debug!(
                        "[STEP 1b] {} -> {}: suppressed by identity-failure cache",
                        local_hex, peer_hex
                    );
                    return Err(P2PError::Network(NetworkError::ProtocolError(
                        format!(
                            "identity exchange with {} suppressed (recent failure)",
                            peer_hex
                        )
                        .into(),
                    )));
                }
                let (tx, _) = broadcast::channel(PENDING_DIAL_BROADCAST_CAPACITY);
                entry.insert(tx.clone());
                tx
            }
        };

        // We own the dial. Make absolutely sure the coordinator slot
        // is cleared no matter how we exit from here — a panic or
        // early return would otherwise leave a permanent entry that
        // causes every future dial to this peer to wait on a dead
        // broadcast.
        struct DialGuard<'a> {
            map: &'a DashMap<PeerId, broadcast::Sender<PendingDialOutcome>>,
            peer_id: PeerId,
            cleared: bool,
        }
        impl<'a> Drop for DialGuard<'a> {
            fn drop(&mut self) {
                if !self.cleared {
                    self.map.remove(&self.peer_id);
                }
            }
        }
        let mut guard = DialGuard {
            map: &self.pending_peer_dials,
            peer_id: *peer_id,
            cleared: false,
        };

        let outcome = self
            .run_owned_dial(peer_id, candidates, &local_hex, &peer_hex)
            .await;

        // Stale routing entries: when the remote authenticated as a
        // different peer, the expected `peer_id` doesn't actually
        // live at any of the candidate addresses. Leaving it in the
        // routing table causes every future DHT lookup that hits
        // this peer_id to pay another `connect_peer` +
        // `wait_for_peer_identity` round-trip only to fail with the
        // same mismatch — so drop it now. The real peer (carried as
        // `actual` in the outcome) is learned via the normal
        // connection-event path that registers it against the
        // channel it actually authenticated on.
        if matches!(outcome, PendingDialOutcome::IdentityMismatch { .. }) {
            let rt_events = {
                let mut dht = self.dht.write().await;
                dht.remove_node_by_id(peer_id).await
            };
            self.broadcast_routing_events_with_quarantine(rt_events)
                .await;
        }

        // Broadcast and clear. Remove BEFORE sending so any task
        // arriving between send and this remove creates a fresh dial
        // rather than waiting on a coordinator whose result has
        // already been delivered.
        self.pending_peer_dials.remove(peer_id);
        guard.cleared = true;
        // `send` fails only if there are no subscribers — that's the
        // common case (we're the only caller), so ignore the error.
        let _ = tx.send(outcome.clone());

        outcome.into_result(peer_id)
    }

    /// Owner-side dial + identity exchange for
    /// [`Self::ensure_peer_channel`]. Runs outside the coordinator
    /// bookkeeping so the owner's side effects (disconnect on
    /// failure, trust penalty) happen exactly once per dial, not
    /// once per subscribed caller.
    async fn run_owned_dial(
        &self,
        peer_id: &PeerId,
        candidates: &[(MultiAddr, AddressType)],
        local_hex: &str,
        peer_hex: &str,
    ) -> PendingDialOutcome {
        info!(
            "[STEP 1b] {} -> {}: No open channel, trying {} dialable address(es)",
            local_hex,
            peer_hex,
            candidates.len()
        );

        let Some(channel_id) = self.dial_addresses(peer_id, candidates).await else {
            warn!(
                "[STEP 1b] {} -> {}: dial failed for all {} candidate address(es)",
                local_hex,
                peer_hex,
                candidates.len()
            );
            self.record_peer_failure(peer_id, TRUST_REASON_DHT_DIAL_FAILED)
                .await;
            return PendingDialOutcome::DialFailed {
                candidates_count: candidates.len(),
            };
        };

        let identity_timeout = self.config.request_timeout.min(IDENTITY_EXCHANGE_TIMEOUT);
        match self
            .transport
            .wait_for_peer_identity(&channel_id, identity_timeout)
            .await
        {
            Ok(authenticated) if &authenticated == peer_id => {
                debug!(
                    "[STEP 1b] {} -> {}: identity confirmed ({})",
                    local_hex,
                    peer_hex,
                    authenticated.to_hex()
                );
                // Drop any cached identity-failure entry: the peer is
                // currently healthy and a stale entry would suppress
                // legitimate dials from other call sites that race in
                // before TTL expiry.
                self.identity_failure_cache.clear(peer_id);
                PendingDialOutcome::Connected
            }
            Ok(authenticated) => {
                warn!(
                    "[STEP 1b] {} -> {}: identity MISMATCH — authenticated as {}. \
                     Routing table entry may be stale.",
                    local_hex,
                    peer_hex,
                    authenticated.to_hex()
                );
                // Suppress further dials to the *expected* peer_id
                // for [`IDENTITY_MISMATCH_CACHE_TTL`]. Local routing
                // eviction (via `remove_node_by_id` in
                // `ensure_peer_channel`) only cleans our own table —
                // authenticated neighbours keep gossiping the stale
                // peer_id in FIND_NODE responses, and without this
                // cache entry every iteration of an iterative lookup
                // would re-dial the same address, hit the same
                // mismatch, and pay another 5 s identity-exchange
                // timeout. The real peer at this address (`actual`)
                // is learned via the connection-event path and is
                // unaffected.
                self.identity_failure_cache.record_mismatch(*peer_id);
                PendingDialOutcome::IdentityMismatch {
                    actual: authenticated,
                }
            }
            Err(e) => {
                warn!(
                    "[STEP 1b] {} -> {}: identity exchange failed, disconnecting channel: {}",
                    local_hex, peer_hex, e
                );
                self.transport.disconnect_channel(&channel_id).await;
                self.record_peer_failure(peer_id, TRUST_REASON_DHT_IDENTITY_EXCHANGE_FAILED)
                    .await;
                // Suppress further dials to this peer for
                // [`IDENTITY_FAILURE_CACHE_TTL`] so that the next
                // iterative DHT lookup (or chunk-fetch close-group
                // walk) doesn't pay the same 5 s timeout against the
                // same broken peer the next time it shows up as a
                // candidate in someone else's FIND_NODE response.
                self.identity_failure_cache.record_failure(*peer_id);
                PendingDialOutcome::IdentityFailed { err: e.to_string() }
            }
        }
    }

    /// Remove expired operations from `active_operations`.
    ///
    /// Uses a 2x timeout multiplier as safety margin. Called at the start of
    /// `send_dht_request` to clean up orphaned entries from dropped futures.
    fn sweep_expired_operations(&self) {
        let mut ops = match self.active_operations.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "active_operations mutex poisoned in sweep_expired_operations, recovering"
                );
                poisoned.into_inner()
            }
        };
        let now = Instant::now();
        ops.retain(|id, ctx| {
            let expired = now.duration_since(ctx.started_at) > ctx.timeout * 2;
            if expired {
                warn!(
                    "Sweeping expired DHT operation {id} (age {:?}, timeout {:?})",
                    now.duration_since(ctx.started_at),
                    ctx.timeout
                );
            }
            !expired
        });
    }

    /// Send a DHT request to a specific peer.
    ///
    /// When `candidates` is `Some(...)`, those typed addresses are used
    /// for the pre-send dial — typically passed through from an iterative
    /// lookup batch so we don't pay a second routing-table read inside
    /// this function. When `None`, [`Self::peer_addresses_for_dial_typed`]
    /// is consulted (the routing table is the authoritative source).
    async fn send_dht_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
        candidates: Option<&[(MultiAddr, AddressType)]>,
    ) -> Result<DhtNetworkResult> {
        Ok(self
            .send_dht_request_with_response_context(peer_id, operation, candidates)
            .await?
            .result)
    }

    async fn send_dht_request_with_response_context(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
        candidates: Option<&[(MultiAddr, AddressType)]>,
    ) -> Result<DhtResponseEnvelope> {
        // Sweep stale entries left by dropped futures before adding a new one
        self.sweep_expired_operations();

        let message_id = Uuid::new_v4().to_string();

        let message = DhtNetworkMessage {
            message_id: message_id.clone(),
            source: self.config.peer_id,
            target: Some(*peer_id),
            message_type: DhtMessageType::Request,
            payload: operation,
            result: None, // Requests don't have results
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: 10,
            hop_count: 0,
        };

        // Serialize message
        let message_data = postcard::to_stdvec(&message)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        // Create oneshot channel for response delivery
        // This eliminates TOCTOU races - no polling, no shared mutable state
        let (response_tx, response_rx) = oneshot::channel();

        // Only track app-level peer IDs. Transport IDs identify communication
        // channels, not peers — multiple peers may share one transport in the future.
        let contacted_nodes = vec![*peer_id];

        // Create operation context for tracking
        let operation_context = DhtOperationContext {
            operation: message.payload.clone(),
            peer_id: *peer_id,
            started_at: Instant::now(),
            timeout: self.config.request_timeout,
            contacted_nodes,
            response_tx: Some(response_tx),
        };

        if let Ok(mut ops) = self.active_operations.lock() {
            ops.insert(message_id.clone(), operation_context);
        }

        // Send message via network layer, reconnecting on demand if needed.
        // Hex-encode peer IDs lazily inside each tracing macro: tracing only
        // evaluates the macro's arguments when the level is enabled, so we
        // pay the allocation cost only on warn (rare) or when DEBUG logging
        // is explicitly turned on.
        debug!(
            "[STEP 1] {} -> {}: Sending {:?} request (msg_id: {})",
            self.config.peer_id.to_hex(),
            peer_id.to_hex(),
            message.payload,
            message_id
        );

        // Ensure we have an identity-authenticated channel to the
        // peer before sending. A fresh dial establishes a QUIC
        // connection but the app-level `peer_to_channel` mapping is
        // only populated after the asynchronous identity-exchange
        // handshake completes — without waiting, a subsequent
        // `send_message` would fail with `PeerNotFound`.
        //
        // Build the candidate address list. When the caller already
        // has typed addresses for this peer (e.g., the iterative
        // lookup batch passes the same `node.typed_addresses()` it
        // just read), use those directly to avoid a redundant
        // routing-table read; otherwise consult the routing table.
        // Trying every candidate — rather than stopping at the first
        // — protects against stale NAT bindings, single-IP-family
        // failures, and recently-relayed peers whose direct address
        // is no longer reachable.
        //
        // [`Self::ensure_peer_channel`] collapses concurrent calls
        // for the same peer onto a single dial so N parallel DHT
        // lookups that all target the same popular peer don't each
        // start their own dial cascade in the identity-exchange
        // window.
        let candidate_addresses: Vec<(MultiAddr, AddressType)> = if let Some(provided) = candidates
        {
            provided.to_vec()
        } else {
            self.peer_addresses_for_dial_typed(peer_id).await
        };
        if let Err(e) = self
            .ensure_peer_channel(peer_id, &candidate_addresses)
            .await
        {
            if let Ok(mut ops) = self.active_operations.lock() {
                ops.remove(&message_id);
            }
            return Err(e);
        }

        let result = match self
            .transport
            .send_message(peer_id, "/dht/1.0.0", message_data)
            .await
        {
            Ok(_) => {
                debug!(
                    "[STEP 2] {} -> {}: Message sent successfully, waiting for response...",
                    self.config.peer_id.to_hex(),
                    peer_id.to_hex()
                );

                // Wait for response via oneshot channel with timeout
                let result = self
                    .wait_for_response(&message_id, response_rx, peer_id)
                    .await;
                match &result {
                    Ok(r) => debug!(
                        "[STEP 6] {} <- {}: Got response: {:?}",
                        self.config.peer_id.to_hex(),
                        peer_id.to_hex(),
                        std::mem::discriminant(&r.result)
                    ),
                    Err(e) => warn!(
                        "[STEP 6 FAILED] {} <- {}: Response error: {}",
                        self.config.peer_id.to_hex(),
                        peer_id.to_hex(),
                        e
                    ),
                }
                result
            }
            Err(e) => {
                warn!(
                    "[STEP 1 FAILED] Failed to send DHT request to {}: {}",
                    peer_id.to_hex(),
                    e
                );
                Err(e)
            }
        };

        // Explicit cleanup — no Drop guard, no tokio::spawn required
        if let Ok(mut ops) = self.active_operations.lock() {
            ops.remove(&message_id);
        }

        // Record trust failure at the RPC level so every failed request
        // (send error, response timeout, etc.) is counted exactly once.
        if result.is_err() {
            self.record_peer_failure(peer_id, TRUST_REASON_DHT_REQUEST_FAILED)
                .await;
        }

        result
    }

    /// Check whether `peer_id` refers to this node.
    fn is_local_peer_id(&self, peer_id: &PeerId) -> bool {
        *peer_id == self.config.peer_id
    }

    /// Resolve any peer identifier to a canonical app-level peer ID.
    ///
    /// For signed messages the event `source` is already the app-level peer ID
    /// (set by `parse_protocol_message`), so `is_known_app_peer_id` succeeds
    /// directly. For unsigned connections the channel ID itself is used as
    /// identity (e.g. in tests).
    async fn canonical_app_peer_id(&self, peer_id: &PeerId) -> Option<PeerId> {
        // Check if this is a known app-level peer ID
        if self.transport.is_known_app_peer_id(peer_id).await {
            return Some(*peer_id);
        }
        // Fallback: connected transport peer (unsigned connections)
        if self.transport.is_peer_connected(peer_id).await {
            return Some(*peer_id);
        }
        None
    }

    /// Attempt to connect to a candidate peer with a timeout derived from the node config.
    ///
    /// All iterative lookups share the same saorsa-transport connection pool, so reusing the node's
    /// connection timeout keeps behavior consistent with the transport while still letting
    /// us parallelize lookups safely.
    ///
    /// Returns the transport channel ID on a successful QUIC connection, or
    /// `None` when the dial fails or is skipped. Callers that need to send
    /// messages immediately should pass the channel ID to
    /// [`TransportHandle::wait_for_peer_identity`] before sending, because
    /// the app-level `peer_to_channel` mapping is only populated after the
    /// asynchronous identity-exchange handshake completes.
    async fn dial_candidate(
        &self,
        peer_id: &PeerId,
        address: &MultiAddr,
        kind: AddressType,
    ) -> Option<String> {
        let peer_hex = peer_id.to_hex();

        // Reject unspecified addresses before attempting the connection.
        if address.ip().is_some_and(|ip| ip.is_unspecified()) {
            debug!(
                "dial_candidate: rejecting unspecified address for {}: {} ({:?})",
                peer_hex, address, kind
            );
            return None;
        }

        match self.transport.connect_peer_typed(address, kind).await {
            Ok(channel_id) => {
                debug!(
                    "dial_candidate: connected to {} at {} ({:?}) (channel {})",
                    peer_hex, address, kind, channel_id
                );
                Some(channel_id)
            }
            Err(e) => {
                debug!(
                    "dial_candidate: failed to connect to {} at {} ({:?}): {}",
                    peer_hex, address, kind, e
                );
                None
            }
        }
    }

    /// Look up connectable typed addresses for `peer_id`.
    ///
    /// Checks the DHT routing table first (source of truth for DHT peer
    /// addresses), then falls back to the transport layer for connected
    /// peers. Returns an empty vec when the peer is unknown or has no
    /// dialable addresses.
    ///
    /// Result is sorted by [`AddressType`] priority — Relay first
    /// (known-good relay endpoint), then Direct, Unverified, and Lan. The
    /// final dial plan may override this order for same-WAN peers so LAN
    /// routes are tried first only when they are plausible.
    pub(crate) async fn peer_addresses_for_dial_typed(
        &self,
        peer_id: &PeerId,
    ) -> Vec<(MultiAddr, AddressType)> {
        // 1. Routing table — filter to dialable QUIC addresses and sort
        //    by AddressType priority (Relay first).
        let typed = self
            .dht
            .read()
            .await
            .get_node_addresses_typed(peer_id)
            .await;
        if !typed.is_empty() {
            return Self::dialable_addresses_typed(&typed);
        }

        // 2. Transport layer — for connected peers not yet in the
        //    routing table. Local-scope addresses are tagged `Lan`; all
        //    other addresses are `Unverified` because a transport-level
        //    handshake does not prove the address is cold-dialable from
        //    arbitrary peers. `Unverified` remains dialable for regular DHT
        //    ops, but relay-candidate selection (which requires `Direct`)
        //    correctly skips it.
        if let Some(info) = self.transport.peer_info(peer_id).await {
            return info
                .addresses
                .into_iter()
                .filter(Self::is_dialable)
                .map(|a| {
                    let ty = if a.ip().is_some_and(is_lan_ip) {
                        AddressType::Lan
                    } else {
                        AddressType::Unverified
                    };
                    (a, ty)
                })
                .collect();
        }

        Vec::new()
    }

    /// Filter and sort typed addresses by [`AddressType::priority`].
    ///
    /// Relay first, Direct second, Unverified third, Lan last. Stable
    /// sort within each tier preserves the input order, so callers that
    /// hand in addresses in a meaningful sub-order (e.g., IPv6 before
    /// IPv4) keep that order within the type tier.
    fn dialable_addresses_typed(
        typed: &[(MultiAddr, AddressType)],
    ) -> Vec<(MultiAddr, AddressType)> {
        let mut candidates: Vec<(MultiAddr, AddressType)> = typed
            .iter()
            .filter(|pair| Self::is_dialable(&pair.0))
            .map(|(addr, ty)| {
                let ty = AddressType::for_advertised_address(addr, *ty);
                (addr.clone(), ty)
            })
            .collect();

        candidates.sort_by_key(|pair| pair.1.priority());

        candidates
    }

    /// Pick a bounded per-family address plan for a single peer, applying
    /// the cold-start policy documented on [`Self::dial_addresses`].
    ///
    /// Context-free rules:
    /// - Relay is preferred first unless the relay endpoint is on our own
    ///   WAN IP.
    /// - Then dial at most one best WAN address per IP family. Direct wins
    ///   over Unverified.
    /// - LAN addresses are used only when there is no WAN/relay alternative.
    ///
    /// The live dial path calls [`Self::select_dial_candidates_with_context`]
    /// instead so same-WAN peers can use LAN routes before relay/direct.
    #[cfg(test)]
    fn select_dial_candidates(typed: &[(MultiAddr, AddressType)]) -> Vec<(MultiAddr, AddressType)> {
        Self::select_dial_candidates_with_context(typed, &DialAddressContext::default())
    }

    fn select_dial_candidates_with_context(
        typed: &[(MultiAddr, AddressType)],
        context: &DialAddressContext,
    ) -> Vec<(MultiAddr, AddressType)> {
        let mut relay: Option<(MultiAddr, AddressType)> = None;
        let mut wan_v4: Option<(usize, MultiAddr, AddressType)> = None;
        let mut wan_v6: Option<(usize, MultiAddr, AddressType)> = None;
        let mut lan_v4: Option<(usize, u8, MultiAddr, AddressType)> = None;
        let mut lan_v6: Option<(usize, u8, MultiAddr, AddressType)> = None;

        for (index, (addr, ty)) in typed.iter().enumerate() {
            if !Self::is_dialable(addr) {
                continue;
            }
            let ty = AddressType::for_advertised_address(addr, *ty);
            if ty == AddressType::Relay {
                if relay.is_none() && !context.address_shares_local_wan(addr) {
                    relay = Some((addr.clone(), ty));
                }
                continue;
            }

            let Some(socket_addr) = addr.dialable_socket_addr() else {
                continue;
            };
            let normalized = saorsa_transport::shared::normalize_socket_addr(socket_addr);
            if ty == AddressType::Lan {
                let score = context.lan_match_score(normalized.ip());
                let slot = if normalized.ip().is_ipv4() {
                    &mut lan_v4
                } else {
                    &mut lan_v6
                };
                let should_replace = slot
                    .as_ref()
                    .map(|(existing_index, existing_score, _, _)| {
                        score < *existing_score
                            || (score == *existing_score && index < *existing_index)
                    })
                    .unwrap_or(true);
                if should_replace {
                    *slot = Some((index, score, addr.clone(), ty));
                }
                continue;
            }

            let slot = if normalized.ip().is_ipv4() {
                &mut wan_v4
            } else {
                &mut wan_v6
            };
            let should_replace = slot
                .as_ref()
                .map(|(_, _, existing_ty)| ty.priority() < existing_ty.priority())
                .unwrap_or(true);
            if should_replace {
                *slot = Some((index, addr.clone(), ty));
            }
        }

        let mut out = Vec::with_capacity(MAX_DIAL_PLAN_SIZE);
        let mut lan: Vec<_> = [lan_v4, lan_v6].into_iter().flatten().collect();
        lan.sort_by_key(|(index, score, _, _)| (*score, *index));
        let mut wan: Vec<_> = [wan_v4, wan_v6].into_iter().flatten().collect();
        wan.sort_by_key(|(index, _, _)| *index);

        let has_wan_or_relay = relay.is_some() || !wan.is_empty();
        let prefer_lan = !lan.is_empty() && context.peer_shares_wan(typed);

        if prefer_lan {
            out.extend(lan.iter().map(|(_, _, addr, ty)| (addr.clone(), *ty)));
        }
        if let Some(relay) = relay {
            out.push(relay);
        }
        out.extend(wan.into_iter().map(|(_, addr, ty)| (addr, ty)));
        if !prefer_lan && !has_wan_or_relay {
            out.extend(lan.into_iter().map(|(_, _, addr, ty)| (addr, ty)));
        }
        out
    }

    /// Wait for DHT network response via oneshot channel with timeout
    ///
    /// Uses oneshot channel instead of polling to eliminate TOCTOU races entirely.
    /// The channel is created in send_dht_request and the sender is stored in the
    /// operation context. When handle_dht_response receives a response, it sends
    /// through the channel. This function awaits on the receiver with timeout.
    ///
    /// When the oneshot sender is dropped, the receiver gets a `RecvError`
    /// and we return a `ProtocolError`.
    ///
    /// Note: cleanup of `active_operations` is handled by explicit removal in the
    /// caller (`send_dht_request`), so this method does not remove entries itself.
    async fn wait_for_response(
        &self,
        _message_id: &str,
        response_rx: oneshot::Receiver<DhtResponseEnvelope>,
        _peer_id: &PeerId,
    ) -> Result<DhtResponseEnvelope> {
        let response_timeout = self.config.request_timeout;

        // Wait for response with timeout - no polling, no TOCTOU race
        match tokio::time::timeout(response_timeout, response_rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_recv_error)) => {
                // Channel closed without response (sender dropped).
                Err(P2PError::Network(NetworkError::ProtocolError(
                    "Response channel closed unexpectedly".into(),
                )))
            }
            Err(_timeout) => Err(P2PError::Network(NetworkError::Timeout)),
        }
    }

    /// Handle incoming DHT message
    pub async fn handle_dht_message(
        &self,
        data: &[u8],
        sender: &PeerId,
        transport_source: Option<&MultiAddr>,
    ) -> Result<Option<Vec<u8>>> {
        // SEC: Reject oversized messages before deserialization to prevent memory exhaustion
        if data.len() > MAX_MESSAGE_SIZE {
            warn!(
                "Rejecting oversized DHT message from {sender}: {} bytes (max: {MAX_MESSAGE_SIZE})",
                data.len()
            );
            return Err(P2PError::Validation(
                format!(
                    "Message size {} bytes exceeds maximum allowed size of {MAX_MESSAGE_SIZE} bytes",
                    data.len()
                )
                .into(),
            ));
        }

        // Deserialize message
        let message: DhtNetworkMessage = postcard::from_bytes(data)
            .map_err(|e| P2PError::Serialization(e.to_string().into()))?;

        debug!(
            "[STEP 3] {}: Received {:?} from {} (msg_id: {})",
            self.config.peer_id.to_hex(),
            message.message_type,
            sender,
            message.message_id
        );

        // Update peer info
        self.update_peer_info(*sender, &message).await;

        match message.message_type {
            DhtMessageType::Request => {
                debug!(
                    "[STEP 3a] {}: Processing {:?} request from {}",
                    self.config.peer_id.to_hex(),
                    message.payload,
                    sender
                );
                let result = self
                    .handle_dht_request(&message, sender, transport_source)
                    .await?;
                debug!(
                    "[STEP 4] {}: Sending response {:?} back to {} (msg_id: {})",
                    self.config.peer_id.to_hex(),
                    std::mem::discriminant(&result),
                    sender,
                    message.message_id
                );
                let response = self.create_response_message(&message, result)?;
                Ok(Some(postcard::to_stdvec(&response).map_err(|e| {
                    P2PError::Serialization(e.to_string().into())
                })?))
            }
            DhtMessageType::Response => {
                debug!(
                    "[STEP 5] {}: Received response from {} (msg_id: {})",
                    self.config.peer_id.to_hex(),
                    sender,
                    message.message_id
                );
                self.handle_dht_response(&message, sender, transport_source)
                    .await?;
                Ok(None)
            }
            DhtMessageType::Broadcast => {
                self.handle_dht_broadcast(&message).await?;
                Ok(None)
            }
            DhtMessageType::Error => {
                warn!("Received DHT error message: {:?}", message);
                Ok(None)
            }
        }
    }

    /// Handle DHT request message.
    ///
    /// `authenticated_sender` is the transport-authenticated peer ID, used
    /// instead of the self-reported `message.source` for any security-sensitive
    /// decisions (e.g. filtering nodes in lookup responses).
    async fn handle_dht_request(
        &self,
        message: &DhtNetworkMessage,
        authenticated_sender: &PeerId,
        transport_source: Option<&MultiAddr>,
    ) -> Result<DhtNetworkResult> {
        match &message.payload {
            DhtNetworkOperation::FindNode { key } => {
                debug!("Handling FIND_NODE request for key: {}", hex::encode(key));
                self.handle_find_node_request(key, authenticated_sender)
                    .await
            }
            DhtNetworkOperation::Ping => {
                debug!("Handling PING request from: {}", authenticated_sender);
                Ok(DhtNetworkResult::PongReceived {
                    responder: self.config.peer_id,
                    latency: Duration::from_millis(0), // Local response
                })
            }
            DhtNetworkOperation::Join => {
                debug!("Handling JOIN request from: {}", authenticated_sender);
                let dht_key = *authenticated_sender.as_bytes();

                // Node will be added to routing table through normal DHT operations
                debug!("Node {} joined the network", authenticated_sender);

                Ok(DhtNetworkResult::JoinSuccess {
                    assigned_key: dht_key,
                    bootstrap_peers: 1,
                })
            }
            DhtNetworkOperation::Leave => {
                debug!("Handling LEAVE request from: {}", authenticated_sender);
                Ok(DhtNetworkResult::LeaveSuccess)
            }
            DhtNetworkOperation::PublishAddressSet { seq, addresses } => {
                info!(
                    "Handling PUBLISH_ADDRESS_SET from {}: seq={} addrs={}",
                    authenticated_sender,
                    seq,
                    addresses.len()
                );
                let filtered_addresses = self
                    .filter_lan_addresses_for_store(addresses.clone(), transport_source)
                    .await;
                let stripped = addresses.len().saturating_sub(filtered_addresses.len());
                if stripped > 0 {
                    debug!(
                        peer = %authenticated_sender.to_hex(),
                        seq,
                        stripped,
                        kept = filtered_addresses.len(),
                        "stripped untrusted LAN address(es) from published address set",
                    );
                }
                let dht = self.dht.read().await;
                let applied = dht
                    .replace_node_addresses(authenticated_sender, filtered_addresses.clone(), *seq)
                    .await;
                // ADR-011: a newer authoritative address set just landed — lift
                // stale dial-failure suppression for its addresses so a
                // self-healed (e.g. reclaimed stable relay) address is retried
                // immediately instead of staying suppressed for the cache TTL.
                //
                // Race guard: only exempt addresses that are STILL the peer's
                // current record after the apply (read back under the same lock
                // hold), so a publish superseded by a newer `seq` between the
                // apply and here cannot grant a stale exemption. The exemption is
                // also keyed by the authenticated publisher, so it can only ever
                // benefit a dial to that exact peer.
                let cleared = if applied {
                    let current = dht.get_node_addresses_typed(authenticated_sender).await;
                    let still_current: Vec<(MultiAddr, AddressType)> = filtered_addresses
                        .iter()
                        .filter(|(addr, _)| current.iter().any(|(c, _)| c == addr))
                        .cloned()
                        .collect();
                    clear_dial_failures_for_published(
                        self.dial_failure_cache.as_ref(),
                        authenticated_sender,
                        true,
                        &still_current,
                    )
                } else {
                    0
                };
                drop(dht);
                if cleared > 0 {
                    debug!(
                        peer = %authenticated_sender.to_hex(),
                        seq,
                        cleared,
                        "ADR-011: cleared dial-failure suppression for freshly-published addresses"
                    );
                }
                Ok(DhtNetworkResult::PublishAddressAck)
            }
        }
    }

    /// Send a DHT request directly to a peer.
    ///
    /// Reserved for potential future use beyond peer phonebook/routing.
    #[allow(dead_code)]
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        operation: DhtNetworkOperation,
    ) -> Result<DhtNetworkResult> {
        self.send_dht_request(peer_id, operation, None).await
    }

    /// Handle DHT response message
    ///
    /// Delivers the response via oneshot channel to the waiting request coroutine.
    /// Uses oneshot channel instead of shared Vec to eliminate TOCTOU races.
    ///
    /// Security: Resolves the sender to an authenticated app-level peer ID and
    /// verifies it matches a contacted peer. Transport IDs identify channels,
    /// not peers, so they are never used for authorization.
    async fn handle_dht_response(
        &self,
        message: &DhtNetworkMessage,
        sender: &PeerId,
        transport_source: Option<&MultiAddr>,
    ) -> Result<()> {
        let message_id = &message.message_id;
        debug!("Handling DHT response for message_id: {message_id}");

        // Get the result from the response message
        let result = match &message.result {
            Some(r) => r.clone(),
            None => {
                warn!("DHT response message {message_id} has no result field");
                return Ok(());
            }
        };

        // Resolve sender to app-level identity. Transport IDs identify channels,
        // not peers, so unauthenticated senders are rejected outright.
        let Some(sender_app_id) = self.canonical_app_peer_id(sender).await else {
            warn!(
                "Rejecting DHT response for {message_id}: sender {} has no authenticated app identity",
                sender
            );
            return Ok(());
        };

        // Find the active operation and send response via oneshot channel
        let Ok(mut ops) = self.active_operations.lock() else {
            warn!("active_operations mutex poisoned");
            return Ok(());
        };
        if let Some(context) = ops.get_mut(message_id) {
            // Authenticate solely on app-level peer ID.
            let source_authorized = context.peer_id == sender_app_id
                || context.contacted_nodes.contains(&sender_app_id);

            if !source_authorized {
                warn!(
                    "Rejecting DHT response for {message_id}: sender app_id {} \
                     (transport={}) not in contacted peers (expected {} or one of {:?})",
                    sender_app_id.to_hex(),
                    sender,
                    context.peer_id.to_hex(),
                    context
                        .contacted_nodes
                        .iter()
                        .map(PeerId::to_hex)
                        .collect::<Vec<_>>()
                );
                return Ok(());
            }

            // Take the sender out of the context (can only send once)
            if let Some(tx) = context.response_tx.take() {
                debug!(
                    "[STEP 5a] {}: Delivering response for msg_id {} to waiting request",
                    self.config.peer_id.to_hex(),
                    message_id
                );
                let response = DhtResponseEnvelope {
                    result,
                    transport_source: transport_source.cloned(),
                };
                if tx.send(response).is_err() {
                    warn!(
                        "[STEP 5a FAILED] {}: Response channel closed for msg_id {} (receiver timed out)",
                        self.config.peer_id.to_hex(),
                        message_id
                    );
                }
            } else {
                debug!(
                    "Response already delivered for message_id: {message_id}, ignoring duplicate"
                );
            }
        } else {
            warn!(
                "[STEP 5 FAILED] {}: No active operation found for msg_id {} (may have timed out)",
                self.config.peer_id.to_hex(),
                message_id
            );
        }

        Ok(())
    }

    /// Handle DHT broadcast message
    async fn handle_dht_broadcast(&self, _message: &DhtNetworkMessage) -> Result<()> {
        // Handle broadcast messages (for network-wide announcements)
        debug!("DHT broadcast handling not fully implemented yet");
        Ok(())
    }

    /// Create response message
    fn create_response_message(
        &self,
        request: &DhtNetworkMessage,
        result: DhtNetworkResult,
    ) -> Result<DhtNetworkMessage> {
        // Create a minimal payload that echoes the original operation type
        // Each variant explicitly extracts its key to avoid silent fallbacks
        let payload = match &result {
            DhtNetworkResult::NodesFound { key, .. } => DhtNetworkOperation::FindNode { key: *key },
            DhtNetworkResult::PongReceived { .. } => DhtNetworkOperation::Ping,
            DhtNetworkResult::JoinSuccess { .. } => DhtNetworkOperation::Join,
            DhtNetworkResult::LeaveSuccess => DhtNetworkOperation::Leave,
            // Use Ping as a lightweight ack — avoids echoing the full
            // PublishAddressSet payload (which contains the address list).
            DhtNetworkResult::PublishAddressAck => DhtNetworkOperation::Ping,
            DhtNetworkResult::PeerRejected => request.payload.clone(),
            DhtNetworkResult::Error { .. } => {
                return Err(P2PError::Dht(crate::error::DhtError::RoutingError(
                    "Cannot create response for error result".to_string().into(),
                )));
            }
        };

        Ok(DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: self.config.peer_id,
            target: Some(request.source),
            message_type: DhtMessageType::Response,
            payload,
            result: Some(result),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "System clock error: unable to get current timestamp".into(),
                    ))
                })?
                .as_secs(),
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count.saturating_add(1),
        })
    }

    /// Update routing-table liveness for a peer on successful message
    /// exchange.
    ///
    /// Standard Kademlia: any successful RPC proves liveness. We touch the
    /// routing table entry to move it to the tail of its k-bucket.
    ///
    /// Intentionally does NOT pass an address: transport-layer observations
    /// only prove reachability from *us* to the peer (possibly through a
    /// NAT mapping we opened), not public reachability. Tagging the
    /// observed address as `Direct` here used to poison relay-candidate
    /// selection by making NAT'd peers look cold-dialable. Authoritative
    /// address typing is the peer's responsibility via `PublishAddressSet`;
    /// new peers not yet in the routing table pick up an initial address
    /// list via [`Self::handle_peer_connected`] (tagged `Unverified`).
    async fn update_peer_info(&self, peer_id: PeerId, _message: &DhtNetworkMessage) {
        let Some(app_peer_id) = self.canonical_app_peer_id(&peer_id).await else {
            debug!(
                "Ignoring DHT peer update for unauthenticated transport peer {}",
                peer_id
            );
            return;
        };

        let dht = self.dht.read().await;
        if dht
            .touch_node_typed(&app_peer_id, None, crate::dht::AddressType::Unverified)
            .await
        {
            trace!("Touched routing table entry for {}", app_peer_id.to_hex());
        }
    }

    /// Reconcile already-connected peers into DHT bookkeeping/routing.
    ///
    /// Looks up each peer's actual user agent from the transport layer.
    /// Peers whose user agent is not yet known (e.g. identity announce still
    /// in flight) are skipped — they will be handled by the normal
    /// `PeerConnected` event path once authentication completes.
    async fn reconcile_connected_peers(self: &Arc<Self>) {
        let connected = self.transport.connected_peers().await;
        if connected.is_empty() {
            return;
        }

        info!(
            "Reconciling {} already-connected peers for DHT state",
            connected.len()
        );
        let mut skipped = 0u32;
        for peer_id in connected {
            if let Some(ua) = self.transport.peer_user_agent(&peer_id).await {
                self.handle_peer_connected(peer_id, &ua).await;
            } else {
                skipped += 1;
                debug!(
                    "Skipping reconciliation for peer {} — user agent not yet known",
                    peer_id.to_hex()
                );
            }
        }
        if skipped > 0 {
            info!(
                "Skipped {} peers during reconciliation (user agent unknown, will arrive via PeerConnected)",
                skipped
            );
        }
    }

    /// Handle an authenticated peer connection event.
    ///
    /// The `node_id` is the authenticated app-level [`PeerId`] — no
    /// `canonical_app_peer_id()` lookup is needed because `PeerConnected`
    /// only fires after identity verification.
    async fn handle_peer_connected(self: &Arc<Self>, node_id: PeerId, user_agent: &str) {
        let app_peer_id_hex = node_id.to_hex();

        info!(
            "DHT peer connected: app_id={}, user_agent={}",
            app_peer_id_hex, user_agent
        );
        let dht_key = *node_id.as_bytes();

        // peer_info() resolves app-level IDs internally via peer_to_channel.
        // Collect all dialable addresses — peers may be multi-homed or
        // reachable via multiple NAT traversal endpoints.
        let addresses: Vec<MultiAddr> = if let Some(info) = self.transport.peer_info(&node_id).await
        {
            info.addresses
                .into_iter()
                .filter(Self::is_dialable)
                .collect()
        } else {
            warn!("peer_info unavailable for app_peer_id {}", app_peer_id_hex);
            Vec::new()
        };

        // Skip peers with no addresses — they cannot be used for DHT routing.
        if addresses.is_empty() {
            warn!(
                "Peer {} has no valid addresses, skipping DHT routing table addition",
                app_peer_id_hex
            );
            return;
        }

        // Only add full nodes to the DHT routing table. Ephemeral clients
        // (user_agent not starting with "node/") are excluded to prevent stale
        // addresses from polluting peer discovery after the client disconnects.
        if !crate::network::is_dht_participant(user_agent) {
            info!(
                "Skipping DHT routing table for ephemeral peer {} (user_agent={})",
                app_peer_id_hex, user_agent
            );
        } else {
            // Transport-observed local-scope addresses are `Lan`; other
            // observed addresses are `Unverified` because a successful
            // handshake with us doesn't prove public cold-dialability. The
            // peer's own `PublishAddressSet` upgrades to `Direct` or `Relay`
            // when authoritative info arrives.
            let address_types = addresses
                .iter()
                .map(|addr| {
                    if addr.ip().is_some_and(is_lan_ip) {
                        crate::dht::AddressType::Lan
                    } else {
                        crate::dht::AddressType::Unverified
                    }
                })
                .collect();
            let node_info = NodeInfo {
                id: node_id,
                addresses,
                address_types,
                last_seen: AtomicInstant::now(),
            };

            let trust_fn = |peer_id: &PeerId| -> f64 {
                self.trust_engine
                    .as_ref()
                    .map(|engine| engine.score(peer_id))
                    .unwrap_or(DEFAULT_NEUTRAL_TRUST)
            };
            let add_result = self.dht.write().await.add_node(node_info, &trust_fn).await;
            match add_result {
                Ok(AdmissionResult::Admitted(rt_events)) => {
                    info!("Added peer {} to DHT routing table", app_peer_id_hex);
                    self.broadcast_routing_events_with_quarantine(rt_events)
                        .await;
                }
                Ok(AdmissionResult::StaleRevalidationNeeded {
                    candidate,
                    candidate_ips,
                    candidate_bucket_idx,
                    stale_peers,
                }) => {
                    debug!(
                        "Peer {} admission deferred: {} stale peers need revalidation",
                        app_peer_id_hex,
                        stale_peers.len()
                    );
                    self.spawn_revalidate_and_retry_admission(
                        candidate,
                        candidate_ips,
                        candidate_bucket_idx,
                        stale_peers,
                        app_peer_id_hex.clone(),
                    );
                }
                Err(e) => {
                    debug!(
                        "Failed to add peer {} to DHT routing table: {}",
                        app_peer_id_hex, e
                    );
                }
            }
        }

        if self.event_tx.receiver_count() > 0 {
            let _ = self.event_tx.send(DhtNetworkEvent::PeerDiscovered {
                peer_id: node_id,
                dht_key,
            });
        }
    }

    /// Spawn stale-peer revalidation and retry routing-table admission.
    ///
    /// This path can spend seconds pinging stale peers, so it must not run
    /// inline on the transport event processor.
    fn spawn_revalidate_and_retry_admission(
        self: &Arc<Self>,
        candidate: NodeInfo,
        candidate_ips: Vec<IpAddr>,
        candidate_bucket_idx: usize,
        stale_peers: Vec<(PeerId, usize)>,
        app_peer_id_hex: String,
    ) {
        let this = Arc::clone(self);
        let trust_engine = self.trust_engine.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let result = tokio::select! {
                () = shutdown.cancelled() => {
                    debug!(
                        "Cancelled stale revalidation for peer {} during shutdown",
                        app_peer_id_hex
                    );
                    return;
                }
                result = async {
                    let trust_fn = |peer_id: &PeerId| -> f64 {
                        trust_engine
                            .as_ref()
                            .map(|engine| engine.score(peer_id))
                            .unwrap_or(DEFAULT_NEUTRAL_TRUST)
                    };

                    this.revalidate_and_retry_admission(
                        candidate,
                        candidate_ips,
                        candidate_bucket_idx,
                        stale_peers,
                        &trust_fn,
                    )
                    .await
                } => result,
            };

            match result {
                Ok((rt_events, candidate_admitted)) => {
                    if candidate_admitted {
                        info!(
                            "Added peer {} to DHT routing table after stale revalidation",
                            app_peer_id_hex
                        );
                    } else {
                        info!(
                            "Stale revalidation removed stale peers; peer {} was not admitted",
                            app_peer_id_hex
                        );
                    }
                    this.broadcast_routing_events_with_quarantine(rt_events)
                        .await;
                }
                Err(e) => {
                    warn!(
                        "Stale revalidation for peer {} failed: {}",
                        app_peer_id_hex, e
                    );
                }
            }
        });
    }

    /// Start network event handler
    async fn start_network_event_handler(&self, self_arc: Arc<Self>) -> Result<()> {
        info!("Starting network event handler...");

        // Subscribe to network events from transport layer
        let mut events = self.transport.subscribe_events();

        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        info!("Network event handler shutting down");
                        break;
                    }
                    recv = events.recv() => {
                        match recv {
                            Ok(event) => match event {
                                crate::network::P2PEvent::PeerConnected(peer_id, ref user_agent) => {
                                    self_arc.handle_peer_connected(peer_id, user_agent).await;
                                }
                                crate::network::P2PEvent::PeerDisconnected(peer_id) => {
                                    // peer_id IS the authenticated app-level PeerId.
                                    // PeerDisconnected only fires when all channels for
                                    // this peer have closed — no multi-channel check needed.
                                    info!(
                                        "DHT peer fully disconnected: app_id={}",
                                        peer_id.to_hex()
                                    );
                                    self_arc.notify_lookup_peer_failed(peer_id);

                                    if self_arc.event_tx.receiver_count() > 0
                                        && let Err(e) = self_arc
                                            .event_tx
                                            .send(DhtNetworkEvent::PeerDisconnected {
                                                peer_id,
                                            })
                                    {
                                        warn!(
                                            "Failed to send PeerDisconnected event: {}",
                                            e
                                        );
                                    }
                                }
                                crate::network::P2PEvent::Message {
                                    topic,
                                    source,
                                    transport_source,
                                    timestamp: _,
                                    data,
                                } => {
                                    trace!(
                                        "  [EVENT] Message received: topic={}, source={:?}, {} bytes",
                                        topic,
                                        source,
                                        data.len()
                                    );
                                    if topic == "/dht/1.0.0" {
                                        // DHT messages must be authenticated.
                                        let Some(source_peer) = source else {
                                            warn!("Ignoring unsigned DHT message");
                                            continue;
                                        };
                                        trace!("  [EVENT] Processing DHT message from {}", source_peer);
                                        // Process the DHT message with backpressure via semaphore
                                        let manager_clone = Arc::clone(&self_arc);
                                        let semaphore = Arc::clone(&self_arc.message_handler_semaphore);
                                        tokio::spawn(async move {
                                            // Acquire permit for backpressure - limits concurrent handlers
                                            let _permit = match semaphore.acquire().await {
                                                Ok(permit) => permit,
                                                Err(_) => {
                                                    warn!("Message handler semaphore closed");
                                                    return;
                                                }
                                            };

                                            // SEC-001: Wrap handle_dht_message with timeout to prevent DoS via long-running handlers
                                            // This ensures permits are released even if a handler gets stuck
                                            match tokio::time::timeout(
                                                REQUEST_TIMEOUT,
                                                manager_clone.handle_dht_message(
                                                    &data,
                                                    &source_peer,
                                                    transport_source.as_ref(),
                                                ),
                                            )
                                            .await
                                            {
                                                Ok(Ok(Some(response))) => {
                                                    // Send response back to the source peer
                                                    if let Err(e) = manager_clone
                                                        .transport
                                                        .send_message(&source_peer, "/dht/1.0.0", response)
                                                        .await
                                                    {
                                                        warn!(
                                                            "Failed to send DHT response to {}: {}",
                                                            source_peer, e
                                                        );
                                                    }
                                                }
                                                Ok(Ok(None)) => {
                                                    // No response needed (e.g., for response messages)
                                                }
                                                Ok(Err(e)) => {
                                                    warn!(
                                                        "Failed to handle DHT message from {}: {}",
                                                        source_peer, e
                                                    );
                                                }
                                                Err(_) => {
                                                    // Timeout occurred - log warning and release permit
                                                    warn!(
                                                        "DHT message handler timed out after {:?} for peer {}: potential DoS attempt or slow processing",
                                                        REQUEST_TIMEOUT, source_peer
                                                    );
                                                }
                                            }
                                            // _permit dropped here, releasing semaphore slot
                                        });
                                    }
                                }
                            },
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!("Network event handler lagged, skipped {} events", skipped);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                info!("Network event channel closed, stopping event handler");
                                break;
                            }
                        }
                    }
                }
            }
        });

        *self.event_handler_handle.write().await = Some(handle);

        Ok(())
    }

    /// Attempt stale peer revalidation and retry admission for a candidate.
    ///
    /// Called when `add_node` returns [`AdmissionResult::StaleRevalidationNeeded`].
    /// Pings stale peers (with the DHT write lock released), evicts non-responders,
    /// and re-evaluates the candidate for admission.
    ///
    /// Concurrency is bounded by a global semaphore ([`MAX_CONCURRENT_REVALIDATIONS`])
    /// and per-bucket tracking to prevent concurrent revalidation of the same bucket.
    async fn revalidate_and_retry_admission(
        &self,
        candidate: NodeInfo,
        candidate_ips: Vec<IpAddr>,
        bucket_idx: usize,
        stale_peers: Vec<(PeerId, usize)>,
        trust_fn: &impl Fn(&PeerId) -> f64,
    ) -> anyhow::Result<(Vec<RoutingTableEvent>, bool)> {
        if stale_peers.is_empty() {
            return Err(anyhow::anyhow!("no stale peers to revalidate"));
        }

        // Try acquire global semaphore (non-blocking to avoid stalling the caller).
        let _permit = self
            .revalidation_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("global revalidation limit reached"))?;

        // Try acquire per-bucket slot to prevent concurrent revalidation.
        // Note: guards only the candidate's target bucket, not all buckets in
        // stale_peers (which may span multiple buckets after routing-neighborhood
        // merge). The DHT write lock provides correctness; this guard only
        // prevents redundant ping work on the same bucket.
        {
            let mut active = self.bucket_revalidation_active.lock();
            if active.contains(&bucket_idx) {
                return Err(anyhow::anyhow!(
                    "revalidation already in progress for bucket {bucket_idx}"
                ));
            }
            active.insert(bucket_idx);
        }

        // Ensure the per-bucket slot is released on all exit paths.
        let _bucket_guard = BucketRevalidationGuard {
            active: self.bucket_revalidation_active.clone(),
            bucket_idx,
        };

        // --- Ping stale peers concurrently with DHT write lock released ---
        // Process in chunks to bound concurrent pings while still parallelising
        // within each chunk (worst-case wall time: chunks * STALE_REVALIDATION_BUDGET
        // instead of stale_peers.len() * STALE_REVALIDATION_BUDGET).
        let mut evicted_peers = Vec::new();
        let mut retained_peers = Vec::new();

        for chunk in stale_peers.chunks(MAX_CONCURRENT_REVALIDATION_PINGS) {
            let results = futures::future::join_all(chunk.iter().map(|(peer_id, _)| async {
                let responded = self.ping_with_identity_confirmation(peer_id).await;
                (*peer_id, responded)
            }))
            .await;

            for (peer_id, responded) in results {
                if responded {
                    retained_peers.push(peer_id);
                } else {
                    evicted_peers.push(peer_id);
                }
            }
        }

        // Failure recording is handled by send_dht_request (via
        // record_peer_failure) — no success recording needed since core
        // only hands out penalties.

        if evicted_peers.is_empty() {
            return Err(anyhow::anyhow!(
                "all stale peers responded — no room for candidate"
            ));
        }

        // --- Re-acquire write lock: evict non-responders and retry admission ---
        let mut dht = self.dht.write().await;
        let mut all_events = Vec::new();

        for peer_id in &evicted_peers {
            let removal_events = dht.remove_node_by_id(peer_id).await;
            all_events.extend(removal_events);
        }

        let candidate_id = candidate.id;
        let candidate_admitted = match dht
            .re_evaluate_admission(candidate, &candidate_ips, trust_fn)
            .await
        {
            Ok(admission_events) => {
                all_events.extend(admission_events);
                true
            }
            Err(err) if !all_events.is_empty() => {
                warn!(
                    "Candidate {} was not admitted after stale-peer eviction: {}; broadcasting committed removal events",
                    candidate_id.to_hex(),
                    err
                );
                false
            }
            Err(err) => return Err(err),
        };

        Ok((all_events, candidate_admitted))
    }

    /// Ping a peer to check liveness.
    ///
    /// Reuses the existing [`send_dht_request`](Self::send_dht_request) flow
    /// which handles serialization, connection setup, and response tracking.
    /// Used during stale peer revalidation to determine which peers should
    /// be evicted.
    async fn ping_peer(&self, peer_id: &PeerId) -> anyhow::Result<()> {
        self.send_dht_request(peer_id, DhtNetworkOperation::Ping, None)
            .await
            .map(|_| ())
            .context("ping failed")
    }

    /// Liveness probe used by the stale-peer eviction paths.
    ///
    /// A peer counts as alive only when **both** conditions hold:
    /// 1. [`Self::ping_peer`] completes successfully within
    ///    [`STALE_REVALIDATION_BUDGET`]. The budget covers a fresh
    ///    identity exchange ([`IDENTITY_EXCHANGE_TIMEOUT`]) plus the
    ///    ping round-trip on the resulting channel — see the constant's
    ///    docs for the breakdown. A stale peer's transport channel is
    ///    routinely gone (NAT rebind, idle timeout) by the time we
    ///    revalidate, and a 1 s budget would cancel the dial mid-handshake
    ///    and false-evict an otherwise-healthy peer.
    /// 2. The peer is in the authenticated app-level set
    ///    ([`TransportHandle::is_known_app_peer_id`]) at the moment of the
    ///    check.
    ///
    /// Condition (1) catches dead-on-the-wire peers (no QUIC reachability,
    /// or no DHT response). Condition (2) is the load-bearing identity
    /// gate: it rejects peers that respond at the transport layer but
    /// have never completed (or have lost) the saorsa-core identity
    /// exchange — the exact failure mode of older-protocol nodes whose
    /// QUIC handshake succeeds but whose identity exchange always times
    /// out. Without (2), such peers could be retained because some
    /// other path opened a half-authenticated transport channel.
    ///
    /// Used by [`Self::revalidate_and_retry_admission`] and
    /// [`Self::revalidate_stale_k_closest`] in place of a bare
    /// `ping_peer().is_ok()` so the routing-table invariant ("every
    /// retained peer is currently identity-confirmed") is enforced
    /// exactly where eviction decisions are made.
    async fn ping_with_identity_confirmation(&self, peer_id: &PeerId) -> bool {
        let ping_ok = tokio::time::timeout(STALE_REVALIDATION_BUDGET, self.ping_peer(peer_id))
            .await
            .is_ok_and(|r| r.is_ok());
        if !ping_ok {
            return false;
        }
        self.transport.is_known_app_peer_id(peer_id).await
    }

    /// Revalidate stale K-closest peers by pinging them and evicting non-responders.
    ///
    /// Piggybacked on the periodic self-lookup to avoid a dedicated background
    /// worker. Ensures offline close-group members are evicted promptly rather
    /// than lingering until admission contention triggers revalidation.
    async fn revalidate_stale_k_closest(&self) {
        let stale_peers = {
            let dht = self.dht.read().await;
            dht.stale_k_closest().await
        };

        if stale_peers.is_empty() {
            return;
        }

        debug!("Revalidating {} stale K-closest peer(s)", stale_peers.len());

        // Ping concurrently in chunks, reusing the same concurrency limit as
        // admission-triggered revalidation.
        let mut non_responders = Vec::new();

        for chunk in stale_peers.chunks(MAX_CONCURRENT_REVALIDATION_PINGS) {
            let results = futures::future::join_all(chunk.iter().map(|peer_id| async {
                let responded = self.ping_with_identity_confirmation(peer_id).await;
                (*peer_id, responded)
            }))
            .await;

            for (peer_id, responded) in results {
                if !responded {
                    non_responders.push(peer_id);
                }
            }
        }

        if non_responders.is_empty() {
            debug!("All stale K-closest peers responded — no evictions");
            return;
        }

        // Evict non-responders under the write lock, then broadcast events
        // after releasing it.
        let all_events = {
            let mut dht = self.dht.write().await;
            let mut events = Vec::new();
            for peer_id in &non_responders {
                events.extend(dht.remove_node_by_id(peer_id).await);
            }
            events
        };

        self.broadcast_routing_events_with_quarantine(all_events)
            .await;
        info!("Evicted {} offline K-closest peer(s)", non_responders.len());
    }

    fn routing_events_can_enable_quarantine_eviction(events: &[RoutingTableEvent]) -> bool {
        events.iter().any(|event| {
            matches!(
                event,
                RoutingTableEvent::PeerAdded(_) | RoutingTableEvent::KClosestPeersChanged { .. }
            )
        })
    }

    async fn enforce_close_group_trust_gate(&self) -> Vec<RoutingTableEvent> {
        let Some(ref engine) = self.trust_engine else {
            return Vec::new();
        };
        let trust_score = |peer_id: &PeerId| engine.score(peer_id);
        let rt_events = {
            let mut dht = self.dht.write().await;
            dht.enforce_close_group_trust_gate(&trust_score).await
        };
        if !rt_events.is_empty() {
            let removed: Vec<String> = rt_events
                .iter()
                .filter_map(|event| match event {
                    RoutingTableEvent::PeerRemoved(peer_id) => Some(peer_id.to_hex()),
                    _ => None,
                })
                .collect();
            info!("Removed close-group trust-gated peer(s): {:?}", removed);
        }
        rt_events
    }

    async fn broadcast_routing_events_with_quarantine(&self, mut events: Vec<RoutingTableEvent>) {
        if !Self::routing_events_can_enable_quarantine_eviction(&events) {
            self.broadcast_routing_events(&events);
            return;
        }

        let original_old_close_group = events.iter().find_map(|event| match event {
            RoutingTableEvent::KClosestPeersChanged { old, .. } => Some(old.clone()),
            _ => None,
        });
        let quarantine_events = self.enforce_close_group_trust_gate().await;
        if quarantine_events.is_empty() {
            self.broadcast_routing_events(&events);
            return;
        }

        if let Some(original_old_close_group) = original_old_close_group {
            let final_new_close_group =
                quarantine_events
                    .iter()
                    .rev()
                    .find_map(|event| match event {
                        RoutingTableEvent::KClosestPeersChanged { new, .. } => Some(new.clone()),
                        _ => None,
                    });

            events.retain(|event| !matches!(event, RoutingTableEvent::KClosestPeersChanged { .. }));
            events.extend(
                quarantine_events.into_iter().filter(|event| {
                    !matches!(event, RoutingTableEvent::KClosestPeersChanged { .. })
                }),
            );
            if let Some(new) = final_new_close_group
                && original_old_close_group != new
            {
                events.push(RoutingTableEvent::KClosestPeersChanged {
                    old: original_old_close_group,
                    new,
                });
            }
        } else {
            events.extend(quarantine_events);
        }

        self.broadcast_routing_events(&events);
    }

    /// Translate core engine routing table events into network events and broadcast them.
    fn broadcast_routing_events(&self, events: &[RoutingTableEvent]) {
        if self.event_tx.receiver_count() == 0 {
            return;
        }
        for event in events {
            match event {
                RoutingTableEvent::PeerAdded(id) => {
                    let _ = self
                        .event_tx
                        .send(DhtNetworkEvent::PeerAdded { peer_id: *id });
                }
                RoutingTableEvent::PeerRemoved(id) => {
                    let _ = self
                        .event_tx
                        .send(DhtNetworkEvent::PeerRemoved { peer_id: *id });
                }
                RoutingTableEvent::KClosestPeersChanged { old, new } => {
                    let _ = self.event_tx.send(DhtNetworkEvent::KClosestPeersChanged {
                        old: old.clone(),
                        new: new.clone(),
                    });
                }
            }
        }
    }

    /// Get current statistics
    /// Update a node's address in the DHT routing table.
    ///
    /// Local-scope addresses are classified [`crate::dht::AddressType::Lan`].
    /// Other addresses are classified [`crate::dht::AddressType::Unverified`]:
    /// transport-layer observations prove only reachability from us, not
    /// public dialability. Callers with authoritative type information (e.g.,
    /// `AddressType::Relay` for relay addresses) must use
    /// [`Self::touch_node_typed`].
    pub async fn touch_node(&self, peer_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let dht = self.dht.read().await;
        let addr_type = if address.and_then(MultiAddr::ip).is_some_and(is_lan_ip) {
            crate::dht::AddressType::Lan
        } else {
            crate::dht::AddressType::Unverified
        };
        if addr_type == crate::dht::AddressType::Unverified {
            dht.touch_node(peer_id, address).await
        } else {
            dht.touch_node_typed(peer_id, address, addr_type).await
        }
    }

    /// Update a node's address with an explicit type tag.
    ///
    /// Prefer over [`Self::touch_node`] when the address class is known
    /// (e.g., `AddressType::Relay` for relay addresses so they are stored
    /// at the front of the address list).
    pub async fn touch_node_typed(
        &self,
        peer_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: crate::dht::AddressType,
    ) -> bool {
        let dht = self.dht.read().await;
        dht.touch_node_typed(peer_id, address, addr_type).await
    }

    /// Merge a legacy ADD_ADDRESS relay hint only while the peer has no
    /// authoritative `PublishAddressSet` sequence.
    ///
    /// Sequence-bearing self-records are full replacements. Once we have one
    /// for a peer, legacy relay hints must not mutate that record or they can
    /// resurrect relay addresses the owner already removed.
    pub async fn touch_legacy_relay_hint_if_unsequenced(
        &self,
        peer_id: &PeerId,
        address: &MultiAddr,
    ) -> bool {
        let dht = self.dht.read().await;
        dht.touch_legacy_relay_hint_if_unsequenced(peer_id, address)
            .await
    }

    /// Ingest a peer's typed address set from a FIND_NODE gossip response
    /// into the local routing table.
    ///
    /// If the report carries a marker-encoded publish sequence in its existing
    /// `distance` metadata slot, it is a propagated `PublishAddressSet` view
    /// and the sequence guard decides whether to replace our local record
    /// wholesale. Older sequence-bearing reports are ignored instead of being
    /// merged, which prevents stale relay addresses from being reintroduced
    /// after the publisher has republished a newer direct-only or re-relayed
    /// set. Legacy reports without a sequence keep the old upgrade-only
    /// behavior: add a new address or promote the existing entry, but never
    /// demote a higher-priority tag already held. Peers absent from the routing
    /// table are left alone; we don't accept *new* peer identities from
    /// untrusted gossip, only additional information about peers we already
    /// know.
    ///
    /// This closes the hole where a NAT'd peer XOR-far from every open
    /// node could never land in anyone's K-closest for `PublishAddressSet`
    /// fan-out — without gossip ingestion it stayed starved of `Direct`
    /// addresses and failed relay acquisition with "no direct-addressable
    /// candidates in routing table" despite having 17 peers in its RT.
    ///
    /// Crucially, this path does NOT refresh `last_seen` for the subject
    /// peer: we ingest *address* information from gossip, but liveness
    /// claims from a third party are not evidence the subject is alive
    /// from our point of view. Letting gossip refresh `last_seen` would
    /// indefinitely defer
    /// [`crate::dht::core_engine::DhtCoreEngine::stale_k_closest`]
    /// eviction for peers we cannot authenticate with (e.g., old-protocol
    /// nodes whose identity exchange always times out) as long as some
    /// authenticated neighbour keeps mentioning them.
    pub async fn merge_gossiped_typed_addresses(&self, node: &DHTNode) {
        self.merge_gossiped_typed_addresses_from_transport(node, None)
            .await;
    }

    async fn merge_gossiped_typed_addresses_from_transport(
        &self,
        node: &DHTNode,
        transport_source: Option<&MultiAddr>,
    ) {
        let node = self
            .gossiped_node_with_trusted_addresses(node.clone(), transport_source)
            .await;
        self.merge_trusted_gossiped_typed_addresses(&node).await;
    }

    async fn gossiped_node_with_trusted_addresses(
        &self,
        mut node: DHTNode,
        transport_source: Option<&MultiAddr>,
    ) -> DHTNode {
        let typed_addresses = self
            .filter_lan_addresses_for_store(node.typed_addresses(), transport_source)
            .await;
        let (addresses, address_types): (Vec<_>, Vec<_>) = typed_addresses.into_iter().unzip();
        node.addresses = addresses;
        node.address_types = address_types;
        node
    }

    async fn merge_trusted_gossiped_typed_addresses(&self, node: &DHTNode) {
        let typed_addresses = node.typed_addresses();
        let dht = self.dht.read().await;
        let publish_seq = dht_node_publish_seq(node);
        if publish_seq != 0 {
            let _ = dht
                .replace_node_addresses_from_gossip(&node.peer_id, typed_addresses, publish_seq)
                .await;
            return;
        }
        for (addr, ty) in typed_addresses {
            dht.merge_typed_address_upgrade_only(&node.peer_id, &addr, ty)
                .await;
        }
    }

    pub async fn get_stats(&self) -> DhtNetworkStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to DHT network events
    /// Emit a [`DhtNetworkEvent`] on the event broadcaster.
    ///
    /// Primarily used by `P2PNode` to emit
    /// [`DhtNetworkEvent::BootstrapComplete`] after the ADR-014 reachability
    /// classifier has run. Internal DHT operations emit their own events
    /// directly.
    pub fn emit_event(&self, event: DhtNetworkEvent) {
        if self.event_tx.receiver_count() > 0 {
            let _ = self.event_tx.send(event);
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<DhtNetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get currently connected peers from the transport layer.
    pub async fn get_connected_peers(&self) -> Vec<PeerId> {
        self.transport.connected_peers().await
    }

    /// Get DHT routing table size (Node-mode peers only).
    pub async fn get_routing_table_size(&self) -> usize {
        self.dht.read().await.routing_table_size().await
    }

    /// Check whether a peer is present in the DHT routing table.
    ///
    /// Only peers that passed the `is_dht_participant` gate are added
    /// to the routing table.
    pub async fn is_in_routing_table(&self, peer_id: &PeerId) -> bool {
        let dht_guard = self.dht.read().await;
        dht_guard.has_node(peer_id).await
    }

    /// Return every peer currently in the DHT routing table.
    ///
    /// Only peers that passed the `is_dht_participant` security gate are
    /// included. Useful for diagnostics and for callers that need the full
    /// `LocalRT(self)` set (e.g. replication hint construction).
    ///
    /// The routing table holds at most `256 * k_value` entries, so
    /// collecting them is inexpensive.
    pub async fn routing_table_peers(&self) -> Vec<DHTNode> {
        let dht_guard = self.dht.read().await;
        let nodes = dht_guard.all_nodes_with_publish_seq().await;
        drop(dht_guard);
        nodes
            .into_iter()
            .map(|(node, publish_seq)| {
                let reliability = self
                    .trust_engine
                    .as_ref()
                    .map(|engine| engine.score(&node.id))
                    .unwrap_or(DEFAULT_NEUTRAL_TRUST);
                DHTNode {
                    peer_id: node.id,
                    address_types: node.address_types,
                    addresses: node.addresses,
                    distance: encode_publish_seq_distance(publish_seq),
                    reliability,
                }
            })
            .collect()
    }

    /// Get this node's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.config.peer_id
    }

    /// Publish this node's complete typed address set to a list of peers.
    ///
    /// Used by the relay-acquisition driver: on initial acquisition, on
    /// relay-lost (before rebinding), and on successful rebind. The sender
    /// is authoritative — the receiver replaces any prior record wholesale,
    /// which is how stale relay addresses get dropped when a session closes.
    ///
    /// `seq` is a non-zero per-call Unix-nanosecond timestamp from
    /// [`Self::next_publish_seq`], guaranteeing monotonicity across sends
    /// from the same node.
    pub async fn publish_address_set_to_peers(
        &self,
        typed_addresses: Vec<(crate::MultiAddr, AddressType)>,
        peers: &[DHTNode],
    ) {
        let seq = Self::next_publish_seq();
        let op = DhtNetworkOperation::PublishAddressSet {
            seq,
            addresses: typed_addresses.clone(),
        };
        for peer in peers {
            if peer.peer_id == self.config.peer_id {
                continue; // Skip self
            }
            // Pass the peer's typed addresses through directly so
            // send_dht_request avoids a redundant routing-table read for
            // a peer we already have in hand.
            let peer_typed = peer.typed_addresses();
            match self
                .send_dht_request(&peer.peer_id, op.clone(), Some(&peer_typed))
                .await
            {
                Ok(_) => {
                    debug!(
                        peer = %peer.peer_id.to_hex(),
                        addrs = typed_addresses.len(),
                        seq,
                        "published address set to peer",
                    );
                }
                Err(e) => {
                    debug!(
                        "Failed to publish address set to peer {}: {}",
                        peer.peer_id.to_hex(),
                        e
                    );
                }
            }
        }
    }

    /// Generate the next monotonic publish sequence number.
    ///
    /// Uses wall-clock Unix nanoseconds so the counter:
    ///
    /// - Is naturally monotonic within a single process under normal clock
    ///   conditions (nanosecond resolution, much higher than the republish
    ///   frequency, which is at most once per relay state change).
    /// - Survives process restarts because wall-clock time advances across
    ///   reboots, so a restarted sender's first republish will always have
    ///   a higher sequence than any pre-restart value stored on receivers.
    /// - Requires no per-sender persistence.
    ///
    /// NTP slews of a few seconds are harmless: the worst case is briefly
    /// rejecting a valid republish, which the driver's reactive triggers
    /// will retry in short order. Always returns a non-zero value because
    /// receivers reserve `0` as their "no sequence observed" sentinel.
    fn next_publish_seq() -> u64 {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => u64::try_from(duration.as_nanos())
                .unwrap_or(u64::MAX)
                .max(1),
            Err(_) => 1,
        }
    }

    /// Get the local listen address of this node's P2P network
    ///
    /// Returns the address other nodes can use to connect to this node.
    pub fn local_addr(&self) -> Option<MultiAddr> {
        self.transport.local_addr()
    }

    /// Connect to a specific peer by address.
    ///
    /// This is useful for manually building network topology in tests.
    pub async fn connect_to_peer(&self, address: &MultiAddr) -> Result<String> {
        self.transport.connect_peer(address).await
    }

    /// Get the transport handle for direct transport-level operations.
    pub fn transport(&self) -> &Arc<crate::transport_handle::TransportHandle> {
        &self.transport
    }

    /// Get the optional trust engine used by this manager.
    pub fn trust_engine(&self) -> Option<Arc<TrustEngine>> {
        self.trust_engine.clone()
    }
}

/// Default request timeout for outbound DHT operations (seconds).
///
/// Governs `wait_for_response`. Peer dials are bounded by the transport
/// strategy's direct connect and handshake timeouts.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 15;

/// Maximum additional wait for outstanding α queries after the first
/// response in a Kademlia lookup iteration arrives.
///
/// `send_dht_request` runs a full dial cascade (direct → hole-punch → relay)
/// before the RPC wait even starts, and that cascade can legitimately take
/// over 20s when the candidate is NAT'd or unresponsive. Waiting for every
/// α query to finish — as `join_all` does — lets one dead peer stall the
/// iteration far beyond the point where Kademlia has enough information to
/// proceed. Once the first response is in, we have new candidates for the
/// next iteration and can safely cap the wait on the stragglers.
///
/// Sized at 5s: a peer with an already-open channel replies in well under
/// a second, so this leaves ample slack for legitimate stragglers while
/// letting us abandon dial cascades that are almost certainly going to
/// fail anyway.
const ITERATION_GRACE_TIMEOUT_SECS: u64 = 5;

/// Default maximum concurrent DHT operations
const DEFAULT_MAX_CONCURRENT_OPS: usize = 100;

impl Default for DhtNetworkConfig {
    fn default() -> Self {
        let adaptive_config = AdaptiveDhtConfig::default();
        Self {
            peer_id: PeerId::from_bytes([0u8; 32]),
            node_config: NodeConfig::default(),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_concurrent_operations: DEFAULT_MAX_CONCURRENT_OPS,
            enable_security: true,
            swap_threshold: adaptive_config.swap_threshold,
            quarantine_threshold: adaptive_config.quarantine_threshold,
            quarantine_readmit_threshold: adaptive_config.quarantine_readmit_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_dialable_accepts_quic_with_routable_ip() {
        let quic = MultiAddr::quic("203.0.113.7:9000".parse().unwrap());
        assert!(DhtNetworkManager::is_dialable(&quic));
    }

    #[test]
    fn stale_revalidation_budget_covers_identity_exchange_plus_ping_rtt() {
        // Cold-channel revalidation must survive a fresh identity exchange
        // (≤ IDENTITY_EXCHANGE_TIMEOUT) followed by a ping round-trip on
        // the resulting authenticated channel. Capping below this is the
        // exact regression the constant was introduced to close — guard
        // the arithmetic so a future tweak to either input is mirrored
        // here intentionally.
        assert_eq!(
            STALE_REVALIDATION_BUDGET,
            IDENTITY_EXCHANGE_TIMEOUT + STALE_REVALIDATION_PING_RTT,
        );
    }

    fn bucket_refresh_candidate(index: usize, refresh_debt_secs: u64) -> BucketRefreshCandidate {
        let refresh_debt = Duration::from_secs(refresh_debt_secs);
        BucketRefreshCandidate {
            index,
            refresh_debt,
            live_peer_age: refresh_debt,
            probe_age: refresh_debt,
        }
    }

    const _: () = assert!(
        MAX_BUCKET_REFRESH_LOOKUPS_PER_PASS > 0,
        "bucket refresh budget must allow at least one lookup"
    );

    #[test]
    fn bucket_refresh_selection_keeps_all_stale_buckets_within_budget() {
        let refresh_budget = MAX_BUCKET_REFRESH_LOOKUPS_PER_PASS;

        let candidates: Vec<_> = (0..refresh_budget)
            .map(|idx| bucket_refresh_candidate(idx, 3_600 + idx as u64))
            .collect();
        let mut selected = DhtNetworkManager::select_bucket_refresh_indices(candidates);
        selected.sort_unstable();

        assert_eq!(selected, (0..refresh_budget).collect::<Vec<_>>());
    }

    #[test]
    fn bucket_refresh_selection_caps_large_stale_sets_by_debt() {
        let refresh_budget = MAX_BUCKET_REFRESH_LOOKUPS_PER_PASS;

        let candidate_count = refresh_budget * 3;
        let candidates: Vec<_> = (0..candidate_count)
            .map(|idx| bucket_refresh_candidate(idx, (idx as u64) * 3_600))
            .collect();
        let mut selected = DhtNetworkManager::select_bucket_refresh_indices(candidates);
        selected.sort_unstable();

        let expected_start = candidate_count - refresh_budget;
        let expected: Vec<_> = (expected_start..candidate_count).collect();

        assert_eq!(selected.len(), refresh_budget);
        assert_eq!(selected, expected);
    }

    #[test]
    fn lookup_peer_states_only_absent_peers_are_contactable() {
        let mut states = LookupPeerStates::default();
        let waiting = pid(1);
        let succeeded = pid(2);
        let failed = pid(3);
        let unresponsive = pid(4);
        let fresh = pid(5);

        states.mark_waiting(waiting);
        states.mark_succeeded(succeeded);
        states.mark_failed(failed);
        states.mark_unresponsive(unresponsive);

        assert!(!states.is_contactable(&waiting));
        assert!(!states.is_contactable(&succeeded));
        assert!(!states.is_contactable(&failed));
        assert!(!states.is_contactable(&unresponsive));
        assert!(states.is_contactable(&fresh));
    }

    #[test]
    fn lookup_peer_states_failure_and_unresponsive_are_final_for_lookup() {
        let mut states = LookupPeerStates::default();
        let failed = pid(7);
        let unresponsive = pid(8);

        states.mark_waiting(failed);
        states.mark_failed(failed);
        states.mark_waiting(unresponsive);
        states.mark_unresponsive(unresponsive);

        assert_eq!(states.state(&failed), Some(LookupPeerState::Failed));
        assert_eq!(
            states.state(&unresponsive),
            Some(LookupPeerState::Unresponsive)
        );
        assert!(!states.is_contactable(&failed));
        assert!(!states.is_contactable(&unresponsive));
    }

    #[tokio::test]
    async fn lookup_failure_coordinator_broadcasts_to_all_subscribers() {
        let coordinator = LookupFailureCoordinator::new();
        let peer = pid(9);
        let mut first = coordinator.subscribe();
        let mut second = coordinator.subscribe();

        coordinator.notify_failed(peer);

        assert_eq!(first.recv().await.unwrap(), peer);
        assert_eq!(second.recv().await.unwrap(), peer);
    }

    #[tokio::test]
    async fn lookup_failure_signal_waits_for_matching_peer() {
        let coordinator = LookupFailureCoordinator::new();
        let target = pid(10);
        let other = pid(11);
        let rx = coordinator.subscribe();

        coordinator.notify_failed(other);
        coordinator.notify_failed(target);

        tokio::time::timeout(
            Duration::from_secs(1),
            DhtNetworkManager::wait_for_lookup_failure_signal(target, rx),
        )
        .await
        .expect("matching peer failure should wake the waiter");
    }

    #[tokio::test]
    async fn lookup_failure_signal_aborts_when_receiver_lagged() {
        let coordinator = LookupFailureCoordinator::new();
        let target = pid(12);
        let other = pid(13);
        let rx = coordinator.subscribe();

        for _ in 0..=LOOKUP_FAILURE_BROADCAST_CAPACITY {
            coordinator.notify_failed(other);
        }

        tokio::time::timeout(
            Duration::from_secs(1),
            DhtNetworkManager::wait_for_lookup_failure_signal(target, rx),
        )
        .await
        .expect("lagged receiver should conservatively wake the waiter");
    }

    #[tokio::test]
    async fn lookup_results_do_not_hand_out_quarantined_peers() {
        let local_peer = pid(0);
        let quarantined_peer = pid(1);
        let below_threshold_peer = pid(2);
        let healthy_peer = pid(3);
        let mut dht =
            DhtCoreEngine::new(local_peer, 4, false, DEFAULT_NEUTRAL_TRUST - 0.15).unwrap();
        dht.set_trust_quarantine_thresholds(0.20, 0.45).unwrap();

        for byte in 1..=5u8 {
            dht.add_node_no_trust(routing_test_node(byte))
                .await
                .unwrap();
        }
        let events = dht
            .enforce_close_group_quarantine(&quarantined_peer, 0.10)
            .await;
        assert!(
            events
                .iter()
                .any(|event| matches!(event, RoutingTableEvent::PeerRemoved(id) if *id == quarantined_peer)),
            "test setup should quarantine the close-group peer"
        );

        let trust_score = |peer_id: &PeerId| {
            if *peer_id == quarantined_peer {
                0.30
            } else if *peer_id == below_threshold_peer {
                0.10
            } else {
                DEFAULT_NEUTRAL_TRUST
            }
        };

        let lookup_key = DhtKey::from_bytes(*local_peer.as_bytes());
        let nodes = dht
            .find_nodes_with_publish_seq_filtered(&lookup_key, 4, |node| {
                let score = trust_score(&node.id);
                node.id != local_peer && !dht.should_avoid_for_lookup(&node.id, score)
            })
            .await
            .unwrap();
        let results = DhtNetworkManager::lookup_results_from_routing_nodes(nodes, 4);
        let result_ids: Vec<PeerId> = results.iter().map(|node| node.peer_id).collect();

        assert_eq!(result_ids, vec![healthy_peer, pid(4), pid(5)]);
        assert!(
            results
                .iter()
                .all(|node| (node.reliability - SELF_RELIABILITY_SCORE).abs() < f64::EPSILON),
            "trust filtering must not change the legacy DHTNode reliability wire value"
        );
    }

    #[test]
    fn is_dialable_rejects_non_quic_transports() {
        let ble = MultiAddr::new(crate::address::TransportAddr::Ble {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            psm: 0x0025,
        });
        let tcp = MultiAddr::tcp("10.0.0.1:80".parse().unwrap());
        let lora = MultiAddr::new(crate::address::TransportAddr::LoRa {
            dev_addr: [0xDE, 0xAD, 0xBE, 0xEF],
            freq_hz: 868_000_000,
        });
        assert!(!DhtNetworkManager::is_dialable(&ble));
        assert!(!DhtNetworkManager::is_dialable(&tcp));
        assert!(!DhtNetworkManager::is_dialable(&lora));
    }

    #[test]
    fn is_dialable_rejects_unspecified_ip() {
        let unspecified = MultiAddr::quic("0.0.0.0:9000".parse().unwrap());
        assert!(!DhtNetworkManager::is_dialable(&unspecified));
    }

    #[test]
    fn is_dialable_accepts_loopback() {
        let loopback = MultiAddr::quic("127.0.0.1:9000".parse().unwrap());
        assert!(DhtNetworkManager::is_dialable(&loopback));
    }

    fn dht_node(seed: u8, entries: Vec<(&str, AddressType)>) -> DHTNode {
        let (addresses, address_types): (Vec<MultiAddr>, Vec<AddressType>) = entries
            .into_iter()
            .map(|(s, t)| (s.parse().unwrap(), t))
            .unzip();
        DHTNode {
            peer_id: PeerId::from_bytes([seed; 32]),
            addresses,
            address_types,
            distance: None,
            reliability: 1.0,
        }
    }

    #[test]
    fn dht_node_typed_addresses_canonicalize_local_scope_direct_to_lan() {
        let node = dht_node(
            1,
            vec![("/ip4/192.168.1.10/udp/10003/quic", AddressType::Direct)],
        );

        let typed = node.typed_addresses();
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0].1, AddressType::Lan);
    }

    fn typed_addresses(entries: Vec<(&str, AddressType)>) -> Vec<(MultiAddr, AddressType)> {
        entries
            .into_iter()
            .map(|(s, t)| (s.parse().unwrap(), t))
            .collect()
    }

    #[test]
    fn store_filter_strips_lan_without_lan_source_or_same_wan() {
        let context = DialAddressContext::from_parts(
            ["203.0.113.9:9000".parse::<SocketAddr>().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );
        let addrs = typed_addresses(vec![
            ("/ip4/192.168.10.179/udp/10449/quic", AddressType::Lan),
            ("/ip4/198.51.100.8/udp/10449/quic", AddressType::Direct),
        ]);

        let filtered =
            DhtNetworkManager::filter_lan_addresses_for_store_with_context(addrs, None, &context);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, AddressType::Direct);
        assert_eq!(
            filtered[0].0,
            "/ip4/198.51.100.8/udp/10449/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn store_filter_canonicalizes_untrusted_private_direct_to_stripped_lan() {
        let context = DialAddressContext::from_parts(
            ["203.0.113.9:9000".parse::<SocketAddr>().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );
        let addrs = typed_addresses(vec![(
            "/ip4/192.168.10.179/udp/10449/quic",
            AddressType::Direct,
        )]);

        let filtered =
            DhtNetworkManager::filter_lan_addresses_for_store_with_context(addrs, None, &context);

        assert!(filtered.is_empty());
    }

    #[test]
    fn store_filter_keeps_lan_when_advertisement_arrived_over_lan() {
        let context = DialAddressContext::from_parts(
            Vec::<SocketAddr>::new(),
            Vec::<MultiAddr>::new(),
            false,
        );
        let source = "/ip4/192.168.1.2/udp/9000/quic"
            .parse::<MultiAddr>()
            .unwrap();
        let addrs = typed_addresses(vec![(
            "/ip4/192.168.10.179/udp/10449/quic",
            AddressType::Direct,
        )]);

        let filtered = DhtNetworkManager::filter_lan_addresses_for_store_with_context(
            addrs,
            Some(&source),
            &context,
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, AddressType::Lan);
    }

    #[test]
    fn store_filter_keeps_lan_when_subject_shares_our_wan() {
        let context = DialAddressContext::from_parts(
            ["203.0.113.9:9000".parse::<SocketAddr>().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );
        let addrs = typed_addresses(vec![
            ("/ip4/192.168.10.179/udp/10449/quic", AddressType::Lan),
            ("/ip4/203.0.113.9/udp/10449/quic", AddressType::Unverified),
        ]);

        let filtered =
            DhtNetworkManager::filter_lan_addresses_for_store_with_context(addrs, None, &context);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|(_, ty)| *ty == AddressType::Lan));
        assert!(
            filtered
                .iter()
                .any(|(addr, ty)| *ty == AddressType::Unverified
                    && addr.ip() == Some("203.0.113.9".parse().unwrap()))
        );
    }

    #[test]
    fn store_filter_does_not_use_relay_as_same_wan_lan_proof() {
        let context = DialAddressContext::from_parts(
            ["203.0.113.9:9000".parse::<SocketAddr>().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );
        let addrs = typed_addresses(vec![
            ("/ip4/192.168.10.179/udp/10449/quic", AddressType::Lan),
            ("/ip4/203.0.113.9/udp/10449/quic", AddressType::Relay),
        ]);

        let filtered =
            DhtNetworkManager::filter_lan_addresses_for_store_with_context(addrs, None, &context);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, AddressType::Relay);
    }

    #[test]
    fn merge_from_adds_relay_entry_to_existing_unverified() {
        let mut existing = dht_node(
            1,
            vec![("/ip4/192.0.2.10/udp/10003/quic", AddressType::Unverified)],
        );
        let incoming = dht_node(
            1,
            vec![("/ip4/198.51.100.7/udp/44100/quic", AddressType::Relay)],
        );

        existing.merge_from(incoming);

        assert_eq!(existing.addresses.len(), 2);
        // Relay sorts first by priority
        assert_eq!(existing.address_types[0], AddressType::Relay);
        assert_eq!(existing.address_types[1], AddressType::Unverified);
        assert_eq!(
            existing.addresses[0],
            "/ip4/198.51.100.7/udp/44100/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn merge_from_upgrades_existing_tag_but_never_demotes() {
        let addr = "/ip4/198.51.100.7/udp/44100/quic";

        // Existing Relay + incoming Unverified for the SAME address must not
        // demote the Relay tag (gossip arriving out of order must not erase
        // authoritative routing information).
        let mut existing = dht_node(1, vec![(addr, AddressType::Relay)]);
        let incoming_demotion = dht_node(1, vec![(addr, AddressType::Unverified)]);
        existing.merge_from(incoming_demotion);
        assert_eq!(existing.addresses.len(), 1);
        assert_eq!(existing.address_types[0], AddressType::Relay);

        // Existing Unverified + incoming Direct for the same address MUST
        // promote (authoritative reachability claim beats a cold-start tag).
        let mut existing = dht_node(1, vec![(addr, AddressType::Unverified)]);
        let incoming_promotion = dht_node(1, vec![(addr, AddressType::Direct)]);
        existing.merge_from(incoming_promotion);
        assert_eq!(existing.addresses.len(), 1);
        assert_eq!(existing.address_types[0], AddressType::Direct);
    }

    #[test]
    fn merge_from_dedupes_identical_relay_entry() {
        let addr = "/ip4/198.51.100.7/udp/44100/quic";
        let mut existing = dht_node(1, vec![(addr, AddressType::Relay)]);
        let incoming = dht_node(1, vec![(addr, AddressType::Relay)]);
        existing.merge_from(incoming);
        assert_eq!(existing.addresses.len(), 1);
        assert_eq!(existing.address_types[0], AddressType::Relay);
    }

    // -----------------------------------------------------------------------
    // FIND_NODE aggregator selection rule — self-report and publish-sequence
    // freshness win before quorum / closest-XOR fallback.
    // -----------------------------------------------------------------------

    /// Build a synthetic PeerId with `byte` in position 0 and zeros
    /// elsewhere, so XOR distances between peers are easy to reason
    /// about by inspecting byte 0.
    fn peer_with_leading(byte: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        PeerId::from_bytes(bytes)
    }

    /// Minimal synthetic `DHTNode` with a single address at the given tier.
    fn report(subject_byte: u8, addr_str: &str, ty: AddressType) -> DHTNode {
        report_with_seq(subject_byte, addr_str, ty, 0)
    }

    fn report_with_seq(
        subject_byte: u8,
        addr_str: &str,
        ty: AddressType,
        publish_seq: u64,
    ) -> DHTNode {
        DHTNode {
            peer_id: peer_with_leading(subject_byte),
            addresses: vec![addr_str.parse().unwrap()],
            address_types: vec![ty],
            distance: encode_publish_seq_distance(publish_seq),
            reliability: 1.0,
        }
    }

    const TEST_WITNESS_K: usize = 7;

    fn witness_node(seed: u8) -> DHTNode {
        DHTNode {
            peer_id: PeerId::from_bytes([seed; 32]),
            addresses: Vec::new(),
            address_types: Vec::new(),
            distance: None,
            reliability: 1.0,
        }
    }

    fn witness_nodes(seeds: &[u8]) -> Vec<DHTNode> {
        seeds.iter().copied().map(witness_node).collect()
    }

    fn witness_view(responder_seed: u8, closest_seeds: &[u8]) -> (PeerId, Vec<DHTNode>) {
        (
            PeerId::from_bytes([responder_seed; 32]),
            witness_nodes(closest_seeds),
        )
    }

    fn responder_view_seeds(view: &ResponderView) -> Vec<u8> {
        view.closest
            .iter()
            .map(|node| node.peer_id.to_bytes()[0])
            .collect()
    }

    #[test]
    fn witnessed_lookup_reuses_transcript_views_and_only_requeries_missing_responders() {
        let mut transcript = FindNodeLookupTranscript::default();
        transcript.record_responder_view(PeerId::from_bytes([1; 32]), witness_nodes(&[2, 3]));
        transcript.record_responder_view(PeerId::from_bytes([3; 32]), Vec::new());

        let initial = witness_nodes(&[1, 2, 3]);
        let (views, missing) = split_witnessed_transcript_views(&initial, &mut transcript);

        assert_eq!(views.len(), 2);
        assert_eq!(views[0].0, PeerId::from_bytes([1; 32]));
        assert_eq!(
            views[0]
                .1
                .iter()
                .map(|node| node.peer_id.to_bytes()[0])
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(views[1].0, PeerId::from_bytes([3; 32]));
        assert!(views[1].1.is_empty());
        assert_eq!(
            missing
                .iter()
                .map(|node| node.peer_id.to_bytes()[0])
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(
            transcript
                .take_responder_view(&PeerId::from_bytes([1; 32]))
                .is_none()
        );
    }

    #[test]
    fn witnessed_group_returns_self_inclusive_capped_node_views_sorted_by_xor() {
        const FALLBACK_TEST_K: usize = 2;

        let key: Key = [0u8; 32];
        let initial = witness_nodes(&[1, 2]);
        let views = vec![witness_view(1, &[4, 5]), witness_view(2, &[3, 6])];

        let group =
            build_witnessed_close_group(&key, FALLBACK_TEST_K, FALLBACK_TEST_K, initial, views);

        assert!(
            group
                .responder_views
                .iter()
                .all(|view| view.closest.len() <= FALLBACK_TEST_K),
            "each responder still votes only for its local closest-K view"
        );
        assert_eq!(responder_view_seeds(&group.responder_views[0]), vec![1, 4]);
        assert_eq!(responder_view_seeds(&group.responder_views[1]), vec![2, 3]);
    }

    #[test]
    fn witnessed_group_allows_wider_responder_views_than_initial_group() {
        const INITIAL_K: usize = 2;
        const VIEW_K: usize = 3;

        let key: Key = [0u8; 32];
        let initial = witness_nodes(&[1, 2]);
        let views = vec![witness_view(1, &[4, 5]), witness_view(2, &[3, 6])];

        let group = build_witnessed_close_group(&key, INITIAL_K, VIEW_K, initial, views);

        assert_eq!(group.k, INITIAL_K);
        assert!(
            group
                .responder_views
                .iter()
                .all(|view| view.closest.len() <= VIEW_K),
            "responder views should use the independent view cap"
        );
        assert_eq!(
            responder_view_seeds(&group.responder_views[0]),
            vec![1, 4, 5]
        );
        assert_eq!(
            responder_view_seeds(&group.responder_views[1]),
            vec![2, 3, 6]
        );
    }

    #[test]
    fn witnessed_group_self_includes_responder_when_response_omits_self() {
        let key: Key = [0u8; 32];
        let initial = witness_nodes(&[1, 2, 3, 4, 5, 6, 7]);
        let views = vec![witness_view(3, &[1, 2, 4, 5, 6, 7, 8])];

        let group =
            build_witnessed_close_group(&key, TEST_WITNESS_K, TEST_WITNESS_K, initial, views);
        let view = group
            .responder_views
            .iter()
            .find(|view| view.responder == PeerId::from_bytes([3; 32]))
            .expect("responder view should be present");

        assert!(
            view.closest
                .iter()
                .any(|node| node.peer_id == PeerId::from_bytes([3; 32])),
            "responder should recognise itself after self-inclusion"
        );
        assert!(
            !view
                .closest
                .iter()
                .any(|node| node.peer_id == PeerId::from_bytes([8; 32])),
            "self-inclusion should still cap the view to K closest peers"
        );
    }

    #[test]
    fn witnessed_group_keeps_relay_only_xor_closer_peer_ahead_of_direct_farther_peer() {
        let key: Key = [0u8; 32];
        let relay_closer = dht_node(
            1,
            vec![("/ip4/198.51.100.1/udp/9001/quic", AddressType::Relay)],
        );
        let direct_farther = dht_node(
            2,
            vec![("/ip4/198.51.100.2/udp/9002/quic", AddressType::Direct)],
        );
        let mut initial = vec![relay_closer.clone(), direct_farther.clone()];
        initial.extend(witness_nodes(&[3, 4, 5, 6, 7]));
        let view_nodes = vec![
            relay_closer,
            direct_farther,
            witness_node(3),
            witness_node(4),
            witness_node(5),
            witness_node(6),
            witness_node(7),
        ];
        let views: Vec<_> = (1..=7)
            .map(|seed| (PeerId::from_bytes([seed; 32]), view_nodes.clone()))
            .collect();

        let group =
            build_witnessed_close_group(&key, TEST_WITNESS_K, TEST_WITNESS_K, initial, views);

        let closest = &group.responder_views[0].closest;
        assert_eq!(
            responder_view_seeds(&group.responder_views[0]),
            vec![1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(closest[0].address_types[0], AddressType::Relay);
        assert_eq!(closest[1].address_types[0], AddressType::Direct);
    }

    #[test]
    fn winner_empty_reports_returns_none() {
        let reports = SubjectReports::new();
        assert!(compute_winner(&peer_with_leading(0x01), &reports).is_none());
    }

    #[test]
    fn winner_self_report_locks_in() {
        // Subject is 0x01. A self-report (responder == subject) must win
        // even against a much closer-XOR third-party report.
        let subject = peer_with_leading(0x01);
        let close_third_party = peer_with_leading(0x02);

        let mut reports = SubjectReports::new();
        reports.insert(
            subject,
            report(0x01, "/ip4/10.0.0.1/udp/9000/quic", AddressType::Direct),
        );
        reports.insert(
            close_third_party,
            report(0x01, "/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
        );

        let (winner_rid, _node) = compute_winner(&subject, &reports).unwrap();
        assert_eq!(winner_rid, subject);
    }

    #[test]
    fn winner_single_third_party_wins_by_default() {
        let subject = peer_with_leading(0xF0);
        let responder = peer_with_leading(0x10);

        let mut reports = SubjectReports::new();
        reports.insert(
            responder,
            report(0xF0, "/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct),
        );

        let (winner_rid, _) = compute_winner(&subject, &reports).unwrap();
        assert_eq!(winner_rid, responder);
    }

    #[test]
    fn winner_quorum_consensus_beats_closer_dissenter() {
        // Subject 0xF0. Closest responder 0xF1 disagrees with two
        // slightly-farther responders 0xF2 and 0xF3. Quorum rule:
        // 2-of-3 among top-3 agree → consensus wins even though the
        // dissenter is strictly XOR-closer.
        let subject = peer_with_leading(0xF0);
        let dissenter = peer_with_leading(0xF1); // closest
        let agree_1 = peer_with_leading(0xF2);
        let agree_2 = peer_with_leading(0xF3);

        let mut reports = SubjectReports::new();
        reports.insert(
            dissenter,
            report(0xF0, "/ip4/6.6.6.6/udp/9000/quic", AddressType::Direct),
        );
        let consensus_addr = "/ip4/1.1.1.1/udp/9000/quic";
        reports.insert(agree_1, report(0xF0, consensus_addr, AddressType::Direct));
        reports.insert(agree_2, report(0xF0, consensus_addr, AddressType::Direct));

        let (winner_rid, winner_node) = compute_winner(&subject, &reports).unwrap();
        // Winner is one of the consensus group, not the closer dissenter.
        assert!(winner_rid == agree_1 || winner_rid == agree_2);
        assert_eq!(
            winner_node.addresses[0],
            consensus_addr.parse::<MultiAddr>().unwrap()
        );
    }

    #[test]
    fn winner_newer_publish_seq_beats_closer_stale_report() {
        // The stale relay report is XOR-closer to the subject, but a newer
        // PublishAddressSet sequence must win so lookups stop dialing dead
        // relay allocations after the publisher republishes/rebinds.
        let subject = peer_with_leading(0xF0);
        let stale_responder = peer_with_leading(0xF1);
        let fresh_responder = peer_with_leading(0xFA);

        let stale_relay = "/ip4/198.51.100.7/udp/46973/quic";
        let fresh_relay = "/ip4/203.0.113.9/udp/60488/quic";

        let mut reports = SubjectReports::new();
        reports.insert(
            stale_responder,
            report_with_seq(0xF0, stale_relay, AddressType::Relay, 10),
        );
        reports.insert(
            fresh_responder,
            report_with_seq(0xF0, fresh_relay, AddressType::Relay, 20),
        );

        let (winner_rid, winner_node) = compute_winner(&subject, &reports).unwrap();
        assert_eq!(winner_rid, fresh_responder);
        assert_eq!(
            winner_node.addresses[0],
            fresh_relay.parse::<MultiAddr>().unwrap()
        );
    }

    #[test]
    fn winner_newer_direct_only_publish_removes_stale_relay() {
        // A relay-lost republish is represented as a newer full address set
        // that simply omits the old relay. The stale sequenced relay report
        // must not survive aggregation.
        let subject = peer_with_leading(0xF0);
        let stale_responder = peer_with_leading(0xF1);
        let fresh_responder = peer_with_leading(0xFA);

        let stale_relay = "/ip4/198.51.100.7/udp/46973/quic";
        let fresh_direct = "/ip4/203.0.113.9/udp/60488/quic";

        let mut reports = SubjectReports::new();
        reports.insert(
            stale_responder,
            report_with_seq(0xF0, stale_relay, AddressType::Relay, 10),
        );
        reports.insert(
            fresh_responder,
            report_with_seq(0xF0, fresh_direct, AddressType::Direct, 20),
        );

        let (winner_rid, winner_node) = compute_winner(&subject, &reports).unwrap();
        assert_eq!(winner_rid, fresh_responder);
        assert_eq!(
            winner_node.addresses,
            vec![fresh_direct.parse::<MultiAddr>().unwrap()]
        );
        assert_eq!(winner_node.address_types, vec![AddressType::Direct]);
    }

    #[test]
    fn lookup_result_uses_per_peer_winner_not_stale_candidate_copy() {
        // The queried candidate entered best_nodes with a stale relay record.
        // A later response in the same lookup reported a newer direct-only
        // publish for the same subject. The final result must be refreshed to
        // the winner before clients receive it.
        let subject = peer_with_leading(0xF0);
        let stale_responder = peer_with_leading(0xF1);
        let fresh_responder = peer_with_leading(0xFA);
        let key = *subject.to_bytes();

        let stale_relay = "/ip4/198.51.100.7/udp/46973/quic";
        let fresh_direct = "/ip4/203.0.113.9/udp/60488/quic";
        let stale_node = report_with_seq(0xF0, stale_relay, AddressType::Relay, 10);
        let fresh_node = report_with_seq(0xF0, fresh_direct, AddressType::Direct, 20);

        let mut reports = SubjectReports::new();
        reports.insert(stale_responder, stale_node.clone());
        reports.insert(fresh_responder, fresh_node);

        let mut all_reports = HashMap::new();
        all_reports.insert(subject, reports);

        let results = apply_lookup_report_winners(vec![stale_node], &all_reports, &key, 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].peer_id, subject);
        assert_eq!(
            results[0].addresses,
            vec![fresh_direct.parse::<MultiAddr>().unwrap()]
        );
        assert_eq!(results[0].address_types, vec![AddressType::Direct]);
    }

    #[test]
    fn winner_no_quorum_falls_back_to_closest_xor() {
        // All three close responders disagree. No consensus → fall back
        // to the XOR-closest responder's report.
        let subject = peer_with_leading(0xF0);
        let closest = peer_with_leading(0xF1);
        let mid = peer_with_leading(0xF4);
        let far = peer_with_leading(0xFF);

        let mut reports = SubjectReports::new();
        reports.insert(
            closest,
            report(0xF0, "/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct),
        );
        reports.insert(
            mid,
            report(0xF0, "/ip4/2.2.2.2/udp/9000/quic", AddressType::Direct),
        );
        reports.insert(
            far,
            report(0xF0, "/ip4/3.3.3.3/udp/9000/quic", AddressType::Direct),
        );

        let (winner_rid, _) = compute_winner(&subject, &reports).unwrap();
        assert_eq!(winner_rid, closest);
    }

    #[test]
    fn winner_outlier_quorum_of_two_from_three() {
        // Three responders: two agree, one disagrees. Regardless of
        // which is closer, the 2-of-3 consensus wins.
        let subject = peer_with_leading(0xF0);
        let r_a = peer_with_leading(0xF1);
        let r_b = peer_with_leading(0xF2);
        let r_c = peer_with_leading(0xF3);

        let agree = "/ip4/9.9.9.9/udp/9000/quic";
        let mut reports = SubjectReports::new();
        reports.insert(r_a, report(0xF0, agree, AddressType::Direct));
        reports.insert(
            r_b,
            report(0xF0, "/ip4/8.8.8.8/udp/9000/quic", AddressType::Direct),
        );
        reports.insert(r_c, report(0xF0, agree, AddressType::Direct));

        let (winner_rid, winner_node) = compute_winner(&subject, &reports).unwrap();
        assert!(winner_rid == r_a || winner_rid == r_c);
        assert_eq!(
            winner_node.addresses[0],
            agree.parse::<MultiAddr>().unwrap()
        );
    }

    #[test]
    fn best_tier_priority_picks_strongest_tag() {
        let node = dht_node(
            1,
            vec![
                ("/ip4/10.0.0.1/udp/9000/quic", AddressType::Unverified),
                ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Relay),
                ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Direct),
            ],
        );
        assert_eq!(best_tier_priority(&node), AddressType::Relay.priority());
    }

    #[test]
    fn best_tier_priority_empty_node_returns_max() {
        let node = DHTNode {
            peer_id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            address_types: vec![],
            distance: None,
            reliability: 1.0,
        };
        assert_eq!(best_tier_priority(&node), u8::MAX);
    }

    #[test]
    fn first_direct_dialable_picks_direct_over_relay() {
        let node = dht_node(
            1,
            vec![
                ("/ip4/10.0.0.1/udp/9000/quic", AddressType::Relay),
                ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ],
        );
        let picked = DhtNetworkManager::first_direct_dialable(&node).unwrap();
        assert_eq!(
            picked,
            "/ip4/203.0.113.7/udp/9001/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn first_direct_dialable_returns_none_when_only_relay() {
        let node = dht_node(1, vec![("/ip4/10.0.0.1/udp/9000/quic", AddressType::Relay)]);
        assert_eq!(DhtNetworkManager::first_direct_dialable(&node), None);
    }

    #[test]
    fn by_distance_comparator_keeps_xor_closer_relay_only_ahead_of_direct() {
        // With key = [0; 32], xor_distance == peer_id, so the lower seed is
        // XOR-closer. Address type must not affect pure distance ordering.
        let key: Key = [0u8; 32];
        let relay_closer = dht_node(1, vec![("/ip4/10.0.0.1/udp/9000/quic", AddressType::Relay)]);
        let direct_farther = dht_node(
            2,
            vec![("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct)],
        );

        // Start in the opposite order so a passing assertion proves the sort
        // actually reordered (rather than leaving an already-correct input).
        let mut nodes = [direct_farther, relay_closer];
        nodes.sort_by(|a, b| DhtNetworkManager::compare_node_distance(a, b, &key));

        assert_eq!(nodes.len(), 2, "distance sort must never drop peers");
        assert_eq!(
            nodes[0].peer_id,
            PeerId::from_bytes([1u8; 32]),
            "XOR-only ordering must keep the XOR-closer peer first"
        );
        assert_eq!(nodes[1].peer_id, PeerId::from_bytes([2u8; 32]));
    }
    #[test]
    fn first_direct_dialable_skips_wildcard_direct() {
        let node = dht_node(
            1,
            vec![
                ("/ip4/0.0.0.0/udp/9000/quic", AddressType::Direct),
                ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ],
        );
        let picked = DhtNetworkManager::first_direct_dialable(&node).unwrap();
        assert_eq!(
            picked,
            "/ip4/203.0.113.7/udp/9001/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn first_direct_dialable_returns_none_for_empty_node() {
        let node = DHTNode {
            peer_id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            address_types: vec![],
            distance: None,
            reliability: 1.0,
        };
        assert_eq!(DhtNetworkManager::first_direct_dialable(&node), None);
    }

    #[test]
    fn first_direct_dialable_skips_lan() {
        let node = dht_node(
            1,
            vec![
                ("/ip4/10.0.0.1/udp/9000/quic", AddressType::Lan),
                ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ],
        );
        let picked = DhtNetworkManager::first_direct_dialable(&node).unwrap();
        assert_eq!(
            picked,
            "/ip4/203.0.113.7/udp/9001/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn first_direct_dialable_canonicalizes_local_scope_direct_to_lan() {
        let node = dht_node(
            1,
            vec![("/ip4/192.168.1.10/udp/9000/quic", AddressType::Direct)],
        );

        assert_eq!(DhtNetworkManager::first_direct_dialable(&node), None);
    }

    #[test]
    fn first_direct_dialable_canonicalizes_mapped_local_scope_direct_to_lan() {
        let node = dht_node(
            1,
            vec![(
                "/ip6/::ffff:192.168.1.10/udp/9000/quic",
                AddressType::Direct,
            )],
        );

        assert_eq!(DhtNetworkManager::first_direct_dialable(&node), None);
    }

    #[test]
    fn first_direct_dialable_for_relay_skips_same_wan_candidate() {
        let node = dht_node(
            1,
            vec![("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct)],
        );
        let context = DialAddressContext::from_parts(
            ["203.0.113.7:12000".parse().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );

        assert_eq!(
            DhtNetworkManager::first_direct_dialable_for_relay(&node, &context),
            None
        );
    }

    #[test]
    fn first_direct_dialable_for_relay_uses_non_same_wan_fallback() {
        let node = dht_node(
            1,
            vec![
                ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
                ("/ip6/2001:db8::7/udp/9002/quic", AddressType::Direct),
            ],
        );
        let context = DialAddressContext::from_parts(
            ["203.0.113.7:12000".parse().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );

        let picked = DhtNetworkManager::first_direct_dialable_for_relay(&node, &context).unwrap();
        assert_eq!(
            picked,
            "/ip6/2001:db8::7/udp/9002/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn first_direct_dialable_skips_unverified() {
        // Unverified addresses are self-published observed externals that
        // have not been proven reachable by the local classifier. The
        // relay-acquisition walker must not pick them as candidate relays
        // (that was the bug which caused NAT'd droplets to dial
        // ephemeral-port "Direct" entries and treat them as reachable).
        let node = dht_node(
            1,
            vec![
                ("/ip4/10.0.0.1/udp/9000/quic", AddressType::Unverified),
                ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ],
        );
        let picked = DhtNetworkManager::first_direct_dialable(&node).unwrap();
        assert_eq!(
            picked,
            "/ip4/203.0.113.7/udp/9001/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn first_direct_dialable_returns_none_when_only_unverified() {
        let node = dht_node(
            1,
            vec![("/ip4/10.0.0.1/udp/9000/quic", AddressType::Unverified)],
        );
        assert_eq!(DhtNetworkManager::first_direct_dialable(&node), None);
    }

    #[test]
    fn first_direct_dialable_rejects_legacy_untagged_addresses() {
        // A DHTNode with a non-empty `addresses` vec but an empty
        // `address_types` — the shape produced by deserializing a
        // pre-ADR-014 record. Legacy publishers never asserted
        // reachability, so such entries must NOT be picked as relay
        // candidates; the fallback is `Unverified`, not `Direct`.
        let node = DHTNode {
            peer_id: PeerId::from_bytes([1u8; 32]),
            addresses: vec!["/ip4/203.0.113.7/udp/9001/quic".parse().unwrap()],
            address_types: vec![], // legacy wire payload
            distance: None,
            reliability: 1.0,
        };
        assert_eq!(DhtNetworkManager::first_direct_dialable(&node), None);
    }

    fn typed(entries: Vec<(&str, AddressType)>) -> Vec<(MultiAddr, AddressType)> {
        entries
            .into_iter()
            .map(|(s, t)| (s.parse().unwrap(), t))
            .collect()
    }

    #[test]
    fn select_dial_candidates_returns_empty_for_empty_input() {
        let picks = DhtNetworkManager::select_dial_candidates(&[]);
        assert!(picks.is_empty());
    }

    #[test]
    fn select_dial_candidates_relay_plus_direct_gives_two() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
            ("/ip4/192.168.1.10/udp/9003/quic", AddressType::Lan),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Relay);
        assert_eq!(picks[1].1, AddressType::Direct);
    }

    #[test]
    fn select_dial_candidates_relay_plus_dual_stack_direct_keeps_both_families() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip6/2001:db8::7/udp/9001/quic", AddressType::Direct),
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 3);
        assert_eq!(picks[0].1, AddressType::Relay);
        assert_eq!(picks[1].0, addrs[1].0);
        assert_eq!(picks[2].0, addrs[2].0);
    }

    #[test]
    fn select_dial_candidates_relay_plus_unverified_gives_two() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
            ("/ip4/192.168.1.10/udp/9003/quic", AddressType::Lan),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Relay);
        assert_eq!(picks[1].1, AddressType::Unverified);
    }

    #[test]
    fn select_dial_candidates_skips_same_wan_relay_for_direct_fallback() {
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9000/quic", AddressType::Relay),
            ("/ip4/198.51.100.9/udp/9001/quic", AddressType::Direct),
        ]);
        let context = DialAddressContext::from_parts(
            ["203.0.113.7:12000".parse().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );

        let picks = DhtNetworkManager::select_dial_candidates_with_context(&addrs, &context);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Direct);
        assert_eq!(picks[0].0, addrs[1].0);
    }

    #[test]
    fn select_dial_candidates_skips_same_wan_relay_for_unverified_fallback() {
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9000/quic", AddressType::Relay),
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Unverified),
        ]);
        let context = DialAddressContext::from_parts(
            ["203.0.113.7:12000".parse().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );

        let picks = DhtNetworkManager::select_dial_candidates_with_context(&addrs, &context);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Unverified);
        assert_eq!(picks[0].0, addrs[1].0);
    }

    #[test]
    fn select_dial_candidates_same_wan_relay_without_fallback_is_empty() {
        let addrs = typed(vec![("/ip4/203.0.113.7/udp/9000/quic", AddressType::Relay)]);
        let context = DialAddressContext::from_parts(
            ["203.0.113.7:12000".parse().unwrap()],
            Vec::<MultiAddr>::new(),
            false,
        );

        let picks = DhtNetworkManager::select_dial_candidates_with_context(&addrs, &context);
        assert!(picks.is_empty());
    }

    #[test]
    fn select_dial_candidates_relay_only_is_one() {
        let addrs = typed(vec![(
            "/ip4/198.51.100.1/udp/9000/quic",
            AddressType::Relay,
        )]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Relay);
    }

    #[test]
    fn select_dial_candidates_direct_plus_unverified_when_no_relay() {
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ("/ip6/2001:db8::9/udp/9002/quic", AddressType::Unverified),
            ("/ip6/fd00::10/udp/9003/quic", AddressType::Lan),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Direct);
        assert_eq!(picks[1].1, AddressType::Unverified);
    }

    #[test]
    fn select_dial_candidates_direct_dominates_same_family_unverified() {
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Direct);
    }

    #[test]
    fn select_dial_candidates_direct_only_is_one() {
        let addrs = typed(vec![(
            "/ip4/203.0.113.7/udp/9001/quic",
            AddressType::Direct,
        )]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Direct);
    }

    #[test]
    fn select_dial_candidates_only_unverified_is_one() {
        let addrs = typed(vec![
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
            ("/ip4/192.0.2.11/udp/9004/quic", AddressType::Unverified),
            ("/ip4/192.168.1.10/udp/9003/quic", AddressType::Lan),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Unverified);
    }

    #[test]
    fn select_dial_candidates_only_unverified_keeps_both_families() {
        let addrs = typed(vec![
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
            ("/ip6/2001:db8::9/udp/9002/quic", AddressType::Unverified),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].0, addrs[0].0);
        assert_eq!(picks[1].0, addrs[1].0);
    }

    #[test]
    fn select_dial_candidates_only_lan_is_one() {
        let addrs = typed(vec![("/ip4/192.168.1.10/udp/9003/quic", AddressType::Lan)]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Lan);
    }

    #[test]
    fn select_dial_candidates_canonicalizes_local_scope_direct_to_lan() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/192.168.1.10/udp/9003/quic", AddressType::Direct),
        ]);

        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Relay);

        let local_only = typed(vec![(
            "/ip4/192.168.1.10/udp/9003/quic",
            AddressType::Unverified,
        )]);
        let picks = DhtNetworkManager::select_dial_candidates(&local_only);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Lan);
    }

    #[test]
    fn select_dial_candidates_canonicalizes_mapped_local_scope_to_lan() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip6/::ffff:127.0.0.1/udp/9001/quic", AddressType::Direct),
            (
                "/ip6/::ffff:100.64.0.1/udp/9002/quic",
                AddressType::Unverified,
            ),
        ]);

        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Relay);

        let local_only = typed(vec![(
            "/ip6/::ffff:100.64.0.1/udp/9002/quic",
            AddressType::Unverified,
        )]);
        let picks = DhtNetworkManager::select_dial_candidates(&local_only);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Lan);
    }

    #[test]
    fn select_dial_candidates_filters_undialable_wildcard() {
        // Wildcard `Direct` must be skipped, leaving the real Direct as
        // the first pick. The other slot stays empty (only Unverified
        // left, which does not combine with a real Direct in this case
        // because we still only keep two total).
        let addrs = typed(vec![
            ("/ip4/0.0.0.0/udp/9000/quic", AddressType::Direct),
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Direct);
        assert_eq!(
            picks[0].0,
            "/ip4/203.0.113.7/udp/9001/quic"
                .parse::<MultiAddr>()
                .unwrap()
        );
    }

    #[test]
    fn select_dial_candidates_prefers_unverified_over_lan_without_local_context() {
        // Without a same-WAN/local-LAN signal, LAN addresses are not tried
        // while a WAN Unverified candidate exists.
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ("/ip6/fd00::10/udp/9003/quic", AddressType::Lan),
            ("/ip6/2001:db8::9/udp/9002/quic", AddressType::Unverified),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Direct);
        assert_eq!(picks[1].1, AddressType::Unverified);
    }

    #[test]
    fn select_dial_candidates_prefers_lan_for_same_wan_peer() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Unverified),
            ("/ip4/192.168.1.30/udp/9001/quic", AddressType::Lan),
        ]);
        let context = DialAddressContext::from_parts(
            ["203.0.113.7:12000".parse().unwrap()],
            ["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
            false,
        );

        let picks = DhtNetworkManager::select_dial_candidates_with_context(&addrs, &context);
        assert_eq!(picks.len(), 3);
        assert_eq!(picks[0].1, AddressType::Lan);
        assert_eq!(picks[1].1, AddressType::Relay);
        assert_eq!(picks[2].1, AddressType::Unverified);
    }

    #[test]
    fn select_dial_candidates_does_not_prefer_lan_for_private_prefix_only() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/192.168.1.30/udp/9001/quic", AddressType::Lan),
        ]);
        let context = DialAddressContext::from_parts(
            Vec::<SocketAddr>::new(),
            ["/ip4/192.168.1.20/udp/9000/quic".parse().unwrap()],
            false,
        );

        let picks = DhtNetworkManager::select_dial_candidates_with_context(&addrs, &context);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Relay);
    }

    #[test]
    fn select_dial_candidates_skips_lan_when_peer_is_external() {
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/192.168.50.30/udp/9001/quic", AddressType::Lan),
        ]);
        let context = DialAddressContext::from_parts(
            ["203.0.113.9:12000".parse().unwrap()],
            ["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
            false,
        );

        let picks = DhtNetworkManager::select_dial_candidates_with_context(&addrs, &context);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Relay);
    }

    #[test]
    fn dial_plan_fully_failed_in_cache_requires_every_planned_address() {
        let cache = DialFailureCache::new();
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
        ]);
        let plan = DhtNetworkManager::select_dial_candidates(&addrs);

        assert!(!DhtNetworkManager::dial_plan_fully_failed_in_cache(
            &cache, &addrs
        ));

        cache.record_failure(plan[0].0.dialable_socket_addr().unwrap(), plan[0].1);
        assert!(
            !DhtNetworkManager::dial_plan_fully_failed_in_cache(&cache, &addrs),
            "one available planned address should keep the candidate queryable"
        );

        cache.record_failure(plan[1].0.dialable_socket_addr().unwrap(), plan[1].1);
        assert!(
            DhtNetworkManager::dial_plan_fully_failed_in_cache(&cache, &addrs),
            "all planned dial addresses in the failure cache should suppress the candidate"
        );
    }

    #[test]
    fn dial_plan_fully_failed_in_cache_empty_plan_is_not_exhausted() {
        let cache = DialFailureCache::new();

        assert!(!DhtNetworkManager::dial_plan_fully_failed_in_cache(
            &cache,
            &[]
        ));
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dial_failure_cache_records_and_checks() {
        let cache = DialFailureCache::new();
        let addr = sock("203.0.113.7:9001");
        assert!(
            !cache.is_failed(&addr, AddressType::Direct),
            "empty cache never reports failed"
        );
        cache.record_failure(addr, AddressType::Direct);
        assert!(
            cache.is_failed(&addr, AddressType::Direct),
            "recorded address must be treated as failed within the TTL"
        );
    }

    #[test]
    fn dial_failure_cache_clear_removes_entry() {
        let cache = DialFailureCache::new();
        let addr = sock("203.0.113.7:9001");
        cache.record_failure(addr, AddressType::Direct);
        cache.clear(&addr);
        assert!(
            !cache.is_failed(&addr, AddressType::Direct),
            "clear() must drop the entry so a subsequent dial is allowed"
        );
    }

    #[test]
    fn publish_self_heal_clears_dial_failures_only_when_applied() {
        let cache = DialFailureCache::new();
        let peer = PeerId::from_bytes([1; 32]);
        let relay = crate::MultiAddr::quic(sock("203.0.113.7:9000"));
        let direct = crate::MultiAddr::quic(sock("203.0.113.8:9000"));
        let relay_sa = relay.dialable_socket_addr().expect("dialable");
        let direct_sa = direct.dialable_socket_addr().expect("dialable");

        cache.record_failure(relay_sa, AddressType::Relay);
        cache.record_failure(direct_sa, AddressType::Direct);
        assert!(cache.is_failed(&relay_sa, AddressType::Relay));
        assert!(cache.is_failed(&direct_sa, AddressType::Direct));

        let addrs = vec![
            (relay.clone(), AddressType::Relay),
            (direct.clone(), AddressType::Direct),
        ];

        // A stale/duplicate publish (not applied) must NOT lift suppression.
        assert_eq!(
            clear_dial_failures_for_published(&cache, &peer, false, &addrs),
            0
        );
        assert!(cache.is_failed(&relay_sa, AddressType::Relay));
        assert!(cache.is_failed(&direct_sa, AddressType::Direct));

        // A newer applied publish clears the per-address failures (neither IP is
        // over the suppression threshold here, so both become dialable).
        assert_eq!(
            clear_dial_failures_for_published(&cache, &peer, true, &addrs),
            2
        );
        assert!(!cache.is_failed(&relay_sa, AddressType::Relay));
        assert!(!cache.is_failed(&direct_sa, AddressType::Direct));
    }

    #[test]
    fn publish_self_heal_keeps_ip_tier_suppression_for_others() {
        let cache = DialFailureCache::new();
        let peer = PeerId::from_bytes([1; 32]);
        // Push one relay IP to the suppression threshold with distinct sessions.
        let mut socks = Vec::new();
        for port in 9001..9001 + DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            let sa = sock(&format!("198.51.100.7:{port}"));
            cache.record_failure(sa, AddressType::Relay);
            socks.push(sa);
        }
        let ip = socks[0].ip();
        assert!(
            cache.ip_is_suppressed(&ip),
            "relay IP should be suppressed once at threshold"
        );

        // The owner re-attests one of those addresses via an applied publish.
        let addrs = vec![(crate::MultiAddr::quic(socks[0]), AddressType::Relay)];
        assert_eq!(
            clear_dial_failures_for_published(&cache, &peer, true, &addrs),
            1
        );

        // Its own per-address entry is cleared, but a republish (weaker evidence
        // than a real dial success) must NOT lift IP-level suppression for the
        // unrelated failed relay sessions sharing that IP.
        assert!(
            cache.entries.get(&socks[0]).is_none(),
            "the re-attested address's per-address entry is cleared"
        );
        assert!(
            cache.ip_is_suppressed(&ip),
            "IP-tier suppression for other relay sessions on the same IP is retained"
        );
        assert!(
            cache.is_failed(&socks[1], AddressType::Relay),
            "another failed relay session on the same IP stays suppressed"
        );
    }

    #[test]
    fn publish_self_heal_exempts_reattested_address_from_ip_suppression() {
        let cache = DialFailureCache::new();
        let owner = PeerId::from_bytes([1; 32]);
        let other = PeerId::from_bytes([2; 32]);
        // Suppress a relay IP with distinct dead sessions.
        let mut socks = Vec::new();
        for port in 9001..9001 + DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            let sa = sock(&format!("198.51.100.9:{port}"));
            cache.record_failure(sa, AddressType::Relay);
            socks.push(sa);
        }
        let ip = socks[0].ip();
        assert!(cache.ip_is_suppressed(&ip));
        // Before re-attestation the exact address is suppressed for any dialer.
        assert!(cache.is_failed_for_dial(&owner, &socks[0], AddressType::Relay));

        // Its owner reclaims and re-attests it via an applied publish.
        let addrs = vec![(crate::MultiAddr::quic(socks[0]), AddressType::Relay)];
        assert_eq!(
            clear_dial_failures_for_published(&cache, &owner, true, &addrs),
            1
        );

        // A dial TO THE OWNER at the exact re-attested socket is now allowed,
        // despite the IP staying suppressed for the other dead sessions — ADR-011
        // self-heal retries it immediately instead of waiting out the IP-tier TTL.
        assert!(
            !cache.is_failed_for_dial(&owner, &socks[0], AddressType::Relay),
            "owner's re-attested stable address must bypass IP-tier suppression"
        );
        // ...but a DIFFERENT peer dialed at the same socket gets NO bypass — the
        // exemption is scoped to the peer that authoritatively re-attested it.
        assert!(
            cache.is_failed_for_dial(&other, &socks[0], AddressType::Relay),
            "a different peer at the same socket is still IP-suppressed"
        );
        assert!(
            cache.ip_is_suppressed(&ip),
            "IP tier stays suppressed for the unrelated dead sessions"
        );
        assert!(
            cache.is_failed_for_dial(&owner, &socks[1], AddressType::Relay),
            "an unrelated dead session on the same IP is still suppressed"
        );

        // Idempotent across repeated checks within the window (the dial-plan
        // predicate and the dial itself both see the exemption).
        assert!(!cache.is_failed_for_dial(&owner, &socks[0], AddressType::Relay));

        // A fresh failure of the re-attested address ends the bypass (per-address
        // suppression takes precedence), so it can't mask a genuinely dead address.
        cache.record_failure(socks[0], AddressType::Relay);
        assert!(
            cache.is_failed_for_dial(&owner, &socks[0], AddressType::Relay),
            "a fresh failure re-suppresses the address"
        );
    }

    #[test]
    fn dial_failure_cache_expires_stale_entries_on_read() {
        // Insert an entry with a recorded_at timestamp older than the TTL
        // and verify is_failed() returns false and removes the entry.
        let cache = DialFailureCache::new();
        let addr = sock("203.0.113.7:9001");
        // Skip when the runner's monotonic clock has less uptime than the
        // TTL. Hit on freshly-booted Windows CI where Instant starts near
        // zero, making `checked_sub` underflow.
        let Some(stale) =
            Instant::now().checked_sub(DIAL_FAILURE_CACHE_TTL + Duration::from_secs(1))
        else {
            eprintln!(
                "skipping: runner Instant is fresher than DIAL_FAILURE_CACHE_TTL ({DIAL_FAILURE_CACHE_TTL:?})"
            );
            return;
        };
        cache.entries.insert(addr, stale);
        assert!(
            !cache.is_failed(&addr, AddressType::Direct),
            "stale entry must not suppress a fresh dial"
        );
        assert!(
            cache.entries.get(&addr).is_none(),
            "stale entry must be evicted lazily on read"
        );
    }

    #[test]
    fn dial_failure_cache_independent_keys_do_not_collide() {
        let cache = DialFailureCache::new();
        let a = sock("203.0.113.7:9001");
        let b = sock("203.0.113.8:9001");
        cache.record_failure(a, AddressType::Direct);
        assert!(cache.is_failed(&a, AddressType::Direct));
        assert!(
            !cache.is_failed(&b, AddressType::Direct),
            "different SocketAddr must not hit"
        );
    }

    /// Helper: a distinct relay-session [`SocketAddr`] at relay-server IP
    /// `203.0.113.50`, varying only the port. Models the many orphaned
    /// MASQUE session addresses a single downed relay leaves circulating.
    fn relay_session(port: u16) -> SocketAddr {
        SocketAddr::new("203.0.113.50".parse().unwrap(), port)
    }

    const TEST_RELAY_IP: &str = "203.0.113.50";

    #[test]
    fn dial_failure_ip_tier_suppresses_unseen_session_after_threshold() {
        let cache = DialFailureCache::new();

        // One short of the threshold: no IP-level suppression yet, so a
        // never-seen session at that IP is still dialable.
        for port in 0..(DIAL_FAILURE_IP_SUPPRESS_THRESHOLD - 1) as u16 {
            cache.record_failure(relay_session(9001 + port), AddressType::Relay);
        }
        let unseen = relay_session(9500);
        assert!(
            !cache.is_failed(&unseen, AddressType::Relay),
            "below the threshold the IP tier must not suppress a fresh session"
        );

        // Cross the threshold with one more distinct dead session.
        cache.record_failure(
            relay_session(9001 + (DIAL_FAILURE_IP_SUPPRESS_THRESHOLD - 1) as u16),
            AddressType::Relay,
        );
        assert!(
            cache.is_failed(&unseen, AddressType::Relay),
            "at the threshold every remaining session at the dead relay IP is suppressed"
        );
        assert!(
            cache.entries.get(&unseen).is_none(),
            "IP-level suppression must not require dialing or recording the unseen session"
        );
    }

    #[test]
    fn dial_failure_ip_tier_redialing_same_session_does_not_inflate_count() {
        let cache = DialFailureCache::new();
        // The same dead session failing repeatedly is one *distinct* address
        // and must not on its own reach the distinct-session threshold.
        for _ in 0..(DIAL_FAILURE_IP_SUPPRESS_THRESHOLD + 2) {
            cache.record_failure(relay_session(9001), AddressType::Relay);
        }
        let unseen = relay_session(9500);
        assert!(
            !cache.is_failed(&unseen, AddressType::Relay),
            "re-dialing a single dead session must not trip IP-level suppression"
        );
    }

    #[test]
    fn dial_failure_ip_tier_success_clears_suppression() {
        let cache = DialFailureCache::new();
        for port in 0..DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            cache.record_failure(relay_session(9001 + port), AddressType::Relay);
        }
        let unseen = relay_session(9500);
        assert!(cache.is_failed(&unseen, AddressType::Relay));

        // A success at any address at that IP proves the relay recovered.
        cache.clear(&relay_session(9001));
        assert!(
            !cache.is_failed(&unseen, AddressType::Relay),
            "a success at the IP must lift IP-level suppression immediately"
        );
    }

    #[test]
    fn dial_failure_ip_tier_shared_ip_success_keeps_live_peer() {
        // A shared NAT IP hosts several churning relay sessions plus one
        // genuinely-live peer. Once the dead sessions trip suppression, a
        // success from the live peer at the same IP must re-admit it.
        let cache = DialFailureCache::new();
        for port in 0..DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            cache.record_failure(relay_session(9001 + port), AddressType::Relay);
        }
        let live_peer = relay_session(7000);
        assert!(
            cache.is_failed(&live_peer, AddressType::Relay),
            "precondition: the live peer's session is initially caught by IP suppression"
        );

        // The live peer answers — record the success.
        cache.clear(&live_peer);
        assert!(
            !cache.is_failed(&live_peer, AddressType::Relay),
            "a live peer that succeeds at a shared IP must not stay suppressed"
        );
    }

    #[test]
    fn dial_failure_ip_tier_ignores_non_relay_failures() {
        // Many distinct Direct failures at one IP must never build IP-level
        // suppression: distinct Direct peers legitimately share a NAT IP.
        let cache = DialFailureCache::new();
        for port in 0..(DIAL_FAILURE_IP_SUPPRESS_THRESHOLD + 2) as u16 {
            cache.record_failure(relay_session(9001 + port), AddressType::Direct);
        }
        let unseen_relay = relay_session(9500);
        assert!(
            !cache.is_failed(&unseen_relay, AddressType::Relay),
            "non-relay failures must not populate the relay-IP suppression tier"
        );
    }

    #[test]
    fn dial_failure_ip_tier_relay_failures_do_not_suppress_direct_dials() {
        // Even at a suppressed relay IP, a Direct dial to the same IP is a
        // distinct peer kind and must not be skipped by the relay tier.
        let cache = DialFailureCache::new();
        for port in 0..DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            cache.record_failure(relay_session(9001 + port), AddressType::Relay);
        }
        let direct = relay_session(9500);
        assert!(
            !cache.is_failed(&direct, AddressType::Direct),
            "IP-level suppression is scoped to relay-kind dials only"
        );
    }

    #[test]
    fn dial_failure_ip_tier_expires_stale_sessions_on_read() {
        let cache = DialFailureCache::new();
        let ip: IpAddr = TEST_RELAY_IP.parse().unwrap();
        let Some(stale) =
            Instant::now().checked_sub(DIAL_FAILURE_CACHE_TTL + Duration::from_secs(1))
        else {
            eprintln!(
                "skipping: runner Instant is fresher than DIAL_FAILURE_CACHE_TTL ({DIAL_FAILURE_CACHE_TTL:?})"
            );
            return;
        };
        let mut sessions = HashMap::new();
        for port in 0..DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            sessions.insert(relay_session(9001 + port), stale);
        }
        cache.ip_failures.insert(ip, sessions);

        assert!(
            !cache.ip_is_suppressed(&ip),
            "all sessions stale: the IP must not suppress a fresh dial"
        );
        assert!(
            cache.ip_failures.get(&ip).is_none(),
            "an IP whose session set empties on expiry must be evicted"
        );
    }

    #[test]
    fn dial_failure_cache_canonicalizes_v4_mapped_v6_key() {
        // A failure recorded under the IPv4-mapped IPv6 form must suppress —
        // and be cleared by — the bare IPv4 form of the same endpoint, so the
        // cache matches the transport's canonicalized endpoint identity.
        let cache = DialFailureCache::new();
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:9001".parse().unwrap();
        let bare: SocketAddr = "203.0.113.7:9001".parse().unwrap();

        cache.record_failure(mapped, AddressType::Direct);
        assert!(
            cache.is_failed(&bare, AddressType::Direct),
            "failure recorded under v4-mapped-v6 must suppress the bare IPv4 form"
        );
        cache.clear(&mapped);
        assert!(
            !cache.is_failed(&bare, AddressType::Direct),
            "clear under v4-mapped-v6 must clear the bare IPv4 form"
        );
    }

    #[test]
    fn dial_failure_ip_tier_canonicalizes_v4_mapped_v6() {
        // IP-tier suppression must collapse v4-mapped-v6 and bare IPv4 to the
        // same relay-server IP: threshold sessions recorded under the mapped
        // form must suppress an unseen bare-IPv4 session at the same endpoint.
        let cache = DialFailureCache::new();
        for port in 0..DIAL_FAILURE_IP_SUPPRESS_THRESHOLD as u16 {
            let mapped: SocketAddr = format!("[::ffff:203.0.113.50]:{}", 9001 + port)
                .parse()
                .unwrap();
            cache.record_failure(mapped, AddressType::Relay);
        }
        let bare_unseen: SocketAddr = "203.0.113.50:9500".parse().unwrap();
        assert!(
            cache.is_failed(&bare_unseen, AddressType::Relay),
            "IP-tier suppression must apply across v4-mapped-v6 / bare IPv4 forms of one IP"
        );
    }

    /// Helper: deterministic [`PeerId`] from a single byte. Mirrors
    /// `make_node` in `core_engine` tests but without addresses since
    /// the identity-failure cache only keys on peer ID.
    fn pid(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn routing_test_node(byte: u8) -> NodeInfo {
        NodeInfo {
            id: pid(byte),
            addresses: vec![MultiAddr::quic(sock(&format!("203.0.{byte}.1:9000")))],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        }
    }

    #[test]
    fn identity_failure_cache_records_and_checks() {
        let cache = IdentityFailureCache::new();
        let peer = pid(7);
        assert!(!cache.is_failed(&peer), "empty cache never reports failed");
        cache.record_failure(peer);
        assert!(
            cache.is_failed(&peer),
            "recorded peer must be treated as failed within the TTL"
        );
    }

    #[test]
    fn identity_failure_cache_clear_removes_entry() {
        let cache = IdentityFailureCache::new();
        let peer = pid(7);
        cache.record_failure(peer);
        cache.clear(&peer);
        assert!(
            !cache.is_failed(&peer),
            "clear() must drop the entry so a successful re-handshake is not suppressed"
        );
    }

    #[test]
    fn identity_failure_cache_expires_stale_entries_on_read() {
        // Insert an entry whose expiry is already in the past and
        // verify is_failed() returns false and removes the entry.
        let cache = IdentityFailureCache::new();
        let peer = pid(7);
        let Some(expired) = Instant::now().checked_sub(Duration::from_secs(1)) else {
            eprintln!("skipping: runner Instant epoch is too fresh to subtract from");
            return;
        };
        cache.entries.insert(peer, expired);
        assert!(
            !cache.is_failed(&peer),
            "expired entry must not suppress a fresh dial"
        );
        assert!(
            cache.entries.get(&peer).is_none(),
            "expired entry must be evicted lazily on read"
        );
    }

    #[test]
    fn identity_failure_cache_independent_keys_do_not_collide() {
        let cache = IdentityFailureCache::new();
        let a = pid(7);
        let b = pid(8);
        cache.record_failure(a);
        assert!(cache.is_failed(&a));
        assert!(!cache.is_failed(&b), "different PeerId must not hit");
    }

    #[test]
    fn identity_failure_cache_mismatch_uses_longer_ttl_than_failure() {
        // record_mismatch must store an expiry that is strictly later
        // than what record_failure stores. We can't observe the exact
        // TTL without sleeping, but we can compare the stored expiry
        // instants against the constants.
        let cache = IdentityFailureCache::new();
        let failed_peer = pid(7);
        let mismatched_peer = pid(8);

        cache.record_failure(failed_peer);
        cache.record_mismatch(mismatched_peer);

        let failed_expiry = *cache
            .entries
            .get(&failed_peer)
            .expect("record_failure must insert an entry")
            .value();
        let mismatch_expiry = *cache
            .entries
            .get(&mismatched_peer)
            .expect("record_mismatch must insert an entry")
            .value();

        assert!(
            mismatch_expiry > failed_expiry,
            "mismatch suppression must outlast a plain identity failure"
        );

        // Both must currently report as failed.
        assert!(cache.is_failed(&failed_peer));
        assert!(cache.is_failed(&mismatched_peer));
    }

    #[test]
    fn test_peer_rejected_round_trips_through_serialization() {
        let result = DhtNetworkResult::PeerRejected;
        let bytes = postcard::to_stdvec(&result).expect("serialization should succeed");
        let deserialized: DhtNetworkResult =
            postcard::from_bytes(&bytes).expect("deserialization should succeed");
        assert!(
            matches!(deserialized, DhtNetworkResult::PeerRejected),
            "round-tripped result should be PeerRejected, got: {deserialized:?}"
        );
    }

    #[test]
    fn test_routing_table_ready_event_construction() {
        let event = DhtNetworkEvent::RoutingTableReady { num_peers: 42 };
        assert!(
            matches!(event, DhtNetworkEvent::RoutingTableReady { num_peers: 42 }),
            "RoutingTableReady event should carry the peer count"
        );
    }

    #[test]
    fn test_bootstrap_complete_event_construction() {
        let event = DhtNetworkEvent::BootstrapComplete { num_peers: 42 };
        assert!(
            matches!(event, DhtNetworkEvent::BootstrapComplete { num_peers: 42 }),
            "BootstrapComplete event should carry the peer count"
        );
    }

    #[test]
    fn test_k_closest_changed_event_uses_old_new_naming() {
        let old = vec![PeerId::random(), PeerId::random()];
        let new = vec![PeerId::random()];
        let event = DhtNetworkEvent::KClosestPeersChanged {
            old: old.clone(),
            new: new.clone(),
        };
        match event {
            DhtNetworkEvent::KClosestPeersChanged {
                old: got_old,
                new: got_new,
            } => {
                assert_eq!(got_old, old);
                assert_eq!(got_new, new);
            }
            _ => panic!("expected KClosestPeersChanged"),
        }
    }

    #[test]
    fn test_peer_rejected_response_message_preserves_request_payload() {
        let request = DhtNetworkMessage {
            message_id: "test-123".to_string(),
            source: PeerId::random(),
            target: Some(PeerId::random()),
            message_type: DhtMessageType::Request,
            payload: DhtNetworkOperation::Ping,
            result: None,
            timestamp: 0,
            ttl: 10,
            hop_count: 0,
        };

        // Serialize & deserialize the full response message to verify
        // PeerRejected survives a wire round-trip inside a DhtNetworkMessage.
        let response = DhtNetworkMessage {
            message_id: request.message_id.clone(),
            source: PeerId::random(),
            target: Some(request.source),
            message_type: DhtMessageType::Response,
            payload: request.payload.clone(),
            result: Some(DhtNetworkResult::PeerRejected),
            timestamp: 0,
            ttl: request.ttl.saturating_sub(1),
            hop_count: request.hop_count.saturating_add(1),
        };

        let bytes = postcard::to_stdvec(&response).expect("serialize response");
        let decoded: DhtNetworkMessage =
            postcard::from_bytes(&bytes).expect("deserialize response");

        assert!(
            matches!(decoded.result, Some(DhtNetworkResult::PeerRejected)),
            "response result should be PeerRejected"
        );
        assert!(
            matches!(decoded.payload, DhtNetworkOperation::Ping),
            "response should echo the request's Ping payload"
        );
    }
}
