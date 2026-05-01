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
    adaptive::TrustEngine,
    adaptive::trust::DEFAULT_NEUTRAL_TRUST,
    address::MultiAddr,
    dht::core_engine::{AddressType, AtomicInstant, NodeInfo},
    dht::{AdmissionResult, DhtCoreEngine, DhtKey, Key, RoutingTableEvent},
    error::{DhtError, IdentityError, NetworkError},
    network::{NodeConfig, NodeMode},
};
use anyhow::Context as _;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use futures::stream::{FuturesUnordered, StreamExt};
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

/// Maximum concurrent stale revalidation passes across all buckets.
const MAX_CONCURRENT_REVALIDATIONS: usize = 8;

/// Maximum concurrent pings within a single stale revalidation pass.
const MAX_CONCURRENT_REVALIDATION_PINGS: usize = 4;

/// Duration after which a bucket without activity is considered stale.
const STALE_BUCKET_THRESHOLD: Duration = Duration::from_secs(3600); // 1 hour

/// Minimum self-lookup interval (randomized between min and max).
const SELF_LOOKUP_INTERVAL_MIN: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum self-lookup interval.
const SELF_LOOKUP_INTERVAL_MAX: Duration = Duration::from_secs(600); // 10 minutes

/// Minimum periodic refresh cadence for stale k-buckets (randomized between
/// min and max). Jittering this interval prevents 1000s of nodes that started
/// in lockstep from all firing their bucket-refresh FIND_NODEs in the same
/// second once their distant buckets cross [`STALE_BUCKET_THRESHOLD`].
const BUCKET_REFRESH_INTERVAL_MIN: Duration = Duration::from_secs(450); // 7.5 minutes

/// Maximum periodic refresh cadence for stale k-buckets.
const BUCKET_REFRESH_INTERVAL_MAX: Duration = Duration::from_secs(750); // 12.5 minutes

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
/// per-peer two-address dial cap, this prevents retry storms against
/// stale Unverified/Direct entries published by NATed peers.
const DIAL_FAILURE_CACHE_TTL: Duration = Duration::from_secs(30 * 60);

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
    pub distance: Option<Vec<u8>>,
    pub reliability: f64,
}

impl DHTNode {
    /// Pair each address with its type tag.
    ///
    /// Untagged entries (legacy records that predate ADR-014, or any
    /// position past the end of `address_types`) default to
    /// [`AddressType::Unverified`] — the conservative assumption that
    /// matches `address_type_at` on `NodeInfo`. A legacy publisher never
    /// asserted reachability for these sockets, so we refuse to let them
    /// stand in for a verified `Direct` tag.
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
                let ty = self
                    .address_types
                    .get(i)
                    .copied()
                    .unwrap_or(AddressType::Unverified);
                (addr.clone(), ty)
            })
            .collect()
    }

    /// Addresses sorted by [`AddressType`] priority: Relay first, then
    /// Direct, then NATted.  Within each tier the original insertion
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
    }
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
    /// Default: 0.0 (disabled).
    pub swap_threshold: f64,
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
#[derive(Debug, Default)]
struct DialFailureCache {
    entries: DashMap<SocketAddr, Instant>,
}

impl DialFailureCache {
    fn new() -> Self {
        Self::default()
    }

    /// Returns true if `addr` failed a dial within the last
    /// [`DIAL_FAILURE_CACHE_TTL`]. Expired entries are removed as a
    /// side effect of the lookup so the cache stays bounded without a
    /// dedicated sweeper.
    ///
    /// The `DashMap::entry` API holds a single shard write lock across
    /// the elapsed-check and the `remove`, so a concurrent
    /// [`Self::record_failure`] cannot slip a fresh entry in between
    /// the check and the eviction.
    fn is_failed(&self, addr: &SocketAddr) -> bool {
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

    fn record_failure(&self, addr: SocketAddr) {
        self.entries.insert(addr, Instant::now());
    }

    /// Clear the cached failure for `addr` after a successful dial so
    /// the next retry is not suppressed by a stale entry. Cheap when
    /// the address is absent (typical success path).
    fn clear(&self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }
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
    response_tx: Option<oneshot::Sender<(PeerId, DhtNetworkResult)>>,
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
///   2. **Quorum** — among the top `QUORUM_TOP_N` closest-XOR
///      responders, if `QUORUM_THRESHOLD`+ agree on the address set
///      (same [`report_signature`]), their consensus wins. One close
///      adversary cannot poison the result when 2+ honest neighbours
///      agree.
///   3. **Fallback** — the closest-XOR responder wins. On an XOR tie
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

    // Rule 2: quorum among top-N.
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

    // Rule 3: fallback — closest-XOR (then strongest-tier) responder.
    let (rid, node, _, _) = by_dist.first()?;
    Some((*rid, *node))
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
            shutdown: CancellationToken::new(),
            event_handler_handle: Arc::new(RwLock::new(None)),
            self_lookup_handle: Arc::new(RwLock::new(None)),
            bucket_refresh_handle: Arc::new(RwLock::new(None)),
            last_rebootstrap: tokio::sync::Mutex::new(None),
            dial_failure_cache: Arc::new(DialFailureCache::new()),
            identity_failure_cache: Arc::new(IdentityFailureCache::new()),
            pending_peer_dials: Arc::new(DashMap::new()),
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
    /// [`BUCKET_REFRESH_INTERVAL_MAX`], finds stale buckets (not refreshed
    /// within [`STALE_BUCKET_THRESHOLD`]) and performs a FIND_NODE lookup for
    /// a random key in each stale bucket's range. This populates stale buckets
    /// with fresh peers.
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
                        let stale_indices = this
                            .dht
                            .read()
                            .await
                            .stale_bucket_indices(STALE_BUCKET_THRESHOLD)
                            .await;

                        if stale_indices.is_empty() {
                            trace!("Bucket refresh: no stale buckets");
                            return;
                        }

                        debug!("Bucket refresh: {} stale buckets", stale_indices.len());
                        let k = this.k_value();

                        for bucket_idx in stale_indices {
                            if shutdown_ref.is_cancelled() {
                                break;
                            }
                            let random_key = {
                                let dht = this.dht.read().await;
                                dht.generate_random_key_for_bucket(bucket_idx)
                            };
                            let Some(key) = random_key else {
                                continue;
                            };

                            let key_bytes: Key = *key.as_bytes();
                            match this.find_closest_nodes_network(&key_bytes, k).await {
                                Ok(nodes) => {
                                    trace!(
                                        "Bucket refresh[{bucket_idx}]: discovered {} peers",
                                        nodes.len()
                                    );
                                    for dht_node in nodes {
                                        if dht_node.peer_id == this.config.peer_id {
                                            continue;
                                        }
                                        this.dial_addresses(&dht_node.peer_id, &dht_node.typed_addresses())
                                            .await;
                                    }
                                }
                                Err(e) => {
                                    debug!("Bucket refresh[{bucket_idx}] lookup failed: {e}");
                                }
                            }
                        }

                        this.maybe_rebootstrap().await;
                    } => {}
                }
            }
        });
        *handle_slot.write().await = Some(handle);
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
    /// hammering bootstrap nodes during transient network partitions.
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
            let op = DhtNetworkOperation::FindNode { key };
            match self.send_dht_request(peer_id, op, None).await {
                Ok(DhtNetworkResult::NodesFound { nodes, .. }) => {
                    for node in &nodes {
                        let typed = node.typed_addresses();
                        let dialable_count =
                            typed.iter().filter(|(a, _)| Self::is_dialable(a)).count();
                        debug!(
                            "DHT bootstrap: peer={} num_addresses={} dialable={}",
                            node.peer_id.to_hex(),
                            node.addresses.len(),
                            dialable_count
                        );
                        // Ingest the responder's typed view of this peer so
                        // later relay acquisition / dial paths can see Direct
                        // and Relay tags without having to rely on the peer
                        // landing in our own K-closest PublishAddressSet
                        // fan-out. No-op when the peer isn't already in the
                        // routing table; upgrade-only on existing entries.
                        self.merge_gossiped_typed_addresses(node).await;
                        if seen.insert(node.peer_id) && dialable_count > 0 {
                            to_dial.push((node.peer_id, typed));
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
    /// Only returns peers that passed the `is_dht_participant` security gate
    /// and were added to the Kademlia routing table.
    ///
    /// Results are sorted by XOR distance to the key.
    pub async fn find_closest_nodes_local(&self, key: &Key, count: usize) -> Vec<DHTNode> {
        debug!(
            "[LOCAL] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let dht_guard = self.dht.read().await;
        match dht_guard.find_nodes(&DhtKey::from_bytes(*key), count).await {
            Ok(nodes) => nodes
                .into_iter()
                .filter(|node| !self.is_local_peer_id(&node.id))
                .map(|node| DHTNode {
                    peer_id: node.id,
                    address_types: node.address_types,
                    addresses: node.addresses,
                    distance: None,
                    reliability: SELF_RELIABILITY_SCORE,
                })
                .collect(),
            Err(e) => {
                warn!("find_nodes failed for key {}: {e}", hex::encode(key));
                Vec::new()
            }
        }
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
        const MAX_ITERATIONS: usize = 20;
        const ALPHA: usize = 3; // Parallel queries per iteration

        debug!(
            "[NETWORK] Finding {} closest nodes to key: {}",
            count,
            hex::encode(key)
        );

        let target_key = DhtKey::from_bytes(*key);
        let mut queried_nodes: HashSet<PeerId> = HashSet::new();
        let mut best_nodes: Vec<DHTNode> = Vec::new();

        // Kademlia correctness: the local node must compete on distance in the
        // final K-closest result, but we must never send an RPC to ourselves.
        // Seed best_nodes with self and mark self as "queried" so the iterative
        // loop never tries to contact us.
        best_nodes.push(self.local_dht_node().await);
        self.mark_self_queried(&mut queried_nodes);

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

        // Start with local knowledge
        let initial = self.find_closest_nodes_local(key, count).await;
        for node in initial {
            if !queried_nodes.contains(&node.peer_id) {
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
                if queried_nodes.contains(&node.peer_id) {
                    continue;
                }
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
                    let op = DhtNetworkOperation::FindNode { key: *key };
                    async move {
                        // Pass the same typed candidate list to both
                        // ensure_peer_channel and send_dht_request so
                        // the request path doesn't pay a redundant
                        // routing-table read. Trying every dialable
                        // address — instead of stopping at the first
                        // — protects against stale NAT bindings,
                        // single-IP-family failures, and
                        // recently-relayed peers whose direct address
                        // is no longer reachable.
                        //
                        // Going through ensure_peer_channel (instead
                        // of dial_addresses directly) registers the
                        // in-flight dial in the peer-dial coordinator,
                        // so a concurrent iterative lookup from a
                        // different top-level operation that happens
                        // to batch the same peer joins this dial
                        // rather than racing it.
                        let _ = self.ensure_peer_channel(&peer_id, &typed).await;
                        (
                            peer_id,
                            self.send_dht_request(&peer_id, op, Some(&typed)).await,
                        )
                    }
                })
                .collect();

            let results = Self::collect_iteration_results(query_stream).await;

            for (peer_id, result) in results {
                queried_nodes.insert(peer_id);

                match result {
                    Ok(DhtNetworkResult::NodesFound { mut nodes, .. }) => {
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }

                        // Truncate response to K closest to the lookup key to
                        // limit amplification from a single response and bound
                        // per-iteration memory growth.
                        nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
                        nodes.truncate(self.k_value());
                        for node in nodes {
                            if queried_nodes.contains(&node.peer_id)
                                || self.is_local_peer_id(&node.peer_id)
                            {
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
                            self.merge_gossiped_typed_addresses(&node).await;
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
                    Ok(DhtNetworkResult::PeerRejected) => {
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
                        self.broadcast_routing_events(&rt_events);
                        let _ = self.transport.disconnect_peer(&peer_id).await;
                    }
                    Ok(_) => {
                        // Add successful node to best_nodes
                        if let Some(queried_node) = batch.iter().find(|n| n.peer_id == peer_id) {
                            best_nodes.push(queried_node.clone());
                        }
                    }
                    Err(e) => {
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

        best_nodes.sort_by(|a, b| Self::compare_node_distance(a, b, key));
        best_nodes.dedup_by_key(|n| n.peer_id);
        best_nodes.truncate(count);

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

        Ok(best_nodes)
    }

    /// Compare two nodes by their XOR distance to a target key.
    fn compare_node_distance(a: &DHTNode, b: &DHTNode, key: &Key) -> std::cmp::Ordering {
        let target_key = DhtKey::from_bytes(*key);
        a.peer_id
            .distance(&target_key)
            .cmp(&b.peer_id.distance(&target_key))
    }

    /// Drain an iteration's α queries with a bounded wait after first response.
    ///
    /// Waits for the first query to complete, then grants the remaining
    /// queries up to `ITERATION_GRACE_TIMEOUT_SECS` to finish before giving
    /// up on them and returning whatever has arrived. Any still-pending
    /// futures are dropped (and cancelled) when the stream is returned.
    async fn collect_iteration_results<S>(mut stream: S) -> Vec<(PeerId, Result<DhtNetworkResult>)>
    where
        S: futures::Stream<Item = (PeerId, Result<DhtNetworkResult>)> + Unpin,
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
    /// The published address list is sourced from:
    ///
    /// 1. The transport's externally-observed reflexive address (set by
    ///    OBSERVED_ADDRESS frames received from peers). This is the only
    ///    authoritative source for a NAT'd node — it is the actual post-NAT
    ///    address that remote peers see the connection arrive from.
    /// 2. The transport's runtime-bound `listen_addrs`, but **only when the
    ///    bind address has a specific (non-wildcard) IP**. Wildcard binds
    ///    (`0.0.0.0` / `[::]`) are bind-side concepts meaning "any interface"
    ///    and are not dialable, so we skip them entirely and rely on (1).
    ///
    /// If neither source produces an address, the returned `DHTNode` has an
    /// empty `addresses` vec. This is the right answer at the publish layer:
    /// it tells consumers "I don't know how to be reached yet" rather than
    /// lying with a bind-side wildcard or a guessed LAN IP that won't work
    /// from the public internet. The empty window closes naturally once the
    /// first peer connects to us and OBSERVED_ADDRESS flows.
    async fn local_dht_node(&self) -> DHTNode {
        let mut addresses: Vec<MultiAddr> = Vec::new();

        // 1. Pinned direct external addresses — the post-NAT addresses
        //    peers observed from QUIC OBSERVED_ADDRESS frames during
        //    bootstrap. Empty until at least one peer has observed us.
        //    Uses `direct_external_addresses()` (not `observed_external_addresses()`)
        //    because the relay address is published via the typed-set path
        //    in the relay driver, not here.
        for observed in self.transport.direct_external_addresses() {
            let resolved = MultiAddr::quic(observed);
            if !addresses.contains(&resolved) {
                addresses.push(resolved);
            }
        }

        // 2. Runtime-bound listen addresses with specific IPs only. Wildcards
        //    and zero ports are pre-bind placeholders or all-interface
        //    bindings — neither is dialable.
        for la in self.transport.listen_addrs().await {
            let Some(sa) = la.dialable_socket_addr() else {
                continue;
            };
            if sa.port() == 0 || sa.ip().is_unspecified() {
                continue;
            }
            let resolved = MultiAddr::quic(sa);
            if !addresses.contains(&resolved) {
                addresses.push(resolved);
            }
        }

        DHTNode {
            peer_id: self.config.peer_id,
            addresses,
            address_types: Vec::new(), // Self-addresses are untagged; the classifier decides.
            distance: None,
            reliability: SELF_RELIABILITY_SCORE,
        }
    }

    /// Add the local app-level peer ID to `queried` so that iterative lookups
    /// never send RPCs to the local node.
    fn mark_self_queried(&self, queried: &mut HashSet<PeerId>) {
        queried.insert(self.config.peer_id);
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
    pub(crate) fn first_direct_dialable(node: &DHTNode) -> Option<MultiAddr> {
        for (i, addr) in node.addresses.iter().enumerate() {
            let addr_type = node
                .address_types
                .get(i)
                .copied()
                .unwrap_or(AddressType::Unverified);
            if addr_type != AddressType::Direct {
                continue;
            }
            let Some(sa) = addr.dialable_socket_addr() else {
                continue;
            };
            if sa.ip().is_unspecified() {
                continue;
            }
            return Some(addr.clone());
        }
        None
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

    /// Try dialing at most two addresses from `typed_addresses`, chosen by
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
    /// consume one of the two plan slots — a fully cached plan therefore
    /// returns `None` without trying anything further down the priority
    /// list. This stops a peer that republishes the same broken Direct /
    /// Unverified pair on every DHT query from causing a dial retry
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
        let plan = Self::select_dial_candidates(typed_addresses);
        if plan.is_empty() {
            debug!(
                "dial_addresses: no dialable addresses for {}",
                peer_id.to_hex()
            );
            return None;
        }
        let mut attempted = 0usize;
        let mut skipped_cached = 0usize;
        for (addr, _ty) in &plan {
            attempted += 1;
            let Some(socket_addr) = addr.dialable_socket_addr() else {
                continue;
            };
            if self.dial_failure_cache.is_failed(&socket_addr) {
                skipped_cached += 1;
                trace!(
                    "dial_addresses: skipping recently failed address {} for {}",
                    addr,
                    peer_id.to_hex()
                );
                continue;
            }
            match self.dial_candidate(peer_id, addr).await {
                Some(channel_id) => {
                    self.dial_failure_cache.clear(&socket_addr);
                    return Some(channel_id);
                }
                None => {
                    self.dial_failure_cache.record_failure(socket_addr);
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

    async fn record_peer_failure(&self, peer_id: &PeerId) {
        if let Some(ref engine) = self.trust_engine {
            engine.update_node_stats(
                peer_id,
                crate::adaptive::NodeStatisticsUpdate::FailedResponse,
            );
        }
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
            self.broadcast_routing_events(&rt_events);
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
            self.record_peer_failure(peer_id).await;
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
                self.record_peer_failure(peer_id).await;
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
                        std::mem::discriminant(r)
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
            self.record_peer_failure(peer_id).await;
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
    async fn dial_candidate(&self, peer_id: &PeerId, address: &MultiAddr) -> Option<String> {
        let peer_hex = peer_id.to_hex();

        // Reject unspecified addresses before attempting the connection.
        if address.ip().is_some_and(|ip| ip.is_unspecified()) {
            debug!(
                "dial_candidate: rejecting unspecified address for {}: {}",
                peer_hex, address
            );
            return None;
        }

        let dial_timeout = self
            .transport
            .connection_timeout()
            .min(self.config.request_timeout);
        match tokio::time::timeout(dial_timeout, self.transport.connect_peer(address)).await {
            Ok(Ok(channel_id)) => {
                debug!(
                    "dial_candidate: connected to {} at {} (channel {})",
                    peer_hex, address, channel_id
                );
                Some(channel_id)
            }
            Ok(Err(e)) => {
                debug!(
                    "dial_candidate: failed to connect to {} at {}: {}",
                    peer_hex, address, e
                );
                None
            }
            Err(_) => {
                debug!(
                    "dial_candidate: timeout connecting to {} at {} (>{:?})",
                    peer_hex, address, dial_timeout
                );
                None
            }
        }
    }

    /// Look up connectable addresses for `peer_id` as bare `MultiAddr`s.
    ///
    /// Thin wrapper over [`Self::peer_addresses_for_dial_typed`] for
    /// callers that don't need the per-address type tag (e.g.,
    /// `network.rs::first_dialable_peer_address`). Internally always
    /// goes through the typed path so the Relay-first sort invariant
    /// holds for both consumer styles.
    pub(crate) async fn peer_addresses_for_dial(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        self.peer_addresses_for_dial_typed(peer_id)
            .await
            .into_iter()
            .map(|(addr, _ty)| addr)
            .collect()
    }

    /// Look up connectable typed addresses for `peer_id`.
    ///
    /// Checks the DHT routing table first (source of truth for DHT peer
    /// addresses), then falls back to the transport layer for connected
    /// peers. Returns an empty vec when the peer is unknown or has no
    /// dialable addresses.
    ///
    /// Result is sorted by [`AddressType`] priority — Relay first
    /// (known-good relay endpoint), then Direct, then NATted — so the
    /// dialer tries the fastest path first.
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
        //    routing table. No type info available, so each address is
        //    tagged `Unverified`: a transport-level handshake does not
        //    prove the address is cold-dialable from arbitrary peers.
        //    `Unverified` is still dialable (sorted after Relay/Direct,
        //    before NATted) so these peers remain reachable for regular
        //    DHT ops, but relay-candidate selection (which requires
        //    `Direct`) correctly skips them.
        if let Some(info) = self.transport.peer_info(peer_id).await {
            return info
                .addresses
                .into_iter()
                .filter(Self::is_dialable)
                .map(|a| (a, AddressType::Unverified))
                .collect();
        }

        Vec::new()
    }

    /// Filter and sort typed addresses by [`AddressType::priority`].
    ///
    /// Relay first, Direct second, NATted last. Stable sort within each
    /// tier preserves the input order, so callers that hand in addresses
    /// in a meaningful sub-order (e.g., IPv6 before IPv4) keep that
    /// order within the type tier.
    fn dialable_addresses_typed(
        typed: &[(MultiAddr, AddressType)],
    ) -> Vec<(MultiAddr, AddressType)> {
        let mut candidates: Vec<(MultiAddr, AddressType)> = typed
            .iter()
            .filter(|pair| Self::is_dialable(&pair.0))
            .cloned()
            .collect();

        candidates.sort_by_key(|pair| pair.1.priority());

        candidates
    }

    /// Pick at most two addresses to dial for a single peer, applying the
    /// cold-start policy documented on [`Self::dial_addresses`].
    ///
    /// Rules:
    /// - If a Relay is published, dial the Relay and (when present) one
    ///   Direct address. Relay paths are the reliable fallback, so we do
    ///   not burn a second attempt on an Unverified guess.
    /// - If no Relay is published but a Direct is, dial the Direct and
    ///   (when present) a single Unverified/NATted address as backup.
    /// - If only Unverified/NATted addresses exist, dial one of them and
    ///   stop. A second attempt from the same bucket is rarely more
    ///   likely to succeed and just extends cold-start latency.
    ///
    /// Peers routinely publish several addresses (IPv4+IPv6, plus one or
    /// more observed externals). Dialing all of them costs a full
    /// connect-timeout per failure, which dominates first-contact latency
    /// when the top choice is unreachable. Capping at two keeps the
    /// worst case to a single retry while still covering the expected
    /// relay→direct and direct→unverified handoffs.
    fn select_dial_candidates(typed: &[(MultiAddr, AddressType)]) -> Vec<(MultiAddr, AddressType)> {
        let dialable: Vec<(MultiAddr, AddressType)> = typed
            .iter()
            .filter(|pair| Self::is_dialable(&pair.0))
            .cloned()
            .collect();

        let relay = dialable
            .iter()
            .find(|(_, t)| *t == AddressType::Relay)
            .cloned();
        let direct = dialable
            .iter()
            .find(|(_, t)| *t == AddressType::Direct)
            .cloned();
        let other = dialable
            .iter()
            .filter(|(_, t)| !matches!(*t, AddressType::Relay | AddressType::Direct))
            .min_by_key(|(_, t)| t.priority())
            .cloned();

        match (relay, direct, other) {
            (Some(r), Some(d), _) => vec![r, d],
            (Some(r), None, _) => vec![r],
            (None, Some(d), Some(o)) => vec![d, o],
            (None, Some(d), None) => vec![d],
            (None, None, Some(o)) => vec![o],
            (None, None, None) => Vec::new(),
        }
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
        response_rx: oneshot::Receiver<(PeerId, DhtNetworkResult)>,
        _peer_id: &PeerId,
    ) -> Result<DhtNetworkResult> {
        let response_timeout = self.config.request_timeout;

        // Wait for response with timeout - no polling, no TOCTOU race
        match tokio::time::timeout(response_timeout, response_rx).await {
            Ok(Ok((_source, result))) => Ok(result),
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
                let result = self.handle_dht_request(&message, sender).await?;
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
                self.handle_dht_response(&message, sender).await?;
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
                let dht = self.dht.read().await;
                dht.replace_node_addresses(authenticated_sender, addresses.clone(), *seq)
                    .await;
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
                // Send the transport-authenticated sender identity, not the
                // self-reported message.source which could be spoofed.
                if tx.send((sender_app_id, result)).is_err() {
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
    async fn reconcile_connected_peers(&self) {
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
    async fn handle_peer_connected(&self, node_id: PeerId, user_agent: &str) {
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
            // Transport-observed addresses are `Unverified` by default: a
            // successful handshake with us doesn't prove the peer is
            // cold-dialable by arbitrary third parties. The peer's own
            // `PublishAddressSet` (driven by the reachability classifier)
            // upgrades to `Direct` or `Relay` when authoritative info
            // arrives.
            let address_types = vec![crate::dht::AddressType::Unverified; addresses.len()];
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
                    self.broadcast_routing_events(&rt_events);
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
                    match self
                        .revalidate_and_retry_admission(
                            candidate,
                            candidate_ips,
                            candidate_bucket_idx,
                            stale_peers,
                            &trust_fn,
                        )
                        .await
                    {
                        Ok(rt_events) => {
                            info!(
                                "Added peer {} to DHT routing table after stale revalidation",
                                app_peer_id_hex
                            );
                            self.broadcast_routing_events(&rt_events);
                        }
                        Err(e) => {
                            warn!(
                                "Stale revalidation for peer {} failed: {}",
                                app_peer_id_hex, e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
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
                                                manager_clone.handle_dht_message(&data, &source_peer),
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
    ) -> anyhow::Result<Vec<RoutingTableEvent>> {
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

        let admission_events = dht
            .re_evaluate_admission(candidate, &candidate_ips, trust_fn)
            .await?;
        all_events.extend(admission_events);

        Ok(all_events)
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

        self.broadcast_routing_events(&all_events);
        info!("Evicted {} offline K-closest peer(s)", non_responders.len());
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
    /// The address is classified [`crate::dht::AddressType::Unverified`]:
    /// transport-layer observations prove only reachability from us, not
    /// public dialability. Callers with authoritative type information (e.g.,
    /// a relay allocation or a peer-advertised `PublishAddressSet`) must use
    /// [`Self::touch_node_typed`].
    pub async fn touch_node(&self, peer_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let dht = self.dht.read().await;
        dht.touch_node(peer_id, address).await
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

    /// Ingest a peer's typed address set from a FIND_NODE gossip response
    /// into the local routing table, upgrading tags only.
    ///
    /// For each `(addr, ty)` pair in `node`, if the peer is already in the
    /// routing table, either add the new address or promote the existing
    /// entry — but never demote a higher-priority tag already held (which
    /// typically came from the peer's own `PublishAddressSet` or from our
    /// own classifier). Peers absent from the routing table are left alone;
    /// we don't accept *new* peer identities from untrusted gossip, only
    /// additional information about peers we already know.
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
        let dht = self.dht.read().await;
        for (addr, ty) in node.typed_addresses() {
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
        let nodes = dht_guard.all_nodes().await;
        drop(dht_guard);
        nodes
            .into_iter()
            .map(|node| {
                let reliability = self
                    .trust_engine
                    .as_ref()
                    .map(|engine| engine.score(&node.id))
                    .unwrap_or(DEFAULT_NEUTRAL_TRUST);
                DHTNode {
                    peer_id: node.id,
                    address_types: node.address_types,
                    addresses: node.addresses,
                    distance: None,
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
    /// `seq` is a per-call Unix-nanosecond timestamp from
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
    /// will retry in short order.
    fn next_publish_seq() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
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
/// Governs `wait_for_response` and the upper bound of `dial_candidate`'s
/// dial timeout (`min(connection_timeout, request_timeout)`). Must stay
/// above the relay stage (~10s) so it never truncates the NAT traversal
/// cascade.
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
        Self {
            peer_id: PeerId::from_bytes([0u8; 32]),
            node_config: NodeConfig::default(),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_concurrent_operations: DEFAULT_MAX_CONCURRENT_OPS,
            enable_security: true,
            swap_threshold: 0.0,
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
    // FIND_NODE aggregator selection rule — closest-XOR-responder wins with
    // self-report lock-in and tier tie-break.
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
        DHTNode {
            peer_id: peer_with_leading(subject_byte),
            addresses: vec![addr_str.parse().unwrap()],
            address_types: vec![ty],
            distance: None,
            reliability: 1.0,
        }
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
    fn first_direct_dialable_skips_natted() {
        let node = dht_node(
            1,
            vec![
                ("/ip4/10.0.0.1/udp/9000/quic", AddressType::NATted),
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
            ("/ip4/192.0.2.10/udp/9003/quic", AddressType::NATted),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Relay);
        assert_eq!(picks[1].1, AddressType::Direct);
    }

    #[test]
    fn select_dial_candidates_relay_only_without_direct_is_one() {
        // With a relay but no direct we do NOT fall back to an Unverified
        // guess — relay paths are already the robust fallback, and the
        // caller gets a deterministic single-dial budget.
        let addrs = typed(vec![
            ("/ip4/198.51.100.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
            ("/ip4/192.0.2.10/udp/9003/quic", AddressType::NATted),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Relay);
    }

    #[test]
    fn select_dial_candidates_direct_plus_unverified_when_no_relay() {
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
            ("/ip4/192.0.2.10/udp/9003/quic", AddressType::NATted),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Direct);
        assert_eq!(picks[1].1, AddressType::Unverified);
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
            ("/ip4/192.0.2.10/udp/9003/quic", AddressType::NATted),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::Unverified);
    }

    #[test]
    fn select_dial_candidates_only_natted_is_one() {
        let addrs = typed(vec![("/ip4/192.0.2.10/udp/9003/quic", AddressType::NATted)]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 1);
        assert_eq!(picks[0].1, AddressType::NATted);
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
    fn select_dial_candidates_prefers_unverified_over_natted() {
        // When the "other" slot is contested, Unverified wins because it
        // has a lower AddressType priority index than NATted.
        let addrs = typed(vec![
            ("/ip4/203.0.113.7/udp/9001/quic", AddressType::Direct),
            ("/ip4/192.0.2.10/udp/9003/quic", AddressType::NATted),
            ("/ip4/192.0.2.9/udp/9002/quic", AddressType::Unverified),
        ]);
        let picks = DhtNetworkManager::select_dial_candidates(&addrs);
        assert_eq!(picks.len(), 2);
        assert_eq!(picks[0].1, AddressType::Direct);
        assert_eq!(picks[1].1, AddressType::Unverified);
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dial_failure_cache_records_and_checks() {
        let cache = DialFailureCache::new();
        let addr = sock("203.0.113.7:9001");
        assert!(!cache.is_failed(&addr), "empty cache never reports failed");
        cache.record_failure(addr);
        assert!(
            cache.is_failed(&addr),
            "recorded address must be treated as failed within the TTL"
        );
    }

    #[test]
    fn dial_failure_cache_clear_removes_entry() {
        let cache = DialFailureCache::new();
        let addr = sock("203.0.113.7:9001");
        cache.record_failure(addr);
        cache.clear(&addr);
        assert!(
            !cache.is_failed(&addr),
            "clear() must drop the entry so a subsequent dial is allowed"
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
            !cache.is_failed(&addr),
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
        cache.record_failure(a);
        assert!(cache.is_failed(&a));
        assert!(!cache.is_failed(&b), "different SocketAddr must not hit");
    }

    /// Helper: deterministic [`PeerId`] from a single byte. Mirrors
    /// `make_node` in `core_engine` tests but without addresses since
    /// the identity-failure cache only keys on peer ID.
    fn pid(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
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
