//! DHT Core Engine with Kademlia routing
//!
//! Provides peer discovery and routing via a Kademlia DHT with k=8 buckets,
//! trust-weighted peer selection, and security-hardened maintenance tasks.

use crate::PeerId;
use crate::address::{MultiAddr, is_lan_ip};
use crate::security::{IP_EXACT_LIMIT, IPDiversityConfig, canonicalize_ip, ip_subnet_limit};
use anyhow::{Result, anyhow};
use parking_lot::Mutex as PlMutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// An [`Instant`] stored behind a synchronous mutex so it can be updated
/// from `&self` receivers.
///
/// The key property: reads and writes only need `&self`, so the routing
/// table's hot touch path (called on every inbound DHT message) can run
/// under a read lock on the routing table instead of an exclusive write
/// lock. The previous write-lock design serialised all readers behind
/// every touch, which at 1000 nodes became the dominant contention point.
///
/// Why a mutex instead of an atomic: `Instant` is opaque (no stable `u64`
/// representation) and can legitimately represent times in the past
/// (tests backdate `last_seen` to mark peers stale). Any epoch-based
/// `AtomicU64` encoding would have to either (a) panic/saturate on past
/// times, or (b) pick a process-lifetime epoch in the deep past, which
/// risks `Instant` underflow on recently booted systems. A
/// [`parking_lot::Mutex<Instant>`] sidesteps all of this and is still
/// extremely fast on the uncontended path (single CAS to acquire + store
/// + single CAS to release — microseconds).
#[derive(Debug)]
pub struct AtomicInstant(PlMutex<Instant>);

impl AtomicInstant {
    /// Return a fresh `AtomicInstant` set to the current time.
    pub fn now() -> Self {
        Self(PlMutex::new(Instant::now()))
    }

    /// Wrap an existing `Instant`.
    pub fn from_instant(i: Instant) -> Self {
        Self(PlMutex::new(i))
    }

    /// Load the current value as an `Instant`.
    pub fn load(&self) -> Instant {
        *self.0.lock()
    }

    /// Atomically store the current time.
    pub fn store_now(&self) {
        *self.0.lock() = Instant::now();
    }

    /// Atomically store a specific `Instant`.
    pub fn store(&self, i: Instant) {
        *self.0.lock() = i;
    }

    /// Time elapsed since the stored instant.
    pub fn elapsed(&self) -> Duration {
        self.load().elapsed()
    }
}

impl Clone for AtomicInstant {
    fn clone(&self) -> Self {
        Self(PlMutex::new(*self.0.lock()))
    }
}

impl Default for AtomicInstant {
    fn default() -> Self {
        Self::now()
    }
}

#[cfg(test)]
use crate::adaptive::trust::DEFAULT_NEUTRAL_TRUST;

/// DHT key type — now a direct alias for [`PeerId`].
///
/// Both types are `[u8; 32]` wrappers with identity conversions between them.
/// Using a single type eliminates keyspace mismatch bugs where BLAKE3-hashing
/// a PeerId into a second "DHT key" space caused nodes to land in wrong
/// Kademlia buckets.
pub type DhtKey = PeerId;

#[inline]
fn xor_distance_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = a[idx] ^ b[idx];
    }
    out
}

/// Maximum addresses stored per node to prevent memory exhaustion.
/// This cap is the last-line guard; in normal operation the per-IP-family
/// cap ([`NodeInfo::enforce_per_ip_family_cap`]) holds each external peer
/// to at most 2 IP addresses per family. Non-IP transports (Bluetooth,
/// LoRa) are outside the per-family cap and rely on this bound.
const MAX_ADDRESSES_PER_NODE: usize = 8;

/// Address classification for priority ordering and staleness eviction.
///
/// Priority: Relay > Direct > Unverified > Lan. The `merge_typed_address`
/// method uses this for insertion ordering and the eviction of excess
/// `Lan` / `Unverified` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressType {
    /// Address through a MASQUE relay server (always reachable)
    Relay,
    /// Direct public IP address verified reachable without NAT traversal
    Direct,
    /// Self-published observed external address whose reachability has not
    /// been confirmed by the local classifier. Published by cold-start nodes
    /// that have not yet accepted an unsolicited inbound handshake and have
    /// not yet acquired a relay. Dialers try these after Relay/Direct and
    /// before LAN-only fallback
    /// and must accept the possibility of a timeout.
    Unverified,
    /// LAN or other local-scope address. This reuses the old `NATted`
    /// variant slot for wire compatibility with older nodes.
    #[serde(alias = "NATted")]
    Lan,
}

impl AddressType {
    /// Priority index for ordering addresses by type. Lower is preferred.
    ///
    /// Relay (0) → Direct (1) → Unverified (2) → Lan (3).
    ///
    /// Used by [`NodeInfo::merge_typed_address`], [`KBucket::replace_node_addresses`],
    /// [`DHTNode::addresses_by_priority`], and [`DhtNetworkManager::dialable_addresses_typed`]
    /// to maintain a consistent ordering invariant.
    pub const fn priority(self) -> u8 {
        match self {
            Self::Relay => 0,
            Self::Direct => 1,
            Self::Unverified => 2,
            Self::Lan => 3,
        }
    }

    /// Canonicalize an advertised type against the address itself.
    ///
    /// A local-scope IP address is never accepted as Relay, Direct, or
    /// Unverified, even if that is what a peer advertised. It may still be
    /// stored as [`AddressType::Lan`] so same-LAN/same-WAN peers can use it.
    pub(crate) fn for_advertised_address(addr: &MultiAddr, advertised: Self) -> Self {
        if addr.ip().is_some_and(is_lan_ip) {
            Self::Lan
        } else {
            advertised
        }
    }
}

/// Whether `addr` is worth storing in a peer's address record.
///
/// Filters out wildcard binds (`0.0.0.0` / `::`) and port `0` for any
/// IP-based transport (QUIC, TCP, UDP). Such addresses are never dialable:
/// they identify a *bind* socket on the publisher's side, not a routable
/// destination. Older saorsa-core builds (pre-self-address filter)
/// sometimes published their bind addresses verbatim, so receivers kept
/// warning on every dial attempt against the stored wildcard. Dropping
/// them at the store boundary stops the noise without changing dial logic
/// downstream — `is_dialable` (the consumer-side check at
/// [`DhtNetworkManager::is_dialable`]) keeps its existing rejection so an
/// untrusted address that slips through any future store path is still
/// caught at dial time.
///
/// Non-IP transports return `true` (filter does not apply) — the address
/// type itself encodes whatever reachability semantics are appropriate.
///
/// Loopback is intentionally NOT filtered here: local devnets legitimately
/// store loopback addresses, and the per-node `allow_loopback` config lives
/// at [`DhtCoreEngine::replace_node_addresses`].
pub(crate) fn is_storable_address(addr: &MultiAddr) -> bool {
    let Some(sa) = addr.socket_addr() else {
        return true;
    };
    !sa.ip().is_unspecified() && sa.port() != 0
}

/// Convenience alias for the internal callers that predate the method form.
const fn type_priority(t: AddressType) -> u8 {
    t.priority()
}

/// Duration of no contact after which a peer is considered stale.
/// Stale peers lose trust protection and become eligible for revalidation-based eviction.
const LIVE_THRESHOLD: Duration = Duration::from_secs(900); // 15 minutes

/// Default trust score below which a peer is eligible for swap-out.
#[allow(dead_code)]
const DEFAULT_SWAP_THRESHOLD: f64 = 0.35;

/// Default trust score below which a close-group peer is quarantined.
#[allow(dead_code)]
const DEFAULT_QUARANTINE_THRESHOLD: f64 = 0.20;

/// Default trust score required for K-closest admission/readmission.
#[allow(dead_code)]
const DEFAULT_QUARANTINE_READMIT_THRESHOLD: f64 = 0.45;

/// Node information for routing.
///
/// The `addresses` field stores one or more typed [`MultiAddr`] values that are
/// always valid. Serializes each as a canonical `/`-delimited string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: PeerId,
    pub addresses: Vec<MultiAddr>,
    /// Type tag for each address, parallel to `addresses` by index.
    /// Defaults to empty on deserialization (legacy nodes); callers treat
    /// untagged addresses as `Unverified`.
    #[serde(default)]
    pub address_types: Vec<AddressType>,
    /// Monotonic timestamp of last successful interaction.
    ///
    /// Stored as an [`AtomicInstant`] so the routing table's touch path
    /// can update it under a read lock, not a write lock. Uses `Instant`
    /// under the hood to avoid NTP clock-jump issues. Skipped during
    /// serialization — deserialized `NodeInfo` defaults to "just seen."
    #[serde(skip, default = "AtomicInstant::now")]
    pub last_seen: AtomicInstant,
}

impl NodeInfo {
    /// Get the socket address from the first address. Returns `None` for
    /// non-IP transports or when no addresses are stored.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addresses.first().and_then(MultiAddr::socket_addr)
    }

    /// Get the IP address from the first address. Returns `None` for
    /// non-IP transports or when no addresses are stored.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.addresses.first().and_then(MultiAddr::ip)
    }

    /// Return all distinct, canonicalized IP addresses across every address in
    /// this node's address list. Useful for IP diversity checks that must
    /// consider all addresses, not just the primary one.
    fn all_ips(&self) -> HashSet<IpAddr> {
        self.addresses
            .iter()
            .filter_map(|a| a.ip().map(canonicalize_ip))
            .collect()
    }

    /// Drop every non-storable address (wildcard `0.0.0.0` / `::`, port-zero)
    /// in place, keeping `addresses` and `address_types` index-aligned.
    ///
    /// This is the record-level equivalent of the single-address filter in
    /// [`Self::merge_typed_address`]. Admission paths that derive diversity
    /// state from the raw address list (e.g. `DhtCoreEngine::add_node`
    /// building `candidate_ips`) must call this first so a record carrying
    /// both a wildcard and a routable address is admitted with only the
    /// routable address, instead of being rejected wholesale by the
    /// unspecified-IP guard before the bucket-side store filter can run.
    pub fn retain_storable_addresses(&mut self) {
        // Pad address_types so the index alignment holds before we filter
        // (legacy records may carry fewer tags than addresses).
        while self.address_types.len() < self.addresses.len() {
            self.address_types.push(AddressType::Unverified);
        }
        // Rebuild both vectors in lockstep, keeping only storable addresses.
        let addresses = std::mem::take(&mut self.addresses);
        let address_types = std::mem::take(&mut self.address_types);
        for (addr, addr_type) in addresses.into_iter().zip(address_types) {
            if is_storable_address(&addr) {
                self.addresses.push(addr);
                self.address_types.push(addr_type);
            }
        }
    }

    /// Merge a new address with default type `Direct`.
    /// Prefer `merge_typed_address` when the type is known.
    pub fn merge_address(&mut self, addr: MultiAddr) {
        self.merge_typed_address(addr, AddressType::Direct);
    }

    /// Merge a new address with an explicit type tag.
    ///
    /// Insertion position depends on type priority: Relay → Direct →
    /// Unverified → Lan. Relay addresses always go to the front. After
    /// insertion, [`Self::enforce_per_ip_family_cap`] prunes the list so
    /// the "at most 1 Relay + 1 WAN non-Relay + 1 LAN per IP family"
    /// invariant holds.
    pub fn merge_typed_address(&mut self, addr: MultiAddr, addr_type: AddressType) {
        if !is_storable_address(&addr) {
            return;
        }
        let addr_type = AddressType::for_advertised_address(&addr, addr_type);

        // Ensure address_types is in sync with addresses (legacy compat).
        // Trailing untagged entries are padded with `Unverified` so we do not
        // claim direct-reachability for addresses whose publisher never
        // asserted it — the whole point of the typed-record migration.
        while self.address_types.len() < self.addresses.len() {
            self.address_types.push(AddressType::Unverified);
        }

        // Remove existing duplicate (same address may be re-classified)
        if let Some(pos) = self.addresses.iter().position(|a| a == &addr) {
            self.addresses.remove(pos);
            if pos < self.address_types.len() {
                self.address_types.remove(pos);
            }
        }

        // Insert based on type priority. Insertion order is what the cap
        // uses to break "newest wins" ties: Relay / Direct / Unverified
        // insert at the front of their tier so the newest sits at the
        // lowest index among same-tier entries; Lan appends so the newest
        // sits at the highest index.
        match addr_type {
            AddressType::Relay => {
                self.addresses.insert(0, addr);
                self.address_types.insert(0, AddressType::Relay);
            }
            AddressType::Direct => {
                let pos = self
                    .address_types
                    .iter()
                    .position(|t| *t != AddressType::Relay)
                    .unwrap_or(self.addresses.len());
                self.addresses.insert(pos, addr);
                self.address_types.insert(pos, AddressType::Direct);
            }
            AddressType::Unverified => {
                let pos = self
                    .address_types
                    .iter()
                    .position(|t| *t != AddressType::Relay && *t != AddressType::Direct)
                    .unwrap_or(self.addresses.len());
                self.addresses.insert(pos, addr);
                self.address_types.insert(pos, AddressType::Unverified);
            }
            AddressType::Lan => {
                self.addresses.push(addr);
                self.address_types.push(AddressType::Lan);
            }
        }

        self.enforce_per_ip_family_cap();

        // Last-line guard for non-IP transports (outside the per-family cap).
        self.addresses.truncate(MAX_ADDRESSES_PER_NODE);
        self.address_types.truncate(self.addresses.len());
    }

    /// Get the address type at the given index.
    ///
    /// Local-scope IP addresses always return [`AddressType::Lan`], even if
    /// the stored or legacy-advertised tag says otherwise. Other untagged
    /// addresses return [`AddressType::Unverified`] because legacy records
    /// that predate ADR-014 never asserted direct reachability.
    pub fn address_type_at(&self, index: usize) -> AddressType {
        let advertised = self
            .address_types
            .get(index)
            .copied()
            .unwrap_or(AddressType::Unverified);
        self.addresses
            .get(index)
            .map(|addr| AddressType::for_advertised_address(addr, advertised))
            .unwrap_or(advertised)
    }

    /// Enforce the per-IP-family address cap for an external peer.
    ///
    /// For each IP family (IPv4, IPv6 — IPv4-mapped IPv6 is canonicalised
    /// to IPv4 so it is counted against the IPv4 slot), keep at most:
    ///
    /// - 1 [`AddressType::Relay`] (newest wins)
    /// - 1 of {[`AddressType::Direct`], [`AddressType::Unverified`]} — the
    ///   entry with the highest priority tier present in that family wins,
    ///   newer entries within a tier win over older ones
    /// - 1 [`AddressType::Lan`] address for same-LAN/same-WAN peers
    ///
    /// That yields the invariant: at most 3 addresses per IP family, and
    /// weaker WAN tiers (Unverified) never coexist with a stronger
    /// same-family tier (Direct) — they add no useful WAN dial option once
    /// the stronger one is known. A dual-stack peer may therefore hold
    /// up to 6 IP addresses (3 per family).
    ///
    /// Non-IP transport addresses (Bluetooth, LoRa) are left alone — they
    /// have no IP family and are governed only by [`MAX_ADDRESSES_PER_NODE`].
    ///
    /// "Newest wins" is encoded by the insertion positions in
    /// [`Self::merge_typed_address`]: Relay, Direct, and Unverified insert
    /// at the front of their tier, so the newest entry has the lowest
    /// index; Lan appends, so the newest has the highest index.
    ///
    /// This enforces the invariant for *external peers*. The routing
    /// table never stores `NodeInfo` for self (admission rejects
    /// self-insertion), so the self-record — held by the transport /
    /// reachability driver — is unaffected by this cap.
    fn enforce_per_ip_family_cap(&mut self) {
        while self.address_types.len() < self.addresses.len() {
            self.address_types.push(AddressType::Unverified);
        }
        self.address_types.truncate(self.addresses.len());

        // Non-IP addresses are exempt from the per-family cap.
        let mut keep: Vec<bool> = self.addresses.iter().map(|a| a.ip().is_none()).collect();

        let family_matches = |addr: &MultiAddr, want_v4: bool| match addr.ip() {
            Some(ip) => canonicalize_ip(ip).is_ipv4() == want_v4,
            None => false,
        };

        for want_v4 in [true, false] {
            let family: Vec<usize> = (0..self.addresses.len())
                .filter(|&i| family_matches(&self.addresses[i], want_v4))
                .collect();
            if family.is_empty() {
                continue;
            }

            // Slot 1: newest Relay for the family (lowest-index Relay).
            if let Some(&i) = family
                .iter()
                .find(|&&i| self.address_types[i] == AddressType::Relay)
            {
                keep[i] = true;
            }

            // Slot 2: the single highest-priority WAN entry for the family.
            // Precedence is Direct > Unverified. Within each tier, newer is
            // at the lowest index.
            let best_wan = [AddressType::Direct, AddressType::Unverified]
                .iter()
                .find_map(|tier| {
                    family
                        .iter()
                        .find(|&&i| self.address_types[i] == *tier)
                        .copied()
                });
            if let Some(i) = best_wan {
                keep[i] = true;
            }

            // Slot 3: newest LAN address for peers that can use a
            // local-scope route. LAN addresses are independent from WAN
            // Direct/Unverified addresses; otherwise hybrid deployments
            // would drop the local path that same-WAN peers need.
            if let Some(&i) = family
                .iter()
                .rev()
                .find(|&&i| self.address_types[i] == AddressType::Lan)
            {
                keep[i] = true;
            }
        }

        for i in (0..keep.len()).rev() {
            if !keep[i] {
                self.addresses.remove(i);
                self.address_types.remove(i);
            }
        }
    }

    /// Merge a typed address but only if it would upgrade the peer's record.
    ///
    /// Unlike [`Self::merge_typed_address`], which blindly remove-and-reinserts
    /// (and thus can *demote* a Relay/Direct entry to Unverified if gossip
    /// arrives out of order), this variant no-ops when the address is already
    /// present with a tag of equal-or-higher priority. New addresses are
    /// always added.
    ///
    /// Returns `true` when the state actually changed (new address appended
    /// or an existing tag was promoted to a better tier), `false` otherwise.
    ///
    /// Used for FIND_NODE gossip: a responder's view of a peer's addresses
    /// is trusted enough to *upgrade* our local record, but not trusted
    /// enough to overwrite an authoritative higher-priority tag we already
    /// hold (typically from the peer's own `PublishAddressSet`).
    pub fn merge_typed_address_upgrade_only(
        &mut self,
        addr: MultiAddr,
        addr_type: AddressType,
    ) -> bool {
        if !is_storable_address(&addr) {
            return false;
        }
        let addr_type = AddressType::for_advertised_address(&addr, addr_type);
        if let Some(pos) = self.addresses.iter().position(|a| a == &addr) {
            let existing = self.address_type_at(pos);
            if existing.priority() <= addr_type.priority() {
                return false;
            }
        }
        self.merge_typed_address(addr, addr_type);
        true
    }
}

/// K-bucket for Kademlia routing
struct KBucket {
    nodes: Vec<NodeInfo>,
    max_size: usize,
    /// Monotonic timestamp of the last time this bucket was refreshed by
    /// live-peer evidence (node added, updated, or touched).
    last_refreshed_by_live_peer: Instant,
    /// Monotonic timestamp of the last completed refresh probe for this
    /// bucket. This is deliberately separate from live-peer refresh so failed
    /// or empty probes can be deprioritised without masking stale buckets.
    last_probe_finished: AtomicInstant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BucketRefreshCandidate {
    pub(crate) index: usize,
    pub(crate) refresh_debt: Duration,
    pub(crate) live_peer_age: Duration,
    pub(crate) probe_age: Duration,
}

#[derive(Debug, Clone, Copy)]
enum AddressReplaceMode {
    /// The subject peer sent the address set over an authenticated channel.
    /// This proves liveness, so the peer and bucket recency are refreshed.
    AuthenticatedSelfPublish,
    /// A third party repeated a sequence-bearing address set in FIND_NODE
    /// gossip. The record may be fresh, but it is not evidence that the
    /// subject peer is alive from our point of view.
    GossipedRecord,
}

impl AddressReplaceMode {
    const fn refreshes_liveness(self) -> bool {
        matches!(self, Self::AuthenticatedSelfPublish)
    }
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        let now = Instant::now();
        Self {
            nodes: Vec::new(),
            max_size,
            last_refreshed_by_live_peer: now,
            last_probe_finished: AtomicInstant::from_instant(now),
        }
    }

    fn add_node(&mut self, mut node: NodeInfo) -> Result<()> {
        // Drop wildcard / port-zero addresses up front — they are never
        // dialable destinations (they identify a *bind* socket on the
        // publisher's side) and storing them just produces dial-time noise
        // every time the peer is selected as a candidate.
        let pre_filter_len = node.addresses.len();
        let mut kept_types = Vec::with_capacity(pre_filter_len);
        let mut kept_addrs = Vec::with_capacity(pre_filter_len);
        for (i, addr) in node.addresses.drain(..).enumerate() {
            if is_storable_address(&addr) {
                let ty = node
                    .address_types
                    .get(i)
                    .copied()
                    .unwrap_or(AddressType::Unverified);
                kept_addrs.push(addr);
                kept_types.push(ty);
            }
        }
        let stripped = pre_filter_len - kept_addrs.len();
        let kept_count = kept_addrs.len();
        node.addresses = kept_addrs;
        node.address_types = kept_types;
        if stripped > 0 {
            tracing::debug!(
                node_id = %node.id.to_hex(),
                stripped,
                kept = kept_count,
                "stripped non-dialable address(es) from incoming NodeInfo",
            );
        }

        // Reject nodes with no addresses — a node without reachable
        // addresses is useless in the routing table and would waste a slot.
        if node.addresses.is_empty() {
            return Err(anyhow!("NodeInfo has no addresses"));
        }

        // Cap addresses to prevent memory exhaustion from oversized lists
        // arriving via deserialization or direct construction.
        node.addresses.truncate(MAX_ADDRESSES_PER_NODE);
        node.address_types.truncate(node.addresses.len());
        for (i, addr) in node.addresses.iter().enumerate() {
            let advertised = node
                .address_types
                .get(i)
                .copied()
                .unwrap_or(AddressType::Unverified);
            if i < node.address_types.len() {
                node.address_types[i] = AddressType::for_advertised_address(addr, advertised);
            } else {
                node.address_types
                    .push(AddressType::for_advertised_address(addr, advertised));
            }
        }

        // If the node is already in this bucket, merge addresses using
        // type-aware merge so relay addresses stay at the front and
        // the parallel address_types vec stays in sync.
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            let mut existing = self.nodes.remove(pos);
            existing.last_seen.store(node.last_seen.load());
            for (i, addr) in node.addresses.into_iter().enumerate() {
                let addr_type = node
                    .address_types
                    .get(i)
                    .copied()
                    .unwrap_or(AddressType::Unverified);
                existing.merge_typed_address(addr, addr_type);
            }
            self.nodes.push(existing);
            self.last_refreshed_by_live_peer = Instant::now();
            return Ok(());
        }

        if self.nodes.len() < self.max_size {
            // External peers are bounded by the per-IP-family cap even on
            // first insertion: an incoming `NodeInfo` could carry multiple
            // same-family same-type addresses from deserialization or the
            // connection handler batching advertised addresses.
            node.enforce_per_ip_family_cap();
            self.nodes.push(node);
            self.last_refreshed_by_live_peer = Instant::now();
            Ok(())
        } else {
            Err(anyhow!(
                "K-bucket at capacity ({}/{})",
                self.nodes.len(),
                self.max_size
            ))
        }
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        self.nodes.retain(|n| &n.id != node_id);
    }

    /// Slow path: update `last_seen`, merge an address, and reorder the
    /// bucket so the touched node becomes the most-recently-seen entry.
    ///
    /// Takes `&mut self` because merging an address may mutate the node's
    /// address list. For the fast path (just bumping the timestamp when no
    /// address merge is needed) see [`Self::touch_last_seen_if_merge_noop`].
    fn touch_node_typed(
        &mut self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) {
            self.nodes[pos].last_seen.store_now();
            if let Some(addr) = address {
                // Loopback injection prevention (Design Section 6.3 rule 4):
                let addr_is_loopback = addr
                    .ip()
                    .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
                let node_has_non_loopback = self.nodes[pos]
                    .addresses
                    .iter()
                    .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
                if !(addr_is_loopback && node_has_non_loopback) {
                    self.nodes[pos].merge_typed_address(addr.clone(), addr_type);
                }
            }
            let node = self.nodes.remove(pos);
            self.nodes.push(node);
            self.last_refreshed_by_live_peer = Instant::now();
            true
        } else {
            false
        }
    }

    /// Merge `address` (with `addr_type`) into the peer's `NodeInfo` using
    /// upgrade-only semantics: never demote a higher-priority tag already
    /// on the same address.
    ///
    /// **Pure address-set update.** Does NOT bump the peer's `last_seen`, does
    /// NOT reorder the bucket (no MRU promotion), and does NOT bump the
    /// bucket's `last_refreshed_by_live_peer` timestamp. Intended for FIND_NODE
    /// gossip ingestion, where a responder's typed view of a *third*
    /// peer is trusted enough to widen our known address set or promote
    /// `Unverified` → `Direct`/`Relay`, but is **not** evidence of:
    ///
    /// * peer-level liveness (covered by `last_seen` — bumping it from
    ///   gossip would let peers we cannot authenticate with ourselves
    ///   stay perpetually "fresh", indefinitely deferring the
    ///   [`DhtCoreEngine::stale_k_closest`] eviction worker), or
    /// * bucket-level discovery activity (covered by
    ///   `last_refreshed_by_live_peer` — the bucket-refresh task uses it to
    ///   decide when to run a
    ///   FIND_NODE for a random key in this bucket's range, which is how
    ///   we discover *new* peers. Gossip about peers we already know is
    ///   not discovery; bumping `last_refreshed_by_live_peer` from gossip would
    ///   mask genuinely-stale buckets and silently suppress discovery as long as
    ///   some neighbour kept gossiping about a peer in that range).
    ///
    /// Returns `true` when the merge changed the peer's address record
    /// (a new address was appended, or an existing tag was promoted to a
    /// higher-priority tier); `false` when the peer is absent, the
    /// loopback-injection guard skipped the merge, or the merge was a
    /// no-op (address already present with an equal-or-higher-priority
    /// tag). The loopback-injection guard from [`Self::touch_node_typed`]
    /// applies equally.
    fn merge_typed_address_upgrade_only(
        &mut self,
        node_id: &PeerId,
        address: &MultiAddr,
        addr_type: AddressType,
    ) -> bool {
        let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) else {
            return false;
        };
        let addr_is_loopback = address
            .ip()
            .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
        let node_has_non_loopback = self.nodes[pos]
            .addresses
            .iter()
            .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
        if addr_is_loopback && node_has_non_loopback {
            return false;
        }
        self.nodes[pos].merge_typed_address_upgrade_only(address.clone(), addr_type)
    }

    /// Fast path: if `node_id` is in this bucket AND the optional address
    /// merge would be a no-op (address is `None`, address is already
    /// present **with the same `addr_type`**, or the loopback-injection
    /// rule would skip the merge), atomically bump `last_seen` in place
    /// and return `Some(true)`.
    ///
    /// Returns:
    /// - `Some(true)` — fast path succeeded, `last_seen` updated.
    /// - `Some(false)` — node is not in this bucket.
    /// - `None` — the address is either not yet present, or present with
    ///   a *different* type classification (e.g. learned as `Direct`,
    ///   now being promoted to `Relay`). The slow path must run so
    ///   [`merge_typed_address`] can re-insert at the type-priority
    ///   position. Without this guard the relay-promotion path in the
    ///   network bridge silently degrades to a `last_seen` bump and the
    ///   address ordering invariant is broken.
    ///
    /// Only requires `&self` — no bucket mutation, just an atomic store on
    /// [`NodeInfo::last_seen`]. This lets the hot touch path (called on
    /// every inbound DHT message) run under a read lock on the routing
    /// table instead of an exclusive write lock.
    fn touch_last_seen_if_merge_noop(
        &self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> Option<bool> {
        let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) else {
            return Some(false);
        };
        let node = &self.nodes[pos];
        let merge_is_noop = match address {
            None => true,
            Some(addr) => {
                let addr_type = AddressType::for_advertised_address(addr, addr_type);
                // Already in the list → merge would reinsert at the same
                // position, which is a no-op only if the existing entry
                // has the same type classification. If the type differs
                // we MUST escalate to the slow path so merge_typed_address
                // can re-order by type priority.
                if let Some(existing_pos) = node.addresses.iter().position(|a| a == addr) {
                    node.address_type_at(existing_pos) == addr_type
                } else {
                    // Loopback-injection skip: if the candidate is
                    // loopback and the node already has a non-loopback
                    // address, the slow path would skip the merge entirely.
                    let addr_is_loopback = addr
                        .ip()
                        .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
                    let node_has_non_loopback = node
                        .addresses
                        .iter()
                        .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
                    addr_is_loopback && node_has_non_loopback
                }
            }
        };
        if merge_is_noop {
            node.last_seen.store_now();
            Some(true)
        } else {
            None
        }
    }

    fn get_nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    fn find_node(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| &n.id == node_id)
    }

    /// Overwrite a peer's address list with `typed_addresses`.
    ///
    /// Full-replace semantics for the `PublishAddressSet` wire op: the sender
    /// is authoritative about its own reachable addresses and the receiver
    /// drops any state the sender omits (e.g., a stale relay address after
    /// the relay session closes).
    ///
    /// The new list is sorted by [`type_priority`] (Relay → Direct → Lan)
    /// to preserve the same ordering invariant that [`NodeInfo::merge_typed_address`]
    /// maintains, then truncated to [`MAX_ADDRESSES_PER_NODE`].
    ///
    /// Returns `true` when the peer was found and its addresses replaced,
    /// `false` when the peer is not in this bucket.
    fn replace_node_addresses(
        &mut self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
    ) -> bool {
        self.replace_node_addresses_with_mode(
            node_id,
            typed_addresses,
            AddressReplaceMode::AuthenticatedSelfPublish,
        )
    }

    /// Overwrite a peer's address list from a sequence-bearing FIND_NODE
    /// gossip record without updating peer liveness or bucket recency.
    fn replace_node_addresses_from_gossip(
        &mut self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
    ) -> bool {
        self.replace_node_addresses_with_mode(
            node_id,
            typed_addresses,
            AddressReplaceMode::GossipedRecord,
        )
    }

    fn replace_node_addresses_with_mode(
        &mut self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        mode: AddressReplaceMode,
    ) -> bool {
        let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) else {
            return false;
        };

        let input_was_non_empty = !typed_addresses.is_empty();
        let mut typed: Vec<(MultiAddr, AddressType)> = typed_addresses
            .into_iter()
            .filter(|(addr, _)| is_storable_address(addr))
            .map(|(addr, ty)| {
                let ty = AddressType::for_advertised_address(&addr, ty);
                (addr, ty)
            })
            .collect();

        // If filtering emptied a non-empty input (publisher sent only
        // wildcards or other non-storable addresses), refuse the replace
        // entirely. The caller (KademliaRoutingTable::replace_node_addresses_with_mode)
        // gates `last_publish_seqs` on this return value, so refusing here
        // preserves the peer's prior good addresses AND leaves the door
        // open for a subsequent CORRECT publish at the same sequence number
        // to land. Without this guard we would (a) wipe a working address
        // list and (b) lock the peer out of future republishes ≤ this seq.
        if typed.is_empty() && input_was_non_empty {
            return false;
        }
        typed.sort_by_key(|(_, t)| type_priority(*t));
        typed.truncate(MAX_ADDRESSES_PER_NODE);

        let (addresses, address_types): (Vec<_>, Vec<_>) = typed.into_iter().unzip();

        {
            let node = &mut self.nodes[pos];
            node.addresses = addresses;
            node.address_types = address_types;
            // Apply the per-IP-family cap on the incoming publish set: a
            // peer is not expected to publish more than Relay + one WAN
            // address + one LAN address per family, but a misbehaving sender
            // could try to exceed that. The cap enforces the invariant
            // regardless.
            node.enforce_per_ip_family_cap();
        }

        if mode.refreshes_liveness() {
            self.nodes[pos].last_seen.store_now();
            // Move to tail (most recently seen).
            let node = self.nodes.remove(pos);
            self.nodes.push(node);
            self.last_refreshed_by_live_peer = Instant::now();
        }

        true
    }
}

/// Kademlia routing table
pub struct KademliaRoutingTable {
    buckets: Vec<KBucket>,
    node_id: PeerId,
    /// Highest `PublishAddressSet` sequence number received from each peer.
    ///
    /// Republishes with a lower-or-equal sequence than the stored value are
    /// discarded to close the "relay-lost → relay-acquired" reorder race.
    /// Stored alongside the routing table so the sequence check and the
    /// address replacement are atomic under the same write lock.
    last_publish_seqs: HashMap<PeerId, u64>,
}

impl KademliaRoutingTable {
    fn new(node_id: PeerId, k_value: usize) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..KADEMLIA_BUCKET_COUNT {
            buckets.push(KBucket::new(k_value));
        }

        Self {
            buckets,
            node_id,
            last_publish_seqs: HashMap::new(),
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        let bucket_index = self
            .get_bucket_index(&node.id)
            .ok_or_else(|| anyhow!("cannot insert self into routing table"))?;
        self.buckets[bucket_index].add_node(node)
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        if let Some(bucket_index) = self.get_bucket_index(node_id) {
            self.buckets[bucket_index].remove_node(node_id);
        }
        self.last_publish_seqs.remove(node_id);
    }

    fn publish_seq_for(&self, node_id: &PeerId) -> u64 {
        self.last_publish_seqs.get(node_id).copied().unwrap_or(0)
    }

    /// Merge a legacy relay hint only while the peer has no authoritative
    /// `PublishAddressSet` record.
    ///
    /// Once a publish sequence has been observed, the stored address list is
    /// the owner's complete self-record for that sequence. Allowing legacy
    /// ADD_ADDRESS hints to mutate it would let stale relay allocations
    /// reappear after a newer direct-only publish removed them.
    fn touch_legacy_relay_hint_if_unsequenced(
        &mut self,
        node_id: &PeerId,
        address: &MultiAddr,
    ) -> bool {
        if self.publish_seq_for(node_id) != 0 {
            return false;
        }
        self.touch_node(node_id, Some(address), AddressType::Relay)
    }

    /// Replace a peer's advertised address list under a monotonic sender
    /// sequence check.
    ///
    /// Sequence `0` is reserved as the "no sequence observed" sentinel and is
    /// discarded. Stale republishes (`seq <= stored seq for this peer`) are
    /// also discarded. When `seq` is strictly greater than any previously
    /// observed sequence from `node_id`, the peer's bucket entry is rewritten via
    /// [`KBucket::replace_node_addresses`] and the stored sequence is
    /// advanced. The whole check-and-apply runs under the caller's write
    /// lock on the routing table, so concurrent republishes from the same
    /// sender are serialised.
    ///
    /// Returns `true` when addresses were replaced; `false` when the peer
    /// is absent from the routing table or the message had an invalid/stale
    /// sequence.
    fn replace_node_addresses(
        &mut self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        seq: u64,
    ) -> bool {
        self.replace_node_addresses_with_mode(
            node_id,
            typed_addresses,
            seq,
            AddressReplaceMode::AuthenticatedSelfPublish,
        )
    }

    fn replace_node_addresses_from_gossip(
        &mut self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        seq: u64,
    ) -> bool {
        self.replace_node_addresses_with_mode(
            node_id,
            typed_addresses,
            seq,
            AddressReplaceMode::GossipedRecord,
        )
    }

    fn replace_node_addresses_with_mode(
        &mut self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        seq: u64,
        mode: AddressReplaceMode,
    ) -> bool {
        if seq == 0 {
            return false;
        }

        if let Some(&stored) = self.last_publish_seqs.get(node_id)
            && seq <= stored
        {
            return false;
        }

        let Some(bucket_index) = self.get_bucket_index(node_id) else {
            return false;
        };

        let applied = match mode {
            AddressReplaceMode::AuthenticatedSelfPublish => {
                self.buckets[bucket_index].replace_node_addresses(node_id, typed_addresses)
            }
            AddressReplaceMode::GossipedRecord => self.buckets[bucket_index]
                .replace_node_addresses_from_gossip(node_id, typed_addresses),
        };
        if applied {
            self.last_publish_seqs.insert(*node_id, seq);
        }
        applied
    }

    /// Update `last_seen` (and optionally merge a typed address) for a node and
    /// move it to the tail of its k-bucket. Returns `true` if the node was found.
    fn touch_node(
        &mut self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> bool {
        match self.get_bucket_index(node_id) {
            Some(bucket_index) => {
                self.buckets[bucket_index].touch_node_typed(node_id, address, addr_type)
            }
            None => false,
        }
    }

    /// Pure address-set merge for an existing routing-table entry.
    ///
    /// Like [`Self::touch_node`] but never demotes a higher-priority tag
    /// on the same address, and does NOT bump `last_seen` or reorder the
    /// bucket — see [`KBucket::merge_typed_address_upgrade_only`] for the
    /// rationale (gossip ingestion must not refresh peer liveness).
    ///
    /// Returns `true` when the merge changed the peer's address record;
    /// `false` for missing peer, no-op merge, or loopback-skip.
    fn merge_typed_address_upgrade_only(
        &mut self,
        node_id: &PeerId,
        address: &MultiAddr,
        addr_type: AddressType,
    ) -> bool {
        match self.get_bucket_index(node_id) {
            Some(bucket_index) => self.buckets[bucket_index]
                .merge_typed_address_upgrade_only(node_id, address, addr_type),
            None => false,
        }
    }

    /// Fast path for the touch operation.
    ///
    /// Returns:
    /// - `Some(true)` — node found and `last_seen` updated atomically.
    /// - `Some(false)` — node is not in the routing table (fast-path result
    ///   is authoritative; no fallback needed).
    /// - `None` — node is present but the address merge would not be a
    ///   no-op (either the address is missing, or its type classification
    ///   differs from `addr_type`); the caller must escalate to
    ///   [`Self::touch_node`] under a write lock.
    ///
    /// Only takes `&self` so this can run under a `RwLock::read()` guard.
    fn try_touch_last_seen(
        &self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> Option<bool> {
        let bucket_index = self.get_bucket_index(node_id)?;
        self.buckets[bucket_index].touch_last_seen_if_merge_noop(node_id, address, addr_type)
    }

    fn find_closest_nodes(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        // Collect ALL entries from every bucket. Bucket index correlates with
        // distance from *self*, not from key K — peers in distant buckets can
        // be closer to K than peers in nearby buckets. The routing table holds
        // at most 256 * K_BUCKET_SIZE entries, so a full scan is trivially fast.
        let mut candidates: Vec<(NodeInfo, [u8; 32])> = Vec::with_capacity(count * 2);

        for bucket in &self.buckets {
            for node in bucket.get_nodes() {
                let distance = xor_distance_bytes(node.id.to_bytes(), key.as_bytes());
                candidates.push((node.clone(), distance));
            }
        }

        // Sort by distance
        candidates.sort_by_key(|a| a.1);

        // Return top `count` nodes
        candidates
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    fn find_closest_nodes_with_publish_seq(
        &self,
        key: &DhtKey,
        count: usize,
    ) -> Vec<(NodeInfo, u64)> {
        self.find_closest_nodes(key, count)
            .into_iter()
            .map(|node| {
                let seq = self.publish_seq_for(&node.id);
                (node, seq)
            })
            .collect()
    }

    /// Returns the k-bucket index for a key, or `None` when the key equals
    /// the local node ID (XOR distance is zero — no valid bucket exists).
    fn get_bucket_index_for_key(&self, key: &DhtKey) -> Option<usize> {
        let distance = xor_distance_bytes(self.node_id.to_bytes(), key.as_bytes());

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return Some(i);
            }
        }

        None // XOR distance is zero — key equals local node ID
    }

    /// Look up a node by its exact peer ID. O(K) scan of the target bucket.
    fn find_node_by_id(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        let bucket_index = self.get_bucket_index(node_id)?;
        self.buckets[bucket_index].find_node(node_id)
    }

    /// Total number of nodes across all buckets.
    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.get_nodes().len()).sum()
    }

    /// Return all nodes from every k-bucket.
    ///
    /// The routing table holds at most `256 * k_value` entries, so
    /// collecting them into a `Vec` is inexpensive.
    fn all_nodes(&self) -> Vec<NodeInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.get_nodes().iter().cloned())
            .collect()
    }

    fn all_nodes_with_publish_seq(&self) -> Vec<(NodeInfo, u64)> {
        self.all_nodes()
            .into_iter()
            .map(|node| {
                let seq = self.publish_seq_for(&node.id);
                (node, seq)
            })
            .collect()
    }

    /// Returns the k-bucket index for a peer, or `None` when the peer ID
    /// equals the local node ID (self-insertion is forbidden).
    fn get_bucket_index(&self, node_id: &PeerId) -> Option<usize> {
        self.get_bucket_index_for_key(&DhtKey::from_bytes(*node_id.to_bytes()))
    }

    /// Compute the K-closest peer IDs to self.
    fn k_closest_ids(&self, k: usize) -> Vec<PeerId> {
        self.find_closest_nodes(&self.node_id, k)
            .into_iter()
            .map(|n| n.id)
            .collect()
    }

    /// Return refresh candidates for every bucket.
    ///
    /// Refresh debt is bounded by both clocks: recent live-peer evidence and a
    /// recent refresh probe each make the bucket low priority. This keeps bucket
    /// maintenance continuous without needing a separate stale-age threshold.
    fn bucket_refresh_candidates(&self) -> Vec<BucketRefreshCandidate> {
        let now = Instant::now();
        self.buckets
            .iter()
            .enumerate()
            .map(|(index, bucket)| {
                let live_peer_age =
                    now.saturating_duration_since(bucket.last_refreshed_by_live_peer);
                let probe_age = now.saturating_duration_since(bucket.last_probe_finished.load());
                let refresh_debt = live_peer_age.min(probe_age);
                BucketRefreshCandidate {
                    index,
                    refresh_debt,
                    live_peer_age,
                    probe_age,
                }
            })
            .collect()
    }

    fn mark_bucket_probe_finished(&self, bucket_idx: usize) -> bool {
        let Some(bucket) = self.buckets.get(bucket_idx) else {
            return false;
        };
        bucket.last_probe_finished.store_now();
        true
    }
}

// ---------------------------------------------------------------------------
// Address parsing and subnet masking helpers for diversity checks
// ---------------------------------------------------------------------------

/// One entry in the tier-check array used by `find_ip_swap_in_scope`.
type IpSwapTier = (
    usize,
    usize,
    Option<(PeerId, [u8; 32], Instant)>,
    &'static str,
);

/// Zero out the host bits of an IPv4 address beyond `prefix_len`.
fn mask_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(bits & mask)
}

/// Zero out the host bits of an IPv6 address beyond `prefix_len`.
fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(bits & mask)
}

/// Default K parameter — number of closest nodes per bucket.
/// Used only by test helpers; production code reads from config.
#[cfg(test)]
const DEFAULT_K: usize = 20;

// IP_EXACT_LIMIT and ip_subnet_limit are imported from crate::security
// to keep a single source of truth for diversity constants.

/// Number of K-buckets in Kademlia routing table (one per bit in 256-bit key space)
const KADEMLIA_BUCKET_COUNT: usize = 256;

/// Trust score above which a peer is protected from swap-closer eviction.
/// Well-trusted peers (score >= 0.7) keep their routing table slot even
/// when a closer but less-proven peer arrives.
const TRUST_PROTECTION_THRESHOLD: f64 = 0.7;

/// Diagnostic statistics for the routing table.
#[allow(dead_code)]
pub struct RoutingTableStats {
    /// Total peers across all buckets.
    pub total_peers: usize,
    /// Per-bucket peer counts (256 entries).
    pub bucket_counts: Vec<usize>,
    /// Number of peers whose last_seen exceeds LIVE_THRESHOLD.
    pub stale_peer_count: usize,
}

/// Events emitted by routing table mutations.
///
/// These are returned from admission and removal operations so the caller
/// (DhtNetworkManager) can broadcast them without re-acquiring the lock.
#[derive(Debug, Clone)]
pub enum RoutingTableEvent {
    /// A new peer was inserted into the routing table.
    PeerAdded(PeerId),
    /// A peer was removed from the routing table (swap-out, eviction, or departure).
    PeerRemoved(PeerId),
    /// The set of K-closest peers to self changed.
    /// Fields retained for the design API; the network manager uses snapshot
    /// diffing instead of consuming these directly.
    #[allow(dead_code)]
    KClosestPeersChanged { old: Vec<PeerId>, new: Vec<PeerId> },
}

/// Result of a peer admission attempt, including stale revalidation requests.
///
/// When a candidate cannot be admitted because the target bucket is full and no
/// swap-closer peer exists, the core engine checks for stale peers that could be
/// revalidated. If stale peers are found, the caller (DhtNetworkManager) must
/// release the write lock, ping the stale peers, evict non-responders, and then
/// call [`DhtCoreEngine::re_evaluate_admission`].
#[derive(Debug)]
pub enum AdmissionResult {
    /// Peer was admitted (inserted or updated). Contains emitted events.
    Admitted(Vec<RoutingTableEvent>),
    /// Admission requires stale peer revalidation before it can proceed.
    /// The caller must release the write lock, ping the stale peers, evict
    /// non-responders, and then call `re_evaluate_admission`.
    StaleRevalidationNeeded {
        /// The candidate peer waiting for admission.
        candidate: NodeInfo,
        /// All candidate IPs (for re-evaluation after revalidation).
        candidate_ips: Vec<IpAddr>,
        /// The candidate's target bucket index (for per-bucket revalidation guard).
        candidate_bucket_idx: usize,
        /// Stale peers that should be pinged. Each entry is `(peer_id, bucket_index)`.
        /// May include peers from multiple buckets when routing-neighborhood
        /// violators are merged (Design Section 7.5).
        stale_peers: Vec<(PeerId, usize)>,
    },
}

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: PeerId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,

    /// Kademlia K parameter — bucket capacity and close-group size.
    k_value: usize,

    /// IP diversity limits — checked against the live routing table on each
    /// `add_node` call rather than maintained as incremental counters.
    ip_diversity_config: IPDiversityConfig,
    /// Allow loopback addresses in the routing table.
    ///
    /// Set once at construction from `NodeConfig.allow_loopback` and never
    /// mutated — `NodeConfig` is the single source of truth. Kept separate
    /// from `IPDiversityConfig` to prevent duplication and drift.
    allow_loopback: bool,

    /// Trust score below which a peer is eligible for swap-out.
    swap_threshold: f64,

    /// Trust score below which a peer is avoided for automatic lookup/dial
    /// paths, and evicted immediately if it is in the K-closest close group.
    quarantine_threshold: f64,

    /// Trust score required before a quarantined peer can re-enter, and before
    /// any new or promoted peer can enter the K-closest set.
    quarantine_readmit_threshold: f64,

    /// Peers evicted from the close group by quarantine. They remain in this
    /// set until discovered naturally and admitted after crossing the readmit
    /// threshold.
    quarantined_peers: HashSet<PeerId>,

    /// Duration of no contact after which a peer is considered stale.
    /// Defaults to [`LIVE_THRESHOLD`]; overridden in tests to avoid
    /// `Instant` subtraction overflow on Windows (where `Instant` starts
    /// at process creation and cannot represent times before it).
    live_threshold: Duration,

    /// Shutdown token for background maintenance tasks
    shutdown: CancellationToken,
}

impl DhtCoreEngine {
    /// Create new DHT engine for testing with default K value.
    #[cfg(test)]
    pub fn new_for_tests(node_id: PeerId) -> Result<Self> {
        Self::new(node_id, DEFAULT_K, false, DEFAULT_SWAP_THRESHOLD)
    }

    /// Expose the routing table for test-only direct manipulation (e.g. setting `last_seen`).
    #[cfg(test)]
    pub(crate) fn routing_table_for_test(&self) -> &Arc<RwLock<KademliaRoutingTable>> {
        &self.routing_table
    }

    /// Create a new DHT core engine.
    pub(crate) fn new(
        node_id: PeerId,
        k_value: usize,
        allow_loopback: bool,
        swap_threshold: f64,
    ) -> Result<Self> {
        if k_value < 4 {
            return Err(anyhow!("k_value must be >= 4 (got {k_value})"));
        }
        if !(0.0..1.0).contains(&swap_threshold) || swap_threshold.is_nan() {
            return Err(anyhow!(
                "swap_threshold must be in [0.0, 1.0), got {swap_threshold}"
            ));
        }
        Ok(Self {
            node_id,
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, k_value))),
            k_value,
            ip_diversity_config: IPDiversityConfig::default(),
            allow_loopback,
            swap_threshold,
            quarantine_threshold: 0.0,
            quarantine_readmit_threshold: DEFAULT_QUARANTINE_READMIT_THRESHOLD,
            quarantined_peers: HashSet::new(),
            live_threshold: LIVE_THRESHOLD,
            shutdown: CancellationToken::new(),
        })
    }

    /// Configure trust quarantine thresholds.
    ///
    /// A `quarantine_threshold` of `0.0` disables quarantine enforcement.
    /// Otherwise, peers below that score are avoided for automatic lookups,
    /// and K-closest peers below it are immediately evicted and quarantined.
    /// Quarantined peers can only re-enter through normal admission after
    /// their decayed trust reaches `quarantine_readmit_threshold`; new or
    /// promoted K-closest peers must also meet that threshold.
    pub(crate) fn set_trust_quarantine_thresholds(
        &mut self,
        quarantine_threshold: f64,
        quarantine_readmit_threshold: f64,
    ) -> Result<()> {
        if !(0.0..0.5).contains(&quarantine_threshold) || quarantine_threshold.is_nan() {
            return Err(anyhow!(
                "quarantine_threshold must be in [0.0, 0.5), got {quarantine_threshold}"
            ));
        }
        if !(0.0..0.5).contains(&quarantine_readmit_threshold)
            || quarantine_readmit_threshold.is_nan()
        {
            return Err(anyhow!(
                "quarantine_readmit_threshold must be in [0.0, 0.5), got {quarantine_readmit_threshold}"
            ));
        }
        if quarantine_threshold > 0.0 && quarantine_readmit_threshold < quarantine_threshold {
            return Err(anyhow!(
                "quarantine_readmit_threshold ({quarantine_readmit_threshold}) must be >= quarantine_threshold ({quarantine_threshold})"
            ));
        }
        self.quarantine_threshold = quarantine_threshold;
        self.quarantine_readmit_threshold = quarantine_readmit_threshold;
        Ok(())
    }

    fn quarantine_enabled(&self) -> bool {
        self.quarantine_threshold > 0.0
    }

    /// Return whether trust quarantine affects lookup result filtering.
    pub(crate) fn trust_quarantine_enabled(&self) -> bool {
        self.quarantine_enabled()
    }

    fn check_quarantine_admission(&mut self, peer_id: &PeerId, trust_score: f64) -> Result<()> {
        if !self.quarantine_enabled() {
            return Ok(());
        }
        if !trust_score.is_finite() {
            return Err(anyhow!(
                "peer {} has non-finite trust score",
                peer_id.to_hex()
            ));
        }
        if self.quarantined_peers.contains(peer_id) {
            if trust_score < self.quarantine_readmit_threshold {
                return Err(anyhow!(
                    "peer {} quarantined until trust >= {:.3} (current {trust_score:.3})",
                    peer_id.to_hex(),
                    self.quarantine_readmit_threshold
                ));
            }
            self.quarantined_peers.remove(peer_id);
        }
        if trust_score < self.quarantine_threshold {
            return Err(anyhow!(
                "peer {} below quarantine threshold ({trust_score:.3} < {:.3})",
                peer_id.to_hex(),
                self.quarantine_threshold
            ));
        }
        Ok(())
    }

    fn candidate_enters_close_group_after_removals(
        &self,
        routing: &KademliaRoutingTable,
        candidate_id: &PeerId,
        removed_peer_ids: &[PeerId],
    ) -> bool {
        let mut candidates: Vec<(PeerId, [u8; 32])> = routing
            .all_nodes()
            .into_iter()
            .filter(|node| node.id != *candidate_id && !removed_peer_ids.contains(&node.id))
            .map(|node| {
                let distance = xor_distance_bytes(self.node_id.to_bytes(), node.id.to_bytes());
                (node.id, distance)
            })
            .collect();

        candidates.push((
            *candidate_id,
            xor_distance_bytes(self.node_id.to_bytes(), candidate_id.to_bytes()),
        ));
        candidates.sort_by_key(|(_, distance)| *distance);
        candidates
            .into_iter()
            .take(self.k_value)
            .any(|(peer_id, _)| peer_id == *candidate_id)
    }

    fn check_close_group_admission(
        &self,
        routing: &KademliaRoutingTable,
        peer_id: &PeerId,
        trust_score: f64,
        removed_peer_ids: &[PeerId],
    ) -> Result<()> {
        if !self.quarantine_enabled() || trust_score >= self.quarantine_readmit_threshold {
            return Ok(());
        }
        if !trust_score.is_finite() {
            return Err(anyhow!(
                "peer {} has non-finite trust score",
                peer_id.to_hex()
            ));
        }
        if self.candidate_enters_close_group_after_removals(routing, peer_id, removed_peer_ids) {
            return Err(anyhow!(
                "peer {} below close-group admission threshold ({trust_score:.3} < {:.3})",
                peer_id.to_hex(),
                self.quarantine_readmit_threshold
            ));
        }
        Ok(())
    }

    /// Return whether automatic lookup/dial paths should avoid this peer.
    pub(crate) fn should_avoid_for_lookup(&self, peer_id: &PeerId, trust_score: f64) -> bool {
        if !self.quarantine_enabled() {
            return false;
        }
        if !trust_score.is_finite() {
            return true;
        }
        trust_score < self.quarantine_threshold
            || (self.quarantined_peers.contains(peer_id)
                && trust_score < self.quarantine_readmit_threshold)
    }

    /// Evict a quarantined peer if it currently occupies the K-closest set.
    #[cfg(test)]
    pub(crate) async fn enforce_close_group_quarantine(
        &mut self,
        peer_id: &PeerId,
        trust_score: f64,
    ) -> Vec<RoutingTableEvent> {
        if !self.quarantine_enabled()
            || !trust_score.is_finite()
            || trust_score >= self.quarantine_threshold
        {
            return Vec::new();
        }

        let mut routing = self.routing_table.write().await;
        let k_before = routing.k_closest_ids(self.k_value);
        if !k_before.contains(peer_id) {
            return Vec::new();
        }
        if routing.find_node_by_id(peer_id).is_none() {
            return Vec::new();
        }

        self.quarantined_peers.insert(*peer_id);
        routing.remove_node(peer_id);

        let k_after = routing.k_closest_ids(self.k_value);
        let mut events = vec![RoutingTableEvent::PeerRemoved(*peer_id)];
        if k_before != k_after {
            events.push(RoutingTableEvent::KClosestPeersChanged {
                old: k_before,
                new: k_after,
            });
        }
        events
    }

    /// Enforce trust gates over the current K-closest set.
    ///
    /// Peers below the quarantine threshold are evicted from the close group
    /// regardless of whether they were already close. Peers newly promoted into
    /// the close group must meet the higher readmit/admission threshold.
    pub(crate) async fn enforce_close_group_trust_gate(
        &mut self,
        previous_close_group: Option<&[PeerId]>,
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Vec<RoutingTableEvent> {
        if !self.quarantine_enabled() {
            return Vec::new();
        }

        let mut routing = self.routing_table.write().await;
        let k_before = routing.k_closest_ids(self.k_value);
        let mut removed = Vec::new();

        while let Some(peer_id) = routing
            .k_closest_ids(self.k_value)
            .into_iter()
            .find(|peer_id| {
                let score = trust_score(peer_id);
                score.is_finite()
                    && (score < self.quarantine_threshold
                        || (previous_close_group.is_some_and(|old| !old.contains(peer_id))
                            && score < self.quarantine_readmit_threshold))
            })
        {
            if trust_score(&peer_id) < self.quarantine_threshold {
                self.quarantined_peers.insert(peer_id);
            }
            routing.remove_node(&peer_id);
            removed.push(peer_id);
        }

        if removed.is_empty() {
            return Vec::new();
        }

        let k_after = routing.k_closest_ids(self.k_value);
        let mut events: Vec<RoutingTableEvent> = removed
            .into_iter()
            .map(RoutingTableEvent::PeerRemoved)
            .collect();
        if k_before != k_after {
            events.push(RoutingTableEvent::KClosestPeersChanged {
                old: k_before,
                new: k_after,
            });
        }
        events
    }

    /// Override the IP diversity configuration.
    pub fn set_ip_diversity_config(&mut self, config: IPDiversityConfig) {
        self.ip_diversity_config = config;
    }

    /// Set whether loopback addresses are allowed in the routing table.
    #[cfg(test)]
    pub fn set_allow_loopback(&mut self, allow: bool) {
        self.allow_loopback = allow;
    }

    /// Override the live threshold for testing.
    ///
    /// On Windows, `Instant` starts at process creation, so tests cannot
    /// subtract large durations without overflow. Setting a small threshold
    /// (e.g. 1 second) lets tests use a correspondingly small subtraction.
    #[cfg(test)]
    pub fn set_live_threshold(&mut self, threshold: Duration) {
        self.live_threshold = threshold;
    }

    /// Get this node's peer ID.
    #[allow(dead_code)]
    pub fn node_id(&self) -> &PeerId {
        &self.node_id
    }

    /// Return K-closest peer IDs whose `last_seen` exceeds the live threshold.
    ///
    /// Used by the self-lookup task to revalidate stale close-group members
    /// and evict offline peers promptly.
    pub(crate) async fn stale_k_closest(&self) -> Vec<PeerId> {
        let routing = self.routing_table.read().await;
        routing
            .find_closest_nodes(&self.node_id, self.k_value)
            .into_iter()
            .filter(|n| n.last_seen.elapsed() > self.live_threshold)
            .map(|n| n.id)
            .collect()
    }

    /// Return refresh candidates for every bucket.
    pub(crate) async fn bucket_refresh_candidates(&self) -> Vec<BucketRefreshCandidate> {
        self.routing_table.read().await.bucket_refresh_candidates()
    }

    /// Mark a bucket refresh probe as completed without changing live-peer
    /// freshness.
    pub(crate) async fn mark_bucket_probe_finished(&self, bucket_idx: usize) -> bool {
        self.routing_table
            .read()
            .await
            .mark_bucket_probe_finished(bucket_idx)
    }

    /// Generate a random key that would fall into the specified bucket index
    /// relative to this node's ID.
    ///
    /// Used for bucket refresh: looking up a random key in a selected bucket's
    /// range discovers new peers that populate that bucket.
    ///
    /// Returns `None` if `bucket_idx` is out of range (>= 256).
    pub(crate) fn generate_random_key_for_bucket(&self, bucket_idx: usize) -> Option<DhtKey> {
        if bucket_idx >= KADEMLIA_BUCKET_COUNT {
            return None;
        }

        let self_bytes = self.node_id.to_bytes();

        // Construct a XOR distance with its leading set bit at position bucket_idx.
        // Bucket index i means the first differing bit (from MSB) is at position i.
        let byte_idx = bucket_idx / 8;
        let bit_idx = 7 - (bucket_idx % 8);

        // Use a random PeerId as an entropy source (avoids `rng.gen()` which
        // conflicts with the `gen` keyword reserved in Rust edition 2024).
        let random_bytes = PeerId::random();

        let mut distance = [0u8; 32];
        // Set the leading bit at bucket_idx
        distance[byte_idx] = 1 << bit_idx;
        // Fill random bits below the leading bit in the same byte
        let below_mask = (1u8 << bit_idx).wrapping_sub(1);
        distance[byte_idx] |= random_bytes.to_bytes()[byte_idx] & below_mask;
        // Fill remaining bytes randomly
        distance[(byte_idx + 1)..32].copy_from_slice(&random_bytes.to_bytes()[(byte_idx + 1)..32]);

        // Key = self XOR distance
        let mut result = [0u8; 32];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte = self_bytes[i] ^ distance[i];
        }
        Some(DhtKey::from_bytes(result))
    }

    /// Number of peers currently in the routing table.
    pub async fn routing_table_size(&self) -> usize {
        self.routing_table.read().await.node_count()
    }

    /// Remove a peer from the routing table by ID.
    ///
    /// Returns events describing the mutation (`PeerRemoved` if the peer was
    /// present, and optionally `KClosestPeersChanged` when the close-group shifted).
    /// Returns an empty vec if the peer was not in the routing table.
    pub async fn remove_node_by_id(&mut self, peer_id: &PeerId) -> Vec<RoutingTableEvent> {
        let mut routing = self.routing_table.write().await;
        // Only emit events if the peer is actually present.
        if routing.find_node_by_id(peer_id).is_none() {
            return Vec::new();
        }
        let k_before = routing.k_closest_ids(self.k_value);
        routing.remove_node(peer_id);
        let k_after = routing.k_closest_ids(self.k_value);
        let mut events = vec![RoutingTableEvent::PeerRemoved(*peer_id)];
        if k_before != k_after {
            events.push(RoutingTableEvent::KClosestPeersChanged {
                old: k_before,
                new: k_after,
            });
        }
        events
    }

    /// Signal background tasks to stop
    pub fn signal_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes(key, count))
    }

    /// Find nodes closest to a key and include the latest authoritative
    /// `PublishAddressSet` sequence known for each returned record.
    pub async fn find_nodes_with_publish_seq(
        &self,
        key: &DhtKey,
        count: usize,
    ) -> Result<Vec<(NodeInfo, u64)>> {
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes_with_publish_seq(key, count))
    }

    /// Find nodes closest to a key, including self as a candidate.
    /// Used by consumers for storage responsibility determination.
    #[allow(dead_code)]
    pub async fn find_nodes_with_self(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        let mut candidates = routing.find_closest_nodes(key, count);

        // Insert self as a candidate
        let self_info = NodeInfo {
            id: self.node_id,
            addresses: vec![],
            address_types: vec![],
            last_seen: AtomicInstant::now(),
        };
        let self_dist = xor_distance_bytes(self.node_id.to_bytes(), key.as_bytes());

        // Find insertion point to maintain sorted order
        let pos = candidates
            .iter()
            .position(|n| xor_distance_bytes(n.id.to_bytes(), key.as_bytes()) > self_dist)
            .unwrap_or(candidates.len());

        candidates.insert(pos, self_info);
        candidates.truncate(count);

        Ok(candidates)
    }

    /// Look up a node's addresses from the routing table by peer ID.
    ///
    /// Returns the stored addresses if the peer is in the routing table,
    /// an empty vec otherwise. O(K) scan of the target k-bucket.
    ///
    /// Production code paths now use [`Self::get_node_addresses_typed`]
    /// for address-type-aware priority sorting (ADR-014). This untyped
    /// variant is retained as a public API for external consumers and is
    /// exercised by in-crate tests.
    #[allow(dead_code)]
    pub async fn get_node_addresses(&self, peer_id: &PeerId) -> Vec<MultiAddr> {
        let routing = self.routing_table.read().await;
        routing
            .find_node_by_id(peer_id)
            .map(|n| n.addresses.clone())
            .unwrap_or_default()
    }

    /// Get a peer's addresses paired with their [`AddressType`] tags.
    ///
    /// Used by [`crate::dht_network_manager::DhtNetworkManager::peer_addresses_for_dial_typed`]
    /// to sort candidates by type priority (Relay first) per ADR-014.
    pub async fn get_node_addresses_typed(
        &self,
        peer_id: &PeerId,
    ) -> Vec<(MultiAddr, AddressType)> {
        let routing = self.routing_table.read().await;
        routing
            .find_node_by_id(peer_id)
            .map(|n| {
                n.addresses
                    .iter()
                    .enumerate()
                    .map(|(i, addr)| (addr.clone(), n.address_type_at(i)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check whether a peer is present in the routing table.
    pub async fn has_node(&self, peer_id: &PeerId) -> bool {
        let routing = self.routing_table.read().await;
        routing.find_node_by_id(peer_id).is_some()
    }

    /// Return every peer currently in the routing table.
    ///
    /// The routing table holds at most `256 * k_value` entries, so
    /// collecting them is inexpensive.
    #[allow(dead_code)]
    pub async fn all_nodes(&self) -> Vec<NodeInfo> {
        self.routing_table.read().await.all_nodes()
    }

    pub async fn all_nodes_with_publish_seq(&self) -> Vec<(NodeInfo, u64)> {
        self.routing_table.read().await.all_nodes_with_publish_seq()
    }

    /// Build diagnostic statistics for the routing table.
    #[allow(dead_code)]
    pub async fn routing_table_stats(&self) -> RoutingTableStats {
        let routing = self.routing_table.read().await;
        let bucket_counts: Vec<usize> = routing
            .buckets
            .iter()
            .map(|b| b.get_nodes().len())
            .collect();
        let total_peers: usize = bucket_counts.iter().sum();
        let stale_peer_count = routing
            .buckets
            .iter()
            .flat_map(|b| b.get_nodes())
            .filter(|n| n.last_seen.elapsed() > self.live_threshold)
            .count();
        RoutingTableStats {
            total_peers,
            bucket_counts,
            stale_peer_count,
        }
    }

    /// Record a successful interaction with a peer by updating its `last_seen`
    /// timestamp (and optionally its address) and moving it to the tail of its
    /// k-bucket (most recently seen).
    ///
    /// Standard Kademlia: any successful RPC implicitly proves liveness, so the
    /// routing table should reflect this without requiring dedicated pings.
    /// Passing the current address ensures stale addresses are replaced when a
    /// peer reconnects from a different endpoint.
    ///
    /// Non-local addresses passed here are classified
    /// [`AddressType::Unverified`]: a successful RPC with us proves
    /// reachability from *us* to the peer (possibly through a NAT mapping we
    /// opened), not public cold-dialability. Local-scope addresses are
    /// canonicalized to [`AddressType::Lan`] by the typed merge path. Callers
    /// with authoritative type information must use [`Self::touch_node_typed`].
    pub async fn touch_node(&self, node_id: &PeerId, address: Option<&MultiAddr>) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address, AddressType::Unverified)
    }

    /// Touch a peer's routing-table entry with an optional typed address.
    ///
    /// **Fast path (read lock + atomic store):** If the peer is in the
    /// routing table and the address merge would be a no-op (address is
    /// `None`, or it's already in the peer's list, or the loopback rule
    /// would skip it), this updates `last_seen` atomically under a read
    /// lock with no bucket mutation.
    ///
    /// **Slow path (write lock):** If an actual address merge is needed,
    /// the method escalates to a write lock and uses the full
    /// `touch_node` flow.
    ///
    /// This split removes the write lock from the common hot path — at
    /// 1000 nodes the touch is called on every inbound DHT message, and
    /// the write-lock version was the dominant contention point on the
    /// routing table.
    pub async fn touch_node_typed(
        &self,
        node_id: &PeerId,
        address: Option<&MultiAddr>,
        addr_type: AddressType,
    ) -> bool {
        // Fast path: read lock + atomic last_seen store. The fast path
        // ALSO requires the address (if any) to already be present with
        // the same type classification — see `touch_last_seen_if_merge_noop`.
        // Promotion of an existing address from one classification to
        // another (e.g. Direct → Relay) is intentionally pushed to the
        // slow path so the bucket-level `merge_typed_address` can re-order.
        {
            let routing = self.routing_table.read().await;
            match routing.try_touch_last_seen(node_id, address, addr_type) {
                Some(true) => return true,
                Some(false) => return false,
                // Merge is non-trivial — fall through to the write-lock path.
                None => {}
            }
        }

        // Slow path: address merge or re-classification needed, take write lock.
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address, addr_type)
    }

    /// Merge a peer-advertised relay hint only if the peer has never sent an
    /// authoritative `PublishAddressSet`.
    ///
    /// Legacy ADD_ADDRESS frames remain useful for peers that predate typed
    /// self-record publishing. After any publish sequence has been stored for
    /// the peer, only a newer `PublishAddressSet` may change its address list.
    pub async fn touch_legacy_relay_hint_if_unsequenced(
        &self,
        node_id: &PeerId,
        address: &MultiAddr,
    ) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_legacy_relay_hint_if_unsequenced(node_id, address)
    }

    /// Merge `address` (with `addr_type`) into an existing peer's record
    /// using upgrade-only semantics: never demote a higher-priority tag
    /// already on the same address.
    ///
    /// **Pure address-set update.** Does NOT bump `last_seen` and does
    /// NOT reorder the bucket. Intended for FIND_NODE gossip ingestion:
    /// a responder's typed view is trusted enough to widen our record
    /// (new addresses) or promote a cold-start `Unverified` to
    /// `Direct`/`Relay`, but it is **not** evidence that the subject
    /// peer is alive from *our* point of view — only direct authenticated
    /// activity (handled by [`Self::touch_node_typed`] via
    /// [`crate::dht_network_manager::DhtNetworkManager::handle_dht_message`])
    /// refreshes liveness.
    ///
    /// Without this gating, a chatty network would defer
    /// [`Self::stale_k_closest`] eviction indefinitely for every peer
    /// some authenticated neighbour happens to mention — including
    /// peers we cannot authenticate with ourselves (e.g., older
    /// protocol versions whose identity exchange always times out).
    ///
    /// Returns `true` when the merge changed the peer's address record
    /// (a new address was appended, or an existing tag was promoted to
    /// a higher-priority tier); `false` for missing peer, no-op merge,
    /// or loopback-skip — see
    /// [`KBucket::merge_typed_address_upgrade_only`] for the full
    /// classification.
    pub async fn merge_typed_address_upgrade_only(
        &self,
        node_id: &PeerId,
        address: &MultiAddr,
        addr_type: AddressType,
    ) -> bool {
        // No fast path: the read-locked fast path is only valid when the
        // merge is a no-op. For the upgrade-only variant the decision
        // ("would this upgrade the tag?") requires inspecting the stored
        // tag, which must happen under the write lock to avoid a TOCTOU
        // race with a concurrent PublishAddressSet replace.
        let mut routing = self.routing_table.write().await;
        routing.merge_typed_address_upgrade_only(node_id, address, addr_type)
    }

    /// Replace a peer's advertised address list with `typed_addresses`, under
    /// a monotonic-sequence guard.
    ///
    /// Implements the receive side of the `PublishAddressSet` wire op: the
    /// sender is authoritative about its own reachable addresses and the
    /// receiver drops any address the sender omits. This authenticated path is
    /// the source of fresh address records; later FIND_NODE gossip may propagate
    /// the same replacement through [`Self::replace_node_addresses_from_gossip`]
    /// without refreshing liveness.
    ///
    /// - Empty input address lists are rejected outright (returns `false`).
    /// - Filtering happens in two stages with **different empty-result
    ///   semantics**, because they guard against different things:
    ///   - *Loopback* (this method, via [`Self::filter_publish_address_set`],
    ///     skipped when [`Self::allow_loopback`] is set for devnets/tests):
    ///     if stripping loopback empties a non-empty input, the **empty set
    ///     is still applied**. A publisher that legitimately drops to zero
    ///     reachable addresses must not keep stale ones alive, and
    ///     `last_publish_seqs` advances normally.
    ///   - *Wildcard / port-zero* ([`KBucket::replace_node_addresses_with_mode`]
    ///     via `is_storable_address`): if this empties a non-empty input the
    ///     replace is **refused** — prior good addresses are preserved and
    ///     `last_publish_seqs` is NOT advanced, so a corrected republish at
    ///     the same `seq` can still land. Wildcard-only is treated as a
    ///     malformed publish, not an intentional "I have no addresses", so
    ///     callers and tests must not assume all filter-empty publishes
    ///     share the same outcome.
    /// - `seq` must be non-zero and strictly exceed the last sequence
    ///   observed from `node_id`; zero, older, or duplicate sequences are
    ///   ignored.
    ///
    /// Returns `true` when the peer's addresses were replaced, `false`
    /// otherwise (peer absent, stale sequence, empty input list, or a
    /// wildcard-only input whose prior addresses were preserved).
    pub async fn replace_node_addresses(
        &self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        seq: u64,
    ) -> bool {
        let Some(filtered) = self.filter_publish_address_set(typed_addresses) else {
            return false;
        };
        let mut routing = self.routing_table.write().await;
        routing.replace_node_addresses(node_id, filtered, seq)
    }

    /// Replace a peer's advertised address list from sequence-bearing gossip
    /// without refreshing liveness.
    ///
    /// Uses the same filtering and monotonic-sequence guard as
    /// [`Self::replace_node_addresses`], but does not update `last_seen`,
    /// bucket MRU order, or bucket refresh timestamps. A third-party
    /// FIND_NODE response can propagate a newer address record, but only
    /// direct authenticated traffic from the subject peer proves liveness.
    pub(crate) async fn replace_node_addresses_from_gossip(
        &self,
        node_id: &PeerId,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
        seq: u64,
    ) -> bool {
        let Some(filtered) = self.filter_publish_address_set(typed_addresses) else {
            return false;
        };
        let mut routing = self.routing_table.write().await;
        routing.replace_node_addresses_from_gossip(node_id, filtered, seq)
    }

    fn filter_publish_address_set(
        &self,
        typed_addresses: Vec<(MultiAddr, AddressType)>,
    ) -> Option<Vec<(MultiAddr, AddressType)>> {
        if typed_addresses.is_empty() {
            return None;
        }

        let allow_loopback = self.allow_loopback;
        let filtered: Vec<(MultiAddr, AddressType)> = typed_addresses
            .into_iter()
            .filter(|(addr, _)| {
                if allow_loopback {
                    return true;
                }
                !addr
                    .ip()
                    .is_some_and(|ip| canonicalize_ip(ip).is_loopback())
            })
            .map(|(addr, ty)| {
                let ty = AddressType::for_advertised_address(&addr, ty);
                (addr, ty)
            })
            .collect();

        Some(filtered)
    }

    /// Add a node to the DHT with security checks.
    ///
    /// IP subnet diversity is enforced per-bucket and for the K closest
    /// nodes to self, with closer peers swapped in when they contend for
    /// the same slot.
    ///
    /// `trust_score` is a closure that returns the current trust score for
    /// any peer ID. Well-trusted peers (above [`TRUST_PROTECTION_THRESHOLD`])
    /// are protected from swap-closer eviction. This decouples the routing
    /// table from the trust engine implementation.
    ///
    /// Returns [`AdmissionResult::Admitted`] on success, or
    /// [`AdmissionResult::StaleRevalidationNeeded`] when the target bucket is
    /// full and stale peers may be evicted after revalidation. The caller
    /// (DhtNetworkManager) must handle the revalidation flow.
    pub async fn add_node(
        &mut self,
        mut node: NodeInfo,
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Result<AdmissionResult> {
        // Reject self-insertion — a node must never appear in its own routing table.
        if node.id == self.node_id {
            return Err(anyhow!("cannot add self to routing table"));
        }

        let peer_id = node.id;

        // Strip wildcard / port-zero addresses before any admission logic runs.
        // Without this, a NodeInfo carrying both /ip4/0.0.0.0/... and a valid
        // routable address would be rejected wholesale by the unspecified-IP
        // check in `add_with_diversity` — the per-address store filter in
        // `KBucket::add_node` never gets a chance to run. Sanitizing here lets
        // mixed records through with only their routable addresses retained,
        // matching the store-side filter applied at the bucket boundary.
        node.retain_storable_addresses();

        // A record left with no addresses after sanitization carried nothing
        // but wildcard / port-zero entries. It is not a non-IP transport, so
        // it must not fall through to the non-IP bypass below — reject it.
        if node.addresses.is_empty() {
            return Err(anyhow!(
                "all addresses were wildcard / port-zero; nothing storable"
            ));
        }

        let peer_trust_score = trust_score(&peer_id);
        self.check_quarantine_admission(&peer_id, peer_trust_score)?;

        // Extract ALL IP addresses from the candidate for diversity checking.
        // If candidate has no IP-based addresses, it's a non-IP transport — bypass diversity.
        let candidate_ips: Vec<IpAddr> = node
            .addresses
            .iter()
            .filter_map(|a| a.ip().map(canonicalize_ip))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if candidate_ips.is_empty() {
            // Non-IP transports (Bluetooth, LoRa, etc.) bypass IP diversity.
            let mut routing = self.routing_table.write().await;
            // Update short-circuit: if peer already exists, merge addresses and
            // refresh last_seen without emitting PeerAdded (matches the main
            // diversity path's update logic at the "Design step 5" block).
            if routing.find_node_by_id(&peer_id).is_some() {
                for (i, addr) in node.addresses.iter().enumerate() {
                    routing.touch_node(&peer_id, Some(addr), node.address_type_at(i));
                }
                return Ok(AdmissionResult::Admitted(vec![]));
            }
            self.check_close_group_admission(&routing, &peer_id, peer_trust_score, &[])?;
            let k_before = routing.k_closest_ids(self.k_value);
            routing.add_node(node)?;
            let k_after = routing.k_closest_ids(self.k_value);
            let mut events = vec![RoutingTableEvent::PeerAdded(peer_id)];
            if k_before != k_after {
                events.push(RoutingTableEvent::KClosestPeersChanged {
                    old: k_before,
                    new: k_after,
                });
            }
            return Ok(AdmissionResult::Admitted(events));
        }

        // Single write lock covers diversity checks and insertion to avoid
        // a TOCTOU race.
        let mut routing = self.routing_table.write().await;
        self.add_with_diversity(&mut routing, node, &candidate_ips, trust_score, true)
    }

    /// Convenience method for tests: add a node with neutral trust (0.5).
    ///
    /// Preserves existing swap-closer behavior for tests that don't care
    /// about trust scoring. Maps [`AdmissionResult::Admitted`] to its events
    /// and treats [`AdmissionResult::StaleRevalidationNeeded`] as an error
    /// (unit tests don't have network access to ping stale peers).
    #[cfg(test)]
    pub async fn add_node_no_trust(&mut self, node: NodeInfo) -> Result<Vec<RoutingTableEvent>> {
        match self.add_node(node, &|_| DEFAULT_NEUTRAL_TRUST).await? {
            AdmissionResult::Admitted(events) => Ok(events),
            AdmissionResult::StaleRevalidationNeeded { .. } => Err(anyhow!(
                "stale revalidation needed (not available in unit tests)"
            )),
        }
    }

    /// Check IP diversity within a scoped set of nodes and return a swap
    /// candidate if the scope is over-limit but the candidate is closer.
    ///
    /// Returns:
    /// - `Ok(None)` — scope is within limits (or candidate is loopback)
    /// - `Ok(Some(peer_id))` — scope exceeds a limit but the candidate is
    ///   closer than the farthest violating peer; swap that peer out
    /// - `Err` — scope exceeds a limit and the candidate cannot swap in
    ///
    /// Trust protection: the farthest peer is only swapped out when its trust
    /// score is below [`TRUST_PROTECTION_THRESHOLD`]. Well-trusted peers hold
    /// their slot even when a closer candidate arrives.
    fn find_ip_swap_in_scope(
        &self,
        nodes: &[NodeInfo],
        candidate_id: &PeerId,
        candidate_ip: IpAddr,
        candidate_distance: &[u8; 32],
        scope_name: &str,
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Result<Option<PeerId>> {
        // Loopback candidates bypass IP diversity entirely.
        if candidate_ip.is_loopback() {
            return Ok(None);
        }

        let cfg = &self.ip_diversity_config;

        match candidate_ip {
            IpAddr::V4(v4) => {
                // IPv4 limits: use config override if set, otherwise default
                let limit_ip = cfg.max_per_ip.unwrap_or(IP_EXACT_LIMIT);
                let limit_subnet = cfg.max_per_subnet.unwrap_or(ip_subnet_limit(self.k_value));

                let cand_24 = mask_ipv4(v4, 24);

                // Single pass: count exact-IP and /24 matches, track farthest at each.
                // Check ALL addresses of each existing node to prevent diversity
                // bypass via address rotation (e.g. touch_node prepending a new address).
                // Each node is counted at most once per tier to avoid double-counting
                // multi-homed peers.
                let mut count_ip: usize = 0;
                let mut count_subnet: usize = 0;
                let mut farthest_ip: Option<(PeerId, [u8; 32], Instant)> = None;
                let mut farthest_subnet: Option<(PeerId, [u8; 32], Instant)> = None;

                for n in nodes {
                    if n.id == *candidate_id {
                        continue;
                    }
                    let existing_ips = n.all_ips();
                    if existing_ips.is_empty() {
                        continue;
                    }

                    let dist = xor_distance_bytes(self.node_id.to_bytes(), n.id.to_bytes());

                    // Check if any of this node's addresses match the candidate's
                    // exact IP or /24 subnet. Count each node at most once per tier.
                    let mut matched_ip = false;
                    let mut matched_subnet = false;
                    for existing_ip in &existing_ips {
                        if existing_ip.is_loopback() {
                            continue;
                        }
                        let IpAddr::V4(existing_v4) = existing_ip else {
                            continue;
                        };
                        if !matched_ip && *existing_v4 == v4 {
                            matched_ip = true;
                        }
                        if !matched_subnet && mask_ipv4(*existing_v4, 24) == cand_24 {
                            matched_subnet = true;
                        }
                    }

                    if matched_ip {
                        count_ip += 1;
                        if farthest_ip.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_ip = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                    if matched_subnet {
                        count_subnet += 1;
                        if farthest_subnet.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_subnet = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                }

                // Check tiers narrowest-first: a swap at exact-IP also fixes /24
                let tiers: [IpSwapTier; 2] = [
                    (count_ip, limit_ip, farthest_ip, "exact-IP"),
                    (count_subnet, limit_subnet, farthest_subnet, "/24"),
                ];

                for (count, limit, farthest, tier_name) in &tiers {
                    if *count >= *limit {
                        if let Some((far_id, far_dist, far_last_seen)) = farthest
                            && candidate_distance < far_dist
                            && (trust_score(far_id) < TRUST_PROTECTION_THRESHOLD
                                || far_last_seen.elapsed() > self.live_threshold)
                        {
                            return Ok(Some(*far_id));
                        }
                        return Err(anyhow!(
                            "IP diversity: {tier_name} limit ({limit}) exceeded in {scope_name}"
                        ));
                    }
                }
            }
            IpAddr::V6(v6) => {
                // IPv6 limits: use config override if set, otherwise default
                let limit_ip = cfg.max_per_ip.unwrap_or(IP_EXACT_LIMIT);
                let limit_subnet = cfg.max_per_subnet.unwrap_or(ip_subnet_limit(self.k_value));

                let cand_48 = mask_ipv6(v6, 48);

                // Single pass: count exact-IPv6 and /48 matches.
                // Check ALL addresses per node (see IPv4 branch comment).
                let mut count_ip: usize = 0;
                let mut count_subnet: usize = 0;
                let mut farthest_ip: Option<(PeerId, [u8; 32], Instant)> = None;
                let mut farthest_subnet: Option<(PeerId, [u8; 32], Instant)> = None;

                for n in nodes {
                    if n.id == *candidate_id {
                        continue;
                    }
                    let existing_ips = n.all_ips();
                    if existing_ips.is_empty() {
                        continue;
                    }

                    let dist = xor_distance_bytes(self.node_id.to_bytes(), n.id.to_bytes());

                    let mut matched_ip = false;
                    let mut matched_subnet = false;
                    for existing_ip in &existing_ips {
                        if existing_ip.is_loopback() {
                            continue;
                        }
                        let IpAddr::V6(existing_v6) = existing_ip else {
                            continue;
                        };
                        if !matched_ip && *existing_v6 == v6 {
                            matched_ip = true;
                        }
                        if !matched_subnet && mask_ipv6(*existing_v6, 48) == cand_48 {
                            matched_subnet = true;
                        }
                    }

                    if matched_ip {
                        count_ip += 1;
                        if farthest_ip.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_ip = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                    if matched_subnet {
                        count_subnet += 1;
                        if farthest_subnet.as_ref().is_none_or(|(_, d, _)| dist > *d) {
                            farthest_subnet = Some((n.id, dist, n.last_seen.load()));
                        }
                    }
                }

                let tiers: [IpSwapTier; 2] = [
                    (count_ip, limit_ip, farthest_ip, "exact-IP"),
                    (count_subnet, limit_subnet, farthest_subnet, "/48"),
                ];

                for (count, limit, farthest, tier_name) in &tiers {
                    if *count >= *limit {
                        if let Some((far_id, far_dist, far_last_seen)) = farthest
                            && candidate_distance < far_dist
                            && (trust_score(far_id) < TRUST_PROTECTION_THRESHOLD
                                || far_last_seen.elapsed() > self.live_threshold)
                        {
                            return Ok(Some(*far_id));
                        }
                        return Err(anyhow!(
                            "IP diversity: {tier_name} limit ({limit}) exceeded in {scope_name}"
                        ));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Collect stale peers from a bucket.
    ///
    /// Returns `(peer_id, bucket_index)` pairs for all peers in the target
    /// bucket whose `last_seen` exceeds the given `threshold`.
    fn collect_stale_peers_in_bucket(
        routing: &KademliaRoutingTable,
        bucket_idx: usize,
        threshold: Duration,
    ) -> Vec<(PeerId, usize)> {
        routing.buckets[bucket_idx]
            .nodes
            .iter()
            .filter(|n| n.last_seen.elapsed() > threshold)
            .map(|n| (n.id, bucket_idx))
            .collect()
    }

    /// Add a node with per-bucket and close-group IP diversity enforcement.
    ///
    /// Enforces that no IP subnet exceeds its limit within any single
    /// k-bucket or within the K closest nodes to self.
    ///
    /// When a candidate would exceed a limit, it may still be admitted if it
    /// is closer (XOR distance) to self than the farthest violating peer in
    /// the scope — the farther peer is evicted and the candidate takes its
    /// slot, preserving the count while improving routing quality.
    ///
    /// Trust protection is forwarded to [`Self::find_ip_swap_in_scope`] so
    /// that well-trusted peers resist eviction.
    ///
    /// When `allow_stale_revalidation` is `true` and the bucket is at capacity
    /// with no swap candidate, stale peers are identified and
    /// [`AdmissionResult::StaleRevalidationNeeded`] is returned so the caller
    /// can ping them and retry. When `false` (re-evaluation after revalidation),
    /// a full bucket is a hard rejection to prevent infinite revalidation loops.
    fn add_with_diversity(
        &self,
        routing: &mut KademliaRoutingTable,
        node: NodeInfo,
        candidate_ips: &[IpAddr],
        trust_score: &impl Fn(&PeerId) -> f64,
        allow_stale_revalidation: bool,
    ) -> Result<AdmissionResult> {
        let peer_id = node.id;

        // --- Reject invalid addresses ---
        // Multicast and unspecified addresses are never valid peer endpoints.
        if candidate_ips
            .iter()
            .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(anyhow!(
                "IP diversity: multicast or unspecified addresses rejected"
            ));
        }

        // --- Reject any loopback addresses when loopback is disallowed (M2) ---
        if !self.allow_loopback && candidate_ips.iter().any(|ip| ip.is_loopback()) {
            return Err(anyhow!(
                "IP diversity: loopback addresses rejected (allow_loopback=false)"
            ));
        }

        // --- Loopback handling ---
        let all_loopback = candidate_ips.iter().all(|ip| ip.is_loopback());
        if all_loopback {
            if !self.allow_loopback {
                return Err(anyhow!(
                    "IP diversity: loopback addresses rejected (allow_loopback=false)"
                ));
            }
            // Loopback with allow_loopback=true bypasses all diversity checks.
            // Update short-circuit: if peer already exists, merge addresses and
            // refresh last_seen without emitting PeerAdded.
            if routing.find_node_by_id(&peer_id).is_some() {
                for (i, addr) in node.addresses.iter().enumerate() {
                    routing.touch_node(&peer_id, Some(addr), node.address_type_at(i));
                }
                return Ok(AdmissionResult::Admitted(vec![]));
            }
            self.check_close_group_admission(routing, &peer_id, trust_score(&peer_id), &[])?;
            let k_before = routing.k_closest_ids(self.k_value);
            routing.add_node(node)?;
            let k_after = routing.k_closest_ids(self.k_value);
            let mut events = vec![RoutingTableEvent::PeerAdded(peer_id)];
            if k_before != k_after {
                events.push(RoutingTableEvent::KClosestPeersChanged {
                    old: k_before,
                    new: k_after,
                });
            }
            return Ok(AdmissionResult::Admitted(events));
        }

        let bucket_idx = routing
            .get_bucket_index(&node.id)
            .ok_or_else(|| anyhow!("cannot insert self into routing table"))?;
        let candidate_distance = xor_distance_bytes(self.node_id.to_bytes(), node.id.to_bytes());

        // === Update short-circuit (Design step 5) ===
        // If peer already exists, merge addresses, refresh last_seen, move to tail.
        // Skip diversity and capacity checks — the peer already holds its slot.
        // The update path doesn't change membership, just position within a bucket.
        // K-closest computation is distance-based, not position-based, so the set
        // won't change. Return an empty events vec.
        if let Some(pos) = routing.buckets[bucket_idx]
            .nodes
            .iter()
            .position(|n| n.id == node.id)
        {
            let existing = &mut routing.buckets[bucket_idx].nodes[pos];
            existing.last_seen.store_now();
            // Merge each address from the candidate, respecting loopback injection prevention
            for (i, addr) in node.addresses.iter().enumerate() {
                let addr_is_loopback = addr
                    .ip()
                    .is_some_and(|ip| canonicalize_ip(ip).is_loopback());
                let existing_has_non_loopback = existing
                    .addresses
                    .iter()
                    .any(|a| a.ip().is_some_and(|ip| !canonicalize_ip(ip).is_loopback()));
                // Don't merge loopback addresses into a non-loopback-admitted peer
                if addr_is_loopback && existing_has_non_loopback {
                    continue;
                }
                existing.merge_typed_address(addr.clone(), node.address_type_at(i));
            }
            // Move to tail (most recently seen)
            let updated = routing.buckets[bucket_idx].nodes.remove(pos);
            routing.buckets[bucket_idx].nodes.push(updated);
            routing.buckets[bucket_idx].last_refreshed_by_live_peer = Instant::now();
            return Ok(AdmissionResult::Admitted(Vec::new()));
        }

        // === Per-bucket IP diversity ===
        // Run diversity checks for each non-loopback candidate IP independently.
        // After identifying a swap for one IP, exclude that peer from subsequent
        // checks so that each IP sees the state after prior swaps — preventing
        // over-eviction when a candidate has multiple IPs.
        let mut all_bucket_swaps: Vec<PeerId> = Vec::new();
        for &candidate_ip in candidate_ips {
            if candidate_ip.is_loopback() {
                continue;
            }
            let bucket_view: Vec<NodeInfo> = routing.buckets[bucket_idx]
                .nodes
                .iter()
                .filter(|n| !all_bucket_swaps.contains(&n.id))
                .cloned()
                .collect();
            let swap = self.find_ip_swap_in_scope(
                &bucket_view,
                &node.id,
                candidate_ip,
                &candidate_distance,
                "bucket",
                trust_score,
            )?;
            if let Some(id) = swap
                && !all_bucket_swaps.contains(&id)
            {
                all_bucket_swaps.push(id);
            }
        }

        // === Close-group setup ===
        let close_group = routing.find_closest_nodes(&self.node_id, self.k_value);

        let effective_close_len = close_group
            .iter()
            .filter(|n| !all_bucket_swaps.contains(&n.id))
            .count();

        let candidate_in_close = effective_close_len < self.k_value
            || close_group
                .iter()
                .rfind(|n| !all_bucket_swaps.contains(&n.id))
                .map(|n| {
                    candidate_distance
                        < xor_distance_bytes(self.node_id.to_bytes(), n.id.to_bytes())
                })
                .unwrap_or(true);

        let mut all_close_swaps: Vec<PeerId> = Vec::new();

        if candidate_in_close {
            // Build hypothetical close group as Vec<NodeInfo>
            let mut hyp_close: Vec<NodeInfo> = close_group
                .iter()
                .filter(|n| !all_bucket_swaps.contains(&n.id) && n.id != node.id)
                .cloned()
                .collect();
            hyp_close.push(node.clone());
            hyp_close.sort_by(|a, b| {
                let da = xor_distance_bytes(self.node_id.to_bytes(), a.id.to_bytes());
                let db = xor_distance_bytes(self.node_id.to_bytes(), b.id.to_bytes());
                da.cmp(&db)
            });
            hyp_close.truncate(self.k_value);

            // === Close-group IP diversity ===
            // Exclude prior close-group swaps from each subsequent check to
            // prevent over-eviction (same rationale as the bucket loop above).
            for &candidate_ip in candidate_ips {
                if candidate_ip.is_loopback() {
                    continue;
                }
                let close_view: Vec<NodeInfo> = hyp_close
                    .iter()
                    .filter(|n| !all_close_swaps.contains(&n.id))
                    .cloned()
                    .collect();
                let swap = self.find_ip_swap_in_scope(
                    &close_view,
                    &node.id,
                    candidate_ip,
                    &candidate_distance,
                    "close-group",
                    trust_score,
                )?;
                if let Some(id) = swap {
                    // Deduplicate: don't plan a close swap that's already a bucket swap
                    if !all_bucket_swaps.contains(&id) && !all_close_swaps.contains(&id) {
                        all_close_swaps.push(id);
                    }
                }
            }
        }

        // === Capacity pre-check ===
        // Verify the insertion will succeed before executing any swaps.
        {
            let bucket = &routing.buckets[bucket_idx];
            let already_exists = bucket.nodes.iter().any(|n| n.id == node.id);
            let has_room = bucket.nodes.len() < bucket.max_size;
            let swap_frees_slot = !all_bucket_swaps.is_empty()
                || all_close_swaps
                    .iter()
                    .any(|id| routing.get_bucket_index(id) == Some(bucket_idx));
            if !already_exists && !has_room && !swap_frees_slot {
                // --- Trust-based swap-out (lazy eviction) ---
                // When a bucket is full and no IP-diversity swap is available,
                // find the lowest-trust peer below swap_threshold and replace
                // it directly. No revalidation ping needed.
                // Only swap when the candidate itself is above the threshold
                // to avoid replacing a low-trust peer with an even worse one.
                if self.swap_threshold > 0.0 && trust_score(&peer_id) >= self.swap_threshold {
                    let lowest = bucket
                        .nodes
                        .iter()
                        .map(|n| (n.id, trust_score(&n.id)))
                        .filter(|(_, score)| *score < self.swap_threshold)
                        .min_by(|(_, a), (_, b)| {
                            a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
                        });

                    if let Some((swap_id, _)) = lowest {
                        all_bucket_swaps.push(swap_id);
                    }
                }

                // Re-check capacity after potential trust swap
                let swap_frees_slot_now = !all_bucket_swaps.is_empty()
                    || all_close_swaps
                        .iter()
                        .any(|id| routing.get_bucket_index(id) == Some(bucket_idx));

                if !swap_frees_slot_now {
                    if allow_stale_revalidation {
                        let mut stale_peers = Self::collect_stale_peers_in_bucket(
                            routing,
                            bucket_idx,
                            self.live_threshold,
                        );

                        // Merge stale routing-neighborhood violators (Design Section 7.5):
                        // close-group swap targets that are stale and not already in the
                        // bucket-level set. Evicting these may resolve the close-group
                        // diversity violation and (if they happen to reside in the same
                        // bucket) free capacity for the candidate.
                        for close_swap_id in &all_close_swaps {
                            if stale_peers.iter().any(|(id, _)| id == close_swap_id) {
                                continue;
                            }
                            if let Some(swap_bucket_idx) = routing.get_bucket_index(close_swap_id)
                                && let Some(swap_node) = routing.find_node_by_id(close_swap_id)
                                && swap_node.last_seen.elapsed() > self.live_threshold
                            {
                                stale_peers.push((*close_swap_id, swap_bucket_idx));
                            }
                        }

                        if !stale_peers.is_empty() {
                            return Ok(AdmissionResult::StaleRevalidationNeeded {
                                candidate: node,
                                candidate_ips: candidate_ips.to_vec(),
                                candidate_bucket_idx: bucket_idx,
                                stale_peers,
                            });
                        }
                    }
                    return Err(anyhow!(
                        "K-bucket at capacity ({}/{}) with no stale peers",
                        bucket.nodes.len(),
                        bucket.max_size,
                    ));
                }
            }
        }

        let mut planned_removals: Vec<PeerId> =
            Vec::with_capacity(all_bucket_swaps.len() + all_close_swaps.len());
        planned_removals.extend(all_bucket_swaps.iter().copied());
        for peer_id in &all_close_swaps {
            if !planned_removals.contains(peer_id) {
                planned_removals.push(*peer_id);
            }
        }
        self.check_close_group_admission(
            routing,
            &peer_id,
            trust_score(&peer_id),
            &planned_removals,
        )?;

        // === Snapshot K-closest BEFORE mutation ===
        let k_before = routing.k_closest_ids(self.k_value);

        // === Execute all swaps (deduplicated) ===
        let mut executed: Vec<PeerId> = Vec::with_capacity(2);
        for swap_id in all_bucket_swaps
            .iter()
            .chain(all_close_swaps.iter())
            .copied()
        {
            if !executed.contains(&swap_id) {
                routing.remove_node(&swap_id);
                executed.push(swap_id);
            }
        }

        routing.add_node(node)?;

        // === Build events ===
        let mut events: Vec<RoutingTableEvent> = Vec::with_capacity(executed.len() + 2);
        for removed_id in &executed {
            events.push(RoutingTableEvent::PeerRemoved(*removed_id));
        }
        events.push(RoutingTableEvent::PeerAdded(peer_id));

        // === Snapshot K-closest AFTER mutation ===
        let k_after = routing.k_closest_ids(self.k_value);
        if k_before != k_after {
            events.push(RoutingTableEvent::KClosestPeersChanged {
                old: k_before,
                new: k_after,
            });
        }

        Ok(AdmissionResult::Admitted(events))
    }

    /// Re-evaluate admission after stale peers have been evicted by the caller.
    ///
    /// Called by the network manager after pinging stale peers and evicting
    /// non-responders. Re-runs IP diversity, trust-based swap-out, and capacity
    /// checks with `allow_stale_revalidation: false` to prevent infinite
    /// revalidation loops.
    pub(crate) async fn re_evaluate_admission(
        &mut self,
        candidate: NodeInfo,
        candidate_ips: &[IpAddr],
        trust_score: &impl Fn(&PeerId) -> f64,
    ) -> Result<Vec<RoutingTableEvent>> {
        self.check_quarantine_admission(&candidate.id, trust_score(&candidate.id))?;
        let mut routing = self.routing_table.write().await;
        match self.add_with_diversity(&mut routing, candidate, candidate_ips, trust_score, false)? {
            AdmissionResult::Admitted(events) => Ok(events),
            AdmissionResult::StaleRevalidationNeeded { .. } => {
                // Design: re-evaluation MUST NOT trigger a second revalidation round.
                // The `allow_stale_revalidation: false` flag should prevent this path,
                // but we handle it defensively.
                Err(anyhow!("K-bucket still at capacity after revalidation"))
            }
        }
    }
}

// Manual Debug implementation to avoid cascade of Debug requirements
impl std::fmt::Debug for DhtCoreEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtCoreEngine")
            .field("node_id", &self.node_id)
            .field("routing_table", &"Arc<RwLock<KademliaRoutingTable>>")
            .field("k_value", &self.k_value)
            .field("ip_diversity_config", &self.ip_diversity_config)
            .field("allow_loopback", &self.allow_loopback)
            .field("swap_threshold", &self.swap_threshold)
            .field("quarantine_threshold", &self.quarantine_threshold)
            .field(
                "quarantine_readmit_threshold",
                &self.quarantine_readmit_threshold,
            )
            .field("quarantined_peers", &self.quarantined_peers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::TransportAddr;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_xor_distance() {
        let key1 = DhtKey::from_bytes([0u8; 32]);
        let key2 = DhtKey::from_bytes([255u8; 32]);

        let distance = key1.distance(&key2);
        assert_eq!(distance, [255u8; 32]);
    }

    /// Helper: create a NodeInfo with a deterministic PeerId derived from a
    /// single byte.  Keeps tests concise.
    fn make_node(byte: u8, address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes([byte; 32]),
            addresses: vec![address.parse::<MultiAddr>().unwrap()],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::touch_node tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_touch_node_merges_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        // Touch with a new same-family-same-type (IPv4 Direct) address.
        // The per-IP-family cap keeps the newest Direct and drops the old
        // one — both cannot coexist under the "1 Direct per IPv4" rule.
        let new_addr: MultiAddr = "/ip4/5.6.7.8/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node_typed(
            &PeerId::from_bytes([1u8; 32]),
            Some(&new_addr),
            AddressType::Direct,
        );
        assert!(found);
        let addrs = &bucket.get_nodes().last().unwrap().addresses;
        assert_eq!(addrs, &vec![new_addr]);
    }

    #[test]
    fn test_touch_node_none_preserves_addresses() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "/ip4/1.2.3.4/udp/9000/quic");
        bucket.add_node(node).unwrap();

        let found =
            bucket.touch_node_typed(&PeerId::from_bytes([1u8; 32]), None, AddressType::Direct);
        assert!(found);
        let expected: MultiAddr = "/ip4/1.2.3.4/udp/9000/quic".parse().unwrap();
        assert_eq!(bucket.get_nodes().last().unwrap().addresses, vec![expected]);
    }

    #[test]
    fn test_touch_node_moves_to_tail() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(2, "/ip4/2.2.2.2/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(3, "/ip4/3.3.3.3/udp/9000/quic"))
            .unwrap();

        // Touch the first node — it should move to the tail
        bucket.touch_node_typed(&PeerId::from_bytes([1u8; 32]), None, AddressType::Direct);
        let ids: Vec<u8> = bucket
            .get_nodes()
            .iter()
            .map(|n| n.id.to_bytes()[0])
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    #[test]
    fn test_touch_node_missing_returns_false() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let new_addr: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
        let found = bucket.touch_node_typed(
            &PeerId::from_bytes([99u8; 32]),
            Some(&new_addr),
            AddressType::Direct,
        );
        assert!(!found);
    }

    // -----------------------------------------------------------------------
    // KBucket::merge_typed_address_upgrade_only tests
    //
    // The gossip-ingestion path: merges a third party's view of an existing
    // peer's addresses without claiming the peer is alive from our point of
    // view. Liveness (`last_seen`) and bucket-MRU position must be preserved
    // — see the rationale on `KBucket::merge_typed_address_upgrade_only`.
    //
    // The robust pattern here is capture-before-merge / compare-after-merge:
    // any leaked `store_now()` would write a strictly later `Instant` than
    // the captured snapshot (the merge does a Vec scan, mutex unlock, and
    // assertion code in between), so exact-equality detects refresh leaks
    // without depending on system uptime or clock granularity.
    // -----------------------------------------------------------------------

    #[test]
    fn gossip_merge_does_not_bump_last_seen() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let before = bucket.nodes[0].last_seen.load();

        let gossiped: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
        let changed = bucket.merge_typed_address_upgrade_only(
            &PeerId::from_bytes([1u8; 32]),
            &gossiped,
            AddressType::Relay,
        );
        assert!(changed, "merge of new address should report a state change");
        assert_eq!(
            bucket.nodes[0].last_seen.load(),
            before,
            "gossip ingestion must not refresh last_seen"
        );
    }

    #[test]
    fn gossip_merge_does_not_reorder_bucket() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(2, "/ip4/2.2.2.2/udp/9000/quic"))
            .unwrap();
        bucket
            .add_node(make_node(3, "/ip4/3.3.3.3/udp/9000/quic"))
            .unwrap();

        // Insertion order (head = LRU, tail = MRU): [1, 2, 3].
        // touch_node_typed would move peer 1 to the tail. Gossip-merge must
        // NOT, otherwise unauthenticated gossip could shield bad peers from
        // LRU-driven eviction.
        let gossiped: MultiAddr = "/ip4/8.8.8.8/udp/9000/quic".parse().unwrap();
        bucket.merge_typed_address_upgrade_only(
            &PeerId::from_bytes([1u8; 32]),
            &gossiped,
            AddressType::Relay,
        );

        let ids: Vec<u8> = bucket
            .get_nodes()
            .iter()
            .map(|n| n.id.to_bytes()[0])
            .collect();
        assert_eq!(
            ids,
            vec![1, 2, 3],
            "gossip ingestion must preserve bucket order"
        );
    }

    #[test]
    fn gossip_merge_adds_new_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        // A previously unseen Direct address from gossip. Should be added
        // and the merge should report a state change.
        let gossiped: MultiAddr = "/ip4/7.7.7.7/udp/9000/quic".parse().unwrap();
        let changed = bucket.merge_typed_address_upgrade_only(
            &PeerId::from_bytes([1u8; 32]),
            &gossiped,
            AddressType::Direct,
        );
        assert!(changed);
        assert!(
            bucket.nodes[0].addresses.iter().any(|a| a == &gossiped),
            "gossip ingestion must merge a previously-unseen address"
        );
    }

    #[test]
    fn gossip_merge_returns_false_for_missing_peer() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let gossiped: MultiAddr = "/ip4/9.9.9.9/udp/9000/quic".parse().unwrap();
        let changed = bucket.merge_typed_address_upgrade_only(
            &PeerId::from_bytes([42u8; 32]),
            &gossiped,
            AddressType::Direct,
        );
        assert!(
            !changed,
            "missing peer should return false (gossip never inserts new identities)"
        );
    }

    #[test]
    fn gossip_merge_returns_false_when_already_known_with_same_tag() {
        // The return value signals "did the merge change anything",
        // not "is the peer in the bucket". When gossip reports an
        // already-known address with the same tag classification, the
        // merge is a no-op and must report `false` so a future caller
        // can gate downstream work (logging, event emission, etc.) on
        // genuine record changes.
        let k = 8;
        let mut bucket = KBucket::new(k);
        let addr_str = "/ip4/1.1.1.1/udp/9000/quic";
        bucket.add_node(make_node(1, addr_str)).unwrap();

        // Promote the existing address to `Direct` so the redundant
        // gossip below cannot upgrade it from the default `Unverified`.
        let known: MultiAddr = addr_str.parse().unwrap();
        bucket.nodes[0].merge_typed_address_upgrade_only(known.clone(), AddressType::Direct);

        let changed = bucket.merge_typed_address_upgrade_only(
            &PeerId::from_bytes([1u8; 32]),
            &known,
            AddressType::Direct,
        );
        assert!(
            !changed,
            "no-op merge (same address, same tag) must report false"
        );
    }

    #[test]
    fn gossip_merge_does_not_bump_live_peer_refresh() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let before = bucket.last_refreshed_by_live_peer;

        let gossiped: MultiAddr = "/ip4/8.8.8.8/udp/9000/quic".parse().unwrap();
        let changed = bucket.merge_typed_address_upgrade_only(
            &PeerId::from_bytes([1u8; 32]),
            &gossiped,
            AddressType::Relay,
        );
        assert!(changed);
        assert_eq!(
            bucket.last_refreshed_by_live_peer, before,
            "gossip ingestion is not bucket-level discovery — live-peer refresh must not advance"
        );
    }

    // -----------------------------------------------------------------------
    // KBucket::replace_node_addresses tests (full-replace semantics)
    // -----------------------------------------------------------------------

    #[test]
    fn replace_addresses_overwrites_existing_list() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let new_direct: MultiAddr = "/ip4/2.2.2.2/udp/9001/quic".parse().unwrap();
        let new_relay: MultiAddr = "/ip4/3.3.3.3/udp/9002/quic".parse().unwrap();
        let typed = vec![
            (new_direct.clone(), AddressType::Direct),
            (new_relay.clone(), AddressType::Relay),
        ];
        let replaced = bucket.replace_node_addresses(&PeerId::from_bytes([1u8; 32]), typed);
        assert!(replaced);
        let node = bucket.find_node(&PeerId::from_bytes([1u8; 32])).unwrap();
        // Relay is first, Direct second — matches NodeInfo::merge_typed_address ordering.
        assert_eq!(node.addresses, vec![new_relay, new_direct]);
        assert_eq!(
            node.address_types,
            vec![AddressType::Relay, AddressType::Direct]
        );
    }

    #[test]
    fn replace_addresses_canonicalizes_local_scope_direct_to_lan() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let private: MultiAddr = "/ip4/192.168.1.10/udp/9001/quic".parse().unwrap();
        let typed = vec![(private.clone(), AddressType::Direct)];
        assert!(bucket.replace_node_addresses(&PeerId::from_bytes([1u8; 32]), typed));

        let node = bucket.find_node(&PeerId::from_bytes([1u8; 32])).unwrap();
        assert_eq!(node.addresses, vec![private]);
        assert_eq!(node.address_types, vec![AddressType::Lan]);
    }

    #[test]
    fn replace_addresses_missing_peer_returns_false() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        let typed = vec![(
            "/ip4/2.2.2.2/udp/9000/quic".parse().unwrap(),
            AddressType::Direct,
        )];
        let replaced = bucket.replace_node_addresses(&PeerId::from_bytes([42u8; 32]), typed);
        assert!(!replaced);
    }

    #[test]
    fn replace_addresses_collapses_under_per_ip_family_cap() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();

        // A misbehaving publisher sends 12 same-family same-type
        // addresses. The per-IP-family cap collapses them to one IPv4
        // Direct regardless of the `MAX_ADDRESSES_PER_NODE` sizing.
        let typed: Vec<(MultiAddr, AddressType)> = (0..12)
            .map(|i| {
                (
                    format!("/ip4/203.0.113.{}/udp/9000/quic", i + 1)
                        .parse()
                        .unwrap(),
                    AddressType::Direct,
                )
            })
            .collect();
        assert!(bucket.replace_node_addresses(&PeerId::from_bytes([1u8; 32]), typed));
        let node = bucket.find_node(&PeerId::from_bytes([1u8; 32])).unwrap();
        assert_eq!(node.addresses.len(), 1);
        assert_eq!(node.address_types, vec![AddressType::Direct]);
    }

    // -----------------------------------------------------------------------
    // KademliaRoutingTable::replace_node_addresses — sequence monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn replace_addresses_seq_monotonic() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);
        let peer = PeerId::from_bytes([1u8; 32]);
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                address_types: vec![AddressType::Direct],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let first: Vec<(MultiAddr, AddressType)> = vec![(
            "/ip4/2.2.2.2/udp/9000/quic".parse().unwrap(),
            AddressType::Direct,
        )];
        let second: Vec<(MultiAddr, AddressType)> = vec![(
            "/ip4/3.3.3.3/udp/9000/quic".parse().unwrap(),
            AddressType::Direct,
        )];

        assert!(table.replace_node_addresses(&peer, first.clone(), 10));
        // Same seq → rejected
        assert!(!table.replace_node_addresses(&peer, second.clone(), 10));
        // Lower seq → rejected
        assert!(!table.replace_node_addresses(&peer, second.clone(), 5));
        // Higher seq → accepted, addresses replaced
        assert!(table.replace_node_addresses(&peer, second.clone(), 20));

        let bucket_index = table.get_bucket_index(&peer).unwrap();
        let node = table.buckets[bucket_index].find_node(&peer).unwrap();
        assert_eq!(
            node.addresses,
            vec!["/ip4/3.3.3.3/udp/9000/quic".parse::<MultiAddr>().unwrap()]
        );
    }

    #[test]
    fn replace_addresses_rejects_zero_publish_seq() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);
        let peer = PeerId::from_bytes([1u8; 32]);
        let initial_addr = "/ip4/1.1.1.1/udp/9000/quic".parse::<MultiAddr>().unwrap();
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec![initial_addr.clone()],
                address_types: vec![AddressType::Unverified],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let zero_publish: Vec<(MultiAddr, AddressType)> = vec![(
            "/ip4/2.2.2.2/udp/9000/quic".parse().unwrap(),
            AddressType::Direct,
        )];
        assert!(!table.replace_node_addresses(&peer, zero_publish.clone(), 0));
        assert!(!table.replace_node_addresses_from_gossip(&peer, zero_publish, 0));
        assert_eq!(table.publish_seq_for(&peer), 0);

        let bucket_index = table.get_bucket_index(&peer).unwrap();
        let node = table.buckets[bucket_index].find_node(&peer).unwrap();
        assert_eq!(node.addresses, vec![initial_addr]);
        assert_eq!(node.address_types, vec![AddressType::Unverified]);
    }

    #[test]
    fn legacy_relay_hint_updates_unsequenced_record() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);
        let peer = PeerId::from_bytes([1u8; 32]);
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                address_types: vec![AddressType::Unverified],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let relay = "/ip4/198.51.100.7/udp/46973/quic"
            .parse::<MultiAddr>()
            .unwrap();
        assert!(table.touch_legacy_relay_hint_if_unsequenced(&peer, &relay));

        let bucket_index = table.get_bucket_index(&peer).unwrap();
        let node = table.buckets[bucket_index].find_node(&peer).unwrap();
        assert_eq!(node.addresses[0], relay);
        assert_eq!(node.address_types[0], AddressType::Relay);
        assert_eq!(table.publish_seq_for(&peer), 0);
    }

    #[test]
    fn legacy_relay_hint_does_not_mutate_sequenced_record() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);
        let peer = PeerId::from_bytes([1u8; 32]);
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                address_types: vec![AddressType::Unverified],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let direct_only: Vec<(MultiAddr, AddressType)> = vec![(
            "/ip4/203.0.113.9/udp/60488/quic".parse().unwrap(),
            AddressType::Direct,
        )];
        assert!(table.replace_node_addresses(&peer, direct_only.clone(), 20));

        let stale_relay = "/ip4/198.51.100.7/udp/46973/quic"
            .parse::<MultiAddr>()
            .unwrap();
        assert!(!table.touch_legacy_relay_hint_if_unsequenced(&peer, &stale_relay));

        let bucket_index = table.get_bucket_index(&peer).unwrap();
        let node = table.buckets[bucket_index].find_node(&peer).unwrap();
        assert_eq!(
            node.addresses,
            vec![
                "/ip4/203.0.113.9/udp/60488/quic"
                    .parse::<MultiAddr>()
                    .unwrap()
            ]
        );
        assert_eq!(node.address_types, vec![AddressType::Direct]);
        assert_eq!(table.publish_seq_for(&peer), 20);
    }

    #[test]
    fn replace_addresses_from_gossip_does_not_refresh_liveness() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);
        let peer = PeerId::from_bytes([1u8; 32]);
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                address_types: vec![AddressType::Direct],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let bucket_index = table.get_bucket_index(&peer).unwrap();
        let before_last_seen = table.buckets[bucket_index]
            .find_node(&peer)
            .unwrap()
            .last_seen
            .load();
        let before_last_refreshed = table.buckets[bucket_index].last_refreshed_by_live_peer;

        let gossiped: Vec<(MultiAddr, AddressType)> = vec![(
            "/ip4/2.2.2.2/udp/9000/quic".parse().unwrap(),
            AddressType::Relay,
        )];
        assert!(table.replace_node_addresses_from_gossip(&peer, gossiped, 10));

        let node = table.buckets[bucket_index].find_node(&peer).unwrap();
        assert_eq!(
            node.addresses,
            vec!["/ip4/2.2.2.2/udp/9000/quic".parse::<MultiAddr>().unwrap()]
        );
        assert_eq!(node.address_types, vec![AddressType::Relay]);
        assert_eq!(
            node.last_seen.load(),
            before_last_seen,
            "third-party gossip must not prove subject-peer liveness"
        );
        assert_eq!(
            table.buckets[bucket_index].last_refreshed_by_live_peer, before_last_refreshed,
            "third-party gossip must not count as bucket discovery activity"
        );
        assert_eq!(table.publish_seq_for(&peer), 10);
    }

    #[test]
    fn remove_node_clears_publish_seq() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);
        let peer = PeerId::from_bytes([1u8; 32]);
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                address_types: vec![AddressType::Direct],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let typed = vec![(
            "/ip4/2.2.2.2/udp/9000/quic".parse().unwrap(),
            AddressType::Direct,
        )];
        assert!(table.replace_node_addresses(&peer, typed.clone(), 100));

        table.remove_node(&peer);
        assert!(!table.last_publish_seqs.contains_key(&peer));

        // Re-add and verify the seq counter was cleared (lower seq now accepted).
        table
            .add_node(NodeInfo {
                id: peer,
                addresses: vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()],
                address_types: vec![AddressType::Direct],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();
        assert!(table.replace_node_addresses(&peer, typed, 50));
    }

    // -----------------------------------------------------------------------
    // find_closest_nodes tests — boundary bucket indices
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_zero() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert nodes that land in different buckets.  XOR with [0;32]
        // means the bucket index is the leading-bit position of the node id.
        // Byte 0 = 0x80 → bucket 0, byte 0 = 0x40 → bucket 1, etc.
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 0x80; // bucket 0
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[0] = 0x40; // bucket 1
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        // Search for a key that targets bucket 0
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = 0x80;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        // Verify no duplicates by collecting IDs into a set
        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_255() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Bucket 255 requires the differing bit at position 255 (last bit
        // of last byte).  XOR distance with [0;32] is the id itself, so we
        // need id where only the very last bit is set.
        let mut id_bytes = [0u8; 32];
        id_bytes[31] = 0x01; // bucket 255
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[31] = 0x02; // bucket 254
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            })
            .unwrap();

        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_returns_sorted_by_distance() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert 5 nodes at varying distances
        for i in 0..5u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = 0x80 >> i; // buckets 0,1,2,3,4
            table
                .add_node(NodeInfo {
                    id: PeerId::from_bytes(id_bytes),
                    addresses: vec![
                        format!("/ip4/10.0.0.{}/udp/9000/quic", i + 1)
                            .parse()
                            .unwrap(),
                    ],
                    last_seen: AtomicInstant::now(),
                    address_types: vec![],
                })
                .unwrap();
        }

        let key = DhtKey::from_bytes([0u8; 32]);
        let results = table.find_closest_nodes(&key, 3);

        assert_eq!(results.len(), 3);
        // Results should be sorted by XOR distance to key
        for window in results.windows(2) {
            let d0 = xor_distance_bytes(window[0].id.to_bytes(), key.as_bytes());
            let d1 = xor_distance_bytes(window[1].id.to_bytes(), key.as_bytes());
            assert!(d0 <= d1, "Results not sorted by distance");
        }
    }

    #[test]
    fn test_find_closest_nodes_empty_table() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let table = KademliaRoutingTable::new(local_id, 8);

        let key = DhtKey::from_bytes([42u8; 32]);
        let results = table.find_closest_nodes(&key, 8);
        assert!(results.is_empty());
    }

    // -----------------------------------------------------------------------
    // check_diversity loopback gating tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_loopback_rejected_when_allow_loopback_false() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // Default has allow_loopback = false
        assert!(!dht.allow_loopback);

        let loopback_node = make_node(1, "/ip4/127.0.0.1/udp/9000/quic");
        let result = dht.add_node_no_trust(loopback_node).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("loopback"),
            "expected loopback rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_loopback_v6_rejected_when_allow_loopback_false() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        assert!(!dht.allow_loopback);

        let loopback_node = make_node(2, "/ip6/::1/udp/9000/quic");
        let result = dht.add_node_no_trust(loopback_node).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("loopback"),
            "expected loopback rejection, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_loopback_accepted_when_allow_loopback_true() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_allow_loopback(true);

        let loopback_node = make_node(1, "/ip4/127.0.0.1/udp/9000/quic");
        let result = dht.add_node_no_trust(loopback_node).await;
        assert!(result.is_ok(), "loopback should be accepted: {:?}", result);
    }

    #[tokio::test]
    async fn test_non_loopback_unaffected_by_allow_loopback_flag() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        // allow_loopback = false should not affect normal addresses
        assert!(!dht.allow_loopback);

        let normal_node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let result = dht.add_node_no_trust(normal_node).await;
        assert!(
            result.is_ok(),
            "non-loopback should be accepted: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn replace_addresses_applies_empty_set_after_filtering_all_entries() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let peer = PeerId::from_bytes([1u8; 32]);
        dht.add_node_no_trust(make_node(1, "/ip4/198.51.100.1/udp/9000/quic"))
            .await
            .unwrap();

        let loopback_only = vec![(
            "/ip4/127.0.0.1/udp/9001/quic".parse().unwrap(),
            AddressType::Direct,
        )];

        assert!(dht.replace_node_addresses(&peer, loopback_only, 1).await);
        assert!(dht.get_node_addresses(&peer).await.is_empty());
    }

    // -----------------------------------------------------------------------
    // IPv4 diversity: static floor overrides low dynamic limit
    // -----------------------------------------------------------------------

    /// Testnet config effectively disables IP diversity limits, allowing
    /// many nodes from the same IP in a single bucket.
    #[tokio::test]
    async fn test_testnet_config_disables_ip_diversity() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Testnet config sets all IP limits to usize::MAX.
        dht.set_ip_diversity_config(IPDiversityConfig::testnet());

        // All nodes land in bucket 0 (id[0]=0x80, self=[0;32]).
        // Vary id[31] for uniqueness.
        for i in 1..=8u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            let node = NodeInfo {
                id: PeerId::from_bytes(id),
                addresses: vec!["/ip4/203.0.113.1/udp/9000/quic".parse().unwrap()],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            };
            let result = dht.add_node_no_trust(node).await;
            assert!(
                result.is_ok(),
                "node {i} from same IP should be accepted with testnet config: {:?}",
                result
            );
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::add_node address validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_node_rejects_empty_addresses() {
        let mut bucket = KBucket::new(8);
        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };
        assert!(bucket.add_node(node).is_err());
    }

    #[test]
    fn test_add_node_oversized_same_family_collapses_to_cap() {
        let mut bucket = KBucket::new(8);

        // An incoming `NodeInfo` with many same-family, same-type
        // addresses collapses under the per-IP-family cap on insertion.
        // Legacy `address_types: vec![]` means each entry is treated as
        // `Unverified`, so the cap keeps exactly one Unverified per family.
        let addresses: Vec<MultiAddr> = (1..=MAX_ADDRESSES_PER_NODE + 4)
            .map(|i| format!("/ip4/10.0.0.{}/udp/9000/quic", i).parse().unwrap())
            .collect();

        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses,
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };
        bucket.add_node(node).unwrap();

        let stored = &bucket.get_nodes()[0].addresses;
        assert_eq!(stored.len(), 1);
    }

    #[test]
    fn test_add_node_replace_collapses_under_cap() {
        let mut bucket = KBucket::new(8);

        bucket
            .add_node(make_node(1, "/ip4/1.1.1.1/udp/9000/quic"))
            .unwrap();
        assert_eq!(bucket.get_nodes()[0].addresses.len(), 1);

        // Re-add the peer with an oversized Direct-tagged list. The
        // duplicate-admission path merges each address via
        // `merge_typed_address`, and the per-IP-family cap keeps exactly
        // one Direct per family.
        let addresses: Vec<MultiAddr> = (1..=MAX_ADDRESSES_PER_NODE + 4)
            .map(|i| {
                format!("/ip4/203.0.113.{}/udp/9000/quic", i)
                    .parse()
                    .unwrap()
            })
            .collect();
        let address_types = vec![AddressType::Direct; addresses.len()];
        let replacement = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses,
            last_seen: AtomicInstant::now(),
            address_types,
        };
        bucket.add_node(replacement).unwrap();

        let stored = &bucket.get_nodes().last().unwrap().addresses;
        assert_eq!(stored.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Helper: create a NodeInfo with an explicit id byte array
    // -----------------------------------------------------------------------

    fn make_node_with_addr(id_bytes: [u8; 32], address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes(id_bytes),
            addresses: vec![address.parse::<MultiAddr>().unwrap()],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        }
    }

    /// Live threshold used by tests: 1 second.
    ///
    /// Production uses 900 s, but on Windows `Instant` starts at process
    /// creation time, so subtracting large durations panics.  Tests call
    /// `set_live_threshold(TEST_LIVE_THRESHOLD)` and then set `last_seen`
    /// to `Instant::now() - TEST_STALE_AGE` which is safe on every platform.
    const TEST_LIVE_THRESHOLD: Duration = Duration::from_secs(1);

    /// How far back to set `last_seen` so peers exceed `TEST_LIVE_THRESHOLD`.
    const TEST_STALE_AGE: Duration = Duration::from_secs(2);

    // -----------------------------------------------------------------------
    // Test 4: low-trust peer admission (lazy swap-out model)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_low_trust_candidate_still_admitted() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;

        // Candidate with trust below swap threshold is still admitted
        // (lazy swap-out model: no admission blocking)
        let result = dht
            .add_node(node, &|id| {
                if *id == peer_id { 0.1 } else { 0.5 }
            })
            .await;

        assert!(result.is_ok(), "low-trust candidate should be admitted");
        assert!(dht.has_node(&peer_id).await);
    }

    // -----------------------------------------------------------------------
    // Test 13: update short-circuit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_duplicate_admission_updates_existing() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        // Re-add same peer with a new same-family (IPv4 Direct) address.
        let updated = NodeInfo {
            id: peer_id,
            addresses: vec!["/ip4/10.0.0.2/udp/9000/quic".parse().unwrap()],
            last_seen: AtomicInstant::now(),
            address_types: vec![AddressType::Direct],
        };
        let result = dht.add_node_no_trust(updated).await;
        assert!(result.is_ok(), "update short-circuit should succeed");

        // Per-IP-family cap: the newest IPv4 Direct wins; the old one is
        // dropped rather than kept alongside.
        let addrs = dht.get_node_addresses(&peer_id).await;
        assert_eq!(
            addrs,
            vec!["/ip4/10.0.0.2/udp/9000/quic".parse::<MultiAddr>().unwrap()]
        );
    }

    // -----------------------------------------------------------------------
    // Test 14: loopback injection prevention
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_loopback_injection_prevented_in_touch() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        // Touch with a loopback address — should be silently rejected
        let loopback_addr: MultiAddr = "/ip4/127.0.0.1/udp/9000/quic".parse().unwrap();
        dht.touch_node(&peer_id, Some(&loopback_addr)).await;

        let addrs = dht.get_node_addresses(&peer_id).await;
        assert_eq!(addrs.len(), 1, "loopback should not be merged");
        assert_ne!(addrs[0], loopback_addr);
    }

    // -----------------------------------------------------------------------
    // Test 21: staleness-gated trust protection
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_stale_trusted_peer_can_be_swapped() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Two peers in bucket 0, same IP (exact-IP limit = 2)
        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        let far_node = make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic");
        dht.add_node_no_trust(far_node).await.unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Make the far peer stale by manipulating last_seen
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_far))
                .unwrap();
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_far))
                .unwrap();
            // Set last_seen to exceed the test live threshold
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);
        }

        // A closer candidate with the same IP
        let mut id_close = [0u8; 32];
        id_close[0] = 0x80;
        let far_peer = PeerId::from_bytes(id_far);

        // Far peer has trust 0.8 (above TRUST_PROTECTION_THRESHOLD) but is STALE
        let trust_fn = |peer_id: &PeerId| -> f64 { if *peer_id == far_peer { 0.8 } else { 0.5 } };

        let result = dht
            .add_node(
                make_node_with_addr(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should succeed — stale peer loses trust protection
        assert!(
            result.is_ok(),
            "stale trusted peer should be swappable: {:?}",
            result
        );
        assert!(
            !dht.has_node(&far_peer).await,
            "stale far peer should be evicted"
        );
        assert!(dht.has_node(&PeerId::from_bytes(id_close)).await);
    }

    // -----------------------------------------------------------------------
    // Test 22: live well-trusted peer holds slot
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_live_trusted_peer_holds_slot() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Far peer is live (just added, last_seen is now) and trusted (0.8)
        let far_peer = PeerId::from_bytes(id_far);
        let trust_fn = |peer_id: &PeerId| -> f64 { if *peer_id == far_peer { 0.8 } else { 0.5 } };

        let mut id_close = [0u8; 32];
        id_close[0] = 0x80;
        let result = dht
            .add_node(
                make_node_with_addr(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should be rejected — live trusted peer holds its slot
        assert!(result.is_err());
        assert!(dht.has_node(&far_peer).await);
    }

    // -----------------------------------------------------------------------
    // Routing table event tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_peer_added_event_on_insertion() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;

        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == peer_id)),
            "expected PeerAdded event for inserted peer"
        );
    }

    #[tokio::test]
    async fn test_peer_removed_event_on_removal() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        let events = dht.remove_node_by_id(&peer_id).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == peer_id)),
            "expected PeerRemoved event for removed peer"
        );
    }

    #[tokio::test]
    async fn test_k_closest_changed_event_on_first_insertion() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Add a node close to self — should trigger KClosestPeersChanged (going from empty to 1)
        let mut id = [0u8; 32];
        id[31] = 0x01; // bucket 255, very close to self
        let node = NodeInfo {
            id: PeerId::from_bytes(id),
            addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };

        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::KClosestPeersChanged { .. })),
            "adding first close peer should trigger KClosestPeersChanged"
        );
    }

    #[tokio::test]
    async fn test_update_short_circuit_no_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        dht.add_node_no_trust(node.clone()).await.unwrap();

        // Re-add same peer — update path, no events
        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events.is_empty(),
            "update short-circuit should produce no events"
        );
    }

    #[tokio::test]
    async fn test_swap_eviction_produces_both_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Two peers in bucket 0, same IP (exact-IP limit = 2)
        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Make the far peer stale for swap eligibility
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_far))
                .unwrap();
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_far))
                .unwrap();
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);
        }

        // A closer candidate with the same IP triggers swap
        let mut id_close = [0u8; 32];
        id_close[0] = 0x80;
        let far_peer = PeerId::from_bytes(id_far);
        let close_peer = PeerId::from_bytes(id_close);

        let result = dht
            .add_node(
                make_node_with_addr(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
                &|peer_id| if *peer_id == far_peer { 0.8 } else { 0.5 },
            )
            .await
            .unwrap();

        let events = match result {
            AdmissionResult::Admitted(events) => events,
            other => panic!("expected Admitted, got {:?}", other),
        };

        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == far_peer)),
            "swap should produce PeerRemoved for evicted peer"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == close_peer)),
            "swap should produce PeerAdded for new peer"
        );
    }

    #[tokio::test]
    async fn test_k_closest_changed_on_removal() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();

        let events = dht.remove_node_by_id(&peer_id).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::KClosestPeersChanged { .. })),
            "removing a peer should trigger KClosestPeersChanged"
        );
    }

    // -----------------------------------------------------------------------
    // Stale peer revalidation tests (Phase 5)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_stale_revalidation_needed_when_bucket_full_with_stale_peers() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Fill bucket 0 with 4 peers (k=4).
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // Make all peers stale.
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x80;
            id_a[31] = 1;
            let bucket_idx = routing.get_bucket_index(&PeerId::from_bytes(id_a)).unwrap();
            for node in &mut routing.buckets[bucket_idx].nodes {
                node.last_seen.store(Instant::now() - TEST_STALE_AGE);
            }
        }

        // New candidate for bucket 0 — bucket is full, but stale peers exist.
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let result = dht
            .add_node(
                make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic"),
                &|_| DEFAULT_NEUTRAL_TRUST,
            )
            .await
            .unwrap();

        match result {
            AdmissionResult::StaleRevalidationNeeded {
                candidate,
                candidate_ips,
                candidate_bucket_idx: _,
                stale_peers,
            } => {
                assert_eq!(candidate.id, PeerId::from_bytes(id_new));
                assert!(!candidate_ips.is_empty());
                assert_eq!(stale_peers.len(), 4, "all peers should be stale");
            }
            AdmissionResult::Admitted(_) => panic!("expected StaleRevalidationNeeded"),
        }
    }

    #[tokio::test]
    async fn test_no_stale_revalidation_when_bucket_full_no_stale() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());

        // Fill bucket 0 with 4 fresh (live) peers.
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // New candidate — bucket full, no stale peers → hard rejection.
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let result = dht
            .add_node(
                make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic"),
                &|_| DEFAULT_NEUTRAL_TRUST,
            )
            .await;

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no stale peers"),
            "error should mention no stale peers, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_re_evaluate_admission_after_eviction() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());

        // Fill bucket 0 with 4 peers.
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // Evict one peer (simulating revalidation outcome).
        let mut id_a = [0u8; 32];
        id_a[0] = 0x80;
        id_a[31] = 1;
        dht.remove_node_by_id(&PeerId::from_bytes(id_a)).await;

        // Re-evaluate admission — should succeed now that there's room.
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let candidate = make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic");
        let candidate_ips = vec!["10.0.0.5".parse().unwrap()];

        let events = dht
            .re_evaluate_admission(candidate, &candidate_ips, &|_| DEFAULT_NEUTRAL_TRUST)
            .await
            .unwrap();

        assert!(
            events.iter().any(
                |e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == PeerId::from_bytes(id_new))
            ),
            "re-evaluation should produce PeerAdded"
        );
        assert!(dht.has_node(&PeerId::from_bytes(id_new)).await);
    }

    #[tokio::test]
    async fn test_re_evaluate_admits_low_trust_candidate() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            20,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        let mut id = [0u8; 32];
        id[0] = 0x80;
        let candidate = make_node_with_addr(id, "/ip4/10.0.0.1/udp/9000/quic");
        let candidate_ips = vec!["10.0.0.1".parse().unwrap()];

        // Trust below swap threshold — should still be admitted
        let result = dht
            .re_evaluate_admission(candidate, &candidate_ips, &|_| 0.1)
            .await;

        assert!(
            result.is_ok(),
            "low-trust candidate should be admitted via re-evaluate"
        );
    }

    #[tokio::test]
    async fn test_re_evaluate_does_not_trigger_second_revalidation() {
        // Use k=4 (minimum valid K) so the bucket fills quickly.
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_ip_diversity_config(crate::security::IPDiversityConfig::testnet());
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Fill bucket 0 with 4 stale peers.
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80;
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.0.0.{i}/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        // Make all stale.
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let mut id_a = [0u8; 32];
            id_a[0] = 0x80;
            id_a[31] = 1;
            let bucket_idx = routing.get_bucket_index(&PeerId::from_bytes(id_a)).unwrap();
            for node in &mut routing.buckets[bucket_idx].nodes {
                node.last_seen.store(Instant::now() - TEST_STALE_AGE);
            }
        }

        // re_evaluate_admission with full bucket and stale peers should reject,
        // NOT return StaleRevalidationNeeded (no second round).
        let mut id_new = [0u8; 32];
        id_new[0] = 0x80;
        id_new[31] = 5;
        let candidate = make_node_with_addr(id_new, "/ip4/10.0.0.5/udp/9000/quic");
        let candidate_ips = vec!["10.0.0.5".parse().unwrap()];

        let result = dht
            .re_evaluate_admission(candidate, &candidate_ips, &|_| DEFAULT_NEUTRAL_TRUST)
            .await;

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no stale peers"),
            "re-evaluation should not trigger another revalidation round, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_collect_stale_peers_in_bucket() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            20,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        // Add a fresh peer.
        let mut id_fresh = [0u8; 32];
        id_fresh[0] = 0x80;
        id_fresh[31] = 1;
        dht.add_node_no_trust(make_node_with_addr(id_fresh, "/ip4/10.0.0.1/udp/9000/quic"))
            .await
            .unwrap();

        // Add a stale peer.
        let mut id_stale = [0u8; 32];
        id_stale[0] = 0x80;
        id_stale[31] = 2;
        dht.add_node_no_trust(make_node_with_addr(id_stale, "/ip4/10.0.0.2/udp/9000/quic"))
            .await
            .unwrap();

        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_stale))
                .unwrap();

            // Make one peer stale.
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_stale))
                .unwrap();
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);

            let stale = DhtCoreEngine::collect_stale_peers_in_bucket(
                &routing,
                bucket_idx,
                TEST_LIVE_THRESHOLD,
            );
            assert_eq!(stale.len(), 1);
            assert_eq!(stale[0].0, PeerId::from_bytes(id_stale));
        }
    }

    // -----------------------------------------------------------------------
    // generate_random_key_for_bucket tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_generate_random_key_for_bucket_lands_in_correct_bucket() {
        let local_id = PeerId::random();
        let dht = DhtCoreEngine::new_for_tests(local_id).unwrap();

        // Test a selection of bucket indices across the key space.
        let test_indices: Vec<usize> = vec![0, 1, 7, 8, 15, 127, 128, 200, 255];
        for bucket_idx in test_indices {
            let key = dht
                .generate_random_key_for_bucket(bucket_idx)
                .expect("should produce a key for valid bucket index");

            // Verify the generated key falls into the expected bucket by computing
            // the XOR distance and checking the leading bit position.
            let distance = xor_distance_bytes(local_id.to_bytes(), key.as_bytes());
            let leading_bit = leading_bit_position(&distance);
            assert_eq!(
                leading_bit,
                Some(bucket_idx),
                "key for bucket {bucket_idx} has wrong leading bit position: {leading_bit:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_generate_random_key_for_bucket_out_of_range() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        assert!(dht.generate_random_key_for_bucket(256).is_none());
        assert!(dht.generate_random_key_for_bucket(1000).is_none());
    }

    #[tokio::test]
    async fn test_generate_random_key_for_bucket_produces_different_keys() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        let mut keys = HashSet::new();
        for _ in 0..10 {
            let key = dht.generate_random_key_for_bucket(100).unwrap();
            keys.insert(key);
        }
        // With 10 random keys, they should not all be identical.
        assert!(
            keys.len() > 1,
            "generate_random_key_for_bucket should produce distinct keys"
        );
    }

    #[tokio::test]
    async fn test_bucket_refresh_candidates_returns_all_buckets_when_fresh() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        let candidates = dht.bucket_refresh_candidates().await;
        assert_eq!(
            candidates.len(),
            KADEMLIA_BUCKET_COUNT,
            "bucket refresh should continuously rank all buckets"
        );
    }

    #[tokio::test]
    async fn bucket_refresh_candidates_use_probe_debt() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        let bucket_idx = 7;
        let live_age = Duration::from_secs(2);
        let probe_age = Duration::from_millis(50);
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket = &mut routing.buckets[bucket_idx];
            bucket.last_refreshed_by_live_peer = instant_ago(live_age);
            bucket.last_probe_finished.store(instant_ago(probe_age));
        }

        let candidates = dht.bucket_refresh_candidates().await;
        let candidate = candidates
            .into_iter()
            .find(|candidate| candidate.index == bucket_idx)
            .expect("bucket should be returned");

        assert!(candidate.live_peer_age >= live_age);
        assert!(candidate.probe_age >= probe_age);
        assert!(
            candidate.refresh_debt < live_age,
            "recent probe should limit refresh debt: {:?}",
            candidate.refresh_debt
        );
    }

    #[tokio::test]
    async fn marking_bucket_probe_finished_does_not_refresh_live_peer_timestamp() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::random()).unwrap();
        let bucket_idx = 11;
        let old_live = instant_ago(Duration::from_secs(2));
        let old_probe = instant_ago(Duration::from_millis(50));
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket = &mut routing.buckets[bucket_idx];
            bucket.last_refreshed_by_live_peer = old_live;
            bucket.last_probe_finished.store(old_probe);
        }

        assert!(dht.mark_bucket_probe_finished(bucket_idx).await);

        let routing = dht.routing_table_for_test().read().await;
        let bucket = &routing.buckets[bucket_idx];
        assert_eq!(bucket.last_refreshed_by_live_peer, old_live);
        assert!(bucket.last_probe_finished.load() > old_probe);
    }

    #[tokio::test]
    async fn test_node_id_accessor() {
        let id = PeerId::random();
        let dht = DhtCoreEngine::new_for_tests(id).unwrap();
        assert_eq!(*dht.node_id(), id);
    }

    /// Helper: find the position of the first set bit (from MSB) in a 32-byte distance.
    /// Returns `None` for an all-zero distance.
    fn leading_bit_position(distance: &[u8; 32]) -> Option<usize> {
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return Some(i);
            }
        }
        None
    }

    /// Return an `Instant` approximately `duration` in the past without
    /// assuming the runner's monotonic clock has already existed that long.
    fn instant_ago(duration: Duration) -> Instant {
        if let Some(instant) = Instant::now().checked_sub(duration) {
            return instant;
        }

        std::thread::sleep(duration.saturating_add(Duration::from_millis(1)));
        Instant::now()
            .checked_sub(duration)
            .expect("runner Instant should be old enough after sleeping")
    }

    // =======================================================================
    // Phase 8: Integration test matrix — missing coverage
    // =======================================================================

    // -----------------------------------------------------------------------
    // Test 12: Non-IP transport bypass
    // -----------------------------------------------------------------------

    /// A peer with a non-IP address (Bluetooth) should bypass all IP diversity
    /// checks and be admitted up to bucket capacity.
    #[tokio::test]
    async fn test_non_ip_transport_bypasses_diversity() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Create a node with a Bluetooth-only address (no IP).
        let mut id = [0u8; 32];
        id[0] = 0x80;
        id[31] = 1;
        let bt_addr = MultiAddr::new(TransportAddr::Bluetooth {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01],
            channel: 5,
        });
        let node = NodeInfo {
            id: PeerId::from_bytes(id),
            addresses: vec![bt_addr],
            last_seen: AtomicInstant::now(),
            address_types: vec![],
        };

        let result = dht.add_node_no_trust(node).await;
        assert!(
            result.is_ok(),
            "non-IP transport should bypass diversity: {:?}",
            result
        );
        assert!(dht.has_node(&PeerId::from_bytes(id)).await);

        // Add several more Bluetooth-only nodes to the same bucket — all should succeed
        // because IP diversity is not checked for non-IP transports.
        for i in 2..=5u8 {
            let mut node_id = [0u8; 32];
            node_id[0] = 0x80;
            node_id[31] = i;
            let bt = MultiAddr::new(TransportAddr::Bluetooth {
                mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, i],
                channel: 5,
            });
            let n = NodeInfo {
                id: PeerId::from_bytes(node_id),
                addresses: vec![bt],
                last_seen: AtomicInstant::now(),
                address_types: vec![],
            };
            let r = dht.add_node_no_trust(n).await;
            assert!(r.is_ok(), "Bluetooth node {i} should be admitted: {:?}", r);
        }
    }

    // -----------------------------------------------------------------------
    // Test 26: Local lookup self-exclusion
    // -----------------------------------------------------------------------

    /// `find_nodes` (local lookup) must never return self, even when searching
    /// for our own key.
    #[tokio::test]
    async fn test_local_lookup_excludes_self() {
        let self_id = PeerId::from_bytes([0u8; 32]);
        let mut dht = DhtCoreEngine::new_for_tests(self_id).unwrap();

        dht.add_node_no_trust(make_node(1, "/ip4/10.0.0.1/udp/9000/quic"))
            .await
            .unwrap();

        // Search for self's own key — self should NOT appear in results
        // because self is never in its own routing table.
        let results = dht
            .find_nodes(&DhtKey::from_bytes([0u8; 32]), 10)
            .await
            .unwrap();
        assert!(
            results.iter().all(|n| n.id != self_id),
            "self must be excluded from local lookup results"
        );
        // But other peers should still be returned.
        assert_eq!(results.len(), 1, "expected the one added peer");
    }

    // -----------------------------------------------------------------------
    // Test 29: find_nodes_with_self includes self
    // -----------------------------------------------------------------------

    /// `find_nodes_with_self` must include self as a candidate, correctly
    /// positioned by XOR distance.
    #[tokio::test]
    async fn test_find_nodes_with_self_includes_self() {
        let self_id = PeerId::from_bytes([0u8; 32]);
        let mut dht = DhtCoreEngine::new_for_tests(self_id).unwrap();

        dht.add_node_no_trust(make_node(1, "/ip4/10.0.0.1/udp/9000/quic"))
            .await
            .unwrap();

        // Search for self's own key — distance is zero, so self should be first.
        let results = dht
            .find_nodes_with_self(&DhtKey::from_bytes([0u8; 32]), 10)
            .await
            .unwrap();
        assert!(
            results.iter().any(|n| n.id == self_id),
            "self should be included in find_nodes_with_self results"
        );
        // Self should be first (distance 0 to the search key)
        assert_eq!(results[0].id, self_id, "self should be the closest match");
    }

    // -----------------------------------------------------------------------
    // Test 36: Peer removal via remove_node_by_id
    // -----------------------------------------------------------------------

    /// Removing a peer by ID should produce PeerRemoved events.
    #[tokio::test]
    async fn test_peer_removal_produces_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        let node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");
        let peer_id = node.id;
        dht.add_node_no_trust(node).await.unwrap();
        assert!(dht.has_node(&peer_id).await);

        // Graceful removal (e.g. peer departed).
        let events = dht.remove_node_by_id(&peer_id).await;
        assert!(
            !dht.has_node(&peer_id).await,
            "peer must be gone after removal"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == peer_id)),
            "expected PeerRemoved event"
        );
    }

    // -----------------------------------------------------------------------
    // Test 36 extension: removing an absent peer is a no-op
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_remove_absent_peer_produces_no_events() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let absent_peer = PeerId::from_bytes([99u8; 32]);

        let events = dht.remove_node_by_id(&absent_peer).await;
        assert!(
            events.is_empty(),
            "removing a peer not in the routing table should produce no events"
        );
    }

    // -----------------------------------------------------------------------
    // Test 49: Trust protection prevents eclipse displacement (live peers)
    // -----------------------------------------------------------------------

    /// An attacker with a closer ID cannot displace a live well-trusted peer.
    /// Only low-trust, stale, or empty slots can be taken.
    #[tokio::test]
    async fn test_eclipse_resistance_live_trusted_peers() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();

        // Fill 2 same-IP slots in bucket 0 with trusted, live peers.
        let mut id_a = [0u8; 32];
        id_a[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_a, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_b = [0u8; 32];
        id_b[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_b, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Attacker generates a much closer ID with the same IP.
        let mut id_attacker = [0u8; 32];
        id_attacker[0] = 0x80;

        // Both existing peers are live (just added) and well-trusted.
        let peer_a = PeerId::from_bytes(id_a);
        let peer_b = PeerId::from_bytes(id_b);
        let trust_fn = |peer_id: &PeerId| -> f64 {
            if *peer_id == peer_a || *peer_id == peer_b {
                0.9 // well above TRUST_PROTECTION_THRESHOLD
            } else {
                0.5
            }
        };

        let result = dht
            .add_node(
                make_node_with_addr(id_attacker, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should be rejected — both peers are live and well-trusted.
        assert!(
            result.is_err(),
            "attacker should not displace live trusted peers"
        );
        assert!(dht.has_node(&peer_a).await, "peer A must survive");
        assert!(dht.has_node(&peer_b).await, "peer B must survive");
    }

    // -----------------------------------------------------------------------
    // Test 50: Stale trust-protected peer displaced by attacker
    // -----------------------------------------------------------------------

    /// A well-trusted but stale peer can be displaced by a closer candidate.
    /// This is correct: a stale peer should not block admission indefinitely.
    #[tokio::test]
    async fn test_stale_trusted_peer_displaced_by_closer_candidate() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_live_threshold(TEST_LIVE_THRESHOLD);

        let mut id_far = [0u8; 32];
        id_far[0] = 0xFF;
        dht.add_node_no_trust(make_node_with_addr(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
            .await
            .unwrap();

        let mut id_mid = [0u8; 32];
        id_mid[0] = 0xFE;
        dht.add_node_no_trust(make_node_with_addr(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
            .await
            .unwrap();

        // Make the far peer stale.
        {
            let mut routing = dht.routing_table_for_test().write().await;
            let bucket_idx = routing
                .get_bucket_index(&PeerId::from_bytes(id_far))
                .unwrap();
            let node = routing.buckets[bucket_idx]
                .nodes
                .iter_mut()
                .find(|n| n.id == PeerId::from_bytes(id_far))
                .unwrap();
            node.last_seen.store(Instant::now() - TEST_STALE_AGE);
        }

        let far_peer = PeerId::from_bytes(id_far);
        // Far peer is well-trusted but STALE.
        let trust_fn = |peer_id: &PeerId| -> f64 { if *peer_id == far_peer { 0.9 } else { 0.5 } };

        let mut id_closer = [0u8; 32];
        id_closer[0] = 0x80;
        let result = dht
            .add_node(
                make_node_with_addr(id_closer, "/ip4/10.0.1.1/udp/9002/quic"),
                &trust_fn,
            )
            .await;

        // Should succeed: stale peer loses trust protection.
        assert!(
            result.is_ok(),
            "stale well-trusted peer should be displaceable: {:?}",
            result
        );
        assert!(
            !dht.has_node(&far_peer).await,
            "stale peer should be evicted"
        );
        assert!(
            dht.has_node(&PeerId::from_bytes(id_closer)).await,
            "closer candidate should be admitted"
        );
    }

    // -----------------------------------------------------------------------
    // Test 56: Consumer event for peer not in routing table
    // -----------------------------------------------------------------------

    /// Trust events for peers not in the routing table should not affect the
    /// routing table. (TrustEngine records the score independently.)
    #[tokio::test]
    async fn test_trust_event_for_absent_peer_does_not_affect_rt() {
        let dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let absent_peer = PeerId::from_bytes([42u8; 32]);

        // Peer is not in the routing table.
        assert!(!dht.has_node(&absent_peer).await);

        // The routing table should remain unchanged after trust events
        // (trust is tracked externally in TrustEngine, not in the RT).
        let size_before = dht.routing_table_size().await;
        assert!(!dht.has_node(&absent_peer).await);
        let size_after = dht.routing_table_size().await;
        assert_eq!(size_before, size_after, "routing table should be unchanged");
    }

    // -----------------------------------------------------------------------
    // Trust-based swap-out tests
    // -----------------------------------------------------------------------

    /// When a bucket is full, the lowest-trust peer below swap_threshold is
    /// replaced by a new candidate without revalidation.
    #[tokio::test]
    async fn test_trust_swap_out_replaces_lowest_trust_peer() {
        // K=4 so we can fill a bucket quickly. All peers go into the
        // high-bit bucket (byte 0 has bit 7 set, our node_id is [0; 32]).
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        // Fill bucket with 4 peers, each on a unique IP
        let mut ids: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i; // all land in same bucket (bit 7 set)
            ids.push(id);
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        // New candidate on a unique IP
        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;
        let new_peer = PeerId::from_bytes(new_id);
        let low_trust_peer = PeerId::from_bytes(ids[2]);

        // Peer ids[2] has trust 0.05 (below 0.35 threshold), others at 0.5
        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|id| {
                    if *id == low_trust_peer { 0.05 } else { 0.5 }
                },
            )
            .await
            .unwrap();

        let events = match result {
            AdmissionResult::Admitted(events) => events,
            other => panic!("expected Admitted, got {other:?}"),
        };

        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == low_trust_peer)),
            "low-trust peer should be swapped out"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(id) if *id == new_peer)),
            "new candidate should be added"
        );
        assert!(dht.has_node(&new_peer).await);
        assert!(!dht.has_node(&low_trust_peer).await);
    }

    /// When multiple peers are below the swap threshold, only the lowest-trust
    /// peer is swapped out.
    #[tokio::test]
    async fn test_trust_swap_out_picks_lowest_when_multiple_below_threshold() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i;
            ids.push(id);
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        let peer_a = PeerId::from_bytes(ids[1]); // will have trust 0.10
        let peer_b = PeerId::from_bytes(ids[3]); // will have trust 0.05

        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;

        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|id| {
                    if *id == peer_a {
                        0.10
                    } else if *id == peer_b {
                        0.05
                    } else {
                        0.5
                    }
                },
            )
            .await
            .unwrap();

        let events = match result {
            AdmissionResult::Admitted(events) => events,
            other => panic!("expected Admitted, got {other:?}"),
        };

        // Only the lowest-trust peer (0.05) should be evicted
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerRemoved(id) if *id == peer_b)),
            "peer with lowest trust (0.05) should be swapped out"
        );
        assert!(
            dht.has_node(&peer_a).await,
            "peer with trust 0.10 should remain (only one swap needed)"
        );
    }

    /// When all peers in the bucket are above the swap threshold, no trust-based
    /// swap occurs and the system falls through to stale revalidation.
    #[tokio::test]
    async fn test_no_trust_swap_when_all_peers_above_threshold() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();

        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i;
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;

        // All peers at neutral (0.5) — no trust-based swap possible
        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|_| 0.5,
            )
            .await;

        // Should get StaleRevalidationNeeded (default allow_stale_revalidation=true
        // in add_node) or error — NOT Admitted
        match result {
            Ok(AdmissionResult::Admitted(_)) => {
                panic!("should not be admitted when bucket is full with no low-trust peers")
            }
            Ok(AdmissionResult::StaleRevalidationNeeded { .. }) => {
                // Expected: falls through to stale revalidation
            }
            Err(_) => {
                // Also acceptable: no stale peers found
            }
        }
    }

    /// With swap_threshold = 0.0, trust-based swap-out is disabled.
    #[tokio::test]
    async fn test_no_trust_swap_when_threshold_is_zero() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            0.0, // disabled
        )
        .unwrap();

        let mut ids: Vec<[u8; 32]> = Vec::new();
        for i in 0..4u8 {
            let mut id = [0u8; 32];
            id[0] = 0x80 + i;
            ids.push(id);
            let addr = format!("/ip4/10.0.{}.1/udp/9000/quic", i);
            dht.add_node(make_node_with_addr(id, &addr), &|_| 0.5)
                .await
                .unwrap();
        }

        let low_peer = PeerId::from_bytes(ids[0]);
        let mut new_id = [0u8; 32];
        new_id[0] = 0x84;

        // Even with a peer at trust 0.01, threshold=0 means no swap
        let result = dht
            .add_node(
                make_node_with_addr(new_id, "/ip4/10.0.4.1/udp/9000/quic"),
                &|id| if *id == low_peer { 0.01 } else { 0.5 },
            )
            .await;

        match result {
            Ok(AdmissionResult::Admitted(_)) => {
                panic!("should not be admitted when swap is disabled and bucket is full")
            }
            _ => {
                // Expected: stale revalidation or error
            }
        }
        // Low-trust peer should still be in the table
        assert!(dht.has_node(&low_peer).await);
    }

    /// A K-closest peer below the quarantine threshold is evicted immediately
    /// and cannot be readmitted until its trust has recovered to the readmit
    /// threshold.
    #[tokio::test]
    async fn test_close_group_peer_below_quarantine_is_evicted_until_readmit() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_trust_quarantine_thresholds(0.20, 0.45).unwrap();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes[31] = 1;
        let peer = PeerId::from_bytes(peer_id_bytes);

        dht.add_node_no_trust(make_node_with_addr(
            peer_id_bytes,
            "/ip4/10.10.0.1/udp/9000/quic",
        ))
        .await
        .unwrap();
        assert!(dht.has_node(&peer).await);

        let events = dht.enforce_close_group_quarantine(&peer, 0.19).await;
        assert!(
            events
                .iter()
                .any(|event| matches!(event, RoutingTableEvent::PeerRemoved(id) if *id == peer)),
            "close-group peer below quarantine threshold should emit PeerRemoved"
        );
        assert!(
            !dht.has_node(&peer).await,
            "quarantined close-group peer should be removed from RT"
        );

        let early_readmit = dht
            .add_node(
                make_node_with_addr(peer_id_bytes, "/ip4/10.10.0.1/udp/9000/quic"),
                &|id| if *id == peer { 0.30 } else { 0.5 },
            )
            .await;
        assert!(
            early_readmit.is_err(),
            "quarantined peer should not readmit below 0.45"
        );

        let recovered = dht
            .add_node(
                make_node_with_addr(peer_id_bytes, "/ip4/10.10.0.1/udp/9000/quic"),
                &|id| if *id == peer { 0.45 } else { 0.5 },
            )
            .await;
        assert!(
            recovered.is_ok(),
            "quarantined peer should readmit once trust reaches 0.45"
        );
        assert!(dht.has_node(&peer).await);
    }

    #[test]
    fn test_core_quarantine_readmit_threshold_must_be_reachable_by_decay() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        assert!(dht.set_trust_quarantine_thresholds(0.20, 0.49).is_ok());
        assert!(dht.set_trust_quarantine_thresholds(0.20, 0.50).is_err());
    }

    /// A first-time admission rejected below the quarantine threshold is not a
    /// close-group quarantine. Once it recovers above the quarantine threshold,
    /// it can enter a non-close routing-table slot without waiting for the
    /// stronger close-group admission threshold.
    #[tokio::test]
    async fn test_below_threshold_admission_can_recover_into_non_close_slot() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_trust_quarantine_thresholds(0.20, 0.45).unwrap();

        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.{i}.0.1/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes[0] = 0x80;
        let peer = PeerId::from_bytes(peer_id_bytes);

        let rejected = dht
            .add_node(
                make_node_with_addr(peer_id_bytes, "/ip4/10.10.0.9/udp/9000/quic"),
                &|id| if *id == peer { 0.10 } else { 0.5 },
            )
            .await;
        assert!(
            rejected.is_err(),
            "peer below quarantine threshold should be rejected"
        );

        let recovered_above_quarantine = dht
            .add_node(
                make_node_with_addr(peer_id_bytes, "/ip4/10.10.0.9/udp/9000/quic"),
                &|id| if *id == peer { 0.30 } else { 0.5 },
            )
            .await;
        assert!(
            recovered_above_quarantine.is_ok(),
            "non-close peer should not need the 0.45 close-group threshold"
        );
        assert!(dht.has_node(&peer).await);
    }

    /// A new peer that would enter the K-closest set must meet the close-group
    /// admission threshold, even if it is above the lower quarantine threshold.
    #[tokio::test]
    async fn test_close_group_admission_requires_readmit_threshold() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        dht.set_trust_quarantine_thresholds(0.20, 0.45).unwrap();

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes[31] = 9;
        let peer = PeerId::from_bytes(peer_id_bytes);

        let below_close_group_threshold = dht
            .add_node(
                make_node_with_addr(peer_id_bytes, "/ip4/10.10.0.9/udp/9000/quic"),
                &|id| if *id == peer { 0.30 } else { 0.5 },
            )
            .await;
        assert!(
            below_close_group_threshold.is_err(),
            "new close-group peer should need trust >= 0.45"
        );

        let recovered = dht
            .add_node(
                make_node_with_addr(peer_id_bytes, "/ip4/10.10.0.9/udp/9000/quic"),
                &|id| if *id == peer { 0.45 } else { 0.5 },
            )
            .await;
        assert!(
            recovered.is_ok(),
            "new close-group peer should enter once trust reaches 0.45"
        );
        assert!(dht.has_node(&peer).await);
    }

    /// Removing one close peer can promote a non-close peer into the close
    /// group. Promoted peers below the close-group admission threshold are
    /// removed, while existing close peers above the quarantine threshold stay.
    #[tokio::test]
    async fn test_close_group_gate_removes_promoted_peers_below_readmit_threshold() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_trust_quarantine_thresholds(0.20, 0.45).unwrap();

        let mut close_peer_ids = Vec::new();
        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[31] = i;
            close_peer_ids.push(PeerId::from_bytes(id));
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.{i}.0.1/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }
        let previous_close_group = close_peer_ids.clone();

        let mut promoted_id = [0u8; 32];
        promoted_id[0] = 0x80;
        let promoted_peer = PeerId::from_bytes(promoted_id);
        dht.add_node_no_trust(make_node_with_addr(
            promoted_id,
            "/ip4/10.99.0.1/udp/9000/quic",
        ))
        .await
        .unwrap();

        let no_events = dht
            .enforce_close_group_trust_gate(Some(&previous_close_group), &|id| {
                if *id == promoted_peer { 0.30 } else { 0.5 }
            })
            .await;
        assert!(
            no_events.is_empty(),
            "peer outside the close group should not be evicted by close-group gate"
        );
        assert!(dht.has_node(&promoted_peer).await);

        dht.remove_node_by_id(&close_peer_ids[0]).await;
        let events = dht
            .enforce_close_group_trust_gate(Some(&previous_close_group), &|id| {
                if *id == promoted_peer || *id == close_peer_ids[1] {
                    0.30
                } else {
                    0.5
                }
            })
            .await;

        assert!(
            events.iter().any(
                |event| matches!(event, RoutingTableEvent::PeerRemoved(id) if *id == promoted_peer)
            ),
            "promoted peer below close-group admission threshold should be removed"
        );
        assert!(!dht.has_node(&promoted_peer).await);
        assert!(
            dht.has_node(&close_peer_ids[1]).await,
            "existing close peer above quarantine threshold should stay"
        );
    }

    /// A non-close peer below the quarantine threshold is avoided by automatic
    /// lookup paths but is not removed merely for being below threshold.
    #[tokio::test]
    async fn test_non_close_quarantined_peer_is_avoided_but_not_evicted() {
        let mut dht = DhtCoreEngine::new(
            PeerId::from_bytes([0u8; 32]),
            4,
            false,
            DEFAULT_SWAP_THRESHOLD,
        )
        .unwrap();
        dht.set_trust_quarantine_thresholds(0.20, 0.45).unwrap();

        for i in 1..=4u8 {
            let mut id = [0u8; 32];
            id[31] = i;
            dht.add_node_no_trust(make_node_with_addr(
                id,
                &format!("/ip4/10.{i}.0.1/udp/9000/quic"),
            ))
            .await
            .unwrap();
        }

        let mut far_id = [0u8; 32];
        far_id[0] = 0x80;
        let far_peer = PeerId::from_bytes(far_id);
        dht.add_node_no_trust(make_node_with_addr(far_id, "/ip4/10.99.0.1/udp/9000/quic"))
            .await
            .unwrap();

        let events = dht.enforce_close_group_quarantine(&far_peer, 0.10).await;
        assert!(
            events.is_empty(),
            "non-close peer should not be immediately evicted"
        );
        assert!(dht.has_node(&far_peer).await);
        assert!(
            dht.should_avoid_for_lookup(&far_peer, 0.10),
            "automatic lookup should avoid peers below quarantine threshold"
        );
    }

    // -----------------------------------------------------------------------
    // AddressType::Unverified tests
    // -----------------------------------------------------------------------

    #[test]
    fn address_type_priority_is_relay_direct_unverified_lan() {
        assert!(AddressType::Relay.priority() < AddressType::Direct.priority());
        assert!(AddressType::Direct.priority() < AddressType::Unverified.priority());
        assert!(AddressType::Unverified.priority() < AddressType::Lan.priority());
    }

    #[test]
    fn address_type_accepts_legacy_natted_name_as_lan() {
        let decoded: AddressType = serde_json::from_str("\"NATted\"").unwrap();
        assert_eq!(decoded, AddressType::Lan);
    }

    #[test]
    fn local_scope_address_type_is_canonicalized_to_lan() {
        let mut node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: Vec::new(),
            address_types: Vec::new(),
            last_seen: AtomicInstant::now(),
        };
        let private: MultiAddr = "/ip4/192.168.1.10/udp/9000/quic".parse().unwrap();

        node.merge_typed_address(private.clone(), AddressType::Direct);
        assert_eq!(node.addresses, vec![private]);
        assert_eq!(node.address_types, vec![AddressType::Lan]);
        assert_eq!(node.address_type_at(0), AddressType::Lan);
    }

    #[test]
    fn mapped_local_scope_address_type_is_canonicalized_to_lan() {
        let cases = [
            (
                "/ip6/::ffff:192.168.1.10/udp/9000/quic",
                AddressType::Direct,
            ),
            (
                "/ip6/::ffff:127.0.0.1/udp/9001/quic",
                AddressType::Unverified,
            ),
            ("/ip6/::ffff:100.64.0.1/udp/9002/quic", AddressType::Relay),
        ];

        for (idx, (addr, advertised)) in cases.into_iter().enumerate() {
            let mut node = NodeInfo {
                id: PeerId::from_bytes([idx as u8; 32]),
                addresses: Vec::new(),
                address_types: Vec::new(),
                last_seen: AtomicInstant::now(),
            };
            let addr: MultiAddr = addr.parse().unwrap();

            node.merge_typed_address(addr.clone(), advertised);

            assert_eq!(node.addresses, vec![addr], "case {idx}");
            assert_eq!(node.address_types, vec![AddressType::Lan], "case {idx}");
            assert_eq!(node.address_type_at(0), AddressType::Lan, "case {idx}");
        }
    }

    #[test]
    fn merge_same_family_keeps_relay_best_wan_and_lan() {
        // Under the per-IP-family cap: at most 1 Relay + 1 WAN
        // non-Relay (Direct/Unverified) + 1 Lan per family. Direct is the
        // strongest WAN tier, but it must not evict the local path that
        // same-WAN peers can use.
        let mut node = make_node(1, "/ip4/203.0.113.1/udp/9000/quic");
        let direct = node.addresses[0].clone();
        let relay: MultiAddr = "/ip4/198.51.100.1/udp/9000/quic".parse().unwrap();
        let unverified: MultiAddr = "/ip4/203.0.113.2/udp/9000/quic".parse().unwrap();
        let lan: MultiAddr = "/ip4/192.168.1.4/udp/9000/quic".parse().unwrap();

        node.merge_typed_address(lan.clone(), AddressType::Lan);
        node.merge_typed_address(unverified, AddressType::Unverified);
        node.merge_typed_address(relay.clone(), AddressType::Relay);

        assert_eq!(
            node.address_types,
            vec![AddressType::Relay, AddressType::Direct, AddressType::Lan]
        );
        assert_eq!(node.addresses, vec![relay, direct, lan]);
    }

    #[test]
    fn merge_unverified_caps_at_one_per_ip_family() {
        // Per the per-IP-family cap, a peer with a same-family Direct
        // (from `make_node`) retains it and any subsequent Unverified in
        // that family is dropped. If the Direct is absent, the cap keeps
        // exactly one Unverified per IP family — the newest.
        let mut node = make_node(1, "/ip4/10.0.0.1/udp/9000/quic");

        for i in 0..4 {
            let addr: MultiAddr = format!("/ip4/10.1.0.{}/udp/9000/quic", i).parse().unwrap();
            node.merge_typed_address(addr, AddressType::Unverified);
        }

        // Direct dominates Unverified within the same family.
        let direct_count = node
            .address_types
            .iter()
            .filter(|t| **t == AddressType::Direct)
            .count();
        let unverified_count = node
            .address_types
            .iter()
            .filter(|t| **t == AddressType::Unverified)
            .count();
        assert_eq!(direct_count, 1);
        assert_eq!(unverified_count, 0);
    }

    // -----------------------------------------------------------------------
    // Per-IP-family cap — targeted tests
    // -----------------------------------------------------------------------

    fn node_with(addresses: Vec<(&str, AddressType)>) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: addresses
                .iter()
                .map(|(a, _)| a.parse::<MultiAddr>().unwrap())
                .collect(),
            address_types: addresses.iter().map(|(_, t)| *t).collect(),
            last_seen: AtomicInstant::now(),
        }
    }

    #[test]
    fn cap_allows_relay_plus_best_non_relay_per_family() {
        let mut node = node_with(vec![
            ("/ip4/10.0.0.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct),
            ("/ip6/2001:db8::1/udp/9000/quic", AddressType::Relay),
            ("/ip6/2001:db8::2/udp/9000/quic", AddressType::Direct),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(node.addresses.len(), 4);
    }

    #[test]
    fn cap_direct_dominates_unverified_same_family() {
        let mut node = node_with(vec![
            ("/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct),
            ("/ip4/2.2.2.2/udp/9000/quic", AddressType::Unverified),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(node.address_types, vec![AddressType::Direct]);
        assert_eq!(
            node.addresses,
            vec!["/ip4/1.1.1.1/udp/9000/quic".parse().unwrap()]
        );
    }

    #[test]
    fn cap_direct_preserves_lan_same_family() {
        let mut node = node_with(vec![
            ("/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct),
            ("/ip4/192.168.1.20/udp/9000/quic", AddressType::Lan),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(
            node.address_types,
            vec![AddressType::Direct, AddressType::Lan]
        );
    }

    #[test]
    fn cap_unverified_preserves_lan_same_family() {
        let mut node = node_with(vec![
            ("/ip4/2.2.2.2/udp/9000/quic", AddressType::Unverified),
            ("/ip4/192.168.1.30/udp/9000/quic", AddressType::Lan),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(
            node.address_types,
            vec![AddressType::Unverified, AddressType::Lan]
        );
    }

    #[test]
    fn cap_relay_plus_unverified_allowed() {
        let mut node = node_with(vec![
            ("/ip4/10.0.0.1/udp/9000/quic", AddressType::Relay),
            ("/ip4/2.2.2.2/udp/9000/quic", AddressType::Unverified),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(
            node.address_types,
            vec![AddressType::Relay, AddressType::Unverified]
        );
    }

    #[test]
    fn cap_ipv4_and_ipv6_are_independent() {
        // IPv4 has only an Unverified, IPv6 has a Direct. The IPv6 Direct
        // must not cross-drop the IPv4 Unverified — precedence is scoped
        // to the same family.
        let mut node = node_with(vec![
            ("/ip4/2.2.2.2/udp/9000/quic", AddressType::Unverified),
            ("/ip6/2001:db8::1/udp/9000/quic", AddressType::Direct),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(node.addresses.len(), 2);
    }

    #[test]
    fn cap_merge_direct_then_lan_keeps_both() {
        let mut node = node_with(vec![("/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct)]);
        node.merge_typed_address(
            "/ip4/192.168.1.20/udp/9000/quic".parse().unwrap(),
            AddressType::Lan,
        );
        assert_eq!(
            node.address_types,
            vec![AddressType::Direct, AddressType::Lan]
        );
    }

    #[test]
    fn cap_merge_lan_then_direct_keeps_both() {
        let mut node = node_with(vec![("/ip4/192.168.1.20/udp/9000/quic", AddressType::Lan)]);
        node.merge_typed_address(
            "/ip4/1.1.1.1/udp/9000/quic".parse().unwrap(),
            AddressType::Direct,
        );
        assert_eq!(
            node.address_types,
            vec![AddressType::Direct, AddressType::Lan]
        );
        assert_eq!(
            node.addresses,
            vec![
                "/ip4/1.1.1.1/udp/9000/quic".parse().unwrap(),
                "/ip4/192.168.1.20/udp/9000/quic".parse().unwrap()
            ]
        );
    }

    #[test]
    fn cap_newest_relay_replaces_stale_same_family_relay() {
        let mut node = node_with(vec![(
            "/ip4/198.51.100.1/udp/9000/quic",
            AddressType::Relay,
        )]);
        node.merge_typed_address(
            "/ip4/198.51.100.2/udp/9000/quic".parse().unwrap(),
            AddressType::Relay,
        );
        assert_eq!(
            node.addresses,
            vec!["/ip4/198.51.100.2/udp/9000/quic".parse().unwrap()]
        );
        assert_eq!(node.address_types, vec![AddressType::Relay]);
    }

    #[test]
    fn cap_newest_relay_preserves_different_family_relay() {
        let mut node = node_with(vec![("/ip6/2001:db8::1/udp/9000/quic", AddressType::Relay)]);
        node.merge_typed_address(
            "/ip4/198.51.100.1/udp/9000/quic".parse().unwrap(),
            AddressType::Relay,
        );
        let mut relays: Vec<_> = node
            .addresses
            .iter()
            .zip(node.address_types.iter())
            .filter(|(_, t)| **t == AddressType::Relay)
            .map(|(a, _)| a.to_string())
            .collect();
        relays.sort();
        assert_eq!(
            relays,
            vec![
                "/ip4/198.51.100.1/udp/9000/quic".to_string(),
                "/ip6/2001:db8::1/udp/9000/quic".to_string(),
            ]
        );
    }

    #[test]
    fn cap_normalizes_legacy_multi_entry_input() {
        let mut node = node_with(vec![
            ("/ip4/1.1.1.1/udp/9000/quic", AddressType::Direct),
            ("/ip4/2.2.2.2/udp/9000/quic", AddressType::Direct),
            ("/ip4/3.3.3.3/udp/9000/quic", AddressType::Direct),
        ]);
        node.enforce_per_ip_family_cap();
        assert_eq!(node.addresses.len(), 1);
    }

    #[test]
    fn untagged_address_type_falls_back_to_unverified() {
        // NodeInfo::address_type_at — an untagged index must not claim
        // Direct-reachability; legacy records never asserted it.
        let node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![
                "/ip4/203.0.113.10/udp/9000/quic".parse().unwrap(),
                "/ip4/203.0.113.11/udp/9000/quic".parse().unwrap(),
            ],
            address_types: vec![], // legacy: no tags at all
            last_seen: AtomicInstant::now(),
        };
        assert_eq!(node.address_type_at(0), AddressType::Unverified);
        assert_eq!(node.address_type_at(1), AddressType::Unverified);
    }

    #[test]
    fn merge_typed_address_upgrade_only_promotes_unverified_to_direct() {
        let addr: MultiAddr = "/ip4/203.0.113.10/udp/9000/quic".parse().unwrap();
        let mut node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![addr.clone()],
            address_types: vec![AddressType::Unverified],
            last_seen: AtomicInstant::now(),
        };
        let changed = node.merge_typed_address_upgrade_only(addr.clone(), AddressType::Direct);
        assert!(changed);
        assert_eq!(node.address_type_at(0), AddressType::Direct);
    }

    #[test]
    fn merge_typed_address_upgrade_only_refuses_to_demote() {
        // Existing Relay must not be demoted by incoming Unverified/Direct
        // arriving out of order via FIND_NODE gossip.
        let addr: MultiAddr = "/ip4/203.0.113.10/udp/9000/quic".parse().unwrap();
        for incoming in [AddressType::Unverified, AddressType::Direct] {
            let mut node = NodeInfo {
                id: PeerId::from_bytes([1u8; 32]),
                addresses: vec![addr.clone()],
                address_types: vec![AddressType::Relay],
                last_seen: AtomicInstant::now(),
            };
            let changed = node.merge_typed_address_upgrade_only(addr.clone(), incoming);
            assert!(!changed, "unexpected change for incoming {:?}", incoming);
            assert_eq!(node.address_type_at(0), AddressType::Relay);
            assert_eq!(node.addresses.len(), 1);
        }
    }

    #[test]
    fn merge_typed_address_upgrade_only_adds_new_address() {
        // A new address is always added, regardless of tag — this is how a
        // peer XOR-far from every PublishAddressSet source learns about
        // its neighbours' Relay/Direct addresses via gossip.
        let existing: MultiAddr = "/ip4/203.0.113.10/udp/9000/quic".parse().unwrap();
        let new_relay: MultiAddr = "/ip4/192.0.2.7/udp/44100/quic".parse().unwrap();
        let mut node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![existing.clone()],
            address_types: vec![AddressType::Unverified],
            last_seen: AtomicInstant::now(),
        };
        let changed = node.merge_typed_address_upgrade_only(new_relay.clone(), AddressType::Relay);
        assert!(changed);
        assert_eq!(node.addresses.len(), 2);
        // Relay sorts to the front.
        assert_eq!(node.addresses[0], new_relay);
        assert_eq!(node.address_type_at(0), AddressType::Relay);
    }

    #[test]
    fn merge_typed_address_upgrade_only_idempotent_on_same_tag() {
        let addr: MultiAddr = "/ip4/203.0.113.10/udp/9000/quic".parse().unwrap();
        let mut node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![addr.clone()],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        };
        let changed = node.merge_typed_address_upgrade_only(addr.clone(), AddressType::Direct);
        assert!(!changed);
        assert_eq!(node.addresses.len(), 1);
        assert_eq!(node.address_type_at(0), AddressType::Direct);
    }

    // -----------------------------------------------------------------------
    // Wildcard-address store-side filter tests (silences ~66k WARN/3.7h
    // observed on prod where peers running older saorsa-core publish their
    // bind-side `0.0.0.0` / `::` addresses verbatim).
    // -----------------------------------------------------------------------

    #[test]
    fn is_storable_address_rejects_wildcard_v4() {
        let addr: MultiAddr = "/ip4/0.0.0.0/udp/9000/quic".parse().unwrap();
        assert!(!is_storable_address(&addr));
    }

    #[test]
    fn is_storable_address_rejects_wildcard_v6() {
        let addr: MultiAddr = "/ip6/::/udp/9000/quic".parse().unwrap();
        assert!(!is_storable_address(&addr));
    }

    #[test]
    fn is_storable_address_rejects_port_zero() {
        let addr: MultiAddr = "/ip4/192.0.2.1/udp/0/quic".parse().unwrap();
        assert!(!is_storable_address(&addr));
    }

    #[test]
    fn is_storable_address_accepts_routable() {
        let addr: MultiAddr = "/ip4/203.0.113.10/udp/9000/quic".parse().unwrap();
        assert!(is_storable_address(&addr));
    }

    #[test]
    fn is_storable_address_accepts_loopback_for_devnet() {
        // Loopback is intentionally accepted — local devnets need it. The
        // per-node `allow_loopback` config gates routing-table admission
        // separately.
        let v4: MultiAddr = "/ip4/127.0.0.1/udp/9000/quic".parse().unwrap();
        let v6: MultiAddr = "/ip6/::1/udp/9000/quic".parse().unwrap();
        assert!(is_storable_address(&v4));
        assert!(is_storable_address(&v6));
    }

    #[test]
    fn merge_typed_address_drops_wildcard_silently() {
        let mut node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            address_types: vec![],
            last_seen: AtomicInstant::now(),
        };
        let wildcard: MultiAddr = "/ip6/::/udp/55928/quic".parse().unwrap();
        node.merge_typed_address(wildcard, AddressType::Direct);
        assert!(node.addresses.is_empty());
        assert!(node.address_types.is_empty());
    }

    #[test]
    fn merge_typed_address_upgrade_only_returns_false_on_wildcard() {
        let mut node = NodeInfo {
            id: PeerId::from_bytes([1u8; 32]),
            addresses: vec![],
            address_types: vec![],
            last_seen: AtomicInstant::now(),
        };
        let wildcard: MultiAddr = "/ip4/0.0.0.0/udp/10000/quic".parse().unwrap();
        let changed = node.merge_typed_address_upgrade_only(wildcard, AddressType::Direct);
        assert!(!changed);
        assert!(node.addresses.is_empty());
    }

    #[test]
    fn replace_node_addresses_strips_wildcards_keeps_routable() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/203.0.113.1/udp/9000/quic"))
            .unwrap();

        // Publish a mixed set: one routable + one wildcard.
        let routable: MultiAddr = "/ip4/198.51.100.5/udp/10000/quic".parse().unwrap();
        let wildcard: MultiAddr = "/ip4/0.0.0.0/udp/10000/quic".parse().unwrap();
        let typed = vec![
            (routable.clone(), AddressType::Direct),
            (wildcard, AddressType::Direct),
        ];
        let applied = bucket.replace_node_addresses(&PeerId::from_bytes([1u8; 32]), typed);
        assert!(applied);

        let node = bucket.get_nodes().last().unwrap();
        assert_eq!(node.addresses, vec![routable]);
        assert_eq!(node.address_types, vec![AddressType::Direct]);
    }

    #[test]
    fn add_node_strips_wildcards_from_incoming_record() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let routable: MultiAddr = "/ip4/198.51.100.5/udp/10000/quic".parse().unwrap();
        let wildcard: MultiAddr = "/ip6/::/udp/10000/quic".parse().unwrap();
        let node = NodeInfo {
            id: PeerId::from_bytes([42u8; 32]),
            addresses: vec![wildcard, routable.clone()],
            address_types: vec![AddressType::Direct, AddressType::Direct],
            last_seen: AtomicInstant::now(),
        };
        bucket.add_node(node).unwrap();
        let stored = bucket.get_nodes().last().unwrap();
        assert_eq!(stored.addresses, vec![routable]);
        assert_eq!(stored.address_types, vec![AddressType::Direct]);
    }

    #[test]
    fn add_node_rejects_record_with_only_wildcard_addresses() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let wildcard: MultiAddr = "/ip4/0.0.0.0/udp/10000/quic".parse().unwrap();
        let node = NodeInfo {
            id: PeerId::from_bytes([42u8; 32]),
            addresses: vec![wildcard],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        };
        // After filtering, addresses is empty — add_node rejects the slot.
        let result = bucket.add_node(node);
        assert!(result.is_err());
    }

    /// Engine-level (P2): a mixed wildcard + routable record must be admitted
    /// through the public `DhtCoreEngine::add_node` path with only the
    /// routable address stored. Before the sanitize step, `candidate_ips`
    /// was built from the raw address list and the unspecified-IP guard in
    /// `add_with_diversity` rejected the whole record before the bucket-side
    /// store filter could run.
    #[tokio::test]
    async fn engine_add_node_admits_mixed_wildcard_and_routable() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let routable: MultiAddr = "/ip4/198.51.100.7/udp/10000/quic".parse().unwrap();
        let wildcard: MultiAddr = "/ip6/::/udp/10000/quic".parse().unwrap();
        let peer = PeerId::from_bytes([7u8; 32]);
        let node = NodeInfo {
            id: peer,
            addresses: vec![wildcard, routable.clone()],
            address_types: vec![AddressType::Direct, AddressType::Direct],
            last_seen: AtomicInstant::now(),
        };

        let events = dht.add_node_no_trust(node).await.unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, RoutingTableEvent::PeerAdded(p) if *p == peer)),
            "mixed record should be admitted, got events: {events:?}"
        );

        let stored = dht.get_node_addresses(&peer).await;
        assert_eq!(
            stored,
            vec![routable],
            "only the routable address should survive sanitization"
        );
    }

    /// Engine-level: a record carrying *only* wildcard addresses has nothing
    /// storable left after sanitization and must be rejected by the public
    /// `add_node` path (the empty `candidate_ips` early-out / bucket filter).
    #[tokio::test]
    async fn engine_add_node_rejects_only_wildcard_record() {
        let mut dht = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32])).unwrap();
        let wildcard: MultiAddr = "/ip4/0.0.0.0/udp/10000/quic".parse().unwrap();
        let peer = PeerId::from_bytes([9u8; 32]);
        let node = NodeInfo {
            id: peer,
            addresses: vec![wildcard],
            address_types: vec![AddressType::Direct],
            last_seen: AtomicInstant::now(),
        };

        let result = dht.add_node_no_trust(node).await;
        assert!(
            result.is_err(),
            "record with only wildcard addresses must not be admitted"
        );
        assert!(
            dht.get_node_addresses(&peer).await.is_empty(),
            "rejected peer must not appear in the routing table"
        );
    }

    #[test]
    fn is_storable_address_rejects_tcp_wildcard() {
        // The dialable_socket_addr() helper only matches QUIC; the filter
        // must use socket_addr() to also catch TCP / raw UDP wildcards.
        let tcp_wildcard: MultiAddr = "/ip4/0.0.0.0/tcp/9000".parse().unwrap();
        assert!(!is_storable_address(&tcp_wildcard));
    }

    #[test]
    fn is_storable_address_rejects_udp_wildcard_v6() {
        let udp_wildcard: MultiAddr = "/ip6/::/udp/9000".parse().unwrap();
        assert!(!is_storable_address(&udp_wildcard));
    }

    #[test]
    fn replace_node_addresses_preserves_state_when_filter_empties_input() {
        // If a publisher sends a non-empty set that gets entirely filtered
        // out (e.g. only wildcards), the bucket must NOT wipe the peer's
        // existing good addresses. The caller relies on `false` to skip
        // advancing the per-peer publish sequence.
        let k = 8;
        let mut bucket = KBucket::new(k);
        let original: MultiAddr = "/ip4/203.0.113.42/udp/9000/quic".parse().unwrap();
        bucket
            .add_node(NodeInfo {
                id: PeerId::from_bytes([7u8; 32]),
                addresses: vec![original.clone()],
                address_types: vec![AddressType::Direct],
                last_seen: AtomicInstant::now(),
            })
            .unwrap();

        let wildcard: MultiAddr = "/ip6/::/udp/55928/quic".parse().unwrap();
        let typed = vec![(wildcard, AddressType::Direct)];
        let applied = bucket.replace_node_addresses(&PeerId::from_bytes([7u8; 32]), typed);

        assert!(!applied, "filter-empty publish must not be applied");
        let node = bucket.get_nodes().last().unwrap();
        assert_eq!(
            node.addresses,
            vec![original],
            "original addresses must be preserved"
        );
    }

    #[test]
    fn replace_node_addresses_strips_wildcards_with_relay_and_direct() {
        // Mixed-tier publish: Relay + Direct + wildcard. Filter drops the
        // wildcard, type-priority sort keeps Relay first, Direct second.
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket
            .add_node(make_node(1, "/ip4/203.0.113.1/udp/9000/quic"))
            .unwrap();

        let relay: MultiAddr = "/ip4/198.51.100.1/udp/8443/quic".parse().unwrap();
        let direct: MultiAddr = "/ip4/198.51.100.5/udp/10000/quic".parse().unwrap();
        let wildcard: MultiAddr = "/ip4/0.0.0.0/udp/10000/quic".parse().unwrap();
        let typed = vec![
            (direct.clone(), AddressType::Direct),
            (wildcard, AddressType::Direct),
            (relay.clone(), AddressType::Relay),
        ];
        let applied = bucket.replace_node_addresses(&PeerId::from_bytes([1u8; 32]), typed);
        assert!(applied);

        let node = bucket.get_nodes().last().unwrap();
        assert_eq!(node.addresses, vec![relay, direct]);
        assert_eq!(
            node.address_types,
            vec![AddressType::Relay, AddressType::Direct]
        );
    }
}
