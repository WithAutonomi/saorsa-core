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

//! Portable DHT peer records, address priorities, and witnessed lookup results.

use crate::address::is_lan_ip;
use crate::{Key, MultiAddr, PeerId};
use saorsa_dht_lookup::LookupNode;
use serde::{Deserialize, Serialize};

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
    /// Used by `NodeInfo::merge_typed_address`, `KBucket::replace_node_addresses`,
    /// [`DHTNode::addresses_by_priority`], and `DhtNetworkManager::dialable_addresses_typed`
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

impl LookupNode for DHTNode {
    fn lookup_peer_id(&self) -> [u8; 32] {
        *self.peer_id.as_bytes()
    }
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
    /// `DhtNetworkManager::dialable_addresses_typed` or use
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
    /// `DhtNetworkManager::find_closest_nodes_network`: different
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

pub(crate) fn encode_publish_seq_distance(seq: u64) -> Option<Vec<u8>> {
    if seq == 0 {
        return None;
    }
    let mut encoded = Vec::with_capacity(PUBLISH_SEQ_DISTANCE_MARKER.len() + 8);
    encoded.extend_from_slice(PUBLISH_SEQ_DISTANCE_MARKER);
    encoded.extend_from_slice(&seq.to_be_bytes());
    Some(encoded)
}

pub(crate) fn dht_node_publish_seq(node: &DHTNode) -> u64 {
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
#[cfg(feature = "native")]
pub type SerializableDHTNode = DHTNode;
