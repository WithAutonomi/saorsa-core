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

//! Shared self-address advertisement policy.
//!
//! A node has two self-advertisement surfaces:
//!
//! - the reachability driver's authoritative `PublishAddressSet` fan-out to
//!   K-closest peers;
//! - the local self-entry returned by self-inclusive DHT lookup APIs.
//!
//! Both surfaces must obey the same address invariants:
//!
//! 1. If a relay address exists, publish it first and tag it
//!    [`AddressType::Relay`].
//! 2. Publish at most one best non-relay address per IP family. A proven
//!    externally reachable address is tagged [`AddressType::Direct`]; an
//!    observed-but-unproven address is tagged [`AddressType::Unverified`].
//!    Direct wins over Unverified within the same family.
//! 3. If there is no relay, publish the same best non-relay set: Direct when
//!    present, otherwise Unverified.
//! 4. Drop non-dialable wildcard or zero-port addresses rather than
//!    advertising placeholders peers cannot connect to.
//!
//! The per-family cap mirrors the peer storage/dial policy. Publishing more
//! same-family non-relay candidates only makes receivers discard or ignore
//! them, so this helper selects the address set receivers can actually use.

use std::net::SocketAddr;

use tracing::{debug, trace};

use crate::MultiAddr;
use crate::dht::AddressType;

pub(crate) fn build_self_address_set<F>(
    observed: impl IntoIterator<Item = SocketAddr>,
    listen: impl IntoIterator<Item = MultiAddr>,
    relay: Option<SocketAddr>,
    mut is_external_proven: F,
) -> SelfAddressSet
where
    F: FnMut(SocketAddr) -> bool,
{
    let mut set = SelfAddressSet::default();
    let mut candidate_index = 0;

    if let Some(relay_addr) = relay {
        let normalized = saorsa_transport::shared::normalize_socket_addr(relay_addr);
        debug!(
            address = %normalized,
            "self-address: adding relay address to publish set"
        );
        set.relay = Some(normalized);
    }

    // Prefer observed (post-NAT) addresses when the reachability tier is the
    // same, since those are what peers actually see from the outside. Listen
    // addresses still participate in tier selection, so a proven Direct
    // listen socket can beat an Unverified observed socket in the same family.
    for sa in observed {
        record_non_relay_self_address(
            sa,
            AddressSource::Observed,
            &mut set,
            &mut candidate_index,
            &mut is_external_proven,
        );
    }
    for addr in listen {
        let Some(sa) = addr.dialable_socket_addr() else {
            trace!(
                address = %addr,
                "self-address: skipping non-dialable listen address"
            );
            continue;
        };
        record_non_relay_self_address(
            sa,
            AddressSource::Listen,
            &mut set,
            &mut candidate_index,
            &mut is_external_proven,
        );
    }

    set
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SelfAddressSet {
    relay: Option<SocketAddr>,
    v4: Option<FamilyAddressChoice>,
    v6: Option<FamilyAddressChoice>,
}

impl SelfAddressSet {
    pub(crate) fn is_empty(&self) -> bool {
        self.relay.is_none() && self.v4.is_none() && self.v6.is_none()
    }

    pub(crate) fn into_typed_vec(self) -> Vec<(MultiAddr, AddressType)> {
        let mut typed = Vec::with_capacity(self.len());
        if let Some(relay) = self.relay {
            typed.push((MultiAddr::quic(relay), AddressType::Relay));
        }
        self.for_each_non_relay(|choice| {
            typed.push((MultiAddr::quic(choice.socket_addr), choice.tag));
        });
        typed
    }

    pub(crate) fn into_parallel_vecs(self) -> (Vec<MultiAddr>, Vec<AddressType>) {
        let mut addresses = Vec::with_capacity(self.len());
        let mut address_types = Vec::with_capacity(self.len());
        if let Some(relay) = self.relay {
            addresses.push(MultiAddr::quic(relay));
            address_types.push(AddressType::Relay);
        }
        self.for_each_non_relay(|choice| {
            addresses.push(MultiAddr::quic(choice.socket_addr));
            address_types.push(choice.tag);
        });
        (addresses, address_types)
    }

    fn len(&self) -> usize {
        usize::from(self.relay.is_some())
            + usize::from(self.v4.is_some())
            + usize::from(self.v6.is_some())
    }

    fn contains_selected(&self, socket_addr: SocketAddr) -> bool {
        self.relay == Some(socket_addr)
            || self
                .v4
                .map(|choice| choice.socket_addr == socket_addr)
                .unwrap_or(false)
            || self
                .v6
                .map(|choice| choice.socket_addr == socket_addr)
                .unwrap_or(false)
    }

    fn record_non_relay_choice(
        &mut self,
        socket_addr: SocketAddr,
        tag: AddressType,
        replace_same_tier: bool,
        candidate_index: usize,
    ) {
        let slot = if socket_addr.ip().is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        };

        let Some(existing) = slot else {
            *slot = Some(FamilyAddressChoice {
                first_seen_index: candidate_index,
                socket_addr,
                tag,
            });
            return;
        };

        if tag.priority() < existing.tag.priority()
            || (replace_same_tier && tag.priority() == existing.tag.priority())
        {
            trace!(
                old_tag = ?existing.tag,
                new_tag = ?tag,
                "self-address: replacing candidate for IP family"
            );
            existing.socket_addr = socket_addr;
            existing.tag = tag;
        }
    }

    fn for_each_non_relay(self, mut visit: impl FnMut(FamilyAddressChoice)) {
        match (self.v4, self.v6) {
            (Some(v4), Some(v6)) if v4.first_seen_index <= v6.first_seen_index => {
                visit(v4);
                visit(v6);
            }
            (Some(v4), Some(v6)) => {
                visit(v6);
                visit(v4);
            }
            (Some(v4), None) => visit(v4),
            (None, Some(v6)) => visit(v6),
            (None, None) => {}
        }
    }
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
    set: &mut SelfAddressSet,
    candidate_index: &mut usize,
    is_external_proven: &mut F,
) where
    F: FnMut(SocketAddr) -> bool,
{
    if socket_addr.ip().is_unspecified() || socket_addr.port() == 0 {
        debug!(
            address = %socket_addr,
            source = source.label(),
            "self-address: skipping non-dialable self address"
        );
        return;
    }
    let normalized = saorsa_transport::shared::normalize_socket_addr(socket_addr);
    // Only emitted addresses need deduping. Same-family candidates that lose
    // selection cannot win later with the same proof state, so tracking every
    // seen candidate would add work without changing the publish set.
    if set.contains_selected(normalized) {
        trace!(
            address = %normalized,
            source = source.label(),
            "self-address: deduped self address"
        );
        return;
    }

    let tag = if is_external_proven(normalized) {
        AddressType::Direct
    } else {
        AddressType::Unverified
    };
    debug!(
        address = %normalized,
        tag = ?tag,
        source = source.label(),
        "self-address: adding address to candidate publish set"
    );
    set.record_non_relay_choice(
        normalized,
        tag,
        source.replace_same_tier(),
        *candidate_index,
    );
    *candidate_index = (*candidate_index).saturating_add(1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FamilyAddressChoice {
    first_seen_index: usize,
    socket_addr: SocketAddr,
    tag: AddressType,
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

    fn typed_self_address_set<F>(
        observed: impl IntoIterator<Item = SocketAddr>,
        listen: impl IntoIterator<Item = MultiAddr>,
        relay: Option<SocketAddr>,
        is_external_proven: F,
    ) -> Vec<(MultiAddr, AddressType)>
    where
        F: FnMut(SocketAddr) -> bool,
    {
        build_self_address_set(observed, listen, relay, is_external_proven).into_typed_vec()
    }

    #[test]
    fn parallel_materialization_matches_typed_order() {
        let proven_v4 = sock("203.0.113.10:10004");
        let set = build_self_address_set(
            [proven_v4, sock("[2001:db8::10]:10004")],
            Vec::<MultiAddr>::new(),
            Some(sock("198.51.100.1:45000")),
            |sa| sa == proven_v4,
        );

        let typed = set.into_typed_vec();
        let (addresses, address_types) = set.into_parallel_vecs();
        let parallel_as_typed: Vec<_> = addresses.into_iter().zip(address_types).collect();

        assert_eq!(parallel_as_typed, typed);
    }

    #[test]
    fn publish_set_keeps_relay_primary_and_unverified_fallback() {
        let typed = typed_self_address_set(
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
        let typed = typed_self_address_set(
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
    fn publish_set_keeps_relay_when_no_non_relay_address_exists() {
        let typed = typed_self_address_set(
            Vec::<SocketAddr>::new(),
            Vec::<MultiAddr>::new(),
            Some(sock("198.51.100.1:45000")),
            |_| false,
        );

        assert_eq!(
            typed,
            vec![(addr("/ip4/198.51.100.1/udp/45000/quic"), AddressType::Relay)]
        );
    }

    #[test]
    fn publish_set_without_relay_prefers_direct_over_unverified() {
        let proven = sock("203.0.113.10:10004");
        let typed = typed_self_address_set(
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
        let typed = typed_self_address_set(
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
        let typed =
            typed_self_address_set([older_v4, newer_v4], Vec::<MultiAddr>::new(), None, |sa| {
                sa == older_v4 || sa == newer_v4
            });

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
        let typed = typed_self_address_set(
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
        let typed = typed_self_address_set(
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

    #[test]
    fn publish_set_drops_wildcard_and_zero_port_addresses() {
        let typed = typed_self_address_set(
            [sock("0.0.0.0:10004"), sock("203.0.113.10:0")],
            [
                addr("/ip4/0.0.0.0/udp/10005/quic"),
                addr("/ip4/203.0.113.11/udp/0/quic"),
            ],
            None,
            |_| false,
        );

        assert!(typed.is_empty());
    }
}
