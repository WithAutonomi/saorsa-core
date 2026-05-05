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

use std::collections::HashSet;
use std::net::SocketAddr;

use tracing::{debug, trace};

use crate::MultiAddr;
use crate::dht::AddressType;

pub(crate) fn build_typed_self_address_set<F>(
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
            "self-address: adding relay address to publish set"
        );
        typed.push((MultiAddr::quic(normalized), AddressType::Relay));
        seen.insert(normalized);
    }

    // Prefer observed (post-NAT) addresses when the reachability tier is the
    // same, since those are what peers actually see from the outside. Listen
    // addresses still participate in tier selection, so a proven Direct
    // listen socket can beat an Unverified observed socket in the same family.
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
                "self-address: skipping non-dialable listen address"
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
    if socket_addr.ip().is_unspecified() || socket_addr.port() == 0 {
        debug!(
            address = %socket_addr,
            source = source.label(),
            "self-address: skipping non-dialable self address"
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
            "self-address: adding address to candidate publish set"
        );
        record_non_relay_choice(non_relay, normalized, tag, source.replace_same_tier());
    } else {
        trace!(
            address = %normalized,
            tag = ?tag,
            source = source.label(),
            "self-address: deduped self address"
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
            "self-address: replacing candidate for IP family"
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
    fn publish_set_keeps_relay_when_no_non_relay_address_exists() {
        let typed = build_typed_self_address_set(
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

    #[test]
    fn publish_set_drops_wildcard_and_zero_port_addresses() {
        let typed = build_typed_self_address_set(
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
