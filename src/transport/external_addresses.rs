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

//! External addresses for this node.
//!
//! ## Why this exists
//!
//! A node behind NAT discovers its external (post-NAT) address from QUIC
//! `OBSERVED_ADDRESS` frames. A single report is retained as an
//! unverified candidate so peers can attempt it after the relay. Once the
//! transport emits `ExternalAddressDiscovered`, the address is **pinned**
//! as direct and retained for the lifetime of the process.
//!
//! When the node acquires a MASQUE relay, the relay-allocated address is
//! stored alongside the non-relay addresses. The relay address is
//! considered the **preferred** address and is returned first by
//! [`ExternalAddresses::all_addresses`].
//!
//! ## Why not a cache?
//!
//! The previous implementation used a frequency- and recency-aware cache.
//! After relay acquisition, direct connections drop, no new observations
//! refresh the cache, and the direct address ages out. Pinning eliminates
//! this problem: the address observed at bootstrap is valid for as long as
//! the NAT mapping holds, and the relay provides reachability regardless.
//! Unverified candidates are still retained because a relay-only self
//! record gives dialers no chance to try a NAT mapping that peers have
//! already observed.

use std::net::SocketAddr;

/// Maximum number of pinned direct addresses retained.
///
/// Caps growth from mobile network handoffs, CGN pool rotation, or other
/// NAT-rebinding events. When the cap is reached, the oldest (first)
/// address is evicted on the assumption that newer observations better
/// reflect the current NAT mapping. 16 is generous enough to cover
/// dual-stack + multi-homed hosts while bounding the self-record size
/// published to K-closest peers.
const MAX_DIRECT_ADDRESSES: usize = 16;

/// Maximum number of observed-but-unproven addresses retained.
///
/// Kept separate from [`MAX_DIRECT_ADDRESSES`] so a stream of unverified
/// NAT rebinding reports cannot evict addresses already pinned as direct.
const MAX_UNVERIFIED_ADDRESSES: usize = 16;

/// External addresses observed from QUIC peers and the relay layer.
///
/// Direct addresses are pinned on first observation and evicted
/// oldest-first when [`MAX_DIRECT_ADDRESSES`] is reached. Unverified
/// addresses are single-peer observations that have not been promoted to
/// direct yet; they are also insertion-ordered and capped.
/// The relay address is set/cleared by the relay acquisition driver.
#[derive(Debug, Default)]
pub(crate) struct ExternalAddresses {
    /// Direct external addresses pinned from QUIC `OBSERVED_ADDRESS` frames
    /// received during bootstrap. Insertion-ordered, deduplicated, capped
    /// at [`MAX_DIRECT_ADDRESSES`].
    direct: Vec<SocketAddr>,
    /// Observed external addresses that are publishable as Unverified but
    /// have not been promoted/pinned as Direct.
    unverified: Vec<SocketAddr>,
    /// Relay-allocated address. `Some` when a MASQUE relay is held, `None`
    /// otherwise.
    relay: Option<SocketAddr>,
}

impl ExternalAddresses {
    /// Create an empty set of external addresses.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Pin a direct external address observed from a QUIC peer.
    ///
    /// Inserts `addr` if it is not already present. When the list is at
    /// capacity, the oldest entry is evicted first.
    pub(crate) fn pin_direct(&mut self, addr: SocketAddr) -> bool {
        let addr = saorsa_transport::shared::normalize_socket_addr(addr);
        if Some(addr) == self.relay || self.direct.contains(&addr) {
            return false;
        }
        self.unverified.retain(|unverified| *unverified != addr);
        if self.direct.len() >= MAX_DIRECT_ADDRESSES {
            self.direct.remove(0);
        }
        self.direct.push(addr);
        true
    }

    /// Retain an observed external address as an unverified publish
    /// candidate.
    ///
    /// Returns `true` only when this changes the publishable address set.
    /// Relay and already-pinned direct addresses are ignored.
    pub(crate) fn record_unverified(&mut self, addr: SocketAddr) -> bool {
        let addr = saorsa_transport::shared::normalize_socket_addr(addr);
        if Some(addr) == self.relay || self.direct.contains(&addr) {
            return false;
        }
        if let Some(pos) = self
            .unverified
            .iter()
            .position(|unverified| *unverified == addr)
        {
            let existing = self.unverified.remove(pos);
            self.unverified.push(existing);
            return false;
        }
        if self.unverified.len() >= MAX_UNVERIFIED_ADDRESSES {
            self.unverified.remove(0);
        }
        self.unverified.push(addr);
        true
    }

    /// Set the relay-allocated address.
    pub(crate) fn set_relay(&mut self, addr: SocketAddr) {
        let addr = saorsa_transport::shared::normalize_socket_addr(addr);
        self.direct.retain(|direct| *direct != addr);
        self.unverified.retain(|unverified| *unverified != addr);
        self.relay = Some(addr);
    }

    /// Clear the relay-allocated address.
    pub(crate) fn clear_relay(&mut self) {
        self.relay = None;
    }

    /// All external addresses, **relay first** (preferred), then pinned
    /// direct addresses, then unverified observed addresses. If the relay
    /// address also appears in either non-relay set, it is not duplicated.
    pub(crate) fn all_addresses(&self) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(self.direct.len() + self.unverified.len() + 1);
        if let Some(relay) = self.relay {
            out.push(relay);
        }
        for &addr in &self.direct {
            if Some(addr) != self.relay {
                out.push(addr);
            }
        }
        for &addr in &self.unverified {
            if Some(addr) != self.relay && !self.direct.contains(&addr) {
                out.push(addr);
            }
        }
        out
    }

    /// Only the pinned direct addresses (no relay).
    pub(crate) fn direct_addresses(&self) -> Vec<SocketAddr> {
        self.direct.clone()
    }

    /// All non-relay addresses that should be considered for typed
    /// self-publication.
    pub(crate) fn non_relay_addresses(&self) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(self.direct.len() + self.unverified.len());
        out.extend(self.direct.iter().copied());
        for &addr in &self.unverified {
            if !self.direct.contains(&addr) {
                out.push(addr);
            }
        }
        out
    }

    /// The relay address, if any.
    #[cfg(test)]
    pub(crate) fn relay_address(&self) -> Option<SocketAddr> {
        self.relay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr(last_octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), port)
    }

    #[test]
    fn empty_returns_nothing() {
        let ext = ExternalAddresses::new();
        assert!(ext.all_addresses().is_empty());
        assert!(ext.direct_addresses().is_empty());
        assert!(ext.relay_address().is_none());
    }

    #[test]
    fn pin_direct_dedup() {
        let mut ext = ExternalAddresses::new();
        let a = addr(1, 9000);
        assert!(ext.pin_direct(a));
        assert!(!ext.pin_direct(a));
        assert!(!ext.pin_direct(a));
        assert_eq!(ext.direct_addresses(), vec![a]);
        assert_eq!(ext.all_addresses(), vec![a]);
    }

    #[test]
    fn all_addresses_relay_first() {
        let mut ext = ExternalAddresses::new();
        let direct = addr(1, 9000);
        let relay = addr(2, 9000);
        ext.pin_direct(direct);
        ext.set_relay(relay);
        assert_eq!(ext.all_addresses(), vec![relay, direct]);
        assert_eq!(ext.relay_address(), Some(relay));
    }

    #[test]
    fn all_addresses_includes_unverified_after_relay() {
        let mut ext = ExternalAddresses::new();
        let relay = addr(1, 9000);
        let unverified = addr(2, 9000);

        ext.set_relay(relay);
        assert!(ext.record_unverified(unverified));

        assert_eq!(ext.all_addresses(), vec![relay, unverified]);
        assert_eq!(ext.non_relay_addresses(), vec![unverified]);
    }

    #[test]
    fn pin_direct_removes_matching_unverified() {
        let mut ext = ExternalAddresses::new();
        let direct = addr(1, 9000);

        assert!(ext.record_unverified(direct));
        assert!(ext.pin_direct(direct));

        assert_eq!(ext.direct_addresses(), vec![direct]);
        assert_eq!(ext.non_relay_addresses(), vec![direct]);
        assert_eq!(ext.all_addresses(), vec![direct]);
    }

    #[test]
    fn set_relay_removes_matching_unverified() {
        let mut ext = ExternalAddresses::new();
        let relay = addr(1, 9000);

        assert!(ext.record_unverified(relay));
        ext.set_relay(relay);

        assert_eq!(ext.all_addresses(), vec![relay]);
        assert!(ext.non_relay_addresses().is_empty());
    }

    #[test]
    fn clear_relay_removes_from_all() {
        let mut ext = ExternalAddresses::new();
        let direct = addr(1, 9000);
        let relay = addr(2, 9000);
        ext.pin_direct(direct);
        ext.set_relay(relay);
        ext.clear_relay();
        assert_eq!(ext.all_addresses(), vec![direct]);
        assert!(ext.relay_address().is_none());
    }

    #[test]
    fn relay_not_duplicated_when_also_pinned() {
        let mut ext = ExternalAddresses::new();
        let same = addr(1, 9000);
        ext.pin_direct(same);
        ext.set_relay(same);
        // Should appear only once, as relay (preferred position).
        assert_eq!(ext.all_addresses(), vec![same]);
        assert!(ext.direct_addresses().is_empty());
    }

    #[test]
    fn relay_address_is_not_pinned_as_direct() {
        let mut ext = ExternalAddresses::new();
        let same = addr(1, 9000);
        ext.set_relay(same);
        assert!(!ext.pin_direct(same));
        assert!(ext.direct_addresses().is_empty());
        assert_eq!(ext.all_addresses(), vec![same]);
    }

    #[test]
    fn relay_address_is_normalized_before_direct_dedup() {
        let mut ext = ExternalAddresses::new();
        let plain = addr(1, 9000);
        let mapped = "[::ffff:192.0.2.1]:9000".parse().unwrap();

        ext.set_relay(mapped);

        assert_eq!(ext.relay_address(), Some(plain));
        assert!(!ext.pin_direct(plain));
        assert!(ext.direct_addresses().is_empty());
        assert_eq!(ext.all_addresses(), vec![plain]);
    }

    #[test]
    fn multiple_direct_addresses_preserved() {
        let mut ext = ExternalAddresses::new();
        let a = addr(1, 9000);
        let b = addr(2, 9000);
        ext.pin_direct(a);
        ext.pin_direct(b);
        assert_eq!(ext.direct_addresses(), vec![a, b]);
        assert_eq!(ext.all_addresses(), vec![a, b]);
    }

    #[test]
    fn direct_addresses_excludes_relay() {
        let mut ext = ExternalAddresses::new();
        let direct = addr(1, 9000);
        let relay = addr(2, 9000);
        ext.pin_direct(direct);
        ext.set_relay(relay);
        assert_eq!(ext.direct_addresses(), vec![direct]);
    }

    #[test]
    fn pin_direct_evicts_oldest_at_capacity() {
        let mut ext = ExternalAddresses::new();
        for i in 0..MAX_DIRECT_ADDRESSES as u8 {
            ext.pin_direct(addr(i, 9000));
        }
        assert_eq!(ext.direct_addresses().len(), MAX_DIRECT_ADDRESSES);

        // Adding one more should evict the oldest (octet 0).
        let new = addr(MAX_DIRECT_ADDRESSES as u8, 9000);
        ext.pin_direct(new);
        assert_eq!(ext.direct_addresses().len(), MAX_DIRECT_ADDRESSES);
        assert!(!ext.direct_addresses().contains(&addr(0, 9000)));
        assert_eq!(*ext.direct_addresses().last().unwrap(), new);
    }
}
