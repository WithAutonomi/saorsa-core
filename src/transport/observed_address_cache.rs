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

//! Observed-address cache for transport-level reflexive address fallback.
//!
//! ## Why this exists
//!
//! `saorsa-transport` exposes the node's externally-observed address (from
//! QUIC `OBSERVED_ADDRESS` frames) only via *active* connections — when every
//! connection drops, the live read returns `None` and the node has no way to
//! tell the DHT how to be reached. The result is a temporary "invisible
//! window" between the connection drop and the next reconnection.
//!
//! This cache fills that gap. It records every `ExternalAddressDiscovered`
//! event the transport emits and serves as a fallback when no live connection
//! has an observation.
//!
//! ## Frequency-based selection
//!
//! Different peers can legitimately observe a node at different addresses
//! (symmetric NAT, multi-homed hosts, dual-stack divergence). The cache
//! tracks how many distinct events have been received for each address and
//! returns the one with the highest count, breaking ties by recency. The
//! intuition: "the address most peers agree on" is the most likely to be
//! reachable from any new peer.
//!
//! ## Recency window for NAT-rebinding handling
//!
//! Pure frequency would let a long-lived stale address (count: 10000, last
//! seen 24h ago) win over a fresh new address (count: 5, last seen now).
//! That is the wrong answer when a NAT mapping has rebinded.
//!
//! Selection is therefore split into two passes:
//!
//! 1. Among entries observed within [`OBSERVATION_RECENCY_WINDOW`], return
//!    the highest-count one (with `last_seen` as the tiebreaker).
//! 2. If nothing is recent, fall back to the global highest-count entry —
//!    handles the case where the node has been quiet for longer than the
//!    recency window.
//!
//! Eviction is also recency-based: when the cache is full, the entry with
//! the *oldest* `last_seen` is removed. This ensures stale high-count
//! entries get pushed out as fresh observations arrive.
//!
//! ## Bounded
//!
//! The cache is bounded at [`MAX_CACHED_OBSERVATIONS`] entries to keep
//! memory predictable. The bound is chosen to comfortably handle:
//!
//! - Dual-stack (IPv4 + IPv6) observations of the same node
//! - Symmetric-NAT divergence (different external port per peer)
//! - A handful of recent NAT rebindings during the recency window
//!
//! ## Persistence
//!
//! The cache is in-memory only. A node restart resets it. This is
//! intentional: a freshly-started node should re-discover its current
//! address from live connections rather than trusting potentially-stale
//! state from a previous run.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Maximum number of distinct observed addresses retained in the cache.
///
/// Bounds memory and protects against pathological cases (a buggy peer
/// reporting random addresses). Sized to fit normal operating conditions:
/// dual-stack + symmetric-NAT divergence + a couple of recent rebindings.
pub(crate) const MAX_CACHED_OBSERVATIONS: usize = 16;

/// Time window during which an observation counts as "recent".
///
/// Within this window, selection prefers the highest-count entry. Beyond
/// it, the cache treats observations as stale candidates that only matter
/// if nothing recent exists.
///
/// 10 minutes is long enough to absorb a normal disconnect+reconnect cycle
/// (typically seconds to a minute) and short enough that a NAT rebinding
/// is reflected in the selection within ~10 min, even if the stale address
/// still wins on raw count.
pub(crate) const OBSERVATION_RECENCY_WINDOW: Duration = Duration::from_secs(600);

/// Per-address bookkeeping inside [`ObservedAddressCache`].
#[derive(Debug, Clone, Copy)]
struct ObservedEntry {
    /// Cumulative count of `ExternalAddressDiscovered` events received for
    /// this address. Each (peer, address) pair contributes at most once,
    /// per saorsa-transport's own dedup, so this is effectively a count of
    /// distinct peers that have agreed on this address.
    count: u64,
    /// The most recent instant we received an event for this address.
    /// Used both for recency-based selection and for LRU eviction.
    last_seen: Instant,
}

/// Bounded cache of observed external addresses with frequency- and
/// recency-aware selection. See module-level docs for the rationale.
#[derive(Debug, Default)]
pub(crate) struct ObservedAddressCache {
    entries: HashMap<SocketAddr, ObservedEntry>,
}

impl ObservedAddressCache {
    /// Create an empty cache.
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record an observation of `addr`. Increments the count for an
    /// existing entry or inserts a new one, evicting the oldest entry by
    /// `last_seen` if the cache is full.
    pub(crate) fn record(&mut self, addr: SocketAddr) {
        self.record_at(addr, Instant::now());
    }

    /// Record an observation at a caller-provided instant. Exposed for
    /// deterministic unit tests; production callers should use [`record`].
    pub(crate) fn record_at(&mut self, addr: SocketAddr, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.count = entry.count.saturating_add(1);
            entry.last_seen = now;
            return;
        }

        if self.entries.len() >= MAX_CACHED_OBSERVATIONS {
            self.evict_oldest();
        }

        self.entries.insert(
            addr,
            ObservedEntry {
                count: 1,
                last_seen: now,
            },
        );
    }

    /// Return the address with the highest observation count among entries
    /// seen within [`OBSERVATION_RECENCY_WINDOW`], breaking ties by most
    /// recent `last_seen`. If no entry is recent, fall back to the highest
    /// count overall (still tiebroken by recency).
    pub(crate) fn most_frequent_recent(&self) -> Option<SocketAddr> {
        self.most_frequent_recent_at(Instant::now())
    }

    /// Selection at a caller-provided "now". Exposed for deterministic
    /// unit tests; production callers should use [`most_frequent_recent`].
    pub(crate) fn most_frequent_recent_at(&self, now: Instant) -> Option<SocketAddr> {
        let recent = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) <= OBSERVATION_RECENCY_WINDOW)
            .max_by_key(|(_, e)| (e.count, e.last_seen))
            .map(|(addr, _)| *addr);

        if recent.is_some() {
            return recent;
        }

        self.entries
            .iter()
            .max_by_key(|(_, e)| (e.count, e.last_seen))
            .map(|(addr, _)| *addr)
    }

    /// Evict the entry with the oldest `last_seen`. No-op on an empty cache.
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen)
            .map(|(addr, _)| *addr);
        if let Some(addr) = oldest {
            self.entries.remove(&addr);
        }
    }

    /// Number of distinct addresses currently cached. Exposed for tests
    /// and diagnostics.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Construct a unique IPv4 socket address for tests.
    fn addr(last_octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), port)
    }

    #[test]
    fn empty_cache_returns_none() {
        let cache = ObservedAddressCache::new();
        assert_eq!(cache.most_frequent_recent(), None);
    }

    #[test]
    fn single_observation_returns_that_address() {
        let mut cache = ObservedAddressCache::new();
        let a = addr(1, 9000);
        cache.record(a);
        assert_eq!(cache.most_frequent_recent(), Some(a));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn repeated_observation_increments_count_without_growing() {
        let mut cache = ObservedAddressCache::new();
        let a = addr(1, 9000);
        cache.record(a);
        cache.record(a);
        cache.record(a);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.most_frequent_recent(), Some(a));
    }

    #[test]
    fn higher_count_wins_among_recent_entries() {
        let mut cache = ObservedAddressCache::new();
        let popular = addr(1, 9000);
        let unpopular = addr(2, 9000);

        // popular: 5 observations, unpopular: 1 observation, all recent.
        for _ in 0..5 {
            cache.record(popular);
        }
        cache.record(unpopular);

        assert_eq!(cache.most_frequent_recent(), Some(popular));
    }

    #[test]
    fn equal_counts_break_tie_by_recency() {
        let mut cache = ObservedAddressCache::new();
        let older = addr(1, 9000);
        let newer = addr(2, 9000);

        let base = Instant::now();
        cache.record_at(older, base);
        cache.record_at(newer, base + Duration::from_secs(1));

        assert_eq!(
            cache.most_frequent_recent_at(base + Duration::from_secs(2)),
            Some(newer)
        );
    }

    #[test]
    fn stale_high_count_loses_to_recent_low_count() {
        // The NAT-rebinding scenario: an old address has a huge count from
        // a long session, but a new address has just started accumulating
        // observations after the rebind. The cache should prefer the new one
        // because the old one is outside the recency window.
        let mut cache = ObservedAddressCache::new();
        let stale = addr(1, 9000);
        let fresh = addr(2, 9000);

        let base = Instant::now();

        // 1000 observations of `stale`, all well outside the recency window.
        let stale_time = base;
        for _ in 0..1000 {
            cache.record_at(stale, stale_time);
        }

        // 3 observations of `fresh`, all just now.
        let fresh_time = base + OBSERVATION_RECENCY_WINDOW + Duration::from_secs(60);
        for _ in 0..3 {
            cache.record_at(fresh, fresh_time);
        }

        let now = fresh_time + Duration::from_secs(1);
        assert_eq!(cache.most_frequent_recent_at(now), Some(fresh));
    }

    #[test]
    fn falls_back_to_global_highest_count_when_nothing_is_recent() {
        // Long-quiet network case: the node has been silent for longer than
        // the recency window, so the recent-pass returns nothing. The
        // fallback returns the highest-count address overall so the node
        // can still publish *something*.
        let mut cache = ObservedAddressCache::new();
        let popular = addr(1, 9000);
        let unpopular = addr(2, 9000);

        let base = Instant::now();
        for _ in 0..5 {
            cache.record_at(popular, base);
        }
        cache.record_at(unpopular, base);

        // Far in the future — every entry is stale, fallback path engages.
        let far_future = base + OBSERVATION_RECENCY_WINDOW * 10;
        assert_eq!(cache.most_frequent_recent_at(far_future), Some(popular));
    }

    #[test]
    fn eviction_removes_oldest_by_last_seen_when_full() {
        let mut cache = ObservedAddressCache::new();
        let base = Instant::now();

        // Fill the cache with MAX entries, each at a distinct time.
        for i in 0..(MAX_CACHED_OBSERVATIONS as u8) {
            cache.record_at(addr(i + 1, 9000), base + Duration::from_secs(u64::from(i)));
        }
        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);

        // The oldest entry is the one inserted at `base` (i = 0, addr=1).
        let oldest = addr(1, 9000);
        assert!(cache.entries.contains_key(&oldest));

        // Insert one more — should evict the oldest.
        let newcomer = addr(99, 9000);
        cache.record_at(
            newcomer,
            base + Duration::from_secs(MAX_CACHED_OBSERVATIONS as u64),
        );

        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);
        assert!(
            !cache.entries.contains_key(&oldest),
            "oldest entry should have been evicted"
        );
        assert!(
            cache.entries.contains_key(&newcomer),
            "newcomer should be present"
        );
    }

    #[test]
    fn re_observing_an_existing_entry_does_not_trigger_eviction() {
        // If we record an address that's already in the cache, we just
        // bump its count and last_seen — no eviction needed even when the
        // cache is full.
        let mut cache = ObservedAddressCache::new();
        let base = Instant::now();

        for i in 0..(MAX_CACHED_OBSERVATIONS as u8) {
            cache.record_at(addr(i + 1, 9000), base + Duration::from_secs(u64::from(i)));
        }
        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);

        // Re-observe the oldest entry, refreshing its last_seen.
        let oldest_addr = addr(1, 9000);
        let refresh_time = base + Duration::from_secs(1000);
        cache.record_at(oldest_addr, refresh_time);

        // Cache size unchanged; the entry is now the youngest.
        assert_eq!(cache.len(), MAX_CACHED_OBSERVATIONS);
        let entry = cache.entries.get(&oldest_addr).copied().unwrap();
        assert_eq!(entry.count, 2);
        assert_eq!(entry.last_seen, refresh_time);
    }
}
