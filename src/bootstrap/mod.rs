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

//! Persisted peer knowledge for warm-starting across restarts.
//!
//! Two files, written side by side:
//!
//! - [`cache`] holds the `k` peers nearest to self — the close group. Kept so a
//!   downgrade to an older binary still finds what it expects.
//! - [`routing_snapshot`] holds the whole routing table. A close group cannot
//!   reconstruct a routing table, because the peers that answer "is anyone
//!   closer to this key than me?" for a distant key are exactly the ones a
//!   close group leaves out. See that module for why this is combinatorial
//!   rather than a matter of degree.

pub mod cache;
pub mod routing_snapshot;

pub use cache::{CachedCloseGroupPeer, CloseGroupCache};
pub use routing_snapshot::{RoutingSnapshot, SnapshotPeer, network_fingerprint};
