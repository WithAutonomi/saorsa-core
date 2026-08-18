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
//! Two files, written side by side: [`cache`] holds the `k` peers nearest to
//! self, and [`routing_snapshot`] holds the whole routing table, which is what
//! a node consults to decide whether anyone is closer to a given key than it is.

pub mod cache;
pub(crate) mod routing_snapshot;

pub use cache::{CachedCloseGroupPeer, CloseGroupCache};
