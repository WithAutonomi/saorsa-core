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

//! # Canary-gated relay acquisition
//!
//! Every non-client node tries to acquire a MASQUE relay from an XOR-closest
//! peer after bootstrap. Once a candidate accepts, the driver asks
//! independent close-group witnesses to cold-dial the relay-allocated
//! address and confirm this node's authenticated identity before the address
//! is published to the DHT.
//!
//! ## Module layout
//!
//! - [`acquisition`]: the reusable XOR-closest [`RelayAcquisition`]
//!   coordinator. Pure logic — wraps a [`RelaySessionEstablisher`] trait so
//!   the walk can be unit-tested with mock establishers.
//! - [`canary`]: internal request/response protocol and quorum check used
//!   to verify a freshly acquired relay from third-party vantage points.
//! - [`session`]: the [`run_relay_acquisition`] entry point. Builds the
//!   filtered candidate list from the routing table and hands it to the
//!   coordinator.
//! - [`driver`]: the [`spawn_acquisition_driver`] background task. Owns
//!   every state transition for this node's relay: initial acquisition,
//!   backoff retry, K-closest-eviction watch, tunnel-health poll, and
//!   the republish-then-reacquire sequence on loss.

pub(crate) mod acquisition;
pub(crate) mod canary;
pub(crate) mod driver;
pub(crate) mod session;

pub(crate) use acquisition::{RelaySessionEstablishError, RelaySessionEstablisher};
pub(crate) use driver::spawn_acquisition_driver;
