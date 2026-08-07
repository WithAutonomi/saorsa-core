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

//! # Unconditional relay acquisition
//!
//! Every non-client node tries to acquire a MASQUE relay from an XOR-closest
//! peer after bootstrap. There is no dial-back probe, no `Public`/`Private`
//! classification, and no `AssumePrivate` flag: the "is this candidate
//! public?" question is inferred ambiently from the dial attempt itself.
//! A private candidate's Direct address is unreachable from outside its NAT,
//! so the QUIC dial fails and the walker advances to the next close peer.
//!
//! ## Module layout
//!
//! - [`acquisition`]: the reusable XOR-closest [`RelayAcquisition`]
//!   coordinator. Pure logic — wraps a [`RelaySessionEstablisher`] trait so
//!   the walk can be unit-tested with mock establishers.
//! - [`session`]: the [`run_relay_acquisition`] entry point. Builds the
//!   filtered candidate list from the routing table and hands it to the
//!   coordinator.
//! - [`driver`]: the [`spawn_acquisition_driver`] background task. Owns
//!   every state transition for this node's relay: initial acquisition,
//!   backoff retry, K-closest-eviction watch, tunnel-health poll, and
//!   the republish-then-reacquire sequence on loss.

pub(crate) mod acquisition;
pub(crate) mod driver;
pub(crate) mod session;

pub(crate) use acquisition::{RelaySessionEstablishError, RelaySessionEstablisher};
pub(crate) use driver::spawn_acquisition_driver;
