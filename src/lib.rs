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

// Enforce no unwrap/expect/panic in production code only (tests can use them)
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![cfg_attr(not(test), warn(clippy::expect_used))]
#![cfg_attr(not(test), warn(clippy::panic))]
// Allow unused_async as many functions are async for API consistency
#![allow(clippy::unused_async)]

//! # Saorsa Core
//!
//! A next-generation peer-to-peer networking foundation built in Rust.
//!
//! ## Features
//!
//! - QUIC-based transport with NAT traversal
//! - IPv4-first with simple addressing
//! - Kademlia DHT for distributed routing
//! - Post-quantum cryptography (ML-DSA-65, ML-KEM-768)

#![allow(missing_docs)]
#![allow(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

// Internal modules — used by the crate but not exposed publicly.
#[cfg(feature = "native")]
pub(crate) mod adaptive;
pub(crate) mod address;
#[cfg(feature = "native")]
pub(crate) mod bgp_geo_provider;
#[cfg(feature = "native")]
pub(crate) mod bootstrap;
#[cfg(feature = "native")]
pub(crate) mod dht;
#[cfg(feature = "native")]
pub(crate) mod dht_network_manager;
pub(crate) mod error;
#[cfg(feature = "native")]
pub(crate) mod network;
mod peer_record;
pub(crate) mod quantum_crypto;
#[cfg(feature = "native")]
pub(crate) mod rate_limit;
#[cfg(feature = "native")]
pub(crate) mod reachability;
#[cfg(feature = "native")]
pub(crate) mod security;
#[cfg(feature = "native")]
pub(crate) mod self_address;
#[cfg(feature = "native")]
pub(crate) mod transport;
pub(crate) mod transport_address;
#[cfg(feature = "native")]
pub(crate) mod transport_handle;
#[cfg(feature = "native")]
pub(crate) mod validation;

/// Transport-independent iterative DHT lookup, shared by native and browser clients.
pub mod dht_lookup;

/// User identity and privacy system (public — accessed via path by saorsa-node).
pub mod identity;

// ---------------------------------------------------------------------------
// Public re-exports — only items that saorsa-node consumes.
// ---------------------------------------------------------------------------

// Networking
pub use address::{MultiAddr, WebRtcCertificateHash, WebRtcDirectAddr};
#[cfg(feature = "native")]
pub use network::{NodeConfig, NodeMode, P2PEvent, P2PNode};

// DHT types — peer discovery, routing, and network events
/// DHT key type (256 bits).
pub type Key = [u8; 32];
pub use dht_lookup::{
    CandidateInsertion, IterativeLookup, LookupConfig, LookupError, LookupKey, LookupNode,
    LookupPeerState, LookupProgress, LookupQuery, LookupQueryOutcome, LookupRunError,
    LookupTermination, collect_after_first_with_grace, run_iterative_lookup, xor_distance,
};
#[cfg(feature = "native")]
pub use dht_network_manager::DhtNetworkEvent;
pub use peer_record::{AddressType, DHTNode, ResponderView, WitnessedCloseGroup};
pub use transport_address::{
    KnownReachability, KnownTransport, MAX_TRANSPORT_ADDRESS_PAYLOAD,
    MAX_TRANSPORT_ADDRESS_RECORDS, TransportAddressRecord,
};

// Close-group cache
#[cfg(feature = "native")]
pub use bootstrap::{CachedCloseGroupPeer, CloseGroupCache};

// Trust & Adaptive DHT
#[cfg(feature = "native")]
pub use adaptive::dht::{AdaptiveDhtConfig, TrustEvent};
#[cfg(feature = "native")]
pub use adaptive::trust::{TrustEngine, TrustRecord};

// Security
#[cfg(feature = "native")]
pub use security::IPDiversityConfig;

// Post-quantum cryptography
pub use quantum_crypto::MlDsa65;

// Canonical peer identity (also accessible via identity::peer_id::PeerId)
pub use identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Crate-internal re-exports — used by sibling modules via `crate::Result` etc.
// ---------------------------------------------------------------------------
pub(crate) use error::{P2PError, P2pResult as Result};

/// Default capacity for broadcast and mpsc event channels throughout the system.
#[cfg(feature = "native")]
pub(crate) const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 1000;
