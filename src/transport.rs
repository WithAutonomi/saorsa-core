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

//! Transport Layer
//!
//! This module provides native saorsa-transport integration for the P2P Foundation.
//!
//! Use `saorsa_transport_adapter::P2PNetworkNode` directly for all networking needs.

// Native saorsa-transport integration with advanced NAT traversal and PQC support
pub mod saorsa_transport_adapter;

// DHT protocol handler for SharedTransport integration
pub mod dht_handler;

// Pinned external addresses: records direct addresses from bootstrap
// OBSERVED_ADDRESS frames and the relay-allocated address. Replaces the
// previous frequency/recency cache with permanent pinning.
pub(crate) mod external_addresses;
