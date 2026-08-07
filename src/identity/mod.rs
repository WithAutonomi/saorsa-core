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

//! Cryptographic Identity Module
//!
//! Provides cryptographic node identity for the P2P network using post-quantum
//! ML-DSA signatures. This module handles peer identity (NodeIdentity), NOT
//! user-facing identity management (which was removed).
//!
//! # Core Types
//!
//! - `NodeIdentity`: Cryptographic identity with ML-DSA keypair
//! - `PeerId`: 32-byte hash of public key
//!
//! # Identity Restart System
//!
//! Enables nodes to detect when their identity doesn't "fit" a DHT close group
//! and automatically regenerate with a new identity.

pub mod node_identity;
pub mod peer_id;

pub use node_identity::{IdentityData, NodeIdentity};
pub use peer_id::{PEER_ID_BYTE_LEN, PeerId, PeerIdParseError};
