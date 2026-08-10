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

//! Quantum-resistant cryptography module
//!
//! This module provides post-quantum cryptographic primitives including:
//! - ML-DSA (Module-Lattice Digital Signature Algorithm) for signatures

pub mod saorsa_transport_integration;

// Re-export saorsa-transport PQC functions for convenience
pub use self::saorsa_transport_integration::{generate_ml_dsa_keypair, ml_dsa_sign, ml_dsa_verify};

// Primary post-quantum cryptography types from saorsa-pqc 0.3.0
pub use saorsa_pqc::MlDsa65;
