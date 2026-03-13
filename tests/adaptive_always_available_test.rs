// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Compile-time + runtime test proving all adaptive/geographic modules
//! are always available under default features.
//!
//! If any of these modules gets re-gated behind a feature flag, this test will
//! fail to compile under `cargo test` (default features).

// ---- Compile-time checks: these imports must resolve without any feature flag ----

// Adaptive module
use saorsa_core::PeerId;
use saorsa_core::adaptive::{
    EigenTrustEngine, HyperbolicCoordinate, MultiArmedBandit, StrategyChoice, ThompsonSampling,
    TrustProvider,
};

// Geographic module
use saorsa_core::geographic_enhanced_network::GeographicNetworkConfig;

// DHT trust integration
use saorsa_core::dht::trust_peer_selector::TrustAwarePeerSelector;

// Prelude re-exports (adaptive types available via prelude)
use saorsa_core::prelude;

// Top-level re-exports
use saorsa_core::EigenTrustEngine as TopLevelEigenTrust;

// ---- Runtime checks ----

#[test]
fn adaptive_module_types_constructible() {
    // EigenTrustEngine
    let engine = EigenTrustEngine::new(std::collections::HashSet::new());
    let _: &dyn TrustProvider = &engine;

    // ThompsonSampling
    let _ts = ThompsonSampling::new();

    // MultiArmedBandit and StrategyChoice are importable
    let _ = std::any::type_name::<MultiArmedBandit>();
    let _ = StrategyChoice::Kademlia;

    // PeerId
    let _nid = PeerId::from_bytes([0u8; 32]);

    // HyperbolicCoordinate (public fields)
    let _coord = HyperbolicCoordinate { r: 0.5, theta: 1.0 };
}

#[test]
fn geographic_module_accessible() {
    let type_name = std::any::type_name::<GeographicNetworkConfig>();
    assert!(!type_name.is_empty());
}

#[test]
fn trust_peer_selector_accessible() {
    let _ = std::any::type_name::<TrustAwarePeerSelector<EigenTrustEngine>>();
}

#[test]
fn prelude_exports_adaptive_types() {
    // These types should be available via prelude
    let _ = prelude::StrategyChoice::Kademlia;
    let _ = prelude::PeerId::from_bytes([0u8; 32]);
}

#[test]
fn top_level_reexports_work() {
    let _ = std::any::type_name::<TopLevelEigenTrust>();
}
