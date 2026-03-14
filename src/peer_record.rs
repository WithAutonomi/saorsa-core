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

//! # Peer Record Types
//!
//! Re-exports core peer identity types and NAT classification for the P2P network.

pub use crate::identity::node_identity::{PeerId, peer_id_from_public_key};
use serde::{Deserialize, Serialize};
use std::fmt;

/// NAT type classification based on IETF draft-seemann-quic-nat-traversal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NatType {
    /// No NAT - public IP address
    NoNat,
    /// Full Cone NAT - best case for hole punching
    FullCone,
    /// Restricted Cone NAT - IP address restricted
    RestrictedCone,
    /// Port Restricted NAT - IP address and port restricted
    PortRestricted,
    /// Symmetric NAT - worst case for hole punching
    Symmetric,
    /// Unknown NAT type - requires further detection
    Unknown,
}

impl NatType {
    /// Check if this NAT type supports hole punching
    pub fn supports_hole_punching(&self) -> bool {
        matches!(
            self,
            NatType::NoNat | NatType::FullCone | NatType::RestrictedCone | NatType::PortRestricted
        )
    }

    /// Get the difficulty score for hole punching (0 = impossible, 100 = easy)
    pub fn hole_punching_difficulty(&self) -> u8 {
        match self {
            NatType::NoNat => 100,
            NatType::FullCone => 90,
            NatType::RestrictedCone => 70,
            NatType::PortRestricted => 50,
            NatType::Symmetric => 10,
            NatType::Unknown => 0,
        }
    }
}

impl fmt::Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatType::NoNat => write!(f, "No NAT"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::RestrictedCone => write!(f, "Restricted Cone"),
            NatType::PortRestricted => write!(f, "Port Restricted"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_hole_punching() {
        assert!(NatType::NoNat.supports_hole_punching());
        assert!(NatType::FullCone.supports_hole_punching());
        assert!(NatType::RestrictedCone.supports_hole_punching());
        assert!(NatType::PortRestricted.supports_hole_punching());
        assert!(!NatType::Symmetric.supports_hole_punching());
        assert!(!NatType::Unknown.supports_hole_punching());
    }
}
