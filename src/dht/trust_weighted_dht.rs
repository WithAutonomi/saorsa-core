//! Trust-weighted DHT trait definition
//!
//! Defines the interface for DHT peer discovery with trust bias.

pub use crate::identity::node_identity::PeerId;
use anyhow::Result;

/// DHT key type (256-bit)
pub type Key = [u8; 32];

/// Contact information for routing
#[derive(Debug, Clone)]
pub struct Contact {
    pub peer: PeerId,
    pub address: String,
}

/// DHT trait for trust-weighted peer discovery (phonebook only)
#[async_trait::async_trait]
pub trait Dht {
    /// Find nodes closest to the target
    async fn find_node(&self, target: PeerId) -> Result<Vec<Contact>>;
}

/// Interaction outcome for trust recording
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Ok,
    Timeout,
    BadData,
    Refused,
}

/// Record an interaction outcome for trust computation
pub async fn record_interaction(_peer: PeerId, _outcome: Outcome) {
    // Global trust recording - would need access to DHT instance
    // This is a placeholder for the global function
}

/// Run EigenTrust computation epoch
pub async fn eigen_trust_epoch() {
    // Global EigenTrust computation - would need access to DHT instance
    // This is a placeholder for the global function
}
