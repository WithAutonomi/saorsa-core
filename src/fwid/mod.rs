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

//! Key derivation and hashing utilities.
//!
//! Provides a 32-byte BLAKE3 key type used for content-addressed lookups.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte BLAKE3 key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key([u8; 32]);

impl Key {
    /// Create a new key from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).context("Invalid hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("Key must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl From<[u8; 32]> for Key {
    fn from(value: [u8; 32]) -> Self {
        Key(value)
    }
}

impl From<Key> for [u8; 32] {
    fn from(value: Key) -> Self {
        value.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hex() {
        let bytes = [42u8; 32];
        let key = Key::new(bytes);
        let hex = key.to_hex();
        let recovered = Key::from_hex(&hex).unwrap();
        assert_eq!(key, recovered);
    }
}
