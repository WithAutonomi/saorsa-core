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

//! Extensions to NodeIdentity for comprehensive test support (sans PoW)

use super::node_identity::{PeerId, NodeIdentity};
use crate::{P2PError, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;

impl NodeIdentity {
    /// Save identity to file
    pub async fn save_to_file(&self, path: &Path) -> Result<()> {
        let data = self.export();
        let json = serde_json::to_string_pretty(&data).map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to serialize identity: {}", e).into(),
            ))
        })?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    format!("Failed to create directory: {}", e).into(),
                ))
            })?;
        }

        fs::write(path, json).await.map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to write identity file: {}", e).into(),
            ))
        })?;

        Ok(())
    }

    /// Load identity from file
    pub async fn load_from_file(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path).await.map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to read identity file: {}", e).into(),
            ))
        })?;

        let data: super::node_identity::IdentityData =
            serde_json::from_str(&json).map_err(|e| {
                P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    format!("Failed to deserialize identity: {}", e).into(),
                ))
            })?;

        Self::import(&data)
    }

    /// Get default identity path
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                "Could not determine home directory".into(),
            ))
        })?;

        Ok(home.join(".p2p").join("identity.json"))
    }

    /// Save to default location
    pub async fn save_default(&self) -> Result<()> {
        let path = Self::default_path()?;
        self.save_to_file(&path).await
    }

    /// Load from default location
    pub async fn load_default() -> Result<Self> {
        let path = Self::default_path()?;
        Self::load_from_file(&path).await
    }

}
