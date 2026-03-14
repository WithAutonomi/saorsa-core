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

//! Component health checkers for various P2P subsystems

#![allow(dead_code)]

use super::HealthStatus;
use crate::Result;
use async_trait::async_trait;
use serde_json::Value as JsonValue;
use tokio::time::{Duration, timeout};

// Reduce type complexity with aliases for boxed async fn types
type BoxedAsyncUsizeFn = Box<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>> + Send>>
        + Send
        + Sync,
>;
type BoxedAsyncBoolFn = Box<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send>>
        + Send
        + Sync,
>;

/// Trait for component health checkers
#[async_trait]
pub trait ComponentChecker: Send + Sync {
    /// Check the health of the component
    async fn check(&self) -> Result<HealthStatus>;

    /// Get debug information about the component
    async fn debug_info(&self) -> Option<JsonValue> {
        None
    }
}

/// Network connectivity health checker
///
/// This is a placeholder implementation that will be connected to the actual
/// Network type once it's available
pub struct NetworkHealthChecker {
    get_peer_count: BoxedAsyncUsizeFn,
    min_peers: usize,
    timeout_duration: Duration,
}

impl NetworkHealthChecker {
    /// Create a new network health checker with a peer count function
    pub fn new<F, Fut>(get_peer_count: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<usize>> + Send + 'static,
    {
        Self {
            get_peer_count: Box::new(move || Box::pin(get_peer_count())),
            min_peers: 1,
            timeout_duration: Duration::from_millis(50),
        }
    }

    /// Set minimum number of peers for healthy status
    pub fn with_min_peers(mut self, min_peers: usize) -> Self {
        self.min_peers = min_peers;
        self
    }
}

#[async_trait]
impl ComponentChecker for NetworkHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        // Check network connectivity with timeout
        let future = (self.get_peer_count)();
        match timeout(self.timeout_duration, future).await {
            Ok(Ok(count)) => {
                if count >= self.min_peers {
                    Ok(HealthStatus::Healthy)
                } else if count > 0 {
                    Ok(HealthStatus::Degraded)
                } else {
                    Ok(HealthStatus::Unhealthy)
                }
            }
            Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
            Err(_) => Ok(HealthStatus::Unhealthy), // Timeout
        }
    }

    async fn debug_info(&self) -> Option<JsonValue> {
        let future = (self.get_peer_count)();
        if let Ok(Ok(count)) = timeout(self.timeout_duration, future).await {
            Some(serde_json::json!({
                "peer_count": count,
                "min_peers": self.min_peers,
            }))
        } else {
            None
        }
    }
}

/// DHT availability health checker
///
/// This is a placeholder implementation that will be connected to the actual
/// DHT type once it's available
pub struct DhtHealthChecker {
    get_routing_table_size: BoxedAsyncUsizeFn,
    min_nodes: usize,
    timeout_duration: Duration,
}

impl DhtHealthChecker {
    /// Create a new DHT health checker with a routing table size function
    pub fn new<F, Fut>(get_routing_table_size: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<usize>> + Send + 'static,
    {
        Self {
            get_routing_table_size: Box::new(move || Box::pin(get_routing_table_size())),
            min_nodes: 3,
            timeout_duration: Duration::from_millis(50),
        }
    }

    /// Set minimum number of DHT nodes for healthy status
    pub fn with_min_nodes(mut self, min_nodes: usize) -> Self {
        self.min_nodes = min_nodes;
        self
    }
}

#[async_trait]
impl ComponentChecker for DhtHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        // Check DHT routing table
        let future = (self.get_routing_table_size)();
        match timeout(self.timeout_duration, future).await {
            Ok(Ok(size)) => {
                if size >= self.min_nodes {
                    Ok(HealthStatus::Healthy)
                } else if size > 0 {
                    Ok(HealthStatus::Degraded)
                } else {
                    Ok(HealthStatus::Unhealthy)
                }
            }
            Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
            Err(_) => Ok(HealthStatus::Unhealthy), // Timeout
        }
    }

    async fn debug_info(&self) -> Option<JsonValue> {
        let future = (self.get_routing_table_size)();
        if let Ok(Ok(size)) = timeout(self.timeout_duration, future).await {
            Some(serde_json::json!({
                "routing_table_size": size,
                "min_nodes": self.min_nodes,
            }))
        } else {
            None
        }
    }
}

use crate::production::ResourceManager;
use std::sync::Arc;

/// Resource usage health checker
pub struct ResourceHealthChecker {
    resource_manager: Arc<ResourceManager>,
    timeout_duration: Duration,
}

impl ResourceHealthChecker {
    /// Create a new resource health checker
    pub fn new(resource_manager: Arc<ResourceManager>) -> Self {
        Self {
            resource_manager,
            timeout_duration: Duration::from_millis(50),
        }
    }
}

#[async_trait]
impl ComponentChecker for ResourceHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        match timeout(self.timeout_duration, self.resource_manager.health_check()).await {
            Ok(Ok(())) => Ok(HealthStatus::Healthy),
            Ok(Err(_)) => Ok(HealthStatus::Degraded),
            Err(_) => Ok(HealthStatus::Unhealthy), // Timeout
        }
    }

    async fn debug_info(&self) -> Option<JsonValue> {
        let active_connections = self.resource_manager.config.max_connections
            - self.resource_manager.connection_semaphore_available();
        Some(serde_json::json!({
            "active_connections": active_connections,
            "max_connections": self.resource_manager.config.max_connections,
        }))
    }
}

/// Transport health checker
///
/// This is a placeholder implementation that will be connected to the actual
/// Transport type once it's available
pub struct TransportHealthChecker {
    is_listening: BoxedAsyncBoolFn,
    timeout_duration: Duration,
}

impl TransportHealthChecker {
    /// Create a new transport health checker with a listening check function
    pub fn new<F, Fut>(is_listening: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<bool>> + Send + 'static,
    {
        Self {
            is_listening: Box::new(move || Box::pin(is_listening())),
            timeout_duration: Duration::from_millis(50),
        }
    }
}

#[async_trait]
impl ComponentChecker for TransportHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        let future = (self.is_listening)();
        match timeout(self.timeout_duration, future).await {
            Ok(Ok(true)) => Ok(HealthStatus::Healthy),
            Ok(Ok(false)) => Ok(HealthStatus::Unhealthy),
            Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
            Err(_) => Ok(HealthStatus::Unhealthy), // Timeout
        }
    }

    async fn debug_info(&self) -> Option<JsonValue> {
        let future = (self.is_listening)();
        if let Ok(Ok(listening)) = timeout(self.timeout_duration, future).await {
            Some(serde_json::json!({
                "is_listening": listening,
                "transport_type": "p2p",
            }))
        } else {
            None
        }
    }
}

/// Peer connections health checker
///
/// This is a placeholder implementation that will be connected to the actual
/// Network type once it's available
pub struct PeerHealthChecker {
    get_peer_count: BoxedAsyncUsizeFn,
    min_peers: usize,
    max_peers: usize,
    timeout_duration: Duration,
}

impl PeerHealthChecker {
    /// Create a new peer health checker with a peer count function
    pub fn new<F, Fut>(get_peer_count: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<usize>> + Send + 'static,
    {
        Self {
            get_peer_count: Box::new(move || Box::pin(get_peer_count())),
            min_peers: 1,
            max_peers: 1000,
            timeout_duration: Duration::from_millis(50),
        }
    }

    /// Set peer count thresholds
    pub fn with_peer_limits(mut self, min: usize, max: usize) -> Self {
        self.min_peers = min;
        self.max_peers = max;
        self
    }
}

#[async_trait]
impl ComponentChecker for PeerHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        let future = (self.get_peer_count)();
        match timeout(self.timeout_duration, future).await {
            Ok(Ok(count)) => {
                if count < self.min_peers {
                    Ok(HealthStatus::Unhealthy)
                } else if count > self.max_peers {
                    Ok(HealthStatus::Degraded) // Too many peers
                } else {
                    Ok(HealthStatus::Healthy)
                }
            }
            Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
            Err(_) => Ok(HealthStatus::Unhealthy), // Timeout
        }
    }

    async fn debug_info(&self) -> Option<JsonValue> {
        let future = (self.get_peer_count)();
        if let Ok(Ok(count)) = timeout(self.timeout_duration, future).await {
            Some(serde_json::json!({
                "peer_count": count,
                "min_peers": self.min_peers,
                "max_peers": self.max_peers,
            }))
        } else {
            None
        }
    }
}

/// Composite health checker that runs multiple checks
pub struct CompositeHealthChecker {
    checkers: Vec<(&'static str, Box<dyn ComponentChecker>)>,
}

impl Default for CompositeHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositeHealthChecker {
    /// Create a new composite health checker
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
        }
    }

    /// Add a component checker
    pub fn add_checker(mut self, name: &'static str, checker: Box<dyn ComponentChecker>) -> Self {
        self.checkers.push((name, checker));
        self
    }
}

#[async_trait]
impl ComponentChecker for CompositeHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        let mut overall_status = HealthStatus::Healthy;

        for (_, checker) in &self.checkers {
            match checker.check().await {
                Ok(HealthStatus::Unhealthy) => return Ok(HealthStatus::Unhealthy),
                Ok(HealthStatus::Degraded) => overall_status = HealthStatus::Degraded,
                Ok(HealthStatus::Healthy) => {}
                Err(_) => return Ok(HealthStatus::Unhealthy),
            }
        }

        Ok(overall_status)
    }

    async fn debug_info(&self) -> Option<JsonValue> {
        let mut info = serde_json::json!({});

        for (name, checker) in &self.checkers {
            if let Some(debug) = checker.debug_info().await {
                info[name] = debug;
            }
        }

        Some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test implementations
    struct TestNetwork {
        peer_count: usize,
    }

    impl TestNetwork {
        fn new(peer_count: usize) -> Self {
            Self { peer_count }
        }

        async fn peer_count(&self) -> Result<usize> {
            Ok(self.peer_count)
        }

        async fn debug_info(&self) -> Result<NetworkDebugInfo> {
            Ok(NetworkDebugInfo {
                peer_count: self.peer_count,
                active_connections: self.peer_count,
                listening_addresses: vec![],
                protocols: vec![],
            })
        }
    }

    struct NetworkDebugInfo {
        peer_count: usize,
        active_connections: usize,
        listening_addresses: Vec<String>,
        protocols: Vec<String>,
    }

    struct TestDHT {
        routing_table_size: usize,
    }

    impl TestDHT {
        fn new(size: usize) -> Self {
            Self {
                routing_table_size: size,
            }
        }

        async fn routing_table_size(&self) -> Result<usize> {
            Ok(self.routing_table_size)
        }

        async fn debug_info(&self) -> Result<DhtDebugInfo> {
            Ok(DhtDebugInfo {
                routing_table_size: self.routing_table_size,
                pending_queries: 0,
            })
        }
    }

    struct DhtDebugInfo {
        routing_table_size: usize,
        pending_queries: usize,
    }

    struct TestTransport {
        listening: bool,
    }

    impl TestTransport {
        fn new(listening: bool) -> Self {
            Self { listening }
        }

        async fn is_listening(&self) -> Result<bool> {
            Ok(self.listening)
        }

        async fn debug_info(&self) -> Result<TransportDebugInfo> {
            Ok(TransportDebugInfo {
                transport_type: "test".to_string(),
                listening_addresses: vec![],
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
            })
        }
    }

    struct TransportDebugInfo {
        transport_type: String,
        listening_addresses: Vec<String>,
        active_connections: usize,
        bytes_sent: u64,
        bytes_received: u64,
    }

    #[tokio::test]
    async fn test_composite_health_checker() {
        // Test composite with simple checkers
        struct AlwaysHealthy;
        #[async_trait]
        impl ComponentChecker for AlwaysHealthy {
            async fn check(&self) -> Result<HealthStatus> {
                Ok(HealthStatus::Healthy)
            }
        }

        struct AlwaysDegraded;
        #[async_trait]
        impl ComponentChecker for AlwaysDegraded {
            async fn check(&self) -> Result<HealthStatus> {
                Ok(HealthStatus::Degraded)
            }
        }

        let checker = CompositeHealthChecker::new()
            .add_checker("healthy", Box::new(AlwaysHealthy))
            .add_checker("degraded", Box::new(AlwaysDegraded));

        let status = checker.check().await.unwrap();
        assert_eq!(status, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn test_composite_health_checker_unhealthy() {
        struct AlwaysUnhealthy;
        #[async_trait]
        impl ComponentChecker for AlwaysUnhealthy {
            async fn check(&self) -> Result<HealthStatus> {
                Ok(HealthStatus::Unhealthy)
            }
        }

        let checker =
            CompositeHealthChecker::new().add_checker("unhealthy", Box::new(AlwaysUnhealthy));

        let status = checker.check().await.unwrap();
        assert_eq!(status, HealthStatus::Unhealthy);
    }
}
