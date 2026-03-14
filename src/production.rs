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

//! Production hardening features for the P2P Foundation
//!
//! This module provides essential production-ready capabilities including:
//! - Resource management and limits
//! - Graceful shutdown handling
//! - Configuration validation
//! - Rate limiting and throttling
//! - Health checks and diagnostics

use crate::error::NetworkError;
use crate::{P2PError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

/// Production configuration with resource limits and performance tuning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Maximum memory usage in bytes (0 = unlimited)
    pub max_memory_bytes: u64,
    /// Maximum bandwidth per second in bytes
    pub max_bandwidth_bps: u64,
    /// Connection timeout for new peers
    pub connection_timeout: Duration,
    /// Keep-alive interval for existing connections
    pub keep_alive_interval: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Enable automatic resource cleanup
    pub enable_auto_cleanup: bool,
    /// Graceful shutdown timeout
    pub shutdown_timeout: Duration,
    /// Rate limiting configuration
    pub rate_limits: RateLimitConfig,
}

/// Rate limiting configuration for different operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum DHT operations per second per peer
    pub dht_ops_per_sec: u32,
    /// Maximum MCP calls per second per peer
    pub mcp_calls_per_sec: u32,
    /// Maximum messages per second per peer
    pub messages_per_sec: u32,
    /// Burst capacity for rate limiting
    pub burst_capacity: u32,
    /// Rate limit window duration
    pub window_duration: Duration,
}

/// Production resource manager for enforcing limits and monitoring
pub struct ResourceManager {
    pub config: ProductionConfig,
    connection_semaphore: Arc<Semaphore>,
    bandwidth_tracker: Arc<BandwidthTracker>,
    rate_limiters: Arc<RwLock<std::collections::HashMap<String, RateLimiter>>>,
    shutdown_signal: Arc<tokio::sync::Notify>,
    is_shutting_down: Arc<std::sync::atomic::AtomicBool>,
}

/// Bandwidth tracking for monitoring and limiting
struct BandwidthTracker {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    last_reset: Arc<RwLock<Instant>>,
    window_duration: Duration,
}

/// Rate limiter using token bucket algorithm
struct RateLimiter {
    tokens: Arc<std::sync::Mutex<f64>>,
    last_refill: Arc<std::sync::Mutex<Instant>>,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl Default for ProductionConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_memory_bytes: 1024 * 1024 * 1024, // 1GB
            max_bandwidth_bps: 100 * 1024 * 1024, // 100 MB/s
            connection_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(60),
            enable_auto_cleanup: true,
            shutdown_timeout: Duration::from_secs(30),
            rate_limits: RateLimitConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            dht_ops_per_sec: 100,
            mcp_calls_per_sec: 50,
            messages_per_sec: 200,
            burst_capacity: 10,
            window_duration: Duration::from_secs(1),
        }
    }
}

impl ResourceManager {
    /// Create a new resource manager with the given configuration
    pub fn new(config: ProductionConfig) -> Self {
        let connection_semaphore = Arc::new(Semaphore::new(config.max_connections));
        let bandwidth_tracker = Arc::new(BandwidthTracker::new(Duration::from_secs(1)));

        Self {
            config,
            connection_semaphore,
            bandwidth_tracker,
            rate_limiters: Arc::new(RwLock::new(std::collections::HashMap::new())),
            shutdown_signal: Arc::new(tokio::sync::Notify::new()),
            is_shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start the resource manager background tasks
    pub async fn start(&self) -> Result<()> {
        info!("Starting production resource manager");

        // Start health check task
        self.spawn_health_checker().await;

        // Start cleanup task
        if self.config.enable_auto_cleanup {
            self.spawn_cleanup_task().await;
        }

        info!("Production resource manager started successfully");
        Ok(())
    }

    /// Gracefully shutdown the resource manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Initiating graceful shutdown of resource manager");

        self.is_shutting_down.store(true, Ordering::SeqCst);
        self.shutdown_signal.notify_waiters();

        // Wait for shutdown timeout
        tokio::time::timeout(self.config.shutdown_timeout, async {
            // Wait for all connections to close gracefully
            while self.connection_semaphore.available_permits() < self.config.max_connections {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| {
            P2PError::Network(crate::error::NetworkError::ProtocolError(
                "Shutdown timeout exceeded".to_string().into(),
            ))
        })?;

        info!("Resource manager shutdown completed");
        Ok(())
    }

    /// Attempt to acquire a connection slot
    pub async fn acquire_connection(&self) -> Result<ConnectionGuard<'_>> {
        if self.is_shutting_down.load(Ordering::SeqCst) {
            return Err(P2PError::Network(
                crate::error::NetworkError::ProtocolError(
                    "System is shutting down".to_string().into(),
                ),
            ));
        }

        let permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                P2PError::Network(crate::error::NetworkError::ProtocolError(
                    "Connection semaphore closed".to_string().into(),
                ))
            })?;

        debug!(
            "Connection acquired, {} remaining",
            self.connection_semaphore.available_permits()
        );
        Ok(ConnectionGuard {
            permit,
            _manager: self,
        })
    }

    /// Check if a peer is within rate limits for the given operation
    pub async fn check_rate_limit(&self, peer_id: &str, operation: &str) -> Result<bool> {
        let limit = match operation {
            "dht" => self.config.rate_limits.dht_ops_per_sec,
            "mcp" => self.config.rate_limits.mcp_calls_per_sec,
            "message" => self.config.rate_limits.messages_per_sec,
            _ => return Ok(true), // Unknown operation, allow
        };

        let mut limiters = self.rate_limiters.write().await;
        let limiter = limiters.entry(peer_id.to_string()).or_insert_with(|| {
            RateLimiter::new(limit as f64, self.config.rate_limits.burst_capacity as f64)
        });

        limiter.try_acquire()
    }

    /// Record bandwidth usage
    pub fn record_bandwidth(&self, bytes_sent: u64, bytes_received: u64) {
        self.bandwidth_tracker.record(bytes_sent, bytes_received);
    }

    /// Get the number of available connection permits
    pub fn connection_semaphore_available(&self) -> usize {
        self.connection_semaphore.available_permits()
    }

    /// Check if the system is healthy
    pub async fn health_check(&self) -> Result<()> {
        let active_connections =
            self.config.max_connections - self.connection_semaphore.available_permits();
        let bandwidth_usage = self.bandwidth_tracker.current_usage();

        // Check bandwidth usage
        if bandwidth_usage > self.config.max_bandwidth_bps {
            warn!(
                "Bandwidth usage ({} bps) exceeds limit ({} bps)",
                bandwidth_usage, self.config.max_bandwidth_bps
            );
        }

        // Check connection count
        if active_connections >= self.config.max_connections {
            warn!(
                "Connection count ({}) at maximum ({})",
                active_connections, self.config.max_connections
            );
        }

        debug!(
            "Health check passed: {} connections, {} bps bandwidth",
            active_connections, bandwidth_usage
        );

        Ok(())
    }

    /// Spawn health check background task
    async fn spawn_health_checker(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(manager.config.health_check_interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = manager.health_check().await {
                            error!("Health check failed: {}", e);
                        }
                    }
                    _ = manager.shutdown_signal.notified() => {
                        debug!("Health checker shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Spawn cleanup background task
    async fn spawn_cleanup_task(&self) {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(300)); // Cleanup every 5 minutes
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        manager.cleanup_resources().await;
                    }
                    _ = manager.shutdown_signal.notified() => {
                        debug!("Cleanup task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Clean up expired resources
    async fn cleanup_resources(&self) {
        debug!("Starting resource cleanup");

        // Clean up expired rate limiters
        let mut limiters = self.rate_limiters.write().await;
        let now = Instant::now();
        limiters.retain(|_, limiter| {
            // If is_expired fails, assume it's expired and remove it
            match limiter.is_expired(now) {
                Ok(expired) => !expired,
                Err(_) => false,
            }
        });

        debug!(
            "Cleanup completed, {} rate limiters remaining",
            limiters.len()
        );
    }
}

// Implement Clone for ResourceManager to allow sharing across tasks
impl Clone for ResourceManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            connection_semaphore: self.connection_semaphore.clone(),
            bandwidth_tracker: self.bandwidth_tracker.clone(),
            rate_limiters: self.rate_limiters.clone(),
            shutdown_signal: self.shutdown_signal.clone(),
            is_shutting_down: self.is_shutting_down.clone(),
        }
    }
}

/// RAII guard for connection permits
pub struct ConnectionGuard<'a> {
    #[allow(dead_code)]
    permit: tokio::sync::OwnedSemaphorePermit,
    _manager: &'a ResourceManager,
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        debug!("Connection released");
    }
}

impl BandwidthTracker {
    fn new(window_duration: Duration) -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_reset: Arc::new(RwLock::new(Instant::now())),
            window_duration,
        }
    }

    fn record(&self, bytes_sent: u64, bytes_received: u64) {
        self.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    fn current_usage(&self) -> u64 {
        let now = Instant::now();

        // Try to read last reset time non-blocking first
        let last_reset = {
            if let Ok(guard) = self.last_reset.try_read() {
                *guard
            } else {
                // If we can't get a read lock, return current values without reset
                let sent = self.bytes_sent.load(Ordering::Relaxed);
                let received = self.bytes_received.load(Ordering::Relaxed);
                return sent + received; // Return raw bytes without rate calculation
            }
        };

        if now.duration_since(last_reset) >= self.window_duration {
            // Try to reset counters for new window
            if let Ok(mut guard) = self.last_reset.try_write() {
                self.bytes_sent.store(0, Ordering::Relaxed);
                self.bytes_received.store(0, Ordering::Relaxed);
                *guard = now;
                return 0;
            }
        }

        let sent = self.bytes_sent.load(Ordering::Relaxed);
        let received = self.bytes_received.load(Ordering::Relaxed);

        // Calculate bytes per second
        let elapsed_secs = now.duration_since(last_reset).as_secs_f64();
        if elapsed_secs > 0.0 {
            ((sent + received) as f64 / elapsed_secs) as u64
        } else {
            0
        }
    }
}

impl RateLimiter {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: Arc::new(std::sync::Mutex::new(max_tokens)),
            last_refill: Arc::new(std::sync::Mutex::new(Instant::now())),
            max_tokens,
            refill_rate,
        }
    }

    fn try_acquire(&self) -> Result<bool> {
        let now = Instant::now();

        // Refill tokens based on elapsed time
        {
            let mut last_refill = self.last_refill.lock().map_err(|_| {
                P2PError::Network(NetworkError::ProtocolError(
                    "mutex lock failed".to_string().into(),
                ))
            })?;
            let elapsed = now.duration_since(*last_refill).as_secs_f64();

            if elapsed > 0.0 {
                let mut tokens = self.tokens.lock().map_err(|_| {
                    P2PError::Network(NetworkError::ProtocolError(
                        "mutex lock failed".to_string().into(),
                    ))
                })?;
                *tokens = (*tokens + elapsed * self.refill_rate).min(self.max_tokens);
                *last_refill = now;
            }
        }

        // Try to consume a token
        let mut tokens = self.tokens.lock().map_err(|_| {
            P2PError::Network(NetworkError::ProtocolError(
                "mutex lock failed".to_string().into(),
            ))
        })?;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn is_expired(&self, now: Instant) -> Result<bool> {
        let last_refill = *self.last_refill.lock().map_err(|_| {
            P2PError::Network(NetworkError::ProtocolError(
                "mutex lock failed".to_string().into(),
            ))
        })?;
        Ok(now.duration_since(last_refill) > Duration::from_secs(300)) // 5 minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    fn create_test_config() -> ProductionConfig {
        ProductionConfig {
            max_connections: 10,
            max_memory_bytes: 1024 * 1024,  // 1MB for testing
            max_bandwidth_bps: 1024 * 1024, // 1MB/s for testing
            connection_timeout: Duration::from_millis(100),
            keep_alive_interval: Duration::from_millis(50),
            health_check_interval: Duration::from_millis(50),
            enable_auto_cleanup: true,
            shutdown_timeout: Duration::from_millis(200),
            rate_limits: RateLimitConfig {
                dht_ops_per_sec: 5,
                mcp_calls_per_sec: 3,
                messages_per_sec: 10,
                burst_capacity: 5,
                window_duration: Duration::from_millis(100),
            },
        }
    }

    #[test]
    fn test_production_config_default() {
        let config = ProductionConfig::default();
        assert_eq!(config.max_connections, 1000);
        assert_eq!(config.max_memory_bytes, 1024 * 1024 * 1024); // 1GB
        assert_eq!(config.max_bandwidth_bps, 100 * 1024 * 1024); // 100MB/s
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.keep_alive_interval, Duration::from_secs(30));
        assert_eq!(config.health_check_interval, Duration::from_secs(60));
        assert!(config.enable_auto_cleanup);
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.dht_ops_per_sec, 100);
        assert_eq!(config.mcp_calls_per_sec, 50);
        assert_eq!(config.messages_per_sec, 200);
        assert_eq!(config.burst_capacity, 10);
        assert_eq!(config.window_duration, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_resource_manager_creation() {
        let config = create_test_config();
        let _manager = ResourceManager::new(config.clone());

        // Verify the manager was created successfully with the given config
        assert_eq!(_manager.config.max_connections, 10);
    }

    #[tokio::test]
    async fn test_resource_manager_cloning() -> Result<()> {
        let config = create_test_config();
        let manager = ResourceManager::new(config);
        let cloned = manager.clone();

        // Both should work independently
        let _guard1 = manager.acquire_connection().await?;
        let _guard2 = cloned.acquire_connection().await?;

        // But they share the same semaphore
        assert_eq!(manager.connection_semaphore.available_permits(), 8);
        assert_eq!(cloned.connection_semaphore.available_permits(), 8);

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_acquisition() -> Result<()> {
        let config = ProductionConfig {
            max_connections: 2,
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Acquire first connection
        let _guard1 = manager.acquire_connection().await?;
        assert_eq!(manager.connection_semaphore.available_permits(), 1);

        // Acquire second connection
        let _guard2 = manager.acquire_connection().await?;
        assert_eq!(manager.connection_semaphore.available_permits(), 0);

        // Drop first guard and check permit is released
        drop(_guard1);
        sleep(Duration::from_millis(1)).await; // Allow time for cleanup
        assert_eq!(manager.connection_semaphore.available_permits(), 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_connection_acquisition_during_shutdown() {
        let config = create_test_config();
        let manager = ResourceManager::new(config);

        // Mark as shutting down
        manager.is_shutting_down.store(true, Ordering::SeqCst);

        // Should fail to acquire connection during shutdown
        let result = manager.acquire_connection().await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("shutting down")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_connection_guard_drop() -> Result<()> {
        let config = create_test_config();
        let manager = ResourceManager::new(config);

        let initial_permits = manager.connection_semaphore.available_permits();
        {
            let _guard = manager.acquire_connection().await?;
            assert_eq!(
                manager.connection_semaphore.available_permits(),
                initial_permits - 1
            );
        }
        // Guard should be dropped and permit released
        assert_eq!(
            manager.connection_semaphore.available_permits(),
            initial_permits
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting_dht_operations() -> Result<()> {
        let config = ProductionConfig {
            rate_limits: RateLimitConfig {
                dht_ops_per_sec: 2,
                burst_capacity: 2,
                ..Default::default()
            },
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Should allow burst capacity
        assert!(manager.check_rate_limit("peer1", "dht").await?);
        assert!(manager.check_rate_limit("peer1", "dht").await?);

        // Should deny after burst exhausted
        assert!(!manager.check_rate_limit("peer1", "dht").await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting_mcp_operations() -> Result<()> {
        let config = ProductionConfig {
            rate_limits: RateLimitConfig {
                mcp_calls_per_sec: 1,
                burst_capacity: 1,
                ..Default::default()
            },
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Should allow first MCP call
        assert!(manager.check_rate_limit("peer2", "mcp").await?);

        // Should deny second MCP call
        assert!(!manager.check_rate_limit("peer2", "mcp").await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting_message_operations() -> Result<()> {
        let config = ProductionConfig {
            rate_limits: RateLimitConfig {
                messages_per_sec: 3,
                burst_capacity: 3,
                ..Default::default()
            },
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Should allow burst capacity for messages
        for _ in 0..3 {
            assert!(manager.check_rate_limit("peer3", "message").await?);
        }

        // Should deny after burst exhausted
        assert!(!manager.check_rate_limit("peer3", "message").await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting_unknown_operation() -> Result<()> {
        let config = create_test_config();
        let manager = ResourceManager::new(config);

        // Unknown operations should be allowed
        assert!(manager.check_rate_limit("peer4", "unknown").await?);
        assert!(manager.check_rate_limit("peer4", "unknown").await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting_different_peers() -> Result<()> {
        let config = ProductionConfig {
            rate_limits: RateLimitConfig {
                dht_ops_per_sec: 1,
                burst_capacity: 1,
                ..Default::default()
            },
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Each peer should have independent rate limits
        assert!(manager.check_rate_limit("peer1", "dht").await?);
        assert!(manager.check_rate_limit("peer2", "dht").await?);

        // But each peer should be limited individually
        assert!(!manager.check_rate_limit("peer1", "dht").await?);
        assert!(!manager.check_rate_limit("peer2", "dht").await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_bandwidth_tracking() {
        let tracker = BandwidthTracker::new(Duration::from_millis(100)); // Shorter window for testing

        tracker.record(1000, 2000);
        let usage = tracker.current_usage();
        assert!(usage > 0);

        // Test reset after window
        sleep(Duration::from_millis(150)).await; // Wait longer than window
        let usage_after_reset = tracker.current_usage();
        assert_eq!(usage_after_reset, 0);
    }

    #[tokio::test]
    async fn test_bandwidth_tracking_rate_calculation() {
        let tracker = BandwidthTracker::new(Duration::from_secs(1));

        // Record some bytes
        tracker.record(500, 500); // 1000 bytes total

        // Wait a short time
        sleep(Duration::from_millis(50)).await;

        let usage = tracker.current_usage();
        // Should calculate bytes per second
        assert!(usage > 10000); // 1000 bytes in 0.05 seconds = ~20000 bps
    }

    #[tokio::test]
    async fn test_bandwidth_tracking_multiple_records() {
        let tracker = BandwidthTracker::new(Duration::from_millis(200));

        tracker.record(100, 200);
        tracker.record(300, 400);
        tracker.record(500, 600);

        let usage = tracker.current_usage();
        assert!(usage > 0);

        // All records should be included in calculation
        let sent = tracker.bytes_sent.load(Ordering::Relaxed);
        let received = tracker.bytes_received.load(Ordering::Relaxed);
        assert_eq!(sent, 900); // 100 + 300 + 500
        assert_eq!(received, 1200); // 200 + 400 + 600
    }

    #[tokio::test]
    async fn test_manager_bandwidth_recording() {
        let config = create_test_config();
        let manager = ResourceManager::new(config);

        // Record some bandwidth usage
        manager.record_bandwidth(1000, 2000);

        // Should be reflected in current usage
        let usage = manager.bandwidth_tracker.current_usage();
        assert!(usage > 0);
    }

    #[tokio::test]
    async fn test_health_check_success() {
        let config = ProductionConfig {
            max_memory_bytes: 2048,   // 2KB
            max_bandwidth_bps: 10000, // 10KB/s
            max_connections: 5,
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Health check should pass with default metrics
        let result = manager.health_check().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_check_bandwidth_warning() {
        let config = ProductionConfig {
            max_bandwidth_bps: 1, // Very low limit to trigger warning
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Record bandwidth to exceed the limit
        manager.record_bandwidth(1000, 2000);

        // Health check should still pass (bandwidth warning only)
        let result = manager.health_check().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_check_connection_warning() -> Result<()> {
        let config = ProductionConfig {
            max_connections: 2,
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Acquire maximum connections
        let _guard1 = manager.acquire_connection().await?;
        let _guard2 = manager.acquire_connection().await?;

        // Health check should still pass (connection warning only)
        let result = manager.health_check().await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_graceful_shutdown() -> Result<()> {
        let config = ProductionConfig {
            shutdown_timeout: Duration::from_millis(100),
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Start manager
        manager.start().await?;

        // Shutdown should complete successfully
        let result = manager.shutdown().await;
        assert!(result.is_ok());

        // Should be marked as shutting down
        assert!(manager.is_shutting_down.load(Ordering::SeqCst));

        Ok(())
    }

    #[tokio::test]
    async fn test_graceful_shutdown_with_connections() -> Result<()> {
        let config = ProductionConfig {
            shutdown_timeout: Duration::from_millis(200),
            max_connections: 2,
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Acquire a connection
        let guard = manager.acquire_connection().await?;

        // Start shutdown in background
        let manager_clone = manager.clone();
        let shutdown_task = tokio::spawn(async move { manager_clone.shutdown().await });

        // Wait a bit then release connection
        sleep(Duration::from_millis(50)).await;
        drop(guard);

        // Shutdown should complete
        let result = shutdown_task.await.expect("Task panicked");
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_shutdown_timeout() -> Result<()> {
        let config = ProductionConfig {
            shutdown_timeout: Duration::from_millis(50), // Very short timeout
            max_connections: 1,
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Acquire and hold a connection
        let _guard = manager.acquire_connection().await?;

        // Shutdown should timeout
        let result = manager.shutdown().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Shutdown timeout"));
        Ok(())
    }

    #[tokio::test]
    async fn test_start_with_disabled_features() {
        let config = ProductionConfig {
            enable_auto_cleanup: false,
            ..create_test_config()
        };
        let manager = ResourceManager::new(config);

        // Should start successfully even with features disabled
        let result = manager.start().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(10.0, 5.0); // 10 tokens max, 5 per second refill

        // Should start with full capacity
        assert!(limiter.try_acquire().expect("Should succeed in test"));
    }

    #[test]
    fn test_rate_limiter_token_exhaustion() {
        let limiter = RateLimiter::new(2.0, 1.0); // 2 tokens max, 1 per second refill

        // Should allow 2 acquisitions
        assert!(limiter.try_acquire().expect("Should succeed in test"));
        assert!(limiter.try_acquire().expect("Should succeed in test"));

        // Should deny third acquisition
        assert!(!limiter.try_acquire().expect("Should succeed in test"));
    }

    #[tokio::test]
    async fn test_rate_limiter_refill() {
        let limiter = RateLimiter::new(1.0, 10.0); // 1 token max, 10 per second refill

        // Exhaust tokens
        assert!(limiter.try_acquire().expect("Should succeed in test"));
        assert!(!limiter.try_acquire().expect("Should succeed in test"));

        // Wait for refill
        sleep(Duration::from_millis(200)).await; // Should refill at least 2 tokens

        // Should allow acquisition again
        assert!(limiter.try_acquire().expect("Should succeed in test"));
    }

    #[test]
    fn test_rate_limiter_expiration() {
        let limiter = RateLimiter::new(10.0, 5.0);

        // Should not be expired initially
        assert!(
            !limiter
                .is_expired(Instant::now())
                .expect("Should succeed in test")
        );

        // Should be expired after 5+ minutes
        let future_time = Instant::now() + Duration::from_secs(400);
        assert!(
            limiter
                .is_expired(future_time)
                .expect("Should succeed in test")
        );
    }

    #[tokio::test]
    async fn test_cleanup_resources() -> Result<()> {
        let config = create_test_config();
        let manager = ResourceManager::new(config);

        // Add some rate limiters
        manager.check_rate_limit("peer1", "dht").await?;
        manager.check_rate_limit("peer2", "mcp").await?;

        // Should have rate limiters
        {
            let limiters = manager.rate_limiters.read().await;
            assert_eq!(limiters.len(), 2);
        }

        // Run cleanup (shouldn't remove recent limiters)
        manager.cleanup_resources().await;

        {
            let limiters = manager.rate_limiters.read().await;
            assert_eq!(limiters.len(), 2); // Should still have both
        }
        Ok(())
    }

    #[test]
    fn test_bandwidth_tracker_creation() {
        let tracker = BandwidthTracker::new(Duration::from_secs(1));

        // Should start with zero usage
        assert_eq!(tracker.current_usage(), 0);
    }

    #[test]
    fn test_bandwidth_tracker_window_reset() {
        let tracker = BandwidthTracker::new(Duration::from_millis(1)); // Very short window

        tracker.record(1000, 2000);

        // Immediately check usage
        let initial_usage = tracker.current_usage();
        assert!(initial_usage > 0);

        // Wait for window to expire and check again
        std::thread::sleep(Duration::from_millis(10));
        let usage_after_window = tracker.current_usage();
        assert_eq!(usage_after_window, 0);
    }
}
