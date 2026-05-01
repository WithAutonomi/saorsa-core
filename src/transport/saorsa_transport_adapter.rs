// Copyright 2024 Saorsa Labs Limited
//
// Adapter for saorsa-transport integration

//! Ant-QUIC Transport Adapter
//!
//! This module provides a clean interface to saorsa-transport's peer-to-peer networking
//! with advanced NAT traversal and post-quantum cryptography.
//!
//! ## Architecture
//!
//! Uses saorsa-transport's LinkTransport trait abstraction:
//! - `P2pLinkTransport` for real network communication
//! - `MockTransport` for testing overlay logic
//! - All communication uses `SocketAddr` for connection addressing
//! - Authenticated public keys exposed via `LinkConn::peer_public_key()`
//! - Built-in NAT traversal, peer discovery, and post-quantum crypto
//!
//! ## Protocol Multiplexing
//!
//! The adapter uses protocol identifiers for overlay network multiplexing:
//! - `SAORSA_DHT_PROTOCOL` ("saorsa-dht/1.0.0") for DHT operations
//! - Custom protocols can be registered for different services
//!
//! **IMPORTANT**: Protocol-based filtering in `accept()` is not yet implemented in saorsa-transport.
//! The `accept()` method accepts all incoming connections regardless of protocol.
//! Applications must validate the protocol on received connections.
//!
//! ## NAT Traversal Configuration
//!
//! NAT traversal behavior is configured via `NetworkConfig`:
//! - `ClientOnly` - No incoming path validations (client mode)
//! - `P2PNode { concurrency_limit }` - Full P2P with configurable concurrency
//! - `Advanced { ... }` - Fine-grained control over all NAT options
//!
//! ## Metrics Integration
//!
//! When saorsa-core is compiled with the `metrics` feature, this adapter
//! automatically enables saorsa-transport's prometheus metrics collection.

use crate::error::{GeoRejectionError, GeographicConfig};
use crate::security::canonicalize_ip;
use crate::transport::external_addresses::ExternalAddresses;
use anyhow::{Context, Result};
use dashmap::{DashMap, DashSet};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace};

// Import saorsa-transport types using the new LinkTransport API (0.14+)
use saorsa_transport::{
    LinkConn, LinkEvent, LinkTransport, NatConfig, P2pConfig, P2pLinkTransport, ProtocolId, Side,
    StrategyConfig,
};

// Import saorsa-transport types for SharedTransport integration
use futures::StreamExt;
use saorsa_transport::SharedTransport;
use saorsa_transport::link_transport::StreamType;

/// Protocol identifier for saorsa DHT overlay
///
/// This protocol identifier is used for multiplexing saorsa's DHT traffic
/// over the QUIC transport. Other protocols can be registered for different services.
pub const SAORSA_DHT_PROTOCOL: ProtocolId = ProtocolId::from_static(b"saorsa-dht/1.0.0");

/// Connection lifecycle events from saorsa-transport
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConnectionEvent {
    /// Connection successfully established
    Established {
        remote_address: SocketAddr,
        public_key: Option<Vec<u8>>,
    },
    /// Connection lost/closed
    Lost {
        remote_address: SocketAddr,
        reason: String,
    },
    /// Connection attempt failed
    Failed {
        remote_address: SocketAddr,
        reason: String,
    },
    /// A connected peer advertised a new reachable address (ADD_ADDRESS frame).
    PeerAddressUpdated {
        peer_addr: SocketAddr,
        advertised_addr: SocketAddr,
    },
}

/// Native saorsa-transport network node using LinkTransport abstraction
///
/// This provides a clean interface to saorsa-transport's peer-to-peer networking
/// with advanced NAT traversal and post-quantum cryptography.
///
/// Generic over the transport type to allow testing with MockTransport.
#[allow(dead_code)]
pub struct P2PNetworkNode<T: LinkTransport = P2pLinkTransport> {
    /// The underlying transport (generic for testing)
    transport: Arc<T>,
    /// Our local binding address
    pub local_addr: SocketAddr,
    /// Peer registry for tracking connected peer addresses
    pub peers: Arc<RwLock<Vec<SocketAddr>>>,
    /// Connection event broadcaster
    event_tx: broadcast::Sender<ConnectionEvent>,
    /// Shutdown signal for event polling task
    shutdown: CancellationToken,
    /// Event forwarder task handle
    event_task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Geographic configuration for diversity enforcement
    geo_config: Option<GeographicConfig>,
    /// Peer region tracking for geographic diversity
    peer_regions: Arc<RwLock<HashMap<String, usize>>>,
    /// Peer quality scores from saorsa-transport Capabilities, keyed by SocketAddr
    peer_quality: Arc<RwLock<HashMap<SocketAddr, f32>>>,
    /// Shared transport for protocol multiplexing
    shared_transport: Arc<SharedTransport<T>>,
}

/// Default maximum number of concurrent QUIC connections when not
/// explicitly configured.
pub const DEFAULT_MAX_CONNECTIONS: usize = 100;

/// Bounded capacity for the relay/peer-address forwarder mpsc channels.
///
/// Replaces the previous `unbounded_channel` so a slow consumer (e.g. the
/// DHT bridge while running an iterative lookup) cannot grow the queue
/// without limit. When the channel is full the forwarder logs and drops
/// the event rather than blocking the receive loop, so we still keep
/// processing newer events.
pub const ADDRESS_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Log a warning every Nth dropped address-event in the forwarder.
///
/// `try_send` failures (channel full) increment a counter; logging at
/// every drop would flood the log under sustained pressure, so we
/// coalesce to one warning per `ADDRESS_EVENT_DROP_LOG_INTERVAL` drops.
const ADDRESS_EVENT_DROP_LOG_INTERVAL: u64 = 32;

/// Resolution-delay budget for the IPv4 attempt in
/// [`DualStackNetworkNode::connect_happy_eyeballs`]'s race.
///
/// Per RFC 8305 §8 ("Connection Attempt Delay"), 50 ms is a sensible
/// default that prefers IPv6 when both stacks are reachable but lets
/// IPv4 take over quickly when the v6 attempt is failing or stalled.
const HAPPY_EYEBALLS_V4_STAGGER: Duration = Duration::from_millis(50);

/// Per-attempt direct-connect timeout used by the Happy Eyeballs race.
///
/// saorsa-transport's `StrategyConfig` default is 3 s, sized for relay
/// handshakes that add one extra RTT. With the dial planner now capping
/// attempts at two addresses per peer (see
/// [`crate::dht_network_manager::DhtNetworkManager::select_dial_candidates`]),
/// a tighter 2 s budget matches the direct / relay-transport RTT we see
/// in practice and shaves a full second off worst-case cold-start
/// latency when the first address is unreachable.
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Increment the drop counter and log periodically when the address-event
/// forwarder fails to push into a bounded channel.
///
/// Used by the forwarder loop in
/// [`DualStackNetworkNode::spawn_peer_address_update_forwarder`] when the
/// downstream consumer is too slow to drain. Drops are coalesced to one
/// warning per [`ADDRESS_EVENT_DROP_LOG_INTERVAL`] events to avoid log
/// floods under sustained backpressure; the very first drop in any burst
/// is always logged so operators see the onset.
fn handle_address_event_drop<T>(
    counter: &AtomicU64,
    event_kind: &'static str,
    err: &tokio::sync::mpsc::error::TrySendError<T>,
) {
    let prev = counter.fetch_add(1, Ordering::Relaxed);
    let kind = match err {
        tokio::sync::mpsc::error::TrySendError::Full(_) => "channel full",
        tokio::sync::mpsc::error::TrySendError::Closed(_) => "consumer closed",
    };
    if prev.is_multiple_of(ADDRESS_EVENT_DROP_LOG_INTERVAL) {
        tracing::warn!(
            event = event_kind,
            reason = kind,
            total_drops = prev + 1,
            "ADDR_FWD: dropped address event"
        );
    }
}

/// Handle a `P2pEvent::PeerConnected` event for the passive
/// reachability classifier.
///
/// Runs the source-disjoint / sibling-hairpin filters, updates
/// `known_peer_ips`, and on a passing `Side::Server` inbound:
/// 1. Marks the peer's IP as `proof_eligible`.
/// 2. Credits the peer's IP against any externals they have already
///    reported observing us at (intersected with currently pinned
///    externals).
///
/// Pure with respect to its arguments — extracted from
/// [`DualStackNetworkNode::spawn_direct_reachability_classifier`] so
/// the per-event logic is independently testable without spawning the
/// whole broadcast loop.
fn handle_peer_connected_for_proof(
    addr: saorsa_transport::TransportAddr,
    side: Side,
    dialed: &DashSet<SocketAddr>,
    known: &DashSet<IpAddr>,
    external: &parking_lot::Mutex<ExternalAddresses>,
    observations: &DashMap<IpAddr, HashSet<SocketAddr>>,
    eligible: &DashSet<IpAddr>,
    proven: &DashMap<SocketAddr, HashSet<IpAddr>>,
) {
    let Some(socket_addr) = addr.as_socket_addr() else {
        tracing::trace!(
            remote = %addr,
            "classifier: ignoring non-socket transport handshake"
        );
        return;
    };
    let normalized = saorsa_transport::shared::normalize_socket_addr(socket_addr);
    let remote_ip = canonicalize_ip(normalized.ip());

    let was_known_before = known.contains(&remote_ip) || dialed.contains(&normalized);
    known.insert(remote_ip);

    if !matches!(side, Side::Server) {
        tracing::trace!(
            remote = %normalized,
            side = ?side,
            "classifier: recorded outbound peer; not a proof candidate"
        );
        return;
    }

    if was_known_before {
        tracing::debug!(
            remote = %normalized,
            "classifier: ignoring inbound from previously-known peer \
             (not source-disjoint; possible pinhole redial)"
        );
        return;
    }

    let pinned_direct = external.lock().direct_addresses();
    let is_own_external_ip = pinned_direct
        .iter()
        .any(|sa| canonicalize_ip(sa.ip()) == remote_ip);
    if is_own_external_ip {
        tracing::trace!(
            remote = %normalized,
            "classifier: ignoring sibling-hairpin handshake from own external IP"
        );
        return;
    }

    eligible.insert(remote_ip);

    if let Some(reports) = observations.get(&remote_ip) {
        // Materialise to a local Vec so the DashMap shard guard is
        // released before recursing into other DashMaps; defensive
        // against a future change adding self-referential writes.
        let prior: Vec<SocketAddr> = reports.iter().copied().collect();
        drop(reports);
        for ext in prior {
            credit_observation(remote_ip, ext, &pinned_direct, proven);
        }
    } else {
        tracing::trace!(
            remote = %remote_ip,
            "classifier: peer is now proof-eligible but has no prior observations; \
             credit deferred until OBSERVED_ADDRESS frame arrives"
        );
    }
}

/// Handle a `P2pEvent::PeerObservedExternal` event.
///
/// Records the peer's report in `peer_observations` (capped at
/// [`crate::transport_handle::MAX_OBSERVATIONS_PER_PEER`]) and, if the
/// peer is already proof-eligible and the reported external is currently
/// pinned, credits the observation against `proven_externals`.
fn handle_peer_observed_external(
    peer_addr: SocketAddr,
    observed_external: SocketAddr,
    external: &parking_lot::Mutex<ExternalAddresses>,
    observations: &DashMap<IpAddr, HashSet<SocketAddr>>,
    eligible: &DashSet<IpAddr>,
    proven: &DashMap<SocketAddr, HashSet<IpAddr>>,
) {
    let normalized_peer = saorsa_transport::shared::normalize_socket_addr(peer_addr);
    let peer_ip = canonicalize_ip(normalized_peer.ip());
    let normalized_ext = saorsa_transport::shared::normalize_socket_addr(observed_external);

    let recorded = {
        let mut entry = observations.entry(peer_ip).or_default();
        if entry.len() >= crate::transport_handle::MAX_OBSERVATIONS_PER_PEER
            && !entry.contains(&normalized_ext)
        {
            tracing::debug!(
                peer = %peer_ip,
                external = %normalized_ext,
                cap = crate::transport_handle::MAX_OBSERVATIONS_PER_PEER,
                "classifier: dropping OBSERVED_ADDRESS report; per-peer observation cap reached"
            );
            false
        } else {
            entry.insert(normalized_ext)
        }
    };

    if !recorded {
        return;
    }

    if !eligible.contains(&peer_ip) {
        tracing::trace!(
            peer = %peer_ip,
            external = %normalized_ext,
            "classifier: observation recorded; peer not yet proof-eligible — credit deferred"
        );
        return;
    }

    let pinned_direct = external.lock().direct_addresses();
    credit_observation(peer_ip, normalized_ext, &pinned_direct, proven);
}

/// Back-fill `proven_externals` when an external is freshly pinned.
///
/// Walks `peer_observations` and credits every proof-eligible peer that
/// previously reported `external` — closing the timing window where a
/// peer's `OBSERVED_ADDRESS` report arrives before saorsa-transport's
/// pinning quorum is reached. The pinned-status check is implicit
/// (`external` is being pinned by the caller), so no further gating is
/// needed before recording.
fn back_fill_proof_on_pin(
    external: SocketAddr,
    observations: &DashMap<IpAddr, HashSet<SocketAddr>>,
    eligible: &DashSet<IpAddr>,
    proven: &DashMap<SocketAddr, HashSet<IpAddr>>,
) {
    let normalized_ext = saorsa_transport::shared::normalize_socket_addr(external);
    for entry in observations.iter() {
        let peer_ip = *entry.key();
        if !eligible.contains(&peer_ip) {
            continue;
        }
        if entry.value().contains(&normalized_ext) {
            record_attributed_observer(peer_ip, normalized_ext, proven);
        }
    }
}

/// Credit `peer_ip` against `external` iff the address is currently
/// pinned. Defers to [`record_attributed_observer`] for the actual
/// write+log.
///
/// Used by the live event handlers; `back_fill_proof_on_pin` calls
/// `record_attributed_observer` directly because the pinned check is
/// trivially satisfied at the call site.
fn credit_observation(
    peer_ip: IpAddr,
    external: SocketAddr,
    pinned_direct: &[SocketAddr],
    proven: &DashMap<SocketAddr, HashSet<IpAddr>>,
) {
    let normalized_ext = saorsa_transport::shared::normalize_socket_addr(external);
    if !pinned_direct.contains(&normalized_ext) {
        tracing::trace!(
            peer = %peer_ip,
            external = %normalized_ext,
            "classifier: peer reported external but it is not currently pinned; \
             back-fill on pin will catch this if quorum is reached later"
        );
        return;
    }
    record_attributed_observer(peer_ip, normalized_ext, proven);
}

/// Insert `peer_ip` into `proven_externals[external]` and log threshold
/// crossings. Caller is responsible for confirming that `external` is
/// pinned (or being pinned right now).
fn record_attributed_observer(
    peer_ip: IpAddr,
    normalized_ext: SocketAddr,
    proven: &DashMap<SocketAddr, HashSet<IpAddr>>,
) {
    let mut entry = proven.entry(normalized_ext).or_default();
    let inserted = entry.insert(peer_ip);
    let count = entry.len();
    drop(entry);

    if !inserted {
        return;
    }

    if count >= crate::transport_handle::MIN_DISTINCT_OBSERVERS_FOR_DIRECT {
        tracing::info!(
            external = %normalized_ext,
            observers = count,
            threshold = crate::transport_handle::MIN_DISTINCT_OBSERVERS_FOR_DIRECT,
            new_observer = %peer_ip,
            "classifier: external promoted to Direct (per-address attribution)"
        );
    } else {
        tracing::debug!(
            external = %normalized_ext,
            observers = count,
            threshold = crate::transport_handle::MIN_DISTINCT_OBSERVERS_FOR_DIRECT,
            new_observer = %peer_ip,
            "classifier: source-disjoint observer recorded; below threshold"
        );
    }
}

#[allow(dead_code)]
impl P2PNetworkNode<P2pLinkTransport> {
    /// Create a new P2P network node with default P2pLinkTransport
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        Self::new_with_max_connections(bind_addr, DEFAULT_MAX_CONNECTIONS, None).await
    }

    /// Create a new P2P network node with a specific connection limit and
    /// optional message-size override.
    ///
    /// When `max_msg_size` is `None` saorsa-transport's built-in default is used.
    pub async fn new_with_max_connections(
        bind_addr: SocketAddr,
        max_connections: usize,
        max_msg_size: Option<usize>,
    ) -> Result<Self> {
        Self::new_with_options(bind_addr, max_connections, max_msg_size, false, true, true).await
    }

    /// Create a new P2P network node with full control over connection
    /// limits, message size, loopback address acceptance, relay service,
    /// and external-address advertisement.
    pub async fn new_with_options(
        bind_addr: SocketAddr,
        max_connections: usize,
        max_msg_size: Option<usize>,
        allow_loopback: bool,
        enable_relay_service: bool,
        advertise_external_addresses: bool,
    ) -> Result<Self> {
        let mut builder = P2pConfig::builder()
            .bind_addr(bind_addr)
            .max_connections(max_connections)
            .conservative_timeouts()
            .data_channel_capacity(P2pConfig::DEFAULT_DATA_CHANNEL_CAPACITY)
            .nat(NatConfig {
                allow_loopback,
                enable_relay_service,
                advertise_external_addresses,
                ..NatConfig::default()
            });
        if let Some(max_msg_size) = max_msg_size {
            builder = builder.max_message_size(max_msg_size);
        }
        let config = builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build P2P config: {}", e))?;

        let transport = P2pLinkTransport::new(config)
            .await
            .context("Failed to create transport")?
            .with_default_strategy(
                StrategyConfig::direct_only()
                    .with_ipv4_timeout(DIRECT_CONNECT_TIMEOUT)
                    .with_ipv6_timeout(DIRECT_CONNECT_TIMEOUT),
            );

        // Get the actual bound address from the endpoint (important for port 0 bindings)
        let actual_addr = transport.endpoint().local_addr().ok_or_else(|| {
            anyhow::anyhow!(
                "Transport endpoint has no local address — bind to {bind_addr} may have failed"
            )
        })?;

        Self::with_transport(Arc::new(transport), actual_addr).await
    }

    /// Create a new P2P network node with custom P2pConfig
    pub async fn new_with_config(_bind_addr: SocketAddr, config: P2pConfig) -> Result<Self> {
        let transport = P2pLinkTransport::new(config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create transport: {}", e))?
            .with_default_strategy(
                StrategyConfig::direct_only()
                    .with_ipv4_timeout(DIRECT_CONNECT_TIMEOUT)
                    .with_ipv6_timeout(DIRECT_CONNECT_TIMEOUT),
            );

        // Get the actual bound address from the endpoint
        let actual_addr = transport.endpoint().local_addr().ok_or_else(|| {
            anyhow::anyhow!("Transport endpoint has no local address — bind may have failed")
        })?;

        Self::with_transport(Arc::new(transport), actual_addr).await
    }

    /// Send data to a peer using P2pEndpoint's send method
    ///
    /// This method is specialized for P2pLinkTransport and uses the underlying
    /// P2pEndpoint's send() method which corresponds with recv() for proper
    /// bidirectional communication.
    ///
    /// On failure the underlying transport error is preserved via
    /// `anyhow::Context` so callers can inspect the cause (e.g. QUIC
    /// `peer did not acknowledge`, `open_uni failed`, `PeerNotFound`).
    pub async fn send_to_peer_optimized(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        trace!(
            "[QUIC SEND] endpoint().send() to {} ({} bytes)",
            addr,
            data.len()
        );
        self.transport
            .endpoint()
            .send(addr, data)
            .await
            .with_context(|| format!("QUIC send to {} ({} bytes) failed", addr, data.len()))
    }

    /// Disconnect a specific peer, closing the underlying QUIC connection.
    ///
    /// Calls `P2pEndpoint::disconnect()` to tear down the QUIC connection
    /// and abort the per-connection reader task, then removes the peer from
    /// the local registry.
    pub async fn disconnect_peer_quic(&self, addr: &SocketAddr) {
        if let Err(e) = self.transport.endpoint().disconnect(addr).await {
            tracing::warn!("QUIC disconnect for peer {}: {}", addr, e);
        }
        // Also clean up from generic adapter state
        P2PNetworkNode::<P2pLinkTransport>::disconnect_peer_inner(
            &self.peers,
            &self.peer_quality,
            addr,
        )
        .await;
    }

    /// Spawn a background task that continuously receives messages from the
    /// QUIC endpoint and forwards them into the provided channel.
    ///
    /// Uses saorsa-transport v0.20's channel-based `recv()` which is fully
    /// event-driven — no polling or timeout parameter. Per-connection
    /// reader tasks inside saorsa-transport feed a shared mpsc channel, so
    /// `recv()` wakes instantly when data arrives on any peer's QUIC
    /// stream. The task exits when the shutdown signal is set, the
    /// channel is closed, or the endpoint shuts down.
    ///
    /// Returns the task handle for cleanup.
    pub fn spawn_recv_task(
        &self,
        tx: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        /// Maximum size of a single received message (16 MB).
        /// Messages exceeding this limit are dropped to prevent memory exhaustion.
        const MAX_RECV_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

        let transport = Arc::clone(&self.transport);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        break;
                    }
                    result = transport.endpoint().recv() => {
                        match result {
                            Ok((addr, data)) => {
                                if data.len() > MAX_RECV_MESSAGE_SIZE {
                                    tracing::warn!(
                                        "Dropping oversized message ({} bytes) from {}",
                                        data.len(),
                                        addr
                                    );
                                    continue;
                                }
                                if tx.send((addr, data)).await.is_err() {
                                    break; // channel closed
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Recv task exiting: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        })
    }
}

#[allow(dead_code)]
impl<T: LinkTransport + Send + Sync + 'static> P2PNetworkNode<T> {
    /// Create with any LinkTransport implementation (for testing)
    pub async fn with_transport(transport: Arc<T>, bind_addr: SocketAddr) -> Result<Self> {
        // Register our protocol
        transport.register_protocol(SAORSA_DHT_PROTOCOL);

        let (event_tx, _) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();

        // Start event forwarder that maps LinkEvent to ConnectionEvent
        let mut link_events = transport.subscribe();
        let event_tx_clone = event_tx.clone();
        let shutdown_clone = shutdown.clone();
        let peers_clone = Arc::new(RwLock::new(Vec::new()));
        let peers_for_task = Arc::clone(&peers_clone);
        let peer_quality = Arc::new(RwLock::new(HashMap::new()));
        let peer_quality_for_task = Arc::clone(&peer_quality);

        let event_task_handle = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown_clone.cancelled() => break,
                    recv = link_events.recv() => match recv {
                    Ok(LinkEvent::PeerConnected { addr, public_key, caps }) => {
                        // Capture quality score from saorsa-transport Capabilities
                        let quality = caps.quality_score();
                        {
                            let mut quality_map = peer_quality_for_task.write().await;
                            quality_map.insert(addr, quality);
                        }

                        // Note: Peer tracking with geographic validation is done by
                        // add_peer() in connect_to_peer() and accept_connection().
                        // The event forwarder only broadcasts the connection event.
                        // This avoids duplicate registration while preserving
                        // geographic validation functionality.

                        let _ = event_tx_clone.send(ConnectionEvent::Established {
                            remote_address: addr,
                            public_key,
                        });
                    }
                    Ok(LinkEvent::PeerDisconnected { addr, reason }) => {
                        // Remove the peer from tracking
                        {
                            let mut peers = peers_for_task.write().await;
                            peers.retain(|a| *a != addr);
                        }
                        // Also remove from quality scores
                        {
                            let mut quality_map = peer_quality_for_task.write().await;
                            quality_map.remove(&addr);
                        }

                        let _ = event_tx_clone.send(ConnectionEvent::Lost {
                            remote_address: addr,
                            reason: format!("{:?}", reason),
                        });
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Lost some events, continue
                        continue;
                    }
                    _ => {}
                }}
            }
        }));

        // Create SharedTransport for protocol multiplexing
        let shared_transport = Arc::new(SharedTransport::from_arc(Arc::clone(&transport)));

        // Note: DHT handler registration happens lazily when a DhtCoreEngine is provided
        // via register_dht_handler() method.
        Ok(Self {
            transport,
            local_addr: bind_addr,
            peers: peers_clone,
            event_tx,
            shutdown,
            event_task_handle,
            geo_config: None,
            peer_regions: Arc::new(RwLock::new(HashMap::new())),
            peer_quality,
            shared_transport,
        })
    }

    /// Register the DHT handler with the SharedTransport.
    ///
    /// This enables handling of DHT stream types (Query, Store, Witness, Replication)
    /// via the SharedTransport multiplexer.
    ///
    /// # Arguments
    ///
    /// * `dht_engine` - The DHT engine to process requests
    pub async fn register_dht_handler(
        &self,
        dht_engine: Arc<RwLock<crate::dht::core_engine::DhtCoreEngine>>,
    ) -> Result<()> {
        use crate::transport::dht_handler::DhtStreamHandler;
        use saorsa_transport::link_transport::ProtocolHandlerExt;

        let handler = DhtStreamHandler::new(dht_engine);
        self.shared_transport
            .register_handler(handler.boxed())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to register DHT handler: {}", e))?;

        tracing::info!("DHT handler registered with SharedTransport");
        Ok(())
    }

    /// Get a reference to the SharedTransport.
    ///
    /// Useful for registering additional protocol handlers.
    pub fn shared_transport(&self) -> Arc<SharedTransport<T>> {
        Arc::clone(&self.shared_transport)
    }

    /// Start the SharedTransport.
    ///
    /// Must be called before sending/receiving via SharedTransport.
    pub async fn start_shared_transport(&self) -> Result<()> {
        self.shared_transport
            .start()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start SharedTransport: {}", e))
    }

    /// Send data via SharedTransport with stream type routing.
    ///
    /// The stream type byte is prepended automatically.
    pub async fn send_typed(
        &self,
        addr: &SocketAddr,
        stream_type: StreamType,
        data: bytes::Bytes,
    ) -> Result<()> {
        self.shared_transport
            .send(addr, stream_type, data)
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Failed to send typed data: {}", e))
    }

    /// Connect to a peer by address
    pub async fn connect_to_peer(&self, peer_addr: SocketAddr) -> Result<SocketAddr> {
        // saorsa-core publishes typed addresses (Direct or Relay-allocated)
        // and is responsible for picking the right one before reaching the
        // transport. Direct addresses are self-asserted by the publisher,
        // not externally verified — actual reachability is discovered at
        // dial time, and failures cascade back to the relay-acquisition
        // driver which may pick a different peer or rebind.
        //
        // The transport's default StrategyConfig::direct_only() disables
        // hole-punching and the in-cascade relay fallback, so this dial
        // is single-shot. 5 s covers a QUIC handshake (1 RTT) + ML-DSA
        // verification + margin for network jitter.
        const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

        let conn = tokio::time::timeout(
            DIAL_TIMEOUT,
            self.transport.dial_addr(peer_addr, SAORSA_DHT_PROTOCOL),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Connection timeout after {:?} to {}",
                DIAL_TIMEOUT,
                peer_addr
            )
        })?
        .map_err(|e| anyhow::anyhow!("Failed to connect to peer {}: {}", peer_addr, e))?;

        let remote_addr = conn.remote_addr();

        // Register the peer with geographic validation
        self.add_peer(remote_addr).await;

        // Note: ConnectionEvent is broadcast by event forwarder
        // to avoid duplicate events

        info!("Connected to peer at {}", remote_addr);
        Ok(remote_addr)
    }

    /// Try to accept one incoming connection.
    ///
    /// Returns `Some(...)` on success, `None` when the endpoint has shut
    /// down. A `None` return is terminal — the caller should exit its
    /// accept loop.
    ///
    /// **NOTE**: Protocol-based filtering is not yet implemented in saorsa-transport's `accept()` method.
    /// This method accepts connections for ANY protocol, not just `SAORSA_DHT_PROTOCOL`.
    /// Applications must validate that incoming connections are using the expected protocol.
    pub async fn accept_connection(&self) -> Option<SocketAddr> {
        let mut incoming = self.transport.accept(SAORSA_DHT_PROTOCOL);
        while let Some(conn_result) = incoming.next().await {
            match conn_result {
                Ok(conn) => {
                    let addr = conn.remote_addr();
                    self.add_peer(addr).await;
                    tracing::info!("Accepted connection from peer at {}", addr);
                    return Some(addr);
                }
                Err(e) => {
                    tracing::warn!("Accept stream error: {}", e);
                }
            }
        }
        None
    }

    /// Static helper for region lookup (used in spawned tasks)
    fn get_region_for_ip_static(ip: &IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                match octets.first() {
                    Some(0..=63) => "NA".to_string(),
                    Some(64..=127) => "EU".to_string(),
                    Some(128..=191) => "APAC".to_string(),
                    Some(192..=223) => "SA".to_string(),
                    Some(224..=255) => "OTHER".to_string(),
                    None => "UNKNOWN".to_string(),
                }
            }
            IpAddr::V6(_) => "UNKNOWN".to_string(),
        }
    }

    /// Send data to a specific peer by address.
    ///
    /// Dials the peer by address, opens a typed unidirectional stream,
    /// writes the data, and finishes the stream.
    pub async fn send_to_peer_raw(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        // Budget covers a single direct dial (~5 s with the
        // direct_only strategy) plus a small-payload write (typically
        // sub-second; oversized payloads are rejected upstream by the
        // protocol-level message-size cap). The legacy ~25 s cascade
        // budget no longer applies — hole-punching and in-cascade
        // relay fallback are disabled at the transport layer.
        const SEND_TIMEOUT: Duration = Duration::from_secs(10);

        tokio::time::timeout(SEND_TIMEOUT, async {
            let conn = self
                .transport
                .dial_addr(*addr, SAORSA_DHT_PROTOCOL)
                .await
                .map_err(|e| anyhow::anyhow!("Dial by address failed: {}", e))?;

            // Open a typed unidirectional stream for DHT messages
            // Using DhtStore stream type for DHT protocol messages
            let mut stream = conn
                .open_uni_typed(StreamType::DhtStore)
                .await
                .map_err(|e| anyhow::anyhow!("Stream open failed: {}", e))?;

            // Use LinkSendStream trait methods directly
            stream
                .write_all(data)
                .await
                .map_err(|e| anyhow::anyhow!("Write failed: {}", e))?;
            stream
                .finish()
                .map_err(|e| anyhow::anyhow!("Stream finish failed: {}", e))?;

            Ok(())
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("send_to_peer_raw timed out after {SEND_TIMEOUT:?} to {addr}")
        })?
    }

    /// Get our local address
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the actual bound listening address
    pub async fn actual_listening_address(&self) -> Result<SocketAddr> {
        // Try to get external address first
        if let Some(addr) = self.transport.external_address() {
            return Ok(addr);
        }
        // Fallback to configured address
        Ok(self.local_addr)
    }

    /// Get our local public key (ML-DSA-65 SPKI bytes)
    pub fn our_public_key(&self) -> Vec<u8> {
        self.transport.local_public_key()
    }

    /// Get our observed external address as reported by peers
    pub fn get_observed_external_address(&self) -> Option<SocketAddr> {
        self.transport.external_address()
    }

    /// Get all connected peer addresses
    pub async fn get_connected_peers(&self) -> Vec<SocketAddr> {
        self.peers.read().await.clone()
    }

    /// Check if a peer is connected
    pub async fn is_connected(&self, addr: &SocketAddr) -> bool {
        self.transport.is_connected(addr)
    }

    /// Check if a peer is authenticated (always true with PQC auth)
    pub async fn is_authenticated(&self, _addr: &SocketAddr) -> bool {
        // With saorsa-transport 0.14+, all connections are PQC authenticated
        true
    }

    /// Connect to bootstrap nodes to join the network
    pub async fn bootstrap_from_nodes(
        &self,
        bootstrap_addrs: &[SocketAddr],
    ) -> Result<Vec<SocketAddr>> {
        let mut connected_peers = Vec::new();

        for &addr in bootstrap_addrs {
            match self.connect_to_peer(addr).await {
                Ok(peer_addr) => {
                    connected_peers.push(peer_addr);
                    tracing::info!("Successfully bootstrapped from {}", addr);
                }
                Err(e) => {
                    tracing::warn!("Failed to bootstrap from {}: {}", addr, e);
                }
            }
        }

        if connected_peers.is_empty() {
            return Err(anyhow::anyhow!("Failed to connect to any bootstrap nodes"));
        }

        Ok(connected_peers)
    }

    /// Internal helper to register a peer with geographic validation
    async fn add_peer(&self, addr: SocketAddr) {
        // Perform geographic validation if configured
        if let Some(ref config) = self.geo_config {
            match self.validate_geographic_diversity(&addr, config).await {
                Ok(()) => {}
                Err(err) => {
                    tracing::warn!("REJECTED peer {} - {}", addr, err);
                    return;
                }
            }
        }

        let mut peers = self.peers.write().await;

        if !peers.contains(&addr) {
            peers.push(addr);

            let region = self.get_region_for_ip(&addr.ip());
            let mut regions = self.peer_regions.write().await;
            *regions.entry(region).or_insert(0) += 1;

            tracing::debug!("Added peer from {}", addr);
        }
    }

    /// Validate geographic diversity before adding a peer
    async fn validate_geographic_diversity(
        &self,
        addr: &SocketAddr,
        config: &GeographicConfig,
    ) -> std::result::Result<(), GeoRejectionError> {
        let region = self.get_region_for_ip(&addr.ip());

        if config.blocked_regions.contains(&region) {
            return Err(GeoRejectionError::BlockedRegion(region));
        }

        let regions = self.peer_regions.read().await;
        let total_peers: usize = regions.values().sum();

        if total_peers > 0 {
            let region_count = *regions.get(&region).unwrap_or(&0);
            let new_ratio = (region_count + 1) as f64 / (total_peers + 1) as f64;

            if new_ratio > config.max_single_region_ratio {
                return Err(GeoRejectionError::DiversityViolation {
                    region,
                    current_ratio: new_ratio * 100.0,
                });
            }
        }

        Ok(())
    }

    /// Get region for an IP address (simplified placeholder)
    fn get_region_for_ip(&self, ip: &IpAddr) -> String {
        Self::get_region_for_ip_static(ip)
    }

    /// Get current region ratio for a specific region
    pub async fn get_region_ratio(&self, region: &str) -> f64 {
        let regions = self.peer_regions.read().await;
        let total_peers: usize = regions.values().sum();
        if total_peers == 0 {
            return 0.0;
        }
        let region_count = *regions.get(region).unwrap_or(&0);
        (region_count as f64 / total_peers as f64) * 100.0
    }

    /// Set geographic configuration for diversity enforcement
    pub fn set_geographic_config(&mut self, config: GeographicConfig) {
        tracing::info!(
            "Geographic validation enabled: mode={:?}, max_ratio={}%, blocked_regions={:?}",
            config.enforcement_mode,
            config.max_single_region_ratio * 100.0,
            config.blocked_regions
        );
        self.geo_config = Some(config);
    }

    /// Check if geographic validation is enabled
    pub fn is_geo_validation_enabled(&self) -> bool {
        self.geo_config.is_some()
    }

    /// Get peer region distribution statistics
    pub async fn get_region_stats(&self) -> HashMap<String, usize> {
        self.peer_regions.read().await.clone()
    }

    /// Send data to a peer.
    pub async fn send_to_peer(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        self.send_to_peer_raw(addr, data).await
    }

    /// Connect to a peer and return the remote address as a string.
    pub async fn connect_to_peer_string(&self, peer_addr: SocketAddr) -> Result<String> {
        let addr = self.connect_to_peer(peer_addr).await?;
        Ok(addr.to_string())
    }

    /// Send a message to a peer.
    pub async fn send_message(&self, addr: &SocketAddr, data: Vec<u8>) -> Result<()> {
        self.send_to_peer(addr, &data).await
    }

    /// Subscribe to connection lifecycle events
    pub fn subscribe_connection_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        self.event_tx.subscribe()
    }

    /// Disconnect a specific peer by removing it from local tracking.
    ///
    /// For `P2pLinkTransport`, prefer `disconnect_peer_quic()` which also
    /// tears down the underlying QUIC connection.
    pub async fn disconnect_peer(&self, addr: &SocketAddr) {
        Self::disconnect_peer_inner(&self.peers, &self.peer_quality, addr).await;
    }

    /// Shared helper to remove a peer from adapter-level tracking.
    async fn disconnect_peer_inner(
        peers: &RwLock<Vec<SocketAddr>>,
        peer_quality: &RwLock<HashMap<SocketAddr, f32>>,
        addr: &SocketAddr,
    ) {
        {
            let mut peers = peers.write().await;
            peers.retain(|a| a != addr);
        }
        {
            let mut quality_map = peer_quality.write().await;
            quality_map.remove(addr);
        }
        tracing::debug!("Disconnected peer {} from adapter", addr);
    }

    /// Shutdown the node gracefully
    pub async fn shutdown(&mut self) {
        tracing::info!("Shutting down P2PNetworkNode");

        self.shutdown.cancel();

        // Stop transport first so the link event stream closes and any
        // event-forwarder task blocked on recv() can exit.
        self.transport.shutdown().await;

        if let Some(handle) = self.event_task_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Dual-stack wrapper managing IPv4 and IPv6 transports.
///
/// When `is_dual_stack` is true (`v6` is Some, `v4` is None), the v6 socket
/// handles both IPv4 and IPv6 via the kernel's dual-stack mechanism
/// (`bindv6only=0`).  The kernel represents IPv4 peers as `[::ffff:x.x.x.x]`
/// internally.  This struct normalises all addresses at its boundary so that
/// code above (saorsa-core) always sees plain IPv4 addresses, while code below
/// (P2PNetworkNode / Quinn) uses the native socket format.
#[allow(dead_code)]
pub struct DualStackNetworkNode<T: LinkTransport = P2pLinkTransport> {
    pub v6: Option<P2PNetworkNode<T>>,
    pub v4: Option<P2PNetworkNode<T>>,
    /// True when v6 handles IPv4 too (bindv6only=0, v4 bind skipped).
    is_dual_stack: bool,
}

/// Return value of [`DualStackNetworkNode::pick_stacks_for`]: the primary and
/// optional fallback `(node, wire_addr)` pair to use when sending to a given
/// address. Either element may be `None` if that stack is absent or would be a
/// wasted attempt for the target family.
type PickedStacks<'a, T> = (
    Option<(&'a P2PNetworkNode<T>, SocketAddr)>,
    Option<(&'a P2PNetworkNode<T>, SocketAddr)>,
);

/// Which concrete stack a [`DispatchPlan`] slot points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackRole {
    V4,
    V6,
}

/// One slot of a [`DispatchPlan`]: which stack to use, and whether the v4
/// address must be rewritten to `[::ffff:x.x.x.x]` form for the v6 wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackChoice {
    role: StackRole,
    /// True iff the caller should wrap a plain-IPv4 `addr` as IPv4-mapped IPv6
    /// before handing it to the chosen node. Only ever set when routing a
    /// v4 target through the v6 socket in dual-stack mode.
    mapped: bool,
}

/// Primary + fallback stack decision produced by [`decide_dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DispatchPlan {
    primary: Option<StackChoice>,
    fallback: Option<StackChoice>,
}

/// Pure decision: given the dual-stack state and target address family, which
/// stack(s) should a send/disconnect go to, and does the v4 address need
/// mapping to the v6 wire form?
///
/// Isolated from the `DualStackNetworkNode` struct so the (is_dual_stack ×
/// has_v6 × has_v4 × addr.family) matrix is unit-testable without having to
/// bind real sockets.
///
/// Invariant maintained by every constructor in this module:
/// `is_dual_stack ⟺ (has_v6 && !has_v4)`. That makes the "v4-target, no v4
/// socket, split-stack" branch unreachable in practice — `has_v4=false &&
/// !is_dual_stack` forces `has_v6=false`. The function still returns a
/// well-defined plan (an empty one) for that shape so callers can't observe
/// a panic if the invariant is ever loosened.
fn decide_dispatch(
    is_dual_stack: bool,
    has_v6: bool,
    has_v4: bool,
    addr_is_v4: bool,
) -> DispatchPlan {
    if is_dual_stack {
        let primary = has_v6.then_some(StackChoice {
            role: StackRole::V6,
            mapped: addr_is_v4,
        });
        let fallback = has_v4.then_some(StackChoice {
            role: StackRole::V4,
            mapped: false,
        });
        return DispatchPlan { primary, fallback };
    }

    let primary = if addr_is_v4 {
        has_v4.then_some(StackChoice {
            role: StackRole::V4,
            mapped: false,
        })
    } else {
        has_v6.then_some(StackChoice {
            role: StackRole::V6,
            mapped: false,
        })
    };
    DispatchPlan {
        primary,
        fallback: None,
    }
}

#[allow(dead_code)]
impl DualStackNetworkNode<P2pLinkTransport> {
    /// Set the target peer ID for a hole-punch attempt to a specific address.
    /// The P2pEndpoint uses this in PUNCH_ME_NOW to let the coordinator match
    /// by peer identity. Keyed by address to avoid concurrent dial races.
    pub async fn set_hole_punch_target_peer_id(&self, target: SocketAddr, peer_id: [u8; 32]) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            node.transport
                .endpoint()
                .set_hole_punch_target_peer_id(target, peer_id)
                .await;
        }
    }

    /// Set a preferred coordinator for hole-punching to a specific target.
    /// The preferred coordinator is a peer that referred us to the target
    /// during a DHT lookup, so it has a connection to the target.
    pub async fn set_hole_punch_preferred_coordinator(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
    ) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            node.transport
                .endpoint()
                .set_hole_punch_preferred_coordinator(target, coordinator)
                .await;
        }
    }

    /// Register a peer ID at the low-level transport endpoint for PUNCH_ME_NOW
    /// relay routing. Called when identity exchange completes on a connection.
    pub async fn register_connection_peer_id(&self, addr: SocketAddr, peer_id: [u8; 32]) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            let endpoint = node.transport.endpoint();
            endpoint.register_connection_peer_id(addr, peer_id);
            // Also register the dual-stack alternate form (IPv4 ↔ IPv4-mapped IPv6)
            // so peer ID routing works regardless of which form the connection uses.
            if let Some(alt) = saorsa_transport::shared::dual_stack_alternate(&addr) {
                endpoint.register_connection_peer_id(alt, peer_id);
            }
        }
    }

    /// Check if a peer has a live QUIC connection via either stack.
    ///
    /// Checks the underlying P2pEndpoint's NatTraversalEndpoint connections
    /// DashMap directly, which is authoritative for QUIC connection state.
    /// Tries both the plain and IPv4-mapped address forms to handle
    /// dual-stack normalization.
    pub async fn is_peer_connected_by_addr(&self, addr: &std::net::SocketAddr) -> bool {
        let mapped = saorsa_transport::shared::dual_stack_alternate(addr);
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            // Check NatTraversalEndpoint's connections (authoritative for QUIC state)
            let endpoint = node.transport.endpoint();
            if endpoint.inner_is_connected(addr) {
                return true;
            }
            if let Some(ref alt) = mapped
                && endpoint.inner_is_connected(alt)
            {
                return true;
            }
            // Also check the link transport capabilities cache
            if node.is_connected(addr).await {
                return true;
            }
            if let Some(ref alt) = mapped
                && node.is_connected(alt).await
            {
                return true;
            }
        }
        false
    }

    /// Check if the proactive relay session is still alive on any stack.
    ///
    /// Returns `true` if no relay was established or the relay is healthy.
    /// Returns `false` if a relay was established but the QUIC connection
    /// has closed — the relayer monitor should trigger rebinding.
    pub fn is_relay_healthy(&self) -> bool {
        // If ANY stack reports an unhealthy relay, the relay is dead.
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            if !node.transport.endpoint().is_relay_healthy() {
                return false;
            }
        }
        true
    }

    /// Enable or disable relay serving on both stacks' MASQUE relay servers.
    ///
    /// Called by the ADR-014 reachability classifier: public nodes leave it
    /// enabled, private nodes disable it so they reject incoming relay
    /// reservation requests.
    pub fn set_relay_serving_enabled(&self, enabled: bool) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            node.transport.endpoint().set_relay_serving_enabled(enabled);
        }
    }

    /// Establish a proactive MASQUE relay session with the relay reachable at
    /// `relay_addr`, rebinding the matching stack's Quinn endpoint onto the
    /// resulting tunnel.
    ///
    /// Used by the ADR-014 relay acquisition coordinator (see
    /// `src/reachability/acquisition.rs`). Dispatches to the stack that
    /// matches the relay's address family: IPv4 relays go through `self.v4`
    /// (falling back to `self.v6` if v4 is absent); IPv6 relays the
    /// reverse. If neither stack is available, returns a
    /// [`saorsa_transport::p2p_endpoint::EndpointError::Config`] describing
    /// the mismatch.
    ///
    /// On success, returns the relay-allocated public socket address the
    /// caller should publish in its DHT self-record. A
    /// `P2pEvent::RelayEstablished` is emitted on the event broadcaster so
    /// the saorsa-core DHT bridge can propagate the address to peers without
    /// needing this return value.
    pub async fn setup_proactive_relay(
        &self,
        relay_addr: SocketAddr,
    ) -> std::result::Result<SocketAddr, saorsa_transport::p2p_endpoint::EndpointError> {
        let node = if relay_addr.is_ipv4() {
            self.v4.as_ref().or(self.v6.as_ref())
        } else {
            self.v6.as_ref().or(self.v4.as_ref())
        }
        .ok_or_else(|| {
            saorsa_transport::p2p_endpoint::EndpointError::Config(format!(
                "no transport stack available for relay address family {}",
                relay_addr
            ))
        })?;

        node.transport
            .endpoint()
            .setup_proactive_relay(relay_addr)
            .await
    }

    /// Shut down the underlying QUIC endpoints on both stacks.
    ///
    /// This cancels each endpoint's internal `CancellationToken`, which
    /// unblocks any in-flight `recv()` calls and aborts per-connection
    /// reader tasks.  Call this **before** joining background tasks that
    /// are blocked inside `endpoint().recv()`.
    pub async fn shutdown_endpoints(&self) {
        if let Some(ref v6) = self.v6 {
            v6.transport.endpoint().shutdown().await;
        }
        if let Some(ref v4) = self.v4 {
            v4.transport.endpoint().shutdown().await;
        }
    }

    /// Spawn background tasks that forward address-related `P2pEvent`s from
    /// each stack's `P2pEndpoint` to the upper layers.
    ///
    /// Four event flavours are bridged:
    ///
    /// - **`PeerAddressUpdated`**: a connected peer advertised a new
    ///   reachable address via an ADD_ADDRESS frame (typically a relay).
    ///   Returned via the first mpsc receiver as
    ///   `(peer_connection_addr, advertised_addr)`.
    /// - **`RelayEstablished`**: this node set up a MASQUE relay and now
    ///   needs to publish the relay address to the K closest peers.
    ///   Returned via the second mpsc receiver.
    /// - **`RelayLost`**: a previously-advertised MASQUE relay address is
    ///   no longer reachable. The reachability driver republishes the
    ///   address set without the relay entry on receipt.  Returned via
    ///   the third mpsc receiver.
    /// - **`ExternalAddressDiscovered`**: a peer reported the address it
    ///   sees this node at, via a QUIC `OBSERVED_ADDRESS` frame. Pinned
    ///   directly into the supplied [`ExternalAddresses`] store. Once
    ///   pinned, the address is retained for the process lifetime.
    ///
    /// Other `P2pEvent` variants are not consumed by saorsa-core and are
    /// silently ignored.
    pub fn spawn_peer_address_update_forwarder(
        &self,
        external_addresses: Arc<parking_lot::Mutex<ExternalAddresses>>,
        peer_observations: Arc<DashMap<IpAddr, HashSet<SocketAddr>>>,
        proof_eligible_peers: Arc<DashSet<IpAddr>>,
        proven_externals: Arc<DashMap<SocketAddr, HashSet<IpAddr>>>,
    ) -> (
        tokio::sync::mpsc::Receiver<(SocketAddr, SocketAddr)>,
        tokio::sync::mpsc::Receiver<SocketAddr>,
        tokio::sync::mpsc::Receiver<SocketAddr>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(ADDRESS_EVENT_CHANNEL_CAPACITY);
        let (relay_tx, relay_rx) = tokio::sync::mpsc::channel(ADDRESS_EVENT_CHANNEL_CAPACITY);
        let (relay_lost_tx, relay_lost_rx) =
            tokio::sync::mpsc::channel(ADDRESS_EVENT_CHANNEL_CAPACITY);
        let drop_counter = Arc::new(AtomicU64::new(0));
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            let mut p2p_rx = node.transport.endpoint().subscribe();
            let tx_clone = tx.clone();
            let relay_tx_clone = relay_tx.clone();
            let relay_lost_tx_clone = relay_lost_tx.clone();
            let ext_clone = Arc::clone(&external_addresses);
            let observations_clone = Arc::clone(&peer_observations);
            let eligible_clone = Arc::clone(&proof_eligible_peers);
            let proven_clone = Arc::clone(&proven_externals);
            let drops = Arc::clone(&drop_counter);
            let local_bind = node.local_address();
            tokio::spawn(async move {
                tracing::debug!(
                    local_bind = %local_bind,
                    "ADDR_FWD: peer address update forwarder started"
                );
                loop {
                    match p2p_rx.recv().await {
                        Ok(saorsa_transport::P2pEvent::PeerAddressUpdated {
                            peer_addr,
                            advertised_addr,
                        }) => {
                            tracing::debug!(
                                "ADDR_FWD: received PeerAddressUpdated peer={} addr={}",
                                peer_addr,
                                advertised_addr
                            );
                            let payload = (
                                saorsa_transport::shared::normalize_socket_addr(peer_addr),
                                saorsa_transport::shared::normalize_socket_addr(advertised_addr),
                            );
                            if let Err(err) = tx_clone.try_send(payload) {
                                handle_address_event_drop(&drops, "PeerAddressUpdated", &err);
                            }
                        }
                        Ok(saorsa_transport::P2pEvent::RelayEstablished { relay_addr }) => {
                            tracing::info!(
                                "ADDR_FWD: received RelayEstablished relay_addr={}",
                                relay_addr
                            );
                            if let Err(err) = relay_tx_clone.try_send(relay_addr) {
                                handle_address_event_drop(&drops, "RelayEstablished", &err);
                            }
                        }
                        Ok(saorsa_transport::P2pEvent::RelayLost { relay_addr }) => {
                            tracing::info!(
                                "ADDR_FWD: received RelayLost relay_addr={}",
                                relay_addr
                            );
                            if let Err(err) = relay_lost_tx_clone.try_send(relay_addr) {
                                handle_address_event_drop(&drops, "RelayLost", &err);
                            }
                        }
                        Ok(saorsa_transport::P2pEvent::ExternalAddressDiscovered { addr }) => {
                            // Convert TransportAddr → SocketAddr for QUIC.
                            // Non-UDP transports (BLE, LoRa) yield None and
                            // are skipped — only routable IP addresses are
                            // pinned.
                            if let Some(socket_addr) = addr.as_socket_addr() {
                                let normalized =
                                    saorsa_transport::shared::normalize_socket_addr(socket_addr);
                                tracing::debug!(
                                    local_bind = %local_bind,
                                    "ADDR_FWD: pinning observed external address {}",
                                    normalized
                                );
                                ext_clone.lock().pin_direct(normalized);

                                // Back-fill: any peer that already reported
                                // observing us at this address before it
                                // cleared saorsa-transport's pinning quorum
                                // gets credited now. Without this, the very
                                // first peer's report (which doesn't trigger
                                // a pin on its own) is lost — saorsa-core
                                // would otherwise need a third independent
                                // observer to reach the proof threshold.
                                back_fill_proof_on_pin(
                                    normalized,
                                    &observations_clone,
                                    &eligible_clone,
                                    &proven_clone,
                                );
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("ADDR_FWD: channel closed, exiting");
                            break;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("ADDR_FWD: lagged {} events", n);
                            continue;
                        }
                        Ok(_other) => {
                            // Other P2pEvent variants (PeerConnected,
                            // PeerDisconnected, NatTraversalProgress,
                            // BootstrapStatus, PeerAuthenticated,
                            // DataReceived, …) are not consumed here.
                            // They are observed via other channels or are
                            // simply not relevant to saorsa-core.
                            continue;
                        }
                    }
                }
            });
        }
        (rx, relay_rx, relay_lost_rx)
    }

    /// Spawn one background task per bound stack (v4, v6) to classify
    /// inbound connections and accumulate per-address proof sets.
    ///
    /// ## What this proves
    ///
    /// `Side::Server` alone is not proof of cold-dialability — it only
    /// proves "a packet landed at our listener," which on a NAT'd host
    /// can be a redial through a NAT pinhole that the inbound peer
    /// already knew about. The classifier records an inbound peer `P`
    /// as proof of cold-dialability for an external `E` iff **all** hold:
    ///
    /// 1. `Side::Server` (someone connected to us, we did not initiate).
    /// 2. The remote socket is not in `dialed_addrs` — guards
    ///    simultaneous-open replies. Pre-populated at every dial site
    ///    (`TransportHandle::connect_peer`).
    /// 3. The remote IP is not in `known_peer_ips` at the moment of the
    ///    event — i.e. not a peer we have ever dialed or accepted from
    ///    before. Closes the bootstrap-redial / pinhole-self-fulfillment
    ///    case where a peer we previously connected to opens a fresh
    ///    QUIC connection through their pre-existing NAT binding.
    /// 4. The remote IP is not equal to any of our own pinned external
    ///    IPs — sibling-hairpin filter (multiple nodes behind one shared
    ///    NAT see each other's traffic as "inbound from our public IP"
    ///    after MASQUERADE; this never left the LAN).
    /// 5. **`P` itself reported `E` via a QUIC `OBSERVED_ADDRESS` frame.**
    ///    `E` is then the per-address attribution signal: the peer's own
    ///    statement that they reached us at `E`. A v4 inbound from `P`
    ///    that reported only `E_v4` cannot promote any other pinned
    ///    external — same family or otherwise.
    ///
    /// When all conditions hold, the remote IP is added to the **specific**
    /// reported external's observer set in `proven_externals`. Once any
    /// external reaches `MIN_DISTINCT_OBSERVERS_FOR_DIRECT` distinct
    /// observer IPs it is considered cold-dialable, and
    /// [`TransportHandle::is_external_proven`] returns `true` for it.
    ///
    /// Per-address attribution is what condition 5 provides. Without it
    /// (a peer that doesn't send `OBSERVED_ADDRESS` — older clients,
    /// constrained transports), the inbound contributes no proof.
    ///
    /// ## Event ordering
    ///
    /// `P2pEvent::PeerConnected` and `P2pEvent::PeerObservedExternal`
    /// arrive in arbitrary order from saorsa-transport. The classifier
    /// stores both `peer_observations` and `proof_eligible_peers` and
    /// credits at whichever event completes the pair (with the further
    /// requirement that the address is currently in `pinned_direct`).
    /// A back-fill on `ExternalAddressDiscovered` (in the address
    /// forwarder) handles the third case where the observation arrives
    /// before saorsa-transport's pinning quorum clears.
    ///
    /// ## What this also does
    ///
    /// On every `PeerConnected` event (any `Side`), the remote IP is
    /// recorded in `known_peer_ips`. This means the very first inbound
    /// from a stranger IP can contribute proof, but every subsequent
    /// inbound from that same IP is recognised as not source-disjoint
    /// and skipped — preventing one chatty peer from inflating its own
    /// proof beyond the single observer slot it deserves.
    ///
    /// `Side::Client` events also write `known_peer_ips`, ensuring that
    /// a peer we dial first cannot later "appear unsolicited" via a
    /// pinhole redial — even if their NAT has remapped them to a port
    /// not in `dialed_addrs`.
    pub fn spawn_direct_reachability_classifier(
        &self,
        dialed_addrs: Arc<DashSet<SocketAddr>>,
        known_peer_ips: Arc<DashSet<IpAddr>>,
        proven_externals: Arc<DashMap<SocketAddr, HashSet<IpAddr>>>,
        external_addresses: Arc<parking_lot::Mutex<ExternalAddresses>>,
        peer_observations: Arc<DashMap<IpAddr, HashSet<SocketAddr>>>,
        proof_eligible_peers: Arc<DashSet<IpAddr>>,
    ) {
        for node in [&self.v6, &self.v4].into_iter().flatten() {
            let mut p2p_rx = node.transport.endpoint().subscribe();
            let dialed = Arc::clone(&dialed_addrs);
            let known = Arc::clone(&known_peer_ips);
            let proven = Arc::clone(&proven_externals);
            let external = Arc::clone(&external_addresses);
            let observations = Arc::clone(&peer_observations);
            let eligible = Arc::clone(&proof_eligible_peers);
            tokio::spawn(async move {
                loop {
                    match p2p_rx.recv().await {
                        Ok(saorsa_transport::P2pEvent::PeerConnected { addr, side, .. }) => {
                            handle_peer_connected_for_proof(
                                addr,
                                side,
                                &dialed,
                                &known,
                                &external,
                                &observations,
                                &eligible,
                                &proven,
                            );
                        }
                        Ok(saorsa_transport::P2pEvent::PeerObservedExternal {
                            peer_addr,
                            observed_external,
                        }) => {
                            handle_peer_observed_external(
                                peer_addr,
                                observed_external,
                                &external,
                                &observations,
                                &eligible,
                                &proven,
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Ok(_other) => continue,
                    }
                }
            });
        }
    }

    /// Create dual nodes bound to IPv6 and IPv4 addresses with default
    /// connection limit.
    pub async fn new(v6_addr: Option<SocketAddr>, v4_addr: Option<SocketAddr>) -> Result<Self> {
        Self::new_with_max_connections(v6_addr, v4_addr, DEFAULT_MAX_CONNECTIONS, None).await
    }

    /// Create dual nodes with an explicit maximum connection limit and
    /// optional message-size override.
    ///
    /// When `max_msg_size` is `None` the crate-level [`MAX_MESSAGE_SIZE`]
    /// default is used.
    pub async fn new_with_max_connections(
        v6_addr: Option<SocketAddr>,
        v4_addr: Option<SocketAddr>,
        max_connections: usize,
        max_msg_size: Option<usize>,
    ) -> Result<Self> {
        Self::new_with_options(
            v6_addr,
            v4_addr,
            max_connections,
            max_msg_size,
            false,
            true,
            true,
        )
        .await
    }

    /// Create dual nodes with full control over connection limits, message
    /// size, loopback address acceptance, relay service, and external-address
    /// advertisement.
    pub async fn new_with_options(
        v6_addr: Option<SocketAddr>,
        v4_addr: Option<SocketAddr>,
        max_connections: usize,
        max_msg_size: Option<usize>,
        allow_loopback: bool,
        enable_relay_service: bool,
        advertise_external_addresses: bool,
    ) -> Result<Self> {
        let v6 = if let Some(addr) = v6_addr {
            Some(
                P2PNetworkNode::new_with_options(
                    addr,
                    max_connections,
                    max_msg_size,
                    allow_loopback,
                    enable_relay_service,
                    advertise_external_addresses,
                )
                .await?,
            )
        } else {
            None
        };
        let v4 = if let Some(addr) = v4_addr {
            match P2PNetworkNode::new_with_options(
                addr,
                max_connections,
                max_msg_size,
                allow_loopback,
                enable_relay_service,
                advertise_external_addresses,
            )
            .await
            {
                Ok(node) => Some(node),
                Err(e) => {
                    // On Linux with net.ipv6.bindv6only=0 (the default), an IPv6
                    // socket bound to [::]:port already accepts IPv4 traffic via
                    // dual-stack.  Binding a separate IPv4 socket to the same port
                    // then fails with "Address in use".  When we already hold an
                    // IPv6 socket on that port we can safely skip the IPv4 bind.
                    //
                    // Only applies when the IPv6 address is unspecified ([::]); a
                    // specific IPv6 address won't accept IPv4 traffic.
                    let same_port = match (v6_addr, v4_addr) {
                        (Some(v6_sock), Some(v4_sock)) => v6_sock.port() == v4_sock.port(),
                        _ => false,
                    };
                    let v6_is_unspecified = matches!(
                        v6_addr,
                        Some(SocketAddr::V6(ref a)) if a.ip().is_unspecified()
                    );
                    // Prefer downcasting through the error chain to find the
                    // original io::Error (works when .context() preserves the
                    // source).  Fall back to string matching because the current
                    // transport layer stringifies the io::Error before wrapping.
                    let is_addr_in_use = e
                        .chain()
                        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                        .any(|io_err| io_err.kind() == std::io::ErrorKind::AddrInUse)
                        || format!("{e:#}").contains("in use");

                    if v6.is_some() && v6_is_unspecified && same_port && is_addr_in_use {
                        info!(
                            port = addr.port(),
                            "IPv6 socket is dual-stack — skipping separate IPv4 bind"
                        );
                        debug!("IPv4 bind error (suppressed): {e}");
                        None
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            None
        };
        let is_dual_stack = v6.is_some() && v4.is_none();
        Ok(Self {
            v6,
            v4,
            is_dual_stack,
        })
    }

    /// Send to peer using P2pEndpoint's optimized send method.
    ///
    /// Routes the send to the appropriate stack based on the target's
    /// address family. In dual-stack mode, converts plain IPv4 to the
    /// IPv4-mapped form expected by the v6 transport before sending.
    ///
    /// **Fallback is NOT attempted across address families.** When the
    /// target is IPv4 and v4 is bound, we never fall back to v6 — the
    /// v6 stack has no record of an IPv4-only peer, so the attempt is
    /// guaranteed to fail with `Peer not found` and just produces log
    /// noise plus wasted latency. The fallback only makes sense for:
    ///
    /// - IPv6 targets when v6 is bound (direct path)
    /// - IPv4 targets on nodes that only bound v6 (dual-stack-over-v6)
    /// - v4-only nodes that need to reach v6 targets — not supported
    pub async fn send_to_peer_optimized(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        // v4 target + v4 stack bound → send via v4 only. A v6 fallback
        // would hit "Peer not found" (v6 has no record) and contribute
        // 1 s of useless ACK-timeout latency on failure.
        if addr.is_ipv4()
            && let Some(v4) = &self.v4
        {
            return v4
                .send_to_peer_optimized(addr, data)
                .await
                .map_err(|e| e.context(format!("IPv4 send to {} failed", addr)));
        }

        // v6 target, or IPv4 target on a v6-only (dual-stack-over-v6)
        // node: route through v6, converting IPv4 → v4-mapped form.
        if let Some(v6) = &self.v6 {
            let wire_addr = self.to_mapped_if_needed(addr);
            return v6
                .send_to_peer_optimized(&wire_addr, data)
                .await
                .map_err(|e| {
                    e.context(format!("IPv6 send to {} (wire {}) failed", addr, wire_addr))
                });
        }

        // Neither stack can take this target. This is unreachable on a
        // correctly-configured dual-stack node but guarded for safety.
        Err(anyhow::anyhow!(
            "send_to_peer_optimized to {}: no compatible stack bound (v4={}, v6={})",
            addr,
            self.v4.is_some(),
            self.v6.is_some()
        ))
    }

    /// Disconnect a peer, closing the underlying QUIC connection.
    ///
    /// Delegates to [`Self::pick_stacks_for`] so the stack carrying the
    /// peer is targeted in split-stack mode, and the single v6 socket
    /// (with mapping for v4 targets) is targeted in dual-stack mode.
    /// Issuing a disconnect to the wrong stack is wasted — on Windows it
    /// actively triggers WSAEADDRNOTAVAIL against a v6-only socket with a
    /// v4 target.
    pub async fn disconnect_peer_by_addr(&self, addr: &SocketAddr) {
        let (primary, fallback) = self.pick_stacks_for(addr);
        if let Some((node, wire_addr)) = primary {
            node.disconnect_peer_quic(&wire_addr).await;
        }
        if let Some((node, wire_addr)) = fallback {
            node.disconnect_peer_quic(&wire_addr).await;
        }
    }

    /// Disconnect a peer by address.
    pub async fn disconnect_peer(&self, addr: &SocketAddr) {
        self.disconnect_peer_by_addr(addr).await;
    }

    /// Spawn recv tasks for all active stacks.
    ///
    /// In dual-stack mode, addresses from the v6 transport are normalised
    /// (IPv4-mapped → plain IPv4) before being sent to the channel so that
    /// saorsa-core always sees a consistent address format.
    pub fn spawn_recv_tasks(
        &self,
        tx: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        if let Some(v6) = self.v6.as_ref() {
            if self.is_dual_stack {
                let (inner_tx, mut inner_rx) = tokio::sync::mpsc::channel::<(SocketAddr, Vec<u8>)>(
                    crate::network::MESSAGE_RECV_CHANNEL_CAPACITY,
                );
                handles.push(v6.spawn_recv_task(inner_tx, shutdown.clone()));
                let outer_tx = tx.clone();
                handles.push(tokio::spawn(async move {
                    while let Some((addr, data)) = inner_rx.recv().await {
                        let norm = saorsa_transport::shared::normalize_socket_addr(addr);
                        if outer_tx.send((norm, data)).await.is_err() {
                            break;
                        }
                    }
                }));
            } else {
                handles.push(v6.spawn_recv_task(tx.clone(), shutdown.clone()));
            }
        }

        if let Some(v4) = self.v4.as_ref() {
            handles.push(v4.spawn_recv_task(tx.clone(), shutdown.clone()));
        }

        handles
    }
}

#[allow(dead_code)]
impl<T: LinkTransport + Send + Sync + 'static> DualStackNetworkNode<T> {
    /// Create with custom transports (for testing)
    pub fn with_transports(v6: Option<P2PNetworkNode<T>>, v4: Option<P2PNetworkNode<T>>) -> Self {
        let is_dual_stack = v6.is_some() && v4.is_none();
        Self {
            v6,
            v4,
            is_dual_stack,
        }
    }

    /// If dual-stack, normalise IPv4-mapped IPv6 → plain IPv4.
    /// Otherwise return unchanged.  Used on all addresses leaving the
    /// transport boundary towards saorsa-core.
    fn normalize(&self, addr: SocketAddr) -> SocketAddr {
        if self.is_dual_stack {
            saorsa_transport::shared::normalize_socket_addr(addr)
        } else {
            addr
        }
    }

    /// If dual-stack and `addr` is plain IPv4, convert to the mapped
    /// form `[::ffff:x.x.x.x]` that the v6 transport expects.
    /// Used on all addresses entering the transport from saorsa-core.
    fn to_mapped_if_needed(&self, addr: &SocketAddr) -> SocketAddr {
        if self.is_dual_stack
            && let SocketAddr::V4(v4) = addr
        {
            return SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0));
        }
        *addr
    }

    /// Pick the primary and fallback nodes for sending to `addr`, plus the
    /// wire-format address to use for each.
    ///
    /// The decision matrix lives in [`decide_dispatch`]; this method resolves
    /// the chosen [`StackChoice`] slots against `self.v6` / `self.v4` and
    /// constructs the appropriate wire address.
    ///
    /// ### Normalisation at the boundary
    ///
    /// A mapped-v4 target (`[::ffff:x.x.x.x]`) arriving here is un-mapped
    /// before the family-based dispatch. Without this, a mapped-v4 learned
    /// from a DHT record or forwarded from the v6 socket's events would
    /// reach the v6 socket in split-stack mode and trip `WSAEADDRNOTAVAIL`
    /// on Windows — the same bug family the dispatcher exists to solve.
    ///
    /// ### Modes
    ///
    /// - **Dual-stack** (`is_dual_stack=true`, Linux default): the v6 socket
    ///   handles both families via kernel mapping. v4 targets are rewritten
    ///   to `[::ffff:x.x.x.x]` at the wire.
    /// - **Split-stack** (`is_dual_stack=false`, typically Windows):
    ///   dispatch by the target's true family. `v6.is_some()`/`v4.is_some()`
    ///   can be any combination — by construction at least one must be Some
    ///   for the caller to reach here usefully.
    fn pick_stacks_for<'a>(&'a self, addr: &SocketAddr) -> PickedStacks<'a, T> {
        let addr = saorsa_transport::shared::normalize_socket_addr(*addr);

        let plan = decide_dispatch(
            self.is_dual_stack,
            self.v6.is_some(),
            self.v4.is_some(),
            addr.is_ipv4(),
        );

        let resolve = |choice: StackChoice| -> Option<(&'a P2PNetworkNode<T>, SocketAddr)> {
            let node = match choice.role {
                StackRole::V4 => self.v4.as_ref()?,
                StackRole::V6 => self.v6.as_ref()?,
            };
            let wire = if choice.mapped {
                if let SocketAddr::V4(v4) = addr {
                    SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
                } else {
                    addr
                }
            } else {
                addr
            };
            Some((node, wire))
        };

        (
            plan.primary.and_then(resolve),
            plan.fallback.and_then(resolve),
        )
    }

    /// Happy Eyeballs connect: race IPv6 and IPv4 attempts.
    ///
    /// ### Dual-stack (single v6 socket via kernel mapping)
    ///
    /// Dial every target through the v6 socket in caller-provided order —
    /// v4 targets get rewritten to `[::ffff:x.x.x.x]` wire form. Ordering
    /// matters: callers sort targets by preference (most-recently-seen,
    /// best-latency, trust score) and Happy Eyeballs relies on that
    /// priority. A bucket-then-merge approach would silently reorder
    /// mixed `[mapped_v4, real_v6]` inputs.
    ///
    /// ### Split-stack (family-specific sockets)
    ///
    /// Bucket targets by their true post-unmapping family — an
    /// `[::ffff:x.x.x.x]:port` target (as stored in the DHT by dual-stack
    /// peers reporting via `ObservedAddress`) un-maps into the v4 bucket
    /// so v4-only hosts (Windows split-stack, `--ipv4-only`, v6-disabled)
    /// can dial it. If both stacks have targets, race them with a 50 ms
    /// Happy Eyeballs head-start for v6.
    ///
    /// The returned address is always normalised (plain IPv4).
    pub async fn connect_happy_eyeballs(&self, targets: &[SocketAddr]) -> Result<SocketAddr> {
        if self.is_dual_stack {
            let dial_list = to_dual_stack_dial_list(targets);
            if dial_list.is_empty() {
                return Err(anyhow::anyhow!("No suitable transport available"));
            }
            let addr = self.connect_sequential(&self.v6, &dial_list).await?;
            return Ok(self.normalize(addr));
        }

        let (v6_targets, v4_targets) = bucket_targets(targets);

        let (v6_node, v4_node) = match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) if !v6_targets.is_empty() && !v4_targets.is_empty() => (v6, v4),
            (Some(_), _) if !v6_targets.is_empty() => {
                let addr = self.connect_sequential(&self.v6, &v6_targets).await?;
                return Ok(self.normalize(addr));
            }
            (_, Some(_)) if !v4_targets.is_empty() => {
                let addr = self.connect_sequential(&self.v4, &v4_targets).await?;
                return Ok(self.normalize(addr));
            }
            _ => return Err(anyhow::anyhow!("No suitable transport available")),
        };

        let v6_targets_clone = v6_targets.clone();
        let v4_targets_clone = v4_targets.clone();

        let v6_fut = async {
            for addr in v6_targets_clone {
                if let Ok(connected_addr) = v6_node.connect_to_peer(addr).await {
                    return Ok(connected_addr);
                }
            }
            Err(anyhow::anyhow!("IPv6 connect attempts failed"))
        };

        let v4_fut = async {
            sleep(HAPPY_EYEBALLS_V4_STAGGER).await;
            for addr in v4_targets_clone {
                if let Ok(connected_addr) = v4_node.connect_to_peer(addr).await {
                    return Ok(connected_addr);
                }
            }
            Err(anyhow::anyhow!("IPv4 connect attempts failed"))
        };

        tokio::select! {
            res6 = v6_fut => match res6 {
                Ok(connected_addr) => Ok(connected_addr),
                Err(_) => {
                    for addr in v4_targets {
                        if let Ok(connected_addr) = v4_node.connect_to_peer(addr).await {
                            return Ok(connected_addr);
                        }
                    }
                    Err(anyhow::anyhow!("All connect attempts failed"))
                }
            },
            res4 = v4_fut => match res4 {
                Ok(connected_addr) => Ok(connected_addr),
                Err(_) => {
                    for addr in v6_targets {
                        if let Ok(connected_addr) = v6_node.connect_to_peer(addr).await {
                            return Ok(connected_addr);
                        }
                    }
                    Err(anyhow::anyhow!("All connect attempts failed"))
                }
            }
        }
    }

    async fn connect_sequential(
        &self,
        node: &Option<P2PNetworkNode<T>>,
        targets: &[SocketAddr],
    ) -> Result<SocketAddr> {
        let node = node
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node not available"))?;
        for &addr in targets {
            if let Ok(connected_addr) = node.connect_to_peer(addr).await {
                return Ok(connected_addr);
            }
        }
        Err(anyhow::anyhow!("All connect attempts failed"))
    }

    /// Return all local listening addresses
    pub async fn local_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            let actual_addr = v6.actual_listening_address().await?;
            out.push(actual_addr);
        }
        if let Some(v4) = &self.v4 {
            let actual_addr = v4.actual_listening_address().await?;
            out.push(actual_addr);
        }
        Ok(out)
    }

    /// Accept the next incoming connection from either stack.
    ///
    /// Returns `None` when shutdown is signalled or no stacks are available.
    /// Addresses are normalised so callers always see plain IPv4.
    pub async fn accept_any(&self) -> Option<SocketAddr> {
        let raw = match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                tokio::select! {
                    res = v6.accept_connection() => res,
                    res = v4.accept_connection() => res,
                }
            }
            (Some(v6), None) => v6.accept_connection().await,
            (None, Some(v4)) => v4.accept_connection().await,
            (None, None) => None,
        };
        raw.map(|a| self.normalize(a))
    }

    /// Get all connected peer addresses (merged from both stacks).
    /// Addresses are normalised so callers always see plain IPv4.
    pub async fn get_connected_peers(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        if let Some(v6) = &self.v6 {
            out.extend(v6.get_connected_peers().await);
        }
        if let Some(v4) = &self.v4 {
            out.extend(v4.get_connected_peers().await);
        }
        if self.is_dual_stack {
            for addr in &mut out {
                *addr = saorsa_transport::shared::normalize_socket_addr(*addr);
            }
        }
        out
    }

    /// Send to peer by address. In dual-stack mode the v6 socket handles
    /// both families (with v4 rewritten to mapped form). In split-stack
    /// mode, dispatch by target family so v4 targets go to the v4 socket
    /// directly — avoids WSAEADDRNOTAVAIL on Windows where the v6 socket
    /// is v6-only.
    pub async fn send_to_peer_raw(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        let (primary, fallback) = self.pick_stacks_for(addr);
        if let Some((node, wire_addr)) = primary
            && node.send_to_peer_raw(&wire_addr, data).await.is_ok()
        {
            return Ok(());
        }
        if let Some((node, wire_addr)) = fallback
            && node.send_to_peer_raw(&wire_addr, data).await.is_ok()
        {
            return Ok(());
        }
        Err(anyhow::anyhow!(
            "send_to_peer_raw to {addr} failed on all available stacks"
        ))
    }

    /// Send to peer by address.
    pub async fn send_to_peer(&self, addr: &SocketAddr, data: &[u8]) -> Result<()> {
        self.send_to_peer_raw(addr, data).await
    }

    /// Subscribe to connection lifecycle events from both stacks.
    /// Addresses in events are normalised so callers always see plain IPv4.
    pub fn subscribe_connection_events(&self) -> broadcast::Receiver<ConnectionEvent> {
        let (tx, rx) = broadcast::channel(crate::DEFAULT_EVENT_CHANNEL_CAPACITY);
        let dual = self.is_dual_stack;

        if let Some(v6) = &self.v6 {
            let mut v6_rx = v6.subscribe_connection_events();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                loop {
                    match v6_rx.recv().await {
                        Ok(event) => {
                            let event = if dual {
                                normalize_connection_event(event)
                            } else {
                                event
                            };
                            let _ = tx_clone.send(event);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                "IPv6 connection event forwarder lagged, skipped {n} events"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                tracing::debug!("IPv6 connection event forwarder exited");
            });
        }

        if let Some(v4) = &self.v4 {
            let mut v4_rx = v4.subscribe_connection_events();
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                loop {
                    match v4_rx.recv().await {
                        Ok(event) => {
                            let _ = tx_clone.send(event);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(
                                "IPv4 connection event forwarder lagged, skipped {n} events"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                tracing::debug!("IPv4 connection event forwarder exited");
            });
        }

        // Drop the original sender so channel lifetime is determined by forwarder tasks
        drop(tx);
        rx
    }

    /// Get observed external address
    pub fn get_observed_external_address(&self) -> Option<SocketAddr> {
        let raw = self
            .v4
            .as_ref()
            .and_then(|v4| v4.get_observed_external_address())
            .or_else(|| {
                self.v6
                    .as_ref()
                    .and_then(|v6| v6.get_observed_external_address())
            });
        raw.map(|a| self.normalize(a))
    }

    /// Return observed external addresses for **every** stack that has one.
    ///
    /// Multi-homed publishing path: each stack (v4 / v6) is queried
    /// independently and any address it reports is included in the
    /// returned list (deduped, normalised). A multi-homed host that has
    /// observations on both v4 and v6 will return both — `local_dht_node`
    /// then publishes both so peers reaching the host on either family
    /// can dial it.
    pub fn get_observed_external_addresses(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for stack in [self.v4.as_ref(), self.v6.as_ref()].into_iter().flatten() {
            if let Some(raw) = stack.get_observed_external_address() {
                let normalized = self.normalize(raw);
                if !out.contains(&normalized) {
                    out.push(normalized);
                }
            }
        }
        out
    }
}

/// Bucket `targets` by their true, post-unmapping address family.
///
/// DHT-stored peer addresses are whatever form the peer reported —
/// dual-stack peers advertise themselves via `ObservedAddress` frames
/// in IPv4-mapped IPv6 (`[::ffff:a.b.c.d]:port`) form, and that
/// representation propagates through DHT lookups. We un-map before
/// bucketing so routing decisions are made by the peer's true family,
/// not by the `SocketAddr` enum variant.
///
/// Without this, a mapped-v4 target is classified as v6, and v4-only
/// callers (Windows split-stack, `--ipv4-only`, v6-disabled hosts) get
/// `NoSuitableTransport` even though the v4 socket could dial the
/// underlying v4 peer perfectly well.
fn bucket_targets(targets: &[SocketAddr]) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for &t in targets {
        let t = saorsa_transport::shared::normalize_socket_addr(t);
        if t.is_ipv6() {
            v6.push(t);
        } else {
            v4.push(t);
        }
    }
    (v6, v4)
}

/// Rebuild `targets` as a single v6-wire dial list for dual-stack mode.
///
/// Plain IPv4 entries are rewritten to `[::ffff:x.x.x.x]`; v6 entries
/// (real v6 and already-mapped v4) pass through unchanged. Caller-
/// provided order is preserved so Happy Eyeballs attempt priority on
/// mixed `[mapped_v4, real_v6]` inputs is not reordered by a
/// bucket-then-merge pass.
fn to_dual_stack_dial_list(targets: &[SocketAddr]) -> Vec<SocketAddr> {
    targets
        .iter()
        .map(|addr| match addr {
            SocketAddr::V4(v4) => {
                SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
            }
            SocketAddr::V6(_) => *addr,
        })
        .collect()
}

/// Normalise addresses in a `ConnectionEvent` (IPv4-mapped → plain IPv4).
fn normalize_connection_event(event: ConnectionEvent) -> ConnectionEvent {
    use saorsa_transport::shared::normalize_socket_addr;
    match event {
        ConnectionEvent::Established {
            remote_address,
            public_key,
        } => ConnectionEvent::Established {
            remote_address: normalize_socket_addr(remote_address),
            public_key,
        },
        ConnectionEvent::Lost {
            remote_address,
            reason,
        } => ConnectionEvent::Lost {
            remote_address: normalize_socket_addr(remote_address),
            reason,
        },
        ConnectionEvent::Failed {
            remote_address,
            reason,
        } => ConnectionEvent::Failed {
            remote_address: normalize_socket_addr(remote_address),
            reason,
        },
        ConnectionEvent::PeerAddressUpdated {
            peer_addr,
            advertised_addr,
        } => ConnectionEvent::PeerAddressUpdated {
            peer_addr: normalize_socket_addr(peer_addr),
            advertised_addr: normalize_socket_addr(advertised_addr),
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::{
        DispatchPlan, StackChoice, StackRole, bucket_targets, decide_dispatch,
        to_dual_stack_dial_list,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Test TDD: verify no duplicate peer registration
    ///
    /// Fixed: Event forwarder no longer tracks peers, only broadcasts events.
    /// Peer tracking with geographic validation is done by add_peer() in
    /// connect_to_peer() and accept_connection(). This avoids duplicate
    /// registration while preserving geographic validation functionality.
    #[test]
    fn test_no_duplicate_peer_registration() {
        // The fix is verified by:
        // - test_send_to_peer_string: Exercises connect_to_peer with add_peer call
        // Integration tests verify the ConnectionEvent broadcasts work correctly.
    }

    const V6: StackChoice = StackChoice {
        role: StackRole::V6,
        mapped: false,
    };
    const V6_MAPPED: StackChoice = StackChoice {
        role: StackRole::V6,
        mapped: true,
    };
    const V4: StackChoice = StackChoice {
        role: StackRole::V4,
        mapped: false,
    };

    #[test]
    fn decide_dispatch_dual_stack_v4_target_maps_onto_v6() {
        assert_eq!(
            decide_dispatch(true, true, false, true),
            DispatchPlan {
                primary: Some(V6_MAPPED),
                fallback: None,
            }
        );
    }

    #[test]
    fn decide_dispatch_dual_stack_v6_target_no_mapping() {
        assert_eq!(
            decide_dispatch(true, true, false, false),
            DispatchPlan {
                primary: Some(V6),
                fallback: None,
            }
        );
    }

    #[test]
    fn decide_dispatch_split_stack_both_sockets_v4_target_uses_v4() {
        assert_eq!(
            decide_dispatch(false, true, true, true),
            DispatchPlan {
                primary: Some(V4),
                fallback: None,
            }
        );
    }

    #[test]
    fn decide_dispatch_split_stack_both_sockets_v6_target_uses_v6() {
        assert_eq!(
            decide_dispatch(false, true, true, false),
            DispatchPlan {
                primary: Some(V6),
                fallback: None,
            }
        );
    }

    #[test]
    fn decide_dispatch_split_stack_v4_only_v4_target() {
        assert_eq!(
            decide_dispatch(false, false, true, true),
            DispatchPlan {
                primary: Some(V4),
                fallback: None,
            }
        );
    }

    #[test]
    fn decide_dispatch_split_stack_v4_only_v6_target_is_unroutable() {
        assert_eq!(
            decide_dispatch(false, false, true, false),
            DispatchPlan::default()
        );
    }

    #[test]
    fn decide_dispatch_split_stack_v6_only_v6_target() {
        assert_eq!(
            decide_dispatch(false, true, false, false),
            DispatchPlan {
                primary: Some(V6),
                fallback: None,
            }
        );
    }

    #[test]
    fn decide_dispatch_split_stack_v6_only_v4_target_is_unroutable() {
        assert_eq!(
            decide_dispatch(false, true, false, true),
            DispatchPlan::default()
        );
    }

    #[test]
    fn decide_dispatch_no_stacks() {
        for addr_is_v4 in [true, false] {
            assert_eq!(
                decide_dispatch(false, false, false, addr_is_v4),
                DispatchPlan::default()
            );
        }
    }

    #[test]
    fn decide_dispatch_dual_stack_with_defensive_v4_fallback() {
        assert_eq!(
            decide_dispatch(true, true, true, true),
            DispatchPlan {
                primary: Some(V6_MAPPED),
                fallback: Some(V4),
            }
        );
        assert_eq!(
            decide_dispatch(true, true, true, false),
            DispatchPlan {
                primary: Some(V6),
                fallback: Some(V4),
            }
        );
    }

    fn mapped_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0,
                0,
                0,
                0,
                0,
                0xffff,
                ((a as u16) << 8) | b as u16,
                ((c as u16) << 8) | d as u16,
            )),
            port,
        )
    }

    fn plain_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn real_v6(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        )
    }

    #[test]
    fn bucket_targets_unmaps_mapped_v4_into_v4_bucket() {
        let (v6, v4) = bucket_targets(&[mapped_v4(1, 2, 3, 4, 5000)]);
        assert!(v6.is_empty(), "mapped-v4 must not stay in v6 bucket");
        assert_eq!(v4, vec![plain_v4(1, 2, 3, 4, 5000)]);
    }

    #[test]
    fn bucket_targets_passes_plain_v4_through() {
        let (v6, v4) = bucket_targets(&[plain_v4(10, 0, 0, 1, 4242)]);
        assert!(v6.is_empty());
        assert_eq!(v4, vec![plain_v4(10, 0, 0, 1, 4242)]);
    }

    #[test]
    fn bucket_targets_passes_real_v6_through() {
        let (v6, v4) = bucket_targets(&[real_v6(6000)]);
        assert_eq!(v6, vec![real_v6(6000)]);
        assert!(v4.is_empty());
    }

    #[test]
    fn bucket_targets_mixed_inputs_split_by_true_family() {
        let (v6, v4) = bucket_targets(&[
            real_v6(1),
            mapped_v4(192, 168, 1, 1, 2),
            plain_v4(10, 0, 0, 1, 3),
        ]);
        assert_eq!(v6, vec![real_v6(1)], "real v6 stays in v6 bucket");
        assert_eq!(
            v4,
            vec![plain_v4(192, 168, 1, 1, 2), plain_v4(10, 0, 0, 1, 3)],
            "mapped-v4 un-maps and joins plain v4 in v4 bucket"
        );
    }

    #[test]
    fn bucket_targets_preserves_order_within_bucket() {
        let (v6, v4) = bucket_targets(&[
            plain_v4(1, 1, 1, 1, 1),
            mapped_v4(2, 2, 2, 2, 2),
            plain_v4(3, 3, 3, 3, 3),
        ]);
        assert!(v6.is_empty());
        assert_eq!(
            v4,
            vec![
                plain_v4(1, 1, 1, 1, 1),
                plain_v4(2, 2, 2, 2, 2),
                plain_v4(3, 3, 3, 3, 3),
            ],
            "bucket must preserve input order (Happy Eyeballs race relies on this)"
        );
    }

    #[test]
    fn to_dual_stack_dial_list_maps_plain_v4_to_mapped_wire_form() {
        let out = to_dual_stack_dial_list(&[plain_v4(1, 2, 3, 4, 5000)]);
        assert_eq!(out, vec![mapped_v4(1, 2, 3, 4, 5000)]);
    }

    #[test]
    fn to_dual_stack_dial_list_passes_already_mapped_v4_through() {
        let already_mapped = mapped_v4(10, 0, 0, 1, 1234);
        let out = to_dual_stack_dial_list(&[already_mapped]);
        assert_eq!(out, vec![already_mapped]);
    }

    #[test]
    fn to_dual_stack_dial_list_passes_real_v6_through() {
        let out = to_dual_stack_dial_list(&[real_v6(6000)]);
        assert_eq!(out, vec![real_v6(6000)]);
    }

    #[test]
    fn to_dual_stack_dial_list_preserves_caller_order_on_mixed_input() {
        let input = [
            mapped_v4(1, 1, 1, 1, 1),
            real_v6(2),
            plain_v4(3, 3, 3, 3, 3),
            real_v6(4),
        ];
        let out = to_dual_stack_dial_list(&input);
        assert_eq!(
            out,
            vec![
                mapped_v4(1, 1, 1, 1, 1),
                real_v6(2),
                mapped_v4(3, 3, 3, 3, 3),
                real_v6(4),
            ],
            "dial list must match caller-provided order exactly"
        );
    }

    #[test]
    fn to_dual_stack_dial_list_empty_input_empty_output() {
        assert!(to_dual_stack_dial_list(&[]).is_empty());
    }
}

#[cfg(test)]
mod classifier_tests {
    use super::{
        back_fill_proof_on_pin, handle_peer_connected_for_proof, handle_peer_observed_external,
    };
    use crate::transport::external_addresses::ExternalAddresses;
    use crate::transport_handle::{
        MAX_OBSERVATIONS_PER_PEER, MIN_DISTINCT_OBSERVERS_FOR_DIRECT,
        external_meets_proof_threshold,
    };
    use dashmap::{DashMap, DashSet};
    use saorsa_transport::{Side, TransportAddr};
    use std::collections::HashSet;
    use std::net::{IpAddr, SocketAddr};

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("test socket addr")
    }

    /// One harness scoped to a single classifier under test.
    ///
    /// Wires up the same Arcs the real classifier owns so the helper
    /// functions can be invoked directly with deterministic state.
    struct ProofHarness {
        dialed: DashSet<SocketAddr>,
        known: DashSet<IpAddr>,
        external: parking_lot::Mutex<ExternalAddresses>,
        observations: DashMap<IpAddr, HashSet<SocketAddr>>,
        eligible: DashSet<IpAddr>,
        proven: DashMap<SocketAddr, HashSet<IpAddr>>,
    }

    impl ProofHarness {
        fn new() -> Self {
            Self {
                dialed: DashSet::new(),
                known: DashSet::new(),
                external: parking_lot::Mutex::new(ExternalAddresses::new()),
                observations: DashMap::new(),
                eligible: DashSet::new(),
                proven: DashMap::new(),
            }
        }

        fn pin(&self, addr: SocketAddr) {
            self.external.lock().pin_direct(addr);
        }

        fn inbound(&self, peer: SocketAddr) {
            self.dispatch_peer_connected(peer, Side::Server);
        }

        fn outbound(&self, peer: SocketAddr) {
            self.dispatch_peer_connected(peer, Side::Client);
        }

        fn dispatch_peer_connected(&self, peer: SocketAddr, side: Side) {
            handle_peer_connected_for_proof(
                TransportAddr::Quic(peer),
                side,
                &self.dialed,
                &self.known,
                &self.external,
                &self.observations,
                &self.eligible,
                &self.proven,
            );
        }

        fn observe(&self, peer: SocketAddr, observed: SocketAddr) {
            handle_peer_observed_external(
                peer,
                observed,
                &self.external,
                &self.observations,
                &self.eligible,
                &self.proven,
            );
        }

        fn pin_with_back_fill(&self, addr: SocketAddr) {
            self.external.lock().pin_direct(addr);
            back_fill_proof_on_pin(addr, &self.observations, &self.eligible, &self.proven);
        }

        fn is_proven(&self, addr: SocketAddr) -> bool {
            external_meets_proof_threshold(addr, &self.proven)
        }

        fn observer_count(&self, addr: SocketAddr) -> usize {
            let normalized = saorsa_transport::shared::normalize_socket_addr(addr);
            self.proven.get(&normalized).map(|s| s.len()).unwrap_or(0)
        }
    }

    /// **Reviewer's regression test.** Two pinned IPv4 externals and two
    /// source-disjoint inbound peers. Each peer reports observing only
    /// one — different — external. Neither external reaches the
    /// distinct-observer quorum, because the other peer's inbound is not
    /// per-address attribution for this address.
    ///
    /// Pre-fix behavior would have promoted **both** externals to Direct
    /// (every same-family pinned external got credited by every
    /// source-disjoint inbound). Post-fix, attribution is per the peer's
    /// own `OBSERVED_ADDRESS` report — no leakage across externals.
    #[test]
    fn two_pinned_externals_two_disjoint_inbounds_each_reports_one_promotes_neither() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        let ext_b = sa("198.51.100.2:10000");
        h.pin(ext_a);
        h.pin(ext_b);

        let p1 = sa("203.0.113.10:55555");
        let p2 = sa("203.0.113.20:55555");

        h.inbound(p1);
        h.observe(p1, ext_a);

        h.inbound(p2);
        h.observe(p2, ext_b);

        assert_eq!(
            h.observer_count(ext_a),
            1,
            "ext_a only got attributed by P1"
        );
        assert_eq!(
            h.observer_count(ext_b),
            1,
            "ext_b only got attributed by P2"
        );
        assert!(
            !h.is_proven(ext_a),
            "ext_a must NOT be promoted by P2's inbound — P2 reported a different external"
        );
        assert!(
            !h.is_proven(ext_b),
            "ext_b must NOT be promoted by P1's inbound — P1 reported a different external"
        );
    }

    /// Convergent case: two pinned externals, both peers report the same
    /// one. Only the reported external reaches quorum.
    #[test]
    fn two_disjoint_inbounds_reporting_same_external_promotes_only_that_external() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        let ext_b = sa("198.51.100.2:10000");
        h.pin(ext_a);
        h.pin(ext_b);

        let p1 = sa("203.0.113.10:0");
        let p2 = sa("203.0.113.20:0");

        h.inbound(p1);
        h.observe(p1, ext_a);
        h.inbound(p2);
        h.observe(p2, ext_a);

        assert!(h.is_proven(ext_a));
        assert!(!h.is_proven(ext_b));
    }

    /// Multi-WAN: two pinned externals, both peers genuinely reach us
    /// via both (e.g. anycast or dual-WAN). Both promote.
    #[test]
    fn two_disjoint_inbounds_reporting_both_externals_promote_both() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        let ext_b = sa("198.51.100.2:10000");
        h.pin(ext_a);
        h.pin(ext_b);

        let p1 = sa("203.0.113.10:0");
        let p2 = sa("203.0.113.20:0");

        h.inbound(p1);
        h.observe(p1, ext_a);
        h.observe(p1, ext_b);
        h.inbound(p2);
        h.observe(p2, ext_a);
        h.observe(p2, ext_b);

        assert!(h.is_proven(ext_a));
        assert!(h.is_proven(ext_b));
    }

    /// Source-disjointness: an inbound from a peer we previously dialed
    /// is not proof-eligible, and their `OBSERVED_ADDRESS` reports do not
    /// credit.
    #[test]
    fn previously_dialed_peer_observation_does_not_credit() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        h.pin(ext_a);

        let p1 = sa("203.0.113.10:0");
        h.outbound(p1); // marks the peer's IP in `known`
        h.inbound(p1); // arrives later; previously known → not eligible
        h.observe(p1, ext_a);

        assert_eq!(h.observer_count(ext_a), 0);
    }

    /// Sibling-hairpin: an inbound whose source IP equals one of our
    /// own pinned externals is rejected (NAT loopback, never left LAN).
    #[test]
    fn inbound_from_own_external_ip_is_filtered() {
        let h = ProofHarness::new();
        let our_external = sa("198.51.100.1:10000");
        h.pin(our_external);

        let sibling = sa("198.51.100.1:55555"); // same IP, different port
        h.inbound(sibling);
        h.observe(sibling, our_external);

        assert_eq!(h.observer_count(our_external), 0);
    }

    /// Out-of-order: observation arrives before its `PeerConnected`.
    /// The cached observation is credited when the peer becomes
    /// proof-eligible.
    #[test]
    fn observation_before_peer_connected_credits_on_inbound() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        h.pin(ext_a);

        let p1 = sa("203.0.113.10:0");
        h.observe(p1, ext_a); // recorded but peer not yet eligible
        h.inbound(p1);

        assert_eq!(h.observer_count(ext_a), 1);
    }

    /// Out-of-order: address pinned after its observation arrived.
    /// The back-fill on pin credits the eligible peer.
    #[test]
    fn observation_before_pin_credits_on_back_fill() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");

        let p1 = sa("203.0.113.10:0");
        h.inbound(p1); // eligible (no pinned externals to compare against)
        h.observe(p1, ext_a); // observed external not yet pinned

        assert_eq!(
            h.observer_count(ext_a),
            0,
            "credit must wait until the address is actually pinned"
        );

        h.pin_with_back_fill(ext_a);

        assert_eq!(h.observer_count(ext_a), 1);
    }

    /// Side::Client never becomes proof-eligible: even a peer we dialed
    /// who later sends us OBSERVED_ADDRESS does not contribute proof.
    #[test]
    fn side_client_does_not_become_proof_eligible() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        h.pin(ext_a);

        let p1 = sa("203.0.113.10:0");
        h.outbound(p1);
        h.observe(p1, ext_a);

        assert_eq!(h.observer_count(ext_a), 0);
    }

    /// IP-level dedup: a chatty peer reconnecting from new ephemeral
    /// ports cannot inflate their proof count beyond one slot.
    #[test]
    fn duplicate_observation_from_same_peer_ip_does_not_double_count() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        h.pin(ext_a);

        let p1 = sa("203.0.113.10:0");
        h.inbound(p1);
        h.observe(p1, ext_a);
        h.observe(p1, ext_a);

        assert_eq!(h.observer_count(ext_a), 1);
        assert!(!h.is_proven(ext_a));
    }

    /// Cross-family isolation: a v4-only inbound and a v6-only inbound
    /// each credit only their reported externals. Neither external
    /// reaches quorum.
    #[test]
    fn cross_family_attribution_does_not_leak() {
        let h = ProofHarness::new();
        let ext_v4 = sa("198.51.100.1:10000");
        let ext_v6 = sa("[2001:db8::1]:10000");
        h.pin(ext_v4);
        h.pin(ext_v6);

        let p_v4 = sa("203.0.113.10:0");
        let p_v6 = sa("[2001:db8:cafe::10]:0");

        h.inbound(p_v4);
        h.observe(p_v4, ext_v4);
        h.inbound(p_v6);
        h.observe(p_v6, ext_v6);

        assert_eq!(h.observer_count(ext_v4), 1);
        assert_eq!(h.observer_count(ext_v6), 1);
        assert!(!h.is_proven(ext_v4));
        assert!(!h.is_proven(ext_v6));
    }

    /// Per-peer observation cap: reports beyond the cap are dropped.
    /// The first `MAX_OBSERVATIONS_PER_PEER` distinct externals are
    /// retained; further distinct externals from the same peer are
    /// silently ignored.
    #[test]
    fn per_peer_observation_cap_enforced() {
        let h = ProofHarness::new();

        let p1 = sa("203.0.113.10:0");
        h.inbound(p1);

        let cap = MAX_OBSERVATIONS_PER_PEER;
        for i in 0..cap {
            let ext = format!("198.51.100.{}:10000", i + 1)
                .parse::<SocketAddr>()
                .expect("addr");
            h.pin(ext);
            h.observe(p1, ext);
        }

        let overflow = sa("198.51.100.250:10000");
        h.pin(overflow);
        h.observe(p1, overflow);

        assert_eq!(
            h.observer_count(overflow),
            0,
            "the cap+1 observation must be dropped, even with the address pinned"
        );
        // Within-cap observations are credited normally.
        let first = sa("198.51.100.1:10000");
        assert_eq!(h.observer_count(first), 1);
    }

    /// Threshold semantics: ≥ `MIN_DISTINCT_OBSERVERS_FOR_DIRECT`
    /// distinct attributable peer IPs must promote to Direct.
    #[test]
    fn threshold_constant_is_respected() {
        let h = ProofHarness::new();
        let ext_a = sa("198.51.100.1:10000");
        h.pin(ext_a);

        let mut ips = Vec::new();
        for i in 0..MIN_DISTINCT_OBSERVERS_FOR_DIRECT {
            let p = format!("203.0.113.{}:0", 10 + i)
                .parse::<SocketAddr>()
                .expect("addr");
            h.inbound(p);
            h.observe(p, ext_a);
            ips.push(p);
        }

        assert!(h.is_proven(ext_a));
        // Sanity: ext_a got exactly MIN_DISTINCT_OBSERVERS_FOR_DIRECT
        // observers, not more.
        assert_eq!(h.observer_count(ext_a), MIN_DISTINCT_OBSERVERS_FOR_DIRECT);
    }
}
