# Trust Signals API Reference

## Overview

saorsa-core provides a response-rate trust system for tracking node reliability.
The trust system is owned by `AdaptiveDHT`, which is the sole authority on peer trust scores.

Core only records penalties — successful responses are the expected baseline
and do not warrant a reward. Positive trust signals are the consumer's
responsibility via `TrustEvent::ApplicationSuccess`.

The trust system enables:
- **Sybil resistance**: Malicious nodes are downscored automatically
- **Close-group quarantine**: K-closest peers below the quarantine threshold are evicted when the routing table can retain at least K peers
- **Self-healing**: Time decay moves quarantined peers back toward neutral over days
- **Lazy swap-out**: Low-trust peers outside the close group are replaced when better candidates arrive

## Quick Start

```rust
use saorsa_core::{P2PNode, TrustEvent};

// Consumer rewards peer after successful application-level operation:
node.report_trust_event(&peer_id, TrustEvent::ApplicationSuccess(1.0)).await;

// Report a connection failure (penalty):
node.report_trust_event(&peer_id, TrustEvent::ConnectionFailed).await;

// Check peer trust before operations:
let trust = node.peer_trust(&peer_id);
if trust < 0.3 {
    tracing::warn!("Low trust peer: {peer_id}");
}
```

## P2PNode Trust Methods

### `report_trust_event(peer_id, event)`

Report a trust event for a peer. Core penalties (connection failures) are
recorded automatically by the DHT layer. Consumers use this API to report
application-level outcomes (rewards and additional penalties).

```rust
pub async fn report_trust_event(&self, peer_id: &PeerId, event: TrustEvent)
```

### `peer_trust(peer_id)`

Get the current trust score for a peer (0.0 to 1.0). Returns 0.5 for unknown peers.

```rust
pub fn peer_trust(&self, peer_id: &PeerId) -> f64
```

### `trust_engine()`

Get the underlying TrustEngine for advanced operations.

```rust
pub fn trust_engine(&self) -> &Arc<TrustEngine>
```

## TrustEvent Enum

Core only records penalties. Rewards are the consumer's responsibility via
`ApplicationSuccess`. Successful responses are the expected baseline and
are not rewarded.

| Event | Severity | Description | Where it fires |
|-------|----------|-------------|----------------|
| `ConnectionFailed` | 1x penalty (core) | Could not establish connection | `send_request()` error, `send_dht_request()` RPC failure |
| `ConnectionTimeout` | 1x penalty (core) | Connection attempt timed out | `send_request()` timeout, `send_dht_request()` RPC timeout |
| `ApplicationSuccess(w)` | Weighted reward (consumer) | Peer completed an application-level task | Consumer code |
| `ApplicationFailure(w)` | Weighted penalty (consumer) | Peer failed an application-level task | Consumer code |

Note: Peer disconnects are normal connection lifecycle — they do not affect trust.

## Trust Thresholds

The routing table uses three trust thresholds:

- `swap_threshold` (`0.35` by default): peers below this score are eligible
  for replacement when a better candidate needs the slot.
- `quarantine_threshold` (`0.20` by default): peers below this score are
  skipped by lookup result selection and automatic lookup/dial paths. If such
  a peer is currently in the K-closest-to-self set, it is evicted and
  quarantined when the routing table can retain at least K peers.
- `quarantine_readmit_threshold` (`0.45` by default): a quarantined peer can
  only re-enter through normal discovery/admission after its decayed trust
  reaches this score. New peers must also meet this threshold before entering
  the routing table. Existing routing-table peers between `0.20` and `0.45`
  may remain in the table, including after moving into the close group.

```rust
use saorsa_core::AdaptiveDhtConfig;

let config = AdaptiveDhtConfig {
    swap_threshold: 0.35,
    quarantine_threshold: 0.20,
    quarantine_readmit_threshold: 0.45,
    ..Default::default()
};
```

Raw DHT routing uses Kademlia XOR distance. Local lookup results, FIND_NODE
responses, and automatic network lookups avoid quarantined peers so known-bad
contacts do not consume query slots or get handed out as lookup candidates.
This filtering is local policy only; the DHT wire protocol and legacy
`DHTNode` fields remain unchanged for backwards compatibility with older nodes.

## Architecture

```
P2PNode
    │
    ├── report_trust_event(peer, event) ──► AdaptiveDHT ──► TrustEngine
    │                                           │
    ├── peer_trust(peer) ◄────────────── TrustEngine.score()
    │
    └── DHT operations ──► DhtNetworkManager ──► TrustEngine
                           (records per-peer outcomes internally)
```

- **TrustEngine** is the sole authority on peer trust scores
- **AdaptiveDHT** owns TrustEngine and DhtNetworkManager
- **DhtNetworkManager** records trust penalties for DHT operations (failed lookups, dial failures)
- **P2PNode** exposes `report_trust_event()` for consumer rewards and additional penalties
