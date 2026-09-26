# saorsa-core

Rust library: post-quantum P2P foundation — QUIC transport (via
`saorsa-transport`), a Kademlia DHT used as a peer phonebook, and trust scoring.
Its main consumer is `saorsa-node`. Canonical home is the `WithAutonomi` GitHub
org (ADR-015); `saorsa-labs/saorsa-core` redirects there. Part of the Autonomi v2
release train.

## Reference docs
- Architecture overview: `ARCHITECTURE.md`; API: `docs/API.md`
- Trust signals for consumers: `docs/trust-signals-api.md`
- Routing table: `docs/ROUTING_TABLE_DESIGN.md`; security: `docs/SECURITY_MODEL.md`
- Infrastructure / bootstrap nodes: `docs/infrastructure/INFRASTRUCTURE.md`
- ADRs: `docs/adr/` (index and template in `docs/adr/README.md`)

## Build and test
No justfile. CI runs (see `.github/workflows/`):
- `cargo fmt --all -- --check`
- `cargo clippy --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used`
  (no `--all-targets`, so tests may unwrap; `.clippy.toml` also allows it in tests)
- `cargo nextest run --lib` and `cargo nextest run --test '*'`; `cargo test --doc`
- **Portable core must stay wasm-clean:**
  `cargo check --lib --no-default-features --target wasm32-unknown-unknown`.
  The only feature is `native` (default), which gates tokio, persistence and
  real networking; identity, addresses, crypto and lookup logic are portable
  (ADR-019). New native-only deps must be optional and gated behind `native`.
- `cargo audit` runs in CI.

## Architecture
- **DHT is a peer phonebook only** — peer records, routing, discovery. No
  application data is stored in the DHT; chunk storage/retrieval lives in
  `saorsa-node` over `send_message`.
- **Trust stays in core.** `AdaptiveDHT` (`src/adaptive/dht.rs`) solely owns the
  `TrustEngine` and `DhtNetworkManager`; every trust signal flows through it.
  Consumers report outcomes with
  `P2PNode::report_trust_event(&peer_id, TrustEvent::ApplicationSuccess(w) | ApplicationFailure(w))`
  (weight clamped to `MAX_CONSUMER_WEIGHT`). Core itself only records penalties
  (`ConnectionFailed`, `ConnectionTimeout`); rewards are the consumer's job.
- Scoring is response-rate with time decay; peers below the swap threshold are
  lazily swapped out when better candidates arrive, not blocked immediately.
- K = 20 (`dht_lookup::DEFAULT_K_VALUE`, minimum 4). BLAKE3 for speed, SHA-2 for
  compatibility.
- Layout: `transport/` (saorsa-transport adapter), `network.rs` (`P2PNode`),
  `dht/`, `dht_network_manager.rs`, `dht_lookup.rs`, `adaptive/` (trust),
  `identity/`, `quantum_crypto/` (re-exports `saorsa-pqc`), `bootstrap/`,
  `reachability/`, `error.rs` (`P2PError`).

## Conventions
- Logging via `tracing`, not `println!`.
- Source files carry the Saorsa Labs dual MIT / Apache-2.0 copyright header.
- Use `saorsa-pqc` types for crypto; zeroize secret material.

## Pull requests
CI (`linear-link` and `pr-template` checks, `.github/scripts/check_pr.py`)
rejects PRs that don't follow `.github/PULL_REQUEST_TEMPLATE.md`:
- Fill every section; ask if a value can't be determined.
- Link Linear with a **closing** word in the description: `Closes V2-123` (or
  fix/resolve/complete/implement, any tense; a `linear.app` URL works as the
  key). A bare key in the description does not link; linking-only words (`ref`,
  `part of`, `towards`, `relates to`) attach without moving the issue to Merged.
- Tick exactly one Risk tier and one Semver impact box (a human confirms them).
  Tier 2/3 needs an ADR link.
