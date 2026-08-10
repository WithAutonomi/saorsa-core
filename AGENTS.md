# Agent Guidelines for Saorsa Core

## DHT Phonebook + Trust Signals (Current Direction)

### Core Responsibilities
- **DHT is a peer phonebook only** (peer records, routing, discovery).
- **User data storage lives in saorsa-node** via `send_message`-style APIs.
- **Trust remains in saorsa-core**: saorsa-node reports data availability outcomes
  so EigenTrust can downscore nodes that fail to serve expected data.

### Trust Signal Hook (saorsa-node → saorsa-core)
```rust
use saorsa_core::adaptive::{EigenTrustEngine, NodeStatisticsUpdate};

// After a data fetch attempt in saorsa-node:
trust_engine
    .update_node_stats(&peer_id, NodeStatisticsUpdate::CorrectResponse)
    .await;
// or on failure:
trust_engine
    .update_node_stats(&peer_id, NodeStatisticsUpdate::FailedResponse)
    .await;
```

## Build/Test Commands
- **Build**: `cargo build --all-features` (release: `cargo build --release`)
- **Test All**: `cargo test --all-features` (doc tests: `cargo test --doc`)
- **Single Test**: `cargo test test_function_name` or `cargo test --test integration_test_name`
- **Lint**: `cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used`
- **Format**: `cargo fmt --all -- --check` (apply: `cargo fmt --all`)
- **Local CI**: `./scripts/local_ci.sh` (runs fmt, clippy, build, tests safely)

## Code Style Guidelines

### Error Handling (ZERO PANICS in production)
- **NEVER use**: `.unwrap()`, `.expect()`, `panic!()` in library/production code
- **Use instead**: `?` operator, `.ok_or()`, `.context()` from `anyhow`
- **Tests OK**: `.unwrap()`/`.expect()` allowed in `#[cfg(test)]` blocks
- **Error types**: `P2PError` enum with structured variants, `thiserror` for derives

### Imports & Dependencies
- **Core async**: `tokio`, `futures`, `async-trait`
- **Serialization**: `serde` with derive features
- **Error handling**: `anyhow`, `thiserror`
- **Logging**: `tracing` (never `println!` in production)
- **Crypto**: `saorsa-pqc` (primary), `saorsa-transport` (QUIC transport)

### Naming Conventions
- **Modules**: `snake_case` (e.g., `dht`, `transport`, `adaptive`)
- **Types/Traits**: `PascalCase` (e.g., `P2PNode`, `AdaptiveNetworkNode`)
- **Functions**: `snake_case` (e.g., `connect_to_peer`, `publish_peer_record`)
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Fields**: `snake_case` (e.g., `content_hash`, `node_id`)

### Formatting & Structure
- **Rust 2024 edition** with `rustfmt` (4 spaces, standard rules)
- **Clippy config**: `.clippy.toml` allows unwrap/expect in tests
- **Documentation**: All public items must be documented
- **Copyright**: Include the dual MIT/Apache-2.0 header on all files

### Architecture Patterns
- **Async traits**: Use `#[async_trait]` for async trait methods
- **Result types**: `Result<T, P2PError>` or `Result<T>` with custom error types
- **Zero-copy**: Use `Cow<'static, str>` for error messages
- **Structured logging**: JSON-based error reporting with `tracing`

### Security & Performance
- **Post-quantum crypto**: Use `saorsa-pqc` types exclusively
- **Memory safety**: Zeroize sensitive data, secure memory pools
- **No secrets in code**: Never commit keys or credentials
- **Performance**: O(n log n) or better, minimize allocations

## Cursor Rules Integration
- **No unwrap/expect/panic** in production (CI enforces)
- **Proper error context** with `.context()` or `?` operator
- **Tracing logging** instead of `println!`
- **Zero-panic guarantee** for library code

## Pull requests: fill the template

When you open a pull request, you MUST use `.github/PULL_REQUEST_TEMPLATE.md` as
the PR body and fill it in completely — do not open a PR with an empty or ad-hoc
description.

- **Fill every field.** Leave nothing blank; if a value isn't determinable, ask
  before opening the PR.
- **Link the Linear issue** — an issue key like `V2-123` or a `linear.app` URL.
  CI blocks PRs with no linked Linear issue.
- **Check exactly one Risk tier box and exactly one Semver impact box.** Propose
  them from the change; a human confirms them at review.
- An **ADR link is required for Tier 2/3**.

CI enforces the Linear link and the template fields (`linear-link` and
`pr-template` status checks); a PR that omits them fails its checks.
