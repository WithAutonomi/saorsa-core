# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🤖 MANDATORY SUBAGENT USAGE

**ALWAYS USE SUBAGENTS. THIS IS NOT OPTIONAL.**

Subagents (via the `Task` tool) MUST be used whenever possible. They provide:
- **Fresh context** - Each subagent starts clean, preventing context pollution
- **Parallel execution** - Multiple agents can work simultaneously
- **Specialization** - Purpose-built agents for specific tasks
- **Unbounded execution** - No context limits when chaining agents

### When to Spawn Subagents

| Task Type | Action |
|-----------|--------|
| Code exploration/search | Spawn `Explore` agent |
| Code review | Spawn review agents in parallel |
| Bug fixes | Spawn `code-fixer` agent |
| Test execution | Spawn `test-runner` agent |
| Build validation | Spawn `build-validator` agent |
| Security scanning | Spawn `security-scanner` agent |
| Documentation audit | Spawn `documentation-auditor` agent |
| Multi-step tasks | Spawn `dev-agent` or `general-purpose` agent |
| Complex research | Spawn `Explore` or `general-purpose` agent |

### Subagent Rules

1. **PREFER subagents over doing work directly** - Even for "simple" tasks
2. **PARALLELIZE when possible** - Spawn multiple agents in a single message
3. **Use background agents** for long-running tasks (`run_in_background: true`)
4. **Chain agents** for complex workflows - Output of one feeds the next
5. **Never accumulate context** - Delegate to fresh agents instead

**IF YOU CAN USE A SUBAGENT, YOU MUST USE A SUBAGENT.**

## Build and Development Commands

### Core Commands
```bash
# Build
cargo build                         # Debug build
cargo build --release               # Release build
cargo build --all-features          # Build with all features

# Tests - MUST ALL PASS before committing
cargo test                          # Run all tests
cargo test --lib                    # Unit tests only
cargo test --test '<test_name>'     # Specific integration test
cargo test test_function_name       # Run specific test by name
cargo test -- --nocapture           # Show println! output
RUST_LOG=debug cargo test           # With debug logging

# Code Quality - MUST PASS before committing
cargo fmt                           # Format code
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used  # Strict linting
cargo audit                         # Security vulnerability check

# Benchmarks
cargo bench                         # Run all benchmarks
cargo bench --bench dht_benchmark  # Run specific benchmark

# Documentation
cargo doc --open                    # Build and open documentation

# Local CI Pipeline (safe, read-only checks)
./scripts/local_ci.sh               # Run full CI pipeline locally
./scripts/check_no_panic_unwrap.sh  # Check for forbidden patterns
```

### Trust System Tests
```bash
# Trust engine unit tests (in src/adaptive/)
cargo test --lib trust
cargo test --lib adaptive::dht
```

## Critical Code Standards

### NO PANICS IN PRODUCTION CODE - ZERO TOLERANCE
Production code **MUST NOT** contain:
- `.unwrap()` - Use `?` operator or `.ok_or()`
- `.expect()` - Use `.context()` from `anyhow` instead  
- `panic!()` - Return `Result` instead
- `unimplemented!()` or `todo!()` - Complete all implementations
- `println!()` - Use `tracing` for logging

**Exception**: Test code (`#[cfg(test)]`) may use `.unwrap()` and `.expect()` for assertions.

### Error Handling Pattern
```rust
// ✅ CORRECT
let value = some_option.ok_or(P2PError::MissingValue)?;
let result = some_result.context("operation failed")?;

// ❌ WRONG - Will fail CI/CD
let value = some_option.unwrap();
let result = some_result.expect("failed");
```

## Architecture Overview

### DHT Phonebook + Trust Signals

The current direction is to use **saorsa-core** for peer discovery and trust, and keep
all application data and business logic in **saorsa-node**. In practice:

- **DHT is a peer phonebook only** (peer records, routing, discovery).
- **Chunk storage/retrieval is done via `send_message`** in saorsa-node.
- **Trust updates remain in saorsa-core**: saorsa-node reports data availability
  outcomes so the TrustEngine can downscore nodes that fail to serve expected data.
  All trust signals flow through `AdaptiveDHT`.

Example trust signal hook:
```rust
use saorsa_core::TrustEvent;

// Core only records penalties — rewards are the consumer's responsibility
node.report_trust_event(&peer_id, TrustEvent::ApplicationSuccess(1.0)).await;
node.report_trust_event(&peer_id, TrustEvent::ApplicationFailure(1.0)).await;
```

### Multi-Layer P2P Architecture

The system combines a DHT peer phonebook with machine learning for optimal routing:

#### 1. Transport Layer (`src/transport/`)
- **Primary**: `saorsa-transport` (0.8+) for QUIC transport with NAT traversal
- **Security**: Post-quantum cryptography (ML-DSA-65, ML-KEM-768)

#### 2. Adaptive Network Layer (`src/adaptive/`)
Trust boundary and adaptive routing:
- **AdaptiveDHT**: Sole owner of TrustEngine and DhtNetworkManager — all trust signals flow through here
- **TrustEngine**: Response-rate scoring with time decay for decentralized reputation
- **TrustEvent**: Unified enum for all trust-relevant outcomes (reported via `P2PNode::report_trust_event`)
- **Lazy swap-out**: Peers below swap threshold are replaced when better candidates arrive (no immediate blocking)

#### 3. DHT Layer (`src/dht/`)
Peer phonebook with geographic awareness (no data storage):
- **Core Engine**: Kademlia-based routing table and peer discovery
- **Geographic Routing**: Region-aware peer selection
- **Trust-Based Swap-Out**: Peers below swap threshold are replaced by better candidates during admission

## External Crate Dependencies

### Saorsa Ecosystem
- `saorsa-pqc` (0.5): Post-quantum cryptography
- `saorsa-transport` (0.25+): QUIC transport with NAT traversal and PQC

### Feature Flags

No feature flags — all functionality is always enabled.

## Testing Infrastructure

### Test Organization
- **Unit Tests**: In-module `#[cfg(test)]` blocks

### Key Tests
```bash
# All unit tests (includes DHT, trust, transport, security)
cargo test --lib
```

## Important Implementation Details

### DHT Configuration
- **Bucket Size**: 20 nodes per k-bucket
- **Concurrency**: Alpha=3 parallel lookups
- **Geographic Awareness**: Region-aware peer selection
- **Trust Integration**: Response-rate scoring with lazy swap-out (no blocking)

### Performance Optimizations
- **Connection Pooling**: Max 100 connections with LRU eviction
- **Message Batching**: 10ms window, 64KB max batch
- **Caching**: LRU caches throughout with configurable TTL
- **Hashing**: BLAKE3 for speed, SHA2 for compatibility

## Licensing

Dual-licensed:
- **MIT OR Apache-2.0**: dual-licensed, at the user's option

All files must include the copyright header with dual-licensing notice.

## Pull requests: fill the template

When you open a pull request, you MUST use `.github/PULL_REQUEST_TEMPLATE.md` as
the PR body and fill it in completely — do not open a PR with an empty or ad-hoc
description.

- **Fill every field.** Leave nothing blank; if a value isn't determinable, ask
  before opening the PR.
- **Link the Linear issue with a closing magic word** — write `Closes V2-123` in
  the `## Linear issue` section, one line per issue. Any of Linear's closing
  words works, in any tense (`close` / `fix` / `resolve` / `complete` /
  `implement`, plus their `-s`, `-d` and `-ing` forms), and the key may be a
  `linear.app` issue URL. A bare `V2-123` does **not** link the PR at all, and
  the linking-only words (`ref`, `part of`, `towards`, `relates to`) attach it
  without driving the Merged transition — CI rejects both. An issue key in the
  branch name or PR title also links, but write the closing form anyway; it is
  what moves the issue to Merged when the PR lands on `main`.
- **Check exactly one Risk tier box and exactly one Semver impact box.** Propose
  them from the change; a human confirms them at review.
- An **ADR link is required for Tier 2/3**.

CI enforces the Linear link and the template fields (`linear-link` and
`pr-template` status checks); a PR that omits them fails its checks.
