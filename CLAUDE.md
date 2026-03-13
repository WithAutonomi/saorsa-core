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

### Adaptive Network Testing Suite
```bash
./scripts/test_adaptive_network.sh  # Run adaptive component tests

# Individual adaptive component tests
cargo test --test adaptive_components_test test_thompson_sampling_basic --release
cargo test --test adaptive_components_test test_multi_armed_bandit_basic --release
cargo test --test adaptive_components_test test_q_learning_cache_basic --release
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
  outcomes so EigenTrust can downscore nodes that fail to serve expected data.

Example trust signal hook:
```rust
use saorsa_core::adaptive::{EigenTrustEngine, NodeStatisticsUpdate};

trust_engine
    .update_node_stats(&peer_id, NodeStatisticsUpdate::CorrectResponse)
    .await;
```

### Multi-Layer P2P Architecture

The system combines a DHT peer phonebook with machine learning for optimal routing:

#### 1. Transport Layer (`src/transport/`)
- **Primary**: `saorsa-transport` (0.8+) for QUIC transport with NAT traversal
- **Security**: Post-quantum cryptography (ML-DSA-65, ML-KEM-768)

#### 2. Adaptive Network Layer (`src/adaptive/`)
Central to the system's intelligence, using ML for dynamic strategy selection:
- **Multi-Armed Bandit**: Thompson Sampling for strategy selection
- **Routing Strategies**: Kademlia DHT, Hyperbolic routing, Trust-based routing
- **ML Components**: Q-Learning cache optimization, Churn prediction

#### 3. DHT Layer (`src/dht/`)
Peer phonebook with geographic awareness (no data storage):
- **Core Engine**: Kademlia-based routing table and peer discovery
- **Geographic Routing**: Region-aware peer selection
- **Trust-Weighted Selection**: EigenTrust-integrated peer scoring
- **Security**: S/Kademlia extensions, Sybil detection, authenticated sibling broadcast

#### 4. Identity System (`src/identity/`)
- **Cryptography**: ML-DSA-65 for post-quantum signatures
- **No PoW**: Pure cryptographic identity without proof-of-work

## External Crate Dependencies

### Saorsa Ecosystem
- `saorsa-pqc` (0.5): Post-quantum cryptography
- `saorsa-transport` (0.25+): QUIC transport with NAT traversal and PQC

### Feature Flags
```toml
default = ["metrics"]
metrics = ["dep:prometheus"]  # Prometheus monitoring
```

## Testing Infrastructure

### Test Organization
- **Unit Tests**: In-module `#[cfg(test)]` blocks
- **Integration Tests**: `tests/` directory
- **Property Tests**: Using `proptest` for randomized testing

### Key Integration Tests
```bash
# DHT & peer discovery
cargo test --test dht_connectivity_diagnostic_test       # DHT connectivity diagnostics
cargo test --test dht_node_mode_gating_test              # Node mode gating
cargo test --test dht_peer_address_population_test       # Peer address population
cargo test --test config_test                            # Configuration tests

# Adaptive networking
cargo test --test adaptive_components_test               # Adaptive component tests
cargo test --test adaptive_integration_tests             # Adaptive integration
cargo test --test multi_armed_bandit_integration_test    # Multi-armed bandit
cargo test --test q_learning_cache_integration_test      # Q-Learning cache
cargo test --test hyperbolic_routing_test                # Hyperbolic routing

# Transport
cargo test --test saorsa_transport_integration_test      # QUIC transport

# Security & trust
cargo test --test eigentrust_integration_test            # Trust system
cargo test --test security_comprehensive_test            # Security validation
cargo test --test trust_weighted_dht_test                # Trust-weighted DHT
cargo test --test trust_weighted_selection_test           # Trust-weighted selection

```

## Common Development Workflows

### Adding New Adaptive Strategy
1. Implement in `src/adaptive/`
2. Add to `RoutingStrategy` enum
3. Update multi-armed bandit
4. Add performance metrics
5. Write tests in `tests/adaptive_components_test.rs`

## Important Implementation Details

### DHT Configuration
- **Bucket Size**: 20 nodes per k-bucket
- **Concurrency**: Alpha=3 parallel lookups
- **Geographic Awareness**: Region-aware peer selection
- **Trust Integration**: EigenTrust-weighted peer scoring

### Performance Optimizations
- **Connection Pooling**: Max 100 connections with LRU eviction
- **Message Batching**: 10ms window, 64KB max batch
- **Caching**: LRU caches throughout with configurable TTL
- **Hashing**: BLAKE3 for speed, SHA2 for compatibility

## Licensing

Dual-licensed:
- **AGPL-3.0**: For open source use
- **Commercial**: Contact david@saorsalabs.com

All files must include the copyright header with dual-licensing notice.

---

## 🚨 CRITICAL: Saorsa Network Infrastructure & Port Isolation

### Infrastructure Documentation
Full infrastructure documentation is available at: `docs/infrastructure/INFRASTRUCTURE.md`

This includes:
- All 9 VPS nodes across 3 cloud providers (DigitalOcean, Hetzner, Vultr)
- Bootstrap node endpoints and IP addresses
- Firewall configurations and SSH access
- Systemd service templates

### ⚠️ PORT ALLOCATION

saorsa-core is a library used by multiple applications. Each application uses a dedicated port range:

| Service | UDP Port Range | Default | Description |
|---------|----------------|---------|-------------|
| saorsa-transport | 9000-9999 | 9000 | QUIC transport layer |
| **saorsa-node** | **10000-10999** | **10000** | Core P2P network nodes (primary user of saorsa-core) |
| communitas | 11000-11999 | 11000 | Collaboration platform nodes |

### 🛑 DO NOT DISTURB OTHER NETWORKS

When testing saorsa-core functionality:

1. **Use ports 10000-10999** for saorsa-node services
2. **NEVER** kill processes on ports 9000-9999 or 11000-11999
3. **NEVER** restart services outside our port range
4. Each network may be running independent tests - respect port boundaries

```bash
# ✅ CORRECT - saorsa-node operations (within 10000-10999)
cargo run --bin saorsa-node -- --listen 0.0.0.0:10000
cargo run --bin saorsa-node -- --listen 0.0.0.0:10001  # Second instance OK
ssh root@saorsa-2.saorsalabs.com "systemctl restart saorsa-node-bootstrap"

# ❌ WRONG - Would disrupt other networks
ssh root@saorsa-2.saorsalabs.com "pkill -f ':9'"    # NEVER - matches saorsa-transport ports
ssh root@saorsa-2.saorsalabs.com "pkill -f ':11'"   # NEVER - matches communitas ports
```

### Bootstrap Endpoints
```
saorsa-2.saorsalabs.com:10000  (NYC - 142.93.199.50)
saorsa-3.saorsalabs.com:10000  (SFO - 147.182.234.192)
```

### Before Any VPS Operations
1. Verify you're targeting the correct port for your application
2. Double-check service names match your application
3. Never run broad `pkill` commands that could affect other services
