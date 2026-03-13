// Copyright 2024 Saorsa Labs Limited
//
#![allow(clippy::unwrap_used, clippy::expect_used)]
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

//! Integration Performance Benchmarks
//!
//! Measures performance of integration test scenarios for regression detection.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use saorsa_core::PeerId;
use saorsa_core::adaptive::{TrustProvider, trust::MockTrustProvider};
use saorsa_core::identity::NodeIdentity;
use std::sync::Arc;
use tokio::runtime::Runtime;

/// Benchmark crypto performance with identity operations
fn benchmark_crypto_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("crypto_performance");

    for message_size in [1024, 10240].iter() {
        group.bench_with_input(
            BenchmarkId::new("encrypt_decrypt", message_size),
            message_size,
            |b, &message_size| {
                b.iter_custom(|iters| {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let _ = rt.block_on(async {
                            benchmark_encryption_operations(message_size).await
                        });
                    }
                    start.elapsed()
                });
            },
        );
    }

    group.finish();
}

/// Benchmark adaptive network operations
fn benchmark_adaptive_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_operations");

    // Benchmark trust operations
    group.bench_function("trust_operations", |b| {
        let trust_provider = Arc::new(MockTrustProvider::new());
        let node_id = PeerId::from_bytes([42u8; 32]);

        b.iter(|| {
            let score = trust_provider.get_trust(&node_id);
            trust_provider.update_trust(&node_id, &node_id, true);
            black_box(score);
        });
    });

    group.finish();
}

async fn benchmark_encryption_operations(
    message_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Simplified encryption benchmark using available crypto functionality
    let identity = NodeIdentity::generate()?;

    let message = vec![0xCD; message_size];

    // Benchmark signature generation and verification
    let signature = identity.sign(&message)?;
    let is_valid = identity.verify(&message, &signature)?;

    if !is_valid {
        return Err("Signature verification failed".into());
    }

    // Benchmark hash operations (variable is intentionally unused for benchmark)
    let _hash = blake3::hash(&message);

    Ok(())
}

criterion_group!(
    benches,
    benchmark_crypto_performance,
    benchmark_adaptive_operations
);
criterion_main!(benches);
