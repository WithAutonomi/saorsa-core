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

//! DHT Performance Benchmarks
//!
//! Comprehensive benchmarks for measuring Saorsa Core DHT performance.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use saorsa_core::PeerId;
use saorsa_core::dht::Key;
use std::net::SocketAddr;

/// Benchmark DHT key operations
fn dht_key_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("dht_key_operations");

    // Benchmark key creation from different data sizes
    for size in [32, 64, 128, 256, 512].iter() {
        let data = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::new("key_creation", size), &data, |b, data| {
            b.iter(|| {
                // Create key from data hash
                let mut key = [0u8; 32];
                if data.len() >= 32 {
                    key.copy_from_slice(&data[..32]);
                } else {
                    let hash = blake3::hash(data);
                    key.copy_from_slice(hash.as_bytes());
                }
                let key: Key = key;
                black_box(key);
            });
        });
    }

    // Benchmark key comparison operations
    let key1: Key = [1u8; 32];
    let key2: Key = [2u8; 32];

    group.bench_function("key_comparison", |b| {
        b.iter(|| black_box(&key1) == black_box(&key2));
    });

    // Benchmark key hashing
    let key: Key = [42u8; 32];
    group.bench_function("key_hashing", |b| {
        b.iter(|| {
            let hash = blake3::hash(&key);
            black_box(hash);
        });
    });

    group.finish();
}

/// Benchmark network address operations
fn network_address_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_address");

    // Benchmark address parsing and validation
    let addresses = vec![
        "127.0.0.1:8080",
        "192.168.1.1:9000",
        "::1:8080",
        "10.0.0.1:3030",
    ];

    for addr_str in addresses {
        group.bench_with_input(
            BenchmarkId::new("address_parsing", addr_str),
            addr_str,
            |b, addr_str| {
                b.iter(|| {
                    let socket_addr: SocketAddr = black_box(addr_str).parse().unwrap();
                    let addr = saorsa_core::MultiAddr::new(socket_addr);
                    black_box(addr);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark peer ID operations
fn peer_id_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("peer_id");

    // Benchmark peer ID generation
    group.bench_function("peer_id_generation", |b| {
        b.iter(|| {
            let peer_id = create_test_peer_id([rand::random::<u8>(); 32]);
            black_box(peer_id);
        });
    });

    // Benchmark peer ID distance calculation
    group.bench_function("peer_id_distance", |b| {
        let id1 = create_test_peer_id([1u8; 32]);
        let id2 = create_test_peer_id([2u8; 32]);

        b.iter(|| {
            let distance = xor_distance(&id1, &id2);
            black_box(distance);
        });
    });

    group.finish();
}

/// Create a test PeerId from bytes
fn create_test_peer_id(bytes: [u8; 32]) -> PeerId {
    PeerId::from_bytes(bytes)
}

/// Calculate XOR distance between two peer IDs
fn xor_distance(a: &PeerId, b: &PeerId) -> [u8; 32] {
    let mut result = [0u8; 32];
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = a_bytes[i] ^ b_bytes[i];
    }
    result
}

criterion_group!(
    benches,
    dht_key_benchmarks,
    network_address_benchmarks,
    peer_id_benchmarks
);
criterion_main!(benches);
