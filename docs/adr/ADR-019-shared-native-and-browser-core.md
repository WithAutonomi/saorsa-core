# ADR-019: Shared core APIs for native and browser clients

## Status

Proposed (2026-09-08)

## Context

Extracting the lookup driver (ADR-016) made browser discovery possible, but did
not make saorsa-core itself portable. Browser clients consequently depended on
separate identity, protocol, payment, and transfer adapters. Native socket,
certificate, filesystem, and runtime dependencies prevented importing the normal
crate graph on wasm32-unknown-unknown.

## Decision

Keep native defaults and introduce an explicit `native` feature boundary.
Identity generation/import/export/signing, addresses, peer records, witnessed
lookup transcripts, and iterative lookup APIs remain in saorsa-core on both
targets. The existing lookup crate remains an implementation dependency and is
re-exported by core; browser clients no longer need to import it separately.
Move peer-record definitions out of the native DHT manager and re-export their
old native paths. Use saorsa-pqc keys directly, converting only at the native
transport's keypair boundary.

Keep OS networking, certificate integration, disk persistence, background tasks,
and the native P2P node behind `native`. Trust remains owned by saorsa-core;
this change does not move trust or user-data storage into the browser adapter.
The DHT remains a peer phonebook; application storage stays in ant-node.

The consuming ant-protocol crate imports portable core, crypto, and EVM APIs on
both targets. Its native transport event helper is feature-gated. Ant-core uses
one Client with a browser I/O adapter; native protocol messages cross WebRTC
rather than requiring a second browser payment or transfer implementation.

## Consequences

Default native APIs remain available. Callers that disabled default features
while still expecting a native P2P node must now explicitly enable `native`.
Serialized peer and payment types stay unchanged. Browser timestamps and timers
use browser facilities; serialized SystemTime fields retain native encoding.

Cross-repository branches pin exact dependency revisions until these features
are released. WASM CI checks compile core itself, rather than only the lookup
subcrate. Native tests and generated-WASM tests verify the shared paths.
