# ADR-016: Transport-independent iterative DHT lookups

## Status

Accepted (2026-08-05)

## Context

Saorsa's Kademlia walk was implemented inside `DhtNetworkManager`, alongside
native QUIC dialing, failure-cache checks, response authentication, address
merging, and trust updates. This worked for native nodes and clients because
`DhtNetworkManager` owns a `saorsa-transport` connection.

Browser clients use WebTransport and cannot instantiate the native Tokio/QUIC
network stack. Reimplementing the iterative walk in JavaScript duplicated XOR
ordering, α-batch selection, final peer states, queue limits, and convergence.
That duplication could silently make native and browser clients select
different close groups.

## Decision

Extract the complete iterative lookup walk into the portable
`saorsa-dht-lookup` crate. Its `IterativeLookup` state machine and
`run_iterative_lookup` driver own:

- unsigned 256-bit XOR ordering with deterministic peer-ID tie breaking;
- bounded closest-first candidate retention;
- `Waiting`, `Succeeded`, `Failed`, and `Unresponsive` peer states;
- α-constrained round selection;
- successful-responder result selection; and
- whole-top-K convergence, exhaustion, and iteration-limit termination.

The engine performs no I/O and depends on neither Tokio nor a transport. It
drives a generic `LookupQuery` interface with each α-sized batch. The query
adapter performs those requests concurrently, validates their responses, and
returns successful, failed, or unresponsive outcomes. The shared runner owns
all round transitions and treats missing batch outcomes as unresponsive.

`DhtNetworkManager` is the native driver. It retains responsibility for QUIC
dialing, the shared failure cache, bounded straggler waits, authenticated
FIND_NODE response processing, address-report consensus, routing-table merges,
and trust signals.

The browser WASM client is the WebTransport query adapter. Rust/WASM invokes
the exact same `run_iterative_lookup` function as native Saorsa; JavaScript only
establishes browser sessions and executes the α-sized FIND_NODE batch requested
by Rust.

Transport-specific eligibility remains in each adapter. In particular, native
lookups may temporarily discard an exhausted address view without assigning a
terminal peer state, while browser lookups discard candidates that have no
WebTransport endpoint. A later response can reintroduce either peer with a
dialable endpoint.

## Consequences

### Positive

- Native and browser clients share one complete lookup loop, including
  scheduling and convergence.
- The portable crate builds for `wasm32-unknown-unknown` without Tokio,
  `mio`, sockets, or browser bindings.
- Transport security remains in the appropriate adapter instead of being
  weakened to fit a lowest-common-denominator interface.
- Engine and generic-driver tests can exercise adversarial candidate ordering
  without a live network.

### Negative

- A coordinated release of `saorsa-dht-lookup`, `saorsa-core`, and browser
  consumers is required.
- Query timing policies remain transport-specific: native QUIC uses a bounded
  straggler grace period, while browser cancellation follows WebTransport API
  capabilities.

### Neutral

- FIND_NODE wire formats do not change.
- Native response authentication, report consensus, trust, and routing-table
  behavior remain in `saorsa-core`.

## Alternatives considered

1. **Keep the JavaScript lookup.** Rejected because it permanently duplicates
   security-sensitive close-group selection behavior.
2. **Compile all of `saorsa-core` to WASM.** Rejected because its native
   transport, Tokio, filesystem, and background-task dependencies are not
   meaningful in a browser.
3. **Put WebTransport inside `saorsa-transport`.** Deferred: browsers expose
   WebTransport through JavaScript APIs, but making transport establishment
   portable would still not justify coupling the pure lookup algorithm to it.
