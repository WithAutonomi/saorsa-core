# ADR-014: Proactive Relay-First NAT Traversal

## Status

Proposed

## Context

Today's connection establishment runs a timeout-driven cascade on every dial:

1. Direct (Happy Eyeballs IPv4 + IPv6, ~3 s)
2. Hole-punch round 1 (~8 s)
3. Hole-punch round 2 (~8 s)
4. Relay via MASQUE (~10 s)

The cascade lives in `saorsa-transport::p2p_endpoint::connect_with_fallback_inner`; saorsa-core wraps it with a 25 s `DIAL_TIMEOUT` in `src/transport/saorsa_transport_adapter.rs:494`.

Problems with this approach:

- **Worst-case exceeds the budget.** `3 + 8 + 8 + 10 ≈ 29 s` against a 25 s outer timeout — under the exact conditions where relay matters most (both peers behind symmetric NAT), the fallback gets squeezed.
- **Reachability is re-derived per dial.** A private node has no memoized answer to "am I reachable from the public internet?" — every outbound dial runs the full cascade regardless of prior outcomes.
- **Symmetric-to-symmetric dials are wasted work.** When both peers are behind symmetric NAT, the ~16 s hole-punch phase cannot succeed. The existing `is_symmetric_nat()` detection in `saorsa-transport/src/nat_traversal_api.rs:~3998` triggers a proactive relay for *inbound* reachability but does not short-circuit outbound dials.
- **No dial-back probe.** Self-reachability is inferred only from QUIC `OBSERVED_ADDRESS` frames received from peers we've already talked to. A cold-start node cannot publish a verified `Direct` address until after its first successful inbound connection — a chicken-and-egg shape that PR #70 partially worked around with a local-IP probe fallback (`dht_network_manager.rs:1321`).
- **UPnP is additive only.** The `UpnpMappingService` in `saorsa-transport/src/upnp.rs` passively augments candidate addresses when it works and silently does nothing when it doesn't. There is no active NAT classification step.

The net effect: connection setup for two private peers takes ~16–29 s in the worst case, where the correct answer ("they both need a relay") could be known in advance.

Existing building blocks that can be reused:

- `AddressType { Relay, Direct, NATted }` enum at `src/dht/core_engine.rs:120` (added in commit `3b7131d`, H4) — already used to prioritize relay over direct in DHT address updates.
- `dialable_addresses()` filter at `src/dht/dht_network_manager.rs:1321` (PR #70) — rejects `0.0.0.0`/`::`/port 0 before any dial attempt.
- `establish_relay_session()` in `saorsa-transport/src/nat_traversal_api.rs:3343` — opens a MASQUE `CONNECT-UDP` session to a relay and returns the relay's allocated public socket address.
- `setup_proactive_relay()` in `saorsa-transport/src/nat_traversal_api.rs:~4027` — end-to-end flow that establishes a relay session, rebinds the local Quinn endpoint onto the MASQUE tunnel (`endpoint.rebind_abstract(relay_socket)` at line 4055), and advertises the relay's allocated address to peers. Currently fired reactively 5 s after symmetric-NAT detection; this ADR repurposes it to fire from the dial-back classifier instead.
- `RelaySession` struct (`nat_traversal_api.rs:210`) with public `connection: InnerConnection` field, plus `relay_sessions()` accessor at `:3504` — together these expose the Quinn `closed()` future for the session's underlying QUIC connection, providing the session-closed subscription mechanism the relayer monitor needs without any new API surface.
- `MasqueRelayServer::handle_connect_request()` at `masque/relay_server.rs:368` — the existing CONNECT-UDP Bind accept path. Already enforces a cap via `client_to_session: HashMap<SocketAddr, u64>` at `:191`, currently hard-capped at 1 session per client SocketAddr. This ADR relaxes that cap to 2.
- Relay-address publish task in `src/network.rs:~1170` — already walks the K closest peers and broadcasts the relay-allocated address when a session is established.
- `MultiAddr` in `src/address.rs:52` — wraps `TransportAddr` with an optional `PeerId` suffix. **No schema change is required** by this ADR (see Decision).

The key insight that unlocks the simple design: the existing MASQUE flow is TURN-style — the private peer's Quinn endpoint is rebound onto the MASQUE tunnel, so from any dialer's perspective the relay is invisible below the QUIC layer. Dialers connect to a normal `/ip4/.../quic/p2p/<target>` address where the socket happens to be a relay's allocated port; the QUIC handshake runs end-to-end with the target's ML-DSA identity through the transparent tunnel. This means the DHT record format, the dialer code path, and the handshake security model all remain unchanged — the only new work is deciding *when* to set up a relay, *which* relay to pick, and enforcing a reservation cap.

## Decision

Move reachability classification from per-dial to per-session. After bootstrap, every node runs a dial-back probe to discover which of its candidate addresses are publicly reachable. Nodes with at least one verified `Direct` address publish it and behave as today. Nodes without any verified `Direct` address acquire a MASQUE relay session from a close-group public peer and publish the relay-allocated socket address as their primary contact.

### Startup sequence

1. Bring up listener; connect to bootstrap peers.
2. Populate the routing table via iterative self-lookup.
3. Immediately after bootstrap completes, run the dial-back probe:
   - Select up to 3 close-group peers (as many as the RT has).
   - For **each candidate address independently**, ask each prober to dial it back.
   - Classification per address:
     - ≥ 2/3 successes → `Direct`
     - < 2/3 successes or 0 → not `Direct`
     - When fewer than 3 probers are available, accept 1/1 or 2/2. This cold-start cost is acceptable; once the network has enough close-group peers, 2/3 quorum kicks in naturally.
4. **If any address is `Direct`** → publish direct addresses in the self-record; done.
5. **If no address is `Direct`** (private node) → proceed to relay acquisition.

### Relay acquisition (private nodes)

1. Iterate XOR-closest peers in the local routing table that advertise at least one `Direct` address in their own record. A `Direct` address in another peer's record is the implicit reachability signal — no separate "public bit" is needed.
2. Call `establish_relay_session(candidate_addr)` (the existing saorsa-transport API) against the closest candidate.
3. On success → the MASQUE relay returns a publicly-routable allocated socket address. Rebind the local Quinn endpoint onto the tunnel (existing `setup_proactive_relay` flow), then publish the allocated address as the private peer's contact.
4. On rejection (relay at capacity) → walk outward to the next-closest candidate; repeat until one accepts.
5. Record the relayer's peer ID internally (in memory on the private peer) for the "relayer must stay in K closest" invariant and for per-relayer quality tracking.

### Reservation protocol

- **Cap**: max 2 concurrent relay clients per public peer.
- **Enforcement**: in the MASQUE relay server's `CONNECT-UDP Bind` accept path — count active relay sessions keyed by the QUIC connection's authenticated peer ID, reject with a distinct error when already at capacity. This is a small addition to saorsa-transport, not a new subsystem.
- **Lifetime**: bound to the underlying QUIC connection between the private peer and the relay. As long as the private peer holds the connection open, the allocation persists. No TTL, no explicit refresh.
- **On disconnect**: the relayer frees the slot immediately when the QUIC connection closes. Subsequent clients can occupy it.

### Published address

The private peer publishes the relay-allocated socket address as a normal `MultiAddr`:

```text
/ip4/<relay_public_ip>/udp/<allocated_port>/quic/p2p/<self_peer_id>
```

- **No `MultiAddr` schema change.** The existing struct and wire format are sufficient.
- **`AddressType::Relay` tag** marks this entry in the DHT record as "terminates at a relay." The tag is metadata for logging, metrics, and the node's own classifier — it does not alter dial behavior on the consuming side.
- **Dialer path is unchanged.** A dialer fetching this record sees a socket address, dials it like any other, and the QUIC handshake runs transparently through the MASQUE tunnel to the private peer's Quinn endpoint. The target's ML-DSA identity verification happens end-to-end; the relay sees encrypted traffic only and cannot MITM.

### `AddressType` semantics

With the classifier producing verified classifications:

- `AddressType::Direct` — address passed the dial-back probe and is reachable without a relay.
- `AddressType::Relay` — address is a relay-allocated socket; the traffic tunnels through a MASQUE session.
- `AddressType::NATted` — unverified or pre-probe state; should not appear in published records.

### Invariants (private node)

- Exactly **one** active relayer at a time (K=1).
- The relayer's peer ID must remain among the K closest peers (K = 20, the Kademlia bucket size). The private peer tracks this internally — the relayer's identity is **not** in the published DHT record, but it is known locally because the private peer chose it.
- On any of the following events, the private peer immediately finds a new relayer, establishes a new MASQUE session, and republishes the new relay-allocated address to its DHT entry:
  - QUIC connection to the relayer closes (saorsa-transport emits an event — see Implementation Scope).
  - Relayer drops out of the K closest peers (any cause).
  - Periodic re-probe reclassifies the node as `Direct`.
- A 10–30 s unreachability window during failover is accepted as the cost of K=1 plus DHT republish latency.

### Re-probe cadence

Three triggers, in order of responsiveness:

1. **Reactive**: on MASQUE session QUIC close → immediate re-probe + rebind. This is the common case and has near-zero latency.
2. **Event-driven**: on network interface change, via the `if-watch` crate (cross-platform — netlink on Linux, `SystemConfiguration` on macOS, `NotifyAddrChange` on Windows).
3. **Periodic**: every 5 minutes as a belt-and-braces check. Catches silent changes (DHCP lease renewal with a new external IP that the OS reports as unchanged). Matches iroh/Tailscale `netcheck` cadence; tighter than libp2p AutoNAT (~15 min) because of our "must be reachable at all times" constraint.

### Relayer selection and trust

Selection is trust-blind: any XOR-closest public peer with a `Direct` address in its own record is a candidate. The trust engine feeds into relay stability **indirectly**: trust-driven evictions from the routing table push a peer out of the K closest set, which triggers relayer rebinding through the same mechanism as any other eviction cause.

Trust attribution for relay-fronted connections happens on the private peer side only. When a dialer fails to connect to a relay-fronted address, the dialer cannot distinguish "relay is down" from "target is down" — it just sees a connection failure. This is acceptable because:

- The dialer uses the cascade as a deep fallback, so a single relay failure does not kill the dial.
- The private peer (target) monitors its own relayer's liveness via the MASQUE session state and rebinds eagerly if quality degrades. Per-relayer quality tracking is a local concern.
- Trust events from the dialer's perspective attribute to the **target's peer ID** (the one in the `/p2p/` suffix of the dialed address), which is semantically correct: from the dialer's vantage point, the target failed to be reachable. The target's relay choice is an implementation detail it owns.

## Consequences

### Positive

- **Dramatic latency reduction for private-to-private dials.** Common case drops from ~16–29 s (cascade) to ~1 RTT to the relayer (~100–300 ms typical), because the DHT record already carries a pre-warmed relay-allocated socket address.
- **Reachability is computed once, not per-dial.** Every dial becomes effectively single-shot.
- **Relay selection is DHT-topologically aligned.** Relayers are drawn from the close-group, which is already the hot set of peers the private peer queries frequently — the relay hop is usually "free" in terms of additional connections maintained.
- **Load on public peers is bounded.** The 2-client-per-public-peer cap ensures popular public peers don't become involuntary infrastructure.
- **Full reuse of the MASQUE TURN-style scaffolding.** `establish_relay_session()`, `setup_proactive_relay()`, `endpoint.rebind_abstract()`, `RelaySession.connection.closed()` (the session-closed future is already publicly accessible via `relay_sessions()`), the K-closest publish task in `network.rs:~1170`, the `AddressType` enum, the `dialable_addresses()` filter, and the `MultiAddr` schema all work unchanged. The **only** saorsa-transport delta is relaxing the existing MASQUE relay server's per-client cap from 1 to 2 — a 10-line change in one file.
- **No `MultiAddr` schema change.** Zero migration pressure on existing serialized records.
- **No dialer-side changes.** Dialers dial relay-allocated addresses the same way they dial direct addresses — the MASQUE tunnel is transparent below QUIC.
- **Nested handshake is not needed.** The target's ML-DSA handshake runs end-to-end over the transparent tunnel; there is no second handshake layer to add.
- **Eliminates the current 25 s vs 29 s budget mismatch** by removing the cascade from the common path. The cascade can remain as a deep fallback for edge cases.

### Negative

- **Failover window.** On relayer drop, there is a 10–30 s window during which the private peer is unreachable from new dialers fetching the stale DHT record. Accepted per decision.
- **LAN optimization lost for private-to-private.** Two peers behind the same NAT will now always go through a public relay rather than connecting directly. This is a conscious simplification trade (keeps the DHT record model simple: one address per peer) and is expected to be rare in practice for the target deployment profile.
- **RT-eviction-driven rebinding can introduce churn** if the K-closest set is volatile (e.g., during rapid network growth). Mitigated by Kademlia's RT stability characteristics; worth measuring in a real network before committing to the strict "must stay in K closest" rule.
- **Cold-start warm-up period.** A brand-new node cannot publish `Direct` addresses until the dial-back probe completes. During this window the node is either unreachable (no relay yet, no verified direct) or reachable only via its initial relay pick. Bounded by bootstrap + probe latency (~few seconds in practice).
- **Trust in bootstraps during cold start.** On a tiny network with only 1 prober available, the classification depends on a single peer's dial-back result. Acceptable trade — adversarial bootstraps matter far more at scale, where the 2/3 quorum rule kicks in.
- **Dialer cannot attribute failures to a specific relayer.** Because the relay is invisible in the published address, a dialer's trust events for a failed relay-fronted connection are attributed to the target, not the relay. Per-relayer quality tracking is therefore a local concern of the private peer (target) only, not a network-wide signal. Acceptable — the private peer is best positioned to judge its own relay's health.

### Neutral

- **Metadata exposure via relays.** Public peers acting as relays see traffic metadata (who talks to whom, timing, shape) for their relay clients, because all ingress to the private peer flows through them. Traffic contents remain end-to-end encrypted via the target's ML-DSA handshake running over the tunnel.
- **The cascade is not deleted.** It remains as a deep fallback path for scenarios not covered by the classifier (e.g., pre-probe dials, probe failures under unusual network conditions). Its timing budget may be tightened since it is no longer the common path.
- **Relayer identity is not in published records.** Informational only — the "relayer in K closest" invariant is enforced by the private peer using its internal knowledge of which peer it picked, so nothing observable requires the identity to be published.

## Implementation Scope

The following items form the concrete work package. Order is suggestive, not strict.

### saorsa-core work items

1. **Dial-back probe protocol**: new message types `DialBackRequest { target_addresses: Vec<MultiAddr> }`, `DialBackResult { reachable: Vec<MultiAddr> }`. Handler on the prober side performs a one-shot QUIC connect attempt to each requested address with a short per-address timeout. Requester aggregates results and applies the 2/3 quorum rule.
2. **Reachability classifier**: consumes probe results, produces per-address `AddressType` classification, persists the result for the session.
3. **Relay acquisition coordinator**: when the classifier reports "no direct addresses," walk XOR-closest candidates (peers whose DHT record contains at least one `Direct` address) and call `establish_relay_session()` on each until one accepts. Track the chosen relayer's peer ID internally for the K-closest invariant.
4. **Wire the classifier to `setup_proactive_relay()`**: replace the existing symmetric-NAT-driven trigger (currently fired 5 s after startup from `nat_traversal_api.rs`) with classifier-driven invocation. The function itself requires no changes — same inputs, same outputs.
5. **Relay-address publisher**: the existing `network.rs:~1170` task already publishes the relay-allocated address to K closest peers when the session is established. Ensure the `AddressType::Relay` tag is set correctly on the published entry.
6. **Relayer monitor**: await the existing `RelaySession.connection.closed()` future from saorsa-transport (`nat_traversal_api.rs:210` — `RelaySession` is public, its `connection` field is public, and `InnerConnection::closed()` is already the idiomatic subscription mechanism; saorsa-core reaches it via `relay_sessions()` at `nat_traversal_api.rs:3504`). Subscribe to routing-table change events in parallel. On session close or "relayer no longer in K closest," trigger rebinding. No new API surface needed in saorsa-transport for this item.
7. **Re-probe scheduler**: 5-minute tokio interval + `if-watch` network-change subscription + reactive session-close hook. Single code path that all three triggers feed into.
8. **Connection budget adjustment**: reduce `DIAL_TIMEOUT` in `src/transport/saorsa_transport_adapter.rs:494` for the common (verified) path. The cascade retains the longer budget for its fallback role.

### saorsa-transport work items (small)

9. **Relax the MASQUE relay server's per-client cap from 1 to 2** (`masque/relay_server.rs`). The existing `handle_connect_request` at line 368 already rejects duplicate sessions from the same client SocketAddr via the `client_to_session: HashMap<SocketAddr, u64>` map at line 191, returning a 409 "Session already exists for this client" error. To support the ADR's "2 per public peer" cap:
   - Add `max_sessions_per_client: usize` to `MasqueRelayConfig` (default 2).
   - Change `client_to_session` from `HashMap<SocketAddr, u64>` to `HashMap<SocketAddr, SmallVec<[u64; 2]>>` (or `Vec<u64>`).
   - Change the capacity check from `contains_key` to `.get(&client_addr).is_some_and(|v| v.len() >= max_sessions_per_client)`.
   - On session insert, append to the vec instead of inserting a new entry.
   - On session close, remove the session ID from the vec and drop the entry when empty.
   - Update `test_duplicate_client_rejected` to assert the 3rd concurrent session is rejected, not the 2nd.

   **Cap key design note**: SocketAddr is the correct cap key at the MASQUE layer (which is peer-agnostic by design). Under normal NAT conditions, distinct clients behind the same CGNAT get distinct NAT-mapped source ports → distinct SocketAddrs from the relay's perspective, so the cap gives correct per-client semantics in practice. A single client that opens multiple QUIC connections from different source ports (e.g., after Quinn path migration) counts as multiple clients — acceptable, still bounds load.

10. **Optional — graceful teardown notification**: when a relay server is shutting down cleanly, notify active relay clients before closing connections so they can rebind proactively and shrink the failover window. Nice-to-have, not required for correctness.

## Alternatives Considered

**Keep the cascade, add NAT classification.** Detect NAT type upfront and skip stages known to be doomed (e.g., symmetric → skip hole-punch). Rejected because: (a) NAT classification is famously unreliable at scale (CGNAT, double NAT, enterprise middleboxes), and (b) even with correct classification, we'd still run a multi-stage cascade per dial — the core latency problem is unchanged.

**Separate public/private "reachability bit" gossiped in DHT records.** An explicit boolean or enum alongside the address list. Rejected because the `AddressType::Direct` marker on an address already carries this information: "has at least one `Direct` address in the record" is a valid and sufficient "this peer is public" signal. Fewer fields, same signal.

**K ≥ 2 relays per private peer.** Advertise multiple relayers for redundancy. Rejected because K=1 plus eager failover and the K-closest invariant keeps the DHT record small and the public-peer load predictable. The 10–30 s failover window is acceptable for the target use cases.

**Bound reservations with a TTL (libp2p circuit-v2 style).** 1-hour TTL with client-driven refresh. Rejected because we already have QUIC connection liveness as a free heartbeat — layering a TTL on top is redundant and introduces refresh-failure edge cases.

**Publish direct-address hints alongside the relay address** (for LAN-local optimization). Rejected to keep the DHT record unambiguous: a private peer's published address list either asserts reachability (`Direct`) or delegates it (`Relay`), never both. The LAN-local case is deferred as a known limitation.

**Explicit connection-routing relay with a `MultiAddr` schema extension** (libp2p circuit-relay-v2 style). An alternative in which the relay is a QUIC-layer peer with its own identity, published explicitly in a compound multiaddr of the form `/ip4/.../quic/p2p/<relayer>/relay/p2p/<target>`, and the dialer runs a nested QUIC handshake bridged by the relay's reservation table. **Rejected** because it requires a new saorsa-transport subsystem (control protocol, stream bridging, nested-handshake support over an arbitrary byte pipe, new client registration and dialer APIs) whose implementation cost is large and whose highest-risk item — running a Quinn client handshake over a non-UDP byte pipe — has unknown feasibility. The TURN-style MASQUE path achieves the same user-visible goals (latency reduction, single-hop private-to-private connectivity, bounded public-peer load) with a small delta on top of existing code. The things the explicit model would have gained — relayer identity visible in the published address, dialer-side trust attribution to specific relayers, a K-closest invariant enforced across the network rather than locally — are all either achievable by other means (local tracking of the chosen relayer on the private-peer side) or deemed not worth the cost.

## References

- Current cascade: `saorsa-transport/src/p2p_endpoint.rs` (`connect_with_fallback_inner`, ~line 1316)
- Dial timeout budget: `src/transport/saorsa_transport_adapter.rs:494`
- Dialable address filter (PR #70): `src/dht/dht_network_manager.rs:1321`
- MASQUE relay session establishment: `saorsa-transport/src/nat_traversal_api.rs:3343` (`establish_relay_session`)
- Proactive relay setup (to be retriggered by classifier): `saorsa-transport/src/nat_traversal_api.rs:~4027` (`setup_proactive_relay`)
- Quinn endpoint rebind onto MASQUE tunnel: `saorsa-transport/src/nat_traversal_api.rs:4055` (`endpoint.rebind_abstract`)
- Relay-address publish task: `src/network.rs:~1170`
- `AddressType` enum (commit `3b7131d`, H4): `src/dht/core_engine.rs:120`
- `MultiAddr`: `src/address.rs:52`
- [libp2p AutoNAT spec](https://github.com/libp2p/specs/blob/master/autonat/README.md) — reference for the dial-back probe model
- iroh/Tailscale `netcheck` — reference for 5-minute reprobe cadence
- [ADR-002: Delegated Transport](./ADR-002-delegated-transport.md) — the delegation boundary this ADR operates within
- [ADR-007: Adaptive Networking with ML](./ADR-007-adaptive-networking.md) — trust/adaptive layer this ADR inherits from
- **IETF MASQUE Drafts**:
  - `draft-ietf-masque-connect-udp-listen-11` — Bound UDP proxying over HTTP (January 2026)
    - https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-udp-listen
  - `draft-ietf-masque-quic-proxy-08` — QUIC-aware proxying using HTTP (March 2026)
    - https://datatracker.ietf.org/doc/html/draft-ietf-masque-quic-proxy
- **IETF QUIC NAT Traversal Draft**:
  - `draft-seemann-quic-nat-traversal-02` — Using QUIC to traverse NATs (March 2024)
    - https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal
