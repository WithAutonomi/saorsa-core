# ADR-016: Trust Quarantine Thresholds and Trust-Neutral Request Transport

## Status

Proposed (2026-07-16) — documents the decisions introduced by open PR [#119](https://github.com/WithAutonomi/saorsa-core/pull/119); to be moved to Accepted when the PR merges.

## Context

Before PR #119, trust enforcement in the DHT was blunt and partially misattributed:

- The routing table had a single trust lever — a swap threshold — with no distinction between "this peer is a weak candidate" and "this peer should be actively avoided". A single threshold cannot express three different questions: *when should a peer become replaceable?*, *when should automatic machinery stop selecting a peer?*, and *what does a new or previously-avoided peer have to prove before entering the routing table?*
- Nothing gated new routing-table admissions on trust, so a peer that had been driven to a low score could be forgotten and immediately re-admitted at the same low score via rediscovery.
- `P2PNode::send_request` automatically reported `TrustEvent::ConnectionTimeout` / `TrustEvent::ConnectionFailed` on every transport error ("Request/Response API — Automatic Trust Feedback"). Generic transport failures are **ambiguous**: at that layer a timeout can mean remote misbehaviour, but it can equally mean network congestion, a slow-but-honest application handler, or local overload. The generic layer cannot tell these apart. Worse, an application-aware downstream caller reporting `ApplicationFailure` for the same operation would then **double-penalize** the failed exchange — once automatically at the transport layer and once explicitly at the application layer.
- Trust scores are still stabilizing in real deployments. An immediate-eviction policy tied to a young scoring model risks ejecting honest peers on transient noise and shrinking the routing table below the Kademlia K target.

The trust model this builds on (see `src/adaptive/trust.rs` and [ADR-007](./ADR-007-adaptive-networking.md)): unknown peers start at neutral trust `0.5`; core records **penalties only** (successful responses are the expected baseline); scores are an EMA (`EMA_WEIGHT = 0.124`) with lazy exponential time decay toward neutral (`DECAY_LAMBDA = 1.394e-5`/s, so a worst-case `0.0` score decays back above `0.35` in ~1 day and above `0.45` in ~46 hours). Rewards are the consumer's responsibility via `TrustEvent::ApplicationSuccess`.

## Decision

PR #119 introduces a three-threshold trust quarantine policy for the DHT routing layer, enabled by default, together with a trust-neutral generic request transport. Trust enforcement becomes **routing-table and automatic-selection policy**, never a transport block.

### 1. Ownership and configuration propagation

`AdaptiveDHT` remains the **sole creator and trust-policy owner** of the `TrustEngine` (`src/adaptive/dht.rs:198`; module doc at `src/adaptive/dht.rs:14-21`) — all trust signals flow through it. Configuration flows one way:

```text
NodeConfig.adaptive_dht_config : AdaptiveDhtConfig     (src/network.rs:263, #[serde(default)])
        │  validated in AdaptiveDHT::new (src/adaptive/dht.rs:222)
        ▼
DhtNetworkConfig { swap_threshold, quarantine_threshold, quarantine_readmit_threshold }
        │  (src/dht_network_manager.rs:626-635)
        ▼
DhtCoreEngine  — swap_threshold via constructor;
                 set_trust_quarantine_thresholds(...) for the quarantine pair
                 (src/dht_network_manager.rs:1725-1742, src/dht/core_engine.rs:1613-1637)
```

`DhtNetworkManager` holds only an injected `Option<Arc<TrustEngine>>`; it never creates one. The policy is **on by default**: `NodeConfig` defaults to `AdaptiveDhtConfig::default()`.

### 2. Three thresholds, not one

Defined in `src/adaptive/dht.rs:33-40` (mirrored as documentation constants in `src/dht/core_engine.rs:205-222`):

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `swap_threshold` | **0.35** | Peer becomes *eligible for lazy swap-out* — replaced only when a better routing-table candidate arrives. Never causes eviction on its own. |
| `quarantine_threshold` | **0.20** | *Automatic avoidance*: lookup/dial machinery stops selecting the peer. The peer is not removed and explicit sends still work. |
| `quarantine_readmit_threshold` | **0.45** | *Admission gate*: a peer **unknown to the routing table** (brand new, or previously quarantined and forgotten) must score at or above this to be admitted/readmitted. |

**Validation** (`AdaptiveDhtConfig::validate`, `src/adaptive/dht.rs:84-138`): all three must be finite and in `[0.0, 0.5)`; when quarantine is active, `quarantine_readmit_threshold >= quarantine_threshold`; when swap and quarantine are both non-zero, `swap_threshold > quarantine_threshold` (swap is a milder condition than avoidance, quarantine is strictly more severe). The quarantine pair is re-checked at the engine boundary in `set_trust_quarantine_thresholds`; `swap_threshold` is validated only by `AdaptiveDhtConfig::validate`. Values at or above neutral `0.5` are rejected because decay approaches neutral asymptotically: negatively observed peers would remain swap/quarantine-eligible indefinitely, while readmission from below at a neutral cutoff would be unreachable in finite time. Invalid config fails node construction (`AdaptiveDHT::new` returns `Err`).

**Disabling**: `quarantine_threshold == 0.0` disables quarantine enforcement (`quarantine_enabled()`, `src/dht/core_engine.rs:1640-1642`). `NodeConfigBuilder::trust_enforcement(false)` (`src/network.rs:518-530`) zeroes all three thresholds — scores are still tracked, but nothing is enforced.

### 3. Only unknown admissions are gated; existing peers in [0.20, 0.45) are preserved

`check_new_peer_admission` (`src/dht/core_engine.rs:1644-1670`) is called **only when the peer is not already in the routing table** (`add_node`, `src/dht/core_engine.rs:2443-2446`; `re_evaluate_admission`, `src/dht/core_engine.rs:3069-3072`). Non-finite trust scores are rejected defensively. Consequences:

- An existing routing-table peer whose score sits in `[0.20, 0.45)` **stays in the table** and may move into the close group (close-group membership is pure XOR distance over table contents). It remains eligible for lazy swap-out below 0.35 and is skipped by automatic selection below 0.20 — but it is never ejected merely for the band it occupies.
- Admission at or above 0.45 clears any quarantine marker (`forget_quarantined_peer`, `src/dht/core_engine.rs:1668`) — this is the readmission point.
- `should_avoid_automatic_candidate` (`src/dht/core_engine.rs:1779-1795`) encodes the asymmetry directly: a peer scoring in `[quarantine, readmit)` is avoided as an automatic candidate *only if it is not already in the routing table*.

### 4. Stale-revalidation concurrency invariant

Stale-peer revalidation (evict-then-readmit under contention) must not let the new-peer admission gate reject a peer that concurrently became known. The invariant: **a peer already present in the routing table is treated as an update, never as a new admission**. `re_evaluate_admission` skips `check_new_peer_admission` when `has_node(&candidate_id)` is true (`src/dht/core_engine.rs:3069-3072`), so a peer with trust in `[0.20, 0.45)` that entered the table during the revalidation window is updated in place with no second admission event. If re-admission fails *after* stale peers were already evicted, `revalidate_and_retry_admission` still broadcasts the committed removal events rather than failing the flow (`src/dht_network_manager.rs:5197+`). Revalidation itself is bounded (`MAX_CONCURRENT_REVALIDATIONS = 8`, `MAX_CONCURRENT_REVALIDATION_PINGS = 4`, per-bucket guards) and re-evaluation runs with `allow_stale_revalidation: false` to prevent recursion.

### 5. Automatic filtering everywhere; explicit sends and wire format untouched

Two engine predicates drive all filtering: `should_avoid_for_lookup` (`src/dht/core_engine.rs:1765-1775` — non-finite, below 0.20, or marked quarantined and below 0.45) and `should_avoid_automatic_candidate` (adds the unknown-peer readmit gate). They are applied on every **automatic** path in `src/dht_network_manager.rs`:

1. Local lookup results / FIND_NODE response serving — `find_closest_nodes_local` (`:2579-2606`)
2. Iterative lookup local seeding — `find_closest_nodes_network` (`:2740`)
3. Iterative lookup candidate/batch selection (`:2786`)
4. Gossiped nodes from FIND_NODE responses (`:2897`)
5. Bootstrap — both the bootstrap peers themselves and gossiped nodes (`:2192-2195`, `:2230-2239`)
6. Bucket refresh (`:1993-2002`)
7. Self-lookup (`:2059-2065`)

**Explicit sends stay unblocked**: `send_dht_request` / `send_dht_request_with_response_context` contain no quarantine checks, and `P2PNode::send_request` / `send_message` never consult trust. Quarantine is local selection policy, not a firewall.

**Wire format is unchanged**: trust is never serialized into DHT lookup results — `lookup_results_from_routing_nodes` keeps the legacy `DHTNode` reliability wire value stable (`src/dht_network_manager.rs:2620-2623`, asserted by test at `:6011`). Older nodes interoperate without change.

### 6. Immediate close-group trust eviction: implemented but disabled

Immediate eviction of below-0.20 close-group peers is **currently switched off** while trust scoring stabilizes: `close_group_immediate_eviction_enabled()` is hard-wired to `false` (`src/dht/core_engine.rs:216-218`). `enforce_close_group_trust_gate` (`src/dht/core_engine.rs:1866-1924`) is still wired through `DhtNetworkManager::enforce_trust_quarantine` and `broadcast_routing_events_with_quarantine`, but returns no events; `enforce_close_group_quarantine` is retained under `#[cfg(test)]`. The gated-off bodies preserve the safety property for re-enablement: eviction only proceeds `while routing.node_count() > k_value`, so the routing table **never shrinks below K** for trust reasons. Until the gate flips, lazy swap-out (0.35) is the sole replacement mechanism for low-trust peers, and peers below 0.20 remain in the table but are avoided by the automatic paths above.

### 7. Bounded quarantine markers

Quarantine markers (`quarantined_peers: HashSet<PeerId>` plus FIFO `quarantined_peer_order`) are bounded at `MAX_QUARANTINED_PEERS = 8192` (`src/dht/core_engine.rs:229`). The key insight making the bound safe (`quarantine_marker_required_for_score`, `src/dht/core_engine.rs:1690-1696`): **a marker is only semantically required while a peer's score is in `[quarantine_threshold, readmit_threshold)`** — below 0.20 the score itself keeps the peer avoided; at/above 0.45 the peer is readmittable and the marker is cleared. When the set is full, `prune_redundant_quarantined_peers` drops (oldest-first) any marker whose current score no longer requires one; if the set is still full, the new marker is simply not inserted — the score-based avoidance clause covers the peer regardless. Note: with immediate eviction disabled (§6), no production path currently inserts markers; the machinery is preserved intact for re-enablement.

### 8. Decay and recovery via rediscovery

There is no active probing of avoided peers. Recovery is `time decay toward neutral` **plus** `natural rediscovery`: a quarantined/avoided peer's score decays back above 0.45 (~46 h from worst case), after which it can re-enter through the normal admission path when it is rediscovered via a FIND_NODE response or an authenticated inbound connection (`docs/ROUTING_TABLE_DESIGN.md:272-278`). Decay-plus-rediscovery *is* the temporary-ban mechanism.

### 9. Application trust weights capped

`TrustEvent::ApplicationSuccess(w)` / `ApplicationFailure(w)` weights are clamped to `MAX_CONSUMER_WEIGHT = 5.0` in `AdaptiveDHT::report_trust_event` (`src/adaptive/dht.rs:44`, `:262`) so no single consumer-reported event can dominate the EMA; zero or negative weights are ignored. The clamp deliberately lives in `AdaptiveDHT`, not `TrustEngine` — the engine applies whatever weight it is given (verified by `test_trust_engine_does_not_clamp_weights`), keeping the policy at the ownership boundary.

### 10. DHT-context scoring: weighted dials, exactly-once requests

The DHT layer keeps automatic penalties **because it has context** — it knows the operation, the failure phase, and the peer's advertised addresses:

- **Pre-request dial failure** — `DHT_DIAL_FAILURE_TRUST_WEIGHT = 2.25` (`src/dht_network_manager.rs:250`), reason `dht_dial_failed`, reported in `run_owned_dial` when every candidate address fails. Calibration: four evenly-spaced dial failures over six hours take a neutral peer below the 0.20 avoidance threshold.
- **Failed DHT RPC** (send error or response timeout) — weight 1.0, reason `dht_request_failed`, recorded at the RPC level in `send_dht_request_with_response_context` (`src/dht_network_manager.rs:4076-4079`).
- **Failed identity exchange after dial** — weight 1.0, reason `dht_identity_exchange_failed`.

**Exactly-once invariant**: each failed DHT request is scored once and only once. (a) Concurrent dials collapse onto a single owner (`run_owned_dial`), so the dial penalty fires once per dial, not once per waiting caller; (b) a dial failure returns early from the request path *before* the RPC-level recording, so it is never also counted as a request failure; (c) RPC failure is recorded at one chokepoint that all callers (including revalidation pings) rely on rather than re-reporting.

### 11. Generic request transport is trust-neutral (commit `5d5f69f`)

`P2PNode::send_request` no longer reports any trust event — it is a pure passthrough to `send_request_reconnecting` (`src/network.rs:1044-1053`; section renamed to "Request/Response API — Trust-Neutral Transport"). Rationale:

- **Ambiguity**: at the generic transport layer, a timeout or connection error cannot be attributed — it may be remote misbehaviour, but equally network congestion, a slow application handler on an honest peer, or local overload. Penalizing on it punishes honest peers for conditions they don't control (`docs/trust-signals-api.md:79-81`).
- **Double-penalty**: application-aware layers (downstream node applications and DHT RPC) already report justified outcomes for the same exchange. Automatic transport penalties would stack a second, unjustified penalty on top of the informed one.

The division of labour: **layers that can judge, report; layers that can't, stay neutral.** The DHT layer keeps its contextual automatic penalties (§10); applications report `ApplicationSuccess`/`ApplicationFailure` (and, where justified, `ConnectionFailed`/`ConnectionTimeout`) explicitly via `P2PNode::report_trust_event`. Regression test: `failed_send_request_leaves_trust_unchanged` (`tests/trust_flow.rs:100`) asserts a failed `send_request` leaves the peer at neutral 0.5.

## Invariants

1. **Threshold ordering**: when quarantine is active, `0 < quarantine_threshold <= quarantine_readmit_threshold < 0.5`; when swap and quarantine are both active, `quarantine_threshold < swap_threshold < 0.5`. Defaults: `0.20 < 0.35` and `0.20 <= 0.45`.
2. **K-sized routing table**: trust enforcement never shrinks the routing table below K (eviction, even when re-enabled, only runs while `node_count > K`).
3. **Known-peer preservation**: a peer already in the routing table is never subjected to the new-peer admission gate — including during stale-revalidation races (§4).
4. **No transport block**: quarantine affects only routing-table membership and automatic selection; explicit sends always go through.
5. **Wire stability**: trust state never leaks into serialized DHT messages; filtering is strictly local policy.
6. **Exactly-once DHT scoring**: one failed DHT request produces exactly one trust penalty (dial 2.25 *or* RPC 1.0 *or* identity-exchange 1.0 — never stacked for the same attempt).
7. **Marker sufficiency**: quarantine markers are required only for scores in `[quarantine, readmit)`; outside that band the score alone determines behaviour, which is what makes the 8192 bound safe.
8. **Penalty-only core**: saorsa-core never auto-rewards; positive signals come exclusively from consumers (capped at weight 5.0).
9. **Trust-neutral generic transport**: `send_request`/`send_message` never report trust events; only application-aware layers do.

## Consequences

### Positive

- **Sybil/misbehaviour pressure without fragility**: low-trust peers stop being handed out by lookups, used for bootstrap/refresh, or dialed by maintenance — while the routing table stays K-sized and honest-but-unlucky peers aren't permanently exiled.
- **Readmission gate closes the forget-and-return loophole**: a peer driven below quarantine cannot be evicted/forgotten and immediately re-admitted at a low score; it must decay back to 0.45 first.
- **No misattributed penalties from generic transport**: honest peers are no longer punished for congestion, slow handlers, or the local node's own overload — and application penalties are no longer doubled by transport-layer penalties for the same exchange.
- **Calibrated avoidance**: the 2.25 dial weight gives persistent unreachability a concrete, documented time-to-avoidance (four spaced failures over six hours from neutral), rather than an emergent accident of unit weights.
- **Fully backward compatible on the wire**: mixed-version networks work; old nodes see identical messages.
- **Bounded memory**: quarantine bookkeeping cannot grow past 8192 entries, and dropping markers under pressure degrades gracefully to score-only avoidance.
- **Operators can turn it off**: `trust_enforcement(false)` gives observe-only mode (scores tracked, nothing enforced) for diagnosis or staged rollout.

### Negative

- **Slower reaction to genuinely malicious close-group peers**: with immediate eviction disabled, a below-0.20 peer stays in the close group until lazy swap-out replaces it; it is avoided by automatic paths but still occupies a slot.
- **Applications now own attribution**: any consumer that relied on `send_request`'s automatic penalties gets no trust signal for its request failures unless it explicitly reports a justified outcome. Silent trust erosion of misbehaving peers via generic requests no longer happens.
- **Recovery latency is fixed by decay**: a wrongly-penalized peer needs up to ~46 h (worst case) to become admissible again; there is no active-probe fast path.
- **More configuration surface**: three interdependent thresholds with ordering rules; invalid combinations fail node construction (loudly, by design).

### Neutral

- The immediate-eviction machinery (gate function, trust-gate enforcement, marker insertion) ships dark: wired, tested, and preserved, but returning no events until `close_group_immediate_eviction_enabled()` flips. Re-enabling it is a one-line change plus recalibration review — a likely follow-up ADR/amendment once scoring is deemed stable.
- With eviction dark, quarantine *markers* have no production writer; the active enforcement today is score-based avoidance (0.20), the unknown-admission gate (0.45), and lazy swap (0.35).
- Trust scores keep being computed identically in observe-only mode, so enabling enforcement later needs no re-learning period.

## Compatibility and Breaking Changes

- **API (breaking)**: `AdaptiveDhtConfig` gains `quarantine_threshold` and `quarantine_readmit_threshold` (with `#[serde(default)]`, so serialized configs deserialize fine); struct-literal construction without `..Default::default()` breaks. `DhtNetworkConfig` gains the same fields.
- **Behavioural (breaking)**: quarantine defaults ON. New routing-table peers must meet 0.45 when enforcement is enabled; peers below 0.20 stop appearing in lookup results and automatic maintenance. `send_request` no longer auto-penalizes failures — consumers relying on that must add explicit `report_trust_event` calls.
- **Wire (non-breaking)**: no message format changes; `DHTNode` reliability keeps its legacy value.

## Operational Implications

- **Defaults are live on upgrade** — no config change needed to get the policy; use `trust_enforcement(false)` to opt out.
- Watch trust-score distribution after deployment: since scores are stabilizing, thresholds (especially 0.45 admission on small networks, where rejecting a scarce peer costs more) may need tuning before immediate eviction is re-enabled.
- Reason strings (`dht_dial_failed`, `dht_request_failed`, `dht_identity_exchange_failed`, `application_failure`, …) are logged with score deltas — use them to audit which layer is driving a peer's score.
- Downstream consumers should classify data-availability outcomes and report only justified `ApplicationSuccess`/`ApplicationFailure` events; generic request transport itself contributes no trust signal.
- Small/bootstrap networks: bootstrap peers themselves are trust-filtered — a bootstrap peer driven below 0.20 will be skipped, so keep multiple bootstrap endpoints configured.

## Alternatives Considered

**Single trust threshold for everything.** One cutoff for swap, avoidance, and admission. Rejected: the three questions have different costs. Swap-eligibility is cheap and reversible; avoidance affects lookup quality; admission controls table churn. A single value is either too aggressive for avoidance or too lax for admission, and it recreates the forget-and-readmit loophole (evict at X, readmit at X).

**Hard transport-level block of quarantined peers.** Refuse all sends to below-threshold peers. Rejected: explicit sends are how applications retry, probe, and recover — blocking them turns a local routing preference into a network partition, breaks consumer semantics, and prevents the very interactions whose successes a consumer could report to rehabilitate a peer.

**Keep immediate close-group eviction active.** Evict on the spot when a K-closest peer drops below 0.20. Rejected *for now*: trust scoring is not yet stable enough; transient noise could eject honest close-group peers and churn the close group. The machinery is retained behind `close_group_immediate_eviction_enabled()` and its K-preservation guard, to be re-enabled once scoring stabilizes.

**Keep generic automatic request penalties (status quo ante).** Let `send_request` keep reporting `ConnectionFailed`/`ConnectionTimeout`. Rejected: the generic layer cannot distinguish remote misbehaviour from congestion, application delay, or local overload, and it double-counts failures that application-aware layers already report with justified weights.

**Parse application protocols in core to disambiguate failures.** Teach saorsa-core enough about each application protocol to attribute failures correctly. Rejected: inverts the layering (core is a phonebook and trust substrate, per the DHT-phonebook architecture), couples core releases to every consumer protocol, and still can't see application-level correctness (e.g. "served the wrong chunk").

**Per-call trust policy parameter on `send_request`.** Let each call site pass `penalize_on_failure: bool` or a policy enum. Rejected: pushes a breaking signature change onto every downstream caller, and the caller that knows enough to set the flag correctly is exactly the caller that can simply call `report_trust_event` — the explicit-report API already is the per-call policy, without changing the transport signature.

## References

- PR: [WithAutonomi/saorsa-core#119](https://github.com/WithAutonomi/saorsa-core/pull/119) — `feat(dht)!: add trust quarantine thresholds`; implementation commits span `898b9fb` through `5d5f69f`, where `5d5f69f` makes generic request transport trust-neutral.
- Key commits: `898b9fb` (thresholds), `f844fc7` (admission gate), `f03fa83` (K-sized table preservation), `6eb61df` (defaults on), `369f1a9` (bounded marker set), `001ca24` (marker semantics), `7159ad4` (stale-revalidation admissions), `f0a0b8b` (disable immediate eviction), `13cf699` (2.25 dial weight), `5d5f69f` (trust-neutral requests)
- Config & ownership: `src/adaptive/dht.rs:33-44` (constants), `:47-72` (`AdaptiveDhtConfig`), `:84-138` (validation), `:217-239` (`AdaptiveDHT::new`); `src/network.rs:255-263` (default enablement), `:505-538` (`trust_enforcement`)
- Engine: `src/dht/core_engine.rs:205-229` (constants, eviction gate, `MAX_QUARANTINED_PEERS`), `:1613-1642` (threshold setter / `quarantine_enabled`), `:1644-1670` (`check_new_peer_admission`), `:1690-1762` (marker lifecycle), `:1765-1795` (avoidance predicates), `:1866-1924` (`enforce_close_group_trust_gate`), `:3055-3081` (`re_evaluate_admission`)
- Manager: `src/dht_network_manager.rs:244-256` (trust reason constants, 2.25 weight), `:3569-3621` (failure recording, avoidance wrapper), `:3771-3806` (owned dial), `:4074-4079` (exactly-once RPC recording), filtering sites §5
- Trust model: `src/adaptive/trust.rs` (EMA, decay, neutral 0.5)
- Trust-neutral transport: `src/network.rs:1006-1053`, `tests/trust_flow.rs:100`
- Docs updated by this PR: [`docs/trust-signals-api.md`](../trust-signals-api.md), [`docs/SECURITY_MODEL.md`](../SECURITY_MODEL.md), [`docs/ROUTING_TABLE_DESIGN.md`](../ROUTING_TABLE_DESIGN.md)
- Related ADRs: [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md), [ADR-007: Adaptive Networking with ML](./ADR-007-adaptive-networking.md), [ADR-009: Sybil Protection Mechanisms](./ADR-009-sybil-protection.md)
