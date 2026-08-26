# ADR-016: Local Response-Rate Trust Quarantine for DHT Routing

## Status

Accepted (2026-06-24, recorded retroactively)

This ADR narrows [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md) for the production trust contract. ADR-006 remains historical context and a possible future direction for distributed EigenTrust/global reputation, but it is not the production contract unless a later ADR introduces global trust propagation.

## Context

`saorsa-core` needs a trust mechanism for DHT routing decisions without turning the DHT into an application data store or a global reputation ledger.

The accepted ADR history is broader than the production architecture:

- ADR-006 describes distributed EigenTrust: global scores, peer-to-peer trust propagation, pre-trusted anchors, and iterative convergence.
- The production requirement is narrower: local trust based on direct response outcomes.
- The DHT is a peer phonebook only: peer records, routing, discovery, address propagation, and liveness.
- User data storage and data availability policy live above `saorsa-core`.
- Application layers still need a way to report data availability outcomes so routing trust can react to peers that fail to serve expected data.

Calling the production system EigenTrust overstates the security model. Operators and higher layers should not expect a peer penalized by one node to be penalized globally, nor should they expect trust transfer through remote recommendations.

## Decision

For the production architecture, `saorsa-core` trust is a local response-rate EMA/quarantine system owned by the adaptive DHT trust layer, not a distributed EigenTrust implementation.

The production trust contract is:

1. **Local score model**
   - Unknown peers start at neutral trust (`0.5`).
   - Successful observations move the score toward `1.0`.
   - Failed observations move the score toward `0.0`.
   - Idle scores decay lazily toward neutral.
   - Scores are local to the observing node.
   - Scores are persisted locally (e.g. the close-group cache) so they survive
     restarts. This persistence is local-only; scores are never sent to or
     received from remote peers. Decay does not run while the node is offline —
     the elapsed clock resumes from restart, so a peer is not penalized for our
     own downtime.

2. **Signal sources**
   - Failed outbound DHT RPCs, dials, and identity exchanges record local penalties.
   - Honest protocol rejection and stale identity cleanup do not necessarily penalize trust.
   - Core does not generally reward successful DHT responses; success is the expected baseline.
   - Application layers may report positive or negative data-serving outcomes.
   - Application-reported events may carry bounded weights so severe data failures can matter more than routine failures.
   - All trust events feed the same local score model.

3. **Routing-table admission**
   - Routable peer admission considers the local trust score alongside normal routing-table rules.
   - Loopback/devnet records and non-IP transport records may bypass trust enforcement where their routing-table path bypasses normal routable-IP admission constraints.
   - Routing trust scores are not authoritative peer-record state. Remote reliability metadata, where present for compatibility, is not imported into the local trust score.
   - A peer below the quarantine/swap threshold is not automatically banned. If there is room and the peer satisfies normal admission rules, it can still be admitted.
   - Under bucket contention, a candidate at or above the quarantine/swap threshold may replace the lowest-trust incumbent below that threshold.
   - The default quarantine/swap threshold is `0.35`.

4. **Lookup avoidance**
   - Iterative lookups query the local routing table and candidate queue, not a global reputation service.
   - Peers removed from the routing table by trust-driven swaps are avoided when seeding from the local table, but they may reappear later through third-party DHT gossip.
   - Lookup does not apply a trust-score filter to every gossiped candidate.
   - Local transient dial and identity failure state may suppress repeated attempts to currently unreachable or stale candidates.

5. **Eviction and readmission**
   - Trust quarantine is lazy and local: poor responders become easier to evict under contention rather than being immediately and globally banned.
   - Two distinct routing-table mechanisms consult trust, each with its own threshold:
     - *Trust-based swap-out* uses the quarantine/swap threshold (default `0.35`, see point 3): under bucket contention a candidate at or above it may replace the lowest-trust incumbent below it.
     - *Swap-closer eviction* uses a separate trust-protection threshold (default `0.7`): when a closer candidate arrives for a full bucket, a live incumbent at or above the protection threshold resists eviction. Incumbents below it lose that protection.
   - Stale peers lose protection regardless of trust once they pass the liveness window, and may be revalidated; non-responders are evicted.
   - Because trust decays toward neutral, a penalized peer can recover locally over time and be readmitted through the normal discovery, dial, authentication, and admission flow.

6. **Bootstrap candidate filtering**
   - Bootstrap uses configured peers and DHT `FIND_NODE` responses.
   - Gossiped candidates are filtered for locally usable, dialable addresses before dial attempts.
   - Bootstrap does not import or propagate remote trust scores.
   - Any admitted peer goes through the same local trust-aware routing-table path as peers discovered later.

7. **Non-goals for the current system**
   - No global EigenTrust gossip.
   - No global reputation vector.
   - No network-wide ban list.
   - No remote trust recommendation import.
   - No user data storage responsibility inside `saorsa-core`.

## Consequences

### Positive

- The trust system stays cheap and local: no gossip protocol, convergence loop, or global reputation storage is required.
- Routing behavior can react to direct local failures while allowing recovery through decay and normal readmission.
- Application layers such as `saorsa-node` can report data-serving outcomes without moving user data storage into `saorsa-core`.
- Future EigenTrust work remains possible, but it must be introduced explicitly as a new protocol and not assumed from current names.

### Negative

- Scores are subjective per node. A peer penalized by one node is not automatically penalized elsewhere.
- Sybil resistance from trust is local and must be combined with identity, IP diversity, bootstrap diversity, and application-level verification.
- A low-trust peer may remain in the routing table until contention, stale revalidation, or another removal path occurs.
- There is no global warning system for peers that fail data availability checks on other nodes.
- A buggy or malicious local consumer can skew this node's routing trust by reporting misleading application events.

### Neutral

- Existing references to "EigenTrust" for the production trust system should be read as historical shorthand unless and until a later ADR introduces global reputation.
- Documentation that promises immediate hard blocking or global reputation propagation should be updated to this ADR's local quarantine semantics.
- A future global reputation system must define trust gossip, anti-spam rules, convergence behavior, persistence, privacy constraints, and how global scores interact with the existing local EMA.

## Alternatives Considered

1. **Treat ADR-006 as already implemented**
   - Rejected because the production contract does not include global trust vectors, trust gossip, remote recommendations, or distributed convergence.

2. **Edit ADR-006 in place**
   - Rejected because ADR-006 is useful historical context and may still describe a future direction. A new ADR makes the production narrowing explicit without rewriting that history.

3. **Add immediate hard blocking for peers below a block threshold**
   - Rejected because hard blocking makes transient failures more expensive, creates stronger recovery requirements, and is not needed for the current routing-table threat model.

4. **Make routing trust-blind**
   - Rejected because routing needs a local mechanism to protect live well-behaved incumbents and make poor responders easier to replace under contention.

## References

- [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md)
- [ADR-008: Bootstrap Peer Discovery Scope](./ADR-008-bootstrap-delegation.md)
- [ADR-009: Sybil Protection Mechanisms](./ADR-009-sybil-protection.md)
- [ADR-014: Proactive Relay-First NAT Traversal](./ADR-014-proactive-relay-first-nat-traversal.md)
