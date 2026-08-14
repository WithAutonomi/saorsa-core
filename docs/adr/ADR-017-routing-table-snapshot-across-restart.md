# ADR-017: Persist the Whole Routing Table Across a Restart

## Status

Proposed

## Context

`saorsa-core` persists exactly one thing across a restart: the close-group cache, which holds the `k` peers nearest to self. Everything else in the routing table is discarded and rebuilt by periodic bucket refresh at two buckets per 7.5 to 12.5 minutes, a cadence this crate's own source comment describes as approximately once-per-day full-table maintenance.

Consumers above this crate do not ask "who are my neighbours". They ask "am I among the `w` closest to key `K`", which `find_closest_nodes_local_with_self` answers from whatever the local table happens to hold. That predicate has no notion of confidence and no failure value: if the table cannot name `w` peers closer to `K` than self, the answer is yes. A node that has just restarted therefore answers yes for most of the keyspace, and keeps doing so for hours.

The effect is measurable in production rather than theoretical. On `ant-prod-01`, two independent restarted services were ranked against the 806-peer fleet by XOR distance to 200 keys each was actively claiming: median true rank 27 and 24, with **0 of 200 keys placing them in the true closest 7 or the true closest 9**. Fleet-wide, restarted nodes report 40 to 60% of their stored records as in range where a converged table reports about 1%. The observable costs attributed to this window are excess records taken in per service at each rollout, a warning flood from probing peers that are not the real holders, and pruning suppressed while the node believes it is responsible for what it holds.

A close group cannot stand in for a routing table here, and the reason is combinatorial rather than a matter of degree. For a key `K`, write `c = CPL(self, K)`. Any peer `p` with `CPL(p, self) == c` agrees with self on bits `[0, c)` and differs at bit `c`; `K` agrees with self on `[0, c)` and also differs at bit `c`; therefore `p` agrees with `K` at bit `c` and is strictly closer to `K` than self is. Every peer in bucket `c` answers the question. A node holding `w` of them always answers correctly; a node whose bucket `c` is empty cannot, however many neighbours it has. Preserving peers across every bucket is what makes a restored table answer as the original did.

Simulated on an 891-node network at the two widths a storage consumer uses, against correct shares of 1.01% and 2.24%:

| restored table | width 9 claim | width 20 claim |
|---|---|---|
| converged table (steady state) | 1.05% | 2.01% |
| today: nearest 20 only | 41.4% | 95.6% |
| nine peers per bucket | 1.05% | 12.3% |
| whole capped table (~129 entries, ~25 KB) | 1.05% | 2.01% |

## Decision

Persist the whole capped routing table to its own snapshot file, and restore it as dial candidates at startup.

1. **Separate file.** The snapshot is written alongside the close-group cache, not in place of it, so an older binary cannot mistake one for the other and a downgrade keeps working exactly as today.
2. **Every bucket, not the nearest `k`.** The snapshot carries the table up to its per-bucket capacity. Nine peers per bucket fixes the narrow width and leaves the wide one at 12.3%, so the shape is the whole table rather than a per-bucket floor.
3. **Bindings, all required before a snapshot is accepted.** Schema version; owning node id; a network fingerprint derived from the configured bootstrap set; an integrity checksum over the payload; and age, reusing the close-group cache's rules including the rejection of timestamps far in the future. The owner binding is load-bearing rather than hygiene: bucket indices are relative to the owner, so another node's snapshot describes a different partition of the id space.
4. **Restored peers are dial candidates only.** They are not inserted into the routing table and confer no authority until dialled and identity-verified through the ordinary path. Routing-table membership is an authorization fact for callers above this crate, and a file on disk must not be able to grant it.
5. **No trust scores are recorded or restored.** The close-group cache imports trust before dialling, which is defensible for `k` vetted neighbours. It is not defensible for a whole table: a file on disk must not decide that hundreds of unverified peers start above neutral. Trust is re-earned from live behaviour.
6. **Bounded cost, then fall back to today's behaviour.** Restoration dials at bounded concurrency (16, against 4 for bootstrap dials, because the set is an order of magnitude larger and the existing path is serial) under a wall-clock budget of 20 seconds. When the budget expires the remaining candidates are abandoned and the table refills at the ordinary refresh cadence, which is precisely the current behaviour.
7. **On by default, with a kill switch.** `NodeConfig::routing_snapshot_restore` defaults to `true`; setting it to `false` restores the pre-change startup path without a rollback.

## Alternatives considered

- **Keep the close-group cache and choose its 20 peers more cleverly.** Rejected on measurement: at that size composition is second-order. Nearest-20 claims 40.5% of the keyspace at width 9 and an arbitrary 20 claims 43.3%. Size dominates.
- **Persist a fixed floor of peers per bucket.** Rejected as insufficient rather than wrong. Nine per bucket answers width 9 correctly but leaves width 20 at 12.3%, and this crate does not know the widths its consumers use.
- **Estimate network size locally and refuse keys beyond an inferred horizon.** Rejected on two grounds. It admits every key out to true rank `slack × width`, which at the studied slack is rank 36, above the rank 24 to 27 band the production over-claim actually occupied: it caught 14.3% of that band with 6 of 10 simulated nodes catching none. It is also punishable, because a refusal resurfaces as an absent answer at the requester's audit, and peers near a victim's id can shrink its estimate.
- **Wait out the transient by tuning the consumer's retention timers.** Rejected: it treats a wrong answer as a scheduling problem, and it makes nodes act fastest exactly when their routing table is least trustworthy.

## Consequences

### Positive

- A restarted node answers responsibility questions as its converged self did, at every width, instead of claiming most of the keyspace for hours.
- The fix is combinatorial, so it does not depend on network size, key distribution, or an estimator an adversary could move.
- Startup performs less discovery work overall: peers are read from disk rather than re-learned over a day of bucket refreshes.
- Consumers gain nothing new to configure. The predicate, its widths and its call sites are untouched.

### Negative

- A new on-disk artifact to version, validate and keep compatible.
- Startup dials a larger candidate set, bounded by the concurrency limit and the 20-second budget.
- A snapshot full of departed peers costs that budget and yields little, though never more than it.
- Peers restored from a snapshot are unverified until dialled, so the table refills slightly behind the file's contents rather than instantly.

### Neutral

- The close-group cache remains, unchanged, with its own trust import and its own validity rules.
- A brand-new node with no snapshot is unaffected and still refills at the ordinary refresh cadence. Accelerating that case is a separate change and is deliberately not in scope here.

## Validation

- Simulation over an 891-node network at widths 9 and 20, table above, reproducing the shape of the production over-claim and the effect of each candidate snapshot.
- Unit tests covering the bindings that decide acceptance (schema version, owner, network fingerprint, checksum, age), the dial-candidate contract, absence of trust restoration, budget expiry leaving the node in today's behaviour, and the kill switch.
- Not yet evidenced: any production or testnet measurement of this change. The over-claim itself is measured in production; the fix is measured only in simulation and tests, and a testnet run is the next step rather than something this ADR claims.
