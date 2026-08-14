# ADR-017: Persist the Whole Routing Table Across a Restart

## Status

Proposed

## Context

`saorsa-core` persists exactly one thing across a restart: the close-group cache, which holds the `k` peers nearest to self. Everything else in the routing table is discarded and rebuilt by periodic bucket refresh at two buckets per 7.5 to 12.5 minutes, a cadence this crate's own source comment describes as approximately once-per-day full-table maintenance.

Consumers above this crate do not ask "who are my neighbours". They ask "am I among the `w` closest to key `K`", which `find_closest_nodes_local_with_self` answers from whatever the local table happens to hold. That predicate has no notion of confidence and no failure value: if the table cannot name `w` peers closer to `K` than self, the answer is yes. A node that has just restarted therefore answers yes for most of the keyspace, and keeps doing so for hours.

The effect is measured in production rather than theoretical. On the Autonomi production fleet, two independent restarted services were ranked against the 806-peer fleet by XOR distance to 200 keys each was actively claiming: median true rank 27 and 24, with **0 of 200 keys placing them in the true closest 7 or the true closest 9**. Fleet-wide, restarted nodes reported 40 to 60% of their stored records as in range where a converged table reports about 1%. Those figures come from production telemetry held outside this repository; they are cited here as the motivation, and nothing in this ADR depends on their exact values.

A close group cannot stand in for a routing table, and the reason is combinatorial rather than a matter of degree. For a key `K`, write `c = CPL(self, K)`. Any peer `p` with `CPL(p, self) == c` agrees with self on bits `[0, c)` and differs at bit `c`; `K` agrees with self on `[0, c)` and also differs at bit `c`; therefore `p` agrees with `K` at bit `c` and is strictly closer to `K` than self is. Every peer in bucket `c` answers the question. A node holding `w` of them always answers correctly; a node whose bucket `c` is empty cannot, however many neighbours it has. Preserving peers across every bucket is what makes a restored table answer as the original did.

Simulated on an 891-node network against correct shares of 1.01% (width 9) and 2.24% (width 20). The simulation lives outside this repository, so these numbers are supporting evidence for the shape of the fix, not a claim this repository can reproduce:

| restored table | width 9 claim | width 20 claim |
|---|---|---|
| converged table (steady state) | 1.05% | 2.01% |
| today: nearest 20 only | 41.4% | 95.6% |
| nine peers per bucket | 1.05% | 12.3% |
| whole capped table (~129 entries, ~25 KB) | 1.05% | 2.01% |

## Decision

Persist the whole capped routing table to its own snapshot file, and restore it as dial candidates at startup.

1. **Separate file.** The snapshot is written alongside `close_group_cache.json`, not in place of it, so an older binary cannot mistake one for the other and a downgrade behaves exactly as today.
2. **Every bucket, not the nearest `k`.** The snapshot carries the table up to its per-bucket capacity, subject to a flat ceiling of 1,024 peers and 8 addresses each. Nine peers per bucket fixes the narrow width and leaves the wide one at 12.3%, so the shape is the whole table rather than a per-bucket floor. The ceiling is well above the ~129 entries a fleet of this size produces; a network large enough to reach it would restore a truncated table, which is still strictly better than the close group alone.
3. **Two bindings, both required.** The schema version, so an unrecognised version is discarded rather than coerced; and the owning node id, which is load-bearing rather than hygiene, because bucket indices are relative to the owner and another node's snapshot describes a different partition of the id space. A snapshot older than seven days, or dated more than five minutes in the future, is refused. That age bound is the snapshot's own, deliberately not the close-group cache's one hour: the cache's bound exists for trust scores on `k` neighbours, while this file answers which parts of the id space the node knew about, which does not rot on the same timescale, and a maintenance window must not cost a node its table.
4. **Bounded load.** The file is opened once and checked through that handle, never re-opened by path, so a file swapped in between the check and the read cannot bypass either. It is refused if it is not a regular file or exceeds 512 KB, the read itself is capped at the same ceiling, and the peer and per-peer address counts are re-applied after parsing, so a corrupt or hostile file cannot become an unbounded dial set.
5. **Restored peers are dial candidates only.** They are not inserted into the routing table and confer no authority until dialled and identity-verified through the ordinary path. Routing-table membership is an authorization fact for callers above this crate, and a file on disk must not be able to grant it. For the same reason the snapshot records **no trust scores**, unlike the close-group cache: pre-dial trust restoration is defensible for `k` vetted neighbours and not for hundreds of unverified peers.
6. **Restored peers do not seed DHT discovery.** A dialled, identity-verified peer is already admitted to the routing table by the connection path. Adding the restored set to the discovery seed list would issue a serial `FIND_NODE` per peer to rediscover the table just restored, and then serially dial everything those queries returned, so the phase's own bound would be defeated by the phase after it.
7. **Bounded cost, then today's behaviour.** Restoration dials at bounded concurrency (16, against 4 for bootstrap dials, because the set is an order of magnitude larger). A 20-second budget stops *new* peers being dialled; dials already in flight are allowed to finish, because cancelling a handshake mid-flight leaves the far side holding a half-open connection. The phase's bound is therefore the budget plus the last peer's attempts, which is why a snapshot peer is tried at no more than two addresses. Whatever is not restored refills through ordinary discovery, which is exactly the behaviour of a node that had no snapshot.
8. **Once per process, and not for clients.** A re-bootstrap does not replay the snapshot, since the table it would restore is the one the node already has. `NodeMode::Client` skips restoration entirely and keeps its existing six-peer startup bound: a client does not serve the DHT, so it never asks the question this repairs.
9. **A save cannot shrink the snapshot while the table is still restoring.** The periodic and shutdown saves write the file; the post-bootstrap save does not. Nothing is written until the restore step has decided how many peers it recovered, so a node stopped before that step — and a client, which never restores — cannot overwrite a good file with an empty or partial table. For an hour after that decision, a save carrying fewer peers than the restore recovered is skipped, because a node stopped mid-restore holds only what it has re-dialled so far and would otherwise shrink its own file a little further on every cycle. After that hour the live table is the node's best knowledge, so the floor stops applying and the file keeps being refreshed rather than ageing out. An empty table is never written.

## Alternatives considered

- **Keep the close-group cache and choose its 20 peers more cleverly.** Rejected on measurement: at that size composition is second-order. Nearest-20 claims 40.5% of the keyspace at width 9 and an arbitrary 20 claims 43.3%. Size dominates.
- **Persist a fixed floor of peers per bucket.** Rejected as insufficient rather than wrong. Nine per bucket answers width 9 correctly but leaves width 20 at 12.3%, and this crate does not know the widths its consumers use.
- **Bind the snapshot to a network fingerprint derived from the configured bootstrap list.** Rejected: it hashes mutable address spellings rather than a stable network identity, and routine seed rotation would invalidate every node's snapshot during exactly the rollout this repairs. A snapshot carried to another network costs failed dials inside the existing budget, which is the same cost as a cold start.
- **Checksum the payload.** Rejected: it provides no authenticity for a locally written file, while JSON parsing is already all-or-nothing, the write is atomic, and live identity verification governs what the contents can achieve.
- **A config kill switch for restoration.** Rejected: new public API for a behaviour that rolls back by shipping the previous version or deleting the file, and one more untested branch through startup.
- **Estimate network size locally and refuse keys beyond an inferred horizon.** Rejected on two grounds. It admits every key out to true rank `slack × width`, which at the studied slack is rank 36, above the rank 24 to 27 band the production over-claim actually occupied: it caught 14.3% of that band with 6 of 10 simulated nodes catching none. It is also punishable, because a refusal resurfaces as an absent answer at the requester's audit, and peers near a victim's id can shrink its estimate.
- **Wait out the transient by tuning the consumer's retention timers.** Rejected: it treats a wrong answer as a scheduling problem, and it makes nodes act fastest exactly when their routing table is least trustworthy.

## Consequences

### Positive

- A restarted node is expected to answer responsibility questions as its converged self did, at both widths, instead of claiming most of the keyspace for hours. That is the simulated result and the intent of the design; it is not yet demonstrated against a live network, see Validation.
- The fix is combinatorial, so it does not depend on network size, key distribution, or an estimator an adversary could move.
- Consumers gain nothing new to configure. The predicate, its widths and its call sites are untouched, and there is no new public API.

### Negative

- A new on-disk artifact to version and keep compatible.
- Startup dials a larger candidate set. New peers stop being dialled at the 20-second budget, but attempts already in flight still run, so the phase can exceed the budget by one peer's two address attempts.
- A snapshot full of departed peers spends that budget and yields little. No new peer is dialled after it, though attempts already in flight still finish.
- Every periodic and shutdown close-group save now writes a second small file before returning.

### Neutral

- The close-group cache remains, unchanged, with its own trust import and its own validity rules.
- A brand-new node with no snapshot is unaffected and still refills at the ordinary refresh cadence. Accelerating that case is a separate change and is deliberately not in scope here.
- Restored peers are unverified until dialled, so the table refills behind the file's contents rather than instantly.

## Validation

- Unit tests in `src/bootstrap/routing_snapshot.rs` for the file contract: disk round trip, missing file treated as absence, truncated file reported, oversized file refused without being read, peer cap re-applied on load, foreign owner refused, unknown schema version refused, and staleness bounded on both sides of now.
- Unit tests in `src/network.rs` for the restore path's candidate selection: self excluded, addresses already queued by an earlier bootstrap priority not redialled, undialable addresses dropped, repeated peers deduplicated, the per-peer dial list bounded, and a full table producing one candidate per peer.
- Not covered by tests in this PR: the dial phase itself against a live transport, including budget expiry, client-mode exclusion, and the no-shrink rule on saves. Those need a multi-node harness.
- **No testnet or production measurement of this change exists.** The over-claim it targets is measured in production; the fix is evidenced by simulation and unit tests only. A dev testnet run is the next step, and nothing here claims fleet readiness.
