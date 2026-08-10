# ADR-016: Age-Bounded, Periodically Refreshed Close-Group Cache

## Status

Proposed

## Context

`saorsa-core` already persists `close_group_cache.json` when a cache directory is configured. On startup, cached peers are assigned bootstrap Priority 0 and their trust scores are imported before configured bootstrap peers are tried.

The live implementation saves this snapshot after initial bootstrap and during graceful shutdown. It does not refresh the cache periodically during normal operation and does not enforce a maximum snapshot age when loading it. A node that runs for a long time and then exits ungracefully can therefore restart with an old, but structurally valid, view of peers and trust.

This does not make a stale cached peer permanently authoritative: bootstrap already falls through to configured peers when cached peers fail. It can nevertheless delay or bias restart bootstrap, and it makes stale-cache behaviour difficult to distinguish from a live bootstrap or partition problem.

ADR-008 records an older direction in which `saorsa-core` did not retain peer contact state. It is already marked Superseded. The close-group cache on current `main` is a narrower mechanism: it snapshots the node's current XOR-close peers and trust, rather than maintaining a general history of peer contact outcomes. This ADR documents and bounds that current mechanism.

## Decision

When `close_group_cache_dir` is configured:

1. Cache validity is determined from the snapshot's persisted `saved_at_epoch_secs`, not filesystem modification time.
2. `NodeConfig::close_group_cache_max_age` controls the maximum age of a snapshot used at startup.
   - The backwards-compatible default is one hour.
   - `None` explicitly disables age enforcement.
   - A snapshot exactly at the limit remains valid; one older than the limit is stale.
   - Future timestamps are treated as age zero using saturating subtraction to tolerate local clock correction.
3. A stale snapshot is skipped as a whole:
   - its trust scores are not imported;
   - its peers are not inserted as Priority-0 bootstrap candidates;
   - configured bootstrap peers remain available through the existing fallback path;
   - the skip is logged with observed and configured age.
4. The node refreshes the snapshot during normal running at the configured DHT refresh cadence, with a one-minute lower bound to prevent a hot write loop from unusually short refresh settings.
5. The first periodic tick occurs after one full interval. The existing post-bootstrap save remains the initial snapshot.
6. Periodic persistence has a dedicated cancellation token and tracked task handle. Shutdown cancels and joins that task before performing the final authoritative snapshot, preventing a late periodic write from racing the shutdown save.
7. Existing atomic temp-file persistence and fail-soft startup behaviour remain unchanged. A load or save error is logged and does not stop node startup or shutdown.

The cache remains local advisory bootstrap material. This ADR does not make cached records signed, encrypted, remotely supplied, or a substitute for configured bootstrap peers and live DHT discovery.

## Consequences

### Positive

- Restart does not prioritise indefinitely old peer and trust state by default.
- Long-running nodes refresh the cache without relying on graceful shutdown.
- The final shutdown snapshot cannot be replaced by a concurrent periodic write.
- Operators can identify stale-cache rejection directly in logs.
- Existing configurations that omit the new field receive a safe one-hour default.
- Operators can explicitly retain legacy no-TTL behaviour when required.

### Negative

- Enabling a cache directory now creates one additional lightweight Tokio task.
- Normal operation performs one small atomic JSON write per DHT refresh interval.
- The one-hour default is an operational policy rather than a proof that every cached peer remains reachable.
- Wall-clock correction can temporarily affect age classification.

### Neutral

- A fresh cached peer can still be offline. Existing bootstrap fallback handles failed cache dials.
- Stale cache files are retained on disk and may be replaced by later successful periodic or shutdown saves; they are not deleted merely because they are stale.
- Cache confidentiality and tamper resistance remain out of scope because the file contains peer addresses and advisory trust state, not node secret keys.

## Alternatives Considered

### Keep save-on-bootstrap and save-on-shutdown only

Rejected because ungraceful exit after a long-running session can retain an old snapshot indefinitely.

### Check filesystem modification time

Rejected because the persisted timestamp travels with the snapshot semantics and is deterministic in tests; file metadata can change during copy or restore.

### Validate every cached peer before admitting it

Rejected as unnecessary duplication. Existing bootstrap dial and identity validation already verify reachability and identity, then fall through to configured peers.

### Import stale trust but skip stale peers

Rejected because one snapshot should have one validity decision. Importing stale trust can influence routing and swap decisions even when the same peer set is considered too old for bootstrap.

### Abort periodic writes without joining

Rejected because an in-flight periodic save could complete after the final shutdown save and replace it with an older snapshot.

## References

- [V2-884: Age-bound and refresh the saorsa-core close-group bootstrap cache](https://linear.app/autonominetwork/issue/V2-884/age-bound-and-refresh-the-saorsa-core-close-group-bootstrap-cache)
- [V2-864: Production pruning/bootstrap investigation](https://linear.app/autonominetwork/issue/V2-864/pruning-defers-100-of-candidates-in-production-no-disk-space-is-ever-reclaimed)
- [ADR-008: Bootstrap Peer Discovery Scope](./ADR-008-bootstrap-delegation.md)
- `src/bootstrap/cache.rs`
- `src/network.rs`
