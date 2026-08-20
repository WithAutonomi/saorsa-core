# ADR-018: Runtime Re-bootstrap Must Be Able to Recover

## Status

Proposed

## Context

`maybe_rebootstrap` is the routing table's runtime repair mechanism: when the
table falls below `AUTO_REBOOTSTRAP_THRESHOLD` (3), it re-seeds via FIND_NODE
against currently connected peers, rate-limited by a five-minute cooldown. Two
of its paths were dead ends — states the repair fired from but could never
leave:

1. **Full isolation.** With zero connections there is nothing to gossip from,
   and the repair returned early. Nothing at runtime ever re-dialed the
   *configured* bootstrap peers — only process startup does that — so a node
   that lost its last connection could only recover by being restarted.
2. **Client-mode starvation.** `bootstrap_from_peers` skipped every
   gossiped-peer dial in client mode (clients dial on demand). But
   routing-table admission is connection-driven (`handle_peer_connected`), so
   a starved client rediscovered the same peers every cycle, dialed none of
   them, and stayed starved. The repair could not, by construction, affect
   its own exit condition.

Both dead ends are observed, not theoretical. A mainnet daemon
(WithAutonomi/ant-sdk#232) sat at routing table size 0 for ~34 hours while
auto-re-bootstrap ran continuously; a restart recovered it immediately. In a
controlled reproduction, a client held 10 identity-verified connections while
its table sat pinned below threshold for 10+ hours across 98 repair cycles —
each one logging `Auto re-bootstrap discovered 10 peers`, because the success
metric counted gossip seen rather than admissions gained.

## Decision

Make the repair able to reach its own exit condition in both states, without
changing what routing-table membership means.

1. **Zero-connections fallback.** When no peers are connected,
   `maybe_rebootstrap` re-dials the configured bootstrap peers — the same
   seeds initial startup uses — and proceeds with whatever connects. Only if
   all of them are unreachable does it give up until the next cooldown.
2. **Starved clients dial.** In client mode, `bootstrap_from_peers` dials
   gossiped peers while the routing table is below the threshold, stopping as
   soon as it clears. Non-starved clients keep the existing skip — the
   ADR-017 §8 rationale (clients don't serve the DHT) is untouched; this only
   restores the client's ability to answer its *own* lookups and report its
   own health. Admission runs asynchronously on the peer-connected event, so
   the size check can lag a dial and over-dial slightly; that is harmless and
   bounded by the gossip set.
3. **Honest observability.** The completion log now reports the routing-table
   size after repair alongside the discovered count, and
   `AUTO_REBOOTSTRAP_THRESHOLD` is public so consumers reporting network
   health (e.g. a daemon `/health` showing "0 of 3") use the same floor the
   DHT repairs toward.
4. **`maybe_rebootstrap` is public.** Daemons gain a manual recovery hook
   (e.g. behind an admin endpoint). The threshold and cooldown checks make an
   extra call cheap and safe.

## Alternatives considered

- **Admit connected, identity-verified peers into the routing table
  directly.** Rejected as broader than the defect: admission policy
  (user-agent gating, IP-diversity, trust-aware swap) is deliberate, and
  changing when peers *qualify* is a different decision from making the
  repair able to dial at all.
- **Insert gossiped peers without dialing.** Rejected: gossip must not grant
  routing-table membership without identity verification through the dial
  path — the same principle as ADR-017 §5.
- **Leave recovery to a supervisor restart.** Rejected: it treats a
  recoverable transport state as fatal, and field experience shows operators
  discover the state only after user-visible write failures.
- **Futility detection for structurally capped tables.** On single-host
  devnets, same-IP diversity caps can pin the table below the threshold
  permanently, so the repair fires every cooldown forever. Deferred: the
  cooldown already bounds the cost, and detecting "cannot possibly reach
  threshold" needs admission-policy introspection that doesn't exist yet.

## Consequences

- Fully isolated nodes and starved clients now recover at runtime; the
  reporter's restart-only failure mode is closed.
- Dial rate increases only for nodes already below the threshold, bounded by
  the gossip set size and the five-minute cooldown.
- New public API: `AUTO_REBOOTSTRAP_THRESHOLD` and
  `DhtNetworkManager::maybe_rebootstrap` (semver: feature).
- `tests/client_rebootstrap.rs` holds regression tests for both dead ends,
  verified to fail against the previous behavior.
