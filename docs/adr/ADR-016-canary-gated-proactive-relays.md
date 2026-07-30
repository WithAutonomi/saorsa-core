# ADR-016: Canary-Gated Proactive Relays

## Status

Accepted

Supersedes [ADR-014](./ADR-014-proactive-relay-first-nat-traversal.md).

## Context

ADR-014 described an earlier relay-first design. The implementation evolved in
several important ways:

- a relay allocation must not be published merely because the requesting node
  can establish it;
- a canary witness must not be allowed to dial an arbitrary requester-chosen
  address;
- a canary dial must not reuse or disconnect a live application connection;
- relay state changes and network teardown must not block one another behind a
  lifecycle mutex; and
- close-group churn is a replication concern, not evidence that a healthy
  relay should be replaced.

This ADR records the implemented model and replaces the contradictory
thresholds, capacity limits, and maintenance behavior in ADR-014.

## Decision

### Relay acquisition and publication

Every non-client node may walk suitable routing-table peers and prepare one
proactive MASQUE allocation. Preparation creates a dedicated relay control
connection and a separate Quinn endpoint, but the allocation remains
provisional and absent from the node's published address set.

The relay signs an allocation receipt over:

- the authenticated target peer ID;
- the authenticated relayer peer ID;
- the allocated public socket address;
- the relay-server allocation identifier; and
- an expiry time.

The target asks three randomized, non-close witnesses to probe the provisional
address. A witness first verifies the signed receipt and all request bindings.
It then opens a fresh one-shot authenticated QUIC connection which never enters
ordinary peer, address, or dial-deduplication maps. The witness closes only that
owned probe connection and reports whether the authenticated target identity
matched.

Admission requires three positive witness results. One explicit
canary-capable failure rejects the provisional allocation.

During the mixed-version rollout, a request that was successfully sent to a
selected witness but receives no canary-protocol response before the response
deadline counts as an assumed positive result. This preserves the pre-canary
behavior until that witness upgrades. This compatibility rule is deliberately
limited to the response stage: failure to connect to a selected witness and an
explicit rate-limit response remain ineligible; neither is promoted to
success. An assumed result is logged separately from a confirmed probe.

The implementation still requires three selectable non-close witnesses and
intentionally has no sparse-network threshold or replacement sampling.

Canary work has its own concurrency semaphore, plus per-source, node-wide, and
per-destination rate limits. These budgets are consumed after inexpensive
source/address validation but before ML-DSA receipt verification, so invalid
receipts cannot create unmetered cryptographic work. Canary work does not
consume the general DHT handler budget.

### Established-relay maintenance

The node polls local tunnel health every five seconds and repeats independent
third-party canary verification every minute, with deterministic initial
jitter. Maintenance accepts two positive witness results, including temporary
assumed-positive legacy results, and rejects on two explicit canary-capable
failures. An inconclusive maintenance round retains the relay and retries after
fifteen seconds. A rejected round withdraws the relay immediately; it is not
confirmed by a second round.

Tunnel death, explicit canary rejection, or an explicit trust/quality decision
may replace a relay. A healthy established relay remains in place when the
K-closest set changes. Close-group changes only publish the current
authoritative address set to peers newly entering the replication set.

### Publication and teardown ordering

On relay loss, local published-relay state is cleared first. DHT withdrawal and
transport teardown then run concurrently, so neither waits for the other.
Relay allocation resources are owned by a small lifecycle actor. The actor
serializes short state transitions; relay acquisition and teardown awaits run
outside it. Generation numbers prevent a late acquisition or canary verdict
from acting on a superseding allocation. Every owned allocation carries a
synchronous cleanup guard: if a lifecycle reply or graceful teardown future is
cancelled, dropping the owner closes the endpoint, aborts the tunnel tasks, and
removes the matching relay session.

Candidate `ADD_ADDRESS` advertisements are allowed while an allocation is
absent or provisional and suppressed only after the relay reaches the
`Published` state. Relay publication itself is owned by the authenticated,
sequenced DHT address-set path. Saorsa-core therefore does not forward or drain
transport `PeerAddressUpdated` events.

### Capacity and address-family ownership

Public relay servers accept at most four active relay clients. A prepared
allocation must preserve the address family of the selected relay path. A
mismatch is aborted through the same transport-stack owner that created it and
is returned as an error; later publication and teardown never redispatch an
allocation to a different stack.

### Packaging

Dependency versioning and release packaging are managed separately by the
release process and are not decided here.

## Consequences

- Published relay addresses are bound to allocations actually issued to the
  requester. They have independent external evidence when selected witnesses
  support canaries; during mixed-version rollout an unsupported selected
  witness temporarily contributes assumed-positive compatibility credit.
- Canary traffic cannot tear down shared application/DHT connections.
- Sybil identities alone cannot turn witnesses into arbitrary reflected
  dialers, and canary work cannot exhaust the general handler pool.
- Healthy relay sessions avoid churn when routing-table responsibility moves.
- DHT withdrawal begins without waiting for local transport shutdown.
- Mixed-version witnesses do not block admission merely because they lack the
  canary protocol; their missing protocol response is temporarily counted as
  positive.
- Routing tables with fewer than three selectable non-close witnesses can
  still produce inconclusive admission.
- The signed receipt adds several kilobytes of ML-DSA public-key and signature
  material to each canary request.
