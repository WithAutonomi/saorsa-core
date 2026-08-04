# ADR-016: Canary-Gated Proactive Relays

## Status

Accepted

Supersedes [ADR-014](./ADR-014-proactive-relay-first-nat-traversal.md).

## Context

ADR-014 described an earlier relay-first design. The implementation evolved in
several important ways:

- a relay allocation must not be published merely because the requesting node
  can establish it;
- the canary protocol is necessarily a bounded public dial service, so its
  abuse controls must not depend on a requester-supplied proof that the
  requester can mint for itself;
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

The target asks three randomized, non-close witnesses to probe the provisional
address using the unreleased `relay-canary-v1` request/response protocol. The
request contains the target peer ID, public relay socket, and an hourly witness
eligibility epoch. Its ordinary signed transport envelope must authenticate as
the same target peer ID, so a node can request a probe only for its own
identity.

Witness eligibility is deterministic and independent of the requested
address. A domain-separated BLAKE3 hash of the target peer ID, witness peer ID,
and eligibility epoch must have its first two bits clear. This assigns roughly
one quarter of witnesses to a target for an hour and prevents a requester from
recruiting the whole routing table for one identity. A witness accepts the
current or immediately previous epoch to tolerate an hour boundary; requesters
use the current epoch and filter candidates before selecting three randomized,
non-close witnesses.

After validating the request, an eligible witness opens a fresh one-shot
authenticated QUIC connection which never enters ordinary peer, address, or
dial-deduplication maps. The witness closes only that owned probe connection.
The wire response is deliberately coarse: success, failure, or rate limited.
Detailed dial and identity failures remain local debug information rather than
turning the protocol into a richer port-scanning oracle.

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

Canary work has its own four-permit concurrency semaphore and hourly limits.
Before starting a dial, each witness consumes all of these budgets:

- at most 4 probes per authenticated target peer ID;
- at most 20 probes per transport source IPv4 address or IPv6 `/64` prefix;
- at most 4 probes per destination socket;
- at most 20 probes per destination IP address; and
- at most 60 probes in total on that witness.

The limits are intentionally redundant. Ephemeral identities cannot bypass the
source-network or witness-wide limits, while rotating destination ports cannot
bypass the destination-IP limit. The source IP is taken from the authenticated
transport connection, never from request data. Validation and budgets happen
before any canary-triggered network acquisition. Canary work does not consume
the general DHT handler budget and does not retry a failed cold dial. Replayed
requests consume the same hourly budgets as new requests.

### Established-relay maintenance

The node polls local tunnel health every five seconds and repeats independent
third-party canary verification every two hours, with deterministic initial
jitter spread across a full interval. The slower external cadence is
intentional: admission already proved reachability, tunnel loss is detected by
the cheap local health path, and every canary round creates three witness
requests plus three fresh PQC relay handshakes. The two-hour interval avoids
continuous fleet-wide dial pressure and remains comfortably inside the hourly
witness budgets.

Maintenance accepts two positive witness results, including temporary
assumed-positive legacy results, and rejects on two explicit canary-capable
failures. An inconclusive maintenance round retains the relay and waits for the
ordinary two-hour interval; immediately retrying unavailable witnesses would
amplify a partial outage. A rejected round withdraws the relay immediately; it
is not confirmed by a second round.

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

- Published relay addresses have independent external reachability evidence
  when selected witnesses support canaries; during mixed-version rollout an
  unsupported selected witness temporarily contributes assumed-positive
  compatibility credit.
- Canary traffic cannot tear down shared application/DHT connections.
- A malicious node can ask eligible witnesses to attempt a connection to an
  unrelated public address, but the authenticated-self rule, deterministic
  witness assignment, hourly peer/source/destination/global limits, and
  isolated concurrency budget strictly bound that service. Canary work cannot
  exhaust the general handler pool.
- Healthy relay sessions avoid churn when routing-table responsibility moves.
- DHT withdrawal begins without waiting for local transport shutdown.
- Mixed-version witnesses do not block admission merely because they lack the
  canary protocol; their missing protocol response is temporarily counted as
  positive.
- Routing tables with fewer than three selectable non-close witnesses can
  still produce inconclusive admission.
- Canary requests carry no allocation receipt. This removes untrusted
  self-signed proof material and several kilobytes of redundant ML-DSA key and
  signature data from every request.
