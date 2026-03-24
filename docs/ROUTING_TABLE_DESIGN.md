# Routing Table Logic Specification (Codebase-Agnostic)

> Status: Design-level specification for pre-implementation validation.

## 1. Purpose

This document specifies routing table behavior as a pure system design, independent of any language, framework, transport, or existing codebase.
It is designed for a Kademlia-style decentralized network with trust-weighted peer management, and assumes Kademlia nearest-peer routing semantics.

Primary goal: validate correctness, safety, and liveness of routing table logic before implementation.

The routing table is a **peer phonebook** — it tracks who is on the network and how to reach them. Higher-level concerns such as data storage responsibility, replication, close group semantics, and quorum math are the API consumer's responsibility (e.g., saorsa-node). The routing table exposes `find_closest_nodes_local(K, count)` and `find_closest_nodes_network(K, count)` as generic primitives; the consumer passes whatever `count` it needs.

## 2. Scope

### In scope

- Kademlia routing table structure, peer admission, eviction, and maintenance.
- Trust-aware peer management and Sybil resistance via IP diversity.
- Iterative and local peer lookup algorithms.
- Close neighborhood maintenance for routing correctness.

### Out of scope

- Concrete wire formats and RPC APIs.
- Data storage, replication, close group semantics, and quorum logic (consumer-side).
- EigenTrust scoring algorithm internals (consumed as an oracle).
- Transport-layer connection management and NAT traversal.
- Disk layout, serialization details, and database choices.

## 3. System Model

- `Node`: participant with a persistent 256-bit identity (`PeerId`), one or more reachable network addresses, and a local routing table.
- `PeerId`: 256-bit cryptographic identity. Used directly as the DHT key for the node's position in the keyspace. No secondary hashing — `DhtKey ≡ PeerId`.
- `Address`: typed multiaddress (e.g., `/ip4/1.2.3.4/udp/9000/quic`). A node may have up to `MAX_ADDRESSES_PER_NODE` addresses (multi-homed, NAT traversal).
- `NodeInfo(N)`: record containing `PeerId`, address list, and `last_seen` timestamp for node `N`.
- `Distance(A, B)`: XOR of the 256-bit representations of `A` and `B`, compared as big-endian unsigned integers.
- `BucketIndex(A, B)`: index of the first bit position (0-indexed from MSB) where `A ⊕ B` differs. Equal IDs have no bucket index (self-insertion is forbidden).
- `KBucket(i)`: the `i`-th k-bucket (0 ≤ `i` < 256), holding up to `K_BUCKET_SIZE` `NodeInfo` entries for peers whose `BucketIndex` relative to the local node is `i`.
- `LocalRT(N)`: node `N`'s authenticated local routing-table peer set. Union of all k-bucket contents, excluding `N` itself.
- `TrustScore(N, P)`: node `N`'s current trust assessment of peer `P`, queried from the EigenTrust subsystem.

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference |
|---|---|---|
| `K_BUCKET_SIZE` | Maximum number of peers per k-bucket | `20` |
| `MAX_ADDRESSES_PER_NODE` | Maximum addresses stored per node | `8` |
| `BUCKET_COUNT` | Number of k-buckets (one per bit in keyspace) | `256` |
| `ALPHA` | Parallel queries per iteration in network lookups | `3` |
| `MAX_LOOKUP_ITERATIONS` | Maximum iterations for iterative network lookups | `20` |
| `IP_EXACT_LIMIT` | Maximum nodes sharing an exact IP per enforcement scope | `2` |
| `IP_SUBNET_LIMIT` | Maximum nodes sharing a subnet per enforcement scope | `K_BUCKET_SIZE / 4` (at least `1`) |
| `IPV4_SUBNET_MASK` | Prefix length for IPv4 subnet grouping | `/24` |
| `IPV6_SUBNET_MASK` | Prefix length for IPv6 subnet grouping | `/64` |
| `TRUST_PROTECTION_THRESHOLD` | Trust score above which a peer resists swap-closer eviction | `0.7` |
| `BLOCK_THRESHOLD` | Trust score below which a peer is evicted and blocked | `0.15` |
| `SELF_LOOKUP_INTERVAL` | Periodic self-lookup cadence | random in `[5 min, 10 min]` |
| `BUCKET_REFRESH_INTERVAL` | Periodic refresh cadence for stale k-buckets | `10 min` |
| `STALE_BUCKET_THRESHOLD` | Duration after which a bucket without activity is considered stale | `1 hour` |
| `LIVE_THRESHOLD` | Duration of no contact after which a peer is considered stale for revalidation and loses trust protection | `15 min` |

Parameter safety constraints (MUST hold):

1. `IP_EXACT_LIMIT >= 1`.
2. `IP_SUBNET_LIMIT >= 1`.
3. `TRUST_PROTECTION_THRESHOLD > BLOCK_THRESHOLD`.
4. `ALPHA >= 1`.
5. `LIVE_THRESHOLD > max(SELF_LOOKUP_INTERVAL)` (peers touched by self-lookup must not oscillate between live and stale between consecutive cycles; at reference values: 15 min > 10 min).
6. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.

## 5. Core Invariants (Must Hold)

1. **Self-exclusion**: A node MUST NOT appear in its own routing table (`LocalRT(N)` never contains `N`).
2. **Bucket correctness**: A peer `P` exists in exactly one k-bucket of node `N`, at index `BucketIndex(N, P)`.
3. **Capacity bound**: Each k-bucket holds at most `K_BUCKET_SIZE` entries.
4. **Address requirement**: A `NodeInfo` with an empty address list MUST NOT be admitted to the routing table.
5. **Authenticated membership**: Only peers that have completed transport-level authentication are eligible for routing table insertion. Unauthenticated peers MUST NOT enter `LocalRT`.
6. **IP diversity**: No enforcement scope (per-bucket or close-group) may exceed `IP_EXACT_LIMIT` nodes per exact IP or `IP_SUBNET_LIMIT` nodes per subnet, except via explicit loopback or testnet overrides.
7. **Trust blocking**: Peers with `TrustScore(self, P) < BLOCK_THRESHOLD` MUST be evicted from the routing table and MUST NOT be re-admitted until their trust score recovers above `BLOCK_THRESHOLD`.
8. **Trust protection (staleness-gated)**: A peer with `TrustScore(self, P) >= TRUST_PROTECTION_THRESHOLD` **AND** `last_seen` within `LIVE_THRESHOLD` MUST NOT be evicted by swap-closer admission. A peer whose `last_seen` exceeds `LIVE_THRESHOLD` receives no trust protection regardless of score — stale peers MUST NOT hold slots against live candidates.
9. **Deterministic distance**: `Distance(A, B)` is symmetric, deterministic, and consistent across all nodes. Two nodes compute the same distance between the same pair of keys.
10. **Atomic admission**: IP diversity checks, capacity checks, swap-closer evictions, and insertion MUST execute within a single write-locked critical section to prevent TOCTOU races.
11. **Monotonic liveness**: `touch_node` updates `last_seen` to the current time and moves the peer to the tail (most recently seen) of its k-bucket. This preserves Kademlia's eviction preference for long-lived peers.
12. **Lookup determinism**: Two nodes with identical `LocalRT` contents compute identical `find_closest_nodes_local(K, count)` results for any key `K` and count. Disagreements between nodes are caused only by routing table divergence, never by algorithm divergence.

## 6. Routing Table Structure

### 6.1 K-Bucket Array

The routing table is an array of `BUCKET_COUNT` (256) k-buckets, indexed 0 through 255.

Each k-bucket `KBucket(i)` stores up to `K_BUCKET_SIZE` `NodeInfo` entries for peers whose XOR distance from the local node has a leading bit position of `i`. Bucket 0 holds the most distant half of the keyspace (peers differing in the MSB), bucket 255 holds the closest peers (differing only in the LSB).

Within each k-bucket, entries are ordered by recency: the most recently seen peer is at the tail. This ordering governs eviction preference — head-of-bucket peers are evicted first when swap-closer admits a new peer.

### 6.2 Bucket Index Computation

For local node `N` and candidate peer `P`:

1. Compute `D = N.id ⊕ P.id` (256-bit XOR).
2. Find the position of the first set bit in `D`, scanning from MSB (bit 0) to LSB (bit 255).
3. That position is `BucketIndex(N, P)`.
4. If `D = 0` (identities are equal), insertion is rejected (Invariant 1).

Property: lower bucket indices correspond to more distant peers. A node has at most 1 bucket-0 peer (the farthest half of the keyspace is sparsely covered), but may fill buckets near 255 with many close peers.

### 6.3 NodeInfo Lifecycle

A `NodeInfo` entry tracks:

- `PeerId`: immutable after creation.
- `addresses`: mutable list of up to `MAX_ADDRESSES_PER_NODE` multiaddresses, ordered by recency (most recent first).
- `last_seen`: timestamp of last successful interaction.

Address management rules:

1. When a known peer is contacted on a new address, that address is prepended to the list. If the address already exists, it is moved to the front.
2. The list is truncated to `MAX_ADDRESSES_PER_NODE` after each update.
3. The first address in the list is the preferred dial address.

## 7. Peer Admission

### 7.1 Admission Flow

When a candidate peer `P` with `NodeInfo` and IP address `candidate_ip` is presented for insertion:

1. **Self-check**: If `P.id == self.id`, reject.
2. **Address check**: If `P.addresses` is empty, reject.
3. **Authentication check**: If `P` has not completed transport-level authentication, reject.
4. **Trust block check**: If `TrustScore(self, P) < BLOCK_THRESHOLD`, reject.
5. **Loopback check**: If `candidate_ip` is loopback and loopback is disallowed, reject. If loopback is allowed, skip all IP diversity checks (step 6–7) and proceed directly to step 8.
6. **Non-IP transport bypass**: If `P` has no IP-based address (e.g., Bluetooth, LoRa), skip IP diversity checks and proceed directly to step 8.
7. **IP diversity enforcement** (under write lock — Invariant 10):
   a. Compute `bucket_idx = BucketIndex(self, P)`.
   b. Run per-bucket IP diversity check (Section 7.2) against nodes in `KBucket(bucket_idx)`.
   c. Run close-group IP diversity check (Section 7.2) against the hypothetical close group to self (the `K_BUCKET_SIZE` closest peers to self, including `P` and excluding any bucket-swap candidates).
   d. Deduplicate swap candidates from steps (b) and (c).
8. **Capacity pre-check**: Verify that one of these holds for `KBucket(bucket_idx)`:
   - `P` already exists in the bucket (update path).
   - The bucket has fewer than `K_BUCKET_SIZE` entries.
   - A swap candidate from step 7 frees a slot in this bucket.
   If none holds, attempt stale peer revalidation (Section 7.5). If revalidation frees at least one slot, proceed. If no slots freed, reject with "bucket at capacity."
9. **Execute swaps**: Remove all deduplicated swap candidates.
10. **Insert**: Add `P` to `KBucket(bucket_idx)`.

If `P` already exists in the bucket, the existing entry is updated (addresses merged, `last_seen` refreshed) rather than creating a duplicate.

### 7.2 IP Diversity Enforcement

IP diversity is checked per scope (a set of `NodeInfo` entries: either a single k-bucket or the K-closest-to-self set). For a candidate with `candidate_ip`:

**Exact IP check:**

1. Count nodes in scope whose IP matches `candidate_ip` exactly.
2. If count `>= IP_EXACT_LIMIT`, attempt swap-closer (Section 7.3).

**Subnet check:**

1. Mask `candidate_ip` to the configured prefix length (`/24` for IPv4, `/64` for IPv6).
2. Count nodes in scope whose masked IP matches the candidate's masked IP.
3. If count `>= IP_SUBNET_LIMIT`, attempt swap-closer (Section 7.3).

Both checks apply independently. If either fails, the candidate is rejected (unless swap-closer succeeds).

### 7.3 Swap-Closer Eviction

When an IP diversity limit is exceeded and a candidate `P` contends for a slot:

1. Among the nodes in scope that share the candidate's IP or subnet (the "violating set"), find the one farthest from the scope's reference point (the local node's ID for close-group scope, or the local node's ID for bucket scope — both use XOR distance to self).
2. Let `V` be that farthest violating peer.
3. If `Distance(self, P) < Distance(self, V)` **AND** (`TrustScore(self, V) < TRUST_PROTECTION_THRESHOLD` **OR** `now - V.last_seen > LIVE_THRESHOLD`):
   - Swap: evict `V`, admit `P`.
4. Otherwise: reject `P`. Live, well-trusted peers hold their slot.

Rationale: swap-closer prefers geographically closer peers (lower XOR distance) while protecting long-lived, recently-seen, well-trusted peers from displacement by unproven newcomers from the same subnet. A peer that has not been seen within `LIVE_THRESHOLD` loses trust protection regardless of its score — it may have silently departed, and holding its slot against a live candidate degrades routing table quality.

### 7.4 Blocked Peer Handling

When any interaction records a trust failure and `TrustScore(self, P)` drops below `BLOCK_THRESHOLD`:

1. Remove `P` from `LocalRT(self)`.
2. Disconnect `P` at the transport layer.
3. Silently drop any incoming DHT messages from `P`.
4. Do not re-admit `P` until `TrustScore(self, P) >= BLOCK_THRESHOLD`.

Blocking is enforced at the routing table layer. API consumers can rely on `LocalRT` membership as the trust gate.

### 7.5 Stale Peer Revalidation on Admission Contention

When a candidate `P` is presented for admission but `KBucket(bucket_idx)` is at capacity and neither the update path, IP diversity swap, nor available capacity can accommodate `P`:

1. Collect all peers `S` in `KBucket(bucket_idx)` where `now - S.last_seen > LIVE_THRESHOLD`.
2. If the stale set is empty: no slots can be freed. Reject `P`.
3. **Ping all stale peers in parallel** (bounded timeout, e.g., 5 seconds).
4. For each peer that responds: `touch_node(S)`, record `SuccessfulResponse` trust event. `S` retains its slot.
5. For each peer that fails to respond: record `ConnectionFailed` trust event, evict `S` from the bucket.
6. If any slots were freed: proceed with admission of `P` (step 9 of Section 7.1).
7. If no slots were freed (all stale peers responded): reject `P` with "bucket at capacity."

The same mechanism applies to close-group IP diversity enforcement (Section 7.2): when a close-group IP diversity violation is detected and the violating peers include stale entries, ping all stale violating peers before deciding whether swap-closer is needed.

**Design rationale**: this is a reactive liveness mechanism inspired by original Kademlia's ping-on-insert design, adapted with a staleness threshold (BEP 5's "questionable" concept). Unlike proactive background pinging (Ethereum discv5's revalidation loop) or connection-state tracking (libp2p), it incurs zero network overhead when there is no admission contention. The cost is paid only when a real candidate needs a slot and an incumbent has not been seen recently — exactly the moment when liveness information has the most value.

Pinging all stale peers in the bucket (not just one) revalidates the entire bucket's stale set in a single contention event, freeing multiple slots if several peers have departed. This avoids repeated single-peer probes across successive admission attempts.

**Latency impact**: stale revalidation adds up to one ping timeout (e.g., 5 seconds) to the admission path, but only when the bucket is full AND contains stale peers AND no other admission path (update, capacity, swap) succeeds. In a healthy network where peers interact regularly, most peers remain within `LIVE_THRESHOLD` and this path is never triggered.

## 8. Peer Lookup

### 8.1 Local Lookup: `find_closest_nodes_local`

Returns the `count` nearest nodes to a key `K` from `LocalRT(self)` without network requests.

Algorithm:

1. Collect all entries from all k-buckets, computing `Distance(K, entry)` for each.
2. Sort all collected candidates by `Distance(K, candidate)`.
3. Return the top `count`.

Note: bucket index correlates with distance from self, not distance from key `K`. Peers in buckets far from `BucketIndex(self, K)` in the spiral can still be closer to `K` than peers in nearby buckets. The routing table holds at most `BUCKET_COUNT * K_BUCKET_SIZE` (5,120) entries, so a full scan and sort is trivially fast.

Properties:
- Read-only: no write lock, safe to call from request handlers.
- Excludes self (Invariant 1).
- Deterministic: same routing table state produces same result.

### 8.2 Network Lookup: `find_closest_nodes_network`

Iterative Kademlia lookup that queries remote peers to refine the closest set.

Algorithm:

1. Seed `best_nodes` with results from `find_closest_nodes_local(K, count)`.
2. Include self in `best_nodes` (self competes on distance but is never queried).
3. Mark self as "queried" to prevent self-RPC.
4. Loop (up to `MAX_LOOKUP_ITERATIONS`):
   a. Select up to `ALPHA` unqueried peers from `best_nodes`, nearest first.
   b. Query each in parallel with `FIND_NODE(K)`.
   c. For each response, record trust outcome (`SuccessfulResponse` or `ConnectionFailed`/`ConnectionTimeout`).
   d. Merge returned peers into `best_nodes`, deduplicating by `PeerId`.
   e. Sort `best_nodes` by `Distance(K, node)`, truncate to `count`.
   f. Convergence check: if no new closer node was discovered in this iteration (the closest peer in `best_nodes` is unchanged), increment a stagnation counter. Stop when stagnation reaches 3 or all candidates have been queried.
5. Return `best_nodes` (may include self).

Properties:
- Makes network requests: MUST NOT be called from within DHT request handlers (deadlock risk).
- Trust recording: each RPC outcome is fed to the trust subsystem.
- Blocked peers: silently excluded from query candidates (they are not in `LocalRT`).

## 9. Routing Table Maintenance

### 9.1 Touch on Interaction

Any successful RPC (inbound or outbound) with a peer `P` triggers `touch_node(P)`:

1. If `P` is in the routing table: update `last_seen` to now, optionally merge the address used, move `P` to the tail of its k-bucket.
2. If `P` is not in the routing table: no action (touch is not an admission path). Re-admission of evicted peers happens only through the normal admission flow — either via a new inbound connection (Section 10.2) or via discovery during a network lookup.

This ensures Kademlia's preference for long-lived peers: recently-active peers move to the tail, and head-of-bucket peers become eviction candidates. It also prevents evicted peers from silently re-entering the routing table by sending RPCs, which would bypass IP diversity and trust checks.

`touch_node` is the sole mechanism that keeps a peer in "live" state (i.e., `last_seen` within `LIVE_THRESHOLD`). A peer that is not touched for longer than `LIVE_THRESHOLD` becomes stale, loses trust protection (Invariant 8), and becomes eligible for revalidation-based eviction on admission contention (Section 7.5).

### 9.2 Self-Lookup for Close Neighborhood Freshness

Nodes MUST periodically perform a network lookup for their own `PeerId` to discover new close peers.

1. On a randomized timer (`SELF_LOOKUP_INTERVAL`), run `find_closest_nodes_network(self.id, K_BUCKET_SIZE)`.
2. For each discovered peer not already in `LocalRT(self)`, attempt admission via the full admission flow (Section 7.1).
3. This keeps the close neighborhood current under churn, which is critical for routing correctness and for API consumers that depend on accurate nearest-peer queries.

### 9.3 Bucket Refresh

Buckets that have not been touched (no node in the bucket updated via `touch_node`) for longer than `STALE_BUCKET_THRESHOLD` are considered stale.

On a periodic timer (`BUCKET_REFRESH_INTERVAL`):

1. For each stale bucket `i`:
   a. Generate a random key `K` that would land in bucket `i` (a key whose XOR with `self.id` has its leading set bit at position `i`).
   b. Perform `find_closest_nodes_network(K, K_BUCKET_SIZE)`.
   c. Attempt to admit discovered peers.
2. Mark the bucket as refreshed.

Purpose: Kademlia requires periodic refresh to maintain routing table completeness. Stale buckets in distant parts of the keyspace would otherwise lose all entries to churn without replacement.

### 9.4 Routing Table Event Notifications

The routing table MUST emit events on membership changes to allow consumers to react without polling:

| Event | Trigger |
|---|---|
| `PeerAdded(PeerId)` | New peer inserted into routing table |
| `PeerRemoved(PeerId)` | Peer evicted, blocked, or departed |
| `KClosestPeersChanged { old, new }` | Composition of the `K_BUCKET_SIZE`-closest peers to self changed |

`KClosestPeersChanged` is emitted when a routing table mutation (admission, eviction, or swap) causes the set of `K_BUCKET_SIZE` nearest peers to self to differ from the pre-mutation set. The routing table snapshots the K-closest set before each mutation and compares after; the event carries both the old and new sets. This fires at most once per mutation, not per swap within a single admission.

Events MUST be emitted reliably for every routing table mutation. Consumers MAY additionally perform periodic recomputation as a defense-in-depth measure, but MUST NOT depend on polling as the primary mechanism.

## 10. Churn Handling

### 10.1 Peer Departure Detection

Peers are detected as departed through:

1. **RPC failure**: Failed outbound RPC records trust failure. If trust drops below `BLOCK_THRESHOLD`, peer is evicted (Section 7.4).
2. **Iterative lookup feedback**: Network lookups record success/failure per queried peer.
3. **Self-lookup refresh**: Periodic self-lookups discover that a previously-close peer is no longer returned by the network.
4. **Stale peer revalidation**: When a new candidate contends for a full bucket, all stale peers (not seen within `LIVE_THRESHOLD`) in that bucket are pinged. Non-responders are evicted immediately (Section 7.5).

The routing table does not run a background ping loop. Liveness is assessed reactively: through actual RPC interactions, trust score changes, and on-demand revalidation during admission contention. This avoids the overhead of proactive health checks (e.g., Ethereum discv5's revalidation loop) while ensuring stale peers are detected at the moment a live replacement is available.

Idle peers that are never contacted and never contended for will decay toward neutral trust (0.5) and lose trust protection after `LIVE_THRESHOLD`, making them displaceable by swap-closer (Invariant 8). Close peers are naturally contacted frequently by lookups and consumer-layer interactions, so silent departures in the close neighborhood are detected quickly through RPC failures and admission contention from self-lookups.

### 10.2 Peer Arrival Handling

New peers enter the routing table through:

1. **Inbound connections**: A new peer connects and completes authentication. After successful handshake, attempt admission.
2. **Iterative lookup discovery**: Network lookups return peers not yet in `LocalRT`. Attempt admission.
3. **Self-lookup discovery**: Periodic self-lookups discover new close peers.
4. **Bootstrap peer seeding**: At startup, bootstrap peers are dialed and their `FIND_NODE(self)` responses seed the routing table.

All paths converge on the same admission flow (Section 7.1), ensuring consistent IP diversity and trust enforcement.

## 11. Bootstrap

### 11.1 Cold Start

A node starting with an empty routing table:

1. Load close group cache from disk (if available) to warm the routing table with previously-known trusted peers and their trust scores.
2. Dial bootstrap peers (well-known, hardcoded or configured).
3. Send `FIND_NODE(self.id)` to each bootstrap peer.
4. Admit returned peers via the standard admission flow.
5. Perform iterative self-lookup to expand close neighborhood.
6. Repeat self-lookup until routing table stabilizes (no new peers discovered for 2 consecutive lookups, or a configured bootstrap timeout is reached).

### 11.2 Warm Restart

A node restarting with a close group cache:

1. Load cached peers and their trust scores into the routing table and trust subsystem.
2. Dial cached peers first (they are likely still alive and nearby).
3. Fall back to bootstrap peers if cached peers are unreachable.
4. Perform iterative self-lookup to update stale entries.

The close group cache (`CloseGroupCache`) stores:

- `K_BUCKET_SIZE` closest peers to self with their addresses and trust records.
- Saved at shutdown, loaded at startup.
- Trust scores are imported without decay for offline time (cannot observe behavior while offline).

## 12. Security Properties

### 12.1 Sybil Resistance via IP Diversity

IP diversity enforcement (Section 7.2) limits the influence of a single operator:

- **Per-bucket**: An attacker controlling one IP can place at most `IP_EXACT_LIMIT` (2) nodes in any single bucket. An attacker controlling a `/24` subnet can place at most `IP_SUBNET_LIMIT` (5) nodes per bucket.
- **Close-group**: The same limits apply to the `K_BUCKET_SIZE` closest peers to self, preventing a single operator from dominating the close neighborhood.
- **Two-scope enforcement**: Both per-bucket and close-group checks must pass. An attacker could fill distant buckets without threatening the close neighborhood, but cannot concentrate nodes near any target.

Limitations:
- An attacker with access to many subnets across diverse providers can still accumulate routing table presence. IP diversity is one layer of defense, complemented by trust scoring and proof-of-work/stake at higher layers.
- VPN and cloud provider ASNs are identifiable (BGP geo provider) but not currently enforced at the routing table level. Future work may add ASN-level diversity.

### 12.2 Eclipse Attack Resistance

An eclipse attack attempts to surround a target node with attacker-controlled peers, isolating it from the honest network.

Defenses:

1. **IP diversity**: Limits attacker concentration per scope (Section 12.1).
2. **Trust protection**: Live, well-trusted peers (score ≥ 0.7, seen within `LIVE_THRESHOLD`) cannot be evicted by swap-closer, even if the attacker generates IDs closer to the target. Stale peers lose this protection — an attacker could displace them, but stale peers are already degrading routing quality and their replacement by any live peer (even an attacker's) is a net improvement for that slot.
3. **Authenticated insertion**: Only transport-authenticated peers enter the routing table. An attacker must complete cryptographic handshakes for each fake identity.
4. **Self-lookup refresh**: Periodic self-lookups discover honest peers that the attacker may be trying to hide.
5. **Close group cache**: On restart, the node reconnects to previously-trusted close peers before the attacker can fill the empty routing table.

### 12.3 Routing Table Poisoning Resistance

An attacker attempts to insert malicious entries via `FIND_NODE` responses:

1. **No blind insertion**: Peers returned by `FIND_NODE` are not automatically added. They must be dialed, authenticated, and pass the admission flow.
2. **Trust baseline**: New peers start at neutral trust (0.5), well above `BLOCK_THRESHOLD` (0.15) but below `TRUST_PROTECTION_THRESHOLD` (0.7). They must demonstrate good behavior to earn protection.
3. **IP diversity gates**: Even if an attacker can authenticate many identities, IP diversity limits prevent flooding.

## 13. Consumer API

The routing table exposes the following queries to consumers (e.g., saorsa-node):

| Query | Input | Output | Description |
|---|---|---|---|
| `find_closest_nodes_local(K, count)` | Key, count | `Vec<NodeInfo>` sorted by distance | Nearest peers from local routing table |
| `find_closest_nodes_network(K, count)` | Key, count | `Vec<NodeInfo>` sorted by distance | Iterative network lookup |
| `is_in_routing_table(P)` | PeerId | bool | Membership check |
| `routing_table_size()` | — | usize | Total peer count |
| `touch_node(P, addr)` | PeerId, optional address | bool | Liveness update on successful interaction |

Consumers MUST NOT:

- Directly read or write k-bucket contents.
- Bypass IP diversity or trust checks when admitting peers.
- Remove peers from the routing table (that is owned by the trust/blocking subsystem).

Consumers MAY:

- Report trust events via the `TrustEvent` interface, which may indirectly cause routing table changes (eviction on block).
- Request network lookups to discover new peers (which may be admitted to the routing table as a side effect).

## 14. Logic-Risk Checklist (Pre-Implementation)

Use this list to find design flaws before coding:

1. **IP diversity deadlock**:
   - In networks where many honest peers share subnets (e.g., all on AWS), can IP diversity limits prevent a node from populating its routing table? `IP_SUBNET_LIMIT = K_BUCKET_SIZE / 4` (5 per subnet per scope) allows 5 AWS peers per bucket, which is substantial. Operators with extreme concentration may need testnet/permissive overrides.

2. **Trust cold-start asymmetry**:
   - New peers start at neutral trust (0.5) and are not protected from swap-closer. A well-established network may be slow to admit new peers if existing peers are all well-trusted (≥ 0.7) and buckets are full. New peers can enter when:
     a. A bucket has capacity, or
     b. An existing peer is below 0.7 trust, or
     c. An existing peer has not been seen within `LIVE_THRESHOLD` (loses trust protection per Invariant 8), or
     d. A stale peer fails revalidation during admission contention (Section 7.5).
   In a stable, healthy network where all incumbents are live and well-trusted, new peers can only enter via (a). This is by design — stable networks resist unnecessary churn.

3. **Self-lookup failure under eclipse**:
   - If an attacker eclipses the self-lookup, the node may not discover honest close peers. Mitigation: cache-based warm restart and multiple independent bootstrap endpoints.

4. **Bucket refresh overhead**:
   - With 256 buckets and high churn, bucket refresh could generate significant network traffic. Mitigation: only stale buckets are refreshed, and the refresh interval is configurable.

5. **Stale `last_seen` and false liveness**:
   - A peer could be in the routing table with a recent `last_seen` (from a `touch_node` on an inbound message) but actually be unreachable for outbound connections. Trust scoring handles this: failed outbound RPCs reduce trust, eventually triggering eviction.

6. **Stale revalidation admission latency**:
   - Stale peer revalidation (Section 7.5) adds up to one ping timeout to the admission path when triggered. In a healthy network this path is rarely hit (most peers are within `LIVE_THRESHOLD`). Under mass churn (many stale peers per bucket), parallel pinging bounds the latency to a single timeout regardless of stale-set size. The timeout should be kept short (e.g., 5 seconds) to limit worst-case admission delay.

7. **Distant stale peers without contention**:
   - A stale peer in a distant, partially-filled bucket may never face admission contention and thus never be revalidated. It will sit at neutral trust (~0.5) indefinitely. This is acceptable: distant peers don't affect close-group accuracy, don't get selected for close-group-based operations, and the slot cost is negligible. Bucket refresh (Section 9.3) may eventually trigger contention if new peers are discovered for that bucket.

8. **Close group cache staleness**:
   - After a long offline period, the close group cache may contain departed peers. Mitigation: warm restart dials cached peers and falls back to bootstrap if they are unreachable. Self-lookup then refreshes the neighborhood.

## 15. Pre-Implementation Test Matrix

Each scenario should assert exact expected outcomes and state transitions.

### Admission Tests

1. **Happy path admission**:
   - Authenticated peer with unique IP, bucket has capacity. Peer is added to correct bucket. `find_closest_nodes_local` returns it at correct distance rank.

2. **Self-insertion rejection**:
   - Attempt to add `self.id` to routing table. Rejected. Routing table unchanged.

3. **Empty address rejection**:
   - Candidate with zero addresses. Rejected with error. Routing table unchanged.

4. **Blocked peer rejection**:
   - Peer with `TrustScore < BLOCK_THRESHOLD`. Rejected. Not in routing table.

5. **Bucket-full rejection (no stale peers)**:
   - Bucket at `K_BUCKET_SIZE` capacity, candidate cannot swap-closer, all incumbent peers have `last_seen` within `LIVE_THRESHOLD`. Stale revalidation finds no candidates. Rejected with "bucket at capacity." Routing table unchanged.

6. **Swap-closer success**:
   - Bucket at capacity, candidate is closer than farthest same-subnet peer (trust < 0.7). Farthest peer evicted, candidate admitted.

7. **Trust-protected swap-closer failure (live peer)**:
   - Same as test 6, but farthest peer has trust ≥ 0.7 AND `last_seen` within `LIVE_THRESHOLD`. Swap rejected. Candidate not admitted.

8. **Exact IP limit enforcement**:
   - Insert `IP_EXACT_LIMIT` peers with same IP. Next peer with same IP rejected unless swap-closer applies.

9. **Subnet limit enforcement**:
   - Insert `IP_SUBNET_LIMIT` peers within same `/24`. Next peer in subnet rejected unless swap-closer applies.

10. **Close-group IP diversity enforcement**:
    - Bucket admits a peer, but it would violate subnet limit in the K-closest-to-self set. Peer triggers close-group swap-closer. If successful, farthest violating peer in close group is evicted.

11. **Loopback bypass**:
    - With loopback allowed, peers on 127.0.0.1 skip all IP diversity checks. Multiple loopback peers admitted up to bucket capacity.

12. **Non-IP transport bypass**:
    - Peer with Bluetooth-only address. IP diversity skipped. Admitted up to bucket capacity.

13. **Duplicate admission (update path)**:
    - Peer already in routing table is re-admitted with new address. Address is merged, `last_seen` updated. No duplicate entry created.

14. **Atomic admission under concurrent access**:
    - Two concurrent admissions targeting the same bucket. Write lock ensures both see consistent state. No TOCTOU: diversity check and insertion are atomic.

### Stale Revalidation Tests

15. **Stale revalidation evicts departed peer**:
    - Bucket at capacity. One peer has `last_seen` older than `LIVE_THRESHOLD`. New candidate arrives. Stale peer is pinged, fails to respond. `ConnectionFailed` trust event recorded. Stale peer evicted. Candidate admitted.

16. **Stale revalidation retains live peer**:
    - Bucket at capacity. One peer has `last_seen` older than `LIVE_THRESHOLD`. New candidate arrives. Stale peer is pinged, responds successfully. `touch_node` called, `SuccessfulResponse` recorded. Stale peer stays (moved to tail). Candidate rejected.

17. **Bulk stale revalidation (multiple stale peers)**:
    - Bucket at capacity with 3 stale peers. New candidate arrives. All 3 pinged in parallel. 2 fail, 1 responds. 2 evicted, 1 stays (moved to tail). Candidate admitted. Bucket now has `K_BUCKET_SIZE - 1` entries (2 freed, 1 filled by candidate).

18. **Stale revalidation not triggered when bucket has capacity**:
    - Bucket has room. Candidate admitted directly. No pings sent, even if existing peers are stale.

19. **Stale revalidation not triggered when swap-closer succeeds**:
    - Bucket at capacity but IP diversity swap-closer frees a slot. Candidate admitted via swap. No stale revalidation pings sent.

20. **Staleness-gated trust protection: swap-closer displaces stale well-trusted peer**:
    - Bucket at capacity. Farthest same-subnet peer has trust ≥ 0.7 but `last_seen` older than `LIVE_THRESHOLD`. Candidate is closer. Swap-closer succeeds — stale peer evicted despite high trust. Candidate admitted.

21. **Staleness-gated trust protection: live well-trusted peer holds slot**:
    - Same as test 20, but farthest peer has `last_seen` within `LIVE_THRESHOLD`. Swap-closer fails — live well-trusted peer holds its slot. Candidate rejected (or proceeds to stale revalidation if other paths exist).

22. **Close-group stale revalidation on IP diversity violation**:
    - Close-group IP diversity check finds violation. Violating peers include stale entries. Stale violating peers pinged. Non-responders evicted from their buckets. Close-group recomputed.

### Lookup Tests

23. **Local lookup correctness**:
    - Insert peers at known distances. `find_closest_nodes_local` returns them in correct XOR distance order.

24. **Local lookup with self-exclusion**:
    - Self is never returned by `find_closest_nodes_local`.

25. **Network lookup convergence**:
    - Mock network with known topology. Iterative lookup converges to the true K-closest peers within `MAX_LOOKUP_ITERATIONS`.

26. **Network lookup records trust**:
    - Successful query records `SuccessfulResponse`. Failed query records `ConnectionFailed` or `ConnectionTimeout`.

27. **Network lookup includes self in result**:
    - Self competes on distance in network lookup results but is never queried.

### Maintenance Tests

28. **Touch moves to tail**:
    - Peer at head of bucket. `touch_node` moves it to tail. Other peers shift forward.

29. **Touch merges address**:
    - Peer touched with new address. New address prepended. Old address retained. List capped at `MAX_ADDRESSES_PER_NODE`.

30. **Self-lookup discovers new close peers**:
    - Peers join network closer to self. Self-lookup discovers them. They pass admission and enter routing table.

31. **Bucket refresh populates stale bucket**:
    - Distant bucket has been idle for > `STALE_BUCKET_THRESHOLD`. Refresh finds peers for that region and populates the bucket.

32. **Blocked peer eviction**:
    - Peer trust drops below 0.15 after failed interaction. Peer is immediately removed from routing table and disconnected.

33. **Blocked peer re-admission after recovery**:
    - Previously blocked peer's trust decays back above 0.15 (idle decay toward 0.5). Peer can now be re-admitted through normal admission flow.

### Bootstrap Tests

34. **Cold start populates routing table**:
    - Empty routing table. Bootstrap peers respond to `FIND_NODE(self)`. Returned peers admitted. Self-lookup expands neighborhood.

35. **Warm restart from cache**:
    - Close group cache loaded. Cached peers dialed successfully. Routing table pre-populated with trusted peers. Self-lookup refines.

36. **Warm restart with stale cache**:
    - All cached peers unreachable. Falls back to bootstrap peers. Routing table eventually populated.

37. **Close group cache save/load roundtrip**:
    - Save K closest peers + trust scores. Restart. Load cache. Trust scores match (no decay for offline time). Addresses preserved.

### Security Tests

38. **IP diversity blocks Sybil cluster**:
    - Attacker attempts to insert 10 peers from one IP. Only 2 admitted per scope. Remaining 8 rejected.

39. **Subnet diversity limits concentration**:
    - Attacker attempts to fill a bucket from one `/24`. At most 5 admitted (K/4). Remaining rejected.

40. **Trust protection prevents eclipse displacement (live peers)**:
    - Attacker generates IDs closer to target. Existing well-trusted peers (≥ 0.7) with `last_seen` within `LIVE_THRESHOLD` hold their slots. Attacker can only displace low-trust, stale, or empty slots.

41. **Stale trust-protected peer displaced by attacker**:
    - Existing well-trusted peer (≥ 0.7) has `last_seen` older than `LIVE_THRESHOLD`. Attacker with closer ID displaces it via swap-closer. This is correct behavior — a stale peer should not block a live candidate, even if the candidate is an attacker. The live candidate will be evaluated on its own behavior going forward.

42. **Unauthenticated peer rejected**:
    - Peer returned by `FIND_NODE` but not yet authenticated. Not admitted to routing table. Must complete handshake first.

43. **Blocked peer messages dropped**:
    - Peer below block threshold sends DHT message. Message silently dropped. No routing table interaction.

## 16. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. Every scenario in Section 15 has deterministic pass/fail expectations.
3. IP diversity, trust protection, and swap-closer interact without deadlock or starvation under all tested topologies.
4. Bootstrap, warm restart, and churn scenarios produce stable routing table states within bounded time.
5. Security properties (Sybil resistance, eclipse resistance, poisoning resistance) degrade gracefully rather than failing catastrophically.
