# Upload, Quote, and Initial Storage Authorization Logic Specification (Codebase-Agnostic)

> Status: Design-level specification for pre-implementation validation.

## 1. Purpose

This document specifies the client upload flow, node quote flow, node upload receive flow, and node-side verification flow for permanent chunk storage.
It is designed to sit between the Routing Table Logic Specification and the Replication Logic Specification.

Primary goal: define how a client discovers the canonical quote candidates for a chunk, obtains quotes, selects a payee majority that the close group will accept, and produces a verifiable authorization proof for initial storage.

## 2. Scope

### In scope

- Client closest-peer lookup for a chunk address.
- Canonical quote-candidate derivation from the lookup result.
- Node quote issuance and candidate-acceptance signaling.
- Client selection of a compatible payee majority.
- Node validation of the selected payee set on direct upload receive.
- The authorization proof object consumed by fresh replication as `PoP`.

### Out of scope

- Payment transfer, settlement, escrow, and receipts.
- Pricing policy and quote economics beyond the presence of opaque quote terms.
- Chunking strategy, file manifests, erasure coding, and reassembly.
- Concrete RPC wire formats and serialization.
- Wallet integration and payment-chain verification.

## 3. System Model

- `Chunk`: immutable content-addressed storage unit with key `K = ChunkAddress`.
- `Client`: uploader that wants to commit chunk `K` to the network.
- `LookupSet(K)`: ordered list of up to `LOOKUP_SET_SIZE` nearest peers to `K` returned by a client network lookup.
- `QuoteCandidates(K)`: the first `QuoteCandidateCount(K)` peers in `LookupSet(K)`, where `QuoteCandidateCount(K) = min(CLOSE_GROUP_SIZE, |LookupSet(K)|)`.
- `SelectedPayees(K)`: subset of `QuoteCandidates(K)` chosen by the client for direct upload payment.
- `PayeeMajorityNeeded(K)`: dynamic threshold defined as `floor(QuoteCandidateCount(K)/2)+1`.
- `QuoteRequest(K)`: session-bound request sent by the client to each peer in `QuoteCandidates(K)`, carrying chunk metadata, the ordered `LookupSet(K)`, and derived `QuoteCandidates(K)`.
- `QuoteRequestHash(K)`: hash of the canonicalized `QuoteRequest(K)` payload.
- `LocalVerifiedLookup(N, K)`: node `N`'s most recent verified closest-peer lookup result for key `K`, obtained either by a fresh network lookup or from a short-lived validation cache.
- `LocalCandidateSet(N, K)`: the first `QuoteCandidateCount(K)` peers from `LocalVerifiedLookup(N, K)`.
- `AcceptedPayees(N, K)`: subset of `QuoteCandidates(K)` that node `N` currently accepts as valid direct-upload payees for chunk `K`.
- `Quote(N, K)`: signed quote response from node `N`, bound to `QuoteRequestHash(K)`, including opaque quote terms and `AcceptedPayees(N, K)`.
- `QuoteBundle(K)`: set of valid quotes collected for one `QuoteRequest(K)`.
- `CompatiblePayeeSet(K, S, QuoteBundle)`: predicate that holds iff `|S| = PayeeMajorityNeeded(K)` and for every `P in S`, a valid quote from `P` exists in `QuoteBundle(K)` with `S ⊆ AcceptedPayees(P, K)`.
- `UploadAuthorization(K)`: proof object produced by the client after quote collection, containing `QuoteRequest(K)`, `SelectedPayees(K)`, and the quote evidence needed to validate the payee-majority decision. This object is the `PoP` referenced by `REPLICATION_DESIGN.md`.
- `StoreAck(K, N)`: acknowledgement from payee `N` that it accepted and durably stored chunk `K` under `UploadAuthorization(K)`.
- `StoredPayeeCount(K)`: number of distinct selected payees that returned valid `StoreAck` for chunk `K`.
- `DirectUploadTarget(K)`: node in `SelectedPayees(K)` that receives chunk bytes directly from the client.
- `FreshReplicationReceiver(K)`: any node that later receives the chunk through fresh replication using the same `UploadAuthorization(K)` as `PoP`.

## 4. Tunable Parameters

All parameters are configurable. Values below are a reference profile used for logic validation.

| Parameter | Meaning | Reference |
|---|---|---|
| `LOOKUP_SET_SIZE` | Number of closest peers requested by client lookup | `20` |
| `CLOSE_GROUP_SIZE` | Canonical quote-candidate width and intended close-group width | `7` |
| `QUOTE_REQUEST_FANOUT` | Number of quote requests the client MUST attempt | `QuoteCandidateCount(K)` |
| `QUOTE_VALIDITY_WINDOW` | Maximum age of a quote when used for direct client upload | `5 min` |
| `LOOKUP_VERIFICATION_CACHE_TTL` | Maximum age of cached `LocalVerifiedLookup(N, K)` used for quote or receive verification | `60s` |
| `MAX_CLIENT_CLOCK_SKEW` | Allowed clock skew for quote timestamps and expiry checks | `30s` |

Parameter safety constraints (MUST hold):

1. `1 <= CLOSE_GROUP_SIZE <= LOOKUP_SET_SIZE`.
2. `QuoteCandidateCount(K) = min(CLOSE_GROUP_SIZE, |LookupSet(K)|)`.
3. `PayeeMajorityNeeded(K) = floor(QuoteCandidateCount(K)/2)+1`.
4. `1 <= PayeeMajorityNeeded(K) <= QuoteCandidateCount(K)`.
5. `QUOTE_VALIDITY_WINDOW > 0`.
6. `LOOKUP_VERIFICATION_CACHE_TTL > 0`.
7. If constraints are violated at runtime reconfiguration, node MUST reject the config and keep the previous valid config.

## 5. Core Invariants (Must Hold)

1. The client MUST derive `QuoteCandidates(K)` from the ordered `LookupSet(K)` and MUST NOT skip a closer peer in favor of a farther peer when building the candidate set.
2. The client MUST attempt quote solicitation to every peer in `QuoteCandidates(K)` before finalizing `SelectedPayees(K)`.
3. `SelectedPayees(K)` MUST be a subset of `QuoteCandidates(K)` with size exactly `PayeeMajorityNeeded(K)`.
4. A direct client upload is valid only if `SelectedPayees(K)` is a `CompatiblePayeeSet`.
5. Each selected payee MUST have signed a quote that explicitly accepts every member of `SelectedPayees(K)` as a valid payee.
6. A quote is valid only if it is bound to one `QuoteRequestHash(K)` and cannot be replayed across different chunks, lookup sets, or upload sessions.
7. A node MUST verify candidate correctness when issuing a quote. Direct-upload receive MUST verify that the stored authorization bundle is consistent with signed quotes, but it need not redo full candidate-set validation if the quote is still within validity.
8. Direct client upload targets are only nodes in `SelectedPayees(K)`. Other close-group members are populated by fresh replication using the same `UploadAuthorization(K)` as `PoP`.
9. `UploadAuthorization(K)` proves initial storage authorization and payee-set validity, but it does NOT prove payment settlement. Payment verification remains out of scope.
10. Timeout or no-response from a quote candidate is neutral. It does not count as approval and does not count as rejection.
11. A quote signer MUST NOT approve a payee outside `QuoteCandidates(K)`.
12. A node MUST reject a direct upload if the quote set is expired under `QUOTE_VALIDITY_WINDOW` at receive time.
13. The client MUST NOT treat an upload as successfully committed unless a close-group majority has actually stored the chunk. In the reference profile, because `SelectedPayees(K)` is exactly a 4-node majority, this means all selected payees must return `StoreAck`.
14. The same `UploadAuthorization(K)` MUST be reusable by fresh-replication receivers as the `PoP` defined in `REPLICATION_DESIGN.md`.

## 6. Protocol Artifacts

### 6.1 QuoteRequest

`QuoteRequest(K)` MUST contain:

1. `upload_session_id`
2. `chunk_address = K`
3. `chunk_size`
4. Optional opaque storage-policy fields that affect quoting
5. Ordered `LookupSet(K)` of up to `LOOKUP_SET_SIZE` peers
6. Ordered `QuoteCandidates(K)` derived from `LookupSet(K)`
7. `issued_at`
8. `expires_at`

Rules:

1. `QuoteCandidates(K)` MUST equal the first `QuoteCandidateCount(K)` peers of `LookupSet(K)`.
2. `expires_at - issued_at` MUST be `<= QUOTE_VALIDITY_WINDOW`.
3. The canonical serialization of `QuoteRequest(K)` defines `QuoteRequestHash(K)`.

### 6.2 Quote

`Quote(N, K)` MUST contain:

1. `quote_request_hash`
2. `signer_peer_id = N`
3. Opaque quote terms or a digest of them
4. `AcceptedPayees(N, K)` encoded as a deterministic subset/bitset over `QuoteCandidates(K)`
5. `issued_at`
6. `expires_at`
7. Signature by `N`

Rules:

1. `AcceptedPayees(N, K)` MUST be a subset of `QuoteCandidates(K)`.
2. A usable quote MUST include `N` in `AcceptedPayees(N, K)`.
3. A quote that omits `N` from `AcceptedPayees(N, K)` is treated as a rejection and MUST NOT be used in `SelectedPayees(K)`.
4. Nodes MAY return no quote at all instead of a rejection quote.

### 6.3 UploadAuthorization

`UploadAuthorization(K)` MUST contain:

1. `QuoteRequest(K)`
2. Ordered `SelectedPayees(K)`
3. `QuoteBundle(K)` containing at least the quotes for all selected payees
4. Canonical digest of the chunk metadata bound by the quote request

Recommended:

1. Include all responsive quotes, not only the selected ones, to simplify later verification and diagnostics.
2. Preserve the original `LookupSet(K)` ordering exactly as used by the client.

## 7. Client Upload Flow

### 7.1 Candidate Discovery

For chunk `K`, the client performs:

1. Run a network closest-peer lookup for `K` requesting `LOOKUP_SET_SIZE` peers.
2. Canonically sort the result by distance to `K`.
3. Set `LookupSet(K)` to the ordered result.
4. Derive `QuoteCandidates(K)` as the first `QuoteCandidateCount(K)` peers from `LookupSet(K)`.
5. Compute `PayeeMajorityNeeded(K)`.

Rules:

1. The client MUST use the ordered lookup output directly.
2. The client MUST NOT cherry-pick a different 7-peer candidate set from deeper in the 20-peer lookup result.
3. If `LookupSet(K)` is empty, upload cannot proceed.

### 7.2 Quote Solicitation

The client then:

1. Constructs one `QuoteRequest(K)`.
2. Sends the same `QuoteRequest(K)` to every peer in `QuoteCandidates(K)`.
3. Waits until either:
   a. all quote candidates have responded or timed out, or
   b. enough valid quotes have arrived to prove at least one compatible payee majority and the client chooses to stop early.
4. Discards invalid, expired, or signature-failing quotes.

Rules:

1. The client MUST attempt quote solicitation to every candidate, even if it later commits with a subset of responsive peers.
2. The client MUST NOT form `SelectedPayees(K)` from peers outside `QuoteCandidates(K)`.

### 7.3 Majority Payee Selection

The client MUST select `SelectedPayees(K)` from the valid quote responses using compatibility, not price alone.

Compatibility algorithm:

1. Let `ResponsiveCandidates` be the set of peers with valid usable quotes.
2. Enumerate all subsets `S ⊆ ResponsiveCandidates` with `|S| = PayeeMajorityNeeded(K)`.
3. `S` is valid only if for every `P in S`, the quote from `P` exists and `S ⊆ AcceptedPayees(P, K)`.
4. The client MAY optimize among valid subsets by cost, latency, trust, or policy.
5. If multiple subsets are equally preferred, the client SHOULD tie-break by:
   a. lower total quote cost,
   b. lower total rank sum in `QuoteCandidates(K)`,
   c. lexicographic peer-id order.

Rules:

1. The client MUST NOT choose the cheapest subset if it is not compatible.
2. If no compatible subset exists, the client MUST abort this upload attempt and retry only after a fresh lookup/quote cycle.

Interpretation:

- For the reference profile with 7 quote candidates, the client is solving for a compatible 4-node majority.
- In graph terms, the client is searching for a size-4 clique in the mutual-acceptance graph induced by the signed quotes.

### 7.4 Upload Commit

After selecting `SelectedPayees(K)`, the client:

1. Constructs `UploadAuthorization(K)`.
2. Sends the chunk bytes plus `UploadAuthorization(K)` directly to each node in `SelectedPayees(K)`.
3. Waits for implementation-defined acceptance acknowledgements.

Rules:

1. The client SHOULD upload in parallel to all selected payees.
2. The client MUST collect `StoreAck` from every selected payee before declaring success. If any selected payee rejects, times out, or fails before acknowledging storage, the client MUST treat the commit as failed and restart from a fresh lookup/quote cycle.
3. Once any selected payee accepts and stores the chunk, that node may hand the chunk to fresh replication using the same `UploadAuthorization(K)` as `PoP`.
4. The client's durability objective is stronger than the node's local admission objective: the node cares that it was validly selected and agreed to store; the client cares that a close-group majority actually stored, because otherwise replication liveness is not assured.

## 8. Node Quote Flow

When node `N` receives `QuoteRequest(K)`:

1. Validate request shape:
   a. `QuoteCandidates(K)` equals the first `QuoteCandidateCount(K)` peers of `LookupSet(K)`.
   b. `expires_at` has not passed under `MAX_CLIENT_CLOCK_SKEW`.
   c. `N` is included in `QuoteCandidates(K)`.
2. Obtain `LocalVerifiedLookup(N, K)`:
   a. reuse cached verified lookup if its age is `<= LOOKUP_VERIFICATION_CACHE_TTL`, otherwise
   b. run a fresh network closest-peer lookup for `K` requesting `LOOKUP_SET_SIZE` peers.
3. Derive `LocalCandidateSet(N, K)` as the first `QuoteCandidateCount(K)` peers of `LocalVerifiedLookup(N, K)`.
4. Compute `AcceptedPayees(N, K)` as the subset of `QuoteCandidates(K)` satisfying all:
   a. candidate is `N` or currently authenticated and present in `LocalRT(N)`,
   b. candidate appears in `LocalCandidateSet(N, K)`,
   c. candidate is not locally blocked by trust policy.
5. If `N ∉ AcceptedPayees(N, K)`, reject the request or return an unusable quote.
6. Otherwise return signed `Quote(N, K)`.

Rules:

1. Quote issuance is local-view dependent. Honest nodes MAY disagree about `AcceptedPayees`.
2. That disagreement is expected; the client resolves it by selecting a compatible majority, not by forcing unanimity.
3. A node MUST NOT approve a candidate it does not currently consider locally valid.

## 9. Node Upload Receive Flow

This section applies to direct client uploads, not later fresh replication.

Receive-time semantics:

1. Quote-time is where node `N` verifies that the client is paying the right candidates.
2. Receive-time is where node `N` verifies that the client is presenting a still-valid authorization bundle that includes `N` as a selected payee.
3. If `N` signed a valid quote and the quote has not expired, `N` SHOULD honor that quote rather than re-running full candidate-set selection against a newer routing view.

When node `N` receives chunk `K` and `UploadAuthorization(K)` directly from a client:

1. Validate the chunk address and content integrity.
2. Validate `UploadAuthorization(K)` structure:
   a. `SelectedPayees(K)` size equals `PayeeMajorityNeeded(K)`,
   b. every selected payee is in `QuoteCandidates(K)`,
   c. every selected payee has a valid signed quote bound to the same `QuoteRequestHash(K)`.
3. Reject if `N ∉ SelectedPayees(K)`.
4. Reject if the quote set is expired under `QUOTE_VALIDITY_WINDOW`.
5. Verify `CompatiblePayeeSet(K, SelectedPayees(K), QuoteBundle(K))`.
6. Verify that the quote signed by `N` exists in the bundle and that `SelectedPayees(K) ⊆ AcceptedPayees(N, K)` in that signed quote.
7. If all checks pass, store the chunk locally and return `StoreAck(K, N)`.
8. Treat the stored chunk as a fresh accepted record with valid `PoP = UploadAuthorization(K)` and hand off to fresh replication.

Rules:

1. A node MUST NOT accept a direct client upload unless its own signed quote is present, valid, unexpired, and approves the selected payee set.
2. A node SHOULD honor its quote within `QUOTE_VALIDITY_WINDOW` even if its current routing view has drifted, unless a stronger local safety policy requires rejection.
3. A non-selected close-group peer MUST reject direct client upload even if it would accept the same `PoP` later via fresh replication.
4. A node's local concern is "was I validly selected and asked to store under a still-valid quote?" The global concern "did enough payees actually store for replication liveness?" is owned by the client commit rule.

## 10. Verification Logic

### 10.1 Candidate Verification

Candidate verification answers: "Did the client pick the right nodes to pay?"

At quote time, for node `N`, the selected payees are locally valid only if:

1. `SelectedPayees(K) ⊆ QuoteCandidates(K)`,
2. `SelectedPayees(K) ⊆ LocalCandidateSet(N, K)`,
3. every selected payee is `N` or is currently authenticated and present in `LocalRT(N)`,
4. no selected payee is locally blocked.

Implications:

1. A client cannot pay an arbitrary cheap node outside the canonical quote candidates.
2. A client cannot pay a candidate that the quoting node did not consider part of the acceptable close-group majority for `K` at quote time.
3. This verification is primarily enforced when the node issues its signed quote. Direct upload receive reuses that signed decision rather than recomputing it by default.

### 10.2 Compatibility Verification

Compatibility verification answers: "Will the selected payees accept each other as valid payees?"

For a selected set `S = SelectedPayees(K)`:

1. For each `P in S`, load the signed quote from `P`.
2. Verify signature and `quote_request_hash`.
3. Verify `S ⊆ AcceptedPayees(P, K)`.
4. If any selected payee does not approve the full selected set, reject.

This creates a majority set that is self-consistent under the selected nodes' signed views.

### 10.3 Durable Authorization for Replication

After a direct upload is accepted by a selected payee:

1. `UploadAuthorization(K)` becomes the durable initial-storage proof for that chunk.
2. Fresh-replication receivers validate it as the `PoP` referenced by `REPLICATION_DESIGN.md`.
3. Fresh-replication receivers do NOT require `self ∈ SelectedPayees(K)`; they require only:
   a. valid `UploadAuthorization(K)`,
   b. normal fresh-replication validation,
   c. current responsibility/range checks from the replication spec.

This is how a 4-payee majority can authorize a 7-holder close group.

Client durability requirement:

1. Authorization alone is not enough for the client.
2. The client needs a close-group majority to have actually stored the chunk before considering the upload successful.
3. If fewer than a majority have stored, the chunk may fail to seed fresh replication reliably and the client MUST retry.

## 11. Failure and Retry Rules

1. Invalid quote signature: discard that quote.
2. Expired quote: discard that quote.
3. No compatible majority from collected quotes: abort and restart with fresh lookup.
4. Direct-upload rejection by any selected payee: client MUST abandon the current authorization bundle and restart.
5. Candidate drift between quote time and receive time: if the quote is still valid, the receiver normally honors it; if local safety policy rejects due to excessive drift, the client restarts with fresh lookup.
6. Lookup disagreement across honest nodes: tolerated as long as a compatible majority exists and all selected payees actually return `StoreAck`.
7. If the network is undersized and `QuoteCandidateCount(K) < CLOSE_GROUP_SIZE`, majority math remains dynamic via `PayeeMajorityNeeded(K)`.

## 12. Interaction with Routing and Replication

### 12.1 Routing Inputs

This design consumes the routing layer for:

1. Network closest-peer lookup for `K` with count `LOOKUP_SET_SIZE`.
2. `LocalRT(self)` membership checks during candidate acceptance.
3. Local block/trust state for rejecting locally invalid payees.

### 12.2 Replication Output

This design produces:

1. `UploadAuthorization(K)` as the concrete `PoP` used by fresh replication.
2. Initial direct holders equal to `SelectedPayees(K)` that actually returned `StoreAck`.
3. A valid starting point for fresh replication to populate the rest of the current close group, provided the client commit rule achieved majority storage first.

### 12.3 Required Contract

The following contract MUST hold across design docs:

1. `CLOSE_GROUP_SIZE` in this document MUST equal `CLOSE_GROUP_SIZE` in the routing and replication documents.
2. `UploadAuthorization(K)` MUST be accepted as `PoP` by the replication layer.
3. Fresh replication MUST treat the chunk as newly authorized storage, not as a repair-only path.

## 13. Logic-Risk Checklist (Pre-Implementation)

Use this list to find design flaws before coding:

1. Quote-view divergence:
   - If honest nodes disagree on the top-7 set, does the client still find a compatible majority often enough?
2. Candidate drift:
   - Can fast churn invalidate quotes too often between quote time and upload receive time?
3. Cheapest-clique bias:
   - Can the client over-optimize for price and repeatedly end up with unstable payee majorities?
4. Mutual-acceptance deadlock:
   - Could no 4-node clique exist even though 7 honest close-group nodes are available?
5. Replay risk:
   - Are quote hashes, session ids, and chunk-address binding sufficient to prevent quote reuse across uploads?
6. Upload commit partial success:
   - If only some selected payees accept before the client disconnects, how are partial stores cleaned up or reused after the client restarts?
7. Colluding quote candidates:
   - If a malicious majority controls enough of the canonical candidate set, can they self-approve and exclude honest peers? This is a higher-layer security assumption, not solved here.
8. Cache staleness:
   - Does `LOOKUP_VERIFICATION_CACHE_TTL` create unacceptable false positives or false negatives under churn?

## 14. Pre-Implementation Test Matrix

Each scenario should assert exact expected outcomes and state transitions.

1. Canonical candidate derivation:
   - Client lookup returns 20 ordered peers; quote candidates are exactly the first 7.
2. Undersized lookup:
   - Client lookup returns 5 peers; quote candidates are those 5 and majority threshold is 3.
3. Quote solicitation fanout:
   - Client attempts quote requests to all quote candidates, not just a preferred subset.
4. Quote self-accept requirement:
   - Node returns a quote that omits itself from `AcceptedPayees`; quote is unusable for selection.
5. Quote bound to request hash:
   - Reusing a quote for a different chunk or session fails verification.
6. Local candidate mismatch:
   - Node receives a quote request but locally sees only 3 of the 7 candidates in its top 7; `AcceptedPayees` includes only those 3.
7. Compatible 4-of-7 majority exists:
   - Client finds a size-4 clique and selects it successfully.
8. Cheapest subset is invalid:
   - Lowest-cost 4-node subset is not mutually accepted; client rejects it and selects a valid higher-cost subset.
9. No compatible majority:
   - Quotes arrive but no size-4 compatible subset exists; client aborts and restarts.
10. Direct upload to non-selected candidate:
   - Node is in `QuoteCandidates` but not in `SelectedPayees`; it rejects direct client upload.
11. Direct upload to selected payee happy path:
   - Node is selected, verifies the quote bundle, its own signed quote, chunk integrity, stores successfully, and returns `StoreAck`.
12. Selected payee local drift tolerance:
   - Node signed a quote earlier, routing view drifts slightly before receive, but quote is still valid; node honors the quote and stores.
13. Expired quote rejection:
   - Client attempts upload after quote expiry; receiver rejects.
14. Selected payee outside local top 7 after drift:
   - Receiver's current lookup would place one selected payee outside `LocalCandidateSet`, but the quote is still valid; receiver still honors its signed quote unless stricter local policy is enabled.
15. Compatibility verification failure:
   - One selected payee's signed quote does not approve the full selected set; receiver rejects.
16. Missing selected-payee quote:
   - `UploadAuthorization(K)` omits the quote for one selected payee; receiver rejects.
17. Quote timeout neutrality:
   - Three quote candidates time out, four compatible quotes remain; client may proceed with those four if they form a valid majority.
18. Missing store acknowledgement:
   - One selected payee never returns `StoreAck`; client treats the upload as failed even if other selected payees stored.
19. Fresh-replication handoff:
   - Selected payee accepts direct upload, then a non-selected close-group node accepts the same `UploadAuthorization(K)` as `PoP` via fresh replication.
20. Non-selected fresh-replication acceptance:
   - Node not in `SelectedPayees` accepts later fresh replication because it is currently responsible and the `PoP` is valid.
21. Replay with different lookup set:
   - Client swaps in a different `LookupSet(K)` but reuses old quotes; verification fails due to `QuoteRequestHash` mismatch.
22. Client cherry-picks cheaper farther peers:
   - Client attempts to build `QuoteCandidates` from ranks 2, 4, 5, 8, 9, 10, 11 of `LookupSet(K)`; nodes reject because the candidate set is not canonical.
23. Mutual acceptance asymmetry:
   - Node A accepts B, but B does not accept A; subsets containing both are invalid.
24. Cache reuse within TTL:
   - Node uses cached `LocalVerifiedLookup(N, K)` under `LOOKUP_VERIFICATION_CACHE_TTL` and produces the same acceptance decision as fresh lookup.
25. Cache expiry triggers fresh validation:
   - Cached lookup is too old; node performs a fresh lookup before quoting or accepting.
26. Dynamic majority in small network:
   - With 3 quote candidates, a 2-node selected set is sufficient and verified correctly.

## 15. Acceptance Criteria for This Design

The design is logically acceptable for implementation when:

1. All invariants in Section 5 can be expressed as executable assertions.
2. The client selection algorithm deterministically rejects non-compatible payee sets.
3. Every direct-upload receiver can independently verify that the client selected a canonical compatible payee majority and that the receiver itself was validly selected.
4. `UploadAuthorization(K)` is concrete enough to replace the abstract `PoP` in `REPLICATION_DESIGN.md`.
5. Every scenario in Section 14 has deterministic pass/fail expectations.
6. The client commit rule explicitly requires actual majority storage acknowledgements before upload success is declared.
7. The routing, upload, and replication documents agree on `CLOSE_GROUP_SIZE`, closest-peer ordering, and the meaning of `PoP`.
