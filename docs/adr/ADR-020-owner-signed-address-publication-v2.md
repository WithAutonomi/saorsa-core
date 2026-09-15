<!-- Copyright 2026 Saorsa Labs Limited -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR-020: Owner-signed address publication V2

## Status

Accepted (2026-09-10). Updated before release (2026-09-15): retain one
FIND_NODE operation and forward signed records in an optional response trailer.

Promoted from `docs/architecture/owner-signed-address-records.md` to record the
implemented protocol and the agreed replacement, reconnect, and persistence
behavior. This extends the portable core in
[ADR-019](./ADR-019-shared-native-and-browser-core.md) and retains the snapshot
policy in [ADR-017](./ADR-017-routing-table-snapshot-across-restart.md).

## Context

The DHT is a peer phonebook: it stores peer address knowledge and supports
routing and discovery. Application data storage remains outside saorsa-core;
trust signals remain in saorsa-core.

V1 describes native QUIC addresses. Browser discovery also needs WebRTC Direct
endpoints, and future transports must be forwardable by nodes that cannot dial
them. A sequence reported by an intermediary does not prove that the owner
published it. V2 therefore needs an extensible address set with a portable
owner signature that survives forwarding.

V1 and V2 coexist without capability negotiation. A user-agent identifies the
software and its node/client role; customizing it must not change the address
protocol. Publications use both address versions; lookups use the existing
FIND_NODE request only, with optional signed records in the response. Receiving a
valid V2 record establishes that its owner publishes V2, so V2 must take
precedence over all V1 information about that owner, regardless of arrival order
or V1 sequence. Expiring the latest known publication would remove potentially
usable addresses without providing any newer information.

Address knowledge also has to reach consumers: automatic reconnect previously
preferred saved connection addresses even when a newer publication had replaced
them in the routing table. Disk snapshots serve a different purpose, providing
QUIC reconnect candidates after restart.

## Decision

### 1. One extensible, owner-signed V2 protocol

Use the existing ML-DSA-65 node identity. A `SignedAddressRecord` contains the
owner peer ID, a nonzero sequence, a nonempty transport-address set, the owner's
public key, and its signature. The signed Postcard tuple is
`("saorsa/address-record/2", owner, sequence, records)`. The public key must
derive the claimed owner peer ID.

Each `TransportAddressRecord` carries numeric transport and reachability IDs
and an opaque, length-delimited address payload. Known payloads encode
`MultiAddr`; unknown IDs remain representable and covered by the signature.

| Field | Stable identifiers |
|-------|--------------------|
| Transport | QUIC = 1; WebRTC Direct = 2 |
| Reachability | Relay = 1; Direct = 2; Unverified = 3; Lan = 4 |

Do not reuse identifiers. Preserve unknown transports and reachability values
for forwarding without pretending to understand or dial them. WebRTC Direct
is represented as `Unverified` in supported local views: QUIC reachability
evidence does not establish reachability of a different transport or UDP port.

Verification lives in portable `saorsa_core::signed_address`, available without
native networking features. It checks bounds, owner/key binding, known-address
validity and ownership, and the signature before producing a
`VerifiedAddressRecord`. Verified records and `DHTNode::address_authority`
cannot be created by deserializing peer-supplied provenance.

Direct V2 publications must come over the authenticated owner's connection.
Native storage still requires routing-table admission; a publication from an
unadmitted peer receives `PeerRejected` for compatibility with older senders.
New senders do not wait for that response or retry the publication; a later
ordinary publication may arrive after admission.
Lookup replies must match a live request from the authenticated responder.
An independently verified signature permits a third party to forward a record;
it does not grant the owner routing-table membership by itself.

### 2. Retain the latest known publication without expiration

V2 publications have **no issuance or expiration timestamps**. The latest
accepted record remains usable as address knowledge regardless of its age,
subject to ordinary address filtering, dial failures, and routing membership.
There is no time-based signature renewal. While its local cache is retained,
the owner reuses the same sequence and signature for unchanged records; changed
records receive a higher sequence.

The periodic self-lookup task republishes the current set to routing peers at
randomized 5–10 minute intervals. Supplemental endpoint registration and the
reachability driver can publish earlier. These are dissemination mechanisms,
not lease renewals or guaranteed recovery deadlines.

This deliberately favors retaining the latest known addresses over discarding
them when newer information is unavailable. A valid signature establishes who
advertised an address, not that the endpoint is reachable now. A failed dial
does not establish a newer publication or require erasing its record.

Sequence watermarks and signed records remain bounded in-memory state tied to
routing membership. Eviction or restart can remove that knowledge. A receiver
without a newer record can accept an old valid publication; this is an accepted
trade-off, not a persistent anti-replay guarantee or proof of global freshness.

### 3. V2 replaces V1 and owns the complete address view

For an admitted native routing peer, retain its address view and the latest
accepted V2 publication with its original proof. Commit the full publication
and its QUIC projection atomically in the routing table. The protocol version
takes precedence over sequence: compare V1 sequences only until V2 is learned,
and compare only V2 sequences thereafter.

| Incoming information | Result |
|----------------------|--------|
| Newer authenticated V1 publication or V1 owner self-report, with no accepted V2 | Replace the QUIC view |
| First valid V2 publication | Replace the complete view, even if its sequence is lower than or equal to the stored V1 sequence and its QUIC addresses disagree |
| Newer valid V2 publication | Replace the complete view and original proof |
| Any V1 publication, self-report, or third-party hint after V2 | Ignore its address changes, regardless of sequence |
| Duplicate or older V2 publication | Preserve the accepted V2 view |
| Invalid V2 record | Reject it without changing addresses or establishing V2 precedence |

Precedence belongs to the **address owner**, not the forwarding responder. An
owner-signed record learned through a correlated lookup trailer has the same
precedence as a direct publication. A responder returning V2 entries does not
make all V1-only subjects in its other response V2 peers. Merely sending a V2
request, acknowledgement, or invalid proof does not establish an owner's V2
address view.

A V2 replacement removes all omitted addresses, including old QUIC addresses
when the new publication contains only WebRTC or unknown transports. The local
QUIC projection can therefore be empty while the complete publication remains
nonempty. Empty complete V2 sets remain invalid. An input rejected entirely by
validation or local filtering does not advance the sequence; a corrected
publication at that sequence can still be accepted.

For example, V1 sequence 12 publishes QUIC A. V2 sequence 10 publishes QUIC B
and WebRTC W1: the view becomes B plus W1. V1 sequence 100 is ignored. V2
sequence 11 containing only W2 replaces the view with W2 and clears QUIC B.
Replaying V2 sequence 10 cannot restore B or W1 while sequence 11 is retained.

V2 precedence has the same lifetime as the stored proof: it is bounded by
routing membership, eviction, and restart. Lookup-local views use the same
precedence until discarded; discovery alone does not create routing membership.

### 4. Preserve owner proof through lookups and forwarding

Forward the original signed publication unchanged. Address filtering,
reachability normalization, and QUIC projection operate on derived local
views; they never rewrite or re-sign the owner's proof. LAN, loopback, address
validity, and native address-cap policies continue to apply locally.

Native and browser report selection share the same provenance-aware merge.
A signed V2 view outranks an authenticated V1 owner report even when the V1
sequence is higher. Authenticated owner self-reports remain supported until V2
is learned; unsigned third-party V1 entries are discovery hints under the
existing quorum policy. Their advertised sequence alone grants no replacement
authority. `AddressAuthority::Signed` describes the accepted V2 view;
`AuthenticatedOwner` describes V1. The former independently combined V1/V2
provenance variant is removed. V1 information never becomes a synthetic V2
publication.

The ordinary lookup response retains all selected peers, including peers known
solely through V1 or restored QUIC candidates. Its address fields contain only
QUIC endpoints. An optional trailer carries available owner proofs for those
same peers. An unsigned entry cannot substitute for a missing proof, and an
absent trailer record never withdraws addresses or erases a base peer entry.

### 5. Publish both transports through the existing native entry points

`publish_address_set_to_peers` is used for V2 as well as V1. Its supplied
`typed_addresses` may contain QUIC and WebRTC endpoints. Supplied endpoints
are merged with registered supplemental endpoints and deduplicated. WebRTC
endpoints without a peer suffix are bound to the local identity and always
carry unverified reachability. Unsupported transports, invalid destinations,
foreign owner bindings, and sets exceeding the wire limits return an error
before signing or sending anything. Supplied endpoints apply to this snapshot;
persistent supplemental registration remains a separate operation.

Register self-owned WebRTC endpoints through `set_supplemental_self_addresses`.
That call replaces the supplemental set, binds missing peer IDs to the local
identity, rejects endpoints bound to another peer, and immediately attempts
publication to the appropriate close peers. Complete V2 records combine those
registered endpoints with the canonical QUIC set. The reachability driver
also constructs that complete set before sending it.

Send the full signed V2 record and its V1 QUIC projection concurrently to every
recipient, with the same publication sequence and independent request IDs.
If there is no QUIC projection, send only V2 because V1 cannot represent that
publication. Empty complete sets are not sent or acknowledged.

Publications are send-only: attempt each applicable version once per distinct
recipient, without creating response waiters. Keep the existing request wire
format so older receivers can process it; any acknowledgement or rejection
they send is ignored. The API returns peers for which all applicable transport
writes succeeded. This confirms sending, not remote processing or storage.
Silence from a peer, including one unable to process V2, has no trust cost.

Do not retry failed publication sends, reconnect to resend them, or maintain
an unacknowledged-publication queue. The reachability driver remembers attempts
against the complete record and target set, including failed attempts. Changed
addresses or browser certificates, new targets, and relay state transitions
can cause new publications. Ordinary periodic republication (every 5–10 minutes)
continues independently of individual send outcomes.

Connection and identity failures use the existing connection coordinator's
trust handling without an additional publication penalty. Once connected,
transport send failures produce at most one failure observation per recipient
per publication, even if both versions fail. Local encoding or signing errors
do not penalize the remote peer. Lookup requests still require responses and
retain the separate policy below.

### 6. Reconnect using the latest published QUIC addresses

The native DHT address store is routing-table state: its QUIC addresses and the
associated V2 publication. Transport `PeerInfo.addresses` describes connection
state and is a separate source. V1/V2 publications update DHT knowledge; they do
not rewrite the transport's saved connection-address list.

Automatic native reconnect resolves candidate sources in this order:

1. Explicit caller-provided addresses.
2. The latest owner-published QUIC view, whether learned through V1 or V2.
3. Saved connection addresses, if no owner-published QUIC view is known.
4. Other known DHT addresses, then the transport's connected-peer view.

An authoritative published view remains authoritative even if dialability
filtering leaves no candidates. Do not fall back to the superseded saved
addresses in that case. Existing address classifications are retained where
known; otherwise caller-provided and saved addresses are `Unverified`.

For example, an existing connection used A and the peer later published B.
After disconnection, an automatic message or request reconnect uses B. An
explicit caller request to dial A still takes priority. Native dialing remains
QUIC-only; retaining WebRTC information supports other consumers and forwarding.

### 7. Keep persistence and WebRTC relearning as they are

Do not add signed V2 records or WebRTC addresses to the native disk snapshots,
and do not add a mandatory V2 refresh request for each restored connection.

Persistence is enabled only when `close_group_cache_dir` is configured; its
default is `None`. The existing files have different scopes:

| File | Persisted peer information | Use after restart |
|------|----------------------------|-------------------|
| `close_group_cache.json` | Closest peers, their QUIC addresses, and trust records | Prioritized bootstrap candidates; default maximum age is one hour |
| `routing_snapshot.json` | Peer IDs and QUIC address lists across routing buckets | Bounded reconnect attempts in node mode; maximum snapshot age is seven days |

Both save the routing table's current QUIC view, including changes accepted
from V2. If V2 replaces A with B, the next eligible save contains B. Publication
does not synchronously write disk: periodic saves and orderly shutdown persist
the routing snapshot, subject to its existing empty-table and restore-floor
guards. Close-group persistence also runs after bootstrap.

Neither file preserves the full signed V2 record, WebRTC endpoints, publication
sequences, or address reachability classifications. Snapshot peers are dial
candidates, not authoritative restored publications or automatic routing-table
members. Reconnection verifies the expected peer identity and uses normal
admission. Node-mode routing snapshot restoration, bounds, and protections
remain as specified in ADR-017; client mode skips that snapshot.

WebRTC address knowledge returns through ordinary lookup trailers and owner
republication. Bootstrap may recover it promptly for some peers, but does not
guarantee immediate recovery for every restored peer. Until their signed
records are relearned, those peers cannot be advertised in V2 discovery replies.
Periodic publication can take minutes, and failures may delay recovery further.
This temporary loss of discovery information is accepted. Saving bare WebRTC
addresses would not provide the owner proof required to forward them in V2.

Snapshot age checks are local bootstrap policy and remain unchanged. They do
not reintroduce an expiration field or age-based rejection for V2 publications.

### 8. One FIND_NODE operation, compatibility, and bounds

No user-agent token, version inference, capability field, or fallback request
selects a lookup version. Native bootstrap, iterative lookup, and witness
re-queries send exactly one existing `FindNode` request per queried peer on
`/dht/1.0.0`. The reply remains `NodesFound`. The unreleased `FindNodeV2` and
`NodesFoundV2` variants are removed, with no reserved wire slots. Existing V1
operation and result discriminants are unchanged; `PublishAddressSetV2` now
occupies operation discriminant 5. V2 publications alone use
`/dht/address/2.0.0`, with their existing send-only behavior.

The response body is:

```text
Postcard(DhtNetworkMessage with NodesFound and QUIC-only addresses)
[ optional: ASCII "ADDRSIG1" + signed-record bundle ]
```

The bundle is a concatenation of `[u32 big-endian byte length][Postcard
SignedAddressRecord]` entries, with no count prefix. Each entry is an unchanged
owner-signed publication, including unknown transport records. This is the
same bundle representation exposed by `signed_address::encode_record_bundle`
and `decode_record_bundle`. The marker identifies extension format 1; it does
not change the signed publication format or its domain separator.

Pre-upgrade readers use `postcard::from_bytes`, which ignores bytes after the
legacy message. They receive the same QUIC peer entries and publication-sequence
metadata and do not interpret the trailer. Upgraded readers use
`postcard::take_from_bytes`, recognize the trailer marker, and decode the bounded
bundle. An absent, unknown, or malformed trailer leaves the legacy reply usable.
A malformed bundle is ignored as a whole; individually invalid signatures are
ignored without losing other valid entries. No new fields are appended to the
serialized Postcard struct or its per-peer records.

Before verifying or storing any trailer proof, the receiver requires the live
request, matching key, and authenticated responder identity. A verified proof
must name a peer present in the base `NodesFound` list. A matching proof upgrades
that peer's derived view under the existing V2-over-V1 precedence; it cannot
introduce unrelated peers through the trailer. LAN and reachability policies
still apply, and only admitted routing peers retain proofs beyond the lookup.
Older intermediaries do not retain or forward trailer proofs, so supplemental
address propagation depends on upgraded responders.

The entire response, including trailer, remains within **64 KiB**. First encode
the complete base peer list; never remove a base peer to make room for a proof.
Then consider proofs in response order, appending complete records that fit the
remaining budget. Skip records that do not fit and continue considering later
ones. Never truncate or re-sign a publication. If no proof fits, send the legacy
response alone. An oversized base response is rejected as before. A missing
proof is incomplete supplemental discovery, not a withdrawal.

The existing request timeout and iterative/witness grace window apply to the
single query per peer. A failed query is scored once; cancellation due to another
lookup's failure does not score it again. Bootstrap does not wait for an
unsupported sibling version. Publications retain their separate send-only
failure policy from section 5.

Browser adapters must send the same `FindNode`, decode the optional trailer,
verify the original signed publications, match owners to base peers, and apply
the shared precedence rules. Those adapters live outside this repository and
must upgrade with this unreleased wire change. `SignedAddressRecord::sign` and
`verify` take no clock argument; `compute_winner` returns an owned peer view.

Bounds remain 16 transport records per publication, 2 KiB per address payload,
40 KiB per encoded signed publication, and at most 256 trailer records, also
constrained by the total 64 KiB message limit. V2 publication messages use the
same 64 KiB envelope limit; the former 960 KiB lookup envelope is removed.

## Consequences

### Positive

- QUIC and WebRTC discovery share a portable owner-authenticated protocol,
  including forwarding through nodes that cannot dial every transport.
- Upgraded peers forward signed records automatically without duplicate lookup
  requests or capability advertisement.
- V1 cannot overwrite any accepted V2 addresses, and reordered V2 messages
  cannot roll back the newest retained V2 publication.
- Usable address knowledge is not discarded solely because time passed.
- Automatic reconnect sees published address changes, and both V1 and V2 QUIC
  updates reach the existing disk snapshots without a new persistence format.

### Negative

- The latest known signed record can advertise unreachable endpoints; there is
  no expiry-based freshness guarantee.
- Restart and eviction lose proof and sequence knowledge, allowing old valid
  records to be accepted again and temporarily reducing V2 discovery coverage.
- The 64 KiB response budget may omit some signed records, especially large
  publications. The complete base peer list remains available, but a lookup
  does not guarantee browser endpoints for every returned peer.
- Older intermediaries ignore supplemental records rather than forwarding them.
- Publications have no storage confirmation or failure-driven retries. A lost
  or unapplied update may remain missing until a later ordinary publication.
- Signatures increase message sizes. Consumers of the earlier draft V2 wire
  format and browser adapters need coordinated upgrades.

### Neutral

- Dial failure handling, reachability evidence, routing admission, trust, and
  snapshot validity retain their separate responsibilities.
- Persisting full V2 records and proactively refreshing every restored peer
  are outside this decision. Existing lookup and publication paths relearn them.

## Alternatives considered

- **Send separate V1 and V2 FIND_NODE requests.** Rejected before release:
  duplicate probes increase traffic and delay bootstrap against older peers.
  The optional trailer forwards signed records through one existing request.
- **Put browser endpoints in legacy address fields.** Rejected: older address
  parsers reject these strings and lose the entire lookup response.
- **Repurpose the per-peer `distance` metadata field.** Rejected: preserving the
  existing sequence marker and metadata semantics avoids changing legacy
  freshness handling. A trailer leaves those bytes untouched.

- **Expire V2 records or renew signatures on a timer.** Rejected: time passing
  provides no replacement addresses. Retain the latest known publication and
  accept that dialing determines current usability.
- **Negotiate V2 through user-agent or HELLO capability tokens.** Rejected:
  use both protocols automatically and derive address precedence from accepted
  owner-signed V2 records.
- **Let V1 and V2 update independently.** Rejected: after V2 is known, a V1
  update must not change any part of that owner's address view.
- **Wait for publication acknowledgements and retry failures.** Rejected:
  publish each version once, score connection/send failures, and let normal
  later publications disseminate the current addresses again.
- **Compare V1 and V2 sequences without protocol precedence.** Rejected: even
  a higher V1 sequence cannot block the first valid V2 publication.
- **Trust an intermediary's sequence or re-sign its merged view.** Rejected:
  preserve the owner's original proof and track derived views locally.
- **Treat absent or unsupported inputs as an empty V2 withdrawal.** Rejected:
  absence of a representable address is not an instruction to clear another
  transport's addresses. V2 publications must remain nonempty.
- **Prefer saved connection addresses for automatic reconnect.** Rejected when
  a newer owner-published QUIC view exists; those saved endpoints may have been
  replaced intentionally. Explicit caller overrides remain supported.
- **Persist WebRTC addresses or full V2 proofs, or fetch V2 after every restored
  connection.** Not adopted: keep QUIC reconnect persistence and accept normal
  relearning of WebRTC and owner proofs after bootstrap.

## Validation and references

Existing regressions cover owner/signature validation, response correlation,
publication ordering, V2 precedence over V1, supplemental-only replacement,
unchanged-signature reuse, forwarding, response bounds, and reconnect source
selection. Lookup regressions cover legacy decoding with trailing bytes, missing
and malformed trailers, retention of every base peer under the size budget,
and single-query operation against legacy and upgraded responders. Publication regressions cover receivers that never reply, absence
of response tracking, one penalty for failed delivery, and suppression of
failed-send retries. Persistence tests cover snapshot encoding, validity, and bounded
dial-candidate selection. These do not establish a time bound for relearning
WebRTC addresses after restart.

- [Portable signed records and verification](../../src/signed_address.rs)
- [Extensible transport records](../../src/transport_address.rs)
- [Native publication, storage, and lookup handling](../../src/dht_network_manager.rs)
- [Publication protocol regression tests](../../src/dht_network_manager/address_v2_tests.rs)
- [Shared report selection](../../src/client_routing.rs) and
  [peer-view merging](../../src/peer_record.rs)
- [Reconnect and persistence integration](../../src/network.rs)
- [Connection recovery regression tests](../../tests/stale_session_reconnect.rs)
- [Routing snapshot format and tests](../../src/bootstrap/routing_snapshot.rs)
- [Close-group cache format](../../src/bootstrap/cache.rs)
- [Reachability publication driver](../../src/reachability/driver.rs)
