<!-- Copyright 2026 Saorsa Labs Limited -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR-020: Owner-signed address publication V2

## Status

Accepted (2026-09-10).

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

V1 and V2 coexist. Treating a V1 QUIC list as a complete V2 replacement would
erase WebRTC addresses simply because V1 cannot represent them. A single shared
version gate would also discard useful delayed V2 information after a newer V1
update. Expiring the latest known publication would remove potentially usable
addresses without providing any newer information.

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
unadmitted peer receives `PeerRejected`, allowing a retry after admission.
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

### 3. Replace QUIC and complete V2 views independently

For an admitted native routing peer, retain two independently versioned views
in the routing table: the QUIC address list and its sequence, and the latest
complete V2 publication with its original proof. Apply replacements within
their scope, rather than accumulating obsolete addresses indefinitely.

| Incoming information | QUIC view | Complete V2 view, including WebRTC |
|----------------------|-----------|-----------------------------------|
| Newer authenticated V1 publication or V1 owner self-report | Replace the QUIC view | Preserve the existing V2 publication and supplemental addresses |
| Valid V2 publication newer than both stored views, with QUIC addresses | Replace the QUIC view | Replace the complete V2 view |
| V2 newer than stored V2 but older than stored QUIC | Preserve newer QUIC | Accept the newer V2 view |
| V2 with a QUIC sequence already accepted through V1 | Require its nonempty QUIC projection to agree | Fill in V2 information if newer than stored V2 |
| Newer V2 containing only supplemental or unknown transports | Preserve existing QUIC and its sequence | Replace the complete V2 view |
| Duplicate or older information for a view | Do not roll that view back | Do not roll that view back |
| Unsigned third-party V1 report claiming a higher sequence | Cannot replace an accepted owner-proven view | Cannot replace an accepted owner-proven view |

A newer V2 replacement that omits WebRTC removes the previous WebRTC addresses.
A V1 message that omits WebRTC never removes them. Empty V2 sets are invalid;
the publication APIs send no empty replacement and define no V2 withdrawal.
An unsupported-only input that produces no complete records is a no-op, not an
empty withdrawal. Existing inbound V1 replacement handling remains QUIC-scoped.
Rejected replacements do not advance the affected version, so a corrected
publication at that sequence can still be accepted.

For example, V2 sequence 10 publishes QUIC A and WebRTC W1. V1 sequence 12
changes QUIC to B: the local view becomes B plus W1. A delayed V2 sequence 11
containing A and W2 updates WebRTC to W2 while QUIC remains B. V2 sequence 13
containing only QUIC C then removes W2. Replaying V2 sequence 11 cannot restore
it while the newer V2 record is retained.

### 4. Preserve owner proof through lookups and forwarding

Forward the original signed publication unchanged. Address filtering,
reachability normalization, and QUIC projection operate on derived local
views; they never rewrite or re-sign the owner's proof. LAN, loopback, address
validity, and native address-cap policies continue to apply locally.

Native and browser report selection share the same provenance-aware merge.
Only owner-proven sequence information can replace an accepted owner view.
Authenticated owner self-reports remain supported for V1 compatibility;
unsigned third-party V1 entries are discovery hints under the existing quorum
policy. Their advertised sequence alone grants no replacement authority.

`AddressAuthority::Combined` represents a newer QUIC view alongside a different
signed V2 publication. It is local provenance, not a signature over the combined
list. Forwarders may therefore send a valid V2 proof containing older QUIC
addresses; recipients that know newer QUIC information keep it. V1 information
never becomes a synthetic V2 publication.

V2 lookup replies include only peers with owner proofs. Peers known solely
through V1 or restored QUIC candidates are omitted until a proof is learned.
An unsigned entry cannot substitute for a missing proof.

### 5. Publish both transports through the existing native entry points

`publish_address_set_to_peers` is used for V2 as well as V1. Its supplied
`typed_addresses` are the native QUIC projection; non-QUIC values in that
argument are not a supplemental-address registration mechanism.

Register self-owned WebRTC endpoints through `set_supplemental_self_addresses`.
That call replaces the supplemental set, binds missing peer IDs to the local
identity, rejects endpoints bound to another peer, and immediately attempts
publication to the appropriate close peers. Complete V2 records combine those
registered endpoints with the canonical QUIC set. The reachability driver
also constructs that complete set before sending it.

After establishing the recipient's capability, a V2 peer receives the full
signed record; a V1 peer receives only its QUIC projection with the same
publication sequence. If there is no QUIC projection, skip V1 recipients.
Empty complete sets are not sent or recorded as acknowledged publications.
Reachability retries track acknowledgements against the exact complete set,
including supplemental endpoints, so a changed WebRTC endpoint cannot be
mistaken for an already acknowledged update.

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

WebRTC address knowledge returns through ordinary V2 lookup responses and owner
republication. Bootstrap may recover it promptly for some peers, but does not
guarantee immediate recovery for every restored peer. Until their signed
records are relearned, those peers cannot be advertised in V2 discovery replies.
Periodic publication can take minutes, and failures may delay recovery further.
This temporary loss of discovery information is accepted. Saving bare WebRTC
addresses would not provide the owner proof required to forward them in V2.

Snapshot age checks are local bootstrap policy and remain unchanged. They do
not reintroduce an expiration field or age-based rejection for V2 publications.

### 8. Capability negotiation, compatibility, and bounds

The signed identity announcement advertises `addr-v2`. V2 uses
`/dht/address/2.0.0` with `PublishAddressSetV2` and `FindNodeV2`; owner signatures
are mandatory in publications and lookup entries. The unsigned V2 draft never
shipped and is not retained as a second mode or capability.

Removing timestamps changes the draft V2 signed wire format and signing domain;
native and browser consumers must upgrade together. `SignedAddressRecord::sign`
and `verify` no longer take a clock argument. `compute_winner` returns an owned
peer view because it may combine reports. V1 keeps its existing operations and
wire discriminants for older peers.

Browser FIND_NODE requests opt into a length-delimited binary proof bundle.
The authenticated HELLO advertises `addr-v2`; proof-enabled replies contain
only proven peers, and ant-core rejects entries without owner proof. Browser
adapters use the portable verifier and preserve original publication bytes.
Older browser servers without the capability can still supply legacy hints.
Upgrading a forwarder does not fix an older consumer that trusts arbitrary
third-party sequence claims.

Bound record collections, address payloads, keys, signatures, and response
decoding. Current limits include 16 transport records, 2 KiB per address
payload, 40 KiB for an encoded signed record, and 256 V2 lookup entries. V2
envelopes allow 960 KiB within the transport's 1 MiB envelope; V1 retains its
64 KiB limit. When bounding a V2 response, retain complete closest-peer signed
records rather than truncating addresses inside a proof.

## Consequences

### Positive

- QUIC and WebRTC discovery share a portable owner-authenticated protocol,
  including forwarding through nodes that cannot dial every transport.
- V1 compatibility cannot accidentally erase supplemental V2 addresses, and
  message reordering cannot roll back a view whose newer version is retained.
- Usable address knowledge is not discarded solely because time passed.
- Automatic reconnect sees published address changes, and both V1 and V2 QUIC
  updates reach the existing disk snapshots without a new persistence format.

### Negative

- The latest known signed record can advertise unreachable endpoints; there is
  no expiry-based freshness guarantee.
- Restart and eviction lose proof and sequence knowledge, allowing old valid
  records to be accepted again and temporarily reducing V2 discovery coverage.
- Signatures increase message sizes. Consumers of the earlier draft V2 wire
  format need coordinated upgrades.

### Neutral

- Dial failure handling, reachability evidence, routing admission, trust, and
  snapshot validity retain their separate responsibilities.
- Persisting full V2 records and proactively refreshing every restored peer
  are outside this decision. Existing lookup and publication paths relearn them.

## Alternatives considered

- **Expire V2 records or renew signatures on a timer.** Rejected: time passing
  provides no replacement addresses. Retain the latest known publication and
  accept that dialing determines current usability.
- **Use one replacement sequence for V1 and V2.** Rejected: a newer QUIC-only
  update must not erase or block independently useful supplemental information.
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
publication ordering, V1 preservation of V2, supplemental-only replacement,
unchanged-signature reuse, forwarding, response bounds, and reconnect source
selection. Persistence tests cover snapshot encoding, validity, and bounded
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
