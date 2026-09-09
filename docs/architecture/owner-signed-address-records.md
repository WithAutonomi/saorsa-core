# Owner-signed address records

Address publications use the existing ML-DSA-65 node identity. A portable
`SignedAddressRecord` binds its public-key-derived peer ID, nonzero sequence,
and the complete nonempty transport-address set. Publications have no issuance
or expiry timestamps. The signed Postcard tuple starts with the domain
`saorsa/address-record/2`.
Unknown numeric transport and reachability identifiers remain opaque and are
covered by the signature, allowing future address types without new operations.

Verification lives in shared `saorsa_core::signed_address`, available without
native networking features. It checks collection and payload bounds, owner/key
binding, known-address validity, and signature before returning a
`VerifiedAddressRecord`. This type and `DHTNode::address_authority` cannot be
deserialized from peer-provided metadata. Native and browser routing use the
same provenance-aware report selection and replacement rules.

## Forwarding and replacement

Forwarders retain the original signed publication. Local address filtering,
reachability normalization, and native QUIC projection never rewrite its proof.
Only an owner-proven sequence can replace an accepted owner view; unsigned
third-party V1 sequences have no authority. Legacy third-party entries remain
discovery hints and use the existing quorum policy. Direct publications over
an authenticated owner connection remain supported for compatibility.

Receivers retain the latest known signed publication without an age limit.
Owners reuse the same signature for unchanged addresses; the periodic self-lookup
task still republishes it for discovery. A changed address set receives a higher
sequence. Sequence watermarks are bounded, in-memory state, so this is not a
persistent anti-replay ledger across eviction or process restart. A receiver
without newer information can accept an old valid publication. This is an
intentional latest-known phonebook policy, not a guarantee of global freshness.

QUIC and V2 versions advance independently. V1 publications and authenticated V1
self-reports update only the native QUIC projection, preserving the signed V2
record, supplemental addresses, and opaque future transports. A delayed V2
publication can update supplemental addresses while its older QUIC projection
is ignored. A newer nonempty V2 replacement that omits WebRTC removes those
WebRTC addresses; an older V2 replay cannot restore them. Equal-sequence V1/V2
projections must agree on their QUIC addresses.

Lookup results use the same scoped merge. `AddressAuthority::Combined` records
the QUIC sequence alongside the unchanged V2 proof when the two views differ.
It is local provenance, not a signature over the combined list. Forwarders send
the original V2 bytes, which can contain older QUIC information; receivers with
newer QUIC information must retain it. V1 information never becomes a synthetic
V2 publication.

Publications remain nonempty full replacements; there is no withdrawal message.
A replacement containing only non-QUIC transports does not erase the previous
native QUIC projection. Authenticity establishes ownership of the advertisement,
not independent evidence that its endpoints are reachable.

## Compatibility and bounds

The signed identity announcement advertises `addr-v2`. V2 uses
`/dht/address/2.0.0` and requires owner signatures in both publications and lookup
entries. Its unsigned draft never shipped and is not retained. There is no
separate signed protocol or capability. Removing timestamps changes the draft
V2 signed wire format and signing domain; native and browser consumers must
upgrade together. `SignedAddressRecord::sign` and `verify` no longer take a
clock argument. `compute_winner` returns an owned peer view because it may
combine information from multiple reports. V1 retains its original operations and
wire discriminants for older peers; only that fallback can supply unsigned
third-party discovery hints.

V2 lookup replies omit peers without an owner proof, including peers
known only through V1 or after cache loss. A V2 reply cannot
substitute an unsigned entry. Its envelopes allow 960 KiB, enough for a full
closest-peer response with ML-DSA proofs while leaving room in the transport's
1 MiB envelope. V1 retains its 64 KiB limit. Record collections, proof sizes,
and V2 lookup entry counts have explicit decoding bounds.

Browser FIND_NODE requests opt into a length-delimited binary proof bundle.
The node returns only proven peers for these requests. The authenticated HELLO
advertises the same `addr-v2` capability, and ant-core rejects any peer without
an owner proof in that response. Browser adapters call the same portable
verifier and preserve the original publication bytes. Older browser servers
without the capability can still supply legacy discovery hints. Upgrading a
forwarder cannot fix the trust policy of an older client that still treats
arbitrary advertised sequences as authority.
