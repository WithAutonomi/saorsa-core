# Owner-signed address records

Address publications use the existing ML-DSA-65 node identity. A portable
`SignedAddressRecord` binds its public-key-derived peer ID, nonzero sequence,
issuance and expiry times, and the complete nonempty transport-address set.
The signed Postcard tuple starts with the domain `saorsa/address-record/1`.
Unknown numeric transport and reachability identifiers remain opaque and are
covered by the signature, allowing future address types without new operations.

Verification lives in shared `saorsa_core::signed_address`, available without
native networking features. It checks collection and payload bounds, owner/key
binding, known-address validity, lifetime, and signature before returning a
`VerifiedAddressRecord`. This type and `DHTNode::address_authority` cannot be
deserialized from peer-provided metadata. Native and browser routing use the
same provenance-aware report selection and replacement rules.

## Forwarding and replacement

Forwarders retain the original signed publication. Local address filtering,
reachability normalization, and native QUIC projection never rewrite its proof.
Only an owner-proven sequence can replace an accepted owner view; unsigned
third-party V1/V2 sequences have no authority. Legacy third-party entries remain
discovery hints and use the existing quorum policy. Direct publications over
an authenticated owner connection remain supported for compatibility.

Records expire after one hour. Owners renew unchanged records after thirty
minutes; the existing periodic self-lookup task also republishes them. Sequence
watermarks remain in the native address cache after proof expiry, but expired
proofs are never forwarded. Watermarks are bounded, in-memory state, so this
is not a persistent anti-replay ledger across eviction or process restart.

Publications remain nonempty full replacements; there is no withdrawal message.
A replacement containing only non-QUIC transports does not erase the previous
native QUIC projection. Authenticity establishes ownership of the advertisement,
not independent evidence that its endpoints are reachable.

## Compatibility and bounds

The signed identity announcement advertises `addr-signed-v1`. Capable peers use
`/dht/address/signed/1.0.0`; other peers keep the existing V1/V2 operations and
wire discriminants. Signed lookup envelopes allow 960 KiB, enough for a full
closest-peer response with ML-DSA proofs while leaving room in the transport's
1 MiB envelope. Legacy topics retain their 64 KiB limit. Record collections,
proof sizes, and signed lookup entry counts have explicit decoding bounds.

Browser FIND_NODE requests opt into a length-delimited binary proof bundle.
The existing JSON header limit stays unchanged. The node forwards the original
proofs, and ant-core verifies them with the same portable implementation before
using their addresses or updating its routing cache. Legacy responses have no
proof bundle and supply hints. Upgrading a forwarder cannot fix the trust policy
of an older client that still treats arbitrary advertised sequences as authority.
