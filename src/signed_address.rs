// Copyright 2026 Saorsa Labs Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable owner-signed address publications. Forward the original signed
//! record; filtering and reachability normalization belong to derived views.

use crate::identity::node_identity::{NodeIdentity, peer_id_from_public_key};
use crate::quantum_crypto::saorsa_transport_integration::{MlDsaPublicKey, MlDsaSignature};
use crate::{
    AddressType, DHTNode, KnownReachability, KnownTransport, MAX_TRANSPORT_ADDRESS_RECORDS,
    MultiAddr, PeerId, TransportAddressRecord,
};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::{fmt, marker::PhantomData, sync::Arc};

/// Capability token for the extensible address protocol with mandatory owner proofs.
pub const ADDRESS_V2_CAPABILITY: &str = "addr-v2";

/// Maximum lifetime and permitted clock skew for a signed publication.
pub const ADDRESS_RECORD_LIFETIME_SECS: u64 = 60 * 60;
/// Republish unchanged records before their signatures expire.
pub const ADDRESS_RECORD_REFRESH_SECS: u64 = ADDRESS_RECORD_LIFETIME_SECS / 2;
/// Upper bound for one encoded signed address record.
pub const MAX_SIGNED_ADDRESS_BYTES: usize = 40 * 1024;
const CLOCK_SKEW_SECS: u64 = 120;
const DOMAIN: &str = "saorsa/address-record/1";

/// Original immutable publication, including the owner's identity proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAddressRecord {
    owner: PeerId,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    #[serde(deserialize_with = "records")]
    records: Vec<TransportAddressRecord>,
    #[serde(deserialize_with = "public_key")]
    public_key: Vec<u8>,
    #[serde(deserialize_with = "signature")]
    signature: Vec<u8>,
}

/// A publication whose owner, bounds, freshness and signature were verified.
/// It cannot be constructed by deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAddressRecord(Arc<SignedAddressRecord>);

/// Local-only provenance. This is deliberately absent from wire peer records.
#[derive(Clone, Debug)]
pub enum AddressAuthority {
    /// Received directly on the owner's authenticated connection.
    AuthenticatedOwner(u64),
    /// A portable owner signature, independently checked by this process.
    Signed(VerifiedAddressRecord),
}

impl AddressAuthority {
    /// Sequence established by the owner rather than asserted by an intermediary.
    pub fn sequence(&self) -> u64 {
        match self {
            Self::AuthenticatedOwner(seq) => *seq,
            Self::Signed(record) => record.sequence(),
        }
    }
}

impl SignedAddressRecord {
    /// Sign one nonempty publication with the existing node identity.
    pub fn sign(
        identity: &NodeIdentity,
        sequence: u64,
        now: u64,
        records: Vec<TransportAddressRecord>,
    ) -> Result<Self, String> {
        let mut record = Self {
            owner: *identity.peer_id(),
            sequence,
            issued_at: now,
            expires_at: now
                .checked_add(ADDRESS_RECORD_LIFETIME_SECS)
                .ok_or("address record expiry overflow")?,
            records,
            public_key: identity.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
        };
        record.validate(now)?;
        record.signature = identity
            .sign(&record.signable_bytes()?)
            .map_err(|e| e.to_string())?
            .as_bytes()
            .to_vec();
        Ok(record)
    }

    fn signable_bytes(&self) -> Result<Vec<u8>, String> {
        postcard::to_stdvec(&(
            DOMAIN,
            self.owner,
            self.sequence,
            self.issued_at,
            self.expires_at,
            &self.records,
        ))
        .map_err(|e| e.to_string())
    }

    fn validate(&self, now: u64) -> Result<(), String> {
        if self.sequence == 0
            || self.records.is_empty()
            || self.records.len() > MAX_TRANSPORT_ADDRESS_RECORDS
        {
            return Err("invalid address record sequence or cardinality".into());
        }
        if self.issued_at > now.saturating_add(CLOCK_SKEW_SECS)
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > ADDRESS_RECORD_LIFETIME_SECS
        {
            return Err("expired or invalid address record lifetime".into());
        }
        for record in &self.records {
            if record.address.is_empty()
                || record.address.len() > crate::MAX_TRANSPORT_ADDRESS_PAYLOAD
            {
                return Err("address record payload exceeds bounds".into());
            }
            if let Some(address) = record.decode_known().map_err(|e| e.to_string())? {
                if !address.is_storable() {
                    return Err("address is not a dialable destination".into());
                }
                if address.peer_id().is_some_and(|id| id != &self.owner)
                    || (address.is_webrtc_direct() && address.peer_id() != Some(&self.owner))
                {
                    return Err("address owner mismatch".into());
                }
            } else if KnownTransport::from_id(record.transport).is_some() {
                return Err("address does not match transport identifier".into());
            }
        }
        Ok(())
    }

    /// Verify the signature and public-key-derived owner before using any fields.
    pub fn verify(&self, now: u64) -> Result<VerifiedAddressRecord, String> {
        self.validate(now)?;
        let key = MlDsaPublicKey::from_bytes(&self.public_key).map_err(|e| e.to_string())?;
        if peer_id_from_public_key(&key) != self.owner {
            return Err("address signing key does not match owner".into());
        }
        let signature = MlDsaSignature::from_bytes(&self.signature).map_err(|e| e.to_string())?;
        if !crate::quantum_crypto::ml_dsa_verify(&key, &self.signable_bytes()?, &signature)
            .map_err(|e| e.to_string())?
        {
            return Err("invalid address record signature".into());
        }
        Ok(VerifiedAddressRecord(Arc::new(self.clone())))
    }

    /// Encode the unchanged publication for forwarding.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        postcard::to_stdvec(self).map_err(|e| e.to_string())
    }
    /// Decode with envelope and collection bounds; verification is still required.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_SIGNED_ADDRESS_BYTES {
            return Err("signed address record exceeds envelope limit".into());
        }
        postcard::from_bytes(bytes).map_err(|e| e.to_string())
    }
}

impl VerifiedAddressRecord {
    /// Owner of this publication.
    pub fn owner(&self) -> PeerId {
        self.0.owner
    }
    /// Owner-established sequence.
    pub fn sequence(&self) -> u64 {
        self.0.sequence
    }
    /// Original records, including unknown transport payloads.
    pub fn records(&self) -> &[TransportAddressRecord] {
        &self.0.records
    }
    /// Whether this record is still acceptable for forwarding.
    pub fn is_current(&self, now: u64) -> bool {
        self.0.validate(now).is_ok()
    }
    /// Whether an unchanged local publication should be renewed.
    pub fn needs_refresh(&self, now: u64) -> bool {
        now >= self.0.issued_at.saturating_add(ADDRESS_RECORD_REFRESH_SECS)
    }
    /// Original signed payload, never a filtered projection.
    pub fn signed(&self) -> &SignedAddressRecord {
        &self.0
    }
    /// Derive a portable view of known transports without modifying the signature.
    pub fn peer_record(&self, reliability: f64) -> DHTNode {
        let mut addresses = Vec::<MultiAddr>::new();
        let mut address_types = Vec::new();
        for record in self.records() {
            if let Ok(Some(address)) = record.decode_known() {
                let kind = if address.is_webrtc_direct() {
                    AddressType::Unverified
                } else {
                    match KnownReachability::from_id(record.reachability) {
                        Some(KnownReachability::Relay) => AddressType::Relay,
                        Some(KnownReachability::Direct) => AddressType::Direct,
                        Some(KnownReachability::Lan) => AddressType::Lan,
                        _ => AddressType::Unverified,
                    }
                };
                address_types.push(AddressType::for_advertised_address(&address, kind));
                addresses.push(address);
            }
        }
        DHTNode {
            peer_id: self.owner(),
            addresses,
            address_types,
            distance: crate::peer_record::encode_publish_seq_distance(self.sequence()),
            reliability,
            address_authority: Some(AddressAuthority::Signed(self.clone())),
        }
    }
}

pub(crate) fn bounded_vec<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {N} elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if seq.size_hint().is_some_and(|size| size > N) {
                return Err(de::Error::custom("collection exceeds address record limit"));
            }
            let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
            while let Some(value) = seq.next_element()? {
                if values.len() == N {
                    return Err(de::Error::custom("collection exceeds address record limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, N>(PhantomData))
}
fn records<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<TransportAddressRecord>, D::Error> {
    bounded_vec::<_, _, MAX_TRANSPORT_ADDRESS_RECORDS>(d)
}
fn public_key<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<_, _, { saorsa_pqc::pqc::types::ML_DSA_65_PUBLIC_KEY_SIZE }>(d)
}
fn signature<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec::<_, _, { saorsa_pqc::pqc::types::ML_DSA_65_SIGNATURE_SIZE }>(d)
}

/// Encode signed records in a length-delimited binary body, outside JSON headers.
pub fn encode_record_bundle(records: &[SignedAddressRecord]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for record in records {
        let encoded = record.encode()?;
        if encoded.len() > MAX_SIGNED_ADDRESS_BYTES {
            return Err("signed record exceeds limit".into());
        }
        let length = u32::try_from(encoded.len()).map_err(|e| e.to_string())?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    Ok(bytes)
}

/// Decode a bounded bundle. Callers must verify each record before accepting it.
pub fn decode_record_bundle(
    mut bytes: &[u8],
    max_records: usize,
) -> Result<Vec<SignedAddressRecord>, String> {
    let mut records = Vec::new();
    while !bytes.is_empty() {
        if records.len() >= max_records || bytes.len() < 4 {
            return Err("invalid signed record bundle".into());
        }
        let prefix: [u8; 4] = bytes[..4].try_into().map_err(|_| "invalid length prefix")?;
        let length = u32::from_be_bytes(prefix) as usize;
        bytes = &bytes[4..];
        let record = bytes.get(..length).ok_or("truncated signed record")?;
        records.push(SignedAddressRecord::decode(record)?);
        bytes = &bytes[length..];
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(identity: &NodeIdentity, sequence: u64) -> SignedAddressRecord {
        SignedAddressRecord::sign(
            identity,
            sequence,
            1000,
            vec![TransportAddressRecord {
                transport: 900,
                reachability: 901,
                address: vec![1, 2, 3],
            }],
        )
        .unwrap()
    }
    #[test]
    fn signatures_bind_owner_sequence_expiry_and_opaque_future_records() {
        let identity = NodeIdentity::generate().unwrap();
        let original = record(&identity, 10);
        let encoded = original.encode().unwrap();
        let verified = SignedAddressRecord::decode(&encoded)
            .unwrap()
            .verify(1000)
            .unwrap();
        assert_eq!(verified.owner(), *identity.peer_id());
        assert_eq!(verified.signed().encode().unwrap(), encoded);
        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.owner = PeerId::from_bytes([7; 32]);
        mutations.push(changed);
        let mut changed = original.clone();
        changed.sequence = u64::MAX;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.expires_at -= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.records[0].address[0] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.signature[0] ^= 1;
        mutations.push(changed);
        for changed in mutations {
            assert!(changed.verify(1000).is_err());
        }
        assert!(
            original
                .verify(1000 + ADDRESS_RECORD_LIFETIME_SECS)
                .is_err()
        );
        assert!(original.verify(0).is_err());
    }
    #[test]
    fn bounded_decode_and_nonempty_rules_apply_before_signature_verification() {
        let identity = NodeIdentity::generate().unwrap();
        assert!(SignedAddressRecord::sign(&identity, 1, 1000, Vec::new()).is_err());
        let mut malformed = record(&identity, 1);
        malformed.records = vec![malformed.records[0].clone(); MAX_TRANSPORT_ADDRESS_RECORDS + 1];
        assert!(SignedAddressRecord::decode(&malformed.encode().unwrap()).is_err());
        malformed = record(&identity, 1);
        malformed.records[0].address = vec![1; crate::MAX_TRANSPORT_ADDRESS_PAYLOAD + 1];
        assert!(SignedAddressRecord::decode(&malformed.encode().unwrap()).is_err());
        let bytes = encode_record_bundle(&[record(&identity, 1)]).unwrap();
        assert_eq!(decode_record_bundle(&bytes, 1).unwrap().len(), 1);
        assert!(decode_record_bundle(&bytes, 0).is_err());
        assert!(decode_record_bundle(&bytes[..bytes.len() - 1], 1).is_err());
    }
    #[test]
    fn deserialization_cannot_grant_authority_or_override_a_verified_view() {
        let identity = NodeIdentity::generate().unwrap();
        let signed = record(&identity, 10).verify(1000).unwrap();
        let known = signed.peer_record(1.0);
        let bytes = postcard::to_stdvec(&known).unwrap();
        let mut hint: DHTNode = postcard::from_bytes(&bytes).unwrap();
        assert!(hint.address_authority.is_none());
        hint.distance = crate::peer_record::encode_publish_seq_distance(u64::MAX);
        hint.addresses
            .push("/ip4/8.8.8.8/udp/1/quic".parse().unwrap());
        assert_eq!(crate::peer_record::dht_node_publish_seq(&hint), 0);
        assert!(!crate::client_routing::may_replace_owner_view(
            &known, &hint
        ));
        let mut merged = known.clone();
        merged.merge_from(hint.clone());
        assert!(merged.addresses.is_empty());
        let reports = std::collections::HashMap::from([
            (known.peer_id, hint),
            (PeerId::from_bytes([9; 32]), known.clone()),
        ]);
        let (_, winner) = crate::client_routing::compute_winner(&known.peer_id, &reports).unwrap();
        assert_eq!(crate::peer_record::dht_node_publish_seq(winner), 10);
    }
}
