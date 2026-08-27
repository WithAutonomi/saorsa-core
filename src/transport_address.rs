//! Extensible address records for the versioned DHT address plane.
//!
//! The wire record deliberately stores numeric identifiers and an opaque,
//! length-delimited payload rather than serialized Rust enums. A node that
//! does not know a future transport or reachability identifier can still
//! decode, retain, and forward the record without interpreting it.

use crate::{MultiAddr, dht::AddressType};
use serde::{Deserialize, Serialize};

/// Maximum encoded address payload accepted from the network.
pub const MAX_TRANSPORT_ADDRESS_PAYLOAD: usize = 2 * 1024;

/// Maximum number of records accepted in one complete address set.
pub const MAX_TRANSPORT_ADDRESS_RECORDS: usize = 16;

/// A transport understood by this implementation.
///
/// This enum is never serialized. Its stable numeric identifier is carried by
/// [`TransportAddressRecord::transport`] so unknown future values remain
/// decodable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownTransport {
    /// Saorsa's native QUIC transport.
    Quic,
    /// Signaling-free, certificate-pinned WebRTC Direct.
    WebRtcDirect,
}

impl KnownTransport {
    /// Stable wire identifier for QUIC.
    pub const QUIC_ID: u16 = 1;
    /// Stable wire identifier for WebRTC Direct.
    pub const WEBRTC_DIRECT_ID: u16 = 2;

    /// Return the stable wire identifier.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Quic => Self::QUIC_ID,
            Self::WebRtcDirect => Self::WEBRTC_DIRECT_ID,
        }
    }

    /// Resolve a known identifier, leaving unknown identifiers opaque.
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            Self::QUIC_ID => Some(Self::Quic),
            Self::WEBRTC_DIRECT_ID => Some(Self::WebRtcDirect),
            _ => None,
        }
    }
}

/// A reachability class understood by this implementation.
///
/// Like [`KnownTransport`], this is an in-memory helper rather than a wire
/// enum. Numeric identifiers are stable and must never be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownReachability {
    Relay,
    Direct,
    Unverified,
    Lan,
}

impl KnownReachability {
    pub const RELAY_ID: u16 = 1;
    pub const DIRECT_ID: u16 = 2;
    pub const UNVERIFIED_ID: u16 = 3;
    pub const LAN_ID: u16 = 4;

    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Relay => Self::RELAY_ID,
            Self::Direct => Self::DIRECT_ID,
            Self::Unverified => Self::UNVERIFIED_ID,
            Self::Lan => Self::LAN_ID,
        }
    }

    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            Self::RELAY_ID => Some(Self::Relay),
            Self::DIRECT_ID => Some(Self::Direct),
            Self::UNVERIFIED_ID => Some(Self::Unverified),
            Self::LAN_ID => Some(Self::Lan),
            _ => None,
        }
    }

    #[must_use]
    pub(crate) const fn from_legacy(value: AddressType) -> Self {
        match value {
            AddressType::Relay => Self::Relay,
            AddressType::Direct => Self::Direct,
            AddressType::Unverified => Self::Unverified,
            AddressType::Lan => Self::Lan,
        }
    }

    #[must_use]
    pub(crate) const fn into_legacy(self) -> AddressType {
        match self {
            Self::Relay => AddressType::Relay,
            Self::Direct => AddressType::Direct,
            Self::Unverified => AddressType::Unverified,
            Self::Lan => AddressType::Lan,
        }
    }
}

/// One address in the extensible V2 address plane.
///
/// `address` is Postcard-encoded [`MultiAddr`] for transports known today.
/// Consumers must inspect `transport` before decoding it. Unknown transports
/// retain opaque bytes so intermediaries can forward them unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAddressRecord {
    pub transport: u16,
    pub reachability: u16,
    pub address: Vec<u8>,
}

impl TransportAddressRecord {
    /// Encode a currently supported address.
    pub fn from_multiaddr(
        address: &MultiAddr,
        reachability: KnownReachability,
    ) -> Result<Option<Self>, postcard::Error> {
        let transport = if address.is_quic() {
            KnownTransport::Quic
        } else if address.is_webrtc_direct() {
            KnownTransport::WebRtcDirect
        } else {
            return Ok(None);
        };

        Ok(Some(Self {
            transport: transport.id(),
            reachability: reachability.id(),
            address: postcard::to_stdvec(address)?,
        }))
    }

    /// Decode an address only when its transport identifier is known.
    ///
    /// Unknown identifiers return `Ok(None)` and remain safe to forward.
    pub fn decode_known(&self) -> Result<Option<MultiAddr>, postcard::Error> {
        let Some(transport) = KnownTransport::from_id(self.transport) else {
            return Ok(None);
        };
        let address: MultiAddr = postcard::from_bytes(&self.address)?;
        let matches_transport = match transport {
            KnownTransport::Quic => address.is_quic(),
            KnownTransport::WebRtcDirect => address.is_webrtc_direct(),
        };
        Ok(matches_transport.then_some(address))
    }

    #[must_use]
    pub(crate) fn legacy_reachability(&self) -> Option<AddressType> {
        KnownReachability::from_id(self.reachability).map(KnownReachability::into_legacy)
    }

    #[must_use]
    pub(crate) fn is_within_wire_bounds(&self) -> bool {
        !self.address.is_empty() && self.address.len() <= MAX_TRANSPORT_ADDRESS_PAYLOAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerId, WebRtcCertificateHash, WebRtcDirectAddr};

    #[test]
    fn known_names_have_stable_open_wire_ids() {
        assert_eq!(KnownTransport::Quic.id(), 1);
        assert_eq!(KnownTransport::WebRtcDirect.id(), 2);
        assert_eq!(KnownReachability::Relay.id(), 1);
        assert_eq!(KnownReachability::Direct.id(), 2);
        assert_eq!(KnownReachability::Unverified.id(), 3);
        assert_eq!(KnownReachability::Lan.id(), 4);
    }

    #[test]
    fn unknown_identifiers_round_trip_without_enum_decode_failure() {
        let record = TransportAddressRecord {
            transport: 900,
            reachability: 901,
            address: vec![1, 2, 3, 4],
        };
        let bytes = postcard::to_stdvec(&record).unwrap();
        let decoded: TransportAddressRecord = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(decoded, record);
        assert_eq!(decoded.decode_known().unwrap(), None);
        assert_eq!(decoded.legacy_reachability(), None);
    }

    #[test]
    fn quic_record_round_trips() {
        let address: MultiAddr = "/ip4/203.0.113.9/udp/12000/quic".parse().unwrap();
        let record = TransportAddressRecord::from_multiaddr(&address, KnownReachability::Direct)
            .unwrap()
            .unwrap();

        assert_eq!(record.transport, KnownTransport::Quic.id());
        assert_eq!(record.legacy_reachability(), Some(AddressType::Direct));
        assert_eq!(record.decode_known().unwrap(), Some(address));
    }

    #[test]
    fn webrtc_direct_record_round_trips_independently_of_reachability() {
        let peer_id = PeerId::from_bytes([0x22; 32]);
        let address = MultiAddr::webrtc_direct(
            WebRtcDirectAddr::new(
                "203.0.113.9:42768".parse().unwrap(),
                WebRtcCertificateHash::new([0x33; 32]),
            )
            .unwrap(),
        )
        .with_peer_id(peer_id);
        let record =
            TransportAddressRecord::from_multiaddr(&address, KnownReachability::Unverified)
                .unwrap()
                .unwrap();

        assert_eq!(record.transport, KnownTransport::WebRtcDirect.id());
        assert_eq!(record.legacy_reachability(), Some(AddressType::Unverified));
        assert_eq!(record.decode_known().unwrap(), Some(address));
    }

    #[test]
    fn declared_transport_must_match_the_encoded_multiaddress() {
        let address: MultiAddr = "/ip4/203.0.113.9/udp/12000/quic".parse().unwrap();
        let mut record =
            TransportAddressRecord::from_multiaddr(&address, KnownReachability::Direct)
                .unwrap()
                .unwrap();
        record.transport = KnownTransport::WebRtcDirect.id();

        assert_eq!(record.decode_known().unwrap(), None);
    }
}
