// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for the request/response API and trust feedback.
//!
//! Tests cover:
//! - `PeerFailureReason` enum semantics
//! - `RequestResponseEnvelope` serialization round-trip
//! - `P2PNode::parse_request_envelope` helper

use saorsa_core::error::PeerFailureReason;

/// Mirror of the private `RequestResponseEnvelope` for constructing test bytes.
#[derive(serde::Serialize, serde::Deserialize)]
struct TestEnvelope {
    message_id: String,
    is_response: bool,
    payload: Vec<u8>,
}

// ---- PeerFailureReason tests ----

#[test]
fn test_failure_reason_transient_classification() {
    assert!(PeerFailureReason::Timeout.is_transient());
    assert!(PeerFailureReason::ConnectionFailed.is_transient());
    assert!(!PeerFailureReason::DataUnavailable.is_transient());
    assert!(!PeerFailureReason::CorruptedData.is_transient());
    assert!(!PeerFailureReason::ProtocolError.is_transient());
    assert!(!PeerFailureReason::Refused.is_transient());
}

#[test]
fn test_failure_reason_severity_ranges() {
    let all_reasons = [
        PeerFailureReason::Timeout,
        PeerFailureReason::ConnectionFailed,
        PeerFailureReason::DataUnavailable,
        PeerFailureReason::CorruptedData,
        PeerFailureReason::ProtocolError,
        PeerFailureReason::Refused,
    ];

    for reason in &all_reasons {
        let severity = reason.trust_severity();
        assert!(
            (0.0..=1.0).contains(&severity),
            "{:?} severity {} out of range",
            reason,
            severity
        );
    }

    // Transient failures have lower severity than data integrity failures
    assert!(
        PeerFailureReason::Timeout.trust_severity()
            < PeerFailureReason::CorruptedData.trust_severity()
    );
    assert!(
        PeerFailureReason::ConnectionFailed.trust_severity()
            < PeerFailureReason::ProtocolError.trust_severity()
    );
}

#[test]
fn test_failure_reason_display() {
    assert_eq!(PeerFailureReason::Timeout.to_string(), "timeout");
    assert_eq!(
        PeerFailureReason::ConnectionFailed.to_string(),
        "connection_failed"
    );
    assert_eq!(
        PeerFailureReason::DataUnavailable.to_string(),
        "data_unavailable"
    );
    assert_eq!(
        PeerFailureReason::CorruptedData.to_string(),
        "corrupted_data"
    );
    assert_eq!(
        PeerFailureReason::ProtocolError.to_string(),
        "protocol_error"
    );
    assert_eq!(PeerFailureReason::Refused.to_string(), "refused");
}

#[test]
fn test_failure_reason_serde_roundtrip() {
    for reason in &[
        PeerFailureReason::Timeout,
        PeerFailureReason::ConnectionFailed,
        PeerFailureReason::DataUnavailable,
        PeerFailureReason::CorruptedData,
        PeerFailureReason::ProtocolError,
        PeerFailureReason::Refused,
    ] {
        let json = serde_json::to_string(reason).unwrap();
        let roundtripped: PeerFailureReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, roundtripped);
    }
}

// ---- RequestResponseEnvelope tests ----

#[test]
fn test_request_envelope_roundtrip() {
    use saorsa_core::P2PNode;

    let data = b"hello world".to_vec();

    let envelope = TestEnvelope {
        message_id: "test-msg-id-123".to_string(),
        is_response: false,
        payload: data.clone(),
    };
    let bytes = postcard::to_allocvec(&envelope).unwrap();

    let parsed = P2PNode::parse_request_envelope(&bytes);
    assert!(parsed.is_some());
    let (msg_id, is_response, payload) = parsed.unwrap();
    assert_eq!(msg_id, "test-msg-id-123");
    assert!(!is_response);
    assert_eq!(payload, data);
}

#[test]
fn test_response_envelope_roundtrip() {
    use saorsa_core::P2PNode;

    let response_data = b"response payload".to_vec();
    let envelope = TestEnvelope {
        message_id: "resp-456".to_string(),
        is_response: true,
        payload: response_data.clone(),
    };
    let bytes = postcard::to_allocvec(&envelope).unwrap();

    let parsed = P2PNode::parse_request_envelope(&bytes);
    assert!(parsed.is_some());
    let (msg_id, is_response, payload) = parsed.unwrap();
    assert_eq!(msg_id, "resp-456");
    assert!(is_response);
    assert_eq!(payload, response_data);
}

#[test]
fn test_parse_invalid_envelope() {
    use saorsa_core::P2PNode;

    // Random bytes should fail to parse
    let garbage = vec![0xFF, 0xFE, 0xFD];
    assert!(P2PNode::parse_request_envelope(&garbage).is_none());
}
