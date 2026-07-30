// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Third-party relay canary probes.
//!
//! A relay acquisition is not publishable just because the local node
//! established a MASQUE session to a candidate relayer. Before the driver
//! writes the relay-allocated address into the DHT, it asks randomized
//! non-close peers to cold-dial that address and confirm that the
//! authenticated identity on the far end is this node.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::stream::{FuturesUnordered, StreamExt};
use rand::{Rng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::address::is_lan_ip;
use crate::dht::AddressType;
use crate::dht_network_manager::{DHTNode, DhtNetworkManager};
use crate::error::P2PError;
use crate::rate_limit::EngineConfig;
use crate::security::canonicalize_ip;
use crate::transport_handle::TransportHandle;
use crate::{MultiAddr, PeerId};

/// Request/response protocol name used with `TransportHandle::send_request`.
pub(crate) const RELAY_CANARY_PROTOCOL: &str = "relay-canary-v2";

/// Wire topic emitted by the request/response wrapper for canary requests.
pub(crate) const RELAY_CANARY_WIRE_TOPIC: &str = "/rr/relay-canary-v2";

/// Number of independent non-close witnesses to ask for a relay proof.
const RELAY_CANARY_WITNESS_TARGET: usize = 3;

/// Positive witness results needed before a relay is publishable.
///
/// Publication is unanimous across the selected independent witnesses. During
/// the mixed-version rollout, a request that was delivered but received no
/// canary-protocol response counts as a positive result so legacy nodes do not
/// make relay availability worse than before the canary gate.
const RELAY_CANARY_ADMISSION_SUCCESSES: usize = RELAY_CANARY_WITNESS_TARGET;

/// One explicit canary-capable dial failure is enough to reject a provisional
/// relay.
const RELAY_CANARY_ADMISSION_FAILURES: usize = 1;

/// Established relays use majority evidence so one witness-specific network
/// failure cannot withdraw a relay that two other witnesses just reached.
const RELAY_CANARY_MAINTENANCE_SUCCESSES: usize = 2;
const RELAY_CANARY_MAINTENANCE_FAILURES: usize = 2;

/// Witness-side handler budget for answering one relay canary request.
///
/// The connect and identity budgets below fit inside this cap, with a small
/// margin for serialization and sending the response before the requester
/// gives up.
pub(crate) const RELAY_CANARY_HANDLER_TIMEOUT: Duration = Duration::from_secs(11);

/// End-to-end budget for asking one witness to dial the proposed relay.
///
/// The witness-side DHT handler has a smaller cap. Keep the requester
/// budget above that so slow-but-valid witness dials are not discarded just
/// before the handler can reply.
const RELAY_CANARY_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);

/// Cold-dial connection budget spent by a witness when probing a relay.
///
/// A relay that cannot establish a transport connection within this window is
/// a failed probe, not an ineligible witness. Keeping this below the handler
/// budget leaves room for the identity check and response.
const RELAY_CANARY_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Sliding window for per-source relay canary rate limiting.
const RELAY_CANARY_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Maximum canary-triggered cold dials a single source may request per window.
const RELAY_CANARY_RATE_MAX_PER_WINDOW: u32 = 1;
const RELAY_CANARY_GLOBAL_RATE_WINDOW: Duration = Duration::from_secs(10);
const RELAY_CANARY_GLOBAL_RATE_MAX_PER_WINDOW: u32 = 16;
const RELAY_CANARY_DESTINATION_RATE_WINDOW: Duration = Duration::from_secs(10);
const RELAY_CANARY_DESTINATION_RATE_MAX_PER_WINDOW: u32 = 2;

/// Per-source throttle applied to inbound relay canary requests.
///
/// Answering a canary request makes this node cold-dial an arbitrary relay
/// address, so each authenticated source is limited to one dial per window to
/// stop a peer using this node as a reflection/amplification dialer. A
/// legitimate source asks any given witness at most once per acquisition cycle
/// (>= the driver backoff), so this never throttles honest traffic.
pub(crate) fn relay_canary_rate_limit_config() -> EngineConfig {
    EngineConfig {
        window: RELAY_CANARY_RATE_WINDOW,
        max_requests: RELAY_CANARY_RATE_MAX_PER_WINDOW,
        burst_size: RELAY_CANARY_RATE_MAX_PER_WINDOW,
    }
}

/// Node-wide cap on accepted canary work, independent of requester identity.
pub(crate) fn relay_canary_global_rate_limit_config() -> EngineConfig {
    EngineConfig {
        window: RELAY_CANARY_GLOBAL_RATE_WINDOW,
        max_requests: RELAY_CANARY_GLOBAL_RATE_MAX_PER_WINDOW,
        burst_size: RELAY_CANARY_GLOBAL_RATE_MAX_PER_WINDOW,
    }
}

/// Cap repeated canary work aimed at the same signed relay allocation.
pub(crate) fn relay_canary_destination_rate_limit_config() -> EngineConfig {
    EngineConfig {
        window: RELAY_CANARY_DESTINATION_RATE_WINDOW,
        max_requests: RELAY_CANARY_DESTINATION_RATE_MAX_PER_WINDOW,
        burst_size: RELAY_CANARY_DESTINATION_RATE_MAX_PER_WINDOW,
    }
}

/// Socket port zero is not a routable service endpoint.
const UNSPECIFIED_PORT: u16 = 0;

/// Request sent to a witness asking it to verify a proposed relay address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RelayCanaryRequest {
    pub(crate) target_peer_id: PeerId,
    pub(crate) relayer_peer_id: PeerId,
    pub(crate) relay_addr: SocketAddr,
    pub(crate) allocation_receipt: saorsa_transport::RelayAllocationReceipt,
}

impl RelayCanaryRequest {
    fn new(
        target_peer_id: PeerId,
        relayer_peer_id: PeerId,
        relay_addr: SocketAddr,
        allocation_receipt: saorsa_transport::RelayAllocationReceipt,
    ) -> Self {
        Self {
            target_peer_id,
            relayer_peer_id,
            relay_addr,
            allocation_receipt,
        }
    }
}

/// Witness response after attempting the cold relay dial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RelayCanaryResponse {
    pub(crate) result: RelayCanaryProbeResult,
}

/// Request-level outcome after the requester has contacted a selected witness.
#[derive(Debug)]
pub(crate) enum RelayCanaryRequestOutcome {
    /// The witness supports the canary protocol and returned a typed result.
    Response(RelayCanaryResponse),
    /// The request was sent, but no canary-protocol response arrived.
    NoProtocolResponse,
}

/// Result of one witness's relay probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum RelayCanaryProbeResult {
    Success,
    DialFailed,
    IdentityExchangeFailed,
    IdentityMismatch,
    WitnessRateLimited,
}

impl RelayCanaryProbeResult {
    fn disposition(&self) -> RelayCanaryProbeDisposition {
        match self {
            Self::Success => RelayCanaryProbeDisposition::Success,
            Self::WitnessRateLimited => RelayCanaryProbeDisposition::Ineligible,
            Self::DialFailed | Self::IdentityExchangeFailed | Self::IdentityMismatch => {
                RelayCanaryProbeDisposition::Failure
            }
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Success => "success".to_string(),
            Self::DialFailed => "dial failed".to_string(),
            Self::IdentityExchangeFailed => "identity exchange failed".to_string(),
            Self::IdentityMismatch => "identity mismatch".to_string(),
            Self::WitnessRateLimited => "witness rate-limited source".to_string(),
        }
    }
}

/// Reject reason for a malformed or unauthorized canary request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayCanaryRequestRejection {
    SourceMismatch {
        source_peer_id: PeerId,
        target_peer_id: PeerId,
    },
    SelfRelayer {
        peer_id: PeerId,
    },
    UnspecifiedPort,
    UnspecifiedIp,
    LocalScopeIp(IpAddr),
    MulticastIp(IpAddr),
    BroadcastIp(Ipv4Addr),
    InvalidAllocationReceipt(String),
}

impl RelayCanaryRequestRejection {
    pub(crate) fn summary(&self) -> String {
        match self {
            Self::SourceMismatch {
                source_peer_id,
                target_peer_id,
            } => format!(
                "source {} does not match target {}",
                source_peer_id.to_hex(),
                target_peer_id.to_hex()
            ),
            Self::SelfRelayer { peer_id } => {
                format!("target {} also claimed to be relayer", peer_id.to_hex())
            }
            Self::UnspecifiedPort => "relay address has port 0".to_string(),
            Self::UnspecifiedIp => "relay address has unspecified IP".to_string(),
            Self::LocalScopeIp(ip) => format!("relay address uses local-scope IP {ip}"),
            Self::MulticastIp(ip) => format!("relay address uses multicast IP {ip}"),
            Self::BroadcastIp(ip) => format!("relay address uses broadcast IP {ip}"),
            Self::InvalidAllocationReceipt(reason) => {
                format!("invalid relay allocation receipt: {reason}")
            }
        }
    }
}

/// Validate a witness can safely act on a canary request.
pub(crate) fn validate_relay_canary_request(
    source_peer_id: &PeerId,
    request: &RelayCanaryRequest,
) -> std::result::Result<(), RelayCanaryRequestRejection> {
    if request.target_peer_id != *source_peer_id {
        return Err(RelayCanaryRequestRejection::SourceMismatch {
            source_peer_id: *source_peer_id,
            target_peer_id: request.target_peer_id,
        });
    }
    if request.relayer_peer_id == request.target_peer_id {
        return Err(RelayCanaryRequestRejection::SelfRelayer {
            peer_id: request.target_peer_id,
        });
    }

    validate_relay_canary_address(request.relay_addr)?;
    request
        .allocation_receipt
        .verify(
            *request.target_peer_id.to_bytes(),
            *request.relayer_peer_id.to_bytes(),
            request.relay_addr,
            SystemTime::now(),
        )
        .map_err(|error| RelayCanaryRequestRejection::InvalidAllocationReceipt(error.to_string()))
}

fn validate_relay_canary_address(
    relay_addr: SocketAddr,
) -> std::result::Result<(), RelayCanaryRequestRejection> {
    if relay_addr.port() == UNSPECIFIED_PORT {
        return Err(RelayCanaryRequestRejection::UnspecifiedPort);
    }

    let ip = relay_addr.ip();
    if ip.is_unspecified() {
        return Err(RelayCanaryRequestRejection::UnspecifiedIp);
    }
    if is_lan_ip(ip) {
        return Err(RelayCanaryRequestRejection::LocalScopeIp(ip));
    }
    if ip.is_multicast() {
        return Err(RelayCanaryRequestRejection::MulticastIp(ip));
    }
    if let IpAddr::V4(ipv4) = ip
        && ipv4 == Ipv4Addr::BROADCAST
    {
        return Err(RelayCanaryRequestRejection::BroadcastIp(ipv4));
    }

    Ok(())
}

/// Aggregate decision for a just-acquired relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayCanaryVerdict {
    Verified {
        successes: usize,
        attempts: usize,
    },
    Rejected {
        successes: usize,
        attempts: usize,
    },
    Inconclusive {
        successes: usize,
        failures: usize,
        unavailable: usize,
    },
}

/// Evidence policy for a relay canary round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayCanaryPolicy {
    /// A provisional relay needs a positive result from every selected witness.
    Admission,
    /// An established relay is retained or rejected by a completed majority.
    Maintenance,
}

impl RelayCanaryPolicy {
    fn required_successes(self) -> usize {
        match self {
            Self::Admission => RELAY_CANARY_ADMISSION_SUCCESSES,
            Self::Maintenance => RELAY_CANARY_MAINTENANCE_SUCCESSES,
        }
    }

    fn required_failures(self) -> usize {
        match self {
            Self::Admission => RELAY_CANARY_ADMISSION_FAILURES,
            Self::Maintenance => RELAY_CANARY_MAINTENANCE_FAILURES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayCanaryProbeDisposition {
    Success,
    AssumedSuccess,
    Failure,
    Ineligible,
}

#[derive(Debug, Clone)]
struct RelayCanarySummary {
    total: usize,
    responses: usize,
    eligible_attempts: usize,
    successes: usize,
    assumed_successes: usize,
    ineligible: usize,
}

impl RelayCanarySummary {
    fn new(total: usize) -> Self {
        Self {
            total,
            responses: 0,
            eligible_attempts: 0,
            successes: 0,
            assumed_successes: 0,
            ineligible: 0,
        }
    }

    fn record(&mut self, disposition: RelayCanaryProbeDisposition) {
        self.responses += 1;
        match disposition {
            RelayCanaryProbeDisposition::Success => {
                self.eligible_attempts += 1;
                self.successes += 1;
            }
            RelayCanaryProbeDisposition::AssumedSuccess => {
                self.eligible_attempts += 1;
                self.successes += 1;
                self.assumed_successes += 1;
            }
            RelayCanaryProbeDisposition::Failure => {
                self.eligible_attempts += 1;
            }
            RelayCanaryProbeDisposition::Ineligible => {
                self.ineligible += 1;
            }
        }
    }

    fn verdict(&self, policy: RelayCanaryPolicy) -> RelayCanaryVerdict {
        let failures = self.eligible_attempts.saturating_sub(self.successes);
        if self.successes >= policy.required_successes() {
            RelayCanaryVerdict::Verified {
                successes: self.successes,
                attempts: self.eligible_attempts,
            }
        } else if failures >= policy.required_failures() {
            RelayCanaryVerdict::Rejected {
                successes: self.successes,
                attempts: self.eligible_attempts,
            }
        } else {
            RelayCanaryVerdict::Inconclusive {
                successes: self.successes,
                failures,
                unavailable: self.ineligible
                    + RELAY_CANARY_WITNESS_TARGET.saturating_sub(self.total),
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RelayCanaryWitness {
    peer_id: PeerId,
    typed_addresses: Vec<(MultiAddr, AddressType)>,
}

#[derive(Debug, Clone)]
struct RelayCanaryProbeReport {
    witness: PeerId,
    disposition: RelayCanaryProbeDisposition,
    detail: String,
}

/// Verify that `relay_addr` is externally dialable before publication.
pub(crate) async fn verify_relay_with_canaries(
    dht: &Arc<DhtNetworkManager>,
    relayer: PeerId,
    relay_addr: SocketAddr,
    allocation_receipt: saorsa_transport::RelayAllocationReceipt,
    policy: RelayCanaryPolicy,
) -> RelayCanaryVerdict {
    let target_peer_id = *dht.peer_id();
    let request = RelayCanaryRequest::new(
        target_peer_id,
        relayer,
        relay_addr,
        allocation_receipt.clone(),
    );
    if let Err(reason) = validate_relay_canary_request(&target_peer_id, &request) {
        warn!(
            relayer = %relayer.to_hex(),
            relay = %relay_addr,
            reason = %reason.summary(),
            "relay canary: refusing invalid relay address"
        );
        return RelayCanaryVerdict::Rejected {
            successes: 0,
            attempts: 0,
        };
    }

    let target_key = *target_peer_id.to_bytes();
    let close_group_ids: HashSet<PeerId> = dht
        .find_closest_nodes_local(&target_key, dht.k_value())
        .await
        .into_iter()
        .map(|node| node.peer_id)
        .collect();
    let routing_table = dht.routing_table_peers().await;
    let routing_table_size = routing_table.len();
    let witnesses = select_relay_canary_witnesses(
        routing_table,
        &close_group_ids,
        &target_peer_id,
        &relayer,
        relay_addr.ip(),
        RELAY_CANARY_WITNESS_TARGET,
        &mut rand::thread_rng(),
    );

    if witnesses.len() < policy.required_successes() {
        warn!(
            relayer = %relayer.to_hex(),
            relay = %relay_addr,
            available = witnesses.len(),
            required = policy.required_successes(),
            ?policy,
            close_group_excluded = close_group_ids.len(),
            routing_table_size,
            "relay canary: insufficient random non-close witnesses, refusing to publish relay"
        );
        return RelayCanaryVerdict::Inconclusive {
            successes: 0,
            failures: 0,
            unavailable: RELAY_CANARY_WITNESS_TARGET.saturating_sub(witnesses.len()),
        };
    }

    debug!(
        relayer = %relayer.to_hex(),
        relay = %relay_addr,
        available_witnesses = witnesses.len(),
        routing_table_size,
        close_group_excluded = close_group_ids.len(),
        "relay canary: probing random non-close witnesses"
    );

    let mut summary = RelayCanarySummary::new(witnesses.len());
    let mut probes = FuturesUnordered::new();
    for witness in witnesses {
        let dht = Arc::clone(dht);
        let request = RelayCanaryRequest::new(
            target_peer_id,
            relayer,
            relay_addr,
            allocation_receipt.clone(),
        );
        probes.push(async move { request_relay_canary(dht, witness, request).await });
    }

    while let Some(report) = probes.next().await {
        summary.record(report.disposition);
        match report.disposition {
            RelayCanaryProbeDisposition::Success => {
                debug!(
                    witness = %report.witness.to_hex(),
                    successes = summary.successes,
                    eligible_attempts = summary.eligible_attempts,
                    responses = summary.responses,
                    "relay canary: witness confirmed relay"
                );
            }
            RelayCanaryProbeDisposition::AssumedSuccess => {
                debug!(
                    witness = %report.witness.to_hex(),
                    detail = %report.detail,
                    successes = summary.successes,
                    assumed_successes = summary.assumed_successes,
                    eligible_attempts = summary.eligible_attempts,
                    responses = summary.responses,
                    "relay canary: assuming positive result from legacy witness"
                );
            }
            RelayCanaryProbeDisposition::Ineligible => {
                debug!(
                    witness = %report.witness.to_hex(),
                    detail = %report.detail,
                    ineligible = summary.ineligible,
                    eligible_attempts = summary.eligible_attempts,
                    responses = summary.responses,
                    "relay canary: witness could not evaluate relay"
                );
            }
            RelayCanaryProbeDisposition::Failure => {
                debug!(
                    witness = %report.witness.to_hex(),
                    detail = %report.detail,
                    successes = summary.successes,
                    eligible_attempts = summary.eligible_attempts,
                    responses = summary.responses,
                    "relay canary: witness failed relay probe"
                );
            }
        }
    }

    let verdict = summary.verdict(policy);
    match &verdict {
        RelayCanaryVerdict::Verified {
            successes,
            attempts,
        } => info!(
            relayer = %relayer.to_hex(),
            relay = %relay_addr,
            successes,
            attempts,
            responses = summary.responses,
            assumed_successes = summary.assumed_successes,
            ineligible = summary.ineligible,
            available_witnesses = summary.total,
            ?policy,
            "relay canary: completed witness round verified relay"
        ),
        RelayCanaryVerdict::Rejected {
            successes,
            attempts,
        } => warn!(
            relayer = %relayer.to_hex(),
            relay = %relay_addr,
            successes,
            attempts,
            responses = summary.responses,
            assumed_successes = summary.assumed_successes,
            ineligible = summary.ineligible,
            available_witnesses = summary.total,
            ?policy,
            "relay canary: completed witness round rejected relay"
        ),
        RelayCanaryVerdict::Inconclusive {
            successes,
            failures,
            unavailable,
        } => warn!(
            relayer = %relayer.to_hex(),
            relay = %relay_addr,
            successes,
            failures,
            unavailable,
            responses = summary.responses,
            assumed_successes = summary.assumed_successes,
            available_witnesses = summary.total,
            ?policy,
            "relay canary: completed witness round was inconclusive"
        ),
    }
    verdict
}

/// Probe `request.relay_addr` from this witness node and return the result.
pub(crate) async fn answer_relay_canary_request(
    transport: &TransportHandle,
    request: RelayCanaryRequest,
) -> RelayCanaryResponse {
    let relay_address = MultiAddr::quic(request.relay_addr);
    let dial = tokio::time::timeout(
        RELAY_CANARY_CONNECT_TIMEOUT,
        // Keep prospective canary probes separately identifiable in structured
        // logs. Correctness comes from dialing the allocated socket and checking
        // the authenticated target identity below.
        transport.probe_relay_canary_authenticated(&relay_address),
    )
    .await;

    let result = match dial {
        Ok(Ok(authenticated_peer)) => {
            if authenticated_peer == request.target_peer_id {
                RelayCanaryProbeResult::Success
            } else {
                debug!(
                    expected = %request.target_peer_id.to_hex(),
                    actual = %authenticated_peer.to_hex(),
                    relay = %request.relay_addr,
                    "relay canary witness: identity mismatch"
                );
                RelayCanaryProbeResult::IdentityMismatch
            }
        }
        Ok(Err(e)) => {
            debug!(
                relay = %request.relay_addr,
                error = %e,
                "relay canary witness: dial failed"
            );
            RelayCanaryProbeResult::DialFailed
        }
        Err(_) => {
            debug!(
                relay = %request.relay_addr,
                timeout = ?RELAY_CANARY_CONNECT_TIMEOUT,
                "relay canary witness: dial timed out"
            );
            RelayCanaryProbeResult::DialFailed
        }
    };

    RelayCanaryResponse { result }
}

fn select_relay_canary_witnesses<R: Rng + ?Sized>(
    mut candidates: Vec<DHTNode>,
    close_group_ids: &HashSet<PeerId>,
    target_peer_id: &PeerId,
    relayer: &PeerId,
    relay_ip: IpAddr,
    count: usize,
    rng: &mut R,
) -> Vec<RelayCanaryWitness> {
    let mut witnesses = Vec::with_capacity(count);
    let mut seen_ips = HashSet::new();
    let relay_ip = canonicalize_ip(relay_ip);

    candidates.shuffle(rng);
    for node in candidates {
        if node.peer_id == *target_peer_id
            || node.peer_id == *relayer
            || close_group_ids.contains(&node.peer_id)
        {
            continue;
        }

        let typed_addresses = node.typed_addresses();
        if !typed_addresses
            .iter()
            .any(|(addr, _)| addr.dialable_socket_addr().is_some())
        {
            continue;
        }

        let Some(ip) = first_dialable_ip(&typed_addresses) else {
            continue;
        };
        let ip = canonicalize_ip(ip);
        if ip == relay_ip || !seen_ips.insert(ip) {
            continue;
        }

        witnesses.push(RelayCanaryWitness {
            peer_id: node.peer_id,
            typed_addresses,
        });
        if witnesses.len() == count {
            break;
        }
    }

    witnesses
}

fn first_dialable_ip(typed_addresses: &[(MultiAddr, AddressType)]) -> Option<IpAddr> {
    typed_addresses
        .iter()
        .filter_map(|(addr, _)| addr.dialable_socket_addr().map(|sa| sa.ip()))
        .next()
}

async fn request_relay_canary(
    dht: Arc<DhtNetworkManager>,
    witness: RelayCanaryWitness,
    request: RelayCanaryRequest,
) -> RelayCanaryProbeReport {
    let witness_peer_id = witness.peer_id;
    let outcome = dht
        .send_relay_canary_request(
            &witness_peer_id,
            &witness.typed_addresses,
            request,
            RELAY_CANARY_REQUEST_TIMEOUT,
        )
        .await;
    relay_canary_probe_report(witness_peer_id, outcome)
}

fn relay_canary_probe_report(
    witness: PeerId,
    outcome: std::result::Result<RelayCanaryRequestOutcome, P2PError>,
) -> RelayCanaryProbeReport {
    match outcome {
        Ok(RelayCanaryRequestOutcome::Response(response)) => RelayCanaryProbeReport {
            witness,
            disposition: response.result.disposition(),
            detail: response.result.summary(),
        },
        Ok(RelayCanaryRequestOutcome::NoProtocolResponse) => RelayCanaryProbeReport {
            witness,
            disposition: RelayCanaryProbeDisposition::AssumedSuccess,
            detail: "no canary-protocol response; treating selected witness as legacy".to_string(),
        },
        Err(error) => RelayCanaryProbeReport {
            witness,
            disposition: RelayCanaryProbeDisposition::Ineligible,
            detail: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr};

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::error::NetworkError;
    use crate::rate_limit::Engine;

    const TARGET_SEED: u8 = 1;
    const RELAYER_SEED: u8 = 2;
    const CLOSE_GROUP_SEED: u8 = 3;
    const FIRST_WITNESS_SEED: u8 = 4;
    const SECOND_WITNESS_SEED: u8 = 5;
    const THIRD_WITNESS_SEED: u8 = 6;
    const DUPLICATE_IP_WITNESS_SEED: u8 = 7;
    const RELAY_IP_WITNESS_SEED: u8 = 8;
    const TEST_PORT: u16 = 9000;
    const TEST_RNG_SEED: u64 = 42;

    fn peer_id(seed: u8) -> PeerId {
        PeerId::from_bytes([seed; 32])
    }

    fn signed_receipt(
        target: PeerId,
        relay_addr: SocketAddr,
    ) -> (PeerId, saorsa_transport::RelayAllocationReceipt) {
        let (public_key, secret_key) =
            saorsa_transport::generate_ml_dsa_keypair().expect("test keypair");
        let relayer = PeerId::from_bytes(saorsa_transport::fingerprint_public_key(&public_key));
        let receipt = saorsa_transport::RelayAllocationReceipt::issue(
            &public_key,
            &secret_key,
            *target.to_bytes(),
            relay_addr,
            1,
        )
        .expect("test allocation receipt");
        (relayer, receipt)
    }

    fn node(seed: u8, ip: Ipv4Addr) -> DHTNode {
        DHTNode {
            peer_id: peer_id(seed),
            addresses: vec![MultiAddr::from_ipv4(ip, TEST_PORT + u16::from(seed))],
            address_types: vec![AddressType::Direct],
            distance: None,
            reliability: 1.0,
        }
    }

    #[test]
    fn witness_selection_uses_random_non_close_independent_sources() {
        let target = peer_id(TARGET_SEED);
        let relayer = peer_id(RELAYER_SEED);
        let relay_ip = Ipv4Addr::new(203, 0, 113, 2);
        let close_group_ids = HashSet::from([peer_id(CLOSE_GROUP_SEED)]);
        let candidates = vec![
            node(TARGET_SEED, Ipv4Addr::new(203, 0, 113, 1)),
            node(RELAYER_SEED, relay_ip),
            node(CLOSE_GROUP_SEED, Ipv4Addr::new(203, 0, 113, 3)),
            node(FIRST_WITNESS_SEED, Ipv4Addr::new(203, 0, 113, 3)),
            node(SECOND_WITNESS_SEED, Ipv4Addr::new(203, 0, 113, 4)),
            node(THIRD_WITNESS_SEED, Ipv4Addr::new(203, 0, 113, 5)),
            node(DUPLICATE_IP_WITNESS_SEED, Ipv4Addr::new(203, 0, 113, 3)),
            node(RELAY_IP_WITNESS_SEED, relay_ip),
        ];
        let mut rng = StdRng::seed_from_u64(TEST_RNG_SEED);

        let witnesses = select_relay_canary_witnesses(
            candidates,
            &close_group_ids,
            &target,
            &relayer,
            IpAddr::V4(relay_ip),
            RELAY_CANARY_WITNESS_TARGET,
            &mut rng,
        );

        let selected: HashSet<PeerId> = witnesses.iter().map(|w| w.peer_id).collect();
        assert_eq!(selected.len(), RELAY_CANARY_WITNESS_TARGET);
        assert!(!selected.contains(&target));
        assert!(!selected.contains(&relayer));
        assert!(!selected.contains(&peer_id(CLOSE_GROUP_SEED)));
        assert!(!selected.contains(&peer_id(RELAY_IP_WITNESS_SEED)));
        assert!(selected.contains(&peer_id(SECOND_WITNESS_SEED)));
        assert!(selected.contains(&peer_id(THIRD_WITNESS_SEED)));

        let duplicate_pair_selected = selected.contains(&peer_id(FIRST_WITNESS_SEED))
            && selected.contains(&peer_id(DUPLICATE_IP_WITNESS_SEED));
        assert!(!duplicate_pair_selected);
    }

    #[test]
    fn witness_rate_limited_is_ineligible_not_relay_failure() {
        assert_eq!(
            RelayCanaryProbeResult::WitnessRateLimited.disposition(),
            RelayCanaryProbeDisposition::Ineligible
        );
    }

    #[test]
    fn explicit_probe_failures_count_as_relay_failures() {
        assert_eq!(
            RelayCanaryProbeResult::DialFailed.disposition(),
            RelayCanaryProbeDisposition::Failure
        );
        assert_eq!(
            RelayCanaryProbeResult::IdentityExchangeFailed.disposition(),
            RelayCanaryProbeDisposition::Failure
        );
        assert_eq!(
            RelayCanaryProbeResult::IdentityMismatch.disposition(),
            RelayCanaryProbeDisposition::Failure
        );
    }

    #[test]
    fn rate_limit_throttles_per_source_not_across_sources() {
        let limiter = Engine::new(relay_canary_rate_limit_config());
        let source = peer_id(FIRST_WITNESS_SEED);
        let other_source = peer_id(SECOND_WITNESS_SEED);

        // First request from a source is admitted, the immediate next is not.
        assert!(limiter.try_consume_key(&source));
        assert!(!limiter.try_consume_key(&source));
        // A different source is unaffected by another source's throttle.
        assert!(limiter.try_consume_key(&other_source));
    }

    #[test]
    fn ineligible_witnesses_produce_inconclusive_verdict() {
        let mut summary = RelayCanarySummary::new(RELAY_CANARY_WITNESS_TARGET);

        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::Ineligible);
        summary.record(RelayCanaryProbeDisposition::Ineligible);
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Admission),
            RelayCanaryVerdict::Inconclusive {
                successes: 1,
                failures: 0,
                unavailable: 2
            }
        );
    }

    #[test]
    fn one_failure_rejects_admission_but_not_healthy_maintenance_majority() {
        let mut summary = RelayCanarySummary::new(RELAY_CANARY_WITNESS_TARGET);

        summary.record(RelayCanaryProbeDisposition::Failure);
        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::Success);
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Admission),
            RelayCanaryVerdict::Rejected {
                successes: 2,
                attempts: 3
            }
        );
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Maintenance),
            RelayCanaryVerdict::Verified {
                successes: 2,
                attempts: 3
            }
        );
    }

    #[test]
    fn two_failures_reject_maintenance_round() {
        let mut summary = RelayCanarySummary::new(RELAY_CANARY_WITNESS_TARGET);

        summary.record(RelayCanaryProbeDisposition::Failure);
        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::Failure);
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Maintenance),
            RelayCanaryVerdict::Rejected {
                successes: 1,
                attempts: 3
            }
        );
    }

    #[test]
    fn split_maintenance_evidence_is_inconclusive() {
        let mut summary = RelayCanarySummary::new(RELAY_CANARY_WITNESS_TARGET);

        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::Failure);
        summary.record(RelayCanaryProbeDisposition::Ineligible);
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Maintenance),
            RelayCanaryVerdict::Inconclusive {
                successes: 1,
                failures: 1,
                unavailable: 1
            }
        );
    }

    #[test]
    fn two_successes_and_one_ineligible_verify_only_maintenance() {
        let mut summary = RelayCanarySummary::new(RELAY_CANARY_WITNESS_TARGET);

        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::Ineligible);
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Admission),
            RelayCanaryVerdict::Inconclusive {
                successes: 2,
                failures: 0,
                unavailable: 1
            }
        );
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Maintenance),
            RelayCanaryVerdict::Verified {
                successes: 2,
                attempts: 2
            }
        );
    }

    #[test]
    fn missing_canary_response_counts_as_legacy_success() {
        assert_eq!(
            relay_canary_probe_report(
                peer_id(FIRST_WITNESS_SEED),
                Ok(RelayCanaryRequestOutcome::NoProtocolResponse)
            )
            .disposition,
            RelayCanaryProbeDisposition::AssumedSuccess
        );
    }

    #[test]
    fn witness_network_timeout_is_ineligible() {
        assert_eq!(
            relay_canary_probe_report(
                peer_id(FIRST_WITNESS_SEED),
                Err(P2PError::Network(NetworkError::Timeout))
            )
            .disposition,
            RelayCanaryProbeDisposition::Ineligible
        );
    }

    #[test]
    fn assumed_legacy_successes_satisfy_admission_threshold() {
        let mut summary = RelayCanarySummary::new(RELAY_CANARY_WITNESS_TARGET);

        summary.record(RelayCanaryProbeDisposition::Success);
        summary.record(RelayCanaryProbeDisposition::AssumedSuccess);
        summary.record(RelayCanaryProbeDisposition::AssumedSuccess);

        assert_eq!(summary.assumed_successes, 2);
        assert_eq!(
            summary.verdict(RelayCanaryPolicy::Admission),
            RelayCanaryVerdict::Verified {
                successes: 3,
                attempts: 3
            }
        );
    }

    #[test]
    fn witness_contact_failure_is_ineligible() {
        assert_eq!(
            relay_canary_probe_report(
                peer_id(FIRST_WITNESS_SEED),
                Err(P2PError::Network(NetworkError::PeerNotFound(
                    "witness".into()
                )))
            )
            .disposition,
            RelayCanaryProbeDisposition::Ineligible
        );
    }

    #[test]
    fn canary_request_rejects_source_mismatch() {
        let relay_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), TEST_PORT));
        let target = peer_id(TARGET_SEED);
        let (relayer, receipt) = signed_receipt(target, relay_addr);
        let request = RelayCanaryRequest::new(target, relayer, relay_addr, receipt);

        let err = validate_relay_canary_request(&peer_id(FIRST_WITNESS_SEED), &request)
            .expect_err("source mismatch must be rejected");

        assert!(matches!(
            err,
            RelayCanaryRequestRejection::SourceMismatch { .. }
        ));
    }

    #[test]
    fn canary_request_accepts_valid_signed_allocation() {
        let target = peer_id(TARGET_SEED);
        let relay_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), TEST_PORT));
        let (relayer, receipt) = signed_receipt(target, relay_addr);
        let request = RelayCanaryRequest::new(target, relayer, relay_addr, receipt);

        assert!(validate_relay_canary_request(&target, &request).is_ok());
    }

    #[test]
    fn canary_request_rejects_receipt_for_another_address() {
        let target = peer_id(TARGET_SEED);
        let signed_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), TEST_PORT));
        let requested_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), TEST_PORT));
        let (relayer, receipt) = signed_receipt(target, signed_addr);
        let request = RelayCanaryRequest::new(target, relayer, requested_addr, receipt);

        let error = validate_relay_canary_request(&target, &request)
            .expect_err("receipt must bind the exact requested allocation");

        assert!(matches!(
            error,
            RelayCanaryRequestRejection::InvalidAllocationReceipt(_)
        ));
    }

    #[test]
    fn canary_request_rejects_local_scope_relay_address() {
        let target = peer_id(TARGET_SEED);
        let relay_addr = SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), TEST_PORT));
        let (relayer, receipt) = signed_receipt(target, relay_addr);
        let request = RelayCanaryRequest::new(target, relayer, relay_addr, receipt);

        let err = validate_relay_canary_request(&peer_id(TARGET_SEED), &request)
            .expect_err("private relay address must be rejected");

        assert!(matches!(err, RelayCanaryRequestRejection::LocalScopeIp(_)));
    }

    #[test]
    fn canary_request_rejects_unspecified_port() {
        let target = peer_id(TARGET_SEED);
        let relay_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), UNSPECIFIED_PORT));
        let (relayer, receipt) = signed_receipt(target, relay_addr);
        let request = RelayCanaryRequest::new(target, relayer, relay_addr, receipt);

        let err = validate_relay_canary_request(&peer_id(TARGET_SEED), &request)
            .expect_err("port zero must be rejected");

        assert_eq!(err, RelayCanaryRequestRejection::UnspecifiedPort);
    }

    #[test]
    fn canary_request_rejects_self_as_relayer() {
        let relay_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), TEST_PORT));
        let (public_key, secret_key) =
            saorsa_transport::generate_ml_dsa_keypair().expect("test keypair");
        let target = PeerId::from_bytes(saorsa_transport::fingerprint_public_key(&public_key));
        let receipt = saorsa_transport::RelayAllocationReceipt::issue(
            &public_key,
            &secret_key,
            *target.to_bytes(),
            relay_addr,
            1,
        )
        .expect("test allocation receipt");
        let request = RelayCanaryRequest::new(target, target, relay_addr, receipt);

        let err = validate_relay_canary_request(&target, &request)
            .expect_err("target must not be its own relayer");

        assert!(matches!(
            err,
            RelayCanaryRequestRejection::SelfRelayer { .. }
        ));
    }
}
