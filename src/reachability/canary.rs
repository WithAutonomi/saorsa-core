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
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use rand::{Rng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::address::is_lan_ip;
use crate::dht::AddressType;
use crate::dht_network_manager::{DHTNode, DhtNetworkManager, IDENTITY_EXCHANGE_TIMEOUT};
use crate::error::{NetworkError, P2PError};
use crate::rate_limit::EngineConfig;
use crate::security::canonicalize_ip;
use crate::transport_handle::TransportHandle;
use crate::{MultiAddr, PeerId};

/// Request/response protocol name used with `TransportHandle::send_request`.
pub(crate) const RELAY_CANARY_PROTOCOL: &str = "relay-canary-v1";

/// Wire topic emitted by the request/response wrapper for canary requests.
pub(crate) const RELAY_CANARY_WIRE_TOPIC: &str = "/rr/relay-canary-v1";

/// Number of independent non-close witnesses to ask for a relay proof.
const RELAY_CANARY_WITNESS_TARGET: usize = 3;

/// Minimum successful witness probes needed before a relay is publishable.
const RELAY_CANARY_REQUIRED_SUCCESSES: usize = 2;

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
const RELAY_CANARY_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Cold-dial identity budget spent by a witness when probing a relay address.
const RELAY_CANARY_DIAL_TIMEOUT: Duration = IDENTITY_EXCHANGE_TIMEOUT;

/// Sliding window for per-source relay canary rate limiting.
const RELAY_CANARY_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Maximum canary-triggered cold dials a single source may request per window.
const RELAY_CANARY_RATE_MAX_PER_WINDOW: u32 = 1;

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

/// Socket port zero is not a routable service endpoint.
const UNSPECIFIED_PORT: u16 = 0;

/// Request sent to a witness asking it to verify a proposed relay address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RelayCanaryRequest {
    pub(crate) target_peer_id: PeerId,
    pub(crate) relayer_peer_id: PeerId,
    pub(crate) relay_addr: SocketAddr,
}

impl RelayCanaryRequest {
    fn new(target_peer_id: PeerId, relayer_peer_id: PeerId, relay_addr: SocketAddr) -> Self {
        Self {
            target_peer_id,
            relayer_peer_id,
            relay_addr,
        }
    }
}

/// Witness response after attempting the cold relay dial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RelayCanaryResponse {
    pub(crate) result: RelayCanaryProbeResult,
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

    validate_relay_canary_address(request.relay_addr)
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
    Verified { successes: usize, attempts: usize },
    Rejected { successes: usize, attempts: usize },
    InsufficientWitnesses { available: usize, required: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayCanaryProbeDisposition {
    Success,
    Failure,
    Ineligible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayCanaryProgressDecision {
    Continue,
    Verified { successes: usize, attempts: usize },
    Rejected { successes: usize, attempts: usize },
}

#[derive(Debug, Clone)]
struct RelayCanaryProgress {
    total: usize,
    responses: usize,
    eligible_attempts: usize,
    successes: usize,
    ineligible: usize,
}

impl RelayCanaryProgress {
    fn new(total: usize) -> Self {
        Self {
            total,
            responses: 0,
            eligible_attempts: 0,
            successes: 0,
            ineligible: 0,
        }
    }

    fn record(&mut self, disposition: RelayCanaryProbeDisposition) -> RelayCanaryProgressDecision {
        self.responses += 1;
        match disposition {
            RelayCanaryProbeDisposition::Success => {
                self.eligible_attempts += 1;
                self.successes += 1;
            }
            RelayCanaryProbeDisposition::Failure => {
                self.eligible_attempts += 1;
            }
            RelayCanaryProbeDisposition::Ineligible => {
                self.ineligible += 1;
            }
        }

        if self.successes >= RELAY_CANARY_REQUIRED_SUCCESSES {
            return RelayCanaryProgressDecision::Verified {
                successes: self.successes,
                attempts: self.eligible_attempts,
            };
        }

        let remaining = self.total.saturating_sub(self.responses);
        if self.successes + remaining < RELAY_CANARY_REQUIRED_SUCCESSES
            && self.eligible_attempts >= RELAY_CANARY_REQUIRED_SUCCESSES
        {
            return RelayCanaryProgressDecision::Rejected {
                successes: self.successes,
                attempts: self.eligible_attempts,
            };
        }

        RelayCanaryProgressDecision::Continue
    }

    fn final_verdict(&self) -> RelayCanaryVerdict {
        if self.eligible_attempts < RELAY_CANARY_REQUIRED_SUCCESSES {
            RelayCanaryVerdict::InsufficientWitnesses {
                available: self.eligible_attempts,
                required: RELAY_CANARY_REQUIRED_SUCCESSES,
            }
        } else {
            RelayCanaryVerdict::Rejected {
                successes: self.successes,
                attempts: self.eligible_attempts,
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
) -> RelayCanaryVerdict {
    let target_peer_id = *dht.peer_id();
    let request = RelayCanaryRequest::new(target_peer_id, relayer, relay_addr);
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

    if witnesses.len() < RELAY_CANARY_REQUIRED_SUCCESSES {
        warn!(
            relayer = %relayer.to_hex(),
            relay = %relay_addr,
            available = witnesses.len(),
            required = RELAY_CANARY_REQUIRED_SUCCESSES,
            close_group_excluded = close_group_ids.len(),
            routing_table_size,
            "relay canary: insufficient random non-close witnesses, refusing to publish relay"
        );
        return RelayCanaryVerdict::InsufficientWitnesses {
            available: witnesses.len(),
            required: RELAY_CANARY_REQUIRED_SUCCESSES,
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

    let mut progress = RelayCanaryProgress::new(witnesses.len());
    let mut probes = FuturesUnordered::new();
    for witness in witnesses {
        let dht = Arc::clone(dht);
        let request = RelayCanaryRequest::new(target_peer_id, relayer, relay_addr);
        probes.push(async move { request_relay_canary(dht, witness, request).await });
    }

    while let Some(report) = probes.next().await {
        let decision = progress.record(report.disposition);
        if report.disposition == RelayCanaryProbeDisposition::Success {
            debug!(
                witness = %report.witness.to_hex(),
                successes = progress.successes,
                eligible_attempts = progress.eligible_attempts,
                responses = progress.responses,
                "relay canary: witness confirmed relay"
            );
        } else if report.disposition == RelayCanaryProbeDisposition::Ineligible {
            debug!(
                witness = %report.witness.to_hex(),
                detail = %report.detail,
                ineligible = progress.ineligible,
                eligible_attempts = progress.eligible_attempts,
                responses = progress.responses,
                "relay canary: witness could not evaluate relay"
            );
        } else {
            debug!(
                witness = %report.witness.to_hex(),
                detail = %report.detail,
                successes = progress.successes,
                eligible_attempts = progress.eligible_attempts,
                responses = progress.responses,
                "relay canary: witness failed relay probe"
            );
        }

        match decision {
            RelayCanaryProgressDecision::Verified {
                successes,
                attempts,
            } => {
                info!(
                    relayer = %relayer.to_hex(),
                    relay = %relay_addr,
                    successes,
                    attempts,
                    responses = progress.responses,
                    ineligible = progress.ineligible,
                    available_witnesses = progress.total,
                    "relay canary: quorum verified relay"
                );
                return RelayCanaryVerdict::Verified {
                    successes,
                    attempts,
                };
            }
            RelayCanaryProgressDecision::Rejected {
                successes,
                attempts,
            } => {
                warn!(
                    relayer = %relayer.to_hex(),
                    relay = %relay_addr,
                    successes,
                    attempts,
                    responses = progress.responses,
                    total = progress.total,
                    ineligible = progress.ineligible,
                    "relay canary: quorum failed relay"
                );
                return RelayCanaryVerdict::Rejected {
                    successes,
                    attempts,
                };
            }
            RelayCanaryProgressDecision::Continue => {}
        }
    }

    progress.final_verdict()
}

/// Probe `request.relay_addr` from this witness node and return the result.
pub(crate) async fn answer_relay_canary_request(
    transport: &TransportHandle,
    request: RelayCanaryRequest,
) -> RelayCanaryResponse {
    let relay_address = MultiAddr::quic(request.relay_addr);
    let dial = tokio::time::timeout(
        RELAY_CANARY_CONNECT_TIMEOUT,
        // The address type is an informational hint for logging/classification;
        // correctness comes from dialing the allocated socket and checking the
        // authenticated target identity below.
        transport.connect_peer_typed(&relay_address, AddressType::Relay),
    )
    .await;

    let result = match dial {
        Ok(Ok(channel_id)) => {
            let identity = transport
                .wait_for_peer_identity(&channel_id, RELAY_CANARY_DIAL_TIMEOUT)
                .await;
            let result = match identity {
                Ok(authenticated) if authenticated == request.target_peer_id => {
                    RelayCanaryProbeResult::Success
                }
                Ok(authenticated) => {
                    debug!(
                        expected = %request.target_peer_id.to_hex(),
                        actual = %authenticated.to_hex(),
                        relay = %request.relay_addr,
                        "relay canary witness: identity mismatch"
                    );
                    RelayCanaryProbeResult::IdentityMismatch
                }
                Err(e) => {
                    debug!(
                        relay = %request.relay_addr,
                        error = %e,
                        "relay canary witness: identity exchange failed"
                    );
                    RelayCanaryProbeResult::IdentityExchangeFailed
                }
            };
            transport.disconnect_channel(&channel_id).await;
            result
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
    match dht
        .send_relay_canary_request(
            &witness_peer_id,
            &witness.typed_addresses,
            request,
            RELAY_CANARY_REQUEST_TIMEOUT,
        )
        .await
    {
        Ok(response) => RelayCanaryProbeReport {
            witness: witness_peer_id,
            disposition: response.result.disposition(),
            detail: response.result.summary(),
        },
        Err(e) => RelayCanaryProbeReport {
            witness: witness_peer_id,
            disposition: canary_request_error_disposition(&e),
            detail: e.to_string(),
        },
    }
}

fn canary_request_error_disposition(error: &P2PError) -> RelayCanaryProbeDisposition {
    match error {
        P2PError::Timeout(_) | P2PError::Network(NetworkError::Timeout) => {
            RelayCanaryProbeDisposition::Failure
        }
        _ => RelayCanaryProbeDisposition::Ineligible,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, SocketAddr};

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
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
    fn ineligible_witnesses_produce_insufficient_witnesses() {
        let mut progress = RelayCanaryProgress::new(RELAY_CANARY_WITNESS_TARGET);

        assert_eq!(
            progress.record(RelayCanaryProbeDisposition::Success),
            RelayCanaryProgressDecision::Continue
        );
        assert_eq!(
            progress.record(RelayCanaryProbeDisposition::Ineligible),
            RelayCanaryProgressDecision::Continue
        );
        assert_eq!(
            progress.record(RelayCanaryProbeDisposition::Ineligible),
            RelayCanaryProgressDecision::Continue
        );
        assert_eq!(
            progress.final_verdict(),
            RelayCanaryVerdict::InsufficientWitnesses {
                available: 1,
                required: RELAY_CANARY_REQUIRED_SUCCESSES
            }
        );
    }

    #[test]
    fn two_eligible_failures_reject_relay() {
        let mut progress = RelayCanaryProgress::new(RELAY_CANARY_WITNESS_TARGET);

        assert_eq!(
            progress.record(RelayCanaryProbeDisposition::Failure),
            RelayCanaryProgressDecision::Continue
        );
        assert_eq!(
            progress.record(RelayCanaryProbeDisposition::Failure),
            RelayCanaryProgressDecision::Rejected {
                successes: 0,
                attempts: 2
            }
        );
    }

    #[test]
    fn request_timeout_counts_as_probe_failure() {
        assert_eq!(
            canary_request_error_disposition(&P2PError::Timeout(RELAY_CANARY_REQUEST_TIMEOUT)),
            RelayCanaryProbeDisposition::Failure
        );
    }

    #[test]
    fn witness_contact_failure_is_ineligible() {
        assert_eq!(
            canary_request_error_disposition(&P2PError::Network(NetworkError::PeerNotFound(
                "witness".into()
            ))),
            RelayCanaryProbeDisposition::Ineligible
        );
    }

    #[test]
    fn canary_request_rejects_source_mismatch() {
        let relay_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), TEST_PORT));
        let request =
            RelayCanaryRequest::new(peer_id(TARGET_SEED), peer_id(RELAYER_SEED), relay_addr);

        let err = validate_relay_canary_request(&peer_id(FIRST_WITNESS_SEED), &request)
            .expect_err("source mismatch must be rejected");

        assert!(matches!(
            err,
            RelayCanaryRequestRejection::SourceMismatch { .. }
        ));
    }

    #[test]
    fn canary_request_rejects_local_scope_relay_address() {
        let request = RelayCanaryRequest::new(
            peer_id(TARGET_SEED),
            peer_id(RELAYER_SEED),
            SocketAddr::from((Ipv4Addr::new(192, 168, 1, 10), TEST_PORT)),
        );

        let err = validate_relay_canary_request(&peer_id(TARGET_SEED), &request)
            .expect_err("private relay address must be rejected");

        assert!(matches!(err, RelayCanaryRequestRejection::LocalScopeIp(_)));
    }

    #[test]
    fn canary_request_rejects_unspecified_port() {
        let request = RelayCanaryRequest::new(
            peer_id(TARGET_SEED),
            peer_id(RELAYER_SEED),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 8), UNSPECIFIED_PORT)),
        );

        let err = validate_relay_canary_request(&peer_id(TARGET_SEED), &request)
            .expect_err("port zero must be rejected");

        assert_eq!(err, RelayCanaryRequestRejection::UnspecifiedPort);
    }

    #[test]
    fn canary_request_rejects_self_as_relayer() {
        let request = RelayCanaryRequest::new(
            peer_id(TARGET_SEED),
            peer_id(TARGET_SEED),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), TEST_PORT)),
        );

        let err = validate_relay_canary_request(&peer_id(TARGET_SEED), &request)
            .expect_err("target must not be its own relayer");

        assert!(matches!(
            err,
            RelayCanaryRequestRejection::SelfRelayer { .. }
        ));
    }
}
