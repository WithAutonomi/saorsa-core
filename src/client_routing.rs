// Copyright 2026 Saorsa Labs Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client-side peer report selection and witness normalization.
//! Transport I/O, node admission, and routing maintenance remain outside this module.

use crate::peer_record::dht_node_publish_seq;
use crate::{DHTNode, Key, MultiAddr, PeerId, ResponderView, WitnessedCloseGroup};
use std::collections::HashMap;

/// Quorum parameters for the iterative FIND_NODE aggregator.
///
/// Among the closest-XOR responders that reported a given subject, a
/// consensus of `QUORUM_THRESHOLD` out of the top `QUORUM_TOP_N`
/// agreeing responders wins outright. A single close-XOR adversary
/// cannot poison the lookup so long as two of its XOR neighbours are
/// honest and agree.
const QUORUM_TOP_N: usize = 3;
const QUORUM_THRESHOLD: usize = 2;

/// All reports collected for a single subject peer during an iterative
/// FIND_NODE lookup, keyed by responder peer_id. Grows as responses
/// arrive and feeds [`compute_winner`].
pub type SubjectReports = HashMap<PeerId, DHTNode>;

/// Best (lowest-numeric) [`crate::AddressType::priority`] across a node's
/// address tags. `u8::MAX` when the address list is empty.
///
/// Used as the fallback tie-breaker in [`compute_winner`]: when no
/// quorum exists and two responders are at the same XOR distance,
/// the one whose best tag tier is stronger wins.
pub fn best_tier_priority(node: &DHTNode) -> u8 {
    node.typed_addresses()
        .iter()
        .map(|(_, t)| t.priority())
        .min()
        .unwrap_or(u8::MAX)
}

/// Canonical signature of a report's address set, used to group
/// responders that agree. Independent of insertion order — addresses
/// are sorted by their string form, and each tag is reduced to its
/// priority byte so [`crate::AddressType`] does not need a [`Hash`] impl.
fn report_signature(node: &DHTNode) -> Vec<(MultiAddr, u8)> {
    let mut sig: Vec<(MultiAddr, u8)> = node
        .typed_addresses()
        .into_iter()
        .map(|(addr, t)| (addr, t.priority()))
        .collect();
    sig.sort_by_key(|a| a.0.to_string());
    sig
}

/// Compute the current winning report for a subject peer given all
/// reports received so far from different responders.
///
/// Rules (applied in order):
///
///   1. **Owner-proven information** — combine the newest QUIC projection and
///      newest signed V2 publication. An intermediary's unsigned sequence has
///      no authority over either view.
///   2. **Self-report** — among unsequenced hints, prefer the subject itself.
///   3. **Quorum** — among the top `QUORUM_TOP_N` closest-XOR
///      responders, if `QUORUM_THRESHOLD`+ agree on the address set
///      (same [`report_signature`]), their consensus wins. One close
///      adversary cannot poison the result when 2+ honest neighbours
///      agree.
///   4. **Fallback** — the closest-XOR responder wins. On an XOR tie
///      the one whose best tag tier is stronger breaks it.
///
/// Returns `None` only when `reports` is empty.
pub fn compute_winner(subject_id: &PeerId, reports: &SubjectReports) -> Option<(PeerId, DHTNode)> {
    if reports.is_empty() {
        return None;
    }

    // Sort all responders by XOR distance to subject (primary), then by
    // best-tier-priority (secondary, for stable tie-break).
    let mut by_dist: Vec<(PeerId, &DHTNode, Key, u8)> = reports
        .iter()
        .map(|(rid, node)| {
            (
                *rid,
                node,
                rid.xor_distance(subject_id),
                best_tier_priority(node),
            )
        })
        .collect();
    by_dist.sort_by(|a, b| a.2.cmp(&b.2).then(a.3.cmp(&b.3)));

    // Rule 1: newest authoritative publish sequence wins. This keeps stale
    // third-party relay records from beating a newer direct-only or re-relayed
    // self-record during an iterative lookup.
    if let Some((rid, node, _, _)) = by_dist
        .iter()
        .filter(|(_, node, _, _)| dht_node_publish_seq(node) != 0)
        .max_by(|a, b| {
            dht_node_publish_seq(a.1)
                .cmp(&dht_node_publish_seq(b.1))
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| b.3.cmp(&a.3))
        })
    {
        let mut winner = (*node).clone();
        for (_, report, _, _) in &by_dist {
            winner.merge_from((*report).clone());
        }
        return Some((*rid, winner));
    }

    // An authenticated self-report wins among unsequenced hints, but cannot
    // downgrade an owner-proven sequenced publication already in this view.
    if let Some(node) = reports.get(subject_id) {
        return Some((*subject_id, node.clone()));
    }

    // Rule 3: quorum among top-N.
    let top_n = &by_dist[..by_dist.len().min(QUORUM_TOP_N)];
    if top_n.len() >= QUORUM_THRESHOLD {
        let mut buckets: HashMap<Vec<(MultiAddr, u8)>, Vec<PeerId>> = HashMap::new();
        for (rid, node, _, _) in top_n {
            buckets
                .entry(report_signature(node))
                .or_default()
                .push(*rid);
        }
        if let Some(group) = buckets.values().find(|g| g.len() >= QUORUM_THRESHOLD)
            && let Some(winner_rid) = group
                .iter()
                .copied()
                .min_by_key(|rid| rid.xor_distance(subject_id))
        {
            // Pick the XOR-closest consensus member as the representative.
            // All consensus reports have the same address set by
            // construction, so any pick is behaviourally equivalent;
            // choosing closest makes the result deterministic.
            return reports
                .get(&winner_rid)
                .map(|node| (winner_rid, node.clone()));
        }
    }

    // Rule 4: fallback — closest-XOR (then strongest-tier) responder.
    let (rid, node, _, _) = by_dist.first()?;
    Some((*rid, (*node).clone()))
}

fn prefer_lookup_record(candidate: &DHTNode, existing: &DHTNode) -> bool {
    let candidate_seq = dht_node_publish_seq(candidate);
    let existing_seq = dht_node_publish_seq(existing);
    candidate_seq > existing_seq
        || (candidate_seq == existing_seq
            && best_tier_priority(candidate) < best_tier_priority(existing))
}

/// Refresh final lookup results with the per-subject winners observed during
/// the lookup.
///
/// `best_nodes` is built from the candidate that was queried at the time it
/// entered an alpha batch. Later responses in the same lookup may carry a
/// fresher sequence-bearing self-record for that same peer. Before returning
/// results to callers, replace every returned peer with the current
/// [`compute_winner`] output so a stale candidate copy cannot leak out to
/// clients that discovered the peer purely through this lookup.
pub fn apply_lookup_report_winners(
    best_nodes: Vec<DHTNode>,
    subject_reports: &HashMap<PeerId, SubjectReports>,
    key: &Key,
    count: usize,
) -> Vec<DHTNode> {
    let mut by_peer: HashMap<PeerId, DHTNode> = HashMap::new();

    for mut node in best_nodes {
        if let Some((_, winner)) = subject_reports
            .get(&node.peer_id)
            .and_then(|reports| compute_winner(&node.peer_id, reports))
        {
            if dht_node_publish_seq(&node) != 0 || dht_node_publish_seq(&winner) != 0 {
                node.merge_from(winner);
            } else {
                node = winner;
            }
        }

        match by_peer.entry(node.peer_id) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if dht_node_publish_seq(&node) != 0 || dht_node_publish_seq(entry.get()) != 0 {
                    entry.get_mut().merge_from(node);
                } else if prefer_lookup_record(&node, entry.get()) {
                    *entry.get_mut() = node;
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(node);
            }
        }
    }

    let mut refreshed: Vec<DHTNode> = by_peer.into_values().collect();
    refreshed.sort_by(|a, b| compare_peer_distance(&a.peer_id, &b.peer_id, key));
    refreshed.truncate(count);
    refreshed
}

fn merge_witnessed_node(nodes: &mut HashMap<PeerId, DHTNode>, node: DHTNode) {
    match nodes.entry(node.peer_id) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.get_mut().merge_from(node);
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(node);
        }
    }
}

fn compare_peer_distance(a: &PeerId, b: &PeerId, key: &Key) -> std::cmp::Ordering {
    let target = PeerId::from_bytes(*key);
    a.xor_distance(&target)
        .cmp(&b.xor_distance(&target))
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// Merge peer records and retain the closest peers in XOR order.
pub fn sort_dedup_witnessed_nodes(
    mut nodes: Vec<DHTNode>,
    key: &Key,
    count: usize,
) -> Vec<DHTNode> {
    let mut by_peer: HashMap<PeerId, DHTNode> = HashMap::new();
    for node in nodes.drain(..) {
        merge_witnessed_node(&mut by_peer, node);
    }

    let mut deduped: Vec<DHTNode> = by_peer.into_values().collect();
    deduped.sort_by(|a, b| compare_peer_distance(&a.peer_id, &b.peer_id, key));
    deduped.truncate(count);
    deduped
}

/// Normalize a witness view, preserving undialable peers as votes.
pub fn self_inclusive_responder_view(
    responder: PeerId,
    closest: Vec<DHTNode>,
    known_nodes: &HashMap<PeerId, DHTNode>,
    key: &Key,
    count: usize,
) -> Vec<DHTNode> {
    let mut view_nodes: HashMap<PeerId, DHTNode> = HashMap::new();
    for node in closest {
        merge_witnessed_node(&mut view_nodes, node);
    }

    if let Some(responder_node) = known_nodes.get(&responder) {
        merge_witnessed_node(&mut view_nodes, responder_node.clone());
    }

    let mut nodes: Vec<DHTNode> = view_nodes.into_values().collect();
    nodes.sort_by(|a, b| compare_peer_distance(&a.peer_id, &b.peer_id, key));
    nodes.truncate(count);
    nodes
}

/// Build the shared, self-inclusive close-group transcript.
pub fn build_witnessed_close_group(
    key: &Key,
    count: usize,
    view_count: usize,
    initial_closest: Vec<DHTNode>,
    responder_node_views: Vec<(PeerId, Vec<DHTNode>)>,
) -> WitnessedCloseGroup {
    let initial_closest = sort_dedup_witnessed_nodes(initial_closest, key, count);

    let mut known_nodes: HashMap<PeerId, DHTNode> = HashMap::new();
    for node in &initial_closest {
        merge_witnessed_node(&mut known_nodes, node.clone());
    }
    for (_, closest) in &responder_node_views {
        for node in closest {
            merge_witnessed_node(&mut known_nodes, node.clone());
        }
    }

    let mut responder_views = Vec::with_capacity(responder_node_views.len());

    for (responder, closest) in responder_node_views {
        let closest =
            self_inclusive_responder_view(responder, closest, &known_nodes, key, view_count);
        responder_views.push(ResponderView { responder, closest });
    }

    responder_views.sort_by(|a, b| compare_peer_distance(&a.responder, &b.responder, key));

    WitnessedCloseGroup {
        target: *key,
        k: count,
        initial_closest,
        responder_views,
    }
}

/// Whether an incoming lookup view may replace an already owner-proven view.
/// Unsigned hints cannot displace a publication or raise its accepted sequence.
/// If neither view supersedes both scopes, use [`DHTNode::merge_from`] instead.
pub fn may_replace_owner_view(current: &DHTNode, incoming: &DHTNode) -> bool {
    use crate::signed_address::AddressAuthority;
    let versions = |node: &DHTNode| {
        let authority = node.address_authority.as_ref();
        (
            authority.map_or(0, AddressAuthority::quic_sequence),
            authority
                .and_then(AddressAuthority::publication)
                .map_or(0, |proof| proof.sequence()),
        )
    };
    let (current_quic, current_v2) = versions(current);
    let (incoming_quic, incoming_v2) = versions(incoming);
    incoming_quic >= current_quic && incoming_v2 >= current_v2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AddressType;

    fn node(id: u8, address: &str) -> DHTNode {
        DHTNode {
            peer_id: PeerId::from_bytes([id; 32]),
            addresses: vec![address.parse().unwrap()],
            address_types: vec![AddressType::Unverified],
            distance: None,
            reliability: 0.5,
            address_authority: None,
        }
    }

    #[test]
    fn portable_lookup_merges_quic_and_signed_transports_in_either_order() {
        use crate::identity::NodeIdentity;
        use crate::signed_address::{AddressAuthority, SignedAddressRecord};
        use crate::{
            KnownReachability, TransportAddressRecord, WebRtcCertificateHash, WebRtcDirectAddr,
        };
        let identity = NodeIdentity::generate().unwrap();
        let owner = *identity.peer_id();
        let signed = |sequence: u64, include_browser: bool| {
            let mut records = vec![
                TransportAddressRecord::from_multiaddr(
                    &"/ip4/9.9.9.9/udp/9000/quic".parse().unwrap(),
                    KnownReachability::Direct,
                )
                .unwrap()
                .unwrap(),
            ];
            if include_browser {
                let browser = MultiAddr::webrtc_direct(
                    WebRtcDirectAddr::new(
                        "203.0.113.7:42768".parse().unwrap(),
                        WebRtcCertificateHash::new([sequence as u8; 32]),
                    )
                    .unwrap(),
                )
                .with_peer_id(owner);
                records.push(
                    TransportAddressRecord::from_multiaddr(&browser, KnownReachability::Unverified)
                        .unwrap()
                        .unwrap(),
                );
            }
            SignedAddressRecord::sign(&identity, sequence, records)
                .unwrap()
                .verify()
                .unwrap()
        };
        let old = signed(10, true);
        let latest = signed(11, true);
        let mut native = node(0, "/ip4/1.1.1.1/udp/9001/quic");
        native.peer_id = owner;
        native.address_authority = Some(AddressAuthority::AuthenticatedOwner(12));
        assert!(!may_replace_owner_view(&latest.peer_record(1.0), &native));
        assert!(!may_replace_owner_view(&native, &latest.peer_record(1.0)));
        let expected_browser = latest
            .peer_record(1.0)
            .addresses
            .into_iter()
            .find(MultiAddr::is_webrtc_direct)
            .unwrap();
        let views = [
            old.peer_record(1.0),
            native.clone(),
            latest.peer_record(1.0),
        ];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut merged = views[order[0]].clone();
            merged.merge_from(views[order[1]].clone());
            merged.merge_from(views[order[2]].clone());
            assert_eq!(
                merged.addresses,
                vec![native.addresses[0].clone(), expected_browser.clone()]
            );
            let authority = merged.address_authority.as_ref().unwrap();
            assert_eq!(authority.quic_sequence(), 12);
            assert_eq!(authority.publication(), Some(&latest));
            let decoded: DHTNode =
                postcard::from_bytes(&postcard::to_stdvec(&merged).unwrap()).unwrap();
            assert!(decoded.address_authority.is_none());
        }
        let reports = SubjectReports::from([
            (PeerId::from_bytes([1; 32]), native.clone()),
            (PeerId::from_bytes([2; 32]), latest.peer_record(1.0)),
        ]);
        let winner = compute_winner(&owner, &reports).unwrap().1;
        assert!(winner.addresses.contains(&expected_browser));
        assert!(winner.addresses.contains(&native.addresses[0]));
        let result = apply_lookup_report_winners(
            vec![native.clone()],
            &HashMap::from([(owner, reports)]),
            owner.as_bytes(),
            1,
        )
        .remove(0);
        assert_eq!(result.addresses, winner.addresses);
        // A conflicting V2 proof at the same QUIC sequence cannot be attached.
        let mut equal_conflict = native.clone();
        equal_conflict.merge_from(signed(12, true).peer_record(1.0));
        assert_eq!(equal_conflict.addresses, native.addresses);
        assert!(
            equal_conflict
                .address_authority
                .unwrap()
                .publication()
                .is_none()
        );
        let mut removed = winner;
        removed.merge_from(signed(13, false).peer_record(1.0));
        removed.merge_from(latest.peer_record(1.0));
        assert!(removed.addresses.iter().all(MultiAddr::is_quic));
        assert_eq!(
            removed
                .address_authority
                .unwrap()
                .publication()
                .unwrap()
                .sequence(),
            13
        );
    }

    #[test]
    fn reports_choose_consensus_then_authenticated_self_report() {
        let subject = PeerId::from_bytes([0; 32]);
        let good = node(0, "/ip4/198.51.100.1/udp/9000/quic");
        let bad = node(0, "/ip4/198.51.100.2/udp/9000/quic");
        let mut reports = SubjectReports::from([
            (PeerId::from_bytes([1; 32]), bad.clone()),
            (PeerId::from_bytes([2; 32]), good.clone()),
            (PeerId::from_bytes([3; 32]), good.clone()),
        ]);
        assert_eq!(
            compute_winner(&subject, &reports).unwrap().1.addresses,
            good.addresses
        );
        reports.insert(subject, bad.clone());
        assert_eq!(
            compute_winner(&subject, &reports).unwrap().1.addresses,
            bad.addresses
        );
        let result = apply_lookup_report_winners(
            vec![good],
            &HashMap::from([(subject, reports)]),
            &[0; 32],
            1,
        );
        assert_eq!(result[0].addresses, bad.addresses);
    }

    #[test]
    fn witnesses_preserve_native_only_and_addressless_peers() {
        let responder = node(2, "/ip4/198.51.100.2/udp/9000/quic");
        let mut closer = node(1, "/ip4/198.51.100.1/udp/9000/quic");
        closer.addresses.clear();
        closer.address_types.clear();
        let group = build_witnessed_close_group(
            &[0; 32],
            1,
            2,
            vec![responder.clone()],
            vec![(responder.peer_id, vec![closer.clone(), closer])],
        );
        assert_eq!(group.responder_views[0].closest.len(), 2);
        assert!(group.responder_views[0].closest[0].addresses.is_empty());
        assert_eq!(
            group.responder_views[0].closest[1].peer_id,
            responder.peer_id
        );
    }
    #[test]
    fn final_lookup_results_cannot_downgrade_an_owner_proven_candidate() {
        let mut current = node(1, "/ip4/9.9.9.9/udp/9000/quic");
        current.address_authority = Some(
            crate::signed_address::AddressAuthority::AuthenticatedOwner(10),
        );
        let hint = node(1, "/ip4/1.1.1.1/udp/9000/quic");
        let reports = HashMap::from([(current.peer_id, HashMap::from([(current.peer_id, hint)]))]);
        let result = apply_lookup_report_winners(vec![current.clone()], &reports, &[0; 32], 1);
        assert_eq!(result[0].addresses, current.addresses);
        assert_eq!(dht_node_publish_seq(&result[0]), 10);
    }
}
