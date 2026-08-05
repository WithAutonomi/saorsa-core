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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

//! Transport-independent Kademlia iterative lookup scheduling.
//!
//! [`run_iterative_lookup`] drives an [`IterativeLookup`] through a generic
//! [`LookupQuery`] adapter. Native QUIC and browser WebTransport therefore
//! share the complete round loop, ordering, peer-state, capacity, and
//! convergence implementation without either transport becoming a dependency
//! of this crate.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::future::{Future, ready};

/// Canonical 256-bit DHT key or peer identity.
pub type LookupKey = [u8; 32];

/// A lookup candidate with a stable 256-bit peer identity.
pub trait LookupNode: Clone {
    /// Return the peer identity used for XOR ordering and deduplication.
    fn lookup_peer_id(&self) -> LookupKey;
}

/// Iterative lookup limits shared by all transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupConfig {
    /// Number of closest successful responders returned.
    pub count: usize,
    /// Maximum queries issued concurrently in one round.
    pub alpha: usize,
    /// Maximum number of query rounds.
    pub max_iterations: usize,
    /// Maximum queued candidates retained from untrusted network input.
    pub max_candidates: usize,
}

impl LookupConfig {
    /// Saorsa's standard Kademlia lookup limits for a requested result count.
    #[must_use]
    pub const fn saorsa(count: usize) -> Self {
        Self {
            count,
            alpha: 3,
            max_iterations: 20,
            max_candidates: 200,
        }
    }

    fn validate(self) -> Result<Self, LookupError> {
        if self.count == 0 {
            return Err(LookupError::InvalidConfig(
                "lookup result count must be greater than zero",
            ));
        }
        if self.alpha == 0 {
            return Err(LookupError::InvalidConfig(
                "lookup alpha must be greater than zero",
            ));
        }
        if self.max_iterations == 0 {
            return Err(LookupError::InvalidConfig(
                "lookup iteration limit must be greater than zero",
            ));
        }
        if self.max_candidates == 0 {
            return Err(LookupError::InvalidConfig(
                "lookup candidate limit must be greater than zero",
            ));
        }
        Ok(self)
    }
}

/// Final reason an iterative lookup stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupTermination {
    /// The complete closest-result set stopped changing and no queued peer
    /// could improve it.
    Converged,
    /// No contactable candidates remain.
    Exhausted,
    /// The configured round limit was reached.
    IterationLimit,
}

/// Result of completing or attempting to begin a lookup round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupProgress {
    /// The transport should begin or continue querying.
    Continue,
    /// The lookup has stopped for the supplied reason.
    Finished(LookupTermination),
}

/// Result of inserting a candidate into the bounded closest-first queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateInsertion {
    /// A new candidate was queued. When capacity was full, `evicted` identifies
    /// the farther peer that was removed.
    Inserted {
        /// Farther peer removed to make room for this candidate.
        evicted: Option<LookupKey>,
    },
    /// The existing queued representation for this peer was updated.
    Replaced,
    /// The peer already has a final state in this lookup.
    AlreadyContacted,
    /// The candidate was farther than every retained candidate at capacity.
    TooFar,
}

/// Per-lookup state of a peer that has been contacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupPeerState {
    /// A query is currently in flight.
    Waiting,
    /// The peer returned a response.
    Succeeded,
    /// The query returned an explicit error.
    Failed,
    /// The transport abandoned the query after its round grace period.
    Unresponsive,
}

/// State-machine misuse or invalid lookup configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// A numeric lookup limit was zero.
    InvalidConfig(&'static str),
    /// Driver methods were called out of order.
    InvalidState(&'static str),
    /// A result was recorded for a peer that is not currently in flight.
    PeerNotWaiting(LookupKey),
}

/// Result of one transport query in an iterative lookup batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupQueryOutcome<N> {
    /// The responder returned a valid response and zero or more validated
    /// candidates.
    Succeeded {
        /// Peer that answered the query.
        responder: LookupKey,
        /// Candidates admitted by the transport's response validator.
        candidates: Vec<N>,
    },
    /// The query completed with a transport or protocol failure.
    Failed {
        /// Peer whose query failed.
        responder: LookupKey,
    },
    /// The transport abandoned the query after its batch grace period.
    Unresponsive {
        /// Peer whose query did not finish in time.
        responder: LookupKey,
    },
}

impl<N> LookupQueryOutcome<N> {
    /// Peer this outcome belongs to.
    #[must_use]
    pub const fn responder(&self) -> &LookupKey {
        match self {
            Self::Succeeded { responder, .. }
            | Self::Failed { responder }
            | Self::Unresponsive { responder } => responder,
        }
    }
}

/// Transport and response-validation boundary used by the shared DHT walk.
///
/// Implementations receive a complete α-sized batch so they can execute its
/// queries concurrently using transport-specific cancellation and timeout
/// facilities. Only validated candidates should be returned to the engine.
pub trait LookupQuery<N: LookupNode> {
    /// Error returned by the transport adapter.
    type Error;

    /// Whether the current address view for a candidate is usable.
    ///
    /// Returning `false` discards this representation without assigning a
    /// final peer state. A later response may therefore reintroduce the same
    /// peer with a usable address.
    fn is_candidate_eligible(
        &mut self,
        _candidate: &N,
    ) -> impl Future<Output = Result<bool, Self::Error>> {
        ready(Ok(true))
    }

    /// Execute one concurrent lookup batch and validate its responses.
    ///
    /// A missing outcome is treated as [`LookupQueryOutcome::Unresponsive`].
    fn query_batch(
        &mut self,
        target: LookupKey,
        count: usize,
        iteration: usize,
        batch: Vec<N>,
    ) -> impl Future<Output = Result<Vec<LookupQueryOutcome<N>>, Self::Error>>;

    /// Observe eviction of a farther queued candidate.
    ///
    /// Stateful validators can use this to release per-candidate evidence.
    fn candidate_evicted(
        &mut self,
        _peer: LookupKey,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

/// Failure produced while the shared engine is driving a transport adapter.
#[derive(Debug)]
pub enum LookupRunError<E> {
    /// The lookup state machine rejected an operation.
    Lookup(LookupError),
    /// The transport adapter failed the complete lookup.
    Query(E),
    /// An adapter returned an outcome for a peer outside the active batch or
    /// returned more than one outcome for the same peer.
    UnexpectedResponder(LookupKey),
}

impl<E: fmt::Display> fmt::Display for LookupRunError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lookup(error) => write!(formatter, "lookup state error: {error}"),
            Self::Query(error) => write!(formatter, "lookup query error: {error}"),
            Self::UnexpectedResponder(peer) => write!(
                formatter,
                "lookup adapter returned unexpected responder {}",
                encode_hex(peer)
            ),
        }
    }
}

impl<E: Error + 'static> Error for LookupRunError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lookup(error) => Some(error),
            Self::Query(error) => Some(error),
            Self::UnexpectedResponder(_) => None,
        }
    }
}

impl<E> From<LookupError> for LookupRunError<E> {
    fn from(error: LookupError) -> Self {
        Self::Lookup(error)
    }
}

impl fmt::Display for LookupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) | Self::InvalidState(message) => {
                formatter.write_str(message)
            }
            Self::PeerNotWaiting(peer) => {
                write!(formatter, "peer {} is not waiting", encode_hex(peer))
            }
        }
    }
}

impl Error for LookupError {}

/// Pull-based, transport-independent Kademlia lookup state machine.
#[derive(Debug)]
pub struct IterativeLookup<N: LookupNode> {
    target: LookupKey,
    config: LookupConfig,
    candidates: BTreeMap<(LookupKey, LookupKey), N>,
    peer_states: HashMap<LookupKey, LookupPeerState>,
    query_order: Vec<LookupKey>,
    in_flight: HashMap<LookupKey, N>,
    successful: HashMap<LookupKey, N>,
    previous_top_k: Vec<LookupKey>,
    iterations: usize,
    round_active: bool,
    round_queries: usize,
    termination: Option<LookupTermination>,
}

impl<N: LookupNode> IterativeLookup<N> {
    /// Construct an empty lookup for `target`.
    pub fn new(target: LookupKey, config: LookupConfig) -> Result<Self, LookupError> {
        Ok(Self {
            target,
            config: config.validate()?,
            candidates: BTreeMap::new(),
            peer_states: HashMap::new(),
            query_order: Vec::new(),
            in_flight: HashMap::new(),
            successful: HashMap::new(),
            previous_top_k: Vec::new(),
            iterations: 0,
            round_active: false,
            round_queries: 0,
            termination: None,
        })
    }

    /// Target key for this lookup.
    #[must_use]
    pub const fn target(&self) -> LookupKey {
        self.target
    }

    /// Active lookup configuration.
    #[must_use]
    pub const fn config(&self) -> LookupConfig {
        self.config
    }

    /// Number of rounds begun so far.
    #[must_use]
    pub const fn iterations(&self) -> usize {
        self.iterations
    }

    /// Current terminal state, if the lookup has stopped.
    #[must_use]
    pub const fn termination(&self) -> Option<LookupTermination> {
        self.termination
    }

    /// Whether a transport round is currently active.
    #[must_use]
    pub const fn round_active(&self) -> bool {
        self.round_active
    }

    /// State currently assigned to a peer.
    #[must_use]
    pub fn peer_state(&self, peer: &LookupKey) -> Option<LookupPeerState> {
        self.peer_states.get(peer).copied()
    }

    /// Whether the peer has never been contacted by this lookup.
    #[must_use]
    pub fn is_contactable(&self, peer: &LookupKey) -> bool {
        !self.peer_states.contains_key(peer)
    }

    /// Peers selected for a transport query, in query order.
    #[must_use]
    pub fn queried_peers(&self) -> &[LookupKey] {
        &self.query_order
    }

    /// Add a successful result that must never be queried, such as the local
    /// node competing in a native lookup's final XOR ordering.
    pub fn add_known_result(&mut self, node: N) {
        let peer = node.lookup_peer_id();
        self.candidates.retain(|(_, id), _| *id != peer);
        self.peer_states.insert(peer, LookupPeerState::Succeeded);
        self.successful.entry(peer).or_insert(node);
    }

    /// Add or update an unqueried candidate.
    pub fn add_candidate(&mut self, node: N) -> CandidateInsertion {
        let peer = node.lookup_peer_id();
        if !self.is_contactable(&peer) {
            return CandidateInsertion::AlreadyContacted;
        }

        let candidate_key = (xor_distance(&peer, &self.target), peer);
        if let std::collections::btree_map::Entry::Occupied(mut entry) =
            self.candidates.entry(candidate_key)
        {
            entry.insert(node);
            return CandidateInsertion::Replaced;
        }

        if self.candidates.len() >= self.config.max_candidates {
            let Some(farthest_key) = self.candidates.keys().next_back().copied() else {
                return CandidateInsertion::TooFar;
            };
            if candidate_key >= farthest_key {
                return CandidateInsertion::TooFar;
            }
            self.candidates.remove(&farthest_key);
            self.candidates.insert(candidate_key, node);
            return CandidateInsertion::Inserted {
                evicted: Some(farthest_key.1),
            };
        }

        self.candidates.insert(candidate_key, node);
        CandidateInsertion::Inserted { evicted: None }
    }

    /// Begin the next α-query round.
    pub fn begin_round(&mut self) -> Result<LookupProgress, LookupError> {
        if self.round_active {
            return Err(LookupError::InvalidState(
                "cannot begin a lookup round while another round is active",
            ));
        }
        if let Some(reason) = self.termination {
            return Ok(LookupProgress::Finished(reason));
        }
        if self.iterations >= self.config.max_iterations {
            return Ok(self.finish(LookupTermination::IterationLimit));
        }
        self.discard_contacted_candidates();
        if self.candidates.is_empty() {
            return Ok(self.finish(LookupTermination::Exhausted));
        }

        self.iterations += 1;
        self.round_queries = 0;
        self.round_active = true;
        Ok(LookupProgress::Continue)
    }

    /// Remove and return the closest candidate for the active round.
    ///
    /// The driver must either call [`Self::mark_waiting`] for the returned
    /// node or discard it as temporarily ineligible before asking for another.
    pub fn take_next_candidate(&mut self) -> Result<Option<N>, LookupError> {
        if !self.round_active {
            return Err(LookupError::InvalidState(
                "cannot select a candidate outside an active lookup round",
            ));
        }
        if self.round_queries >= self.config.alpha {
            return Ok(None);
        }
        self.discard_contacted_candidates();
        Ok(self.candidates.pop_first().map(|(_, node)| node))
    }

    /// Mark a selected node as an in-flight query in the active round.
    pub fn mark_waiting(&mut self, node: N) -> Result<(), LookupError> {
        if !self.round_active {
            return Err(LookupError::InvalidState(
                "cannot start a query outside an active lookup round",
            ));
        }
        if self.round_queries >= self.config.alpha {
            return Err(LookupError::InvalidState(
                "lookup round already reached its alpha limit",
            ));
        }
        let peer = node.lookup_peer_id();
        if !self.is_contactable(&peer) {
            return Err(LookupError::InvalidState(
                "cannot query a peer that already has lookup state",
            ));
        }
        self.peer_states.insert(peer, LookupPeerState::Waiting);
        self.query_order.push(peer);
        self.in_flight.insert(peer, node);
        self.round_queries += 1;
        Ok(())
    }

    /// Record a successful response and retain the queried peer as a result.
    pub fn record_success(&mut self, peer: &LookupKey) -> Result<(), LookupError> {
        let node = self.take_waiting(peer)?;
        self.peer_states.insert(*peer, LookupPeerState::Succeeded);
        self.successful.entry(*peer).or_insert(node);
        Ok(())
    }

    /// Record an explicit query or transport failure.
    pub fn record_failure(&mut self, peer: &LookupKey) -> Result<(), LookupError> {
        self.take_waiting(peer)?;
        self.peer_states.insert(*peer, LookupPeerState::Failed);
        Ok(())
    }

    /// Record a query abandoned after the transport's round grace period.
    pub fn record_unresponsive(&mut self, peer: &LookupKey) -> Result<(), LookupError> {
        self.take_waiting(peer)?;
        self.peer_states
            .insert(*peer, LookupPeerState::Unresponsive);
        Ok(())
    }

    /// Peers still waiting in the active round, in XOR order.
    #[must_use]
    pub fn waiting_peers(&self) -> Vec<LookupKey> {
        let mut peers = self.in_flight.keys().copied().collect::<Vec<_>>();
        peers.sort_by_key(|peer| (xor_distance(peer, &self.target), *peer));
        peers
    }

    /// Complete the current round and evaluate native Saorsa convergence.
    pub fn complete_round(&mut self) -> Result<LookupProgress, LookupError> {
        if !self.round_active {
            return Err(LookupError::InvalidState(
                "cannot complete a lookup round when none is active",
            ));
        }
        if !self.in_flight.is_empty() {
            return Err(LookupError::InvalidState(
                "cannot complete a lookup round with queries still waiting",
            ));
        }
        self.round_active = false;

        let current_top_k = self.result_peer_ids();
        if current_top_k == self.previous_top_k {
            if current_top_k.len() < self.config.count && !self.candidates.is_empty() {
                self.previous_top_k = current_top_k;
                return Ok(LookupProgress::Continue);
            }
            let has_promising_candidate = self.has_promising_candidate();
            if !has_promising_candidate {
                return Ok(self.finish(LookupTermination::Converged));
            }
        }
        self.previous_top_k = current_top_k;

        if self.iterations >= self.config.max_iterations {
            return Ok(self.finish(LookupTermination::IterationLimit));
        }
        self.discard_contacted_candidates();
        if self.candidates.is_empty() {
            return Ok(self.finish(LookupTermination::Exhausted));
        }
        Ok(LookupProgress::Continue)
    }

    /// Successful responders sorted closest-first and truncated to K.
    #[must_use]
    pub fn results(&self) -> Vec<N> {
        let mut nodes = self.successful.values().cloned().collect::<Vec<_>>();
        nodes.sort_by_key(|node| {
            let peer = node.lookup_peer_id();
            (xor_distance(&peer, &self.target), peer)
        });
        nodes.truncate(self.config.count);
        nodes
    }

    fn take_waiting(&mut self, peer: &LookupKey) -> Result<N, LookupError> {
        if self.peer_states.get(peer) != Some(&LookupPeerState::Waiting) {
            return Err(LookupError::PeerNotWaiting(*peer));
        }
        self.in_flight
            .remove(peer)
            .ok_or(LookupError::PeerNotWaiting(*peer))
    }

    fn result_peer_ids(&self) -> Vec<LookupKey> {
        self.results()
            .into_iter()
            .map(|node| node.lookup_peer_id())
            .collect()
    }

    fn has_promising_candidate(&self) -> bool {
        let Some(worst_result) = self.result_peer_ids().last().copied() else {
            return !self.candidates.is_empty();
        };
        let worst_distance = xor_distance(&worst_result, &self.target);
        self.candidates
            .keys()
            .next()
            .is_some_and(|(distance, _)| *distance < worst_distance)
    }

    fn discard_contacted_candidates(&mut self) {
        self.candidates
            .retain(|(_, peer), _| !self.peer_states.contains_key(peer));
    }

    fn finish(&mut self, reason: LookupTermination) -> LookupProgress {
        self.round_active = false;
        self.termination = Some(reason);
        LookupProgress::Finished(reason)
    }
}

/// Run an iterative lookup to completion through a transport/query adapter.
///
/// This function owns the complete transport-independent walk: round
/// creation, closest-first α selection, peer state transitions, admission of
/// validated candidates, bounded-queue eviction, convergence, exhaustion,
/// and the iteration limit. The adapter owns only address eligibility,
/// concurrent request execution, and response validation.
pub async fn run_iterative_lookup<N, Q>(
    lookup: &mut IterativeLookup<N>,
    query: &mut Q,
) -> Result<LookupTermination, LookupRunError<Q::Error>>
where
    N: LookupNode,
    Q: LookupQuery<N>,
{
    loop {
        match lookup.begin_round()? {
            LookupProgress::Continue => {}
            LookupProgress::Finished(reason) => return Ok(reason),
        }

        let mut batch = Vec::new();
        while let Some(candidate) = lookup.take_next_candidate()? {
            if query
                .is_candidate_eligible(&candidate)
                .await
                .map_err(LookupRunError::Query)?
            {
                lookup.mark_waiting(candidate.clone())?;
                batch.push(candidate);
            }
        }

        if batch.is_empty() {
            match lookup.complete_round()? {
                LookupProgress::Continue => continue,
                LookupProgress::Finished(reason) => return Ok(reason),
            }
        }

        let mut awaiting = batch
            .iter()
            .map(LookupNode::lookup_peer_id)
            .collect::<HashSet<_>>();
        let outcomes = query
            .query_batch(
                lookup.target(),
                lookup.config().count,
                lookup.iterations(),
                batch,
            )
            .await
            .map_err(LookupRunError::Query)?;

        for outcome in outcomes {
            let responder = *outcome.responder();
            if !awaiting.remove(&responder) {
                return Err(LookupRunError::UnexpectedResponder(responder));
            }
            match outcome {
                LookupQueryOutcome::Succeeded {
                    responder,
                    candidates,
                } => {
                    lookup.record_success(&responder)?;
                    for candidate in candidates {
                        if !query
                            .is_candidate_eligible(&candidate)
                            .await
                            .map_err(LookupRunError::Query)?
                        {
                            continue;
                        }
                        if let CandidateInsertion::Inserted {
                            evicted: Some(evicted),
                        } = lookup.add_candidate(candidate)
                        {
                            query
                                .candidate_evicted(evicted)
                                .await
                                .map_err(LookupRunError::Query)?;
                        }
                    }
                }
                LookupQueryOutcome::Failed { responder } => {
                    lookup.record_failure(&responder)?;
                }
                LookupQueryOutcome::Unresponsive { responder } => {
                    lookup.record_unresponsive(&responder)?;
                }
            }
        }

        for responder in awaiting {
            lookup.record_unresponsive(&responder)?;
        }

        match lookup.complete_round()? {
            LookupProgress::Continue => {}
            LookupProgress::Finished(reason) => return Ok(reason),
        }
    }
}

/// Compute the unsigned 256-bit XOR distance used for Kademlia ordering.
#[must_use]
pub fn xor_distance(left: &LookupKey, right: &LookupKey) -> LookupKey {
    let mut distance = [0u8; 32];
    for (index, output) in distance.iter_mut().enumerate() {
        *output = left[index] ^ right[index];
    }
    distance
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Node(LookupKey);

    impl LookupNode for Node {
        fn lookup_peer_id(&self) -> LookupKey {
            self.0
        }
    }

    fn node(last: u8) -> Node {
        let mut peer = [0; 32];
        peer[31] = last;
        Node(peer)
    }

    fn peer(last: u8) -> LookupKey {
        node(last).0
    }

    fn start_batch(lookup: &mut IterativeLookup<Node>) -> Vec<Node> {
        assert_eq!(
            lookup.begin_round().expect("begin round"),
            LookupProgress::Continue
        );
        let mut batch = Vec::new();
        while let Some(candidate) = lookup.take_next_candidate().expect("take candidate") {
            lookup
                .mark_waiting(candidate.clone())
                .expect("mark waiting");
            batch.push(candidate);
        }
        batch
    }

    #[test]
    fn orders_batches_by_xor_distance_and_enforces_alpha() {
        let mut lookup =
            IterativeLookup::new([0; 32], LookupConfig::saorsa(20)).expect("valid lookup");
        for id in [9, 1, 7, 2, 3] {
            lookup.add_candidate(node(id));
        }

        let batch = start_batch(&mut lookup);
        assert_eq!(batch, vec![node(1), node(2), node(3)]);
    }

    #[test]
    fn failed_and_unresponsive_peers_cannot_be_reintroduced() {
        let mut lookup =
            IterativeLookup::new([0; 32], LookupConfig::saorsa(3)).expect("valid lookup");
        lookup.add_candidate(node(1));
        lookup.add_candidate(node(2));
        let batch = start_batch(&mut lookup);
        lookup.record_failure(&batch[0].0).expect("record failure");
        lookup
            .record_unresponsive(&batch[1].0)
            .expect("record timeout");

        assert_eq!(
            lookup.add_candidate(node(1)),
            CandidateInsertion::AlreadyContacted
        );
        assert_eq!(
            lookup.add_candidate(node(2)),
            CandidateInsertion::AlreadyContacted
        );
        assert!(!lookup.is_contactable(&peer(1)));
        assert!(!lookup.is_contactable(&peer(2)));
    }

    #[test]
    fn bounded_queue_evicts_only_a_farther_candidate() {
        let config = LookupConfig {
            max_candidates: 2,
            ..LookupConfig::saorsa(2)
        };
        let mut lookup = IterativeLookup::new([0; 32], config).expect("valid lookup");
        lookup.add_candidate(node(10));
        lookup.add_candidate(node(20));
        assert_eq!(
            lookup.add_candidate(node(5)),
            CandidateInsertion::Inserted {
                evicted: Some(peer(20))
            }
        );
        assert_eq!(lookup.add_candidate(node(30)), CandidateInsertion::TooFar);
    }

    #[test]
    fn runs_a_multi_round_lookup_to_exhaustion() {
        let mut lookup =
            IterativeLookup::new([0; 32], LookupConfig::saorsa(3)).expect("valid lookup");
        for id in [30, 40, 50] {
            lookup.add_candidate(node(id));
        }

        let first = start_batch(&mut lookup);
        for candidate in first {
            lookup.record_success(&candidate.0).expect("record success");
        }
        lookup.add_candidate(node(10));
        lookup.add_candidate(node(20));
        assert_eq!(
            lookup.complete_round().expect("complete first"),
            LookupProgress::Continue
        );

        let second = start_batch(&mut lookup);
        assert_eq!(second, vec![node(10), node(20)]);
        for candidate in second {
            lookup.record_success(&candidate.0).expect("record success");
        }
        assert_eq!(
            lookup.complete_round().expect("complete second"),
            LookupProgress::Finished(LookupTermination::Exhausted)
        );
        assert_eq!(lookup.results(), vec![node(10), node(20), node(30)]);
    }

    #[test]
    fn unchanged_top_k_converges_when_only_farther_candidates_remain() {
        let config = LookupConfig {
            alpha: 1,
            ..LookupConfig::saorsa(1)
        };
        let mut lookup = IterativeLookup::new([0; 32], config).expect("valid lookup");
        lookup.add_candidate(node(10));
        lookup.add_candidate(node(30));
        lookup.add_candidate(node(40));

        let first = start_batch(&mut lookup);
        lookup.record_success(&first[0].0).expect("record success");
        assert_eq!(
            lookup.complete_round().expect("complete first"),
            LookupProgress::Continue
        );

        let second = start_batch(&mut lookup);
        lookup.record_success(&second[0].0).expect("record success");
        assert_eq!(
            lookup.complete_round().expect("complete second"),
            LookupProgress::Finished(LookupTermination::Converged)
        );
        assert_eq!(lookup.results(), vec![node(10)]);
    }

    #[derive(Default)]
    struct MockQuery {
        batches: Vec<Vec<LookupKey>>,
    }

    impl LookupQuery<Node> for MockQuery {
        type Error = Infallible;

        fn query_batch(
            &mut self,
            _target: LookupKey,
            _count: usize,
            iteration: usize,
            batch: Vec<Node>,
        ) -> impl Future<Output = Result<Vec<LookupQueryOutcome<Node>>, Self::Error>> {
            self.batches
                .push(batch.iter().map(LookupNode::lookup_peer_id).collect());
            let outcomes = if iteration == 1 {
                vec![
                    LookupQueryOutcome::Succeeded {
                        responder: peer(1),
                        candidates: vec![node(0)],
                    },
                    LookupQueryOutcome::Failed { responder: peer(2) },
                ]
            } else {
                batch
                    .into_iter()
                    .map(|candidate| LookupQueryOutcome::Succeeded {
                        responder: candidate.lookup_peer_id(),
                        candidates: Vec::new(),
                    })
                    .collect()
            };
            ready(Ok(outcomes))
        }
    }

    #[test]
    fn shared_runner_owns_rounds_and_drives_query_batches() {
        let config = LookupConfig {
            alpha: 2,
            ..LookupConfig::saorsa(2)
        };
        let mut lookup = IterativeLookup::new([0; 32], config).expect("valid lookup");
        for id in [3, 1, 2] {
            lookup.add_candidate(node(id));
        }
        let mut query = MockQuery::default();

        let reason = futures::executor::block_on(run_iterative_lookup(&mut lookup, &mut query))
            .expect("run lookup");

        assert_eq!(reason, LookupTermination::Exhausted);
        assert_eq!(
            query.batches,
            vec![vec![peer(1), peer(2)], vec![peer(0), peer(3)]]
        );
        assert_eq!(lookup.results(), vec![node(0), node(1)]);
    }

    struct MissingOutcomeQuery;

    impl LookupQuery<Node> for MissingOutcomeQuery {
        type Error = Infallible;

        fn query_batch(
            &mut self,
            _target: LookupKey,
            _count: usize,
            _iteration: usize,
            batch: Vec<Node>,
        ) -> impl Future<Output = Result<Vec<LookupQueryOutcome<Node>>, Self::Error>> {
            ready(Ok(batch
                .first()
                .map(|candidate| LookupQueryOutcome::Succeeded {
                    responder: candidate.lookup_peer_id(),
                    candidates: Vec::new(),
                })
                .into_iter()
                .collect()))
        }
    }

    #[test]
    fn shared_runner_marks_missing_batch_outcomes_unresponsive() {
        let config = LookupConfig {
            alpha: 2,
            ..LookupConfig::saorsa(2)
        };
        let mut lookup = IterativeLookup::new([0; 32], config).expect("valid lookup");
        lookup.add_candidate(node(1));
        lookup.add_candidate(node(2));

        futures::executor::block_on(run_iterative_lookup(&mut lookup, &mut MissingOutcomeQuery))
            .expect("run lookup");

        assert_eq!(
            lookup.peer_state(&peer(1)),
            Some(LookupPeerState::Succeeded)
        );
        assert_eq!(
            lookup.peer_state(&peer(2)),
            Some(LookupPeerState::Unresponsive)
        );
    }

    #[test]
    fn rejects_zero_limits() {
        let invalid = LookupConfig {
            alpha: 0,
            ..LookupConfig::saorsa(1)
        };
        assert!(matches!(
            IterativeLookup::<Node>::new([0; 32], invalid),
            Err(LookupError::InvalidConfig(_))
        ));
    }
}
