//! Temporal XOF producer bookkeeping for analysis controls, not a ROM theorem.
//! Answers are trusted oracle events, not data accepted from a proof. A caller
//! may complete the first 64 output bytes at the first input query for analysis;
//! this does not assert that production consumed 64 bytes from that reader.
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub(crate) struct View {
    origin: Arc<()>,
    before: usize,
}
/// Exclusive pre-phase boundary. Unlike an original query View, this does
/// not include an input first queried at the boundary's next event.
#[derive(Clone, Debug)]
pub(crate) struct Checkpoint {
    origin: Arc<()>,
    next_event: usize,
}
#[derive(Clone, Debug)]
pub(crate) enum QueryExposure {
    Fresh,
    PreviouslyQueried { first: View },
}
struct Producer {
    input: Arc<[u8]>,
    answered_at: usize,
}
/// Trusted recorder attribution, never inferred from an input's syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryActor {
    Unknown,
    Adversary,
    Verifier,
    Setup,
}
struct Query {
    view: View,
    answer: [u8; 64],
    first_actor: QueryActor,
    output_prefix: Arc<[u8]>,
    prefix_observations: Vec<(usize, usize)>,
}
/// Predictable exposure sums at fresh-input answers. These are realized
/// diagnostic counts, not expectation bounds or charged attacker work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Exposure {
    pub(crate) fresh_answers: usize,
    pub(crate) target_pairs: u128,
    pub(crate) collision_pairs: u128,
}
pub(crate) struct History {
    origin: Arc<()>,
    events: usize,
    queries: HashMap<Arc<[u8]>, Query>,
    producers: HashMap<[u8; 64], Producer>,
    targets: HashSet<[u8; 64]>,
    prefixes: HashMap<[u8; 64], Arc<[u8]>>,
    availability_hits: usize,
    collisions: usize,
    exposure: Exposure,
}
impl Default for History {
    fn default() -> Self {
        Self {
            origin: Arc::new(()),
            events: 0,
            queries: HashMap::new(),
            producers: HashMap::new(),
            targets: HashSet::new(),
            prefixes: HashMap::new(),
            availability_hits: 0,
            collisions: 0,
            exposure: Exposure::default(),
        }
    }
}
impl History {
    fn targets(&mut self, input: &[u8]) -> Arc<[u8]> {
        let Some(prefix) = input.get(..64) else {
            return Arc::from(input); // No eligible window in a short input.
        };
        let key: [u8; 64] = prefix.try_into().unwrap();
        let shared = self.prefixes.get(&key).map_or(0, |previous| {
            if input.starts_with(previous.as_ref()) {
                return previous.len();
            }
            if previous.starts_with(input) {
                return input.len();
            }
            previous
                .iter()
                .zip(input)
                .take_while(|(a, b)| a == b)
                .count()
        });
        // Every window fully contained in the exact shared prefix was indexed
        // by the previous input. Keep all windows crossing its boundary.
        let start = shared.saturating_sub(63);
        self.targets.extend(
            input[start..]
                .windows(64)
                .map(|window| <[u8; 64]>::try_from(window).unwrap()),
        );
        if let Some(previous) = self.prefixes.get(&key) {
            if previous.as_ref() == input {
                return Arc::clone(previous);
            }
        }
        let input: Arc<[u8]> = Arc::from(input);
        self.prefixes.insert(key, Arc::clone(&input));
        input
    }
    /// Register another oracle input before its answer; it cannot produce XOF
    /// links. Every overlapping window is eligible, with no input/query cutoff.
    pub(crate) fn declare_external_input(&mut self, input: &[u8]) {
        self.targets(input);
        self.events += 1;
    }
    /// Record one trusted answer, freezing a fresh input's view before its own
    /// answer is available. Repeated inputs retain their original frozen view.
    pub(crate) fn query(&mut self, input: &[u8], answer: [u8; 64]) -> Result<View, &'static str> {
        self.query_with_actor(input, answer, QueryActor::Unknown)
    }
    /// Actor labels are caller-provided recording premises. Neither repeats
    /// nor later better-informed callers may relabel the original query.
    pub(crate) fn query_with_actor(
        &mut self,
        input: &[u8],
        answer: [u8; 64],
        actor: QueryActor,
    ) -> Result<View, &'static str> {
        if self
            .queries
            .get(input)
            .is_some_and(|query| query.answer != answer)
        {
            return Err("inconsistent answer to repeated XOF input");
        }
        let fresh = !self.queries.contains_key(input);
        let input = self.targets(input);
        if fresh {
            // Targets include this query's own input, registered before the
            // answer. Previous producers include distinct outputs only.
            // Do not inspect the current answer when determining exposure.
            let exposure = Exposure {
                fresh_answers: self
                    .exposure
                    .fresh_answers
                    .checked_add(1)
                    .ok_or("fresh-answer counter overflow")?,
                target_pairs: self
                    .exposure
                    .target_pairs
                    .checked_add(self.targets.len() as u128)
                    .ok_or("target-exposure counter overflow")?,
                collision_pairs: self
                    .exposure
                    .collision_pairs
                    .checked_add(self.producers.len() as u128)
                    .ok_or("collision-exposure counter overflow")?,
            };
            self.exposure = exposure;
        }
        let view = self
            .queries
            .entry(Arc::clone(&input))
            .or_insert_with(|| Query {
                view: View {
                    origin: Arc::clone(&self.origin),
                    before: self.events,
                },
                answer,
                first_actor: actor,
                output_prefix: Arc::from(answer.as_slice()),
                prefix_observations: vec![(self.events, 64)],
            })
            .view
            .clone();
        if let Some(previous) = self.producers.get(&answer) {
            if fresh && previous.input.as_ref() != input.as_ref() {
                self.collisions += 1;
            }
        } else {
            if self.targets.contains(&answer) {
                self.availability_hits += 1;
            }
            self.producers.insert(
                answer,
                Producer {
                    input,
                    answered_at: self.events,
                },
            );
        }
        self.events += 1;
        Ok(view)
    }
    /// Record a trusted, possibly longer prefix of the same XOF stream.
    /// The first 64 bytes must be supplied even if the real reader consumed
    /// fewer; this is the same explicit analysis completion as `query`.
    /// Prefix extensions retain the original actor/view and add no fresh
    /// oracle opportunity. This checks recorded consistency, not randomness
    /// or whether a production reader actually supplied these bytes.
    pub(crate) fn query_output_prefix(
        &mut self,
        input: &[u8],
        output: &[u8],
        actor: QueryActor,
    ) -> Result<View, &'static str> {
        let answer: [u8; 64] = output
            .get(..64)
            .ok_or("XOF prefix recording requires 64-byte analysis completion")?
            .try_into()
            .unwrap();
        if let Some(query) = self.queries.get(input) {
            let overlap = output.len().min(query.output_prefix.len());
            if output[..overlap] != query.output_prefix[..overlap] {
                return Err("inconsistent prefix of repeated XOF stream");
            }
        }
        let event = self.events;
        let view = self.query_with_actor(input, answer, actor)?;
        let query = self.queries.get_mut(input).unwrap();
        if output.len() > query.output_prefix.len() {
            query.output_prefix = Arc::from(output);
            query.prefix_observations.push((event, output.len()));
        }
        Ok(view)
    }
    /// Bytes recorded strictly before this exclusive boundary. Later prefix
    /// extensions cannot retroactively reveal more at an earlier checkpoint.
    /// `None` means foreign history or no recorded input, not an empty stream.
    pub(crate) fn output_prefix_at(&self, checkpoint: &Checkpoint, input: &[u8]) -> Option<&[u8]> {
        if !Arc::ptr_eq(&self.origin, &checkpoint.origin) {
            return None;
        }
        let query = self.queries.get(input)?;
        let length = query
            .prefix_observations
            .iter()
            .rev()
            .find(|(event, _)| *event < checkpoint.next_event)?
            .1;
        Some(&query.output_prefix[..length])
    }
    pub(crate) fn first_query_actor(&self, view: &View, input: &[u8]) -> Option<QueryActor> {
        self.input_is_original_view(view, input)
            .then(|| self.queries.get(input).map(|query| query.first_actor))?
    }
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            origin: Arc::clone(&self.origin),
            next_event: self.events,
        }
    }
    /// Classify an exact stream input at a saved pre-phase boundary without
    /// reading its answer. Later queries cannot change this classification.
    /// A previously queried prefix conservatively counts as preexposed even
    /// when the verifier will consume more bytes than the caller read earlier.
    pub(crate) fn query_exposure_at(
        &self,
        checkpoint: &Checkpoint,
        input: &[u8],
    ) -> Option<QueryExposure> {
        if !Arc::ptr_eq(&self.origin, &checkpoint.origin) {
            return None;
        }
        Some(match self.queries.get(input) {
            Some(query) if query.view.before < checkpoint.next_event => {
                QueryExposure::PreviouslyQueried {
                    first: query.view.clone(),
                }
            }
            _ => QueryExposure::Fresh,
        })
    }
    pub(crate) fn producer<'a>(&'a self, view: &View, answer: &[u8; 64]) -> Option<&'a [u8]> {
        if !Arc::ptr_eq(&self.origin, &view.origin) {
            return None;
        }
        let producer = self.producers.get(answer)?;
        (producer.answered_at < view.before).then_some(producer.input.as_ref())
    }
    /// Original view for a recorded input, not authority to follow it from a
    /// different query. Ancestor traversal must use `producer_first_view`.
    pub(crate) fn first_view(&self, input: &[u8]) -> Option<View> {
        self.queries.get(input).map(|query| query.view.clone())
    }
    /// Whether this exact input was queried strictly before this frozen view.
    /// A later query or repetition cannot repair the original prefix history.
    pub(crate) fn input_was_queried(&self, view: &View, input: &[u8]) -> bool {
        Arc::ptr_eq(&self.origin, &view.origin)
            && self
                .queries
                .get(input)
                .is_some_and(|query| query.view.before < view.before)
    }
    /// Bind candidate bytes to their original query view without reading coins.
    pub(crate) fn input_is_original_view(&self, view: &View, input: &[u8]) -> bool {
        Arc::ptr_eq(&self.origin, &view.origin)
            && self
                .queries
                .get(input)
                .is_some_and(|query| query.view.before == view.before)
    }
    /// Distinct input/original-view metadata visible at this boundary.
    /// Oracle answers are deliberately not exposed by this iterator.
    pub(crate) fn query_inputs_at<'a>(
        &'a self,
        view: &View,
    ) -> Option<impl Iterator<Item = (&'a [u8], View)> + 'a> {
        if !Arc::ptr_eq(&self.origin, &view.origin) {
            return None;
        }
        let before = view.before;
        Some(
            self.queries
                .iter()
                .filter(move |(_, query)| query.view.before <= before)
                .map(|(input, query)| (input.as_ref(), query.view.clone())),
        )
    }

    /// Earliest matching input at or before this view, using metadata only.
    /// The predicate must classify input syntax, not inspect oracle answers.
    pub(crate) fn first_query_matching<'a>(
        &'a self,
        view: &View,
        matches: impl Fn(&[u8]) -> bool,
    ) -> Option<(&'a [u8], View)> {
        if !Arc::ptr_eq(&self.origin, &view.origin) {
            return None;
        }
        self.queries
            .iter()
            .filter(|(input, query)| query.view.before <= view.before && matches(input))
            .min_by_key(|(_, query)| query.view.before)
            .map(|(input, query)| (input.as_ref(), query.view.clone()))
    }

    /// Follow an already available producer using its own original view, not
    /// the descendant's larger producer map. Every successful edge decreases
    /// the query epoch, so no dependency cycle can be traversed this way.
    pub(crate) fn producer_first_view<'a>(
        &'a self,
        view: &View,
        answer: &[u8; 64],
    ) -> Option<(&'a [u8], View)> {
        let input = self.producer(view, answer)?;
        let first = self.first_view(input)?;
        (first.before < view.before).then_some((input, first))
    }
    /// Materialize only when a legacy prefix interpreter needs its map API.
    /// Views themselves retain a token/epoch rather than copying every map.
    pub(crate) fn producers(&self, view: &View) -> Option<HashMap<[u8; 64], Vec<u8>>> {
        if !Arc::ptr_eq(&self.origin, &view.origin) {
            return None;
        }
        Some(
            self.producers
                .iter()
                .filter(|(_, producer)| producer.answered_at < view.before)
                .map(|(&answer, producer)| (answer, producer.input.to_vec()))
                .collect(),
        )
    }
    pub(crate) fn exposure(&self) -> Exposure {
        self.exposure
    }
    pub(crate) fn availability_hits(&self) -> usize {
        self.availability_hits
    }
    pub(crate) fn collisions(&self) -> usize {
        self.collisions
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_query_actor_cannot_be_reassigned_by_replays() {
        use super::{History, QueryActor, QueryExposure};
        let mut history = History::default();
        let first = history
            .query_with_actor(b"selected stream", [1; 64], QueryActor::Adversary)
            .unwrap();
        let boundary = history.checkpoint();
        let replay = history
            .query_with_actor(b"selected stream", [1; 64], QueryActor::Verifier)
            .unwrap();
        assert_eq!(
            history.first_query_actor(&replay, b"selected stream"),
            Some(QueryActor::Adversary)
        );
        let Some(QueryExposure::PreviouslyQueried { first: exposed }) =
            history.query_exposure_at(&boundary, b"selected stream")
        else {
            panic!("adversarially exposed stream must not become fresh");
        };
        assert_eq!(
            history.first_query_actor(&exposed, b"selected stream"),
            Some(QueryActor::Adversary)
        );
        let unknown = history.query(b"unattributed", [2; 64]).unwrap();
        history
            .query_with_actor(b"unattributed", [2; 64], QueryActor::Adversary)
            .unwrap();
        assert_eq!(
            history.first_query_actor(&unknown, b"unattributed"),
            Some(QueryActor::Unknown)
        );
        let verifier = history
            .query_with_actor(b"fresh verifier", [3; 64], QueryActor::Verifier)
            .unwrap();
        let setup = history
            .query_with_actor(b"setup stream", [4; 64], QueryActor::Setup)
            .unwrap();
        assert_eq!(
            history.first_query_actor(&verifier, b"fresh verifier"),
            Some(QueryActor::Verifier)
        );
        assert_eq!(
            history.first_query_actor(&setup, b"setup stream"),
            Some(QueryActor::Setup)
        );
        assert!(history.first_query_actor(&first, b"unattributed").is_none());
        let other = History::default();
        assert!(
            other
                .first_query_actor(&first, b"selected stream")
                .is_none()
        );
        assert!(
            history
                .query_with_actor(b"selected stream", [5; 64], QueryActor::Setup)
                .is_err()
        );
        assert_eq!(
            history.first_query_actor(&first, b"selected stream"),
            Some(QueryActor::Adversary)
        );
    }

    #[test]
    fn phase_boundaries_classify_first_exposure_without_late_repair() {
        use super::{History, QueryExposure};
        let mut history = History::default();
        let start = history.checkpoint();
        // Registering a proposed digest does not query its sampler input.
        history.declare_external_input(&[3; 64]);
        assert!(matches!(
            history.query_exposure_at(&start, b"sampler"),
            Some(QueryExposure::Fresh)
        ));
        let at_phase = history.checkpoint();
        let original = history.query(b"sampler", [3; 64]).unwrap();
        // The query at exactly the checkpoint's next event was still fresh.
        assert!(matches!(
            history.query_exposure_at(&at_phase, b"sampler"),
            Some(QueryExposure::Fresh)
        ));
        assert!(matches!(
            history.query_exposure_at(&start, b"sampler"),
            Some(QueryExposure::Fresh)
        ));
        let next_phase = history.checkpoint();
        let Some(QueryExposure::PreviouslyQueried { first }) =
            history.query_exposure_at(&next_phase, b"sampler")
        else {
            panic!("later phase must retain the original first query");
        };
        assert!(history.input_is_original_view(&first, b"sampler"));
        assert!(history.input_is_original_view(&original, b"sampler"));
        history.query(b"sampler", [3; 64]).unwrap();
        history.query(b"other input", [4; 64]).unwrap();
        assert!(matches!(
            history.query_exposure_at(&at_phase, b"sampler"),
            Some(QueryExposure::Fresh)
        ));
        assert!(matches!(
            history.query_exposure_at(&next_phase, b"other input"),
            Some(QueryExposure::Fresh)
        ));
        let Some(QueryExposure::PreviouslyQueried { first }) =
            history.query_exposure_at(&next_phase, b"sampler")
        else {
            panic!("repeat must not replace original provenance");
        };
        assert!(history.input_is_original_view(&first, b"sampler"));
        let foreign = History::default().checkpoint();
        assert!(history.query_exposure_at(&foreign, b"sampler").is_none());
    }

    #[test]
    fn exposure_is_predictable_and_does_not_recharge_repeats() {
        use super::{Exposure, History};
        let mut history = History::default();
        assert_eq!(history.exposure(), Exposure::default());
        history.declare_external_input(&[7; 65]); // Two equal windows, one target.
        assert_eq!(history.exposure(), Exposure::default());
        history.query(&[8; 64], [9; 64]).unwrap();
        assert_eq!(
            history.exposure(),
            Exposure {
                fresh_answers: 1,
                target_pairs: 2,
                collision_pairs: 0,
            }
        );
        // A target revealed after the answer is exposed only at later fresh
        // queries, even if an old input is queried again after that reveal.
        history.declare_external_input(&[9; 64]);
        history.query(&[8; 64], [9; 64]).unwrap();
        assert_eq!(history.exposure().target_pairs, 2);
        history.query(b"short second input", [9; 64]).unwrap();
        assert_eq!(
            history.exposure(),
            Exposure {
                fresh_answers: 2,
                target_pairs: 5,
                collision_pairs: 1,
            }
        );
        assert_eq!(history.collisions(), 1);
        history.query(b"short third input", [7; 64]).unwrap();
        assert_eq!(
            history.exposure(),
            Exposure {
                fresh_answers: 3,
                target_pairs: 8,
                collision_pairs: 2,
            }
        );
        assert_eq!(history.availability_hits(), 1);
        let snapshot = history.exposure();
        assert!(history.query(b"short third input", [1; 64]).is_err());
        assert_eq!(history.exposure(), snapshot);
        // Exposure at the first query cannot depend on its answer.
        let mut different = History::default();
        different.declare_external_input(&[7; 65]);
        different.query(&[8; 64], [7; 64]).unwrap();
        assert_eq!(
            different.exposure(),
            Exposure {
                fresh_answers: 1,
                target_pairs: 2,
                collision_pairs: 0,
            }
        );
        assert_eq!(different.availability_hits(), 1);
    }

    #[test]
    fn first_matching_query_preserves_original_order_and_view_bounds() {
        let mut history = super::History::default();
        let first = history.query(b"family descendant", [1; 64]).unwrap();
        let root = history.query(b"family root", [2; 64]).unwrap();
        let (input, view) = history
            .first_query_matching(&root, |input| input.starts_with(b"family"))
            .unwrap();
        assert_eq!(input, b"family descendant");
        assert_eq!(history.query_inputs_at(&first).unwrap().count(), 1);
        assert_eq!(history.query_inputs_at(&root).unwrap().count(), 2);

        assert!(history.input_is_original_view(&view, input));
        assert!(
            history
                .first_query_matching(&first, |input| input == b"family root")
                .is_none()
        );
        let repeat = history.query(b"family descendant", [1; 64]).unwrap();
        assert!(
            history
                .first_query_matching(&repeat, |input| input == b"family root")
                .is_none()
        );
        let mut foreign = super::History::default();
        let other = foreign.query(b"family root", [2; 64]).unwrap();
        assert!(history.first_query_matching(&other, |_| true).is_none());
        assert!(history.query_inputs_at(&other).is_none());
    }

    use super::*;

    #[test]
    fn prefix_index_preserves_all_naive_targets_and_boundary_availability() {
        let mut history = History::default();
        let mut naive = HashSet::<[u8; 64]>::new();
        let base = (0..256).map(|i| i as u8).collect::<Vec<_>>();
        let mut inputs = vec![base.clone(), base.clone(), vec![3; 12]];
        for shared in 0..=base.len() {
            let mut changed = base[..shared].to_vec();
            changed.extend_from_slice(&[99; 80]);
            inputs.push(changed);
            inputs.push(base.clone());
        }
        for input in inputs {
            naive.extend(input.windows(64).map(|w| <[u8; 64]>::try_from(w).unwrap()));
            history.declare_external_input(&input);
            assert_eq!(history.targets, naive);
        }
        let mut extended = base.clone();
        extended.push(77);
        let boundary: [u8; 64] = extended[extended.len() - 64..].try_into().unwrap();
        assert!(!history.targets.contains(&boundary));
        let view = history.query(&extended, boundary).unwrap();
        assert!(history.producer(&view, &boundary).is_none());
        assert_eq!(history.availability_hits(), 1);
        let repeated = history.query(&extended, boundary).unwrap();
        assert_eq!(view.before, repeated.before);
        assert_eq!(history.availability_hits(), 1);
        assert_eq!(history.collisions(), 0);
    }

    #[test]
    fn xof_first_views_exclude_self_late_repair_and_foreign_histories() {
        let mut history = History::default();
        let first = history.query(b"first", [1; 64]).unwrap();
        assert!(history.producer(&first, &[1; 64]).is_none());
        let second = history.query(b"second", [2; 64]).unwrap();
        assert_eq!(
            history.producer(&second, &[1; 64]),
            Some(b"first".as_slice())
        );
        assert!(history.producer(&second, &[2; 64]).is_none());
        let (ancestor_input, ancestor_view) =
            history.producer_first_view(&second, &[1; 64]).unwrap();
        assert_eq!(ancestor_input, b"first");
        assert!(ancestor_view.before < second.before);
        assert!(history.producers(&ancestor_view).unwrap().is_empty());
        assert!(
            history
                .producer_first_view(&ancestor_view, &[2; 64])
                .is_none()
        );
        assert!(history.first_view(b"unqueried input").is_none());
        history.query(b"late", [3; 64]).unwrap();
        let repeated = history.query(b"second", [2; 64]).unwrap();
        assert_eq!(repeated.before, second.before);
        assert!(history.producer(&repeated, &[3; 64]).is_none());
        assert_eq!(history.producers(&repeated).unwrap().len(), 1);
        let other = History::default();
        assert!(other.producer(&second, &[1; 64]).is_none());
        assert!(other.producers(&second).is_none());
        assert!(other.producer_first_view(&second, &[1; 64]).is_none());
        assert!(history.query(b"second", [9; 64]).is_err());
        assert_eq!(
            history.producer(&second, &[1; 64]),
            Some(b"first".as_slice())
        );
    }

    #[test]
    fn xof_targets_precede_answers_and_repeated_queries_are_not_collisions() {
        let mut history = History::default();
        history.declare_external_input(&[7; 64]);
        let before = history.query(b"late producer", [7; 64]).unwrap();
        assert!(history.producer(&before, &[7; 64]).is_none());
        assert_eq!(history.availability_hits(), 1);
        history.query(b"late producer", [7; 64]).unwrap();
        assert_eq!(history.availability_hits(), 1);
        assert_eq!(history.collisions(), 0);
        history.query(b"distinct producer", [7; 64]).unwrap();
        assert_eq!(history.collisions(), 1);
        history.query(b"distinct producer", [7; 64]).unwrap();
        assert_eq!(history.collisions(), 1);
        let mut own_target = History::default();
        let view = own_target.query(&[8; 64], [8; 64]).unwrap();
        assert!(own_target.producer(&view, &[8; 64]).is_none());
        assert_eq!(own_target.availability_hits(), 1);
    }
}
