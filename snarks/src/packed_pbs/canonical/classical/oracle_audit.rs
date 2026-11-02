//! Optional interface-level counters, never complete security/resource admission.
use super::*;
use pcs::utils::hash::Hash;
use serde::de::DeserializeOwned;
use sha2::Digest;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
pub mod reader_stream;

/// Borrowed events from the instrumented hash and transcript-reader interfaces.
pub enum OracleEvent<'a> {
    Hash { input: &'a [u8], output: Digest512 },
    Reader(helper::classical_transcript::audit::ReaderEvent<'a>),
}
/// Optional synchronous observer. Callbacks must not query observed interfaces.
pub type EventCallback = Arc<dyn Fn(OracleEvent<'_>) + Send + Sync>;

/// Observed PCS SHA512 requests and transcript SHAKE input/output activity.
/// Direct primitive calls outside those interfaces are excluded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OracleCounts {
    pub hash_queries: u128,
    pub hash_input_bytes: u128,
    pub max_hash_input: u128,
    pub xof_queries: u128,
    pub xof_input_bytes: u128,
    pub max_xof_input: u128,
    pub xof_output_bytes: u128,
    pub max_xof_output: u128,
    pub lookup_reciprocal_rejections: u128,
    pub column_sampling_phases: u128,
    pub column_values_sampled: u128,
    pub column_candidate_draws: u128,
    pub max_column_candidates_per_value: u128,
    pub field_sampling_phases: u128,
    pub field_values_sampled: u128,
    pub field_candidate_draws: u128,
    pub max_field_candidates_per_value: u128,
    pub field_output_bytes: u128,
    pub max_field_phase_output_bytes: u128,
    pub max_field_values_per_phase: u128,
    pub max_column_values_per_phase: u128,
}
struct State {
    enabled: AtomicBool,
    counts: Mutex<OracleCounts>,
    events: Option<EventCallback>,
}
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("events", &self.events.is_some())
            .finish_non_exhaustive()
    }
}
static ACTIVE: Mutex<Option<Arc<State>>> = Mutex::new(None);
struct Guard(Arc<State>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.enabled.store(false, Ordering::Release);
        let mut active = ACTIVE.lock().unwrap();
        if active.as_ref().is_some_and(|s| Arc::ptr_eq(s, &self.0)) {
            *active = None;
        }
    }
}
fn observe() -> Result<Guard, Error> {
    observe_events(None)
}
fn observe_events(events: Option<EventCallback>) -> Result<Guard, Error> {
    let mut active = ACTIVE.lock().unwrap();
    if active.is_some() {
        return Err(error("oracle counter scope already active"));
    }
    let state = Arc::new(State {
        enabled: AtomicBool::new(true),
        counts: Mutex::new(OracleCounts::default()),
        events,
    });
    *active = Some(Arc::clone(&state));
    Ok(Guard(state))
}

/// SHA512-compatible hash for the audit verifier; cloned states retain their
/// own absorbed lengths and the scope's observer across synchronous workers.
#[derive(Clone, Debug)]
pub struct CountingSha512 {
    hash: Sha512,
    bytes: u128,
    observer: Option<Arc<State>>,
    input: Option<Vec<u8>>,
}
impl Default for CountingSha512 {
    fn default() -> Self {
        let observer = ACTIVE.lock().unwrap().clone();
        let input = observer
            .as_ref()
            .filter(|state| state.events.is_some())
            .map(|_| Vec::new());
        Self {
            hash: Sha512::default(),
            bytes: 0,
            observer,
            input,
        }
    }
}
impl Hash for CountingSha512 {
    type Output = Digest512;
    fn update_hash_value(&mut self, input: &[u8]) {
        Digest::update(&mut self.hash, input);
        self.bytes += input.len() as u128;
        if let Some(bytes) = &mut self.input {
            bytes.extend_from_slice(input);
        }
    }
    fn output_reset(&mut self) -> Digest512 {
        let output = Digest512(self.hash.finalize_reset().into());
        let bytes = std::mem::take(&mut self.bytes);
        if let Some(state) = &self.observer {
            if state.enabled.load(Ordering::Acquire) {
                {
                    let mut counts = state.counts.lock().unwrap();
                    counts.hash_queries += 1;
                    counts.hash_input_bytes += bytes;
                    counts.max_hash_input = counts.max_hash_input.max(bytes);
                }
                if let (Some(callback), Some(input)) = (&state.events, &self.input) {
                    callback(OracleEvent::Hash { input, output });
                }
            }
        }
        if let Some(input) = &mut self.input {
            input.clear();
        }
        output
    }
}

fn observe_transcript(
    state: &Arc<State>,
) -> Result<helper::classical_transcript::audit::ObservationGuard, Error> {
    let xof_state = Arc::clone(state);
    let resource_state = Arc::clone(state);
    let inputs = move |input: &[u8]| {
        let mut counts = xof_state.counts.lock().unwrap();
        counts.xof_queries += 1;
        counts.xof_input_bytes += input.len() as u128;
        counts.max_xof_input = counts.max_xof_input.max(input.len() as u128);
    };
    let resources = move |event| match event {
        helper::classical_transcript::audit::ResourceEvent::ColumnSampling {
            values,
            candidates,
            max_candidates_per_value,
        } => {
            let mut counts = resource_state.counts.lock().unwrap();
            counts.column_sampling_phases += 1;
            counts.column_values_sampled += values;
            counts.max_column_values_per_phase = counts.max_column_values_per_phase.max(values);
            counts.column_candidate_draws += candidates;
            counts.max_column_candidates_per_value = counts
                .max_column_candidates_per_value
                .max(max_candidates_per_value);
        }
        helper::classical_transcript::audit::ResourceEvent::XofOutput {
            bytes,
            total_for_query,
        } => {
            let mut counts = resource_state.counts.lock().unwrap();
            counts.xof_output_bytes += bytes;
            counts.max_xof_output = counts.max_xof_output.max(total_for_query);
        }
        helper::classical_transcript::audit::ResourceEvent::FieldSampling {
            values,
            candidates,
            max_candidates_per_value,
            consumed_bytes,
        } => {
            let mut counts = resource_state.counts.lock().unwrap();
            counts.field_sampling_phases += 1;
            counts.field_values_sampled += values;
            counts.max_field_values_per_phase = counts.max_field_values_per_phase.max(values);
            counts.field_candidate_draws += candidates;
            counts.max_field_candidates_per_value = counts
                .max_field_candidates_per_value
                .max(max_candidates_per_value);
            counts.field_output_bytes += consumed_bytes;
            counts.max_field_phase_output_bytes =
                counts.max_field_phase_output_bytes.max(consumed_bytes);
        }
        helper::classical_transcript::audit::ResourceEvent::LookupReciprocalRejected => {
            resource_state
                .counts
                .lock()
                .unwrap()
                .lookup_reciprocal_rejections += 1;
        }
    };
    if let Some(callback) = state.events.clone() {
        helper::classical_transcript::audit::observe_with_reader_events(resources, move |event| {
            if let helper::classical_transcript::audit::ReaderEvent::Start { input, .. } = &event {
                inputs(input);
            }
            callback(OracleEvent::Reader(event));
        })
        .map_err(error)
    } else {
        helper::classical_transcript::audit::observe_with_resources(inputs, resources)
            .map_err(error)
    }
}

/// Strict verifier result and its measured interface requests, including a
/// rejected verifier execution. Instrumentation is not a latency benchmark.
pub struct VerificationObservation {
    pub verification: Result<(), Error>,
    pub counts: OracleCounts,
}

/// Re-decode the exact ordinary proof payload and execute the strict verifier.
/// Scope/decode errors are returned separately from the observed verifier result.
pub fn verify<F, EF, P>(
    bundle: &ProfileParameters<P>,
    setup: &VerifierSetup,
    statement: &Statement<'_, F>,
    proof: &Proof<
        F,
        EF,
        <P as CanonicalPcs<F, Sha512>>::SingleProof,
        <P as CanonicalPcs<F, Sha512>>::BatchProof,
    >,
) -> Result<VerificationObservation, Error>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, CountingSha512>,
    <P as CanonicalPcs<F, CountingSha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, CountingSha512>>::BatchProof: DeserializeOwned,
{
    verify_with_optional_events::<F, EF, P>(bundle, setup, statement, proof, None)
}

/// Execute the same strict verifier with optional concrete interface events.
/// Captured events exclude direct primitive calls outside these interfaces.
pub fn verify_with_optional_events<F, EF, P>(
    bundle: &ProfileParameters<P>,
    setup: &VerifierSetup,
    statement: &Statement<'_, F>,
    proof: &Proof<
        F,
        EF,
        <P as CanonicalPcs<F, Sha512>>::SingleProof,
        <P as CanonicalPcs<F, Sha512>>::BatchProof,
    >,
    events: Option<EventCallback>,
) -> Result<VerificationObservation, Error>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, CountingSha512>,
    <P as CanonicalPcs<F, CountingSha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, CountingSha512>>::BatchProof: DeserializeOwned,
{
    bundle
        .profile()
        .validate_field::<F, EF>()
        .map_err(convert)?;
    let id = bundle.profile().id();
    if id != setup.profile_id || id != proof.profile_id {
        return Err(error("classical verifier profile mismatch"));
    }
    let bytes = bincode::serde::encode_to_vec(&proof.payload, bincode::config::standard())
        .map_err(convert)?;
    let (payload, used): (
        shared::Proof<
            F,
            EF,
            Digest512,
            <P as CanonicalPcs<F, CountingSha512>>::SingleProof,
            <P as CanonicalPcs<F, CountingSha512>>::BatchProof,
        >,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).map_err(convert)?;
    if used != bytes.len() {
        return Err(error("audit proof payload trailing bytes"));
    }
    let guard = observe_events(events)?;
    let state = Arc::clone(&guard.0);
    let xof_guard = observe_transcript(&state)?;
    let transcript = bundle.profile().parent_transcript::<F>().map_err(convert)?;
    let verification =
        super::super::verify_inner::<F, EF, CountingSha512, P, stages::ClassicalShared>(
            &parameters(bundle),
            &setup.inner,
            statement,
            &payload,
            Some(transcript),
        );
    drop(xof_guard);
    drop(guard);
    let counts = state.counts.lock().unwrap().clone();
    Ok(VerificationObservation {
        verification,
        counts,
    })
}

/// Measured honest activity; hash input lengths and direct Digest calls are
/// deliberately absent rather than reported as zero.
#[derive(Clone, Debug, Serialize)]
pub struct HonestOracleActivity {
    pub hash_queries: u128,
    pub xof_queries: u128,
    pub xof_input_bytes: u128,
    pub max_xof_input: u128,
    pub xof_output_bytes: u128,
    pub max_xof_output: u128,
    pub lookup_reciprocal_rejections: u128,
    pub column_sampling_phases: u128,
    pub column_values_sampled: u128,
    pub column_candidate_draws: u128,
    pub max_column_candidates_per_value: u128,
    pub field_sampling_phases: u128,
    pub field_values_sampled: u128,
    pub field_candidate_draws: u128,
    pub max_field_candidates_per_value: u128,
    pub field_output_bytes: u128,
    pub max_field_phase_output_bytes: u128,
    pub max_field_values_per_phase: u128,
    pub max_column_values_per_phase: u128,
}

/// Measure synchronous standard-SHA512 setup/prover activity. Hash observation
/// is process-wide; XOF/resource observation follows this thread's roots and
/// their descendants. Native controls invoke one such activity at a time.
pub fn measure_standard_sha512<R>(
    run: impl FnOnce() -> R,
) -> Result<(R, HonestOracleActivity), Error> {
    let guard = observe()?;
    let state = Arc::clone(&guard.0);
    let hash_state = Arc::clone(&state);
    let hash_guard = pcs::utils::hash::audit::observe(move |_| {
        hash_state.counts.lock().unwrap().hash_queries += 1;
    })
    .map_err(error)?;
    let xof_guard = observe_transcript(&state)?;
    let result = run();
    drop(xof_guard);
    drop(hash_guard);
    drop(guard);
    let counts = state.counts.lock().unwrap().clone();
    let activity = HonestOracleActivity {
        hash_queries: counts.hash_queries,
        xof_queries: counts.xof_queries,
        xof_input_bytes: counts.xof_input_bytes,
        max_xof_input: counts.max_xof_input,
        xof_output_bytes: counts.xof_output_bytes,
        max_xof_output: counts.max_xof_output,
        lookup_reciprocal_rejections: counts.lookup_reciprocal_rejections,
        column_sampling_phases: counts.column_sampling_phases,
        column_values_sampled: counts.column_values_sampled,
        column_candidate_draws: counts.column_candidate_draws,
        max_column_candidates_per_value: counts.max_column_candidates_per_value,
        field_sampling_phases: counts.field_sampling_phases,
        field_values_sampled: counts.field_values_sampled,
        field_candidate_draws: counts.field_candidate_draws,
        max_field_candidates_per_value: counts.max_field_candidates_per_value,
        field_output_bytes: counts.field_output_bytes,
        max_field_phase_output_bytes: counts.max_field_phase_output_bytes,
        max_field_values_per_phase: counts.max_field_values_per_phase,
        max_column_values_per_phase: counts.max_column_values_per_phase,
    };
    Ok((result, activity))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counter_hash_matches_sha512_clone_and_reset() {
        let guard = observe().unwrap();
        let state = Arc::clone(&guard.0);
        let mut first = CountingSha512::default();
        assert!(first.input.is_none());
        first.update_hash_value(b"abc");
        let mut second = first.clone();
        second.update_hash_value(b"d");
        assert_eq!(
            first.output_reset(),
            Digest512(Sha512::digest(b"abc").into())
        );
        assert_eq!(
            second.output_reset(),
            Digest512(Sha512::digest(b"abcd").into())
        );
        first.update_hash_value(b"z");
        assert_eq!(first.output_reset(), Digest512(Sha512::digest(b"z").into()));
        let counts = state.counts.lock().unwrap().clone();
        assert_eq!(
            (
                counts.hash_queries,
                counts.hash_input_bytes,
                counts.max_hash_input
            ),
            (3, 8, 4)
        );
        drop(guard);
        second.output_reset();
        assert_eq!(*state.counts.lock().unwrap(), counts);

        // A second scope is exclusive, and fresh worker-local hashers plus
        // parent-state clones charge only the active scope.
        let guard = observe().unwrap();
        assert!(observe().is_err());
        let active = Arc::clone(&guard.0);
        let mut parent = CountingSha512::default();
        parent.update_hash_value(b"abc");
        let child = parent.clone();
        let outputs = std::thread::spawn(move || {
            let mut child = child;
            let mut fresh = CountingSha512::default();
            fresh.update_hash_value(b"abcd");
            (child.output_reset(), fresh.output_reset())
        })
        .join()
        .unwrap();
        assert_eq!(
            outputs,
            (
                Digest512(Sha512::digest(b"abc").into()),
                Digest512(Sha512::digest(b"abcd").into())
            )
        );
        // A surviving hasher from the disabled scope must not charge this one.
        second.update_hash_value(b"old");
        second.output_reset();
        let counts = active.counts.lock().unwrap().clone();
        assert_eq!(
            (
                counts.hash_queries,
                counts.hash_input_bytes,
                counts.max_hash_input
            ),
            (2, 7, 4)
        );
        drop(guard);
        parent.output_reset();
        assert_eq!(*active.counts.lock().unwrap(), counts);

        // Real field sampling plus synthetic column resource events exercise
        // aggregation without imposing a sampler cap or changing transcript data.
        use helper::FiatShamirTranscript;
        let (_, activity) = measure_standard_sha512(|| {
            let mut trans = helper::Transcript::<algebra::BabyBear>::new_classical(&[37; 64]);
            let _: Vec<_> = trans.get_vec_challenge(b"small phase", 3);
            let _: Vec<_> = trans.get_vec_challenge(b"large phase", 7);
            let _: Vec<_> = trans.get_vec_challenge(b"empty phase", 0);
            for values in [2, 5] {
                trans.audit_resource_event(
                    helper::classical_transcript::audit::ResourceEvent::ColumnSampling {
                        values,
                        candidates: values,
                        max_candidates_per_value: 1,
                    },
                );
            }
        })
        .unwrap();
        assert_eq!(activity.field_sampling_phases, 3);
        assert_eq!(activity.field_values_sampled, 10);
        assert_eq!(activity.max_field_values_per_phase, 7);
        assert_eq!(activity.column_sampling_phases, 2);
        assert_eq!(activity.column_values_sampled, 7);
        assert_eq!(activity.max_column_values_per_phase, 5);

        // Optional events preserve cloned hash preimages and actual reader
        // bytes while using the same counter aggregation as the default path.
        #[derive(Debug)]
        enum Captured {
            Hash(Vec<u8>, Digest512),
            Start(Vec<u8>),
            Output(Vec<u8>),
        }
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);
        let events: EventCallback = Arc::new(move |event| {
            use helper::classical_transcript::audit::ReaderEvent;
            let event = match event {
                OracleEvent::Hash { input, output } => Captured::Hash(input.to_vec(), output),
                OracleEvent::Reader(ReaderEvent::Start { input, .. }) => {
                    Captured::Start(input.to_vec())
                }
                OracleEvent::Reader(ReaderEvent::Output { bytes, .. }) => {
                    Captured::Output(bytes.to_vec())
                }
            };
            sink.lock().unwrap().push(event);
        });
        let guard = observe_events(Some(events)).unwrap();
        let state = Arc::clone(&guard.0);
        let transcript_guard = observe_transcript(&state).unwrap();
        let mut parent = CountingSha512::default();
        assert!(parent.input.is_some());
        parent.update_hash_value(b"ab");
        let mut child = parent.clone();
        child.update_hash_value(b"c");
        parent.update_hash_value(b"d");
        child.output_reset();
        parent.output_reset();
        let mut transcript = helper::Transcript::<algebra::BabyBear>::new_classical(&[38; 64]);
        transcript.get_challenge_bytes(b"observed bytes", &mut [0; 80]);
        let _: Vec<_> = transcript.get_vec_challenge(b"observed field", 2);
        drop(transcript_guard);
        drop(guard);
        let counts = state.counts.lock().unwrap().clone();
        let captured = captured.lock().unwrap();
        let mut hashes = Vec::new();
        let (mut inputs, mut outputs) = (0u128, 0u128);
        for event in captured.iter() {
            match event {
                Captured::Hash(input, output) => {
                    assert_eq!(*output, Digest512(Sha512::digest(input).into()));
                    hashes.push(input.as_slice());
                }
                Captured::Start(input) => inputs += input.len() as u128,
                Captured::Output(bytes) => outputs += bytes.len() as u128,
            }
        }
        assert_eq!(hashes, [b"abc".as_slice(), b"abd".as_slice()]);
        assert_eq!((counts.hash_queries, counts.hash_input_bytes), (2, 6));
        assert_eq!(counts.xof_queries, 3);
        assert_eq!(counts.xof_input_bytes, inputs);
        assert_eq!(counts.xof_output_bytes, outputs);
        drop(captured);
        parent.update_hash_value(b"disabled");
        parent.output_reset();
        assert_eq!(*state.counts.lock().unwrap(), counts);
    }
}
