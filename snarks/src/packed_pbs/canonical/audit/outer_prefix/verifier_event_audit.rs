//! Real accumulator PCS verification events, not a complete PBS trace.
use super::*;
use std::sync::{Arc, LazyLock, Mutex};
mod complete_pbs_event_audit;
mod monomial_event_audit;
mod key_switch_event_audit;
mod temporal_child_audit;
mod temporal_child_stream_audit;
mod preserved_trace_replay;
mod proposed_phase_audit;
pub(super) use proposed_phase_audit::{exercise_primary_column_binding, exercise_primary_atomic_column_binding, RecordedStreams};
static TRACE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
enum Event {
    Hash(Digest512, Vec<u8>),
    Xof(Vec<u8>),
}
#[derive(Default)]
struct Capture {
    history: classical_history::History,
    events: Vec<Event>,
}
static ACTIVE: LazyLock<Mutex<Option<Arc<Mutex<Capture>>>>> = LazyLock::new(|| Mutex::new(None));
struct CaptureGuard;
impl Drop for CaptureGuard {
    fn drop(&mut self) {
        *ACTIVE.lock().unwrap() = None;
    }
}
#[derive(Clone, Debug, Default)]
struct EventHash {
    state: Sha512,
    input: Vec<u8>,
}
impl pcs::utils::hash::Hash for EventHash {
    type Output = Digest512;
    fn update_hash_value(&mut self, bytes: &[u8]) {
        Digest::update(&mut self.state, bytes);
        self.input.extend_from_slice(bytes);
    }
    fn output_reset(&mut self) -> Digest512 {
        let output = Digest512(self.state.finalize_reset().into());
        let input = std::mem::take(&mut self.input);
        complete_pbs_event_audit::record_hash(output, &input);
        let active = ACTIVE.lock().unwrap().clone();
        if let Some(active) = active {
            let mut capture = active.lock().unwrap();
            // Register input windows before the digest is returned to callers.
            capture.history.expose(output, input.clone());
            capture.events.push(Event::Hash(output, input));
        }
        output
    }
}

fn exercise<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, EventHash>,
{
    let profile = bundle.profile();
    let pp = super::super::super::classical::parameters(&bundle);
    let capture = Arc::new(Mutex::new(Capture::default()));
    {
        let mut active = ACTIVE.lock().unwrap();
        assert!(active.is_none());
        *active = Some(Arc::clone(&capture));
    }
    let hash_guard = CaptureGuard;
    let xof_capture = Arc::clone(&capture);
    let xof_guard = helper::classical_transcript::audit::observe(move |input| {
        let mut capture = xof_capture.lock().unwrap();
        capture.history.declare_input(input);
        capture.events.push(Event::Xof(input.to_vec()));
    })
    .unwrap();

    let (width, vars) = (8, 3);
    let shape = crate::packed_accumulator::Shape::new(width, 3).unwrap();
    let mut words = vec![vec![F::zero(); width << vars]; 7];
    for half in 0..2 {
        for row in 0..3 {
            for coefficient in 0..width {
                let at = (half * 4 + row) * width + coefficient;
                words[0][at] = F::from(row);
                words[1][at] = F::from(row);
                words[3][at] = F::from(row + 1);
                words[4][at] = F::one();
            }
        }
    }
    let tables: Vec<_> = words
        .into_iter()
        .map(|word| PackedTable::new(vars, width, word).unwrap())
        .collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(9931);
    let retained: Vec<_> = tables
        .iter()
        .enumerate()
        .map(|(slot, table)| {
            <P as CanonicalPcs<F, EventHash>>::commit(
                accumulator_parameters::<P>(&pp, slot).unwrap(),
                table,
                &mut rng,
            )
            .ok()
            .unwrap()
        })
        .collect();
    let oracles: Vec<crate::packed_oracle::CanonicalProverOracle<'_, F, EventHash, P>> = retained
        .iter()
        .enumerate()
        .map(
            |(slot, (commitment, state))| crate::packed_oracle::CanonicalProverOracle {
                parameters: accumulator_parameters::<P>(&pp, slot).unwrap(),
                commitment,
                state,
            },
        )
        .collect();
    let public: Vec<_> = oracles.iter().map(|source| source.verifier()).collect();
    let private: Vec<_> = oracles.iter().collect();
    let initial = vec![F::zero(); width * 2];
    let final_acc = vec![F::from(3usize); width * 2];
    let mut prover = profile.parent_transcript::<F>().unwrap();
    let proof = crate::packed_accumulator::prove_canonical::<F, EventHash, P>(
        &mut prover,
        &shape,
        &initial,
        &final_acc,
        &private,
    )
    .unwrap();
    let mut prover_finish = [0; 64];
    prover.get_challenge_bytes(b"observed accumulator continuation", &mut prover_finish);
    let start = capture.lock().unwrap().events.len();
    let mut verifier = profile.parent_transcript::<F>().unwrap();
    crate::packed_accumulator::verify_canonical::<F, EventHash, P>(
        &mut verifier,
        &shape,
        &initial,
        &final_acc,
        &public,
        &proof,
    )
    .unwrap();
    let end = capture.lock().unwrap().events.len();
    let mut verifier_finish = [0; 64];
    verifier.get_challenge_bytes(b"observed accumulator continuation", &mut verifier_finish);
    assert_eq!(prover_finish, verifier_finish);
    drop(xof_guard);
    drop(hash_guard);

    let mut unobserved = profile.parent_transcript::<F>().unwrap();
    crate::packed_accumulator::verify_canonical::<F, EventHash, P>(
        &mut unobserved,
        &shape,
        &initial,
        &final_acc,
        &public,
        &proof,
    )
    .unwrap();
    let mut unobserved_finish = [0; 64];
    unobserved.get_challenge_bytes(b"observed accumulator continuation", &mut unobserved_finish);
    assert_eq!(unobserved_finish, verifier_finish);
    assert_eq!(capture.lock().unwrap().events.len(), end + 1);

    let mut replay = classical_history::History::default();
    let capture = capture.lock().unwrap();
    for event in &capture.events {
        match event {
            Event::Hash(output, input) => replay.expose(*output, input.clone()),
            Event::Xof(input) => replay.declare_input(input),
        }
    }
    assert_eq!(replay.hash_queries(), capture.history.hash_queries());
    assert_eq!(replay.xof_queries(), capture.history.xof_queries());
    assert_eq!(replay.events(), capture.events.len());
    assert_eq!(
        replay.availability_hits(),
        capture.history.availability_hits()
    );
    let hash_queries = capture.events[start..end]
        .iter()
        .filter(|event| matches!(event, Event::Hash(..)))
        .count();
    let xof_queries = end - start - hash_queries;
    assert!(hash_queries > 0 && xof_queries > 0);
    let sources: Vec<_> = public
        .iter()
        .map(|source| {
            (
                <P as CanonicalPcs<F, Sha512>>::context(source.parameters)
                    .ok()
                    .unwrap(),
                source.commitment.clone(),
            )
        })
        .collect();
    for (_, commitment) in &sources {
        let first = capture.history.view(commitment.root).unwrap();
        let replayed = replay.view(commitment.root).unwrap();
        assert_eq!(first.as_ref(), replayed.as_ref());
    }
    let mut binding = profile.parent_transcript::<F>().unwrap();
    let (base, _) = crate::packed_accumulator::audit::binding_queries::<F, Sha512, P>(
        &mut binding,
        &shape,
        &initial,
        &final_acc,
        &public,
    )
    .unwrap();
    let task = AccumulatorTask {
        shape,
        initial,
        final_acc,
        sources,
        base,
    };
    let (promises, values) =
        accumulator_history_values::<F, EF, P>(profile, &pp, &task, &capture.history).unwrap();
    assert!(promises.iter().all(|&promised| promised));
    assert_eq!(encoded(&values), encoded(&proof.values));
    assert!(accumulator_values_valid::<F, P>(&pp, &task, &values));
    println!(
        "HB_ACCUMULATOR_EVENT_TRACE {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"verifier_hash_queries\":{},\"verifier_xof_queries\":{},\"total_events\":{},\"availability_hits\":{},\"full_pbs_trace\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        hash_queries,
        xof_queries,
        capture.events.len(),
        replay.availability_hits()
    );
}
fn field<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for version in [4, 5] {
        for backend in [
            Backend::Brakedown,
            Backend::Polyfrim,
            Backend::PolyfrimDictionary,
            Backend::FragmentedPipfri,
            Backend::FragmentedPipfriVirtual,
        ] {
            let spec = Specification {
                backend,
                roles: std::array::from_fn(|_| Role {
                    num_vars: 3,
                    width: 8,
                    queries: 8,
                    left_vars: (backend == Backend::Brakedown).then_some(1),
                    block_width: (backend == Backend::Brakedown).then_some(2),
                }),
                blowup: 2,
                fragment_vars: matches!(
                    backend,
                    Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
                )
                .then_some(2),
            };
            let profile = if version == 4 {
                ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
            } else {
                ClassicalProfile::new_atomic_columns::<F, EF>(spec)
            }
            .unwrap();
            match backend {
                Backend::Brakedown => {
                    exercise::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap())
                }
                Backend::Polyfrim => {
                    exercise::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap())
                }
                Backend::PolyfrimDictionary => {
                    exercise::<F, EF, _>(profile.polyfrim_dictionary_parameters::<F, EF>().unwrap())
                }
                Backend::FragmentedPipfri => {
                    exercise::<F, EF, _>(profile.fragmented_parameters::<F, EF>().unwrap())
                }
                Backend::FragmentedPipfriVirtual => {
                    exercise::<F, EF, _>(profile.fragmented_virtual_parameters::<F, EF>().unwrap())
                }
            }
        }
    }
}
#[test]
fn production_accumulator_oracle_events() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    field::<algebra::BabyBear, algebra::BabyBearExtension6>();
    field::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
