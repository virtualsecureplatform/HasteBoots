//! Actual pre-answer child/receipt inputs feeding the existing prefix replay.
//! This is a primitive control, not a complete admissible-prefix reduction.
use super::*;
use helper::classical_transcript::{ClassicalTranscript, audit};
use std::sync::{Arc, Mutex};

#[test]
fn actual_xof_producer_views_replay_receipts_without_late_repair() {
    type F = algebra::BabyBear;
    fn scenario() -> (Vec<F>, [u8; 64]) {
        let mut parent = ClassicalTranscript::new(b"producer history control", &[23; 64]);
        let values = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    parent.with_child(b"history child", b"trusted parameters", |child| {
                        child.challenge_prime::<F>(b"history field", 1)
                    })
                })
                .join()
                .unwrap()
        });
        let mut after = [0; 64];
        parent.challenge_bytes(b"after child", &mut after);
        (values, after)
    }
    let inputs = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let observed = Arc::clone(&inputs);
    let guard = audit::observe(move |input| observed.lock().unwrap().push(input.to_vec())).unwrap();
    let actual = scenario();
    drop(guard);
    assert_eq!(actual, scenario());
    let inputs = inputs.lock().unwrap();
    // Seed, field stream, consumed-byte receipt, child finish, parent phase.
    assert_eq!(inputs.len(), 5);
    assert!(inputs[2].starts_with(RECEIPT_DOMAIN));
    let mut history = classical_xof_history::History::default();
    let views = inputs
        .iter()
        .map(|input| history.query(input, shake64(input)).unwrap())
        .collect::<Vec<_>>();
    let seed = shake64(&inputs[0]);
    let finish = shake64(&inputs[3]);
    assert_eq!(
        history.producer(&views[3], &seed),
        Some(inputs[0].as_slice())
    );
    assert!(history.producer(&views[3], &finish).is_none());
    assert_eq!(
        history.producer(&views[4], &finish),
        Some(inputs[3].as_slice())
    );
    let (_, raw) = raw_prime_phase::<F>(&inputs[1], 1);
    let (receipt, producer) = receipt(&raw);
    assert_eq!(producer, inputs[2]);
    let known_at_finish = history.producers(&views[3]).unwrap();
    assert_eq!(
        encoded(&replay_receipt::<F>(&receipt, 1, &known_at_finish).unwrap()),
        encoded(&actual.0)
    );
    // All later answers are now in the registry, but cannot repair an earlier
    // field-query view or the immutable first view of a repeated input.
    assert!(replay_receipt::<F>(&receipt, 1, &history.producers(&views[1]).unwrap()).is_none());
    let repeated = history.query(&inputs[1], shake64(&inputs[1])).unwrap();
    assert!(replay_receipt::<F>(&receipt, 1, &history.producers(&repeated).unwrap()).is_none());
    assert_eq!(history.availability_hits(), 0);
    assert_eq!(history.collisions(), 0);
}

fn typed_child_scenario<F, EF>(profile: &ClassicalProfile) -> (Vec<EF>, [u8; 64])
where
    F: NTTField,
    EF: AbstractExtensionField<F>,
{
    let mut parent = profile.parent_transcript::<F>().unwrap();
    let values = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                parent
                    .with_classical_extension_child::<F, EF, _>(
                        b"history typed child",
                        b"trusted typed parameters",
                        |child| child.get_vec_challenge(b"history extension values", 2),
                    )
                    .unwrap()
            })
            .join()
            .unwrap()
    });
    let mut after = [0; 64];
    parent.get_challenge_bytes(b"after typed child", &mut after);
    (values, after)
}

fn exercise_typed_child<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for version in [4, 5] {
        let spec = Specification {
            backend: Backend::Brakedown,
            roles: std::array::from_fn(|_| Role {
                num_vars: 3,
                width: 8,
                queries: 8,
                left_vars: Some(1),
                block_width: Some(2),
            }),
            blowup: 2,
            fragment_vars: None,
        };
        let profile = if version == 4 {
            ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
        } else {
            ClassicalProfile::new_atomic_columns::<F, EF>(spec)
        }
        .unwrap();
        let inputs = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let observed = Arc::clone(&inputs);
        let guard =
            audit::observe(move |input| observed.lock().unwrap().push(input.to_vec())).unwrap();
        let actual = typed_child_scenario::<F, EF>(&profile);
        drop(guard);
        let reference = typed_child_scenario::<F, EF>(&profile);
        assert_eq!(encoded(&actual.0), encoded(&reference.0));
        assert_eq!(actual.1, reference.1);
        let inputs = inputs.lock().unwrap();
        // Seed, empty identity stream/receipt, field stream/receipt, finish,
        // parent continuation. All are actual production observer inputs.
        assert_eq!(inputs.len(), 7);
        assert_eq!(inputs[2], receipt(&[]).1);
        let mut history = classical_xof_history::History::default();
        let views = inputs
            .iter()
            .map(|input| history.query(input, shake64(input)).unwrap())
            .collect::<Vec<_>>();
        let before = history.producers(&views[3]).unwrap();
        let child = typed_child_prefix::<F, EF>(&profile, &inputs[3], &before).unwrap();
        assert_eq!(child.label, b"history typed child");
        assert_eq!(child.context, b"trusted typed parameters");
        assert_eq!(child.parent_input, inputs[0]);
        let mut phase = Vec::new();
        frame(&mut phase, 1, b"typed request kind", b"vector");
        frame(&mut phase, 1, b"field challenge kind", b"extension vector");
        frame(&mut phase, 1, b"extension basis", &raw_basis::<F, EF>());
        let prime: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
        let mut descriptor = prime.to_le_bytes().to_vec();
        descriptor.extend((2 * EF::D as u64).to_le_bytes());
        frame(&mut phase, 4, b"history extension values", &descriptor);
        assert_eq!(child.rest, phase);
        let (_, raw) = raw_prime_phase::<F>(&inputs[3], 2 * EF::D);
        let (field_receipt, producer) = receipt(&raw);
        assert_eq!(inputs[4], producer);
        let base_values = replay_receipt::<F>(
            &field_receipt,
            2 * EF::D,
            &history.producers(&views[5]).unwrap(),
        )
        .unwrap();
        let expected = actual
            .0
            .iter()
            .flat_map(|value| {
                (0..EF::D).map(move |coordinate| {
                    value
                        .as_base_slice()
                        .get(coordinate)
                        .copied()
                        .unwrap_or_else(F::zero)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(encoded(&base_values), encoded(&expected));
        let seed = shake64(&inputs[0]);
        let (parent_query, parent_view) = history.producer_first_view(&views[3], &seed).unwrap();
        assert_eq!(parent_query, inputs[0]);
        let parent_before = history.producers(&parent_view).unwrap();
        assert_eq!(parent_before, history.producers(&views[0]).unwrap());
        assert!(parent_before.is_empty());
        // The child has already completed its identity receipt, but that
        // producer cannot be imported into its parent's earlier query view.
        assert!(replay_receipt::<F>(&receipt(&[]).0, 0, &parent_before).is_none());
        assert!(replay_receipt::<F>(&receipt(&[]).0, 0, &before).is_some());
        let mut finish_input = raw_child::<F, EF>(&profile, child.label, child.context, &seed);
        finish_input.extend(&phase);
        frame(
            &mut finish_input,
            5,
            b"history extension values",
            &field_receipt,
        );
        frame(
            &mut finish_input,
            2,
            b"classical child finish",
            &64u64.to_le_bytes(),
        );
        assert_eq!(finish_input, inputs[5]);
        let finish = shake64(&inputs[5]);
        assert!(history.producer(&views[5], &finish).is_none());
        assert_eq!(
            history.producer(&views[6], &finish),
            Some(inputs[5].as_slice())
        );
        let mut parent_input = inputs[0].clone();
        frame(&mut parent_input, 3, b"classical child seed", &seed);
        frame(&mut parent_input, 7, b"history typed child", &finish);
        frame(
            &mut parent_input,
            2,
            b"after typed child",
            &64u64.to_le_bytes(),
        );
        assert_eq!(parent_input, inputs[6]);
        let mut missing_seed = before.clone();
        missing_seed.remove(&seed);
        assert!(typed_child_prefix::<F, EF>(&profile, &inputs[3], &missing_seed).is_none());
        // Even genuine earlier XOF answers cannot be substituted for the exact
        // parent fork: label/context and producer namespace must match.
        for (label, context, selected_seed) in [
            (b"wrong child label".as_slice(), child.context, seed),
            (child.label, b"wrong child context".as_slice(), seed),
            (child.label, child.context, shake64(&inputs[2])),
        ] {
            let mut changed = raw_child::<F, EF>(&profile, label, context, &selected_seed);
            changed.extend(&phase);
            assert!(typed_child_prefix::<F, EF>(&profile, &changed, &before).is_none());
        }
        let mut altered_spec = profile.specification().clone();
        altered_spec.roles[0].queries += 1;
        let altered = if version == 4 {
            ClassicalProfile::new_atomic_zerocheck::<F, EF>(altered_spec)
        } else {
            ClassicalProfile::new_atomic_columns::<F, EF>(altered_spec)
        }
        .unwrap();
        assert!(typed_child_prefix::<F, EF>(&altered, &inputs[3], &before).is_none());
        // Reordered adversarial candidates can declare links before their
        // producers. Later genuine answers still cannot repair that first view.
        let mut late = classical_xof_history::History::default();
        let early = late.query(&inputs[3], shake64(&inputs[3])).unwrap();
        late.query(&inputs[0], seed).unwrap();
        late.query(&inputs[2], shake64(&inputs[2])).unwrap();
        let repeated = late.query(&inputs[3], shake64(&inputs[3])).unwrap();
        for view in [&early, &repeated] {
            assert!(
                typed_child_prefix::<F, EF>(&profile, &inputs[3], &late.producers(view).unwrap())
                    .is_none()
            );
        }
        assert!(late.availability_hits() >= 2);
        assert_eq!(history.availability_hits(), 0);
        assert_eq!(history.collisions(), 0);
        println!(
            "HB_XOF_TYPED_CHILD_CONTROL prime={} degree={} version={} inputs=7 prior_producers=true late_repair_rejected=true full_pbs=false",
            F::MODULUS_VALUE,
            EF::D,
            version
        );
    }
}

#[test]
fn actual_typed_child_producer_views_all_extensions() {
    exercise_typed_child::<algebra::BabyBear, algebra::BabyBearExetension>();
    exercise_typed_child::<algebra::BabyBear, algebra::BabyBearExtension5>();
    exercise_typed_child::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_typed_child::<algebra::BabyBear, algebra::BabyBearExtension8>();
    exercise_typed_child::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    exercise_typed_child::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    exercise_typed_child::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
    exercise_typed_child::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

fn detached_child_scenario<F, EF>(profile: &ClassicalProfile) -> (Vec<EF>, [u8; 64])
where
    F: NTTField,
    EF: AbstractExtensionField<F>,
{
    let mut parent = profile.parent_transcript::<F>().unwrap();
    let values = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut child = parent
                    .fork_classical_extension::<F, EF>(
                        b"history typed child",
                        b"trusted typed parameters",
                    )
                    .unwrap();
                let values = child.get_vec_challenge(b"history extension values", 2);
                parent.finish_classical_child(&mut child).unwrap();
                assert!(parent.finish_classical_child(&mut child).is_err());
                values
            })
            .join()
            .unwrap()
    });
    let mut after = [0; 64];
    parent.get_challenge_bytes(b"after typed child", &mut after);
    (values, after)
}

fn exercise_detached_child<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for version in [4, 5] {
        let spec = Specification {
            backend: Backend::Brakedown,
            roles: std::array::from_fn(|_| Role {
                num_vars: 3,
                width: 8,
                queries: 8,
                left_vars: Some(1),
                block_width: Some(2),
            }),
            blowup: 2,
            fragment_vars: None,
        };
        let profile = if version == 4 {
            ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
        } else {
            ClassicalProfile::new_atomic_columns::<F, EF>(spec)
        }
        .unwrap();
        let inputs = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let observed = Arc::clone(&inputs);
        let guard =
            audit::observe(move |input| observed.lock().unwrap().push(input.to_vec())).unwrap();
        let actual = detached_child_scenario::<F, EF>(&profile);
        drop(guard);
        let reference = typed_child_scenario::<F, EF>(&profile);
        assert_eq!(encoded(&actual.0), encoded(&reference.0));
        assert_eq!(actual.1, reference.1);
        let unobserved = detached_child_scenario::<F, EF>(&profile);
        assert_eq!(encoded(&actual.0), encoded(&unobserved.0));
        assert_eq!(actual.1, unobserved.1);
        let inputs = inputs.lock().unwrap();
        // Seed, parent checkpoint, identity stream/receipt, field stream/receipt,
        // repeated parent checkpoint, child finish, parent continuation.
        assert_eq!(inputs.len(), 9);
        assert_eq!(inputs[1], inputs[6]);
        assert_eq!(inputs[3], receipt(&[]).1);
        let mut history = classical_xof_history::History::default();
        let views = inputs
            .iter()
            .map(|input| history.query(input, shake64(input)).unwrap())
            .collect::<Vec<_>>();
        let before = history.producers(&views[4]).unwrap();
        let child = typed_child_prefix::<F, EF>(&profile, &inputs[4], &before).unwrap();
        assert_eq!(child.label, b"history typed child");
        assert_eq!(child.context, b"trusted typed parameters");
        assert_eq!(child.parent_input, inputs[0]);
        let seed = shake64(&inputs[0]);
        let checkpoint = shake64(&inputs[1]);
        let mut checkpoint_input = inputs[0].clone();
        frame(&mut checkpoint_input, 3, b"classical child seed", &seed);
        frame(&mut checkpoint_input, 8, b"parent checkpoint", &[]);
        assert_eq!(checkpoint_input, inputs[1]);
        let (_, checkpoint_view) = history.producer_first_view(&views[7], &checkpoint).unwrap();
        let checkpoint_before = history.producers(&checkpoint_view).unwrap();
        assert_eq!(checkpoint_before, history.producers(&views[1]).unwrap());
        assert_eq!(checkpoint_before, history.producers(&views[6]).unwrap());
        assert!(replay_receipt::<F>(&receipt(&[]).0, 0, &checkpoint_before).is_none());
        assert!(replay_receipt::<F>(&receipt(&[]).0, 0, &before).is_some());
        let (_, raw) = raw_prime_phase::<F>(&inputs[4], 2 * EF::D);
        let (field_receipt, receipt_input) = receipt(&raw);
        assert_eq!(receipt_input, inputs[5]);
        let finish_before = history.producers(&views[7]).unwrap();
        let values = replay_receipt::<F>(&field_receipt, 2 * EF::D, &finish_before).unwrap();
        let expected = actual
            .0
            .iter()
            .flat_map(|value| {
                (0..EF::D).map(move |coordinate| {
                    value
                        .as_base_slice()
                        .get(coordinate)
                        .copied()
                        .unwrap_or_else(F::zero)
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(encoded(&values), encoded(&expected));
        assert!(replay_receipt::<F>(&field_receipt, 2 * EF::D, &checkpoint_before).is_none());
        let finish = shake64(&inputs[7]);
        assert!(history.producer(&views[7], &finish).is_none());
        assert_eq!(
            history.producer(&views[8], &finish),
            Some(inputs[7].as_slice())
        );
        let mut parent_input = inputs[0].clone();
        frame(&mut parent_input, 3, b"classical child seed", &seed);
        frame(&mut parent_input, 7, b"history typed child", &finish);
        frame(
            &mut parent_input,
            2,
            b"after typed child",
            &64u64.to_le_bytes(),
        );
        assert_eq!(parent_input, inputs[8]);
        assert_eq!(history.availability_hits(), 0);
        assert_eq!(history.collisions(), 0);
        println!(
            "HB_XOF_DETACHED_CHILD_CONTROL prime={} degree={} version={} inputs=9 checkpoint_first_view=true scoped_outputs_equal=true full_pbs=false",
            F::MODULUS_VALUE,
            EF::D,
            version
        );
    }
}

#[test]
fn actual_detached_child_producer_views_all_extensions() {
    exercise_detached_child::<algebra::BabyBear, algebra::BabyBearExetension>();
    exercise_detached_child::<algebra::BabyBear, algebra::BabyBearExtension5>();
    exercise_detached_child::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_detached_child::<algebra::BabyBear, algebra::BabyBearExtension8>();
    exercise_detached_child::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    exercise_detached_child::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    exercise_detached_child::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
    exercise_detached_child::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}
