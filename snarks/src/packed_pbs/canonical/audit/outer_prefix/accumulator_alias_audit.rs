//! Seven logical source slots may share one immutable context/root assignment.
use super::*;

fn exercise<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
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
    })
    .unwrap();
    let bundle = profile.brakedown_parameters::<F, EF>().unwrap();
    let pp = super::super::super::classical::parameters(&bundle);
    let aliases = [0, 1, 2, 3, 4, 2, 2];
    let sources = aliases
        .iter()
        .enumerate()
        .map(|(slot, &identity)| {
            (
                <_ as CanonicalPcs<F, Sha512>>::context(accumulator_parameters(&pp, slot).unwrap())
                    .ok()
                    .unwrap(),
                Commitment {
                    root: Digest512([identity + 11; 64]),
                },
            )
        })
        .collect::<Vec<_>>();
    let shape = crate::packed_accumulator::Shape::new(8, 3).unwrap();
    let initial = vec![F::zero(); 16];
    let final_acc = vec![F::from(3usize); 16];
    let public = sources
        .iter()
        .enumerate()
        .map(|(slot, (_, commitment))| CanonicalVerifierOracle {
            parameters: accumulator_parameters(&pp, slot).unwrap(),
            commitment,
        })
        .collect::<Vec<_>>();
    let mut transcript = profile.parent_transcript::<F>().unwrap();
    let (base, _) = crate::packed_accumulator::audit::binding_queries::<F, Sha512, _>(
        &mut transcript,
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
    exercise_accumulator_assigned_words(&pp, &task);
    let mut words = vec![vec![F::zero(); 64]; 7];
    for half in 0..2 {
        for row in 0..3 {
            for lane in 0..8 {
                let at = (half * 4 + row) * 8 + lane;
                words[0][at] = F::from(row);
                words[1][at] = F::from(row);
                words[3][at] = F::from(row + 1);
                words[4][at] = F::one();
            }
        }
    }
    let tables = words
        .into_iter()
        .map(|values| PackedTable::new(3, 8, values).unwrap())
        .collect::<Vec<_>>();
    let mut seen = std::collections::HashSet::new();
    let values = accumulator_assigned_values(&pp, &task, |source| {
        assert!(
            seen.insert(encoded(source)),
            "a repeated source cannot request a replacement assignment"
        );
        task.sources
            .iter()
            .position(|s| encoded(s) == encoded(source))
            .map(|slot| tables[slot].clone())
    })
    .unwrap();
    assert_eq!(seen.len(), 5);
    assert_eq!(values.len(), 7);
    assert!(accumulator_values_valid(&pp, &task, &values));
    println!(
        "HB_ACCUMULATOR_ASSIGNED_ALIAS prime={} degree={} logical_sources=7 unique_assignments=5 source_authentication=false",
        F::MODULUS_VALUE,
        EF::D
    );
}

#[test]
fn accumulator_assigned_aliases_are_immutable() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

// Actual prefix roots can alias slots whose arbitrary synthetic words differ.
// The standalone arithmetic control must build and bind its own assignments.
fn exercise_prefix_alias_geometry<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
        backend: Backend::Brakedown,
        roles: std::array::from_fn(|_| Role {
            num_vars: 8,
            width: 8,
            queries: 8,
            left_vars: Some(4),
            block_width: Some(2),
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    let bundle = profile.brakedown_parameters::<F, EF>().unwrap();
    let pp = super::super::super::classical::parameters(&bundle);
    let aliases = [0, 1, 1, 3, 4, 2, 2];
    let sources = aliases
        .iter()
        .enumerate()
        .map(|(slot, &identity)| {
            (
                <_ as CanonicalPcs<F, Sha512>>::context(accumulator_parameters(&pp, slot).unwrap())
                    .unwrap(),
                Commitment {
                    root: Digest512([identity + 31; 64]),
                },
            )
        })
        .collect();
    let task = AccumulatorTask {
        shape: crate::packed_accumulator::Shape::new(32, 21).unwrap(),
        initial: vec![F::from(7usize); 64],
        final_acc: vec![F::from(11usize); 64],
        sources,
        base: Vec::new(),
    };
    exercise_accumulator_assigned_geometry(&profile, &pp, &task);
}

#[test]
fn accumulator_prefix_aliases_use_independent_arithmetic_assignments() {
    exercise_prefix_alias_geometry::<algebra::BabyBear, algebra::BabyBearExtension6>();
    exercise_prefix_alias_geometry::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
