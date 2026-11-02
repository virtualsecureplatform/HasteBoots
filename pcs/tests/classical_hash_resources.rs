//! Count actual verifier hash outputs, including adapter/binding metadata.
use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::Transcript;
use pcs::{
    matrix_weighted::{self, backend::CanonicalPcs},
    utils::{
        code::{BlockReedSolomonCode, RowCode},
        hash::{Digest512, Hash},
    },
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::atomic::{AtomicUsize, Ordering};

static MAX_UPDATES: AtomicUsize = AtomicUsize::new(0);
static OUTPUTS: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Debug, Default)]
struct Counted {
    hash: sha2::Sha512,
    updates: usize,
}
impl Hash for Counted {
    type Output = Digest512;
    fn update_hash_value(&mut self, input: &[u8]) {
        self.updates += 1;
        Hash::update_hash_value(&mut self.hash, input);
    }
    fn output_reset(&mut self) -> Self::Output {
        assert!(
            self.updates <= 2,
            "native SHA input exceeded two-slice envelope"
        );
        MAX_UPDATES.fetch_max(self.updates, Ordering::Relaxed);
        self.updates = 0;
        OUTPUTS.fetch_add(1, Ordering::Relaxed);
        Hash::output_reset(&mut self.hash)
    }
}

fn verify_count<F, P>(pp: &P, count: usize, expected: usize, exact: bool)
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Counted>,
    P::Error: std::fmt::Debug,
{
    let vars = pp.num_vars();
    let width = pp.width();
    let table = PackedTable::new(
        vars,
        width,
        (0..width << vars).map(|i| F::from(i * i + 7)).collect(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(811);
    let (root, state) = pp.commit(&table, &mut rng).unwrap();
    let queries: Vec<Vec<_>> = (0..count)
        .map(|member| {
            (0..vars)
                .map(|bit| MatrixPair {
                    zero: Matrix::identity(width).unwrap(),
                    one: Matrix::new(
                        width,
                        (0..width * width)
                            .map(|i| F::from(i + bit + member + 1))
                            .collect(),
                    )
                    .unwrap(),
                })
                .collect()
        })
        .collect();
    let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
    let mut prover = Transcript::<F>::new_classical_atomic_zerocheck(&[91; 64]);
    let proof = pp
        .open_many(&mut prover, &root, &state, &queries, &values)
        .unwrap();
    OUTPUTS.store(0, Ordering::Relaxed);
    MAX_UPDATES.store(0, Ordering::Relaxed);
    pp.verify_many(
        &mut Transcript::<F>::new_classical_atomic_zerocheck(&[91; 64]),
        &root,
        &queries,
        &values,
        &proof,
    )
    .unwrap();
    let actual = OUTPUTS.load(Ordering::Relaxed);
    assert!(MAX_UPDATES.load(Ordering::Relaxed) <= 2);
    if exact {
        assert_eq!(actual, expected);
    } else {
        assert!(actual <= expected, "{actual} > {expected}");
    }
}

fn check<F, E>()
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let vars = 3;
    let width = 8;
    let queries = 7;
    for blowup in [2usize, 4, 8] {
        for count in [1usize, 2, 4] {
            let paths: Vec<_> = (0..vars)
                .map(|i| vars + blowup.ilog2() as usize - i)
                .collect();
            let direct_auth = 2 * queries * count * paths.iter().sum::<usize>()
                + queries * paths[1..].iter().sum::<usize>();
            let direct =
                matrix_weighted::polyfrim::Parameters::<F, E>::new(vars, width, blowup, queries)
                    .unwrap();
            verify_count::<F, _>(&direct, count, direct_auth + vars + 2, true);
            let compact = matrix_weighted::polyfrim::compact::Parameters::<F, E>::new(
                vars, width, blowup, queries,
            )
            .unwrap();
            verify_count::<F, _>(&compact, count, direct_auth + vars + 3, true);
            let rounds = 2;
            let fragment_paths: Vec<_> = (0..rounds)
                .map(|i| rounds + blowup.ilog2() as usize - i)
                .collect();
            let all = fragment_paths.iter().sum::<usize>();
            let derived = fragment_paths[1..].iter().sum::<usize>();
            let source = queries * fragment_paths[0];
            let ordinary_auth =
                queries * (all + derived) + source + queries * all + 2 * queries + queries * rounds;
            let ordinary = matrix_weighted::fragmented_pipfri::Parameters::<F, E>::new(
                vars, width, blowup, queries, rounds,
            )
            .unwrap();
            verify_count::<F, _>(&ordinary, count, ordinary_auth + 4, true);
            let virtual_auth = 2 * queries * derived + source + 2 * queries;
            let virtual_pp =
                matrix_weighted::fragmented_pipfri::virtual_source::Parameters::<F, E>::new(
                    vars, width, blowup, queries, rounds,
                )
                .unwrap();
            verify_count::<F, _>(&virtual_pp, count, virtual_auth + 7, true);
            let code = BlockReedSolomonCode::<F>::new(4, width, blowup).unwrap();
            let blocks = code.codeword_blocks();
            let bound = queries.min(blocks) * (blocks.ilog2() as usize + 1) + 1;
            let brakedown =
                matrix_weighted::Parameters::new_encoded::<F>(vars, width, 1, queries, code)
                    .unwrap();
            verify_count::<F, _>(&brakedown, count, bound, false);
        }
    }
}

fn assert_rejected_resources<E>(
    atomic: bool,
    draws: usize,
    field_values: usize,
    field_bytes: usize,
    malformed: bool,
    verify: impl FnOnce() -> Result<(), E>,
) {
    #[cfg(feature = "transcript-audit")]
    {
        use helper::classical_transcript::audit::{self, ResourceEvent};
        use std::sync::{Arc, Mutex};
        #[derive(Default)]
        struct Counts {
            queries: usize,
            output_bytes: u128,
            field_phases: usize,
            field_values: u128,
            field_candidates: u128,
            field_bytes: u128,
            column_phases: usize,
            column_values: u128,
            column_candidates: u128,
        }
        let counts = Arc::new(Mutex::new(Counts::default()));
        let inputs = Arc::clone(&counts);
        let resources = Arc::clone(&counts);
        let guard = audit::observe_with_resources(
            move |_| inputs.lock().unwrap().queries += 1,
            move |event| {
                let mut counts = resources.lock().unwrap();
                match event {
                    ResourceEvent::XofOutput { bytes, .. } => counts.output_bytes += bytes,
                    ResourceEvent::FieldSampling {
                        values,
                        candidates,
                        consumed_bytes,
                        ..
                    } => {
                        counts.field_phases += 1;
                        counts.field_values += values;
                        counts.field_candidates += candidates;
                        counts.field_bytes += consumed_bytes;
                    }
                    ResourceEvent::ColumnSampling {
                        values, candidates, ..
                    } => {
                        counts.column_phases += 1;
                        counts.column_values += values;
                        counts.column_candidates += candidates;
                    }
                    ResourceEvent::LookupReciprocalRejected => {
                        panic!("Brakedown has no lookup retry")
                    }
                }
            },
        )
        .unwrap();
        assert!(verify().is_err());
        drop(guard);
        let counts = counts.lock().unwrap();
        if malformed {
            assert_eq!(counts.queries, 0);
            assert_eq!(counts.output_bytes, 0);
            assert_eq!(counts.field_phases + counts.column_phases, 0);
        } else {
            assert_eq!(counts.field_phases, 1);
            assert_eq!(counts.field_values, field_values as u128);
            assert_eq!(
                counts.field_bytes,
                counts.field_candidates * field_bytes as u128
            );
            if atomic {
                assert_eq!(counts.column_phases, 0);
                assert_eq!(counts.queries, 3); // field, receipt, fixed byte block
                assert_eq!(
                    counts.output_bytes,
                    counts.field_bytes + 64 + 8 * draws as u128
                );
            } else {
                assert_eq!(counts.column_phases, 1);
                assert_eq!(counts.column_values, draws as u128);
                assert!(counts.column_candidates >= draws as u128);
                assert_eq!(counts.queries as u128, 2 + counts.column_candidates);
                assert_eq!(
                    counts.output_bytes,
                    counts.field_bytes + 64 + 8 * counts.column_candidates
                );
            }
        }
    }
    #[cfg(not(feature = "transcript-audit"))]
    {
        let _ = (atomic, draws, field_values, field_bytes, malformed);
        assert!(verify().is_err());
    }
}

fn rejected_brakedown_hashes<F: NTTField + Serialize>() {
    let vars = 4;
    let width = 4;
    let left = 2;
    let table = PackedTable::new(
        vars,
        width,
        (0..width << vars).map(|i| F::from(i * i + 3)).collect(),
    )
    .unwrap();
    let query: Vec<_> = (0..vars)
        .map(|_| MatrixPair {
            zero: Matrix::identity(width).unwrap(),
            one: Matrix::identity(width).unwrap(),
        })
        .collect();
    let value = table.evaluate(&query).unwrap();
    for atomic in [false, true] {
        let transcript = || {
            if atomic {
                Transcript::<F>::new_classical_atomic_columns(&[93; 64])
            } else {
                Transcript::<F>::new_classical_atomic_zerocheck(&[93; 64])
            }
        };
        for draws in [1usize, 8, 40] {
            let code = BlockReedSolomonCode::<F>::new(1 << (vars - left), width, 2).unwrap();
            let blocks = code.codeword_blocks();
            let cap = 1 + draws.min(blocks) * (blocks.ilog2() as usize + 1);
            let pp = matrix_weighted::Parameters::new_encoded::<F>(vars, width, left, draws, code)
                .unwrap();
            let (root, state) = pp.commit::<F, Counted>(&table).unwrap();
            let single = pp
                .open::<F, Counted>(&mut transcript(), &root, &state, &query, &value)
                .unwrap();
            let queries = vec![query.clone(), query.clone()];
            let values = vec![value.clone(), value.clone()];
            let batch = pp
                .open_many::<F, Counted>(&mut transcript(), &root, &state, &queries, &values)
                .unwrap();
            // Early shape rejections occur before the single binding hash,
            // but after the batch binding hash. No adversarial vector length
            // can reach the authentication loop through these guards.
            for change in 0..8 {
                let mut s = single.clone();
                let mut b = batch.clone();
                match change {
                    0 => {
                        s.test.clear();
                        b.test.clear();
                    }
                    1 => {
                        s.evaluation.clear();
                        b.evaluations.clear();
                    }
                    2 => {
                        s.columns.clear();
                        b.columns.clear();
                    }
                    3 => {
                        s.columns
                            .resize(draws.min(blocks) + 1, s.columns[0].clone());
                        b.columns
                            .resize(draws.min(blocks) + 1, b.columns[0].clone());
                    }
                    4 => {
                        s.columns[0].values.pop();
                        b.columns[0].values.pop();
                    }
                    5 => {
                        s.columns[0].path.pop();
                        b.columns[0].path.pop();
                    }
                    6 => {
                        s.columns[0].path.push(Digest512::default());
                        b.columns[0].path.push(Digest512::default());
                    }
                    _ => {
                        s.test.push(F::from(0));
                        b.evaluations[0].push(F::from(0));
                    }
                }
                OUTPUTS.store(0, Ordering::Relaxed);
                assert_rejected_resources(
                    atomic,
                    draws,
                    width * width * (1 << left),
                    std::mem::size_of::<F>(),
                    true,
                    || pp.verify::<F, Counted>(&mut transcript(), &root, &query, &value, &s),
                );
                assert_eq!(OUTPUTS.load(Ordering::Relaxed), 0);
                OUTPUTS.store(0, Ordering::Relaxed);
                assert_rejected_resources(
                    atomic,
                    draws,
                    width * width * (1 << left),
                    std::mem::size_of::<F>(),
                    true,
                    || {
                        pp.verify_many::<F, Counted>(
                            &mut transcript(),
                            &root,
                            &queries,
                            &values,
                            &b,
                        )
                    },
                );
                assert_eq!(OUTPUTS.load(Ordering::Relaxed), 1);
            }
            // Well-shaped failures can run joined Rayon workers, so check
            // the all-columns bound rather than assuming early cancellation.
            for change in 0..3 {
                let mut s = single.clone();
                let mut b = batch.clone();
                match change {
                    0 => {
                        s.columns[0].values[0] += F::from(1);
                        b.columns[0].values[0] += F::from(1);
                    }
                    1 => {
                        s.columns[0].path[0].0[0] ^= 1;
                        b.columns[0].path[0].0[0] ^= 1;
                    }
                    _ => {
                        s.columns[0].path.last_mut().unwrap().0[0] ^= 1;
                        b.columns[0].path.last_mut().unwrap().0[0] ^= 1;
                    }
                }
                OUTPUTS.store(0, Ordering::Relaxed);
                assert_rejected_resources(
                    atomic,
                    draws,
                    width * width * (1 << left),
                    std::mem::size_of::<F>(),
                    false,
                    || pp.verify::<F, Counted>(&mut transcript(), &root, &query, &value, &s),
                );
                assert!(OUTPUTS.load(Ordering::Relaxed) <= cap);
                OUTPUTS.store(0, Ordering::Relaxed);
                assert_rejected_resources(
                    atomic,
                    draws,
                    width * width * (1 << left),
                    std::mem::size_of::<F>(),
                    false,
                    || {
                        pp.verify_many::<F, Counted>(
                            &mut transcript(),
                            &root,
                            &queries,
                            &values,
                            &b,
                        )
                    },
                );
                assert!(OUTPUTS.load(Ordering::Relaxed) <= cap);
            }
        }
    }
}

#[test]
fn adapter_hash_counts_include_metadata_for_all_five_backends() {
    // One test owns the global counter, including joined Rayon workers.
    check::<algebra::BabyBear, algebra::BabyBearExtension6>();
    check::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    rejected_brakedown_hashes::<algebra::BabyBear>();
    rejected_brakedown_hashes::<algebra::Goldilocks>();
}
