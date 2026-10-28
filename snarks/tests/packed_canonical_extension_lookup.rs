use algebra::{AbstractExtensionField, NTTField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    masked_polyfrim::{Parameters, Proof as MaskedProof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_extension_lookup::canonical::{self, Proof},
    packed_oracle::CanonicalProverOracle,
    packed_tuple_lookup::Config,
};
fn exercise<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (vars, partial, repetitions) in [(0, false, 1), (2, false, 2), (2, true, 2)] {
        let size = (1usize << vars) * width;
        let active = if partial { size - 3 } else { size };
        let config = Config::new(
            active,
            (0usize..3)
                .map(|i| vec![F::from(i), F::from(i + 1)])
                .collect(),
            repetitions,
        )
        .unwrap();
        let tables: Vec<_> = (0..2)
            .map(|column| {
                PackedTable::new(
                    vars,
                    width,
                    (0..size)
                        .map(|i| {
                            F::from(if i < active {
                                i % 3 + column
                            } else {
                                99 + column
                            })
                        })
                        .collect(),
                )
                .unwrap()
            })
            .collect();
        let pp: Vec<_> = (0..2)
            .map(|i| Parameters::<F, EF>::new(vars, width, 11 + i, 2, 1, repetitions).unwrap())
            .collect();
        let helper =
            Parameters::<F, EF>::new(vars + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
        let (roots, states): (Vec<_>, Vec<_>) = tables
            .iter()
            .enumerate()
            .map(|(i, t)| {
                CanonicalPcs::<F, Sha256>::commit(
                    &pp[i],
                    t,
                    &mut StdRng::seed_from_u64(437 + i as u64),
                )
                .unwrap()
            })
            .unzip();
        let sources: Vec<_> = (0..2)
            .map(|i| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &pp[i],
                commitment: &roots[i],
                state: &states[i],
            })
            .collect();
        let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
        let mut prover = Transcript::new_direct();
        let proof = canonical::prove::<F, EF, Sha256, _, _>(
            &mut prover,
            &config,
            &helper,
            &sources.iter().collect::<Vec<_>>(),
            &mut StdRng::seed_from_u64(438),
        )
        .unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct();
        canonical::verify::<F, EF, Sha256, _>(&mut verifier, &config, &helper, &public, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == repetitions));
        for g in &proof.groups {
            assert_eq!(
                g.reciprocal_opening
                    .openings
                    .iter()
                    .map(|p| p.index)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );
        }
        let mut bad = proof.clone();
        bad.groups[0].source_values[0][0] += F::one();
        assert!(
            canonical::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &config,
                &helper,
                &public,
                &bad
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad.source_openings.pop();
        assert!(
            canonical::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &config,
                &helper,
                &public,
                &bad
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad.groups[0].reciprocal_opening.openings.pop();
        assert!(
            canonical::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &config,
                &helper,
                &public,
                &bad
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad.reciprocal_commitments[0].root[0] ^= 1;
        assert!(
            canonical::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &config,
                &helper,
                &public,
                &bad
            )
            .is_err()
        );
        let changed = Config::new(
            active,
            (0usize..3)
                .map(|i| vec![F::from(i), F::from(i + 2)])
                .collect(),
            repetitions,
        )
        .unwrap();
        assert!(
            canonical::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &changed,
                &helper,
                &public,
                &proof
            )
            .is_err()
        );
        assert!(
            canonical::prove::<F, EF, Sha256, _, _>(
                &mut Transcript::new_direct(),
                &config,
                &helper,
                &sources.iter().collect::<Vec<_>>(),
                &mut StdRng::seed_from_u64(439)
            )
            .is_err()
        );
        assert!(states.iter().all(|s| s.spent().unwrap() == repetitions));
        println!(
            "HB_CANONICAL_MASKED_EXTENSION_LOOKUP {{\"prime\":{},\"extension_degree\":{},\"source_variables\":{},\"width\":{},\"active\":{},\"repetitions\":{},\"child_openings\":{},\"native_pbs\":false,\"whole_security_certified\":false}}",
            F::MODULUS_VALUE,
            EF::D,
            vars,
            width,
            active,
            repetitions,
            4 * repetitions
        );
    }
}
#[test]
fn babybear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
#[test]
fn brakedown() {
    use algebra::{BabyBear as F, BabyBearExtension6 as E};
    use pcs::matrix_weighted::{BatchOpening, Parameters as BaseParameters};
    let pp = BaseParameters::balanced_block_rs(2, 8, 8, 2).unwrap();
    let helper = BaseParameters::balanced_block_rs(5, 8, 8, 2).unwrap();
    let table = PackedTable::new(2, 8, (0usize..32).map(|i| F::from(i % 2)).collect()).unwrap();
    let (root, state) = pp.commit::<F, Sha256>(&table).unwrap();
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &state,
    };
    let config = Config::new(29, vec![vec![F::from(0usize)], vec![F::from(1usize)]], 2).unwrap();
    let mut prover = Transcript::new_direct();
    let proof = canonical::prove::<F, E, Sha256, _, _>(
        &mut prover,
        &config,
        &helper,
        &[&source],
        &mut StdRng::seed_from_u64(7),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, E, [u8; 32], BatchOpening<F, [u8; 32]>>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    canonical::verify::<F, E, Sha256, _>(
        &mut verifier,
        &config,
        &helper,
        &[source.verifier()],
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
}

#[test]
fn goldilocks_public_table_aliases_and_response_codec() {
    use algebra::{Field, Goldilocks as F, GoldilocksExtension3 as E};
    let pp = Parameters::<F, E>::new(2, 4, 11, 2, 1, 1).unwrap();
    let helper = Parameters::<F, E>::new(4, 4, 12, 2, 1, 2).unwrap();
    let table = PackedTable::new(2, 4, vec![F::new(0); 16]).unwrap();
    let (root, state) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &table, &mut StdRng::seed_from_u64(432)).unwrap();
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &state,
    };
    let config = Config::new(15, vec![vec![F::new(0)], vec![F::new(2)]], 1).unwrap();
    let mut prover = Transcript::new_direct();
    let proof = canonical::prove::<F, E, Sha256, _, _>(
        &mut prover,
        &config,
        &helper,
        &[&source],
        &mut StdRng::seed_from_u64(433),
    )
    .unwrap();
    let alias = Config::new(15, vec![vec![F::new(F::MODULUS_VALUE)], vec![F::new(2)]], 1).unwrap();
    let mut verifier = Transcript::new_direct();
    canonical::verify::<F, E, Sha256, _>(
        &mut verifier,
        &alias,
        &helper,
        &[source.verifier()],
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    let mut bad = proof.clone();
    bad.multiplicities[0] = F::new(F::MODULUS_VALUE + 15);
    let err = canonical::verify::<F, E, Sha256, _>(
        &mut Transcript::new_direct(),
        &config,
        &helper,
        &[source.verifier()],
        &bad,
    )
    .unwrap_err();
    assert!(
        err.0.contains("noncanonical public packed response"),
        "{err}"
    );
    let mut bad = proof;
    bad.groups[0].source_values[0][0] = F::new(F::MODULUS_VALUE);
    let err = canonical::verify::<F, E, Sha256, _>(
        &mut Transcript::new_direct(),
        &config,
        &helper,
        &[source.verifier()],
        &bad,
    )
    .unwrap_err();
    assert!(
        err.0.contains("noncanonical public packed response"),
        "{err}"
    );
}
