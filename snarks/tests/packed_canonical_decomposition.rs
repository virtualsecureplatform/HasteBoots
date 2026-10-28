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
    packed_decomposition::{
        Config,
        canonical::{self, Proof},
    },
    packed_oracle::CanonicalProverOracle,
};
fn fixture<F: NTTField>(width: usize) -> (Config, Vec<PackedTable<F>>) {
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let size = 2 * width;
    let active = size - 1;
    let config = Config::new::<F>(8, active, 1).unwrap();
    let values: Vec<_> = (0..active)
        .map(|i| [0, 1, p - 1, p - 2, 12345, p / 2][i % 6])
        .chain(std::iter::once(0))
        .collect();
    let mut tables = vec![
        PackedTable::new(
            1,
            width,
            values.iter().map(|&v| F::from(v as usize)).collect(),
        )
        .unwrap(),
    ];
    for limb in 0..config.num_digits::<F>().unwrap() {
        tables.push(
            PackedTable::new(
                1,
                width,
                values
                    .iter()
                    .map(|&v| F::from(((v >> (8 * limb)) & 255) as usize))
                    .collect(),
            )
            .unwrap(),
        );
    }
    (config, tables)
}
fn exercise<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (config, tables) = fixture::<F>(width);
    let d = config.num_digits::<F>().unwrap();
    let pp: Vec<_> = (0..=d)
        .map(|i| Parameters::<F, EF>::new(1, width, 11, 2, 1, if i == 0 { 1 } else { 2 }).unwrap())
        .collect();
    let borrow = Parameters::<F, EF>::new(1, width, 12, 2, 1, 3).unwrap();
    let helper = Parameters::<F, EF>::new(1 + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(&pp[i], t, &mut StdRng::seed_from_u64(382 + i as u64))
                .unwrap()
        })
        .unzip();
    let sources: Vec<_> = (0..=d)
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp[i],
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let public: Vec<_> = sources[1..].iter().map(|s| s.verifier()).collect();
    let mut prover = Transcript::new_direct();
    let proof = canonical::prove::<F, EF, Sha256, _, _>(
        &mut prover,
        &config,
        &sources[0],
        &borrow,
        &helper,
        &sources[1..].iter().collect::<Vec<_>>(),
        &mut StdRng::seed_from_u64(386),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    canonical::verify::<F, EF, Sha256, _>(
        &mut verifier,
        &config,
        &sources[0].verifier(),
        &borrow,
        &helper,
        &public,
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    assert_eq!(states[0].spent().unwrap(), 1);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 2));
    for (i, c) in proof.comparisons.iter().enumerate() {
        assert_eq!(c.source_openings[0].openings[0].index, 1);
        assert_eq!(
            c.source_openings[1].openings[0].index,
            if i == 0 { 1 } else { 2 }
        );
        assert_eq!(c.source_openings[2].openings[0].index, 1);
        assert_eq!(
            c.groups[0]
                .reciprocal_opening
                .openings
                .iter()
                .map(|p| p.index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
    let mut bad = proof.clone();
    bad.borrow_commitments.pop();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0].verifier(),
            &borrow,
            &helper,
            &public,
            &bad
        )
        .is_err()
    );
    let mut bad = proof.clone();
    bad.comparisons.pop();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0].verifier(),
            &borrow,
            &helper,
            &public,
            &bad
        )
        .is_err()
    );
    let mut bad = proof.clone();
    bad.linear.values[0][0] += F::one();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0].verifier(),
            &borrow,
            &helper,
            &public,
            &bad
        )
        .is_err()
    );
    let mut bad = proof.clone();
    bad.comparisons[0].groups[0].source_values[0][0] += F::one();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0].verifier(),
            &borrow,
            &helper,
            &public,
            &bad
        )
        .is_err()
    );
    let wrong = Parameters::<F, EF>::new(1, width, 13, 2, 1, 3).unwrap();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0].verifier(),
            &wrong,
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
            &sources[0],
            &borrow,
            &helper,
            &sources[1..].iter().collect::<Vec<_>>(),
            &mut StdRng::seed_from_u64(387)
        )
        .is_err()
    );
    assert_eq!(states[0].spent().unwrap(), 1);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 2));
    println!(
        "HB_MASKED_CANONICAL_DECOMPOSITION {{\"prime\":{},\"width\":{},\"digits\":{},\"active\":{},\"child_openings\":{},\"native_pbs\":false,\"whole_security_certified\":false}}",
        F::MODULUS_VALUE,
        width,
        d,
        config.logical_len(),
        7 * d + 2
    );
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
    use pcs::matrix_weighted::{BatchOpening, Opening, Parameters as BaseParameters};
    let (config, tables) = fixture::<F>(8);
    let pp = BaseParameters::balanced_block_rs(1, 8, 8, 2).unwrap();
    let helper = BaseParameters::balanced_block_rs(4, 8, 8, 2).unwrap();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let sources: Vec<_> = (0..tables.len())
        .map(|i| CanonicalProverOracle::<F, Sha256, _> {
            parameters: &pp,
            commitment: &roots[i],
            state: &states[i],
        })
        .collect();
    let mut prover = Transcript::new_direct();
    let proof = canonical::prove::<F, E, Sha256, _, _>(
        &mut prover,
        &config,
        &sources[0],
        &pp,
        &helper,
        &sources[1..].iter().collect::<Vec<_>>(),
        &mut StdRng::seed_from_u64(9),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, E, [u8; 32], Opening<F, [u8; 32]>, BatchOpening<F, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    canonical::verify::<F, E, Sha256, _>(
        &mut verifier,
        &config,
        &sources[0].verifier(),
        &pp,
        &helper,
        &sources[1..]
            .iter()
            .map(|s| s.verifier())
            .collect::<Vec<_>>(),
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
}
