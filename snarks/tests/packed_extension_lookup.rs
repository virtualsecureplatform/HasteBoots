use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, NTTField, matrix_weighted::PackedTable,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_extension as bridge,
    packed_extension_lookup::{self as lookup, Proof},
    packed_oracle::ProverOracle,
    packed_tuple_lookup::Config,
};
fn mappings<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let mut fixture = Transcript::<EF>::new_direct_extension::<F>();
    for k in [8usize, 16] {
        for mu in 0..=3 {
            let data: Vec<_> = (0..(1 << mu) * k).map(|i| F::from(i * i + 3)).collect();
            let table = PackedTable::new(mu, k, data.clone()).unwrap();
            let n = mu + k.ilog2() as usize;
            let point = fixture.get_vec_challenge(b"source scalar point", n);
            let q = bridge::scalar_query::<F, EF>(mu, k, &point).unwrap();
            let value = table.evaluate(&q.query).unwrap();
            let projected = q.apply(&value, k).unwrap();
            let expected =
                DenseMultilinearExtension::from_evaluations_vec(n, data).evaluate_ext::<EF>(&point);
            assert_eq!(bridge::element::<F, EF>(k, &projected).unwrap(), expected);
            assert_eq!(projected, bridge::vector::<F, EF>(k, expected).unwrap());
        }
        for n in 0..=4 {
            let values = fixture.get_vec_challenge(b"extension helper values", 1 << n);
            let table = bridge::table::<F, EF>(n, k, &values).unwrap();
            // Unused committed lanes need not be zero for this projection.
            let mut raw = table.values().to_vec();
            for row in 0..1 << n {
                for j in EF::D..k {
                    raw[row * k + j] = F::from(99 + row + j);
                }
            }
            let table = PackedTable::new(n, k, raw).unwrap();
            let point = fixture.get_vec_challenge(b"helper point", n);
            let q = bridge::coefficients_query::<F, EF>(k, &point).unwrap();
            let projected = q.apply(&table.evaluate(&q.query).unwrap(), k).unwrap();
            assert_eq!(
                bridge::element::<F, EF>(k, &projected).unwrap(),
                DenseMultilinearExtension::from_evaluations_vec(n, values).evaluate(&point)
            );
        }
    }
    // Right order matters: the scalar lane selector is not an extension
    // multiplication matrix. Moving it to the left loses lane seven entirely.
    let k = 8;
    let mu = 1;
    let point = fixture.get_vec_challenge(b"wrong order fixture", 4);
    let q = bridge::scalar_query::<F, EF>(mu, k, &point).unwrap();
    let lanes = bridge::scalar_query::<F, EF>(0, k, &point[..3])
        .unwrap()
        .post_matrix
        .unwrap();
    let mut wrong = bridge::coefficients_query::<F, EF>(k, &point[3..])
        .unwrap()
        .query;
    wrong[0].zero = lanes.mul(&wrong[0].zero).unwrap();
    wrong[0].one = lanes.mul(&wrong[0].one).unwrap();
    let mut values = vec![F::from(0usize); 16];
    values[7] = F::from(1usize);
    let table = PackedTable::new(mu, k, values).unwrap();
    assert_ne!(
        table.evaluate(&q.query).unwrap(),
        table.evaluate(&wrong).unwrap()
    );
    assert!(bridge::scalar_query::<F, EF>(0, 4, &[]).is_err());
    assert!(bridge::scalar_query::<F, EF>(0, 8, &[]).is_err());
    let mut bad = bridge::vector::<F, EF>(8, EF::one()).unwrap();
    if EF::D < 8 {
        bad[7] = F::from(1usize);
        assert!(bridge::element::<F, EF>(8, &bad).is_err());
    }
}
fn roundtrip<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (mu, k, len, repetitions) in [
        (0, 8usize, 1, 1),
        (0, 8, 8, 2),
        (1, 8, 11, 1),
        (2, 8, 32, 1),
        (3, 8, 53, 2),
        (2, 16, 64, 1),
    ] {
        for columns in [1, 3] {
            let public: Vec<Vec<F>> = (0..4)
                .map(|i| (0..columns).map(|j| F::from(i * (j + 1) + j * j)).collect())
                .collect();
            let tables: Vec<_> = (0..columns)
                .map(|j| {
                    PackedTable::new(
                        mu,
                        k,
                        (0..(1 << mu) * k)
                            .map(|i| {
                                if i < len {
                                    public[i % 4][j]
                                } else {
                                    F::from(999 + j)
                                }
                            })
                            .collect(),
                    )
                    .unwrap()
                })
                .collect();
            let pp =
                Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 32, 2).unwrap();
            let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                mu + k.ilog2() as usize,
                k,
                32,
                2,
            )
            .unwrap();
            let (roots, states): (Vec<_>, Vec<_>) = tables
                .iter()
                .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                .unzip();
            let oracles: Vec<_> = tables
                .iter()
                .zip(&roots)
                .zip(&states)
                .map(|((table, commitment), state)| ProverOracle {
                    parameters: &pp,
                    table,
                    commitment,
                    state,
                })
                .collect();
            let refs: Vec<_> = oracles.iter().collect();
            let expected: Vec<_> = oracles.iter().map(ProverOracle::verifier).collect();
            let config = Config::new(len, public.clone(), repetitions).unwrap();
            let mut prover = Transcript::new_direct();
            let proof =
                lookup::prove::<F, EF, Sha256, _>(&mut prover, &config, &helper, &refs).unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<F, EF, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut verifier = Transcript::new_direct();
            lookup::verify::<F, EF, Sha256, _>(&mut verifier, &config, &helper, &expected, &proof)
                .unwrap();
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
            let reject = |p: &Proof<F, EF, [u8; 32]>| {
                assert!(
                    lookup::verify::<F, EF, Sha256, _>(
                        &mut Transcript::new_direct(),
                        &config,
                        &helper,
                        &expected,
                        p
                    )
                    .is_err()
                )
            };
            let mut bad = proof.clone();
            bad.multiplicities[0] += F::from(1usize);
            reject(&bad);
            let mut bad = proof.clone();
            bad.groups[0].reciprocal_value += EF::monomial(EF::D - 1);
            reject(&bad);
            let mut bad = proof.clone();
            bad.groups[0].source_values[0][0] += F::from(1usize);
            reject(&bad);
            let mut bad = proof.clone();
            bad.groups[0].sum.pop();
            reject(&bad);
            let mut bad = proof.clone();
            let extra = bad.groups[0].zero[0].clone();
            bad.groups[0].zero.push(extra);
            reject(&bad);
            let mut bad = proof.clone();
            bad.reciprocal_commitments[0].root[0] ^= 1;
            reject(&bad);
            let mut bad = proof.clone();
            bad.groups[0].reciprocal_opening.columns[0].values[0] += F::from(1usize);
            reject(&bad);
            let mut bad = proof.clone();
            bad.source_openings.pop();
            reject(&bad);
            let wrong =
                Config::new(if len == 1 { 2 } else { len - 1 }, public, repetitions).unwrap();
            assert!(
                lookup::verify::<F, EF, Sha256, _>(
                    &mut Transcript::new_direct(),
                    &wrong,
                    &helper,
                    &expected,
                    &proof
                )
                .is_err()
            );
        }
    }
}
#[test]
fn babybear_quintic_query_mappings() {
    mappings::<algebra::BabyBear, algebra::BabyBearExtension5>();
}
#[test]
fn goldilocks_quintic_query_mappings() {
    mappings::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}
#[test]
fn babybear_quintic_lookup() {
    roundtrip::<algebra::BabyBear, algebra::BabyBearExtension5>();
}
#[test]
fn goldilocks_quintic_lookup() {
    roundtrip::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

#[test]
fn babybear_degree6_query_mappings() {
    mappings::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn babybear_degree6_lookup() {
    roundtrip::<algebra::BabyBear, algebra::BabyBearExtension6>();
}

#[test]
fn babybear_degree8_query_mappings() {
    mappings::<algebra::BabyBear, algebra::BabyBearExtension8>();
}
#[test]
fn babybear_degree8_lookup() {
    roundtrip::<algebra::BabyBear, algebra::BabyBearExtension8>();
}

fn basis_padding<F, EF>(width: usize)
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let mut transcript = Transcript::<EF>::new_direct_extension::<F>();
    for n in 0..=4 {
        let values = transcript.get_vec_challenge(b"basis values", 1 << n);
        let point = transcript.get_vec_challenge(b"basis point", n);
        let basis = bridge::table::<F, EF>(n, EF::D, &values).unwrap();
        let padded = bridge::table::<F, EF>(n, width, &values).unwrap();
        let mut raw = padded.values().to_vec();
        for row in 0..1 << n {
            for lane in EF::D..width {
                raw[row * width + lane] = F::from(row + lane + 9);
            }
        }
        let padded = PackedTable::new(n, width, raw).unwrap();
        let dense_query = bridge::coefficients_query::<F, EF>(EF::D, &point).unwrap();
        let padded_query = bridge::coefficients_query::<F, EF>(width, &point).unwrap();
        let dense = dense_query
            .apply(&basis.evaluate(&dense_query.query).unwrap(), EF::D)
            .unwrap();
        let padded = padded_query
            .apply(&padded.evaluate(&padded_query.query).unwrap(), width)
            .unwrap();
        let expected = DenseMultilinearExtension::from_evaluations_vec(n, values).evaluate(&point);
        assert_eq!(bridge::element::<F, EF>(EF::D, &dense).unwrap(), expected);
        assert_eq!(bridge::element::<F, EF>(width, &padded).unwrap(), expected);
        assert_eq!(dense, padded[..EF::D]);
    }
}
#[test]
fn basis_projection_commutes_with_padding_babybear() {
    basis_padding::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn basis_projection_commutes_with_padding_goldilocks() {
    basis_padding::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
