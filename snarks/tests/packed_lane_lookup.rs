use algebra::{BabyBear, Goldilocks, NTTField, PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_lane_lookup::{self, Config, Proof},
    packed_oracle::ProverOracle,
};
fn roundtrip<F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>>() {
    for (n, k, length, repetitions) in [
        (0usize, 2usize, 2usize, 3usize),
        (1, 1, 2, 2),
        (2, 4, 13, 5),
        (2, 4, 16, 5),
        (3, 8, 64, 9),
    ] {
        for columns in [1, 3] {
            let public: Vec<Vec<F>> = (0..4)
                .map(|i| (0..columns).map(|j| F::from(i * (j + 1) + j * j)).collect())
                .collect();
            let tables: Vec<_> = (0..columns)
                .map(|j| {
                    PackedTable::new(
                        n,
                        k,
                        (0..(1 << n) * k)
                            .map(|i| {
                                if i < length {
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
            let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, k, 32, 2).unwrap();
            let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                n + k.ilog2() as usize,
                k,
                32,
                2,
            )
            .unwrap();
            let (commitments, states): (Vec<_>, Vec<_>) = tables
                .iter()
                .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                .unzip();
            let oracles: Vec<_> = tables
                .iter()
                .zip(&commitments)
                .zip(&states)
                .map(|((table, commitment), state)| ProverOracle {
                    parameters: &pp,
                    table,
                    commitment,
                    state,
                })
                .collect();
            let config = Config::new(length, public, repetitions).unwrap();
            let mut prover = Transcript::new();
            let proof = packed_lane_lookup::prove::<F, Sha256, _>(
                &mut prover,
                &config,
                &helper,
                &oracles.iter().collect::<Vec<_>>(),
            )
            .unwrap();
            if n == 0 && columns == 1 {
                let mut measured_transcript = Transcript::new();
                let mut statistics = packed_lane_lookup::ProverStatistics::default();
                let measured = packed_lane_lookup::prove_with_statistics::<F, Sha256, _>(
                    &mut measured_transcript,
                    &config,
                    &helper,
                    &oracles.iter().collect::<Vec<_>>(),
                    &mut statistics,
                )
                .unwrap();
                assert_eq!(
                    bincode::serde::encode_to_vec(&measured, bincode::config::standard()).unwrap(),
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap()
                );
            }
            assert_eq!(proof.groups.len(), repetitions.div_ceil(k));
            let actual = packed_lane_lookup::effective_repetitions(repetitions, k).unwrap();
            assert_eq!(actual, proof.groups.len() * k);
            // Reconstruct helpers using direct inversions against original data,
            // independently of the prover's public-table inverse cache.
            let mut reference = Transcript::<F>::new();
            let contexts: Vec<_> = oracles
                .iter()
                .map(|s| {
                    (
                        s.parameters.context_digest::<F, Sha256>().unwrap(),
                        s.commitment,
                    )
                })
                .collect();
            reference.append_message(
                b"lane packed original tuple lookup v1",
                &(
                    &config,
                    actual,
                    helper.context_digest::<F, Sha256>().unwrap(),
                    contexts,
                ),
            );
            reference.append_message(b"lane lookup multiplicities", &proof.multiplicities);
            for (g, commitment) in proof.reciprocal_commitments.iter().enumerate() {
                let mut pairs = Vec::new();
                for _ in 0..k {
                    let y = reference.get_challenge(b"lane tuple hash challenge");
                    let mut power = F::from(1);
                    let powers: Vec<_> = (0..columns)
                        .map(|_| {
                            let p = power;
                            power *= y;
                            p
                        })
                        .collect();
                    let hashes: Vec<_> = config
                        .table()
                        .iter()
                        .map(|row| {
                            row.iter()
                                .zip(&powers)
                                .fold(F::from(0), |s, (&a, &p)| s + a * p)
                        })
                        .collect();
                    let r = loop {
                        let r = reference.get_challenge(b"lane tuple reciprocal challenge");
                        if r != F::from(0) && !hashes.iter().any(|&t| r + t == F::from(0)) {
                            break r;
                        }
                    };
                    pairs.push((powers, r));
                }
                let mut values = Vec::new();
                let mut sums = vec![F::from(0); k];
                for row in 0..(1 << n) * k {
                    for (lane, (powers, r)) in pairs.iter().enumerate() {
                        let f = if row < length {
                            let a = tables
                                .iter()
                                .zip(powers)
                                .fold(F::from(0), |s, (t, &p)| s + t.values()[row] * p);
                            F::from(1) / (*r + a)
                        } else {
                            F::from(0)
                        };
                        values.push(f);
                        sums[lane] += f;
                    }
                }
                let direct = PackedTable::new(helper.num_vars(), k, values).unwrap();
                let (expected, _) = helper.commit::<F, Sha256>(&direct).unwrap();
                assert_eq!(expected.root, commitment.root);
                assert_eq!(sums, proof.groups[g].sum_claim);
            }
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<F, [u8; 32]>, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let public: Vec<_> = oracles.iter().map(|s| s.verifier()).collect();
            let mut verifier = Transcript::new();
            packed_lane_lookup::verify::<F, Sha256, _>(
                &mut verifier,
                &config,
                &helper,
                &public,
                &proof,
            )
            .unwrap();
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
            let reject = |p: &Proof<F, [u8; 32]>| {
                packed_lane_lookup::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &config,
                    &helper,
                    &public,
                    p,
                )
                .is_err()
            };
            for column in 0..columns {
                let mut bad = proof.clone();
                bad.groups[0].source_values[column][0] += F::from(1);
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.source_openings[column].columns.clear();
                assert!(reject(&bad));
            }
            let mut bad = proof.clone();
            bad.groups[0].reciprocal_value[0] += F::from(1);
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.groups[0].reciprocal_opening.columns[0].values[0] += F::from(1);
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.multiplicities[0] += F::from(1);
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.groups.pop();
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.reciprocal_commitments.pop();
            assert!(reject(&bad));
            if k > 1 {
                let mut bad = proof.clone();
                bad.groups[0].sum_claim[0] += F::from(1);
                bad.groups[0].sum_claim[1] -= F::from(1);
                assert!(reject(&bad));
            }
            let wrong = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                helper.num_vars(),
                k,
                33,
                2,
            )
            .unwrap();
            assert!(
                packed_lane_lookup::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &config,
                    &wrong,
                    &public,
                    &proof
                )
                .is_err()
            );
        }
    }
}
#[test]
fn lane_group_lookup_roundtrip_and_canonical_authentication() {
    roundtrip::<BabyBear>();
    roundtrip::<Goldilocks>();
}
#[test]
fn lane_group_repetition_counts_are_checked() {
    assert_eq!(packed_lane_lookup::effective_repetitions(9, 8).unwrap(), 16);
    assert!(packed_lane_lookup::effective_repetitions(0, 8).is_err());
    assert!(packed_lane_lookup::effective_repetitions(1, 3).is_err());
    assert!(packed_lane_lookup::effective_repetitions(usize::MAX, 8).is_err());
}
