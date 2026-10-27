use algebra::{BabyBear, Goldilocks, NTTField, PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_oracle::ProverOracle,
    packed_tuple_lookup::{self, Config, Proof},
};
fn roundtrip<F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>>() {
    for columns in [1, 2, 3] {
        let length = 13usize;
        let width = 3;
        let n = 3;
        let public: Vec<Vec<F>> = (0..5)
            .map(|i| (0..columns).map(|j| F::from(i * (j + 1) + j)).collect())
            .collect();
        let tables: Vec<_> = (0..columns)
            .map(|j| {
                PackedTable::new(
                    n,
                    width,
                    (0..24)
                        .map(|i| {
                            if i < length {
                                public[i % 5][j]
                            } else {
                                F::from(999 + j)
                            }
                        })
                        .collect(),
                )
                .unwrap()
            })
            .collect();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 32, 2).unwrap();
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
        let refs: Vec<_> = oracles.iter().collect();
        let config = Config::new(length, public, 2).unwrap();
        let mut prover = Transcript::new();
        let proof =
            packed_tuple_lookup::prove::<F, Sha256, _>(&mut prover, &config, &refs).unwrap();
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let public: Vec<_> = oracles.iter().map(|s| s.verifier()).collect();
        let mut verifier = Transcript::new();
        packed_tuple_lookup::verify::<F, Sha256, _>(&mut verifier, &config, &public, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        for col in 0..columns {
            let mut bad = proof.clone();
            bad.repetitions[0].source_values[col][0] += F::from(1);
            assert!(
                packed_tuple_lookup::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &config,
                    &public,
                    &bad
                )
                .is_err()
            );
            let mut bad = proof.clone();
            bad.source_openings[col].columns.clear();
            assert!(
                packed_tuple_lookup::verify::<F, Sha256, _>(
                    &mut Transcript::new(),
                    &config,
                    &public,
                    &bad
                )
                .is_err()
            );
        }
        let mut bad = proof.clone();
        bad.multiplicities[0] += F::from(1);
        assert!(
            packed_tuple_lookup::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &config,
                &public,
                &bad
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad.repetitions[0].source_values.pop();
        assert!(
            packed_tuple_lookup::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &config,
                &public,
                &bad
            )
            .is_err()
        );
        let changed = Config::new(length - 1, config.table().to_vec(), 2).unwrap();
        assert!(
            packed_tuple_lookup::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &changed,
                &public,
                &proof
            )
            .is_err()
        );
    }
}
#[test]
fn original_tuple_lookup_roundtrip_and_authentication() {
    roundtrip::<BabyBear>();
    roundtrip::<Goldilocks>();
}
#[test]
fn tuple_membership_checks_joint_rows_not_marginals() {
    type F = BabyBear;
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, 2, 32, 2).unwrap();
    let tables: Vec<_> = [vec![0, 1, 0, 1], vec![1, 0, 1, 0]]
        .into_iter()
        .map(|v| PackedTable::new(1, 2, v.into_iter().map(F::from).collect()).unwrap())
        .collect();
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
    let config = Config::new(
        4,
        vec![vec![F::from(0), F::from(0)], vec![F::from(1), F::from(1)]],
        2,
    )
    .unwrap();
    assert!(
        packed_tuple_lookup::prove::<F, Sha256, _>(
            &mut Transcript::new(),
            &config,
            &oracles.iter().collect::<Vec<_>>()
        )
        .is_err()
    );
    assert_eq!(config.hash_collision_numerator(), 2);
    assert_eq!(config.rational_degree_bound(), 5);
    assert_eq!(config.reciprocal_domain_lower_bound().unwrap(), 2013265918);
    assert!(Config::new(1, vec![vec![F::from(0)], vec![F::from(0)]], 1).is_err());
    assert!(Config::new(1, vec![vec![F::from(0)], vec![F::from(0), F::from(1)]], 1).is_err());
}
