use algebra::{BabyBear, Goldilocks, NTTField, PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_lookup::{self, Config, Proof},
    packed_oracle::{ProverOracle, VerifierOracle},
};

fn roundtrip<F: PrimeField + NTTField + Serialize + DeserializeOwned + From<usize>>() {
    for (length, width) in [(1usize, 1usize), (7, 4), (32, 8), (93, 5)] {
        let cells = length.div_ceil(width).max(2).next_power_of_two();
        let table = PackedTable::new(
            cells.ilog2() as usize,
            width,
            (0..cells * width)
                .map(|i| {
                    if i < length {
                        F::from(i % 4)
                    } else {
                        F::from(999)
                    }
                })
                .collect(),
        )
        .unwrap();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
            table.num_vars(),
            width,
            32,
            2,
        )
        .unwrap();
        let (commitment, state) = pp.commit::<F, Sha256>(&table).unwrap();
        let oracle = ProverOracle {
            parameters: &pp,
            commitment: &commitment,
            state: &state,
            table: &table,
        };
        let config = Config::new(
            length,
            [2usize, 0, 3, 1].into_iter().map(F::from).collect(),
            2,
        )
        .unwrap();
        let mut prover = Transcript::new();
        let proof = packed_lookup::prove::<F, Sha256, _>(&mut prover, &config, &oracle).unwrap();
        // Independently reconstruct each helper using one division per entry.
        // This checks the public-table inverse cache and its canonical roots.
        let mut reference = Transcript::<F>::new();
        reference.append_message(
            b"packed scalar lookup v1",
            &(
                &config,
                pp.context_digest::<F, Sha256>().unwrap(),
                &commitment,
            ),
        );
        reference.append_message(b"packed lookup multiplicities", &proof.multiplicities);
        for helper_commitment in &proof.reciprocal_commitments {
            let r = loop {
                let r = reference.get_challenge(b"packed lookup reciprocal challenge");
                if r != F::zero() && !config.table().iter().any(|&t| r + t == F::zero()) {
                    break r;
                }
            };
            let direct = PackedTable::new(
                table.num_vars(),
                width,
                table
                    .values()
                    .iter()
                    .enumerate()
                    .map(|(i, &a)| {
                        if i < length {
                            F::one() / (r + a)
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
            )
            .unwrap();
            let (expected, _) = pp.commit::<F, Sha256>(&direct).unwrap();
            assert_eq!(expected.root, helper_commitment.root);
        }
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (Proof<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new();
        packed_lookup::verify::<F, Sha256, _>(&mut verifier, &config, &oracle.verifier(), &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        assert_eq!(config.excluded_challenges(), 4);
        assert_eq!(config.rational_degree_bound(), (length + 3) as u128);
    }
}
#[test]
fn reciprocal_lookup_roundtrip_babybear_and_goldilocks_with_arbitrary_padding() {
    roundtrip::<BabyBear>();
    roundtrip::<Goldilocks>();
}
#[test]
fn lookup_rejects_tampering_wrong_statements_and_malformed_shapes() {
    type F = BabyBear;
    let table = PackedTable::new(3, 4, (0..32).map(|i| F::from(i % 4)).collect()).unwrap();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(3, 4, 64, 2).unwrap();
    let (commitment, state) = pp.commit::<F, Sha256>(&table).unwrap();
    let oracle = ProverOracle {
        parameters: &pp,
        commitment: &commitment,
        state: &state,
        table: &table,
    };
    let config = Config::new(29, (0..4).map(F::from).collect(), 2).unwrap();
    let proof =
        packed_lookup::prove::<F, Sha256, _>(&mut Transcript::new(), &config, &oracle).unwrap();
    let reject = |p: &Proof<F, [u8; 32]>| {
        packed_lookup::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &config,
            &oracle.verifier(),
            p,
        )
        .is_err()
    };
    let mut bad = proof.clone();
    bad.multiplicities[0] += F::from(1);
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.multiplicities.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.repetitions.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.reciprocal_commitments.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.reciprocal_commitments[0].root[0] ^= 1;
    assert!(reject(&bad));
    for i in 0..2 {
        let mut bad = proof.clone();
        bad.repetitions[i].sum_claim[0] += F::from(1);
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.repetitions[i].source_value[0] += F::from(1);
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.repetitions[i].reciprocal_value[0] += F::from(1);
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.repetitions[i].source_value.clear();
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.repetitions[i].reciprocal_opening.columns[0].values[0] += F::from(1);
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.repetitions[i].zero.first.clear();
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.repetitions[i].sum.rounds.pop();
        assert!(reject(&bad));
    }
    let mut bad = proof.clone();
    bad.source_opening.columns.clear();
    assert!(reject(&bad));
    for changed in [
        Config::new(28, (0..4).map(F::from).collect(), 2).unwrap(),
        Config::new(29, (0..5).map(F::from).collect(), 2).unwrap(),
        Config::new(29, (0..4).map(F::from).collect(), 1).unwrap(),
    ] {
        assert!(
            packed_lookup::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &changed,
                &oracle.verifier(),
                &proof
            )
            .is_err()
        );
    }
    // A genuine proof for different valid data must fail under the expected root.
    let other = PackedTable::new(3, 4, vec![F::from(2); 32]).unwrap();
    let (other_commitment, other_state) = pp.commit::<F, Sha256>(&other).unwrap();
    let other_oracle = ProverOracle {
        parameters: &pp,
        commitment: &other_commitment,
        state: &other_state,
        table: &other,
    };
    let other_proof =
        packed_lookup::prove::<F, Sha256, _>(&mut Transcript::new(), &config, &other_oracle)
            .unwrap();
    assert!(reject(&other_proof));
    let wrong_state = ProverOracle {
        parameters: &pp,
        commitment: &commitment,
        state: &state,
        table: &other,
    };
    assert!(
        packed_lookup::prove::<F, Sha256, _>(&mut Transcript::new(), &config, &wrong_state)
            .is_err()
    );
    let outside = PackedTable::new(3, 4, vec![F::from(7); 32]).unwrap();
    let (outside_commitment, outside_state) = pp.commit::<F, Sha256>(&outside).unwrap();
    let outside = ProverOracle {
        parameters: &pp,
        commitment: &outside_commitment,
        state: &outside_state,
        table: &outside,
    };
    assert!(
        packed_lookup::prove::<F, Sha256, _>(&mut Transcript::new(), &config, &outside).is_err()
    );
    let oversized = Config::new(33, (0..4).map(F::from).collect(), 2).unwrap();
    assert!(
        packed_lookup::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &oversized,
            &oracle.verifier(),
            &proof
        )
        .is_err()
    );
    let wrong_pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(3, 4, 63, 2).unwrap();
    let wrong = VerifierOracle {
        parameters: &wrong_pp,
        commitment: &commitment,
    };
    assert!(
        packed_lookup::verify::<F, Sha256, _>(&mut Transcript::new(), &config, &wrong, &proof)
            .is_err()
    );
}
#[test]
fn lookup_config_rejects_characteristic_cancellation_and_duplicate_entries() {
    type F = BabyBear;
    assert!(Config::new(0, vec![F::from(0)], 1).is_err());
    assert!(Config::new(1, Vec::<F>::new(), 1).is_err());
    assert!(Config::new(1, vec![F::from(0)], 0).is_err());
    assert!(Config::new(1, vec![F::from(2), F::from(2)], 1).is_err());
    assert!(Config::new(2013265921, vec![F::from(0)], 1).is_err());
    let config = Config::new(10, vec![F::from(1), F::from(2)], 3).unwrap();
    assert_eq!(config.excluded_challenges(), 3);
    assert_eq!(config.challenge_domain_size().unwrap(), 2013265918);
}
