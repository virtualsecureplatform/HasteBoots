#[allow(dead_code)]
#[path = "support/legacy_opening_batch_v1.rs"]
mod legacy;
use algebra::{
    NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_opening_batch::{OpeningBatch, Proof},
    packed_oracle::VerifierOracle,
};

fn exercise<F: NTTField + Serialize + DeserializeOwned>(k: usize) {
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(5, k, 64, 2).unwrap();
    let tables: Vec<_> = (0..3)
        .map(|j| {
            PackedTable::new(
                5,
                k,
                (0..32 * k)
                    .map(|i| F::from((j + 1) * (i * i + 3) + i))
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let slots = [0, 1, 0, 2];
    let oracles: Vec<_> = slots
        .iter()
        .map(|&i| VerifierOracle {
            parameters: &pp,
            commitment: &roots[i],
        })
        .collect();
    let references: Vec<_> = slots.iter().map(|&i| &states[i]).collect();
    let mut fixture = Transcript::<F>::new_direct();
    let queries: Vec<Vec<_>> = (0..2)
        .map(|_| {
            (0..5)
                .map(|_| MatrixPair {
                    zero: Matrix::new(k, fixture.get_vec_challenge(b"deferred zero", k * k))
                        .unwrap(),
                    one: Matrix::new(k, fixture.get_vec_challenge(b"deferred one", k * k)).unwrap(),
                })
                .collect()
        })
        .collect();
    let claims = vec![
        (
            0,
            queries[0].clone(),
            tables[0].evaluate(&queries[0]).unwrap(),
        ),
        (
            2,
            queries[1].clone(),
            tables[0].evaluate(&queries[1]).unwrap(),
        ),
        (
            1,
            queries[0].clone(),
            tables[1].evaluate(&queries[0]).unwrap(),
        ),
    ];
    let build = |trans: &mut Transcript<F>, claims: &[(usize, Vec<MatrixPair<F>>, Vec<F>)]| {
        let mut batch = OpeningBatch::<F, Sha256, _>::new(trans, &oracles).unwrap();
        for (slot, query, value) in claims {
            batch
                .push(trans, *slot, query.clone(), value.clone())
                .unwrap();
        }
        batch
    };
    let mut prover = Transcript::new_direct();
    let batch = build(&mut prover, &claims);
    assert_eq!(batch.claim_count(), 3);
    assert_eq!(batch.used_sources(), 2);
    let proof = batch.prove(&mut prover, &references).unwrap();
    assert_eq!(proof.openings.len(), 2);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    build(&mut verifier, &claims)
        .verify(&mut verifier, &proof)
        .unwrap();
    let after = prover.get_challenge(b"after batch");
    assert_eq!(after, verifier.get_challenge(b"after batch"));
    let mut reference = Transcript::new_direct();
    let mut previous = legacy::OpeningBatch::<F, Sha256, _>::new(&mut reference, &oracles).unwrap();
    for (slot, query, value) in &claims {
        previous
            .push(&mut reference, *slot, query.clone(), value.clone())
            .unwrap();
    }
    let previous = previous.prove(&mut reference, &references).unwrap();
    assert_eq!(
        bytes,
        bincode::serde::encode_to_vec(&previous, bincode::config::standard()).unwrap()
    );
    assert_eq!(after, reference.get_challenge(b"after batch"));
    let mut old_verifier = Transcript::new_direct();
    let mut old_batch =
        legacy::OpeningBatch::<F, Sha256, _>::new(&mut old_verifier, &oracles).unwrap();
    for (slot, query, value) in &claims {
        old_batch
            .push(&mut old_verifier, *slot, query.clone(), value.clone())
            .unwrap();
    }
    old_batch.verify(&mut old_verifier, &previous).unwrap();
    assert_eq!(after, old_verifier.get_challenge(b"after batch"));

    let mut missing = Transcript::new_direct();
    assert!(
        build(&mut missing, &claims[..2])
            .verify(&mut missing, &proof)
            .is_err()
    );
    let mut wrong = claims.clone();
    wrong[0].2[0] += F::one();
    let mut trans = Transcript::new_direct();
    assert!(
        build(&mut trans, &wrong)
            .verify(&mut trans, &proof)
            .is_err()
    );
    let mut wrong = claims.clone();
    wrong.swap(0, 1);
    let mut trans = Transcript::new_direct();
    assert!(
        build(&mut trans, &wrong)
            .verify(&mut trans, &proof)
            .is_err()
    );
    let mut bad = proof.clone();
    bad.openings[0].columns[0].values[0] += F::one();
    let mut trans = Transcript::new_direct();
    assert!(build(&mut trans, &claims).verify(&mut trans, &bad).is_err());
    let mut bad = proof.clone();
    bad.openings.pop();
    let mut trans = Transcript::new_direct();
    assert!(build(&mut trans, &claims).verify(&mut trans, &bad).is_err());
    let mut trans = Transcript::new_direct();
    let mut batch = OpeningBatch::<F, Sha256, _>::new(&mut trans, &oracles).unwrap();
    assert!(
        batch
            .push(&mut trans, 99, queries[0].clone(), vec![F::zero(); k])
            .is_err()
    );
    assert!(
        batch
            .push(&mut trans, 0, vec![], vec![F::zero(); k])
            .is_err()
    );
    assert!(
        batch
            .verify(&mut trans, &Proof { openings: vec![] })
            .is_err()
    );
}
#[test]
fn babybear_deferred_claims() {
    exercise::<algebra::BabyBear>(8);
}
#[test]
fn goldilocks_deferred_claims() {
    exercise::<algebra::Goldilocks>(4);
}

#[test]
fn equal_roots_with_different_parameter_contexts_do_not_alias() {
    use algebra::{BabyBear as F, Field};
    let a = Parameters::new_encoded::<F>(
        2,
        8,
        0,
        64,
        BlockReedSolomonCode::<F>::new(4, 8, 2).unwrap(),
    )
    .unwrap();
    let b = Parameters::new_encoded::<F>(
        3,
        8,
        1,
        64,
        BlockReedSolomonCode::<F>::new(4, 4, 2).unwrap(),
    )
    .unwrap();
    let (ra, sa) = a
        .commit::<F, Sha256>(&PackedTable::new(2, 8, vec![F::new(0); 32]).unwrap())
        .unwrap();
    let (rb, sb) = b
        .commit::<F, Sha256>(&PackedTable::new(3, 8, vec![F::new(0); 64]).unwrap())
        .unwrap();
    assert_eq!(ra.root, rb.root);
    let oracles = [
        VerifierOracle {
            parameters: &a,
            commitment: &ra,
        },
        VerifierOracle {
            parameters: &b,
            commitment: &rb,
        },
    ];
    let mut prover = Transcript::new_direct();
    let mut batch = OpeningBatch::<F, Sha256, _>::new(&mut prover, &oracles).unwrap();
    for (slot, n) in [(0, 2), (1, 3)] {
        let q = (0..n)
            .map(|_| MatrixPair {
                zero: Matrix::identity(8).unwrap(),
                one: Matrix::identity(8).unwrap(),
            })
            .collect();
        batch
            .push(&mut prover, slot, q, vec![F::new(0); 8])
            .unwrap();
    }
    assert_eq!(batch.used_sources(), 2);
    assert_eq!(
        batch
            .prove(&mut prover, &[&sa, &sb])
            .unwrap()
            .openings
            .len(),
        2
    );
}
