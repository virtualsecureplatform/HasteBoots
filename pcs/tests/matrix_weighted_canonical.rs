use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{Parameters, aggregate::canonical},
    utils::code::BlockReedSolomonCode,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

fn exercise<F, EF>(k: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let n = 5;
    let pp = Parameters::new_encoded::<F>(
        n,
        k,
        1,
        64,
        BlockReedSolomonCode::<F>::new(1 << (n - 1), k, 2).unwrap(),
    )
    .unwrap();
    // Two different committed tables agree at this Boolean query. Equality of
    // values must never be used as a substitute for equality of roots.
    let query: Vec<_> = (0..n)
        .map(|_| MatrixPair {
            zero: Matrix::identity(k).unwrap(),
            one: Matrix::new(k, vec![F::zero(); k * k]).unwrap(),
        })
        .collect();
    let tables: Vec<_> = (0..3)
        .map(|i| {
            PackedTable::new(
                n,
                k,
                (0..(1 << n) * k)
                    .map(|j| F::from(if j < k { j } else { j + i * 17 }))
                    .collect(),
            )
            .unwrap()
        })
        .collect();
    let committed: Vec<_> = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .collect();
    let order = [0, 1, 0, 2, 1];
    let roots: Vec<_> = order.iter().map(|&i| committed[i].0.clone()).collect();
    let states: Vec<_> = order.iter().map(|&i| &committed[i].1).collect();
    let values: Vec<_> = order
        .iter()
        .map(|&i| tables[i].evaluate(&query).unwrap())
        .collect();
    assert_eq!(values[0], values[1]);
    assert_ne!(roots[0].root, roots[1].root);
    let mut prover = Transcript::new_direct();
    let proof =
        canonical::prove::<F, EF, Sha256, _>(&pp, &mut prover, &roots, &states, &query, &values)
            .unwrap();
    assert_eq!(proof.opening.columns.len(), 3);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (canonical::Proof<F, EF, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    canonical::verify::<F, EF, Sha256, _>(&pp, &mut verifier, &roots, &query, &values, &proof)
        .unwrap();
    assert_eq!(
        prover.get_challenge(b"after canonical"),
        verifier.get_challenge(b"after canonical")
    );
    let mut conflicting = values.clone();
    conflicting[2][0] += F::one();
    let mut rejected = Transcript::new_direct();
    let mut untouched = Transcript::<F>::new_direct();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &pp,
            &mut rejected,
            &roots,
            &query,
            &conflicting,
            &proof
        )
        .is_err()
    );
    assert_eq!(
        rejected.get_challenge(b"unchanged"),
        untouched.get_challenge(b"unchanged")
    );
    assert!(
        canonical::prove::<F, EF, Sha256, _>(
            &pp,
            &mut Transcript::new_direct(),
            &roots,
            &states,
            &query,
            &conflicting
        )
        .is_err()
    );
    let mut reordered = roots.clone();
    reordered.swap(0, 1);
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &pp,
            &mut Transcript::new_direct(),
            &reordered,
            &query,
            &values,
            &proof
        )
        .is_err()
    );
    let mut missing = proof.clone();
    missing.opening.columns.pop();
    assert!(
        canonical::verify::<F, EF, Sha256, _>(
            &pp,
            &mut Transcript::new_direct(),
            &roots,
            &query,
            &values,
            &missing
        )
        .is_err()
    );
    let mut wrong_states = states.clone();
    wrong_states[0] = states[1];
    assert!(
        canonical::prove::<F, EF, Sha256, _>(
            &pp,
            &mut Transcript::new_direct(),
            &roots,
            &wrong_states,
            &query,
            &values
        )
        .is_err()
    );
}

#[test]
fn babybear_canonical_roots() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_canonical_roots() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
