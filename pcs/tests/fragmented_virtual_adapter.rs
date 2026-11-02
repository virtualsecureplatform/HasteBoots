use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{
        backend::CanonicalPcs,
        fragmented_pipfri::virtual_source::{Parameters, Proof},
    },
    utils::hash::Digest512,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha512;

fn exercise<F, E>()
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (vars, width) in [(0, 1), (0, 4), (3, 2)] {
        let pp = Parameters::<F, E>::new(vars, width, 2, 8, 2).unwrap();
        let table = PackedTable::new(
            vars,
            width,
            (0..(width << vars)).map(|i| F::from(i * i + 7)).collect(),
        )
        .unwrap();
        let (root, state) = <Parameters<F, E> as CanonicalPcs<F, Sha512>>::commit(
            &pp,
            &table,
            &mut StdRng::seed_from_u64(37),
        )
        .unwrap();
        let ordinary =
            pcs::matrix_weighted::fragmented_pipfri::Parameters::<F, E>::new(vars, width, 2, 8, 2)
                .unwrap();
        let (old_root, _old_state) =
            <pcs::matrix_weighted::fragmented_pipfri::Parameters<F, E> as CanonicalPcs<
                F,
                Sha512,
            >>::commit(&ordinary, &table, &mut StdRng::seed_from_u64(37))
            .unwrap();
        assert_eq!(root.root, old_root.root);
        let foreign = Parameters::<F, E>::new(vars, width, 2, 9, 2).unwrap();
        let (foreign_root, foreign_state) = <Parameters<F, E> as CanonicalPcs<F, Sha512>>::commit(
            &foreign,
            &table,
            &mut StdRng::seed_from_u64(37),
        )
        .unwrap();
        for count in [1, 4, 16] {
            let mut coins = Transcript::<F>::new_classical(&[3; 64]);
            let queries: Vec<Vec<_>> = (0..count)
                .map(|_| {
                    (0..vars)
                        .map(|_| {
                            let a = coins.get_vec_challenge(
                                b"dense noncommuting matrices",
                                2 * width * width,
                            );
                            MatrixPair {
                                zero: Matrix::new(width, a[..width * width].to_vec()).unwrap(),
                                one: Matrix::new(width, a[width * width..].to_vec()).unwrap(),
                            }
                        })
                        .collect()
                })
                .collect();
            let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
            assert!(
                <Parameters<F, E> as CanonicalPcs<F, Sha512>>::open_many(
                    &pp,
                    &mut Transcript::new_classical(&[5; 64]),
                    &foreign_root,
                    &foreign_state,
                    &queries,
                    &values,
                )
                .is_err()
            );
            let mut prover = Transcript::<F>::new_classical(&[5; 64]);
            let proof = <Parameters<F, E> as CanonicalPcs<F, Sha512>>::open_many(
                &pp,
                &mut prover,
                &root,
                &state,
                &queries,
                &values,
            )
            .unwrap();
            let bytes = bincode::serde::encode_to_vec(proof, bincode::config::standard()).unwrap();
            let (decoded, used): (Proof<E, Digest512>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut verifier = Transcript::<F>::new_classical(&[5; 64]);
            <Parameters<F, E> as CanonicalPcs<F, Sha512>>::verify_many(
                &pp,
                &mut verifier,
                &root,
                &queries,
                &values,
                &decoded,
            )
            .unwrap();
            let mut a = [0; 32];
            let mut b = [0; 32];
            prover.get_challenge_bytes(b"finished", &mut a);
            verifier.get_challenge_bytes(b"finished", &mut b);
            assert_eq!(a, b);
            if vars > 0 && count > 1 {
                // The same valid claims in a different order must not reuse
                // an existing bridge: lane weights bind the ordered packet.
                let mut reordered_queries = queries.clone();
                let mut reordered_values = values.clone();
                reordered_queries.reverse();
                reordered_values.reverse();
                assert!(
                    <Parameters<F, E> as CanonicalPcs<F, Sha512>>::verify_many(
                        &pp,
                        &mut Transcript::new_classical(&[5; 64]),
                        &root,
                        &reordered_queries,
                        &reordered_values,
                        &decoded,
                    )
                    .is_err()
                );
            }
            if vars > 1 {
                // Recompute true outputs after reversing the noncommuting
                // matrix sequence; proof reuse must still fail.
                let reversed: Vec<Vec<_>> = queries
                    .iter()
                    .map(|q| q.iter().cloned().rev().collect())
                    .collect();
                let outputs: Vec<_> = reversed
                    .iter()
                    .map(|q| table.evaluate(q).unwrap())
                    .collect();
                assert!(
                    <Parameters<F, E> as CanonicalPcs<F, Sha512>>::verify_many(
                        &pp,
                        &mut Transcript::new_classical(&[5; 64]),
                        &root,
                        &reversed,
                        &outputs,
                        &decoded,
                    )
                    .is_err()
                );
            }
            let mut wrong = values.clone();
            wrong[0][0] += F::one();
            assert!(
                <Parameters<F, E> as CanonicalPcs<F, Sha512>>::verify_many(
                    &pp,
                    &mut Transcript::new_classical(&[5; 64]),
                    &root,
                    &queries,
                    &wrong,
                    &decoded
                )
                .is_err()
            );
            assert!(
                <Parameters<F, E> as CanonicalPcs<F, Sha512>>::verify_many(
                    &pp,
                    &mut Transcript::new_classical(&[6; 64]),
                    &root,
                    &queries,
                    &values,
                    &decoded
                )
                .is_err()
            );
        }
    }
}
#[test]
fn babybear_virtual_fragmented_ordered_matrix_bridge() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_virtual_fragmented_ordered_matrix_bridge() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
