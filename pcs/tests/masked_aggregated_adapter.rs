use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::masked_polyfrim::{Parameters, aggregated::Proof};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

fn exercise<F, E>()
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, E>::new(3, 2, 13, 2, 1, 22)
        .unwrap()
        .with_transient_source_values();
    let table =
        PackedTable::new(3, 2, (0..16).map(|i| F::from(i * i + 7 * i + 3)).collect()).unwrap();
    let (root, state) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(924))
        .unwrap();
    assert_eq!(state.cached_codeword_elements().unwrap(), 0);
    let mut coins = Transcript::<F>::new_direct();
    let mut end = 0;
    for count in [1, 4, 16] {
        let first = end;
        let queries: Vec<Vec<_>> = (0..count)
            .map(|_| {
                (0..3)
                    .map(|_| {
                        let v = coins.get_vec_challenge(b"aggregated adapter matrices", 8);
                        MatrixPair {
                            zero: Matrix::new(2, v[..4].to_vec()).unwrap(),
                            one: Matrix::new(2, v[4..].to_vec()).unwrap(),
                        }
                    })
                    .collect()
            })
            .collect();
        let claims: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
        let mut wrong = claims.clone();
        wrong[count - 1][0] += F::one();
        let mut attempted = Transcript::new_direct();
        let mut untouched = Transcript::<F>::new_direct();
        assert!(
            pp.open_many_aggregated::<Sha256>(&mut attempted, &root, &state, &queries, &wrong)
                .is_err()
        );
        assert_eq!(
            attempted.get_challenge(b"adapter preflight after"),
            untouched.get_challenge(b"adapter preflight after")
        );
        assert_eq!(state.spent().unwrap(), first);
        let mut pt = Transcript::new_direct();
        let proof = pp
            .open_many_aggregated::<Sha256>(&mut pt, &root, &state, &queries, &claims)
            .unwrap();
        assert_eq!(proof.first, first);
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (decoded, used): (Proof<E, [u8; 32]>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut vt = Transcript::new_direct();
        pp.verify_many_aggregated::<Sha256>(&mut vt, &root, &queries, &claims, &decoded)
            .unwrap();
        assert_eq!(
            pt.get_challenge(b"adapter after"),
            vt.get_challenge(b"adapter after")
        );
        end += count;
        assert_eq!(state.spent().unwrap(), end);
        assert_eq!(state.cached_codeword_elements().unwrap(), 0);
        let mut foreign = root.clone();
        foreign.root[0] ^= 1;
        assert!(
            pp.verify_many_aggregated::<Sha256>(
                &mut Transcript::new_direct(),
                &foreign,
                &queries,
                &claims,
                &decoded
            )
            .is_err()
        );
        let mut bad = decoded.clone();
        bad.proximity_sources[0].path[0][0] ^= 1;
        assert!(
            pp.verify_many_aggregated::<Sha256>(
                &mut Transcript::new_direct(),
                &root,
                &queries,
                &claims,
                &bad
            )
            .is_err()
        );
        let mut bad = decoded.clone();
        bad.first = usize::MAX;
        let mut attempted = Transcript::new_direct();
        let mut untouched = Transcript::<F>::new_direct();
        assert!(
            pp.verify_many_aggregated::<Sha256>(&mut attempted, &root, &queries, &claims, &bad)
                .is_err()
        );
        assert_eq!(
            attempted.get_challenge(b"bad schedule after"),
            untouched.get_challenge(b"bad schedule after")
        );
        if count == 1 {
            let mut pt = Transcript::new_direct();
            let old = pp
                .open_many::<Sha256>(&mut pt, &root, &state, &queries, &claims)
                .unwrap();
            assert_eq!(old.openings[0].index, end);
            let mut vt = Transcript::new_direct();
            pp.verify_many::<Sha256>(&mut vt, &root, &queries, &claims, &old)
                .unwrap();
            assert_eq!(
                pt.get_challenge(b"mixed after"),
                vt.get_challenge(b"mixed after")
            );
            end += 1;
        }
    }
    assert_eq!(end, 22);
    let queries = vec![vec![
        MatrixPair {
            zero: Matrix::identity(2).unwrap(),
            one: Matrix::identity(2).unwrap()
        };
        3
    ]];
    let claims = vec![table.evaluate(&queries[0]).unwrap()];
    let mut attempted = Transcript::new_direct();
    let mut untouched = Transcript::<F>::new_direct();
    assert!(
        pp.open_many_aggregated::<Sha256>(&mut attempted, &root, &state, &queries, &claims)
            .is_err()
    );
    assert!(
        pp.open_many_joint::<Sha256>(&mut attempted, &root, &state, &queries, &claims)
            .is_err()
    );
    assert!(
        pp.open_many::<Sha256>(&mut attempted, &root, &state, &queries, &claims)
            .is_err()
    );
    assert_eq!(
        attempted.get_challenge(b"exhausted after"),
        untouched.get_challenge(b"exhausted after")
    );
    assert_eq!(state.spent().unwrap(), 22);
    assert_eq!(state.cached_codeword_elements().unwrap(), 0);
}
#[test]
fn babybear_aggregated_adapter() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_aggregated_adapter() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
