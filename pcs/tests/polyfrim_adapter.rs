use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::{
    Commitment,
    backend::CanonicalPcs,
    polyfrim::{Parameters, Proof},
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

fn classical_roundtrip<F, E>()
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::utils::hash::Digest512;
    use sha2::Sha512;
    let pp = Parameters::<F, E>::new(3, 2, 2, 8).unwrap();
    let table = PackedTable::new(3, 2, (0..16).map(|i| F::from(i * i + 7)).collect()).unwrap();
    let (root, state) = pp.commit::<Sha512>(&table).unwrap();
    let mut coins = Transcript::<F>::new_classical(&[3; 64]);
    let queries: Vec<Vec<_>> = (0..4)
        .map(|_| {
            (0..3)
                .map(|_| {
                    let values = coins.get_vec_challenge(b"matrix", 8);
                    MatrixPair {
                        zero: Matrix::new(2, values[..4].to_vec()).unwrap(),
                        one: Matrix::new(2, values[4..].to_vec()).unwrap(),
                    }
                })
                .collect()
        })
        .collect();
    let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
    let mut prover = Transcript::<F>::new_classical(&[5; 64]);
    let proof = pp
        .open_many::<Sha512>(&mut prover, &root, &state, &queries, &values)
        .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (decoded, used): (Proof<E, Digest512>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::<F>::new_classical(&[5; 64]);
    pp.verify_many::<Sha512>(&mut verifier, &root, &queries, &values, &decoded)
        .unwrap();
    assert_eq!(fingerprint(&mut prover), fingerprint(&mut verifier));
    assert!(
        pp.verify_many::<Sha512>(
            &mut Transcript::<F>::new_classical(&[6; 64]),
            &root,
            &queries,
            &values,
            &decoded
        )
        .is_err()
    );
}

#[test]
fn babybear_classical_sha512_adapter_roundtrip() {
    classical_roundtrip::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_classical_sha512_adapter_roundtrip() {
    classical_roundtrip::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

fn base_storage_equivalence<F, E>()
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use sha2::Sha512;
    for (vars, width) in [(0, 1), (0, 4), (3, 2), (4, 8), (11, 8)] {
        let mut pp = Parameters::<F, E>::new(vars, width, 2, 8).unwrap();
        if vars == 11 {
            pp = pp.with_parallel_oracles();
        }
        let reference = pp.clone().with_extension_storage_reference();
        assert_eq!(
            pp.context_digest::<Sha512>(),
            reference.context_digest::<Sha512>()
        );
        let table = PackedTable::new(
            vars,
            width,
            (0..(width << vars))
                .map(|i| F::from(i * i + 3 * i + 7))
                .collect(),
        )
        .unwrap();
        let (root, state) = pp.commit::<Sha512>(&table).unwrap();
        let (old_root, old_state) = reference.commit::<Sha512>(&table).unwrap();
        assert_eq!(root.root, old_root.root);
        assert_eq!(
            state.cached_codeword_elements(),
            old_state.cached_codeword_elements()
        );
        assert_eq!(
            state.cached_codeword_bytes(),
            state.cached_codeword_elements() * std::mem::size_of::<F>()
        );
        assert_eq!(
            old_state.cached_codeword_bytes(),
            old_state.cached_codeword_elements() * std::mem::size_of::<E>()
        );
        for count in [1, 4, 16] {
            let mut coins = Transcript::<F>::new_classical(&[41; 64]);
            let mut queries: Vec<Vec<_>> = (0..count)
                .map(|_| {
                    (0..vars)
                        .map(|_| {
                            let v = coins.get_vec_challenge(b"dense matrix", 2 * width * width);
                            MatrixPair {
                                zero: Matrix::new(width, v[..width * width].to_vec()).unwrap(),
                                one: Matrix::new(width, v[width * width..].to_vec()).unwrap(),
                            }
                        })
                        .collect()
                })
                .collect();
            // Shared ordered prefixes followed by independently dense suffixes.
            if vars > 1 {
                for i in 1..count {
                    for j in 0..vars - 1 {
                        queries[i][j] = queries[0][j].clone();
                    }
                }
            }
            let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
            let mut a = Transcript::<F>::new_classical(&[42; 64]);
            let mut b = Transcript::<F>::new_classical(&[42; 64]);
            let proof = pp
                .open_many::<Sha512>(&mut a, &root, &state, &queries, &values)
                .unwrap();
            let old = reference
                .open_many::<Sha512>(&mut b, &old_root, &old_state, &queries, &values)
                .unwrap();
            assert_eq!(
                bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap(),
                bincode::serde::encode_to_vec(old, bincode::config::standard()).unwrap(),
                "vars={vars} width={width} count={count}"
            );
            assert_eq!(fingerprint(&mut a), fingerprint(&mut b));
            let mut verifier = Transcript::<F>::new_classical(&[42; 64]);
            pp.verify_many::<Sha512>(&mut verifier, &root, &queries, &values, &proof)
                .unwrap();
        }
    }
}
#[test]
fn babybear_base_storage_exact_wire_equivalence() {
    base_storage_equivalence::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_base_storage_exact_wire_equivalence() {
    base_storage_equivalence::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

fn fingerprint<F: algebra::Field>(t: &mut Transcript<F>) -> [u8; 32] {
    let mut bytes = [0; 32];
    t.get_challenge_bytes(b"adapter complete transcript", &mut bytes);
    bytes
}
fn exercise<F, E>()
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for variables in [0, 3] {
        for width in [1, 2, 3, 4] {
            let pp = Parameters::<F, E>::new(variables, width, 2, 8).unwrap();
            let table = PackedTable::new(
                variables,
                width,
                (0..(width << variables))
                    .map(|i| F::from(i * i + 3 * i + 7))
                    .collect(),
            )
            .unwrap();
            let mut rng = StdRng::seed_from_u64(1030);
            let mut untouched_rng = rng.clone();
            let (root, state) =
                <Parameters<F, E> as CanonicalPcs<F, Sha256>>::commit(&pp, &table, &mut rng)
                    .unwrap();
            assert_eq!(rng.next_u64(), untouched_rng.next_u64());
            assert!(<Parameters<F, E> as CanonicalPcs<F, Sha256>>::opening_limit(&pp).is_none());
            let (again, _) = pp.commit::<Sha256>(&table).unwrap();
            assert_eq!(root.root, again.root);
            assert_eq!(state.table().values(), table.values());
            assert_eq!(
                state.cached_codeword_elements(),
                (width << variables.max(1)) * 2
            );
            let mut coins = Transcript::<F>::new_direct();
            for count in [1, 4, 16] {
                let queries: Vec<Vec<_>> = (0..count)
                    .map(|_| {
                        (0..variables)
                            .map(|_| {
                                let v = coins.get_vec_challenge(
                                    b"dense noncommuting matrices",
                                    2 * width * width,
                                );
                                MatrixPair {
                                    zero: Matrix::new(width, v[..width * width].to_vec()).unwrap(),
                                    one: Matrix::new(width, v[width * width..].to_vec()).unwrap(),
                                }
                            })
                            .collect()
                    })
                    .collect();
                let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
                let mut bad = values.clone();
                bad[count - 1][0] += F::one();
                let mut rejected = Transcript::new_direct();
                assert!(
                    pp.open_many::<Sha256>(&mut rejected, &root, &state, &queries, &bad)
                        .is_err()
                );
                assert_eq!(
                    fingerprint(&mut rejected),
                    fingerprint(&mut Transcript::<F>::new_direct())
                );
                let mut pt = Transcript::new_direct();
                let proof = pp
                    .open_many::<Sha256>(&mut pt, &root, &state, &queries, &values)
                    .unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (decoded, used): (Proof<E, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut vt = Transcript::new_direct();
                pp.verify_many::<Sha256>(&mut vt, &root, &queries, &values, &decoded)
                    .unwrap();
                assert_eq!(fingerprint(&mut pt), fingerprint(&mut vt));
                for foreign in [Commitment { root: [0; 32] }, Commitment { root: [1; 32] }] {
                    assert!(
                        pp.verify_many::<Sha256>(
                            &mut Transcript::new_direct(),
                            &foreign,
                            &queries,
                            &values,
                            &decoded
                        )
                        .is_err()
                    );
                }
                let mut broken = decoded.clone();
                broken.packed[0][0][0].path[0][0] ^= 1;
                assert!(
                    pp.verify_many::<Sha256>(
                        &mut Transcript::new_direct(),
                        &root,
                        &queries,
                        &values,
                        &broken
                    )
                    .is_err()
                );
                let mut broken = decoded.clone();
                broken.consistency.pop();
                assert!(
                    pp.verify_many::<Sha256>(
                        &mut Transcript::new_direct(),
                        &root,
                        &queries,
                        &values,
                        &broken
                    )
                    .is_err()
                );
                assert!(
                    pp.verify_many::<Sha256>(
                        &mut Transcript::new_direct(),
                        &root,
                        &queries,
                        &bad,
                        &decoded
                    )
                    .is_err()
                );
                let changed = Parameters::<F, E>::new(variables, width, 4, 8).unwrap();
                assert!(
                    changed
                        .open_many::<Sha256>(
                            &mut Transcript::new_direct(),
                            &root,
                            &state,
                            &queries,
                            &values
                        )
                        .is_err()
                );
                assert!(
                    changed
                        .verify_many::<Sha256>(
                            &mut Transcript::new_direct(),
                            &root,
                            &queries,
                            &values,
                            &decoded
                        )
                        .is_err()
                );
                if count > 1 && variables > 0 {
                    let mut reversed = queries.clone();
                    reversed.reverse();
                    let mut reversed_values = values.clone();
                    reversed_values.reverse();
                    assert!(
                        pp.verify_many::<Sha256>(
                            &mut Transcript::new_direct(),
                            &root,
                            &reversed,
                            &reversed_values,
                            &decoded
                        )
                        .is_err()
                    );
                }
            }
            assert!(
                pp.open_many::<Sha256>(&mut Transcript::new_direct(), &root, &state, &[], &[])
                    .is_err()
            );
        }
    }
}
#[test]
fn babybear_unmasked_adapter() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_unmasked_adapter() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
#[test]
fn invalid_geometry_is_rejected() {
    type P = Parameters<algebra::BabyBear, algebra::BabyBearExtension6>;
    for args in [
        (usize::MAX, 2, 2, 8),
        (2, 0, 2, 8),
        (2, usize::MAX, 2, 8),
        (0, 1usize << (usize::BITS / 2), 2, 8),
        (2, 2, 1, 8),
        (2, 2, 3, 8),
        (2, 2, 2, 0),
    ] {
        assert!(P::new(args.0, args.1, args.2, args.3).is_err());
    }
}

#[test]
fn canonical_backend_domains_are_disjoint() {
    use pcs::matrix_weighted::masked_polyfrim;
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    macro_rules! domains {
        ($p:ty) => {
            [
                <$p as CanonicalPcs<F, Sha256>>::LINEAR_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::NTT_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::RELATION_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::ACCUMULATOR_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::REGISTRY_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::CLAIM_DOMAIN,
                <$p as CanonicalPcs<F, Sha256>>::SEAL_DOMAIN,
            ]
        };
    }
    let all: std::collections::HashSet<_> = domains!(Parameters<F,E>)
        .into_iter()
        .chain(domains!(pcs::matrix_weighted::polyfrim::compact::Parameters<F,E>))
        .chain(domains!(masked_polyfrim::Parameters<F,E>))
        .chain(domains!(masked_polyfrim::joint::Parameters<F,E>))
        .chain(domains!(masked_polyfrim::aggregated::Parameters<F,E>))
        .chain(domains!(
            pcs::matrix_weighted::Parameters<pcs::utils::code::BlockReedSolomonCode<F>>
        ))
        .collect();
    assert_eq!(all.len(), 42);
}
