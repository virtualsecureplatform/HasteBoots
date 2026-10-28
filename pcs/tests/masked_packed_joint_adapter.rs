use algebra::{
    AbstractExtensionField, Field, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::masked_polyfrim::{Parameters, joint::Proof};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn query<F: NTTField>(variables: usize, width: usize, index: usize) -> Vec<MatrixPair<F>> {
    (0..variables)
        .map(|i| MatrixPair {
            zero: Matrix::new(
                width,
                (0..width * width)
                    .map(|j| F::from(3 * i + 2 * j + index + 1))
                    .collect(),
            )
            .unwrap(),
            one: Matrix::new(
                width,
                (0..width * width)
                    .map(|j| F::from(j * j + 5 * i + 2 * index + 3))
                    .collect(),
            )
            .unwrap(),
        })
        .collect()
}
fn exercise<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Parameters::<F, EF>::new(3, 2, 13, 2, 1, 21).unwrap();
    assert_eq!(pp.num_vars(), 3);
    assert_eq!(pp.physical_vars(), 13);
    assert_eq!(pp.width(), 2);
    let table = PackedTable::new(3, 2, (0..16).map(|i| F::from(i * i + 7)).collect()).unwrap();
    let (root, state) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(519))
        .unwrap();
    assert_eq!(state.table().values(), table.values());
    let mut first = 0;
    for count in [1, 4, 16] {
        let queries: Vec<_> = (first..first + count)
            .map(|i| query::<F>(3, 2, i))
            .collect();
        let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
        let mut false_values = values.clone();
        false_values[count - 1][0] += F::one();
        let mut attempted = Transcript::new_direct();
        let mut unchanged = Transcript::<F>::new_direct();
        assert!(
            pp.open_many_joint::<Sha256>(&mut attempted, &root, &state, &queries, &false_values)
                .is_err()
        );
        assert_eq!(state.spent().unwrap(), first);
        assert_eq!(
            attempted.get_challenge(b"atomic preflight"),
            unchanged.get_challenge(b"atomic preflight")
        );
        let mut prover = Transcript::new_direct();
        let proof = pp
            .open_many_joint::<Sha256>(&mut prover, &root, &state, &queries, &values)
            .unwrap();
        assert_eq!(
            proof.responses.iter().map(|p| p.index).collect::<Vec<_>>(),
            (first..first + count).collect::<Vec<_>>()
        );
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (decoded, used): (Proof<EF, [u8; 32]>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct();
        pp.verify_many_joint::<Sha256>(&mut verifier, &root, &queries, &values, &decoded)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after batch"),
            verifier.get_challenge(b"after batch")
        );
        println!(
            r#"HB_MASKED_PACKED_JOINT_ADAPTER {{"prime":{},"extension_degree":{},"logical_vars":3,"physical_vars":13,"width":2,"batch_size":{},"first_index":{},"root":"{}","context":"{}","proof_bytes":{},"proof_sha256":"{}","verified":true,"native_fhe":false,"shared_source_proximity":true,"full_query_aggregation":false,"whole_proof_security_certified":false}}"#,
            F::MODULUS_VALUE,
            EF::D,
            count,
            first,
            hex(&root.root),
            hex(&pp.context_digest::<Sha256>()),
            bytes.len(),
            digest(&bytes)
        );

        assert!(
            pp.verify_many_joint::<Sha256>(
                &mut Transcript::new_direct(),
                &root,
                &queries,
                &false_values,
                &decoded
            )
            .is_err()
        );
        let mut wrong_root = root.clone();
        wrong_root.root[0] ^= 1;
        assert!(
            pp.verify_many_joint::<Sha256>(
                &mut Transcript::new_direct(),
                &wrong_root,
                &queries,
                &values,
                &decoded
            )
            .is_err()
        );
        assert!(
            pp.open_many_joint::<Sha256>(
                &mut Transcript::new_direct(),
                &wrong_root,
                &state,
                &queries,
                &values
            )
            .is_err()
        );
        assert_eq!(state.spent().unwrap(), first + count);
        if count > 1 {
            let mut changed = decoded.clone();
            changed.responses.swap(0, 1);
            assert!(
                pp.verify_many_joint::<Sha256>(
                    &mut Transcript::new_direct(),
                    &root,
                    &queries,
                    &values,
                    &changed
                )
                .is_err()
            );
            let mut reordered = queries.clone();
            reordered.reverse();
            let mut claimed = values.clone();
            claimed.reverse();
            assert!(
                pp.verify_many_joint::<Sha256>(
                    &mut Transcript::new_direct(),
                    &root,
                    &reordered,
                    &claimed,
                    &decoded
                )
                .is_err()
            );
        }
        first += count;
    }
    let q = vec![query::<F>(3, 2, 30)];
    let v = vec![table.evaluate(&q[0]).unwrap()];
    let mut attempted = Transcript::new_direct();
    let mut unchanged = Transcript::<F>::new_direct();
    assert!(
        pp.open_many_joint::<Sha256>(&mut attempted, &root, &state, &q, &v)
            .is_err()
    );
    assert_eq!(state.spent().unwrap(), 21);
    assert_eq!(
        attempted.get_challenge(b"exhausted"),
        unchanged.get_challenge(b"exhausted")
    );
    // Constant logical tables still use one retained physical commitment.
    let pp = Parameters::<F, EF>::new(0, 1, 9, 2, 1, 1).unwrap();
    let table = PackedTable::new(0, 1, vec![F::from(19usize)]).unwrap();
    let (root, state) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(520))
        .unwrap();
    let proof = pp
        .open_many_joint::<Sha256>(
            &mut Transcript::new_direct(),
            &root,
            &state,
            &[vec![]],
            &[table.values().to_vec()],
        )
        .unwrap();
    pp.verify_many_joint::<Sha256>(
        &mut Transcript::new_direct(),
        &root,
        &[vec![]],
        &[table.values().to_vec()],
        &proof,
    )
    .unwrap();
}
#[test]
fn babybear_sextic_ordered_1_4_16() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_cubic_ordered_1_4_16() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
#[test]
fn equal_roots_cannot_alias_different_logical_contexts() {
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    let a = Parameters::<F, E>::new(1, 1, 9, 2, 1, 1).unwrap();
    let b = Parameters::<F, E>::new(2, 1, 9, 2, 1, 1).unwrap();
    let ta = PackedTable::new(1, 1, vec![F::new(7); 2]).unwrap();
    let tb = PackedTable::new(2, 1, vec![F::new(7); 4]).unwrap();
    let (ra, sa) = a
        .commit::<Sha256, _>(&ta, &mut StdRng::seed_from_u64(6))
        .unwrap();
    let (rb, sb) = b
        .commit::<Sha256, _>(&tb, &mut StdRng::seed_from_u64(6))
        .unwrap();
    assert_eq!(ra.root, rb.root);
    assert_ne!(a.context_digest::<Sha256>(), b.context_digest::<Sha256>());
    let q = vec![query::<F>(1, 1, 0)];
    let v = vec![ta.evaluate(&q[0]).unwrap()];
    let mut attempted = Transcript::new_direct();
    let mut unchanged = Transcript::new_direct();
    assert!(
        a.open_many_joint::<Sha256>(&mut attempted, &ra, &sb, &q, &v)
            .is_err()
    );
    assert_eq!(sa.spent().unwrap(), 0);
    assert_eq!(sb.spent().unwrap(), 0);
    assert_eq!(
        attempted.get_challenge(b"context"),
        unchanged.get_challenge(b"context")
    );
}
#[test]
fn concurrent_openers_share_one_lifetime() {
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    let pp = Arc::new(Parameters::<F, E>::new(1, 1, 10, 2, 1, 2).unwrap());
    let table = PackedTable::new(1, 1, vec![F::new(5), F::new(8)]).unwrap();
    let (root, state) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(912))
        .unwrap();
    let state = Arc::new(state);
    let queries = vec![query::<F>(1, 1, 0)];
    let values = vec![table.evaluate(&queries[0]).unwrap()];
    let jobs: Vec<_> = (0..4)
        .map(|_| {
            let pp = pp.clone();
            let state = state.clone();
            let root = root.clone();
            let queries = queries.clone();
            let values = values.clone();
            std::thread::spawn(move || {
                let mut t = Transcript::new_direct();
                pp.open_many_joint::<Sha256>(&mut t, &root, &state, &queries, &values)
                    .map(|p| (p, t.get_challenge(b"concurrent after")))
            })
        })
        .collect();
    let mut indices = Vec::new();
    let mut errors = 0;
    for job in jobs {
        match job.join().unwrap() {
            Ok((p, after)) => {
                let mut t = Transcript::new_direct();
                pp.verify_many_joint::<Sha256>(&mut t, &root, &queries, &values, &p)
                    .unwrap();
                assert_eq!(after, t.get_challenge(b"concurrent after"));
                indices.push(p.responses[0].index);
            }
            Err(_) => errors += 1,
        }
    }
    indices.sort();
    assert_eq!(indices, vec![0, 1]);
    assert_eq!(errors, 2);
    assert_eq!(state.spent().unwrap(), 2);
}

#[test]
fn mixed_apis_share_one_private_lifetime() {
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    let pp = Parameters::<F, E>::new(1, 1, 10, 2, 1, 2).unwrap();
    let table = PackedTable::new(1, 1, vec![F::new(5), F::new(8)]).unwrap();
    let (root, state) = pp
        .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(913))
        .unwrap();
    let queries = vec![query::<F>(1, 1, 0)];
    let values = vec![table.evaluate(&queries[0]).unwrap()];
    let mut old_pt = Transcript::new_direct();
    let old = pp
        .open_many::<Sha256>(&mut old_pt, &root, &state, &queries, &values)
        .unwrap();
    assert_eq!(old.openings[0].index, 0);
    let mut old_vt = Transcript::new_direct();
    pp.verify_many::<Sha256>(&mut old_vt, &root, &queries, &values, &old)
        .unwrap();
    assert_eq!(
        old_pt.get_challenge(b"old mixed after"),
        old_vt.get_challenge(b"old mixed after")
    );
    let mut pt = Transcript::new_direct();
    let joint = pp
        .open_many_joint::<Sha256>(&mut pt, &root, &state, &queries, &values)
        .unwrap();
    assert_eq!(joint.first, 1);
    let mut vt = Transcript::new_direct();
    pp.verify_many_joint::<Sha256>(&mut vt, &root, &queries, &values, &joint)
        .unwrap();
    assert_eq!(
        pt.get_challenge(b"joint mixed after"),
        vt.get_challenge(b"joint mixed after")
    );
    assert_eq!(state.spent().unwrap(), 2);
    let mut attempted = Transcript::new_direct();
    let mut unchanged = Transcript::<F>::new_direct();
    assert!(
        pp.open_many::<Sha256>(&mut attempted, &root, &state, &queries, &values)
            .is_err()
    );
    assert!(
        pp.open_many_joint::<Sha256>(&mut attempted, &root, &state, &queries, &values)
            .is_err()
    );
    assert_eq!(state.spent().unwrap(), 2);
    assert_eq!(
        attempted.get_challenge(b"mixed exhausted"),
        unchanged.get_challenge(b"mixed exhausted")
    );
}
