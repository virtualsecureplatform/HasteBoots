use algebra::{
    BabyBear as F, Field,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{Opening, Parameters},
    utils::code::{BlockReedSolomonCode, ReedSolomonCode, RowCode},
};
use sha2::Sha256;

fn query(n: usize, k: usize) -> Vec<MatrixPair<F>> {
    (0..n)
        .map(|i| MatrixPair {
            zero: Matrix::new(
                k,
                (0..k * k)
                    .map(|j| F::new((i * 17 + j + 1) as u32))
                    .collect(),
            )
            .unwrap(),
            one: Matrix::new(
                k,
                (0..k * k)
                    .map(|j| F::new((i * 13 + j + 23) as u32))
                    .collect(),
            )
            .unwrap(),
        })
        .collect()
}

#[test]
fn block_openings_authenticate_every_coordinate_and_parameter_binding() {
    for (n, width, left, block) in [(0, 5, 0, 5), (4, 5, 2, 5), (7, 6, 3, 6), (8, 5, 3, 4)] {
        let cols = 1usize << (n - left);
        let code = BlockReedSolomonCode::<F>::new(cols, block, 2).unwrap();
        let blocks = code.codeword_blocks();
        let params = Parameters::new_encoded::<F>(n, width, left, blocks * 10, code).unwrap();
        let table = PackedTable::new(
            n,
            width,
            (0..(1 << n) * width)
                .map(|i| F::new(i as u32 + 1))
                .collect(),
        )
        .unwrap();
        let (commitment, state) = params.commit::<F, Sha256>(&table).unwrap();
        let query = query(n, width);
        let value = table.evaluate(&query).unwrap();
        let mut prover = Transcript::new();
        let proof = params
            .open::<F, Sha256>(&mut prover, &commitment, &state, &query, &value)
            .unwrap();
        let mut verifier = Transcript::new();
        params
            .verify::<F, Sha256>(&mut verifier, &commitment, &query, &value, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        assert_eq!(proof.columns[0].values.len(), (1 << left) * width * block);
        for coordinate in 0..block {
            let mut bad = proof.clone();
            bad.columns[0].values[coordinate] += F::new(1);
            assert!(
                params
                    .verify::<F, Sha256>(&mut Transcript::new(), &commitment, &query, &value, &bad)
                    .is_err()
            );
        }
        let changed = Parameters::new_encoded::<F>(
            n,
            width,
            left,
            blocks * 10 + 1,
            BlockReedSolomonCode::<F>::new(cols, block, 2).unwrap(),
        )
        .unwrap();
        assert!(
            changed
                .open::<F, Sha256>(&mut Transcript::new(), &commitment, &state, &query, &value)
                .is_err()
        );
        assert!(
            changed
                .verify::<F, Sha256>(&mut Transcript::new(), &commitment, &query, &value, &proof)
                .is_err()
        );
    }
}

#[test]
fn matrix_weighted_openings_all_splits_and_shapes() {
    for n in [0, 1, 3, 4] {
        for k in [1, 2, 5] {
            for left in 0..=n {
                let cols = 1usize << (n - left);
                // Non-power-of-two encoded column counts exercise padded Merkle trees.
                let pp =
                    Parameters::new::<F>(n, k, left, 12, ReedSolomonCode::new(cols, 2 * cols + 1))
                        .unwrap();
                let table = PackedTable::new(
                    n,
                    k,
                    (0..(1 << n) * k).map(|i| F::new((i + 2) as u32)).collect(),
                )
                .unwrap();
                let (commitment, state) = pp.commit::<_, Sha256>(&table).unwrap();
                let query = query(n, k);
                let value = table.evaluate(&query).unwrap();
                let mut prover = Transcript::new();
                let proof = pp
                    .open::<_, Sha256>(&mut prover, &commitment, &state, &query, &value)
                    .unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, consumed): (Opening<F, [u8; 32]>, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(consumed, bytes.len());
                let mut verifier = Transcript::new();
                pp.verify::<_, Sha256>(&mut verifier, &commitment, &query, &value, &proof)
                    .unwrap();
                assert_eq!(
                    prover.get_challenge(b"after"),
                    verifier.get_challenge(b"after")
                );
            }
        }
    }
}

#[test]
fn opening_rejects_tampering_and_malformed_shapes() {
    let pp = Parameters::new::<F>(4, 2, 2, 20, ReedSolomonCode::new(4, 8)).unwrap();
    let table = PackedTable::new(4, 2, (1..=32).map(F::new).collect()).unwrap();
    let (commitment, state) = pp.commit::<_, Sha256>(&table).unwrap();
    let query = query(4, 2);
    let value = table.evaluate(&query).unwrap();
    let proof = pp
        .open::<_, Sha256>(&mut Transcript::new(), &commitment, &state, &query, &value)
        .unwrap();
    let check = |proof: &Opening<F, [u8; 32]>| {
        pp.verify::<_, Sha256>(&mut Transcript::new(), &commitment, &query, &value, proof)
            .is_err()
    };
    let mut bad = proof.clone();
    bad.test[0] += F::new(1);
    assert!(check(&bad));
    let mut bad = proof.clone();
    bad.evaluation[0] += F::new(1);
    assert!(check(&bad));
    let mut bad = proof.clone();
    bad.columns[0].values[0] += F::new(1);
    assert!(check(&bad));
    let mut bad = proof.clone();
    bad.columns[0].path[0][0] ^= 1;
    assert!(check(&bad));
    let mut bad = proof.clone();
    bad.columns[0].path.clear();
    assert!(check(&bad));
    let mut bad = proof.clone();
    bad.columns.pop();
    assert!(check(&bad));
    let mut bad = proof.clone();
    bad.test.clear();
    assert!(check(&bad));
    let mut value = value;
    value[0] += F::new(1);
    assert!(
        pp.verify::<_, Sha256>(&mut Transcript::new(), &commitment, &query, &value, &proof)
            .is_err()
    );
}

#[test]
fn balanced_block_layout_is_supported_and_reduces_opening_payload() {
    let balanced = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(18, 8, 512, 2).unwrap();
    assert!(balanced.left_vars() < 9);
    assert_eq!(
        balanced.code().message_len(),
        1 << (18 - balanced.left_vars())
    );
    let cost = |left: usize| {
        let cols = 1usize << (18 - left);
        let code = BlockReedSolomonCode::<F>::new(cols, 8, 2).unwrap();
        2 * 8 * cols + 512.min(code.codeword_blocks()) * (1 << left) * 8 * 8
    };
    assert!(cost(balanced.left_vars()) < cost(9));
    assert!(
        Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(usize::BITS as usize, 8, 512, 2)
            .is_err()
    );
    assert!(Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(4, 0, 512, 2).is_err());
}

#[test]
fn batch_openings_share_prefixes_and_check_every_claim() {
    use pcs::matrix_weighted::BatchOpening;
    for left in [0, 2, 4] {
        let pp = Parameters::new::<F>(
            4,
            2,
            left,
            64,
            ReedSolomonCode::new(1 << (4 - left), 2 * (1 << (4 - left)) + 1),
        )
        .unwrap();
        let table = PackedTable::new(4, 2, (1..=32).map(F::new).collect()).unwrap();
        let (commitment, state) = pp.commit::<_, Sha256>(&table).unwrap();
        let first = query(4, 2);
        let mut second = first.clone();
        second[3].zero = Matrix::identity(2).unwrap();
        let mut third = first.clone();
        third[0].one = Matrix::identity(2).unwrap();
        let queries = vec![first.clone(), first, second, third];
        let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
        let mut prover = Transcript::new();
        let proof = pp
            .open_many::<_, Sha256>(&mut prover, &commitment, &state, &queries, &values)
            .unwrap();
        assert_eq!(
            proof.evaluations.len(),
            match left {
                0 => 1,
                2 => 2,
                _ => 3,
            }
        );
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used): (BatchOpening<F, [u8; 32]>, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new();
        pp.verify_many::<_, Sha256>(&mut verifier, &commitment, &queries, &values, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        let check = |p: &BatchOpening<F, [u8; 32]>| {
            pp.verify_many::<_, Sha256>(&mut Transcript::new(), &commitment, &queries, &values, p)
                .is_err()
        };
        for group in 0..proof.evaluations.len() {
            let mut bad = proof.clone();
            bad.evaluations[group][0] += F::new(1);
            assert!(check(&bad));
        }
        let mut bad = proof.clone();
        bad.test[0] += F::new(1);
        assert!(check(&bad));
        let mut bad = proof.clone();
        bad.columns[0].values[0] += F::new(1);
        assert!(check(&bad));
        let mut bad = proof.clone();
        bad.evaluations.pop();
        assert!(check(&bad));
        let mut bad = proof.clone();
        bad.columns.clear();
        assert!(check(&bad));
        let mut bad = proof.clone();
        bad.columns[0].path.clear();
        assert!(check(&bad));
        for index in 0..values.len() {
            let mut changed = values.clone();
            changed[index][0] += F::new(1);
            assert!(
                pp.verify_many::<_, Sha256>(
                    &mut Transcript::new(),
                    &commitment,
                    &queries,
                    &changed,
                    &proof
                )
                .is_err()
            );
            assert!(
                pp.open_many::<_, Sha256>(
                    &mut Transcript::new(),
                    &commitment,
                    &state,
                    &queries,
                    &changed
                )
                .is_err()
            );
        }
        let mut changed = queries.clone();
        changed.reverse();
        assert!(
            pp.verify_many::<_, Sha256>(
                &mut Transcript::new(),
                &commitment,
                &changed,
                &values,
                &proof
            )
            .is_err()
        );
        assert!(
            pp.verify_many::<_, Sha256>(&mut Transcript::new(), &commitment, &[], &[], &proof)
                .is_err()
        );
        assert!(
            pp.open_many::<_, Sha256>(&mut Transcript::new(), &commitment, &state, &[], &[])
                .is_err()
        );
        assert!(
            pp.verify_many::<_, Sha256>(
                &mut Transcript::new(),
                &commitment,
                &queries[..1],
                &values,
                &proof
            )
            .is_err()
        );
    }
}
