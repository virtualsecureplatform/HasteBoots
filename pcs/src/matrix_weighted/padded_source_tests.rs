//! Authentic RS columns with forbidden padded coefficients must still reject.
use super::*;
use algebra::{Field, matrix_weighted::Matrix};
use sha2::Sha512;

fn check<F: NTTField + Serialize + for<'de> Deserialize<'de>>(width: usize, block: usize) {
    let code = BlockReedSolomonCode::<F>::new(1, block, 2).unwrap();
    let pp = Parameters::new_encoded::<F>(1, width, 1, 4, code).unwrap();
    let table = PackedTable::new(1, width, vec![F::zero(); 2 * width]).unwrap();
    let (control_root, mut state) = pp.commit::<F, Sha512>(&table).unwrap();
    let zero = Matrix::new(width, vec![F::zero(); width * width]).unwrap();
    let query = vec![MatrixPair {
        zero: zero.clone(),
        one: zero,
    }];
    let value = vec![F::zero(); width];
    let transcript = || Transcript::<F>::new_classical(&[37; 64]);
    let control = pp
        .open(&mut transcript(), &control_root, &state, &query, &value)
        .unwrap();
    pp.verify::<F, Sha512>(&mut transcript(), &control_root, &query, &value, &control)
        .unwrap();

    // Same one-block RS degree/domain, but permit all block coefficients.
    // Coordinate one is a forbidden padding position for message_len=1.
    let full = BlockReedSolomonCode::<F>::new(block, block, 2).unwrap();
    assert_eq!(full.message_blocks(), pp.code.message_blocks());
    let length = pp.code.codeword_blocks();
    assert_eq!(full.codeword_blocks(), length);
    let stride = length * block;
    let mut coefficients = vec![F::zero(); block];
    coefficients[1] = F::one();
    full.encode_row(&coefficients, &mut state.encoded[..stride]);
    for symbol in state.encoded[..stride].chunks_exact(block) {
        assert_eq!(symbol[1], F::one()); // A constant, valid RS coordinate.
        assert!(
            symbol
                .iter()
                .enumerate()
                .all(|(i, &x)| i == 1 || x == F::zero())
        );
    }
    let rows = 2 * width;
    let leaves: Vec<_> = (0..length)
        .map(|index| {
            let column: Vec<_> = (0..rows)
                .flat_map(|row| {
                    state.encoded[row * stride + index * block..row * stride + (index + 1) * block]
                        .iter()
                        .copied()
                })
                .collect();
            hash_column::<F, Sha512>(&column)
        })
        .collect();
    state.tree.generate(&leaves);
    let root = Commitment {
        root: state.tree.root,
    };
    assert_ne!(root.root, control_root.root);

    // The structured query is zero: it cannot expose padding on its own.
    // Fresh random responses still come from the claimed all-zero table.
    let proof = pp
        .open(&mut transcript(), &root, &state, &query, &value)
        .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Opening<F, <Sha512 as Hash>::Output>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut replay = transcript();
    pp.bind::<F, Sha512>(&mut replay, &root, &query, &value)
        .unwrap();
    let random = replay.get_vec_challenge(b"mw random linear test", width * rows);
    assert!((0..width).any(|lane| random[lane * rows] != F::zero()));
    replay.append_message(b"mw linear responses", &(&proof.test, &proof.evaluation));
    let indices = sample_columns(&mut replay, length, pp.queries);
    assert_eq!(indices.len(), proof.columns.len());
    for (&index, column) in indices.iter().zip(&proof.columns) {
        assert_eq!(column.path[0], hash_column::<F, Sha512>(&column.values));
        assert!(MerkleTree::<Sha512>::check(&root.root, index, &column.path));
        assert_eq!(column.values[1], F::one());
    }
    assert!(proof.evaluation.iter().all(|&x| x == F::zero()));
    let error = pp
        .verify::<F, Sha512>(&mut transcript(), &root, &query, &value, &proof)
        .unwrap_err();
    assert_eq!(error.0, "linear response inconsistent with committed block");
}

#[test]
fn babybear_padding_is_checked_with_authentic_rs_columns() {
    check::<algebra::BabyBear>(8, 8);
    check::<algebra::BabyBear>(6, 8);
}

#[test]
fn goldilocks_padding_is_checked_with_authentic_rs_columns() {
    check::<algebra::Goldilocks>(4, 4);
    check::<algebra::Goldilocks>(3, 4);
}
