use super::*;
use algebra::{BabyBear, Field, Goldilocks};
use sha2::Sha256;

fn check<F: NTTField + Serialize>(lazy_zero: Option<F>) {
    for n in [6, 10, 14] {
        for width in [1, 4, 8] {
            let left = if n == 14 { 3 } else { n / 2 };
            let code = BlockReedSolomonCode::<F>::new(1 << (n - left), 3, 2).unwrap();
            let pp = Parameters::new_encoded::<F>(n, width, left, 4, code).unwrap();
            let size = (1 << n) * width;
            let mut sparse = vec![F::zero(); size];
            sparse[size - 1] = F::one();
            let mut cases = vec![
                vec![F::zero(); size],
                sparse,
                (0..size).map(|i| F::from(i + 1)).collect(),
            ];
            if let Some(zero) = lazy_zero {
                cases.push(vec![zero; size]);
            }
            for values in cases {
                let table = PackedTable::new(n, width, values).unwrap();
                let (commitment, state) = pp.commit::<F, Sha256>(&table).unwrap();
                let rows = (1 << left) * width;
                let block = pp.code.block_width();
                let length = pp.code.codeword_blocks();
                let stride = block * length;
                // Original row encoder and per-column hashing, without sharing.
                let mut encoded = vec![F::zero(); rows * stride];
                for row in 0..rows {
                    let input: Vec<_> = (0..pp.code.message_len())
                        .map(|right| table.at(row / width + (right << left))[row % width])
                        .collect();
                    pp.code
                        .encode_row(&input, &mut encoded[row * stride..(row + 1) * stride]);
                }
                assert_eq!(
                    bincode::serde::encode_to_vec(&state.encoded, bincode::config::standard())
                        .unwrap(),
                    bincode::serde::encode_to_vec(&encoded, bincode::config::standard()).unwrap(),
                );
                let leaves: Vec<_> = (0..length)
                    .map(|column| {
                        let values: Vec<_> = (0..rows)
                            .flat_map(|row| {
                                encoded[row * stride + column * block
                                    ..row * stride + (column + 1) * block]
                                    .iter()
                                    .copied()
                            })
                            .collect();
                        hash_column::<F, Sha256>(&values)
                    })
                    .collect();
                for tile in [1, 3, 4, 8] {
                    assert_eq!(
                        hash_columns::<F, Sha256>(&encoded, rows, length, block, tile),
                        leaves
                    );
                }
                let mut reference = MerkleTree::<Sha256>::new();
                reference.generate(&leaves);
                assert_eq!(commitment.root, reference.root);
                assert_eq!(state.tree.tree, reference.tree);
                assert_eq!(state.tree.depth, reference.depth);
                assert_eq!(state.tree.input_size, reference.input_size);
                for column in 0..length {
                    assert_eq!(state.tree.query(column), reference.query(column));
                }
            }
        }
    }
}
#[test]
fn zero_columns_preserve_every_babybear_leaf_and_path() {
    check::<BabyBear>(None);
}
#[test]
fn zero_columns_preserve_every_goldilocks_leaf_and_path() {
    check::<Goldilocks>(Some(Goldilocks::new(Goldilocks::MODULUS_VALUE)));
}
