use algebra::{BabyBear, Field, Goldilocks, NTTField, transformation::AbstractNTT};
use pcs::utils::code::{BlockReedSolomonCode, RowCode};

fn check<F: NTTField>() {
    for (message_len, width, blowup) in
        [(1, 1, 2), (11, 5, 2), (32, 6, 4), (129, 7, 2), (512, 5, 2)]
    {
        let code = BlockReedSolomonCode::<F>::new(message_len, width, blowup).unwrap();
        let length = code.codeword_blocks();
        let input: Vec<_> = (0..message_len).map(|i| F::from(i * 7 + 3)).collect();
        let other: Vec<_> = (0..message_len).map(|i| F::from(i * i + 9)).collect();
        let sum: Vec<_> = input.iter().zip(&other).map(|(&a, &b)| a + b).collect();
        let mut encoded = vec![F::zero(); length * width];
        let mut encoded_other = encoded.clone();
        let mut encoded_sum = encoded.clone();
        code.encode_row(&input, &mut encoded);
        code.encode_row(&other, &mut encoded_other);
        code.encode_row(&sum, &mut encoded_sum);
        assert_eq!(
            encoded_sum,
            encoded
                .iter()
                .zip(&encoded_other)
                .map(|(&a, &b)| a + b)
                .collect::<Vec<_>>()
        );

        // Recover the ordered NTT domain with the polynomial X, then verify the
        // full encoding with independent Horner evaluation, not a second NTT.
        let table = F::get_ntt_table(length.ilog2()).unwrap();
        let mut domain = vec![F::zero(); length];
        domain[1] = F::one();
        table.transform_slice(&mut domain);
        let mut expected_points = Vec::with_capacity(length);
        let root = table.root();
        let step = root * root;
        let mut point = root;
        for _ in 0..length {
            expected_points.push(point);
            point *= step;
        }
        let mut sorted = domain.clone();
        sorted.sort();
        expected_points.sort();
        assert_eq!(sorted, expected_points);
        sorted.dedup();
        assert_eq!(sorted.len(), length);
        for (column, &point) in domain.iter().enumerate() {
            for lane in 0..width {
                let value = (0..code.message_blocks())
                    .rev()
                    .fold(F::zero(), |acc, block| {
                        acc * point
                            + input
                                .get(block * width + lane)
                                .copied()
                                .unwrap_or_else(F::zero)
                    });
                assert_eq!(encoded[column * width + lane], value);
            }
        }
        let different = encoded
            .chunks_exact(width)
            .zip(encoded_other.chunks_exact(width))
            .filter(|(a, b)| a != b)
            .count();
        assert!(different >= length - code.message_blocks() + 1);
    }
}

#[test]
fn block_rs_matches_polynomial_evaluation_and_is_base_linear() {
    check::<BabyBear>();
    check::<Goldilocks>();
}

#[test]
fn block_rs_rejects_invalid_or_unsupported_dimensions() {
    for (n, k, blowup) in [
        (0, 4, 2),
        (10, 0, 2),
        (10, 4, 1),
        (10, 4, 3),
        (usize::MAX, 1, 2),
    ] {
        assert!(BlockReedSolomonCode::<BabyBear>::new(n, k, blowup).is_err());
    }
    assert!(BlockReedSolomonCode::<BabyBear>::new(1usize << 27, 1, 2).is_err());
}

// Retain the pre-shortcut NTT path as a wire-level reference. Equality of field
// elements alone does not detect Goldilocks lazy-representation differences.
fn legacy_encode<F: NTTField>(code: &BlockReedSolomonCode<F>, input: &[F]) -> Vec<F> {
    let n = code.codeword_blocks();
    let k = code.block_width();
    let table = F::get_ntt_table(n.ilog2()).unwrap();
    let mut encoded = vec![F::zero(); n * k];
    for lane in 0..k {
        let mut coordinate = vec![F::zero(); n];
        for (block, chunk) in input.chunks(k).enumerate() {
            if let Some(&value) = chunk.get(lane) {
                coordinate[block] = value;
            }
        }
        table.transform_slice(&mut coordinate);
        for (symbol, value) in encoded.chunks_exact_mut(k).zip(coordinate) {
            symbol[lane] = value;
        }
    }
    encoded
}
fn check_zero_rows<F: NTTField + serde::Serialize>() {
    for (len, width, blowup) in [(1, 1, 2), (64, 4, 2), (4096, 8, 2), (2048, 1, 4)] {
        let code = BlockReedSolomonCode::<F>::new(len, width, blowup).unwrap();
        for input in [
            vec![F::zero(); len],
            (0..len)
                .map(|i| {
                    if i % 3 == 0 {
                        F::zero()
                    } else {
                        F::from(i + 1)
                    }
                })
                .collect(),
        ] {
            let mut encoded = vec![F::one(); code.codeword_blocks() * width];
            code.encode_row(&input, &mut encoded);
            let expected = legacy_encode(&code, &input);
            assert_eq!(
                bincode::serde::encode_to_vec(&encoded, bincode::config::standard()).unwrap(),
                bincode::serde::encode_to_vec(&expected, bincode::config::standard()).unwrap(),
            );
        }
    }
}
#[test]
fn zero_rows_preserve_legacy_ntt_wire_values() {
    check_zero_rows::<BabyBear>();
    check_zero_rows::<Goldilocks>();
    let code = BlockReedSolomonCode::<Goldilocks>::new(64, 4, 2).unwrap();
    let input = vec![Goldilocks::new(Goldilocks::MODULUS_VALUE); 64];
    let mut encoded = vec![Goldilocks::from(1usize); code.codeword_blocks() * 4];
    code.encode_row(&input, &mut encoded);
    assert_eq!(
        bincode::serde::encode_to_vec(&encoded, bincode::config::standard()).unwrap(),
        bincode::serde::encode_to_vec(legacy_encode(&code, &input), bincode::config::standard())
            .unwrap(),
    );
}
