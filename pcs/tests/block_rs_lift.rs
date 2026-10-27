//! Algebraic lifting step only: this is not an extraction/proximity theorem.
use algebra::{AbstractExtensionField, NTTField, transformation::AbstractNTT};
use helper::{FiatShamirTranscript, Transcript};
use pcs::utils::code::{BlockReedSolomonCode, RowCode};
use serde::Serialize;

fn check<F: NTTField + Serialize, K: AbstractExtensionField<F>>() {
    let k = K::D;
    let source_rows = 3;
    let columns = 16 * k;
    let code = BlockReedSolomonCode::<F>::new(columns, k, 2).unwrap();
    assert_eq!(code.message_len(), k * code.message_blocks());
    let length = code.codeword_blocks();
    let mut transcript = Transcript::<F>::new_direct();
    let source = transcript.get_vec_challenge(b"lift source coefficients", source_rows * columns);
    let random = transcript.get_vec_challenge(b"lift base random matrix", k * source_rows);
    let basis: Vec<K> = (0..k)
        .map(|i| K::from_base_fn(|j| if i == j { F::one() } else { F::zero() }))
        .collect();
    // This basis-coordinate map is a bijection F^k -> K for each source row.
    let alpha: Vec<K> = (0..source_rows)
        .map(|r| K::from_base_fn(|i| random[i * source_rows + r]))
        .collect();
    for r in 0..source_rows {
        for i in 0..k {
            assert_eq!(alpha[r].as_base_slice()[i], random[i * source_rows + r]);
        }
    }
    let encode = |row: &[F]| {
        let mut out = vec![F::zero(); length * k];
        code.encode_row(row, &mut out);
        out
    };
    let lift = |row: &[F]| row.chunks_exact(k).map(K::from_base_slice).collect::<Vec<_>>();
    let message_rows: Vec<_> = source.chunks_exact(columns).map(lift).collect();
    let encoded_rows: Vec<_> = source.chunks_exact(columns).map(|row| lift(&encode(row))).collect();
    let tests: Vec<Vec<F>> = (0..k)
        .map(|i| (0..columns).map(|j| {
            (0..source_rows).fold(F::zero(), |acc, r| {
                acc + random[i * source_rows + r] * source[r * columns + j]
            })
        }).collect())
        .collect();
    let encoded_tests: Vec<_> = tests.iter().map(|row| lift(&encode(row))).collect();
    let message_tests: Vec<_> = tests.iter().map(|row| lift(row)).collect();
    let combined_message: Vec<K> = (0..code.message_blocks())
        .map(|j| (0..source_rows).fold(K::zero(), |acc, r| acc + alpha[r] * message_rows[r][j]))
        .collect();
    for j in 0..code.message_blocks() {
        assert_eq!(combined_message[j],
            (0..k).fold(K::zero(), |acc, i| acc + basis[i] * message_tests[i][j]));
    }
    // Recover the NTT's ordering using X, check the complete point set, and
    // evaluate the lifted polynomial by Horner rather than an extension NTT.
    let table = F::get_ntt_table(length.ilog2()).unwrap();
    let mut points = vec![F::zero(); length];
    points[1] = F::one();
    table.transform_slice(&mut points);
    let mut expected_points = Vec::new();
    let mut point = table.root();
    let step = point * point;
    for _ in 0..length {
        expected_points.push(point);
        point *= step;
    }
    let mut sorted = points.clone();
    sorted.sort();
    expected_points.sort();
    assert_eq!(sorted, expected_points);
    let wrong_alpha: Vec<K> = (0..source_rows)
        .map(|r| K::from_base_fn(|i| random[r * k + i]))
        .collect();
    let mut wrong_order_differs = false;
    for (j, &point) in points.iter().enumerate() {
        let expected = combined_message.iter().rev()
            .fold(K::zero(), |acc, &coefficient| acc * K::from_base(point) + coefficient);
        let from_tests = (0..k).fold(K::zero(), |acc, i| acc + basis[i] * encoded_tests[i][j]);
        let from_columns = (0..source_rows).fold(K::zero(), |acc, r| acc + alpha[r] * encoded_rows[r][j]);
        assert_eq!(from_tests, expected);
        assert_eq!(from_columns, expected);
        let wrong = (0..source_rows).fold(K::zero(), |acc, r| acc + wrong_alpha[r] * encoded_rows[r][j]);
        wrong_order_differs |= wrong != expected;
    }
    assert!(wrong_order_differs, "row-major random matrix must not be transposed");
    // A changed authenticated coordinate affects the lifted check at that
    // column; no assertion about adversarially chosen responses follows here.
    assert_ne!(alpha[0], K::zero());
    let mut corrupt = encoded_rows;
    corrupt[0][3] += basis[1];
    let from_corrupt = (0..source_rows).fold(K::zero(), |acc, r| acc + alpha[r] * corrupt[r][3]);
    let from_tests = (0..k).fold(K::zero(), |acc, i| acc + basis[i] * encoded_tests[i][3]);
    assert_ne!(from_corrupt, from_tests);
}

#[test]
fn babybear_eight_base_tests_lift_to_one_full_field_test() {
    check::<algebra::BabyBear, algebra::BabyBearExtension8>();
}

#[test]
fn goldilocks_four_base_tests_lift_to_one_full_field_test() {
    check::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
}
