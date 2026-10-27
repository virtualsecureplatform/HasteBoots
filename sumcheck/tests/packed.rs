use algebra::{
    BabyBear as F, Field,
    matrix_weighted::{Matrix, MatrixPair, PackedTable, matrix_weights},
};
use helper::{FiatShamirTranscript, Transcript};
use sumcheck::packed::{self, PackedShape};
use sumcheck::packed_zero;

fn table(n: usize, k: usize, offset: u32) -> PackedTable<F> {
    PackedTable::new(
        n,
        k,
        (0..(1 << n) * k)
            .map(|i| F::new((i as u32 + offset) % 97))
            .collect(),
    )
    .unwrap()
}

#[test]
fn packed_roundtrip_and_authenticated_terminal() {
    for n in [0, 1, 3, 5] {
        for k in [1, 2, 5] {
            for d in [1, 2, 3] {
                let factors: Vec<_> = (0..d).map(|i| table(n, k, 3 + i as u32 * 7)).collect();
                let shape = PackedShape {
                    num_vars: n,
                    width: k,
                    num_factors: d,
                    terms: vec![(F::new(7), (0..d).collect()), (-F::new(3), vec![0])],
                };
                let sum = packed::sum(&shape, &factors).unwrap();
                let mut prover = Transcript::new();
                let (proof, p) = packed::prove(&mut prover, &shape, &factors, &sum).unwrap();
                let mut verifier = Transcript::new();
                let v = packed::verify(&mut verifier, &shape, &sum, &proof).unwrap();
                assert_eq!(p.query, v.query);
                let terminal = factors
                    .iter()
                    .map(|t| t.evaluate(&v.query).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(shape.evaluate(&terminal).unwrap(), v.expected);
                assert_eq!(
                    prover.get_challenge(b"after"),
                    verifier.get_challenge(b"after")
                );
            }
        }
    }
}

#[test]
fn rejects_malformed_and_changed_claims() {
    let shape = PackedShape {
        num_vars: 3,
        width: 5,
        num_factors: 2,
        terms: vec![(F::new(1), vec![0, 1])],
    };
    let factors = vec![table(3, 5, 2), table(3, 5, 17)];
    let sum = packed::sum(&shape, &factors).unwrap();
    let (proof, _) = packed::prove(&mut Transcript::new(), &shape, &factors, &sum).unwrap();
    let mut bad = proof.clone();
    bad.rounds.pop();
    assert!(packed::verify(&mut Transcript::new(), &shape, &sum, &bad).is_err());
    let mut bad = proof.clone();
    bad.rounds.push(bad.rounds[0].clone());
    assert!(packed::verify(&mut Transcript::new(), &shape, &sum, &bad).is_err());
    let mut bad = proof.clone();
    bad.rounds[0].pop();
    assert!(packed::verify(&mut Transcript::new(), &shape, &sum, &bad).is_err());
    let mut bad = proof.clone();
    bad.rounds[1][2] += F::new(1);
    assert!(packed::verify(&mut Transcript::new(), &shape, &sum, &bad).is_err());
    let mut wrong_sum = sum.clone();
    wrong_sum[0] += F::new(1);
    assert!(packed::verify(&mut Transcript::new(), &shape, &wrong_sum, &proof).is_err());
    let mut changed = Transcript::new();
    changed.append_message(b"statement", &123u64);
    // First consistency check still holds, but subsequent round consistency must fail.
    assert!(packed::verify(&mut changed, &shape, &sum, &proof).is_err());
    let mut false_witness = factors.clone();
    false_witness[0] = table(3, 5, 89);
    assert!(packed::prove(&mut Transcript::new(), &shape, &false_witness, &sum).is_err());
}

#[test]
fn noncommuting_matrix_order_matches_explicit_weights() {
    let a = MatrixPair {
        zero: Matrix::new(2, [1, 2, 0, 1].map(F::new).to_vec()).unwrap(),
        one: Matrix::new(2, [2, 1, 1, 0].map(F::new).to_vec()).unwrap(),
    };
    let b = MatrixPair {
        zero: Matrix::new(2, [0, 1, 1, 3].map(F::new).to_vec()).unwrap(),
        one: Matrix::new(2, [1, 0, 2, 1].map(F::new).to_vec()).unwrap(),
    };
    let query = vec![a.clone(), b.clone()];
    let t = table(2, 2, 11);
    let weights = matrix_weights(2, &query).unwrap();
    assert_eq!(weights[1], b.zero.mul(&a.one).unwrap());
    let mut expected = vec![F::new(0); 2];
    for (i, w) in weights.iter().enumerate() {
        w.add_mul(t.at(i), &mut expected);
    }
    assert_eq!(t.evaluate(&query).unwrap(), expected);
    assert_ne!(t.evaluate(&query).unwrap(), t.evaluate(&[b, a]).unwrap());
    assert!(PackedTable::<F>::new(usize::MAX, 2, vec![]).is_err());
    assert!(Matrix::<F>::new(0, vec![]).is_err());
}

#[test]
fn in_place_folding_matches_allocating_folding() {
    for width in [1, 5, 8] {
        let challenges: Vec<_> = (0..width).map(|i| F::new((i * 37 + 11) as u32)).collect();
        let pair = packed::challenge_pair(&challenges).unwrap();
        let mut actual = table(5, width, 7);
        let mut expected = actual.clone();
        for _ in 0..5 {
            expected = expected.fold(&pair).unwrap();
            actual.fold_in_place(&pair).unwrap();
            assert_eq!(actual.values(), expected.values());
            assert_eq!(actual.num_vars(), expected.num_vars());
        }
        let constant = actual.values().to_vec();
        assert!(actual.fold_in_place(&pair).is_err());
        assert_eq!(actual.values(), constant);
    }
}

#[test]
fn zero_check_authenticates_original_tables() {
    for n in [1, 2, 4] {
        for k in [1, 2, 5] {
            let a = table(n, k, 3);
            let b = table(n, k, 17);
            let c = PackedTable::new(
                n,
                k,
                a.values()
                    .iter()
                    .zip(b.values())
                    .map(|(&a, &b)| a * b)
                    .collect(),
            )
            .unwrap();
            let factors = vec![a, b, c];
            let shape = PackedShape {
                num_vars: n,
                width: k,
                num_factors: 3,
                terms: vec![(F::new(1), vec![0, 1]), (-F::new(1), vec![2])],
            };
            let mut prover = Transcript::new();
            let (proof, p) = packed_zero::prove(&mut prover, &shape, &factors).unwrap();
            let mut verifier = Transcript::new();
            let v = packed_zero::verify(&mut verifier, &shape, &proof).unwrap();
            assert_eq!(p.query, v.query);
            let terminal: Vec<_> = factors
                .iter()
                .map(|t| t.evaluate(&v.query).unwrap())
                .collect();
            v.check(&shape, &terminal).unwrap();
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
            let mut bad = proof.clone();
            bad.first[0][0] = F::new(1);
            assert!(packed_zero::verify(&mut Transcript::new(), &shape, &bad).is_err());
            let mut bad = proof.clone();
            bad.first.pop();
            assert!(packed_zero::verify(&mut Transcript::new(), &shape, &bad).is_err());
            let mut bad_terminal = terminal;
            bad_terminal[2][0] += F::new(1);
            assert!(v.check(&shape, &bad_terminal).is_err());
            let mut bad_factors = factors;
            bad_factors[2] = table(n, k, 91);
            assert!(packed_zero::prove(&mut Transcript::new(), &shape, &bad_factors).is_err());
        }
    }
}

fn retained_terminals<F: algebra::NTTField + serde::Serialize>() {
    for n in [0, 1, 3] {
        for width in [1, 2, 5, 8] {
            let a = PackedTable::new(
                n,
                width,
                (0..(1 << n) * width).map(|i| F::from(i * 13 + 5)).collect(),
            )
            .unwrap();
            let constant = PackedTable::new(
                n,
                width,
                (0..1 << n)
                    .flat_map(|_| (0..width).map(|i| F::from(i * 11 + 7)))
                    .collect(),
            )
            .unwrap();
            let shape = PackedShape {
                num_vars: n,
                width,
                num_factors: 2,
                terms: vec![(F::from(1), vec![0, 1])],
            };
            let factors = vec![a.clone(), constant.clone()];
            let sum = packed::sum(&shape, &factors).unwrap();
            let mut prover = Transcript::new();
            let (proof, claim, terminals) =
                packed::prove_with_terminal_values(&mut prover, &shape, &factors, &sum).unwrap();
            for (t, v) in factors.iter().zip(&terminals) {
                assert_eq!(&t.evaluate(&claim.query).unwrap(), v);
            }
            let mut legacy = Transcript::new();
            let (old, old_claim) = packed::prove(&mut legacy, &shape, &factors, &sum).unwrap();
            assert_eq!(proof.rounds, old.rounds);
            assert_eq!(claim.query, old_claim.query);
            assert_eq!(claim.expected, old_claim.expected);
            assert_eq!(
                prover.get_challenge(b"after retained sum terminals"),
                legacy.get_challenge(b"after retained sum terminals")
            );
            let mut verifier = Transcript::new();
            let verified = packed::verify(&mut verifier, &shape, &sum, &proof).unwrap();
            assert_eq!(shape.evaluate(&terminals).unwrap(), verified.expected);
            if n == 0 {
                continue;
            }
            let product = PackedTable::new(
                n,
                width,
                a.values()
                    .iter()
                    .zip(constant.values())
                    .map(|(&a, &b)| a * b)
                    .collect(),
            )
            .unwrap();
            let factors = vec![a, constant, product];
            let zero_shape = PackedShape {
                num_vars: n,
                width,
                num_factors: 3,
                terms: vec![(F::from(1), vec![0, 1]), (-F::from(1), vec![2])],
            };
            let mut prover = Transcript::new();
            let (proof, claim, terminals) =
                packed_zero::prove_with_terminal_values(&mut prover, &zero_shape, &factors)
                    .unwrap();
            assert_eq!(terminals.len(), factors.len());
            for (t, v) in factors.iter().zip(&terminals) {
                assert_eq!(&t.evaluate(&claim.query).unwrap(), v);
            }
            let mut legacy = Transcript::new();
            let (old, old_claim) = packed_zero::prove(&mut legacy, &zero_shape, &factors).unwrap();
            assert_eq!(proof.first, old.first);
            assert_eq!(proof.rest.rounds, old.rest.rounds);
            assert_eq!(claim.query, old_claim.query);
            assert_eq!(claim.equality, old_claim.equality);
            assert_eq!(
                prover.get_challenge(b"after retained zero terminals"),
                legacy.get_challenge(b"after retained zero terminals")
            );
            let mut verifier = Transcript::new();
            let verified = packed_zero::verify(&mut verifier, &zero_shape, &proof).unwrap();
            assert_eq!(claim.equality, verified.equality);
            assert_eq!(claim.expected, verified.expected);
            verified.check(&zero_shape, &terminals).unwrap();
        }
    }
}
#[test]
fn retained_terminal_vectors_match_original_dense_tables_and_transcripts() {
    retained_terminals::<algebra::BabyBear>();
    retained_terminals::<algebra::Goldilocks>();
}
