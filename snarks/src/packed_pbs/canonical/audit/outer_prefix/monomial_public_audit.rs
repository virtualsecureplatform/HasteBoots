//! Explicit public NTT values and matrix contraction, independent of Plan::evaluate.
use super::*;
use algebra::matrix_weighted::{Matrix, MatrixPair};

fn power<F: NTTField>(mut x: F, mut exponent: usize) -> F {
    let mut result = F::one();
    while exponent != 0 {
        if exponent & 1 != 0 {
            result *= x;
        }
        x *= x;
        exponent >>= 1;
    }
    result
}

pub(super) fn public_value<F: NTTField>(
    plan: &crate::packed_monomial::Plan,
    width: usize,
    query: &[MatrixPair<F>],
) -> Option<Vec<F>> {
    let n = plan.polynomial_size();
    if !width.is_power_of_two() || width > n {
        return None;
    }
    let size = n.checked_mul(plan.padded_rounds())?.checked_mul(2)?;
    let variables = (size / width).ilog2() as usize;
    if query.len() != variables || query.iter().any(|q| q.validate(width).is_err()) {
        return None;
    }
    F::generate_ntt_table(n.ilog2()).ok()?;
    F::init_ntt_table(n.ilog2()).ok()?;
    let root = F::get_ntt_table(n.ilog2()).ok()?.root();
    let bits = n.ilog2();
    // Evaluate signed monomials at every negacyclic NTT point directly. No
    // production transform, table evaluator or closed-form query is used.
    let mut values = Vec::with_capacity(size);
    for _half in 0..2 {
        for row in 0..plan.padded_rounds() {
            for index in 0..n {
                let value = match plan.rotations().get(row) {
                    None => F::zero(),
                    Some(&rotation) => {
                        let reversed = if bits == 0 {
                            0
                        } else {
                            index.reverse_bits() >> (usize::BITS - bits)
                        };
                        power(root, rotation * (2 * reversed + 1))
                    }
                };
                values.push(value);
            }
        }
    }
    // Fold least-significant Boolean variables first using explicit dense
    // matrix entries, retaining multiplication order for noncommuting queries.
    for pair in query {
        let mut next = vec![F::zero(); values.len() / 2];
        for (index, out) in next.chunks_exact_mut(width).enumerate() {
            for row in 0..width {
                for col in 0..width {
                    out[row] += pair.zero.values()[row * width + col]
                        * values[2 * index * width + col]
                        + pair.one.values()[row * width + col]
                            * values[(2 * index + 1) * width + col];
                }
            }
        }
        values = next;
    }
    Some(values)
}

fn exercise<F: NTTField>() {
    for n in [32, 1024] {
        let plan = crate::packed_monomial::Plan::new(n, vec![1, n + 3, 2 * n - 1]).unwrap();
        for width in [2, 8] {
            let variables = (2 * n * plan.padded_rounds() / width).ilog2() as usize;
            let query: Vec<_> = (0..variables)
                .map(|bit| {
                    let matrix = |offset| {
                        Matrix::new(
                            width,
                            (0..width * width)
                                .map(|i| F::from(1 + offset + (i * (bit + 3) + i / width * 7) % 23))
                                .collect(),
                        )
                        .unwrap()
                    };
                    MatrixPair {
                        zero: matrix(2 * bit),
                        one: matrix(3 * bit + 5),
                    }
                })
                .collect();
            let independent = public_value(&plan, width, &query).unwrap();
            assert_eq!(independent, plan.evaluate(width, &query).unwrap());
            assert_eq!(
                independent,
                plan.table::<F>(width).unwrap().evaluate(&query).unwrap()
            );
            let mut reversed = query.clone();
            reversed.reverse();
            assert_ne!(independent, public_value(&plan, width, &reversed).unwrap());
            assert!(public_value(&plan, width, &query[..variables - 1]).is_none());
            assert!(public_value(&plan, 3, &query).is_none());
            let wrong_plan =
                crate::packed_monomial::Plan::new(n, vec![0, n + 3, 2 * n - 1]).unwrap();
            assert_ne!(
                independent,
                public_value(&wrong_plan, width, &query).unwrap()
            );
            println!(
                "HB_MONOMIAL_PUBLIC_VALUE prime={} n={} width={} rounds=3",
                F::MODULUS_VALUE,
                n,
                width
            );
        }
    }
}

#[test]
fn monomial_public_factor_independent() {
    exercise::<algebra::BabyBear>();
    exercise::<algebra::Goldilocks>();
}
