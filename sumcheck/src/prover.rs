//! Prover for multilinear sumcheck protocol
// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/protocol/prover.rs.

use core::panic;
use std::vec;

use algebra::Field;
use algebra::{DenseMultilinearExtension, ListOfProductsOfPolynomials};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{Deserialize, Serialize};

use super::IPForMLSumcheck;
use super::verifier::VerifierMsg;

/// Prover Message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverMsg<F: Field> {
    /// evaluations on P(0), P(1), P(2), ...
    pub(crate) evaluations: Vec<F>,
}

/// Prover State
pub struct ProverState<F: Field> {
    /// sampled randomness given by the verifier
    pub randomness: Vec<F>,
    /// Stores the list of products that is meant to be added together.
    /// Each multiplicand is represented by the index in flattened_ml_extensions
    pub list_of_products: Vec<(F, Vec<usize>)>,
    /// Stores the linear operations, each of which is successively (in the same order) performed over the each MLE of each product stored in the above `products`
    /// so each (a: F, b: F) can used to wrap a linear operation over the original MLE f, i.e. a \cdot f + b
    pub linear_ops: Vec<Vec<(F, F)>>,
    /// Stores a list of multilinear extensions in which `self.list_of_products` point to
    pub flattened_ml_extensions: Vec<DenseMultilinearExtension<F>>,
    /// Number of variables
    pub num_vars: usize,
    /// Max number of multiplicands in a product
    pub max_multiplicands: usize,
    /// The current round number
    pub round: usize,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// Initilaize the prover to argue for the sum of polynomial over {0, 1}^`num_vars`
    ///
    /// The polynomial is represented by a list of products of polynomials along with its coefficient that is meant to be added together.
    ///
    /// This data structure of the polynomial is a list of list of `(coefficient, DenseMultilinearExtension`.
    /// * Number of products n = `polynomial.products.len()`,
    /// * Number of multiplicands of i-th product m_i = `polynomial.products[i].1.len`,
    /// * Coefficient of i-th product c_i = `polynomial.products[i].0`
    ///
    /// The resulting polynomial is
    ///
    /// $$\sum_{i=0}^{n} c_i \cdot \prod_{j=0}^{m_i}P_{ij}$$
    pub fn prover_init(polynomial: &ListOfProductsOfPolynomials<F>) -> ProverState<F> {
        if polynomial.num_variables == 0 {
            panic!("Attempt to prove a constant.")
        }

        // create a deep copy of all unique MLExtensions
        let flattened_ml_extensions = polynomial
            .flattened_ml_extensions
            .iter()
            .map(|x| x.as_ref().clone())
            .collect();

        ProverState {
            randomness: Vec::with_capacity(polynomial.num_variables),
            list_of_products: polynomial.products.clone(),
            linear_ops: polynomial.linear_ops.clone(),
            flattened_ml_extensions,
            num_vars: polynomial.num_variables,
            max_multiplicands: polynomial.max_multiplicands,
            round: 0,
        }
    }

    /// Receive message from the verifier, generate prover messages, and proceed to the next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    pub fn prove_round(
        prover_state: &mut ProverState<F>,
        v_msg: &Option<VerifierMsg<F>>,
    ) -> ProverMsg<F> {
        if let Some(msg) = v_msg {
            if prover_state.round == 0 {
                panic!("First round should be prover first.")
            }
            prover_state.randomness.push(msg.randomness);

            // fix argument
            let i = prover_state.round;
            let r = prover_state.randomness[i - 1];
            prover_state
                .flattened_ml_extensions
                .par_iter_mut()
                .for_each(|mulplicand| {
                    // Prover tables are owned here. Fold them in place instead
                    // of cloning the full table before discarding half of it.
                    let remaining = mulplicand.evaluations.len() / 2;
                    for b in 0..remaining {
                        let left = mulplicand.evaluations[2 * b];
                        let right = mulplicand.evaluations[2 * b + 1];
                        mulplicand.evaluations[b] = left + r * (right - left);
                    }
                    mulplicand.evaluations.truncate(remaining);
                    mulplicand.num_vars -= 1;
                });
        } else if prover_state.round > 0 {
            panic!("Verifier message is empty")
        }

        prover_state.round += 1;

        if prover_state.round > prover_state.num_vars {
            panic!("Prover is not active");
        }

        let i = prover_state.round;
        let nv = prover_state.num_vars;
        // the degree of univariate polynomial sent by prover at this round
        let degree = prover_state.max_multiplicands;

        // In effect, this loop is essentially doing simply:
        // for b in 0..1 << (nv - i)
        // The goal is to evaluate degree + 1 points for each b, all of which has been fixed with the same (i-1) variables.
        // Note that the function proved in the sumcheck is a sum of products.
        let res = prover_state
            .list_of_products
            .par_iter()
            .zip(prover_state.linear_ops.par_iter())
            .map(|((coefficient, products), linear_ops)| {
                let mut products_sum = vec![F::zero(); degree + 1];
                let mut product = vec![F::zero(); degree + 1];
                for b in 0..1 << (nv - i) {
                    product.fill(*coefficient);
                    // This loop is evaluating each MLE to update the product via performing the accumulated multiplication.
                    for (&jth_product, &(op_a, op_b)) in products.iter().zip(linear_ops.iter()) {
                        // (a, b) is a wrapped linear operation over original MLE
                        let table = &prover_state.flattened_ml_extensions[jth_product];
                        let left = table[b << 1];
                        let difference = table[(b << 1) + 1] - left;
                        // Most factors have the identity affine wrapper. In an
                        // extension field, multiplying by one still executes a
                        // full field multiplication unless we specialize it.
                        let (mut start, step) = if op_a == F::one() {
                            (left, difference)
                        } else {
                            (left * op_a, difference * op_a)
                        };
                        if op_b != F::zero() {
                            start += op_b;
                        }
                        // Evaluate each point P(t) for t = 0..degree + 1 via the accumulated addition instead of the multiplication by t.
                        // [t|b] = [0|b] + t * ([1|b] - [0|b]) represented by little-endian
                        for p in product.iter_mut() {
                            *p *= start;
                            start += step;
                        }
                    }
                    for t in 0..degree + 1 {
                        products_sum[t] += product[t];
                    }
                }
                products_sum
            })
            .reduce(
                || vec![F::zero(); degree + 1],
                |mut acc, a| {
                    for (acc, a) in acc.iter_mut().zip(a) {
                        *acc += a;
                    }
                    acc
                },
            );
        ProverMsg { evaluations: res }
    }
}

impl<F: Field> ProverState<F> {
    /// Fast evaluation of all involved MLEs after the last round of the sumcheck protocol
    #[inline]
    pub fn fast_evaluate(&self) -> Vec<F> {
        // TODO assert round is the last round?
        let last_random = *self.randomness.last().unwrap();
        let fast_compute = |mle: &DenseMultilinearExtension<F>| {
            mle.evaluations[0] + last_random * (mle.evaluations[1] - mle.evaluations[0])
        };
        self.flattened_ml_extensions
            .par_iter()
            .map(fast_compute)
            .collect::<Vec<_>>()
    }
}

#[cfg(test)]
mod regression {
    use super::*;
    use algebra::{BabyBear, BabyBearExetension, Field, Goldilocks, MultilinearExtension};
    use rand::SeedableRng;
    use std::rc::Rc;

    // Independent direct interpolation, retaining the allocation-based folding
    // used by the artifact, checks that the optimized path changes no messages.
    fn check<F: Field>() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(9321);
        let mut one = F::zero();
        let mut values = Vec::new();
        for _ in 0..32 {
            values.push(F::random(&mut rng));
            one += F::one();
        }
        let a = Rc::new(DenseMultilinearExtension::from_evaluations_vec(5, values));
        let mut polynomial = ListOfProductsOfPolynomials::new(5);
        polynomial.add_product_with_linear_op(
            [a.clone(), a.clone()],
            &[(one, F::one()), (F::one(), -one)],
            one,
        );
        polynomial.add_product([a.clone(), a.clone(), a], -F::one());
        let mut state = IPForMLSumcheck::prover_init(&polynomial);
        let mut reference = IPForMLSumcheck::prover_init(&polynomial);
        for round in 0..5 {
            let r = F::random(&mut rng);
            let message = if round == 0 {
                None
            } else {
                Some(VerifierMsg { randomness: r })
            };
            if round > 0 {
                for table in &mut reference.flattened_ml_extensions {
                    *table = table.fix_variables(&[r]);
                }
            }
            let degree = reference.max_multiplicands;
            let mut expected = vec![F::zero(); degree + 1];
            for ((coefficient, indices), ops) in
                reference.list_of_products.iter().zip(&reference.linear_ops)
            {
                for b in 0..(1 << (4 - round)) {
                    let mut node = F::zero();
                    for expected in &mut expected {
                        let mut value = *coefficient;
                        for (&index, &(a, c)) in indices.iter().zip(ops) {
                            let table = &reference.flattened_ml_extensions[index];
                            let at = table[2 * b] + node * (table[2 * b + 1] - table[2 * b]);
                            value *= a * at + c;
                        }
                        *expected += value;
                        node += F::one();
                    }
                }
            }
            let actual = IPForMLSumcheck::prove_round(&mut state, &message);
            assert_eq!(actual.evaluations, expected);
            for (actual, expected) in state
                .flattened_ml_extensions
                .iter()
                .zip(&reference.flattened_ml_extensions)
            {
                assert_eq!(actual.evaluations, expected.evaluations);
                assert_eq!(actual.num_vars, expected.num_vars);
            }
        }
    }

    #[test]
    fn scalar_optimization_preserves_all_round_messages() {
        check::<BabyBear>();
        check::<BabyBearExetension>();
        check::<Goldilocks>();
    }
}
