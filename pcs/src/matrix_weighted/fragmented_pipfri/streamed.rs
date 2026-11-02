//! Stream each projected matrix kernel through the source fold table. Linearity
//! lets each claim contribute separately without allocating their summed kernel.
use super::*;
use rayon::prelude::*;
use sumcheck::prover::ProverMsg;

// Classify public matrices once per proof, rather than scan K^2 entries at
// every node of every round. Dense queries keep the reference multiplication.
enum MatrixAction<F> {
    Scalar {
        width: usize,
        value: F,
    },
    Sparse {
        width: usize,
        entries: Vec<(usize, usize, F)>,
    },
    Dense(Matrix<F>),
}
impl<F: Field> MatrixAction<F> {
    fn new(matrix: &Matrix<F>) -> Self {
        let width = matrix.width();
        // A noncanonical entry may be mathematically zero/one while carrying a
        // different serialized representative. Keep its original operations.
        if matrix.values().iter().any(|x| !x.is_canonical()) {
            return Self::Dense(matrix.clone());
        }
        let value = matrix.values()[0];
        if matrix.values().iter().enumerate().all(|(i, &x)| {
            x == if i / width == i % width {
                value
            } else {
                F::zero()
            }
        }) {
            return Self::Scalar { width, value };
        }
        let entries: Vec<_> = matrix
            .values()
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, v)| *v != F::zero())
            .map(|(i, v)| (i / width, i % width, v))
            .collect();
        if entries.len() < width * width / 2 {
            Self::Sparse { width, entries }
        } else {
            Self::Dense(matrix.clone())
        }
    }
    fn apply<E: AbstractExtensionField<F>>(&self, row: &[E]) -> Vec<E> {
        match self {
            Self::Scalar { width, value } => {
                debug_assert_eq!(*width, row.len());
                row.iter().map(|&v| E::zero() + v * *value).collect()
            }
            Self::Sparse { width, entries } => {
                let mut out = vec![E::zero(); *width];
                for &(i, j, value) in entries {
                    out[j] += row[i] * value;
                }
                out
            }
            Self::Dense(matrix) => row_mul(row, matrix),
        }
    }
}

// Produce Boolean suffix evaluations after fixing low coordinates. The stack
// descends matrix indices, preserving the noncommutative row-product order.
struct KernelStream<'a, F: Field, E: AbstractExtensionField<F>> {
    query: &'a [(MatrixAction<F>, MatrixAction<F>)],
    fixed: usize,
    lane_bits: usize,
    point: &'a [E],
    stack: Vec<(usize, Vec<E>)>,
    leaf: std::vec::IntoIter<E>,
}
impl<'a, F: Field, E: AbstractExtensionField<F>> KernelStream<'a, F, E> {
    fn new(
        query: &'a [(MatrixAction<F>, MatrixAction<F>)],
        row: &[E],
        lane_bits: usize,
        point: &'a [E],
    ) -> Self {
        Self {
            query,
            fixed: point.len().saturating_sub(lane_bits),
            lane_bits,
            point,
            stack: vec![(query.len(), row.to_vec())],
            leaf: Vec::new().into_iter(),
        }
    }
}
impl<F: Field, E: AbstractExtensionField<F>> Iterator for KernelStream<'_, F, E> {
    type Item = E;
    fn next(&mut self) -> Option<E> {
        loop {
            if let Some(value) = self.leaf.next() {
                return Some(value);
            }
            let (remaining, mut row) = self.stack.pop()?;
            if remaining > self.fixed {
                let pair = &self.query[remaining - 1];
                // LIFO: push the one branch first to emit zero before one.
                self.stack.push((remaining - 1, pair.1.apply(&row)));
                self.stack.push((remaining - 1, pair.0.apply(&row)));
                continue;
            }
            for i in (0..self.fixed).rev() {
                let a = self.query[i].0.apply(&row);
                let b = self.query[i].1.apply(&row);
                let r = self.point[self.lane_bits + i];
                row = a.into_iter().zip(b).map(|(a, b)| a + r * (b - a)).collect();
            }
            for &r in self.point.iter().take(self.lane_bits) {
                let half = row.len() / 2;
                for j in 0..half {
                    row[j] = row[2 * j] + r * (row[2 * j + 1] - row[2 * j]);
                }
                row.truncate(half);
            }
            self.leaf = row.into_iter();
        }
    }
}

pub(super) fn prove<F: Field, E: AbstractExtensionField<F> + Serialize>(
    source: &[F],
    width: usize,
    queries: &[Vec<MatrixPair<F>>],
    rho: &[E],
    trans: &mut Transcript<E>,
) -> (sumcheck::Proof<E>, Vec<E>) {
    prove_mode::<F, E, true>(source, width, queries, rho, trans)
}
fn prove_mode<F: Field, E: AbstractExtensionField<F> + Serialize, const COMPILED: bool>(
    source: &[F],
    width: usize,
    queries: &[Vec<MatrixPair<F>>],
    rho: &[E],
    trans: &mut Transcript<E>,
) -> (sumcheck::Proof<E>, Vec<E>) {
    let lane_bits = width.ilog2() as usize;
    let n = lane_bits + queries[0].len();
    if n == 0 {
        return (vec![], vec![]);
    }
    trans.append_message(
        b"polynomial info",
        &PolynomialInfo {
            num_variables: n,
            max_multiplicands: 2,
        },
    );
    // The first round reads base elements directly. Only after its challenge do
    // we allocate an extension table, already half the size of the source.
    let mut folded: Vec<E> = Vec::new();
    let mut point = Vec::with_capacity(n);
    let mut proof = Vec::with_capacity(n);
    let compiled: Vec<Vec<_>> = queries
        .iter()
        .map(|q| {
            q.iter()
                .map(|pair| {
                    (
                        if COMPILED {
                            MatrixAction::new(&pair.zero)
                        } else {
                            MatrixAction::Dense(pair.zero.clone())
                        },
                        if COMPILED {
                            MatrixAction::new(&pair.one)
                        } else {
                            MatrixAction::Dense(pair.one.clone())
                        },
                    )
                })
                .collect()
        })
        .collect();
    for round in 0..n {
        let mut evaluations = [E::zero(); 3];
        let mut streams: Vec<_> = compiled
            .iter()
            .zip(rho.chunks_exact(width))
            .map(|(q, row)| KernelStream::new(q, row, lane_bits, &point))
            .collect();
        let remaining = source.len() >> round;
        // At most 4096 extension elements, independent of source size. Sum the
        // claim kernels before multiplying, rather than repeating expensive
        // source/kernel extension multiplications once per claim.
        let mut tile = vec![E::zero(); remaining.min(4096)];
        for offset in (0..remaining).step_by(tile.len()) {
            let len = tile.len().min(remaining - offset);
            let tile = &mut tile[..len];
            tile.fill(E::zero());
            if streams.len() > 1 && len >= 4096 && rayon::current_num_threads() > 1 {
                // At most one stream group per worker. Each group retains a
                // bounded tile rather than allocating a full source kernel.
                let group_size = streams.len().div_ceil(rayon::current_num_threads());
                let combined = streams
                    .par_chunks_mut(group_size)
                    .map(|group| {
                        let mut partial = vec![E::zero(); len];
                        for stream in group {
                            for value in &mut partial {
                                *value += stream.next().expect("validated kernel dimensions");
                            }
                        }
                        partial
                    })
                    .reduce(
                        || vec![E::zero(); len],
                        |mut a, b| {
                            for (a, b) in a.iter_mut().zip(b) {
                                *a += b;
                            }
                            a
                        },
                    );
                tile.copy_from_slice(&combined);
            } else {
                for stream in &mut streams {
                    for value in tile.iter_mut() {
                        *value += stream.next().expect("validated kernel dimensions");
                    }
                }
            }
            for (j, pair) in tile.chunks_exact(2).enumerate() {
                let index = offset + 2 * j;
                let a = pair[0];
                let b = pair[1];
                if round == 0 {
                    let x = source[index];
                    let y = source[index + 1];
                    evaluations[0] += a * x;
                    evaluations[1] += b * y;
                    evaluations[2] += (b + b - a) * (y + y - x);
                } else {
                    let x = folded[index];
                    let y = folded[index + 1];
                    evaluations[0] += x * a;
                    evaluations[1] += y * b;
                    evaluations[2] += (y + y - x) * (b + b - a);
                }
            }
        }
        debug_assert!(streams.iter_mut().all(|s| s.next().is_none()));
        let message = ProverMsg::from_evaluations(evaluations.to_vec());
        trans.append_message(b"sumcheck msg", &message);
        proof.push(message);
        let r = trans.get_challenge(b"random point in each round");
        point.push(r);
        if round == 0 {
            folded = source
                .chunks_exact(2)
                .map(|a| E::from_base(a[0]) + r * (a[1] - a[0]))
                .collect();
        } else {
            let half = folded.len() / 2;
            for j in 0..half {
                folded[j] = folded[2 * j] + r * (folded[2 * j + 1] - folded[2 * j]);
            }
            folded.truncate(half);
        }
    }
    (proof, point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::ListOfProductsOfPolynomials;
    use std::rc::Rc;

    fn action_representatives<F, E>()
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize,
    {
        let mut coins = Transcript::<E>::new_classical_extension::<F>(&[91; 64]);
        for width in [1, 2, 4, 8] {
            let rows = [
                coins.get_vec_challenge(b"row", width),
                vec![E::from_base_fn(|_| F::new(F::MODULUS_VALUE)); width],
                (0..width)
                    .map(|i| {
                        E::from_base_fn(|j| {
                            if (i + j) % 2 == 0 {
                                F::new(F::MODULUS_VALUE)
                            } else {
                                F::one()
                            }
                        })
                    })
                    .collect(),
            ];
            for kind in 0..5 {
                let mut values = vec![F::zero(); width * width];
                for i in 0..width {
                    match kind {
                        0 => (),
                        1 => values[i * width + i] = F::one(),
                        2 => values[i * width + (i + 1) % width] = F::from(i + 2),
                        3 => {
                            for j in 0..width {
                                values[i * width + j] = F::from(i * width + j + 3);
                            }
                        }
                        _ => values[i * width + i] = F::new(F::MODULUS_VALUE),
                    }
                }
                let matrix = Matrix::new(width, values).unwrap();
                let action = MatrixAction::new(&matrix);
                for row in &rows {
                    assert_eq!(
                        bincode::serde::encode_to_vec(
                            action.apply(row),
                            bincode::config::standard()
                        )
                        .unwrap(),
                        bincode::serde::encode_to_vec(
                            row_mul(row, &matrix),
                            bincode::config::standard()
                        )
                        .unwrap(),
                        "width={width} kind={kind}"
                    );
                }
            }
        }
    }
    #[test]
    fn babybear_actions_preserve_raw_representatives() {
        action_representatives::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_actions_preserve_raw_representatives() {
        action_representatives::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    fn differential<F, E>(structured: bool)
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize,
    {
        let mut coins = Transcript::<F>::new_classical(&[21; 64]);
        let mut extension = Transcript::<E>::new_classical_extension::<F>(&[22; 64]);
        for vars in [0, 1, 3, 4, 10] {
            for width in [1usize, 2, 4, 8] {
                let n = vars + width.ilog2() as usize;
                let source: Vec<F> = coins.get_vec_challenge(b"source", width << vars);
                for count in [1, 4, 16] {
                    let queries: Vec<Vec<_>> = (0..count)
                        .map(|member| {
                            (0..vars)
                                .map(|coordinate| {
                                    let mut entries =
                                        coins.get_vec_challenge(b"dense matrix", 2 * width * width);
                                    if structured {
                                        match (member + coordinate) % 4 {
                                            0 | 1 => {
                                                let a = if (member + coordinate) % 4 == 1 {
                                                    F::one()
                                                } else {
                                                    entries[0]
                                                };
                                                let b = if (member + coordinate) % 4 == 1 {
                                                    F::zero()
                                                } else {
                                                    entries[1]
                                                };
                                                entries.fill(F::zero());
                                                for i in 0..width {
                                                    entries[i * width + i] = a;
                                                    entries[width * width + i * width + i] = b;
                                                }
                                            }
                                            2 => {
                                                let previous = entries.clone();
                                                entries.fill(F::zero());
                                                for i in 0..width {
                                                    entries[i * width + i] = previous[i];
                                                    entries[width * width
                                                        + i * width
                                                        + (i + 1) % width] = previous[width + i];
                                                }
                                            }
                                            _ => (),
                                        }
                                    }
                                    MatrixPair {
                                        zero: Matrix::new(width, entries[..width * width].to_vec())
                                            .unwrap(),
                                        one: Matrix::new(width, entries[width * width..].to_vec())
                                            .unwrap(),
                                    }
                                })
                                .collect()
                        })
                        .collect();
                    let rho =
                        extension.get_vec_challenge(b"full extension projections", count * width);
                    let mut streamed = Transcript::<E>::new_classical_extension::<F>(&[23; 64]);
                    let mut reference = Transcript::<E>::new_classical_extension::<F>(&[23; 64]);
                    let (actual, point) = prove(&source, width, &queries, &rho, &mut streamed);
                    let (expected, expected_point) = if n == 0 {
                        (vec![], vec![])
                    } else {
                        let a = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                            n,
                            source.iter().copied().map(E::from_base).collect(),
                        ));
                        let b = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                            n,
                            kernel(width, &queries, &rho),
                        ));
                        let mut poly = ListOfProductsOfPolynomials::new(n);
                        poly.add_product([a, b], E::one());
                        let (proof, state) = MLSumcheck::prove(&mut reference, &poly).unwrap();
                        (proof, state.randomness)
                    };
                    if structured && n > 0 {
                        let weights = kernel(width, &queries, &rho);
                        let claim = source
                            .iter()
                            .zip(&weights)
                            .fold(E::zero(), |sum, (&a, &b)| sum + b * a);
                        let mut verifier = Transcript::<E>::new_classical_extension::<F>(&[23; 64]);
                        let sub = MLSumcheck::verify(
                            &mut verifier,
                            &PolynomialInfo {
                                num_variables: n,
                                max_multiplicands: 2,
                            },
                            claim,
                            &actual,
                        )
                        .unwrap();
                        let polynomial = DenseMultilinearExtension::from_evaluations_vec(
                            n,
                            source.iter().copied().map(E::from_base).collect(),
                        );
                        let kernel_poly =
                            DenseMultilinearExtension::from_evaluations_vec(n, weights);
                        assert_eq!(
                            sub.expected_evaluations,
                            polynomial.evaluate(&sub.point) * kernel_poly.evaluate(&sub.point)
                        );
                        let mut materialized_verifier =
                            Transcript::<E>::new_classical_extension::<F>(&[23; 64]);
                        let materialized_sub = MLSumcheck::verify(
                            &mut materialized_verifier,
                            &PolynomialInfo {
                                num_variables: n,
                                max_multiplicands: 2,
                            },
                            claim,
                            &expected,
                        )
                        .unwrap();
                        assert_eq!(
                            materialized_sub.expected_evaluations,
                            polynomial.evaluate(&materialized_sub.point)
                                * kernel_poly.evaluate(&materialized_sub.point)
                        );
                    }
                    let (expected, expected_point) = if structured {
                        reference = Transcript::<E>::new_classical_extension::<F>(&[23; 64]);
                        let dense = prove_mode::<F, E, false>(
                            &source,
                            width,
                            &queries,
                            &rho,
                            &mut reference,
                        );
                        if bincode::serde::encode_to_vec(&dense.0, bincode::config::standard())
                            .unwrap()
                            != bincode::serde::encode_to_vec(&expected, bincode::config::standard())
                                .unwrap()
                        {
                            eprintln!(
                                "materialized_vs_dense_stream_wire_difference field={} vars={vars} width={width} count={count}",
                                std::any::type_name::<E>()
                            );
                        }
                        dense
                    } else {
                        (expected, expected_point)
                    };
                    assert_eq!(
                        point, expected_point,
                        "vars={vars} width={width} count={count}"
                    );
                    assert_eq!(
                        bincode::serde::encode_to_vec(actual, bincode::config::standard()).unwrap(),
                        bincode::serde::encode_to_vec(expected, bincode::config::standard())
                            .unwrap()
                    );
                    let mut a = [0; 64];
                    let mut b = [0; 64];
                    streamed.get_challenge_bytes(b"continuation", &mut a);
                    reference.get_challenge_bytes(b"continuation", &mut b);
                    assert_eq!(a, b);
                }
            }
        }
    }

    #[test]
    fn babybear_stream_matches_materialized_sumcheck() {
        differential::<algebra::BabyBear, algebra::BabyBearExtension6>(false);
    }
    #[test]
    fn goldilocks_stream_matches_materialized_sumcheck() {
        differential::<algebra::Goldilocks, algebra::GoldilocksExtension3>(false);
    }

    #[test]
    fn babybear_structured_stream_matches_materialized_sumcheck() {
        differential::<algebra::BabyBear, algebra::BabyBearExtension6>(true);
    }
    #[test]
    fn goldilocks_structured_stream_matches_materialized_sumcheck() {
        differential::<algebra::Goldilocks, algebra::GoldilocksExtension3>(true);
    }
    fn profile<F, E>(width: usize, structured: bool)
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize,
    {
        use std::time::Instant;
        let vars = 12;
        let n = vars + width.ilog2() as usize;
        let mut coins = Transcript::<F>::new_classical(&[31; 64]);
        let mut extension = Transcript::<E>::new_classical_extension::<F>(&[32; 64]);
        let source: Vec<F> = coins.get_vec_challenge(b"source", width << vars);
        for count in [1, 4, 16] {
            let queries: Vec<Vec<_>> = (0..count)
                .map(|member| {
                    (0..vars)
                        .map(|coordinate| {
                            let mut entries =
                                coins.get_vec_challenge(b"dense matrix", 2 * width * width);
                            if structured {
                                let previous = entries.clone();
                                match (member + coordinate) % 4 {
                                    0 | 1 => {
                                        entries.fill(F::zero());
                                        let a = if (member + coordinate) % 4 == 1 {
                                            F::one()
                                        } else {
                                            previous[0]
                                        };
                                        let b = if (member + coordinate) % 4 == 1 {
                                            F::zero()
                                        } else {
                                            previous[1]
                                        };
                                        for i in 0..width {
                                            entries[i * width + i] = a;
                                            entries[width * width + i * width + i] = b;
                                        }
                                    }
                                    2 => {
                                        entries.fill(F::zero());
                                        for i in 0..width {
                                            entries[i * width + i] = previous[i];
                                            entries[width * width + i * width + (i + 1) % width] =
                                                previous[width + i];
                                        }
                                    }
                                    _ => (),
                                }
                            }
                            MatrixPair {
                                zero: Matrix::new(width, entries[..width * width].to_vec())
                                    .unwrap(),
                                one: Matrix::new(width, entries[width * width..].to_vec()).unwrap(),
                            }
                        })
                        .collect()
                })
                .collect();
            let rho = extension.get_vec_challenge(b"projections", count * width);
            let run = |stream: bool| {
                let mut trans = Transcript::<E>::new_classical_extension::<F>(&[33; 64]);
                let start = Instant::now();
                let (proof, point) = if stream {
                    prove(&source, width, &queries, &rho, &mut trans)
                } else if structured {
                    prove_mode::<F, E, false>(&source, width, &queries, &rho, &mut trans)
                } else {
                    let a = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                        n,
                        source.iter().copied().map(E::from_base).collect(),
                    ));
                    let b = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                        n,
                        kernel(width, &queries, &rho),
                    ));
                    let mut poly = ListOfProductsOfPolynomials::new(n);
                    poly.add_product([a, b], E::one());
                    let (proof, state) = MLSumcheck::prove(&mut trans, &poly).unwrap();
                    (proof, state.randomness)
                };
                let seconds = start.elapsed().as_secs_f64();
                let mut tail = [0; 32];
                trans.get_challenge_bytes(b"profile continuation", &mut tail);
                (
                    seconds,
                    bincode::serde::encode_to_vec(
                        (proof, point, tail),
                        bincode::config::standard(),
                    )
                    .unwrap(),
                )
            };
            // One warm pair, then ten measured pairs with reversed order.
            let (_, reference) = run(false);
            assert_eq!(run(true).1, reference);
            let mut materialized = Vec::new();
            let mut streamed = Vec::new();
            for repetition in 0..10 {
                for stream in if repetition % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let (seconds, bytes) = run(stream);
                    assert_eq!(bytes, reference);
                    if stream {
                        streamed.push(seconds);
                    } else {
                        materialized.push(seconds);
                    }
                }
            }
            eprintln!(
                "fragmented_kernel_profile structured={structured} field={} vars={vars} width={width} batch={count} materialized={materialized:?} streamed={streamed:?}",
                std::any::type_name::<E>()
            );
        }
    }

    #[test]
    #[ignore = "manual native kernel comparison; excludes scalar PCS and full PBS"]
    fn profile_fragmented_streamed_kernel() {
        profile::<algebra::BabyBear, algebra::BabyBearExtension6>(8, false);
        profile::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, false);
    }
    #[test]
    #[ignore = "manual structured kernel comparison against previous dense streamed schedule"]
    fn profile_fragmented_compiled_matrices() {
        profile::<algebra::BabyBear, algebra::BabyBearExtension6>(8, true);
        profile::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, true);
    }
}
