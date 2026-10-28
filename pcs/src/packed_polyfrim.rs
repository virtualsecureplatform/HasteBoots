//! Algebraic core for direct ordered-matrix PolyFRIM.
//!
//! This is not a PCS. Its authenticated submodule checks sampled transitions;
//! proximity testing and hiding remain open. Unlike a scalar fragment reduction, folds retain the original order
//! of all matrix factors. Coefficients are interleaved by lane.

/// Authenticated sampled matrix transitions; proximity and hiding remain separate.
pub mod authenticated;

use algebra::{
    Field,
    matrix_weighted::{MatrixPair, PackedTable, ShapeError},
};

/// Vector polynomial with power-of-two coefficient count and consecutive lanes.
/// Private coefficients are prover data, never a serialized opening proof.
pub struct Polynomial<F> {
    width: usize,
    coefficients: Vec<F>,
}

impl<F: Field> Polynomial<F> {
    /// Convert Boolean cell evaluations to multilinear monomial coefficients.
    /// Bit i of the univariate exponent represents Boolean variable i.
    pub fn from_table(table: &PackedTable<F>) -> Result<Self, ShapeError> {
        table.validate()?;
        let width = table.width();
        let mut coefficients = table.values().to_vec();
        let cells = coefficients.len() / width;
        for bit in 0..table.num_vars() {
            let step = 1usize << bit;
            for cell in 0..cells {
                if cell & step != 0 {
                    for lane in 0..width {
                        let low = coefficients[(cell - step) * width + lane];
                        coefficients[cell * width + lane] -= low;
                    }
                }
            }
        }
        Ok(Self {
            width,
            coefficients,
        })
    }

    /// Number of vector coefficients, including any high-variable padding.
    pub fn len(&self) -> usize {
        self.coefficients.len() / self.width
    }

    /// A polynomial always has at least its constant coefficient.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Append one high coefficient variable supplied by a private RNG upstream.
    /// A final Boolean query (I,0) removes these coefficients after earlier folds.
    /// This identity alone does not establish hiding of an opening transcript.
    pub fn pad(&mut self, high_coefficients: &[F]) -> Result<(), ShapeError> {
        if high_coefficients.len() != self.coefficients.len() {
            return Err(ShapeError("packed polynomial padding length"));
        }
        self.coefficients.extend_from_slice(high_coefficients);
        Ok(())
    }

    /// Evaluate the lane polynomials at a univariate domain point.
    pub fn evaluate(&self, point: F) -> Vec<F> {
        let mut out = vec![F::zero(); self.width];
        for coefficient in self.coefficients.chunks_exact(self.width).rev() {
            for (value, &c) in out.iter_mut().zip(coefficient) {
                *value = *value * point + c;
            }
        }
        out
    }

    /// Eliminate the low coefficient bit with A=M0+M1 and B=M1.
    /// This preserves the Boolean-table query M0*T0 + M1*T1.
    pub fn fold(&self, pair: &MatrixPair<F>) -> Result<Self, ShapeError> {
        pair.validate(self.width)?;
        if self.len() == 1 {
            return Err(ShapeError("cannot fold constant polynomial"));
        }
        let mut coefficients = vec![F::zero(); self.coefficients.len() / 2];
        for (input, out) in self
            .coefficients
            .chunks_exact(2 * self.width)
            .zip(coefficients.chunks_exact_mut(self.width))
        {
            let (even, odd) = input.split_at(self.width);
            pair.zero.add_mul(even, out);
            pair.one.add_mul(even, out);
            pair.one.add_mul(odd, out);
        }
        Ok(Self {
            width: self.width,
            coefficients,
        })
    }
}

/// Compute the expected next oracle symbol at beta^2 from authenticated values
/// at beta and -beta. The caller must authenticate both values against one root
/// and separately establish the required degree/proximity properties.
/// Rejects beta=0, characteristic two, and malformed shapes before arithmetic.
pub fn fold_symbol<F: Field>(
    pair: &MatrixPair<F>,
    beta: F,
    positive: &[F],
    negative: &[F],
) -> Result<Vec<F>, ShapeError> {
    let width = pair.zero.width();
    pair.validate(width)?;
    if positive.len() != width || negative.len() != width || width == 0 {
        return Err(ShapeError("packed polynomial symbol length"));
    }
    let two = F::one() + F::one();
    if beta == F::zero() || two == F::zero() {
        return Err(ShapeError("packed polynomial antipodal domain"));
    }
    let half = two.inv();
    let odd_scale = half * beta.inv();
    let even: Vec<F> = positive
        .iter()
        .zip(negative)
        .map(|(&p, &n)| (p + n) * half)
        .collect();
    let odd: Vec<F> = positive
        .iter()
        .zip(negative)
        .map(|(&p, &n)| (p - n) * odd_scale)
        .collect();
    let mut out = vec![F::zero(); width];
    pair.zero.add_mul(&even, &mut out);
    pair.one.add_mul(&even, &mut out);
    pair.one.add_mul(&odd, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        BabyBear, Goldilocks,
        matrix_weighted::{Matrix, matrix_weights},
    };
    use num_traits::{One, Zero};

    fn scalar<F: Field>(mut n: usize) -> F {
        let mut out = F::zero();
        let mut bit = F::one();
        while n > 0 {
            if n & 1 != 0 {
                out += bit;
            }
            bit += bit;
            n >>= 1;
        }
        out
    }
    fn audit<F: Field>() {
        for variables in 0..=6 {
            for width in [1, 2, 4, 8] {
                let values: Vec<F> = (0..(1 << variables) * width)
                    .map(|i| scalar::<F>(i * i + 3 * i + 11))
                    .collect();
                let table = PackedTable::new(variables, width, values).unwrap();
                let query: Vec<_> = (0..variables)
                    .map(|i| MatrixPair {
                        zero: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| scalar::<F>(i + 2 * j + 1))
                                .collect(),
                        )
                        .unwrap(),
                        one: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| scalar::<F>(3 * i + j * j + 2))
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect();
                let mut expected = vec![F::zero(); width];
                for (index, weight) in matrix_weights(width, &query).unwrap().iter().enumerate() {
                    weight.add_mul(table.at(index), &mut expected);
                }
                let mut poly = Polynomial::from_table(&table).unwrap();
                let padding: Vec<_> = (0..poly.len() * width)
                    .map(|i| scalar::<F>(7 * i + 13))
                    .collect();
                poly.pad(&padding).unwrap();
                let mut padded_query = query.clone();
                padded_query.push(MatrixPair {
                    zero: Matrix::identity(width).unwrap(),
                    one: Matrix::new(width, vec![F::zero(); width * width]).unwrap(),
                });
                for pair in &padded_query {
                    let next = poly.fold(pair).unwrap();
                    for point in [1, 2, 7, 31] {
                        let beta = scalar::<F>(point);
                        assert_eq!(
                            fold_symbol(pair, beta, &poly.evaluate(beta), &poly.evaluate(-beta))
                                .unwrap(),
                            next.evaluate(beta * beta)
                        );
                    }
                    poly = next;
                }
                assert_eq!(poly.evaluate(scalar::<F>(19)), expected);
                assert!(poly.fold(&padded_query[0]).is_err());
            }
        }
    }
    #[test]
    fn ordered_padded_ladders_babybear() {
        audit::<BabyBear>();
    }
    #[test]
    fn ordered_padded_ladders_goldilocks() {
        audit::<Goldilocks>();
    }
    #[test]
    fn matrix_order_is_observable() {
        type F = BabyBear;
        let z = F::zero();
        let o = F::one();
        let table = PackedTable::new(2, 2, vec![o, z, z, z, z, z, z, z]).unwrap();
        let zero = Matrix::new(2, vec![z; 4]).unwrap();
        let a = MatrixPair {
            zero: Matrix::new(2, vec![o, o, z, o]).unwrap(),
            one: zero.clone(),
        };
        let b = MatrixPair {
            zero: Matrix::new(2, vec![o, z, o, o]).unwrap(),
            one: zero,
        };
        let polynomial = Polynomial::from_table(&table).unwrap();
        let ordered = polynomial.fold(&a).unwrap().fold(&b).unwrap().evaluate(o);
        let reversed = polynomial.fold(&b).unwrap().fold(&a).unwrap().evaluate(o);
        assert_eq!(ordered, vec![o, o]);
        assert_eq!(reversed, vec![o + o, o]);
        assert_ne!(ordered, reversed);
    }
    #[test]
    fn reject_invalid_domain_and_shapes() {
        let pair = MatrixPair {
            zero: Matrix::<BabyBear>::identity(2).unwrap(),
            one: Matrix::identity(2).unwrap(),
        };
        let symbol = vec![BabyBear::one(); 2];
        assert!(fold_symbol(&pair, BabyBear::zero(), &symbol, &symbol).is_err());
        assert!(fold_symbol(&pair, BabyBear::one(), &symbol[..1], &symbol).is_err());
        let table = PackedTable::new(0, 2, symbol).unwrap();
        let mut poly = Polynomial::from_table(&table).unwrap();
        assert!(poly.pad(&[]).is_err());
        assert_eq!(poly.len(), 1);
    }
}
