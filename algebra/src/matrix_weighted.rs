//! Base-field tables and ordered matrix queries for packed sumcheck.
//!
//! Table indices are little endian. Eliminating variable zero applies its
//! matrix first: the weight of index `b` is `M[n-1][b[n-1]] ... M[0][b[0]]`.

use crate::Field;
use serde::{Deserialize, Serialize};

/// An invalid table, matrix, or query shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid matrix-weighted shape: {0}")]
pub struct ShapeError(pub &'static str);

/// A vector-valued Boolean table, with consecutive lanes at each Boolean index.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackedTable<F> {
    num_vars: usize,
    width: usize,
    values: Vec<F>,
}

impl<F: Field> PackedTable<F> {
    /// Construct a table; zero-variable tables represent constant vectors.
    pub fn new(num_vars: usize, width: usize, values: Vec<F>) -> Result<Self, ShapeError> {
        let table = Self {
            num_vars,
            width,
            values,
        };
        table.validate()?;
        Ok(table)
    }

    /// Check dimensions, including after deserialization.
    pub fn validate(&self) -> Result<(), ShapeError> {
        let size = 1usize
            .checked_shl(
                u32::try_from(self.num_vars).map_err(|_| ShapeError("variable count overflow"))?,
            )
            .and_then(|n| n.checked_mul(self.width));
        if self.width == 0 || size != Some(self.values.len()) {
            return Err(ShapeError("table length or width"));
        }
        Ok(())
    }

    /// Number of Boolean variables.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
    /// Number of packed lanes.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Flattened, Boolean-index-major values.
    pub fn values(&self) -> &[F] {
        &self.values
    }
    /// Vector at a Boolean index.
    pub fn at(&self, index: usize) -> &[F] {
        &self.values[index * self.width..(index + 1) * self.width]
    }

    /// Return the lane vector when every Boolean cell is equal in the field.
    /// This checks values on demand, including lazy field representatives;
    /// there is no trusted cache flag to invalidate after deserialization.
    pub fn constant_lanes(&self) -> Result<Option<&[F]>, ShapeError> {
        self.validate()?;
        let first = &self.values[..self.width];
        Ok(self
            .values
            .chunks_exact(self.width)
            .all(|v| v == first)
            .then_some(first))
    }

    /// Eliminate the least significant remaining variable.
    pub fn fold(&self, pair: &MatrixPair<F>) -> Result<Self, ShapeError> {
        self.validate()?;
        pair.validate(self.width)?;
        if self.num_vars == 0 {
            return Err(ShapeError("cannot fold a constant"));
        }
        let mut values = vec![F::zero(); self.values.len() / 2];
        if let Some(lanes) = self.constant_lanes()? {
            let mut vector = vec![F::zero(); self.width];
            pair.zero.add_mul(lanes, &mut vector);
            pair.one.add_mul(lanes, &mut vector);
            for out in values.chunks_exact_mut(self.width) {
                out.copy_from_slice(&vector);
            }
            return Self::new(self.num_vars - 1, self.width, values);
        }
        for (index, out) in values.chunks_exact_mut(self.width).enumerate() {
            pair.zero.add_mul(self.at(2 * index), out);
            pair.one.add_mul(self.at(2 * index + 1), out);
        }
        Self::new(self.num_vars - 1, self.width, values)
    }

    /// Fold an owned table in place with one temporary lane vector. Previously
    /// consumed input pairs can safely be overwritten by their output vector.
    pub fn fold_in_place(&mut self, pair: &MatrixPair<F>) -> Result<(), ShapeError> {
        self.validate()?;
        pair.validate(self.width)?;
        if self.num_vars == 0 {
            return Err(ShapeError("cannot fold a constant"));
        }
        let remaining = self.values.len() / 2;
        if let Some(lanes) = self.constant_lanes()? {
            let mut vector = vec![F::zero(); self.width];
            pair.zero.add_mul(lanes, &mut vector);
            pair.one.add_mul(lanes, &mut vector);
            for out in self.values[..remaining].chunks_exact_mut(self.width) {
                out.copy_from_slice(&vector);
            }
            self.values.truncate(remaining);
            self.num_vars -= 1;
            return Ok(());
        }
        let mut vector = vec![F::zero(); self.width];
        for index in 0..remaining / self.width {
            vector.fill(F::zero());
            pair.zero.add_mul(self.at(2 * index), &mut vector);
            pair.one.add_mul(self.at(2 * index + 1), &mut vector);
            self.values[index * self.width..(index + 1) * self.width].copy_from_slice(&vector);
        }
        self.values.truncate(remaining);
        self.num_vars -= 1;
        Ok(())
    }

    /// Evaluate an ordered query by folding in variable order.
    pub fn evaluate(&self, query: &[MatrixPair<F>]) -> Result<Vec<F>, ShapeError> {
        self.validate()?;
        if query.len() != self.num_vars {
            return Err(ShapeError("query variable count"));
        }
        let mut table = self.clone();
        for pair in query {
            table.fold_in_place(pair)?;
        }
        Ok(table.values)
    }
}

/// A square, row-major base-field matrix.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Matrix<F> {
    width: usize,
    values: Vec<F>,
}

impl<F: Field> Matrix<F> {
    /// Construct a square matrix.
    pub fn new(width: usize, values: Vec<F>) -> Result<Self, ShapeError> {
        let matrix = Self { width, values };
        matrix.validate(width)?;
        Ok(matrix)
    }
    /// Identity matrix.
    pub fn identity(width: usize) -> Result<Self, ShapeError> {
        let len = width
            .checked_mul(width)
            .ok_or(ShapeError("matrix overflow"))?;
        let mut values = vec![F::zero(); len];
        for i in 0..width {
            values[i * width + i] = F::one();
        }
        Self::new(width, values)
    }
    /// Validate shape against a trusted width.
    pub fn validate(&self, width: usize) -> Result<(), ShapeError> {
        if width == 0 || self.width != width || width.checked_mul(width) != Some(self.values.len())
        {
            return Err(ShapeError("matrix dimensions"));
        }
        Ok(())
    }
    /// Matrix width.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Row-major coefficients.
    pub fn values(&self) -> &[F] {
        &self.values
    }
    /// Add a matrix-vector product to `out` (dimensions must match).
    pub fn add_mul(&self, vector: &[F], out: &mut [F]) {
        assert_eq!(vector.len(), self.width);
        assert_eq!(out.len(), self.width);
        for (row, out) in self.values.chunks_exact(self.width).zip(out) {
            for (&coefficient, &value) in row.iter().zip(vector) {
                *out += coefficient * value;
            }
        }
    }
    /// Multiply two matrices, preserving their order.
    pub fn mul(&self, right: &Self) -> Result<Self, ShapeError> {
        self.validate(self.width)?;
        right.validate(self.width)?;
        let k = self.width;
        let mut result = vec![F::zero(); k * k];
        for a in 0..k {
            for c in 0..k {
                for b in 0..k {
                    result[a * k + b] += self.values[a * k + c] * right.values[c * k + b];
                }
            }
        }
        Self::new(k, result)
    }
}

/// The two matrices selecting the zero and one slices of a variable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatrixPair<F> {
    /// Weight of the zero slice.
    pub zero: Matrix<F>,
    /// Weight of the one slice.
    pub one: Matrix<F>,
}

impl<F: Field> MatrixPair<F> {
    /// Validate both matrices against a trusted packing width.
    pub fn validate(&self, width: usize) -> Result<(), ShapeError> {
        self.zero.validate(width)?;
        self.one.validate(width)
    }
}

/// Expand an ordered query into one matrix weight per Boolean index.
pub fn matrix_weights<F: Field>(
    width: usize,
    query: &[MatrixPair<F>],
) -> Result<Vec<Matrix<F>>, ShapeError> {
    let mut weights = vec![Matrix::identity(width)?];
    for pair in query {
        pair.validate(width)?;
        let mut next = Vec::with_capacity(weights.len() * 2);
        for weight in &weights {
            next.push(pair.zero.mul(weight)?);
        }
        for weight in &weights {
            next.push(pair.one.mul(weight)?);
        }
        weights = next;
    }
    Ok(weights)
}

/// Evaluate the public scalar-prefix mask without materializing its Boolean
/// table. The first `active_scalars` flattened entries are one, including a
/// possible partial lane vector. Work is O(width² * query.len()).
pub fn evaluate_prefix_indicator<F: Field>(
    width: usize,
    query: &[MatrixPair<F>],
    active_scalars: usize,
) -> Result<Vec<F>, ShapeError> {
    let cells = 1usize
        .checked_shl(u32::try_from(query.len()).map_err(|_| ShapeError("variable count overflow"))?)
        .ok_or(ShapeError("variable count overflow"))?;
    let capacity = cells
        .checked_mul(width)
        .ok_or(ShapeError("mask capacity overflow"))?;
    if width == 0 || active_scalars > capacity {
        return Err(ShapeError("prefix mask length or width"));
    }
    for pair in query {
        pair.validate(width)?;
    }
    let mut all = Vec::with_capacity(query.len() + 1);
    all.push(vec![F::one(); width]);
    for pair in query {
        let mut next = vec![F::zero(); width];
        pair.zero.add_mul(all.last().unwrap(), &mut next);
        pair.one.add_mul(all.last().unwrap(), &mut next);
        all.push(next);
    }
    fn prefix<F: Field>(
        width: usize,
        query: &[MatrixPair<F>],
        all: &[Vec<F>],
        count: usize,
    ) -> Vec<F> {
        let n = query.len();
        if count == 0 {
            return vec![F::zero(); width];
        }
        if count == 1usize << n {
            return all[n].clone();
        }
        let half = 1usize << (n - 1);
        let lower = prefix(
            width,
            &query[..n - 1],
            all,
            if count <= half { count } else { count - half },
        );
        let mut result = vec![F::zero(); width];
        if count <= half {
            query[n - 1].zero.add_mul(&lower, &mut result);
        } else {
            query[n - 1].zero.add_mul(&all[n - 1], &mut result);
            query[n - 1].one.add_mul(&lower, &mut result);
        }
        result
    }
    let full = active_scalars / width;
    let tail = active_scalars % width;
    let mut result = prefix(width, query, &all, full);
    if tail != 0 {
        let mut vector = vec![F::zero(); width];
        vector[..tail].fill(F::one());
        for (bit, pair) in query.iter().enumerate() {
            let mut next = vec![F::zero(); width];
            if (full >> bit) & 1 == 0 {
                pair.zero.add_mul(&vector, &mut next);
            } else {
                pair.one.add_mul(&vector, &mut next);
            }
            vector = next;
        }
        for (out, value) in result.iter_mut().zip(vector) {
            *out += value;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    use crate::BabyBear as F;
    use num_traits::{One, Zero};
    #[test]
    fn public_prefix_matches_materialized_noncommuting_queries() {
        for n in 0..=5 {
            for width in [1, 3, 8] {
                let query: Vec<_> = (0..n)
                    .map(|bit| MatrixPair {
                        zero: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|i| F::new((i * 3 + bit + 1) as u32))
                                .collect(),
                        )
                        .unwrap(),
                        one: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|i| F::new((i * 7 + bit + 4) as u32))
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect();
                let capacity = (1 << n) * width;
                for count in 0..=capacity {
                    let table = PackedTable::new(
                        n,
                        width,
                        (0..capacity)
                            .map(|i| if i < count { F::one() } else { F::zero() })
                            .collect(),
                    )
                    .unwrap();
                    assert_eq!(
                        evaluate_prefix_indicator(width, &query, count).unwrap(),
                        table.evaluate(&query).unwrap()
                    );
                }
                assert!(evaluate_prefix_indicator(width, &query, capacity + 1).is_err());
            }
        }
        assert!(evaluate_prefix_indicator::<F>(0, &[], 0).is_err());
        // A virtual 2^40-cell table must not allocate space proportional to it.
        let query: Vec<MatrixPair<F>> = vec![
            MatrixPair {
                zero: Matrix::identity(1).unwrap(),
                one: Matrix::identity(1).unwrap()
            };
            40
        ];
        if usize::BITS > 40 {
            assert_eq!(
                evaluate_prefix_indicator(1, &query, (1usize << 39) + 3).unwrap(),
                vec![F::new((((1u64 << 39) + 3) % 2013265921) as u32)]
            );
        }
    }
}

/// Evaluate a public lane vector repeated at every Boolean cell, without
/// allocating that table. Matrix order is the same as ordinary folding.
pub fn evaluate_constant_lanes<F: Field>(
    width: usize,
    query: &[MatrixPair<F>],
    lanes: &[F],
) -> Result<Vec<F>, ShapeError> {
    if width == 0 || lanes.len() != width {
        return Err(ShapeError("constant lane dimensions"));
    }
    let mut value = lanes.to_vec();
    for pair in query {
        pair.validate(width)?;
        let mut next = vec![F::zero(); width];
        pair.zero.add_mul(&value, &mut next);
        pair.one.add_mul(&value, &mut next);
        value = next;
    }
    Ok(value)
}

/// Canonical query authenticating a scalar-to-lanes broadcast. For a constant
/// source, apply `post_matrix` to the authenticated source vector locally.
#[derive(Clone, Debug)]
pub struct BroadcastQuery<F> {
    /// Query against the original (unbroadcast) table.
    pub query: Vec<MatrixPair<F>>,
    /// A terminal transformation only needed for zero-variable sources.
    pub post_matrix: Option<Matrix<F>>,
}
impl<F: Field> BroadcastQuery<F> {
    /// Convert the authenticated canonical value to the broadcast value.
    pub fn apply(&self, value: &[F], width: usize) -> Result<Vec<F>, ShapeError> {
        if width == 0 || value.len() != width {
            return Err(ShapeError("broadcast value dimensions"));
        }
        match &self.post_matrix {
            Some(matrix) => {
                matrix.validate(width)?;
                let mut result = vec![F::zero(); width];
                matrix.add_mul(value, &mut result);
                Ok(result)
            }
            None => Ok(value.to_vec()),
        }
    }
}

/// Pull back a query on A[k*b+l][r]=a[b][l] to the original canonical table.
/// The log2(k) low Boolean variables select a source lane. Their matrix weights
/// form C; C is multiplied on the RIGHT of the first remaining matrix pair.
pub fn broadcast_query<F: Field>(
    source_variables: usize,
    width: usize,
    query: &[MatrixPair<F>],
) -> Result<BroadcastQuery<F>, ShapeError> {
    if !width.is_power_of_two() {
        return Err(ShapeError("broadcast requires power-of-two width"));
    }
    let low = width.ilog2() as usize;
    if source_variables.checked_add(low) != Some(query.len()) {
        return Err(ShapeError("broadcast query variable count"));
    }
    for pair in query {
        pair.validate(width)?;
    }
    let weights = matrix_weights(width, &query[..low])?;
    let ones = vec![F::one(); width];
    let mut coefficients = vec![
        F::zero();
        width
            .checked_mul(width)
            .ok_or(ShapeError("broadcast matrix overflow"))?
    ];
    for (column, matrix) in weights.iter().enumerate() {
        let mut value = vec![F::zero(); width];
        matrix.add_mul(&ones, &mut value);
        for row in 0..width {
            coefficients[row * width + column] = value[row];
        }
    }
    let matrix = Matrix::new(width, coefficients)?;
    let mut canonical = query[low..].to_vec();
    if let Some(first) = canonical.first_mut() {
        first.zero = first.zero.mul(&matrix)?;
        first.one = first.one.mul(&matrix)?;
        Ok(BroadcastQuery {
            query: canonical,
            post_matrix: None,
        })
    } else {
        Ok(BroadcastQuery {
            query: canonical,
            post_matrix: Some(matrix),
        })
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::*;
    use crate::{BabyBear, Goldilocks, PrimeField};
    fn check<F: PrimeField + From<usize>>() {
        for n in [0, 1, 3] {
            for width in [1usize, 2, 4, 8] {
                let values: Vec<_> = (0..(1 << n) * width).map(|i| F::from(i + 1)).collect();
                let source = PackedTable::new(n, width, values.clone()).unwrap();
                let broadcast = PackedTable::new(
                    n + width.ilog2() as usize,
                    width,
                    values.iter().flat_map(|&v| vec![v; width]).collect(),
                )
                .unwrap();
                let query: Vec<_> = (0..broadcast.num_vars())
                    .map(|i| MatrixPair {
                        zero: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| F::from(i * 17 + j * 3 + 1))
                                .collect(),
                        )
                        .unwrap(),
                        one: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| F::from(i * 13 + j * 7 + 23))
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect();
                let pulled = broadcast_query(n, width, &query).unwrap();
                assert_eq!(
                    pulled
                        .apply(&source.evaluate(&pulled.query).unwrap(), width)
                        .unwrap(),
                    broadcast.evaluate(&query).unwrap()
                );
                let lanes: Vec<_> = (0..width).map(|i| F::from(i + 3)).collect();
                let constant = PackedTable::new(
                    broadcast.num_vars(),
                    width,
                    (0..1 << broadcast.num_vars())
                        .flat_map(|_| lanes.clone())
                        .collect(),
                )
                .unwrap();
                assert_eq!(
                    evaluate_constant_lanes(width, &query, &lanes).unwrap(),
                    constant.evaluate(&query).unwrap()
                );
                if n > 0 && width > 1 {
                    // Reversing C and the first high matrix is generally wrong.
                    let low = width.ilog2() as usize;
                    let c = broadcast_query(0, width, &query[..low])
                        .unwrap()
                        .post_matrix
                        .unwrap();
                    let mut wrong = query[low..].to_vec();
                    wrong[0].zero = c.mul(&wrong[0].zero).unwrap();
                    wrong[0].one = c.mul(&wrong[0].one).unwrap();
                    assert_ne!(
                        source.evaluate(&wrong).unwrap(),
                        broadcast.evaluate(&query).unwrap()
                    );
                }
            }
        }
    }
    #[test]
    fn broadcast_pullback_matches_noncommuting_tables() {
        check::<BabyBear>();
        check::<Goldilocks>();
    }
    #[test]
    fn broadcast_rejects_invalid_dimensions() {
        assert!(broadcast_query::<BabyBear>(0, 3, &[]).is_err());
        assert!(broadcast_query::<BabyBear>(1, 2, &[]).is_err());
        assert!(evaluate_constant_lanes::<BabyBear>(0, &[], &[]).is_err());
    }
}

#[cfg(test)]
mod constant_fold_tests {
    use super::*;
    use crate::{BabyBear, Goldilocks, PrimeField};
    fn check<F: PrimeField + From<usize>>() {
        for width in [1, 3, 8] {
            let n = 4;
            let lanes: Vec<_> = (0..width).map(|i| F::from(i + 3)).collect();
            let table =
                PackedTable::new(n, width, (0..1 << n).flat_map(|_| lanes.clone()).collect())
                    .unwrap();
            assert_eq!(table.constant_lanes().unwrap(), Some(lanes.as_slice()));
            let query: Vec<_> = (0..n)
                .map(|i| MatrixPair {
                    zero: Matrix::new(
                        width,
                        (0..width * width)
                            .map(|j| F::from(i * 5 + j * 3 + 1))
                            .collect(),
                    )
                    .unwrap(),
                    one: Matrix::new(
                        width,
                        (0..width * width)
                            .map(|j| F::from(i * 11 + j * 7 + 2))
                            .collect(),
                    )
                    .unwrap(),
                })
                .collect();
            let mut expected = vec![F::zero(); width];
            for matrix in matrix_weights(width, &query).unwrap() {
                matrix.add_mul(&lanes, &mut expected);
            }
            assert_eq!(table.evaluate(&query).unwrap(), expected);
            let mut allocating = table.clone();
            let mut owned = table;
            for pair in &query {
                allocating = allocating.fold(pair).unwrap();
                owned.fold_in_place(pair).unwrap();
                assert_eq!(allocating.values(), owned.values());
            }
            assert_eq!(owned.values(), expected.as_slice());
            let changed =
                PackedTable::new(1, width, (0..2 * width).map(|i| F::from(i)).collect()).unwrap();
            assert!(changed.constant_lanes().unwrap().is_none());
        }
    }
    #[test]
    fn constant_folds_match_expanded_ordered_weights() {
        check::<BabyBear>();
        check::<Goldilocks>();
    }
    #[test]
    fn lazy_goldilocks_constant_cells_are_equal_as_field_values() {
        use num_traits::Zero;
        let zero = Goldilocks::zero();
        let lazy = Goldilocks::new(Goldilocks::MODULUS_VALUE);
        let table = PackedTable::new(2, 1, vec![zero, lazy, lazy, zero]).unwrap();
        assert!(table.constant_lanes().unwrap().is_some());
        let pair = MatrixPair {
            zero: Matrix::new(1, vec![Goldilocks::from(7)]).unwrap(),
            one: Matrix::new(1, vec![Goldilocks::from(9)]).unwrap(),
        };
        assert_eq!(table.evaluate(&[pair.clone(), pair]).unwrap(), vec![zero]);
    }
}
