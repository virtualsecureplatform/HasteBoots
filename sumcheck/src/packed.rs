//! Packed sumcheck (2025/719, §3.2), using base-field matrix challenges.
//!
//! Verification returns an opening obligation, not acceptance of the witness.
//! Callers must authenticate every factor at the returned matrix-weighted query.

use crate::error::Error;
use crate::verifier::interpolate_uni_poly;
use algebra::{
    Field, PrimeField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable, ShapeError},
};
use helper::{FiatShamirTranscript, Transcript};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Public structure of a sum of products, shared across all packed lanes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackedShape<F> {
    /// Number of Boolean variables.
    pub num_vars: usize,
    /// Number of packed coordinates.
    pub width: usize,
    /// Number of committed factor tables.
    pub num_factors: usize,
    /// Scalar coefficient and factor indices for each product.
    pub terms: Vec<(F, Vec<usize>)>,
}

impl<F: PrimeField> PackedShape<F> {
    /// Validate dimensions and the interpolation degree against the field.
    pub fn validate(&self) -> Result<usize, Error> {
        if self.width == 0
            || self.num_factors == 0
            || self.terms.is_empty()
            || self.num_vars >= usize::BITS as usize
        {
            return Err(reject("empty or oversized packed shape"));
        }
        if self.terms.iter().any(|(_, factors)| {
            factors.is_empty() || factors.iter().any(|&i| i >= self.num_factors)
        }) {
            return Err(reject("invalid packed product indices"));
        }
        let degree = self
            .terms
            .iter()
            .map(|(_, factors)| factors.len())
            .max()
            .unwrap();
        let round_degree = self
            .width
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| n.checked_mul(degree))
            .ok_or_else(|| reject("degree overflow"))?;
        // Avoid converting field moduli through floating point, or narrowing them.
        let characteristic = F::MODULUS_VALUE
            .to_string()
            .parse::<u128>()
            .map_err(|_| reject("unsupported field characteristic"))?;
        if round_degree as u128 + 1 >= characteristic {
            return Err(reject("field too small for packed interpolation"));
        }
        Ok(round_degree)
    }

    /// Evaluate the sum of products on authenticated factor vectors.
    pub fn evaluate(&self, factors: &[Vec<F>]) -> Result<Vec<F>, Error> {
        self.validate()?;
        if factors.len() != self.num_factors || factors.iter().any(|v| v.len() != self.width) {
            return Err(reject("incorrect terminal factor dimensions"));
        }
        let mut output = vec![F::zero(); self.width];
        for (coefficient, indices) in &self.terms {
            for lane in 0..self.width {
                output[lane] += indices
                    .iter()
                    .fold(*coefficient, |acc, &i| acc * factors[i][lane]);
            }
        }
        Ok(output)
    }
}

/// Round polynomials represented by evaluations at consecutive field elements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackedProof<F> {
    /// One degree-bounded univariate per Boolean variable.
    pub rounds: Vec<Vec<F>>,
}

/// Obligation that must be discharged by matrix-weighted commitment openings.
#[derive(Clone, Debug)]
pub struct PackedSubclaim<F> {
    /// Matrix-pair query in least-significant-variable-first order.
    pub query: Vec<MatrixPair<F>>,
    /// Expected sum of products of the authenticated factor vectors.
    pub expected: Vec<F>,
}

/// Build Lagrange weights for nodes `0..count`, using one inverse per node.
pub fn lagrange_weights<F: PrimeField>(count: usize, point: F) -> Vec<F> {
    let mut nodes = Vec::with_capacity(count);
    let mut node = F::zero();
    for i in 0..count {
        if point == node {
            let mut result = vec![F::zero(); count];
            result[i] = F::one();
            return result;
        }
        nodes.push(node);
        node += F::one();
    }
    (0..count)
        .map(|i| {
            let mut numerator = F::one();
            let mut denominator = F::one();
            for j in 0..count {
                if i != j {
                    numerator *= point - nodes[j];
                    denominator *= nodes[i] - nodes[j];
                }
            }
            numerator / denominator
        })
        .collect()
}

/// Matrix pair induced by one independent challenge for each packed lane.
pub fn challenge_pair<F: PrimeField>(challenges: &[F]) -> Result<MatrixPair<F>, ShapeError> {
    let k = challenges.len();
    let mut zero = Vec::with_capacity(k * k);
    let mut one = Vec::with_capacity(k * k);
    for &r in challenges {
        let weights = lagrange_weights(2 * k, r);
        for lane in 0..k {
            zero.push(weights[2 * lane]);
            one.push(weights[2 * lane + 1]);
        }
    }
    Ok(MatrixPair {
        zero: Matrix::new(k, zero)?,
        one: Matrix::new(k, one)?,
    })
}

/// Prove a packed sumcheck. The caller must bind the statement and commitments
/// to `trans` before calling this function.
pub fn prove<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    claimed_sum: &[F],
) -> Result<(PackedProof<F>, PackedSubclaim<F>), Error> {
    prove_with_terminal_values(trans, shape, factors, claimed_sum)
        .map(|(proof, subclaim, _)| (proof, subclaim))
}

/// Prove the same protocol and retain the already-folded factor values.
/// These are prover outputs, not authenticated verifier obligations by themselves.
pub fn prove_with_terminal_values<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    claimed_sum: &[F],
) -> Result<(PackedProof<F>, PackedSubclaim<F>, Vec<Vec<F>>), Error> {
    prove_with_rounds(trans, shape, factors, claimed_sum, |_, _, _| Ok(()))
}

/// Prove with an authenticated-oracle callback after each fresh matrix challenge
/// and before the next round message/challenge. Callback messages belong to the
/// transcript; the verifier must execute the identical callback schedule.
pub fn prove_with_rounds<F, T>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    claimed_sum: &[F],
    mut after_challenge: T,
) -> Result<(PackedProof<F>, PackedSubclaim<F>, Vec<Vec<F>>), Error>
where
    F: PrimeField + Serialize,
    T: FnMut(&mut Transcript<F>, usize, &MatrixPair<F>) -> Result<(), Error>,
{
    let degree = shape.validate()?;
    validate_tables(shape, factors)?;
    bind(trans, shape, claimed_sum)?;
    let mut tables = factors.to_vec();
    let mut expected = claimed_sum.to_vec();
    let mut query = Vec::with_capacity(shape.num_vars);
    let mut rounds = Vec::with_capacity(shape.num_vars);
    for round in 0..shape.num_vars {
        let suffixes = 1usize << (shape.num_vars - round - 1);
        let evaluations = round_evaluations(shape, &tables, suffixes, degree);
        check_round(shape.width, &evaluations, &expected)?;
        trans.append_message(b"packed round", &evaluations);
        let r = trans.get_vec_challenge(b"packed independent challenges", shape.width);
        expected = r
            .iter()
            .map(|&r| interpolate_uni_poly(&evaluations, r))
            .collect();
        let pair = challenge_pair(&r).map_err(shape_error)?;
        tables
            .par_iter_mut()
            .try_for_each(|table| table.fold_in_place(&pair).map_err(shape_error))?;
        after_challenge(trans, round, &pair)?;
        query.push(pair);
        rounds.push(evaluations);
    }
    let terminal: Vec<Vec<F>> = tables.iter().map(|t| t.values().to_vec()).collect();
    if shape.evaluate(&terminal)? != expected {
        return Err(reject("false packed terminal claim"));
    }
    Ok((
        PackedProof { rounds },
        PackedSubclaim { query, expected },
        terminal,
    ))
}

/// Verify round consistency and return the remaining commitment obligation.
pub fn verify<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    claimed_sum: &[F],
    proof: &PackedProof<F>,
) -> Result<PackedSubclaim<F>, Error> {
    verify_with_rounds(trans, shape, claimed_sum, proof, |_, _, _| Ok(()))
}

/// Verify with the same per-challenge authenticated-oracle schedule as proving.
pub fn verify_with_rounds<F, T>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    claimed_sum: &[F],
    proof: &PackedProof<F>,
    mut after_challenge: T,
) -> Result<PackedSubclaim<F>, Error>
where
    F: PrimeField + Serialize,
    T: FnMut(&mut Transcript<F>, usize, &MatrixPair<F>) -> Result<(), Error>,
{
    let degree = shape.validate()?;
    if proof.rounds.len() != shape.num_vars || proof.rounds.iter().any(|p| p.len() != degree + 1) {
        return Err(reject("incorrect packed proof length"));
    }
    bind(trans, shape, claimed_sum)?;
    let mut expected = claimed_sum.to_vec();
    let mut query = Vec::with_capacity(shape.num_vars);
    for (round, evaluations) in proof.rounds.iter().enumerate() {
        check_round(shape.width, evaluations, &expected)?;
        trans.append_message(b"packed round", evaluations);
        let r = trans.get_vec_challenge(b"packed independent challenges", shape.width);
        expected = r
            .iter()
            .map(|&r| interpolate_uni_poly(evaluations, r))
            .collect();
        let pair = challenge_pair(&r).map_err(shape_error)?;
        after_challenge(trans, round, &pair)?;
        query.push(pair);
    }
    Ok(PackedSubclaim { query, expected })
}

/// Compute an honest hypercube sum, useful for constructing claims and fixtures.
pub fn sum<F: PrimeField>(
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
) -> Result<Vec<F>, Error> {
    shape.validate()?;
    validate_tables(shape, factors)?;
    let mut total = vec![F::zero(); shape.width];
    for b in 0..(1usize << shape.num_vars) {
        for (coefficient, indices) in &shape.terms {
            for lane in 0..shape.width {
                total[lane] += indices
                    .iter()
                    .fold(*coefficient, |acc, &i| acc * factors[i].at(b)[lane]);
            }
        }
    }
    Ok(total)
}

pub(crate) fn validate_tables<F: PrimeField>(
    shape: &PackedShape<F>,
    tables: &[impl std::borrow::Borrow<PackedTable<F>>],
) -> Result<(), Error> {
    if tables.len() != shape.num_factors {
        return Err(reject("incorrect packed factor count"));
    }
    for table in tables {
        let table = table.borrow();
        table.validate().map_err(shape_error)?;
        if table.num_vars() != shape.num_vars || table.width() != shape.width {
            return Err(reject("incorrect packed factor shape"));
        }
    }
    Ok(())
}

fn bind<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    claim: &[F],
) -> Result<(), Error> {
    if claim.len() != shape.width {
        return Err(reject("incorrect packed claim width"));
    }
    trans.append_message(b"packed sumcheck v1", shape);
    trans.append_message(b"packed claimed sum", &claim);
    Ok(())
}

pub(crate) fn check_round<F: Field>(
    width: usize,
    evaluations: &[F],
    expected: &[F],
) -> Result<(), Error> {
    for lane in 0..width {
        if evaluations[2 * lane] + evaluations[2 * lane + 1] != expected[lane] {
            return Err(reject("packed round inconsistent with claim"));
        }
    }
    Ok(())
}

pub(crate) fn reject(message: &str) -> Error {
    Error::Reject(Some(message.into()))
}
pub(crate) fn shape_error(error: ShapeError) -> Error {
    reject(&error.to_string())
}

// Forward differences extrapolate the degree-(2k-1) lane interpolation with
// additions only, instead of multiplying by a dense basis at every node.
#[derive(Default)]
pub(crate) struct DifferenceScratch<F> {
    differences: Vec<F>,
    diagonal: Vec<F>,
}

pub(crate) fn extrapolate<F: Field>(
    values: &mut Vec<F>,
    output_len: usize,
    scratch: &mut DifferenceScratch<F>,
) {
    if output_len <= values.len() {
        return;
    }
    let differences = &mut scratch.differences;
    let diagonal = &mut scratch.diagonal;
    differences.clear();
    differences.extend_from_slice(values);
    diagonal.clear();
    diagonal.push(*values.last().unwrap());
    for order in 1..values.len() {
        for i in 0..values.len() - order {
            differences[i] = differences[i + 1] - differences[i];
        }
        diagonal.push(differences[values.len() - order - 1]);
    }
    while values.len() < output_len {
        for i in (0..diagonal.len() - 1).rev() {
            let next = diagonal[i + 1];
            diagonal[i] += next;
        }
        values.push(diagonal[0]);
    }
}

// Cell-constant factors have the same 2k interpolation inputs for every
// suffix. Cache their evaluations once, without reordering product arithmetic.
pub(crate) fn constant_interpolations<F: Field>(
    tables: &[impl std::borrow::Borrow<PackedTable<F>> + Sync],
    degree: usize,
) -> Vec<Option<Vec<F>>> {
    tables
        .par_iter()
        .map(|table| {
            let table = table.borrow();
            if table
                .constant_lanes()
                .expect("validated packed factor")
                .is_none()
            {
                return None;
            }
            let mut values = Vec::with_capacity(degree + 1);
            for lane in 0..table.width() {
                values.push(table.at(0)[lane]);
                values.push(table.at(1)[lane]);
            }
            extrapolate(&mut values, degree + 1, &mut DifferenceScratch::default());
            Some(values)
        })
        .collect()
}

pub(crate) fn round_evaluations<F: PrimeField>(
    shape: &PackedShape<F>,
    tables: &[PackedTable<F>],
    suffixes: usize,
    degree: usize,
) -> Vec<F> {
    let cached = constant_interpolations(tables, degree);
    (0..suffixes)
        .into_par_iter()
        .fold(
            || {
                (
                    vec![F::zero(); degree + 1],
                    (0..tables.len())
                        .map(|i| {
                            cached[i]
                                .clone()
                                .unwrap_or_else(|| Vec::with_capacity(degree + 1))
                        })
                        .collect::<Vec<_>>(),
                    DifferenceScratch::default(),
                )
            },
            |(mut total, mut interpolated, mut scratch), b| {
                for (i, (table, values)) in tables.iter().zip(&mut interpolated).enumerate() {
                    if cached[i].is_some() {
                        continue;
                    }
                    values.clear();
                    for lane in 0..shape.width {
                        values.push(table.at(2 * b)[lane]);
                        values.push(table.at(2 * b + 1)[lane]);
                    }
                    extrapolate(values, degree + 1, &mut scratch);
                }
                for (coefficient, indices) in &shape.terms {
                    for (node, out) in total.iter_mut().enumerate() {
                        *out += indices
                            .iter()
                            .fold(*coefficient, |value, &i| value * interpolated[i][node]);
                    }
                }
                (total, interpolated, scratch)
            },
        )
        .map(|(total, _, _)| total)
        .reduce(
            || vec![F::zero(); degree + 1],
            |mut left, right| {
                for (a, b) in left.iter_mut().zip(right) {
                    *a += b;
                }
                left
            },
        )
}

#[cfg(test)]
mod constant_tests {
    use super::*;
    use algebra::{BabyBear, Goldilocks};
    fn check<F: PrimeField + From<usize>>() {
        for k in [1, 3, 8] {
            let n = 3;
            let dense = PackedTable::new(
                n,
                k,
                (0..(1 << n) * k).map(|i| F::from(i * 7 + 3)).collect(),
            )
            .unwrap();
            let constant = PackedTable::new(
                n,
                k,
                (0..1 << n)
                    .flat_map(|_| (0..k).map(|i| F::from(i * 3 + 5)))
                    .collect(),
            )
            .unwrap();
            let zero = PackedTable::new(n, k, vec![F::zero(); (1 << n) * k]).unwrap();
            let tables = vec![dense, constant, zero];
            let shape = PackedShape {
                num_vars: n,
                width: k,
                num_factors: 3,
                terms: vec![
                    (F::one(), vec![0, 1, 1]),
                    (F::from(2), vec![1]),
                    (F::one(), vec![0, 2]),
                ],
            };
            let degree = shape.validate().unwrap();
            let cached = constant_interpolations(&tables, degree);
            assert!(cached[0].is_none());
            assert!(cached[1].is_some());
            assert!(cached[2].is_some());
            let actual = round_evaluations(&shape, &tables, 1 << (n - 1), degree);
            let mut expected = vec![F::zero(); degree + 1];
            for (node, out) in expected.iter_mut().enumerate() {
                // Direct interpolation from the 2k Boolean/lane values uses
                // multiplication/division, independently of forward differences.
                let weights = lagrange_weights(2 * k, F::from(node));
                for b in 0..1 << (n - 1) {
                    let at: Vec<_> = tables
                        .iter()
                        .map(|table| {
                            (0..k).fold(F::zero(), |s, lane| {
                                s + weights[2 * lane] * table.at(2 * b)[lane]
                                    + weights[2 * lane + 1] * table.at(2 * b + 1)[lane]
                            })
                        })
                        .collect();
                    for (coefficient, indices) in &shape.terms {
                        *out += indices.iter().fold(*coefficient, |v, &i| v * at[i]);
                    }
                }
            }
            assert_eq!(actual, expected);
        }
        let original = vec![F::from(2), F::from(7), F::from(11)];
        let mut values = original.clone();
        extrapolate(
            &mut values,
            original.len(),
            &mut DifferenceScratch::default(),
        );
        assert_eq!(values, original);
    }
    #[test]
    fn cached_rounds_match_direct_interpolation() {
        check::<BabyBear>();
        check::<Goldilocks>();
    }
}
