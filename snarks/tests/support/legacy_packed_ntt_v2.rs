//! Frozen NTT reference from 624adca; retain direct Brakedown dispatch.
//! Tensor-row variant of the vector NTT check in 2025/719 Appendix H.1.
//!
//! Each of k row challenges is an independent Boolean-MLE tensor, instead of a
//! dense vector of row coefficients. The row-check error is (log2(m)/p)^k.
//! Claimed folded polynomials are bound before independent matrix challenges
//! compress their coefficients. Their source values are authenticated against
//! the SAME commitments used by other relations; no unlinked witness view is
//! introduced. Forward and inverse NTT relations both use coefficient/NTT roles.

use algebra::{
    NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, Parameters},
    utils::{code::RowCode, hash::Hash},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use snarks::packed_oracle::{ProverOracle, VerifierOracle};
use sumcheck::packed::challenge_pair;

/// Invalid shape, false NTT relation, or rejected commitment opening.
#[derive(Debug, thiserror::Error)]
#[error("packed NTT: {0}")]
pub struct Error(pub String);

/// Trusted NTT relation shape, derived from canonical oracle parameters.
#[derive(Clone, Debug, Serialize)]
pub struct Shape {
    polynomial_size: usize,
    width: usize,
    num_polynomials: usize,
}

impl Shape {
    /// Construct a relation for all polynomial blocks of an existing oracle.
    /// Packing width and polynomial size must be powers of two, with width <= N.
    pub fn new<F: NTTField, C>(
        parameters: &Parameters<C>,
        polynomial_size: usize,
    ) -> Result<Self, Error> {
        let width = parameters.width();
        if !width.is_power_of_two() || !polynomial_size.is_power_of_two() || width > polynomial_size
        {
            return Err(error("invalid NTT polynomial size or packing width"));
        }
        let length = (1usize << parameters.num_vars())
            .checked_mul(width)
            .ok_or_else(|| error("table size overflow"))?;
        if length < polynomial_size || length % polynomial_size != 0 {
            return Err(error("NTT size does not divide the canonical table"));
        }
        F::generate_ntt_table(polynomial_size.ilog2()).map_err(convert)?;
        F::init_ntt_table(polynomial_size.ilog2()).map_err(convert)?;
        Ok(Self {
            polynomial_size,
            width,
            num_polynomials: length / polynomial_size,
        })
    }
    /// Coefficients per polynomial.
    pub fn polynomial_size(&self) -> usize {
        self.polynomial_size
    }
    /// Number of independent tensor-row checks.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Number of canonical polynomial blocks, including zero padding.
    pub fn num_polynomials(&self) -> usize {
        self.num_polynomials
    }
    /// Number of random row variables per repetition.
    pub fn row_variables(&self) -> usize {
        self.num_polynomials.ilog2() as usize
    }
    /// Number of packed coefficient variables in the compression query.
    pub fn coefficient_variables(&self) -> usize {
        (self.polynomial_size / self.width).ilog2() as usize
    }

    fn validate<C>(&self, parameters: &Parameters<C>) -> Result<(), Error> {
        if parameters.width() != self.width
            || !self.width.is_power_of_two()
            || !self.polynomial_size.is_power_of_two()
            || self.polynomial_size < self.width
            || !self.num_polynomials.is_power_of_two()
            || parameters.num_vars() != self.coefficient_variables() + self.row_variables()
        {
            return Err(error("canonical oracle does not match NTT shape"));
        }
        Ok(())
    }
}

/// Complete NTT component proof, with no private source tables in the verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// k folded coefficient vectors, each of length N.
    pub coefficients: Vec<Vec<F>>,
    /// k folded NTT vectors, each of length N, in the native bit-reversed order.
    pub evaluations: Vec<Vec<F>>,
    /// Authenticate the folded coefficients against their canonical source.
    pub coefficient_opening: BatchOpening<F, O>,
    /// Authenticate the folded evaluations against their canonical source.
    pub evaluation_opening: BatchOpening<F, O>,
}

/// Prove that every canonical polynomial block satisfies evaluation = NTT(coefficients).
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &ProverOracle<'_, F, H, C>,
    evaluations: &ProverOracle<'_, F, H, C>,
) -> Result<Proof<F, H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, H, C>(
        trans,
        shape,
        &coefficients.verifier(),
        &evaluations.verifier(),
    )?;
    for oracle in [coefficients, evaluations] {
        oracle.table.validate().map_err(convert)?;
        if oracle.table.width() != shape.width
            || oracle.table.num_vars() != oracle.parameters.num_vars()
        {
            return Err(error("source table shape mismatch"));
        }
    }
    let points = row_points(trans, shape);
    let folded_coefficients = fold_rows(shape, coefficients.table, &points);
    let folded_evaluations = fold_rows(shape, evaluations.table, &points);
    trans.append_message(
        b"packed NTT folded polynomials",
        &(&folded_coefficients, &folded_evaluations),
    );
    check_folded::<F>(shape, &folded_coefficients, &folded_evaluations)?;
    let compression = coefficient_query(trans, shape)?;
    let queries = points
        .iter()
        .map(|point| source_query(shape, &compression, point))
        .collect::<Result<Vec<_>, _>>()?;
    let coefficient_values = folded_coefficients
        .iter()
        .map(|v| compressed_value(shape, v, &compression))
        .collect::<Result<Vec<_>, _>>()?;
    let evaluation_values = folded_evaluations
        .iter()
        .map(|v| compressed_value(shape, v, &compression))
        .collect::<Result<Vec<_>, _>>()?;
    let coefficient_opening = coefficients
        .parameters
        .open_many::<F, H>(
            trans,
            coefficients.commitment,
            coefficients.state,
            &queries,
            &coefficient_values,
        )
        .map_err(convert)?;
    let evaluation_opening = evaluations
        .parameters
        .open_many::<F, H>(
            trans,
            evaluations.commitment,
            evaluations.state,
            &queries,
            &evaluation_values,
        )
        .map_err(convert)?;
    Ok(Proof {
        coefficients: folded_coefficients,
        evaluations: folded_evaluations,
        coefficient_opening,
        evaluation_opening,
    })
}

/// Verify the local NTTs and all source openings using trusted canonical commitments.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &VerifierOracle<'_, H::Output, C>,
    evaluations: &VerifierOracle<'_, H::Output, C>,
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, H, C>(trans, shape, coefficients, evaluations)?;
    let points = row_points(trans, shape);
    trans.append_message(
        b"packed NTT folded polynomials",
        &(&proof.coefficients, &proof.evaluations),
    );
    check_folded::<F>(shape, &proof.coefficients, &proof.evaluations)?;
    let compression = coefficient_query(trans, shape)?;
    let queries = points
        .iter()
        .map(|point| source_query(shape, &compression, point))
        .collect::<Result<Vec<_>, _>>()?;
    let coefficient_values = proof
        .coefficients
        .iter()
        .map(|v| compressed_value(shape, v, &compression))
        .collect::<Result<Vec<_>, _>>()?;
    let evaluation_values = proof
        .evaluations
        .iter()
        .map(|v| compressed_value(shape, v, &compression))
        .collect::<Result<Vec<_>, _>>()?;
    coefficients
        .parameters
        .verify_many::<F, H>(
            trans,
            coefficients.commitment,
            &queries,
            &coefficient_values,
            &proof.coefficient_opening,
        )
        .map_err(convert)?;
    evaluations
        .parameters
        .verify_many::<F, H>(
            trans,
            evaluations.commitment,
            &queries,
            &evaluation_values,
            &proof.evaluation_opening,
        )
        .map_err(convert)?;
    Ok(())
}

fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &VerifierOracle<'_, H::Output, C>,
    evaluations: &VerifierOracle<'_, H::Output, C>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    shape.validate(coefficients.parameters)?;
    shape.validate(evaluations.parameters)?;
    let table = F::get_ntt_table(shape.polynomial_size.ilog2()).map_err(convert)?;
    let contexts = (
        coefficients
            .parameters
            .context_digest::<F, H>()
            .map_err(convert)?,
        evaluations
            .parameters
            .context_digest::<F, H>()
            .map_err(convert)?,
    );
    trans.append_message(
        b"packed tensor NTT v2",
        &(
            F::MODULUS_VALUE.to_string(),
            shape,
            table.root(),
            contexts,
            coefficients.commitment,
            evaluations.commitment,
        ),
    );
    Ok(())
}

fn row_points<F: NTTField>(trans: &mut Transcript<F>, shape: &Shape) -> Vec<Vec<F>> {
    (0..shape.width)
        .map(|_| {
            trans.get_vec_challenge(b"packed NTT independent row point", shape.row_variables())
        })
        .collect()
}

fn tensor<F: NTTField>(point: &[F]) -> Vec<F> {
    let mut values = vec![F::one()];
    for &r in point {
        let mut next = Vec::with_capacity(values.len() * 2);
        for &value in &values {
            next.push((F::one() - r) * value);
        }
        for &value in &values {
            next.push(r * value);
        }
        values = next;
    }
    values
}

fn fold_rows<F: NTTField>(shape: &Shape, table: &PackedTable<F>, points: &[Vec<F>]) -> Vec<Vec<F>> {
    let weights: Vec<_> = points.iter().map(|point| tensor(point)).collect();
    let n = shape.polynomial_size;
    let tile = n.min(128);
    let tiles = n / tile;
    let mut folded = vec![F::zero(); shape.width * n];
    folded
        .par_chunks_exact_mut(tile)
        .enumerate()
        .for_each(|(index, out)| {
            let repetition = index / tiles;
            let start = (index % tiles) * tile;
            for (row, &weight) in table.values().chunks_exact(n).zip(&weights[repetition]) {
                for (out, &value) in out.iter_mut().zip(&row[start..start + tile]) {
                    *out += weight * value;
                }
            }
        });
    folded.chunks_exact(n).map(|row| row.to_vec()).collect()
}

fn check_folded<F: NTTField>(
    shape: &Shape,
    coefficients: &[Vec<F>],
    evaluations: &[Vec<F>],
) -> Result<(), Error> {
    if coefficients.len() != shape.width
        || evaluations.len() != shape.width
        || coefficients
            .iter()
            .chain(evaluations)
            .any(|row| row.len() != shape.polynomial_size)
    {
        return Err(error("malformed folded polynomial dimensions"));
    }
    let table = F::get_ntt_table(shape.polynomial_size.ilog2()).map_err(convert)?;
    for (coefficients, evaluations) in coefficients.iter().zip(evaluations) {
        let mut expected = coefficients.clone();
        table.transform_slice(&mut expected);
        if expected != *evaluations {
            return Err(error("folded NTT identity failed"));
        }
    }
    Ok(())
}

fn coefficient_query<F: NTTField>(
    trans: &mut Transcript<F>,
    shape: &Shape,
) -> Result<Vec<MatrixPair<F>>, Error> {
    (0..shape.coefficient_variables())
        .map(|_| {
            let r = trans.get_vec_challenge(b"packed NTT coefficient compression", shape.width);
            challenge_pair(&r).map_err(convert)
        })
        .collect()
}

fn source_query<F: NTTField>(
    shape: &Shape,
    compression: &[MatrixPair<F>],
    point: &[F],
) -> Result<Vec<MatrixPair<F>>, Error> {
    let mut query = compression.to_vec();
    let identity = |scalar| {
        let mut values = vec![F::zero(); shape.width * shape.width];
        for i in 0..shape.width {
            values[i * shape.width + i] = scalar;
        }
        Matrix::new(shape.width, values).map_err(convert)
    };
    for &r in point {
        query.push(MatrixPair {
            zero: identity(F::one() - r)?,
            one: identity(r)?,
        });
    }
    Ok(query)
}

fn compressed_value<F: NTTField>(
    shape: &Shape,
    values: &[F],
    query: &[MatrixPair<F>],
) -> Result<Vec<F>, Error> {
    PackedTable::new(shape.coefficient_variables(), shape.width, values.to_vec())
        .map_err(convert)?
        .evaluate(query)
        .map_err(convert)
}

fn error(message: &str) -> Error {
    Error(message.into())
}
fn convert(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}
