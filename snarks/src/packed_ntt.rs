//! Tensor-row variant of the vector NTT check in 2025/719 Appendix H.1.
//!
//! Each of k row challenges is an independent Boolean-MLE tensor, instead of a
//! dense vector of row coefficients. The row-check error is (log2(m)/p)^k.
//! Claimed folded polynomials are bound before independent matrix challenges
//! compress their coefficients. Their source values are authenticated against
//! the SAME commitments used by other relations; no unlinked witness view is
//! introduced. Forward and inverse NTT relations both use coefficient/NTT roles.

use crate::packed_oracle::{
    CanonicalProverOracle, CanonicalVerifierOracle, ProverOracle, VerifierOracle,
};
use algebra::{
    NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, Parameters, backend::CanonicalPcs},
    utils::{code::RowCode, hash::Hash},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
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
        Self::from_dimensions::<F>(parameters.num_vars(), parameters.width(), polynomial_size)
    }
    /// Construct the same logical NTT shape for a trusted canonical PCS backend.
    pub fn new_canonical<F, H, P>(parameters: &P, polynomial_size: usize) -> Result<Self, Error>
    where
        F: NTTField + Serialize,
        H: Hash + Send + Sync,
        P: CanonicalPcs<F, H>,
    {
        Self::from_dimensions::<F>(parameters.num_vars(), parameters.width(), polynomial_size)
    }
    fn from_dimensions<F: NTTField>(
        num_vars: usize,
        width: usize,
        polynomial_size: usize,
    ) -> Result<Self, Error> {
        if !width.is_power_of_two() || !polynomial_size.is_power_of_two() || width > polynomial_size
        {
            return Err(error("invalid NTT polynomial size or packing width"));
        }
        let length = 1usize
            .checked_shl(u32::try_from(num_vars).map_err(|_| error("table dimension overflow"))?)
            .and_then(|n| n.checked_mul(width))
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

    fn validate(&self, num_vars: usize, width: usize) -> Result<(), Error> {
        if width != self.width
            || !self.width.is_power_of_two()
            || !self.polynomial_size.is_power_of_two()
            || self.polynomial_size < self.width
            || !self.num_polynomials.is_power_of_two()
            || num_vars != self.coefficient_variables() + self.row_variables()
        {
            return Err(error("canonical oracle does not match NTT shape"));
        }
        Ok(())
    }
}

/// Complete NTT component proof, with no private source tables in the verifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalProof<F, P> {
    /// k folded coefficient vectors, each of length N.
    pub coefficients: Vec<Vec<F>>,
    /// k folded NTT vectors, each of length N, in the native bit-reversed order.
    pub evaluations: Vec<Vec<F>>,
    /// Authenticate the folded coefficients against their canonical source.
    pub coefficient_opening: P,
    /// Authenticate the folded evaluations against their canonical source.
    pub evaluation_opening: P,
}

/// Legacy Brakedown packet spelling and wire layout.
pub type Proof<F, O> = CanonicalProof<F, BatchOpening<F, O>>;
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
    prove_inner::<F, H, Parameters<C>>(
        trans,
        shape,
        &coefficients.verifier(),
        coefficients.state,
        coefficients.table,
        &evaluations.verifier(),
        evaluations.state,
        evaluations.table,
    )
}
/// Prove the transform against the actual retained tables of a canonical backend.
pub fn prove_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &CanonicalProverOracle<'_, F, H, P>,
    evaluations: &CanonicalProverOracle<'_, F, H, P>,
) -> Result<CanonicalProof<F, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    prove_inner::<F, H, P>(
        trans,
        shape,
        &coefficients.verifier(),
        coefficients.state,
        coefficients.table(),
        &evaluations.verifier(),
        evaluations.state,
        evaluations.table(),
    )
}
fn prove_inner<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &CanonicalVerifierOracle<'_, H::Output, P>,
    coefficient_state: &P::State,
    coefficient_table: &PackedTable<F>,
    evaluations: &CanonicalVerifierOracle<'_, H::Output, P>,
    evaluation_state: &P::State,
    evaluation_table: &PackedTable<F>,
) -> Result<CanonicalProof<F, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, H, P>(trans, shape, coefficients, evaluations)?;
    for (oracle, table) in [
        (coefficients, coefficient_table),
        (evaluations, evaluation_table),
    ] {
        table.validate().map_err(convert)?;
        if table.width() != shape.width || table.num_vars() != oracle.parameters.num_vars() {
            return Err(error("source table shape mismatch"));
        }
    }
    let points = row_points(trans, shape);
    let folded_coefficients: Vec<_> = fold_rows(shape, coefficient_table, &points)
        .into_iter()
        .map(|v| coefficients.parameters.normalize_values(v))
        .collect();
    let folded_evaluations: Vec<_> = fold_rows(shape, evaluation_table, &points)
        .into_iter()
        .map(|v| evaluations.parameters.normalize_values(v))
        .collect();
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
        .open_many(
            trans,
            coefficients.commitment,
            coefficient_state,
            &queries,
            &coefficient_values,
        )
        .map_err(convert)?;
    let evaluation_opening = evaluations
        .parameters
        .open_many(
            trans,
            evaluations.commitment,
            evaluation_state,
            &queries,
            &evaluation_values,
        )
        .map_err(convert)?;
    Ok(CanonicalProof {
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
    verify_canonical::<F, H, Parameters<C>>(trans, shape, coefficients, evaluations, proof)
}
/// Verify local transforms and every caller-root opening through a canonical PCS.
pub fn verify_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &CanonicalVerifierOracle<'_, H::Output, P>,
    evaluations: &CanonicalVerifierOracle<'_, H::Output, P>,
    proof: &CanonicalProof<F, P::BatchProof>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, H, P>(trans, shape, coefficients, evaluations)?;
    for row in &proof.coefficients {
        coefficients
            .parameters
            .validate_values(row)
            .map_err(convert)?;
    }
    for row in &proof.evaluations {
        evaluations
            .parameters
            .validate_values(row)
            .map_err(convert)?;
    }
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
        .verify_many(
            trans,
            coefficients.commitment,
            &queries,
            &coefficient_values,
            &proof.coefficient_opening,
        )
        .map_err(convert)?;
    evaluations
        .parameters
        .verify_many(
            trans,
            evaluations.commitment,
            &queries,
            &evaluation_values,
            &proof.evaluation_opening,
        )
        .map_err(convert)?;
    Ok(())
}

fn bind<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &CanonicalVerifierOracle<'_, H::Output, P>,
    evaluations: &CanonicalVerifierOracle<'_, H::Output, P>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    shape.validate(
        coefficients.parameters.num_vars(),
        coefficients.parameters.width(),
    )?;
    shape.validate(
        evaluations.parameters.num_vars(),
        evaluations.parameters.width(),
    )?;
    let table = F::get_ntt_table(shape.polynomial_size.ilog2()).map_err(convert)?;
    let contexts = (
        coefficients.parameters.context().map_err(convert)?,
        evaluations.parameters.context().map_err(convert)?,
    );
    trans.append_message(
        P::NTT_DOMAIN,
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

#[cfg(test)]
pub(crate) fn audit_binding_row_points<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &CanonicalVerifierOracle<'_, H::Output, P>,
    evaluations: &CanonicalVerifierOracle<'_, H::Output, P>,
) -> Result<Vec<Vec<F>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, H, P>(trans, shape, coefficients, evaluations)?;
    Ok(row_points(trans, shape))
}

#[cfg(test)]
pub(crate) fn audit_folded_compression<F: NTTField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &[Vec<F>],
    evaluations: &[Vec<F>],
) -> Result<Vec<MatrixPair<F>>, Error> {
    trans.append_message(b"packed NTT folded polynomials", &(coefficients, evaluations));
    check_folded::<F>(shape, coefficients, evaluations)?;
    coefficient_query(trans, shape)
}

fn row_points<F: NTTField>(trans: &mut Transcript<F>, shape: &Shape) -> Vec<Vec<F>> {
    if trans.uses_atomic_ntt_rows() {
        let rows = shape.row_variables();
        let count = shape
            .width
            .checked_mul(rows)
            .expect("trusted NTT row geometry");
        let values = trans.get_vec_challenge(b"packed NTT atomic row points v2", count);
        return if rows == 0 {
            vec![vec![]; shape.width]
        } else {
            values.chunks_exact(rows).map(<[F]>::to_vec).collect()
        };
    }
    (0..shape.width)
        .map(|_| {
            trans.get_vec_challenge(b"packed NTT independent row point", shape.row_variables())
        })
        .collect()
}

#[cfg(test)]
mod atomic_row_tests {
    use super::*;
    fn check<F: NTTField + Serialize>() {
        for vars in [2, 4] {
            let shape = Shape::from_dimensions::<F>(vars, 8, 32).unwrap();
            for atomic in [false, true] {
                let make = || {
                    if atomic {
                        Transcript::<F>::new_classical_atomic_ntt(&[44; 64])
                    } else {
                        Transcript::<F>::new_classical(&[44; 64])
                    }
                };
                let mut actual = make();
                let mut expected = make();
                let points = row_points(&mut actual, &shape);
                let reference: Vec<F> = if atomic {
                    expected.get_vec_challenge(
                        b"packed NTT atomic row points v2",
                        shape.width * shape.row_variables(),
                    )
                } else {
                    (0..shape.width)
                        .flat_map(|_| {
                            expected.get_vec_challenge(
                                b"packed NTT independent row point",
                                shape.row_variables(),
                            )
                        })
                        .collect()
                };
                assert_eq!(points.len(), shape.width);
                assert_eq!(points.into_iter().flatten().collect::<Vec<_>>(), reference);
                assert_eq!(
                    actual.get_challenge(b"after rows"),
                    expected.get_challenge(b"after rows")
                );
            }
        }
    }
    #[test]
    fn atomic_ntt_rows_match_one_phase_and_legacy_schedule() {
        check::<algebra::BabyBear>();
        check::<algebra::Goldilocks>();
    }
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

#[cfg(test)]
pub(crate) type AuditSourceObligations<F> = (Vec<Vec<MatrixPair<F>>>, Vec<Vec<F>>, Vec<Vec<F>>);

#[cfg(all(test, feature = "transcript-audit"))]
pub(crate) fn audit_verified_source_obligations<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    coefficients: &CanonicalVerifierOracle<'_, H::Output, P>,
    evaluations: &CanonicalVerifierOracle<'_, H::Output, P>,
    proof: &CanonicalProof<F, P::BatchProof>,
) -> Result<AuditSourceObligations<F>, Error>
where F: NTTField + Serialize, H: Hash + Send + Sync, P: CanonicalPcs<F, H>,
{
    let points = audit_binding_row_points::<F, H, P>(trans, shape, coefficients, evaluations)?;
    let compression = audit_folded_compression(trans, shape, &proof.coefficients, &proof.evaluations)?;
    let (queries, co, ev) = audit_source_obligations(shape, &compression, &points, &proof.coefficients, &proof.evaluations)?;
    coefficients.parameters.verify_many(trans, coefficients.commitment, &queries, &co, &proof.coefficient_opening).map_err(convert)?;
    evaluations.parameters.verify_many(trans, evaluations.commitment, &queries, &ev, &proof.evaluation_opening).map_err(convert)?;
    Ok((queries, co, ev))
}

#[cfg(test)]
pub(crate) fn audit_source_obligations<F: NTTField>(
    shape: &Shape,
    compression: &[MatrixPair<F>],
    points: &[Vec<F>],
    coefficients: &[Vec<F>],
    evaluations: &[Vec<F>],
) -> Result<AuditSourceObligations<F>, Error> {
    let queries = points.iter().map(|p| source_query(shape, compression, p)).collect::<Result<_, _>>()?;
    let co = coefficients.iter().map(|p| compressed_value(shape, p, compression)).collect::<Result<_, _>>()?;
    let ev = evaluations.iter().map(|p| compressed_value(shape, p, compression)).collect::<Result<_, _>>()?;
    Ok((queries, co, ev))
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
