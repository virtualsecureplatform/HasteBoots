//! Packed ZeroCheck from 2025/719 §5.1, including its special first round.
//!
//! Independent equality points and a random mixing matrix are essential here;
//! repeating a scalar ZeroCheck is not a substitute for this construction.

use crate::{
    error::Error,
    packed::{
        self, DifferenceScratch, PackedProof, PackedShape, extrapolate, reject, shape_error,
        validate_tables,
    },
    verifier::interpolate_uni_poly,
};
use algebra::{
    PrimeField,
    matrix_weighted::{MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Independent relations with shared matrix challenges and terminal query.
pub mod batch;

/// Packed ZeroCheck proof, with one initial polynomial per equality point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroProof<F> {
    /// Coefficients of the linear-in-t first message, in evaluation form in y.
    pub first: Vec<Vec<F>>,
    /// Packed sumcheck over the remaining variables, including the EQ factor.
    pub rest: PackedProof<F>,
}

/// Opening obligation against the original committed factors.
#[derive(Clone, Debug)]
pub struct ZeroSubclaim<F> {
    /// Query for each original factor table.
    pub query: Vec<MatrixPair<F>>,
    /// Expected product/sum after multiplication by the public equality vector.
    pub expected: Vec<F>,
    /// Verifier-computed value of the public matrix-weighted EQ factor.
    pub equality: Vec<F>,
}

impl<F: PrimeField> ZeroSubclaim<F> {
    /// Check terminal vectors only after authenticating them with a commitment.
    pub fn check(&self, shape: &PackedShape<F>, factors: &[Vec<F>]) -> Result<(), Error> {
        let actual = shape.evaluate(factors)?;
        if actual.len() != self.expected.len()
            || actual.len() != self.equality.len()
            || actual
                .iter()
                .zip(&self.equality)
                .zip(&self.expected)
                .any(|((&a, &b), &c)| a * b != c)
        {
            return Err(reject("packed ZeroCheck terminal identity failed"));
        }
        Ok(())
    }
}

/// Prove that the sum-of-products expression vanishes at every Boolean index
/// in every lane. Commitments and public statement must already be bound.
pub fn prove<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
) -> Result<(ZeroProof<F>, ZeroSubclaim<F>), Error> {
    prove_with_terminal_values(trans, shape, factors).map(|(proof, subclaim, _)| (proof, subclaim))
}

/// Retain original-factor terminals already computed by the folding prover.
/// The returned vectors still require authentication against canonical roots.
pub fn prove_with_terminal_values<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
) -> Result<(ZeroProof<F>, ZeroSubclaim<F>, Vec<Vec<F>>), Error> {
    prove_with_rounds(trans, shape, factors, |_, _, _| Ok(()))
}

/// Prove with an oracle-fold callback after each original-factor challenge.
/// The special first ZeroCheck round is callback zero; subsequent callbacks
/// precede the next packed-sumcheck challenge. Empty callbacks preserve the
/// existing proof bytes and transcript.
pub fn prove_with_rounds<F, T>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    factors: &[PackedTable<F>],
    mut after_challenge: T,
) -> Result<(ZeroProof<F>, ZeroSubclaim<F>, Vec<Vec<F>>), Error>
where
    F: PrimeField + Serialize,
    T: FnMut(&mut Transcript<F>, usize, &MatrixPair<F>) -> Result<(), Error>,
{
    let degree = bind(trans, shape)?;
    validate_tables(shape, factors)?;
    let points = sample_points(trans, shape);
    let equality: Vec<_> = points.iter().map(|p| equality_table(p)).collect();
    let first = first_evaluations(shape, factors, degree, &equality);
    check_first(shape, degree, &first)?;
    let (pair, mixing, claim) = reduce(trans, shape, &first)?;
    after_challenge(trans, 0, &pair)?;
    let eq = mixed_equality(shape, &equality, &mixing)?;
    let mut folded = factors
        .par_iter()
        .map(|t| t.fold(&pair).map_err(shape_error))
        .collect::<Result<Vec<_>, _>>()?;
    folded.push(eq.clone());
    let reduced = reduced_shape(shape);
    let (rest, subclaim, mut terminals) =
        packed::prove_with_rounds(trans, &reduced, &folded, &claim, |t, i, pair| {
            after_challenge(t, i + 1, pair)
        })?;
    let equality = terminals
        .pop()
        .ok_or_else(|| reject("missing equality terminal"))?;
    let mut query = vec![pair];
    query.extend(subclaim.query);
    Ok((
        ZeroProof { first, rest },
        ZeroSubclaim {
            query,
            expected: subclaim.expected,
            equality,
        },
        terminals,
    ))
}

/// Verify and return the matrix-weighted opening obligations.
pub fn verify<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    proof: &ZeroProof<F>,
) -> Result<ZeroSubclaim<F>, Error> {
    verify_with_rounds(trans, shape, proof, |_, _, _| Ok(()))
}

/// Verify the same first-round and subsequent oracle-fold callback schedule.
pub fn verify_with_rounds<F, T>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    proof: &ZeroProof<F>,
    mut after_challenge: T,
) -> Result<ZeroSubclaim<F>, Error>
where
    F: PrimeField + Serialize,
    T: FnMut(&mut Transcript<F>, usize, &MatrixPair<F>) -> Result<(), Error>,
{
    let degree = bind(trans, shape)?;
    check_first(shape, degree, &proof.first)?;
    let points = sample_points(trans, shape);
    let (pair, mixing, claim) = reduce(trans, shape, &proof.first)?;
    after_challenge(trans, 0, &pair)?;
    let subclaim = packed::verify_with_rounds(
        trans,
        &reduced_shape(shape),
        &claim,
        &proof.rest,
        |t, i, pair| after_challenge(t, i + 1, pair),
    )?;
    let equality = evaluate_public_equality(shape.width, &points, &mixing, &subclaim.query);
    let mut query = vec![pair];
    query.extend(subclaim.query);
    Ok(ZeroSubclaim {
        query,
        expected: subclaim.expected,
        equality,
    })
}

fn first_evaluations<F: PrimeField>(
    shape: &PackedShape<F>,
    factors: &[impl std::borrow::Borrow<PackedTable<F>> + Sync],
    degree: usize,
    equality: &[Vec<F>],
) -> Vec<Vec<F>> {
    let suffixes = 1usize << (shape.num_vars - 1);
    let k = shape.width;
    let cached = packed::constant_interpolations(factors, degree);
    let first_flat = (0..suffixes)
        .into_par_iter()
        .fold(
            || {
                (
                    vec![F::zero(); k * (degree + 1)],
                    (0..factors.len())
                        .map(|i| {
                            cached[i]
                                .clone()
                                .unwrap_or_else(|| Vec::with_capacity(degree + 1))
                        })
                        .collect::<Vec<_>>(),
                    DifferenceScratch::default(),
                )
            },
            |(mut total, mut at, mut scratch), b| {
                for (i, (table, out)) in factors.iter().zip(&mut at).enumerate() {
                    let table = table.borrow();
                    if cached[i].is_some() {
                        continue;
                    }
                    out.clear();
                    for lane in 0..k {
                        out.push(table.at(2 * b)[lane]);
                        out.push(table.at(2 * b + 1)[lane]);
                    }
                    extrapolate(out, degree + 1, &mut scratch);
                }
                for node in 0..=degree {
                    let mut value = F::zero();
                    for (coefficient, indices) in &shape.terms {
                        value += indices
                            .iter()
                            .fold(*coefficient, |value, &i| value * at[i][node]);
                    }
                    for lane in 0..k {
                        total[lane * (degree + 1) + node] += equality[lane][b] * value;
                    }
                }
                (total, at, scratch)
            },
        )
        .map(|(total, _, _)| total)
        .reduce(
            || vec![F::zero(); k * (degree + 1)],
            |mut a, b| {
                for (a, b) in a.iter_mut().zip(b) {
                    *a += b;
                }
                a
            },
        );
    first_flat
        .chunks_exact(degree + 1)
        .map(|v| v.to_vec())
        .collect()
}

fn bind<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
) -> Result<usize, Error> {
    let degree = shape.validate()?;
    if shape.num_vars == 0 {
        return Err(reject("ZeroCheck needs at least one variable"));
    }
    reduced_shape(shape).validate()?;
    trans.append_message(b"packed zerocheck v1", shape);
    Ok(degree)
}

fn reduced_shape<F: PrimeField>(shape: &PackedShape<F>) -> PackedShape<F> {
    PackedShape {
        num_vars: shape.num_vars - 1,
        width: shape.width,
        num_factors: shape.num_factors + 1,
        terms: shape
            .terms
            .iter()
            .map(|(c, indices)| {
                let mut factors = indices.clone();
                factors.push(shape.num_factors);
                (*c, factors)
            })
            .collect(),
    }
}

fn sample_points<F: PrimeField>(trans: &mut Transcript<F>, shape: &PackedShape<F>) -> Vec<Vec<F>> {
    (0..shape.width)
        .map(|_| trans.get_vec_challenge(b"packed zero independent equality", shape.num_vars - 1))
        .collect()
}

fn equality_table<F: PrimeField>(point: &[F]) -> Vec<F> {
    let mut values = vec![F::one()];
    for &r in point {
        let mut next = Vec::with_capacity(values.len() * 2);
        for &v in &values {
            next.push((F::one() - r) * v);
        }
        for &v in &values {
            next.push(r * v);
        }
        values = next;
    }
    values
}

// Distribute the scalar equality weights into the ordered matrices. This keeps
// verifier work O(k^3 * num_vars), rather than materializing a Boolean table.
fn evaluate_public_equality<F: PrimeField>(
    k: usize,
    points: &[Vec<F>],
    mixing: &[F],
    query: &[MatrixPair<F>],
) -> Vec<F> {
    let mut total = vec![F::zero(); k];
    for c in 0..k {
        let mut vector: Vec<_> = (0..k).map(|a| mixing[a * k + c]).collect();
        for (j, pair) in query.iter().enumerate() {
            let r = points[c][j];
            let mut zero = vec![F::zero(); k];
            let mut one = vec![F::zero(); k];
            pair.zero.add_mul(&vector, &mut zero);
            pair.one.add_mul(&vector, &mut one);
            vector = zero
                .iter()
                .zip(one)
                .map(|(&a, b)| (F::one() - r) * a + r * b)
                .collect();
        }
        for (a, b) in total.iter_mut().zip(vector) {
            *a += b;
        }
    }
    total
}

fn mixed_equality<F: PrimeField>(
    shape: &PackedShape<F>,
    equality: &[Vec<F>],
    mixing: &[F],
) -> Result<PackedTable<F>, Error> {
    let k = shape.width;
    let mut eq = vec![F::zero(); equality[0].len() * k];
    for (b, out) in eq.chunks_exact_mut(k).enumerate() {
        for a in 0..k {
            for c in 0..k {
                out[a] += mixing[a * k + c] * equality[c][b];
            }
        }
    }
    PackedTable::new(shape.num_vars - 1, k, eq).map_err(shape_error)
}

fn check_first<F: PrimeField>(
    shape: &PackedShape<F>,
    degree: usize,
    first: &[Vec<F>],
) -> Result<(), Error> {
    if first.len() != shape.width || first.iter().any(|v| v.len() != degree + 1) {
        return Err(reject("incorrect packed ZeroCheck first-message shape"));
    }
    if first
        .iter()
        .any(|p| p[..2 * shape.width].iter().any(|&v| v != F::zero()))
    {
        return Err(reject("packed ZeroCheck boundary is nonzero"));
    }
    Ok(())
}

fn reduce<F: PrimeField + Serialize>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    first: &[Vec<F>],
) -> Result<(MatrixPair<F>, Vec<F>, Vec<F>), Error> {
    let k = shape.width;
    trans.append_message(b"packed zero first message", &first);
    let mixing = trans.get_vec_challenge(b"packed zero mixing matrix", k * k);
    let r = trans.get_vec_challenge(b"packed zero first challenge", k);
    let pair = packed::challenge_pair(&r).map_err(shape_error)?;
    let claim = (0..k)
        .map(|a| {
            (0..k).fold(F::zero(), |sum, b| {
                sum + mixing[a * k + b] * interpolate_uni_poly(&first[b], r[a])
            })
        })
        .collect();
    Ok((pair, mixing, claim))
}
