//! Linear identities between canonical packed tables, with no duplicate views.
//!
//! All roots and trusted relation coefficients are fixed before one common
//! ordered-matrix query. A nonzero residual table survives each fold except
//! with probability at most ((2k-1)/p)^k; union bound over the variables.
use crate::packed_oracle::{ProverOracle, VerifierOracle};
use algebra::{PrimeField, matrix_weighted::MatrixPair};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::Opening,
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use sumcheck::packed::challenge_pair;

/// Invalid trusted relation, false identity, or rejected canonical opening.
#[derive(Debug, thiserror::Error)]
#[error("packed linear check: {0}")]
pub struct Error(pub String);
/// A trusted zero-valued linear combination of source table indices.
#[derive(Clone, Debug, Serialize)]
pub struct Relation<F> {
    /// Coefficient and canonical source index for each summand.
    pub terms: Vec<(F, usize)>,
}
/// Authenticated evaluations; the verifier never receives private source tables.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// One vector per canonical source at the common query.
    pub values: Vec<Vec<F>>,
    /// Openings against the expected source roots.
    pub openings: Vec<Opening<F, O>>,
}
/// Prove all trusted identities using the same canonical roots and matrix query.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    sources: &[&ProverOracle<'_, F, H, C>],
    relations: &[Relation<F>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let query = query::<F, H, C>(trans, &public, relations)?;
    let values = sources
        .iter()
        .map(|s| s.table.evaluate(&query).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    check(&values, relations, sources[0].parameters.width())?;
    let openings = sources
        .iter()
        .zip(&values)
        .map(|(s, v)| {
            s.parameters
                .open::<F, H>(trans, s.commitment, s.state, &query, v)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Proof { values, openings })
}
/// Verify all identities and all canonical source openings.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    relations: &[Relation<F>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let query = query::<F, H, C>(trans, sources, relations)?;
    if proof.openings.len() != sources.len() || proof.values.len() != sources.len() {
        return Err(error("incorrect source proof count"));
    }
    check(&proof.values, relations, sources[0].parameters.width())?;
    for ((s, v), opening) in sources.iter().zip(&proof.values).zip(&proof.openings) {
        s.parameters
            .verify::<F, H>(trans, s.commitment, &query, v, opening)
            .map_err(convert)?;
    }
    Ok(())
}
fn query<F, H, C>(
    trans: &mut Transcript<F>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    relations: &[Relation<F>],
) -> Result<Vec<MatrixPair<F>>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if sources.is_empty()
        || relations.is_empty()
        || relations
            .iter()
            .any(|r| r.terms.is_empty() || r.terms.iter().any(|(_, i)| *i >= sources.len()))
    {
        return Err(error("empty or invalid trusted linear relations"));
    }
    let pp = sources[0].parameters;
    if sources
        .iter()
        .any(|s| s.parameters.width() != pp.width() || s.parameters.num_vars() != pp.num_vars())
    {
        return Err(error("incompatible source dimensions"));
    }
    let p: u128 = F::MODULUS_VALUE.to_string().parse().map_err(convert)?;
    if (pp.width() as u128) * 2 >= p {
        return Err(error("field too small for matrix interpolation"));
    }
    let contexts = sources
        .iter()
        .map(|s| {
            Ok((
                s.parameters.context_digest::<F, H>().map_err(convert)?,
                s.commitment,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(
        b"packed canonical linear relations v1",
        &(contexts, relations),
    );
    (0..pp.num_vars())
        .map(|_| {
            challenge_pair(
                &trans.get_vec_challenge(b"packed linear independent challenges", pp.width()),
            )
            .map_err(convert)
        })
        .collect()
}
fn check<F: PrimeField>(
    values: &[Vec<F>],
    relations: &[Relation<F>],
    width: usize,
) -> Result<(), Error> {
    if values.iter().any(|v| v.len() != width) {
        return Err(error("source evaluation width"));
    }
    for relation in relations {
        for lane in 0..width {
            let residual = relation
                .terms
                .iter()
                .fold(F::zero(), |s, (a, i)| s + *a * values[*i][lane]);
            if residual != F::zero() {
                return Err(error("false canonical linear identity"));
            }
        }
    }
    Ok(())
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
