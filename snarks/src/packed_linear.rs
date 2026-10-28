//! Linear identities between canonical packed tables, with no duplicate views.
//!
//! All roots and trusted relation coefficients are fixed before one common
//! ordered-matrix query. A nonzero residual table survives each fold except
//! with probability at most ((2k-1)/p)^k; union bound over the variables.
use crate::packed_oracle::{
    CanonicalProverOracle, CanonicalVerifierOracle, ProverOracle, VerifierOracle,
};
use algebra::{PrimeField, matrix_weighted::MatrixPair};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{Opening, Parameters, backend::CanonicalPcs},
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
pub struct CanonicalProof<F, P> {
    /// One vector per canonical source at the common query.
    pub values: Vec<Vec<F>>,
    /// Openings against the expected source roots.
    pub openings: Vec<P>,
}
/// Existing Brakedown wire spelling, retaining its single-opening packet layout.
pub type Proof<F, O> = CanonicalProof<F, Opening<F, O>>;
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
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    let tables: Vec<_> = sources.iter().map(|s| s.table).collect();
    prove_inner::<F, H, Parameters<C>>(trans, &public, &states, &tables, relations)
}
/// Prove identities using the actual retained tables of a trusted PCS backend.
pub fn prove_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    relations: &[Relation<F>],
) -> Result<CanonicalProof<F, P::SingleProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    let tables: Vec<_> = sources.iter().map(|s| s.table()).collect();
    prove_inner::<F, H, P>(trans, &public, &states, &tables, relations)
}
fn prove_inner<F, H, P>(
    trans: &mut Transcript<F>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    states: &[&P::State],
    tables: &[&algebra::matrix_weighted::PackedTable<F>],
    relations: &[Relation<F>],
) -> Result<CanonicalProof<F, P::SingleProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let query = query::<F, H, P>(trans, sources, relations)?;
    let mut values = Vec::with_capacity(sources.len());
    let mut queries = Vec::with_capacity(sources.len());
    for (source, table) in sources.iter().zip(tables) {
        let value = table.evaluate(&query).map_err(convert)?;
        let (q, v) = source
            .parameters
            .normalize_claim(query.clone(), value)
            .map_err(convert)?;
        queries.push(q);
        values.push(v);
    }
    check(&values, relations, sources[0].parameters.width())?;
    let openings = sources
        .iter()
        .zip(states)
        .zip(&queries)
        .zip(&values)
        .map(|(((source, state), query), value)| {
            source
                .parameters
                .open(trans, source.commitment, state, query, value)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    Ok(CanonicalProof { values, openings })
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
    verify_canonical::<F, H, Parameters<C>>(trans, sources, relations, proof)
}
/// Verify trusted identities and every expected root through a canonical backend.
pub fn verify_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    relations: &[Relation<F>],
    proof: &CanonicalProof<F, P::SingleProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let query = query::<F, H, P>(trans, sources, relations)?;
    if proof.openings.len() != sources.len() || proof.values.len() != sources.len() {
        return Err(error("incorrect source proof count"));
    }
    for (source, value) in sources.iter().zip(&proof.values) {
        source.parameters.validate_values(value).map_err(convert)?;
    }
    check(&proof.values, relations, sources[0].parameters.width())?;
    for ((source, value), opening) in sources.iter().zip(&proof.values).zip(&proof.openings) {
        let (query, value) = source
            .parameters
            .normalize_claim(query.clone(), value.clone())
            .map_err(convert)?;
        source
            .parameters
            .verify(trans, source.commitment, &query, &value, opening)
            .map_err(convert)?;
    }
    Ok(())
}
fn query<F, H, P>(
    trans: &mut Transcript<F>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    relations: &[Relation<F>],
) -> Result<Vec<MatrixPair<F>>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
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
        .map(|s| Ok((s.parameters.context().map_err(convert)?, s.commitment)))
        .collect::<Result<Vec<_>, Error>>()?;
    let normalized: Vec<_> = relations
        .iter()
        .map(|r| {
            let coefficients = pp.normalize_values(r.terms.iter().map(|(a, _)| *a).collect());
            Relation {
                terms: coefficients
                    .into_iter()
                    .zip(r.terms.iter().map(|(_, i)| *i))
                    .collect(),
            }
        })
        .collect();
    trans.append_message(P::LINEAR_DOMAIN, &(contexts, &normalized));
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

#[cfg(test)]
pub(crate) mod audit;
