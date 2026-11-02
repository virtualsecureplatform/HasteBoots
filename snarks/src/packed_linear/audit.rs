//! Test-only linear identities reported separately from strict source authentication.
use super::*;
pub(crate) fn prove<F, H, P>(
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
    let q = query::<F, H, P>(trans, &public, relations)?;
    let claims = sources
        .iter()
        .map(|s| {
            s.parameters
                .normalize_claim(q.clone(), s.table().evaluate(&q).map_err(convert)?)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let values = claims.iter().map(|(_, v)| v.clone()).collect();
    let openings = sources
        .iter()
        .zip(&claims)
        .map(|(s, (q, v))| {
            s.parameters
                .open(trans, s.commitment, s.state, q, v)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    Ok(CanonicalProof { values, openings })
}
pub(crate) fn verify<F, H, P>(
    trans: &mut Transcript<F>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    relations: &[Relation<F>],
    proof: &CanonicalProof<F, P::SingleProof>,
) -> Result<Vec<bool>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_queries::<F, H, P>(trans, sources, relations, proof).map(|result| result.0)
}
pub(crate) fn verify_queries<F, H, P>(
    trans: &mut Transcript<F>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    relations: &[Relation<F>],
    proof: &CanonicalProof<F, P::SingleProof>,
) -> Result<(Vec<bool>, Vec<Vec<MatrixPair<F>>>), Error>
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
    let valid = relations
        .iter()
        .map(|r| {
            check(
                &proof.values,
                std::slice::from_ref(r),
                sources[0].parameters.width(),
            )
            .is_ok()
        })
        .collect();
    let mut queries = Vec::with_capacity(sources.len());
    for ((source, value), opening) in sources.iter().zip(&proof.values).zip(&proof.openings) {
        let (query, value) = source
            .parameters
            .normalize_claim(query.clone(), value.clone())
            .map_err(convert)?;
        queries.push(query.clone());
        source
            .parameters
            .verify(trans, source.commitment, &query, &value, opening)
            .map_err(convert)?;
    }
    Ok((valid, queries))
}
