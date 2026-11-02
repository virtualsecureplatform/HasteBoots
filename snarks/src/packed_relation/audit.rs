//! Test-only foreign algebra with every terminal authenticated to its actual root.
use super::*;
pub(crate) fn prove_foreign<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[&crate::packed_oracle::CanonicalProverOracle<'_, F, H, P>],
    factors: &[PackedTable<F>],
) -> Result<CanonicalRelationProof<F, P::SingleProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let shape = canonical_shape::<F, H, P>(shape, sources[0].parameters);
    bind_sources::<F, H, P>(trans, &shape, &public, false)?;
    let (zero, subclaim, _) =
        packed_zero::prove_with_terminal_values(trans, &shape, factors).map_err(convert)?;
    let values = sources
        .iter()
        .map(|s| {
            s.table()
                .evaluate(&subclaim.query)
                .map(|v| s.parameters.normalize_values(v))
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    trans.append_message(b"packed relation terminal values", &values);
    let openings = sources
        .iter()
        .zip(&values)
        .map(|(s, v)| {
            s.parameters
                .open(trans, s.commitment, s.state, &subclaim.query, v)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    Ok(CanonicalRelationProof {
        zero,
        values,
        openings,
    })
}
pub(crate) fn verify<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[crate::packed_oracle::CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalRelationProof<F, P::SingleProof>,
) -> Result<bool, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_subclaim::<F, H, P>(trans, shape, sources, proof).map(|result| result.0)
}
pub(crate) fn verify_subclaim<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[crate::packed_oracle::CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalRelationProof<F, P::SingleProof>,
) -> Result<(bool, sumcheck::packed_zero::ZeroSubclaim<F>), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.is_empty() {
        return Err(Error(
            "incorrect factor commitment/opening dimensions".into(),
        ));
    }
    let normalized = Some(canonical_shape::<F, H, P>(shape, sources[0].parameters));
    let shape = normalized.as_ref().unwrap_or(shape);
    shape.validate().map_err(convert)?;
    if sources.len() != shape.num_factors
        || proof.values.len() != shape.num_factors
        || proof.openings.len() != shape.num_factors
        || proof.values.iter().any(|v| v.len() != shape.width)
    {
        return Err(Error(
            "incorrect factor commitment/opening dimensions".into(),
        ));
    }
    for (source, value) in sources.iter().zip(&proof.values) {
        source.parameters.validate_values(value).map_err(convert)?;
    }
    bind_sources::<F, H, P>(trans, shape, sources, false)?;
    let subclaim = packed_zero::verify(trans, shape, &proof.zero).map_err(convert)?;
    let valid = subclaim.check(shape, &proof.values).is_ok();
    trans.append_message(b"packed relation terminal values", &proof.values);
    for ((source, value), opening) in sources.iter().zip(&proof.values).zip(&proof.openings) {
        source
            .parameters
            .verify(trans, source.commitment, &subclaim.query, value, opening)
            .map_err(convert)?;
    }
    Ok((valid, subclaim))
}
