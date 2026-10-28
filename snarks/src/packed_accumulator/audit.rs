//! Test-only fresh certificates that bypass arithmetic, never source authentication.
use super::*;
pub(crate) fn prove<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
) -> Result<(CanonicalProof<F, P::BatchProof>, bool), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let initial = sources[0].parameters.normalize_values(initial.to_vec());
    let final_acc = sources[0].parameters.normalize_values(final_acc.to_vec());
    let (base, queries) =
        bind_queries_backend::<F, H, P>(trans, shape, &initial, &final_acc, &public)?;
    let values = sources
        .iter()
        .zip(&queries)
        .map(|(s, q)| {
            evaluate_many(s.table(), q).map(|v| {
                v.into_iter()
                    .map(|v| s.parameters.normalize_values(v))
                    .collect()
            })
        })
        .collect::<Result<Vec<Vec<_>>, _>>()?;
    let valid = check(shape, &initial, &final_acc, &base, &values).is_ok();
    let openings = sources
        .iter()
        .zip(&queries)
        .zip(&values)
        .map(|((s, q), v)| {
            s.parameters
                .open_many(trans, s.commitment, s.state, q, v)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    Ok((CanonicalProof { values, openings }, valid))
}
pub(crate) fn verify<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalProof<F, P::BatchProof>,
) -> Result<bool, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.len() != SOURCES {
        return Err(error("audit source count"));
    }
    let initial = sources[0].parameters.normalize_values(initial.to_vec());
    let final_acc = sources[0].parameters.normalize_values(final_acc.to_vec());
    let (base, queries) =
        bind_queries_backend::<F, H, P>(trans, shape, &initial, &final_acc, sources)?;
    if proof.values.len() != SOURCES
        || proof.openings.len() != SOURCES
        || proof.values.iter().zip(&queries).any(|(v, q)| {
            v.len() != q.len() || v.iter().any(|v| v.len() != sources[0].parameters.width())
        })
    {
        return Err(error("audit source proof dimensions"));
    }
    for (((s, q), v), opening) in sources
        .iter()
        .zip(&queries)
        .zip(&proof.values)
        .zip(&proof.openings)
    {
        for value in v {
            s.parameters.validate_values(value).map_err(convert)?;
        }
        s.parameters
            .verify_many(trans, s.commitment, q, v, opening)
            .map_err(convert)?;
    }
    Ok(check(shape, &initial, &final_acc, &base, &proof.values).is_ok())
}
