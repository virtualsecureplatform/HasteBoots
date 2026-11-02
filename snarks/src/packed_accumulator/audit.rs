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
    verify_queries::<F, H, P>(trans, shape, initial, final_acc, sources, proof)
        .map(|result| result.0)
}
pub(crate) fn verify_queries<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalProof<F, P::BatchProof>,
) -> Result<(bool, Vec<Vec<Vec<MatrixPair<F>>>>), Error>
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
    Ok((
        check(shape, &initial, &final_acc, &base, &proof.values).is_ok(),
        queries,
    ))
}

/// Observe the production binding, base challenges and ordered query maps.
pub(crate) fn binding_queries<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
) -> Result<(Vec<MatrixPair<F>>, Vec<Vec<Vec<MatrixPair<F>>>>), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let first = sources.first().ok_or_else(|| error("audit source count"))?;
    let initial = first.parameters.normalize_values(initial.to_vec());
    let final_acc = first.parameters.normalize_values(final_acc.to_vec());
    bind_queries_backend::<F, H, P>(trans, shape, &initial, &final_acc, sources)
}

/// Observe production arithmetic after the same trusted shape/value preflight.
/// This never authenticates the source opening packets.
pub(crate) fn terminal_valid<F, H, P>(
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    base: &[MatrixPair<F>],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    values: &[Vec<Vec<F>>],
) -> bool
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let Some(first) = sources.first() else {
        return false;
    };
    let width = first.parameters.width();
    let Ok(counts) = shape.opening_counts(width) else {
        return false;
    };
    if sources.len() != SOURCES
        || values.len() != SOURCES
        || base.len() != first.parameters.num_vars()
        || shape.validate_dimensions(base.len(), width).is_err()
        || initial.len() != 2 * shape.polynomial_size
        || final_acc.len() != initial.len()
        || values
            .iter()
            .zip(counts)
            .any(|(rows, n)| rows.len() != n || rows.iter().any(|v| v.len() != width))
    {
        return false;
    }
    if base.iter().any(|pair| pair.validate(width).is_err()) {
        return false;
    }
    for (source, rows) in sources.iter().zip(values) {
        if source.parameters.width() != width
            || source.parameters.num_vars() != base.len()
            || rows
                .iter()
                .any(|row| source.parameters.validate_values(row).is_err())
        {
            return false;
        }
    }
    let initial = first.parameters.normalize_values(initial.to_vec());
    let final_acc = first.parameters.normalize_values(final_acc.to_vec());
    check(shape, &initial, &final_acc, base, values).is_ok()
}
