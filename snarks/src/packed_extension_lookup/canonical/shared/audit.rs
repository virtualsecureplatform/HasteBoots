//! Test-only foreign lookup witnesses with strict algebra and actual-root openings.
use super::*;
pub(crate) fn prove<F, EF, H, P, R>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    requests: &[Request<F>],
    witness: &[&PackedTable<F>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_inner::<F, EF, H, P, R, false>(
        parent,
        helper,
        sources,
        requests,
        witness,
        &mut ProverStatistics::default(),
        rng,
    )
}
pub(crate) struct SourceClaims<F> {
    pub(crate) source_query: Vec<algebra::matrix_weighted::MatrixPair<F>>,
    pub(crate) used: Vec<bool>,
    pub(crate) helper_query: Vec<algebra::matrix_weighted::MatrixPair<F>>,
    pub(crate) helper_values: Vec<Vec<F>>,
}

pub(crate) fn verify<F, EF, H, P>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<bool, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_claims::<F, EF, H, P>(parent, helper, sources, requests, proof).map(|result| result.0)
}
pub(crate) fn verify_claims<F, EF, H, P>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(bool, SourceClaims<F>), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let mut valid = true;
    let requests = canonical_requests::<F, H, P>(
        requests,
        sources
            .first()
            .ok_or_else(|| error("empty shared registry"))?
            .parameters,
    )?;
    let requests = &requests[..];
    let (n, k, count) = preflight::<F, EF, H, P>(parent, helper, sources, requests)?;
    let mut registry = CanonicalOpeningBatch::<F, H, P>::new(parent, sources).map_err(convert)?;
    let used = used_slots(sources.len(), requests);
    if proof.helper_openings.len() != count {
        return Err(error("shared helper opening count"));
    }
    if proof.multiplicities.len() != requests.len()
        || proof
            .multiplicities
            .iter()
            .zip(requests)
            .any(|(m, r)| m.len() != r.config.table().len())
        || proof.helper_roots.len() != count
        || proof.helper_values.len() != count
        || proof.source_values.len() != sources.len()
        || proof.source_values.iter().any(|v| v.len() != k)
    {
        return Err(error("shared lookup proof dimensions"));
    }
    for m in &proof.multiplicities {
        sources[0].parameters.validate_values(m).map_err(convert)?;
    }
    for (i, (source, value)) in sources.iter().zip(&proof.source_values).enumerate() {
        source.parameters.validate_values(value).map_err(convert)?;
        if !used[i] && value.iter().any(|&x| x != F::zero()) {
            return Err(error("unused shared source value"));
        }
    }
    if proof.helper_values.iter().any(|v| !v.is_canonical()) {
        return Err(error("noncanonical shared helper scalar"));
    }
    let mut child = child_shared::<F, EF>(parent, &proof.multiplicities);
    let challenges = all_challenges(&mut child, requests);
    child.append_message(b"shared lookup helper roots", &proof.helper_roots);
    let mut eq_points = Vec::new();
    let mut sums = Vec::new();
    for (i, c) in &challenges {
        eq_points.push(child.get_vec_challenge(b"shared lookup equality point", n));
        sums.push(table_sum::<F, EF>(c, &proof.multiplicities[*i]));
        sums.push(EF::zero());
    }
    let claims = sumcheck::batch::verify(
        &mut child,
        &equation_infos(requests, n),
        &sums,
        &proof.algebra,
    )
    .map_err(convert)?;
    let point = &claims[0].point;
    let pulled = bridge::scalar_query::<F, EF>(sources[0].parameters.num_vars(), k, point)
        .map_err(convert)?;
    for (i, (request, c)) in challenges.iter().enumerate() {
        if claims[2 * i].expected_evaluations != proof.helper_values[i] {
            return Err(error("shared lookup sum/helper terminal mismatch"));
        }
        let values: Vec<_> = requests[*request]
            .source_slots
            .iter()
            .map(|&slot| proof.source_values[slot].clone())
            .collect();
        match check_terminal::<F, EF>(
            requests[*request].config.logical_len(),
            c,
            &eq_points[i],
            point,
            &pulled,
            &values,
            proof.helper_values[i],
            claims[2 * i + 1].expected_evaluations,
            k,
        ) {
            Ok(()) => {}
            Err(e) if e.0 == "terminal reciprocal identity" => valid = false,
            Err(e) => return Err(e),
        }
    }
    child.append_message(
        b"shared lookup terminal values",
        &(&proof.source_values, &proof.helper_values),
    );
    finish_child(parent, &mut child);
    let helper_query =
        bridge::coefficients_query::<F, EF>(helper.width(), point).map_err(convert)?;
    let helper_claims: Vec<_> = proof
        .helper_values
        .iter()
        .map(|&v| bridge::vector::<F, EF>(helper.width(), v).map_err(convert))
        .collect::<Result<_, _>>()?;
    for ((root, value), opening) in proof
        .helper_roots
        .iter()
        .zip(&helper_claims)
        .zip(&proof.helper_openings)
    {
        let value = helper.normalize_values(value.clone());
        helper
            .verify(parent, root, &helper_query.query, &value, opening)
            .map_err(convert)?;
    }
    source_claims::<F, H, P>(
        parent,
        &mut registry,
        sources,
        &used,
        &pulled.query,
        &proof.source_values,
    )?;
    registry
        .verify(parent, &proof.source_opening)
        .map_err(convert)?;
    Ok((
        valid,
        SourceClaims {
            source_query: pulled.query,
            used,
            helper_query: helper_query.query,
            helper_values: helper_claims
                .into_iter()
                .map(|value| helper.normalize_values(value))
                .collect(),
        },
    ))
}

// Observe production compression/degree helpers without exposing or injecting
// a production transcript state. Only audit builds include this entry point.
pub(crate) fn compression_claims<F, EF>(
    requests: &[Request<F>],
    multiplicities: &[Vec<F>],
    accepted: &[(usize, usize, EF, EF)],
    variables: usize,
) -> (Vec<algebra::PolynomialInfo>, Vec<EF>)
where
    F: PrimeField,
    EF: AbstractExtensionField<F>,
{
    let mut claims = Vec::new();
    for &(index, _, hash, reciprocal) in accepted {
        let request = &requests[index];
        let mut power = EF::one();
        let powers: Vec<_> = (0..request.config.num_columns())
            .map(|_| {
                let value = power;
                power *= hash;
                value
            })
            .collect();
        let table: Vec<_> = request
            .config
            .table()
            .iter()
            .map(|row| {
                row.iter()
                    .zip(&powers)
                    .fold(EF::zero(), |out, (&a, &b)| out + b * a)
            })
            .collect();
        let denominators: Vec<_> = table.iter().map(|&value| reciprocal + value).collect();
        let challenge = crate::packed_extension_lookup::Challenge {
            powers,
            r: reciprocal,
            inverses: crate::packed_extension_lookup::table_reciprocals::<F, EF>(&denominators),
        };
        claims.push(crate::packed_extension_lookup::table_sum::<F, EF>(
            &challenge,
            &multiplicities[index],
        ));
        claims.push(EF::zero());
    }
    (
        crate::packed_extension_lookup::shared::equation_infos(requests, variables),
        claims,
    )
}

pub(crate) fn terminal_valid<F, EF>(
    requests: &[Request<F>],
    accepted: &[(usize, usize, EF, EF)],
    equality_points: &[Vec<EF>],
    point: &[EF],
    sources: &[Vec<F>],
    helpers: &[EF],
    expected: &[EF],
    source_vars: usize,
    width: usize,
) -> bool
where
    F: PrimeField,
    EF: AbstractExtensionField<F>,
{
    let Ok(pulled) = crate::packed_extension::scalar_query::<F, EF>(source_vars, width, point)
    else {
        return false;
    };
    if accepted.len() != helpers.len()
        || equality_points.len() != helpers.len()
        || expected.len() != 2 * helpers.len()
    {
        return false;
    }
    for (index, &(request_index, _, hash, reciprocal)) in accepted.iter().enumerate() {
        if expected[2 * index] != helpers[index] {
            return false;
        }
        let Some(request) = requests.get(request_index) else {
            return false;
        };
        let mut power = EF::one();
        let powers: Vec<_> = (0..request.config.num_columns())
            .map(|_| {
                let value = power;
                power *= hash;
                value
            })
            .collect();
        let challenge = crate::packed_extension_lookup::Challenge {
            powers,
            r: reciprocal,
            inverses: Vec::new(),
        };
        let Some(local) = request
            .source_slots
            .iter()
            .map(|&slot| sources.get(slot).cloned())
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        if crate::packed_extension_lookup::check_terminal::<F, EF>(
            request.config.logical_len(),
            &challenge,
            &equality_points[index],
            point,
            &pulled,
            &local,
            helpers[index],
            expected[2 * index + 1],
            width,
        )
        .is_err()
        {
            return false;
        }
    }
    true
}

/// Observe the actual source-claim registration on an isolated public transcript.
pub(crate) fn source_obligations<F, H, P>(
    parent: &mut Transcript<F>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    requests: &[Request<F>],
    query: &[algebra::matrix_weighted::MatrixPair<F>],
    values: &[Vec<F>],
) -> Result<(usize, usize), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let used = used_slots(sources.len(), requests);
    let mut registry = CanonicalOpeningBatch::<F, H, P>::new(parent, sources).map_err(convert)?;
    source_claims::<F, H, P>(parent, &mut registry, sources, &used, query, values)?;
    Ok((registry.claim_count(), registry.used_sources()))
}
