//! Test-only foreign lookup witnesses with strict algebra and actual-root openings.
use super::*;
pub(crate) fn prove<F, EF, H, P, R>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    witness: &[&PackedTable<F>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_inner::<F, EF, H, P, R, false>(
        parent,
        config,
        helper,
        sources,
        witness,
        &mut ProverStatistics::default(),
        rng,
    )
}
pub(crate) fn verify<F, EF, H, P>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, EF, H::Output, P::BatchProof>,
) -> Result<bool, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let mut valid = true;
    let config = canonical_config::<F, H, P>(
        config,
        sources
            .first()
            .ok_or_else(|| error("source column count"))?
            .parameters,
    )?;
    let config = &config;
    let (n, k) = bind::<F, EF, H, P>(parent, config, helper, sources)?;
    let count = config.repetitions();
    if proof.multiplicities.len() != config.table().len()
        || proof.groups.len() != count
        || proof.reciprocal_commitments.len() != count
        || (proof.source_openings.len() != sources.len())
        || proof.groups.iter().any(|g| {
            g.source_values.len() != sources.len() || g.source_values.iter().any(|v| v.len() != k)
        })
    {
        return Err(error("proof counts or source value dimensions"));
    }
    sources[0]
        .parameters
        .validate_values(&proof.multiplicities)
        .map_err(convert)?;
    for group in &proof.groups {
        if !group.sum_claim.is_canonical() || !group.reciprocal_value.is_canonical() {
            return Err(error("noncanonical lookup scalar"));
        }
        for (source, values) in sources.iter().zip(&group.source_values) {
            source.parameters.validate_values(values).map_err(convert)?;
        }
    }
    let mut child = child::<F, EF>(parent, &proof.multiplicities);
    let challenges = challenges(&mut child, config);
    child.append_message(
        b"extension lookup reciprocal roots",
        &proof.reciprocal_commitments,
    );
    let partial = config.logical_len() != 1usize << n;
    let mut algebra = Vec::with_capacity(count);
    let mut queries = Vec::with_capacity(count);
    for (group, c) in proof.groups.iter().zip(&challenges) {
        if group.sum_claim != table_sum::<F, EF>(c, &proof.multiplicities) {
            return Err(error("reciprocal sum claim"));
        }
        child.append_message(b"extension lookup sum claim", &group.sum_claim);
        let sum = MLSumcheck::verify(
            &mut child,
            &PolynomialInfo {
                num_variables: n,
                max_multiplicands: 1,
            },
            group.sum_claim,
            &group.sum,
        )
        .map_err(convert)?;
        let eq_point = child.get_vec_challenge(b"extension lookup identity point", n);
        let zero = MLSumcheck::verify(
            &mut child,
            &PolynomialInfo {
                num_variables: n,
                max_multiplicands: if partial { 4 } else { 3 },
            },
            EF::zero(),
            &group.zero,
        )
        .map_err(convert)?;
        let pulled =
            bridge::scalar_query::<F, EF>(sources[0].parameters.num_vars(), k, &zero.point)
                .map_err(convert)?;
        match check_terminal::<F, EF>(
            config.logical_len(),
            c,
            &eq_point,
            &zero.point,
            &pulled,
            &group.source_values,
            group.reciprocal_value,
            zero.expected_evaluations,
            k,
        ) {
            Ok(()) => {}
            Err(e) if e.0 == "terminal reciprocal identity" => valid = false,
            Err(e) => return Err(e),
        }
        child.append_message(
            b"extension lookup terminal claims",
            &(&group.source_values, group.reciprocal_value),
        );
        queries.push(pulled.query);
        algebra.push(Algebra {
            sum_point: sum.point,
            sum_value: sum.expected_evaluations,
            zero_point: zero.point,
        });
    }
    finish_child(parent, &mut child);
    for (i, (group, a)) in proof.groups.iter().zip(&algebra).enumerate() {
        let q0 = bridge::coefficients_query::<F, EF>(k, &a.sum_point).map_err(convert)?;
        let q1 = bridge::coefficients_query::<F, EF>(k, &a.zero_point).map_err(convert)?;
        helper
            .verify_many(
                parent,
                &proof.reciprocal_commitments[i],
                &[q0.query, q1.query],
                &[
                    bridge::vector::<F, EF>(k, a.sum_value).map_err(convert)?,
                    bridge::vector::<F, EF>(k, group.reciprocal_value).map_err(convert)?,
                ],
                &group.reciprocal_opening,
            )
            .map_err(convert)?;
    }
    for (j, (source, opening)) in sources.iter().zip(&proof.source_openings).enumerate() {
        source
            .parameters
            .verify_many(
                parent,
                source.commitment,
                &queries,
                &proof
                    .groups
                    .iter()
                    .map(|g| g.source_values[j].clone())
                    .collect::<Vec<_>>(),
                opening,
            )
            .map_err(convert)?;
    }
    Ok(valid)
}
