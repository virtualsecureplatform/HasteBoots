//! Test-only foreign public factors, with strict source authentication.
use super::*;
#[cfg(feature = "transcript-audit")]
pub(crate) fn product_subclaim<F, H, P>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    evaluation_parameters: &P,
    coefficients: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, H::Output, P::BatchProof, P::SingleProof>,
) -> Result<
    (
        sumcheck::packed_zero::ZeroSubclaim<F>,
        Vec<packed_ntt::AuditSourceObligations<F>>,
    ),
    Error,
>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, H, P>(trans, plan, evaluation_parameters, coefficients)?;
    if proof.evaluations.len() != 2 || proof.ntt.len() != 2 {
        return Err(error("monomial audit source count"));
    }
    trans.append_message(b"public canonical monomial NTT roots", &proof.evaluations);
    let shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(evaluation_parameters, plan.polynomial_size)
            .map_err(convert)?;
    let mut obligations = Vec::new();
    for i in 0..2 {
        let evaluation = CanonicalVerifierOracle {
            parameters: evaluation_parameters,
            commitment: &proof.evaluations[i],
        };
        obligations.push(
            packed_ntt::audit_verified_source_obligations::<F, H, P>(
                trans,
                &shape,
                &coefficients[i],
                &evaluation,
                &proof.ntt[i],
            )
            .map_err(convert)?,
        );
    }
    let subclaim = packed_zero::verify(
        trans,
        &product_shape(
            evaluation_parameters.num_vars(),
            evaluation_parameters.width(),
        ),
        &proof.product,
    )
    .map_err(convert)?;
    Ok((subclaim, obligations))
}
pub(crate) fn bind_for_test<F, H, P>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    evaluation_parameters: &P,
    coefficients: &[CanonicalVerifierOracle<'_, H::Output, P>],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, H, P>(trans, plan, evaluation_parameters, coefficients)
}

pub(crate) fn prove_foreign<F, H, P, R>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    actual: &Plan,
    evaluation_parameters: &P,
    coefficients: &[&CanonicalProverOracle<'_, F, H, P>],
    rng: &mut R,
) -> Result<Proof<F, H::Output, P::BatchProof, P::SingleProof>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let public: Vec<_> = coefficients.iter().map(|s| s.verifier()).collect();
    bind::<F, H, P>(trans, plan, evaluation_parameters, &public)?;
    let tables = coefficients
        .iter()
        .map(|s| {
            let table = s.table();
            if table.num_vars() != evaluation_parameters.num_vars()
                || table.width() != evaluation_parameters.width()
            {
                return Err(error("coefficient table shape"));
            }
            transform(plan, table)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| evaluation_parameters.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    drop(tables);
    trans.append_message(b"public canonical monomial NTT roots", &evaluations);
    let oracles: Vec<_> = evaluations
        .iter()
        .zip(&states)
        .map(|(commitment, state)| CanonicalProverOracle::<F, H, P> {
            parameters: evaluation_parameters,
            commitment,
            state,
        })
        .collect();
    let ntt_shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(evaluation_parameters, plan.polynomial_size)
            .map_err(convert)?;
    let ntt = (0..2)
        .map(|i| {
            packed_ntt::prove_canonical::<F, H, P>(trans, &ntt_shape, coefficients[i], &oracles[i])
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let width = evaluation_parameters.width();
    let shape = product_shape(evaluation_parameters.num_vars(), width);
    let public_table = actual.table::<F>(width)?;
    let factors = [oracles[0].table(), &public_table, oracles[1].table()];
    let (product, subclaim, terminals) =
        packed_zero::prove_with_borrowed_terminal_values(trans, &shape, &factors)
            .map_err(convert)?;
    let values = vec![
        evaluation_parameters.normalize_values(terminals[0].clone()),
        evaluation_parameters.normalize_values(terminals[2].clone()),
    ];
    subclaim
        .check(
            &shape,
            &[
                values[0].clone(),
                evaluation_parameters.normalize_values(actual.evaluate(width, &subclaim.query)?),
                values[1].clone(),
            ],
        )
        .map_err(convert)?;
    let openings = oracles
        .iter()
        .zip(&values)
        .map(|(s, v)| {
            evaluation_parameters
                .open(trans, s.commitment, s.state, &subclaim.query, v)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    Ok(Proof {
        evaluations,
        ntt,
        product,
        values,
        openings,
    })
}
pub(crate) struct Queries<F> {
    pub(crate) product: sumcheck::packed_zero::ZeroSubclaim<F>,
    #[cfg(feature = "transcript-audit")]
    pub(crate) ntt: Vec<packed_ntt::AuditSourceObligations<F>>,
}
pub(crate) fn verify<F, H, P>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    evaluation_parameters: &P,
    coefficients: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, H::Output, P::BatchProof, P::SingleProof>,
) -> Result<bool, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_queries::<F, H, P>(trans, plan, evaluation_parameters, coefficients, proof)
        .map(|result| result.0)
}
pub(crate) fn verify_queries<F, H, P>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    evaluation_parameters: &P,
    coefficients: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, H::Output, P::BatchProof, P::SingleProof>,
) -> Result<(bool, Queries<F>), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, H, P>(trans, plan, evaluation_parameters, coefficients)?;
    if proof.evaluations.len() != 2
        || proof.ntt.len() != 2
        || proof.values.len() != 2
        || proof.openings.len() != 2
        || proof
            .values
            .iter()
            .any(|v| v.len() != evaluation_parameters.width())
    {
        return Err(error("monomial proof counts"));
    }
    for value in &proof.values {
        evaluation_parameters
            .validate_values(value)
            .map_err(convert)?;
    }
    trans.append_message(b"public canonical monomial NTT roots", &proof.evaluations);
    let oracles: Vec<_> = proof
        .evaluations
        .iter()
        .map(|commitment| CanonicalVerifierOracle {
            parameters: evaluation_parameters,
            commitment,
        })
        .collect();
    let ntt_shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(evaluation_parameters, plan.polynomial_size)
            .map_err(convert)?;
    #[cfg(feature = "transcript-audit")]
    let mut ntt = Vec::new();
    for i in 0..2 {
        #[cfg(feature = "transcript-audit")]
        ntt.push(
            packed_ntt::audit_verified_source_obligations::<F, H, P>(
                trans,
                &ntt_shape,
                &coefficients[i],
                &oracles[i],
                &proof.ntt[i],
            )
            .map_err(convert)?,
        );
        #[cfg(not(feature = "transcript-audit"))]
        packed_ntt::verify_canonical::<F, H, P>(
            trans,
            &ntt_shape,
            &coefficients[i],
            &oracles[i],
            &proof.ntt[i],
        )
        .map_err(convert)?;
    }
    let shape = product_shape(
        evaluation_parameters.num_vars(),
        evaluation_parameters.width(),
    );
    let subclaim = packed_zero::verify(trans, &shape, &proof.product).map_err(convert)?;
    let valid = subclaim
        .check(
            &shape,
            &[
                proof.values[0].clone(),
                evaluation_parameters.normalize_values(
                    plan.evaluate(evaluation_parameters.width(), &subclaim.query)?,
                ),
                proof.values[1].clone(),
            ],
        )
        .is_ok();
    for i in 0..2 {
        evaluation_parameters
            .verify(
                trans,
                oracles[i].commitment,
                &subclaim.query,
                &proof.values[i],
                &proof.openings[i],
            )
            .map_err(convert)?;
    }
    Ok((
        valid,
        Queries {
            product: subclaim,
            #[cfg(feature = "transcript-audit")]
            ntt,
        },
    ))
}
