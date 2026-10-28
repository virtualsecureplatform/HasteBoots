//! Public rotation products authenticated by a statically selected PCS backend.
//! Derived evaluation roots are constrained by NTT checks against original
//! coefficient roots. Public algebra remains non-hiding.
use super::*;
use crate::packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle};
use pcs::matrix_weighted::backend::CanonicalPcs;
use rand::{CryptoRng, Rng};

/// Two linked NTT roots, their transforms, and the public rotation identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O, B, S> {
    pub evaluations: Vec<Commitment<O>>,
    pub ntt: Vec<packed_ntt::CanonicalProof<F, B>>,
    pub product: ZeroProof<F>,
    pub values: Vec<Vec<F>>,
    pub openings: Vec<S>,
}
fn bind<F, H, P>(
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
    if coefficients.len() != 2 {
        return Err(error("expected input/product coefficient roots"));
    }
    let width = evaluation_parameters.width();
    let variables = plan.variables(width)?;
    if evaluation_parameters.num_vars() != variables
        || coefficients
            .iter()
            .any(|s| s.parameters.width() != width || s.parameters.num_vars() != variables)
    {
        return Err(error("canonical rotation table shape"));
    }
    let root = ntt_table::<F>(plan.polynomial_size)?.root();
    let contexts = coefficients
        .iter()
        .map(|s| Ok((s.parameters.context().map_err(convert)?, s.commitment)))
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(
        b"packed canonical backend expected monomial product v1",
        &(
            plan,
            root,
            evaluation_parameters.context().map_err(convert)?,
            contexts,
        ),
    );
    Ok(())
}
fn transform<F: NTTField>(plan: &Plan, table: &PackedTable<F>) -> Result<PackedTable<F>, Error> {
    table.validate().map_err(convert)?;
    ntt_table::<F>(plan.polynomial_size)?;
    let mut values = table.values().to_vec();
    values
        .par_chunks_exact_mut(plan.polynomial_size)
        .try_for_each(|poly| {
            F::get_ntt_table(plan.polynomial_size.ilog2())
                .map_err(convert)?
                .transform_slice(poly);
            Ok::<(), Error>(())
        })?;
    PackedTable::new(table.num_vars(), table.width(), values).map_err(convert)
}
/// Commit both derived evaluation tables with private randomness, then link them
/// to actual retained coefficient sources. Trusted parameters set reuse budgets.
pub fn prove<F, H, P, R>(
    trans: &mut Transcript<F>,
    plan: &Plan,
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
    let public_table = plan.table::<F>(width)?;
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
                evaluation_parameters.normalize_values(plan.evaluate(width, &subclaim.query)?),
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
/// Verify both original-source NTT links and the caller's exact public rotations.
/// Evaluation parameters are trusted caller inputs, never proof metadata.
pub fn verify<F, H, P>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    evaluation_parameters: &P,
    coefficients: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, H::Output, P::BatchProof, P::SingleProof>,
) -> Result<(), Error>
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
    for i in 0..2 {
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
    subclaim
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
        .map_err(convert)?;
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
    Ok(())
}

#[cfg(test)]
mod tests;
