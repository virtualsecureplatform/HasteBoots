//! Canonical-source common-query authentication. Alias decisions are derived
//! from caller roots under one trusted parameter context, never from the proof.
//! Every alias must claim the same field value before any aggregation weights.
use super::*;

/// One joint packet for the first occurrence of each distinct canonical root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, EF, O> {
    /// No root identifiers or alias decisions are serialized here.
    pub opening: super::Proof<F, EF, O>,
}
fn bind<F, EF, H, C>(
    pp: &Parameters<C>,
    trans: &mut Transcript<F>,
    roots: &[Commitment<H::Output>],
    query: &[MatrixPair<F>],
    values: &[Vec<F>],
) -> Result<Vec<usize>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash,
    C: RowCode<F> + Serialize,
{
    if roots.is_empty()
        || roots.len() != values.len()
        || query.len() != pp.num_vars
        || values.iter().any(|v| v.len() != pp.width)
    {
        return Err(Error("canonical aggregate dimensions"));
    }
    for pair in query {
        pair.validate(pp.width)
            .map_err(|_| Error("canonical aggregate matrix"))?;
    }
    let mut representatives: Vec<usize> = Vec::new();
    let mut aliases = Vec::with_capacity(roots.len());
    for (i, root) in roots.iter().enumerate() {
        if let Some(group) = representatives
            .iter()
            .position(|&j| root.root == roots[j].root)
        {
            if values[i] != values[representatives[group]] {
                return Err(Error("canonical alias value mismatch"));
            }
            aliases.push(group);
        } else {
            aliases.push(representatives.len());
            representatives.push(i);
        }
    }
    trans.append_message(
        b"mw canonical-source common-query v1",
        &(
            pp.context_digest::<F, H>()?,
            EF::D,
            roots,
            query,
            values,
            &aliases,
        ),
    );
    Ok(representatives)
}
/// Prove all ordered obligations, using the first state per distinct root.
/// Equal roots alias only within this single complete parameter context/query.
pub fn prove<F, EF, H, C>(
    pp: &Parameters<C>,
    trans: &mut Transcript<F>,
    roots: &[Commitment<H::Output>],
    states: &[&State<F, H>],
    query: &[MatrixPair<F>],
    values: &[Vec<F>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if states.len() != roots.len() {
        return Err(Error("canonical aggregate state count"));
    }
    let representatives = bind::<F, EF, H, C>(pp, trans, roots, query, values)?;
    let unique_roots: Vec<_> = representatives.iter().map(|&i| roots[i].clone()).collect();
    let unique_states: Vec<_> = representatives.iter().map(|&i| states[i]).collect();
    let unique_values: Vec<_> = representatives.iter().map(|&i| values[i].clone()).collect();
    let opening = super::prove::<F, EF, H, C>(
        pp,
        trans,
        &unique_roots,
        &unique_states,
        query,
        &unique_values,
    )?;
    Ok(Proof { opening })
}
/// Reconstruct canonical obligations and authenticate each distinct root.
/// Conflicting alias values are rejected before the random linear test/weights.
pub fn verify<F, EF, H, C>(
    pp: &Parameters<C>,
    trans: &mut Transcript<F>,
    roots: &[Commitment<H::Output>],
    query: &[MatrixPair<F>],
    values: &[Vec<F>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let representatives = bind::<F, EF, H, C>(pp, trans, roots, query, values)?;
    let unique_roots: Vec<_> = representatives.iter().map(|&i| roots[i].clone()).collect();
    let unique_values: Vec<_> = representatives.iter().map(|&i| values[i].clone()).collect();
    super::verify::<F, EF, H, C>(
        pp,
        trans,
        &unique_roots,
        query,
        &unique_values,
        &proof.opening,
    )
}
