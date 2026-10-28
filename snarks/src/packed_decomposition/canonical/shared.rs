//! Radix reconstruction and canonicity with one shared lookup point for all limbs.
//! Public algebra and independent per-root PCS authentication; not a hiding proof.
use super::*;
use crate::packed_extension_lookup::canonical::shared as comparisons;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, O, S, B> {
    /// Original borrow roots, in least-significant-first order.
    pub borrow_commitments: Vec<Commitment<O>>,
    /// Reconstruction and initial/final zero-borrow identities.
    pub linear: packed_linear::CanonicalProof<F, S>,
    /// Every limb transition, sharing one terminal point.
    pub comparisons: comparisons::Proof<F, EF, O, S, B>,
}
fn bind<F, EF, H, P>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &CanonicalVerifierOracle<'_, H::Output, P>,
    borrow: &P,
    helper: &P,
    digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    trans.append_message(b"packed canonical shared radix decomposition v1", &());
    super::bind::<F, EF, H, P>(trans, config, source, borrow, helper, digits)
}
/// Original source needs one opening; each digit and borrow needs two, and
/// each reciprocal helper needs one, independently of the repetition count.
pub fn prove<F, EF, H, P, R>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &CanonicalProverOracle<'_, F, H, P>,
    borrow: &P,
    helper: &P,
    digits: &[&CanonicalProverOracle<'_, F, H, P>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let public: Vec<_> = digits.iter().map(|d| d.verifier()).collect();
    bind::<F, EF, H, P>(trans, config, &source.verifier(), borrow, helper, &public)?;
    let columns = borrow_tables::<F, H, P>(config, source, digits)?;
    let (borrow_commitments, states): (Vec<_>, Vec<_>) = columns
        .into_iter()
        .map(|t| borrow.commit(&t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    trans.append_message(
        b"packed canonical decomposition borrow roots",
        &borrow_commitments,
    );
    let borrows: Vec<_> = borrow_commitments
        .iter()
        .zip(&states)
        .map(|(commitment, state)| CanonicalProverOracle::<F, H, P> {
            parameters: borrow,
            commitment,
            state,
        })
        .collect();
    let mut linear_sources = vec![source];
    linear_sources.extend(digits.iter().copied());
    linear_sources.extend(borrows.iter());
    let linear =
        packed_linear::prove_canonical::<F, H, P>(trans, &linear_sources, &relations::<F>(config)?)
            .map_err(convert)?;
    let registry: Vec<_> = digits.iter().copied().chain(borrows.iter()).collect();
    let comparisons = comparisons::prove::<F, EF, H, P, R>(
        trans,
        helper,
        &registry,
        &comparison_requests::<F>(config)?,
        rng,
    )
    .map_err(convert)?;
    Ok(Proof {
        borrow_commitments,
        linear,
        comparisons,
    })
}
/// Verify reconstruction, zero borrow endpoints, ranges and subtraction from p-1.
pub fn verify<F, EF, H, P>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &CanonicalVerifierOracle<'_, H::Output, P>,
    borrow: &P,
    helper: &P,
    digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, EF, H, P>(trans, config, source, borrow, helper, digits)?;
    let d = config.num_digits::<F>()?;
    if proof.borrow_commitments.len() != d + 1 {
        return Err(error("decomposition proof counts"));
    }
    trans.append_message(
        b"packed canonical decomposition borrow roots",
        &proof.borrow_commitments,
    );
    let borrows: Vec<_> = proof
        .borrow_commitments
        .iter()
        .map(|commitment| CanonicalVerifierOracle {
            parameters: borrow,
            commitment,
        })
        .collect();
    let mut linear_sources = Vec::with_capacity(2 * d + 2);
    for s in std::iter::once(source).chain(digits).chain(&borrows) {
        linear_sources.push(CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        });
    }
    packed_linear::verify_canonical::<F, H, P>(
        trans,
        &linear_sources,
        &relations::<F>(config)?,
        &proof.linear,
    )
    .map_err(convert)?;
    let registry: Vec<_> = digits
        .iter()
        .chain(&borrows)
        .map(|s| CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    comparisons::verify::<F, EF, H, P>(
        trans,
        helper,
        &registry,
        &comparison_requests::<F>(config)?,
        &proof.comparisons,
    )
    .map_err(convert)
}

#[cfg(test)]
mod tests;
