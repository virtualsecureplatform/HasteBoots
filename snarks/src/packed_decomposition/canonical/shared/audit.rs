//! Test-only noncanonical digit certificates with genuine comparisons and openings.
use super::*;
pub(crate) fn prove<F, EF, H, P, R>(
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
    prove_inner::<F, EF, H, P, R>(trans, config, source, borrow, helper, digits, rng, false)
}
pub(crate) fn prove_false_lookup<F, EF, H, P, R>(
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
    prove_inner::<F, EF, H, P, R>(trans, config, source, borrow, helper, digits, rng, true)
}
fn prove_inner<F, EF, H, P, R>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &CanonicalProverOracle<'_, F, H, P>,
    borrow: &P,
    helper: &P,
    digits: &[&CanonicalProverOracle<'_, F, H, P>],
    rng: &mut R,
    false_lookup: bool,
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
    let pp = source.parameters;
    let d = config.num_digits::<F>()?;
    for s in std::iter::once(source).chain(digits.iter().copied()) {
        s.table().validate().map_err(convert)?;
        if s.table().num_vars() != pp.num_vars() || s.table().width() != pp.width() {
            return Err(error("source table shape"));
        }
    }
    let mut borrows = vec![vec![F::zero(); source.table().values().len()]; d + 1];
    let radix = config.radix()?;
    let bounds = (0..d)
        .map(|i| config.modulus_digit::<F>(i))
        .collect::<Result<Vec<_>, _>>()?;
    for row in 0..config.logical_len() {
        let mut carry = 0;
        for i in 0..d {
            let digit: usize = digits[i].table().values()[row]
                .canonicalized()
                .value()
                .try_into()
                .map_err(|_| error("digit conversion"))?;
            if digit >= radix {
                return Err(error("out-of-range digit"));
            }
            carry = usize::from(digit + carry > bounds[i]);
            borrows[i + 1][row] = field::<F>(carry)?;
        }
    }
    let honest = false_lookup.then(|| borrows.clone());
    if false_lookup {
        assert!(d > 1);
        borrows[1].fill(field::<F>(2)?);
    }
    let (borrow_commitments, states): (Vec<_>, Vec<_>) = borrows
        .into_iter()
        .map(|v| {
            let table = PackedTable::new(pp.num_vars(), pp.width(), v).map_err(convert)?;
            borrow.commit(&table, rng).map_err(convert)
        })
        .collect::<Result<Vec<_>, Error>>()?
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
        packed_linear::audit::prove::<F, H, P>(trans, &linear_sources, &relations::<F>(config)?)
            .map_err(convert)?;
    let registry: Vec<_> = digits.iter().copied().chain(borrows.iter()).collect();
    let comparisons = if false_lookup {
        let mut witness: Vec<_> = digits.iter().map(|s| s.table().clone()).collect();
        witness.extend(
            honest
                .as_ref()
                .unwrap()
                .iter()
                .map(|v| PackedTable::new(pp.num_vars(), pp.width(), v.clone()).map_err(convert))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let tables: Vec<_> = witness.iter().collect();
        comparisons::audit::prove::<F, EF, H, P, R>(
            trans,
            helper,
            &registry,
            &comparison_requests::<F>(config)?,
            &tables,
            rng,
        )
        .map_err(convert)?
    } else {
        comparisons::prove::<F, EF, H, P, R>(
            trans,
            helper,
            &registry,
            &comparison_requests::<F>(config)?,
            rng,
        )
        .map_err(convert)?
    };
    Ok(Proof {
        borrow_commitments,
        linear,
        comparisons,
    })
}
/// Verify reconstruction, zero borrow endpoints, ranges and subtraction from p-1.
pub(crate) fn verify<F, EF, H, P>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &CanonicalVerifierOracle<'_, H::Output, P>,
    borrow: &P,
    helper: &P,
    digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<([bool; 3], bool), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_queries::<F, EF, H, P>(trans, config, source, borrow, helper, digits, proof)
        .map(|result| result.0)
}
pub(crate) fn verify_queries<F, EF, H, P>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &CanonicalVerifierOracle<'_, H::Output, P>,
    borrow: &P,
    helper: &P,
    digits: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<
    (
        ([bool; 3], bool),
        Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
        Option<crate::packed_extension_lookup::canonical::shared::audit::SourceClaims<F>>,
    ),
    Error,
>
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
    let (valid, queries) = packed_linear::audit::verify_queries::<F, H, P>(
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
    let (lookup_valid, lookup_claims) = comparisons::audit::verify_claims::<F, EF, H, P>(
        trans,
        helper,
        &registry,
        &comparison_requests::<F>(config)?,
        &proof.comparisons,
    )
    .map_err(convert)?;
    Ok((
        (
            valid
                .try_into()
                .map_err(|_| error("audit linear identity count"))?,
            lookup_valid,
        ),
        queries,
        Some(lookup_claims),
    ))
}
