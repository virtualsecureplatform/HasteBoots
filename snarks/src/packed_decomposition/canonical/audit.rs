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
    let comparisons = comparison_requests::<F>(config)?
        .iter()
        .map(|request| {
            let sources: Vec<_> = request
                .source_slots
                .iter()
                .map(|&slot| registry[slot])
                .collect();
            lookup::prove::<F, EF, H, P, R>(trans, &request.config, helper, &sources, rng)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
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
) -> Result<[bool; 3], Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bind::<F, EF, H, P>(trans, config, source, borrow, helper, digits)?;
    let d = config.num_digits::<F>()?;
    if proof.borrow_commitments.len() != d + 1 || proof.comparisons.len() != d {
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
    let valid = packed_linear::audit::verify::<F, H, P>(
        trans,
        &linear_sources,
        &relations::<F>(config)?,
        &proof.linear,
    )
    .map_err(convert)?;
    let registry: Vec<_> = digits.iter().chain(&borrows).collect();
    for (request, comparison) in comparison_requests::<F>(config)?
        .iter()
        .zip(&proof.comparisons)
    {
        let sources: Vec<_> = request
            .source_slots
            .iter()
            .map(|&slot| CanonicalVerifierOracle {
                parameters: registry[slot].parameters,
                commitment: registry[slot].commitment,
            })
            .collect();
        lookup::verify::<F, EF, H, P>(trans, &request.config, helper, &sources, comparison)
            .map_err(convert)?;
    }
    valid
        .try_into()
        .map_err(|_| error("audit linear identity count"))
}
