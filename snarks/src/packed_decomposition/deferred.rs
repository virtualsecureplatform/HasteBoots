//! Canonical decomposition with shared source authentication across limbs.
//! Reconstruction and borrow endpoints retain their existing linear check.
//! This separate experimental API is not a complete PBS protocol or hiding proof.
use super::*;
use crate::packed_extension_lookup::deferred as lookup;
use algebra::AbstractExtensionField;

/// One comparison packet contains every limb and shared source authentication.
pub type Proof<F, EF, O> = super::Proof<F, O, lookup::Proof<F, EF, O>>;

/// Prove canonical integer digits, authenticating shared borrow roots once.
pub fn prove<F, EF, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    super::prove_impl::<F, H, C, Deferred<EF>>(
        trans,
        config,
        source,
        Some(helper),
        digits,
        &mut crate::packed_lane_lookup::ProverStatistics::default(),
    )
}
/// Verify canonical digits against the caller's expected source and digit roots.
pub fn verify<F, EF, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &VerifierOracle<'_, H::Output, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    super::verify_impl::<F, H, C, Deferred<EF>>(trans, config, source, Some(helper), digits, proof)
}

pub(crate) struct Deferred<EF>(std::marker::PhantomData<EF>);
impl<F, EF, H, C> Backend<F, H, C> for Deferred<EF>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type Proof = lookup::Proof<F, EF, H::Output>;
    const EXTENSION: bool = true;
    const DEFERRED: bool = true;
    fn bind_domain(trans: &mut Transcript<F>) {
        trans.append_message(b"canonical deferred extension decomposition v1", &EF::D);
    }
    fn comparison_packets(_limbs: usize) -> usize {
        1
    }
    fn prove_comparisons(
        trans: &mut Transcript<F>,
        requests: &[lookup::Request<F>],
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        registry: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Vec<Self::Proof>, Error> {
        Ok(vec![
            lookup::prove_with_statistics::<F, EF, H, C>(
                trans,
                helper.ok_or_else(|| error("missing helper parameters"))?,
                registry,
                requests,
                statistics,
            )
            .map_err(convert)?,
        ])
    }
    fn verify_comparisons(
        trans: &mut Transcript<F>,
        requests: &[lookup::Request<F>],
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        registry: &[VerifierOracle<'_, H::Output, C>],
        proofs: &[Self::Proof],
    ) -> Result<(), Error> {
        if proofs.len() != 1 {
            return Err(error("deferred comparison packet count"));
        }
        lookup::verify::<F, EF, H, C>(
            trans,
            helper.ok_or_else(|| error("missing helper parameters"))?,
            registry,
            requests,
            &proofs[0],
        )
        .map_err(convert)
    }
    fn prove(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        sources: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Self::Proof, Error> {
        let requests = [lookup::Request {
            config: config.clone(),
            source_slots: (0..sources.len()).collect(),
        }];
        Ok(Self::prove_comparisons(trans, &requests, helper, statistics, sources)?.remove(0))
    }
    fn verify(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        sources: &[VerifierOracle<'_, H::Output, C>],
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let requests = [lookup::Request {
            config: config.clone(),
            source_slots: (0..sources.len()).collect(),
        }];
        <Self as Backend<F, H, C>>::verify_comparisons(
            trans,
            &requests,
            helper,
            sources,
            std::slice::from_ref(proof),
        )
    }
}
