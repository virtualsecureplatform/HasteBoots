//! Trusted complete-PBS key ownership for statically selected PCS backends.
//! This setup is not a masked complete-PBS proof format or verifier.
use super::*;
use crate::packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle};
use pcs::matrix_weighted::backend::CanonicalPcs;
use rand::{CryptoRng, Rng};

/// Trusted logical source/helper geometries, never read from proof metadata.
pub struct Parameters<'a, P> {
    pub source: &'a P,
    pub helper: &'a P,
    pub final_source: &'a P,
    pub final_helper: &'a P,
}
impl<P> Parameters<'_, P> {
    fn validate<F, H>(&self, cfg: &Config) -> Result<(), Error>
    where
        F: NTTField + Serialize,
        H: Hash + Send + Sync,
        P: CanonicalPcs<F, H>,
    {
        let width = self.source.width();
        let dims = cfg.variables(width)?;
        for (role, (pp, n)) in [
            self.source,
            self.helper,
            self.final_source,
            self.final_helper,
        ]
        .into_iter()
        .zip(dims)
        .enumerate()
        {
            let valid_width = if role % 2 == 0 {
                pp.width() == width
            } else {
                pp.width() > 0 && pp.width() <= width
            };
            if !valid_width || pp.num_vars() != n {
                return Err(error("incompatible trusted PCS geometry"));
            }
            pp.context().map_err(convert)?;
        }
        Ok(())
    }
}
/// Retained original key sessions. This cannot clone, serialize or refresh masks.
pub struct ProverSetup<F, H, P>
where
    F: NTTField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verifier: VerifierSetup<H::Output>,
    br: bk::canonical::ProverKey<F, H, P>,
    ks: ks::canonical::ProverKey<F, H, P>,
}
impl<F, H, P> ProverSetup<F, H, P>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    /// Borrow the original switching-key owner for canonical final-stage proving.
    pub fn switching_key(&self) -> &ks::canonical::ProverKey<F, H, P> {
        &self.ks
    }
    /// Public trusted roots/configuration only; no retained source state escapes.
    pub fn verifier(&self) -> VerifierSetup<H::Output> {
        self.verifier.clone()
    }
    pub fn br_oracles<'a>(
        &'a self,
        pp: &'a P,
    ) -> Result<Vec<CanonicalProverOracle<'a, F, H, P>>, Error> {
        self.br.oracles(pp).map_err(convert)
    }
    pub fn ks_oracles<'a>(
        &'a self,
        pp: &'a P,
    ) -> Result<Vec<CanonicalProverOracle<'a, F, H, P>>, Error> {
        self.ks.oracles(pp).map_err(convert)
    }
}
/// Public preprocessing uses authenticated native keys, with no trace input.
/// The caller provisions each root's lifetime budget across all future uses.
pub fn preprocess<F, H, P, R>(
    pp: &Parameters<'_, P>,
    config: Config,
    br: &[NTTRGSW<F>],
    ks: &[NTTGadgetRLWE<F>],
    rng: &mut R,
) -> Result<ProverSetup<F, H, P>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    pp.validate::<F, H>(&config)?;
    // Check the native bootstrapping key configuration before any commitments.
    if br.len() != config.lwe
        || br
            .first()
            .is_none_or(|r| r.c_neg_s_m().basis().bits() != config.br_bits)
    {
        return Err(error(
            "bootstrapping key does not match trusted configuration",
        ));
    }
    let br = bk::canonical::prepare::<F, H, P, R>(pp.source, config.n, br, rng).map_err(convert)?;
    let ks = ks::canonical::preprocess::<F, H, P, R>(
        pp.final_source,
        ks::Config::new::<F>(config.n, config.lwe, config.ks_bits, config.repetitions)
            .map_err(convert)?,
        ks,
        rng,
    )
    .map_err(convert)?;
    let verifier = VerifierSetup {
        config,
        br: br.expected().clone(),
        ks: ks.expected().clone(),
    };
    Ok(ProverSetup { verifier, br, ks })
}
/// Validate all logical dimensions and key contexts against trusted public setup.
pub fn validate<F, H, P>(
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    pp.validate::<F, H>(&setup.config)?;
    br_oracles::<F, H, P>(pp.source, setup)?;
    ks_oracles::<F, H, P>(pp.final_source, setup)?;
    Ok(())
}
/// Borrow independently expected bootstrapping-key roots for public verification.
pub fn br_oracles<'a, F, H, P>(
    pp: &'a P,
    setup: &'a VerifierSetup<H::Output>,
) -> Result<Vec<CanonicalVerifierOracle<'a, H::Output, P>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    bk::canonical::public_oracles::<F, H, P>(pp, &setup.br).map_err(convert)
}
/// Borrow independently expected switching-key roots for public verification.
pub fn ks_oracles<'a, F, H, P>(
    pp: &'a P,
    setup: &'a VerifierSetup<H::Output>,
) -> Result<Vec<CanonicalVerifierOracle<'a, H::Output, P>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    ks::canonical::public_oracles::<F, H, P>(pp, &setup.ks).map_err(convert)
}

/// Trusted switching-key descriptor for canonical final-stage verification.
pub fn switching_key<O>(setup: &VerifierSetup<O>) -> &ks::ExpectedKey<O> {
    &setup.ks
}
