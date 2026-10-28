//! Canonical backend ownership of trusted native switching-key sources.
use super::*;
use crate::packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle};
use pcs::matrix_weighted::backend::CanonicalPcs;
use rand::{CryptoRng, Rng};

/// Original retained key states; no cloned masks or duplicate witness tables.
pub struct ProverKey<F, H, P>
where
    F: NTTField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    expected: ExpectedKey<H::Output>,
    states: Vec<P::State>,
    marker: std::marker::PhantomData<F>,
}
impl<F, H, P> ProverKey<F, H, P>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    pub fn expected(&self) -> &ExpectedKey<H::Output> {
        &self.expected
    }
    /// Repeated borrowing preserves the backend session's lifetime counter.
    pub fn oracles<'a>(
        &'a self,
        pp: &'a P,
    ) -> Result<Vec<CanonicalProverOracle<'a, F, H, P>>, Error> {
        public_oracles::<F, H, P>(pp, &self.expected)?;
        Ok(self
            .expected
            .roots
            .iter()
            .zip(&self.states)
            .map(|(commitment, state)| CanonicalProverOracle {
                parameters: pp,
                commitment,
                state,
            })
            .collect())
    }
}
/// Public expected key descriptors come from trusted preprocessing, not proofs.
pub fn public_oracles<'a, F, H, P>(
    pp: &'a P,
    key: &'a ExpectedKey<H::Output>,
) -> Result<Vec<CanonicalVerifierOracle<'a, H::Output, P>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if pp.context().map_err(convert)? != key.context {
        return Err(error("switching key context mismatch"));
    }
    Ok(key
        .roots
        .iter()
        .map(|commitment| CanonicalVerifierOracle {
            parameters: pp,
            commitment,
        })
        .collect())
}
/// Commit only the authenticated native switching key under trusted geometry.
pub fn preprocess<F, H, P, R>(
    pp: &P,
    config: Config,
    key: &[NTTGadgetRLWE<F>],
    rng: &mut R,
) -> Result<ProverKey<F, H, P>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let tables = key_tables::<F>(pp.num_vars(), pp.width(), &config, key)?;
    let context = pp.context().map_err(convert)?;
    let (roots, states) = tables
        .iter()
        .map(|t| pp.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    Ok(ProverKey {
        expected: ExpectedKey {
            config,
            context,
            roots,
        },
        states,
        marker: std::marker::PhantomData,
    })
}

/// Complete final-stage proof composition over retained canonical backend roots.
pub mod protocol;
