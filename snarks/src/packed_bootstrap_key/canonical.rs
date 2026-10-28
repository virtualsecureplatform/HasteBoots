//! Canonical backend ownership of trusted native bootstrapping-key sources.
use super::*;
use crate::packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle};
use pcs::matrix_weighted::backend::CanonicalPcs;
use rand::{CryptoRng, Rng};

/// Retained source states. Neither cloneable nor serializable; public roots are
/// obtained separately and never reconstruct private masked sessions.
pub struct ProverKey<F, H, P>
where
    F: NTTField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    expected: PublicKey<H::Output>,
    states: Vec<P::State>,
    marker: std::marker::PhantomData<F>,
}
impl<F, H, P> ProverKey<F, H, P>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    pub fn expected(&self) -> &PublicKey<H::Output> {
        &self.expected
    }
    /// Borrow the same retained source state on every invocation.
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
/// Construct trusted public descriptors without private PCS state.
pub fn public_oracles<'a, F, H, P>(
    pp: &'a P,
    key: &'a PublicKey<H::Output>,
) -> Result<Vec<CanonicalVerifierOracle<'a, H::Output, P>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if pp.context().map_err(convert)? != key.context {
        return Err(Error("public key context mismatch".into()));
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
/// Commit authenticated native evaluation-key tables once, with private RNG.
/// No execution-trace key columns are accepted by this setup function.
pub fn prepare<F, H, P, R>(
    pp: &P,
    n: usize,
    key: &[NTTRGSW<F>],
    rng: &mut R,
) -> Result<ProverKey<F, H, P>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let tables = tables(pp.width(), n, key)?;
    if tables[0].num_vars() != pp.num_vars() {
        return Err(Error("public key PCS dimensions".into()));
    }
    let context = pp.context().map_err(convert)?;
    let (roots, states) = tables
        .iter()
        .map(|t| pp.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    Ok(ProverKey {
        expected: PublicKey {
            roots,
            context,
            polynomial_size: n,
            rounds: key.len(),
            basis_bits: key[0].c_neg_s_m().basis().bits(),
        },
        states,
        marker: std::marker::PhantomData,
    })
}
