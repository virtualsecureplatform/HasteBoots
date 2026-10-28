//! References to canonical committed tables; these are not prover-supplied wire metadata.

use algebra::matrix_weighted::PackedTable;
use pcs::{
    matrix_weighted::{Commitment, Parameters, State},
    utils::hash::Hash,
};

/// Prover access to one already committed table, without creating another view commitment.
pub struct ProverOracle<'a, F, H: Hash + Send + Sync, C> {
    /// Trusted encoding and table dimensions.
    pub parameters: &'a Parameters<C>,
    /// Canonical commitment used by every relation referring to this table.
    pub commitment: &'a Commitment<H::Output>,
    /// Private commitment state, never sent to the verifier.
    pub state: &'a State<F, H>,
    /// Private Boolean evaluation table in canonical lane order.
    pub table: &'a PackedTable<F>,
}

/// Verifier access to a canonical commitment and its trusted parameters.
pub struct CanonicalVerifierOracle<'a, O, P> {
    /// Complete trusted backend parameters and logical dimensions.
    pub parameters: &'a P,
    /// Expected canonical root, supplied by the caller.
    pub commitment: &'a Commitment<O>,
}
/// Legacy Brakedown oracle spelling, preserving existing callers.
pub type VerifierOracle<'a, O, C> = CanonicalVerifierOracle<'a, O, Parameters<C>>;

/// Prover references for a trusted canonical backend, without a second table view.
pub struct CanonicalProverOracle<'a, F, H, P>
where
    F: algebra::PrimeField,
    H: Hash + Send + Sync,
    P: pcs::matrix_weighted::backend::CanonicalPcs<F, H>,
{
    /// Complete trusted backend parameters.
    pub parameters: &'a P,
    /// Root shared by every relation referring to this table.
    pub commitment: &'a Commitment<H::Output>,
    /// Private retained state, including any bounded mask session.
    pub state: &'a P::State,
}
impl<'a, F, H, P> CanonicalProverOracle<'a, F, H, P>
where
    F: algebra::PrimeField,
    H: Hash + Send + Sync,
    P: pcs::matrix_weighted::backend::CanonicalPcs<F, H>,
{
    /// Borrow the backend's actual retained logical table for prover algebra.
    pub fn table(&self) -> &PackedTable<F> {
        P::table(self.state)
    }
    /// Remove private state access before public verification.
    pub fn verifier(&self) -> CanonicalVerifierOracle<'a, H::Output, P> {
        CanonicalVerifierOracle {
            parameters: self.parameters,
            commitment: self.commitment,
        }
    }
}

impl<'a, F, H: Hash + Send + Sync, C> ProverOracle<'a, F, H, C> {
    /// Remove private witness/state access for a verifier invocation.
    pub fn verifier(&self) -> VerifierOracle<'a, H::Output, C> {
        VerifierOracle {
            parameters: self.parameters,
            commitment: self.commitment,
        }
    }
}
