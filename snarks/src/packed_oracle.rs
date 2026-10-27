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
pub struct VerifierOracle<'a, O, C> {
    /// Trusted encoding and table dimensions, not copied from a proof.
    pub parameters: &'a Parameters<C>,
    /// Expected canonical commitment.
    pub commitment: &'a Commitment<O>,
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
