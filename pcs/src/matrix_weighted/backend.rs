//! Statically selected canonical packed-oracle backend boundary.
//!
//! Backend choice and parameters are trusted caller inputs, never proof metadata.
use super::{BatchOpening, Commitment, Parameters, State, masked_polyfrim};
use crate::utils::{code::RowCode, hash::Hash};
use algebra::{
    AbstractExtensionField, NTTField, PrimeField,
    matrix_weighted::{MatrixPair, PackedTable},
};
use helper::Transcript;
use rand::{CryptoRng, Rng};
use serde::Serialize;

/// Canonical table commitments and ordered terminal authentication.
/// Implementations must bind the complete parameter context and expected root.
pub trait CanonicalPcs<F: PrimeField, H: Hash + Send + Sync> {
    /// Private retained source state; not part of a verifier proof.
    type State;
    /// Public ordered-query authentication packet.
    type BatchProof: Serialize;
    /// Parameter/prover/verifier failure.
    type Error: std::fmt::Display;
    /// Registry framing, selected by the trusted backend.
    const REGISTRY_DOMAIN: &'static [u8];
    /// Framing for an algebra-derived claim before later challenges.
    const CLAIM_DOMAIN: &'static [u8];
    /// Framing for the final number of claims and used canonical roots.
    const SEAL_DOMAIN: &'static [u8];
    /// Logical number of Boolean cell variables.
    fn num_vars(&self) -> usize;
    /// Original consecutive lane count.
    fn width(&self) -> usize;
    /// Complete context used together with the root for alias decisions.
    fn context(&self) -> Result<H::Output, Self::Error>;
    /// Normalize a checked claim for this backend's transcript representation.
    /// The legacy default retains its original wire bytes.
    fn normalize_claim(
        &self,
        query: Vec<MatrixPair<F>>,
        values: Vec<F>,
    ) -> Result<(Vec<MatrixPair<F>>, Vec<F>), Self::Error> {
        Ok((query, values))
    }
    /// Commit an original logical table, with fresh private randomness if needed.
    fn commit<R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        rng: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Self::Error>;
    /// Borrow the retained logical table for prover-side algebra.
    fn table(state: &Self::State) -> &PackedTable<F>;
    /// Authenticate all expected ordered claims against this exact source root.
    fn open_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Self::BatchProof, Self::Error>;
    /// Verify all caller-derived claims, using no private table or source state.
    fn verify_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Self::Error>;
}
impl<F, H, C> CanonicalPcs<F, H> for Parameters<C>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type State = State<F, H>;
    type BatchProof = BatchOpening<F, H::Output>;
    type Error = super::Error;
    const REGISTRY_DOMAIN: &'static [u8] = b"packed deferred opening registry v1";
    const CLAIM_DOMAIN: &'static [u8] = b"packed deferred opening claim v1";
    const SEAL_DOMAIN: &'static [u8] = b"packed deferred opening seal v1";
    fn num_vars(&self) -> usize {
        Parameters::num_vars(self)
    }
    fn width(&self) -> usize {
        Parameters::width(self)
    }
    fn context(&self) -> Result<H::Output, Self::Error> {
        self.context_digest::<F, H>()
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        _rng: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Self::Error> {
        Parameters::commit::<F, H>(self, table)
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        state.table()
    }
    fn open_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Self::BatchProof, Self::Error> {
        Parameters::open_many::<F, H>(self, t, root, state, queries, values)
    }
    fn verify_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Self::Error> {
        Parameters::verify_many::<F, H>(self, t, root, queries, values, proof)
    }
}
impl<F, EF, H> CanonicalPcs<F, H> for masked_polyfrim::Parameters<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
{
    type State = masked_polyfrim::State<F, EF, H>;
    type BatchProof = masked_polyfrim::Proof<EF, H::Output>;
    type Error = masked_polyfrim::Error;
    const REGISTRY_DOMAIN: &'static [u8] = b"masked packed opening registry v2";
    const CLAIM_DOMAIN: &'static [u8] = b"masked packed opening claim v2";
    const SEAL_DOMAIN: &'static [u8] = b"masked packed opening seal v2";
    fn num_vars(&self) -> usize {
        self.num_vars()
    }
    fn width(&self) -> usize {
        self.width()
    }
    fn context(&self) -> Result<H::Output, Self::Error> {
        Ok(self.context_digest::<H>())
    }
    fn normalize_claim(
        &self,
        query: Vec<MatrixPair<F>>,
        values: Vec<F>,
    ) -> Result<(Vec<MatrixPair<F>>, Vec<F>), Self::Error> {
        let (mut queries, mut values) = self.claims(&[query], &[values])?;
        Ok((queries.remove(0), values.remove(0)))
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        rng: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Self::Error> {
        self.commit::<H, R>(table, rng)
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        state.table()
    }
    fn open_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Self::BatchProof, Self::Error> {
        self.open_many::<H>(t, root, state, queries, values)
    }
    fn verify_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Self::Error> {
        self.verify_many::<H>(t, root, queries, values, proof)
    }
}
