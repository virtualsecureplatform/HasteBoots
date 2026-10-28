//! Statically selected canonical packed-oracle backend boundary.
//!
//! Backend choice and parameters are trusted caller inputs, never proof metadata.
use super::{BatchOpening, Commitment, Opening, Parameters, State, masked_polyfrim};
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
    /// Public authentication of one ordered query.
    type SingleProof: Serialize;
    /// Domain binding a complete trusted linear relation before fresh queries.
    const LINEAR_DOMAIN: &'static [u8];
    /// Domain binding ordered coefficient/evaluation roots and trusted NTT shape.
    const NTT_DOMAIN: &'static [u8];
    /// Context-bound polynomial relation framing for the canonical API.
    const RELATION_DOMAIN: &'static [u8];
    /// Bind accumulator geometry, public endpoints and ordered expected roots.
    const ACCUMULATOR_DOMAIN: &'static [u8];
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
    /// Declared per-source opening lifetime, if this backend bounds reuse.
    /// None means the backend does not expose a finite opening limit.
    fn opening_limit(&self) -> Option<usize> {
        None
    }
    /// Remaining private allowance, when tracked by the retained owner.
    /// This is a preflight observation, not an atomic multi-source reservation.
    fn remaining_openings(&self, _state: &Self::State) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }
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
    /// Normalize public/proof scalar values for this backend's wire contract.
    fn normalize_values(&self, values: Vec<F>) -> Vec<F> {
        values
    }
    /// Reject unsupported encodings in already serialized proof responses.
    fn validate_values(&self, _values: &[F]) -> Result<(), Self::Error> {
        Ok(())
    }
    /// Authenticate one caller-derived ordered matrix response.
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        query: &[MatrixPair<F>],
        value: &[F],
    ) -> Result<Self::SingleProof, Self::Error>;
    /// Verify one response against the independently expected source root.
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        query: &[MatrixPair<F>],
        value: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Self::Error>;
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
    type SingleProof = Opening<F, H::Output>;
    const LINEAR_DOMAIN: &'static [u8] = b"packed canonical linear relations v1";
    const ACCUMULATOR_DOMAIN: &'static [u8] = b"packed accumulator canonical linkage v1";
    const NTT_DOMAIN: &'static [u8] = b"packed tensor NTT v2";
    const RELATION_DOMAIN: &'static [u8] = b"HasteBoots canonical packed relation v2";
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
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        query: &[MatrixPair<F>],
        value: &[F],
    ) -> Result<Self::SingleProof, Self::Error> {
        Parameters::open::<F, H>(self, t, root, state, query, value)
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        query: &[MatrixPair<F>],
        value: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Self::Error> {
        Parameters::verify::<F, H>(self, t, root, query, value, proof)
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
    type SingleProof = masked_polyfrim::Proof<EF, H::Output>;
    const LINEAR_DOMAIN: &'static [u8] = b"masked packed canonical linear relations v2";
    const ACCUMULATOR_DOMAIN: &'static [u8] = b"masked packed accumulator canonical linkage v2";
    const NTT_DOMAIN: &'static [u8] = b"masked packed tensor NTT v2";
    const RELATION_DOMAIN: &'static [u8] = b"HasteBoots masked packed relation v2";
    type Error = masked_polyfrim::Error;
    const REGISTRY_DOMAIN: &'static [u8] = b"masked packed opening registry v2";
    const CLAIM_DOMAIN: &'static [u8] = b"masked packed opening claim v2";
    const SEAL_DOMAIN: &'static [u8] = b"masked packed opening seal v2";
    fn opening_limit(&self) -> Option<usize> {
        Some(self.max_openings())
    }
    fn remaining_openings(&self, state: &Self::State) -> Result<Option<usize>, Self::Error> {
        Ok(Some(self.max_openings().saturating_sub(state.spent()?)))
    }
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
    fn normalize_values(&self, values: Vec<F>) -> Vec<F> {
        values.into_iter().map(|v| v.canonicalized()).collect()
    }
    fn validate_values(&self, values: &[F]) -> Result<(), Self::Error> {
        if values.iter().any(|v| !v.is_canonical()) {
            Err(masked_polyfrim::Error(
                "noncanonical public packed response",
            ))
        } else {
            Ok(())
        }
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        query: &[MatrixPair<F>],
        value: &[F],
    ) -> Result<Self::SingleProof, Self::Error> {
        self.open_many::<H>(t, root, state, &[query.to_vec()], &[value.to_vec()])
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        query: &[MatrixPair<F>],
        value: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Self::Error> {
        self.verify_many::<H>(t, root, &[query.to_vec()], &[value.to_vec()], proof)
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

impl<F, EF, H> CanonicalPcs<F, H> for masked_polyfrim::joint::Parameters<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
{
    type State = masked_polyfrim::State<F, EF, H>;
    type BatchProof = masked_polyfrim::joint::Proof<EF, H::Output>;
    type SingleProof = masked_polyfrim::joint::Proof<EF, H::Output>;
    const LINEAR_DOMAIN: &'static [u8] =
        b"joint-source masked packed canonical linear relations v1";
    const ACCUMULATOR_DOMAIN: &'static [u8] =
        b"joint-source masked packed accumulator canonical linkage v1";
    const NTT_DOMAIN: &'static [u8] = b"joint-source masked packed tensor NTT v1";
    const RELATION_DOMAIN: &'static [u8] = b"HasteBoots joint-source masked packed relation v1";
    type Error = masked_polyfrim::Error;
    const REGISTRY_DOMAIN: &'static [u8] = b"joint-source masked packed opening registry v1";
    const CLAIM_DOMAIN: &'static [u8] = b"joint-source masked packed opening claim v1";
    const SEAL_DOMAIN: &'static [u8] = b"joint-source masked packed opening seal v1";
    fn opening_limit(&self) -> Option<usize> {
        Some(self.max_openings())
    }
    fn remaining_openings(&self, state: &Self::State) -> Result<Option<usize>, Self::Error> {
        Ok(Some(self.max_openings().saturating_sub(state.spent()?)))
    }
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
    fn normalize_values(&self, values: Vec<F>) -> Vec<F> {
        values.into_iter().map(|v| v.canonicalized()).collect()
    }
    fn validate_values(&self, values: &[F]) -> Result<(), Self::Error> {
        if values.iter().any(|v| !v.is_canonical()) {
            Err(masked_polyfrim::Error(
                "noncanonical public packed response",
            ))
        } else {
            Ok(())
        }
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        query: &[MatrixPair<F>],
        value: &[F],
    ) -> Result<Self::SingleProof, Self::Error> {
        self.open_many::<H>(t, root, state, &[query.to_vec()], &[value.to_vec()])
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        query: &[MatrixPair<F>],
        value: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Self::Error> {
        self.verify_many::<H>(t, root, &[query.to_vec()], &[value.to_vec()], proof)
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
