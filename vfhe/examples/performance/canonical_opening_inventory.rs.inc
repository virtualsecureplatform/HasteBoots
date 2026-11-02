//! Benchmark-only observations of successful public PCS verification calls.
use algebra::{
    matrix_weighted::{MatrixPair, PackedTable},
    PrimeField,
};
use helper::Transcript;
use pcs::{
    matrix_weighted::{backend::CanonicalPcs, Commitment},
    utils::hash::Hash,
};
use rand::{CryptoRng, Rng};
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    role: usize,
    kind: &'static str,
    num_vars: usize,
    width: usize,
    queries: usize,
    context_sha256: String,
    root_hex: String,
}
impl Event {
    pub fn json(&self) -> String {
        // Strings are fixed kind tags or lowercase hex, never caller text.
        format!("{{\"role\":{},\"kind\":\"{}\",\"num_vars\":{},\"width\":{},\"queries\":{},\"context_sha256\":\"{}\",\"root_hex\":\"{}\"}}",
            self.role,self.kind,self.num_vars,self.width,self.queries,self.context_sha256,self.root_hex)
    }
}
pub type Log = Arc<Mutex<Vec<Event>>>;
pub struct Observed<P> {
    inner: P,
    enabled: bool,
    role: usize,
    num_vars: usize,
    width: usize,
    context_sha256: String,
    log: Log,
}
impl<P> Observed<P> {
    pub fn new<F: PrimeField, H: Hash + Send + Sync>(
        inner: P,
        role: usize,
        enabled: bool,
        log: Log,
    ) -> Self
    where
        P: CanonicalPcs<F, H>,
    {
        let context = <P as CanonicalPcs<F, H>>::context(&inner).unwrap_or_else(|e| panic!("{e}"));
        Self {
            role,
            enabled,
            num_vars: <P as CanonicalPcs<F, H>>::num_vars(&inner),
            width: <P as CanonicalPcs<F, H>>::width(&inner),
            context_sha256: super::digest(&context),
            inner,
            log,
        }
    }
    fn record<H: Hash>(&self, root: &Commitment<H::Output>, kind: &'static str, queries: usize) {
        if self.enabled {
            self.log.lock().unwrap().push(Event {
                role: self.role,
                kind,
                num_vars: self.num_vars,
                width: self.width,
                queries,
                context_sha256: self.context_sha256.clone(),
                root_hex: root
                    .root
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            });
        }
    }
}
impl<F: PrimeField, H: Hash + Send + Sync, P: CanonicalPcs<F, H>> CanonicalPcs<F, H>
    for Observed<P>
{
    type State = P::State;
    type SingleProof = P::SingleProof;
    type BatchProof = P::BatchProof;
    type Error = P::Error;
    const LINEAR_DOMAIN: &'static [u8] = P::LINEAR_DOMAIN;
    const NTT_DOMAIN: &'static [u8] = P::NTT_DOMAIN;
    const RELATION_DOMAIN: &'static [u8] = P::RELATION_DOMAIN;
    const ACCUMULATOR_DOMAIN: &'static [u8] = P::ACCUMULATOR_DOMAIN;
    const REGISTRY_DOMAIN: &'static [u8] = P::REGISTRY_DOMAIN;
    const CLAIM_DOMAIN: &'static [u8] = P::CLAIM_DOMAIN;
    const SEAL_DOMAIN: &'static [u8] = P::SEAL_DOMAIN;
    fn num_vars(&self) -> usize {
        self.num_vars
    }
    fn width(&self) -> usize {
        self.width
    }
    fn opening_limit(&self) -> Option<usize> {
        <P as CanonicalPcs<F, H>>::opening_limit(&self.inner)
    }
    fn remaining_openings(&self, state: &Self::State) -> Result<Option<usize>, Self::Error> {
        <P as CanonicalPcs<F, H>>::remaining_openings(&self.inner, state)
    }
    fn context(&self) -> Result<H::Output, Self::Error> {
        <P as CanonicalPcs<F, H>>::context(&self.inner)
    }
    fn normalize_claim(
        &self,
        q: Vec<MatrixPair<F>>,
        v: Vec<F>,
    ) -> Result<(Vec<MatrixPair<F>>, Vec<F>), Self::Error> {
        <P as CanonicalPcs<F, H>>::normalize_claim(&self.inner, q, v)
    }
    fn normalize_values(&self, v: Vec<F>) -> Vec<F> {
        <P as CanonicalPcs<F, H>>::normalize_values(&self.inner, v)
    }
    fn validate_values(&self, v: &[F]) -> Result<(), Self::Error> {
        <P as CanonicalPcs<F, H>>::validate_values(&self.inner, v)
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        t: &PackedTable<F>,
        r: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Self::Error> {
        <P as CanonicalPcs<F, H>>::commit(&self.inner, t, r)
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        <P as CanonicalPcs<F, H>>::table(state)
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[MatrixPair<F>],
        v: &[F],
    ) -> Result<Self::SingleProof, Self::Error> {
        <P as CanonicalPcs<F, H>>::open(&self.inner, t, root, state, q, v)
    }
    fn open_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[Vec<MatrixPair<F>>],
        v: &[Vec<F>],
    ) -> Result<Self::BatchProof, Self::Error> {
        <P as CanonicalPcs<F, H>>::open_many(&self.inner, t, root, state, q, v)
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[MatrixPair<F>],
        v: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Self::Error> {
        <P as CanonicalPcs<F, H>>::verify(&self.inner, t, root, q, v, proof)?;
        self.record::<H>(root, "single", 1);
        Ok(())
    }
    fn verify_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[Vec<MatrixPair<F>>],
        v: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Self::Error> {
        <P as CanonicalPcs<F, H>>::verify_many(&self.inner, t, root, q, v, proof)?;
        self.record::<H>(root, "batch", q.len());
        Ok(())
    }
}
