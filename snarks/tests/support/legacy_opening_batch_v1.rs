//! Frozen registry reference from 659db21; retain direct Brakedown dispatch.
//! Bind canonical sources before algebra, then authenticate all expected claims.
//! This component is non-hiding and does not supply a Fiat-Shamir certificate.
use algebra::{PrimeField, matrix_weighted::MatrixPair};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, State},
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use snarks::packed_oracle::VerifierOracle;

/// Invalid registry, claim, private state or rejected terminal authentication.
#[derive(Debug, thiserror::Error)]
#[error("packed opening batch: {0}")]
pub struct Error(String);
/// Authentication only. Claims and source identifiers come from the caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// One packet per used distinct (parameter context, root), in registry order.
    pub openings: Vec<BatchOpening<F, O>>,
}
/// Expected opening obligations, constructed independently by each party.
/// It cannot be deserialized from a proof or cloned as an unchecked certificate.
pub struct OpeningBatch<'a, F, H: Hash + Send + Sync, C> {
    oracles: Vec<VerifierOracle<'a, H::Output, C>>,
    representatives: Vec<usize>,
    groups: Vec<usize>,
    queries: Vec<Vec<Vec<MatrixPair<F>>>>,
    values: Vec<Vec<Vec<F>>>,
    claims: usize,
}
impl<'a, F, H, C> OpeningBatch<'a, F, H, C>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    /// Register and bind all source slots before their algebraic challenges.
    /// Equal roots alias only when their complete parameter contexts also match.
    pub fn new(
        trans: &mut Transcript<F>,
        oracles: &[VerifierOracle<'a, H::Output, C>],
    ) -> Result<Self, Error> {
        if oracles.is_empty() {
            return Err(Error("empty source registry".into()));
        }
        let contexts: Vec<_> = oracles
            .iter()
            .map(|o| o.parameters.context_digest::<F, H>().map_err(convert))
            .collect::<Result<_, _>>()?;
        let mut representatives: Vec<usize> = Vec::new();
        let mut groups = Vec::new();
        for (i, oracle) in oracles.iter().enumerate() {
            let group = representatives.iter().position(|&j| {
                contexts[i] == contexts[j] && oracle.commitment.root == oracles[j].commitment.root
            });
            groups.push(match group {
                Some(j) => j,
                None => {
                    representatives.push(i);
                    representatives.len() - 1
                }
            });
        }
        let registry: Vec<_> = oracles
            .iter()
            .zip(&contexts)
            .map(|(o, c)| (c, o.commitment))
            .collect();
        trans.append_message(b"packed deferred opening registry v1", &registry);
        let count = representatives.len();
        Ok(Self {
            oracles: oracles
                .iter()
                .map(|o| VerifierOracle {
                    parameters: o.parameters,
                    commitment: o.commitment,
                })
                .collect(),
            representatives,
            groups,
            queries: vec![Vec::new(); count],
            values: vec![Vec::new(); count],
            claims: 0,
        })
    }
    /// Bind one algebra-derived obligation immediately, before later challenges.
    pub fn push(
        &mut self,
        trans: &mut Transcript<F>,
        slot: usize,
        query: Vec<MatrixPair<F>>,
        value: Vec<F>,
    ) -> Result<(), Error> {
        let oracle = self
            .oracles
            .get(slot)
            .ok_or_else(|| Error("unknown source slot".into()))?;
        if query.len() != oracle.parameters.num_vars() || value.len() != oracle.parameters.width() {
            return Err(Error("claim dimensions".into()));
        }
        for pair in &query {
            pair.validate(oracle.parameters.width()).map_err(convert)?;
        }
        trans.append_message(
            b"packed deferred opening claim v1",
            &(self.claims, slot, &query, &value),
        );
        let group = self.groups[slot];
        self.queries[group].push(query);
        self.values[group].push(value);
        self.claims += 1;
        Ok(())
    }
    /// Number of individual expected claims, including repeated points.
    pub fn claim_count(&self) -> usize {
        self.claims
    }
    /// Number of distinct registered sources that actually have claims.
    pub fn used_sources(&self) -> usize {
        self.queries.iter().filter(|q| !q.is_empty()).count()
    }
    fn seal(&self, trans: &mut Transcript<F>) -> Result<(), Error> {
        if self.claims == 0 {
            return Err(Error("no expected opening claims".into()));
        }
        trans.append_message(
            b"packed deferred opening seal v1",
            &(self.claims, self.used_sources()),
        );
        Ok(())
    }
    /// Consume all obligations and prove them using states in original slot order.
    pub fn prove(
        self,
        trans: &mut Transcript<F>,
        states: &[&State<F, H>],
    ) -> Result<Proof<F, H::Output>, Error> {
        if states.len() != self.oracles.len() {
            return Err(Error("source state count".into()));
        }
        self.seal(trans)?;
        let mut openings = Vec::new();
        for (group, &slot) in self.representatives.iter().enumerate() {
            if self.queries[group].is_empty() {
                continue;
            }
            let oracle = &self.oracles[slot];
            openings.push(
                oracle
                    .parameters
                    .open_many::<F, H>(
                        trans,
                        oracle.commitment,
                        states[slot],
                        &self.queries[group],
                        &self.values[group],
                    )
                    .map_err(convert)?,
            );
        }
        Ok(Proof { openings })
    }
    /// Consume caller-derived obligations and authenticate every one publicly.
    pub fn verify(
        self,
        trans: &mut Transcript<F>,
        proof: &Proof<F, H::Output>,
    ) -> Result<(), Error> {
        if proof.openings.len() != self.used_sources() {
            return Err(Error("opening packet count".into()));
        }
        self.seal(trans)?;
        let mut openings = proof.openings.iter();
        for (group, &slot) in self.representatives.iter().enumerate() {
            if self.queries[group].is_empty() {
                continue;
            }
            let oracle = &self.oracles[slot];
            oracle
                .parameters
                .verify_many::<F, H>(
                    trans,
                    oracle.commitment,
                    &self.queries[group],
                    &self.values[group],
                    openings.next().unwrap(),
                )
                .map_err(convert)?;
        }
        Ok(())
    }
}
fn convert(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}
