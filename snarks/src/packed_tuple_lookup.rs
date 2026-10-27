//! Public tuple lookups with independent hash/reciprocal pairs and canonical inputs.
//!
//! Original tuple multiplicities and all source roots precede every challenge.
//! No compressed-source view is committed: reciprocal ZeroChecks authenticate
//! the original columns directly. Hash collisions are separately budgeted.
use crate::packed_oracle::{ProverOracle, VerifierOracle};
use algebra::{
    PrimeField,
    matrix_weighted::{PackedTable, evaluate_prefix_indicator},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, Commitment},
    utils::{code::RowCode, hash::Hash},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use sumcheck::{
    packed::{self, PackedProof, PackedShape},
    packed_zero::{self, ZeroProof},
};

/// Invalid trusted configuration, false membership, or rejected canonical opening.
#[derive(Debug, thiserror::Error)]
#[error("packed tuple lookup: {0}")]
pub struct Error(pub String);
/// Trusted distinct public tuples and independent repetition count.
#[derive(Clone, Debug, Serialize)]
pub struct Config<F> {
    logical_len: usize,
    table: Vec<Vec<F>>,
    repetitions: usize,
}
impl<F: PrimeField> Config<F> {
    /// Configure membership for the first logical_len entries of each column.
    pub fn new(logical_len: usize, table: Vec<Vec<F>>, repetitions: usize) -> Result<Self, Error> {
        let config = Self {
            logical_len,
            table,
            repetitions,
        };
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<(), Error> {
        let p = characteristic::<F>()?;
        let columns = self.table.first().map_or(0, Vec::len);
        if self.logical_len == 0
            || columns == 0
            || self.repetitions == 0
            || self.table.iter().any(|t| t.len() != columns)
            || self.table.iter().collect::<HashSet<_>>().len() != self.table.len()
            || self.logical_len as u128 + self.table.len() as u128 - 1 >= p
            || self.table.len() as u128 + 1 >= p
        {
            return Err(error(
                "invalid tuple table, length, characteristic or repetitions",
            ));
        }
        Ok(())
    }
    /// Active scalar entries in each canonical column.
    pub fn logical_len(&self) -> usize {
        self.logical_len
    }
    /// Public ordered tuple entries.
    pub fn table(&self) -> &[Vec<F>] {
        &self.table
    }
    /// Number of original columns.
    pub fn num_columns(&self) -> usize {
        self.table[0].len()
    }
    /// Independent hash/reciprocal pairs; packed width alone does not amplify them.
    pub fn repetitions(&self) -> usize {
        self.repetitions
    }
    /// Numerator of the fixed-bad-row hash collision bound, denominator p.
    pub fn hash_collision_numerator(&self) -> u128 {
        self.table.len() as u128 * (self.num_columns() - 1) as u128
    }
    /// Rational numerator degree after a fixed hash (denominator domain below).
    pub fn rational_degree_bound(&self) -> u128 {
        self.logical_len as u128 + self.table.len() as u128 - 1
    }
    /// Lower bound on the accepted r-domain size, including excluded zero/poles.
    pub fn reciprocal_domain_lower_bound(&self) -> Result<u128, Error> {
        self.validate()?;
        Ok(characteristic::<F>()? - self.table.len() as u128 - 1)
    }
}
/// One repetition, using one independently sampled tuple hash and reciprocal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Repetition<F, O> {
    /// Lane sums of the reciprocal helper.
    pub sum_claim: Vec<F>,
    /// Packed degree-one sumcheck.
    pub sum: PackedProof<F>,
    /// Reciprocal identity against the original columns and public mask.
    pub zero: ZeroProof<F>,
    /// Original canonical column values at the ZeroCheck query.
    pub source_values: Vec<Vec<F>>,
    /// Helper value at that query.
    pub reciprocal_value: Vec<F>,
    /// Sum and ZeroCheck helper queries authenticated together.
    pub reciprocal_opening: BatchOpening<F, O>,
}
/// Complete tuple-membership component, without private sources at verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Original tuple multiplicities fixed before every hash and reciprocal.
    pub multiplicities: Vec<F>,
    /// All reciprocal roots fixed before algebraic challenges.
    pub reciprocal_commitments: Vec<Commitment<O>>,
    /// Fixed number of independent tuple tests.
    pub repetitions: Vec<Repetition<F, O>>,
    /// One batch of all terminal queries per original canonical column.
    pub source_openings: Vec<BatchOpening<F, O>>,
}
struct Challenge<F> {
    powers: Vec<F>,
    r: F,
    table: Vec<F>,
}

/// Prove membership of canonical column tuples in the trusted public table.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    sources: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    bind::<F, H, C>(trans, config, &public)?;
    let pp = sources[0].parameters;
    for source in sources {
        source.table.validate().map_err(convert)?;
        if source.table.num_vars() != pp.num_vars() || source.table.width() != pp.width() {
            return Err(error("source table dimensions"));
        }
    }
    let index: HashMap<_, _> = config
        .table
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, t)| (t, i))
        .collect();
    let mut key = vec![F::zero(); config.num_columns()];
    let mut active_indices = Vec::with_capacity(config.logical_len);
    let mut multiplicities = vec![F::zero(); config.table.len()];
    for row in 0..config.logical_len {
        for (a, source) in key.iter_mut().zip(sources) {
            *a = source.table.values()[row];
        }
        let i = *index
            .get(key.as_slice())
            .ok_or_else(|| error("source tuple outside public table"))?;
        active_indices.push(i);
        multiplicities[i] += F::one();
    }
    trans.append_message(b"packed tuple multiplicities", &multiplicities);
    let challenges = challenges(trans, config);
    let length = sources[0].table.values().len();
    let mask = PackedTable::new(
        pp.num_vars(),
        pp.width(),
        (0..length)
            .map(|i| {
                if i < config.logical_len {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect(),
    )
    .map_err(convert)?;
    let helpers = challenges
        .iter()
        .map(|challenge| {
            let inverses: Vec<_> = challenge
                .table
                .iter()
                .map(|&t| F::one() / (challenge.r + t))
                .collect();
            let mut values = vec![F::zero(); length];
            values[..config.logical_len]
                .par_iter_mut()
                .zip(active_indices.par_iter())
                .for_each(|(a, &i)| *a = inverses[i]);
            PackedTable::new(pp.num_vars(), pp.width(), values).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (reciprocal_commitments, states): (Vec<_>, Vec<_>) = helpers
        .iter()
        .map(|t| pp.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    trans.append_message(b"packed tuple reciprocal roots", &reciprocal_commitments);
    let mut repetitions = Vec::with_capacity(config.repetitions);
    let mut queries = Vec::with_capacity(config.repetitions);
    let mut values = vec![Vec::with_capacity(config.repetitions); sources.len()];
    for (i, challenge) in challenges.iter().enumerate() {
        let sum_shape = sum_shape(pp.num_vars(), pp.width());
        let sum_claim =
            packed::sum(&sum_shape, std::slice::from_ref(&helpers[i])).map_err(convert)?;
        check_total(challenge, &multiplicities, &sum_claim, pp.width())?;
        let (sum, sum_subclaim) = packed::prove(
            trans,
            &sum_shape,
            std::slice::from_ref(&helpers[i]),
            &sum_claim,
        )
        .map_err(convert)?;
        let zero_shape = zero_shape(pp.num_vars(), pp.width(), challenge);
        let mut factors: Vec<_> = sources.iter().map(|s| s.table.clone()).collect();
        factors.push(helpers[i].clone());
        factors.push(mask.clone());
        let (zero, zero_subclaim) =
            packed_zero::prove(trans, &zero_shape, &factors).map_err(convert)?;
        let source_values = sources
            .iter()
            .map(|s| s.table.evaluate(&zero_subclaim.query).map_err(convert))
            .collect::<Result<Vec<_>, _>>()?;
        let reciprocal_value = helpers[i].evaluate(&zero_subclaim.query).map_err(convert)?;
        let mut terminal = source_values.clone();
        terminal.push(reciprocal_value.clone());
        terminal.push(
            evaluate_prefix_indicator(pp.width(), &zero_subclaim.query, config.logical_len)
                .map_err(convert)?,
        );
        zero_subclaim
            .check(&zero_shape, &terminal)
            .map_err(convert)?;
        let reciprocal_opening = pp
            .open_many::<F, H>(
                trans,
                &reciprocal_commitments[i],
                &states[i],
                &[sum_subclaim.query, zero_subclaim.query.clone()],
                &[sum_subclaim.expected, reciprocal_value.clone()],
            )
            .map_err(convert)?;
        for (column, value) in values.iter_mut().zip(&source_values) {
            column.push(value.clone());
        }
        queries.push(zero_subclaim.query);
        repetitions.push(Repetition {
            sum_claim,
            sum,
            zero,
            source_values,
            reciprocal_value,
            reciprocal_opening,
        });
    }
    let source_openings = sources
        .iter()
        .zip(&values)
        .map(|(source, values)| {
            source
                .parameters
                .open_many::<F, H>(trans, source.commitment, source.state, &queries, values)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Proof {
        multiplicities,
        reciprocal_commitments,
        repetitions,
        source_openings,
    })
}
/// Verify membership while authenticating every original column separately.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, H, C>(trans, config, sources)?;
    if proof.multiplicities.len() != config.table.len()
        || proof.repetitions.len() != config.repetitions
        || proof.reciprocal_commitments.len() != config.repetitions
        || proof.source_openings.len() != sources.len()
        || proof
            .repetitions
            .iter()
            .any(|r| r.source_values.len() != sources.len())
    {
        return Err(error("tuple proof counts"));
    }
    let pp = sources[0].parameters;
    trans.append_message(b"packed tuple multiplicities", &proof.multiplicities);
    let challenges = challenges(trans, config);
    trans.append_message(
        b"packed tuple reciprocal roots",
        &proof.reciprocal_commitments,
    );
    let mut queries = Vec::with_capacity(config.repetitions);
    let mut values = vec![Vec::with_capacity(config.repetitions); sources.len()];
    for (i, challenge) in challenges.iter().enumerate() {
        let rep = &proof.repetitions[i];
        check_total(challenge, &proof.multiplicities, &rep.sum_claim, pp.width())?;
        let sum_subclaim = packed::verify(
            trans,
            &sum_shape(pp.num_vars(), pp.width()),
            &rep.sum_claim,
            &rep.sum,
        )
        .map_err(convert)?;
        let zero_shape = zero_shape(pp.num_vars(), pp.width(), challenge);
        let zero_subclaim = packed_zero::verify(trans, &zero_shape, &rep.zero).map_err(convert)?;
        pp.verify_many::<F, H>(
            trans,
            &proof.reciprocal_commitments[i],
            &[sum_subclaim.query, zero_subclaim.query.clone()],
            &[sum_subclaim.expected, rep.reciprocal_value.clone()],
            &rep.reciprocal_opening,
        )
        .map_err(convert)?;
        let mut terminal = rep.source_values.clone();
        terminal.push(rep.reciprocal_value.clone());
        terminal.push(
            evaluate_prefix_indicator(pp.width(), &zero_subclaim.query, config.logical_len)
                .map_err(convert)?,
        );
        zero_subclaim
            .check(&zero_shape, &terminal)
            .map_err(convert)?;
        for (column, value) in values.iter_mut().zip(&rep.source_values) {
            column.push(value.clone());
        }
        queries.push(zero_subclaim.query);
    }
    for ((source, values), opening) in sources.iter().zip(&values).zip(&proof.source_openings) {
        source
            .parameters
            .verify_many::<F, H>(trans, source.commitment, &queries, values, opening)
            .map_err(convert)?;
    }
    Ok(())
}
fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    sources: &[VerifierOracle<'_, H::Output, C>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    config.validate()?;
    if sources.len() != config.num_columns() {
        return Err(error("source column count"));
    }
    let pp = sources[0].parameters;
    let length = 1usize
        .checked_shl(u32::try_from(pp.num_vars()).map_err(convert)?)
        .and_then(|n| n.checked_mul(pp.width()))
        .ok_or_else(|| error("capacity overflow"))?;
    if pp.num_vars() == 0
        || pp.width() == 0
        || config.logical_len > length
        || sources
            .iter()
            .any(|s| s.parameters.num_vars() != pp.num_vars() || s.parameters.width() != pp.width())
    {
        return Err(error("source dimensions"));
    }
    let contexts = sources
        .iter()
        .map(|s| {
            Ok((
                s.parameters.context_digest::<F, H>().map_err(convert)?,
                s.commitment,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(b"packed original tuple lookup v1", &(config, contexts));
    Ok(())
}
fn challenges<F: PrimeField>(trans: &mut Transcript<F>, config: &Config<F>) -> Vec<Challenge<F>> {
    (0..config.repetitions)
        .map(|_| {
            let y = trans.get_challenge(b"packed tuple hash challenge");
            let mut power = F::one();
            let powers: Vec<_> = (0..config.num_columns())
                .map(|_| {
                    let result = power;
                    power *= y;
                    result
                })
                .collect();
            let table: Vec<_> = config
                .table
                .iter()
                .map(|row| {
                    row.iter()
                        .zip(&powers)
                        .fold(F::zero(), |s, (&a, &p)| s + a * p)
                })
                .collect();
            let r = loop {
                let r = trans.get_challenge(b"packed tuple reciprocal challenge");
                if r != F::zero() && !table.iter().any(|&t| r + t == F::zero()) {
                    break r;
                }
            };
            Challenge { powers, r, table }
        })
        .collect()
}
fn check_total<F: PrimeField>(
    challenge: &Challenge<F>,
    h: &[F],
    lanes: &[F],
    width: usize,
) -> Result<(), Error> {
    if lanes.len() != width || h.len() != challenge.table.len() {
        return Err(error("tuple sum dimensions"));
    }
    let expected = h
        .iter()
        .zip(&challenge.table)
        .fold(F::zero(), |s, (&h, &t)| s + h / (challenge.r + t));
    if lanes.iter().copied().fold(F::zero(), |s, a| s + a) != expected {
        return Err(error("tuple reciprocal total mismatch"));
    }
    Ok(())
}
fn sum_shape<F: PrimeField>(num_vars: usize, width: usize) -> PackedShape<F> {
    PackedShape {
        num_vars,
        width,
        num_factors: 1,
        terms: vec![(F::one(), vec![0])],
    }
}
fn zero_shape<F: PrimeField>(
    num_vars: usize,
    width: usize,
    challenge: &Challenge<F>,
) -> PackedShape<F> {
    let l = challenge.powers.len();
    let mut terms = vec![(challenge.r, vec![l]), (-F::one(), vec![l + 1])];
    terms.extend(
        challenge
            .powers
            .iter()
            .enumerate()
            .map(|(i, &p)| (p, vec![l, l + 1, i])),
    );
    PackedShape {
        num_vars,
        width,
        num_factors: l + 2,
        terms,
    }
}
fn characteristic<F: PrimeField>() -> Result<u128, Error> {
    F::MODULUS_VALUE.to_string().parse().map_err(convert)
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
