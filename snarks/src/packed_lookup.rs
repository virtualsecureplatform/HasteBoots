//! Small-public-table packed lookup via reciprocal sums (2025/719, Appendix H.1).
//!
//! Multiplicities are bound BEFORE lookup challenges. Helper reciprocals are
//! committed before sum/ZeroCheck challenges; all terminal witness values are
//! authenticated against canonical commitments. Padding uses a public mask.
use crate::packed_oracle::{ProverOracle, VerifierOracle};
use algebra::{
    PrimeField,
    matrix_weighted::{PackedTable, evaluate_prefix_indicator},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, Commitment, Parameters},
    utils::{code::RowCode, hash::Hash},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sumcheck::{
    packed::{self, PackedProof, PackedShape},
    packed_zero::{self, ZeroProof},
};

/// Invalid configuration, false lookup, or rejected authenticated subproof.
#[derive(Debug, thiserror::Error)]
#[error("packed lookup: {0}")]
pub struct Error(pub String);

/// Trusted public lookup statement. Never take this configuration from a proof.
#[derive(Clone, Debug, Serialize)]
pub struct Config<F> {
    logical_len: usize,
    table: Vec<F>,
    repetitions: usize,
}
impl<F: PrimeField> Config<F> {
    /// Construct a lookup over a distinct, explicit public scalar table.
    pub fn new(logical_len: usize, table: Vec<F>, repetitions: usize) -> Result<Self, Error> {
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
        if self.logical_len == 0
            || self.table.is_empty()
            || self.repetitions == 0
            || self.logical_len as u128 + self.table.len() as u128 - 1 >= p
            || self
                .table
                .iter()
                .enumerate()
                .any(|(i, t)| self.table[..i].contains(t))
            || p <= self.excluded_challenges() as u128
        {
            return Err(error(
                "invalid length, table, repetition count or challenge domain",
            ));
        }
        Ok(())
    }
    /// Number of active flattened scalar entries in the canonical source.
    pub fn logical_len(&self) -> usize {
        self.logical_len
    }
    /// Trusted distinct table entries.
    pub fn table(&self) -> &[F] {
        &self.table
    }
    /// Independent reciprocal challenges (separate from packed lanes).
    pub fn repetitions(&self) -> usize {
        self.repetitions
    }
    /// Number of rejected challenge values: zero and negated table entries.
    pub fn excluded_challenges(&self) -> usize {
        self.table.len() + usize::from(!self.table.contains(&F::zero()))
    }
    /// Accepted challenge-domain size for soundness accounting.
    pub fn challenge_domain_size(&self) -> Result<u128, Error> {
        self.validate()?;
        Ok(characteristic::<F>()? - self.excluded_challenges() as u128)
    }
    /// Degree numerator in the scalar rational-identity error bound.
    /// The lookup-only error is at most (numerator / domain_size)^repetitions,
    /// before sumcheck, ZeroCheck, commitment and Fiat-Shamir errors.
    pub fn rational_degree_bound(&self) -> u128 {
        self.logical_len as u128 + self.table.len() as u128 - 1
    }
}

/// One repetition's algebraic proof and authenticated reciprocal helper values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Repetition<F, O> {
    /// Lane sums, whose total must equal the public-table rational sum.
    pub sum_claim: Vec<F>,
    /// Degree-one packed sum of reciprocals.
    pub sum: PackedProof<F>,
    /// Pointwise reciprocal identity, including inactive padding.
    pub zero: ZeroProof<F>,
    /// Canonical source value at the reciprocal ZeroCheck query.
    pub source_value: Vec<F>,
    /// Helper value at that query (the sum query value is derived).
    pub reciprocal_value: Vec<F>,
    /// Both helper queries authenticated together.
    pub reciprocal_opening: BatchOpening<F, O>,
}
/// Complete scalar-table lookup component; no private table is given to verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Public-table multiplicities, fixed before all reciprocal challenges.
    pub multiplicities: Vec<F>,
    /// Auxiliary reciprocal roots, fixed before algebraic challenges.
    pub reciprocal_commitments: Vec<Commitment<O>>,
    /// Fixed number of independent rational checks.
    pub repetitions: Vec<Repetition<F, O>>,
    /// All ZeroCheck source queries against the original canonical root.
    pub source_opening: BatchOpening<F, O>,
}

/// Prove active entries belong to the trusted public table. Padding may contain
/// arbitrary values; it is excluded by the authenticated public mask identity.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    source: &ProverOracle<'_, F, H, C>,
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, H, C>(trans, config, &source.verifier())?;
    source.table.validate().map_err(convert)?;
    let parameters = source.parameters;
    if source.table.num_vars() != parameters.num_vars()
        || source.table.width() != parameters.width()
    {
        return Err(error("canonical source table dimensions"));
    }
    // Resolve membership once. Public tables are small; each reciprocal helper
    // can reuse its M distinct inverses instead of performing N inversions.
    let indices: HashMap<_, _> = config
        .table
        .iter()
        .copied()
        .enumerate()
        .map(|(i, t)| (t, i))
        .collect();
    let active_indices = source.table.values()[..config.logical_len]
        .iter()
        .map(|a| {
            indices
                .get(a)
                .copied()
                .ok_or_else(|| error("source entry outside public table"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut multiplicities = vec![F::zero(); config.table.len()];
    for &i in &active_indices {
        multiplicities[i] += F::one();
    }
    trans.append_message(b"packed lookup multiplicities", &multiplicities);
    let challenges = challenges(trans, config);
    let mask = mask_table(parameters, config.logical_len)?;
    let helpers: Vec<_> = challenges
        .iter()
        .map(|&r| {
            let inverses: Vec<_> = config.table.iter().map(|&t| F::one() / (r + t)).collect();
            let mut values = vec![F::zero(); source.table.values().len()];
            values[..config.logical_len]
                .par_iter_mut()
                .zip(active_indices.par_iter())
                .for_each(|(value, &index)| *value = inverses[index]);
            PackedTable::new(parameters.num_vars(), parameters.width(), values).map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    let (reciprocal_commitments, states): (Vec<_>, Vec<_>) = helpers
        .iter()
        .map(|t| parameters.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    trans.append_message(b"packed lookup reciprocal roots", &reciprocal_commitments);
    let mut repetitions = Vec::with_capacity(config.repetitions);
    let mut source_queries = Vec::with_capacity(config.repetitions);
    let mut source_values = Vec::with_capacity(config.repetitions);
    for (i, &r) in challenges.iter().enumerate() {
        let sum_shape = sum_shape::<F, C>(parameters);
        let sum_claim =
            packed::sum(&sum_shape, std::slice::from_ref(&helpers[i])).map_err(convert)?;
        check_total(config, &multiplicities, r, &sum_claim, parameters.width())?;
        let (sum, sum_subclaim) = packed::prove(
            trans,
            &sum_shape,
            std::slice::from_ref(&helpers[i]),
            &sum_claim,
        )
        .map_err(convert)?;
        let zero_shape = zero_shape(parameters, r);
        let factors = vec![source.table.clone(), helpers[i].clone(), mask.clone()];
        let (zero, zero_subclaim) =
            packed_zero::prove(trans, &zero_shape, &factors).map_err(convert)?;
        let source_value = source
            .table
            .evaluate(&zero_subclaim.query)
            .map_err(convert)?;
        let reciprocal_value = helpers[i].evaluate(&zero_subclaim.query).map_err(convert)?;
        let mask_value =
            evaluate_prefix_indicator(parameters.width(), &zero_subclaim.query, config.logical_len)
                .map_err(convert)?;
        zero_subclaim
            .check(
                &zero_shape,
                &[source_value.clone(), reciprocal_value.clone(), mask_value],
            )
            .map_err(convert)?;
        let reciprocal_opening = parameters
            .open_many::<F, H>(
                trans,
                &reciprocal_commitments[i],
                &states[i],
                &[sum_subclaim.query, zero_subclaim.query.clone()],
                &[sum_subclaim.expected, reciprocal_value.clone()],
            )
            .map_err(convert)?;
        source_queries.push(zero_subclaim.query);
        source_values.push(source_value.clone());
        repetitions.push(Repetition {
            sum_claim,
            sum,
            zero,
            source_value,
            reciprocal_value,
            reciprocal_opening,
        });
    }
    let source_opening = parameters
        .open_many::<F, H>(
            trans,
            source.commitment,
            source.state,
            &source_queries,
            &source_values,
        )
        .map_err(convert)?;
    Ok(Proof {
        multiplicities,
        reciprocal_commitments,
        repetitions,
        source_opening,
    })
}

/// Verify membership using only the trusted configuration, source root and proof.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    source: &VerifierOracle<'_, H::Output, C>,
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, H, C>(trans, config, source)?;
    if proof.multiplicities.len() != config.table.len()
        || proof.repetitions.len() != config.repetitions
        || proof.reciprocal_commitments.len() != config.repetitions
    {
        return Err(error("incorrect lookup proof counts"));
    }
    trans.append_message(b"packed lookup multiplicities", &proof.multiplicities);
    let challenges = challenges(trans, config);
    trans.append_message(
        b"packed lookup reciprocal roots",
        &proof.reciprocal_commitments,
    );
    let parameters = source.parameters;
    let mut queries = Vec::with_capacity(config.repetitions);
    let mut values = Vec::with_capacity(config.repetitions);
    for (i, &r) in challenges.iter().enumerate() {
        let rep = &proof.repetitions[i];
        check_total(
            config,
            &proof.multiplicities,
            r,
            &rep.sum_claim,
            parameters.width(),
        )?;
        let sum_subclaim = packed::verify(
            trans,
            &sum_shape::<F, C>(parameters),
            &rep.sum_claim,
            &rep.sum,
        )
        .map_err(convert)?;
        let zero_shape = zero_shape(parameters, r);
        let zero_subclaim = packed_zero::verify(trans, &zero_shape, &rep.zero).map_err(convert)?;
        parameters
            .verify_many::<F, H>(
                trans,
                &proof.reciprocal_commitments[i],
                &[sum_subclaim.query, zero_subclaim.query.clone()],
                &[sum_subclaim.expected, rep.reciprocal_value.clone()],
                &rep.reciprocal_opening,
            )
            .map_err(convert)?;
        let mask_value =
            evaluate_prefix_indicator(parameters.width(), &zero_subclaim.query, config.logical_len)
                .map_err(convert)?;
        zero_subclaim
            .check(
                &zero_shape,
                &[
                    rep.source_value.clone(),
                    rep.reciprocal_value.clone(),
                    mask_value,
                ],
            )
            .map_err(convert)?;
        queries.push(zero_subclaim.query);
        values.push(rep.source_value.clone());
    }
    parameters
        .verify_many::<F, H>(
            trans,
            source.commitment,
            &queries,
            &values,
            &proof.source_opening,
        )
        .map_err(convert)
}
fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    source: &VerifierOracle<'_, H::Output, C>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    config.validate()?;
    let pp = source.parameters;
    let capacity = 1usize
        .checked_shl(u32::try_from(pp.num_vars()).map_err(convert)?)
        .and_then(|n| n.checked_mul(pp.width()))
        .ok_or_else(|| error("source capacity overflow"))?;
    if pp.num_vars() == 0 || pp.width() == 0 || config.logical_len > capacity {
        return Err(error("source capacity or ZeroCheck dimensions"));
    }
    trans.append_message(
        b"packed scalar lookup v1",
        &(
            config,
            pp.context_digest::<F, H>().map_err(convert)?,
            source.commitment,
        ),
    );
    Ok(())
}
fn challenges<F: PrimeField>(trans: &mut Transcript<F>, config: &Config<F>) -> Vec<F> {
    (0..config.repetitions)
        .map(|_| {
            loop {
                let r = trans.get_challenge(b"packed lookup reciprocal challenge");
                if r != F::zero() && !config.table.iter().any(|&t| r + t == F::zero()) {
                    break r;
                }
            }
        })
        .collect()
}
fn check_total<F: PrimeField>(
    config: &Config<F>,
    h: &[F],
    r: F,
    lanes: &[F],
    width: usize,
) -> Result<(), Error> {
    if lanes.len() != width || h.len() != config.table.len() {
        return Err(error("sum or multiplicity dimensions"));
    }
    let actual = lanes.iter().copied().fold(F::zero(), |a, b| a + b);
    let expected = h
        .iter()
        .zip(&config.table)
        .fold(F::zero(), |a, (&h, &t)| a + h / (r + t));
    if actual != expected {
        return Err(error("reciprocal total differs from public table"));
    }
    Ok(())
}
fn sum_shape<F: PrimeField, C>(pp: &Parameters<C>) -> PackedShape<F> {
    PackedShape {
        num_vars: pp.num_vars(),
        width: pp.width(),
        num_factors: 1,
        terms: vec![(F::one(), vec![0])],
    }
}
fn zero_shape<F: PrimeField, C>(pp: &Parameters<C>, r: F) -> PackedShape<F> {
    // f*(r + mask*a) = mask. Since r!=0, inactive f is forced to zero
    // even when a padded entry is -r. The cubic term is intentional.
    PackedShape {
        num_vars: pp.num_vars(),
        width: pp.width(),
        num_factors: 3,
        terms: vec![
            (r, vec![1]),
            (F::one(), vec![1, 2, 0]),
            (-F::one(), vec![2]),
        ],
    }
}
fn mask_table<F: PrimeField, C>(
    pp: &Parameters<C>,
    active: usize,
) -> Result<PackedTable<F>, Error> {
    let length = (1usize << pp.num_vars()) * pp.width();
    PackedTable::new(
        pp.num_vars(),
        pp.width(),
        (0..length)
            .map(|i| if i < active { F::one() } else { F::zero() })
            .collect(),
    )
    .map_err(convert)
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

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::BabyBear as F;
    use num_traits::{One, Zero};
    use pcs::utils::code::ReedSolomonCode;
    #[test]
    fn inactive_pole_cannot_hide_nonzero_reciprocal() {
        let pp = Parameters::new::<F>(1, 2, 0, 4, ReedSolomonCode::new(2, 4)).unwrap();
        let r = F::from(5usize);
        let a = vec![F::from(1usize), -r];
        let mut f = vec![F::one() / (r + a[0]), F::from(7usize)];
        let mask = vec![F::one(), F::zero()];
        // The tempting unmasked denominator would incorrectly accept this pole.
        assert_eq!(f[1] * (r + a[1]), mask[1]);
        let shape = zero_shape(&pp, r);
        assert_ne!(
            shape
                .evaluate(&[a.clone(), f.clone(), mask.clone()])
                .unwrap()[1],
            F::zero()
        );
        f[1] = F::zero();
        assert_eq!(shape.evaluate(&[a, f, mask]).unwrap(), vec![F::zero(); 2]);
    }
}
