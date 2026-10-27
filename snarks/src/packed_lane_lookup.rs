//! Lookup repetitions packed into helper lanes, authenticated against original roots.
//!
//! A helper cell indexes one original scalar tuple; lanes index independent
//! hash/reciprocal pairs. Broadcast query pullbacks avoid source-view commitments.
use crate::packed_oracle::{ProverOracle, VerifierOracle};
pub use crate::packed_tuple_lookup::Config;
use algebra::{
    PrimeField,
    matrix_weighted::{
        PackedTable, broadcast_query, evaluate_constant_lanes, evaluate_prefix_indicator,
    },
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
/// Invalid trusted layout, false lookup or rejected canonical opening.
#[derive(Debug, thiserror::Error)]
#[error("packed lane lookup: {0}")]
pub struct Error(pub String);
/// One complete group of k independent rational challenges.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group<F, O> {
    /// One reciprocal sum per independent challenge lane.
    pub sum_claim: Vec<F>,
    /// Certifies the vector of sums (not just their scalar total).
    pub sum: PackedProof<F>,
    /// Reciprocal identities against broadcast original columns.
    pub zero: ZeroProof<F>,
    /// Canonical source vectors at the pulled-back queries.
    pub source_values: Vec<Vec<F>>,
    /// Helper value at the ZeroCheck query.
    pub reciprocal_value: Vec<F>,
    /// Authenticates the sum and ZeroCheck helper queries together.
    pub reciprocal_opening: BatchOpening<F, O>,
}
/// Lane-batched tuple lookup with no committed compressed or broadcast source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Original tuple multiplicities fixed before every challenge pair.
    pub multiplicities: Vec<F>,
    /// One helper root per full group, all fixed before algebraic challenges.
    pub reciprocal_commitments: Vec<Commitment<O>>,
    /// Exactly ceil(requested_repetitions/k) full groups.
    pub groups: Vec<Group<F, O>>,
    /// All pulled-back queries authenticated against each original column root.
    pub source_openings: Vec<BatchOpening<F, O>>,
}
struct Challenge<F> {
    powers: Vec<F>,
    r: F,
    table: Vec<F>,
}
/// Actual number of independent pairs, including a complete final group.
pub fn effective_repetitions(requested: usize, width: usize) -> Result<usize, Error> {
    if requested == 0 || !width.is_power_of_two() {
        return Err(error("invalid repetitions or lane width"));
    }
    requested
        .div_ceil(width)
        .checked_mul(width)
        .ok_or_else(|| error("repetition overflow"))
}
/// Prover-only wall-clock phase measurements; never part of the transcript.
#[derive(Default, Debug)]
pub struct ProverStatistics {
    /// Input indexing and private broadcast/reciprocal/mask preparation.
    pub preparation: std::time::Duration,
    /// Committing reciprocal helpers.
    pub commitment: std::time::Duration,
    /// Sum claims and packed sumcheck.
    pub sumcheck: std::time::Duration,
    /// Constructing factors and packed ZeroCheck.
    pub zero_check: std::time::Duration,
    /// Evaluating canonical terminal claims and checking public factors.
    pub terminal_evaluation: std::time::Duration,
    /// All helper and original-source openings.
    pub openings: std::time::Duration,
}
/// Prove using the ordinary path without retaining phase measurements.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_with_statistics(
        trans,
        config,
        helper,
        sources,
        &mut ProverStatistics::default(),
    )
}
/// Prove tuples using independent challenge pairs in helper lanes. Helper
/// parameters have mu+log2(k) variables; original canonical sources have mu.
pub fn prove_with_statistics<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    statistics: &mut ProverStatistics,
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let timer = std::time::Instant::now();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let count = bind::<F, H, C>(trans, config, helper, &public)?;
    let k = helper.width();
    let mu = sources[0].parameters.num_vars();
    for source in sources {
        source.table.validate().map_err(convert)?;
        if source.table.num_vars() != mu || source.table.width() != k {
            return Err(error("source table dimensions"));
        }
    }
    let original_len = sources[0].table.values().len();
    let length = original_len
        .checked_mul(k)
        .ok_or_else(|| error("helper size overflow"))?;
    let index: HashMap<_, _> = config
        .table()
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, t)| (t, i))
        .collect();
    let mut key = vec![F::zero(); sources.len()];
    let mut active_indices = Vec::with_capacity(config.logical_len());
    let mut multiplicities = vec![F::zero(); config.table().len()];
    for row in 0..config.logical_len() {
        for (value, source) in key.iter_mut().zip(sources) {
            *value = source.table.values()[row];
        }
        let i = *index
            .get(key.as_slice())
            .ok_or_else(|| error("source tuple outside public table"))?;
        multiplicities[i] += F::one();
        active_indices.push(i);
    }
    trans.append_message(b"lane lookup multiplicities", &multiplicities);
    let challenges = challenges(trans, config, count, k);
    let broadcast = sources
        .iter()
        .map(|s| {
            let mut values = vec![F::zero(); length];
            values
                .par_chunks_exact_mut(k)
                .zip(s.table.values().par_iter())
                .for_each(|(out, &value)| out.fill(value));
            PackedTable::new(helper.num_vars(), k, values).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let helpers = challenges
        .iter()
        .map(|group| {
            let inverses: Vec<Vec<_>> = group
                .iter()
                .map(|c| c.table.iter().map(|&t| F::one() / (c.r + t)).collect())
                .collect();
            let mut values = vec![F::zero(); length];
            values[..config.logical_len() * k]
                .par_chunks_exact_mut(k)
                .zip(active_indices.par_iter())
                .for_each(|(out, &i)| {
                    for lane in 0..k {
                        out[lane] = inverses[lane][i];
                    }
                });
            PackedTable::new(helper.num_vars(), k, values).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    statistics.preparation += timer.elapsed();
    let timer = std::time::Instant::now();
    let (reciprocal_commitments, states): (Vec<_>, Vec<_>) = helpers
        .iter()
        .map(|t| helper.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    trans.append_message(b"lane lookup reciprocal roots", &reciprocal_commitments);
    statistics.commitment += timer.elapsed();
    let timer = std::time::Instant::now();
    let mask = PackedTable::new(
        helper.num_vars(),
        k,
        (0..length)
            .map(|i| {
                if i < config.logical_len() * k {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect(),
    )
    .map_err(convert)?;
    statistics.preparation += timer.elapsed();
    let partial = config.logical_len() != original_len;
    let mut groups = Vec::with_capacity(count);
    let mut queries = Vec::with_capacity(count);
    let mut values = vec![Vec::with_capacity(count); sources.len()];
    for (i, challenge) in challenges.iter().enumerate() {
        let timer = std::time::Instant::now();
        let sum_shape = sum_shape(helper.num_vars(), k);
        let sum_claim =
            packed::sum(&sum_shape, std::slice::from_ref(&helpers[i])).map_err(convert)?;
        check_sums(challenge, &multiplicities, &sum_claim)?;
        let (sum, sum_subclaim) = packed::prove(
            trans,
            &sum_shape,
            std::slice::from_ref(&helpers[i]),
            &sum_claim,
        )
        .map_err(convert)?;
        statistics.sumcheck += timer.elapsed();
        let timer = std::time::Instant::now();
        let zero_shape = zero_shape(helper.num_vars(), k, sources.len(), partial);
        let constants = constants(challenge, sources.len());
        let mut factors = broadcast.clone();
        factors.push(helpers[i].clone());
        factors.push(mask.clone());
        for vector in &constants {
            factors.push(
                PackedTable::new(
                    helper.num_vars(),
                    k,
                    (0..original_len)
                        .flat_map(|_| vector.iter().copied())
                        .collect(),
                )
                .map_err(convert)?,
            );
        }
        let (zero, zero_subclaim, terminals) =
            packed_zero::prove_with_terminal_values(trans, &zero_shape, &factors)
                .map_err(convert)?;
        statistics.zero_check += timer.elapsed();
        let timer = std::time::Instant::now();
        let pulled = broadcast_query(mu, k, &zero_subclaim.query).map_err(convert)?;
        let source_values = if pulled.post_matrix.is_none() {
            terminals[..sources.len()].to_vec()
        } else {
            // A zero-variable source still needs its canonical (untransformed)
            // vector: the broadcast post-matrix need not be invertible.
            sources
                .iter()
                .map(|s| s.table.evaluate(&pulled.query).map_err(convert))
                .collect::<Result<Vec<_>, _>>()?
        };
        let reciprocal_value = terminals[sources.len()].clone();
        check_terminal(
            &zero_shape,
            &zero_subclaim,
            &pulled,
            &source_values,
            &reciprocal_value,
            &constants,
            config.logical_len(),
        )?;
        statistics.terminal_evaluation += timer.elapsed();
        let timer = std::time::Instant::now();
        let reciprocal_opening = helper
            .open_many::<F, H>(
                trans,
                &reciprocal_commitments[i],
                &states[i],
                &[sum_subclaim.query, zero_subclaim.query],
                &[sum_subclaim.expected, reciprocal_value.clone()],
            )
            .map_err(convert)?;
        statistics.openings += timer.elapsed();
        for (column, value) in values.iter_mut().zip(&source_values) {
            column.push(value.clone());
        }
        queries.push(pulled.query);
        groups.push(Group {
            sum_claim,
            sum,
            zero,
            source_values,
            reciprocal_value,
            reciprocal_opening,
        });
    }
    let timer = std::time::Instant::now();
    let source_openings = sources
        .iter()
        .zip(&values)
        .map(|(s, values)| {
            s.parameters
                .open_many::<F, H>(trans, s.commitment, s.state, &queries, values)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    statistics.openings += timer.elapsed();
    Ok(Proof {
        multiplicities,
        reciprocal_commitments,
        groups,
        source_openings,
    })
}
/// Verify all lane claims and pulled-back canonical openings. A partial final
/// group contains fresh independent pairs, never duplicated filler challenges.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let count = bind::<F, H, C>(trans, config, helper, sources)?;
    let k = helper.width();
    let mu = sources[0].parameters.num_vars();
    if proof.multiplicities.len() != config.table().len()
        || proof.groups.len() != count
        || proof.reciprocal_commitments.len() != count
        || proof.source_openings.len() != sources.len()
        || proof
            .groups
            .iter()
            .any(|g| g.source_values.len() != sources.len())
    {
        return Err(error("lane lookup proof counts"));
    }
    trans.append_message(b"lane lookup multiplicities", &proof.multiplicities);
    let challenges = challenges(trans, config, count, k);
    trans.append_message(
        b"lane lookup reciprocal roots",
        &proof.reciprocal_commitments,
    );
    let partial = config.logical_len() != (1usize << mu) * k;
    let mut queries = Vec::with_capacity(count);
    let mut values = vec![Vec::with_capacity(count); sources.len()];
    for (i, challenge) in challenges.iter().enumerate() {
        let group = &proof.groups[i];
        check_sums(challenge, &proof.multiplicities, &group.sum_claim)?;
        let sum_subclaim = packed::verify(
            trans,
            &sum_shape(helper.num_vars(), k),
            &group.sum_claim,
            &group.sum,
        )
        .map_err(convert)?;
        let zero_shape = zero_shape(helper.num_vars(), k, sources.len(), partial);
        let zero_subclaim =
            packed_zero::verify(trans, &zero_shape, &group.zero).map_err(convert)?;
        let pulled = broadcast_query(mu, k, &zero_subclaim.query).map_err(convert)?;
        helper
            .verify_many::<F, H>(
                trans,
                &proof.reciprocal_commitments[i],
                &[sum_subclaim.query, zero_subclaim.query.clone()],
                &[sum_subclaim.expected, group.reciprocal_value.clone()],
                &group.reciprocal_opening,
            )
            .map_err(convert)?;
        check_terminal(
            &zero_shape,
            &zero_subclaim,
            &pulled,
            &group.source_values,
            &group.reciprocal_value,
            &constants(challenge, sources.len()),
            config.logical_len(),
        )?;
        for (column, value) in values.iter_mut().zip(&group.source_values) {
            column.push(value.clone());
        }
        queries.push(pulled.query);
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
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
) -> Result<usize, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if sources.len() != config.num_columns() {
        return Err(error("source column count"));
    }
    let pp = sources[0].parameters;
    let k = pp.width();
    let actual = effective_repetitions(config.repetitions(), k)?;
    let count = actual / k;
    let capacity = 1usize
        .checked_shl(u32::try_from(pp.num_vars()).map_err(convert)?)
        .and_then(|n| n.checked_mul(k))
        .and_then(|n| n.checked_mul(k))
        .ok_or_else(|| error("helper capacity overflow"))?;
    if helper.width() != k
        || helper.num_vars() != pp.num_vars() + k.ilog2() as usize
        || helper.num_vars() == 0
        || config.logical_len() > capacity / k
        || sources
            .iter()
            .any(|s| s.parameters.width() != k || s.parameters.num_vars() != pp.num_vars())
    {
        return Err(error("incompatible helper or source dimensions"));
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
    trans.append_message(
        b"lane packed original tuple lookup v1",
        &(
            config,
            actual,
            helper.context_digest::<F, H>().map_err(convert)?,
            contexts,
        ),
    );
    Ok(count)
}
fn challenges<F: PrimeField>(
    trans: &mut Transcript<F>,
    config: &Config<F>,
    groups: usize,
    width: usize,
) -> Vec<Vec<Challenge<F>>> {
    (0..groups)
        .map(|_| {
            (0..width)
                .map(|_| {
                    let y = trans.get_challenge(b"lane tuple hash challenge");
                    let mut power = F::one();
                    let powers: Vec<_> = (0..config.num_columns())
                        .map(|_| {
                            let p = power;
                            power *= y;
                            p
                        })
                        .collect();
                    let table: Vec<_> = config
                        .table()
                        .iter()
                        .map(|row| {
                            row.iter()
                                .zip(&powers)
                                .fold(F::zero(), |s, (&a, &p)| s + a * p)
                        })
                        .collect();
                    let r = loop {
                        let r = trans.get_challenge(b"lane tuple reciprocal challenge");
                        if r != F::zero() && !table.iter().any(|&t| r + t == F::zero()) {
                            break r;
                        }
                    };
                    Challenge { powers, r, table }
                })
                .collect()
        })
        .collect()
}
fn check_sums<F: PrimeField>(group: &[Challenge<F>], h: &[F], sums: &[F]) -> Result<(), Error> {
    if sums.len() != group.len() {
        return Err(error("lane sum width"));
    }
    for (challenge, &sum) in group.iter().zip(sums) {
        if h.len() != challenge.table.len() {
            return Err(error("multiplicity count"));
        }
        let expected = h
            .iter()
            .zip(&challenge.table)
            .fold(F::zero(), |s, (&h, &t)| s + h / (challenge.r + t));
        if sum != expected {
            return Err(error("independent lane reciprocal sum mismatch"));
        }
    }
    Ok(())
}
fn constants<F: PrimeField>(group: &[Challenge<F>], columns: usize) -> Vec<Vec<F>> {
    std::iter::once(group.iter().map(|c| c.r).collect())
        .chain((1..columns).map(|j| group.iter().map(|c| c.powers[j]).collect()))
        .collect()
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
    columns: usize,
    partial: bool,
) -> PackedShape<F> {
    let f = columns;
    let mask = columns + 1;
    let r = columns + 2;
    let mut terms = vec![(F::one(), vec![f, r]), (-F::one(), vec![mask])];
    for j in 0..columns {
        let mut indices = vec![f, j];
        if j > 0 {
            indices.push(columns + 2 + j);
        }
        if partial {
            indices.push(mask);
        }
        terms.push((F::one(), indices));
    }
    PackedShape {
        num_vars,
        width,
        num_factors: 2 * columns + 2,
        terms,
    }
}
fn check_terminal<F: PrimeField>(
    shape: &PackedShape<F>,
    subclaim: &packed_zero::ZeroSubclaim<F>,
    pulled: &algebra::matrix_weighted::BroadcastQuery<F>,
    source_values: &[Vec<F>],
    reciprocal: &[F],
    constants: &[Vec<F>],
    active: usize,
) -> Result<(), Error> {
    let mut terminal = source_values
        .iter()
        .map(|v| pulled.apply(v, shape.width).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    terminal.push(reciprocal.to_vec());
    terminal.push(
        evaluate_prefix_indicator(
            shape.width,
            &subclaim.query,
            active
                .checked_mul(shape.width)
                .ok_or_else(|| error("mask overflow"))?,
        )
        .map_err(convert)?,
    );
    for vector in constants {
        terminal
            .push(evaluate_constant_lanes(shape.width, &subclaim.query, vector).map_err(convert)?);
    }
    subclaim.check(shape, &terminal).map_err(convert)
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
    #[test]
    fn inactive_lane_poles_cannot_hide_nonzero_helpers() {
        let shape = zero_shape::<F>(1, 4, 3, true);
        // R + sum Y^j*A_j is zero, but only R remains when mask=0.
        let mut factors = vec![
            vec![-F::from(5usize); 4],
            vec![F::zero(); 4],
            vec![F::zero(); 4],
            vec![F::from(7usize); 4],
            vec![F::zero(); 4],
            vec![F::from(5usize); 4],
            vec![F::one(); 4],
            vec![F::one(); 4],
        ];
        assert_eq!(shape.validate().unwrap(), 4 * (2 * 4 - 1));
        assert!(
            shape
                .evaluate(&factors)
                .unwrap()
                .iter()
                .all(|&v| v != F::zero())
        );
        factors[3].fill(F::zero());
        assert_eq!(shape.evaluate(&factors).unwrap(), vec![F::zero(); 4]);
        let full = zero_shape::<F>(1, 4, 3, false);
        assert_eq!(full.validate().unwrap(), 3 * (2 * 4 - 1));
    }
}
