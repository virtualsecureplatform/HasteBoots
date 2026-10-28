//! Experimental extension-field rational lookups over canonical packed roots.
//!
//! Algebraic checks run in a direct-sampled extension transcript seeded by 64
//! parent transcript bytes. Its final digest binds helper roots, messages and
//! terminal claims before base-field PCS randomness. No compressed/broadcast
//! source is committed. This component has no whole-proof security certificate.
/// Same phase counters used by the lane backend; not serialized or transcript data.
pub use crate::packed_lane_lookup::ProverStatistics;
use crate::packed_opening_batch::OpeningBatch;

/// Lookup groups sharing deferred authentication of canonical sources.
pub mod deferred;
/// Multiple requests sharing scalar sum/identity challenges and PCS queries.
pub mod shared;

use crate::{
    packed_extension as bridge,
    packed_oracle::{ProverOracle, VerifierOracle},
    packed_tuple_lookup::Config,
};
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials,
    PolynomialInfo, PrimeField, matrix_weighted::PackedTable,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, Commitment, Parameters},
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, rc::Rc};
use sumcheck::{MLSumcheck, Proof as SumProof};
/// Invalid geometry, nonmembership, or rejected algebraic/canonical certificate.
#[derive(Debug, thiserror::Error)]
#[error("packed extension lookup: {0}")]
pub struct Error(pub String);
/// One independent extension-field compression/reciprocal pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group<F: Field, EF: Field, O> {
    /// Claimed reciprocal sum, checked against fixed public-table multiplicities.
    pub sum_claim: EF,
    /// Sum of the helper over its full Boolean domain.
    pub sum: SumProof<EF>,
    /// Equality-weighted reciprocal identity at every Boolean cell.
    pub zero: SumProof<EF>,
    /// Actual canonical MW source values, before a possible constant post-map.
    pub source_values: Vec<Vec<F>>,
    /// Extension helper value at the identity subclaim point.
    pub reciprocal_value: EF,
    /// Both helper subclaims authenticated against the one coefficient root.
    pub reciprocal_opening: BatchOpening<F, O>,
}
/// Lookup proof with multiplicities fixed before all extension challenges.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, O> {
    /// Public-table multiplicities, supplied in the original prime field.
    pub multiplicities: Vec<F>,
    /// Coefficient-packed helper roots, fixed before sumcheck challenges.
    pub reciprocal_commitments: Vec<Commitment<O>>,
    /// Exactly the trusted repetition count; extension degree is not repetitions.
    pub groups: Vec<Group<F, EF, O>>,
    /// Batched canonical openings for each original source root.
    pub source_openings: Vec<BatchOpening<F, O>>,
}
struct Challenge<EF> {
    powers: Vec<EF>,
    r: EF,
    inverses: Vec<EF>,
}
struct Algebra<EF> {
    sum_point: Vec<EF>,
    sum_value: EF,
    zero_point: Vec<EF>,
}
/// Prove using the supplied canonical sources and explicit helper geometry.
pub fn prove<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_with_statistics::<F, EF, H, C>(
        parent,
        config,
        helper,
        sources,
        &mut ProverStatistics::default(),
    )
}
/// Prove with phase counters. No new source commitment or source-view root exists.
pub fn prove_with_statistics<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    statistics: &mut ProverStatistics,
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let witness: Vec<_> = sources.iter().map(|s| s.table).collect();
    prove_impl::<F, EF, H, C>(parent, config, helper, sources, &witness, statistics, true)
}
fn prove_impl<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    witness: &[&PackedTable<F>],
    statistics: &mut ProverStatistics,
    strict: bool,
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_inner::<F,EF,H,C>(parent,config,helper,sources,witness,statistics,strict,None)
}
fn prove_inner<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    witness: &[&PackedTable<F>],
    statistics: &mut ProverStatistics,
    strict: bool,
    deferred: Option<(&mut OpeningBatch<'_,F,H,C>, &[usize])>,
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let timer = std::time::Instant::now();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let (n, k) = bind::<F, EF, H, C>(parent, config, helper, &public)?;
    if witness.len() != sources.len() {
        return Err(error("source witness count"));
    }
    for (table, source) in witness.iter().zip(sources) {
        table.validate().map_err(convert)?;
        source.table.validate().map_err(convert)?;
        if table.width() != k
            || table.num_vars() != source.parameters.num_vars()
            || source.table.width() != k
            || source.table.num_vars() != table.num_vars()
        {
            return Err(error("source witness dimensions"));
        }
    }
    let size = 1usize << n;
    let partial = config.logical_len() != size;
    let index: HashMap<_, _> = config
        .table()
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, t)| (t, i))
        .collect();
    let mut key = vec![F::zero(); sources.len()];
    let mut indices = Vec::with_capacity(config.logical_len());
    let mut multiplicities = vec![F::zero(); config.table().len()];
    for row in 0..config.logical_len() {
        for (v, table) in key.iter_mut().zip(witness) {
            *v = table.values()[row];
        }
        let i = *index
            .get(key.as_slice())
            .ok_or_else(|| error("source tuple outside public table"))?;
        multiplicities[i] += F::one();
        indices.push(i);
    }
    let mut child = child::<F, EF>(parent, &multiplicities);
    let challenges = challenges(&mut child, config);
    let helper_values: Vec<Vec<EF>> = challenges
        .iter()
        .map(|c| {
            let mut values = vec![EF::zero(); size];
            for (out, &i) in values.iter_mut().zip(&indices) {
                *out = c.inverses[i];
            }
            values
        })
        .collect();
    let tables = helper_values
        .iter()
        .map(|v| bridge::table::<F, EF>(n, k, v).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    statistics.preparation += timer.elapsed();
    let timer = std::time::Instant::now();
    let (reciprocal_commitments, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| helper.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    child.append_message(
        b"extension lookup reciprocal roots",
        &reciprocal_commitments,
    );
    statistics.commitment += timer.elapsed();
    let mut groups = Vec::with_capacity(challenges.len());
    let mut algebra = Vec::with_capacity(challenges.len());
    let mut source_queries = Vec::with_capacity(challenges.len());
    for (i, c) in challenges.iter().enumerate() {
        let timer = std::time::Instant::now();
        let h = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            n,
            helper_values[i].clone(),
        ));
        let sum_claim = h.evaluations.iter().copied().fold(EF::zero(), |a, b| a + b);
        if sum_claim != table_sum::<F, EF>(c, &multiplicities) {
            return Err(error("reciprocal sum claim"));
        }
        child.append_message(b"extension lookup sum claim", &sum_claim);
        let mut sum_poly = ListOfProductsOfPolynomials::new(n);
        sum_poly.add_product([h.clone()], EF::one());
        let (sum, sum_state) = MLSumcheck::prove(&mut child, &sum_poly).map_err(convert)?;
        let sum_point = sum_state.randomness.clone();
        let sum_value = sum_state.fast_evaluate()[0];
        drop(sum_state);
        statistics.sumcheck += timer.elapsed();
        let timer = std::time::Instant::now();
        let mut g = vec![EF::zero(); size];
        for ((table, &power), j) in witness.iter().zip(&c.powers).zip(0..) {
            for (out, &value) in g.iter_mut().zip(table.values()) {
                if j == 0 {
                    *out = EF::from_base(value);
                } else {
                    *out += power * value;
                }
            }
        }
        let g = Rc::new(DenseMultilinearExtension::from_evaluations_vec(n, g));
        let eq_point = child.get_vec_challenge(b"extension lookup identity point", n);
        let eq = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            n,
            equality_table(&eq_point),
        ));
        let mask = partial.then(|| {
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                n,
                (0..size)
                    .map(|j| {
                        if j < config.logical_len() {
                            EF::one()
                        } else {
                            EF::zero()
                        }
                    })
                    .collect(),
            ))
        });
        let zero_poly = identity_polynomial(&eq, &h, &g, mask.as_ref(), c.r);
        statistics.preparation += timer.elapsed();
        let timer = std::time::Instant::now();
        let (zero, zero_state) = MLSumcheck::prove(&mut child, &zero_poly).map_err(convert)?;
        let zero_point = zero_state.randomness.clone();
        let terminals = zero_state.fast_evaluate();
        let reciprocal_value = terminals[zero_poly.raw_pointers_lookup_table[&Rc::as_ptr(&h)]];
        let expected = zero_poly.products.iter().zip(&zero_poly.linear_ops).fold(
            EF::zero(),
            |out, ((coef, factors), ops)| {
                out + factors
                    .iter()
                    .zip(ops)
                    .fold(*coef, |v, (&idx, &(a, b))| v * (a * terminals[idx] + b))
            },
        );
        drop(zero_state);
        statistics.zero_check += timer.elapsed();
        let timer = std::time::Instant::now();
        let pulled =
            bridge::scalar_query::<F, EF>(sources[0].parameters.num_vars(), k, &zero_point)
                .map_err(convert)?;
        let source_values = sources
            .iter()
            .map(|s| s.table.evaluate(&pulled.query).map_err(convert))
            .collect::<Result<Vec<_>, _>>()?;
        if strict {
            check_terminal::<F, EF>(
                config.logical_len(),
                c,
                &eq_point,
                &zero_point,
                &pulled,
                &source_values,
                reciprocal_value,
                expected,
                k,
            )?;
        }
        child.append_message(
            b"extension lookup terminal claims",
            &(&source_values, reciprocal_value),
        );
        statistics.terminal_evaluation += timer.elapsed();
        groups.push(Group {
            sum_claim,
            sum,
            zero,
            source_values,
            reciprocal_value,
            reciprocal_opening: BatchOpening {
                test: vec![],
                evaluations: vec![],
                columns: vec![],
            },
        });
        source_queries.push(pulled.query);
        algebra.push(Algebra {
            sum_point,
            sum_value,
            zero_point,
        });
    }
    finish_child(parent, &mut child);
    let timer = std::time::Instant::now();
    for (i, (group, a)) in groups.iter_mut().zip(&algebra).enumerate() {
        let q0 = bridge::coefficients_query::<F, EF>(k, &a.sum_point).map_err(convert)?;
        let q1 = bridge::coefficients_query::<F, EF>(k, &a.zero_point).map_err(convert)?;
        group.reciprocal_opening = helper
            .open_many::<F, H>(
                parent,
                &reciprocal_commitments[i],
                &states[i],
                &[q0.query, q1.query],
                &[
                    bridge::vector::<F, EF>(k, a.sum_value).map_err(convert)?,
                    bridge::vector::<F, EF>(k, group.reciprocal_value).map_err(convert)?,
                ],
            )
            .map_err(convert)?;
    }
    let source_openings = if let Some((batch,slots))=deferred {
        if slots.len()!=sources.len() {return Err(error("deferred source slot count"));}
        for j in 0..sources.len() {
            for (query,group) in source_queries.iter().zip(&groups) {
                batch.push(parent,slots[j],query.clone(),group.source_values[j].clone()).map_err(convert)?;
            }
        }
        Vec::new()
    } else {
        sources
        .iter()
        .enumerate()
        .map(|(j, s)| {
            s.parameters
                .open_many::<F, H>(
                    parent,
                    s.commitment,
                    s.state,
                    &source_queries,
                    &groups
                        .iter()
                        .map(|g| g.source_values[j].clone())
                        .collect::<Vec<_>>(),
                )
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?
    };
    statistics.openings += timer.elapsed();
    Ok(Proof {
        multiplicities,
        reciprocal_commitments,
        groups,
        source_openings,
    })
}
/// Verify from expected source roots, trusted table/geometry and the proof only.
pub fn verify<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, EF, H, C>(parent, config, helper, sources, proof, true)
}
fn verify_impl<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, EF, H::Output>,
    strict: bool,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_inner::<F,EF,H,C>(parent,config,helper,sources,proof,strict,None)
}
fn verify_inner<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, EF, H::Output>,
    strict: bool,
    deferred: Option<(&mut OpeningBatch<'_,F,H,C>, &[usize])>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let (n, k) = bind::<F, EF, H, C>(parent, config, helper, sources)?;
    let count = config.repetitions();
    if proof.multiplicities.len() != config.table().len()
        || proof.groups.len() != count
        || proof.reciprocal_commitments.len() != count
        || (if deferred.is_some() { !proof.source_openings.is_empty() } else { proof.source_openings.len() != sources.len() })
        || proof.groups.iter().any(|g| {
            g.source_values.len() != sources.len() || g.source_values.iter().any(|v| v.len() != k)
        })
    {
        return Err(error("proof counts or source value dimensions"));
    }
    let mut child = child::<F, EF>(parent, &proof.multiplicities);
    let challenges = challenges(&mut child, config);
    child.append_message(
        b"extension lookup reciprocal roots",
        &proof.reciprocal_commitments,
    );
    let partial = config.logical_len() != 1usize << n;
    let mut algebra = Vec::with_capacity(count);
    let mut queries = Vec::with_capacity(count);
    for (group, c) in proof.groups.iter().zip(&challenges) {
        if group.sum_claim != table_sum::<F, EF>(c, &proof.multiplicities) {
            return Err(error("reciprocal sum claim"));
        }
        child.append_message(b"extension lookup sum claim", &group.sum_claim);
        let sum = MLSumcheck::verify(
            &mut child,
            &PolynomialInfo {
                num_variables: n,
                max_multiplicands: 1,
            },
            group.sum_claim,
            &group.sum,
        )
        .map_err(convert)?;
        let eq_point = child.get_vec_challenge(b"extension lookup identity point", n);
        let zero = MLSumcheck::verify(
            &mut child,
            &PolynomialInfo {
                num_variables: n,
                max_multiplicands: if partial { 4 } else { 3 },
            },
            EF::zero(),
            &group.zero,
        )
        .map_err(convert)?;
        let pulled =
            bridge::scalar_query::<F, EF>(sources[0].parameters.num_vars(), k, &zero.point)
                .map_err(convert)?;
        if strict {
            check_terminal::<F, EF>(
                config.logical_len(),
                c,
                &eq_point,
                &zero.point,
                &pulled,
                &group.source_values,
                group.reciprocal_value,
                zero.expected_evaluations,
                k,
            )?;
        }
        child.append_message(
            b"extension lookup terminal claims",
            &(&group.source_values, group.reciprocal_value),
        );
        queries.push(pulled.query);
        algebra.push(Algebra {
            sum_point: sum.point,
            sum_value: sum.expected_evaluations,
            zero_point: zero.point,
        });
    }
    finish_child(parent, &mut child);
    for (i, (group, a)) in proof.groups.iter().zip(&algebra).enumerate() {
        let q0 = bridge::coefficients_query::<F, EF>(k, &a.sum_point).map_err(convert)?;
        let q1 = bridge::coefficients_query::<F, EF>(k, &a.zero_point).map_err(convert)?;
        helper
            .verify_many::<F, H>(
                parent,
                &proof.reciprocal_commitments[i],
                &[q0.query, q1.query],
                &[
                    bridge::vector::<F, EF>(k, a.sum_value).map_err(convert)?,
                    bridge::vector::<F, EF>(k, group.reciprocal_value).map_err(convert)?,
                ],
                &group.reciprocal_opening,
            )
            .map_err(convert)?;
    }
    if let Some((batch,slots))=deferred {
        if slots.len()!=sources.len() {return Err(error("deferred source slot count"));}
        for j in 0..sources.len() {
            for (query,group) in queries.iter().zip(&proof.groups) {
                batch.push(parent,slots[j],query.clone(),group.source_values[j].clone()).map_err(convert)?;
            }
        }
    } else {
    for (j, (source, opening)) in sources.iter().zip(&proof.source_openings).enumerate() {
        source
            .parameters
            .verify_many::<F, H>(
                parent,
                source.commitment,
                &queries,
                &proof
                    .groups
                    .iter()
                    .map(|g| g.source_values[j].clone())
                    .collect::<Vec<_>>(),
                opening,
            )
            .map_err(convert)?;
    }
    }
    Ok(())
}
fn bind<F, EF, H, C>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
) -> Result<(usize, usize), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if sources.len() != config.num_columns() {
        return Err(error("source column count"));
    }
    let pp = sources[0].parameters;
    let k = pp.width();
    if EF::D == 0 || k < EF::D || !k.is_power_of_two() {
        return Err(error("extension degree/packed width"));
    }
    let n = pp
        .num_vars()
        .checked_add(k.ilog2() as usize)
        .ok_or_else(|| error("helper variable overflow"))?;
    let capacity = 1usize
        .checked_shl(u32::try_from(n).map_err(convert)?)
        .ok_or_else(|| error("helper domain overflow"))?;
    if n == 0
        || helper.num_vars() != n
        || helper.width() != k
        || config.logical_len() > capacity
        || sources
            .iter()
            .any(|s| s.parameters.num_vars() != pp.num_vars() || s.parameters.width() != k)
    {
        return Err(error("incompatible source/helper geometry"));
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
    parent.append_message(
        b"packed extension tuple lookup v1",
        &(
            config,
            EF::D,
            helper.context_digest::<F, H>().map_err(convert)?,
            contexts,
        ),
    );
    Ok((n, k))
}
fn child<F: PrimeField + Serialize, EF: AbstractExtensionField<F>>(
    parent: &mut Transcript<F>,
    multiplicities: &[F],
) -> Transcript<EF> {
    parent.append_message(b"extension lookup multiplicities", &multiplicities);
    let mut seed = [0u8; 64];
    parent.get_challenge_bytes(b"extension lookup child seed v1", &mut seed);
    let mut child = Transcript::<EF>::new_direct_extension::<F>();
    child.append_message(b"extension lookup parent seed", &seed.as_slice());
    child
}
fn finish_child<F: Field, EF: Field>(parent: &mut Transcript<F>, child: &mut Transcript<EF>) {
    let mut digest = [0u8; 32];
    child.get_challenge_bytes(b"extension lookup algebra digest", &mut digest);
    parent.append_message(b"extension lookup algebra transcript", &digest);
}
fn challenges<F: PrimeField, EF: AbstractExtensionField<F> + Serialize>(
    child: &mut Transcript<EF>,
    config: &Config<F>,
) -> Vec<Challenge<EF>> {
    (0..config.repetitions())
        .map(|_| {
            let y = child.get_challenge(b"extension tuple hash challenge");
            let mut power = EF::one();
            let powers: Vec<_> = (0..config.num_columns())
                .map(|_| {
                    let out = power;
                    power *= y;
                    out
                })
                .collect();
            let table: Vec<_> = config
                .table()
                .iter()
                .map(|t| {
                    t.iter()
                        .zip(&powers)
                        .fold(EF::zero(), |out, (&a, &b)| out + b * a)
                })
                .collect();
            let r = loop {
                let r = child.get_challenge(b"extension tuple reciprocal challenge");
                if r != EF::zero() && !table.iter().any(|&t| r + t == EF::zero()) {
                    break r;
                }
            };
            let denominators: Vec<_> = table.iter().map(|&t| r + t).collect();
            let inverses = table_reciprocals::<F, EF>(&denominators);
            Challenge { powers, r, inverses }
        })
        .collect()
}
fn table_sum<F: Field, EF: AbstractExtensionField<F>>(
    c: &Challenge<EF>,
    multiplicities: &[F],
) -> EF {
    c.inverses
        .iter()
        .zip(multiplicities)
        .fold(EF::zero(), |sum, (&inverse, &m)| {
            sum + inverse * m
        })
}

// Montgomery's trick. Challenges exclude zero denominators before this call.
// Keep order and reuse the same values in helper construction and table sums.
fn batch_reciprocals<EF: Field>(values: &[EF]) -> Vec<EF> {
    if values.is_empty() {
        return vec![];
    }
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = EF::one();
    for &value in values {
        assert!(value != EF::zero(), "zero reciprocal denominator");
        prefixes.push(product);
        product *= value;
    }
    let mut inverse = EF::one() / product;
    let mut out = vec![EF::zero(); values.len()];
    for i in (0..values.len()).rev() {
        out[i] = inverse * prefixes[i];
        inverse *= values[i];
    }
    out
}

fn table_reciprocals<F: PrimeField, EF: AbstractExtensionField<F>>(values: &[EF]) -> Vec<EF> {
    // BabyBear arithmetic has canonical serialized representatives. Goldilocks
    // allows lazy representatives: batching changes bytes even for [1,-1].
    // Keep its individual inverse encoding, but compute the table only once.
    if std::any::TypeId::of::<F>() == std::any::TypeId::of::<algebra::BabyBear>() {
        batch_reciprocals(values)
    } else {
        values.iter().map(|&value| EF::one() / value).collect()
    }
}
fn equality_table<EF: Field>(point: &[EF]) -> Vec<EF> {
    let mut out = vec![EF::one()];
    for &x in point {
        let len = out.len();
        out.resize(2 * len, EF::zero());
        for i in 0..len {
            let a = out[i];
            out[i] = a * (EF::one() - x);
            out[i + len] = a * x;
        }
    }
    out
}
fn equality<EF: Field>(a: &[EF], b: &[EF]) -> EF {
    a.iter().zip(b).fold(EF::one(), |out, (&x, &y)| {
        out * (x * y + (EF::one() - x) * (EF::one() - y))
    })
}
fn prefix<EF: Field>(point: &[EF], count: usize) -> EF {
    if count == 1usize << point.len() {
        return EF::one();
    }
    let mut same = EF::one();
    let mut out = EF::zero();
    for i in (0..point.len()).rev() {
        if count >> i & 1 == 1 {
            out += same * (EF::one() - point[i]);
            same *= point[i];
        } else {
            same *= EF::one() - point[i];
        }
    }
    out
}
fn identity_polynomial<EF: Field>(
    eq: &Rc<DenseMultilinearExtension<EF>>,
    h: &Rc<DenseMultilinearExtension<EF>>,
    g: &Rc<DenseMultilinearExtension<EF>>,
    mask: Option<&Rc<DenseMultilinearExtension<EF>>>,
    r: EF,
) -> ListOfProductsOfPolynomials<EF> {
    let mut p = ListOfProductsOfPolynomials::new(h.num_vars);
    if let Some(mask) = mask {
        p.add_product([eq.clone(), h.clone()], r);
        p.add_product([eq.clone(), mask.clone(), g.clone(), h.clone()], EF::one());
        p.add_product([eq.clone(), mask.clone()], -EF::one());
    } else {
        p.add_product_with_linear_op(
            [eq.clone(), h.clone(), g.clone()],
            &[
                (EF::one(), EF::zero()),
                (EF::one(), EF::zero()),
                (EF::one(), r),
            ],
            EF::one(),
        );
        p.add_product([eq.clone()], -EF::one());
    }
    p
}
fn check_terminal<F: Field, EF: AbstractExtensionField<F>>(
    logical_len: usize,
    c: &Challenge<EF>,
    eq_point: &[EF],
    point: &[EF],
    pulled: &bridge::Query<F>,
    sources: &[Vec<F>],
    h: EF,
    expected: EF,
    k: usize,
) -> Result<(), Error> {
    let mut g = EF::zero();
    for (v, &w) in sources.iter().zip(&c.powers) {
        g += w * bridge::element::<F, EF>(k, &pulled.apply(v, k).map_err(convert)?)
            .map_err(convert)?;
    }
    let mask = prefix(point, logical_len);
    let value = equality(eq_point, point) * (c.r * h + mask * g * h - mask);
    if value != expected {
        return Err(error("terminal reciprocal identity"));
    }
    Ok(())
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
    use num_traits::Zero;
    fn reciprocal_reference<F: PrimeField, EF: AbstractExtensionField<F> + Serialize>() {
        let mut trans = Transcript::<EF>::new_direct_extension::<F>();
        for len in [0, 1, 2, 17, 511] {
            let mut values = trans.get_vec_challenge(b"batch reciprocal reference", len);
            for value in &mut values {
                if *value == EF::zero() { *value = EF::one(); }
            }
            if len > 1 { values[0] = EF::one(); values[1] = -EF::one(); }
            let actual = table_reciprocals::<F, EF>(&values);
            let expected: Vec<_> = values.iter().map(|&v| EF::one() / v).collect();
            assert_eq!(batch_reciprocals(&values), expected);
            assert_eq!(actual, expected);
            assert_eq!(bincode::serde::encode_to_vec(&actual, bincode::config::standard()).unwrap(),
                       bincode::serde::encode_to_vec(&expected, bincode::config::standard()).unwrap());
            assert!(actual.iter().zip(&values).all(|(&a, &v)| a * v == EF::one()));
        }
    }
    #[test]
    fn batch_reciprocals_dispatch_preserves_individual_inverse_bytes() {
        reciprocal_reference::<algebra::BabyBear, algebra::BabyBearExtension5>();
        reciprocal_reference::<algebra::BabyBear, algebra::BabyBearExtension6>();
        reciprocal_reference::<algebra::BabyBear, algebra::BabyBearExtension8>();
        reciprocal_reference::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
        reciprocal_reference::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }
    #[test]
    #[should_panic(expected = "zero reciprocal denominator")]
    fn batch_reciprocals_reject_zero() {
        batch_reciprocals(&[algebra::BabyBearExtension6::zero()]);
    }
    use algebra::NTTField;
    use pcs::utils::code::BlockReedSolomonCode;
    use sha2::Sha256;
    fn forgery<F, EF>()
    where
        F: NTTField + Serialize,
        EF: AbstractExtensionField<F> + Serialize,
    {
        let (mu, k) = (2, 8);
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 32, 2).unwrap();
        let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(5, k, 32, 2).unwrap();
        let fake = PackedTable::new(mu, k, vec![F::zero(); 32]).unwrap();
        let config = Config::new(32, vec![vec![F::zero()], vec![F::from(2usize)]], 1).unwrap();
        for bad in [false, true] {
            let actual =
                PackedTable::new(mu, k, vec![if bad { F::one() } else { F::zero() }; 32]).unwrap();
            let (root, state) = pp.commit::<F, Sha256>(&actual).unwrap();
            let source = ProverOracle {
                parameters: &pp,
                commitment: &root,
                state: &state,
                table: &actual,
            };
            let mut prover = Transcript::new_direct();
            let proof = prove_impl::<F, EF, Sha256, _>(
                &mut prover,
                &config,
                &helper,
                &[&source],
                &[&fake],
                &mut ProverStatistics::default(),
                !bad,
            )
            .unwrap();
            // Independently replay every algebraic child and every genuine
            // canonical opening. Only the final public source equation is false.
            let mut replay = Transcript::new_direct();
            verify_impl::<F, EF, Sha256, _>(
                &mut replay,
                &config,
                &helper,
                &[source.verifier()],
                &proof,
                false,
            )
            .unwrap();
            assert_eq!(
                prover.get_challenge(b"after complete children"),
                replay.get_challenge(b"after complete children")
            );
            let result = verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &config,
                &helper,
                &[source.verifier()],
                &proof,
            );
            if bad {
                assert_eq!(result.unwrap_err().0, "terminal reciprocal identity");
            } else {
                result.unwrap();
            }
        }
    }
    #[test]
    fn babybear_genuine_children_with_false_source_fail() {
        forgery::<algebra::BabyBear, algebra::BabyBearExtension5>();
    }
    #[test]
    fn goldilocks_genuine_children_with_false_source_fail() {
        forgery::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }
    #[test]
    fn goldilocks_cubic_genuine_children_with_false_source_fail() {
        forgery::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
    #[test]
    fn babybear_degree8_false_source_genuine_children() {
        forgery::<algebra::BabyBear, algebra::BabyBearExtension8>();
    }

    #[test]
    fn babybear_degree6_false_source_genuine_children() {
        forgery::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }

}
