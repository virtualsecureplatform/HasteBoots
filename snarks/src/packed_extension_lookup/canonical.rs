//! Extension-field lookup algebra with canonical backend authentication.
//! Original sources and coefficient-packed reciprocal helpers retain their roots.
use super::*;
use crate::packed_oracle::{CanonicalProverOracle, CanonicalVerifierOracle};
use pcs::matrix_weighted::backend::CanonicalPcs;
use rand::{CryptoRng, Rng};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group<F: Field, EF: Field, B> {
    pub sum_claim: EF,
    pub sum: SumProof<EF>,
    pub zero: SumProof<EF>,
    pub source_values: Vec<Vec<F>>,
    pub reciprocal_value: EF,
    pub reciprocal_opening: B,
}
impl<F: Field, EF: Field, B> Group<F, EF, B> {
    fn with_opening<Q>(self, q: Q) -> Group<F, EF, Q> {
        Group {
            sum_claim: self.sum_claim,
            sum: self.sum,
            zero: self.zero,
            source_values: self.source_values,
            reciprocal_value: self.reciprocal_value,
            reciprocal_opening: q,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, O, B> {
    pub multiplicities: Vec<F>,
    pub reciprocal_commitments: Vec<Commitment<O>>,
    pub groups: Vec<Group<F, EF, B>>,
    pub source_openings: Vec<B>,
}
fn canonical_config<F, H, P>(config: &Config<F>, pp: &P) -> Result<Config<F>, Error>
where
    F: PrimeField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    Config::new(
        config.logical_len(),
        config
            .table()
            .iter()
            .map(|v| pp.normalize_values(v.clone()))
            .collect(),
        config.repetitions(),
    )
    .map_err(convert)
}
/// Prove membership using actual retained sources and private helper randomness.
pub fn prove<F, EF, H, P, R>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_with_statistics::<F, EF, H, P, R>(
        parent,
        config,
        helper,
        sources,
        &mut crate::packed_extension_lookup::ProverStatistics::default(),
        rng,
    )
}
/// Prove with lookup phase counters; counters never enter the transcript.
pub fn prove_with_statistics<F, EF, H, P, R>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    statistics: &mut crate::packed_extension_lookup::ProverStatistics,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let witness: Vec<_> = sources.iter().map(|s| s.table()).collect();
    prove_inner::<F, EF, H, P, R, true>(parent, config, helper, sources, &witness, statistics, rng)
}
fn prove_inner<F, EF, H, P, R, const STRICT: bool>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    witness: &[&PackedTable<F>],
    statistics: &mut ProverStatistics,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let timer = std::time::Instant::now();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let config = canonical_config::<F, H, P>(
        config,
        sources
            .first()
            .ok_or_else(|| error("source column count"))?
            .parameters,
    )?;
    let config = &config;
    let (n, k) = bind::<F, EF, H, P>(parent, config, helper, &public)?;
    if witness.len() != sources.len() {
        return Err(error("source witness count"));
    }
    for (table, source) in witness.iter().zip(sources) {
        table.validate().map_err(convert)?;
        source.table().validate().map_err(convert)?;
        if table.width() != k
            || table.num_vars() != source.parameters.num_vars()
            || source.table().width() != k
            || source.table().num_vars() != table.num_vars()
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
    let multiplicities = sources[0].parameters.normalize_values(multiplicities);
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
        .map(|v| bridge::table::<F, EF>(n, helper.width(), v).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    statistics.preparation += timer.elapsed();
    let timer = std::time::Instant::now();
    let (reciprocal_commitments, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| helper.commit(t, rng).map_err(convert))
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
        let sum_claim = h
            .evaluations
            .iter()
            .copied()
            .fold(EF::zero(), |a, b| a + b)
            .canonicalized();
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
        let reciprocal_value =
            terminals[zero_poly.raw_pointers_lookup_table[&Rc::as_ptr(&h)]].canonicalized();
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
            .map(|s| {
                s.table()
                    .evaluate(&pulled.query)
                    .map(|v| s.parameters.normalize_values(v))
                    .map_err(convert)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if STRICT {
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
            reciprocal_opening: (),
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
    let mut completed = Vec::with_capacity(groups.len());
    for (i, (group, a)) in groups.into_iter().zip(&algebra).enumerate() {
        let q0 =
            bridge::coefficients_query::<F, EF>(helper.width(), &a.sum_point).map_err(convert)?;
        let q1 =
            bridge::coefficients_query::<F, EF>(helper.width(), &a.zero_point).map_err(convert)?;
        let opening = helper
            .open_many(
                parent,
                &reciprocal_commitments[i],
                &states[i],
                &[q0.query, q1.query],
                &[
                    bridge::vector::<F, EF>(helper.width(), a.sum_value).map_err(convert)?,
                    bridge::vector::<F, EF>(helper.width(), group.reciprocal_value)
                        .map_err(convert)?,
                ],
            )
            .map_err(convert)?;
        completed.push(group.with_opening(opening));
    }
    let groups = completed;
    let source_openings = sources
        .iter()
        .enumerate()
        .map(|(j, s)| {
            s.parameters
                .open_many(
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
        .collect::<Result<Vec<_>, _>>()?;
    statistics.openings += timer.elapsed();
    Ok(Proof {
        multiplicities,
        reciprocal_commitments,
        groups,
        source_openings,
    })
}
/// Verify extension algebra and authenticate original sources and helpers.
pub fn verify<F, EF, H, P>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, EF, H::Output, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, true>(parent, config, helper, sources, proof)
}
fn verify_inner<F, EF, H, P, const STRICT: bool>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &Proof<F, EF, H::Output, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let config = canonical_config::<F, H, P>(
        config,
        sources
            .first()
            .ok_or_else(|| error("source column count"))?
            .parameters,
    )?;
    let config = &config;
    let (n, k) = bind::<F, EF, H, P>(parent, config, helper, sources)?;
    let count = config.repetitions();
    if proof.multiplicities.len() != config.table().len()
        || proof.groups.len() != count
        || proof.reciprocal_commitments.len() != count
        || (proof.source_openings.len() != sources.len())
        || proof.groups.iter().any(|g| {
            g.source_values.len() != sources.len() || g.source_values.iter().any(|v| v.len() != k)
        })
    {
        return Err(error("proof counts or source value dimensions"));
    }
    sources[0]
        .parameters
        .validate_values(&proof.multiplicities)
        .map_err(convert)?;
    for group in &proof.groups {
        if !group.sum_claim.is_canonical() || !group.reciprocal_value.is_canonical() {
            return Err(error("noncanonical lookup scalar"));
        }
        for (source, values) in sources.iter().zip(&group.source_values) {
            source.parameters.validate_values(values).map_err(convert)?;
        }
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
        if STRICT {
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
        let q0 =
            bridge::coefficients_query::<F, EF>(helper.width(), &a.sum_point).map_err(convert)?;
        let q1 =
            bridge::coefficients_query::<F, EF>(helper.width(), &a.zero_point).map_err(convert)?;
        helper
            .verify_many(
                parent,
                &proof.reciprocal_commitments[i],
                &[q0.query, q1.query],
                &[
                    bridge::vector::<F, EF>(helper.width(), a.sum_value).map_err(convert)?,
                    bridge::vector::<F, EF>(helper.width(), group.reciprocal_value)
                        .map_err(convert)?,
                ],
                &group.reciprocal_opening,
            )
            .map_err(convert)?;
    }
    for (j, (source, opening)) in sources.iter().zip(&proof.source_openings).enumerate() {
        source
            .parameters
            .verify_many(
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
    Ok(())
}
fn bind<F, EF, H, P>(
    parent: &mut Transcript<F>,
    config: &Config<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
) -> Result<(usize, usize), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
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
        || (helper.width() != k && helper.width() != EF::D)
        || config.logical_len() > capacity
        || sources
            .iter()
            .any(|s| s.parameters.num_vars() != pp.num_vars() || s.parameters.width() != k)
    {
        return Err(error("incompatible source/helper geometry"));
    }
    let contexts = sources
        .iter()
        .map(|s| Ok((s.parameters.context().map_err(convert)?, s.commitment)))
        .collect::<Result<Vec<_>, Error>>()?;
    parent.append_message(
        b"packed canonical backend extension tuple lookup v1",
        &(config, EF::D, helper.context().map_err(convert)?, contexts),
    );
    Ok((n, k))
}

#[cfg(test)]
mod tests;

/// Shared scalar challenges with canonical source sessions.
pub mod shared;

#[cfg(test)]
pub(crate) mod audit;
