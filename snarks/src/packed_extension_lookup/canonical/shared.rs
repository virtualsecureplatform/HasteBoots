//! Multiple reciprocal lookups with one shared scalar point and canonical PCS.
//! Every sum and reciprocal identity remains an independent scalar equation.
//! Public algebra; independent per-root PCS packets are not joint aggregation.
use super::*;
/// Trusted ordered configuration and slots in a single canonical source context.
pub use crate::packed_extension_lookup::deferred::Request;
use crate::packed_extension_lookup::shared::{all_challenges, child_shared, equation_infos};
use crate::packed_opening_batch::{CanonicalOpeningBatch, CanonicalProof as Authentication};

/// Shared-query algebra, per-helper openings and grouped source authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, O, S, B> {
    /// Per-request multiplicities, fixed before compression challenges.
    pub multiplicities: Vec<Vec<F>>,
    /// One coefficient helper root per ordered request/repetition.
    pub helper_roots: Vec<Commitment<O>>,
    /// Separate sum/identity equations, interleaved per helper.
    pub algebra: sumcheck::batch::Proof<EF>,
    /// One common-query claim per original source registry slot.
    pub source_values: Vec<Vec<F>>,
    /// The same authenticated helper value is used in both equations.
    pub helper_values: Vec<EF>,
    /// Used source obligations, grouped only by canonical root/context.
    pub source_opening: Authentication<B>,
    /// One independently authenticated packet per coefficient helper.
    pub helper_openings: Vec<S>,
}
fn preflight<F, EF, H, P>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    requests: &[Request<F>],
) -> Result<(usize, usize, usize), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.is_empty()
        || requests.is_empty()
        || requests.iter().any(|r| {
            r.source_slots.len() != r.config.num_columns()
                || r.source_slots.iter().any(|&i| i >= sources.len())
        })
    {
        return Err(error("shared lookup registry/request dimensions"));
    }
    if sources.iter().any(|s| {
        s.parameters.num_vars() != sources[0].parameters.num_vars()
            || s.parameters.width() != sources[0].parameters.width()
    }) {
        return Err(error("shared lookup registry geometry"));
    }
    parent.append_message(b"canonical shared-query extension lookups v1", &requests);
    let mut geometry = None;
    let mut count = 0usize;
    for request in requests {
        let local: Vec<_> = request
            .source_slots
            .iter()
            .map(|&i| CanonicalVerifierOracle {
                parameters: sources[i].parameters,
                commitment: sources[i].commitment,
            })
            .collect();
        let current = bind::<F, EF, H, P>(parent, &request.config, helper, &local)?;
        if geometry.is_some_and(|g| g != current) {
            return Err(error("shared lookup geometry"));
        }
        geometry = Some(current);
        count = count
            .checked_add(request.config.repetitions())
            .ok_or_else(|| error("shared lookup repetitions overflow"))?;
    }
    let (n, k) = geometry.unwrap();
    Ok((n, k, count))
}
fn canonical_requests<F, H, P>(requests: &[Request<F>], pp: &P) -> Result<Vec<Request<F>>, Error>
where
    F: PrimeField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    requests
        .iter()
        .map(|r| {
            Ok(Request {
                config: canonical_config::<F, H, P>(&r.config, pp)?,
                source_slots: r.source_slots.clone(),
            })
        })
        .collect()
}
fn used_slots<F>(sources: usize, requests: &[Request<F>]) -> Vec<bool> {
    let mut used = vec![false; sources];
    for r in requests {
        for &slot in &r.source_slots {
            used[slot] = true;
        }
    }
    used
}
fn source_claims<F, H, P>(
    parent: &mut Transcript<F>,
    registry: &mut CanonicalOpeningBatch<'_, F, H, P>,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    used: &[bool],
    query: &[algebra::matrix_weighted::MatrixPair<F>],
    values: &[Vec<F>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let mut representatives: Vec<(usize, H::Output)> = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        if !used[i] {
            continue;
        }
        let context = source.parameters.context().map_err(convert)?;
        if let Some((j, _)) = representatives
            .iter()
            .find(|(j, c)| *c == context && sources[*j].commitment.root == source.commitment.root)
        {
            if values[*j] != values[i] {
                return Err(error("inconsistent shared source alias"));
            }
        } else {
            registry
                .push(parent, i, query.to_vec(), values[i].clone())
                .map_err(convert)?;
            representatives.push((i, context));
        }
    }
    Ok(())
}
/// Prove all trusted requests using canonical private source oracles.
/// Sources share logical dimensions; physical contexts may differ. Memory grows with
/// helper count; callers must choose bounded groups for native-sized workloads.
pub fn prove<F, EF, H, P, R>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    requests: &[Request<F>],
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_with_statistics::<F, EF, H, P, R>(
        parent,
        helper,
        sources,
        requests,
        &mut ProverStatistics::default(),
        rng,
    )
}
/// Prove with phase counters. Joint sum/identity algebra is counted in
/// `sumcheck`; `zero_check` is reserved for a separate ZeroCheck invocation.
pub fn prove_with_statistics<F, EF, H, P, R>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    requests: &[Request<F>],
    statistics: &mut ProverStatistics,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let witness: Vec<_> = sources.iter().map(|s| s.table()).collect();
    prove_inner::<F, EF, H, P, R, true>(
        parent, helper, sources, requests, &witness, statistics, rng,
    )
}
fn prove_inner<F, EF, H, P, R, const STRICT: bool>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
    requests: &[Request<F>],
    witness: &[&PackedTable<F>],
    statistics: &mut ProverStatistics,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    let timer = std::time::Instant::now();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let requests = canonical_requests::<F, H, P>(
        requests,
        sources
            .first()
            .ok_or_else(|| error("empty shared registry"))?
            .parameters,
    )?;
    let requests = &requests[..];
    let (n, k, count) = preflight::<F, EF, H, P>(parent, helper, &public, requests)?;
    let mut registry = CanonicalOpeningBatch::<F, H, P>::new(parent, &public).map_err(convert)?;
    let used = used_slots(sources.len(), requests);
    if witness.len() != sources.len() {
        return Err(error("shared lookup witness count"));
    }
    for (table, source) in witness.iter().zip(sources) {
        table.validate().map_err(convert)?;
        source.table().validate().map_err(convert)?;
        if table.num_vars() != source.parameters.num_vars()
            || table.width() != k
            || source.table().num_vars() != source.parameters.num_vars()
            || source.table().width() != k
        {
            return Err(error("shared lookup source witness shape"));
        }
    }
    let size = 1usize << n;
    let mut multiplicities = Vec::new();
    let mut indices = Vec::new();
    for request in requests {
        let index: HashMap<_, _> = request
            .config
            .table()
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, t)| (t, i))
            .collect();
        let mut counts = vec![F::zero(); request.config.table().len()];
        let mut rows = Vec::new();
        for row in 0..request.config.logical_len() {
            let tuple: Vec<_> = request
                .source_slots
                .iter()
                .map(|&i| witness[i].values()[row])
                .collect();
            let at = *index
                .get(&tuple)
                .ok_or_else(|| error("shared lookup tuple outside public table"))?;
            counts[at] += F::one();
            rows.push(at);
        }
        multiplicities.push(sources[0].parameters.normalize_values(counts));
        indices.push(rows);
    }
    let mut child = child_shared::<F, EF>(parent, &multiplicities);
    let challenges = all_challenges(&mut child, requests);
    let helpers: Vec<_> = challenges
        .iter()
        .map(|(i, c)| {
            let mut values = vec![EF::zero(); size];
            for (out, &at) in values.iter_mut().zip(&indices[*i]) {
                *out = c.inverses[at];
            }
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(n, values))
        })
        .collect();
    drop(indices);
    let helper_tables: Vec<_> = helpers
        .iter()
        .map(|h| bridge::table::<F, EF>(n, k, &h.evaluations).map_err(convert))
        .collect::<Result<_, _>>()?;
    statistics.preparation += timer.elapsed();
    let timer = std::time::Instant::now();
    let committed: Vec<_> = helper_tables
        .iter()
        .map(|t| helper.commit(t, rng).map_err(convert))
        .collect::<Result<_, _>>()?;
    drop(helper_tables);
    let helper_roots: Vec<_> = committed.iter().map(|(r, _)| r.clone()).collect();
    child.append_message(b"shared lookup helper roots", &helper_roots);
    statistics.commitment += timer.elapsed();
    let timer = std::time::Instant::now();
    let mut polys = Vec::with_capacity(2 * count);
    let mut sums = Vec::new();
    let mut eq_points = Vec::new();
    for ((i, c), h) in challenges.iter().zip(&helpers) {
        let config = &requests[*i].config;
        let eq_point = child.get_vec_challenge(b"shared lookup equality point", n);
        let eq = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            n,
            equality_table(&eq_point),
        ));
        let mut g = vec![EF::zero(); size];
        for (&slot, &power) in requests[*i].source_slots.iter().zip(&c.powers) {
            for (out, &v) in g.iter_mut().zip(witness[slot].values()) {
                *out += power * v;
            }
        }
        let g = Rc::new(DenseMultilinearExtension::from_evaluations_vec(n, g));
        let mask = (config.logical_len() != size).then(|| {
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
        let mut sum = ListOfProductsOfPolynomials::new(n);
        sum.add_product([h.clone()], EF::one());
        polys.push(sum);
        polys.push(identity_polynomial(&eq, h, &g, mask.as_ref(), c.r));
        sums.push(table_sum::<F, EF>(c, &multiplicities[*i]));
        sums.push(EF::zero());
        eq_points.push(eq_point);
    }
    let refs: Vec<_> = polys.iter().collect();
    statistics.preparation += timer.elapsed();
    let timer = std::time::Instant::now();
    let (algebra, states) = sumcheck::batch::prove(&mut child, &refs, &sums).map_err(convert)?;
    statistics.sumcheck += timer.elapsed();
    let timer = std::time::Instant::now();
    // Only folded terminal states are needed after the algebra completes.
    drop(refs);
    drop(polys);
    drop(helpers);
    let point = &states[0].randomness;
    let pulled = bridge::scalar_query::<F, EF>(sources[0].parameters.num_vars(), k, point)
        .map_err(convert)?;
    let source_values: Vec<_> = sources
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if used[i] {
                s.table()
                    .evaluate(&pulled.query)
                    .map(|v| s.parameters.normalize_values(v))
                    .map_err(convert)
            } else {
                Ok(vec![F::zero(); k])
            }
        })
        .collect::<Result<_, _>>()?;
    let helper_values: Vec<_> = (0..count)
        .map(|i| states[2 * i].fast_evaluate()[0].canonicalized())
        .collect();
    // Verify both scalar obligations locally using the very same helper value.
    for (i, (request, c)) in challenges.iter().enumerate() {
        let terminals = states[2 * i + 1].fast_evaluate();
        let p = &states[2 * i + 1];
        let expected = p.list_of_products.iter().zip(&p.linear_ops).fold(
            EF::zero(),
            |out, ((coefficient, factors), ops)| {
                out + factors
                    .iter()
                    .zip(ops)
                    .fold(*coefficient, |v, (&j, &(a, b))| v * (a * terminals[j] + b))
            },
        );
        let values: Vec<_> = requests[*request]
            .source_slots
            .iter()
            .map(|&slot| source_values[slot].clone())
            .collect();
        if STRICT {
            check_terminal::<F, EF>(
                requests[*request].config.logical_len(),
                c,
                &eq_points[i],
                point,
                &pulled,
                &values,
                helper_values[i],
                expected,
                k,
            )?;
        }
    }
    child.append_message(
        b"shared lookup terminal values",
        &(&source_values, &helper_values),
    );
    finish_child(parent, &mut child);
    statistics.terminal_evaluation += timer.elapsed();
    let timer = std::time::Instant::now();
    let helper_query = bridge::coefficients_query::<F, EF>(k, point).map_err(convert)?;
    let helper_claims: Vec<_> = helper_values
        .iter()
        .map(|&v| bridge::vector::<F, EF>(k, v).map_err(convert))
        .collect::<Result<_, _>>()?;
    let helper_openings = committed
        .iter()
        .zip(&helper_claims)
        .map(|((root, state), value)| {
            let value = helper.normalize_values(value.clone());
            helper
                .open(parent, root, state, &helper_query.query, &value)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    source_claims::<F, H, P>(
        parent,
        &mut registry,
        &public,
        &used,
        &pulled.query,
        &source_values,
    )?;
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    let source_opening = registry.prove(parent, &states).map_err(convert)?;
    statistics.openings += timer.elapsed();
    Ok(Proof {
        multiplicities,
        helper_roots,
        algebra,
        source_values,
        helper_values,
        source_opening,
        helper_openings,
    })
}
/// Verify all sum/identity equations and authenticate their shared terminals.
pub fn verify<F, EF, H, P>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, true>(parent, helper, sources, requests, proof)
}
fn verify_inner<F, EF, H, P, const STRICT: bool>(
    parent: &mut Transcript<F>,
    helper: &P,
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let requests = canonical_requests::<F, H, P>(
        requests,
        sources
            .first()
            .ok_or_else(|| error("empty shared registry"))?
            .parameters,
    )?;
    let requests = &requests[..];
    let (n, k, count) = preflight::<F, EF, H, P>(parent, helper, sources, requests)?;
    let mut registry = CanonicalOpeningBatch::<F, H, P>::new(parent, sources).map_err(convert)?;
    let used = used_slots(sources.len(), requests);
    if proof.helper_openings.len() != count {
        return Err(error("shared helper opening count"));
    }
    if proof.multiplicities.len() != requests.len()
        || proof
            .multiplicities
            .iter()
            .zip(requests)
            .any(|(m, r)| m.len() != r.config.table().len())
        || proof.helper_roots.len() != count
        || proof.helper_values.len() != count
        || proof.source_values.len() != sources.len()
        || proof.source_values.iter().any(|v| v.len() != k)
    {
        return Err(error("shared lookup proof dimensions"));
    }
    for m in &proof.multiplicities {
        sources[0].parameters.validate_values(m).map_err(convert)?;
    }
    for (i, (source, value)) in sources.iter().zip(&proof.source_values).enumerate() {
        source.parameters.validate_values(value).map_err(convert)?;
        if !used[i] && value.iter().any(|&x| x != F::zero()) {
            return Err(error("unused shared source value"));
        }
    }
    if proof.helper_values.iter().any(|v| !v.is_canonical()) {
        return Err(error("noncanonical shared helper scalar"));
    }
    let mut child = child_shared::<F, EF>(parent, &proof.multiplicities);
    let challenges = all_challenges(&mut child, requests);
    child.append_message(b"shared lookup helper roots", &proof.helper_roots);
    let mut eq_points = Vec::new();
    let mut sums = Vec::new();
    for (i, c) in &challenges {
        eq_points.push(child.get_vec_challenge(b"shared lookup equality point", n));
        sums.push(table_sum::<F, EF>(c, &proof.multiplicities[*i]));
        sums.push(EF::zero());
    }
    let claims = sumcheck::batch::verify(
        &mut child,
        &equation_infos(requests, n),
        &sums,
        &proof.algebra,
    )
    .map_err(convert)?;
    let point = &claims[0].point;
    let pulled = bridge::scalar_query::<F, EF>(sources[0].parameters.num_vars(), k, point)
        .map_err(convert)?;
    for (i, (request, c)) in challenges.iter().enumerate() {
        if claims[2 * i].expected_evaluations != proof.helper_values[i] {
            return Err(error("shared lookup sum/helper terminal mismatch"));
        }
        let values: Vec<_> = requests[*request]
            .source_slots
            .iter()
            .map(|&slot| proof.source_values[slot].clone())
            .collect();
        if STRICT {
            check_terminal::<F, EF>(
                requests[*request].config.logical_len(),
                c,
                &eq_points[i],
                point,
                &pulled,
                &values,
                proof.helper_values[i],
                claims[2 * i + 1].expected_evaluations,
                k,
            )?;
        }
    }
    child.append_message(
        b"shared lookup terminal values",
        &(&proof.source_values, &proof.helper_values),
    );
    finish_child(parent, &mut child);
    let helper_query = bridge::coefficients_query::<F, EF>(k, point).map_err(convert)?;
    let helper_claims: Vec<_> = proof
        .helper_values
        .iter()
        .map(|&v| bridge::vector::<F, EF>(k, v).map_err(convert))
        .collect::<Result<_, _>>()?;
    for ((root, value), opening) in proof
        .helper_roots
        .iter()
        .zip(&helper_claims)
        .zip(&proof.helper_openings)
    {
        let value = helper.normalize_values(value.clone());
        helper
            .verify(parent, root, &helper_query.query, &value, opening)
            .map_err(convert)?;
    }
    source_claims::<F, H, P>(
        parent,
        &mut registry,
        sources,
        &used,
        &pulled.query,
        &proof.source_values,
    )?;
    registry
        .verify(parent, &proof.source_opening)
        .map_err(convert)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod audit;
