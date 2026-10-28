//! Multiple reciprocal lookups with one shared scalar point and canonical PCS.
//! Every sum and reciprocal identity remains an independent scalar equation.
//! Experimental, non-hiding, and not yet a complete PBS wire protocol.
/// Trusted ordered configuration and slots in a single canonical source context.
pub use super::deferred::Request;
use super::*;
use pcs::matrix_weighted::aggregate::canonical as authentication;

/// Shared-query lookup algebra and two canonical authentication packets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, O> {
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
    /// All source obligations, deduplicated only by canonical root/context.
    pub source_opening: authentication::Proof<F, EF, O>,
    /// All coefficient helpers at the common helper query.
    pub helper_opening: authentication::Proof<F, EF, O>,
}
fn preflight<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    requests: &[Request<F>],
) -> Result<(usize, usize, usize), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
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
    let context = sources[0]
        .parameters
        .context_digest::<F, H>()
        .map_err(convert)?;
    for source in sources {
        if source
            .parameters
            .context_digest::<F, H>()
            .map_err(convert)?
            != context
        {
            return Err(error("shared lookup source contexts differ"));
        }
    }
    parent.append_message(b"shared-query extension lookups v1", &requests);
    let mut geometry = None;
    let mut count = 0usize;
    for request in requests {
        let local: Vec<_> = request
            .source_slots
            .iter()
            .map(|&i| VerifierOracle {
                parameters: sources[i].parameters,
                commitment: sources[i].commitment,
            })
            .collect();
        let current = super::bind::<F, EF, H, C>(parent, &request.config, helper, &local)?;
        if geometry.is_some_and(|g| g != current) {
            return Err(error("shared lookup geometry"));
        }
        geometry = Some(current);
        count = count
            .checked_add(request.config.repetitions())
            .ok_or_else(|| error("shared lookup repetitions overflow"))?;
    }
    // Bind even unused registry slots before any child/PCS challenge.
    parent.append_message(
        b"shared lookup complete source registry",
        &(
            context,
            sources.iter().map(|s| s.commitment).collect::<Vec<_>>(),
        ),
    );
    let (n, k) = geometry.unwrap();
    Ok((n, k, count))
}
pub(super) fn child_shared<F: PrimeField + Serialize, EF: AbstractExtensionField<F>>(
    parent: &mut Transcript<F>,
    multiplicities: &[Vec<F>],
) -> Transcript<EF> {
    parent.append_message(b"shared lookup grouped multiplicities", &multiplicities);
    let flat: Vec<_> = multiplicities.iter().flatten().copied().collect();
    super::child(parent, &flat)
}
pub(super) fn all_challenges<F: PrimeField, EF: AbstractExtensionField<F> + Serialize>(
    child: &mut Transcript<EF>,
    requests: &[Request<F>],
) -> Vec<(usize, Challenge<EF>)> {
    requests
        .iter()
        .enumerate()
        .flat_map(|(i, request)| {
            child.append_message(b"shared lookup challenge request", &i);
            super::challenges(child, &request.config)
                .into_iter()
                .map(move |c| (i, c))
        })
        .collect()
}
pub(super) fn equation_infos<F: PrimeField>(requests: &[Request<F>], n: usize) -> Vec<PolynomialInfo> {
    requests
        .iter()
        .flat_map(|r| {
            (0..r.config.repetitions()).flat_map(move |_| {
                [
                    PolynomialInfo {
                        num_variables: n,
                        max_multiplicands: 1,
                    },
                    PolynomialInfo {
                        num_variables: n,
                        max_multiplicands: if r.config.logical_len() == 1usize << n {
                            3
                        } else {
                            4
                        },
                    },
                ]
            })
        })
        .collect()
}
/// Prove all trusted requests using canonical private source oracles.
/// Sources must share their complete PCS parameter context. Memory grows with
/// helper count; callers must choose bounded groups for native-sized workloads.
pub fn prove<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    requests: &[Request<F>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_with_statistics::<F, EF, H, C>(
        parent,
        helper,
        sources,
        requests,
        &mut ProverStatistics::default(),
    )
}
/// Prove with phase counters. Joint sum/identity algebra is counted in
/// `sumcheck`; `zero_check` is reserved for a separate ZeroCheck invocation.
pub fn prove_with_statistics<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    requests: &[Request<F>],
    statistics: &mut ProverStatistics,
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let witness: Vec<_> = sources.iter().map(|s| s.table).collect();
    prove_inner::<F, EF, H, C>(
        parent, helper, sources, requests, &witness, true, statistics,
    )
}
fn prove_inner<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    requests: &[Request<F>],
    witness: &[&PackedTable<F>],
    strict: bool,
    statistics: &mut ProverStatistics,
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let timer = std::time::Instant::now();
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let (n, k, count) = preflight::<F, EF, H, C>(parent, helper, &public, requests)?;
    if witness.len() != sources.len() {
        return Err(error("shared lookup witness count"));
    }
    for (table, source) in witness.iter().zip(sources) {
        table.validate().map_err(convert)?;
        source.table.validate().map_err(convert)?;
        if table.num_vars() != source.parameters.num_vars()
            || table.width() != k
            || source.table.num_vars() != source.parameters.num_vars()
            || source.table.width() != k
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
        multiplicities.push(counts);
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
        .map(|t| helper.commit::<F, H>(t).map_err(convert))
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
        .map(|s| s.table.evaluate(&pulled.query).map_err(convert))
        .collect::<Result<_, _>>()?;
    let helper_values: Vec<_> = (0..count)
        .map(|i| states[2 * i].fast_evaluate()[0])
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
        if strict {
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
    let helper_states: Vec<_> = committed.iter().map(|(_, s)| s).collect();
    let helper_opening = authentication::prove::<F, EF, H, C>(
        helper,
        parent,
        &helper_roots,
        &helper_states,
        &helper_query.query,
        &helper_claims,
    )
    .map_err(convert)?;
    let roots: Vec<_> = sources.iter().map(|s| s.commitment.clone()).collect();
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    let source_opening = authentication::prove::<F, EF, H, C>(
        sources[0].parameters,
        parent,
        &roots,
        &states,
        &pulled.query,
        &source_values,
    )
    .map_err(convert)?;
    statistics.openings += timer.elapsed();
    Ok(Proof {
        multiplicities,
        helper_roots,
        algebra,
        source_values,
        helper_values,
        source_opening,
        helper_opening,
    })
}
/// Verify all sum/identity equations and authenticate their shared terminals.
pub fn verify<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_inner::<F, EF, H, C>(parent, helper, sources, requests, proof, true)
}
fn verify_inner<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output>,
    strict: bool,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let (n, k, count) = preflight::<F, EF, H, C>(parent, helper, sources, requests)?;
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
        if strict {
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
    authentication::verify::<F, EF, H, C>(
        helper,
        parent,
        &proof.helper_roots,
        &helper_query.query,
        &helper_claims,
        &proof.helper_opening,
    )
    .map_err(convert)?;
    let roots: Vec<_> = sources.iter().map(|s| s.commitment.clone()).collect();
    authentication::verify::<F, EF, H, C>(
        sources[0].parameters,
        parent,
        &roots,
        &pulled.query,
        &proof.source_values,
        &proof.source_opening,
    )
    .map_err(convert)
}

// Test-only malicious-prover/reference adapters; production entry points always
// enforce the terminal source identity.
#[cfg(test)]
pub(crate) fn prove_foreign_for_audit<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    requests: &[Request<F>],
    witness: &[&PackedTable<F>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_inner::<F, EF, H, C>(
        parent,
        helper,
        sources,
        requests,
        witness,
        false,
        &mut ProverStatistics::default(),
    )
}
#[cfg(test)]
pub(crate) fn verify_reference_for_audit<F, EF, H, C>(
    parent: &mut Transcript<F>,
    helper: &Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    requests: &[Request<F>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_inner::<F, EF, H, C>(parent, helper, sources, requests, proof, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::NTTField;
    use pcs::utils::code::BlockReedSolomonCode;
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    fn foreign<F, EF>(k: usize)
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        let mu = k.ilog2() as usize + 1;
        let n = mu + k.ilog2() as usize;
        let size = (1 << mu) * k;
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu, k, 32, 2).unwrap();
        let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, k, 32, 2).unwrap();
        let fake: Vec<_> = (0..2)
            .map(|_| PackedTable::new(mu, k, vec![F::one(); size]).unwrap())
            .collect();
        let requests: Vec<_> = (0..2)
            .map(|i| Request {
                config: Config::new(size - 3 * i, (0..4).map(|v| vec![F::from(v)]).collect(), 1)
                    .unwrap(),
                source_slots: vec![i],
            })
            .collect();
        for bad_slot in [None, Some(0), Some(1)] {
            let tables: Vec<_> = (0..2)
                .map(|i| {
                    PackedTable::new(
                        mu,
                        k,
                        vec![
                            if bad_slot == Some(i) {
                                F::from(9usize)
                            } else {
                                F::one()
                            };
                            size
                        ],
                    )
                    .unwrap()
                })
                .collect();
            let committed: Vec<_> = tables
                .iter()
                .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                .collect();
            let oracles: Vec<_> = (0..2)
                .map(|i| ProverOracle {
                    parameters: &pp,
                    commitment: &committed[i].0,
                    state: &committed[i].1,
                    table: &tables[i],
                })
                .collect();
            let refs: Vec<_> = oracles.iter().collect();
            let public: Vec<_> = oracles.iter().map(|o| o.verifier()).collect();
            let mut prover = Transcript::new_direct();
            // All helper algebra uses valid foreign values while the final PCS
            // packet proves the actual committed source values (including 9).
            let proof = prove_inner::<F, EF, Sha256, _>(
                &mut prover,
                &helper,
                &refs,
                &requests,
                &fake.iter().collect::<Vec<_>>(),
                false,
                &mut ProverStatistics::default(),
            )
            .unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<F, EF, [u8; 32]>, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut reference = Transcript::new_direct();
            verify_inner::<F, EF, Sha256, _>(
                &mut reference,
                &helper,
                &public,
                &requests,
                &proof,
                false,
            )
            .unwrap();
            assert_eq!(
                prover.get_challenge(b"after shared foreign roots"),
                reference.get_challenge(b"after shared foreign roots")
            );
            let result = verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &helper,
                &public,
                &requests,
                &proof,
            );
            let production_accepted = result.is_ok();
            if bad_slot.is_none() {
                result.unwrap();
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("terminal reciprocal identity")
                );
                assert!(
                    prove::<F, EF, Sha256, _>(
                        &mut Transcript::new_direct(),
                        &helper,
                        &refs,
                        &requests
                    )
                    .is_err()
                );
            }
            let slot = bad_slot
                .map(|i| i.to_string())
                .unwrap_or_else(|| "null".into());
            eprintln!(
                "HB_SHARED_LOOKUP_BINDING_CASE {{\"kind\":\"shared-query-extension-lookup\",\"prime\":{},\"requests\":2,\"malicious_slot\":{slot},\"reference_scope\":\"fresh-helper-algebra-and-actual-root-authentication\",\"production_accepted\":{production_accepted}}}",
                F::MODULUS_VALUE
            );
        }
    }
    #[test]
    fn babybear_shared_foreign_sources_reject() {
        foreign::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
    }
    #[test]
    fn goldilocks_shared_foreign_sources_reject() {
        foreign::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
    }
}
