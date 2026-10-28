//! Independent canonical decompositions with bounded shared-query comparisons.
//! Every reconstruction/end-point equation is checked before joint lookups.
//! Experimental and non-hiding; not yet a complete cross-statement PBS format.
use super::*;
use crate::packed_extension_lookup::shared as lookup;
use algebra::{AbstractExtensionField, Field};
use pcs::matrix_weighted::State;

/// Trusted grouping rule, derived identically by prover and verifier.
pub const MAX_GROUP: usize = 4;
/// Member reconstruction/endpoints; comparisons are mandatory in the outer proof.
pub type MemberProof<F, O> = super::Proof<F, O, ()>;
/// One complete certificate for an ordered list of decompositions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: Field, EF: Field, O> {
    /// One independently checked reconstruction and endpoint certificate per member.
    pub members: Vec<MemberProof<F, O>>,
    /// Exactly ceil(member_count/MAX_GROUP) shared comparison packets.
    pub comparisons: Vec<lookup::Proof<F, EF, O>>,
}
pub(crate) struct Batched;
impl<F, H, C> Backend<F, H, C> for Batched
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type Proof = ();
    const EXTENSION: bool = true;
    fn bind_domain(trans: &mut Transcript<F>) {
        trans.append_message(b"canonical decomposition batch member v1", &());
    }
    fn comparison_packets(_limbs: usize) -> usize {
        1
    }
    fn prove_comparisons(
        trans: &mut Transcript<F>,
        _requests: &[lookup::Request<F>],
        _helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        _statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        _registry: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Vec<()>, Error> {
        trans.append_message(b"decomposition batch comparison obligation", &());
        Ok(vec![()])
    }
    fn verify_comparisons(
        trans: &mut Transcript<F>,
        _requests: &[lookup::Request<F>],
        _helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        _registry: &[VerifierOracle<'_, H::Output, C>],
        proofs: &[()],
    ) -> Result<(), Error> {
        if proofs.len() != 1 {
            return Err(error("batch comparison obligation count"));
        }
        trans.append_message(b"decomposition batch comparison obligation", &());
        Ok(())
    }
    fn prove(
        _trans: &mut Transcript<F>,
        _config: &packed_tuple_lookup::Config<F>,
        _helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        _statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        _sources: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<(), Error> {
        Err(error("batch comparisons require an outer certificate"))
    }
    fn verify(
        _trans: &mut Transcript<F>,
        _config: &packed_tuple_lookup::Config<F>,
        _helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        _sources: &[VerifierOracle<'_, H::Output, C>],
        _proof: &(),
    ) -> Result<(), Error> {
        Err(error("batch comparisons require an outer certificate"))
    }
}
fn bind_batch<F, EF, H, C>(
    trans: &mut Transcript<F>,
    configs: &[Config],
    helper: &pcs::matrix_weighted::Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    digits: &[Vec<VerifierOracle<'_, H::Output, C>>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F>,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if configs.is_empty() || configs.len() != sources.len() || configs.len() != digits.len() {
        return Err(error("decomposition batch dimensions"));
    }
    let context = sources[0]
        .parameters
        .context_digest::<F, H>()
        .map_err(convert)?;
    for ((config, source), digits) in configs.iter().zip(sources).zip(digits) {
        if digits.len() != config.num_digits::<F>()? {
            return Err(error("decomposition batch digit count"));
        }
        for oracle in std::iter::once(source).chain(digits) {
            if oracle
                .parameters
                .context_digest::<F, H>()
                .map_err(convert)?
                != context
            {
                return Err(error("decomposition batch source contexts differ"));
            }
        }
    }
    let roots: Vec<_> = sources
        .iter()
        .zip(digits)
        .map(|(s, d)| {
            (
                s.commitment,
                d.iter().map(|d| d.commitment).collect::<Vec<_>>(),
            )
        })
        .collect();
    trans.append_message(
        b"canonical decomposition shared comparison batch v1",
        &(
            MAX_GROUP,
            EF::D,
            configs,
            context,
            helper.context_digest::<F, H>().map_err(convert)?,
            roots,
        ),
    );
    Ok(())
}
fn requests<F: PrimeField>(configs: &[Config]) -> Result<Vec<lookup::Request<F>>, Error> {
    let mut offset = 0;
    let mut all = Vec::new();
    for config in configs {
        let mut local = super::comparison_requests::<F>(config)?;
        for request in &mut local {
            for slot in &mut request.source_slots {
                *slot += offset;
            }
        }
        offset += 2 * config.num_digits::<F>()? + 1;
        all.extend(local);
    }
    Ok(all)
}
/// Prove independent decompositions and jointly authenticate each bounded group.
/// Private borrow states are moved to the group owner, never recommitted/cloned.
pub fn prove<F, EF, H, C>(
    trans: &mut Transcript<F>,
    configs: &[Config],
    helper: &pcs::matrix_weighted::Parameters<C>,
    sources: &[&ProverOracle<'_, F, H, C>],
    digits: &[Vec<&ProverOracle<'_, F, H, C>>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let public_digits: Vec<Vec<_>> = digits
        .iter()
        .map(|d| d.iter().map(|d| d.verifier()).collect())
        .collect();
    bind_batch::<F, EF, H, C>(trans, configs, helper, &public, &public_digits)?;
    let mut members = Vec::new();
    let mut comparisons = Vec::new();
    for start in (0..configs.len()).step_by(MAX_GROUP) {
        let end = (start + MAX_GROUP).min(configs.len());
        let mut borrows: Vec<Vec<State<F, H>>> = Vec::with_capacity(end - start);
        for i in start..end {
            trans.append_message(b"decomposition batch instance", &i);
            let mut retained = None;
            members.push(super::prove_retained::<F, H, C, Batched>(
                trans,
                &configs[i],
                sources[i],
                Some(helper),
                &digits[i],
                &mut crate::packed_lane_lookup::ProverStatistics::default(),
                Some(&mut retained),
            )?);
            borrows.push(retained.ok_or_else(|| error("missing retained comparison sources"))?);
        }
        let mut registry = Vec::new();
        for i in start..end {
            registry.extend(digits[i].iter().map(|d| ProverOracle {
                parameters: d.parameters,
                commitment: d.commitment,
                state: d.state,
                table: d.table,
            }));
            registry.extend(
                borrows[i - start]
                    .iter()
                    .zip(&members[i].borrow_commitments)
                    .map(|(state, commitment)| ProverOracle {
                        parameters: sources[i].parameters,
                        commitment,
                        state,
                        table: state.table(),
                    }),
            );
        }
        trans.append_message(b"decomposition comparison group", &(start, end));
        let local = requests::<F>(&configs[start..end])?;
        comparisons.push(
            lookup::prove::<F, EF, H, C>(
                trans,
                helper,
                &registry.iter().collect::<Vec<_>>(),
                &local,
            )
            .map_err(convert)?,
        );
    }
    Ok(Proof {
        members,
        comparisons,
    })
}
/// Verify every member and mandatory shared comparison group against trusted roots.
pub fn verify<F, EF, H, C>(
    trans: &mut Transcript<F>,
    configs: &[Config],
    helper: &pcs::matrix_weighted::Parameters<C>,
    sources: &[VerifierOracle<'_, H::Output, C>],
    digits: &[Vec<VerifierOracle<'_, H::Output, C>>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind_batch::<F, EF, H, C>(trans, configs, helper, sources, digits)?;
    if proof.members.len() != configs.len()
        || proof.comparisons.len() != configs.len().div_ceil(MAX_GROUP)
    {
        return Err(error("decomposition batch proof count"));
    }
    for (group, start) in (0..proof.members.len()).step_by(MAX_GROUP).enumerate() {
        let end = (start + MAX_GROUP).min(proof.members.len());
        for i in start..end {
            trans.append_message(b"decomposition batch instance", &i);
            super::verify_impl::<F, H, C, Batched>(
                trans,
                &configs[i],
                &sources[i],
                Some(helper),
                &digits[i],
                &proof.members[i],
            )?;
        }
        let mut registry = Vec::new();
        for i in start..end {
            registry.extend(digits[i].iter().map(|d| VerifierOracle {
                parameters: d.parameters,
                commitment: d.commitment,
            }));
            registry.extend(
                proof.members[i]
                    .borrow_commitments
                    .iter()
                    .map(|commitment| VerifierOracle {
                        parameters: sources[i].parameters,
                        commitment,
                    }),
            );
        }
        trans.append_message(b"decomposition comparison group", &(start, end));
        lookup::verify::<F, EF, H, C>(
            trans,
            helper,
            &registry,
            &requests::<F>(&configs[start..end])?,
            &proof.comparisons[group],
        )
        .map_err(convert)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::NTTField;
    use pcs::utils::code::BlockReedSolomonCode;
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    fn forged<F, EF>(k: usize)
    where
        F: NTTField + Serialize + DeserializeOwned,
        EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        let mu = k.ilog2() as usize + 1;
        let size = (1 << mu) * k;
        let pp = pcs::matrix_weighted::Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
            mu, k, 32, 2,
        )
        .unwrap();
        let helper =
            pcs::matrix_weighted::Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                mu + k.ilog2() as usize,
                k,
                32,
                2,
            )
            .unwrap();
        let config = Config::new::<F>(8, size, 1).unwrap();
        let configs = vec![config.clone(), config.clone()];
        let d = config.num_digits::<F>().unwrap();
        let zero = PackedTable::new(mu, k, vec![F::zero(); size]).unwrap();
        let (borrow_root, borrow_state) = pp.commit::<F, Sha256>(&zero).unwrap();
        let borrow = ProverOracle {
            parameters: &pp,
            commitment: &borrow_root,
            state: &borrow_state,
            table: borrow_state.table(),
        };
        for bad_member in [None, Some(0), Some(1)] {
            let tables: Vec<Vec<_>> = (0..2)
                .map(|i| {
                    (0..d + 1)
                        .map(|j| {
                            PackedTable::new(
                                mu,
                                k,
                                vec![
                                    if bad_member == Some(i) && j < 2 {
                                        F::from(256usize)
                                    } else {
                                        F::zero()
                                    };
                                    size
                                ],
                            )
                            .unwrap()
                        })
                        .collect()
                })
                .collect();
            let committed: Vec<Vec<_>> = tables
                .iter()
                .map(|t| {
                    t.iter()
                        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                        .collect()
                })
                .collect();
            let oracles: Vec<Vec<_>> = tables
                .iter()
                .zip(&committed)
                .map(|(tables, c)| {
                    tables
                        .iter()
                        .zip(c)
                        .map(|(table, (commitment, state))| ProverOracle {
                            parameters: &pp,
                            commitment,
                            state,
                            table,
                        })
                        .collect()
                })
                .collect();
            let sources: Vec<_> = oracles.iter().map(|o| &o[0]).collect();
            let digits: Vec<Vec<_>> = oracles.iter().map(|o| o[1..].iter().collect()).collect();
            let public: Vec<_> = sources.iter().map(|o| o.verifier()).collect();
            let pd: Vec<Vec<_>> = digits
                .iter()
                .map(|d| d.iter().map(|o| o.verifier()).collect())
                .collect();
            let mut prover = Transcript::new_direct();
            bind_batch::<F, EF, Sha256, _>(&mut prover, &configs, &helper, &public, &pd).unwrap();
            let mut members = Vec::new();
            for i in 0..2 {
                prover.append_message(b"decomposition batch instance", &i);
                prover.append_message(b"canonical decomposition batch member v1", &());
                super::super::bind::<F, Sha256, _>(&mut prover, &config, &public[i], &pd[i])
                    .unwrap();
                super::super::bind_helper::<F, Sha256, _>(&mut prover, Some(&helper), &pp).unwrap();
                let borrow_commitments = vec![borrow_root.clone(); d + 1];
                prover.append_message(b"packed decomposition borrow roots", &borrow_commitments);
                let mut registry = vec![sources[i]];
                registry.extend(digits[i].iter().copied());
                registry.extend(std::iter::repeat_n(&borrow, d + 1));
                let linear = packed_linear::prove::<F, Sha256, _>(
                    &mut prover,
                    &registry,
                    &super::super::relations::<F>(&config).unwrap(),
                )
                .unwrap();
                prover.append_message(b"decomposition batch comparison obligation", &());
                members.push(MemberProof {
                    borrow_commitments,
                    linear,
                    comparisons: vec![()],
                });
            }
            let mut registry = Vec::new();
            for i in 0..2 {
                registry.extend(digits[i].iter().copied());
                registry.extend(std::iter::repeat_n(&borrow, d + 1));
            }
            let local = requests::<F>(&configs).unwrap();
            prover.append_message(b"decomposition comparison group", &(0usize, 2usize));
            let comparison = lookup::prove_foreign_for_audit::<F, EF, Sha256, _>(
                &mut prover,
                &helper,
                &registry,
                &local,
                &vec![&zero; registry.len()],
            )
            .unwrap();
            let proof = Proof {
                members,
                comparisons: vec![comparison],
            };
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<F, EF, [u8; 32]>, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut reference = Transcript::new_direct();
            bind_batch::<F, EF, Sha256, _>(&mut reference, &configs, &helper, &public, &pd)
                .unwrap();
            for i in 0..2 {
                reference.append_message(b"decomposition batch instance", &i);
                super::super::verify_impl::<F, Sha256, _, Batched>(
                    &mut reference,
                    &config,
                    &public[i],
                    Some(&helper),
                    &pd[i],
                    &proof.members[i],
                )
                .unwrap();
            }
            let public_registry: Vec<_> = registry.iter().map(|o| o.verifier()).collect();
            reference.append_message(b"decomposition comparison group", &(0usize, 2usize));
            lookup::verify_reference_for_audit::<F, EF, Sha256, _>(
                &mut reference,
                &helper,
                &public_registry,
                &local,
                &proof.comparisons[0],
            )
            .unwrap();
            assert_eq!(
                prover.get_challenge(b"after reconstructed batch"),
                reference.get_challenge(b"after reconstructed batch")
            );
            let result = verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &configs,
                &helper,
                &public,
                &pd,
                &proof,
            );
            let accepted = result.is_ok();
            if bad_member.is_none() {
                result.unwrap();
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("terminal reciprocal identity")
                );
            }
            let bad = bad_member
                .map(|i| i.to_string())
                .unwrap_or_else(|| "null".into());
            eprintln!(
                "HB_BATCH_DECOMPOSITION_BINDING_CASE {{\"prime\":{},\"members\":2,\"malicious_member\":{bad},\"reference_scope\":\"fresh-linear-members-and-lookup-algebra-actual-root-openings\",\"production_accepted\":{accepted}}}",
                F::MODULUS_VALUE
            );
        }
    }
    #[test]
    fn babybear_genuine_batched_noncanonical_digit_rejects() {
        forged::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
    }
    #[test]
    fn goldilocks_genuine_batched_noncanonical_digit_rejects() {
        forged::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
    }
}
