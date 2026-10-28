//! Complete PBS batches with mandatory cross-statement comparison packets.
//! Experimental and non-hiding; whole-proof security and promotion remain open.
use crate::packed_extension_lookup::shared as lookup;
use crate::packed_pbs::*;
use algebra::AbstractExtensionField;
use relation::batch::canonical as relations;

/// Distinct outer transcript, including ordered statement and source inventories.
pub const TRANSCRIPT_ID: &str = "merlin-direct-joint-comparisons-pbs-batch-v1";
const DOMAIN: &[u8] = b"HasteBoots complete binary NAND PBS joint comparison batch v9";
const MAX_GROUP: usize = decomp::batch::MAX_GROUP;
/// Partial member; only the complete outer verifier discharges its obligations.
pub type MemberProof<F, O> = crate::packed_pbs::Proof<F, O, decomp::Proof<F, O, ()>, ()>;
/// Complete ordered certificate; all three outer proof collections are mandatory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: algebra::Field, EF: algebra::Field, O> {
    /// Version 9, distinct from the previous complete batch formats.
    pub protocol_version: u32,
    /// Independently checked canonical PBS constraints.
    pub members: Vec<MemberProof<F, O>>,
    /// Independent Hadamard equations with canonical joint authentication.
    pub hadamard: relations::Proof<F, EF, O>,
    /// Groups of at most four blind-rotation decompositions, in member/half order.
    pub blind_rotation: Vec<lookup::Proof<F, EF, O>>,
    /// Groups of at most four final key-switch decompositions.
    pub key_switch: Vec<lookup::Proof<F, EF, O>>,
}
fn bind<F, EF, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    statements: &[Statement<'_, F>],
    members: &[MemberProof<F, H::Output>],
) -> Result<Vec<Vec<Commitment<H::Output>>>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    pp.validate(&setup.config)?;
    if statements.is_empty() || statements.len() != members.len() {
        return Err(error("comparison batch member count"));
    }
    let d = setup
        .config
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    let k = setup
        .ks
        .config()
        .decomposition::<F>()
        .map_err(convert)?
        .num_digits::<F>()
        .map_err(convert)?;
    if setup.br.roots().len() != 2 * d
        || members.iter().any(|m| {
            m.protocol_version != COMPARISON_BATCH_PROTOCOL_VERSION
                || m.coefficients.len() != 2 * d + 1
                || m.evaluations.len() != 2 * d + 1
                || m.decomposition.len() != 2
                || m.decomposition
                    .iter()
                    .any(|p| p.borrow_commitments.len() != d + 1)
                || m.key_switch.coefficients.len() != k + 1
                || m.key_switch.decomposition.borrow_commitments.len() != k + 1
        })
    {
        return Err(error("comparison batch member shape/version"));
    }
    let roots = members
        .iter()
        .map(|m| bk::commitments::<F, H, C>(pp.source, &setup.br, &m.evaluations).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let contexts = [pp.source, pp.helper, pp.final_source, pp.final_helper]
        .iter()
        .map(|p| p.context_digest::<F, H>().map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let comparison_roots: Vec<_> = members
        .iter()
        .map(|m| {
            (
                &m.coefficients,
                m.decomposition
                    .iter()
                    .map(|d| &d.borrow_commitments)
                    .collect::<Vec<_>>(),
                &m.key_switch.coefficients,
                &m.key_switch.decomposition.borrow_commitments,
            )
        })
        .collect();
    trans.append_message(
        DOMAIN,
        &(
            COMPARISON_BATCH_PROTOCOL_VERSION,
            MAX_GROUP,
            EF::D,
            setup,
            contexts,
            statements,
            &roots,
            comparison_roots,
        ),
    );
    Ok(roots)
}
fn group<F: NTTField>(trans: &mut Transcript<F>, final_stage: bool, start: usize, end: usize) {
    trans.append_message(b"PBS shared lookup group", &(final_stage, start, end));
}
/// Prove complete statements, reusing owned source states for joint authentication.
pub fn prove<F, EF, H, C>(
    pp: &Parameters<'_, C>,
    setup: &ProverSetup<F, H>,
    statements: &[Statement<'_, F>],
    traces: &[&PBSTrace<F>],
) -> Result<Proof<F, EF, H::Output>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if statements.is_empty() || statements.len() != traces.len() {
        return Err(error("comparison batch statement/trace count"));
    }
    let mut members = Vec::new();
    let mut owners = Vec::new();
    for (statement, trace) in statements.iter().zip(traces) {
        let mut owner = None;
        members.push(prove_inner::<
            F,
            H,
            C,
            decomp::batch::Batched,
            hadamard::Batched,
        >(
            pp,
            setup,
            statement,
            trace,
            &mut ProverStatistics::default(),
            Some(&mut owner),
        )?);
        owners.push(owner.ok_or_else(|| error("missing comparison batch owner"))?);
    }
    let mut trans = Transcript::new_direct();
    let roots = bind::<F, EF, H, C>(&mut trans, pp, &setup.verifier, statements, &members)?;
    let key = setup.br.oracles(pp.source).map_err(convert)?;
    let d = key.len();
    let mut tables = Vec::new();
    let mut states = Vec::new();
    for owner in &owners {
        if owner.states.len() != d + 1 {
            return Err(error("comparison batch evaluation owner shape"));
        }
        let mut t = Vec::new();
        let mut s = Vec::new();
        for i in 0..d {
            t.push(owner.states[i].table());
            s.push(&owner.states[i]);
            t.push(key[i].table);
            s.push(key[i].state);
        }
        t.push(owner.states[d].table());
        s.push(&owner.states[d]);
        tables.push(t);
        states.push(s);
    }
    let shapes = vec![hadamard_shape(pp.source, d); members.len()];
    let slices: Vec<_> = tables.iter().map(Vec::as_slice).collect();
    let hadamard = relations::prove_borrowed::<F, EF, H, C>(
        &mut trans, &shapes, pp.source, &slices, &roots, &states,
    )
    .map_err(convert)?;
    drop(slices);
    drop(tables);
    drop(states);
    for o in &mut owners {
        o.states.clear();
        o.tables.clear();
    }
    let mut blind_rotation = Vec::new();
    let mut key_switch = Vec::new();
    for final_stage in [false, true] {
        let config = if final_stage {
            setup
                .verifier
                .ks
                .config()
                .decomposition::<F>()
                .map_err(convert)?
        } else {
            setup.verifier.config.decomposition::<F>()?
        };
        let n = config.num_digits::<F>().map_err(convert)?;
        let count = members.len() * if final_stage { 1 } else { 2 };
        let source = if final_stage {
            pp.final_source
        } else {
            pp.source
        };
        let helper = if final_stage {
            pp.final_helper
        } else {
            pp.helper
        };
        for start in (0..count).step_by(MAX_GROUP) {
            let end = (start + MAX_GROUP).min(count);
            let mut registry = Vec::new();
            for i in start..end {
                let (coefficients, borrows, co, bo, offset) = if final_stage {
                    let o = owners[i]
                        .key_switch
                        .as_ref()
                        .ok_or_else(|| error("missing final comparison owner"))?;
                    (
                        &o.coefficients,
                        &o.borrows,
                        &members[i].key_switch.coefficients,
                        &members[i].key_switch.decomposition.borrow_commitments,
                        0,
                    )
                } else {
                    let (m, h) = (i / 2, i % 2);
                    (
                        &owners[m].coefficients,
                        &owners[m].borrows[h],
                        &members[m].coefficients,
                        &members[m].decomposition[h].borrow_commitments,
                        h * n,
                    )
                };
                if coefficients.len() < offset + n || borrows.len() != n + 1 {
                    return Err(error("comparison source owner shape"));
                }
                for j in 0..n {
                    let state = &coefficients[offset + j];
                    registry.push(ProverOracle {
                        parameters: source,
                        commitment: &co[offset + j],
                        state,
                        table: state.table(),
                    });
                }
                for (state, commitment) in borrows.iter().zip(bo) {
                    registry.push(ProverOracle {
                        parameters: source,
                        commitment,
                        state,
                        table: state.table(),
                    });
                }
            }
            group(&mut trans, final_stage, start, end);
            let proof = lookup::prove::<F, EF, H, C>(
                &mut trans,
                helper,
                &registry.iter().collect::<Vec<_>>(),
                &decomp::batch::requests::<F>(&vec![config.clone(); end - start])
                    .map_err(convert)?,
            )
            .map_err(convert)?;
            drop(registry);
            if final_stage {
                key_switch.push(proof);
                for o in &mut owners[start..end] {
                    o.key_switch = None;
                }
            } else {
                blind_rotation.push(proof);
                for o in &mut owners[start / 2..end.div_ceil(2)] {
                    o.coefficients.clear();
                    o.borrows.clear();
                }
            }
        }
    }
    Ok(Proof {
        protocol_version: COMPARISON_BATCH_PROTOCOL_VERSION,
        members,
        hadamard,
        blind_rotation,
        key_switch,
    })
}
/// Check every member and all mandatory outer comparison and Hadamard packets.
pub fn verify<F, EF, H, C>(
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    statements: &[Statement<'_, F>],
    proof: &Proof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if proof.protocol_version != COMPARISON_BATCH_PROTOCOL_VERSION
        || proof.blind_rotation.len() != (2 * proof.members.len()).div_ceil(MAX_GROUP)
        || proof.key_switch.len() != proof.members.len().div_ceil(MAX_GROUP)
    {
        return Err(error("comparison batch version/group count"));
    }
    let mut trans = Transcript::new_direct();
    let roots = bind::<F, EF, H, C>(&mut trans, pp, setup, statements, &proof.members)?;
    for (statement, member) in statements.iter().zip(&proof.members) {
        verify_impl::<F, H, C, decomp::batch::Batched, hadamard::Batched>(
            pp, setup, statement, member,
        )?;
    }
    let shapes = vec![hadamard_shape(pp.source, setup.br.roots().len()); proof.members.len()];
    relations::verify::<F, EF, H, C>(&mut trans, &shapes, pp.source, &roots, &proof.hadamard)
        .map_err(convert)?;
    for final_stage in [false, true] {
        let config = if final_stage {
            setup.ks.config().decomposition::<F>().map_err(convert)?
        } else {
            setup.config.decomposition::<F>()?
        };
        let n = config.num_digits::<F>().map_err(convert)?;
        let count = proof.members.len() * if final_stage { 1 } else { 2 };
        let source = if final_stage {
            pp.final_source
        } else {
            pp.source
        };
        let helper = if final_stage {
            pp.final_helper
        } else {
            pp.helper
        };
        for (packet, start) in (0..count).step_by(MAX_GROUP).enumerate() {
            let end = (start + MAX_GROUP).min(count);
            let mut registry = Vec::new();
            for i in start..end {
                let (co, bo, offset) = if final_stage {
                    let m = &proof.members[i];
                    (
                        &m.key_switch.coefficients,
                        &m.key_switch.decomposition.borrow_commitments,
                        0,
                    )
                } else {
                    let (m, h) = (&proof.members[i / 2], i % 2);
                    (
                        &m.coefficients,
                        &m.decomposition[h].borrow_commitments,
                        h * n,
                    )
                };
                registry.extend(co[offset..offset + n].iter().chain(bo).map(|commitment| {
                    VerifierOracle {
                        parameters: source,
                        commitment,
                    }
                }));
            }
            group(&mut trans, final_stage, start, end);
            lookup::verify::<F, EF, H, C>(
                &mut trans,
                helper,
                &registry,
                &decomp::batch::requests::<F>(&vec![config.clone(); end - start])
                    .map_err(convert)?,
                if final_stage {
                    &proof.key_switch[packet]
                } else {
                    &proof.blind_rotation[packet]
                },
            )
            .map_err(convert)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
