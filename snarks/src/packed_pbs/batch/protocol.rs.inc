/// Member constraints excluding Hadamard, which the outer proof must discharge.
/// There is deliberately no public standalone verifier for this member format.
pub type MemberProof<F, EF, O> =
    crate::packed_pbs::Proof<F, O, decomp::deferred::Proof<F, EF, O>, ()>;
/// One complete certificate for an ordered list of native NAND statements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F: algebra::Field, EF: algebra::Field, O> {
    /// Checked outer protocol version, distinct from all standalone formats.
    pub protocol_version: u32,
    /// Every member's canonical non-Hadamard PBS constraints, in caller order.
    pub members: Vec<MemberProof<F, EF, O>>,
    /// Shared-challenge independent Hadamard equations and one joint PCS packet.
    pub hadamard: relations::Proof<F, EF, O>,
}

fn bind<F, EF, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, C>,
    setup: &VerifierSetup<H::Output>,
    statements: &[Statement<'_, F>],
    members: &[MemberProof<F, EF, H::Output>],
) -> Result<Vec<Vec<Commitment<H::Output>>>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    pp.validate(&setup.config)?;
    if statements.is_empty()
        || members.len() != statements.len()
        || members
            .iter()
            .any(|m| m.protocol_version != BATCH_PROTOCOL_VERSION)
    {
        return Err(error("joint PBS batch member count/version"));
    }
    let d = setup
        .config
        .decomposition::<F>()?
        .num_digits::<F>()
        .map_err(convert)?;
    if setup.br.roots().len() != 2 * d {
        return Err(error("joint PBS trusted key/digit count"));
    }
    let roots = members
        .iter()
        .map(|m| bk::commitments::<F, H, C>(pp.source, &setup.br, &m.evaluations).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let contexts = [pp.source, pp.helper, pp.final_source, pp.final_helper]
        .iter()
        .map(|p| p.context_digest::<F, H>().map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    trans.append_message(
        DOMAIN,
        &(OUTER_VERSION, EF::D, setup, contexts, statements, &roots),
    );
    Ok(roots)
}

/// Prove all ordered statements with shared preprocessing and joint Hadamard PCS.
/// Traces remain private; original evaluation tables/states are moved into a
/// batch owner rather than recomputed or recommitted for authentication.
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
        return Err(error("joint PBS statement/trace count"));
    }
    let mut members = Vec::with_capacity(statements.len());
    let mut witnesses = Vec::with_capacity(statements.len());
    for (statement, trace) in statements.iter().zip(traces) {
        let mut witness = None;
        members.push(crate::packed_pbs::prove_inner::<
            F,
            H,
            C,
            decomp::deferred::Deferred<EF>,
            hadamard::Batched,
        >(
            pp,
            setup,
            statement,
            trace,
            &mut ProverStatistics::default(),
            Some(&mut witness),
        )?);
        witnesses.push(witness.ok_or_else(|| error("missing joint PBS source owner"))?);
    }
    let mut trans = Transcript::new_direct();
    let roots = bind::<F, EF, H, C>(&mut trans, pp, &setup.verifier, statements, &members)?;
    let key = setup.br.oracles(pp.source).map_err(convert)?;
    let d = key.len();
    let mut factors = Vec::with_capacity(members.len());
    let mut states = Vec::with_capacity(members.len());
    for witness in &witnesses {
        if witness.tables.len() != d + 1 || witness.states.len() != d + 1 {
            return Err(error("joint PBS evaluation owner shape"));
        }
        let mut tables = Vec::with_capacity(2 * d + 1);
        let mut references = Vec::with_capacity(2 * d + 1);
        for i in 0..d {
            tables.push(&witness.tables[i]);
            references.push(&witness.states[i]);
            tables.push(key[i].table);
            references.push(key[i].state);
        }
        tables.push(&witness.tables[d]);
        references.push(&witness.states[d]);
        factors.push(tables);
        states.push(references);
    }
    let shapes = vec![hadamard_shape(pp.source, d); members.len()];
    let tables: Vec<_> = factors.iter().map(Vec::as_slice).collect();
    let hadamard = relations::prove_borrowed::<F, EF, H, C>(
        &mut trans, &shapes, pp.source, &tables, &roots, &states,
    )
    .map_err(convert)?;
    Ok(Proof {
        protocol_version: OUTER_VERSION,
        members,
        hadamard,
    })
}

/// Verify every native NAND member and the mandatory joint Hadamard certificate.
/// No trace, private state or independently declared key/root registry is taken.
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
    if proof.protocol_version != OUTER_VERSION {
        return Err(error("unsupported joint PBS batch version"));
    }
    let mut trans = Transcript::new_direct();
    let roots = bind::<F, EF, H, C>(&mut trans, pp, setup, statements, &proof.members)?;
    for (statement, member) in statements.iter().zip(&proof.members) {
        crate::packed_pbs::verify_impl::<F, H, C, decomp::deferred::Deferred<EF>, hadamard::Batched>(
            pp, setup, statement, member,
        )?;
    }
    let shapes = vec![hadamard_shape(pp.source, setup.br.roots().len()); proof.members.len()];
    relations::verify::<F, EF, H, C>(&mut trans, &shapes, pp.source, &roots, &proof.hadamard)
        .map_err(convert)
}
