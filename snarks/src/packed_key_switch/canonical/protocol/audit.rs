//! Test-only foreign key products and extraction targets; strict source openings.
use super::*;
pub(crate) fn extraction<F, H, P>(
    pp: &P,
    key: &ExpectedKey<H::Output>,
    accumulator: &[F],
    a: &[F],
    b: F,
) -> Result<(PackedTable<F>, PackedTable<F>, PackedShape<F>), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let (mask, target) =
        extraction_tables_dimensions(pp.num_vars(), pp.width(), key.config(), accumulator, a, b)?;
    Ok((
        mask,
        target,
        extraction_shape_dimensions(pp.num_vars(), pp.width()),
    ))
}

pub(crate) fn public_input<F, H, P>(
    trans: &mut Transcript<F>,
    pp: &P,
    key: &ExpectedKey<H::Output>,
    accumulator: &[F],
    root: &Commitment<H::Output>,
) -> Result<(PackedTable<F>, Vec<algebra::matrix_weighted::MatrixPair<F>>), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let table = input_dimensions(pp.num_vars(), pp.width(), key.config(), accumulator)?;
    let query = public_input_query::<F, H, P>(trans, pp, root, &table)?;
    Ok((table, query))
}

pub(crate) fn expected_key<F, H, P>(
    parameters: &P,
    config: Config,
    roots: Vec<Commitment<H::Output>>,
) -> Result<ExpectedKey<H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    config.validate_geometry(parameters.num_vars(), parameters.width())?;
    if roots.len() != config.digits::<F>()? {
        return Err(error("audit switching-key roots"));
    }
    Ok(ExpectedKey {
        config,
        context: parameters.context().map_err(convert)?,
        roots,
    })
}

pub(crate) fn bind_shared<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    co: &[Commitment<H::Output>],
    ev: &[Commitment<H::Output>],
    input: &Commitment<H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let acc = pp.coefficients.normalize_values(acc.to_vec());
    let a = pp.coefficients.normalize_values(a.to_vec());
    let b = pp.coefficients.normalize_values(vec![b])[0];
    <comparison::Shared as comparison::Comparison<F, EF, H, P>>::bind(trans);
    bind::<F, EF, H, P>(trans, pp, key, &acc, &a, b, co, ev, input)
}

pub(crate) fn prove_foreign<F, EF, H, P, R>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ProverKey<F, H, P>,
    acc: &[F],
    a: &[F],
    b: F,
    actual_a: &[F],
    actual_b: F,
    coefficients: &[PackedTable<F>],
    foreign_key: bool,
    false_lookup: bool,
    rng: &mut R,
) -> Result<Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_inner::<F, EF, H, P, R, comparison::PerLimb>(
        trans,
        pp,
        key,
        acc,
        a,
        b,
        actual_a,
        actual_b,
        coefficients,
        foreign_key,
        false_lookup,
        rng,
    )
}
pub(crate) fn prove_shared<F, EF, H, P, R>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ProverKey<F, H, P>,
    acc: &[F],
    a: &[F],
    b: F,
    actual_a: &[F],
    actual_b: F,
    coefficients: &[PackedTable<F>],
    foreign_key: bool,
    false_lookup: bool,
    rng: &mut R,
) -> Result<shared::Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
{
    prove_inner::<F, EF, H, P, R, comparison::Shared>(
        trans,
        pp,
        key,
        acc,
        a,
        b,
        actual_a,
        actual_b,
        coefficients,
        foreign_key,
        false_lookup,
        rng,
    )
}
fn prove_inner<F, EF, H, P, R, D>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ProverKey<F, H, P>,
    acc: &[F],
    a: &[F],
    b: F,
    actual_a: &[F],
    actual_b: F,
    coefficients: &[PackedTable<F>],
    foreign_key: bool,
    false_lookup: bool,
    rng: &mut R,
) -> Result<BackendProof<F, H::Output, P::SingleProof, P::BatchProof, D::Proof>, Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    R: Rng + CryptoRng,
    D: comparison::Comparison<F, EF, H, P>,
{
    let acc = pp.coefficients.normalize_values(acc.to_vec());
    let a = pp.coefficients.normalize_values(a.to_vec());
    let b = pp.coefficients.normalize_values(vec![b])[0];
    preflight::<F, EF, H, P>(pp, key.expected(), &acc, &a)?;
    let cfg = &key.expected.config;
    let d = cfg.digits::<F>()?;
    if coefficients.len() != d + 1
        || coefficients.iter().any(|t| {
            t.num_vars() != pp.coefficients.num_vars() || t.width() != pp.coefficients.width()
        })
    {
        return Err(error("private coefficient source count or dimensions"));
    }
    let (roots, states): (Vec<_>, Vec<_>) = coefficients
        .iter()
        .map(|t| pp.coefficients.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    F::init_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let native = F::get_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let transformed = states
        .iter()
        .map(|s| {
            let table = P::table(s);
            let mut v = table.values().to_vec();
            for poly in v.chunks_exact_mut(cfg.n) {
                native.transform_slice(poly);
            }
            PackedTable::new(pp.evaluations.num_vars(), pp.evaluations.width(), v).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, ntt_states): (Vec<_>, Vec<_>) = transformed
        .iter()
        .map(|t| pp.evaluations.commit(t, rng).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    drop(transformed);
    let input = input_dimensions(pp.input.num_vars(), pp.input.width(), cfg, &acc)?;
    let (input_root, input_state) = pp.input.commit(&input, rng).map_err(convert)?;
    D::bind(trans);
    bind::<F, EF, H, P>(
        trans,
        pp,
        key.expected(),
        &acc,
        &a,
        b,
        &roots,
        &evaluations,
        &input_root,
    )?;
    let iq = public_input_query::<F, H, P>(trans, pp.input, &input_root, &input)?;
    let iv = pp
        .input
        .normalize_values(P::table(&input_state).evaluate(&iq).map_err(convert)?);
    let input_opening = pp
        .input
        .open(trans, &input_root, &input_state, &iq, &iv)
        .map_err(convert)?;
    let co = oracles::<F, H, P>(pp.coefficients, &roots, &states);
    let ev = oracles::<F, H, P>(pp.evaluations, &evaluations, &ntt_states);
    let ko = key.oracles(pp.key)?;
    let shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    let ntt = (0..=d)
        .map(|i| {
            packed_ntt::prove_canonical::<F, H, P>(trans, &shape, &co[i], &ev[i]).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let factors: Vec<_> = (0..d)
        .flat_map(|i| [&ev[i], &ko[i]])
        .chain(std::iter::once(&ev[d]))
        .collect();
    let product = if foreign_key {
        let foreign: Vec<_> = factors
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if i % 2 == 1 {
                    PackedTable::new(
                        pp.evaluations.num_vars(),
                        pp.evaluations.width(),
                        vec![F::zero(); s.table().values().len()],
                    )
                    .unwrap()
                } else {
                    s.table().clone()
                }
            })
            .collect();
        packed_relation::audit::prove_foreign::<F, H, P>(
            trans,
            &product_shape_dimensions(pp.evaluations.num_vars(), pp.evaluations.width(), d),
            &factors,
            &foreign,
        )
        .map_err(convert)?
    } else {
        packed_relation::prove_canonical::<F, H, P>(
            trans,
            &product_shape_dimensions(pp.evaluations.num_vars(), pp.evaluations.width(), d),
            &factors,
            &mut packed_relation::ProverStatistics::default(),
        )
        .map_err(convert)?
    };
    let source = CanonicalProverOracle::<F, H, P> {
        parameters: pp.input,
        commitment: &input_root,
        state: &input_state,
    };
    let decomposition = D::audit_prove(
        trans,
        &cfg.decomposition::<F>()?,
        &source,
        pp.borrows,
        pp.helper,
        &co[..d].iter().collect::<Vec<_>>(),
        false_lookup,
        rng,
    )?;
    let (mask, target) = extraction_tables_dimensions(
        pp.coefficients.num_vars(),
        pp.coefficients.width(),
        cfg,
        &acc,
        actual_a,
        actual_b,
    )?;
    let shape = extraction_shape_dimensions(pp.coefficients.num_vars(), pp.coefficients.width());
    let (zero, subclaim, terminals) = packed_zero::prove_with_borrowed_terminal_values(
        trans,
        &shape,
        &[co[d].table(), &mask, &target],
    )
    .map_err(convert)?;
    let value = pp.coefficients.normalize_values(terminals[0].clone());
    subclaim
        .check(
            &shape,
            &[
                value.clone(),
                mask.evaluate(&subclaim.query).map_err(convert)?,
                target.evaluate(&subclaim.query).map_err(convert)?,
            ],
        )
        .map_err(convert)?;
    let opening = pp
        .coefficients
        .open(trans, &roots[d], &states[d], &subclaim.query, &value)
        .map_err(convert)?;
    Ok(BackendProof {
        coefficients: roots,
        evaluations,
        input: input_root,
        input_opening,
        ntt,
        product,
        decomposition,
        extraction: Extraction {
            zero,
            value,
            opening,
        },
    })
}
pub(crate) fn verify<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(bool, bool, [bool; 3], bool), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, comparison::PerLimb>(trans, pp, key, acc, a, b, proof)
        .map(|result| result.0)
}
pub(crate) fn verify_queries<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<((bool, bool, [bool; 3], bool), FinalQueries<F>), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, comparison::PerLimb>(trans, pp, key, acc, a, b, proof)
}
pub(crate) fn verify_shared<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &shared::Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<(bool, bool, [bool; 3], bool), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, comparison::Shared>(trans, pp, key, acc, a, b, proof)
        .map(|result| result.0)
}
#[cfg_attr(not(feature = "transcript-audit"), allow(dead_code))]
pub(crate) struct FinalQueries<F> {
    pub(crate) input: Vec<algebra::matrix_weighted::MatrixPair<F>>,
    pub(crate) extraction: sumcheck::packed_zero::ZeroSubclaim<F>,
    pub(crate) product: sumcheck::packed_zero::ZeroSubclaim<F>,
    pub(crate) decomposition: Vec<Vec<algebra::matrix_weighted::MatrixPair<F>>>,
    pub(crate) lookup:
        Option<crate::packed_extension_lookup::canonical::shared::audit::SourceClaims<F>>,
    #[cfg(feature = "transcript-audit")]
    pub(crate) ntt: Vec<packed_ntt::AuditSourceObligations<F>>,
}

pub(crate) fn verify_shared_queries<F, EF, H, P>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &shared::Proof<F, EF, H::Output, P::SingleProof, P::BatchProof>,
) -> Result<((bool, bool, [bool; 3], bool), FinalQueries<F>), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, EF, H, P, comparison::Shared>(trans, pp, key, acc, a, b, proof)
}

fn verify_inner<F, EF, H, P, D>(
    trans: &mut Transcript<F>,
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
    a: &[F],
    b: F,
    proof: &BackendProof<F, H::Output, P::SingleProof, P::BatchProof, D::Proof>,
) -> Result<((bool, bool, [bool; 3], bool), FinalQueries<F>), Error>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
    D: comparison::Comparison<F, EF, H, P>,
{
    let acc = pp.coefficients.normalize_values(acc.to_vec());
    let a = pp.coefficients.normalize_values(a.to_vec());
    let b = pp.coefficients.normalize_values(vec![b])[0];
    D::bind(trans);
    bind::<F, EF, H, P>(
        trans,
        pp,
        key,
        &acc,
        &a,
        b,
        &proof.coefficients,
        &proof.evaluations,
        &proof.input,
    )?;
    let cfg = &key.config;
    let d = cfg.digits::<F>()?;
    if proof.ntt.len() != d + 1 {
        return Err(error("NTT proof count"));
    }
    pp.coefficients
        .validate_values(&proof.extraction.value)
        .map_err(convert)?;
    let input = input_dimensions(pp.input.num_vars(), pp.input.width(), cfg, &acc)?;
    let input_query = public_input_query::<F, H, P>(trans, pp.input, &proof.input, &input)?;
    let input_value = pp
        .input
        .normalize_values(input.evaluate(&input_query).map_err(convert)?);
    pp.input
        .verify(
            trans,
            &proof.input,
            &input_query,
            &input_value,
            &proof.input_opening,
        )
        .map_err(convert)?;
    let co = public(pp.coefficients, &proof.coefficients);
    let ev = public(pp.evaluations, &proof.evaluations);
    let ko = public_oracles::<F, H, P>(pp.key, key)?;
    let shape =
        packed_ntt::Shape::new_canonical::<F, H, P>(pp.coefficients, cfg.n).map_err(convert)?;
    #[cfg(feature = "transcript-audit")]
    let mut ntt_claims = Vec::new();
    for i in 0..=d {
        #[cfg(feature = "transcript-audit")]
        ntt_claims.push(
            packed_ntt::audit_verified_source_obligations::<F, H, P>(
                trans,
                &shape,
                &co[i],
                &ev[i],
                &proof.ntt[i],
            )
            .map_err(convert)?,
        );
        #[cfg(not(feature = "transcript-audit"))]
        packed_ntt::verify_canonical::<F, H, P>(trans, &shape, &co[i], &ev[i], &proof.ntt[i])
            .map_err(convert)?;
    }
    let factors: Vec<_> = (0..d)
        .flat_map(|i| [&ev[i], &ko[i]])
        .chain(std::iter::once(&ev[d]))
        .map(|s| CanonicalVerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    let (product_valid, product_claim) = packed_relation::audit::verify_subclaim::<F, H, P>(
        trans,
        &product_shape_dimensions(pp.evaluations.num_vars(), pp.evaluations.width(), d),
        &factors,
        &proof.product,
    )
    .map_err(convert)?;
    let ((decomposition_valid, lookup_valid), decomposition_queries, lookup_claims) =
        D::audit_verify(
            trans,
            &cfg.decomposition::<F>()?,
            &CanonicalVerifierOracle {
                parameters: pp.input,
                commitment: &proof.input,
            },
            pp.borrows,
            pp.helper,
            &co[..d]
                .iter()
                .map(|s| CanonicalVerifierOracle {
                    parameters: s.parameters,
                    commitment: s.commitment,
                })
                .collect::<Vec<_>>(),
            &proof.decomposition,
        )?;
    let (mask, target) = extraction_tables_dimensions(
        pp.coefficients.num_vars(),
        pp.coefficients.width(),
        cfg,
        &acc,
        &a,
        b,
    )?;
    let shape = extraction_shape_dimensions(pp.coefficients.num_vars(), pp.coefficients.width());
    let subclaim = packed_zero::verify(trans, &shape, &proof.extraction.zero).map_err(convert)?;
    let valid = subclaim
        .check(
            &shape,
            &[
                proof.extraction.value.clone(),
                mask.evaluate(&subclaim.query).map_err(convert)?,
                target.evaluate(&subclaim.query).map_err(convert)?,
            ],
        )
        .is_ok();
    pp.coefficients
        .verify(
            trans,
            &proof.coefficients[d],
            &subclaim.query,
            &proof.extraction.value,
            &proof.extraction.opening,
        )
        .map_err(convert)?;
    Ok((
        (product_valid, valid, decomposition_valid, lookup_valid),
        FinalQueries {
            input: input_query,
            extraction: subclaim,
            product: product_claim,
            decomposition: decomposition_queries,
            lookup: lookup_claims,
            #[cfg(feature = "transcript-audit")]
            ntt: ntt_claims,
        },
    ))
}

/// Genuine canonical negative-a digits with the zero-key product as final word.
pub(crate) fn zero_key_coefficients<F, H, P>(
    pp: &Parameters<'_, P>,
    key: &ExpectedKey<H::Output>,
    acc: &[F],
) -> Result<Vec<PackedTable<F>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let cfg = &key.config;
    let source = input_dimensions(pp.input.num_vars(), pp.input.width(), cfg, acc)?;
    let d = cfg.digits::<F>()?;
    let radix = cfg.decomposition::<F>()?.radix().map_err(convert)?;
    let mut words = vec![vec![F::zero(); source.values().len()]; d + 1];
    for (row, &x) in source.values().iter().enumerate() {
        let mut integer: usize = x.canonicalized().value().try_into().ok().unwrap();
        for limb in words.iter_mut().take(d) {
            limb[row] = F::from(integer % radix);
            integer /= radix;
        }
        assert_eq!(integer, 0);
    }
    words
        .into_iter()
        .map(|v| {
            PackedTable::new(pp.coefficients.num_vars(), pp.coefficients.width(), v)
                .map_err(convert)
        })
        .collect()
}
