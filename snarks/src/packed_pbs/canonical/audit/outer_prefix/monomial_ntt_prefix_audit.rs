//! Fixed-slot first monomial NTT request after the conditional outer prefix.
use super::*;

pub(super) fn request<F, P>(
    pp: &Parameters<'_, P>,
    n: usize,
    component: usize,
    coefficients: &[Commitment<Digest512>],
    evaluations: &[Commitment<Digest512>],
) -> Option<(NttRowTask, Vec<u8>)>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    if component >= 2 || coefficients.len() != 2 || evaluations.len() != 2 {
        return None;
    }
    let source = pp.accumulators[component];
    let shape = ntt::Shape::new_canonical::<F, Sha512, P>(pp.monomial, n).ok()?;
    if source.width() != shape.width() || source.num_vars() != pp.monomial.num_vars() {
        return None;
    }
    let contexts = (source.context().ok()?, pp.monomial.context().ok()?);
    let root = F::get_ntt_table(n.ilog2()).ok()?.root();
    let mut out = Vec::new();
    frame(
        &mut out,
        1,
        P::NTT_DOMAIN,
        &encoded(&(
            F::MODULUS_VALUE.to_string(),
            &shape,
            root,
            contexts,
            &coefficients[component],
            &evaluations[component],
        )),
    );
    frame(&mut out, 1, b"typed request kind", b"vector");
    frame(&mut out, 1, b"field challenge kind", b"prime vector");
    let p: u128 = F::MODULUS_VALUE.to_string().parse().ok()?;
    let count = shape.width().checked_mul(shape.row_variables())?;
    let mut descriptor = p.to_le_bytes().to_vec();
    descriptor.extend(u64::try_from(count).ok()?.to_le_bytes());
    frame(&mut out, 4, b"packed NTT atomic row points v2", &descriptor);
    Some((
        NttRowTask {
            component,
            coefficients: (contexts.0, coefficients[component].clone()),
            evaluations: (contexts.1, evaluations[component].clone()),
            shape,
        },
        out,
    ))
}

fn first_row_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttRowTask, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (evaluations, rest) = super::monomial_entry_audit::prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views,
    )?;
    let header = initial_header::<F>(profile)?;
    let mut outer = input.strip_prefix(header.as_slice())?;
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let (_, _, _, accumulators, _) = recover::<F, EF, P>(pp, setup, statement, primary)?;
    let (task, expected) =
        request::<F, P>(pp, setup.config.n, 0, accumulators.get(..2)?, &evaluations)?;
    Some((task, rest.strip_prefix(expected.as_slice())?))
}

fn first_row_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<NttRowTask>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (task, rest) =
        first_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    rest.is_empty().then_some(task)
}

fn compression_query<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
    round: usize,
) -> Option<NttCompression<F>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (row, rest) =
        first_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    // Existing canonical profiles use the same role-0 parameters for these
    // sources. Require exact contexts before using the shared NTT body parser.
    if row.coefficients.0 != pp.coefficients.context().ok()?
        || row.evaluations.0 != pp.evaluations.context().ok()?
    {
        return None;
    }
    let (task, rest) = ntt_compression_body::<F, P>(pp, row, rest, before, round)?;
    rest.is_empty().then_some(task)
}

fn batch_prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(NttBatchTask<F>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (row, rest) =
        first_row_prefix::<F, EF, P>(profile, pp, setup, statement, input, before, views)?;
    if row.coefficients.0 != pp.coefficients.context().ok()?
        || row.evaluations.0 != pp.evaluations.context().ok()?
    {
        return None;
    }
    let last = row.shape.coefficient_variables().checked_sub(1)?;
    let (task, rest) = ntt_compression_body::<F, P>(pp, row, rest, before, last)?;
    ntt_batch_body(task, rest, before)
}

pub(super) fn polynomials<F, P>(
    pp: &Parameters<'_, P>,
    row: &NttRowTask,
) -> (Vec<Vec<F>>, Vec<Vec<F>>)
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    let n = row.shape.polynomial_size();
    let coefficients = (0..row.shape.width())
        .map(|lane| {
            let mut poly = vec![F::zero(); n];
            poly[(lane + 1) % n] = F::from(lane + 1);
            poly
        })
        .collect::<Vec<_>>();
    let table = F::get_ntt_table(n.ilog2()).unwrap();
    let evaluations = coefficients
        .iter()
        .map(|poly| {
            let mut transformed = poly.clone();
            table.transform_slice(&mut transformed);
            pp.monomial.normalize_values(transformed)
        })
        .collect();
    (coefficients, evaluations)
}

pub(super) fn exercise<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    evaluations: &[Commitment<Digest512>],
    before: &Producers,
    views: &FirstViews,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let header = initial_header::<F>(profile).unwrap();
    let mut outer = input.strip_prefix(header.as_slice()).unwrap();
    let primary = message(
        &mut outer,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )
    .unwrap();
    let (_, _, _, coefficients, _) = recover::<F, EF, P>(pp, setup, statement, primary).unwrap();
    let coefficients = &coefficients[..2];
    let (expected, tail) =
        request::<F, P>(pp, setup.config.n, 0, coefficients, evaluations).unwrap();
    let mut complete = input.to_vec();
    complete.extend(&tail);
    let task = first_row_query::<F, EF, P>(profile, pp, setup, statement, &complete, before, views)
        .unwrap();
    assert_eq!(task.component, 0);
    assert_eq!(encoded(&task.coefficients), encoded(&expected.coefficients));
    assert_eq!(encoded(&task.evaluations), encoded(&expected.evaluations));
    let mut wrong = input.to_vec();
    wrong.extend(
        request::<F, P>(pp, setup.config.n, 1, coefficients, evaluations)
            .unwrap()
            .1,
    );
    assert!(
        first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, before, views).is_none()
    );
    let mut wrong = complete.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(
        first_row_query::<F, EF, P>(profile, pp, setup, statement, &wrong, before, views).is_none()
    );
    assert!(
        first_row_query::<F, EF, P>(
            profile,
            pp,
            setup,
            statement,
            &complete[..complete.len() - 1],
            before,
            views
        )
        .is_none()
    );
    let mut known = before.clone();
    let (_, raw) = raw_prime_phase::<F>(
        &complete,
        expected.shape.width() * expected.shape.row_variables(),
    );
    let (phase, producer) = receipt(&raw);
    known.insert(phase[16..].try_into().unwrap(), producer);
    frame(&mut complete, 5, b"packed NTT atomic row points v2", &phase);
    let (co, ev) = polynomials::<F, P>(pp, &expected);
    frame(
        &mut complete,
        1,
        b"packed NTT folded polynomials",
        &encoded(&(&co, &ev)),
    );
    for round in 0..expected.shape.coefficient_variables() {
        complete.extend(ntt_compression_tail::<F>(expected.shape.width()));
        let parsed = compression_query::<F, EF, P>(
            profile, pp, setup, statement, &complete, &known, views, round,
        )
        .unwrap();
        assert_eq!(parsed.compression.len(), round);
        assert_eq!(encoded(&parsed.coefficients), encoded(&co));
        assert_eq!(encoded(&parsed.evaluations), encoded(&ev));
        let mut wrong = complete.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(
            compression_query::<F, EF, P>(
                profile, pp, setup, statement, &wrong, &known, views, round
            )
            .is_none()
        );
        let (_, raw) = raw_prime_phase::<F>(&complete, expected.shape.width());
        let (phase, producer) = receipt(&raw);
        known.insert(phase[16..].try_into().unwrap(), producer);
        frame(
            &mut complete,
            5,
            b"packed NTT coefficient compression",
            &phase,
        );
    }
    let (mut batch, rest) =
        batch_prefix::<F, EF, P>(profile, pp, setup, statement, &complete, &known, views).unwrap();
    assert!(rest.is_empty());
    assert_eq!(batch.queries.len(), expected.shape.width());
    assert_eq!(
        encoded(&batch.source()),
        encoded(&(&expected.coefficients.0, &expected.coefficients.1))
    );
    batch.evaluation = true;
    assert_eq!(
        encoded(&batch.source()),
        encoded(&(&expected.evaluations.0, &expected.evaluations.1))
    );
    println!(
        "HB_MONOMIAL_NTT_PREFIX prime={} degree={} version={} backend={:?} component=0 earlier_openings_conditional=true",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend
    );
}
