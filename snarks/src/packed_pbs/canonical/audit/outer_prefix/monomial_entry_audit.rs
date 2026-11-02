//! Independent public monomial binding. No claim of an accepted prior prefix.
use super::*;

fn binding<F, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    cfg: &Config,
    statement: &PublicStatement<F>,
    roots: &[Commitment<Digest512>],
) -> Option<Vec<u8>>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    if roots.len() != 2 {
        return None;
    }
    profile.parent_transcript::<F>().ok()?;
    let (plan, _) = public_inputs(cfg, &statement.borrowed()).ok()?;
    let width = pp.monomial.width();
    if !width.is_power_of_two() || width > cfg.n {
        return None;
    }
    let variables = (cfg.n / width).ilog2() as usize + plan.padded_rounds().ilog2() as usize + 1;
    let role = profile.specification().roles.first()?;
    if role.width != width
        || role.num_vars != variables
        || pp.monomial.num_vars() != variables
        || pp.accumulators[..2]
            .iter()
            .any(|p| p.width() != width || p.num_vars() != variables)
    {
        return None;
    }
    let contexts = pp.accumulators[..2]
        .iter()
        .zip(roots)
        .map(|(parameters, root)| Some((parameters.context().ok()?, root)))
        .collect::<Option<Vec<_>>>()?;
    F::generate_ntt_table(cfg.n.ilog2()).ok()?;
    F::init_ntt_table(cfg.n.ilog2()).ok()?;
    let root = F::get_ntt_table(cfg.n.ilog2()).ok()?.root();
    let mut result = Vec::new();
    frame(
        &mut result,
        1,
        b"packed canonical backend expected monomial product v1",
        &encoded(&(&plan, root, pp.monomial.context().ok()?, contexts)),
    );
    Some(result)
}

// Recover the fixed source slots from the outer binding; equality of root bytes
// does not select either role. Prior-stage acceptance remains a separate gate.
#[allow(dead_code)]
fn outer_binding<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
) -> Option<Vec<u8>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let header = initial_header::<F>(profile)?;
    let mut rest = input.strip_prefix(header.as_slice())?;
    let primary = message(
        &mut rest,
        1,
        <stages::ClassicalShared as stages::Mode>::DOMAIN,
    )?;
    let (_, _, _, roots, _) = recover::<F, EF, P>(pp, setup, statement, primary)?;
    binding(profile, pp, &setup.config, statement, roots.get(..2)?)
}

// Advance only after collecting all seven preceding accumulator openings and
// checking its public arithmetic. Earlier opaque PCS completions remain
// explicit obligations of that prefix interpreter.
pub(super) fn prefix<'a, F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &'a [u8],
    before: &Producers,
    views: &FirstViews,
) -> Option<(Vec<Commitment<Digest512>>, &'a [u8])>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let (_, rest) = accumulator_opening_prefix::<F, EF, P>(
        profile, pp, setup, statement, input, before, views, true,
    )?;
    let binding = outer_binding::<F, EF, P>(profile, pp, setup, statement, input)?;
    let mut rest = rest.strip_prefix(binding.as_slice())?;
    let mut body = message(&mut rest, 1, b"public canonical monomial NTT roots")?;
    let evaluations = vector::<Commitment<Digest512>>(&mut body, 2)?;
    body.is_empty().then_some((evaluations, rest))
}

pub(super) fn exercise_prefix<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &Parameters<'_, P>,
    setup: &VerifierSetup<Digest512>,
    statement: &PublicStatement<F>,
    input: &[u8],
    before: &Producers,
    views: &FirstViews,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let binding = outer_binding::<F, EF, P>(profile, pp, setup, statement, input).unwrap();
    let roots = vec![
        Commitment {
            root: Digest512([43; 64]),
        },
        Commitment {
            root: Digest512([47; 64]),
        },
    ];
    let mut complete = input.to_vec();
    complete.extend(&binding);
    let roots_start = complete.len();
    frame(
        &mut complete,
        1,
        b"public canonical monomial NTT roots",
        &encoded(&roots),
    );
    let (recovered, rest) =
        prefix::<F, EF, P>(profile, pp, setup, statement, &complete, before, views).unwrap();
    assert!(rest.is_empty());
    assert_eq!(encoded(&recovered), encoded(&roots));
    super::monomial_ntt_prefix_audit::exercise::<F, EF, P>(
        profile, pp, setup, statement, &complete, &roots, before, views,
    );
    let mut wrong = complete.clone();
    wrong[roots_start - 1] ^= 1;
    assert!(prefix::<F, EF, P>(profile, pp, setup, statement, &wrong, before, views).is_none());
    let mut wrong = complete[..roots_start].to_vec();
    frame(
        &mut wrong,
        1,
        b"public canonical monomial NTT roots",
        &encoded(&roots[..1].to_vec()),
    );
    assert!(prefix::<F, EF, P>(profile, pp, setup, statement, &wrong, before, views).is_none());
    assert!(
        prefix::<F, EF, P>(
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
    println!(
        "HB_MONOMIAL_PREFIX prime={} degree={} version={} backend={:?} earlier_openings_conditional=true",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend
    );
}

fn exercise<F, EF, P>(bundle: ProfileParameters<P>, cfg: &Config)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F>,
    P: CanonicalPcs<F, Sha512>,
{
    let profile = bundle.profile();
    let pp = super::super::super::classical::parameters(&bundle);
    let mut statement = PublicStatement {
        left_a: (0..cfg.lwe).map(|i| F::from(i + 1)).collect(),
        right_a: (0..cfg.lwe).map(|i| F::from(i + 3)).collect(),
        left_b: F::one(),
        right_b: F::one(),
        output_a: vec![F::zero(); cfg.lwe],
        output_b: F::zero(),
    };
    let roots = vec![
        Commitment {
            root: Digest512([3; 64]),
        },
        Commitment {
            root: Digest512([7; 64]),
        },
    ];
    let expected = binding(profile, &pp, cfg, &statement, &roots).unwrap();
    let (plan, _) = public_inputs(cfg, &statement.borrowed()).unwrap();
    let sources = pp.accumulators[..2]
        .iter()
        .zip(&roots)
        .map(|(parameters, commitment)| CanonicalVerifierOracle {
            parameters: *parameters,
            commitment,
        })
        .collect::<Vec<_>>();
    let mut transcript = profile.parent_transcript::<F>().unwrap();
    crate::packed_monomial::canonical::audit::bind_for_test::<F, Sha512, P>(
        &mut transcript,
        &plan,
        pp.monomial,
        &sources,
    )
    .unwrap();
    let mut bytes = initial_header::<F>(profile).unwrap();
    bytes.extend(&expected);
    frame(
        &mut bytes,
        2,
        b"monomial binding replay",
        &64u64.to_le_bytes(),
    );
    let mut actual = [0; 64];
    transcript.get_challenge_bytes(b"monomial binding replay", &mut actual);
    assert_eq!(actual, shake64(&bytes));
    super::monomial_ntt_audit::exercise::<F, P>(profile, &pp, &plan, &roots, &expected);
    let mut swapped = roots.clone();
    swapped.swap(0, 1);
    assert_ne!(
        expected,
        binding(profile, &pp, cfg, &statement, &swapped).unwrap()
    );
    // Root aliasing retains both ordered context slots.
    swapped[1] = swapped[0].clone();
    assert!(binding(profile, &pp, cfg, &statement, &swapped).is_some());
    assert!(binding(profile, &pp, cfg, &statement, &roots[..1]).is_none());
    statement.left_a.pop();
    assert!(binding(profile, &pp, cfg, &statement, &roots).is_none());
    println!(
        "HB_MONOMIAL_BINDING prime={} degree={} n={} lwe={} version={} backend={:?}",
        F::MODULUS_VALUE,
        EF::D,
        cfg.n,
        cfg.lwe,
        profile.version(),
        profile.specification().backend
    );
}

fn field<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    for (n, lwe) in [(32, 21), (1024, 728)] {
        let cfg = Config::new::<F>(n, lwe, 8, 5, 1, 1).unwrap();
        for version in [4, 5] {
            for backend in [
                Backend::Brakedown,
                Backend::Polyfrim,
                Backend::PolyfrimDictionary,
                Backend::FragmentedPipfri,
                Backend::FragmentedPipfriVirtual,
            ] {
                let roles = cfg.variables(8).unwrap().map(|num_vars| Role {
                    num_vars,
                    width: 8,
                    queries: 8,
                    left_vars: (backend == Backend::Brakedown).then_some(num_vars / 2),
                    block_width: (backend == Backend::Brakedown).then_some(8),
                });
                let spec = Specification {
                    backend,
                    roles,
                    blowup: 2,
                    fragment_vars: matches!(
                        backend,
                        Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
                    )
                    .then_some(8),
                };
                let profile = if version == 4 {
                    ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
                } else {
                    ClassicalProfile::new_atomic_columns::<F, EF>(spec)
                }
                .unwrap();
                match backend {
                    Backend::Brakedown => {
                        exercise::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap(), &cfg)
                    }
                    Backend::Polyfrim => {
                        exercise::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap(), &cfg)
                    }
                    Backend::PolyfrimDictionary => exercise::<F, EF, _>(
                        profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
                        &cfg,
                    ),
                    Backend::FragmentedPipfri => exercise::<F, EF, _>(
                        profile.fragmented_parameters::<F, EF>().unwrap(),
                        &cfg,
                    ),
                    Backend::FragmentedPipfriVirtual => exercise::<F, EF, _>(
                        profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
                        &cfg,
                    ),
                }
            }
        }
    }
}

#[test]
fn monomial_source_binding_geometries() {
    field::<algebra::BabyBear, algebra::BabyBearExtension6>();
    field::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
