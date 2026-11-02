//! Independent final-stage binding, not accepted monomial-prefix coupling.
use super::*;
use crate::packed_key_switch::{ExpectedKey, canonical::protocol as final_protocol};

fn final_contexts<F, P>(bundle: ProfileParameters<P>) -> Option<(Digest512, Digest512)>
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    Some((
        bundle.roles()[2].context().ok()?,
        bundle.roles()[3].context().ok()?,
    ))
}

fn binding<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &final_protocol::Parameters<'_, P>,
    key: &ExpectedKey<Digest512>,
    accumulator: &[F],
    output_a: &[F],
    output_b: F,
    coefficients: &[Commitment<Digest512>],
    evaluations: &[Commitment<Digest512>],
    input: &Commitment<Digest512>,
) -> Option<Vec<u8>>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    profile.validate_field::<F, EF>().ok()?;
    let (expected_context, expected_helper) = match profile.specification().backend {
        Backend::Brakedown => {
            final_contexts::<F, _>(profile.brakedown_parameters::<F, EF>().ok()?)?
        }
        Backend::Polyfrim => final_contexts::<F, _>(profile.polyfrim_parameters::<F, EF>().ok()?)?,
        Backend::PolyfrimDictionary => {
            final_contexts::<F, _>(profile.polyfrim_dictionary_parameters::<F, EF>().ok()?)?
        }
        Backend::FragmentedPipfri => {
            final_contexts::<F, _>(profile.fragmented_parameters::<F, EF>().ok()?)?
        }
        Backend::FragmentedPipfriVirtual => {
            final_contexts::<F, _>(profile.fragmented_virtual_parameters::<F, EF>().ok()?)?
        }
    };
    let cfg = key.config();
    let n = cfg.polynomial_size();
    let width = pp.coefficients.width();
    if !width.is_power_of_two() || width > n || width < EF::D || EF::D == 0 {
        return None;
    }
    let variables = n.checked_mul(2)?.checked_div(width)?.ilog2() as usize;
    let role = profile.specification().roles.get(2)?;
    let helper = profile.specification().roles.get(3)?;
    if role.width != width
        || role.num_vars != variables
        || helper.width != pp.helper.width()
        || helper.num_vars != pp.helper.num_vars()
        || pp.helper.context().ok()? != expected_helper
        || pp.helper.num_vars() != variables.checked_add(width.ilog2() as usize)?
        || ![width, EF::D].contains(&pp.helper.width())
        || accumulator.len() != 2 * n
        || output_a.len() != cfg.output_dimension()
    {
        return None;
    }
    let digits = cfg.digits::<F>().ok()?;
    if key.roots().len() != digits
        || coefficients.len() != digits + 1
        || evaluations.len() != digits + 1
    {
        return None;
    }
    for p in [
        pp.coefficients,
        pp.evaluations,
        pp.key,
        pp.input,
        pp.borrows,
    ] {
        if p.width() != width || p.num_vars() != variables || p.context().ok()? != expected_context
        {
            return None;
        }
    }
    crate::packed_key_switch::canonical::public_oracles::<F, Sha512, P>(pp.key, key).ok()?;
    let contexts = [
        pp.coefficients,
        pp.evaluations,
        pp.key,
        pp.input,
        pp.borrows,
        pp.helper,
    ]
    .iter()
    .map(|p| p.context().ok())
    .collect::<Option<Vec<_>>>()?;
    let accumulator = pp.coefficients.normalize_values(accumulator.to_vec());
    let output_a = pp.coefficients.normalize_values(output_a.to_vec());
    let output_b = pp.coefficients.normalize_values(vec![output_b])[0];
    let mut bytes = Vec::new();
    frame(
        &mut bytes,
        1,
        b"canonical shared-comparison final key switch v1",
        &[],
    );
    frame(
        &mut bytes,
        1,
        b"packed canonical backend original key switch v1",
        &encoded(&(
            key,
            EF::D,
            contexts,
            accumulator,
            output_a,
            output_b,
            coefficients,
            evaluations,
            input,
        )),
    );
    Some(bytes)
}

fn exercise<F, EF, P>(
    bundle: ProfileParameters<P>,
    wrong_bundle: ProfileParameters<P>,
    n: usize,
    lwe: usize,
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let profile = bundle.profile();
    let pp = super::super::super::classical::parameters(&bundle);
    let cfg = crate::packed_key_switch::Config::new::<F>(n, lwe, 5, 1).unwrap();
    let digits = cfg.digits::<F>().unwrap();
    let roots = (0..digits)
        .map(|i| Commitment {
            root: Digest512([u8::try_from(i + 31).unwrap(); 64]),
        })
        .collect();
    let key = final_protocol::audit::expected_key::<F, Sha512, P>(pp.final_stage.key, cfg, roots)
        .unwrap();
    let co = (0..=digits)
        .map(|i| Commitment {
            root: Digest512([u8::try_from(i + 61).unwrap(); 64]),
        })
        .collect::<Vec<_>>();
    let ev = (0..=digits)
        .map(|i| Commitment {
            root: Digest512([u8::try_from(i + 91).unwrap(); 64]),
        })
        .collect::<Vec<_>>();
    let input = Commitment {
        root: Digest512([127; 64]),
    };
    let accumulator = (0..2 * n).map(|i| F::from(i + 17)).collect::<Vec<_>>();
    let output_a = (0..lwe).map(|i| F::from(i + 23)).collect::<Vec<_>>();
    let output_b = F::one();
    let expected = binding::<F, EF, P>(
        profile,
        &pp.final_stage,
        &key,
        &accumulator,
        &output_a,
        output_b,
        &co,
        &ev,
        &input,
    )
    .unwrap();
    let wrong_helper = &wrong_bundle.roles()[3];
    assert_eq!(wrong_helper.width(), pp.final_stage.helper.width());
    assert_eq!(wrong_helper.num_vars(), pp.final_stage.helper.num_vars());
    assert_ne!(
        wrong_helper.context().ok().unwrap(),
        pp.final_stage.helper.context().ok().unwrap()
    );
    let mixed = final_protocol::Parameters {
        coefficients: pp.final_stage.coefficients,
        evaluations: pp.final_stage.evaluations,
        key: pp.final_stage.key,
        input: pp.final_stage.input,
        borrows: pp.final_stage.borrows,
        helper: wrong_helper,
    };
    assert!(
        binding::<F, EF, P>(
            profile,
            &mixed,
            &key,
            &accumulator,
            &output_a,
            output_b,
            &co,
            &ev,
            &input
        )
        .is_none()
    );
    let mut transcript = profile.parent_transcript::<F>().unwrap();
    final_protocol::audit::bind_shared::<F, EF, Sha512, P>(
        &mut transcript,
        &pp.final_stage,
        &key,
        &accumulator,
        &output_a,
        output_b,
        &co,
        &ev,
        &input,
    )
    .unwrap();
    let mut bytes = initial_header::<F>(profile).unwrap();
    bytes.extend(&expected);
    frame(
        &mut bytes,
        2,
        b"final key-switch binding replay",
        &64u64.to_le_bytes(),
    );
    let mut actual = [0; 64];
    transcript.get_challenge_bytes(b"final key-switch binding replay", &mut actual);
    assert_eq!(actual, shake64(&bytes));
    super::key_switch_extraction_audit::exercise::<F, EF, P>(
        profile, pp.final_stage.coefficients, &key, &accumulator, &output_a, output_b,
    );
    exercise_public_input::<F, EF, P>(
        profile,
        &pp.final_stage,
        &key,
        &accumulator,
        &output_a,
        output_b,
        &co,
        &ev,
        &input,
        &expected,
    );
    assert!(
        binding::<F, EF, P>(
            profile,
            &pp.final_stage,
            &key,
            &accumulator[..accumulator.len() - 1],
            &output_a,
            output_b,
            &co,
            &ev,
            &input
        )
        .is_none()
    );
    assert!(
        binding::<F, EF, P>(
            profile,
            &pp.final_stage,
            &key,
            &accumulator,
            &output_a[..output_a.len() - 1],
            output_b,
            &co,
            &ev,
            &input
        )
        .is_none()
    );
    assert!(
        binding::<F, EF, P>(
            profile,
            &pp.final_stage,
            &key,
            &accumulator,
            &output_a,
            output_b,
            &co[..digits],
            &ev,
            &input
        )
        .is_none()
    );
    let mut changed = accumulator.clone();
    changed[0] += F::one();
    assert_ne!(
        expected,
        binding::<F, EF, P>(
            profile,
            &pp.final_stage,
            &key,
            &changed,
            &output_a,
            output_b,
            &co,
            &ev,
            &input
        )
        .unwrap()
    );
    assert_ne!(
        expected,
        binding::<F, EF, P>(
            profile,
            &pp.final_stage,
            &key,
            &accumulator,
            &output_a,
            output_b + F::one(),
            &co,
            &ev,
            &input
        )
        .unwrap()
    );
    assert_ne!(
        expected,
        binding::<F, EF, P>(
            profile,
            &pp.final_stage,
            &key,
            &accumulator,
            &output_a,
            output_b,
            &ev,
            &co,
            &input
        )
        .unwrap()
    );
    println!(
        "HB_FINAL_KEY_BINDING prime={} degree={} n={} lwe={} version={} backend={:?} accepted_prefix=false",
        F::MODULUS_VALUE,
        EF::D,
        n,
        lwe,
        profile.version(),
        profile.specification().backend
    );
}

fn exercise_public_input<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &final_protocol::Parameters<'_, P>,
    key: &ExpectedKey<Digest512>,
    accumulator: &[F],
    output_a: &[F],
    output_b: F,
    coefficients: &[Commitment<Digest512>],
    evaluations: &[Commitment<Digest512>],
    input: &Commitment<Digest512>,
    binding: &[u8],
) where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let n = key.config().polynomial_size();
    let width = pp.input.width();
    let reference = (0..2 * n).map(|i| -accumulator[i % n]).collect::<Vec<_>>();
    let mut production = profile.parent_transcript::<F>().unwrap();
    final_protocol::audit::bind_shared::<F, EF, Sha512, P>(
        &mut production,
        pp,
        key,
        accumulator,
        output_a,
        output_b,
        coefficients,
        evaluations,
        input,
    )
    .unwrap();
    let (table, query) = final_protocol::audit::public_input::<F, Sha512, P>(
        &mut production,
        pp.input,
        key,
        accumulator,
        input,
    )
    .unwrap();
    assert_eq!(encoded(&reference), encoded(&table.values().to_vec()));
    assert_eq!(query.len(), pp.input.num_vars());
    let mut bytes = initial_header::<F>(profile).unwrap();
    bytes.extend(binding);
    frame(
        &mut bytes,
        1,
        b"canonical key-switch known input v1",
        &encoded(&(
            pp.input.context().ok().unwrap(),
            input,
            pp.input.normalize_values(reference.clone()),
        )),
    );
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    for pair in &query {
        frame(&mut bytes, 1, b"typed request kind", b"vector");
        frame(&mut bytes, 1, b"field challenge kind", b"prime vector");
        let mut descriptor = p.to_le_bytes().to_vec();
        descriptor.extend((width as u64).to_le_bytes());
        frame(
            &mut bytes,
            4,
            b"canonical key-switch public input challenges",
            &descriptor,
        );
        let (coins, raw) = raw_prime_phase::<F>(&bytes, width);
        let coins = coins
            .into_iter()
            .map(|v| F::from(usize::try_from(v).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            encoded(pair),
            encoded(&sumcheck::packed::challenge_pair(&coins).unwrap())
        );
        frame(
            &mut bytes,
            5,
            b"canonical key-switch public input challenges",
            &receipt(&raw).0,
        );
    }
    frame(
        &mut bytes,
        2,
        b"final public input replay",
        &64u64.to_le_bytes(),
    );
    let mut actual = [0; 64];
    production.get_challenge_bytes(b"final public input replay", &mut actual);
    assert_eq!(actual, shake64(&bytes));
    // Independent dense contraction of the public table, retaining little-endian
    // Boolean order and forward matrix action on column vectors.
    let mut values = reference.clone();
    for pair in &query {
        let mut next = vec![F::zero(); values.len() / 2];
        for (index, out) in next.chunks_exact_mut(width).enumerate() {
            for row in 0..width {
                for col in 0..width {
                    out[row] += pair.zero.values()[row * width + col]
                        * values[2 * index * width + col]
                        + pair.one.values()[row * width + col]
                            * values[(2 * index + 1) * width + col];
                }
            }
        }
        values = next;
    }
    assert_eq!(
        encoded(&pp.input.normalize_values(values)),
        encoded(&pp.input.normalize_values(table.evaluate(&query).unwrap()))
    );
    let mut changed = accumulator.to_vec();
    changed[n] += F::one();
    let mut isolated = profile.parent_transcript::<F>().unwrap();
    let (changed_table, _) = final_protocol::audit::public_input::<F, Sha512, P>(
        &mut isolated,
        pp.input,
        key,
        &changed,
        input,
    )
    .unwrap();
    assert_eq!(
        encoded(&reference),
        encoded(&changed_table.values().to_vec())
    );
    changed[0] += F::one();
    let mut isolated = profile.parent_transcript::<F>().unwrap();
    let (changed_table, _) = final_protocol::audit::public_input::<F, Sha512, P>(
        &mut isolated,
        pp.input,
        key,
        &changed,
        input,
    )
    .unwrap();
    assert_ne!(
        encoded(&reference),
        encoded(&changed_table.values().to_vec())
    );
    println!(
        "HB_FINAL_PUBLIC_INPUT prime={} degree={} n={} lwe={} version={} backend={:?} phases={} source_opening_authenticated=false",
        F::MODULUS_VALUE,
        EF::D,
        n,
        key.config().output_dimension(),
        profile.version(),
        profile.specification().backend,
        query.len()
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
                let spec = Specification {
                    backend,
                    roles: cfg.variables(8).unwrap().map(|num_vars| Role {
                        num_vars,
                        width: 8,
                        queries: 8,
                        left_vars: (backend == Backend::Brakedown).then_some(num_vars / 2),
                        block_width: (backend == Backend::Brakedown).then_some(8),
                    }),
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
                let mut wrong_spec = profile.specification().clone();
                wrong_spec.roles[3].queries += 1;
                let wrong_profile = if version == 4 {
                    ClassicalProfile::new_atomic_zerocheck::<F, EF>(wrong_spec)
                } else {
                    ClassicalProfile::new_atomic_columns::<F, EF>(wrong_spec)
                }
                .unwrap();
                match backend {
                    Backend::Brakedown => exercise::<F, EF, _>(
                        profile.brakedown_parameters::<F, EF>().unwrap(),
                        wrong_profile.brakedown_parameters::<F, EF>().unwrap(),
                        n,
                        lwe,
                    ),
                    Backend::Polyfrim => exercise::<F, EF, _>(
                        profile.polyfrim_parameters::<F, EF>().unwrap(),
                        wrong_profile.polyfrim_parameters::<F, EF>().unwrap(),
                        n,
                        lwe,
                    ),
                    Backend::PolyfrimDictionary => exercise::<F, EF, _>(
                        profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
                        wrong_profile
                            .polyfrim_dictionary_parameters::<F, EF>()
                            .unwrap(),
                        n,
                        lwe,
                    ),
                    Backend::FragmentedPipfri => exercise::<F, EF, _>(
                        profile.fragmented_parameters::<F, EF>().unwrap(),
                        wrong_profile.fragmented_parameters::<F, EF>().unwrap(),
                        n,
                        lwe,
                    ),
                    Backend::FragmentedPipfriVirtual => exercise::<F, EF, _>(
                        profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
                        wrong_profile
                            .fragmented_virtual_parameters::<F, EF>()
                            .unwrap(),
                        n,
                        lwe,
                    ),
                }
            }
        }
    }
}

#[test]
fn final_key_switch_public_binding() {
    field::<algebra::BabyBear, algebra::BabyBearExtension6>();
    field::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
