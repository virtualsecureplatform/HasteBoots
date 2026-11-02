//! Accepted final-stage control with nonzero synthetic public switching keys.
use super::*;
use crate::packed_key_switch::{self as switching, canonical as key_setup};
use key_setup::protocol::{self, shared};

fn exercise<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, EventHash>,
    <P as CanonicalPcs<F, Sha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, Sha512>>::BatchProof: DeserializeOwned,
{
    let profile = bundle.profile();
    let parameters = crate::packed_pbs::canonical::classical::parameters(&bundle);
    let pp = &parameters.final_stage;
    let (n, lwe, width, variables): (usize, usize, usize, usize) = (32, 21, 8, 3);
    F::init_ntt_table(n.ilog2()).unwrap();
    let capture = Arc::new(Mutex::new(Capture::default()));
    {
        let mut active = ACTIVE.lock().unwrap();
        assert!(active.is_none());
        *active = Some(Arc::clone(&capture));
    }
    let hash_guard = CaptureGuard;
    let observed = Arc::clone(&capture);
    let xof_guard = helper::classical_transcript::audit::observe(move |input| {
        let mut capture = observed.lock().unwrap();
        capture.history.declare_input(input);
        capture.events.push(Event::Xof(input.to_vec()));
    })
    .unwrap();
    let cfg = switching::Config::new::<F>(n, lwe, 5, 1).unwrap();
    let digits = cfg.digits::<F>().unwrap();
    let mut native = lattice::NTTGadgetRLWE::<F>::zero(n, algebra::Basis::new(5));
    // Constant NTT vectors represent nonzero constant coefficient polynomials.
    for (j, polynomial) in native.iter_mut().enumerate() {
        polynomial.a_mut_slice().fill(F::from(j + 1));
        polynomial.b_mut_slice().fill(F::from(j + 3));
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(14929);
    let key =
        key_setup::preprocess::<F, EventHash, P, _>(pp.key, cfg, &[native], &mut rng).unwrap();
    let accumulator = (0..2 * n).map(|i| F::from(i + 17)).collect::<Vec<_>>();
    // Retain the canonical negative-a digits; independently replace the helper's
    // zero-product placeholder by the product of these nonzero public keys.
    let mut coefficients =
        protocol::audit::zero_key_coefficients::<F, EventHash, P>(pp, key.expected(), &accumulator)
            .unwrap();
    let mut product = vec![F::zero(); 2 * n];
    for j in 0..digits {
        for i in 0..n {
            product[i] += coefficients[j].values()[i] * F::from(j + 1);
            product[n + i] += coefficients[j].values()[n + i] * F::from(j + 3);
        }
    }
    assert!(product.iter().any(|&v| v != F::zero()));
    let a = (0..lwe)
        .map(|i| if i == 0 { product[0] } else { -product[n - i] })
        .collect::<Vec<_>>();
    let characteristic: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let b = product[n] + accumulator[n] + F::from(usize::try_from(characteristic / 8).unwrap());
    coefficients[digits] = PackedTable::new(variables, width, product).unwrap();
    let mut prover = profile.parent_transcript::<F>().unwrap();
    let proof = shared::prove::<F, EF, EventHash, P, _>(
        &mut prover,
        pp,
        &key,
        &accumulator,
        &a,
        b,
        &coefficients,
        &mut rng,
    )
    .unwrap();
    let bytes = encoded(&proof);
    let mut prover_finish = [0; 64];
    prover.get_challenge_bytes(
        b"observed final key-switch continuation",
        &mut prover_finish,
    );
    let start = capture.lock().unwrap().events.len();
    let mut verifier = profile.parent_transcript::<F>().unwrap();
    shared::verify::<F, EF, EventHash, P>(
        &mut verifier,
        pp,
        key.expected(),
        &accumulator,
        &a,
        b,
        &proof,
    )
    .unwrap();
    let end = capture.lock().unwrap().events.len();
    let mut verifier_finish = [0; 64];
    verifier.get_challenge_bytes(
        b"observed final key-switch continuation",
        &mut verifier_finish,
    );
    assert_eq!(prover_finish, verifier_finish);
    drop(xof_guard);
    drop(hash_guard);
    let (decoded, used): (
        shared::Proof<
            F,
            EF,
            Digest512,
            <P as CanonicalPcs<F, Sha512>>::SingleProof,
            <P as CanonicalPcs<F, Sha512>>::BatchProof,
        >,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut normal = profile.parent_transcript::<F>().unwrap();
    shared::verify::<F, EF, Sha512, P>(
        &mut normal,
        pp,
        key.expected(),
        &accumulator,
        &a,
        b,
        &decoded,
    )
    .unwrap();
    let mut finish = [0; 64];
    normal.get_challenge_bytes(b"observed final key-switch continuation", &mut finish);
    assert_eq!(finish, verifier_finish);
    let mut audit = profile.parent_transcript::<F>().unwrap();
    let (valid, claims) = protocol::audit::verify_shared_queries::<F, EF, Sha512, P>(
        &mut audit,
        pp,
        key.expected(),
        &accumulator,
        &a,
        b,
        &decoded,
    )
    .unwrap();
    assert_eq!(valid, (true, true, [true; 3], true));
    audit.get_challenge_bytes(b"observed final key-switch continuation", &mut finish);
    assert_eq!(finish, verifier_finish);
    assert_eq!(capture.lock().unwrap().events.len(), end + 1);

    let capture = capture.lock().unwrap();
    let mut replay = classical_history::History::default();
    for event in &capture.events {
        match event {
            Event::Hash(output, input) => {
                assert_eq!(*output, Digest512(Sha512::digest(input).into()));
                replay.expose(*output, input.clone());
            }
            Event::Xof(input) => replay.declare_input(input),
        }
    }
    assert_eq!(replay.events(), capture.events.len());
    assert_eq!(replay.hash_queries(), capture.history.hash_queries());
    assert_eq!(replay.xof_queries(), capture.history.xof_queries());
    assert_eq!(
        replay.availability_hits(),
        capture.history.availability_hits()
    );
    for root in [&decoded.input, &decoded.coefficients[digits]] {
        assert_eq!(
            capture.history.view(root.root).unwrap().as_ref(),
            replay.view(root.root).unwrap().as_ref()
        );
    }
    let bindings = expected_child_bindings::<F, EF, P>(
        profile,
        pp,
        key.expected(),
        &decoded,
        &claims,
        &accumulator,
    );
    let mut bound = 0;
    let temporal = super::temporal_child_audit::check_with_seed::<F, EF>(
        profile,
        &capture.events,
        start..end,
        |parent, label, context| {
            let Some((_, expected_label, expected_context)) =
                pcs_child_labels(profile.specification().backend)
            else {
                return;
            };
            if label != expected_label {
                return;
            } // The lookup child has its own body interpreter.
            assert_eq!(context, expected_context);
            let (helper, expected, count) = &bindings[bound];
            let parameters = if *helper { pp.helper } else { pp.coefficients };
            let parsed =
                ordered_claim_audit::decode::<F, P>(profile, parameters, parent, *count).unwrap();
            let (replayed, _) = super::monomial_event_audit::claim_seed_tail::<F, P>(
                profile,
                parameters,
                &parsed.root,
                &parsed.queries,
                &parsed.values,
            );
            assert_eq!(&replayed, expected);
            assert!(parent.ends_with(expected));
            bound += 1;
        },
    );
    assert_eq!(bound, bindings.len());
    println!(
        "HB_FINAL_KEY_CHILD_CLAIMS {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"bound_openings\":{},\"nested_claim_counts_preflighted\":true,\"full_pbs_trace\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        bound
    );
    println!(
        "HB_FINAL_KEY_TEMPORAL_ORIGINS {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"verifier_child_queries\":{},\"unique_child_seeds\":{},\"initial_identity_queries\":{},\"all_input_windows_registered\":true,\"availability_hits\":0,\"output_collisions\":0,\"full_pbs_trace\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        temporal.0,
        temporal.1,
        temporal.2
    );
    let (
        ntt_source_claims,
        product_source_claims,
        decomposition_source_claims,
        lookup_source_claims,
        lookup_helper_claims,
    ) = assert_source_words::<F, EF, P>(
        profile,
        pp,
        key.expected(),
        &decoded,
        &claims,
        |root| capture.history.view(root),
        &accumulator,
        &a,
        b,
        true,
    );
    let hashes = capture.events[start..end]
        .iter()
        .filter(|e| matches!(e, Event::Hash(..)))
        .count();
    println!(
        "HB_FINAL_KEY_EVENT_TRACE {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"n\":{},\"lwe\":{},\"proof_bytes\":{},\"verifier_hash_queries\":{},\"verifier_xof_queries\":{},\"nonzero_key\":true,\"frozen_input_and_extraction_match\":true,\"ntt_source_claims\":{},\"product_source_claims\":{},\"decomposition_source_claims\":{},\"lookup_source_claims\":{},\"lookup_helper_claims\":{},\"full_pbs_trace\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        n,
        lwe,
        bytes.len(),
        hashes,
        end - start - hashes,
        ntt_source_claims,
        product_source_claims,
        decomposition_source_claims,
        lookup_source_claims,
        lookup_helper_claims
    );
}

fn expected_child_bindings<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &protocol::Parameters<'_, P>,
    key: &switching::ExpectedKey<Digest512>,
    proof: &shared::Proof<F, EF, Digest512, P::SingleProof, P::BatchProof>,
    claims: &protocol::audit::FinalQueries<F>,
    accumulator: &[F],
) -> Vec<(bool, Vec<u8>, usize)>
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    if profile.specification().backend == Backend::Brakedown {
        return Vec::new();
    }
    let context = pp.coefficients.context().ok().unwrap();
    for source in [pp.evaluations, pp.key, pp.input, pp.borrows] {
        assert_eq!(source.context().ok().unwrap(), context);
    }
    let mut result = Vec::new();
    let mut push = |helper: bool,
                    root: &Commitment<Digest512>,
                    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
                    values: &[Vec<F>]| {
        let parameters = if helper { pp.helper } else { pp.coefficients };
        let (tail, count) = super::monomial_event_audit::claim_seed_tail::<F, P>(
            profile, parameters, root, queries, values,
        );
        result.push((helper, tail, count));
    };
    let n = key.config().polynomial_size();
    let digits = key.config().digits::<F>().unwrap();
    let input = PackedTable::new(
        pp.input.num_vars(),
        pp.input.width(),
        (0..2 * n).map(|i| -accumulator[i % n]).collect(),
    )
    .unwrap();
    push(
        false,
        &proof.input,
        &[claims.input.clone()],
        &[pp.input
            .normalize_values(input.evaluate(&claims.input).unwrap())],
    );
    for (i, (queries, co, ev)) in claims.ntt.iter().enumerate() {
        push(false, &proof.coefficients[i], queries, co);
        push(false, &proof.evaluations[i], queries, ev);
    }
    for (i, value) in proof.product.values.iter().enumerate() {
        let root = if i == 2 * digits {
            &proof.evaluations[digits]
        } else if i % 2 == 0 {
            &proof.evaluations[i / 2]
        } else {
            &key.roots()[i / 2]
        };
        push(
            false,
            root,
            &[claims.product.query.clone()],
            &[value.clone()],
        );
    }
    let linear_roots = std::iter::once(&proof.input)
        .chain(proof.coefficients.iter().take(digits))
        .chain(&proof.decomposition.borrow_commitments);
    for ((root, query), value) in linear_roots
        .zip(&claims.decomposition)
        .zip(&proof.decomposition.linear.values)
    {
        push(false, root, &[query.clone()], &[value.clone()]);
    }
    let lookup = claims.lookup.as_ref().unwrap();
    let comparison = &proof.decomposition.comparisons;
    for (root, value) in comparison.helper_roots.iter().zip(&lookup.helper_values) {
        push(true, root, &[lookup.helper_query.clone()], &[value.clone()]);
    }
    let mut seen = std::collections::HashSet::new();
    for (i, root) in proof
        .coefficients
        .iter()
        .take(digits)
        .chain(&proof.decomposition.borrow_commitments)
        .enumerate()
    {
        if lookup.used[i] && seen.insert(root.root) {
            push(
                false,
                root,
                &[lookup.source_query.clone()],
                &[comparison.source_values[i].clone()],
            );
        }
    }
    push(
        false,
        &proof.coefficients[digits],
        &[claims.extraction.query.clone()],
        &[proof.extraction.value.clone()],
    );
    result
}

/// Match final-stage accepted claims against immutable first-declaration words.
/// The caller supplies the actual entry transcript's verifier obligations.
pub(super) fn assert_source_words<F, EF, P>(
    profile: &ClassicalProfile,
    pp: &protocol::Parameters<'_, P>,
    key: &switching::ExpectedKey<Digest512>,
    decoded: &shared::Proof<F, EF, Digest512, P::SingleProof, P::BatchProof>,
    claims: &protocol::audit::FinalQueries<F>,
    mut view: impl FnMut(Digest512) -> Option<Arc<FrozenWordView>>,
    accumulator: &[F],
    a: &[F],
    b: F,
    require_nonzero: bool,
) -> (usize, usize, usize, usize, usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let n = key.config().polynomial_size();
    let lwe = key.config().output_dimension();
    let digits = key.config().digits::<F>().unwrap();
    let variables = pp.coefficients.num_vars();
    let width = pp.coefficients.width();
    let context = <P as CanonicalPcs<F, Sha512>>::context(pp.coefficients)
        .ok()
        .unwrap();
    let sources = vec![
        (context, decoded.input.clone()),
        (context, decoded.coefficients[digits].clone()),
    ];
    let queries = vec![claims.input.clone(), claims.extraction.query.clone()];
    let mut calls = 0;
    assert!(
        monomial_word_audit::values_many_for_role::<F, EF, P>(
            monomial_word_audit::SourceRole::Main,
            profile,
            pp.coefficients,
            &sources,
            &queries,
            |_| {
                calls += 1;
                None
            },
        )
        .is_none()
    );
    assert_eq!(calls, 0);
    let (promises, assigned) = monomial_word_audit::values_many_for_role::<F, EF, P>(
        monomial_word_audit::SourceRole::Final,
        profile,
        pp.coefficients,
        &sources,
        &queries,
        |source| view(source.1.root),
    )
    .unwrap();
    assert!(promises.iter().all(|&p| p));
    let mut ntt_source_claims = 0;
    assert_eq!(claims.ntt.len(), digits + 1);
    for (component, (queries, co, ev)) in claims.ntt.iter().enumerate() {
        let sources = vec![
            (context, decoded.coefficients[component].clone()),
            (context, decoded.evaluations[component].clone()),
        ];
        let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
            monomial_word_audit::SourceRole::Final,
            profile,
            pp.coefficients,
            &sources,
            queries,
            |source| view(source.1.root),
        )
        .unwrap();
        assert!(promises.iter().all(|&p| p));
        for (source, expected) in [(0, co), (1, ev)] {
            assert_eq!(values[source].len(), expected.len());
            for (value, expected) in values[source].iter().zip(expected) {
                assert_eq!(
                    encoded(value),
                    encoded(&<P as CanonicalPcs<F, Sha512>>::normalize_values(
                        pp.coefficients,
                        expected.clone()
                    ))
                );
                ntt_source_claims += 1;
            }
        }
    }
    assert_eq!(ntt_source_claims, (digits + 1) * 2 * width);
    // Product factors alternate digit evaluations and trusted public key words;
    // the last factor is the product evaluation. Resolve every factor using its
    // own first-declaration view, including setup key commitments.
    let mut product_source_claims = 0;
    let mut product_values = Vec::new();
    for (index, expected) in decoded.product.values.iter().enumerate() {
        let root = if index == 2 * digits {
            &decoded.evaluations[digits]
        } else if index % 2 == 0 {
            &decoded.evaluations[index / 2]
        } else {
            &key.roots()[index / 2]
        };
        let sources = vec![(context, root.clone()), (context, root.clone())];
        let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
            monomial_word_audit::SourceRole::Final,
            profile,
            pp.evaluations,
            &sources,
            &[claims.product.query.clone()],
            |source| view(source.1.root),
        )
        .unwrap();
        assert!(promises.iter().all(|&p| p));
        assert_eq!(encoded(&values[0][0]), encoded(expected));
        product_values.push(values[0][0].clone());
        product_source_claims += 1;
    }
    assert_eq!(product_source_claims, 2 * digits + 1);
    // Independent terminal equation: sum digit_j * key_j - product.
    // Use the assigned values rather than the proof's copied terminal values.
    assert_eq!(claims.product.equality.len(), width);
    assert_eq!(claims.product.expected.len(), width);
    for lane in 0..width {
        let sum = (0..digits).fold(F::zero(), |sum, digit| {
            sum + product_values[2 * digit][lane] * product_values[2 * digit + 1][lane]
        });
        assert_eq!(
            (sum - product_values[2 * digits][lane]) * claims.product.equality[lane],
            claims.product.expected[lane],
        );
    }
    let linear_roots = std::iter::once(&decoded.input)
        .chain(decoded.coefficients.iter().take(digits))
        .chain(&decoded.decomposition.borrow_commitments)
        .collect::<Vec<_>>();
    assert_eq!(linear_roots.len(), 2 * digits + 2);
    assert_eq!(claims.decomposition.len(), linear_roots.len());
    assert_eq!(
        decoded.decomposition.linear.values.len(),
        linear_roots.len()
    );
    let mut decomposition_source_claims = 0;
    for ((root, query), expected) in linear_roots
        .iter()
        .zip(&claims.decomposition)
        .zip(&decoded.decomposition.linear.values)
    {
        let sources = vec![(context, (*root).clone()), (context, (*root).clone())];
        let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
            monomial_word_audit::SourceRole::Final,
            profile,
            pp.coefficients,
            &sources,
            &[query.clone()],
            |source| view(source.1.root),
        )
        .unwrap();
        assert!(promises.iter().all(|&p| p));
        assert_eq!(encoded(&values[0][0]), encoded(expected));
        decomposition_source_claims += 1;
    }
    assert_eq!(decomposition_source_claims, 2 * digits + 2);
    let lookup = claims.lookup.as_ref().expect("shared lookup obligations");
    let comparison = &decoded.decomposition.comparisons;
    let registry = decoded
        .coefficients
        .iter()
        .take(digits)
        .chain(&decoded.decomposition.borrow_commitments)
        .collect::<Vec<_>>();
    assert_eq!(registry.len(), lookup.used.len());
    assert_eq!(registry.len(), comparison.source_values.len());
    let mut lookup_source_claims = 0;
    for (index, root) in registry.iter().enumerate() {
        if !lookup.used[index] {
            continue;
        }
        let sources = vec![(context, (*root).clone()), (context, (*root).clone())];
        let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
            monomial_word_audit::SourceRole::Final,
            profile,
            pp.coefficients,
            &sources,
            &[lookup.source_query.clone()],
            |source| view(source.1.root),
        )
        .unwrap();
        assert!(promises.iter().all(|&p| p));
        assert_eq!(
            encoded(&values[0][0]),
            encoded(&comparison.source_values[index])
        );
        lookup_source_claims += 1;
    }
    assert_eq!(comparison.helper_roots.len(), lookup.helper_values.len());
    let helper_context = <P as CanonicalPcs<F, Sha512>>::context(pp.helper)
        .ok()
        .unwrap();
    let mut lookup_helper_claims = 0;
    for (root, expected) in comparison.helper_roots.iter().zip(&lookup.helper_values) {
        let sources = vec![
            (helper_context, root.clone()),
            (helper_context, root.clone()),
        ];
        let (promises, values) = monomial_word_audit::values_many_for_role::<F, EF, P>(
            monomial_word_audit::SourceRole::FinalHelper,
            profile,
            pp.helper,
            &sources,
            &[lookup.helper_query.clone()],
            |source| view(source.1.root),
        )
        .unwrap();
        assert!(promises.iter().all(|&p| p));
        assert_eq!(encoded(&values[0][0]), encoded(expected));
        lookup_helper_claims += 1;
    }
    assert!(lookup_source_claims > 0 && lookup_helper_claims > 0);
    let public_input = PackedTable::new(
        variables,
        width,
        (0..2 * n).map(|i| -accumulator[i % n]).collect(),
    )
    .unwrap();
    assert_eq!(
        encoded(&assigned[0][0]),
        encoded(&<P as CanonicalPcs<F, Sha512>>::normalize_values(
            pp.input,
            public_input.evaluate(&claims.input).unwrap(),
        ))
    );
    assert_eq!(encoded(&assigned[1][1]), encoded(&decoded.extraction.value));
    if require_nonzero {
        assert!(assigned[1][1].iter().any(|&v| v != F::zero()));
    }
    let (mask, target) =
        key_switch_extraction_audit::reference(n, lwe, &accumulator, &a, b).unwrap();
    let mask = PackedTable::new(variables, width, mask)
        .unwrap()
        .evaluate(&claims.extraction.query)
        .unwrap();
    let target = PackedTable::new(variables, width, target)
        .unwrap()
        .evaluate(&claims.extraction.query)
        .unwrap();
    for lane in 0..width {
        assert_eq!(
            (assigned[1][1][lane] * mask[lane] - target[lane]) * claims.extraction.equality[lane],
            claims.extraction.expected[lane]
        );
    }
    (
        ntt_source_claims,
        product_source_claims,
        decomposition_source_claims,
        lookup_source_claims,
        lookup_helper_claims,
    )
}

fn field<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    for version in [4, 5] {
        for backend in [
            Backend::Brakedown,
            Backend::Polyfrim,
            Backend::PolyfrimDictionary,
            Backend::FragmentedPipfri,
            Backend::FragmentedPipfriVirtual,
        ] {
            let specification = Specification {
                backend,
                roles: cfg.variables(8).unwrap().map(|num_vars| Role {
                    num_vars,
                    width: 8,
                    queries: 8,
                    left_vars: (backend == Backend::Brakedown).then_some(num_vars / 2),
                    block_width: (backend == Backend::Brakedown).then_some(2),
                }),
                blowup: 2,
                fragment_vars: matches!(
                    backend,
                    Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
                )
                .then_some(4),
            };
            let profile = if version == 4 {
                ClassicalProfile::new_atomic_zerocheck::<F, EF>(specification)
            } else {
                ClassicalProfile::new_atomic_columns::<F, EF>(specification)
            }
            .unwrap();
            match backend {
                Backend::Brakedown => {
                    exercise::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap())
                }
                Backend::Polyfrim => {
                    exercise::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap())
                }
                Backend::PolyfrimDictionary => {
                    exercise::<F, EF, _>(profile.polyfrim_dictionary_parameters::<F, EF>().unwrap())
                }
                Backend::FragmentedPipfri => {
                    exercise::<F, EF, _>(profile.fragmented_parameters::<F, EF>().unwrap())
                }
                Backend::FragmentedPipfriVirtual => {
                    exercise::<F, EF, _>(profile.fragmented_virtual_parameters::<F, EF>().unwrap())
                }
            }
        }
    }
}

#[test]
fn production_final_key_switch_source_words() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    field::<algebra::BabyBear, algebra::BabyBearExtension6>();
    field::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn production_final_key_switch_ntt_words_focused() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    type F = algebra::BabyBear;
    type EF = algebra::BabyBearExtension6;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
        backend: Backend::Brakedown,
        roles: cfg.variables(8).unwrap().map(|num_vars| Role {
            num_vars,
            width: 8,
            queries: 8,
            left_vars: Some(num_vars / 2),
            block_width: Some(2),
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    exercise::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap());
}

#[test]
fn production_final_key_child_claim_bindings_smoke() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    type F = algebra::BabyBear;
    type EF = algebra::BabyBearExtension6;
    let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let profile = ClassicalProfile::new_atomic_columns::<F, EF>(Specification {
        backend: Backend::Polyfrim,
        roles: cfg.variables(8).unwrap().map(|num_vars| Role {
            num_vars,
            width: 8,
            queries: 8,
            left_vars: None,
            block_width: None,
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    exercise::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap());
}
