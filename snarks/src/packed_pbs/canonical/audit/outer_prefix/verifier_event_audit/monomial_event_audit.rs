//! Accepted monomial controls and actual first-declaration evaluation words.
use super::*;
use crate::packed_monomial::canonical as monomial;

pub(super) fn claim_seed_tail<F, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    root: &Commitment<Digest512>,
    queries: &[Vec<algebra::matrix_weighted::MatrixPair<F>>],
    values: &[Vec<F>],
) -> (Vec<u8>, usize)
where
    F: NTTField + Serialize,
    P: CanonicalPcs<F, Sha512>,
{
    assert_eq!(queries.len(), values.len());
    let (binding, label, context) = pcs_child_labels(profile.specification().backend).unwrap();
    let (mut queries, mut values) = (queries.to_vec(), values.to_vec());
    if matches!(
        profile.specification().backend,
        Backend::Polyfrim | Backend::PolyfrimDictionary
    ) {
        for (query, value) in queries.iter_mut().zip(&mut values) {
            (*query, *value) = parameters
                .normalize_claim(query.clone(), value.clone())
                .ok()
                .unwrap();
        }
    }
    let mut tail = Vec::new();
    frame(
        &mut tail,
        1,
        binding,
        &encoded(&(parameters.context().ok().unwrap(), root, &queries, &values)),
    );
    frame(&mut tail, 6, label, context);
    frame(&mut tail, 2, b"classical child seed", &64u64.to_le_bytes());
    (tail, queries.len())
}

fn temporal_child_views<F, EF, P>(
    profile: &ClassicalProfile,
    parameters: &P,
    events: &[Event],
    verifier: std::ops::Range<usize>,
    expected_bindings: &[(Vec<u8>, usize)],
    mut source_view: impl FnMut(Digest512) -> Option<Arc<FrozenWordView>>,
) -> (usize, usize, usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
{
    let mut history = classical_xof_history::History::default();
    let mut seen = std::collections::HashSet::<&[u8]>::new();
    let mut header = Vec::new();
    frame(
        &mut header,
        0,
        b"protocol",
        b"HasteBoots framed SHAKE256 v1",
    );
    frame(
        &mut header,
        0,
        b"application",
        b"HasteBoots framed SHAKE256 child v1",
    );
    frame(&mut header, 0, b"trusted profile", &profile.id().0);
    let empty_receipt = receipt(&[]).0;
    let empty_digest: [u8; 64] = empty_receipt[16..].try_into().unwrap();
    let mut identity_receipt_frame = Vec::new();
    frame(
        &mut identity_receipt_frame,
        5,
        b"typed extension identity",
        &empty_receipt,
    );
    let (mut checked, mut repeated_checked) = (0, 0);
    let mut bound_openings = std::collections::HashSet::new();
    for (index, event) in events.iter().enumerate() {
        let input = match event {
            Event::Hash(_, input) => {
                history.declare_external_input(input);
                continue;
            }
            Event::Xof(input) => input,
        };
        let repeated = !seen.insert(input.as_slice());
        let view = history.query(input, shake64(input)).unwrap();
        let Some(mut rest) = input.strip_prefix(header.as_slice()) else {
            continue;
        };
        let label = message(&mut rest, 1, b"child label").unwrap();
        let context = message(&mut rest, 1, b"child context").unwrap();
        let seed: [u8; 64] = message(&mut rest, 1, b"parent seed")
            .unwrap()
            .try_into()
            .unwrap();
        let identity = raw_child::<F, EF>(profile, label, context, &seed);
        let identity_request = identity
            .strip_suffix(identity_receipt_frame.as_slice())
            .unwrap();
        if input == identity_request {
            continue; // Initial zero-value identity, before its own receipt.
        }
        assert!(
            input.starts_with(&identity),
            "unexpected typed child initialization"
        );
        // The generic child interpreter needs these two producers only. Fetch
        // them from the temporal view rather than cloning the entire history.
        let mut before = Producers::new();
        for digest in [seed, empty_digest] {
            before.insert(digest, history.producer(&view, &digest).unwrap().to_vec());
        }
        let child = typed_child_prefix::<F, EF>(profile, input, &before).unwrap();
        let (parent_input, _) = history.producer_first_view(&view, &seed).unwrap();
        assert_eq!(child.parent_input, parent_input);
        assert_eq!(child.label, label);
        assert_eq!(child.context, context);
        if verifier.contains(&index) {
            if bound_openings.insert(seed) {
                let (expected, count) = expected_bindings.get(bound_openings.len() - 1).unwrap();
                let mut parsed =
                    ordered_claim_audit::decode::<F, P>(profile, parameters, parent_input, *count)
                        .unwrap();
                let frozen = source_view(parsed.root.root).unwrap();
                let task = ordered_claim_audit::fixed_task::<F, EF, P>(
                    monomial_word_audit::SourceRole::Main,
                    profile,
                    parameters,
                    &parsed,
                    &frozen,
                )
                .unwrap();
                assert!(!task.is_bad());
                let (replayed, _) = claim_seed_tail::<F, P>(
                    profile,
                    parameters,
                    &parsed.root,
                    &parsed.queries,
                    &parsed.values,
                );
                assert_eq!(&replayed, expected);
                assert!(
                    parent_input.ends_with(expected),
                    "PCS child source/ordered-claim binding mismatch"
                );
                // Syntax-valid changed values are a false task for this same
                // immutable word/query, not another permitted assignment.
                parsed.values[0][0] += F::one();
                let changed = ordered_claim_audit::fixed_task::<F, EF, P>(
                    monomial_word_audit::SourceRole::Main,
                    profile,
                    parameters,
                    &parsed,
                    &frozen,
                )
                .unwrap();
                assert!(changed.promised && changed.is_bad());
            }
            checked += 1;
            repeated_checked += usize::from(repeated);
        }
    }
    assert_eq!(history.availability_hits(), 0);
    assert_eq!(history.collisions(), 0);
    assert_eq!(bound_openings.len(), expected_bindings.len());
    assert_eq!(
        checked, repeated_checked,
        "verifier child requests must match the prover trace"
    );
    if profile.specification().backend == Backend::Brakedown {
        assert_eq!(checked, 0);
    } else {
        assert!(checked > 0);
    }
    (checked, repeated_checked, bound_openings.len())
}

fn exercise<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512> + CanonicalPcs<F, EventHash>,
    <P as CanonicalPcs<F, Sha512>>::SingleProof: DeserializeOwned,
    <P as CanonicalPcs<F, Sha512>>::BatchProof: DeserializeOwned,
{
    let profile = bundle.profile();
    let pp = super::super::super::super::classical::parameters(&bundle);
    let capture = Arc::new(Mutex::new(Capture::default()));
    {
        let mut active = ACTIVE.lock().unwrap();
        assert!(active.is_none());
        *active = Some(Arc::clone(&capture));
    }
    let hash_guard = CaptureGuard;
    let xof_capture = Arc::clone(&capture);
    let xof_guard = helper::classical_transcript::audit::observe(move |input| {
        let mut capture = xof_capture.lock().unwrap();
        capture.history.declare_input(input);
        capture.events.push(Event::Xof(input.to_vec()));
    })
    .unwrap();
    let (n, width, rounds, vars) = (32, 8, 3, 5);
    let plan = crate::packed_monomial::Plan::new(n, vec![1, n + 3, 2 * n - 1]).unwrap();
    let mut input = vec![F::zero(); width << vars];
    let mut output = input.clone();
    for half in 0..2 {
        for row in 0..plan.padded_rounds() {
            for i in 0..n {
                let base = (half * plan.padded_rounds() + row) * n;
                let value = F::from(i + 1 + 3 * row + 7 * half);
                input[base + i] = value;
                if let Some(&rotation) = plan.rotations().get(row) {
                    let shifted = i + rotation;
                    output[base + shifted % n] = if shifted / n % 2 == 0 { value } else { -value };
                }
            }
        }
    }
    let tables = [
        PackedTable::new(vars, width, input).unwrap(),
        PackedTable::new(vars, width, output).unwrap(),
    ];
    let mut rng = rand::rngs::StdRng::seed_from_u64(11939);
    let retained = tables
        .iter()
        .enumerate()
        .map(|(i, table)| {
            <P as CanonicalPcs<F, EventHash>>::commit(pp.accumulators[i], table, &mut rng)
                .ok()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let oracles = retained
        .iter()
        .enumerate()
        .map(
            |(i, (commitment, state))| crate::packed_oracle::CanonicalProverOracle::<
                F,
                EventHash,
                P,
            > {
                parameters: pp.accumulators[i],
                commitment,
                state,
            },
        )
        .collect::<Vec<_>>();
    let public = oracles.iter().map(|s| s.verifier()).collect::<Vec<_>>();
    let private = oracles.iter().collect::<Vec<_>>();
    let mut prover = profile.parent_transcript::<F>().unwrap();
    let proof =
        monomial::prove::<F, EventHash, P, _>(&mut prover, &plan, pp.monomial, &private, &mut rng)
            .unwrap();
    let bytes = encoded(&proof);
    let mut prover_finish = [0; 64];
    prover.get_challenge_bytes(b"observed monomial continuation", &mut prover_finish);
    let start = capture.lock().unwrap().events.len();
    let mut verifier = profile.parent_transcript::<F>().unwrap();
    monomial::verify::<F, EventHash, P>(&mut verifier, &plan, pp.monomial, &public, &proof)
        .unwrap();
    let end = capture.lock().unwrap().events.len();
    let mut verifier_finish = [0; 64];
    verifier.get_challenge_bytes(b"observed monomial continuation", &mut verifier_finish);
    assert_eq!(prover_finish, verifier_finish);
    drop(xof_guard);
    drop(hash_guard);

    let (decoded, used): (
        monomial::Proof<
            F,
            Digest512,
            <P as CanonicalPcs<F, Sha512>>::BatchProof,
            <P as CanonicalPcs<F, Sha512>>::SingleProof,
        >,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut standard = profile.parent_transcript::<F>().unwrap();
    monomial::verify::<F, Sha512, P>(&mut standard, &plan, pp.monomial, &public, &decoded).unwrap();
    let mut finish = [0; 64];
    standard.get_challenge_bytes(b"observed monomial continuation", &mut finish);
    assert_eq!(finish, verifier_finish);
    assert_eq!(capture.lock().unwrap().events.len(), end + 1);
    let mut prefix = profile.parent_transcript::<F>().unwrap();
    let (subclaim, obligations) = monomial::audit::product_subclaim::<F, Sha512, P>(
        &mut prefix,
        &plan,
        pp.monomial,
        &public,
        &decoded,
    )
    .unwrap();
    for i in 0..2 {
        <P as CanonicalPcs<F, Sha512>>::verify(
            pp.monomial,
            &mut prefix,
            &decoded.evaluations[i],
            &subclaim.query,
            &decoded.values[i],
            &decoded.openings[i],
        )
        .ok()
        .unwrap();
    }
    let mut replay_finish = [0; 64];
    prefix.get_challenge_bytes(b"observed monomial continuation", &mut replay_finish);
    assert_eq!(replay_finish, verifier_finish);

    let capture = capture.lock().unwrap();
    let mut expected_bindings = Vec::new();
    if profile.specification().backend != Backend::Brakedown {
        for (index, (queries, co, ev)) in obligations.iter().enumerate() {
            expected_bindings.push(claim_seed_tail::<F, P>(
                profile,
                pp.accumulators[index],
                &retained[index].0,
                queries,
                co,
            ));
            expected_bindings.push(claim_seed_tail::<F, P>(
                profile,
                pp.monomial,
                &decoded.evaluations[index],
                queries,
                ev,
            ));
        }
        for index in 0..2 {
            expected_bindings.push(claim_seed_tail::<F, P>(
                profile,
                pp.monomial,
                &decoded.evaluations[index],
                &[subclaim.query.clone()],
                &[decoded.values[index].clone()],
            ));
        }
        assert_eq!(expected_bindings.len(), 6);
    }
    let temporal = temporal_child_views::<F, EF, P>(
        profile,
        pp.monomial,
        &capture.events,
        start..end,
        &expected_bindings,
        |root| capture.history.view(root),
    );
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
    assert_eq!(replay.hash_queries(), capture.history.hash_queries());
    assert_eq!(replay.xof_queries(), capture.history.xof_queries());
    assert_eq!(replay.events(), capture.events.len());
    assert_eq!(
        replay.availability_hits(),
        capture.history.availability_hits()
    );
    let context = <P as CanonicalPcs<F, Sha512>>::context(pp.monomial)
        .ok()
        .unwrap();
    let sources = decoded
        .evaluations
        .iter()
        .map(|root| (context, root.clone()))
        .collect::<Vec<_>>();
    for (_, root) in &sources {
        assert_eq!(
            replay.view(root.root).unwrap().as_ref(),
            capture.history.view(root.root).unwrap().as_ref()
        );
    }
    let mut queries = obligations
        .iter()
        .flat_map(|o| o.0.iter().cloned())
        .collect::<Vec<_>>();
    let product_query = queries.len();
    queries.push(subclaim.query.clone());
    let (promises, evaluation_values) = monomial_word_audit::values_many::<F, EF, P>(
        profile,
        pp.monomial,
        &sources,
        &queries,
        |s| capture.history.view(s.1.root),
    )
    .unwrap();
    assert!(promises.iter().all(|&p| p));
    let coefficient_sources = public
        .iter()
        .map(|s| {
            (
                <P as CanonicalPcs<F, Sha512>>::context(s.parameters)
                    .ok()
                    .unwrap(),
                s.commitment.clone(),
            )
        })
        .collect::<Vec<_>>();
    let (promises, coefficient_values) = monomial_word_audit::values_many::<F, EF, P>(
        profile,
        pp.monomial,
        &coefficient_sources,
        &queries,
        |s| capture.history.view(s.1.root),
    )
    .unwrap();
    assert!(promises.iter().all(|&p| p));
    let mut offset = 0;
    for (component, (component_queries, co, ev)) in obligations.iter().enumerate() {
        for j in 0..component_queries.len() {
            assert_eq!(
                encoded(&coefficient_values[component][offset + j]),
                encoded(&<P as CanonicalPcs<F, Sha512>>::normalize_values(
                    pp.accumulators[component],
                    co[j].clone()
                ))
            );
            assert_eq!(
                encoded(&evaluation_values[component][offset + j]),
                encoded(&<P as CanonicalPcs<F, Sha512>>::normalize_values(
                    pp.monomial,
                    ev[j].clone()
                ))
            );
        }
        offset += component_queries.len();
    }
    let values = evaluation_values
        .iter()
        .map(|group| group[product_query].clone())
        .collect::<Vec<_>>();
    assert_eq!(encoded(&values), encoded(&decoded.values));
    assert!(monomial_terminal_audit::terminal_valid(
        &plan, width, &subclaim, &values
    ));
    let hash_queries = capture.events[start..end]
        .iter()
        .filter(|e| matches!(e, Event::Hash(..)))
        .count();
    let xof_queries = end - start - hash_queries;
    assert!(hash_queries > 0 && xof_queries > 0);
    println!(
        "HB_MONOMIAL_EVENT_TRACE {{\"prime\":\"{}\",\"degree\":{},\"version\":{},\"backend\":\"{:?}\",\"n\":{},\"rounds\":{},\"proof_bytes\":{},\"verifier_hash_queries\":{},\"verifier_xof_queries\":{},\"total_events\":{},\"evaluation_words_match_accepted_claims\":true,\"ntt_words_match_accepted_claims\":true,\"verifier_temporal_child_queries\":{},\"repeated_verifier_child_queries\":{},\"verifier_bound_child_openings\":{},\"child_claim_envelopes_preflighted\":true,\"child_fixed_word_tasks_checked\":true,\"false_child_value_tasks_classified\":true,\"xof_availability_hits\":0,\"xof_output_collisions\":0,\"all_input_windows_registered\":true,\"full_pbs_trace\":false,\"security_qualified\":false}}",
        F::MODULUS_VALUE,
        EF::D,
        profile.version(),
        profile.specification().backend,
        n,
        rounds,
        bytes.len(),
        hash_queries,
        xof_queries,
        capture.events.len(),
        temporal.0,
        temporal.1,
        temporal.2
    );
}

fn field<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
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
                roles: std::array::from_fn(|_| Role {
                    num_vars: 5,
                    width: 8,
                    queries: 8,
                    left_vars: (backend == Backend::Brakedown).then_some(2),
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
                ClassicalProfile::new_atomic_zerocheck::<F, EF>(spec)
            } else {
                ClassicalProfile::new_atomic_columns::<F, EF>(spec)
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
fn production_monomial_oracle_events() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    field::<algebra::BabyBear, algebra::BabyBearExtension6>();
    field::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn production_monomial_ntt_source_words_smoke() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    let profile = ClassicalProfile::new_atomic_columns::<
        algebra::BabyBear,
        algebra::BabyBearExtension6,
    >(Specification {
        backend: Backend::Brakedown,
        roles: std::array::from_fn(|_| Role {
            num_vars: 5,
            width: 8,
            queries: 8,
            left_vars: Some(2),
            block_width: Some(2),
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6, _>(
        profile
            .brakedown_parameters::<algebra::BabyBear, algebra::BabyBearExtension6>()
            .unwrap(),
    );
}

#[test]
fn production_monomial_temporal_producers_smoke() {
    let _serial = TRACE_TEST_LOCK.lock().unwrap();
    let profile = ClassicalProfile::new_atomic_columns::<
        algebra::BabyBear,
        algebra::BabyBearExtension6,
    >(Specification {
        backend: Backend::Polyfrim,
        roles: std::array::from_fn(|_| Role {
            num_vars: 5,
            width: 8,
            queries: 8,
            left_vars: None,
            block_width: None,
        }),
        blowup: 2,
        fragment_vars: None,
    })
    .unwrap();
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6, _>(
        profile
            .polyfrim_parameters::<algebra::BabyBear, algebra::BabyBearExtension6>()
            .unwrap(),
    );
}
