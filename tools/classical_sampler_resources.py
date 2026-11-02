"""Analysis-only byte ceilings for canonical rejection phases; no runtime cap."""
from fractions import Fraction
from polyfrim_opening_terms import encode


def xof_expected_exposure_bound(*, expected_target_pairs,
                                expected_collision_pairs, output_bits=512):
    """Conditional ideal-XOF first-prefix exception bound, without a query cap.

    At each fresh input, count registered target windows and distinct prior
    outputs before exposing the current output. Supply bounds on expectations
    of the sums, not realized trace counts. Repeated inputs expose no fresh
    randomness. All external input windows must be registered before answers.
    This concerns the first output_bits bits, not arbitrary reader overlaps.
    """
    pairs = (expected_target_pairs, expected_collision_pairs)
    if (any(type(v) not in (int, Fraction) or v < 0 for v in pairs)
            or type(output_bits) is not int or output_bits < 1):
        raise ValueError('nonnegative exact expectation bounds and positive output bits required')
    targets, collisions = map(Fraction, pairs)
    support = 1 << output_bits
    return dict(expected_target_pairs=encode(targets),
        expected_collision_pairs=encode(collisions), output_bits=output_bits,
        availability_contribution=encode(targets/support),
        collision_contribution=encode(collisions/support),
        total=encode(min(Fraction(1), (targets+collisions)/support)),
        required_premises=[
            'Fresh input prefixes are conditionally uniform in the same complete ideal-XOF experiment',
            'Every relevant input window is registered before its answer, including external hash inputs',
            'Supplied bounds cover expectations of predictable exposure sums, not observed trace counts',
            'Prefix outputs at repeated inputs are consistent and charged only once'],
        input_bounds_verified=False, attacker_work_coupling_established=False,
        whole_proof_security_certified=False)


def ideal_oracle_expected_exposure_bound(*, expected_hash_target_pairs,
                                        expected_hash_collision_pairs,
                                        expected_xof_target_pairs,
                                        expected_xof_collision_pairs,
                                        output_bits=512):
    """Union ideal-hash and ideal-XOF exposure terms in one experiment.

    Every bound is mandatory. Hash counts may conservatively include repeat
    requests; only fresh inputs create the bad events being bounded. This
    covers within-oracle output collisions and first-answer window hits, not
    unregistered cross-oracle coincidences or whole-proof coverage failures.
    """
    hash_bounds = (expected_hash_target_pairs, expected_hash_collision_pairs)
    xof_bounds = (expected_xof_target_pairs, expected_xof_collision_pairs)
    # Reuse exact expectation/dimension validation; both families use the same
    # conditional-uniform-prefix union lemma, without requiring event independence.
    for targets, collisions in (hash_bounds, xof_bounds):
        xof_expected_exposure_bound(expected_target_pairs=targets,
                                   expected_collision_pairs=collisions,
                                   output_bits=output_bits)
    hash_term = sum(map(Fraction, hash_bounds))/(1 << output_bits)
    xof_term = sum(map(Fraction, xof_bounds))/(1 << output_bits)
    return dict(output_bits=output_bits, hash_contribution=encode(hash_term),
        xof_contribution=encode(xof_term),
        total=encode(min(Fraction(1), hash_term+xof_term)),
        required_premises=[
            'Fresh hash outputs and XOF prefixes are conditionally uniform given the complete joint history',
            'Relevant input windows from both oracle families are registered before each answer',
            'All supplied bounds cover expectations in the same complete adversary/verifier experiment',
            'Repeated outputs are consistent and only fresh inputs create first-answer bad events'],
        input_bounds_verified=False, attacker_work_coupling_established=False,
        whole_proof_security_certified=False)


def native_hash_input_envelope():
    """Native <=64-bit SHA call inventory: at most two safe byte slices/output.

    Hash metadata helpers pass one serialized Vec; Brakedown adds one fixed
    prefix, and Merkle nodes pass two 64-byte digests. Profile IDs pass one
    contiguous allocation or a fixed namespace plus serialized descriptor.
    This bounds verifier inputs, not arbitrary adversarial oracle inputs.
    """
    slice_max = 2**63-1
    return dict(pointer_bits_upper_bound=64, maximum_updates_per_output=2,
        maximum_safe_byte_slice_bytes=slice_max,
        maximum_hash_query_input_bytes=2*slice_max,
        maximum_overlapping_64_byte_windows_per_input=2*slice_max-63,
        required_premises=['Safe contiguous slice/Vec construction on a <=64-bit runtime',
            'Audited native SHA helpers use at most two updates between resets'],
        scope='All selected native verifier SHA512 inputs, including profile IDs',
        arbitrary_adversarial_input_bound=False,
        full_protocol_resource_coupling_established=False)


def column_rejection_envelope(domain, draws, candidate_limit=8, *, sample_bits=64):
    """Model matrix_weighted::sample_columns, including its u64::MAX cutoff.

    sample_bits is exposed for exhaustive small-domain checks. Production is 64.
    Each candidate is a distinct byte challenge, including rejected candidates.
    """
    if (any(type(v) is not int for v in (domain, draws, candidate_limit, sample_bits))
            or not 1 <= sample_bits <= 64 or not 1 <= domain < 2**sample_bits
            or not 0 <= draws < 2**64 or candidate_limit < 1):
        raise ValueError('positive representable domain/limit and exact draw count required')
    support = 1 << sample_bits
    maximum = support-1
    cutoff = maximum-maximum % domain
    rejection = Fraction(support-cutoff, support)
    return dict(domain=domain, independent_draws=draws, sample_bits=sample_bits,
        acceptance_cutoff=cutoff, rejection_probability=encode(rejection),
        candidate_limit_per_draw=candidate_limit,
        first_excess_union=encode(min(Fraction(1), draws*rejection**candidate_limit)),
        byte_challenge_queries_upper_bound=draws*candidate_limit,
        byte_challenge_output_bytes_upper_bound=draws*candidate_limit*((sample_bits+7)//8),
        accepted_columns_uniform_conditional_on_no_excess=True,
        analysis_only_stop=True, production_loop_unchanged=True)


def column_stop_first_family_bound(domain, draws, rejected_candidate_limit, *,
                                   expected_families, sample_bits=64):
    """Conditional whole-family stop charge at first syntactic exposure.

    The root's complete output tree is fresh before ANY member is queried,
    including a descendant off the eventual canonical path. Repeats and later
    root queries do not create fresh families. Geometry/coverage need proof.
    """
    actors = ('adversary', 'verifier', 'setup', 'unknown')
    if (not isinstance(expected_families, dict) or set(expected_families) != set(actors)
            or any(type(value) not in (int, Fraction) or value < 0
                   for value in expected_families.values())):
        raise ValueError('all exact nonnegative actor family-expectation bounds required')
    local = column_rejection_envelope(domain, draws, rejected_candidate_limit, sample_bits=sample_bits)
    encoded = local['first_excess_union']['exact']
    tail = Fraction(int(encoded['numerator_hex'], 16), int(encoded['denominator_hex'], 16))
    terms = {actor: Fraction(expected_families[actor])*tail for actor in actors}
    return dict(domain=domain, draws=draws, rejected_candidate_limit=rejected_candidate_limit,
        sample_bits=sample_bits, per_family_stop_bound=encode(tail),
        actor_contributions={actor: encode(value) for actor, value in terms.items()},
        total=encode(min(Fraction(1), sum(terms.values()))),
        required_premises=[
            'Canonical maximal trailing byte runs partition every relevant oracle input into disjoint families',
            'No input in the selected family was queried before its recorded first member',
            'Ideal byte-prefix outputs on the complete family tree are fresh given outside-family history',
            'Actual sampler phases follow that tree with the stated or dominated domain/draw geometry',
            'Supplied actor expectations cover first syntactic families in the same complete experiment'],
        complete_family_coverage_established=False, output_tree_model_established=False,
        input_expectation_bounds_verified=False, production_loops_unchanged=True,
        whole_proof_security_certified=False)


def column_run_expected_resources(domain, draws, root_request_bytes, *, sample_bits=64):
    """Exact uncapped moments for one fixed v4 run in the independent-stream game.

    Each candidate is an eight-byte request, including rejection candidates.
    Root length and trusted draw count are fixed at family entry. This supplies
    no whole-verifier bound or adversarial first-entry/source interpretation.
    sample_bits only reduces the sample support for exhaustive analysis tests;
    transcript requests and inline responses remain eight bytes as in production.
    """
    label = b'mw unbiased column'
    frame_bytes = 1+8+len(label)+8+8
    if (any(type(v) is not int for v in (domain, draws, root_request_bytes, sample_bits))
            or not 1 <= sample_bits <= 64 or not 1 <= domain < 2**sample_bits
            or not 0 <= draws < 2**64 or root_request_bytes < frame_bytes):
        raise ValueError('trusted domain, draw count and complete root request required')
    support = 1 << sample_bits
    cutoff = support-1-(support-1) % domain
    acceptance = Fraction(cutoff, support)
    rejection = 1-acceptance
    mean = draws/acceptance
    second = draws*(draws+rejection)/acceptance**2
    # Request i has root_bytes + i*(response_frame + request_frame) bytes.
    stride = 2*frame_bytes
    inputs = root_request_bytes*mean + Fraction(stride, 2)*(second-mean)
    return dict(domain=domain, independent_draws=draws, sample_bits=sample_bits,
        root_request_bytes=root_request_bytes, acceptance_cutoff=cutoff,
        acceptance_probability=encode(acceptance),
        expected_candidate_queries=encode(mean),
        expected_squared_candidate_queries=encode(second),
        expected_reader_bytes=encode(8*mean),
        additional_input_bytes_per_candidate=stride,
        expected_total_request_input_bytes=encode(inputs),
        almost_sure_termination_in_independent_stream_game=True,
        deterministic_retry_cap=None, production_loop_unchanged=True,
        required_premises=['Fixed trusted root length and accepted draw count at family entry',
            'Independent uniform candidate streams along the canonical run'],
        global_resource_bound_established=False,
        source_and_first_entry_coupling_established=False,
        whole_proof_security_certified=False)


def rejection_envelope(prime, coefficients, candidate_limit=512):
    if (any(type(v) is not int for v in (prime, coefficients, candidate_limit))
            or not 2 <= prime < 2**128 or not 0 <= coefficients < 2**64 or candidate_limit < 1):
        raise ValueError('trusted modulus/count and positive analysis limit required')
    bits = (prime-1).bit_length()
    support = 1 << bits
    rejected = Fraction(support-prime, support)
    error = min(Fraction(1), coefficients*rejected**candidate_limit)
    raw_bytes = coefficients*candidate_limit*((bits+7)//8)
    return dict(mask_bits=bits, bytes_per_candidate=(bits+7)//8,
        coefficient_count_ceiling=coefficients, candidate_limit_per_coefficient=candidate_limit,
        maximum_raw_bytes=raw_bytes,
        maximum_receipt_input_bytes=len(b'HasteBoots consumed field bytes v1')+raw_bytes,
        rejection_probability=encode(rejected), first_excess_union=encode(error),
        analysis_only_stop=True, production_loop_unchanged=True,
        accepted_values_uniform_conditional_on_no_excess=True)


def field_stop_first_query_bound(prime, rejected_candidate_limit, *, expected_coefficients):
    """Conditional uncapped-query field-rejection stop bound by first input.

    Each eligible input fixes a flat base-field coefficient count before its
    first answer. Complete that input's canonical sampler virtually; repeats
    reference the same stream. Supplied actor sums are expectations, not traces.
    rejected_candidate_limit is an analysis stop, never a production loop cap.
    """
    actors = ('adversary', 'verifier', 'setup', 'unknown')
    if (type(prime) is not int or not 2 <= prime < 2**128
            or type(rejected_candidate_limit) is not int or rejected_candidate_limit < 1
            or not isinstance(expected_coefficients, dict) or set(expected_coefficients) != set(actors)
            or any(type(value) not in (int, Fraction) or value < 0
                   for value in expected_coefficients.values())):
        raise ValueError('trusted modulus, positive stop and all exact actor expectation bounds required')
    support = 1 << (prime-1).bit_length()
    rejection = Fraction(support-prime, support)
    tail = rejection**rejected_candidate_limit
    terms = {actor: Fraction(expected_coefficients[actor])*tail for actor in actors}
    return dict(rejected_candidate_limit=rejected_candidate_limit,
        per_coefficient_stop_bound=encode(tail),
        actor_contributions={actor: encode(value) for actor, value in terms.items()},
        total=encode(min(Fraction(1), sum(terms.values()))),
        required_premises=[
            'Eligible request syntax includes every bounded trusted verifier field request at the chosen profile/modulus',
            'Flat coefficient counts are fixed before each distinct input first exposes its independent ideal stream',
            'Virtual canonical whole-stream completion agrees with any later actual use of that input',
            'Actor-weighted coefficient expectations cover the same complete experiment, including unclassified origins'],
        input_expectation_bounds_verified=False, complete_request_coverage_established=False,
        whole_stream_model_established=False, production_loops_unchanged=True,
        whole_proof_security_certified=False)


def native_phase_envelope(profile, schedule, candidate_limit=512):
    """Coefficient-count ceiling from the selected typed native call shapes.

    Role query ceilings conservatively bound any one PCS call's claim count.
    This does not bound how many oracle requests the whole verifier makes.
    """
    variables, widths = profile['role_variables'], profile['role_widths']
    degree = profile['extension_degree']
    k = widths[0]
    scalar_vars = max(v+(w-1).bit_length() for v, w in zip(variables, widths))
    parent = max(k*k+k, k*max(variables), degree*scalar_vars)
    backend = profile['backend']
    counts = []
    for role, (v, w) in enumerate(zip(variables, widths)):
        claims = schedule['role_ordered_query_ceilings'][role]
        if backend == 'Brakedown':
            count = w*w*(1 << profile['role_left_vars'][role])
        elif backend in ('Polyfrim', 'PolyfrimDictionary'):
            count = max(1, v)*claims*w*degree
        elif backend in ('FragmentedPipfri', 'FragmentedPipfriVirtual'):
            count = claims*w*degree
        else:
            raise ValueError('unsupported typed PCS sampling shape')
        counts.append(count)
    result = rejection_envelope(int(profile['prime']), max(parent, *counts), candidate_limit)
    result.update(parent_coefficient_count_ceiling=parent, pcs_role_coefficient_count_ceilings=counts,
        scope='Per fresh field phase under trusted typed call-shape ceilings',
        excluded=['Total phase count, byte-challenge outputs and child-link resource costs',
                  'Complete admissible-prefix and all-trials work composition'],
        global_resource_bound_established=False)
    return result


def native_pcs_query_envelope(profile, schedule, column_candidate_limit=8):
    """PCS-only query ceilings for typed schedules four/five, including early rejects.

    Count invocations, not distinct inputs: repeated checkpoint/empty receipt
    inputs are conservatively charged again. No parent algebra is included.
    """
    if profile['descriptor_version'] not in (4, 5):
        raise ValueError('audited atomic schedule four or five required')
    rows = []
    backend = profile['backend']
    for role, (v, w, q) in enumerate(zip(profile['role_variables'],
                                        profile['role_widths'], profile['role_queries'])):
        calls = schedule['role_opening_call_ceilings'][role]
        claims = schedule['role_ordered_query_ceilings'][role]
        if backend == 'Brakedown':
            from classical_brakedown_resources import call_envelope
            per_call = call_envelope(profile, role, column_candidate_limit=column_candidate_limit)
            fields, checkpoints = calls*per_call['field_phases_upper_bound'], 0
            if profile['descriptor_version'] == 5:
                byte_queries = calls*per_call['column_xof_queries_upper_bound']
                byte_outputs = calls*per_call['column_output_bytes_upper_bound']
                detail = dict(index_phases=calls, atomic_columns=True, per_call_resources=per_call)
            else:
                columns = column_rejection_envelope(per_call['codeword_blocks'], calls*q,
                                                     column_candidate_limit)
                byte_queries = calls*per_call['column_xof_queries_upper_bound']
                byte_outputs = calls*per_call['column_output_bytes_upper_bound']
                detail = dict(column_sampler=columns, atomic_columns=False, per_call_resources=per_call)
        else:
            # Detached typed child: seed/finish byte requests, two checkpoints,
            # and an empty extension-identity field phase (two XOF producers).
            checkpoints = 2*calls
            if backend in ('Polyfrim', 'PolyfrimDictionary'):
                rounds = max(1, v)
                fields = calls*(2+rounds)  # identity, joint projection, folds
                indices = calls+claims  # rolling plus one per ordered member
            elif backend in ('FragmentedPipfri', 'FragmentedPipfriVirtual'):
                scalar = v+(w-1).bit_length()
                rounds = min(max(1, scalar), profile['fragment_vars'])
                fields = calls*(3+scalar+rounds)  # identity, rho, bridge, gamma, folds
                indices = calls*(1 if backend == 'FragmentedPipfriVirtual' else 2)
            else:
                raise ValueError('unsupported typed PCS backend')
            byte_queries = 2*calls+indices
            byte_outputs = 128*calls+8*q*indices
            detail = dict(index_phases=indices, rolling_rounds_per_call=rounds)
        rows.append(dict(role=role, calls=calls, field_phases=fields,
            field_xof_queries=2*fields, checkpoint_queries=checkpoints,
            byte_challenge_queries=byte_queries, byte_challenge_output_bytes=byte_outputs,
            checkpoint_output_bytes=64*checkpoints,
            xof_queries=2*fields+checkpoints+byte_queries, **detail))
    return dict(roles=rows, **{key: sum(r[key] for r in rows) for key in (
        'field_phases', 'field_xof_queries', 'checkpoint_queries', 'byte_challenge_queries',
        'byte_challenge_output_bytes', 'checkpoint_output_bytes', 'xof_queries')},
        scope='PCS invocation ceilings only; conditional on column retry stop where applicable',
        parent_submitted_call_bound_established=schedule.get('submitted_call_bound_established', False),
        parent_submitted_call_bound_source_reviewed=schedule.get('submitted_call_bound_source_reviewed', False),
        excluded=['Parent algebra, lookup children, outer transcript initialization',
                  'Input/frame byte lengths and field sampler raw-output lengths',
                  'Complete first-query and all-trials work coupling'],
        global_resource_bound_established=False)


def native_verifier_query_envelope(profile, schedule, parent):
    """Whole typed verifier invocation counts, stopped at first lookup retry.

    Parent phase inventory includes every nonempty field request. Three shared
    lookup children additionally contribute empty identity phases and links.
    The prime outer constructor absorbs bytes but makes no oracle request.
    """
    pcs = native_pcs_query_envelope(profile, schedule)
    lookup_children = 3  # Two main decompositions, one final key decomposition.
    parent_fields = parent['phase_count']+lookup_children
    parent_counts = dict(field_phases=parent_fields, field_xof_queries=2*parent_fields,
        checkpoint_queries=2*lookup_children, byte_challenge_queries=2*lookup_children,
        byte_challenge_output_bytes=128*lookup_children,
        checkpoint_output_bytes=128*lookup_children,
        xof_queries=2*parent_fields+4*lookup_children)
    totals = {key: parent_counts[key]+pcs[key] for key in parent_counts}
    return dict(parent=parent_counts, pcs=pcs, totals=totals,
        stopping_conditions=['First rejected reciprocal challenge in any lookup']+
            (['Brakedown column candidate limit in PCS resource envelope']
             if profile['backend'] == 'Brakedown' and profile['descriptor_version'] == 4 else []),
        scope='Conditional typed native verifier XOF invocation ceilings, including early-reject prefixes',
        excluded=['Serialized input/frame byte ceilings and field stream byte ceilings',
                  'Complete admissible-prefix/source and all-trials work composition'],
        global_resource_bound_established=False)


def native_verifier_output_envelope(profile, schedule, parent, candidate_limit=512):
    """Finite output bytes and sampler stop error in the stopped ideal game.

    Fresh independent challenge streams are a premise, not established here.
    Lookup reciprocal retry error is already included in parent lookup terms.
    """
    queries = native_verifier_query_envelope(profile, schedule, parent)
    phase = native_phase_envelope(profile, schedule, candidate_limit)
    fields = queries['totals']['field_phases']
    prime = int(profile['prime'])
    support = 1 << (prime-1).bit_length()
    field_stop = fields*phase['coefficient_count_ceiling']*Fraction(
        support-prime, support)**candidate_limit
    column_stop = Fraction()
    for role in queries['pcs']['roles']:
        if 'column_sampler' in role:
            column = role['column_sampler']
            rejection = Fraction(2**64-column['acceptance_cutoff'], 2**64)
            column_stop += column['independent_draws']*rejection**column['candidate_limit_per_draw']
    raw = fields*phase['maximum_raw_bytes']
    receipts = 64*fields
    byte_outputs = queries['totals']['byte_challenge_output_bytes']
    checkpoints = queries['totals']['checkpoint_output_bytes']
    return dict(field_phases=fields, xof_queries=queries['totals']['xof_queries'],
        field_raw_output_bytes=raw, field_receipt_output_bytes=receipts,
        field_receipt_producer_input_bytes=fields*phase['maximum_receipt_input_bytes'],
        byte_challenge_output_bytes=byte_outputs, checkpoint_output_bytes=checkpoints,
        total_xof_output_bytes=raw+receipts+byte_outputs+checkpoints,
        canonical_field_stop_union=encode(min(Fraction(1), field_stop)),
        column_stop_union=encode(min(Fraction(1), column_stop)),
        additional_sampler_stop_union=encode(min(Fraction(1), field_stop+column_stop)),
        lookup_first_retry_already_charged_in_parent=True,
        required_premises=['Fresh independent ideal challenge streams at typed phases',
                           'Trusted native call/claim ceilings and first lookup retry stop'],
        excluded=['Framed transcript input lengths and other hash inputs',
                  'Adversarial oracle queries and all verifier invocations across all trials',
                  'Actual first-query/source and complete work coupling'],
        production_loop_unchanged=True, global_resource_bound_established=False)


def native_pcs_frame_envelope(profile, schedule):
    """Additional PCS frames, including ephemeral checkpoint frames.

    This bounds increments, not a child/parent's pre-existing input prefix.
    The byte bound uses the stated 64-bit runtime and successful slice/Vec
    construction, not an attacker query cutoff or a new production limit.
    """
    queries = native_pcs_query_envelope(profile, schedule)
    backend = profile['backend']
    rows = []
    for role, resource in enumerate(queries['roles']):
        calls, fields = resource['calls'], resource['field_phases']
        if backend == 'Brakedown':
            field_frames = 4*fields  # typed request kind, field kind, request, receipt
            # Single openings bind context and claim separately, unlike the
            # one-message batch binding. Charge the larger shape to all calls.
            link_frames, metadata = 0, 3*calls
            index_frames = (3 if profile['descriptor_version'] == 5 else 2)*resource['byte_challenge_queries']
        else:
            # Regular typed requests add a scalar/vector marker. The empty
            # child identity uses the byte engine directly and omits it.
            field_frames = 5*fields-calls
            # Fork, seed request/receipt, six child initialization messages,
            # finish request/receipt and parent's finish link. Identity is
            # already included among field phases; checkpoints are separate.
            link_frames = 12*calls
            rounds = resource['rolling_rounds_per_call']
            if backend in ('Polyfrim', 'PolyfrimDictionary'):
                metadata = calls*(4+rounds)+2*schedule['role_ordered_query_ceilings'][role]
            else:
                scalar = profile['role_variables'][role]+(profile['role_widths'][role]-1).bit_length()
                # Parent ordered claim, polynomial info, scalar adapter,
                # scalar claim, public roots and rolling binding: six fixed
                # frames; constant bridges may omit polynomial info.
                metadata = calls*(6+scalar+rounds)
            index_frames = 3*resource['index_phases']  # domain, request, output
        checkpoint_frames = resource['checkpoint_queries']
        rows.append(dict(role=role, field_frames=field_frames, child_link_frames=link_frames,
            metadata_frames=metadata, index_frames=index_frames, checkpoint_frames=checkpoint_frames,
            additional_frames=field_frames+link_frames+metadata+index_frames+checkpoint_frames))
    frames = sum(r['additional_frames'] for r in rows)
    maximum_frame_bytes = 17+2*(2**64-1)
    return dict(roles=rows, additional_frames=frames, maximum_frame_bytes=maximum_frame_bytes,
        additional_framed_input_bytes=frames*maximum_frame_bytes,
        required_premises=['64-bit runtime with successful slice/Vec construction',
                           'Typed native call/claim ceilings and column retry stop'],
        scope='Additional PCS frames only; all child initialization and checkpoint snapshots counted',
        excluded=['Parent-stage/registry frames and pre-existing parent prefixes',
                  'Raw field-receipt producer inputs (not framed)',
                  'Complete admissible-prefix and all-trials work composition'],
        global_resource_bound_established=False)


def native_verifier_frame_envelope(profile, schedule, parent):
    """Stopped typed verifier frame ceiling across all parent/child histories."""
    from classical_parent_phases import packed_stages
    packed = packed_stages(int(profile['prime']), profile['role_widths'][0],
                           schedule_version=profile['descriptor_version'])
    base_fields = packed['phase_count']
    extension_fields = parent['phase_count']-base_fields+3
    bits = (int(profile['prime'])-1).bit_length()
    digits, switch_digits = (bits+7)//8, (bits+4)//5
    main_vars, _, final_vars, _ = profile['role_variables']
    # Exactly the shared native call graph: two main comparisons and one
    # final comparison; helper scalar geometries are independent of packing.
    comparisons = [(digits, 21), (digits, 21), (switch_digits, 11)]
    metadata = dict(
        outer_constructor_and_schedule=8+(profile['descriptor_version'] == 5), outer_binding=1,
        ntt_bindings_and_folded_polynomials=2*(2*digits+switch_digits+4),
        zerocheck_bindings_first_and_round_messages=2*(main_vars+3)+2*(final_vars+3),
        main_and_final_product_bindings_and_terminals=4,
        monomial_binding_and_evaluation_roots=2,
        final_key_mode_binding_and_known_input=3,
        accumulator_binding=1,
        decomposition_and_lookup_metadata=sum(11+2*d+n for d, n in comparisons),
        lookup_registry_initializations_and_seals=6,
        lookup_registry_claims=sum(2*d+1 for d, _ in comparisons))
    parent_frames = 4*base_fields+5*extension_fields-3+36+6+sum(metadata.values())
    pcs = native_pcs_frame_envelope(profile, schedule)
    total = parent_frames+pcs['additional_frames']
    phase = native_phase_envelope(profile, schedule)
    framed = total*pcs['maximum_frame_bytes']
    maximum_input = max(framed, phase['maximum_receipt_input_bytes'])
    return dict(parent_prime_field_frames=4*base_fields,
        parent_extension_field_frames=5*extension_fields-3,
        typed_request_kind_frames_included=True,
        parent_lookup_child_link_frames=36, parent_checkpoint_frames=6,
        parent_metadata_frames=metadata, parent_frames=parent_frames,
        pcs_additional_frames=pcs['additional_frames'], total_frames=total,
        maximum_frame_bytes=pcs['maximum_frame_bytes'],
        maximum_framed_prefix_bytes=framed,
        maximum_receipt_producer_input_bytes=phase['maximum_receipt_input_bytes'],
        maximum_xof_query_input_bytes=maximum_input,
        maximum_overlapping_64_byte_windows_per_input=max(0, maximum_input-63),
        required_premises=['64-bit runtime with successful slice/Vec construction',
            'Selected native shared-stage source/claim ceilings',
            'First lookup reciprocal retry and canonical/column sampler stops'],
        scope='Stopped typed verifier query input lengths; all parent/child frames overcounted together',
        excluded=['Adversarial candidate inputs and complete first-query/source coupling',
                  'All-trials hash/XOF/work and complete soundness composition'],
        global_resource_bound_established=False)


def native_xof_work_envelope(profile, schedule, parent, *, honest_outputs):
    """Conditional XOF-only work polynomial, with caller-specified offset."""
    from hash_query_budget import bounded_input_xof_work
    query = native_verifier_query_envelope(profile, schedule, parent)
    frames = native_verifier_frame_envelope(profile, schedule, parent)
    result = bounded_input_xof_work(512, query['totals']['xof_queries'],
        frames['maximum_xof_query_input_bytes'], honest_outputs)
    result['coefficients'] = {k: encode(v) for k, v in result['coefficients'].items()}
    result.update(scope='Conditional ideal-XOF collision/link polynomial only',
        eligible_input_filter_established=False,
        length_filter_preserves_bounded_trace_outside_output_collisions=True,
        length_filter_scope='Bounded stopped verifier traces; does not establish arbitrary candidate stage/source admissibility',
        excluded=['Algebraic/PCS/sampler stopping errors and Merkle availability',
                  'Actual admissible-prefix/source and all-trials coupling',
                  'Knowledge and native performance qualification'])
    return result
