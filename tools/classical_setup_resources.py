"""Structural successful-setup counts for the canonical Brakedown backend.

Parameter construction and native key generation are outside this scope. This
does not bound proving, rejected verification or all trials.
"""
from brakedown_opening_terms import opening_terms
from classical_profile_descriptor import decode_descriptor


def setup_resources(descriptor, *, br_bits, ks_bits):
    profile = decode_descriptor(descriptor)
    if profile['backend'] != 'Brakedown':
        raise ValueError('only the reviewed Brakedown commitment path is supported')
    prime = int(profile['prime'])
    bits = prime.bit_length()
    if any(type(b) is not int or not 0 < b < bits for b in (br_bits, ks_bits)):
        raise ValueError('radix bits must be positive native field radix widths')
    # Native Basis::decompose_len uses modulus bit length; KS repeatedly
    # divides p-1 by the radix. These agree for the supported odd primes.
    br_digits = (bits + br_bits - 1) // br_bits
    ks_digits = ((prime - 1).bit_length() + ks_bits - 1) // ks_bits
    # Standard bincode unsigned integers on this native 64-bit runtime occupy
    # at most nine bytes. Both field newtypes serialize a single u32/u64.
    # Context tuple: modulus string, six usize values, code-domain byte slice,
    # then BlockReedSolomonCode's four usize values, modulus string, field root.
    context_bytes = (len(b'HasteBoots/mw-parameters/v2')
                     + 2 * (9 + len(str(prime))) + 6 * 9
                     + 9 + len(b'block-rs/negacyclic-ntt/v1') + 4 * 9 + 9)
    commitments = []
    for role, tables in ((0, 2 * br_digits), (2, ks_digits)):
        geometry = opening_terms(
            profile['role_variables'][role], profile['role_widths'][role],
            profile['role_left_vars'][role], profile['role_block_widths'][role],
            profile['blowup'], profile['role_queries'][role], prime)
        columns = geometry['encoded_blocks']
        cells = ((1 << profile['role_left_vars'][role])
                 * profile['role_widths'][role] * profile['role_block_widths'][role])
        leaf_bytes = len(b'HasteBoots/mw-column/v1') + 9 + cells * 9
        table_bytes = columns * leaf_bytes + (columns - 1) * 128 + context_bytes
        commitments.append(dict(role=role, tables=tables, encoded_columns=columns,
                                hash_queries_per_table_upper_bound=2 * columns,
                                hash_queries_upper_bound=tables * 2 * columns,
                                leaf_hash_input_bytes_upper_bound=leaf_bytes,
                                hash_input_bytes_upper_bound=tables * table_bytes))
    standard = 6 + sum(row['hash_queries_upper_bound'] for row in commitments)
    profile_bytes = len(b'HasteBoots classical profile v1') + len(descriptor)
    total_bytes = (6 * context_bytes + profile_bytes
                   + sum(row['hash_input_bytes_upper_bound'] for row in commitments))
    return dict(
        scope='successful canonical classical Brakedown preprocess; factories and key generation excluded',
        br_bits=br_bits, ks_bits=ks_bits, commitments=commitments,
        external_context_hash_queries=6,
        standard_hash_queries_upper_bound=standard,
        direct_profile_id_hash_queries=1,
        hash_queries_upper_bound=standard + 1,
        context_hash_input_bytes_upper_bound=context_bytes,
        profile_id_hash_input_bytes=profile_bytes,
        hash_input_bytes_upper_bound=total_bytes,
        max_hash_input_bytes_upper_bound=max(
            context_bytes, profile_bytes, 128,
            *(row['leaf_hash_input_bytes_upper_bound'] for row in commitments)),
        xof_queries=0, committed_roots=2 * br_digits + ks_digits,
        zero_table_optimization_can_reduce_count=True,
        proving_resources_bounded=False, rejected_verifier_resources_bounded=False,
        hash_input_bytes_bounded=True, all_trials_bound_established=False,
        security_qualified=False, performance_gate=False)


def prover_commitment_resources(descriptor, *, repetitions):
    """All fresh table commitments in one successful shared-radix native PBS.

    Retained BR/KS roots are reused, not recommitted. The v12 native schedule
    fixes BR/KS radix widths to 8/5 in the accompanying resource worksheets.
    Only commitment hashing is included; this is not a full prover bound.
    """
    profile = decode_descriptor(descriptor)
    if profile['descriptor_version'] not in (4, 5):
        raise ValueError('shared classical schedule four or five required')
    if type(repetitions) is not int or not 1 <= repetitions < 2**64:
        raise ValueError('positive native lookup repetition count required')
    setup = setup_resources(descriptor, br_bits=8, ks_bits=5)
    bits = int(profile['prime']).bit_length()
    d, s = (bits + 7)//8, (bits + 4)//5
    stages = dict(
        main_coefficients=[2*d+1, 0, 0, 0],
        main_evaluations=[2*d+1, 0, 0, 0],
        accumulators=[4, 0, 0, 0],
        decomposition_inputs=[2, 0, 0, 0],
        monomial_evaluations=[2, 0, 0, 0],
        main_borrows=[2*(d+1), 0, 0, 0],
        main_reciprocal_helpers=[0, 2*d*repetitions, 0, 0],
        final_coefficients=[0, 0, s+1, 0],
        final_evaluations=[0, 0, s+1, 0],
        final_input=[0, 0, 1, 0],
        final_borrows=[0, 0, s+1, 0],
        final_reciprocal_helpers=[0, 0, 0, s*repetitions])
    roles = []
    for role in range(4):
        tables = sum(row[role] for row in stages.values())
        geometry = opening_terms(profile['role_variables'][role],
            profile['role_widths'][role], profile['role_left_vars'][role],
            profile['role_block_widths'][role], profile['blowup'],
            profile['role_queries'][role], int(profile['prime']))
        columns = geometry['encoded_blocks']
        cells = ((1 << profile['role_left_vars'][role])
                 * profile['role_widths'][role] * profile['role_block_widths'][role])
        leaf_bytes = len(b'HasteBoots/mw-column/v1') + 9 + cells*9
        roles.append(dict(role=role, tables=tables, encoded_columns=columns,
            hash_queries_upper_bound=tables*2*columns,
            hash_input_bytes_upper_bound=tables*(columns*leaf_bytes
                + (columns-1)*128 + setup['context_hash_input_bytes_upper_bound']),
            max_hash_input_bytes_upper_bound=max(leaf_bytes, 128,
                setup['context_hash_input_bytes_upper_bound'])))
    return dict(scope='Fresh commitments only in one successful shared-radix native PBS',
        br_bits=8, ks_bits=5, repetitions=repetitions, stages=stages, roles=roles,
        committed_roots=sum(row['tables'] for row in roles),
        hash_queries_upper_bound=sum(row['hash_queries_upper_bound'] for row in roles),
        hash_input_bytes_upper_bound=sum(row['hash_input_bytes_upper_bound'] for row in roles),
        max_hash_input_bytes_upper_bound=max(row['max_hash_input_bytes_upper_bound'] for row in roles),
        retained_key_roots_recommitted=False, opening_hashes_included=False,
        external_context_hashes_included=False, full_prover_resources_bounded=False,
        security_qualified=False, performance_gate=False)


def prover_opening_hash_resources(descriptor):
    """Brakedown opening hashes for the selected native one-repetition schedule.

    Both open and open_many hash exactly two parameter contexts on successful
    paths: the retained state check and the transcript binding. Merkle paths
    are copied from retained state, with no leaf or internal-node rehashing.
    """
    from polyfrim_opening_terms import shared_stage_schedule
    profile = decode_descriptor(descriptor)
    setup = setup_resources(descriptor, br_bits=8, ks_bits=5)
    if profile['descriptor_version'] not in (4, 5):
        raise ValueError('shared classical schedule four or five required')
    width = profile['role_widths'][0]
    lane_bits = (width - 1).bit_length()
    if (profile['role_variables'] != [21-lane_bits, 21, 11-lane_bits, 11]
            or profile['role_widths'][2] != width):
        raise ValueError('selected native 1024/728 geometry required')
    schedule = shared_stage_schedule(dict(prime=int(profile['prime']), width=width,
        lwe_dimension=728, lookup_repetitions=1))
    roles = [dict(role=i, calls_upper_bound=calls,
                  hash_queries_upper_bound=2*calls,
                  hash_input_bytes_upper_bound=2*calls*setup['context_hash_input_bytes_upper_bound'])
             for i, calls in enumerate(schedule['role_opening_call_ceilings'])]
    return dict(scope='Successful native Brakedown opening calls only; retained states supplied',
        stages=schedule['stages'], roles=roles,
        hash_queries_upper_bound=sum(row['hash_queries_upper_bound'] for row in roles),
        hash_input_bytes_upper_bound=sum(row['hash_input_bytes_upper_bound'] for row in roles),
        max_hash_input_bytes_upper_bound=setup['context_hash_input_bytes_upper_bound'],
        merkle_paths_rehashed=False, commitments_included=False,
        external_context_hashes_included=False, full_prover_resources_bounded=False,
        security_qualified=False, performance_gate=False)


def prover_hash_resources(descriptor):
    """Complete successful SHA512 path for selected native Brakedown v12 PBS.

    No XOF/stopping bound or arbitrary rejected-prover path is asserted.
    """
    from classical_candidate_terms import parent_context_inventory
    profile = decode_descriptor(descriptor)
    commitments = prover_commitment_resources(descriptor, repetitions=1)
    openings = prover_opening_hash_resources(descriptor)
    setup = setup_resources(descriptor, br_bits=8, ks_bits=5)
    shared = parent_context_inventory(profile)
    stages = dict(shared['stages'])
    # Shared verifier binds/preflights match the prover except these calls.
    # Before witness preparation, prove_inner borrows both native key owners.
    # Final prove_inner also preflights once before bind() preflights again:
    # five source contexts + public-key context + one helper context.
    stages['prover_retained_key_preparation'] = [1, 0, 1, 0]
    stages['prover_final_extra_preflight'] = [0, 0, 6, 1]
    roles = [sum(row[i] for row in stages.values()) for i in range(4)]
    external = sum(roles)
    hashes = commitments['hash_queries_upper_bound'] + openings['hash_queries_upper_bound'] + external + 2
    byte_count = (commitments['hash_input_bytes_upper_bound']
        + openings['hash_input_bytes_upper_bound']
        + external*setup['context_hash_input_bytes_upper_bound']
        + 2*setup['profile_id_hash_input_bytes'])
    return dict(scope='Successful classical native Brakedown v12 proving facade; retained setup supplied',
        commitments=commitments, openings=openings,
        external_context_stages=stages, external_role_context_calls=roles,
        external_context_hash_queries=external, direct_profile_id_hash_queries=2,
        hash_queries_upper_bound=hashes, hash_input_bytes_upper_bound=byte_count,
        max_hash_input_bytes_upper_bound=max(commitments['max_hash_input_bytes_upper_bound'],
            openings['max_hash_input_bytes_upper_bound'], setup['profile_id_hash_input_bytes']),
        successful_prover_hash_resources_bounded=True,
        setup_included=False, xof_resources_bounded=False,
        rejected_prover_paths_bounded=False, full_prover_resources_bounded=False,
        all_trials_bound_established=False, security_qualified=False, performance_gate=False)


def prover_stopped_resource_model(descriptor):
    """Conditional native Brakedown prover XOF model, with analysis-only stops.

    Successful honest prover/verifier transcript requests must match on the
    same proof; this is an explicit coupling premise, not proved by arithmetic.
    Production samplers remain uncapped. A completed measured run is only a
    control of that premise, never a bound on all possible oracle streams.
    """
    from classical_candidate_terms import candidate_terms
    hashes = prover_hash_resources(descriptor)
    candidate = candidate_terms(descriptor)
    query = candidate['verifier_xof_resource_envelope']
    output = candidate['verifier_xof_output_envelope']
    frame = candidate['verifier_frame_resource_envelope']
    maximum_input = frame['maximum_xof_query_input_bytes']
    return dict(scope='Conditional successful honest native Brakedown prover in stopped ideal game',
        hash_resources=hashes,
        xof_queries_upper_bound=query['totals']['xof_queries'],
        field_sampling_phases_upper_bound=query['totals']['field_phases'],
        xof_input_bytes_upper_bound=query['totals']['xof_queries']*maximum_input,
        max_xof_input_bytes_upper_bound=maximum_input,
        xof_output_bytes_upper_bound=output['total_xof_output_bytes'],
        max_xof_output_bytes_upper_bound=output['total_xof_output_bytes'],
        additional_sampler_stop_union=output['additional_sampler_stop_union'],
        stops=['First rejected lookup reciprocal challenge',
               'First field value requiring more than 512 canonical candidates']
              + (['First sequential column draw requiring more than eight candidates']
                 if candidate['profile']['descriptor_version']==4 else []),
        required_premises=['Successful honest prover and matched verifier have the same typed transcript request schedule',
            'Trusted source/claim/frame bounds cover that schedule',
            'Fresh independent ideal streams justify each sampler stop charge'],
        analysis_only_stops=True, production_loops_capped=False,
        prover_verifier_resource_coupling_established=False,
        unconditional_prover_resources_bounded=False,
        all_honest_work_bounded=False, all_trials_bound_established=False,
        security_qualified=False, performance_gate=False)
