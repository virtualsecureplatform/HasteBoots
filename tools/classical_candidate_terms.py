#!/usr/bin/env python3
"""Compose conditional parent/PCS terms for a caller-selected native descriptor.

Never loads verifier parameters or certifies security. Trusted Rust factory
admission, all fixed-word/prefix lemmas and global oracle/work caps remain required.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from classical_profile_descriptor import decode_descriptor
from classical_parent_phases import parent_stages
from polyfrim_opening_terms import opening_terms, encode, shared_stage_schedule, authentication_resources as poly_authentication
from fragmented_opening_terms import terms as fragmented_terms
from brakedown_opening_terms import opening_terms as brakedown_terms
from fragmented_opening_terms import authentication_resources as fragmented_authentication
from classical_sampler_resources import (native_phase_envelope, column_rejection_envelope,
    native_pcs_query_envelope, native_verifier_query_envelope, native_verifier_output_envelope,
    native_pcs_frame_envelope, native_verifier_frame_envelope, native_hash_input_envelope)


def parent_context_inventory(profile):
    """Context calls outside PCS, before applying backend hash multiplicity."""
    bits = (int(profile['prime'])-1).bit_length()
    d, s = (bits+7)//8, (bits+4)//5
    stages = dict(
        outer_validation_twice=[24, 4, 12, 4],
        outer_context_binding=[10, 1, 5, 1],
        main_public_key=[1, 0, 0, 0],
        main_product_factors=[4*d+1, 0, 0, 0],
        main_and_monomial_ntt=[4*d+6, 0, 0, 0],
        main_shared_comparisons=[20*d+12, 2*d+2, 0, 0],
        accumulator=[7, 0, 0, 0],
        monomial=[3, 0, 0, 0],
        final_key_preflight_binding_public_key_and_known_input=[0, 0, 13, 2],
        final_ntt=[0, 0, 2*s+2, 0],
        final_product_factors=[0, 0, 2*s+1, 0],
        final_shared_comparison=[0, 0, 10*s+6, s+1])
    calls = [sum(row[i] for row in stages.values()) for i in range(4)]
    per_context = 2 if profile['backend'] == 'PolyfrimDictionary' else 1
    return dict(stages=stages, role_context_calls=calls,
        hashes_per_context=per_context, total_context_hash_outputs=sum(calls)*per_context,
        # The public classical wrapper computes the trusted profile ID once
        # explicitly and once in parent_transcript; these use SHA512 directly.
        outer_profile_id_hash_outputs=2,
        scope='Native shared verifier parent contexts and outer profile ID checks; preprocessing excluded')


def candidate_terms(descriptor):
    profile = decode_descriptor(descriptor)
    prime, degree = int(profile['prime']), profile['extension_degree']
    widths, variables, queries = (profile[k] for k in ('role_widths', 'role_variables', 'role_queries'))
    parent = parent_stages(prime, degree, widths[0], schedule_version=profile['descriptor_version'])
    if (variables != parent['role_variables'] or widths[2] != widths[0]
            or any(w not in (widths[0], degree) for w in (widths[1], widths[3]))
            or any(type(q) is not int or q < 1 for q in queries)
            or profile['blowup'] not in (2, 4, 8)):
        raise ValueError('descriptor differs from supported original native role geometry')
    backend = profile['backend']
    brakedown = backend == 'Brakedown'
    fragmented = backend in ('FragmentedPipfri', 'FragmentedPipfriVirtual')
    if fragmented:
        if len(set(widths)) != 1 or profile['fragment_vars'] not in (8, 10, 12, 14, 16):
            raise ValueError('supported fragmented native widths/cap required')
    elif profile['fragment_vars'] is not None:
        raise ValueError('direct PolyFRIM must not carry a fragment cap')
    if not brakedown and any(x is not None for k in ('role_left_vars', 'role_block_widths') for x in profile[k]):
        raise ValueError('non-Brakedown descriptor carries row-code geometry')
    schedule = shared_stage_schedule(dict(prime=prime, width=widths[0], lwe_dimension=728,
                                          lookup_repetitions=1))
    roles = []
    pcs_union = Fraction()
    for role in range(4):
        if brakedown:
            row = brakedown_terms(variables[role], widths[role], profile['role_left_vars'][role],
                profile['role_block_widths'][role], profile['blowup'], queries[role], prime)
            error = row['total']
            row = {k: encode(v) if isinstance(v, Fraction) else v for k, v in row.items()}
            count = schedule['role_opening_call_ceilings'][role]
            model = ('PCS call ceiling; one atomic column phase' if profile['descriptor_version'] == 5 else
                     'PCS call ceiling; sequential column-byte prefix coupling remains required for schedule four')
            auth = dict(per_call_upper_bound=row['authentication_hash_outputs_upper_bound'], calls=count)
            auth_total = count*row['authentication_hash_outputs_upper_bound']
            column_sampler = column_rejection_envelope(row['encoded_blocks'], queries[role])
            binding_hashes_per_call = 1
        elif fragmented:
            mode = 'virtual' if backend == 'FragmentedPipfriVirtual' else 'reference'
            row = fragmented_terms(prime, degree, variables[role], widths[role],
                profile['fragment_vars'], profile['blowup'], queries[role], mode)
            error = Fraction(row['interactive_union'])
            count = schedule['role_opening_call_ceilings'][role]
            model = 'PCS call ceiling; one ordered bridge per call'
            auth = fragmented_authentication(variables[role], widths[role], profile['fragment_vars'],
                                            profile['blowup'], queries[role], mode)
            auth_total = count*auth['authentication_hash_outputs']
            auth = dict(per_call=auth, calls=count)
            binding_hashes_per_call = 7 if mode == 'virtual' else 4
        else:
            row = opening_terms(variables[role], prime, degree, queries[role], profile['blowup'])
            error = row['total']
            row = {k: encode(v) for k, v in row.items()}
            count = schedule['role_ordered_query_ceilings'][role]
            model = 'Conservatively charge each ordered query as a separate opening'
            auth = poly_authentication(variables[role], queries[role], count,
                schedule['role_opening_call_ceilings'][role], profile['blowup'])
            auth_total = auth['authentication_hash_outputs']
            auth = dict(per_role=auth)
            binding_hashes_per_call = max(1, variables[role])+(3 if backend == 'PolyfrimDictionary' else 2)
        contribution = count*error
        pcs_union += contribution
        roles.append(dict(role=role, queries=queries[role], charged_openings=count,
                          count_model=model, per_opening=row, contribution=encode(contribution),
                          authentication_resources=auth,
                          authentication_hash_outputs_upper_bound=auth_total))
        binding_total = schedule['role_opening_call_ceilings'][role]*binding_hashes_per_call
        roles[-1].update(pcs_binding_hash_outputs_per_call=binding_hashes_per_call,
            pcs_binding_hash_outputs_upper_bound=binding_total,
            pcs_total_hash_outputs_upper_bound=auth_total+binding_total)
        if brakedown and profile['descriptor_version'] == 4:
            roles[-1]['column_sampler_resource_envelope'] = dict(
                per_call=column_sampler, calls=count,
                all_calls=column_rejection_envelope(row['encoded_blocks'], count*queries[role]))
    parent_union = Fraction(parent['conditional_phase_union'])
    parent_hashes = parent_context_inventory(profile)
    pcs_hashes = sum(r['pcs_total_hash_outputs_upper_bound'] for r in roles)
    return dict(profile=profile,
        profile_id_sha512=hashlib.sha512(b'HasteBoots classical profile v1'+descriptor).hexdigest(),
        profile_descriptor_sha512=hashlib.sha512(descriptor).hexdigest(),
        parent=parent, roles=roles, shared_stage_schedule=schedule,
        parent_union=encode(parent_union), pcs_union=encode(min(Fraction(1), pcs_union)),
        conditional_ideal_game_union=encode(min(Fraction(1), parent_union+pcs_union)),
        authentication_hash_outputs_upper_bound=sum(r['authentication_hash_outputs_upper_bound'] for r in roles),
        authentication_scope='PCS authentication only; higher-level hashes/preprocessing excluded',
        pcs_total_hash_outputs_upper_bound=pcs_hashes,
        pcs_hash_scope='All standalone PCS verifier hashes; parent context calls and preprocessing excluded',
        parent_hash_resources=parent_hashes,
        verifier_hash_outputs_upper_bound=pcs_hashes+parent_hashes['total_context_hash_outputs']+2,
        verifier_hash_input_envelope=native_hash_input_envelope(),
        verifier_hash_scope='Typed verifier invocation including outer profile IDs; honest preprocessing excluded',
        sampler_resource_envelope=native_phase_envelope(profile, schedule),
        pcs_xof_resource_envelope=native_pcs_query_envelope(profile, schedule),
        verifier_xof_resource_envelope=native_verifier_query_envelope(profile, schedule, parent),
        verifier_xof_output_envelope=native_verifier_output_envelope(profile, schedule, parent),
        pcs_frame_resource_envelope=native_pcs_frame_envelope(profile, schedule),
        verifier_frame_resource_envelope=native_verifier_frame_envelope(profile, schedule, parent),
        scope='Conditional fixed-word ideal-challenge parent plus PCS subtotal',
        fixed_source_contract=dict(
            scope='One table per root/trusted context, shared by every opening',
            decoding='Unique promised decoding, coordinate-zero projection where applicable; zero fallback otherwise',
            false_pcs_task='Out-of-promise source or any false ordered claim',
            actual_hash_xof_coupling_established=False),
        missing=['Reviewed source/virtual-word and admissible-prefix composition',
                 *(['Schedule-four Brakedown sequential column-byte coupling'] if brakedown and profile['descriptor_version'] == 4 else []),
                 'Global hash/XOF, all-trials verifier/resource/work envelopes',
                 'Complete soundness and required knowledge argument',
                 'Rust factory admission and matched native performance gates'],
        whole_security_certified=False, promotion_gate=False, query_count_selected=False)


def candidate_oracle_work(descriptor, *, honest_hashes, honest_xof_outputs, honest_roots):
    """Descriptor-bound conditional oracle terms; all offsets must be supplied."""
    from hash_query_budget import joint_filtered_oracle_work
    candidate = candidate_terms(descriptor)
    inputs = candidate['verifier_frame_resource_envelope']['maximum_xof_query_input_bytes']
    hash_inputs = candidate['verifier_hash_input_envelope']['maximum_hash_query_input_bytes']
    result = joint_filtered_oracle_work(512, candidate['verifier_hash_outputs_upper_bound'],
        candidate['verifier_xof_resource_envelope']['totals']['xof_queries'],
        hash_inputs, inputs, honest_hashes, honest_xof_outputs, honest_roots)
    for family in ('merkle', 'xof'):
        result[family] = {k: encode(v) for k, v in result[family].items()}
    result.update(profile_id_sha512=candidate['profile_id_sha512'],
        verifier_hash_input_envelope=candidate['verifier_hash_input_envelope'],
        scope='Conditional descriptor-bound Merkle/XOF all-trials polynomials',
        excluded=['Algebraic/opening/sampler stop error composition',
                  'Actual candidate-prefix/source/filter coupling and knowledge',
                  'Rust factory admission and matched performance gates'])
    return result


def candidate_classical_work(descriptor, *, honest_hashes, honest_xof_outputs,
                             honest_roots, target_bits=128):
    """Union conditional all-trials components before optimizing integer work.

    This arithmetic does not prove candidate-prefix/source/filter admissibility.
    Honest XOF offsets conservatively receive phase opportunities as well as
    collision/link charges. No adversarial query cutoff is imposed.
    """
    from classical_work_cost import minimum_work
    if type(target_bits) is not int or target_bits < 1:
        raise ValueError('positive integer target bits required')
    candidate = candidate_terms(descriptor)
    if candidate['profile']['descriptor_version'] != 5:
        raise ValueError('combined work worksheet requires explicit atomic-column schedule five')
    oracle = candidate_oracle_work(descriptor, honest_hashes=honest_hashes,
        honest_xof_outputs=honest_xof_outputs, honest_roots=honest_roots)
    def exact(encoded):
        value = encoded['exact']
        return Fraction(int(value['numerator_hex'], 16), int(value['denominator_hex'], 16))
    pcs_errors = [exact(r['per_opening']['total']) if 'total' in r['per_opening'] else
                  Fraction(r['per_opening']['interactive_union']) for r in candidate['roles']]
    sampler = exact(candidate['sampler_resource_envelope']['first_excess_union'])
    adversarial = min(Fraction(1), max(Fraction(candidate['parent']['maximum_phase_error']),
                                     *pcs_errors)+sampler)
    submission = min(Fraction(1), exact(candidate['conditional_ideal_game_union'])+
        exact(candidate['verifier_xof_output_envelope']['additional_sampler_stop_union']))
    components = dict(phase=dict(constant=honest_xof_outputs*adversarial,
                                 linear=adversarial+submission, quadratic=Fraction()))
    for family in ('merkle', 'xof'):
        components[family] = {k: exact(v) for k, v in oracle[family].items()}
    total = {k: sum((c[k] for c in components.values()), Fraction())
             for k in ('constant', 'linear', 'quadratic')}
    work, bracket = minimum_work([total['linear'], total['quadratic']], total['constant'])
    return dict(profile_id_sha512=candidate['profile_id_sha512'], target_bits=target_bits,
        components={name: {k: encode(v) for k, v in c.items()} for name, c in components.items()},
        combined_polynomial={k: encode(v) for k, v in total.items()},
        adversarial_phase_error=encode(adversarial), verifier_submission_error=encode(submission),
        minimum_work_per_success_bound=encode(work),
        minimum_budget_per_success_bound=encode(work),
        work_measure="fixed_maximum_budget", unrestricted_expected_work_certified=False,
        conditional_work_target_met=work >= 2**target_bits,
        saturation_bracket=bracket, minimum_attack_budget=1,
        honest_offsets=dict(hashes=honest_hashes, xof_outputs=honest_xof_outputs, roots=honest_roots),
        scope='Conditional schedule-five phase/Merkle/XOF union, minimized over all positive integer work',
        required_premises=['Every candidate first-query prefix determines its trusted task/source state',
            'Uniform fixed-task conditional phase bounds and typed verifier call/claim ceilings',
            'Global source/root and eligible-window filters preserve the reduction',
            'Charged all-trials queries/submissions and justified honest offsets'],
        missing=['Actual complete prefix/source/filter and soundness/knowledge composition',
                 'Rust security admission and matched native performance gates'],
        protocol_bound_established=False, security_qualified=False,
        promotion_gate=False, query_count_selected=False)


def candidate_classical_work_with_setups(descriptor, *, setups, remaining_hashes,
                                         remaining_xof_outputs, remaining_roots,
                                         target_bits=128):
    """Add reviewed native setup costs to explicitly assumed remaining work.

    Setups count original preprocessing invocations across the modeled lifetime,
    not proofs using a retained key. Remaining offsets exclude these invocations.
    Their validity and the whole-protocol premises remain caller obligations.
    """
    from classical_setup_resources import setup_resources
    from hash_query_budget import integer
    integer(setups, 'setup invocations', 1)
    for name, value in (('remaining hashes', remaining_hashes),
                        ('remaining XOF outputs', remaining_xof_outputs),
                        ('remaining roots', remaining_roots)):
        integer(value, name)
    # The native parent/resource worksheets currently fix these radix widths.
    setup = setup_resources(descriptor, br_bits=8, ks_bits=5)
    result = candidate_classical_work(descriptor,
        honest_hashes=remaining_hashes + setups * setup['hash_queries_upper_bound'],
        honest_xof_outputs=remaining_xof_outputs + setups * setup['xof_queries'],
        honest_roots=remaining_roots + setups * setup['committed_roots'],
        target_bits=target_bits)
    result['honest_offset_inventory'] = dict(
        setup_invocations=setups, per_setup=setup,
        remaining_assumed_offsets=dict(hashes=remaining_hashes,
            xof_outputs=remaining_xof_outputs, roots=remaining_roots),
        remaining_offsets_established=False,
        all_honest_work_bounded=False)
    return result


def candidate_classical_work_for_lifetime(descriptor, *, setups, proofs,
        remaining_hashes, remaining_xof_outputs, remaining_roots, target_bits=128):
    """Conditional work with explicit native setup/proof lifetime inventories.

    Honest invocation counts are not adversarial-query cutoffs. Remaining
    offsets exclude the counted preprocessing/proving facade invocations.
    """
    from classical_setup_resources import setup_resources, prover_stopped_resource_model
    from hash_query_budget import integer
    integer(setups, 'setup invocations', 1)
    integer(proofs, 'proof invocations', 1)
    for name, value in (('remaining hashes', remaining_hashes),
                        ('remaining XOF outputs', remaining_xof_outputs),
                        ('remaining roots', remaining_roots)):
        integer(value, name)
    setup = setup_resources(descriptor, br_bits=8, ks_bits=5)
    prover = prover_stopped_resource_model(descriptor)
    hashes = setups*setup['hash_queries_upper_bound'] + proofs*prover['hash_resources']['hash_queries_upper_bound']
    outputs = proofs*prover['xof_queries_upper_bound']
    roots = setups*setup['committed_roots'] + proofs*prover['hash_resources']['commitments']['committed_roots']
    result = candidate_classical_work(descriptor,
        honest_hashes=remaining_hashes+hashes,
        honest_xof_outputs=remaining_xof_outputs+outputs,
        honest_roots=remaining_roots+roots, target_bits=target_bits)
    result['honest_offset_inventory'] = dict(setup_invocations=setups,
        proof_invocations=proofs, per_setup=setup, per_proof=prover,
        derived_offsets=dict(hashes=hashes, xof_outputs=outputs, roots=roots),
        remaining_assumed_offsets=dict(hashes=remaining_hashes,
            xof_outputs=remaining_xof_outputs, roots=remaining_roots),
        remaining_offsets_established=False, all_honest_work_bounded=False,
        prover_xof_coupling_established=False,
        honest_stopping_composition_established=False)
    result['required_premises'] += [
        'Selected honest prover/verifier request-schedule coupling and honest sampler-stop composition',
        'Remaining offsets cover factories, key generation and every other honest oracle activity']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--descriptor', type=Path, help='Caller-selected raw bincode descriptor')
    source.add_argument('--log', type=Path, help='Native log with one diagnostic trusted profile header')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--classical-work', action='store_true', help='Emit conditional combined work report; requires all honest offsets')
    parser.add_argument('--honest-hashes', type=int)
    parser.add_argument('--honest-xof-outputs', type=int)
    parser.add_argument('--honest-roots', type=int)
    parser.add_argument('--target-bits', type=int)
    parser.add_argument('--brakedown-setups', type=int,
        help='Add this many native 8/5-radix setups; explicit honest offsets then cover remaining work only')
    parser.add_argument('--brakedown-proofs', type=int,
        help='Also add this many native stopped prover invocations; requires --brakedown-setups')
    args = parser.parse_args()
    offsets = (args.honest_hashes, args.honest_xof_outputs, args.honest_roots)
    if args.classical_work and any(v is None for v in offsets):
        parser.error('--classical-work requires all three explicit honest offsets')
    if args.brakedown_proofs is not None and args.brakedown_setups is None:
        parser.error('--brakedown-proofs requires --brakedown-setups')
    if not args.classical_work and (any(v is not None for v in offsets)
            or args.target_bits is not None or args.brakedown_setups is not None):
        parser.error('honest offsets and target bits require --classical-work')
    if args.log is not None:
        from compare_classical_native_validation import profile_header
        header = profile_header(args.log)
        if header is None:
            parser.error('one trusted profile header is required')
        data = bytes.fromhex(header['descriptor_bincode_hex'])
    else:
        data = args.descriptor.read_bytes()
    try:
        if args.brakedown_proofs is not None:
            result = candidate_classical_work_for_lifetime(data,
                setups=args.brakedown_setups, proofs=args.brakedown_proofs,
                remaining_hashes=args.honest_hashes,
                remaining_xof_outputs=args.honest_xof_outputs,
                remaining_roots=args.honest_roots,
                target_bits=128 if args.target_bits is None else args.target_bits)
        elif args.brakedown_setups is not None:
            result = candidate_classical_work_with_setups(data, setups=args.brakedown_setups,
                remaining_hashes=args.honest_hashes,
                remaining_xof_outputs=args.honest_xof_outputs,
                remaining_roots=args.honest_roots,
                target_bits=128 if args.target_bits is None else args.target_bits)
        else:
            result = (candidate_classical_work(data, honest_hashes=args.honest_hashes,
                honest_xof_outputs=args.honest_xof_outputs, honest_roots=args.honest_roots,
                target_bits=128 if args.target_bits is None else args.target_bits)
                if args.classical_work else candidate_terms(data))
    except ValueError as error:
        parser.error(str(error))
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
