#!/usr/bin/env python3
"""Compare observed native verifier activity with conditional model ceilings.

Agreement is a sample consistency check, never a deterministic bound or proof.
"""
import argparse
import hashlib
import json
from pathlib import Path

from audit_classical_native_oracle_counts import audit, COLUMN_SAMPLER_KEYS
from classical_candidate_terms import candidate_terms


def comparison(path, *, require_xof_output_counts=False):
    evidence = audit(path, require_rejections=True, require_lookup_retry_counts=True,
                     require_field_sampling_counts=True,
                     require_xof_output_counts=require_xof_output_counts)
    descriptor = bytes.fromhex(evidence['profile']['descriptor_bincode_hex'])
    model = candidate_terms(descriptor)
    assert model['profile_id_sha512'] == evidence['profile']['profile_id_sha512']
    phase = model['sampler_resource_envelope']
    queries = model['verifier_xof_resource_envelope']['totals']
    output = model['verifier_xof_output_envelope']
    hash_length = model['verifier_hash_input_envelope']['maximum_hash_query_input_bytes']
    xof_length = model['verifier_frame_resource_envelope']['maximum_xof_query_input_bytes']
    profile_length = len(b'HasteBoots classical profile v1') + len(descriptor)
    hash_queries = model['verifier_hash_outputs_upper_bound']
    field_values = output['field_phases'] * phase['coefficient_count_ceiling']
    limits = dict(hash_queries=hash_queries, hash_input_bytes=hash_queries * hash_length,
                  max_hash_input=hash_length, xof_queries=queries['xof_queries'],
                  xof_input_bytes=queries['xof_queries'] * xof_length,
                  max_xof_input=xof_length, field_sampling_phases=output['field_phases'],
                  field_values_sampled=field_values,
                  field_candidate_draws=field_values * phase['candidate_limit_per_coefficient'],
                  field_output_bytes=output['field_raw_output_bytes'],
                  max_field_phase_output_bytes=phase['maximum_raw_bytes'],
                  xof_output_bytes=output['total_xof_output_bytes'],
                  # Conservative: total output also bounds any single reader.
                  max_xof_output=output['total_xof_output_bytes'])
    column_roles = [role for role in model['verifier_xof_resource_envelope']['pcs']['roles']
                    if 'column_sampler' in role]
    if column_roles:
        limits.update(column_sampling_phases=sum(role['calls'] for role in column_roles),
                      column_values_sampled=sum(role['column_sampler']['independent_draws'] for role in column_roles),
                      column_candidate_draws=sum(role['column_sampler']['byte_challenge_queries_upper_bound']
                                                 for role in column_roles))
    results = []
    for stage, rows in [('accepted', evidence['measurements']),
                        ('rejected', evidence['rejected_measurements'])]:
        for row in rows:
            observed = dict(row)
            # Both observed verifier paths perform the profile check and create
            # the parent transcript. These direct SHA512 calls are not observed
            # by CountingSha512. The model already includes these two calls.
            observed['hash_queries'] += 2
            observed['hash_input_bytes'] += 2 * profile_length
            observed['max_hash_input'] = max(observed['max_hash_input'], profile_length)
            column_stop = True
            if column_roles:
                column_stop = (row['max_column_candidates_per_value'] <= min(
                    role['column_sampler']['candidate_limit_per_draw'] for role in column_roles)
                    if all(key in row for key in COLUMN_SAMPLER_KEYS) else None)
            stops = dict(before_first_lookup_retry=row['lookup_reciprocal_rejections'] == 0,
                         before_field_candidate_excess=(row['max_field_candidates_per_value']
                                                       <= phase['candidate_limit_per_coefficient']),
                         before_column_candidate_excess=column_stop)
            domain = (False if False in stops.values() else
                      None if None in stops.values() else True)
            checks = {key: dict(observed=observed.get(key), conditional_ceiling=ceiling,
                               within_ceiling=(observed[key] <= ceiling if key in observed else None))
                      for key, ceiling in limits.items()}
            results.append(dict(stage=stage, ordinal=row['ordinal'],
                                proof_sha256=row['proof_sha256'],
                                stopping_condition_observations=stops,
                                observed_in_stopped_domain=domain, comparisons=checks))
    within = [check['within_ceiling'] for row in results for check in row['comparisons'].values()]
    domains = [row['observed_in_stopped_domain'] for row in results]
    return dict(log=evidence['log'], log_sha256=evidence['log_sha256'],
                profile_id_sha512=model['profile_id_sha512'], completed_proofs=evidence['completed_proofs'],
                executions=results, all_recorded_metrics_within_conditional_ceilings=all(
                    value is not False for value in within),
                all_metrics_recorded=all(value is not None for value in within),
                all_executions_observed_in_stopped_domain=(False if False in domains else
                                                          None if None in domains else True),
                sample_conditional_comparison_passed=all(value is True for value in within + domains),
                fixed_direct_profile_hash_calls_added_per_execution=2,
                fixed_direct_profile_hash_input_bytes_per_call=profile_length,
                direct_calls_observed=False,
                honest_activity_compared_to_verifier_ceilings=False,
                model_resource_coupling_established=model['verifier_frame_resource_envelope'][
                    'global_resource_bound_established'],
                required_model_premises=model['verifier_frame_resource_envelope']['required_premises'],
                missing_protocol_arguments=model['missing'],
                deterministic_resource_bound_established=False,
                security_qualified=False, performance_gate=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--require-xof-output-counts', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = comparison(args.log, require_xof_output_counts=args.require_xof_output_counts)
    names = ('compare_classical_native_resources.py', 'audit_classical_native_oracle_counts.py',
             'compare_classical_native_validation.py', 'classical_candidate_terms.py',
             'classical_sampler_resources.py', 'classical_parent_phases.py',
             'classical_profile_descriptor.py', 'polyfrim_opening_terms.py',
             'fragmented_opening_terms.py', 'brakedown_opening_terms.py')
    result['analysis_source_sha256'] = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in names}
    with Path(args.output).open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
