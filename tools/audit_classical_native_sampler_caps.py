"""Compare fully audited native counter records with conditional verifier caps.

Passing observations are regression evidence, not universal adversarial bounds.
Production executions beyond analysis stops remain valid counter observations.
"""
import argparse

from audit_artifacts import write_json_new
from audit_classical_native_oracle_counts import audit
from classical_candidate_terms import candidate_terms
from classical_window_work import native_first_query_sampler_stop_polynomial


def compare_audited_records(records):
    """Input must already pass the native count/phase-maxima auditor."""
    header = records['profile']
    candidate = candidate_terms(bytes.fromhex(header['descriptor_bincode_hex']))
    if candidate['profile_id_sha512'] != header['profile_id_sha512']:
        raise ValueError('candidate/count profile identity mismatch')
    sampler = native_first_query_sampler_stop_polynomial(candidate, honest_xof_outputs=0)
    field = candidate['sampler_resource_envelope']
    geometry = sampler['column_geometry']
    shape_caps = dict(max_field_values_per_phase=field['coefficient_count_ceiling'],
                      max_column_values_per_phase=0 if geometry is None else geometry['ordered_draws'])
    totals = candidate['verifier_xof_resource_envelope']['totals']
    caps = dict(hash_queries=candidate['verifier_hash_outputs_upper_bound'],
        xof_queries=totals['xof_queries'], field_sampling_phases=totals['field_phases'],
        max_hash_input=candidate['verifier_hash_input_envelope']['maximum_hash_query_input_bytes'],
        max_xof_input=candidate['verifier_frame_resource_envelope']['maximum_xof_query_input_bytes'],
        xof_output_bytes=candidate['verifier_xof_output_envelope']['total_xof_output_bytes'])
    outcomes = []
    for kind, rows in [('accepted', records['measurements']), ('rejected', records['rejected_measurements'])]:
        for row in rows:
            for key, bound in shape_caps.items():
                if row[key] > bound:
                    raise ValueError('observed sampler shape exceeds conditional cap: '+key)
            outside = []
            if row['lookup_reciprocal_rejections']:
                outside.append('lookup retry')
            if row['max_field_candidates_per_value'] > field['candidate_limit_per_coefficient']:
                outside.append('field candidate excess')
            if geometry is not None and row['max_column_candidates_per_value'] > geometry['rejected_candidate_limit']:
                outside.append('column candidate excess')
            if not outside:
                for key, bound in caps.items():
                    if row[key] > bound:
                        raise ValueError('observed stopped execution exceeds conditional cap: '+key)
            outcomes.append(dict(kind=kind, ordinal=row['ordinal'], proof_sha256=row['proof_sha256'],
                shape_caps_satisfied=True, stopped_caps_checked=not outside,
                outside_analysis_stops=outside,
                observed_phase_maxima={key: row[key] for key in shape_caps}))
    return dict(profile_id_sha512=header['profile_id_sha512'],
        profile_descriptor_sha512=header['profile_descriptor_sha512'],
        shape_caps=shape_caps, conditional_verifier_caps=caps, records=outcomes,
        stopped_records_checked=sum(row['stopped_caps_checked'] for row in outcomes),
        outside_stopped_game_records=sum(bool(row['outside_analysis_stops']) for row in outcomes),
        honest_activity_compared_to_verifier_caps=False, direct_primitive_calls_included=False,
        scope='Observed accepted/rejected native interface records only; excludes honest setup/prover caps',
        deterministic_resource_bound_established=False, native_verifier_caps_established=False,
        security_qualified=False, performance_qualified=False)


def audit_native_sampler_caps(path):
    records = audit(path, require_rejections=True, require_lookup_retry_counts=True,
        require_field_sampling_counts=True, require_honest_activity=True,
        require_xof_output_counts=True, require_column_sampling_counts=True,
        require_sampler_phase_maxima=True)
    result = compare_audited_records(records)
    result.update(log=records['log'], log_sha256=records['log_sha256'],
                  completed_proofs=records['completed_proofs'],
                  rejected_executions_checked=records['rejected_executions_checked'], native=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit_native_sampler_caps(args.log))


if __name__ == '__main__':
    main()
