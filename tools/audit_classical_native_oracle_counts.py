#!/usr/bin/env python3
"""Join measured interface counts to completed correctness proofs, never bounds."""
import argparse
import hashlib
import json
from pathlib import Path
from compare_classical_native_validation import profile_header, records

PHASE_MAX_KEYS = ('max_field_values_per_phase', 'max_column_values_per_phase')

PREFIX = 'HB_CLASSICAL_ORACLE_COUNTS '
HONEST_PREFIX = 'HB_CLASSICAL_HONEST_ORACLE_ACTIVITY '
REJECTION_PREFIX = 'HB_CLASSICAL_ORACLE_REJECTION_COUNTS '
COUNT_KEYS = ('hash_queries', 'hash_input_bytes', 'max_hash_input',
              'xof_queries', 'xof_input_bytes', 'max_xof_input')
COLUMN_SAMPLER_KEYS = ('column_sampling_phases', 'column_values_sampled',
                       'column_candidate_draws', 'max_column_candidates_per_value')
XOF_OUTPUT_KEYS = ('xof_output_bytes', 'max_xof_output')
FIELD_SAMPLER_KEYS = ('field_sampling_phases', 'field_values_sampled', 'field_candidate_draws',
                      'max_field_candidates_per_value', 'field_output_bytes',
                      'max_field_phase_output_bytes')


def audit(path, *, toy=False, require_rejections=False, require_lookup_retry_counts=False,
          require_field_sampling_counts=False, require_honest_activity=False, require_xof_output_counts=False, require_column_sampling_counts=False,
          require_sampler_phase_maxima=False):
    proofs = records(path, toy=toy)
    header = profile_header(path)
    if header is None:
        raise ValueError('trusted profile header required for count evidence')
    rows, rejections, activities = [], [], []
    with Path(path).open() as source:
        for line in source:
            prefix = next((p for p in (PREFIX, REJECTION_PREFIX, HONEST_PREFIX) if line.startswith(p)), None)
            if prefix is not None:
                if not line.endswith('\n'):
                    raise ValueError('partial oracle count record')
                (rows if prefix == PREFIX else rejections if prefix == REJECTION_PREFIX else activities).append(json.loads(line[len(prefix):]))
    if len(rows) != len(proofs):
        raise ValueError('oracle count/completed proof count mismatch')
    for row, proof in zip(rows, proofs):
        expected = dict(profile_id_sha512=proof['profile_id_sha512'],
                        proof_sha256=proof['proof_sha256'], ordinal=proof['ordinal'],
                        native=not toy, ring_dimension=proof['ring_dimension'],
                        lwe_dimension=proof['lwe_dimension'],
                        direct_primitive_calls_included=False,
                        security_qualified=False, performance_gate=False)
        for key, value in expected.items():
            if type(row.get(key)) is not type(value) or row[key] != value:
                raise ValueError('oracle count/proof binding mismatch: ' + key)
        for key in COUNT_KEYS:
            if type(row.get(key)) is not int or row[key] <= 0:
                raise ValueError('invalid positive integer oracle count: ' + key)
        for kind in ('hash', 'xof'):
            if row['max_' + kind + '_input'] > row[kind + '_input_bytes']:
                raise ValueError('oracle maximum exceeds total input bytes')
    if require_rejections or rejections:
        if len(rejections) != len(proofs):
            raise ValueError('rejected execution/completed proof count mismatch')
        for row, proof in zip(rejections, proofs):
            expected = dict(profile_id_sha512=proof['profile_id_sha512'],
                            proof_sha256=proof['proof_sha256'], ordinal=proof['ordinal'],
                            native=not toy, ring_dimension=proof['ring_dimension'],
                            lwe_dimension=proof['lwe_dimension'], rejected=True,
                            direct_primitive_calls_included=False,
                            security_qualified=False, performance_gate=False)
            for key, value in expected.items():
                if type(row.get(key)) is not type(value) or row[key] != value:
                    raise ValueError('rejected execution/proof binding mismatch: ' + key)
            altered = row.get('altered_statement_sha256')
            if (not isinstance(altered, str) or len(altered) != 64
                    or any(c not in '0123456789abcdef' for c in altered)
                    or altered == proof['statement_sha256']):
                raise ValueError('invalid altered-statement fingerprint')
            for key in COUNT_KEYS:
                if type(row.get(key)) is not int or row[key] < 0:
                    raise ValueError('invalid nonnegative rejected execution count: ' + key)
            for kind in ('hash', 'xof'):
                queries, total, maximum = (row[kind + '_queries'], row[kind + '_input_bytes'],
                                           row['max_' + kind + '_input'])
                if maximum > total or (queries == 0 and (total or maximum)) or (total > 0 and maximum == 0):
                    raise ValueError('inconsistent rejected execution input counts')
    if activities or require_honest_activity:
        if len(activities) != len(proofs) + 1:
            raise ValueError('honest activity/completed proof count mismatch')
        for index, row in enumerate(activities):
            proof = proofs[max(0, index - 1)]
            expected = dict(stage='setup' if index == 0 else 'prove',
                            ordinal=None if index == 0 else proof['ordinal'],
                            proof_sha256=None if index == 0 else proof['proof_sha256'],
                            profile_id_sha512=proof['profile_id_sha512'],
                            trusted_setup_sha256=proof['trusted_setup_sha256'],
                            native=not toy, ring_dimension=proof['ring_dimension'],
                            lwe_dimension=proof['lwe_dimension'], hash_input_bytes_recorded=False,
                            direct_primitive_calls_included=False,
                            security_qualified=False, performance_gate=False)
            for key, value in expected.items():
                if key not in row or type(row[key]) is not type(value) or row[key] != value:
                    raise ValueError('honest activity/proof binding mismatch: ' + key)
            if 'hash_input_bytes' in row or 'max_hash_input' in row:
                raise ValueError('unobserved honest hash input lengths must be absent')
            keys = ('hash_queries', 'xof_queries', 'xof_input_bytes', 'max_xof_input',
                    'lookup_reciprocal_rejections') + FIELD_SAMPLER_KEYS
            if any(type(row.get(key)) is not int or row[key] < 0 for key in keys):
                raise ValueError('invalid or missing honest activity count')
            if row['hash_queries'] == 0:
                raise ValueError('honest activity has no observed hash outputs')
            queries, total, maximum = (row['xof_queries'], row['xof_input_bytes'], row['max_xof_input'])
            if maximum > total or (queries == 0 and (total or maximum)) or (total > 0 and maximum == 0):
                raise ValueError('inconsistent honest activity input counts')
    all_measurements = rows + rejections + activities
    for row in all_measurements:
        if 'lookup_reciprocal_rejections' not in row:
            if require_lookup_retry_counts:
                raise ValueError('lookup retry count missing')
        elif (type(row['lookup_reciprocal_rejections']) is not int
              or row['lookup_reciprocal_rejections'] < 0):
            raise ValueError('invalid nonnegative lookup retry count')
    for row in all_measurements:
        present = [key in row for key in COLUMN_SAMPLER_KEYS]
        if not any(present):
            if require_column_sampling_counts:
                raise ValueError('column sampler counts missing')
            continue
        if not all(present):
            raise ValueError('partial column sampler counts')
        if any(type(row[key]) is not int or row[key] < 0 for key in COLUMN_SAMPLER_KEYS):
            raise ValueError('invalid nonnegative column sampler count')
        phases, values, draws, maximum = (row[key] for key in COLUMN_SAMPLER_KEYS)
        if (draws < values or draws > row['xof_queries']
                or (values == 0 and (draws or maximum))
                or (values > 0 and (phases == 0 or maximum == 0 or maximum > draws
                                   or maximum * values < draws or draws - maximum < values - 1))):
            raise ValueError('inconsistent column sampler counts')
    sequential_columns = (header['backend'] == 'Brakedown' and header['descriptor_version'] != 5)
    for row in all_measurements:
        if all(key in row for key in COLUMN_SAMPLER_KEYS):
            if not sequential_columns and any(row[key] for key in COLUMN_SAMPLER_KEYS):
                raise ValueError('sequential column counts contradict trusted sampler profile')
    # A completed Brakedown proof necessarily executes PCS sampling. Setup and
    # early rejected verifier executions need not reach any column draw.
    for row in rows + [row for row in activities if row['stage'] == 'prove']:
        if sequential_columns and all(key in row for key in COLUMN_SAMPLER_KEYS):
            if row['column_sampling_phases'] == 0 or row['column_values_sampled'] == 0:
                raise ValueError('completed sequential proof has no observed column sampling')
    candidate_bytes = ((int(header['prime']) - 1).bit_length() + 7) // 8
    for row in all_measurements:
        present = [key in row for key in FIELD_SAMPLER_KEYS]
        if not any(present):
            if require_field_sampling_counts:
                raise ValueError('field sampler counts missing')
            continue
        if not all(present):
            raise ValueError('partial field sampler counts')
        if any(type(row[key]) is not int or row[key] < 0 for key in FIELD_SAMPLER_KEYS):
            raise ValueError('invalid nonnegative field sampler count')
        phases, values, draws, maximum, output, phase_output = (row[key] for key in FIELD_SAMPLER_KEYS)
        if (draws < values or output != candidate_bytes * draws or 2 * phases > row['xof_queries']
                or phase_output > output or phase_output * phases < output
                or phase_output < candidate_bytes * maximum
                or (values == 0 and (draws or maximum or output or phase_output))
                or (values > 0 and (phases == 0 or maximum == 0 or maximum > draws
                                   or maximum * values < draws or draws - maximum < values - 1))):
            raise ValueError('inconsistent field sampler counts')
    for row in all_measurements:
        present = [key in row for key in XOF_OUTPUT_KEYS]
        if not any(present):
            if require_xof_output_counts:
                raise ValueError('XOF output counts missing')
            continue
        if not all(present):
            raise ValueError('partial XOF output counts')
        if any(type(row[key]) is not int or row[key] < 0 for key in XOF_OUTPUT_KEYS):
            raise ValueError('invalid nonnegative XOF output count')
        output, maximum = (row[key] for key in XOF_OUTPUT_KEYS)
        if maximum > output or maximum * row['xof_queries'] < output or (output > 0 and maximum == 0):
            raise ValueError('inconsistent XOF output counts')
        if all(key in row for key in COLUMN_SAMPLER_KEYS):
            if output < 8 * row['column_candidate_draws']:
                raise ValueError('XOF output counts omit column candidate bytes')
        if all(key in row for key in FIELD_SAMPLER_KEYS):
            # Each field phase reads its field stream and a 64-byte receipt.
            if (output < row['field_output_bytes'] + 64 * row['field_sampling_phases']
                    + 8 * row.get('column_candidate_draws', 0)
                    or maximum < row['max_field_phase_output_bytes']):
                raise ValueError('XOF output counts omit field stream or receipt bytes')
    for row in all_measurements:
        present = [key in row for key in PHASE_MAX_KEYS]
        if not any(present) and not require_sampler_phase_maxima:
            continue
        if not all(present):
            raise ValueError('sampler phase maxima missing or partial')
        if not all(key in row for key in FIELD_SAMPLER_KEYS+COLUMN_SAMPLER_KEYS):
            raise ValueError('sampler phase maxima require complete sampler counts')
        if any(type(row[key]) is not int or row[key] < 0 for key in PHASE_MAX_KEYS):
            raise ValueError('invalid sampler phase maximum')
        for maximum, total, phases in [
                (row['max_field_values_per_phase'], row['field_values_sampled'], row['field_sampling_phases']),
                (row['max_column_values_per_phase'], row['column_values_sampled'], row['column_sampling_phases'])]:
            if maximum > total or maximum*phases < total or (phases == 0 and maximum):
                raise ValueError('sampler phase maximum contradicts totals')
        field_max = row['max_field_values_per_phase']
        if (candidate_bytes*field_max > row['max_field_phase_output_bytes']
                or row['max_field_phase_output_bytes'] > candidate_bytes*field_max*row['max_field_candidates_per_value']):
            raise ValueError('field phase maximum contradicts observed bytes')
    phase_maxima_recorded = all(all(key in row for key in PHASE_MAX_KEYS) for row in all_measurements)
    accepted_field_counts_recorded = all(all(key in row for key in FIELD_SAMPLER_KEYS) for row in rows)
    accepted_retry_counts_recorded = all('lookup_reciprocal_rejections' in row for row in rows)
    return dict(log=str(Path(path).resolve()), completed_proofs=len(proofs),
                native=not toy, profile=header, measurements=rows,
                rejected_measurements=rejections,
                honest_activity=activities, honest_activity_recorded=bool(activities),
                column_sampling_counts_recorded=all(all(key in row for key in COLUMN_SAMPLER_KEYS)
                                                   for row in all_measurements),
                xof_output_counts_recorded=all(all(key in row for key in XOF_OUTPUT_KEYS)
                                               for row in all_measurements),
                rejected_executions_checked=len(rejections),
                lookup_retry_counts_recorded=all('lookup_reciprocal_rejections' in row for row in all_measurements),
                all_accepted_executions_before_first_lookup_retry=(
                    all(row['lookup_reciprocal_rejections'] == 0 for row in rows)
                    if accepted_retry_counts_recorded else None),
                observed_maximum_per_proof={key: max(row[key] for row in rows)
                                            for key in COUNT_KEYS},
                log_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                field_sampling_counts_recorded=all(all(key in row for key in FIELD_SAMPLER_KEYS)
                                                   for row in all_measurements),
                analytical_field_candidate_threshold=512,
                all_accepted_executions_before_field_candidate_excess=(
                    all(row['max_field_candidates_per_value'] <= 512 for row in rows)
                    if accepted_field_counts_recorded else None),
                sampler_phase_maxima_recorded=phase_maxima_recorded,
                observed_maximum_phase_values=({key: max(row[key] for row in all_measurements)
                                               for key in PHASE_MAX_KEYS} if phase_maxima_recorded else None),
                deterministic_resource_bound_established=False,
                direct_primitive_calls_included=False,
                security_qualified=False, performance_gate=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--toy', action='store_true',
                        help='explicitly validate n32/LWE21 instrumentation controls')
    parser.add_argument('--require-field-sampling-counts', action='store_true',
                        help='require actual canonical field sampler output metrics')
    parser.add_argument('--require-lookup-retry-counts', action='store_true',
                        help='require observed retry counters; no retry cutoff is imposed')
    parser.add_argument('--require-column-sampling-counts', action='store_true',
                        help='require observed sequential column candidate counts')
    parser.add_argument('--require-xof-output-counts', action='store_true',
                        help='require consumed output bytes and maximum per XOF reader')
    parser.add_argument('--require-sampler-phase-maxima', action='store_true',
                        help='require observed maximum accepted values per field/column phase')
    parser.add_argument('--require-honest-activity', action='store_true',
                        help='require setup and proof-bound honest activity observations')
    parser.add_argument('--require-rejections', action='store_true',
                        help='require one measured altered-output rejection per proof')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = audit(args.log, toy=args.toy, require_rejections=args.require_rejections,
                   require_lookup_retry_counts=args.require_lookup_retry_counts,
                   require_field_sampling_counts=args.require_field_sampling_counts,
                   require_honest_activity=args.require_honest_activity,
                   require_xof_output_counts=args.require_xof_output_counts,
                   require_column_sampling_counts=args.require_column_sampling_counts,
                   require_sampler_phase_maxima=args.require_sampler_phase_maxima)
    with Path(args.output).open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
