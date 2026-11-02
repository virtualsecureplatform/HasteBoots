"""Bind the first verifier reader captures to completed native correctness rows."""
import argparse
import json
import os
from pathlib import Path

from audit_artifacts import write_json_new
from audit_classical_native_oracle_counts import audit as audit_counts
from audit_classical_reader_event_stream import audit as audit_stream
from compare_classical_native_validation import records

PREFIX = 'HB_CLASSICAL_READER_TRACE '
METRICS = ('hash_queries', 'xof_queries', 'hash_input_bytes', 'xof_input_bytes',
           'max_hash_input', 'max_xof_input')


def audit_bound_trace(row, proof, measurement, kind, *, toy=False):
    """Proof and measurement must already pass the strict native row auditors."""
    expected = dict(kind=kind, ordinal=0, profile_id_sha512=proof['profile_id_sha512'],
        proof_sha256=proof['proof_sha256'], trusted_setup_sha256=proof['trusted_setup_sha256'],
        statement_sha256=proof['statement_sha256'] if kind == 'accepted' else measurement['altered_statement_sha256'],
        native=not toy, ring_dimension=proof['ring_dimension'], lwe_dimension=proof['lwe_dimension'],
        ordinary_counter_match=True, direct_primitive_calls_included=False,
        security_qualified=False, performance_gate=False)
    for key, value in expected.items():
        if type(row.get(key)) is not type(value) or row[key] != value:
            raise ValueError('reader trace/proof binding mismatch: '+key)
    encoded = row.get('trace_path_hex')
    if not isinstance(encoded, str) or not encoded:
        raise ValueError('reader trace path encoding missing')
    raw_path = bytes.fromhex(encoded)
    if raw_path.hex() != encoded:
        raise ValueError('noncanonical reader trace path encoding')
    fingerprint = row.get('trace_sha512')
    if (not isinstance(fingerprint, str) or len(fingerprint) != 128
            or any(c not in '0123456789abcdef' for c in fingerprint)):
        raise ValueError('invalid reader trace fingerprint')
    result = audit_stream(os.fsdecode(raw_path), fingerprint)
    if any(value for phase in ('setup', 'prove') for value in result['phases'][phase].values()):
        raise ValueError('verifier-only reader capture contains other phases')
    observed = result['phases']['verify']
    for key in METRICS:
        if observed[key] != measurement[key]:
            raise ValueError('reader trace/counter mismatch: '+key)
    for trace_key, counter_key in [('output_bytes', 'xof_output_bytes'),
                                   ('max_reader_output', 'max_xof_output')]:
        if observed[trace_key] != measurement[counter_key]:
            raise ValueError('reader output/counter mismatch: '+counter_key)
    result.update(kind=kind, ordinal=0, proof_sha256=proof['proof_sha256'],
        statement_sha256=expected['statement_sha256'], ordinary_counter_match_recorded=True)
    return result


def audit(log, *, toy=False):
    counts = audit_counts(log, toy=toy, require_rejections=True,
        require_lookup_retry_counts=True, require_field_sampling_counts=True,
        require_honest_activity=True, require_xof_output_counts=True,
        require_column_sampling_counts=True, require_sampler_phase_maxima=True)
    proofs = records(log, toy=toy)
    rows = []
    for line in Path(log).read_text().splitlines(keepends=True):
        if line.startswith(PREFIX):
            if not line.endswith('\n'):
                raise ValueError('partial reader capture record')
            rows.append(json.loads(line[len(PREFIX):]))
    if len(rows) != 2:
        raise ValueError('exactly the first accepted/rejected capture pair required')
    traces = [audit_bound_trace(row, proofs[0], measurement, kind, toy=toy)
              for row, measurement, kind in zip(rows,
                  (counts['measurements'][0], counts['rejected_measurements'][0]),
                  ('accepted', 'rejected'))]
    if traces[0]['path'] == traces[1]['path']:
        raise ValueError('accepted and rejected captures alias the same file')
    return dict(log=counts['log'], log_sha256=counts['log_sha256'],
        completed_proofs=len(proofs), captured_verifier_executions=2, native=not toy,
        traces=traces, scope='First accepted and altered-output rejected verifier executions only',
        direct_primitive_calls_included=False, complete_native_reader_coverage_established=False,
        ideal_stream_model_established=False, security_qualified=False, performance_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--toy', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit(args.log, toy=args.toy))


if __name__ == '__main__':
    main()
