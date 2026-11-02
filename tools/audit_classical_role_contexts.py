"""Join caller role diagnostics to captured Brakedown parameter preimages.

This checks observed geometry, not NTT-root algebra or semantic stage admission.
"""
import argparse
import json
from pathlib import Path

from audit_artifacts import write_json_new
from audit_classical_native_oracle_counts import audit as audit_counts
from audit_classical_native_reader_events import audit as audit_bindings
from audit_classical_reader_event_stream import audit as audit_stream
from classical_profile_descriptor import Reader
from compare_classical_native_validation import records
from classical_brakedown_geometry import role_geometry

PREFIX = 'HB_CLASSICAL_ROLE_CONTEXTS '
PARAMETERS = b'HasteBoots/mw-parameters/v2'
DOMAIN = b'block-rs/negacyclic-ntt/v1'


def parse_context_geometry(data, profile, role):
    """Check the complete serialized geometry; root algebra remains separate."""
    expected = role_geometry(profile, role)
    if not data.startswith(PARAMETERS):
        raise ValueError('Brakedown parameter preimage namespace required')
    reader = Reader(data[len(PARAMETERS):])
    if reader.string() != profile['prime']:
        raise ValueError('context base modulus mismatch')
    observed = tuple(reader.unsigned() for _ in range(6))
    keys = ('num_vars', 'width', 'left_vars', 'ordered_quota', 'block_width', 'codeword_blocks')
    if observed != tuple(expected[key] for key in keys):
        raise ValueError('parameter context differs from caller role geometry')
    if reader.take(reader.unsigned()) != DOMAIN:
        raise ValueError('unsupported row-code namespace')
    code = tuple(reader.unsigned() for _ in range(4))
    if code != tuple(expected[key] for key in ('message_len', 'block_width', 'message_blocks', 'codeword_blocks')):
        raise ValueError('serialized block-code geometry mismatch')
    if reader.string() != profile['prime']:
        raise ValueError('serialized block-code modulus mismatch')
    root = reader.unsigned(32 if profile['prime'] == '2013265921' else 64)
    if reader.at != len(reader.data):
        raise ValueError('trailing parameter context bytes')
    return dict(expected, ntt_root_wire_repr=root, ntt_root_algebra_checked=False)


def audit(log, *, toy=False):
    counts = audit_counts(log, toy=toy, require_rejections=True, require_lookup_retry_counts=True,
        require_field_sampling_counts=True, require_honest_activity=True, require_xof_output_counts=True,
        require_column_sampling_counts=True, require_sampler_phase_maxima=True)
    binding = audit_bindings(log, toy=toy)
    proof = records(log, toy=toy)[0]
    rows = [json.loads(line[len(PREFIX):]) for line in Path(log).read_text().splitlines()
            if line.startswith(PREFIX)]
    if len(rows) != 1:
        raise ValueError('one caller context diagnostic required')
    row = rows[0]
    expected = dict(profile_id_sha512=proof['profile_id_sha512'], caller_factory_contexts=True,
                    native=not toy, ring_dimension=proof['ring_dimension'], lwe_dimension=proof['lwe_dimension'],
                    security_qualified=False, performance_gate=False)
    for key, value in expected.items():
        if type(row.get(key)) is not type(value) or row[key] != value:
            raise ValueError('role context/proof binding mismatch: '+key)
    contexts = row.get('role_contexts_sha512')
    if (not isinstance(contexts, list) or len(contexts) != 4
            or any(not isinstance(h, str) or len(h) != 128
                   or any(c not in '0123456789abcdef' for c in h) for h in contexts)):
        raise ValueError('four canonical role contexts required')
    known = {h: [i for i, value in enumerate(contexts) if value == h] for h in contexts}
    preimages, geometries, additional = {}, {}, set()

    def hashed(phase, output, data):
        digest = output.hex()
        if digest not in known:
            if data[:len(PARAMETERS)] == PARAMETERS:
                additional.add(digest)
            return
        data = bytes(data)
        if digest in preimages and preimages[digest] != data:
            raise ValueError('conflicting declared context preimages')
        preimages[digest] = data
        for role in known[digest]:
            geometries[role] = parse_context_geometry(data, counts['profile'], role)

    trace = binding['traces'][0]
    streamed = audit_stream(trace['path'], trace['trace_sha512'], on_hash=hashed)
    if set(geometries) != set(range(4)):
        raise ValueError('declared role context preimages missing from accepted capture')
    return dict(log=counts['log'], log_sha256=counts['log_sha256'],
        profile_id_sha512=proof['profile_id_sha512'], native=not toy,
        accepted_trace_sha512=streamed['trace_sha512'],
        roles=[dict(role=i, context_sha512=contexts[i], geometry=geometries[i]) for i in range(4)],
        additional_parameter_contexts=sorted(additional),
        all_declared_context_preimages_observed=True,
        all_parameter_contexts_declared=not additional,
        caller_diagnostics_trusted_as_factory_output=True,
        ntt_root_algebra_checked=False, semantic_stage_binding_established=False,
        arbitrary_query_coverage_established=False, security_qualified=False, performance_qualified=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log')
    parser.add_argument('--toy', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit(args.log, toy=args.toy))
