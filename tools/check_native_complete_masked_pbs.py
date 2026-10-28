#!/usr/bin/env python3
"""Check native PBS artifact/report consistency, not cryptographic proof validity."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--replay-log', type=Path)
    args = parser.parse_args()
    directory = args.directory
    record = json.loads((directory / 'verified-record.json').read_text())
    expected = {'algebra::BabyBear': (8, 76, [18, 21, 8, 11]),
                'algebra::Goldilocks': (4, 132, [19, 21, 9, 11])}
    width, slots, dims = expected[record['field']]
    assert record['protocol_version'] == 11 and record['queries'] == 128
    assert record['lookup_repetitions'] == 1 and record['width'] == width
    assert record['ring_dimension'] == 1024
    assert record['lwe_dimension'] == record['output_dimension'] == 728
    assert record['root_slots'] == slots
    for key in ['verified', 'altered_output_rejected', 'complete_pbs', 'original_size', 'transient_cache']:
        assert record[key] is True
    for key in ['whole_security_matched', 'hiding_certified', 'performance_gate']:
        assert record[key] is False
    for file, key in [('proof.bin', 'proof_sha256'), ('statement.bin', 'statement_sha256'),
                      ('trusted-setup.bin', 'trusted_setup_sha256'),
                      ('parameters.bin', 'parameters_sha256'),
                      ('fhe-parameters.txt', 'fhe_parameters_sha256')]:
        assert digest(directory / file) == record[key], file
    assert (directory / 'proof.bin').stat().st_size == record['proof_bytes'] > 0
    geometry = json.loads((directory / 'geometry.json').read_text())
    logical = [dims[0]] * 5 + [dims[1]] + [dims[0]] * 5 + [dims[2]] * 5 + [dims[3]]
    budgets = [width + 2, width + 1, 1, 2, 3, 2, width + 1,
               width + 8, width + 1, 3, 2, width + 2, width + 1, 1, 2, 3, 2]
    assert len(geometry) == len(logical) == len(budgets) == 17
    for (variables, physical, lanes, budget), expected_vars, expected_budget in zip(geometry, logical, budgets):
        assert variables == expected_vars and physical >= variables and lanes == width and budget == expected_budget
        allowance = budget * (width + 8 * 128 * (width + 1) * (physical + 2))
        assert (1 << physical) >= allowance
        if physical > variables:
            previous = budget * (width + 8 * 128 * (width + 1) * (physical + 1))
            assert (1 << (physical - 1)) < previous
    replayed = False
    if args.replay_log:
        rows = [json.loads(line.split(' ', 1)[1]) for line in args.replay_log.read_text().splitlines()
                if line.startswith('HB_NATIVE_COMPLETE_MASKED_REPLAY ')]
        assert len(rows) == 1
        replay = rows[0]
        for key in ['field', 'proof_sha256', 'proof_bytes', 'statement_sha256', 'parameters_sha256',
                    'trusted_setup_sha256', 'native_key_roots_sha256', 'verified', 'original_size',
                    'complete_pbs', 'whole_security_matched']:
            assert replay[key] == record[key], key
        replayed = True
    print(json.dumps(dict(field=record['field'], proof_sha256=record['proof_sha256'],
                          proof_bytes=record['proof_bytes'], artifacts_match=True,
                          fresh_process_replay_report_matches=replayed,
                          cryptographic_verifier=False, whole_security_matched=False)))


if __name__ == '__main__':
    main()
