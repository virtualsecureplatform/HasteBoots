#!/usr/bin/env python3
"""Check small complete aggregated-PBS reports, not cryptographic proof validity."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--current-log', type=Path, required=True)
    parser.add_argument('--previous-json', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    text = args.current_log.read_text()
    assert 'test result: ok. 2 passed;' in text
    prefix = 'HB_COMPLETE_CANONICAL_MASKED_PROFILE '
    rows = [json.loads(line.split(prefix, 1)[1]) for line in text.splitlines() if prefix in line]
    expected = {(2013265921, 11): (8, 441, 165), (2013265921, 10): (8, 468, 177),
                (18446744069414584321, 11): (4, 499, 291),
                (18446744069414584321, 10): (4, 554, 317)}
    assert len(rows) == 4 and {(r['prime'], r['protocol_version']) for r in rows} == set(expected)
    previous = {(r['prime'], r['protocol_version']): r
                for r in json.loads(args.previous_json.read_text())['records']}
    comparisons = []
    for row in rows:
        key = row['prime'], row['protocol_version']
        width, children, sources = expected[key]
        old = previous[key]
        assert row['backend'] == 'aggregated-query' and old['backend'] == 'joint-source'
        assert row['width'] == width and row['polynomial_size'] == 32 and row['lwe_dimension'] == 21
        assert row['queries'] == row['lookup_repetitions'] == 1
        assert row['child_openings'] == children and row['source_certificates'] == sources
        assert row['query_ladder_fri_certificates'] == sources < children
        for name in ['verified', 'complete_pbs']:
            assert row[name] is True
        for name in ['original_size', 'whole_security_matched', 'performance_gate']:
            assert row[name] is False
        for name in ['fixture_sha256', 'parameters_sha256', 'fhe_parameters_sha256',
                     'native_key_roots_sha256', 'child_openings', 'source_certificates']:
            assert row[name] == old[name], (key, name)
        assert row['trusted_setup_sha256'] != old['trusted_setup_sha256']
        assert len(row['canonical_contexts_sha256']) == len(row['proof_sha256']) == 64
        assert row['proof_bytes'] < old['proof_bytes']
        comparisons.append(dict(prime=row['prime'], protocol_version=row['protocol_version'],
                                prior_bytes=old['proof_bytes'], aggregate_bytes=row['proof_bytes'],
                                reduction_pct=100 * (1 - row['proof_bytes'] / old['proof_bytes']),
                                prior_query_fri=children, aggregate_query_fri=sources))
    result = dict(records=rows, comparisons=comparisons, whole_security_matched=False,
                  performance_gate=False, cryptographic_verifier=False)
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(comparisons, indent=2))


if __name__ == '__main__':
    main()
