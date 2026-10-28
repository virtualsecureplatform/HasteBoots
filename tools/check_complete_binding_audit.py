#!/usr/bin/env python3
"""Check coverage and expected reports in complete binding-audit logs.

Cryptographic replay and production verification run in Rust. This validates
those emitted reports and their exact case coverage; it does not independently
verify proof bytes or certify security, hiding, or original-size parameters.
"""
import argparse
import json
from pathlib import Path
import re

ATTACKS = {'Control', 'Initial', 'Final', 'Addition', 'Chain', 'DigitA', 'DigitB',
           'Rotation', 'ExtractionA', 'ExtractionB', 'KeyProduct', 'SwitchKeyProduct',
           'CanonicalA', 'CanonicalB', 'SwitchCanonical'}
PRIMES = {2013265921, 18446744069414584321}
PREFIXES = {10: 'HB_V10_FRESH_LINKAGE_CASE ', 11: 'HB_V11_FRESH_BINDING_CASE '}


def parse(raw):
    records = []
    for line in raw.splitlines():
        for version, prefix in PREFIXES.items():
            if prefix in line:
                record = json.loads(line.split(prefix, 1)[1])
                assert record['protocol_version'] == version, 'prefix/version mismatch'
                records.append(record)
    return records


def validate(records, backend, versions):
    selected = [r for r in records if r['backend'] == backend and r['protocol_version'] in versions]
    expected = {(v, p, a) for v in versions for p in PRIMES for a in ATTACKS}
    seen = set()
    for r in selected:
        version, prime, attack = r['protocol_version'], r['prime'], r['attack']
        key = (version, prime, attack)
        assert key in expected and key not in seen, f'unexpected or duplicate case: {key}'
        seen.add(key)
        assert r['reference_scope'] == 'complete-strict-children-and-actual-root-openings'
        checks = {
            'reference_decomposition_valid': [[True, True, attack != 'CanonicalA'], [True, True, attack != 'CanonicalB']],
            'reference_switch_decomposition_valid': [True, True, attack != 'SwitchCanonical'],
            'reference_key_product_valid': attack != 'KeyProduct',
            'reference_switch_key_product_valid': attack != 'SwitchKeyProduct',
            'reference_linkage_valid': attack not in {'Initial', 'Final', 'Addition', 'Chain', 'DigitA', 'DigitB'},
            'reference_monomial_valid': attack != 'Rotation',
            'reference_extraction_valid': attack not in {'ExtractionA', 'ExtractionB'},
            'production_accepted': attack == 'Control',
            'encrypted_profile': False, 'original_size': False,
        }
        def bool_shape(actual, wanted):
            if isinstance(wanted, list):
                return isinstance(actual, list) and len(actual) == len(wanted) and all(
                    bool_shape(a, b) for a, b in zip(actual, wanted))
            return type(actual) is bool and actual == wanted
        for name, wanted in checks.items():
            assert bool_shape(r[name], wanted), (key, name, r[name], wanted)
        assert type(r['proof_bytes']) is int and r['proof_bytes'] > 0
        for name in ['proof_sha256', 'transcript_bytes']:
            assert re.fullmatch('[0-9a-f]{64}', r[name]), (key, name)
        if attack == 'Control':
            assert r['production_error'] is None
        else:
            label = ('false canonical linear identity' if attack in {'CanonicalA', 'CanonicalB', 'SwitchCanonical'}
                     else 'packed ZeroCheck terminal identity' if attack in {'KeyProduct', 'SwitchKeyProduct', 'ExtractionA', 'ExtractionB'}
                     else 'packed public monomial product' if attack == 'Rotation'
                     else 'packed accumulator linkage')
            assert isinstance(r['production_error'], str) and label in r['production_error'], key
    assert seen == expected, f'missing cases: {sorted(expected - seen)}'
    return sorted(selected, key=lambda r: (r['protocol_version'], r['prime'], r['attack']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--backend', required=True)
    parser.add_argument('--versions', nargs='+', type=int, choices=[10, 11], default=[10, 11])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = args.log.read_text()
    assert re.search(r'test result: ok\. \d+ passed; 0 failed;', raw), 'no successful Rust test completion'
    assert 'test result: FAILED.' not in raw and 'error: test failed' not in raw, 'Rust test failure in log'
    records = validate(parse(raw), args.backend, set(args.versions))
    result = {'backend': args.backend, 'versions': sorted(set(args.versions)),
              'certificates': len(records), 'accepted_controls': sum(r['production_accepted'] for r in records),
              'rejected_attacks': sum(not r['production_accepted'] for r in records),
              'whole_security_certified': False, 'hiding_certified': False,
              'original_size': False, 'records': records}
    with args.output.open('x') as output:
        output.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'records'}, indent=2))


if __name__ == '__main__':
    main()
