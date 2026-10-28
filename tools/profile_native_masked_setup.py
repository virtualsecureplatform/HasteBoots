#!/usr/bin/env python3
"""Run isolated original-native masked key setups; not full PBS validation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    records = []
    env = dict(os.environ, RAYON_NUM_THREADS='8')
    geometries = {
        'babybear': ([18, 21, 8, 11], [18, 21, 18, 18], 8, 7, 251658240),
        'goldilocks': ([19, 21, 9, 11], [19, 21, 17, 17], 16, 13, 322961408),
    }
    for field, policies in [('babybear', ['retained', 'transient']),
                            ('goldilocks', ['transient', 'retained'])]:
        for policy in policies:
            log = args.output / f'{field}-{policy}.log'
            timing = args.output / f'{field}-{policy}.time'
            with log.open('x') as stream:
                if timing.exists():
                    raise FileExistsError(timing)
                subprocess.run(['/usr/bin/time', '-v', '-o', str(timing), str(binary), field, policy],
                               env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
            found = [json.loads(line.split(' ', 1)[1]) for line in log.read_text().splitlines()
                     if line.startswith('HB_NATIVE_MASKED_SETUP ')]
            assert len(found) == 1
            record = found[0]
            logical, physical, br, ks, elements = geometries[field]
            assert record['logical_vars'] == logical and record['physical_vars'] == physical
            assert record['br_sources'] == br and record['ks_sources'] == ks
            assert record['ring_dimension'] == 1024 and record['lwe_dimension'] == 728
            assert record['queries'] == 128 and record['budget'] == 1
            assert record['native_keys'] and record['verified']
            assert not record['complete_pbs'] and not record['whole_security_matched']
            assert record['transient'] == (policy == 'transient')
            expected = 0 if record['transient'] else elements
            assert record['cache_before_elements'] == record['cache_after_elements'] == expected
            assert len(record['proof_sha256']) == len(record['transcript_sha256']) == len(record['proof_bytes']) == 2
            record['peak_rss_kib'] = int(re.search(r'Maximum resident set size \(kbytes\): (\d+)', timing.read_text())[1])
            records.append(record)
            print(json.dumps(record), flush=True)
    invariant = ['field', 'ring_dimension', 'lwe_dimension', 'queries', 'budget', 'br_sources',
                 'ks_sources', 'logical_vars', 'physical_vars', 'native_parameters_sha256',
                 'parameters_sha256', 'native_tables_sha256', 'roots_sha256', 'proof_sha256',
                 'transcript_sha256', 'proof_bytes', 'rng_tail', 'verified', 'native_keys',
                 'complete_pbs', 'whole_security_matched']
    for offset in [0, 2]:
        a, b = records[offset:offset + 2]
        assert all(a[key] == b[key] for key in invariant)
    result = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  rayon_threads=8, native_keys=True, complete_pbs=False,
                  whole_security_matched=False, exact_invariants=invariant, records=records)
    with (args.output / 'checked-records.json').open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
