#!/usr/bin/env python3
"""Repeat the deterministic small complete masked-PBS integration executable.

Build with: cargo test --release --locked -p vfhe --test
packed_canonical_shared_pbs --no-run. This does not select secure parameters or
measure original-size PBS. Public deterministic masks are test controls only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=int, default=2)
    args = parser.parse_args()
    if args.runs < 2:
        parser.error('at least two runs are required for reproducibility')
    executable = args.executable.resolve(strict=True)
    source = args.source_archive.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {
        'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
        'source_archive_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'rayon_threads': 8,
        'runs': args.runs,
        'complete_pbs': True,
        'original_size': False,
        'whole_security_matched': False,
        'performance_gate': False,
    }
    (args.output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    reference = None
    summaries = []
    prefix = 'HB_COMPLETE_CANONICAL_MASKED_PROFILE '
    expected = {(2013265921, 10), (2013265921, 11),
                (18446744069414584321, 10), (18446744069414584321, 11)}
    for run in range(args.runs):
        completed = subprocess.run(
            ['/usr/bin/time', '-v', str(executable), '--nocapture', '--test-threads=1'],
            env=os.environ | {'RAYON_NUM_THREADS': '8'}, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        raw = completed.stdout
        (args.output / f'run-{run}.log').write_text(raw)
        completed.check_returncode()
        records = [json.loads(line.split(prefix, 1)[1])
                   for line in raw.splitlines() if prefix in line]
        assert len(records) == 4 and {
            (r['prime'], r['protocol_version']) for r in records
        } == expected, 'missing or duplicated full-proof records'
        assert 'test result: ok. 2 passed;' in raw, 'integration checks did not finish'
        stable = [{k: v for k, v in r.items() if not k.endswith('_s')} for r in records]
        if reference is None:
            reference = stable
        assert stable == reference, 'deterministic full-proof fingerprints changed'
        for prime in sorted({r['prime'] for r in records}):
            old = next(r for r in records if r['prime'] == prime and r['protocol_version'] == 10)
            new = next(r for r in records if r['prime'] == prime and r['protocol_version'] == 11)
            for key in ['fixture_sha256', 'parameters_sha256', 'fhe_parameters_sha256',
                        'trusted_setup_sha256']:
                assert old[key] == new[key], (prime, key)
            assert all(r['verified'] and r['complete_pbs'] and not r['original_size']
                       and not r['whole_security_matched'] and not r['performance_gate']
                       and r['queries'] == r['lookup_repetitions'] == 1 for r in [old, new])
            summaries.append({
                'run': run, 'prime': prime,
                'v10_prove_s': old['prove_s'], 'v11_prove_s': new['prove_s'],
                'prove_reduction_pct': 100 * (1 - new['prove_s'] / old['prove_s']),
                'v10_proof_bytes': old['proof_bytes'], 'v11_proof_bytes': new['proof_bytes'],
                'v10_children': old['child_openings'], 'v11_children': new['child_openings'],
                'execution_order': [11, 10],
                'whole_security_matched': False, 'performance_gate': False,
            })
        rss = int(re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', raw)[1])
        (args.output / f'run-{run}.json').write_text(
            json.dumps({'records': records, 'peak_rss_kib': rss}, indent=2) + '\n')
        print(f'run {run}: four decoded complete proofs verified; peak RSS {rss} KiB', flush=True)
    (args.output / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
    print(json.dumps(summaries, indent=2), flush=True)


if __name__ == '__main__':
    main()
