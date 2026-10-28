#!/usr/bin/env python3
"""Measure retained/generated virtual-source controls in separate processes.

This is an algebraic component control, not native PBS or security-matched timing.
Build the ignored PCS resource test, then pass its frozen test executable and an
immutable source archive. Every child performs decoded verification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

PREFIX = 'HB_GENERATED_SOURCE_RESOURCE '
TEST = 'packed_polyfrim::authenticated::proximity::batch::profile::generated_source_resource_profile'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--batches', type=int, nargs='+', choices=[1, 4, 16], default=[1, 4, 16])
    args = parser.parse_args()
    executable = args.executable.resolve()
    archive = args.source_archive.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {'executable': str(executable), 'executable_sha256': digest(executable),
                'source_archive': str(archive), 'source_archive_sha256': digest(archive),
                'batches': sorted(set(args.batches)), 'test': TEST, 'rayon_threads': 1,
                'scope': 'separate-process algebraic virtual-source component',
                'timing_claim': False, 'whole_security_matched': False, 'complete_pbs': False}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    records = []
    for field, prime, degree in [('babybear', 2013265921, 6), ('goldilocks', 18446744069414584321, 3)]:
        for batch in manifest['batches']:
            pair = []
            for mode in ['retained', 'generated']:
                stem = args.output / f'{field}-b{batch}-{mode}'
                env = dict(os.environ, RAYON_NUM_THREADS='1', HB_SOURCE_MODE=mode,
                           HB_SOURCE_BATCH=str(batch), HB_SOURCE_FIELD=field)
                command = ['/usr/bin/time', '-f', '{"peak_rss_kib":%M,"elapsed_s":%e}',
                           '-o', str(stem.with_suffix('.time.json')), str(executable),
                           TEST, '--ignored', '--exact', '--nocapture', '--test-threads=1']
                with stem.with_suffix('.log').open('x') as log:
                    child = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
                    stem.with_suffix('.process.json').write_text(json.dumps({'wrapper_pid': child.pid, 'argv': command}, indent=2) + '\n')
                    code = child.wait()
                stem.with_suffix('.exit.json').write_text(json.dumps({'returncode': code}) + '\n')
                assert code == 0, (field, batch, mode, code)
                raw = stem.with_suffix('.log').read_text()
                assert 'test result: ok. 1 passed; 0 failed;' in raw
                reports = [json.loads(line.split(PREFIX, 1)[1]) for line in raw.splitlines() if PREFIX in line]
                assert len(reports) == 1
                record = reports[0]
                assert (record['prime'], record['extension_degree'], record['batch_size'], record['mode']) == (prime, degree, batch, mode)
                assert (record['variables'], record['width'], record['blowup'], record['queries']) == (15, 2, 4, 8)
                assert record['verified'] is True
                assert all(record[name] is False for name in ['complete_pbs', 'original_size', 'whole_security_matched', 'performance_gate'])
                for name in ['proof_sha256', 'fixture_sha256', 'transcript_sha256']:
                    assert len(record[name]) == 64 and all(c in '0123456789abcdef' for c in record[name])
                record['process_resources'] = json.loads(stem.with_suffix('.time.json').read_text())
                assert record['peak_rss_kib'] > 0 and record['process_resources']['peak_rss_kib'] > 0
                records.append(record)
                pair.append(record)
            for name in ['proof_bytes', 'proof_sha256', 'fixture_sha256', 'transcript_sha256']:
                assert pair[0][name] == pair[1][name], (field, batch, name)
            print(json.dumps({'field': field, 'batch': batch, 'retained_peak_kib': pair[0]['process_resources']['peak_rss_kib'],
                              'generated_peak_kib': pair[1]['process_resources']['peak_rss_kib'], 'proofs_equal': True}), flush=True)
    assert digest(executable) == manifest['executable_sha256'] and digest(archive) == manifest['source_archive_sha256']
    (args.output / 'checked-records.json').write_text(json.dumps({'manifest': manifest, 'records': records}, indent=2) + '\n')


if __name__ == '__main__':
    main()
