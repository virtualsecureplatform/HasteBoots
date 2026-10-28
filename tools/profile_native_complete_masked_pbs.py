#!/usr/bin/env python3
"""Run one original-size complete masked PBS and fresh-process public replay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--field', choices=['babybear', 'goldilocks'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    binary = args.executable.resolve(strict=True)
    archive = args.source_archive.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    metadata = dict(executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    source_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                    field=args.field, rayon_threads=8, queries=128, lookup_repetitions=1,
                    ring_dimension=1024, lwe_dimension=728, original_size=True,
                    complete_pbs=True, whole_security_matched=False, performance_gate=False)
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    env = dict(os.environ, RAYON_NUM_THREADS='8')
    for mode in ['prove', 'replay']:
        command = ['/usr/bin/time', '-v', '-o', str(output / f'{mode}.time'),
                   str(binary), mode, args.field, str(output / 'artifacts')]
        with (output / f'{mode}.log').open('x') as stream:
            process = subprocess.Popen(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
            # PID is a locator, not evidence of liveness: inspect the process.
            (output / f'{mode}-process.json').write_text(json.dumps(
                dict(pid=process.pid, command=command), indent=2) + '\n')
            print(f'{mode}: started PID {process.pid}', flush=True)
            code = process.wait()
            (output / f'{mode}-exit.json').write_text(json.dumps(dict(returncode=code)) + '\n')
            if code:
                raise subprocess.CalledProcessError(code, command)
        print(f'{mode}: finished', flush=True)
    checker = Path(__file__).with_name('check_native_complete_masked_pbs.py')
    checked = subprocess.run([sys.executable, str(checker), str(output / 'artifacts'),
                              '--replay-log', str(output / 'replay.log')],
                             check=True, text=True, capture_output=True)
    with (output / 'checked-report.json').open('x') as stream:
        stream.write(checked.stdout)
    print(checked.stdout, end='', flush=True)


if __name__ == '__main__':
    main()
