#!/usr/bin/env python3
"""Run native correctness schedules sequentially, recording terminal status.

Each output directory is exclusive. Interrupted or failed jobs require inspection;
this runner never treats partial logs as success or silently restarts them.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from compare_classical_native_validation import effective_queries, profile_header, records


def role_counts(value):
    try:
        counts = [int(q.strip()) for q in value.split(',')]
    except ValueError as error:
        raise argparse.ArgumentTypeError('four positive comma-separated counts required') from error
    if len(counts) != 4 or any(q <= 0 or q >= 2**64 for q in counts):
        raise argparse.ArgumentTypeError('four positive comma-separated counts required')
    return counts


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_status(path, status):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(status, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fields', nargs='+', choices=['babybear', 'goldilocks'],
                        default=['babybear', 'goldilocks'])
    parser.add_argument('--backends', nargs='+',
                        choices=['brakedown', 'polyfrim', 'dictionary', 'fragmented', 'virtual'],
                        default=['brakedown', 'polyfrim', 'dictionary', 'fragmented', 'virtual'])
    parser.add_argument('--fresh-21', action='store_true')
    parser.add_argument('--width', type=int, choices=[4, 8, 16])
    parser.add_argument('--blowup', type=int, choices=[2, 4, 8])
    parser.add_argument('--extension-degree', type=int, choices=[2, 3, 4, 5, 6, 8])
    parser.add_argument('--fragment-vars', type=int, choices=[8, 10, 12, 14, 16])
    parser.add_argument('--helper-basis', action='store_true')
    schedule_group = parser.add_mutually_exclusive_group()
    schedule_group.add_argument('--atomic-ntt', action='store_true')
    schedule_group.add_argument('--atomic-phases', action='store_true')
    schedule_group.add_argument('--atomic-zerocheck', action='store_true')
    schedule_group.add_argument('--atomic-columns', action='store_true')
    parser.add_argument('--require-profile-header', action='store_true')
    query_group = parser.add_mutually_exclusive_group()
    query_group.add_argument('--queries', type=int)
    query_group.add_argument('--role-queries', type=role_counts)
    args = parser.parse_args()
    if args.queries is not None and not 0 < args.queries < 2**64:
        parser.error('positive query count required')
    requested_queries = args.role_queries or [args.queries or 1]*4
    for field in args.fields:
        if (args.extension_degree is not None
                and args.extension_degree not in {'babybear': [4, 5, 6, 8], 'goldilocks': [2, 3, 4, 5]}[field]):
            parser.error(f'unsupported extension degree {args.extension_degree} for {field}')
    if args.helper_basis and any(backend in ('fragmented', 'virtual') for backend in args.backends):
        parser.error('--helper-basis requires selecting only nonfragmented backends')
    if args.width is not None:
        for field in args.fields:
            if args.width not in ({'babybear': [8, 16], 'goldilocks': [4, 8]}[field]):
                parser.error(f'unsupported width {args.width} for {field}')
    for field in args.fields:
        degree = args.extension_degree or {'babybear': 6, 'goldilocks': 3}[field]
        width = args.width or {'babybear': 8, 'goldilocks': 4}[field]
        if width < degree:
            parser.error(f'{field} source width {width} is smaller than extension degree {degree}; select a larger --width')
    runner = args.runner.resolve(strict=True)
    binary_hash = digest(runner)
    # Exclusive creation prevents accidental reruns or truncation of evidence.
    args.output.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, RAYON_NUM_THREADS='16')
    field_controls = {}
    for field in args.fields:
        for backend in args.backends:
            name = f'{field}-{backend}'
            command = ['taskset', '-c', '0-15', str(runner), field, backend]
            if args.fresh_21:
                command.append('--fresh-21')
            if args.helper_basis:
                command.append('--helper-basis')
            if args.atomic_ntt:
                command.append('--atomic-ntt')
            if args.atomic_phases:
                command.append('--atomic-phases')
            if args.atomic_zerocheck:
                command.append('--atomic-zerocheck')
            if args.atomic_columns:
                command.append('--atomic-columns')
            if args.queries is not None:
                command.extend(['--queries', str(args.queries)])
            if args.role_queries is not None:
                command.extend(['--role-queries', ','.join(str(q) for q in args.role_queries)])
            for option, value in [('--width', args.width), ('--blowup', args.blowup),
                                  ('--extension-degree', args.extension_degree),
                                  ('--fragment-vars', args.fragment_vars)]:
                if value is not None:
                    command.extend([option, str(value)])
            status_path = args.output / f'{name}.json'
            log_path = args.output / f'{name}.log'
            status = dict(command=command, binary_sha256=binary_hash, workers=16,
                          cpus='0-15', log=str(log_path), status='starting',
                          correctness_only=True, security_qualified=False,
                          performance_gate=False)
            write_status(status_path, status)
            try:
                if digest(runner) != binary_hash:
                    raise ValueError('runner changed before native job')
                with log_path.open('x') as log:
                    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                               env=environment)
                    status.update(status='running', pid=process.pid)
                    write_status(status_path, status)
                    print(f'{name}: pid={process.pid}', flush=True)
                    status['exit_code'] = process.wait()
                if status['exit_code'] != 0:
                    raise ValueError(f"native process exited {status['exit_code']}")
                rows = records(log_path)
                expected = 21 if args.fresh_21 else 4
                if len(rows) != expected or digest(runner) != binary_hash:
                    raise ValueError('schedule length or runner fingerprint changed')
                prime = {'babybear': '2013265921', 'goldilocks': '18446744069414584321'}[field]
                variant = dict(brakedown='Brakedown', polyfrim='Polyfrim',
                               dictionary='PolyfrimDictionary', fragmented='FragmentedPipfri',
                               virtual='FragmentedPipfriVirtual')[backend]
                if any(row['prime'] != prime or row['backend'] != variant
                       or row['extension_degree'] != (args.extension_degree or {'babybear': 6, 'goldilocks': 3}[field])
                       or effective_queries(row) != tuple(requested_queries) for row in rows):
                    raise ValueError('native records do not match requested field/backend/query count')
                header = profile_header(log_path)
                if args.require_profile_header and header is None:
                    raise ValueError('trusted profile header required for this run')
                if header is not None:
                    width = args.width or {'babybear': 8, 'goldilocks': 4}[field]
                    helper = header['extension_degree'] if args.helper_basis else width
                    lanes = width.bit_length()-1
                    variables = [21-lanes, 21, 11-lanes, 11]
                    expected_profile = dict(descriptor_version=5 if args.atomic_columns else 4 if args.atomic_zerocheck else 3 if args.atomic_phases else 2 if args.atomic_ntt else 1,
                        role_widths=[width, helper, width, helper], role_variables=variables,
                        role_queries=requested_queries, blowup=args.blowup or 2,
                        fragment_vars=(args.fragment_vars or 12) if backend in ('fragmented', 'virtual') else None,
                        role_left_vars=[n//2 for n in variables] if backend == 'brakedown' else [None]*4,
                        role_block_widths=[width]*4 if backend == 'brakedown' else [None]*4)
                    for key, value in expected_profile.items():
                        if header[key] != value:
                            raise ValueError(f'trusted profile does not match requested {key}')
                control_keys = ('fhe_parameters_sha256', 'native_keys_sha256', 'statement_sha256')
                identities = [tuple(row[key] for key in control_keys) for row in rows]
                if field in field_controls:
                    control_name, control_identities = field_controls[field]
                    if identities != control_identities:
                        raise ValueError('FHE parameters, public keys or statements differ from field control')
                else:
                    control_name = name
                    field_controls[field] = (control_name, identities)
                status.update(status='passed', completed_proofs=len(rows),
                              log_sha256=digest(log_path), field_control=control_name,
                              field_control_identity_keys=list(control_keys),
                              profile_header_validated=header is not None)
                write_status(status_path, status)
                print(f'{name}: passed {len(rows)} proofs', flush=True)
            except Exception as error:
                status.update(status='failed', error=str(error))
                write_status(status_path, status)
                raise


if __name__ == '__main__':
    main()
