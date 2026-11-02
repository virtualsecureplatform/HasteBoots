#!/usr/bin/env python3
"""Compare complete v11 helper layouts; no whole-security or promotion claim."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess

from benchmark_affinity import cpu_set
from compare_canonical_polyfrim import PRIMES, read_records, read_lookup_profiles
from compare_canonical_kernels import equivalent
from joint_pbs_timing import assert_idle


def compare(before, after):
    if len(before) != len(after):
        raise ValueError('different proof schedules')
    shared = ('prime', 'extension_degree', 'protocol_version', 'ring_dimension', 'lwe_dimension',
              'output_dimension', 'width', 'queries', 'lookup_repetitions', 'ordinal', 'warmup', 'cold',
              'left', 'right', 'output', 'root_slots', 'group_size', 'group_index',
              'fhe_parameters_sha256', 'native_keys_sha256', 'statement_sha256', 'trusted_setup_sha256',
              'rs_encoders_sha256')
    for a, b in zip(before, after):
        if a['basis_helpers'] is not False or b['basis_helpers'] is not True:
            raise ValueError('incorrect helper layout comparison')
        for key in shared:
            if a[key] != b[key]:
                raise ValueError(f'changed {key}')
        for role, (x, y) in enumerate(zip(a['rs_layouts'], b['rs_layouts'])):
            if any(u != v for i, (u, v) in enumerate(zip(x, y)) if i != 1 or role % 2 == 0):
                raise ValueError('changed RS domain, rate, row split or source packing')
        if any(a['contexts_sha256'][i] != b['contexts_sha256'][i] for i in (0, 2)):
            raise ValueError('changed source/key context')
        if any(a['contexts_sha256'][i] == b['contexts_sha256'][i] for i in (1, 3)):
            raise ValueError('helper context did not bind new geometry')
        if a['parameters_sha256'] == b['parameters_sha256']:
            raise ValueError('trusted parameter digest did not change')
    rows = [[r for r in values if not r['warmup']] for values in (before, after)]
    medians = [statistics.median(r['complete_s'] for r in values) for values in rows]
    return dict(padded_median_s=medians[0], basis_median_s=medians[1],
                latency_reduction=1-medians[1]/medians[0],
                maximum_byte_ratio=max(b['proof_bytes']/a['proof_bytes'] for a, b in zip(before, after)),
                fixed_word_helper_exception_bits={mode: {label: max(0., layout[1] * math.log2(row['prime']) - math.log2(layout[5] * (layout[5] + 1)))
                    for label, layout in zip(('main', 'final'), (row['rs_layouts'][1], row['rs_layouts'][3]))}
                    for mode, row in (('padded', before[0]), ('basis', after[0]))},
                projection_model='per opening; fixed available words and independent interactive coins; not a full PCS/security bound',
                whole_security_matched=False, performance_gate=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fields', choices=PRIMES, nargs='+', default=list(PRIMES))
    parser.add_argument('--iterations', type=int, default=10)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--validation', action='store_true')
    parser.add_argument('--toy', action='store_true')
    parser.add_argument('--cold', action='store_true')
    parser.add_argument('--correctness-only', action='store_true')
    parser.add_argument('--cpus', help='Same explicit logical CPU set for both profiles, e.g. 0-15')
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0 or len(set(args.fields)) != len(args.fields):
        parser.error('invalid schedule')
    if args.validation and not args.correctness_only:
        parser.error('validation is correctness-only')
    if not args.correctness_only and (args.iterations < 10 or args.warmups < 1 or not args.cpus):
        parser.error('timing requires explicit CPU affinity, one warmup and ten measured proofs')
    allowed = sorted(os.sched_getaffinity(0))
    try:
        affinity = cpu_set(args.cpus, allowed) if args.cpus else allowed
    except ValueError as error:
        parser.error(str(error))
    args.output.mkdir(parents=True, exist_ok=False)
    binary = (args.output/'canonical-pbs.bin').resolve()
    archive = args.output/'executed-sources.tar.gz'
    shutil.copy2(args.executable, binary); shutil.copy2(args.source_archive, archive)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    shutil.copy2(__file__, args.output/'executed-driver.py')
    manifest = dict(terminal=False, executable_sha256=sha(binary), source_archive_sha256=sha(archive),
                    driver_sha256=sha(Path(__file__)), threads=16, cpu_affinity=affinity,
                    explicit_affinity=args.cpus is not None, toy=args.toy, validation=args.validation,
                    iterations=args.iterations, warmups=args.warmups, cold=args.cold,
                    correctness_only=args.correctness_only,
                    executed_warmups=0 if args.validation else args.warmups,
                    proofs_per_process=21 if args.validation else args.iterations + args.warmups,
                    measured_proofs_per_process=21 if args.validation else args.iterations,
                    whole_security_matched=False,
                    performance_gate=False, commands=[], summaries=[])
    def write(): (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    write(); previous = {}
    for order in (0, 1):
        for field in args.fields if order == 0 else list(reversed(args.fields)):
            paired = {}; profiles = {}
            for mode in ('padded', 'basis') if order == 0 else ('basis', 'padded'):
                if not args.correctness_only: assert_idle()
                name = f'{field}-{mode}-{order}'
                cmd = [str(binary), field, 'brakedown']
                if not args.toy: cmd += ['--full']
                if args.cold: cmd += ['--cold']
                if mode == 'basis': cmd += ['--basis-helpers']
                cmd += ['--validation-batches'] if args.validation else ['--iterations', str(args.iterations), '--warmups', str(args.warmups)]
                entry = dict(name=name, argv=cmd); manifest['commands'].append(entry); write()
                logpath = args.output/f'{name}.log'
                with logpath.open('x') as log:
                    process = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(args.output/f'{name}.time'), *cmd],
                        stdout=log, stderr=subprocess.STDOUT, env={**os.environ, 'RAYON_NUM_THREADS':'16'},
                        preexec_fn=lambda: os.sched_setaffinity(0, affinity))
                    entry['pid'] = process.pid; write(); entry['returncode'] = process.wait(); write()
                if entry['returncode']: raise RuntimeError(f'{name} failed')
                rows = read_records(logpath, field, 'brakedown', not args.toy, args.validation,
                                    args.iterations, args.warmups, args.cold, basis_helpers=mode == 'basis')
                paired[mode] = rows; profiles[mode] = read_lookup_profiles(logpath, rows)
                if order: equivalent(previous[field, mode], rows)
                previous[field, mode] = rows
            result = compare(paired['padded'], paired['basis']); result.update(field=field, order=order)
            result['lookup_medians_s'] = {mode: {key: statistics.median(p[key] for p, r in zip(profiles[mode], paired[mode]) if not r['warmup'])
                for key in ('preparation_s', 'commitment_s', 'sumcheck_s', 'zero_check_s', 'terminal_evaluation_s', 'openings_s')} for mode in profiles}
            manifest['summaries'].append(result); write(); print(json.dumps(result), flush=True)
    manifest['terminal'] = True; write()

if __name__ == '__main__': main()
