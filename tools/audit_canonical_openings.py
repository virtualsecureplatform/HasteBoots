#!/usr/bin/env python3
"""Observe successful complete-verifier PCS calls; never certify security.

One proof per configuration. Counts describe these valid traces, not an
adversarial maximum, root freeze schedule, hash budget or timing experiment.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from benchmark_affinity import cpu_set
from compare_canonical_kernels import equivalent
from compare_canonical_polyfrim import PRIMES, read_records, read_opening_inventory
from joint_pbs_timing import assert_idle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpus', required=True)
    parser.add_argument('--fields', nargs='+', choices=PRIMES, default=list(PRIMES))
    parser.add_argument('--backends', nargs='+', choices=['brakedown','polyfrim','polyfrim-compact'],
                        default=['brakedown','polyfrim','polyfrim-compact'])
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--compare-disabled', action='store_true')
    args = parser.parse_args()
    if len(set(args.fields)) != len(args.fields) or len(set(args.backends)) != len(args.backends):
        parser.error('duplicate configuration')
    try: affinity = cpu_set(args.cpus, sorted(os.sched_getaffinity(0)))
    except ValueError as error: parser.error(str(error))
    args.output.mkdir(parents=True, exist_ok=False)
    binary = (args.output/'canonical-pbs.bin').resolve()
    shutil.copy2(args.executable, binary)
    shutil.copy2(args.source_archive, args.output/'sources.tar.gz')
    shutil.copy2(__file__, args.output/'executed-driver.py')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = dict(terminal=False, full=args.full, threads=16, cpu_affinity=affinity,
                    timing_eligible=False, whole_security_certified=False, promotion_gate=False,
                    scope=__doc__, executable_sha256=sha(binary),
                    source_archive_sha256=sha(args.output/'sources.tar.gz'),
                    driver_sha256=sha(Path(__file__)),
                    reader_sha256=sha(Path(__file__).with_name('compare_canonical_polyfrim.py')),
                    commands=[], summaries=[])
    write = lambda: (args.output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    write()
    for field in args.fields:
        for backend in args.backends:
            paired = {}
            for enabled in ([False,True] if args.compare_disabled else [True]):
                assert_idle()
                name = f'{field}-{backend}-'+('inventory' if enabled else 'disabled')
                cmd = [str(binary), field, backend, '--iterations','1','--warmups','0']
                if args.full: cmd += ['--full']
                if enabled: cmd += ['--opening-inventory']
                entry = dict(name=name, argv=cmd)
                manifest['commands'].append(entry); write()
                path = args.output/f'{name}.log'
                with path.open('x') as stream:
                    process = subprocess.Popen(['/usr/bin/time','-v','-o',str(args.output/f'{name}.time'),*cmd],
                        stdout=stream,stderr=subprocess.STDOUT,env={**os.environ,'RAYON_NUM_THREADS':'16'},
                        preexec_fn=lambda: os.sched_setaffinity(0,affinity))
                    entry['pid']=process.pid; write(); entry['returncode']=process.wait()
                write()
                if entry['returncode']: raise RuntimeError(f'{name} failed: {entry["returncode"]}')
                rows = read_records(path,field,backend,args.full,False,1,0,opening_inventory=enabled)
                paired[enabled] = rows
                if enabled:
                    profile = read_opening_inventory(path,rows)[0]
                    events = profile['events']
                    roles = []
                    for role in range(4):
                        selected = [e for e in events if e['role']==role]
                        roles.append(dict(role=role,num_vars=selected[0]['num_vars'],width=selected[0]['width'],
                            successful_calls=len(selected),ordered_claims=sum(e['queries'] for e in selected),
                            distinct_context_roots=len({(e['context_sha256'],e['root_hex']) for e in selected}),
                            batch_size_histogram=dict(sorted(Counter(e['queries'] for e in selected).items()))))
                    result = dict(field=field,backend=backend,roles=roles,successful_calls=len(events),
                                  proof_sha256=rows[0]['proof_sha256'],log_sha256=sha(path),
                                  disabled_comparison_wire_exact=None,whole_security_certified=False)
            if args.compare_disabled:
                equivalent(paired[False],paired[True]); result['disabled_comparison_wire_exact']=True
            manifest['summaries'].append(result); write(); print(json.dumps(result),flush=True)
    manifest['terminal']=True; write()


if __name__=='__main__': main()
