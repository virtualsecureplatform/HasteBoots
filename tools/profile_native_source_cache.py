#!/usr/bin/env python3
"""Compare one synthetic PCS source at native key-source dimensions, serially."""
import argparse
import json
import os
from pathlib import Path
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
    for repetition, policies in enumerate([['retained', 'transient'], ['transient', 'retained']], 1):
        for field, variables in [('babybear', 18), ('goldilocks', 19)]:
            for policy in policies:
                stem = f'{field}-{policy}-{repetition}'
                log = args.output / f'{stem}.log'
                timing = args.output / f'{stem}.time'
                # Refuse to overwrite partial or completed evidence.
                with log.open('x') as stream:
                    if timing.exists():
                        raise FileExistsError(timing)
                    command = ['/usr/bin/time', '-v', '-o', str(timing), str(binary),
                               field, 'joint', str(variables), str(variables), '1', '128', policy]
                    subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
                lines = log.read_text().splitlines()
                profile = [json.loads(line.split(' ', 1)[1]) for line in lines
                           if line.startswith('HB_MASKED_JOINT_PROFILE ')]
                resource = [json.loads(line.split(' ', 1)[1]) for line in lines
                            if line.startswith('HB_MASKED_SOURCE_RESOURCES ')]
                assert len(profile) == len(resource) == 1
                p, r = profile[0], resource[0]
                assert p['verified'] and not p['complete_pbs'] and not p['whole_security_matched']
                assert p['logical_vars'] == p['physical_vars'] == variables
                assert p['queries'] == r['queries'] == 128 and p['spent'] == p['budget'] == 1
                assert p['field'] == r['field'] == field and p['batch_size'] == 1
                assert r['transient'] == (policy == 'transient')
                expected = 0 if r['transient'] else 16777216
                assert r['committed_cache_elements'] == r['opened_cache_elements'] == expected
                assert r['extension_element_bytes'] == 24
                record = dict(repetition=repetition, policy=policy, profile=p, resource=r)
                records.append(record)
                print(json.dumps(record), flush=True)
    invariants = ['field', 'mode', 'logical_vars', 'physical_vars', 'width', 'batch_size',
                  'queries', 'budget', 'fixture_sha256', 'parameters_sha256', 'root_sha256',
                  'query_sha256', 'proof_sha256', 'transcript_sha256', 'rng_tail', 'spent',
                  'proof_bytes', 'source_certificates', 'masked_ladders', 'verified',
                  'full_query_aggregation', 'whole_security_matched', 'complete_pbs']
    for field in ['babybear', 'goldilocks']:
        group = [r['profile'] for r in records if r['profile']['field'] == field]
        for record in group[1:]:
            assert all(record[k] == group[0][k] for k in invariants)
    result = dict(synthetic_source=True, complete_pbs=False, whole_security_matched=False,
                  repetitions=2, exact_invariants=invariants, records=records)
    with (args.output / 'checked-records.json').open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
