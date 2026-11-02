#!/usr/bin/env python3
"""Partial ideal-interactive algebraic budget for canonical v11 PBS.

Excludes every PCS/hash error and
adaptive Fiat-Shamir compilation. This tool never certifies full security.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from compare_canonical_polyfrim import read_records, read_opening_inventory
from packed_budget import (canonical_ntt_algebraic_bounds,
                           fixed_table_equality_bound, zerocheck_algebraic_bound,
                           extension_lookup_algebraic_bounds)
from polyfrim_opening_terms import encode, schedule_ceiling


def partial_terms(record, source_variables, final_variables):
    if record.get('protocol_version') != 11 or record.get('group_size') != 1:
        raise ValueError('only canonical v11 single-PBS profiles are covered')
    schedule = schedule_ceiling(record)  # Selected radix 8/5, one lookup pair.
    if record['root_slots'] != schedule['private_root_slots']:
        raise ValueError('canonical root schema differs from the selected profile')
    p,k,size = record['prime'],record['width'],record['ring_dimension']
    if type(size) is not int or size < k or size & (size-1):
        raise ValueError('invalid ring dimension')
    coefficient_variables=(size//k).bit_length()-1
    row_variables=(record['lwe_dimension']-1).bit_length()
    if (source_variables != coefficient_variables+row_variables+1
            or final_variables != coefficient_variables+1):
        raise ValueError('source geometry differs from canonical accumulator layout')
    d=((p-1).bit_length()+7)//8
    s=((p-1).bit_length()+4)//5
    extension_degree=record['extension_degree']
    if (p,extension_degree) not in {(2013265921,6),(18446744069414584321,3)}:
        raise ValueError('unsupported selected extension field')
    terms={}
    for stage,variables,links in [('main',source_variables,2*d+1),
                                  ('monomial',source_variables,2),
                                  ('final',final_variables,s+1)]:
        for name,value in canonical_ntt_algebraic_bounds(p,k,variables,size,links).items():
            terms[f'{stage}_ntt_{name}']=value
    terms['final_input_equality']=fixed_table_equality_bound(p,k,final_variables)
    # Six arithmetic/endpoint equations plus one continuity equation. All
    # public linear maps reduce to fixed residual tables at the common base
    # query. Sharing this query does not invalidate a union over equations.
    terms['accumulator_linear_identities']=7*fixed_table_equality_bound(p,k,source_variables)
    # Each of two main decompositions and the final decomposition checks
    # reconstruction plus zero initial/final borrow tables at a shared query.
    terms['main_decomposition_linear_identities']=6*fixed_table_equality_bound(p,k,source_variables)
    terms['final_decomposition_linear_identities']=3*fixed_table_equality_bound(p,k,final_variables)
    for stage,variables in [('main_hadamard',source_variables),
                            ('monomial_product',source_variables),
                            ('final_product',final_variables),
                            ('extraction',final_variables)]:
        terms[f'{stage}_zerocheck']=zerocheck_algebraic_bound(p,k,2,variables)
    for stage,variables,bits,count in [('main',source_variables,8,2*d),
                                       ('final',final_variables,5,s)]:
        scalar_variables=variables+k.bit_length()-1
        for name,value in extension_lookup_algebraic_bounds(
                p,extension_degree,scalar_variables,1 << scalar_variables,
                2*(1 << bits),3,count,record['lookup_repetitions']).items():
            terms[f'{stage}_lookup_{name}']=value
    return terms


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--copies',type=int,default=1)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.copies < 1:
        parser.error('positive multiplicity required')
    manifest_path=args.run/'manifest.json'
    manifest=json.loads(manifest_path.read_text())
    if manifest.get('terminal') is not True or not manifest.get('commands') or any(
            command.get('returncode') != 0 for command in manifest['commands']):
        raise ValueError('completed successful observation required')
    summaries=[]
    for summary in manifest['summaries']:
        field,backend=summary['field'],summary['backend']
        log=args.run/f'{field}-{backend}-inventory.log'
        if hashlib.sha256(log.read_bytes()).hexdigest() != summary['log_sha256']:
            raise ValueError('changed observation log')
        records=read_records(log,field,backend,manifest['full'],False,1,0,opening_inventory=True)
        record=records[0]
        events=read_opening_inventory(log,records)[0]['events']
        if len(events) != summary['successful_calls'] or record['proof_sha256'] != summary['proof_sha256']:
            raise ValueError('observation summary mismatch')
        dimensions={}
        for role in (0,2):
            geometries={(e['num_vars'],e['width']) for e in events if e['role']==role}
            if len(geometries) != 1:
                raise ValueError('ambiguous or absent source geometry')
            variables,width=geometries.pop()
            if width != record['width']:
                raise ValueError('inconsistent source width')
            dimensions[role]=variables
        terms=partial_terms(record,dimensions[0],dimensions[2])
        subtotal=sum(terms.values(),Fraction())
        summaries.append(dict(field=field,backend=backend,
            source_variables=dimensions[0],final_variables=dimensions[2],
            copies=args.copies,terms={name:encode(value) for name,value in terms.items()},
            subtotal=encode(subtotal),copies_subtotal=encode(args.copies*subtotal),
            whole_security_certified=False,promotion_gate=False))
    if not summaries:
        raise ValueError('no observations')
    sources=['tools/canonical_algebra_terms.py','tools/packed_budget.py',
             'snarks/src/packed_pbs/canonical.rs','snarks/src/packed_ntt.rs',
             'snarks/src/packed_relation.rs','snarks/src/packed_monomial.rs',
             'snarks/src/packed_monomial/canonical.rs','snarks/src/packed_key_switch.rs',
             'snarks/src/packed_key_switch/canonical/protocol.rs','snarks/src/packed_accumulator.rs',
             'snarks/src/packed_decomposition.rs','snarks/src/packed_decomposition/canonical/shared.rs',
             'snarks/src/packed_linear.rs',
             'snarks/src/packed_extension_lookup.rs','snarks/src/packed_extension_lookup/shared.rs',
             'snarks/src/packed_extension_lookup/canonical/shared.rs',
             'sumcheck/src/packed_zero.rs']
    repository=Path(__file__).resolve().parent.parent
    report=dict(scope=__doc__,summaries=summaries,
        assumptions=['fixed available committed tables','authenticated terminal factors',
                     'ideal independent uniform interactive challenges',
                     'packed ZeroCheck Theorem 3 applies to the implemented reduction'],
        exact_encoding='hex-rational-v1',whole_security_certified=False,promotion_gate=False,
        observation_manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        source_sha256={name:hashlib.sha256((repository/name).read_bytes()).hexdigest() for name in sources})
    with args.output.open('x') as stream:
        json.dump(report,stream,indent=2)
        stream.write('\n')
    print(json.dumps([dict(field=s['field'],bits=s['copies_subtotal']['bits']) for s in summaries]))


if __name__=='__main__':
    main()
