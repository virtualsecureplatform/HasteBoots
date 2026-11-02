#!/usr/bin/env python3
"""Compose conditional canonical-v11 terms; never a whole-security certificate.

Combines candidate PCS, identified algebraic and proposed classical-RO Merkle
terms. RS/rolling/availability reductions and the per-owner ceiling need review.
Adaptive Fiat-Shamir composition is excluded, not assigned zero error.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path

from hash_query_budget import worst_bounds
from polyfrim_opening_terms import encode


def rational(item):
    exact=item['exact']
    numerator=int(exact['numerator_hex'],16)
    denominator=int(exact['denominator_hex'],16)
    if numerator < 0 or denominator < 1:
        raise ValueError('invalid nonnegative exact fraction')
    return Fraction(numerator,denominator)


def required_algebra_terms():
    return ({f'{stage}_ntt_{kind}' for stage in ('main','monomial','final')
             for kind in ('row_identity','coefficient_compression')}
            | {'final_input_equality','accumulator_linear_identities',
               'main_decomposition_linear_identities','final_decomposition_linear_identities'}
            | {f'{stage}_zerocheck' for stage in
               ('main_hadamard','monomial_product','final_product','extraction')}
            | {f'{stage}_lookup_{kind}' for stage in ('main','final') for kind in
               ('rational_identity','sumcheck','identity_equality_reduction','identity_sumcheck')})


def combine(openings, algebra, hash_queries):
    if type(hash_queries) is not int or hash_queries < 1:
        raise ValueError('explicit positive global Merkle-oracle query budget required')
    manifest=openings.get('observation_manifest_sha256')
    if not isinstance(manifest,str) or len(manifest) != 64 or manifest != algebra.get('observation_manifest_sha256'):
        raise ValueError('worksheets must derive from the same observation manifest')
    if any(report.get('exact_encoding') != 'hex-rational-v1' for report in (openings,algebra)):
        raise ValueError('exact hex-rational worksheets required')
    target=openings['target_bits']
    if type(target) is not int or target < 1:
        raise ValueError('invalid target')
    lookup={}
    for row in algebra['summaries']:
        key=(row['field'],row['backend'])
        if key in lookup:
            raise ValueError('duplicate algebra profile')
        lookup[key]=row
    results=[]
    seen=set()
    for row in openings['summaries']:
        key=(row['field'],row['backend'])
        if key in seen or key not in lookup:
            raise ValueError('duplicate or unmatched opening profile')
        seen.add(key)
        other=lookup[key]
        if row['count_model'] != 'conditional-per-owner-ceiling':
            raise ValueError('composition requires the conditional schedule ceiling')
        copies=row['copies_of_observed_pattern']
        if type(copies) is not int or copies < 1 or copies != other['copies']:
            raise ValueError('worksheet multiplicities differ')
        if not required_algebra_terms() <= other['terms'].keys():
            raise ValueError('algebra worksheet is missing identified stage terms')
        # Recompute subtotals from exact contributions; ignore displayed bits.
        algebra_total=copies*sum((rational(value) for value in other['terms'].values()),Fraction())
        opening_total=sum((rational(role['contribution']) for role in row['roles']),Fraction())
        if (algebra_total != rational(other['copies_subtotal'])
                or min(Fraction(1),opening_total) != rational(row['total'])):
            raise ValueError('inconsistent worksheet subtotal')
        declaration=row['merkle_root_declarations']
        roots=declaration['all_copies']
        internal=sum(role['charged_internal_root_declarations']['total_merkle_roots'] for role in row['roles'])
        if (internal != declaration['internal_per_copy']
                or roots != copies*(internal+declaration['outer_slots_per_copy'])):
            raise ValueError('inconsistent root declaration count')
        # One global collision term for all copies, never one per proof/root.
        hash_terms=worst_bounds(256,hash_queries,roots)
        subtotal=opening_total+algebra_total+sum(hash_terms.values(),Fraction())
        results.append(dict(field=key[0],backend=key[1],copies=copies,
            observed_pcs_queries=row['observed_queries'],evaluated_pcs_queries=row['evaluated_queries'],
            hypothetical_query_override=row['hypothetical_query_override'],
            root_declarations=roots,digest_bits=256,global_distinct_merkle_queries=hash_queries,
            terms=dict(openings=encode(opening_total),algebra=encode(algebra_total),
                       **{name:encode(value) for name,value in hash_terms.items()}),
            candidate_subtotal=encode(min(Fraction(1),subtotal)),
            candidate_terms_below_target=subtotal <= Fraction(1,2**target),
            whole_security_certified=False,promotion_gate=False))
    if not results:
        raise ValueError('no matched profiles')
    return dict(scope=__doc__,target_bits=target,summaries=results,
        exact_encoding='hex-rational-v1',observation_manifest_sha256=manifest,
        hash_resource_scope='All adversary, honest and verifier queries to the modeled Merkle hash oracle across all copies; assumed, not measured',
        transcript_assumptions=dict(implementation='Merlin 3.0.0 / STROBE-128',
            merkle_sha256_model_covers_transcript=False,
            fiat_shamir_error_bound=None,
            fiat_shamir_query_budget=None,
            seed_output_length_is_security_level=False,
            accepted_proof_root_count_covers_all_grinding_trials=False),
        missing=['reviewed fixed-word RS and distance-sensitive rolling reductions',
                 'reviewed hash availability reduction for production encodings',
                 'proof that per-owner schedule ceilings cover every accepted verifier path',
                 'adaptive Fiat-Shamir composition of parent and extension child transcripts',
                 'transcript primitive model and query/grinding resources, separate from Merkle SHA-256',
                 'whole-security-matched baseline and parameters'],
        whole_security_certified=False,promotion_gate=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openings',type=Path,required=True)
    parser.add_argument('--algebra',type=Path,required=True)
    parser.add_argument('--hash-queries',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=combine(json.loads(args.openings.read_text()),json.loads(args.algebra.read_text()),args.hash_queries)
    files=[args.openings,args.algebra,Path(__file__),Path(__file__).with_name('hash_query_budget.py')]
    result['input_sha256']={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    with args.output.open('x') as stream:
        json.dump(result,stream,indent=2)
        stream.write('\n')
    print(json.dumps([dict(field=row['field'],bits=row['candidate_subtotal']['bits'],
                          candidate_terms_below_target=row['candidate_terms_below_target'])
                      for row in result['summaries']]))


if __name__=='__main__':
    main()
