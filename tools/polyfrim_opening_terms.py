#!/usr/bin/env python3
"""Candidate opening terms for observed valid traces, never full security.

Excludes hash availability, algebraic PBS stages, adaptive/FS compilation and
proof of a trusted-shape maximum. The RS/rolling derivations require review.
"""
import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from compare_canonical_polyfrim import read_records, read_opening_inventory
from run_classical_native_validation import role_counts


def schedule_ceiling(record):
    """Aggregate the existing canonical per-owner allowance, for one lookup pair.

    This assumes the per-owner schedule in canonical/budget.rs is conservative.
    It is not a proof of that assumption or of full cryptographic security.
    Every API call has >=1 ordered query, so charging each allowed query as a
    separate batch conservatively covers aliasing and batching.
    """
    if type(record['lookup_repetitions']) is not int or record['lookup_repetitions'] != 1:
        raise ValueError('schedule ceiling is limited to the selected one-pair profile')
    p,k,lwe=record['prime'],record['width'],record['lwe_dimension']
    if any(type(v) is not int for v in (p,k,lwe)) or p<3 or k<1 or k&(k-1) or lwe<1:
        raise ValueError('invalid schedule dimensions')
    d=((p-1).bit_length()+7)//8
    s=((p-1).bit_length()+4)//5
    row=(lwe-1).bit_length()
    # (name, logical owner slots, ordered-query allowance per owner).
    source=[('coefficients',2*d+1,k+2),('evaluations',2*d+1,k+1),
            ('trusted_bootstrap_key',2*d,1),('decomposition_inputs',2,2),
            ('borrows',2*(d+1),3),('accumulator_input',1,k+row+3),
            ('monomial_product',1,k+1),('external_input',1,3),
            ('accumulator_output',1,2),('monomial_evaluations',2,k+1)]
    final=[('coefficients',s+1,k+2),('evaluations',s+1,k+1),
           ('trusted_switch_key',s,1),('input',1,2),('borrows',s+1,3)]
    owners=[source,[('helpers',2*d,2)],final,[('helpers',s,2)]]
    return dict(assumed_radix_bits=[8,5],lookup_repetitions=1,
        private_root_slots=8*d+4*s+16,trusted_key_slots=2*d+s,
        logical_owner_slots=[sum(n for _,n,_ in group) for group in owners],
        ordered_query_ceilings=[sum(n*q for _,n,q in group) for group in owners],
        owner_schedule=owners,
        premise='Per-owner canonical_opening_budget allowances cover every accepted verifier path')


def shared_stage_schedule(record):
    """Opening ceilings from the shared verifier's stage loops, not owner caps.

    Selected native fields/widths, radix 8/5 and one lookup pair. Submitted-call
    counts include rejected paths and the first failing delegated PCS call,
    by the shape-guard argument in docs/canonical-opening-budget.md.
    Root aliases can reduce grouped lookup calls. No cryptographic error or
    all-trials attacker-work envelope is established by these counts alone.
    """
    p, k, lwe = (record[name] for name in ('prime', 'width', 'lwe_dimension'))
    reps = record['lookup_repetitions']
    widths = {2013265921: (8, 16), 18446744069414584321: (4, 8)}
    if (any(type(v) is not int for v in (p, k, lwe, reps)) or p not in widths
            or k not in widths[p] or lwe < 1 or reps != 1):
        raise ValueError('selected shared-stage field/width/one-pair configuration required')
    d, s = ((p-1).bit_length()+7)//8, ((p-1).bit_length()+4)//5
    row = (lwe-1).bit_length()
    # Each tuple is (role, stage, maximum PCS invocations, ordered queries).
    # NTT: two calls with k queries per transform relation.
    # Lookup source groups: d digits plus d+1 borrows, excluding unused input.
    # Accumulator: seven source groups; carry partition has row+1 queries.
    stages = [
        (0, 'main_ntt', 2*(2*d+1), 2*(2*d+1)*k),
        (0, 'main_key_product', 4*d+1, 4*d+1),
        (0, 'main_decomposition_linear', 2*(2*d+2), 2*(2*d+2)),
        (0, 'main_lookup_sources', 2*(2*d+1), 2*(2*d+1)),
        (0, 'accumulator', 7, row+12),
        (0, 'monomial_ntt', 4, 4*k),
        (0, 'monomial_product', 2, 2),
        (1, 'main_lookup_helpers', 2*d, 2*d),
        (2, 'final_known_input', 1, 1),
        (2, 'final_ntt', 2*(s+1), 2*(s+1)*k),
        (2, 'final_key_product', 2*s+1, 2*s+1),
        (2, 'final_decomposition_linear', 2*s+2, 2*s+2),
        (2, 'final_lookup_sources', 2*s+1, 2*s+1),
        (2, 'final_extraction', 1, 1),
        (3, 'final_lookup_helpers', s, s),
    ]
    calls = [sum(n for role, _, n, _ in stages if role == i) for i in range(4)]
    queries = [sum(q for role, _, _, q in stages if role == i) for i in range(4)]
    return dict(radix_bits=[8, 5], lookup_repetitions=1,
        role_opening_call_ceilings=calls, role_ordered_query_ceilings=queries,
        role_polyfrim_sampling_phase_ceilings=[c+q for c, q in zip(calls, queries)],
        role_brakedown_sampling_phase_ceilings=calls,
        role_virtual_fragmented_sampling_phase_ceilings=calls,
        role_reference_fragmented_sampling_phase_ceilings=[2*c for c in calls],
        stages=[dict(role=r, stage=name, calls=c, ordered_queries=q) for r, name, c, q in stages],
        # A source argument and finite controls are available. Independent
        # mathematical review must discharge this premise in the full proof.
        submitted_call_bound_source_reviewed=True,
        submitted_call_bound_established=False,
        submitted_call_bound_scope='One trusted fixed shared v11/v12 invocation, including rejected paths; radix 8/5 and one lookup pair',
        submitted_calls_counted_before_delegation=True,
        transcript_byte_and_attacker_work_bounds_established=False,
        uses_owner_allowance_assumption=False, security_qualified=False,
        performance_gate=False)


def opening_terms(variables, prime, degree, queries, blowup=2):
    if any(type(x) is not int for x in (variables, prime, degree, queries, blowup)) or not (
            0 <= variables <= 32 and prime >= 3 and degree >= 1 and queries >= 1
            and blowup in (2, 4, 8)):
        raise ValueError('invalid candidate opening geometry')
    rounds = max(1, variables) # Constant adapter uses one dummy variable.
    field = prime**degree
    geometry = [(1 << (rounds-i), blowup << (rounds-i)) for i in range(rounds+1)]
    vector = sum((Fraction(n*(n+1),field) for _,n in geometry[:-1]),Fraction())
    rolling_field = sum((Fraction(2*n*(n+1),field) for _,n in geometry[1:]),Fraction())
    miss = []
    for i, (message, n) in enumerate(geometry[:-1]):
        next_message, next_n = geometry[i+1]
        current_errors = (n-message)//4
        next_errors = (next_n-next_message)//4 if i+1 < rounds else 0
        rejecting = max(0,next_n-next_message+1-current_errors-next_errors)
        miss.append(Fraction(next_n-rejecting,next_n))
    terms = dict(vector_projection=vector, rolling_field=rolling_field,
                 rolling_sampling=Fraction(3*blowup+1,4*blowup)**queries,
                 nearby_consistency=max(miss)**queries)
    terms['total'] = min(Fraction(1),sum(terms.values(),Fraction()))
    return terms


def internal_root_declarations(variables, ordered_claims, calls):
    """Schema-derived Merkle declarations, not observed hash-query epochs.

    Each claim has L-1 packed ladder roots; each API batch has L-1 rolling
    derived roots. Source roots belong to the enclosing PBS inventory. The L
    projected identifiers per call are virtual handles, not Merkle words.
    """
    if any(type(x) is not int for x in (variables,ordered_claims,calls)) or not (
            0 <= variables <= 32 and 1 <= calls <= ordered_claims):
        raise ValueError('invalid PolyFRIM declaration geometry')
    rounds=max(1,variables)
    packed=ordered_claims*(rounds-1)
    rolling=calls*(rounds-1)
    return dict(packed_ladder_roots=packed,rolling_derived_roots=rolling,
                total_merkle_roots=packed+rolling,
                virtual_projection_identifiers=calls*rounds)


def encode(value):
    # Native consistency denominators can have tens of thousands of bits.
    # Hex avoids Python's decimal-digit limit without disabling that guard.
    return dict(exact=dict(numerator_hex=format(value.numerator,'x'),
                           denominator_hex=format(value.denominator,'x')),
                bits=None if value == 0 else
                math.log2(value.denominator)-math.log2(value.numerator))


def authentication_resources(variables, queries, ordered_claims, calls, blowup=2, *, reuse_rolling_context=True):
    """Trusted-shape full-hash counts for direct/dictionary authentication.

    Counts repeated samples and repeated paths independently. Packed leaves
    hash once. Current rolling checks reuse their bound context; the optional
    uncached model retains the earlier conservative count. Binding contexts,
    identifiers and other hashes outside authentication remain excluded.
    """
    internal = internal_root_declarations(variables, ordered_claims, calls)
    if (type(queries) is not int or queries < 1 or type(blowup) is not int
            or blowup not in (2, 4, 8) or type(reuse_rolling_context) is not bool):
        raise ValueError('positive query count and selected expansion required')
    rounds = max(1, variables)
    domain_log = rounds + blowup.bit_length()-1
    paths = [domain_log-layer for layer in range(rounds)]
    packed = 2*queries*ordered_claims*sum(paths)
    rolling = queries*calls*sum(paths[1:])
    contexts = 0 if reuse_rolling_context else queries*calls*(rounds-1)
    return dict(packed_merkle_hash_outputs=packed, rolling_merkle_hash_outputs=rolling,
                rolling_leaf_context_hash_outputs=contexts,
                authentication_hash_outputs=packed+rolling+contexts,
                dictionary_hash_reference_ceiling=packed+rolling+internal['total_merkle_roots'],
                rolling_context_reused_from_binding=reuse_rolling_context,
                query_draws_preserved=True,
                excluded=['Higher-level parameter/context and virtual-identifier hashes',
                          'Honest preprocessing, XOF and all-trials resource/work envelopes'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    query_group=parser.add_mutually_exclusive_group()
    query_group.add_argument('--queries',type=int,help='Hypothetical uniform count; does not change recorded proofs')
    query_group.add_argument('--role-queries',type=role_counts,
                             help='Hypothetical source,helper,final-source,final-helper counts')
    parser.add_argument('--blowup',type=int,choices=[2,4,8],
                        help='Hypothetical expansion; recorded proofs use blowup two')
    parser.add_argument('--copies',type=int,default=1,help='Multiplicity of the selected count model; not an adversary resource bound')
    parser.add_argument('--target',type=int,default=128)
    ceiling_group=parser.add_mutually_exclusive_group()
    ceiling_group.add_argument('--schedule-ceiling',action='store_true',
                        help='Use the conditional per-owner schedule ceiling instead of observed API counts')
    ceiling_group.add_argument('--stage-ceiling',action='store_true',
                        help='Use the shared verifier stage-loop ceilings without owner allowances')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.copies<1 or args.target<1 or (args.queries is not None and args.queries<1):
        parser.error('positive multiplicity/target/query count required')
    manifest=json.loads((args.run/'manifest.json').read_text())
    if manifest.get('terminal') is not True or any(c.get('returncode') != 0 for c in manifest['commands']):
        raise ValueError('completed successful observation required')
    summaries=[]
    for summary in manifest['summaries']:
        field,backend=summary['field'],summary['backend']
        if backend not in ('polyfrim','polyfrim-compact'): continue
        log=args.run/f'{field}-{backend}-inventory.log'
        if hashlib.sha256(log.read_bytes()).hexdigest()!=summary['log_sha256']:
            raise ValueError('changed observation log')
        rows=read_records(log,field,backend,manifest['full'],False,1,0,opening_inventory=True)
        record=rows[0]
        events=read_opening_inventory(log,rows)[0]['events']
        if len(events)!=summary['successful_calls'] or record['proof_sha256']!=summary['proof_sha256']:
            raise ValueError('observation summary mismatch')
        queries=record['queries'] if args.queries is None else args.queries
        role_queries=args.role_queries or [queries]*4
        uniform=all(q==role_queries[0] for q in role_queries)
        queries=role_queries[0] if uniform else None
        blowup=args.blowup or 2
        counts=Counter((e['role'],e['num_vars']) for e in events)
        schedule=schedule_ceiling(record)
        stage=shared_stage_schedule(record) if args.stage_ceiling else None
        if record['root_slots'] != schedule['private_root_slots']:
            raise ValueError('canonical v11 root schema differs from the count model')
        for role in range(4):
            selected=[e for e in events if e['role']==role]
            if sum(e['queries'] for e in selected)>schedule['ordered_query_ceilings'][role]:
                raise ValueError('observed queries exceed the proposed schedule ceiling')
            if len({e['root_hex'] for e in selected})>schedule['logical_owner_slots'][role]:
                raise ValueError('observed roots exceed the logical owner count')
            if stage is not None and (len(selected)>stage['role_opening_call_ceilings'][role]
                    or sum(e['queries'] for e in selected)>stage['role_ordered_query_ceilings'][role]):
                raise ValueError('observed openings exceed the shared stage-loop ceiling')
        total=Fraction();roles=[]
        for (role,variables),count in sorted(counts.items()):
            terms=opening_terms(variables,record['prime'],record['extension_degree'],role_queries[role],blowup)
            charged=(stage['role_ordered_query_ceilings'][role] if stage is not None else
                     schedule['ordered_query_ceilings'][role] if args.schedule_ceiling else count)
            contribution=args.copies*charged*terms['total'];total+=contribution
            selected=[e for e in events if e['role']==role]
            ordered=sum(e['queries'] for e in selected)
            # Charging each allowed query as a separate batch maximizes both
            # the matrix ladder count and rolling-root count under the ceiling.
            root_claims=charged if args.schedule_ceiling or stage is not None else ordered
            root_calls=(stage['role_opening_call_ceilings'][role] if stage is not None else
                        root_claims if args.schedule_ceiling else count)
            roles.append(dict(role=role,variables=variables,queries=role_queries[role],blowup=blowup,observed_calls=count,
                              charged_openings_per_copy=charged,
                              observed_internal_root_declarations=internal_root_declarations(variables,ordered,count),
                              charged_internal_root_declarations=internal_root_declarations(variables,root_claims,root_calls),
                              authentication_resources_per_copy=authentication_resources(
                                  variables,role_queries[role],root_claims,root_calls,blowup),
                              per_call_terms={k:encode(v) for k,v in terms.items()},
                              contribution=encode(contribution)))
        outer_roots=schedule['private_root_slots']+schedule['trusted_key_slots']
        internal_roots=sum(r['charged_internal_root_declarations']['total_merkle_roots'] for r in roles)
        summaries.append(dict(field=field,backend=backend,observed_queries=record['queries'],
            evaluated_queries=queries,evaluated_role_queries=role_queries,
            observed_blowup=2,evaluated_blowup=blowup,
            hypothetical_blowup_override=args.blowup is not None,
            hypothetical_query_override=args.queries is not None or args.role_queries is not None,
            count_model=('shared-stage-ceiling' if stage is not None else
                         'conditional-per-owner-ceiling' if args.schedule_ceiling else 'observed-valid-trace'),
            schedule_ceiling=schedule,
            shared_stage_schedule=stage,
            copies_of_observed_pattern=args.copies,roles=roles,total=encode(min(Fraction(1),total)),
            merkle_root_declarations=dict(outer_slots_per_copy=outer_roots,
                internal_per_copy=internal_roots,all_copies=args.copies*(outer_roots+internal_roots),
                scope='Schema-derived declaration count; not distinct digests or hash-query freeze epochs'),
            authentication_hash_outputs_all_copies=args.copies*sum(
                r['authentication_resources_per_copy']['authentication_hash_outputs'] for r in roles),
            opening_terms_below_target=total<=Fraction(1,2**args.target),
            whole_security_certified=False,promotion_gate=False))
    if not summaries: raise ValueError('no observed unmasked PolyFRIM traces')
    result=dict(scope=__doc__,target_bits=args.target,exact_encoding='hex-rational-v1',summaries=summaries,
                observation_manifest_sha256=hashlib.sha256((args.run/'manifest.json').read_bytes()).hexdigest(),
                whole_security_certified=False,promotion_gate=False)
    with args.output.open('x') as stream: json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps([dict(field=s['field'],backend=s['backend'],bits=s['total']['bits'],
                          opening_terms_below_target=s['opening_terms_below_target']) for s in summaries]))


if __name__=='__main__':main()
