#!/usr/bin/env python3
"""Conditional ideal fixed-word fragmented opening terms; never qualification.

Uses the separately stated RS/rolling, bridge and power-curve derivations.
Availability, actual first-query coupling, XOF/links and whole PBS are excluded.
"""
import argparse
from fractions import Fraction
import json


def terms(prime, degree, source_vars, width, fragment_vars, blowup, queries, mode):
    for name, value, lower in [('prime', prime, 3), ('degree', degree, 1),
            ('source_vars', source_vars, 0), ('width', width, 1),
            ('fragment_vars', fragment_vars, 1), ('blowup', blowup, 2), ('queries', queries, 1)]:
        if type(value) is not int or value < lower:
            raise ValueError(f'invalid {name}')
    if mode not in ('virtual', 'reference') or width & (width-1) or blowup & (blowup-1):
        raise ValueError('supported mode and power-of-two packing/blowup required')
    logical = source_vars + width.bit_length()-1
    if logical >= 64 or fragment_vars >= 64 or width < degree:
        raise ValueError('unsupported trusted profile dimensions')
    physical = max(1, logical)  # The scalar adapter duplicates a constant.
    rounds = min(physical, fragment_vars)
    message = 1 << rounds
    fragments = 1 << (physical-rounds)
    domain = message * blowup
    cardinality = prime ** degree
    source_radius = Fraction(blowup-1, 4*blowup)
    rolling_radius = source_radius if mode == 'virtual' else source_radius / 2
    gamma = min(Fraction(1), Fraction((fragments-1)*domain*(domain+1), cardinality))
    folds = [min(Fraction(1), Fraction(2*(domain >> j)*((domain >> j)+1), cardinality))
             for j in range(1, rounds+1)]
    sampling = (1-rolling_radius) ** queries
    sampling_phases = 1 if mode == 'virtual' else 2
    compression = Fraction(1, cardinality)
    sumcheck_round = Fraction(2, cardinality)
    bridge = compression + logical * sumcheck_round
    phases = [compression, gamma, sampling, *folds]
    if logical:
        phases.append(sumcheck_round)
    return dict(mode=mode, prime=prime, extension_degree=degree, source_vars=source_vars,
        width=width, queries=queries, fragment_vars_cap=fragment_vars, blowup=blowup,
        scalar_logical_vars=logical, scalar_physical_vars=physical,
        fragment_length=message, fragment_count=fragments, encoded_fragment_length=domain,
        source_radius=str(source_radius), rolling_radius=str(rolling_radius),
        bridge_compression=str(compression), bridge_sumcheck_round=str(sumcheck_round),
        bridge_sumcheck_rounds=logical, bridge_interactive_union=str(bridge),
        gamma_phase=str(gamma), rolling_fold_phases=[str(x) for x in folds],
        sampling_phase=str(sampling), sampling_phases=sampling_phases,
        maximum_component_phase_error=str(max(phases)),
        interactive_union=str(min(Fraction(1), bridge+gamma+sum(folds)+sampling_phases*sampling)),
        required_premises=['trusted field/domain and parameter geometry',
            'fixed semantic source and derived words at the required freezes',
            'uniform RS exceptional-polynomial and rolling state lemmas',
            'ideal uniform challenge phases and actual-protocol coupling'],
        excluded=['Merkle availability and global root/work resources',
            'XOF primitive and child-link failures', 'whole PBS state/knowledge composition'],
        security_qualified=False, performance_gate=False, query_count_selected=False)


def shared_terms(prime, degree, role_variables, width, fragment_vars, blowup,
                 role_queries, mode, lwe_dimension=728):
    """Conditional four-role subtotal using actual shared-stage call ceilings.

    Fragmented profiles use the same packing width for all roles. Each API
    call has one bridge regardless of its number of ordered claims; the lane
    compression term must not acquire an extra claim-count multiplier.
    This accepted-path subtotal is not an all-trials FS linear coefficient.
    """
    from polyfrim_opening_terms import shared_stage_schedule
    if any(not isinstance(v, (list, tuple)) or len(v) != 4
           for v in (role_variables, role_queries)):
        raise ValueError('exactly four role variable/query counts required')
    schedule = shared_stage_schedule(dict(prime=prime, width=width,
        lwe_dimension=lwe_dimension, lookup_repetitions=1))
    roles = []
    total = Fraction()
    maximum = Fraction()
    for role in range(4):
        row = terms(prime, degree, role_variables[role], width, fragment_vars,
                    blowup, role_queries[role], mode)
        calls = schedule['role_opening_call_ceilings'][role]
        contribution = calls*Fraction(row['interactive_union'])
        total += contribution
        maximum = max(maximum, Fraction(row['maximum_component_phase_error']))
        roles.append(dict(role=role, calls=calls, per_call=row,
                          contribution=str(contribution)))
    return dict(roles=roles, shared_stage_schedule=schedule,
                opening_interactive_union=str(min(Fraction(1), total)),
                maximum_opening_phase_error=str(maximum),
                scope='Conditional accepted-path fragmented opening subtotal',
                excluded=['Parent PBS algebra and full bad-state composition',
                          'Availability, first-query/child links and all-trials work caps',
                          'Knowledge/extraction'],
                security_qualified=False, performance_gate=False,
                query_count_selected=False)


def authentication_resources(source_vars, width, fragment_vars, blowup, queries, mode):
    values = (source_vars, width, fragment_vars, blowup, queries)
    if (any(type(v) is not int for v in values) or source_vars < 0 or width < 1
            or width & (width-1) or not 1 <= fragment_vars < 64
            or blowup not in (2, 4, 8) or queries < 1 or mode not in ('virtual', 'reference')):
        raise ValueError('supported fragmented authentication geometry required')
    physical = max(1, source_vars+width.bit_length()-1)
    rounds = min(physical, fragment_vars)
    domain_log = rounds+blowup.bit_length()-1
    if physical >= 64 or domain_log >= 64:
        raise ValueError('fragmented domain exceeds native size')
    paths = [domain_log-i for i in range(rounds)]
    virtual = mode == 'virtual'
    rolling = queries*(2*sum(paths[1:]) if virtual else sum(paths)+sum(paths[1:]))
    source = queries*paths[0]
    ladder = 0 if virtual else queries*sum(paths)
    # packed_leaf -> PipFRI context -> rolling context: two additional outputs.
    source_contexts = 2*queries
    # Ordinary consistency uses standalone check_pair, unlike cached verify_mode.
    ladder_contexts = 0 if virtual else queries*rounds
    return dict(mode=mode, rounds=rounds,
        rolling_merkle_hash_outputs=rolling, source_fragment_merkle_hash_outputs=source,
        public_fold_merkle_hash_outputs=ladder,
        source_fragment_context_hash_outputs=source_contexts,
        public_fold_context_hash_outputs=ladder_contexts,
        authentication_hash_outputs=rolling+source+ladder+source_contexts+ladder_contexts,
        internal_merkle_root_declarations=2*(rounds-1) if virtual else 2*rounds-1,
        virtual_identifiers=1 if virtual else 0,
        independent_index_draws=queries if virtual else 2*queries,
        source_fragment_field_elements_per_pair=2*(1 << (physical-rounds)),
        excluded=['Higher-level binding/context/identifier hashes and preprocessing',
                  'XOF, global root freezes and all-trials work accounting'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ['prime', 'degree', 'source-vars', 'width', 'fragment-vars', 'blowup', 'queries']:
        parser.add_argument('--'+option, type=int, required=True)
    parser.add_argument('--mode', choices=['virtual', 'reference'], required=True)
    args = parser.parse_args()
    print(json.dumps(terms(args.prime, args.degree, args.source_vars, args.width,
        args.fragment_vars, args.blowup, args.queries, args.mode), indent=2))


if __name__ == '__main__':
    main()
