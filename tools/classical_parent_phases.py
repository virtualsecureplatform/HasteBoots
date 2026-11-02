#!/usr/bin/env python3
"""Conditional native packed-stage phase inventory; not whole PBS security."""
import argparse
from fractions import Fraction
import json
from packed_budget import atomic_zerocheck_phase_bounds, fixed_table_equality_bound


def packed_stages(prime, width, *, schedule_version):
    widths = {2013265921: (8, 16), 18446744069414584321: (4, 8)}
    if (type(prime) is not int or type(width) is not int
            or prime not in widths or width not in widths[prime]
            or type(schedule_version) is not int or schedule_version not in (4, 5)):
        raise ValueError('selected native field/width and explicit schedule four or five required')
    n, lwe = 1024, 728
    lane_bits = width.bit_length()-1
    main_vars = (2*n*(1 << (lwe-1).bit_length())).bit_length()-1-lane_bits
    final_vars = (2*n).bit_length()-1-lane_bits
    coefficient_vars = n.bit_length()-1-lane_bits
    digits = ((prime-1).bit_length()+7)//8
    switch_digits = ((prime-1).bit_length()+4)//5
    phases = []

    def add(stage, kind, count, error):
        phases.append(dict(stage=stage, phase=kind, count=count, error=str(error)))

    compression = Fraction(2*width-1, prime)**width
    for stage, variables, relations in [
            ('main_ntt', main_vars, 2*digits+1),
            ('monomial_ntt', main_vars, 2),
            ('final_ntt', final_vars, switch_digits+1)]:
        row_vars = variables-coefficient_vars
        add(stage, 'atomic_row_points', relations, Fraction(row_vars, prime)**width)
        # One first-nonzero residual is fixed before this common compression
        # point; no assumed independence across the 2k response polynomials.
        add(stage, 'coefficient_fold', relations*coefficient_vars, compression)

    for stage, variables in [('main_product', main_vars), ('monomial_product', main_vars),
                             ('final_product', final_vars), ('extraction', final_vars)]:
        bounds = atomic_zerocheck_phase_bounds(prime, width, 2, variables,
                                               schedule_version=schedule_version)
        add(stage, 'initial_equality', 1, bounds['initial_equality'])
        add(stage, 'first_mixed_challenge', 1, bounds['first_mixed_challenge'])
        add(stage, 'remaining_round', variables-1, bounds['remaining_round'])
    equality_phase = fixed_table_equality_bound(prime, width, 1)
    for stage, count in [('main_linear_reconstruction', 2*main_vars),
                         ('final_linear_reconstruction', final_vars),
                         ('accumulator_linear_identities', main_vars),
                         ('final_known_input', final_vars)]:
        add(stage, 'fixed_residual_fold', count, equality_phase)
    union = sum((p['count']*Fraction(p['error']) for p in phases), Fraction())
    return dict(prime=prime, width=width, descriptor_version=schedule_version,
                ring_dimension=n, lwe_dimension=lwe, role_variables=[main_vars, main_vars+lane_bits,
                    final_vars, final_vars+lane_bits], phases=phases,
                phase_count=sum(p['count'] for p in phases),
                conditional_phase_union=str(min(Fraction(1), union)),
                maximum_phase_error=str(max(Fraction(p['error']) for p in phases)),
                required_premises=['Fixed decoded factor/source tables coupled to authentication',
                    'NTT response packet fixed before common coefficient compression',
                    'Fixed linear/accumulator residual tables and ordered query-map identities',
                    'Atomic schedule-four conditional bad-transition lemmas'],
                excluded=['Extension lookup and all PCS opening phases',
                    'Availability, admissible-prefix/FS links and all-trials resource caps',
                    'Complete soundness and knowledge composition'],
                security_qualified=False, performance_gate=False, query_count_selected=False)


def lookup_stages(prime, degree, width, *, schedule_version):
    from classical_profile_descriptor import FIELD_NONRESIDUES
    packed_stages(prime, width, schedule_version=schedule_version)
    if type(degree) is not int or (str(prime), degree) not in FIELD_NONRESIDUES or width < degree:
        raise ValueError('supported extension degree and compatible packing width required')
    q = prime**degree
    digits = ((prime-1).bit_length()+7)//8
    switch_digits = ((prime-1).bit_length()+4)//5
    phases = []
    for stage, calls, requests, logical, variables, table in [
            ('main_lookups', 2, digits, 2**21, 21, 512),
            ('final_lookups', 1, switch_digits, 2**11, 11, 64)]:
        pairs = calls*requests  # Selected native repetitions = one.
        compression = Fraction(2*table, q)  # Three tuple columns.
        rational = Fraction(logical+table-1, q)
        retry = Fraction(table+1, q)
        for kind, count, error in [
                ('tuple_compression', pairs, compression),
                ('reciprocal_with_first_retry_stop', pairs, rational+retry),
                ('helper_equality_point', pairs, Fraction(variables, q)),
                ('shared_scalar_sumcheck_round', calls*variables, Fraction(3, q))]:
            phases.append(dict(stage=stage, phase=kind, count=count, error=str(error)))
        phases[-3].update(rational_escape=str(rational), first_retry_stop=str(retry))
    union = sum((p['count']*Fraction(p['error']) for p in phases), Fraction())
    return dict(prime=prime, extension_degree=degree, width=width, descriptor_version=schedule_version,
                phases=phases, phase_count=sum(p['count'] for p in phases),
                conditional_phase_union=str(min(Fraction(1), union)),
                maximum_phase_error=str(max(Fraction(p['error']) for p in phases)),
                scalar_identity_degree=3, lookup_repetitions=1,
                required_premises=['Fixed decoded sources/multiplicities before compression',
                    'Helpers bound before equality points; separate scalar equations retained',
                    'Conditional first-false-task lemmas and first-rejection analysis stop'],
                excluded=['PCS, availability and complete prefix/FS/work composition',
                          'Byte/identity/link queries needed for oracle-resource accounting'],
                security_qualified=False, performance_gate=False, query_count_selected=False)


def parent_stages(prime, degree, width, *, schedule_version):
    base = packed_stages(prime, width, schedule_version=schedule_version)
    lookup = lookup_stages(prime, degree, width, schedule_version=schedule_version)
    phases = base['phases'] + lookup['phases']
    base.update(extension_degree=degree, phases=phases,
        phase_count=sum(p['count'] for p in phases),
        conditional_phase_union=str(min(Fraction(1), sum(
            (p['count']*Fraction(p['error']) for p in phases), Fraction()))),
        maximum_phase_error=str(max(Fraction(p['error']) for p in phases)),
        required_premises=base['required_premises']+lookup['required_premises'],
        excluded=['All PCS opening phases',
            'Availability, complete admissible-prefix/FS links and all-trials resource caps',
            'Byte/identity/link query resource costs', 'Complete soundness and knowledge composition'])
    return base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prime', type=int, required=True)
    parser.add_argument('--width', type=int, required=True)
    parser.add_argument('--schedule-version', type=int, required=True)
    parser.add_argument('--extension-degree', type=int,
                        help='Include native extension lookup phases for this trusted degree')
    args = parser.parse_args()
    result = (packed_stages(args.prime, args.width, schedule_version=args.schedule_version)
              if args.extension_degree is None else parent_stages(
                  args.prime, args.extension_degree, args.width, schedule_version=args.schedule_version))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
