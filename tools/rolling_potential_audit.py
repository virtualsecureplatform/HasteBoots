#!/usr/bin/env python3
"""Tiny-field audit of one near-case rolling error-potential step.

This does not certify the general induction, hash availability, FS or PBS.
The field/code, error triples and binary successor perturbations are explicit.
"""
import json


def audit():
    p = 17
    beta = [pow(3, 2*j+1, p) for j in range(4)]
    points = [x for b in beta for x in (b, -b % p)]
    assert len(set(points)) == 8 and len({b*b % p for b in beta}) == 4
    def lift(mask):
        return sum(3 << (2*j) for j in range(4) if mask >> j & 1)
    lifts = [lift(mask) for mask in range(16)]
    checks = exceptional = 0
    for errors in ((1, 0, 0), (0, 1, 1), (1, 2, 3), (0, 0, 0)):
        even, odd, original = [[c]*4 for c in (2, 3, 4)]
        for row, error in zip((even, odd, original), errors):
            row[0] = (row[0]+error) % p
        word = [v for j, b in enumerate(beta) for v in
                ((even[j]+b*odd[j]) % p, (even[j]-b*odd[j]) % p)]
        # Exhaust all degree-<2 predecessor codewords; the old bad set can
        # be any of the 256 subsets of the eight initial positions.
        disagreements = [sum((value != (a+b*x) % p) << j
                             for j, (x, value) in enumerate(zip(points, word)))
                         for a in range(p) for b in range(p)]
        previous = [min((bad | mask).bit_count() for mask in disagreements)
                    for bad in range(256)]
        common_bad = int(any(errors))
        for alpha in range(p):
            combined = [(e+alpha*o+alpha*alpha*u) % p
                        for e, o, u in zip(even, odd, original)]
            decoded = (2+alpha*3+alpha*alpha*4) % p
            support = sum((x != decoded) << j for j, x in enumerate(combined))
            if support != common_bad:
                exceptional += 1
                continue
            for perturbation in range(16):
                successor = [(decoded+(perturbation >> j & 1)) % p for j in range(4)]
                mismatch = sum((a != b) << j for j, (a, b) in
                               enumerate(zip(combined, successor)))
                for bad in range(256):
                    next_bad = bad | lifts[mismatch]
                    # For a binary perturbation of a constant, constants
                    # decoded and decoded+1 dominate every other codeword.
                    potential = min((next_bad | lifts[perturbation]).bit_count(),
                                    (next_bad | lifts[15 ^ perturbation]).bit_count())
                    assert potential >= min(previous[bad], 2) # delta=1/4, |L0|=8.
                    checks += 1
    return dict(prime=p, predecessor_domain=8, predecessor_degree_bound=2,
                successor_domain=4, successor_degree_bound=1, radius='1/4',
                error_triples=4, all_past_bad_sets=256, binary_successor_words=16,
                all_field_challenges=17, nonexceptional_potential_checks=checks,
                cancellation_challenges_excluded=exceptional,
                whole_security_certified=False,
                scope='Selected near-case finite model, not a general proof or production verifier test')


if __name__ == '__main__':
    print(json.dumps(audit(), indent=2))
