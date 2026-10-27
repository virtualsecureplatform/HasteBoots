#!/usr/bin/env python3
"""Resource worksheet for the proposed classical-RO Merkle reduction.

No Fiat-Shamir, quantum, knowledge, hiding or whole-proof certificate is emitted.
Query counts are explicit assumptions, not inferred from benchmark timings.
"""
import argparse
from fractions import Fraction
import json
import math


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def schedule_bounds(bits, queries, freezes):
    """One global collision term, plus target hits for each root's freeze.

    A freeze entry may group `roots` declared at the same query count. Counts
    include new adversary, honest and verifier queries to the modeled oracle.
    """
    integer(bits, "digest bits", 1)
    integer(queries, "global distinct queries")
    if not isinstance(freezes, list) or not freezes:
        raise ValueError("a nonempty explicit freeze schedule is required")
    targets = 0
    for freeze in freezes:
        if not isinstance(freeze, dict) or set(freeze) != {"pre", "post", "roots"}:
            raise ValueError("freeze must have exactly pre, post, roots")
        a = integer(freeze["pre"], "pre-freeze queries")
        b = integer(freeze["post"], "post-freeze queries")
        roots = integer(freeze["roots"], "root declarations", 1)
        if a + b > queries:
            raise ValueError("freeze query counts exceed the global budget")
        targets += roots * (2 * a + 1) * b
    return {"global_collisions": Fraction(queries * (queries - 1), 2 ** (bits + 1)),
            "late_target_hits": Fraction(targets, 2 ** bits)}


def worst_bounds(bits, queries, roots):
    """Maximize each freeze term under A+B<=T; no independence assumed."""
    integer(queries, "global distinct queries")
    integer(roots, "root declarations", 1)
    # (2A+1)(T-A) is maximized at A=floor(T/2), giving T(T+1)/2.
    return schedule_bounds(bits, queries, [dict(pre=queries // 2,
        post=queries - queries // 2, roots=roots)])


def maximum_queries(bits, roots, target):
    """Largest T whose schedule-independent hash bound fits 2^-target."""
    integer(bits, "digest bits", 1)
    integer(roots, "root declarations", 1)
    integer(target, "target bits", 1)
    threshold = Fraction(1, 2 ** target)
    def fits(t):
        return sum(worst_bounds(bits, t, roots).values()) <= threshold
    lo, hi = 0, 1
    while fits(hi):
        lo, hi = hi, 2 * hi
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid
    return lo


def describe(value):
    return dict(numerator=str(value.numerator), denominator=str(value.denominator),
        bits=None if value == 0 else math.log2(value.denominator) - math.log2(value.numerator))


def report(bits, queries, roots, target, freezes=None):
    integer(roots, "root declarations", 1)
    integer(target, "target bits", 1)
    errors = worst_bounds(bits, queries, roots) if freezes is None else schedule_bounds(bits, queries, freezes)
    if freezes is not None and sum(f["roots"] for f in freezes) != roots:
        raise ValueError("schedule root count differs from declared roots")
    total = sum(errors.values())
    return dict(scope="proposed classical random-oracle Merkle availability only",
        digest_bits=bits, global_distinct_queries=queries, root_declarations=roots,
        target_bits=target, schedule=freezes, contributions={k: describe(v) for k,v in errors.items()},
        union_bound=describe(total), hash_term_fits_target=total <= Fraction(1, 2 ** target),
        maximum_queries_without_schedule=maximum_queries(bits, roots, target),
        whole_proof_security_certified=False,
        missing=["reviewed Merkle/RS reduction", "actual multi-root query inventory",
                 "Fiat-Shamir and parent/child transcript reduction",
                 "knowledge/hiding analysis", "quantum analysis if required"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest-bits", type=int, default=256)
    parser.add_argument("--queries", type=int, required=True)
    parser.add_argument("--roots", type=int, required=True)
    parser.add_argument("--target", type=int, default=128)
    parser.add_argument("--schedule", help="JSON array of {pre,post,roots}; otherwise maximize each freeze")
    args = parser.parse_args()
    try:
        result = report(args.digest_bits, args.queries, args.roots, args.target,
                        None if args.schedule is None else json.loads(args.schedule))
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
