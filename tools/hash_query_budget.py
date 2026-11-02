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


def global_target_bounds(bits, queries, roots):
    """One predictable target set for all roots, with deterministic envelopes.

    At most two digest targets per eligible internal preimage, plus declared
    root targets. Counts include all trials and honest/verifier hash queries.
    """
    integer(bits, 'digest bits', 1)
    integer(queries, 'global distinct queries')
    integer(roots, 'all-trials root declarations')
    return dict(global_collisions=Fraction(queries*(queries-1), 2**(bits+1)),
                late_target_hits=Fraction(queries*(2*queries+roots), 2**bits))


def global_work_coefficients(bits, hash_per_work, hash_offset, roots_per_work, root_offset):
    """Nonnegative polynomial envelope in attacker work, not measured counters.

    Caller must prove H<=hash_per_work*T+hash_offset and an analogous root cap.
    Replaces H(H-1) by H^2 to keep every coefficient nonnegative.
    """
    integer(bits, 'digest bits', 1)
    for name, value in [('hash_per_work', hash_per_work), ('hash_offset', hash_offset),
                        ('roots_per_work', roots_per_work), ('root_offset', root_offset)]:
        integer(value, name)
    a, h, b, r = hash_per_work, hash_offset, roots_per_work, root_offset
    denominator = 2**(bits+1)
    return dict(constant=Fraction(5*h*h+2*h*r, denominator),
                linear=Fraction(10*a*h+2*(a*r+b*h), denominator),
                quadratic=Fraction(5*a*a+2*a*b, denominator))


def xof_link_bounds(bits, outputs, windows):
    """Conditional ideal-XOF fingerprint collisions and predictable-window hits.

    outputs counts distinct producer inputs, including consumed-byte receipt
    producers. windows bounds all proposed digest-size windows registered
    before fresh outputs, across all trials and verifier invocations. Neither
    parameter is an observed final-proof counter or a phase-order assumption.
    """
    integer(bits, 'fingerprint bits', 1)
    integer(outputs, 'global distinct fingerprint outputs')
    integer(windows, 'global predictable windows')
    return dict(output_collisions=Fraction(outputs*(outputs-1), 2**(bits+1)),
                late_link_hits=Fraction(outputs*windows, 2**bits))


def xof_work_coefficients(bits, outputs_per_work, output_offset,
                          windows_per_work, window_offset):
    """Nonnegative all-trials envelope for caller-proved affine resource caps.

    Uses M^2 in place of M(M-1). A bounded candidate-input length alone does
    not justify the window cap unless every relevant input obeys that bound.
    """
    integer(bits, 'fingerprint bits', 1)
    for name, value in [('outputs_per_work', outputs_per_work),
                        ('output_offset', output_offset),
                        ('windows_per_work', windows_per_work),
                        ('window_offset', window_offset)]:
        integer(value, name)
    a, m, b, w = outputs_per_work, output_offset, windows_per_work, window_offset
    denominator = 2**(bits+1)
    return dict(constant=Fraction(m*m+2*m*w, denominator),
                linear=Fraction(2*a*m+2*(a*w+b*m), denominator),
                quadratic=Fraction(a*a+2*a*b, denominator))


def bounded_input_xof_work(bits, verifier_outputs, eligible_input_bytes, honest_outputs):
    """Conditional caps from charged oracle queries/submissions and a filter.

    Every *eligible* candidate input must be at most eligible_input_bytes;
    all other oracle inputs still count in M, but register no link windows.
    The caller must justify that filtering cannot discard a relevant producer.
    A verifier invocation uses at most verifier_outputs producer invocations.
    Queries and submissions each cost at least one unit of attacker work.
    """
    for name, value in [('verifier outputs', verifier_outputs),
                        ('eligible input bytes', eligible_input_bytes),
                        ('honest output offset', honest_outputs)]:
        integer(value, name)
    integer(bits, 'fingerprint bits', 1)
    fingerprint_bytes = (bits+7)//8
    windows = max(0, eligible_input_bytes-fingerprint_bytes+1)
    outputs_per_work = 1+verifier_outputs
    return dict(outputs_per_work=outputs_per_work, output_offset=honest_outputs,
        fingerprint_bytes=fingerprint_bytes,
        windows_per_input=windows, windows_per_work=windows*outputs_per_work,
        window_offset=windows*honest_outputs,
        coefficients=xof_work_coefficients(bits, outputs_per_work, honest_outputs,
                                           windows*outputs_per_work, windows*honest_outputs),
        required_premises=['All adversarial queries and verifier submissions charged across all trials',
            'Every relevant eligible candidate input satisfies the stated length filter',
            'Verifier output count and honest output offset cover every producer'],
        resource_coupling_established=False, whole_proof_security_certified=False)


def joint_filtered_oracle_work(bits, verifier_hashes, verifier_xof_outputs,
                               hash_input_bytes, xof_input_bytes,
                               honest_hashes, honest_xof_outputs, honest_roots):
    """Conditional shared-window caps for both oracle families, across trials.

    Root declarations must occur in eligible bounded inputs (or the explicit
    honest root offset). Count every digest-sized window rather than charging
    only declarations visible in a final accepted proof. Output collisions
    include all inputs, even those excluded from window registration.
    """
    values = locals().copy()
    for name, value in values.items():
        integer(value, name, 1 if name == 'bits' else 0)
    fingerprint_bytes = (bits+7)//8
    hash_windows = max(0, hash_input_bytes-fingerprint_bytes+1)
    xof_windows = max(0, xof_input_bytes-fingerprint_bytes+1)
    a, b = 1+verifier_hashes, 1+verifier_xof_outputs
    roots_per_work = hash_windows*a+xof_windows*b
    root_offset = hash_windows*honest_hashes+xof_windows*honest_xof_outputs+honest_roots
    return dict(fingerprint_bytes=fingerprint_bytes,
        hash_windows_per_input=hash_windows, xof_windows_per_input=xof_windows,
        hash_per_work=a, hash_offset=honest_hashes,
        xof_per_work=b, xof_offset=honest_xof_outputs,
        roots_per_work=roots_per_work, root_offset=root_offset,
        merkle=global_work_coefficients(bits, a, honest_hashes, roots_per_work, root_offset),
        xof=xof_work_coefficients(bits, b, honest_xof_outputs,
                                 xof_windows*b, xof_windows*honest_xof_outputs),
        required_premises=['Charged queries and verifier submissions across all trials',
            'Every relevant root declaration lies in an eligible bounded input or honest offset',
            'Eligible window filters preserve the actual source/link reduction',
            'Per-verifier counts, stopped execution bounds and honest offsets justified'],
        resource_coupling_established=False, whole_proof_security_certified=False)


def maximum_queries(bits, roots, target, *, global_targets=False):
    """Largest T whose schedule-independent hash bound fits 2^-target."""
    integer(bits, "digest bits", 1)
    integer(roots, "root declarations", 1)
    integer(target, "target bits", 1)
    threshold = Fraction(1, 2 ** target)
    def fits(t):
        bounds = global_target_bounds if global_targets else worst_bounds
        return sum(bounds(bits, t, roots).values()) <= threshold
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


def report(bits, queries, roots, target, freezes=None, *, global_targets=False):
    integer(roots, "root declarations", 1)
    integer(target, "target bits", 1)
    if type(global_targets) is not bool or global_targets and freezes is not None:
        raise ValueError('choose global targets or an explicit freeze schedule')
    errors = (global_target_bounds(bits, queries, roots) if global_targets else
              worst_bounds(bits, queries, roots) if freezes is None else schedule_bounds(bits, queries, freezes))
    if freezes is not None and sum(f["roots"] for f in freezes) != roots:
        raise ValueError("schedule root count differs from declared roots")
    total = sum(errors.values())
    return dict(scope="proposed classical random-oracle Merkle availability only",
        digest_bits=bits, global_distinct_queries=queries, root_declarations=roots,
        target_model='global-predictable-target-set' if global_targets else 'per-freeze-target-union',
        target_bits=target, schedule=freezes, contributions={k: describe(v) for k,v in errors.items()},
        union_bound=describe(total), hash_term_fits_target=total <= Fraction(1, 2 ** target),
        maximum_queries_without_schedule=maximum_queries(bits, roots, target, global_targets=global_targets),
        whole_proof_security_certified=False,
        missing=["reviewed Merkle/RS reduction", "all-trials query/root and attacker-work envelopes",
                 "Fiat-Shamir and parent/child transcript reduction",
                 "knowledge analysis"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest-bits", type=int, default=256)
    parser.add_argument("--queries", type=int, required=True)
    parser.add_argument("--roots", type=int, required=True)
    parser.add_argument("--target", type=int, default=128)
    parser.add_argument("--schedule", help="JSON array of {pre,post,roots}; otherwise maximize each freeze")
    parser.add_argument('--global-targets', action='store_true', help='Use the shared predictable target-set envelope')
    args = parser.parse_args()
    try:
        result = report(args.digest_bits, args.queries, args.roots, args.target,
                        None if args.schedule is None else json.loads(args.schedule),
                        global_targets=args.global_targets)
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
