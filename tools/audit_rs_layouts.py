#!/usr/bin/env python3
"""Check measured layouts against hypotheses of the proposed RS audit bound.

No Merkle extraction, Fiat-Shamir, composition or promotion claim is made.
The existing performance/security budget is not modified by this tool.
"""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from full_pbs_budget import from_log, full_bounds

PRIMES = {2013265921, 2**64-2**32+1}


def bits(value):
    return math.log2(value.denominator)-math.log2(value.numerator)


def audit_layout(layout):
    names = ("prime", "width", "block_width", "row_message_scalars",
             "row_message_blocks", "row_encoded_blocks", "queries")
    if any(type(layout.get(k)) is not int or layout[k] < 1 for k in names):
        raise ValueError("positive integer dimensions required")
    p, k, block, scalars, m, n, queries = (layout[k] for k in names)
    if k > 32 or k & (k-1):
        raise ValueError("audit supports power-of-two packing widths up to 32")
    if p not in PRIMES or layout.get("row_code") != "block-rs":
        raise ValueError("independently checked native prime and block RS required")
    if block != k or scalars != k*m:
        raise ValueError("lifting audit requires unpadded symbols and block width equal to packing width")
    if n <= m or n < 32 or n & (n-1) or m & (m-1) or (p-1) % (2*n):
        raise ValueError("invalid native RS message/domain geometry")
    distance = n-m+1
    radius = (distance-1)//3
    assert 2*radius < distance and n >= m+2*radius
    q, coefficient = p**k, n*(n+1)
    proposed_random = Fraction(coefficient, q)
    current_random = Fraction(n, p)**k
    far_gap = Fraction(radius+1, n)
    near_gap = Fraction(distance-radius, n)
    current_gap = Fraction(distance, 3*n)
    far_tail = (1-far_gap)**queries
    near_tail = (1-near_gap)**queries
    current_tail = (1-current_gap)**queries
    return dict(symbol_degree=k, symbol_field_size=str(q), message_symbols=m,
        encoded_symbols=n, minimum_distance_symbols=distance, common_error_radius=radius,
        certificate_degree_bound=coefficient,
        proposed_random_test_bits=bits(proposed_random),
        current_random_test_bits=bits(current_random),
        proposed_far_tail_bits=bits(far_tail),
        current_tail_bits=bits(current_tail),
        current_random_term_dominates=proposed_random <= current_random,
        current_tail_dominates_both=far_tail <= current_tail and near_tail <= current_tail)


def audit_packet(record, layouts):
    if record.get("protocol_version", 1) not in (2, 3):
        raise ValueError("audit excludes legacy seed-expansion transcripts")
    full_bounds(record, layouts)
    return dict(field=record["field"], lookup_degree=record.get("lookup_field_degree", 1),
                layouts={role: audit_layout(layout) for role, layout in layouts.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    packets = []
    for path in args.logs:
        record, layouts = from_log(path.read_text())
        packet = audit_packet(record, layouts)
        packet.update(log=str(path), log_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        packets.append(packet)
    result = dict(scope="proposed RS-specific interactive argument for fixed available words; not a whole-PCS/FS/composition certificate",
                  existing_budgets_modified=False, packets=packets)
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(dict(layouts=sum(len(x["layouts"]) for x in packets),
        all_current_terms_dominate=all(v["current_random_term_dominates"] and v["current_tail_dominates_both"]
            for x in packets for v in x["layouts"].values()), scope=result["scope"]), indent=2))


if __name__ == "__main__": main()
