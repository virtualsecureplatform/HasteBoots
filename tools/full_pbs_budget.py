#!/usr/bin/env python3
"""Experimental interactive error inventory of the complete packed NAND relation.

This is NOT a Fiat-Shamir, knowledge, hiding, hash-binding, or security-matched
baseline analysis. The MW row-code adaptation still needs independent review.
"""
import argparse
import json
from fractions import Fraction
from pathlib import Path
from packed_budget import (component_bounds, lane_decomposition_component_bounds,
                           accumulator_component_bounds, monomial_component_bounds,
                           key_switch_component_bounds, extension_decomposition_component_bounds)

ROLES = ("source", "helper", "final_source", "final_helper")


def protocol_metadata(record):
    version=record.get("protocol_version",1)
    transcript=record.get("transcript","legacy-aes128-seed" if version==1 else None)
    known={1:"legacy-aes128-seed",2:"merlin-direct-canonical-rejection-v1",3:"merlin-direct-prime-parent-extension-child-v1",4:"merlin-direct-extension-comparisons-aggregated-hadamard-v1",5:"merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1"}
    if type(version) is not int or version not in known or transcript!=known[version]:
        raise ValueError("unsupported or inconsistent complete proof transcript version")
    return version,transcript


def full_bounds(record, layouts):
    version,_ = protocol_metadata(record)
    decomposition_bound = lane_decomposition_component_bounds
    if version in (3,4,5):
        if record.get("lookup_backend") != ("deferred-extension" if version==5 else "extension") or type(record.get("lookup_field_degree")) is not int:
            raise ValueError("extension protocol requires explicit backend and field degree")
        decomposition_bound = extension_decomposition_component_bounds
    names = ("prime", "width", "polynomial_size", "input_dimension", "output_dimension",
             "basis_bits", "key_switch_basis_bits", "lookup_repetitions",
             "private_coefficient_roots", "ntt_links")
    if record.get("kind") != "complete-binary-nand-pbs" or set(layouts) != set(ROLES):
        raise ValueError("complete NAND record and exactly four trusted layouts required")
    if any(type(record.get(n)) is not int or record[n] < 1 for n in names):
        raise ValueError("missing complete relation dimensions")
    p,k,size,lwe,out,bits,ks_bits,reps,roots,links = (record[n] for n in names)
    if out != lwe or size != 1 << (lwe-1).bit_length() or k & (k-1) or k > size or max(bits,ks_bits) >= p.bit_length():
        raise ValueError("unsupported dimensions, width, or radix")
    digits = ((p-1).bit_length()+bits-1)//bits
    if roots != 2*digits+1 or links != roots:
        raise ValueError("canonical private source/NTT inventory mismatch")
    padded = 1 << (lwe-1).bit_length()
    coefficient = (size//k).bit_length()-1
    row = padded.bit_length()-1
    variables = coefficient+row+1
    short = coefficient+1
    expected = (variables, variables+k.bit_length()-1, short, short+k.bit_length()-1)
    for role,n in zip(ROLES, expected):
        c = layouts[role]
        if c.get("row_code") != "block-rs" or c.get("prime") != p or c.get("width") != k or c.get("variables") != n:
            raise ValueError("incompatible complete proof layouts")
        left = c.get("left_vars")
        if type(left) is not int or not 0 <= left <= n or c.get("row_message_scalars") != 1 << (n-left):
            raise ValueError("inconsistent physical row geometry")
        component_bounds(dict(c, degree=3, factors=1))
    source,helper,final,final_helper = (layouts[r] for r in ROLES)
    errors = {}
    def add(prefix, contributions):
        errors.update({prefix+"_"+name:value for name,value in contributions.items()})
    add("hadamard",component_bounds(dict(source,degree=2,factors=4*digits+1)))
    if version in (4,5):
        if (record.get("hadamard_backend") != "multi-root" or k < 3
            or source["block_width"] != k
            or source["row_message_scalars"] != k*source["row_message_blocks"]):
            raise ValueError("aggregate Hadamard requires explicit mode and unpadded equal-width block RS")
        # Keep the old per-factor PCS terms conservatively. For k>=3,n>=2
        # they dominate the proposed concatenated fixed-word RS term/tail.
        # Add the new full-coordinate extension cancellation term explicitly.
        degree=record["lookup_field_degree"]
        if degree < 1:
            raise ValueError("invalid aggregation field degree")
        errors["hadamard_aggregation_cancellation"]=Fraction(1,p**degree)

    if version==5:
        # No new algebraic compression: every derived query/value is still
        # checked. Keep the old per-limb source PCS count as an upper bound
        # on the <=2*d+1 canonical source packets (previously 3*d).
        # The fixed-word/shared-column argument requires native unpadded
        # source geometry, including the final key-switch decomposition.
        for c in (source,final):
            if c["block_width"]!=k or c["row_message_scalars"]!=k*c["row_message_blocks"]:
                raise ValueError("deferred source authentication requires unpadded equal-width block RS")

    length,message = source["row_encoded_blocks"],source["row_message_blocks"]
    proximity = (1-Fraction(length-message+1,3*length))**source["queries"]
    responses = 4*links if source["left_vars"] <= coefficient else 2*links*(k+1)
    add("private_ntt",{
        "row_identity": links*Fraction(row+1,p)**k,
        "coefficient_compression": links*2*k*coefficient*Fraction(2*k-1,p)**k,
        "proximity": responses*proximity,
        "random_linear_test": 2*links*Fraction(length,p)**k,
    })
    lane = dict(source,degree=3,factors=2*digits,logical_len=2*size*padded,
                public_table_len=2*(1<<bits),excluded_challenges=2*(1<<bits)+1,
                repetitions=reps,tuple_columns=3,linear_checks=2,linear_sources=4*(digits+1),
                effective_repetitions=((reps+k-1)//k)*k,lookup_groups=(reps+k-1)//k)
    lane.update({"helper_"+n:helper[n] for n in ("variables","row_message_scalars","row_message_blocks","row_encoded_blocks","block_width","queries")})
    if version in (3,4,5):
        lane["lookup_field_degree"] = record["lookup_field_degree"]
    add("decomposition",decomposition_bound(lane))
    queries = row+12
    responses = 14 if source["left_vars"] <= coefficient else queries+7
    add("accumulator",accumulator_component_bounds(dict(source,degree=1,factors=7,
        linear_relations=7,polynomial_size=size,rounds=lwe,padded_rounds=padded,
        coefficient_variables=coefficient,source_queries=queries,response_groups=responses)))
    add("monomial",monomial_component_bounds(dict(source,polynomial_size=size,rounds=lwe,padded_rounds=padded)))
    final_record = dict(final,polynomial_size=size,output_dimension=lwe,basis_bits=ks_bits,
                        digits=((p-1).bit_length()+ks_bits-1)//ks_bits,repetitions=reps)
    final_record.update({"helper_"+n:final_helper[n] for n in ("variables","row_message_scalars","row_message_blocks","row_encoded_blocks","block_width","queries")})
    if version in (3,4,5):
        final_record["lookup_field_degree"] = record["lookup_field_degree"]
    add("key_switch",key_switch_component_bounds(final_record, decomposition_bound=decomposition_bound))
    return errors


def from_log(text):
    layouts = {}
    record = None
    for line in text.splitlines():
        if line.startswith("HB_FULL_PCS "):
            layout = json.loads(line[len("HB_FULL_PCS "):])
            layouts[layout["role"]] = layout
        elif line.startswith("HB_FULL_PBS "):
            record = json.loads(line[len("HB_FULL_PBS "):])
    if record is None:
        raise ValueError("missing HB_FULL_PBS record")
    return record, layouts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log",type=Path)
    parser.add_argument("--target",type=int,default=128)
    args = parser.parse_args()
    if args.target < 1:
        parser.error("positive target required")
    record,layouts = from_log(args.log.read_text())
    version,transcript = protocol_metadata(record)
    errors = full_bounds(record,layouts)
    total = sum(errors.values())
    print(json.dumps({
        "analysis":"complete relation experimental interactive inventory; not Fiat-Shamir or whole-proof security",
        "kind":record["kind"],"protocol_version":version,"transcript":transcript,
        "field":record.get("field"),"target_bits":args.target,
        "interactive_bound_below_target":total <= Fraction(1,2**args.target),
        "private_ntt_links":record["ntt_links"],
        "contributions":{n:float(v) for n,v in errors.items()},"total":float(total),
    },indent=2))

if __name__ == "__main__":
    main()
