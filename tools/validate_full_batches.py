#!/usr/bin/env python3
"""Audit fresh-input 1/4/16 complete PBS logs; no aggregated proof claim."""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re

from full_pbs_budget import full_bounds, ROLES


def validate(text, field, full=True, profile="standard", aggregate_hadamard=False, defer_lookup_sources=False, shared_query_lookups=False):
    if field not in ("babybear", "goldilocks"):
        raise ValueError("unsupported field")
    if type(aggregate_hadamard) is not bool:
        raise ValueError("aggregation selection must be explicit bool")
    if type(defer_lookup_sources) is not bool or (defer_lookup_sources and not aggregate_hadamard):
        raise ValueError("deferred sources require explicit aggregate Hadamard selection")
    if type(shared_query_lookups) is not bool or (shared_query_lookups and (not aggregate_hadamard or defer_lookup_sources)):
        raise ValueError("shared queries require aggregate Hadamard and exclude deferred mode")
    gold = field == "goldilocks"
    prime, width, degree, roots = (2**64-2**32+1, 4, 3, 17) if gold else (2013265921, 8, 5, 9)
    if profile not in ("standard", "babybear6-helper1", "babybear8-helper1", "babybear-lanes-helper1") or (profile != "standard" and gold):
        raise ValueError("unsupported field/profile combination")
    helper_extra = int(profile != "standard")
    lanes = profile == "babybear-lanes-helper1"
    if aggregate_hadamard and lanes:
        raise ValueError("aggregate Hadamard requires extension comparisons")
    if helper_extra:
        degree = 1 if lanes else (6 if profile == "babybear6-helper1" else 8)
    layouts, rows = {}, []
    for line in text.splitlines():
        if line.startswith("HB_FULL_PCS "):
            layout = json.loads(line.split(" ", 1)[1])
            if layout.get("role") in layouts:
                raise ValueError("duplicate layout")
            layouts[layout["role"]] = layout
        elif line.startswith("HB_FULL_PBS "):
            rows.append(json.loads(line.split(" ", 1)[1]))
    schedule = [(size, i) for size in (1, 4, 16) for i in range(size)]
    if len(rows) != len(schedule) or set(layouts) != set(ROLES):
        raise ValueError("exact 21 proofs and four layouts required")
    if any(type(x.get("queries")) is not int or x["queries"] != 544 for x in layouts.values()):
        raise ValueError("unexpected oracle profile")
    if helper_extra and full:
        expected_left = dict(source=3, helper=6, final_source=1, final_helper=5)
        if any(type(layouts[role].get("left_vars")) is not int or
               layouts[role]["left_vars"] != left for role, left in expected_left.items()):
            raise ValueError("native shifted-helper profile mismatch")
    seen_statements, seen_proofs = set(), set()
    errors = []
    for iteration, ((size, index), row) in enumerate(zip(schedule, rows)):
        left, right = index & 1, (index >> 1) & 1
        expected = dict(kind="complete-binary-nand-pbs", field=field, prime=prime,
            width=width, lookup_field_degree=degree, lookup_backend="shared-extension" if shared_query_lookups else "deferred-extension" if defer_lookup_sources else ("lanes" if lanes else "extension"), lookup_repetitions=16 if lanes else 1,
            protocol_version=8 if shared_query_lookups else 5 if defer_lookup_sources else (4 if aggregate_hadamard else (2 if lanes else 3)),
            transcript="merlin-direct-shared-query-comparisons-v1" if shared_query_lookups else "merlin-direct-aggregated-hadamard-deferred-lookup-sources-v1" if defer_lookup_sources else "merlin-direct-extension-comparisons-aggregated-hadamard-v1" if aggregate_hadamard else ("merlin-direct-canonical-rejection-v1" if lanes else "merlin-direct-prime-parent-extension-child-v1"),
            verification_scope="complete-serialized-public-verifier", security="experimental-unbudgeted",
            full_parameters=full, seed=42, batch_size=1, iteration=iteration, verified=True,
            polynomial_size=1024 if full else 32, input_dimension=728 if full else 32,
            output_dimension=728 if full else 32, basis_bits=8, key_switch_basis_bits=5,
            private_coefficient_roots=roots, ntt_links=roots,
            validation_mode="independent-fresh-inputs", validation_group_size=size,
            validation_group_index=index, left_plaintext=left, right_plaintext=right,
            decrypted_plaintext=1-left*right)
        if any(type(row.get(k)) is not type(v) or row[k] != v for k, v in expected.items()):
            raise ValueError("validation schedule, native parameters or verification mismatch")
        if aggregate_hadamard and row.get("hadamard_backend") != "multi-root":
            raise ValueError("missing aggregate Hadamard mode")
        if type(row.get("helper_left_extra", 0)) is not int or row.get("helper_left_extra", 0) != helper_extra:
            raise ValueError("helper split profile mismatch")
        for key in ("statement_sha256", "proof_sha256", "fhe_parameters_sha256", "native_keys_sha256"):
            if not isinstance(row.get(key), str) or not re.fullmatch("[a-f0-9]{64}", row[key]):
                raise ValueError("missing artifact digest")
        for key in ("statement_sha256", "proof_sha256"):
            seen = seen_statements if key == "statement_sha256" else seen_proofs
            if row[key] in seen:
                raise ValueError("repeated statement or proof in fresh-input validation")
            seen.add(row[key])
        for key in ("native_keys_sha256", "fhe_parameters_sha256", "setup_ns"):
            if row.get(key) != rows[0].get(key):
                raise ValueError("preprocessing or native keys changed within process")
        for key in ("setup_ns", "trace_ns", "prove_ns", "serialization_ns", "complete_ns", "verify_ns", "proof_bytes"):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError("invalid timing or byte metadata")
        if row["proof_bytes"] == 0 or row["complete_ns"] < sum(row[k] for k in ("trace_ns", "prove_ns", "serialization_ns")):
            raise ValueError("inconsistent proof bytes or complete timing")
        error = sum(full_bounds(row, layouts).values(), Fraction())
        if not 0 < error <= Fraction(1, 2**128):
            raise ValueError("per-proof interactive inventory misses threshold")
        errors.append(error)
    union = sum(errors, Fraction())
    if helper_extra and union > Fraction(1, 2**128):
        raise ValueError("shifted-helper profile misses 21-proof interactive union threshold")
    return dict(field=field, profile=profile, aggregate_hadamard=aggregate_hadamard, defer_lookup_sources=defer_lookup_sources, shared_query_lookups=shared_query_lookups, full_parameters=full, proofs=len(rows), groups=[1, 4, 16],
        scope=("independent single-PBS proofs with shared preprocessing and shared-query comparison authentication; no cross-statement aggregation or FS certificate" if shared_query_lookups else "independent single-PBS proofs with shared preprocessing, within-proof Hadamard aggregation and per-decomposition deferred lookup source authentication; no cross-statement aggregation or FS certificate" if defer_lookup_sources else "independent single-PBS proofs with shared preprocessing and within-proof Hadamard aggregation; no cross-statement aggregation or FS certificate" if aggregate_hadamard else "independent single-PBS proofs with shared preprocessing; no aggregation or FS certificate"),
        per_proof_interactive_bits=-math.log2(float(max(errors))),
        all_21_interactive_union_bits=-math.log2(float(union)),
        native_keys_sha256=rows[0]["native_keys_sha256"],
        fhe_parameters_sha256=rows[0]["fhe_parameters_sha256"], rows=rows, layouts=layouts)


def match_native_reference(result, text):
    """Compare actual native-key/parameter digests with a prior complete run."""
    references = [json.loads(line.split(" ", 1)[1]) for line in text.splitlines()
                  if line.startswith("HB_FULL_PBS ")]
    if not references:
        raise ValueError("missing prior complete native reference")
    keys = ("kind", "field", "prime", "full_parameters", "seed", "polynomial_size",
            "input_dimension", "output_dimension", "basis_bits", "key_switch_basis_bits",
            "fhe_parameters_sha256", "native_keys_sha256", "verification_scope", "verified")
    row = result["rows"][0]
    if any(type(ref.get(k)) is not type(row[k]) or ref[k] != row[k]
           for ref in references for k in keys):
        raise ValueError("native FHE/key fixture differs from prior complete run")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--field", choices=("babybear", "goldilocks"), required=True)
    parser.add_argument("--toy", action="store_true")
    parser.add_argument("--profile", choices=("standard", "babybear6-helper1", "babybear8-helper1", "babybear-lanes-helper1"), default="standard")
    parser.add_argument("--aggregate-hadamard", action="store_true")
    parser.add_argument("--defer-lookup-sources", action="store_true")
    parser.add_argument("--shared-query-lookups", action="store_true")
    parser.add_argument("--reference-log", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.log.read_text(), args.field, not args.toy, args.profile, args.aggregate_hadamard, args.defer_lookup_sources, args.shared_query_lookups)
    if args.reference_log:
        match_native_reference(result, args.reference_log.read_text())
        result["reference_log_sha256"] = hashlib.sha256(args.reference_log.read_bytes()).hexdigest()
    result["log_sha256"] = hashlib.sha256(args.log.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("rows", "layouts")}, indent=2))


if __name__ == "__main__":
    main()
