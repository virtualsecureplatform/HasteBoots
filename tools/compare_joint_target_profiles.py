#!/usr/bin/env python3
"""Compare complete PBS profiles at a common conditional interactive target.

This does not certify Fiat-Shamir, MW adaptation, hiding or promotion security.
"""
import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import re

from full_pbs_budget import full_bounds, ROLES

PROFILES = {"lanes": (1, 16, 2, "merlin-direct-canonical-rejection-v1"),
            "extension": (6, 1, 3, "merlin-direct-prime-parent-extension-child-v1")}
FIXTURE = ("kind", "field", "prime", "full_parameters", "seed", "batch_size",
           "polynomial_size", "input_dimension", "output_dimension", "basis_bits",
           "key_switch_basis_bits", "private_coefficient_roots", "ntt_links",
           "fhe_parameters_sha256", "native_keys_sha256", "statement_sha256")
DIGESTS = ("fhe_parameters_sha256", "native_keys_sha256", "statement_sha256", "proof_sha256")


def controls(text, profile):
    degree, reps, version, transcript = PROFILES[profile]
    layouts, rows = {}, []
    for line in text.splitlines():
        if line.startswith("HB_FULL_PCS "):
            item = json.loads(line.split(" ", 1)[1])
            if item.get("role") in layouts:
                raise ValueError("duplicate layout")
            layouts[item["role"]] = item
        elif line.startswith("HB_FULL_PBS "):
            rows.append(json.loads(line.split(" ", 1)[1]))
    if set(layouts) != set(ROLES) or len(rows) != 2:
        raise ValueError("exact four layouts and two complete controls required")
    for role, left in dict(source=3, helper=6, final_source=1, final_helper=5).items():
        if type(layouts[role].get("left_vars")) is not int or layouts[role]["left_vars"] != left:
            raise ValueError("native shifted-helper geometry mismatch")
        if type(layouts[role].get("queries")) is not int or layouts[role]["queries"] != 544:
            raise ValueError("unexpected oracle query count")
    for i, row in enumerate(rows):
        expected = dict(kind="complete-binary-nand-pbs", field="babybear", prime=2013265921,
            width=8, helper_left_extra=1, lookup_backend=profile, lookup_field_degree=degree,
            lookup_repetitions=reps, protocol_version=version, transcript=transcript,
            verification_scope="complete-serialized-public-verifier", verified=True,
            security="experimental-unbudgeted", full_parameters=True, seed=42, batch_size=1,
            polynomial_size=1024, input_dimension=728, output_dimension=728, basis_bits=8,
            key_switch_basis_bits=5, private_coefficient_roots=9, ntt_links=9, iteration=i,
            validation_mode="repeated-statement", validation_group_size=1, validation_group_index=0,
            left_plaintext=1, right_plaintext=1, decrypted_plaintext=0)
        if any(type(row.get(k)) is not type(v) or row[k] != v for k, v in expected.items()):
            raise ValueError("protocol, native fixture or complete verification mismatch")
        for key in DIGESTS:
            if not isinstance(row.get(key), str) or not re.fullmatch("[a-f0-9]{64}", row[key]):
                raise ValueError("missing public fixture/proof digest")
        for key in ("setup_ns", "trace_ns", "prove_ns", "serialization_ns", "complete_ns", "verify_ns", "proof_bytes"):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError("invalid timing/byte record")
        if row["proof_bytes"] == 0 or row["complete_ns"] < sum(row[k] for k in ("trace_ns", "prove_ns", "serialization_ns")):
            raise ValueError("inconsistent complete timing or empty proof")
        error = sum(full_bounds(row, layouts).values(), Fraction())
        if not 0 < 21*error <= Fraction(1, 2**128):
            raise ValueError("profile misses common conditional 21-proof target")
        row["interactive_bits"] = -math.log2(float(error))
        row["joint_21_interactive_bits"] = -math.log2(float(21*error))
        row["pcs_layouts"] = layouts
    if any(rows[0][k] != rows[1][k] for k in FIXTURE+DIGESTS+("proof_bytes", "setup_ns", "pcs_layouts")):
        raise ValueError("fixture, wire data or preprocessing changed on reuse")
    return rows


def compare(packets):
    if set(packets) != {(s, p) for s in (0, 1) for p in PROFILES}:
        raise ValueError("two sessions of both profiles required")
    baseline = packets[(0, "lanes")][0]
    if any(row[k] != baseline[k] for rows in packets.values() for row in rows
           for k in FIXTURE+("pcs_layouts",)):
        raise ValueError("profiles use different native fixtures, keys or layouts")
    for profile in PROFILES:
        if any(packets[(0, profile)][i][k] != packets[(1, profile)][i][k]
               for i in (0, 1) for k in DIGESTS+("proof_bytes", "pcs_layouts")):
            raise ValueError("profile wire data changed across processes")
    comparisons = []
    for session in (0, 1):
        lanes, extension = (packets[(session, p)][1] for p in ("lanes", "extension"))
        comparisons.append(dict(session=session, lane_reused_ns=lanes["complete_ns"],
            extension_reused_ns=extension["complete_ns"],
            latency_reduction=1-extension["complete_ns"]/lanes["complete_ns"],
            byte_ratio=extension["proof_bytes"]/lanes["proof_bytes"],
            lane_joint_21_bits=lanes["joint_21_interactive_bits"],
            extension_joint_21_bits=extension["joint_21_interactive_bits"]))
    return dict(scope="complete experimental profiles at a common conditional interactive target; no FS/security-matched promotion claim",
                target_bits=128, target_proofs=21, comparisons=comparisons,
                latency_engineering_gate=all(x["latency_reduction"] >= .10 for x in comparisons),
                bytes_engineering_gate=all(x["byte_ratio"] <= 2 for x in comparisons))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    paths = {(s, p): args.directory/f"native-{s}-{p}.log" for s in (0, 1) for p in PROFILES}
    packets = {key: controls(path.read_text(), key[1]) for key, path in paths.items()}
    result = compare(packets)
    result["packets"] = {f"{s}-{p}": rows for (s, p), rows in packets.items()}
    result["files_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths.values()}
    (args.directory/"comparison.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("packets", "files_sha256")}, indent=2))


if __name__ == "__main__":
    main()
