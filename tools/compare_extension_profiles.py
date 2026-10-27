#!/usr/bin/env python3
"""Check saved complete Goldilocks extension profiles; no security promotion claim."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
from fractions import Fraction
from full_pbs_budget import full_bounds, ROLES

PROFILES = {"d5-w8": (5, 8), "d3-w8": (3, 8), "d3-w4": (3, 4)}
FIXTURE = ("kind", "field", "prime", "full_parameters", "seed", "batch_size",
           "polynomial_size", "input_dimension", "output_dimension", "basis_bits",
           "key_switch_basis_bits", "private_coefficient_roots", "ntt_links",
           "statement_sha256", "fhe_parameters_sha256", "native_keys_sha256")
DIGESTS = ("statement_sha256", "fhe_parameters_sha256", "native_keys_sha256", "proof_sha256")


def read_rows(text, profile, full):
    degree, width = PROFILES[profile]
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
        raise ValueError("exact four layouts and two complete proofs required")
    for i, row in enumerate(rows):
        expected = dict(kind="complete-binary-nand-pbs", field="goldilocks", prime=2**64-2**32+1,
            width=width, lookup_field_degree=degree, lookup_backend="extension",lookup_repetitions=1,
            protocol_version=3, transcript="merlin-direct-prime-parent-extension-child-v1",
            verification_scope="complete-serialized-public-verifier",security="experimental-unbudgeted",
            full_parameters=full, seed=42,batch_size=1,iteration=i,verified=True,
            polynomial_size=1024 if full else 32,input_dimension=728 if full else 32,
            output_dimension=728 if full else 32,basis_bits=8,key_switch_basis_bits=5,
            private_coefficient_roots=17,ntt_links=17)
        if any(type(row.get(k)) is not type(v) or row[k] != v for k,v in expected.items()):
            raise ValueError("complete profile or native FHE contract mismatch")
        if any(type(x.get("queries")) is not int or x["queries"] != 544 for x in layouts.values()):
            raise ValueError("unexpected oracle profile")
        for key in DIGESTS:
            if not isinstance(row.get(key),str) or not re.fullmatch("[a-f0-9]{64}",row[key]):
                raise ValueError("missing fixture/key/proof digest")
        for key in ("setup_ns","trace_ns","prove_ns","serialization_ns","complete_ns","verify_ns","proof_bytes"):
            if type(row.get(key)) is not int or row[key] < 0:
                raise ValueError("invalid timing or byte record")
        if row["proof_bytes"] == 0 or row["complete_ns"] < row["trace_ns"]+row["prove_ns"]+row["serialization_ns"]:
            raise ValueError("inconsistent complete timing/bytes")
        error=sum(full_bounds(row,layouts).values())
        if error <= 0 or error > Fraction(1,2**128):
            raise ValueError("interactive inventory misses 128-bit threshold")
        row["interactive_bits"]=-math.log2(float(error))
        row["pcs_layouts"]=layouts
    if any(rows[0][key]!=rows[1][key] for key in FIXTURE+DIGESTS+("pcs_layouts",)):
        raise ValueError("fixture, key, layouts or deterministic proof changed on reuse")
    return rows


def compare_packets(packets):
    if set(packets) != {(s,p) for s in range(2) for p in PROFILES}:
        raise ValueError("two sessions of all three profiles required")
    baseline=packets[(0,"d5-w8")][0]
    for rows in packets.values():
        if any(row[key]!=baseline[key] for row in rows for key in FIXTURE):
            raise ValueError("different actual FHE fixture or native keys")
    for profile in PROFILES:
        a,b=packets[(0,profile)],packets[(1,profile)]
        if any(a[i][key]!=b[i][key] for i in range(2) for key in DIGESTS+("pcs_layouts",)):
            raise ValueError("profile wire data changed across processes")
    return [{"session":s,"profile":p,"initial_complete_ns":packets[(s,p)][0]["complete_ns"],
        "reused_complete_ns":packets[(s,p)][1]["complete_ns"],
        "reused_reduction":1-packets[(s,p)][1]["complete_ns"]/packets[(s,"d5-w8")][1]["complete_ns"],
        "proof_bytes":packets[(s,p)][1]["proof_bytes"],
        "byte_ratio":packets[(s,p)][1]["proof_bytes"]/packets[(s,"d5-w8")][1]["proof_bytes"],
        "interactive_bits":packets[(s,p)][1]["interactive_bits"]} for s in range(2) for p in PROFILES]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    args=parser.parse_args();root=args.directory
    packets={(s,p):read_rows((root/f"native-{s}-{p}.log").read_text(),p,True) for s in range(2) for p in PROFILES}
    toy={p:read_rows((root/f"toy-{p}.log").read_text(),p,False) for p in PROFILES}
    archived=read_rows((root/"toy-archived-d5-w8.log").read_text(),"d5-w8",False)
    if any(archived[i][k]!=toy["d5-w8"][i][k] for i in range(2) for k in FIXTURE+DIGESTS+("pcs_layouts",)):
        raise ValueError("default quintic wire behavior changed")
    result=dict(scope="complete experimental extension profiles; interactive inventory only; no FS/security-matched promotion",
        comparison=compare_packets(packets),packets={f"{s}-{p}":rows for (s,p),rows in packets.items()},
        wire_control="archived/default quintic toy proofs identical",
        files_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.glob("*.log"))})
    (root/"comparison.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result["comparison"],indent=2))

if __name__=="__main__": main()
