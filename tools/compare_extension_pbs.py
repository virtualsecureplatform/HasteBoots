#!/usr/bin/env python3
"""Compare complete lane-v2 and extension-v3 proofs on identical native inputs.

This deliberately compares two experimental protocols. Interactive inventory
checks do not establish Fiat-Shamir security or security-matched promotion.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
from full_pbs_budget import full_bounds, ROLES

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ("kind", "field", "security", "full_parameters", "seed", "batch_size", "prime",
           "width", "polynomial_size", "input_dimension", "output_dimension", "basis_bits",
           "key_switch_basis_bits", "private_coefficient_roots", "ntt_links", "verification_scope",
           "statement_sha256", "fhe_parameters_sha256", "native_keys_sha256", "pcs_layouts")
DIGESTS = ("statement_sha256", "fhe_parameters_sha256", "native_keys_sha256", "proof_sha256")


def read_rows(text, field, backend, iterations, full):
    layouts, rows = {}, []
    for line in text.splitlines():
        if line.startswith("HB_FULL_PCS "):
            layout = json.loads(line.split(" ", 1)[1])
            if layout.get("role") in layouts:
                raise ValueError("duplicate PCS role")
            layouts[layout["role"]] = layout
        elif line.startswith("HB_FULL_PBS "):
            rows.append(json.loads(line.split(" ", 1)[1]))
    if set(layouts) != set(ROLES) or iterations < 2 or len(rows) != iterations:
        raise ValueError("exact four layouts and initial/reused proof sequence required")
    extension = backend == "extension"
    for i, row in enumerate(rows):
        expected = dict(field=field, lookup_backend=backend, iteration=i, verified=True,
            full_parameters=full, batch_size=1, seed=42, width=8,
            prime={"babybear":2**31-2**27+1,"goldilocks":2**64-2**32+1}[field],
            protocol_version=3 if extension else 2, lookup_field_degree=5 if extension else 1,
            lookup_repetitions=1 if extension else 16, security="experimental-unbudgeted",
            transcript="merlin-direct-prime-parent-extension-child-v1" if extension else "merlin-direct-canonical-rejection-v1",
            verification_scope="complete-serialized-public-verifier")
        expected.update(polynomial_size=1024 if full else 32,
                        input_dimension=728 if full else 32,output_dimension=728 if full else 32,
                        basis_bits=8,key_switch_basis_bits=5)
        if any(type(row.get(k)) is not type(v) or row[k] != v for k,v in expected.items()):
            raise ValueError("verification, protocol or native fixture profile mismatch")
        for name in DIGESTS:
            if not isinstance(row.get(name),str) or not re.fullmatch("[0-9a-f]{64}",row[name]):
                raise ValueError("canonical public fixture/key/proof digest required")
        for name in ("complete_ns","prove_ns","serialization_ns","verify_ns","proof_bytes"):
            if type(row.get(name)) is not int or row[name] < 1:
                raise ValueError("positive integer timings and proof sizes required")
        full_bounds(row, layouts)
        row["pcs_layouts"] = layouts
        if any(row.get(k) != rows[0].get(k) for k in (*FIXTURE,*DIGESTS,"proof_bytes")):
            raise ValueError("fixture or deterministic proof changed within key reuse")
    return rows


def compare(lanes, extension):
    if any(lanes[0].get(k) != extension[0].get(k) for k in FIXTURE):
        raise ValueError("native public ciphertexts, FHE parameters, keys or layouts differ")
    old = statistics.median(r["complete_ns"] for r in lanes[1:])
    new = statistics.median(r["complete_ns"] for r in extension[1:])
    return dict(lanes_reused_ns=old, extension_reused_ns=new,
        reused_latency_reduction=1-new/old, proof_bytes_ratio=extension[0]["proof_bytes"]/lanes[0]["proof_bytes"],
        lanes_bytes=lanes[0]["proof_bytes"],extension_bytes=extension[0]["proof_bytes"],
        reused_samples_per_process=len(extension)-1,
        security="different experimental protocols; no security-matched promotion")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("saved",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--threads",type=int,default=16)
    parser.add_argument("--sessions",type=int,default=2)
    parser.add_argument("--iterations",type=int,default=2)
    parser.add_argument("--fields",nargs="+",choices=["babybear","goldilocks"],default=["babybear","goldilocks"])
    parser.add_argument("--full",action="store_true")
    args=parser.parse_args()
    if args.threads<1 or args.sessions<1 or args.iterations<2 or len(args.fields)!=len(set(args.fields)):
        parser.error("positive counts, at least two iterations and unique fields required")
    manifest=json.loads((args.saved/"manifest.json").read_text())
    binaries={}
    for field in args.fields:
        name=f"packed_extension_pbs_{field}"
        path=(args.saved/name).resolve()
        if manifest.get("security")!="experimental-unbudgeted" or hashlib.sha256(path.read_bytes()).hexdigest()!=manifest.get("binary_sha256",{}).get(name):
            raise ValueError("saved executable hash or profile mismatch")
        binaries[field]=path
    args.output.mkdir(parents=True,exist_ok=False)
    sessions=[]
    for session in range(args.sessions):
        for field in args.fields:
            pair={}
            order=["lanes","extension"] if session%2==0 else ["extension","lanes"]
            for backend in order:
                stem=args.output/f"session-{session+1}-{field}-{backend}"
                command=[str(binaries[field]),"--iterations",str(args.iterations)]
                if args.full: command.append("--full")
                if backend=="lanes":command.append("--lanes")
                print(stem.name,flush=True)
                started=datetime.datetime.now(datetime.timezone.utc).isoformat()
                with stem.with_suffix(".log").open("x") as log:
                    subprocess.run(["/usr/bin/time","-v","-o",str(stem.with_suffix(".resources").resolve()),*command],
                        cwd=ROOT,env=dict(os.environ,RAYON_NUM_THREADS=str(args.threads)),stdout=log,stderr=subprocess.STDOUT,check=True)
                pair[backend]=read_rows(stem.with_suffix(".log").read_text(),field,backend,args.iterations,args.full)
                pair[backend+"_started_utc"]=started
                print(f"  initial {pair[backend][0]['complete_ns']/1e9:.3f}s; reused {pair[backend][-1]['complete_ns']/1e9:.3f}s",flush=True)
            sessions.append(dict(session=session+1,field=field,order=order,**pair,comparison=compare(pair["lanes"],pair["extension"])))
            (args.output/"sessions.json").write_text(json.dumps(sessions,indent=2)+"\n")
    (args.output/"summary.json").write_text(json.dumps(dict(threads=args.threads,iterations=args.iterations,sessions=sessions),indent=2)+"\n")

if __name__=="__main__":
    main()
