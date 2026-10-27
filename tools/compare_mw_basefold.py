#!/usr/bin/env python3
"""Paired native Hadamard-only MW-Brakedown / structured MW-Basefold smokes.

Both modes use the same saved executable and exact native factor/input fixture.
A common query count is not a security-matched parameter choice. No complete-PBS
performance or whole-proof security promotion follows from this comparison.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PROFILE=("field","verification_scope","security","full_parameters","seed","variables","width","factors","queries","blowup","fixture_sha256","fhe_parameters_sha256")

def read_rows(text,field,backend,iterations,full,queries):
    rows=[json.loads(l.split(" ",1)[1]) for l in text.splitlines() if l.startswith("HB_MW_COMPARISON ")]
    if len(rows)!=iterations or iterations<2:raise ValueError("initial and reused component records required")
    for i,row in enumerate(rows):
        expected=dict(field=field,backend=backend,iteration=i,verified=True,full_parameters=full,
            verification_scope="native-hadamard-only",security="experimental-unbudgeted",seed=42,
            variables=18 if full else 8,width=8,factors=17 if field=="babybear" else 33,queries=queries,blowup=2)
        if any(type(row.get(k)) is not type(v) or row[k]!=v for k,v in expected.items()):raise ValueError("component profile or verification mismatch")
        for key in ("fixture_sha256","fhe_parameters_sha256","proof_sha256"):
            if not isinstance(row.get(key),str) or not re.fullmatch("[0-9a-f]{64}",row[key]):raise ValueError("canonical digest required")
        for key in ("commit_ns","prove_ns","serialization_ns","verify_ns","proof_bytes"):
            if type(row.get(key)) is not int or row[key]<1:raise ValueError("positive integer timings and bytes required")
        if any(row.get(k)!=rows[0].get(k) for k in (*PROFILE,"proof_sha256","proof_bytes")):raise ValueError("fixture/proof changed within commitment reuse")
    return rows

def compare(old,new):
    if any(old[0].get(k)!=new[0].get(k) for k in PROFILE):raise ValueError("native factors, public ciphertexts, FHE parameters or query profile differ")
    a=statistics.median(r["prove_ns"] for r in old[1:]);b=statistics.median(r["prove_ns"] for r in new[1:])
    return dict(brakedown_reused_prove_ns=a,basefold_reused_prove_ns=b,reused_prover_reduction=1-b/a,
        proof_bytes_ratio=new[0]["proof_bytes"]/old[0]["proof_bytes"],brakedown_bytes=old[0]["proof_bytes"],basefold_bytes=new[0]["proof_bytes"],
        brakedown_commit_ns=old[0]["commit_ns"],basefold_commit_ns=new[0]["commit_ns"],
        scope="native Hadamard component with existing commitments; not complete PBS or security-matched promotion")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("saved",type=Path);parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--threads",type=int,default=16);parser.add_argument("--sessions",type=int,default=2)
    parser.add_argument("--iterations",type=int,default=2);parser.add_argument("--queries",type=int,default=544)
    parser.add_argument("--fields",nargs="+",choices=["babybear","goldilocks"],default=["babybear","goldilocks"])
    parser.add_argument("--full",action="store_true");args=parser.parse_args()
    if min(args.threads,args.sessions,args.queries)<1 or args.iterations<2 or len(args.fields)!=len(set(args.fields)):parser.error("positive counts, unique fields and at least two iterations required")
    manifest=json.loads((args.saved/"manifest.json").read_text());binaries={}
    for field in args.fields:
        name=f"mw_basefold_{field}";path=(args.saved/name).resolve()
        if manifest.get("security")!="experimental-unbudgeted" or hashlib.sha256(path.read_bytes()).hexdigest()!=manifest.get("binary_sha256",{}).get(name):raise ValueError("saved binary hash/profile mismatch")
        binaries[field]=path
    args.output.mkdir(parents=True,exist_ok=False);sessions=[]
    for session in range(args.sessions):
        for field in args.fields:
            pair={};order=["mw-brakedown","structured-mw-basefold"] if session%2==0 else ["structured-mw-basefold","mw-brakedown"]
            for backend in order:
                stem=args.output/f"session-{session+1}-{field}-{backend}"
                command=[str(binaries[field]),"--queries",str(args.queries),"--iterations",str(args.iterations)]
                if args.full:command.append("--full")
                if backend=="mw-brakedown":command.append("--brakedown")
                print(stem.name,flush=True)
                with stem.with_suffix(".log").open("x") as log:
                    subprocess.run(["/usr/bin/time","-v","-o",str(stem.with_suffix(".resources").resolve()),*command],cwd=ROOT,
                        env=dict(os.environ,RAYON_NUM_THREADS=str(args.threads)),stdout=log,stderr=subprocess.STDOUT,check=True)
                pair[backend]=read_rows(stem.with_suffix(".log").read_text(),field,backend,args.iterations,args.full,args.queries)
                print(f"  reused proof {pair[backend][-1]['prove_ns']/1e9:.3f}s, bytes {pair[backend][0]['proof_bytes']}",flush=True)
            sessions.append(dict(session=session+1,field=field,order=order,**pair,comparison=compare(pair['mw-brakedown'],pair['structured-mw-basefold'])))
            (args.output/"sessions.json").write_text(json.dumps(sessions,indent=2)+"\n")
    (args.output/"summary.json").write_text(json.dumps(dict(threads=args.threads,iterations=args.iterations,queries=args.queries,sessions=sessions),indent=2)+"\n")

if __name__=="__main__":main()
