#!/usr/bin/env python3
"""Paired smokes of saved complete packed-PBS executables, with hash validation.

This compares engineering changes within the experimental backend, not a
security-matched baseline or a promotion decision.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
from full_pbs_budget import from_log, full_bounds, protocol_metadata

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ("kind", "protocol_version", "transcript", "field", "security", "full_parameters", "seed", "batch_size",
           "prime", "width", "polynomial_size", "input_dimension", "output_dimension",
           "basis_bits", "key_switch_basis_bits", "lookup_repetitions",
           "private_coefficient_roots", "ntt_links", "source_variables", "source_left_vars",
           "source_message_blocks", "source_encoded_blocks", "source_queries",
           "helper_variables", "helper_left_vars", "helper_message_blocks",
           "helper_encoded_blocks", "helper_queries", "pcs_layouts")


def compare(old, new):
    if old.get("protocol_version") == 3:
        if any(old.get(k) is None or old.get(k) != new.get(k) for k in ("lookup_backend","lookup_field_degree")):
            raise ValueError("extension lookup metadata differ")
    if any(k not in old or k not in new or old[k] != new[k] for k in PROFILE):
        raise ValueError("complete protocol/fixture/layout metadata differ")
    if any(type(r.get(k)) is not int or r[k] < 1 for r in (old,new) for k in ("complete_ns","proof_bytes")):
        raise ValueError("positive integer complete time and proof bytes required")
    return dict(complete_latency_reduction=1-new["complete_ns"]/old["complete_ns"],
                proof_bytes_ratio=new["proof_bytes"]/old["proof_bytes"],
                latency_below_90_percent=new["complete_ns"]*10 <= old["complete_ns"]*9,
                bytes_within_2x=new["proof_bytes"] <= old["proof_bytes"]*2,
                security="experimental backend engineering comparison; no security-matched promotion")


def read_complete(text):
    if sum(line.startswith("HB_FULL_PBS ") for line in text.splitlines()) != 1:
        raise ValueError("exactly one complete proof record required")
    record, layouts = from_log(text)
    record["protocol_version"],record["transcript"]=protocol_metadata(record)
    full_bounds(record, layouts)  # Validate all four layouts and actual inventory.
    record["pcs_layouts"] = layouts
    return record


def checked_binary(binary, manifest):
    binary = binary.resolve()
    expected = None
    for line in manifest.read_text().splitlines():
        digest, filename = line.split(maxsplit=1)
        path = Path(filename.lstrip("*"))
        if (path if path.is_absolute() else ROOT/path).resolve() == binary:
            expected = digest
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if expected is None or expected != digest:
        raise ValueError(f"saved executable does not match manifest: {binary}")
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline",type=Path)
    parser.add_argument("candidate",type=Path)
    parser.add_argument("--baseline-manifest",type=Path,required=True)
    parser.add_argument("--candidate-manifest",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--threads",type=int,default=16)
    parser.add_argument("--sessions",type=int,default=2)
    parser.add_argument("--full",action="store_true")
    args = parser.parse_args()
    if args.threads<1 or args.sessions<1:
        parser.error("positive thread and session counts required")
    binaries=dict(baseline=args.baseline.resolve(),candidate=args.candidate.resolve())
    hashes={name:checked_binary(binaries[name],manifest) for name,manifest in
            [("baseline",args.baseline_manifest),("candidate",args.candidate_manifest)]}
    args.output.mkdir(parents=True,exist_ok=False)
    sessions=[]
    for session in range(args.sessions):
        data={}
        order=["baseline","candidate"] if session%2==0 else ["candidate","baseline"]
        for name in order:
            print(f"Session {session+1}: {name}",flush=True)
            stem=args.output/f"session-{session+1}-{name}"
            command=[str(binaries[name])]+(["--full"] if args.full else [])
            resources=stem.with_suffix(".resources")
            if Path("/usr/bin/time").exists():
                command=["/usr/bin/time","-v","-o",str(resources),*command]
            started=datetime.datetime.now(datetime.timezone.utc).isoformat()
            with stem.with_suffix(".log").open("w") as log:
                subprocess.run(command,cwd=ROOT,env=dict(os.environ,RAYON_NUM_THREADS=str(args.threads)),stdout=log,stderr=subprocess.STDOUT,check=True)
            record=read_complete(stem.with_suffix(".log").read_text())
            if record.get("full_parameters") != args.full:
                raise ValueError("unexpected complete proof profile")
            data[name]=record
            data[name]["run_started_utc"]=started
            print(f"  complete={record['complete_ns']/1e9:.3f}s bytes={record['proof_bytes']}",flush=True)
        comparison=compare(data["baseline"],data["candidate"])
        sessions.append(dict(order=order,**data,comparison=comparison))
        (args.output/"sessions.json").write_text(json.dumps(sessions,indent=2)+"\n")
    metrics={name:{key:statistics.median(s[name][key] for s in sessions)
                   for key in sessions[0][name] if key.endswith("_ns") or key=="proof_bytes"}
             for name in binaries}
    result=dict(scope="paired experimental complete-PBS engineering smokes; not security-matched promotion",
                binary_sha256=hashes,threads=args.threads,sessions=args.sessions,platform=platform.uname()._asdict(),
                fixture_provenance="reported seed and FHE/layout metadata; these executables do not report ciphertext/key digests",
                metrics=metrics,comparisons=[s["comparison"] for s in sessions])
    (args.output/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))

if __name__ == "__main__":
    main()
