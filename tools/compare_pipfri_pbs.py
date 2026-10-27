#!/usr/bin/env python3
"""Alternate saved native PipFRI reference binaries with exact fixture checks.

These are engineering smokes within an experimental, unbudgeted protocol. They
are not security-matched promotion evidence. Defaults measure one reused-key
proof per process; increase --iterations for a larger within-process sample.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ("field", "backend", "security", "transcript", "fragment_vars_max",
           "blowup", "queries", "verification_scope", "seed", "threads",
           "fhe_parameters_sha256", "statement_sha256", "trusted_bsk_root")
HASH_FIELDS = ("fhe_parameters_sha256", "statement_sha256", "trusted_bsk_root")
SIZE_FIELDS = ("proof_bytes", "pcs_bytes", "piop_bytes")


def checked_binary(directory, field):
    directory = Path(directory).resolve()
    manifest = json.loads((directory / "manifest.json").read_text())
    path = directory / f"pipfri_pbs_{field}"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if manifest.get("security") != "experimental-unbudgeted" or manifest.get("binary_sha256", {}).get(path.name) != digest:
        raise ValueError("saved executable hash or security profile mismatch")
    return path, digest


def read_rows(text, field, iterations, threads, seed):
    rows = [json.loads(line.split(" ", 1)[1]) for line in text.splitlines()
            if line.startswith("HB_PIPFRI_BENCH ")]
    if len(rows) != iterations or iterations < 2:
        raise ValueError("initial and reused proof records required without truncation")
    for i, row in enumerate(rows):
        expected = dict(field=field, backend="ordinary-pipfri-reference-v1",
                        security="experimental-unbudgeted",
                        transcript="merlin-direct-extension-canonical-rejection-v1",
                        verification_scope="legacy-four-stage-wrapper-in-memory",
                        threads=threads, seed=seed, iteration=i, verified=True,
                        warmup=False, cold=False, new_key_commitment=(i == 0))
        if any(key not in row or type(row[key]) is not type(value) or row[key] != value for key, value in expected.items()):
            raise ValueError("verification, execution profile or key-reuse sequence mismatch")
        for key in (*SIZE_FIELDS, "complete_ns", "fragment_vars_max", "blowup", "queries"):
            if type(row.get(key)) is not int or row[key] < 1:
                raise ValueError("positive integer geometry/timing/size required")
        if row["blowup"] < 2 or row["blowup"] & (row["blowup"] - 1):
            raise ValueError("invalid RS blowup")
        for key in HASH_FIELDS:
            value = row.get(key)
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("canonical public fixture/key digest required")
        if any(row.get(key) != rows[0].get(key) for key in (*PROFILE, *SIZE_FIELDS)):
            raise ValueError("fixture, protocol or proof sizes changed during key reuse")
    return rows


def compare(baseline, candidate):
    if any(baseline[0].get(k) != candidate[0].get(k) for k in (*PROFILE, *SIZE_FIELDS)):
        raise ValueError("protocol, public fixture, expected key root or serialized sizes differ")
    old = statistics.median(r["complete_ns"] for r in baseline[1:])
    new = statistics.median(r["complete_ns"] for r in candidate[1:])
    return dict(baseline_reused_ns=old, candidate_reused_ns=new,
                reused_latency_reduction=1-new/old,
                baseline_initial_ns=baseline[0]["complete_ns"],
                candidate_initial_ns=candidate[0]["complete_ns"],
                reused_samples_per_process=dict(baseline=len(baseline)-1, candidate=len(candidate)-1),
                proof_bytes=candidate[0]["proof_bytes"],
                security="experimental engineering comparison; no security-matched promotion")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fields", nargs="+", choices=["babybear", "goldilocks"], default=["babybear", "goldilocks"])
    parser.add_argument("--sessions", type=int, default=2)
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.sessions < 1 or args.iterations < 2 or args.threads < 1:
        parser.error("positive sessions/threads and at least two iterations required")
    if len(set(args.fields)) != len(args.fields) or not 0 <= args.seed < 2**64:
        parser.error("unique fields and a u64 seed required")
    binaries = {label: {f: checked_binary(directory, f) for f in args.fields}
                for label, directory in [("baseline", args.baseline), ("candidate", args.candidate)]}
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for session in range(args.sessions):
        order = ["baseline", "candidate"] if session % 2 == 0 else ["candidate", "baseline"]
        for field in args.fields:
            data = {}
            for label in order:
                binary, digest = binaries[label][field]
                stem = args.output / f"session-{session+1}-{field}-{label}"
                command = [str(binary), "--iterations", str(args.iterations), "--warmups", "0", "--seed", str(args.seed)]
                timed = ["/usr/bin/time", "-v", "-o", str(stem.with_suffix(".time")), *command] if Path("/usr/bin/time").exists() else command
                print(f"Session {session+1}, {field}: {label}", flush=True)
                started = datetime.datetime.now(datetime.timezone.utc).isoformat()
                with stem.with_suffix(".log").open("w") as stdout, stem.with_suffix(".stderr").open("w") as stderr:
                    subprocess.run(timed, cwd=ROOT, env=dict(os.environ, RAYON_NUM_THREADS=str(args.threads), RUST_LOG="info"), stdout=stdout, stderr=stderr, check=True)
                rows = read_rows(stem.with_suffix(".log").read_text(), field, args.iterations, args.threads, args.seed)
                data[label] = rows
                stem.with_suffix(".json").write_text(json.dumps(dict(binary_sha256=digest, command=command, started_utc=started, rows=rows), indent=2)+"\n")
                print(f"  reused={statistics.median(r['complete_ns'] for r in rows[1:])/1e9:.3f}s; bytes={rows[0]['proof_bytes']}", flush=True)
            result = dict(session=session+1, field=field, order=order, **compare(data["baseline"], data["candidate"]))
            records.append(result)
            (args.output / "summary.json").write_text(json.dumps(records, indent=2)+"\n")
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
