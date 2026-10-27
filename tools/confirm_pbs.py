#!/usr/bin/env python3
"""Compare saved BabyBear benchmark binaries without rebuilding either source."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

from bench_pbs import ROOT, summarize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=ROOT / "target" / "performance" / datetime.datetime.now(datetime.timezone.utc).strftime("confirm-%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()
    if args.threads < 1 or args.iterations < 1 or not 0 <= args.seed < 2**64:
        parser.error("positive thread/iteration counts and a u64 seed are required")
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for name, source in [("baseline", args.baseline), ("candidate", args.candidate)]:
        binary = (source / "bin" / "bench_pbs_babybear").resolve()
        provenance = json.loads((source / "provenance.json").read_text())
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != provenance["binary_sha256"]["babybear"]:
            raise ValueError(f"{name}: saved binary hash does not match provenance")
        invocation = [str(binary), "--iterations", str(args.iterations), "--warmups", "1", "--seed", str(args.seed)]
        peak = args.output / f"{name}.peak-rss-kib"
        if Path("/usr/bin/time").exists():
            invocation = ["/usr/bin/time", "-f", "%M", "-o", str(peak), *invocation]
        samples = []
        print(f"Confirming {name}", flush=True)
        with (args.output / f"{name}.log").open("w") as log:
            process = subprocess.Popen(invocation, cwd=ROOT, env=dict(os.environ, RAYON_NUM_THREADS=str(args.threads)), stdout=subprocess.PIPE, stderr=log, text=True)
            for line in process.stdout:
                log.write(line)
                log.flush()
                if line.startswith("HB_BENCH "):
                    sample = json.loads(line[9:])
                    samples.append(sample)
                    print(f"  {name} iteration={sample['iteration']} complete={sample['complete_ns']/1e9:.3f}s", flush=True)
            if process.wait():
                raise RuntimeError(f"{name} benchmark failed; inspect the log")
        if len(samples) != args.iterations + 1:
            raise RuntimeError(f"{name}: unexpected sample count")
        (args.output / f"{name}.jsonl").write_text("".join(json.dumps(s) + "\n" for s in samples))
        results[name] = summarize(samples)
        results[name]["binary_sha256"] = digest
        results[name]["source_session"] = str(source.resolve())
        if peak.exists():
            results[name]["process_peak_rss_kib"] = int(peak.read_text().strip())
    old = results["baseline"]["metrics"]
    new = results["candidate"]["metrics"]
    results["comparison"] = {
        "threads": args.threads,
        "seed": args.seed,
        "complete_latency_reduction": 1 - new["complete_ns"]["median"] / old["complete_ns"]["median"],
        "proof_bytes_ratio": new["proof_bytes"]["median"] / old["proof_bytes"]["median"],
        "meets_latency_and_size_thresholds": new["complete_ns"]["median"] <= old["complete_ns"]["median"] * 0.9 and new["proof_bytes"]["median"] <= old["proof_bytes"]["median"] * 2,
        "security": "artifact-only comparison; no complete 128-bit proof-security claim",
    }
    (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results["comparison"], indent=2))


if __name__ == "__main__":
    main()
