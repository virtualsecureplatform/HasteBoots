#!/usr/bin/env python3
"""Run the complete PBS benchmarks; preserve raw samples and build provenance."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
from archive_sources import snapshot_sources
import sys

ROOT = Path(__file__).resolve().parents[1]


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def summarize(samples):
    measured = [sample for sample in samples if not sample["warmup"]]
    keys = [key for key in measured[0] if key.endswith("_ns") or key.endswith("_bytes")]
    return {
        "count": len(measured),
        "metrics": {key: {
            "median": statistics.median(sample[key] for sample in measured),
            "min": min(sample[key] for sample in measured),
            "max": max(sample[key] for sample in measured),
            "stdev": statistics.stdev(sample[key] for sample in measured) if len(measured) > 1 else 0,
        } for key in keys},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fields", nargs="+", choices=["babybear", "goldilocks"], default=["babybear"])
    parser.add_argument("--threads", nargs="+", type=int, default=[1])
    parser.add_argument("--modes", nargs="+", choices=["warm", "cold"], default=["warm", "cold"])
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=ROOT / "target" / "performance" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0 or any(n < 1 for n in args.threads) or not 0 <= args.seed < 2**64:
        parser.error("invalid iteration, warmup, thread count or u64 seed")
    args.output.mkdir(parents=True, exist_ok=False)
    if not (ROOT / "Cargo.lock").exists():
        subprocess.run(["cargo", "generate-lockfile"], cwd=ROOT, check=True)
    build = ["cargo", "build", "--release", "--locked", "-p", "vfhe"]
    for field in args.fields:
        build += ["--example", f"bench_pbs_{field}"]
    subprocess.run(build, cwd=ROOT, check=True)
    metadata = json.loads(command("cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"))
    target = Path(metadata["target_directory"])
    binaries = args.output / "bin"
    binaries.mkdir()
    for field in args.fields:
        shutil.copy2(target / "release" / "examples" / f"bench_pbs_{field}", binaries / f"bench_pbs_{field}")
    provenance = {
        "date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "revision": command("git", "rev-parse", "HEAD"),
        "status": command("git", "status", "--short"),
        "rustc": command("rustc", "-Vv"),
        "platform": platform.platform(),
        "cpu": Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else platform.processor(),
        "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
        "binary_sha256": {field: hashlib.sha256((binaries / f"bench_pbs_{field}").read_bytes()).hexdigest() for field in args.fields},
        "build_environment": {name: os.environ[name] for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"] if name in os.environ},
        "settings": {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()},
        "security": "artifact parameters; not a whole-proof 128-bit claim",
    }
    (args.output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    # Preserve the actual changed/new source, not just the base commit ID.
    tracked = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=ROOT)
    (args.output / "changes.patch").write_bytes(tracked)
    pinned_lock = snapshot_sources(ROOT, args.output / "source.tar.gz")
    if hashlib.sha256(pinned_lock).hexdigest() != provenance["lock_sha256"]:
        raise RuntimeError("Cargo.lock changed during source capture; rerun with stable sources")
    (args.output / "Cargo.lock").write_bytes(pinned_lock)
    provenance["source_archive_sha256"] = hashlib.sha256((args.output / "source.tar.gz").read_bytes()).hexdigest()
    provenance["source_archive_contains_lock"] = True
    (args.output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    summaries = {}
    for field in args.fields:
        for threads in args.threads:
            for mode in args.modes:
                label = f"{field}-{threads}t-{mode}"
                env = dict(os.environ, RAYON_NUM_THREADS=str(threads))
                executable = (binaries / f"bench_pbs_{field}").resolve()
                invocation = [str(executable), "--iterations", str(args.iterations), "--warmups", str(args.warmups), "--seed", str(args.seed)]
                if mode == "cold":
                    invocation.append("--cold")
                # GNU time reports whole-process peak RSS, including setup and verification.
                peak = args.output / f"{label}.peak-rss-kib"
                if sys.platform.startswith("linux") and Path("/usr/bin/time").exists():
                    invocation = ["/usr/bin/time", "-f", "%M", "-o", str(peak), *invocation]
                samples = []
                print(f"Running {label}", flush=True)
                with (args.output / f"{label}.log").open("w") as log:
                    process = subprocess.Popen(invocation, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=log)
                    for line in process.stdout:
                        log.write(line)
                        log.flush()
                        if line.startswith("HB_BENCH "):
                            sample = json.loads(line[len("HB_BENCH "):])
                            samples.append(sample)
                            print(f"  iteration={sample['iteration']} warmup={sample['warmup']} complete={sample['complete_ns']/1e9:.3f}s", flush=True)
                    if process.wait():
                        raise RuntimeError(f"{label} failed; inspect {log.name}")
                if len(samples) != args.iterations + args.warmups:
                    raise RuntimeError(f"{label}: unexpected number of samples")
                (args.output / f"{label}.jsonl").write_text("".join(json.dumps(s) + "\n" for s in samples))
                summaries[label] = summarize(samples)
                if peak.exists():
                    summaries[label]["process_peak_rss_kib"] = int(peak.read_text().strip())
                (args.output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
