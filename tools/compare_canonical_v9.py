#!/usr/bin/env python3
"""Compare complete v11 against the frozen complete-v9 fork on identical inputs.

Engineering measurements only; neither profile has certified whole security.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess

from benchmark_affinity import cpu_set
from compare_canonical_kernels import equivalent
from compare_canonical_polyfrim import PRIMES, read_records
from joint_pbs_timing import assert_idle, validate_run, validate_repeated_wire


def matched_workload(v9, canonical):
    packets, members = v9["packets"], v9["members"]
    if len(packets) != len(canonical) or len(members) != len(canonical):
        raise ValueError("different complete single-proof schedules")
    keys = {"prime": "prime", "width": "width", "polynomial_size": "ring_dimension",
            "input_dimension": "lwe_dimension", "output_dimension": "output_dimension",
            "lookup_field_degree": "extension_degree", "lookup_repetitions": "lookup_repetitions",
            "native_keys_sha256": "native_keys_sha256", "fhe_parameters_sha256": "fhe_parameters_sha256"}
    for packet, member, row in zip(packets, members, canonical):
        if row.get("v9_fixture") is not True:
            raise ValueError("canonical runner must select the explicit v9 fixture")
        for old, new in keys.items():
            if type(packet[old]) is not type(row[new]) or packet[old] != row[new]:
                raise ValueError(f"changed workload: {old}")
        for old, new in (("statement_sha256", "statement_sha256"),
                         ("left_plaintext", "left"), ("right_plaintext", "right"),
                         ("decrypted_plaintext", "output")):
            if type(member[old]) is not type(row[new]) or member[old] != row[new]:
                raise ValueError(f"changed encrypted statement: {old}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v9-directory", type=Path, required=True)
    parser.add_argument("--v9-sources", type=Path, required=True)
    parser.add_argument("--canonical", type=Path, required=True)
    parser.add_argument("--canonical-sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpus", required=True)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--toy", action="store_true")
    parser.add_argument("--correctness-only", action="store_true")
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0:
        parser.error("invalid proof schedule")
    if not args.correctness_only and (args.iterations < 10 or args.warmups < 1 or args.toy):
        parser.error("timing requires native parameters, one warmup and ten measured proofs")
    try:
        affinity = cpu_set(args.cpus, sorted(os.sched_getaffinity(0)))
    except ValueError as error:
        parser.error(str(error))
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = dict(terminal=False, cold=False, threads=16, cpu_affinity=affinity,
                    iterations=args.iterations, warmups=args.warmups, toy=args.toy,
                    timing_eligible=not args.correctness_only and not args.toy,
                    comparison="complete v9 joint-comparisons versus canonical v11 Brakedown",
                    whole_security_matched=False, promotion_gate=False,
                    builds={}, commands=[], summaries=[])
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    write = lambda: (args.output/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    shutil.copy2(__file__, args.output/"executed-driver.py")
    manifest["driver_sha256"] = sha(Path(__file__))
    manifest["validation_sources_sha256"] = {
        name: sha(Path(__file__).with_name(name)) for name in
        ("benchmark_affinity.py", "compare_canonical_kernels.py", "compare_canonical_polyfrim.py",
         "joint_pbs_timing.py", "validate_joint_pbs_batches.py", "batch_phase_statistics.py", "full_pbs_budget.py")}
    binaries = {}
    for field in PRIMES:
        path = args.output/f"v9-{field}.bin"
        shutil.copy2(args.v9_directory/f"{field}.bin", path)
        binaries[field, "v9"] = path.resolve()
        manifest["builds"][f"v9-{field}"] = sha(path)
    path = args.output/"canonical.bin"
    shutil.copy2(args.canonical, path)
    for field in PRIMES:
        binaries[field, "canonical"] = path.resolve()
    manifest["builds"]["canonical"] = sha(path)
    for name, source in (("v9", args.v9_sources), ("canonical", args.canonical_sources)):
        path = args.output/f"{name}-sources.tar.gz"
        shutil.copy2(source, path)
        manifest["builds"][f"{name}_sources"] = sha(path)
    write()
    previous = {}
    total = args.iterations + args.warmups
    for order in (0, 1):
        for field in list(PRIMES) if order == 0 else list(reversed(PRIMES)):
            paired = {}
            for mode in (("v9", "canonical") if order == 0 else ("canonical", "v9")):
                assert_idle()
                name = f"{field}-{mode}-{order}"
                if mode == "v9":
                    cmd = [str(binaries[field, mode]), "--joint-comparisons", "--iterations", str(total)]
                else:
                    cmd = [str(binaries[field, mode]), field, "brakedown", "--v9-fixture",
                           "--iterations", str(args.iterations), "--warmups", str(args.warmups)]
                if not args.toy:
                    cmd += ["--full"]
                entry = dict(name=name, argv=cmd)
                manifest["commands"].append(entry)
                write()
                log = args.output/f"{name}.log"
                with log.open("x") as stream:
                    process = subprocess.Popen(["/usr/bin/time", "-v", "-o", str(args.output/f"{name}.time"), *cmd],
                        stdout=stream, stderr=subprocess.STDOUT, env={**os.environ, "RAYON_NUM_THREADS": "16"},
                        preexec_fn=lambda: os.sched_setaffinity(0, affinity))
                    entry["pid"] = process.pid
                    write()
                    entry["returncode"] = process.wait()
                write()
                if entry["returncode"]:
                    raise RuntimeError(f"{name} failed: {entry['returncode']}")
                if mode == "v9":
                    rows = validate_run(log.read_text(), field, "joint-comparisons", total, full=not args.toy)
                    if order:
                        validate_repeated_wire(previous[field, mode], rows)
                else:
                    rows = read_records(log, field, "brakedown", not args.toy, False,
                                        args.iterations, args.warmups, v9_fixture=True)
                    if order:
                        equivalent(previous[field, mode], rows)
                previous[field, mode] = paired[mode] = rows
            matched_workload(paired["v9"], paired["canonical"])
            old = paired["v9"]["packets"][args.warmups:]
            new = paired["canonical"][args.warmups:]
            medians = dict(v9=statistics.median(r["complete_ns"]/1e9 for r in old),
                           canonical=statistics.median(r["complete_s"] for r in new))
            result = dict(field=field, order=order, complete_median_s=medians,
                          improvement=1-medians["canonical"]/medians["v9"],
                          max_byte_ratio=max(b["proof_bytes"]/a["proof_bytes"] for a, b in zip(old, new)),
                          encrypted_workload_matched=True, whole_security_matched=False, promotion_gate=False)
            manifest["summaries"].append(result)
            write()
            print(json.dumps(result), flush=True)
    manifest["engineering_gate"] = manifest["timing_eligible"] and all(
        r["improvement"] >= .1 and r["max_byte_ratio"] <= 2 for r in manifest["summaries"])
    manifest["terminal"] = True
    write()


if __name__ == "__main__":
    main()
