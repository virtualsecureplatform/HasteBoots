#!/usr/bin/env python3
"""Compare complete v11 PolyFRIM and Brakedown controls; never certify security."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess

from joint_pbs_timing import assert_idle

PRIMES = {"babybear": 2013265921, "goldilocks": 18446744069414584321}
DIGESTS = ("fhe_parameters_sha256", "native_keys_sha256", "parameters_sha256", "statement_sha256", "trusted_setup_sha256", "proof_sha256")
DURATIONS = ("setup_s", "trace_s", "prove_s", "serialization_s", "complete_s", "decode_s", "verify_s")


def read_records(path, field, backend, full, validation, count, warmups, cold=False, parallel_oracles=False, basis_helpers=False, v9_fixture=False, opening_inventory=False):
    if v9_fixture and validation:
        raise ValueError("v9 fixture is single-proof timing only")
    if backend not in ("brakedown", "polyfrim", "polyfrim-compact"):
        raise ValueError("unsupported backend")
    records = [json.loads(line.split("HB_CANONICAL_PBS ", 1)[1]) for line in Path(path).read_text().splitlines() if line.startswith("HB_CANONICAL_PBS ")]
    schedule = [(n, i) for n in (1, 4, 16) for i in range(n)] if validation else [(1, i) for i in range(warmups + count)]
    if len(records) != len(schedule):
        raise ValueError("missing or extra complete proof records")
    for ordinal, (r, (group, index)) in enumerate(zip(records, schedule)):
        expected = dict(backend=backend, prime=PRIMES[field], extension_degree=6 if field == "babybear" else 3,
                        protocol_version=11, ring_dimension=1024 if full else 32, lwe_dimension=728 if full else 32 if v9_fixture else 21,
                        output_dimension=728 if full else 32 if v9_fixture else 21, width=8 if field == "babybear" else 4,
                        group_size=group, group_index=index, ordinal=ordinal, warmup=not validation and ordinal < warmups,
                        queries=544 if backend == "brakedown" else 128, cold=cold, left=0 if v9_fixture else ordinal // 2 % 2, right=0 if v9_fixture else ordinal % 2,
                        verified=True, altered_output_rejected=True, complete_pbs=True, original_size=full,
                        whole_security_matched=False, hiding_certified=False, performance_gate=False, lookup_repetitions=1)
        if opening_inventory or "opening_inventory" in r:
            if type(r.get("opening_inventory")) is not bool or r["opening_inventory"] != opening_inventory:
                raise ValueError("unexpected opening inventory policy")
        if v9_fixture or "v9_fixture" in r:
            if type(r.get("v9_fixture")) is not bool or r["v9_fixture"] != v9_fixture:
                raise ValueError("unexpected v9 input fixture policy")
        if "parallel_oracles" in r and (type(r["parallel_oracles"]) is not bool or r["parallel_oracles"] != parallel_oracles):
            raise ValueError("unexpected parallel oracle policy")
        if parallel_oracles and "parallel_oracles" not in r:
            raise ValueError("parallel oracle metadata missing")
        if basis_helpers or "basis_helpers" in r:
            helper_width = expected["extension_degree"] if basis_helpers else expected["width"]
            if type(r.get("basis_helpers")) is not bool or r["basis_helpers"] != basis_helpers:
                raise ValueError("unexpected helper packing policy")
            for key in ("helper_width", "final_helper_width"):
                if type(r.get(key)) is not int or r[key] != helper_width:
                    raise ValueError("unexpected helper width")
            if basis_helpers and backend != "brakedown":
                raise ValueError("basis helper profile is Brakedown-only")
            contexts = r.get("contexts_sha256")
            encoders = r.get("rs_encoders_sha256")
            def digests(values, count):
                return isinstance(values, list) and len(values) == count and all(isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v) for v in values)
            if not digests(contexts, 4) or not digests(encoders, 4 if backend == "brakedown" else 0):
                raise ValueError("missing trusted layout digests")
            layouts = r.get("rs_layouts")
            if backend == "brakedown":
                source_vars = (2 * expected["ring_dimension"] // expected["width"]).bit_length() - 1
                lane_vars = expected["width"].bit_length() - 1
                final_vars = source_vars
                source_vars += (expected["lwe_dimension"] - 1).bit_length()
                dimensions = (source_vars, source_vars + lane_vars, final_vars, final_vars + lane_vars)
                if not isinstance(layouts, list) or len(layouts) != 4:
                    raise ValueError("missing RS layouts")
                for role, layout in enumerate(layouts):
                    if not isinstance(layout, list) or len(layout) != 6 or any(type(v) is not int for v in layout):
                        raise ValueError("invalid RS layout")
                    n, width, left, symbol, message, blocks = layout
                    if n != dimensions[role] or width != (helper_width if role % 2 else expected["width"]) or not 0 <= left <= n or symbol != expected["width"]:
                        raise ValueError("changed source/helper/RS symbol geometry")
                    need = ((1 << (n - left)) + symbol - 1) // symbol
                    if message != 1 << (need - 1).bit_length() or blocks != max(32, 2 * message):
                        raise ValueError("changed RS domain or rate")
            elif layouts != []:
                raise ValueError("unexpected RS layout")
        for key, value in expected.items():
            if type(r.get(key)) is not type(value) or r[key] != value:
                raise ValueError(f"{key}: {r.get(key)!r} != {value!r}")
        if type(r.get("output")) is not int or r["output"] != 1-r["left"]*r["right"]:
            raise ValueError("incorrect decrypted NAND output")
        for key in DIGESTS:
            value = r.get(key)
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError(f"invalid {key}")
        for key in DURATIONS:
            if type(r.get(key)) not in (int, float) or not math.isfinite(r[key]) or r[key] < 0:
                raise ValueError(f"invalid {key}")
        for key in ("proof_bytes", "queries", "root_slots"):
            if type(r.get(key)) is not int or r[key] <= 0:
                raise ValueError(f"invalid {key}")
        phases = r.get("phase_s")
        if not isinstance(phases, list) or len(phases) != 7 or any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in phases):
            raise ValueError("invalid phase durations")
        if sum(phases) > r["prove_s"] * 1.01 + .001:
            raise ValueError("phases exceed proving duration")
        if r["trace_s"] + r["prove_s"] + r["serialization_s"] > r["complete_s"] * 1.001 + .001:
            raise ValueError("complete duration omits required stages")
        if cold and r["setup_s"] > r["complete_s"]:
            raise ValueError("cold duration omits preprocessing")
    for key in ("fhe_parameters_sha256", "native_keys_sha256", "parameters_sha256", "trusted_setup_sha256", "queries", "root_slots"):
        if len({r[key] for r in records}) != 1:
            raise ValueError(f"changing reused setup/profile: {key}")
    if any("basis_helpers" in r for r in records):
        for key in ("basis_helpers", "helper_width", "final_helper_width", "rs_layouts", "rs_encoders_sha256", "contexts_sha256"):
            if any(r.get(key) != records[0].get(key) for r in records):
                raise ValueError(f"changing trusted layout metadata: {key}")
    if len({r["statement_sha256"] for r in records}) != len(records):
        raise ValueError("expected fresh encrypted statements")
    return records



def read_opening_inventory(path, records):
    """Validate optional public-verifier observations, not a security budget."""
    prefix = "HB_CANONICAL_OPENING_INVENTORY "
    profiles = [json.loads(line[len(prefix):]) for line in Path(path).read_text().splitlines() if line.startswith(prefix)]
    if len(profiles) != len(records):
        raise ValueError("missing or extra opening inventories")
    def digest(value):
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    for profile, record in zip(profiles, records):
        if record.get("opening_inventory") is not True:
            raise ValueError("opening inventory policy not selected")
        if profile.get("backend") != record["backend"] or type(profile.get("ordinal")) is not int or profile["ordinal"] != record["ordinal"]:
            raise ValueError("opening inventory schedule mismatch")
        if profile.get("scope") != "successful-complete-verification" or profile.get("includes_altered_output_replay") is not False:
            raise ValueError("opening inventory scope mismatch")
        contexts = record.get("contexts_sha256")
        if not isinstance(contexts, list) or len(contexts) != 4 or not all(digest(x) for x in contexts):
            raise ValueError("missing expected opening contexts")
        short = (2*record["ring_dimension"]//record["width"]).bit_length()-1
        source = short + (record["lwe_dimension"]-1).bit_length()
        lanes = record["width"].bit_length()-1
        dimensions = (source, source+lanes, short, short+lanes)
        widths = (record["width"], record.get("helper_width", record["width"]),
                  record["width"], record.get("final_helper_width", record["width"]))
        events = profile.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("empty opening inventory")
        roles = set()
        for event in events:
            if not isinstance(event, dict): raise ValueError("invalid opening event")
            role = event.get("role")
            if type(role) is not int or not 0 <= role < 4: raise ValueError("invalid opening role")
            roles.add(role)
            if any(type(event.get(k)) is not int for k in ("num_vars", "width", "queries")):
                raise ValueError("invalid opening dimensions/count")
            if event["num_vars"] != dimensions[role] or event["width"] != widths[role] or event["queries"] < 1:
                raise ValueError("changed opening geometry/count")
            if event.get("kind") not in ("single", "batch") or (event["kind"] == "single" and event["queries"] != 1):
                raise ValueError("invalid opening kind/count")
            if event.get("context_sha256") != contexts[role] or not digest(event.get("root_hex")):
                raise ValueError("invalid opening context/root")
        if roles != set(range(4)): raise ValueError("missing complete-proof opening role")
    return profiles


def read_lookup_profiles(path, records):
    """Check optional main-decomposition diagnostics against complete records."""
    prefix = "HB_CANONICAL_LOOKUP_PROFILE "
    profiles = [json.loads(line[len(prefix):]) for line in Path(path).read_text().splitlines() if line.startswith(prefix)]
    if len(profiles) != len(records):
        raise ValueError("missing or extra lookup profiles")
    keys = ("preparation_s", "commitment_s", "sumcheck_s", "zero_check_s", "terminal_evaluation_s", "openings_s")
    for profile, record in zip(profiles, records):
        if profile.get("backend") != record["backend"] or type(profile.get("ordinal")) is not int or profile["ordinal"] != record["ordinal"]:
            raise ValueError("lookup profile schedule mismatch")
        if profile.get("scope") != "main-decomposition-lookups" or profile.get("includes_final_key_switch") is not False:
            raise ValueError("lookup profile scope mismatch")
        if any(type(profile.get(key)) not in (int, float) or not math.isfinite(profile[key]) or profile[key] < 0 for key in keys):
            raise ValueError("invalid lookup phase duration")
        if sum(profile[key] for key in keys) > record["phase_s"][3] + 1e-8:
            raise ValueError("lookup phases exceed decomposition")
    return profiles


def compare(a, b):
    if len(a) != len(b):
        raise ValueError("different schedules")
    for x, y in zip(a, b):
        for key in ("prime", "extension_degree", "width", "ring_dimension", "lwe_dimension", "output_dimension", "fhe_parameters_sha256", "native_keys_sha256", "statement_sha256", "ordinal", "group_size", "group_index", "warmup", "cold", "left", "right", "output", "root_slots"):
            if x[key] != y[key]:
                raise ValueError(f"different workload: {key}")
    measured_a, measured_b = ([r for r in records if not r["warmup"]] for records in (a, b))
    before, after = (statistics.median(r["complete_s"] for r in records) for records in (measured_a, measured_b))
    return {"brakedown_median_s": before, "polyfrim_median_s": after,
            "latency_reduction": 1-after/before if before else None,
            "maximum_byte_ratio": max(y["proof_bytes"]/x["proof_bytes"] for x, y in zip(a, b)),
            "whole_security_matched": False, "performance_gate": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fields", nargs="+", choices=PRIMES, default=list(PRIMES))
    parser.add_argument("--candidate", choices=("polyfrim", "polyfrim-compact"), default="polyfrim")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--validation", action="store_true")
    parser.add_argument("--correctness-only", action="store_true")
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--cold", action="store_true")
    parser.add_argument("--parallel-oracles", action="store_true")
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0 or len(set(args.fields)) != len(args.fields):
        parser.error("invalid iteration count, warmups or duplicate fields")
    if args.validation and not args.correctness_only:
        parser.error("validation is correctness-only")
    if not args.correctness_only and (args.iterations < 10 or args.warmups < 1):
        parser.error("timing requires at least one warmup and ten measured proofs")
    args.output.mkdir(parents=True, exist_ok=False)
    executable = (args.output / "canonical-pbs.bin").resolve()
    archive = args.output / "executed-sources.tar.gz"
    shutil.copy2(args.executable, executable)
    shutil.copy2(args.source_archive, archive)
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = dict(executable_sha256=sha(executable), source_archive_sha256=sha(archive),
                    threads=16, candidate=args.candidate, full=args.full, validation=args.validation, correctness_only=args.correctness_only,
                    iterations=args.iterations, warmups=args.warmups, cold=args.cold, parallel_oracles=args.parallel_oracles, whole_security_matched=False,
                    commands=[], terminal=False)
    write = lambda: (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    write()
    previous = {}
    summaries = []
    for order in (0, 1):
        for field in args.fields if order == 0 else list(reversed(args.fields)):
            result = {}
            for backend in (("brakedown", args.candidate) if order == 0 else (args.candidate, "brakedown")):
                if not args.correctness_only:
                    assert_idle()
                name = f"{field}-{backend}-{order}"
                cmd = [str(executable), field, backend]
                if args.full: cmd += ["--full"]
                if args.cold: cmd += ["--cold"]
                if args.parallel_oracles and backend != "brakedown": cmd += ["--parallel-oracles"]
                cmd += ["--validation-batches"] if args.validation else ["--iterations", str(args.iterations), "--warmups", str(args.warmups)]
                entry = dict(name=name, argv=cmd)
                manifest["commands"].append(entry)
                write()
                with (args.output / f"{name}.log").open("x") as log:
                    process = subprocess.Popen(["/usr/bin/time", "-v", "-o", str(args.output / f"{name}.time"), *cmd],
                                               stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "RAYON_NUM_THREADS": "16"})
                    entry["pid"] = process.pid
                    write()
                    entry["returncode"] = process.wait()
                write()
                if entry["returncode"]:
                    raise RuntimeError(f"{name} exited {entry['returncode']}")
                records = read_records(args.output / f"{name}.log", field, backend, args.full, args.validation, args.iterations, args.warmups, args.cold, args.parallel_oracles and backend != "brakedown")
                if order:
                    for x,y in zip(previous[field,backend], records):
                        for key in (*DIGESTS,"proof_bytes","queries","root_slots"):
                            if x[key] != y[key]: raise ValueError(f"changed {key} across reversed orders")
                previous[field,backend] = records
                result[backend] = records
            summary = compare(result["brakedown"], result[args.candidate])
            summary.update(field=field, order=order, candidate=args.candidate)
            summaries.append(summary)
            print(json.dumps(summary), flush=True)
    manifest.update(terminal=True, comparisons=summaries, performance_gate=False)
    write()

if __name__ == "__main__":
    main()
