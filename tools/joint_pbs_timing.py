#!/usr/bin/env python3
"""Two-order serial complete single-PBS timing with digest-linked phase checks.

Conditional interactive profiles only; no whole-security or promotion claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
from batch_phase_statistics import validate as validate_phases
from validate_joint_pbs_batches import validate as validate_batches

ROOT = Path(__file__).resolve().parents[1]


def records(text, prefix):
    return [json.loads(line.split(" ", 1)[1]) for line in text.splitlines() if line.startswith(prefix + " ")]


def validate_run(text, field, mode, iterations=2, reference=None, full=True):
    if type(iterations) is not int or iterations < 1 or mode not in ("separate-v5", "joint-comparisons"):
        raise ValueError("explicit complete single-PBS timing mode/count required")
    result = validate_batches(text, field, full=full, mode=mode, schedule=(1,) * iterations)
    if [r.get("timing_iteration") for r in result["packets"]] != list(range(iterations)) or any(type(r.get("timing_iteration")) is not int for r in result["packets"]):
        raise ValueError("timing iteration schedule mismatch")
    phases = records(text, "HB_BATCH_PHASES")
    if len(phases) != iterations or len({r.get("proof_sha256") for r in phases}) != iterations:
        raise ValueError("exactly one measured phase record per proof required")
    by_digest = {r["proof_sha256"]: r for r in phases}
    checks = []
    for packet in result["packets"]:
        if packet["proof_sha256"] not in by_digest:
            raise ValueError("missing linked proof phases")
        checks.append(validate_phases(packet, by_digest[packet["proof_sha256"]]))
    if reference is not None:
        if result["layouts"] != reference["layouts"] or len(reference["members"]) < iterations:
            raise ValueError("timing layout/reference schedule mismatch")
        for packet in result["packets"]:
            for key in ("native_keys_sha256", "fhe_parameters_sha256", "prime", "width", "lookup_field_degree", "polynomial_size", "input_dimension", "output_dimension"):
                if packet[key] != reference["packets"][0][key]:
                    raise ValueError("timing native key/parameter fixture mismatch")
        for current, prior in zip(result["members"], reference["members"]):
            for key in ("statement_sha256", "left_plaintext", "right_plaintext", "decrypted_plaintext"):
                if current[key] != prior[key]:
                    raise ValueError("timing statement fixture mismatch")
    result.update(phases=phases, phase_checks=checks,
                  measurement_scope="complete single-PBS trace/prove/serialization with reused setup; conditional interactive profiles only")
    return result


def validate_repeated_wire(first, second):
    """Require the same seeded workload and certificate in reversed orders.

    Call after validate_run on each raw log. Timing and phase durations may vary;
    the complete proof, ordered statements and trusted configuration may not.
    """
    for key in ("field", "mode", "full_parameters", "batch_sizes", "layouts"):
        if first[key] != second[key]:
            raise ValueError(f"repeated timing configuration mismatch: {key}")
    if first["members"] != second["members"]:
        raise ValueError("repeated timing ordered member/proof mismatch")
    keys = ("proof_sha256", "proof_bytes", "statements_sha256",
            "native_keys_sha256", "fhe_parameters_sha256", "seed",
            "protocol_version", "transcript", "timing_iteration")
    if len(first["packets"]) != len(second["packets"]):
        raise ValueError("repeated timing packet count mismatch")
    for old, new in zip(first["packets"], second["packets"]):
        for key in keys:
            if old[key] != new[key]:
                raise ValueError(f"repeated timing certificate mismatch: {key}")
    return dict(proofs=len(first["packets"]), exact_wire=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_idle():
    """Guard against our own overlapping builds/tests/native benchmarks."""
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            if proc.stat().st_uid != os.getuid():
                continue
            argv = (proc / "cmdline").read_bytes().split(b"\0")
            executable = argv[0].decode()
            name = Path(executable).name
            if name in ("cargo", "rustc") or (executable.startswith(str(ROOT / "target")) and (executable.endswith(".bin") or "/deps/" in executable or "/examples/" in executable)):
                raise RuntimeError(f"timing must wait for active process {proc.name}: {name}")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--build-directory", type=Path, required=True)
    parser.add_argument("--native-reference-directory", type=Path, required=True)
    args = parser.parse_args()
    output, build, native = args.output.resolve(), args.build_directory.resolve(), args.native_reference_directory.resolve()
    assert not output.exists()
    assert json.loads((build / "build-status.json").read_text())["exit_code"] == 0
    assert json.loads((build / "toy-status.json").read_text())["exit_code"] == 0
    status = json.loads((native / "status.json").read_text())
    assert status["terminal"] and status["exit_code"] == 0
    assert_idle()
    references = {}
    for field in ("babybear", "goldilocks"):
        path = native / f"native-{field}-joint-comparisons.json"
        reference = json.loads(path.read_text())
        assert sha(native / f"native-{field}-joint-comparisons.log") == reference["log_sha256"]
        references[field] = reference
    output.mkdir(parents=True)
    provenance = dict(scope=__doc__, source_archive=str(build / "build-sources.tar.gz"),
                      source_archive_sha256=sha(build / "build-sources.tar.gz"),
                      driver_sha256=sha(Path(__file__)), RAYON_NUM_THREADS=16, iterations=2,
                      native_reference=str(native), binaries={})
    for field in references:
        shutil.copy2(build / (field + ".bin"), output / (field + ".bin"))
        provenance["binaries"][field] = sha(output / (field + ".bin"))
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    completed, commands, results = [], [], {}

    def save(data):
        temporary = output / "status.tmp"
        temporary.write_text(json.dumps(dict(controller_pid=os.getpid(), **data), indent=2) + "\n")
        temporary.replace(output / "status.json")

    try:
        for order, fields, modes in ((0, ("babybear", "goldilocks"), ("separate-v5", "joint-comparisons")),
                                     (1, ("goldilocks", "babybear"), ("joint-comparisons", "separate-v5"))):
            for field in fields:
                for mode in modes:
                    assert_idle()
                    name = f"native-{order}-{field}-{mode}"
                    command = ["/usr/bin/time", "-v", str(output / (field + ".bin")), "--full", "--iterations", "2",
                               "--separate" if mode == "separate-v5" else "--joint-comparisons"]
                    commands.append(dict(name=name, command=command))
                    (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
                    with (output / (name + ".log")).open("x") as log, (output / (name + ".resources")).open("x") as resources:
                        child = subprocess.Popen(command, cwd=ROOT, env=dict(os.environ, RAYON_NUM_THREADS="16"), stdout=log, stderr=resources)
                        save(dict(running=name, pid=child.pid, start_ticks=Path(f"/proc/{child.pid}/stat").read_text().split()[21],
                                  completed=completed, phase="timing-running", do_not_compile_or_test=True))
                        code = child.wait()
                    if code:
                        raise RuntimeError(f"{name} exited {code}")
                    result = validate_run((output / (name + ".log")).read_text(), field, mode, reference=references[field])
                    result["log_sha256"] = sha(output / (name + ".log"))
                    (output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
                    results[name] = result
                    completed.append(name)
        repeated_wire = {}
        for field in references:
            for mode in ("separate-v5", "joint-comparisons"):
                repeated_wire[f"{field}-{mode}"] = validate_repeated_wire(
                    results[f"native-0-{field}-{mode}"], results[f"native-1-{field}-{mode}"])
        comparisons = []
        for field in references:
            for order in range(2):
                old = results[f"native-{order}-{field}-separate-v5"]
                new = results[f"native-{order}-{field}-joint-comparisons"]
                a, b = (statistics.median(p["complete_ns"] for p in r["packets"]) for r in (old, new))
                comparisons.append(dict(field=field, order=order, baseline_complete_ns=a, candidate_complete_ns=b,
                                        improvement_percent=100 * (1 - b / a)))
        (output / "summary.json").write_text(json.dumps(dict(comparisons=comparisons, proofs=16, repeated_wire=repeated_wire,
            ten_percent_in_both_orders=all(c["improvement_percent"] >= 10 for c in comparisons),
            whole_security_matched=False), indent=2) + "\n")
        save(dict(terminal=True, exit_code=0, completed=completed, proofs=16, do_not_compile_or_test=False))
    except BaseException as error:
        save(dict(terminal=True, exit_code=1, completed=completed, error=repr(error), do_not_compile_or_test=False))
        raise


if __name__ == "__main__":
    main()
