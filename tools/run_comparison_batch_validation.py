#!/usr/bin/env python3
"""Serial frozen-binary v9 correctness and v6/v7 wire controls, optionally native.

This creates a new artifact directory and never builds, resumes or overwrites a
run. A live process must be polled through its recorded PID/session, not restarted.
Measurements are correctness evidence, not paired timing or whole-proof security.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from validate_joint_pbs_batches import validate

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--build-directory", type=Path, required=True)
    parser.add_argument("--native", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    build = args.build_directory.resolve()
    assert not output.exists(), "use a fresh output directory"
    assert (build / "build-sources.tar.gz").is_file()
    assert all((build / (field + ".bin")).is_file() for field in ("babybear", "goldilocks"))
    output.mkdir(parents=True)
    completed = []
    results = {}
    commands = []

    def save(data):
        temporary = output / "status.tmp"
        temporary.write_text(json.dumps(dict(controller_pid=os.getpid(), **data), indent=2) + "\n")
        temporary.replace(output / "status.json")

    provenance = dict(scope="complete v9 correctness; conditional interactive accounting only; no paired timing or whole-security claim",
                      build_source_sha256=sha(build / "build-sources.tar.gz"),
                      source_archive=str(build / "build-sources.tar.gz"), driver_sha256=sha(Path(__file__)),
                      RAYON_NUM_THREADS=16, binaries={})
    for field in ("babybear", "goldilocks"):
        binary = output / (field + ".bin")
        shutil.copy2(build / (field + ".bin"), binary)
        provenance["binaries"][field] = sha(binary)
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    schedule = [(False, field, mode) for field in ("babybear", "goldilocks")
                for mode in ("joint-hadamard", "canonical-sources", "joint-comparisons")]
    if args.native:
        schedule += [(True, field, "joint-comparisons") for field in ("babybear", "goldilocks")]
    try:
        for full, field, mode in schedule:
            name = f"{'native' if full else 'toy'}-{field}-{mode}"
            command = ["/usr/bin/time", "-v", str(output / (field + ".bin")), "--validation-batches"]
            if mode != "joint-hadamard":
                command.append("--" + mode)
            if full:
                command.append("--full")
            commands.append(dict(name=name, command=command))
            (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
            with (output / (name + ".log")).open("x") as log, (output / (name + ".resources")).open("x") as resources:
                child = subprocess.Popen(command, cwd=ROOT, env=dict(os.environ, RAYON_NUM_THREADS="16"), stdout=log, stderr=resources)
                save(dict(running=name, pid=child.pid, start_ticks=Path(f"/proc/{child.pid}/stat").read_text().split()[21], completed=completed))
                code = child.wait()
            if code:
                raise RuntimeError(f"{name} exited {code}")
            log = output / (name + ".log")
            reference = ROOT / "target/performance" / ("deferred-pbs-native-fresh" if full else "deferred-pbs") / (field + ".log" if full else f"toy-{field}-fresh.log")
            result = validate(log.read_text(), field, full=full, mode=mode, reference_text=reference.read_text())
            result.update(log_sha256=sha(log), reference_sha256=sha(reference))
            if mode != "joint-comparisons":
                wire_reference = ROOT / "target/performance/shared-fold-pbs" / f"{field}-{mode}.log"
                old = [json.loads(line.split(" ", 1)[1]) for line in wire_reference.read_text().splitlines() if line.startswith("HB_FULL_BATCH_PBS ")]
                assert len(old) == len(result["packets"]) == 3
                for new, prior in zip(result["packets"], old):
                    for key in ("proof_bytes", "proof_sha256", "statements_sha256", "fhe_parameters_sha256", "native_keys_sha256"):
                        assert new[key] == prior[key], (name, key)
                result.update(all_wire_controls_exact=True, wire_reference_sha256=sha(wire_reference))
            (output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
            results[name] = dict(packets=3, members=21, validated=True)
            completed.append(name)
        save(dict(terminal=True, exit_code=0, completed=completed, results=results, scope=provenance["scope"]))
    except BaseException as error:
        save(dict(terminal=True, exit_code=1, completed=completed, results=results, error=repr(error)))
        raise


if __name__ == "__main__":
    main()
