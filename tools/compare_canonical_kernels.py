#!/usr/bin/env python3
"""Wire-exact before/after timing for the unchanged canonical Brakedown protocol."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess

from benchmark_affinity import cpu_set
from compare_canonical_polyfrim import DIGESTS, PRIMES, read_records, read_lookup_profiles
from joint_pbs_timing import assert_idle


def equivalent(before, after):
    if len(before) != len(after):
        raise ValueError("different proof schedules")
    keys = (*DIGESTS, "prime", "extension_degree", "protocol_version", "ring_dimension", "lwe_dimension",
            "output_dimension", "width", "queries", "lookup_repetitions", "ordinal", "warmup", "cold",
            "left", "right", "output", "proof_bytes", "root_slots", "group_size", "group_index")
    for a,b in zip(before,after):
        for key in keys:
            if a[key] != b[key]:
                raise ValueError(f"changed {key}: no wire-exact timing comparison")
    return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for mode in ("before","after"):
        parser.add_argument(f"--{mode}",type=Path,required=True)
        parser.add_argument(f"--{mode}-sources",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--fields",nargs="+",choices=PRIMES,default=list(PRIMES))
    parser.add_argument("--iterations",type=int,default=10)
    parser.add_argument("--warmups",type=int,default=1)
    parser.add_argument("--toy",action="store_true")
    parser.add_argument("--cold",action="store_true")
    parser.add_argument("--correctness-only",action="store_true")
    parser.add_argument("--comparison-label", default="wire-exact prover kernel comparison")
    parser.add_argument("--cpus", help="Explicit logical CPU affinity, e.g. 0-15")
    parser.add_argument("--basis-helpers", action="store_true")
    args=parser.parse_args()
    if args.iterations<1 or args.warmups<0 or len(set(args.fields))!=len(args.fields):
        parser.error("invalid schedule")
    if not args.correctness_only and (args.iterations<10 or args.warmups<1 or not args.cpus):
        parser.error("timing requires explicit affinity, one warmup and ten measured proofs")
    allowed = sorted(os.sched_getaffinity(0))
    try:
        affinity = cpu_set(args.cpus, allowed) if args.cpus else allowed
    except ValueError as error:
        parser.error(str(error))
    args.output.mkdir(parents=True,exist_ok=False)
    manifest=dict(terminal=False,threads=16,toy=args.toy,iterations=args.iterations,warmups=args.warmups,
                  cold=args.cold,correctness_only=args.correctness_only,whole_security_matched=False,
                  promotion_gate=False, comparison_label=args.comparison_label, fields=args.fields, cpu_affinity=affinity, explicit_affinity=args.cpus is not None,
                  basis_helpers=args.basis_helpers, timing_eligible=not args.correctness_only and not args.toy,
                  driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  builds={},commands=[],summaries=[])
    shutil.copy2(__file__, args.output/"executed-driver.py")
    write=lambda:(args.output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    binaries={}
    for mode in ("before","after"):
        binary=(args.output/f"{mode}.bin").resolve()
        archive=args.output/f"{mode}-sources.tar.gz"
        shutil.copy2(getattr(args,mode),binary)
        shutil.copy2(getattr(args,mode+"_sources"),archive)
        binaries[mode]=binary
        manifest["builds"][mode]=dict(executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),source_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())
    write()
    previous={}
    for order in (0,1):
        for field in args.fields if order==0 else list(reversed(args.fields)):
            paired={}
            for mode in (("before","after") if order==0 else ("after","before")):
                if not args.correctness_only: assert_idle()
                name=f"{field}-{mode}-{order}"
                cmd=[str(binaries[mode]),field,"brakedown","--iterations",str(args.iterations),"--warmups",str(args.warmups)]
                if not args.toy:cmd += ["--full"]
                if args.cold:cmd += ["--cold"]
                if args.basis_helpers: cmd += ["--basis-helpers"]
                entry=dict(name=name,argv=cmd);manifest["commands"].append(entry);write()
                with (args.output/f"{name}.log").open("x") as log:
                    process=subprocess.Popen(["/usr/bin/time","-v","-o",str(args.output/f"{name}.time"),*cmd],stdout=log,stderr=subprocess.STDOUT,env={**os.environ,"RAYON_NUM_THREADS":"16"},
                        preexec_fn=lambda: os.sched_setaffinity(0, affinity))
                    entry["pid"]=process.pid;write();entry["returncode"]=process.wait()
                write()
                if entry["returncode"]:raise RuntimeError(f"{name} failed: {entry['returncode']}")
                records=read_records(args.output/f"{name}.log",field,"brakedown",not args.toy,False,args.iterations,args.warmups,args.cold,basis_helpers=args.basis_helpers)
                if order:equivalent(previous[field,mode],records)
                previous[field,mode]=records;paired[mode]=records
            equivalent(paired["before"],paired["after"])
            measured={mode:[r for r in rows if not r['warmup']] for mode,rows in paired.items()}
            medians={mode:statistics.median(r['complete_s'] for r in rows) for mode,rows in measured.items()}
            result=dict(field=field,order=order,complete_median_s=medians,improvement=1-medians['after']/medians['before'],
                        proof_bytes=[r['proof_bytes'] for r in measured['after']],wire_exact=True,whole_security_matched=False,promotion_gate=False,
                        phase_medians_s={mode:[statistics.median(r['phase_s'][i] for r in rows) for i in range(7)] for mode,rows in measured.items()})
            profile_logs = {mode: args.output/f"{field}-{mode}-{order}.log" for mode in ("before", "after")}
            if all("HB_CANONICAL_LOOKUP_PROFILE " in path.read_text() for path in profile_logs.values()):
                phases = ("preparation_s", "commitment_s", "sumcheck_s", "zero_check_s", "terminal_evaluation_s", "openings_s")
                result["lookup_scope"] = "main-decomposition-lookups"
                result["lookup_medians_s"] = {}
                for mode, path in profile_logs.items():
                    profiles = read_lookup_profiles(path, paired[mode])
                    selected = [p for p, r in zip(profiles, paired[mode]) if not r["warmup"]]
                    result["lookup_medians_s"][mode] = {key: statistics.median(p[key] for p in selected) for key in phases}
            manifest['summaries'].append(result);write();print(json.dumps(result),flush=True)
    manifest['engineering_latency_gate'] = manifest['timing_eligible'] and all(r['improvement'] >= .10 for r in manifest['summaries'])
    manifest['terminal']=True;write()

if __name__=='__main__':main()
