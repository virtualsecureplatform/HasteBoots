#!/usr/bin/env python3
"""Capture workspace sources and Cargo.lock, including the ignored lockfile."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def snapshot_sources(repo, output):
    """Return the exact lock bytes embedded in a new source archive.

    Existing archives are never overwritten. Git's normal source inventory is
    augmented with Cargo.lock even when the repository ignores it.
    """
    repo,output = Path(repo).resolve(),Path(output).resolve()
    pinned=(repo/"Cargo.lock").read_bytes()
    if output.exists():
        raise FileExistsError(output)
    paths=set(subprocess.check_output(["git","ls-files","--cached","--others","--exclude-standard","-z"],cwd=repo).decode().split("\0"))
    paths.discard("")
    paths.add("Cargo.lock")
    output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(output,"w:gz") as archive:
        for relative in sorted(paths):
            path=repo/relative
            if path.resolve()==output or "__pycache__" in path.parts:
                continue
            if relative=="Cargo.lock":
                info=tarfile.TarInfo("Cargo.lock")
                info.size=len(pinned)
                info.mode=0o644
                archive.addfile(info,io.BytesIO(pinned))
            elif path.is_file() or path.is_symlink():
                archive.add(path,arcname=relative,recursive=False)
    return pinned


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output",type=Path)
    parser.add_argument("--repo",type=Path,default=ROOT)
    args=parser.parse_args()
    pinned=snapshot_sources(args.repo,args.output)
    print(json.dumps(dict(source_archive=str(args.output.resolve()),
        archive_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
        lock_sha256=hashlib.sha256(pinned).hexdigest()),indent=2))

if __name__=="__main__":
    main()
