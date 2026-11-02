"""Record/verify a repository review checkpoint; never certify security.

Inventory tracked and nonignored candidate files, excluding the manifest itself.
Ignored traces/build products are not a part of this source checkpoint.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess

from audit_artifacts import write_json_new

SCHEMA = 'HasteBoots/security-proof-baseline/v1'


def inventory(root, manifest):
    root, manifest = Path(root).resolve(), Path(manifest).resolve()
    excluded = manifest.relative_to(root).as_posix()
    raw = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root)
    paths = sorted(set(os.fsdecode(p) for p in raw.split(b'\0') if p))
    records = []
    for name in paths:
        if name == excluded:
            continue
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('repository-relative paths required')
        path = root/name
        if path.is_symlink():
            data = os.fsencode(os.readlink(path))
            record = dict(path=name, kind='symlink', sha256=hashlib.sha256(data).hexdigest())
        elif path.is_file():
            with path.open('rb') as source:
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
            record = dict(path=name, kind='file', sha256=digest,
                          executable=bool(path.stat().st_mode & 0o100))
        elif not path.exists():
            continue  # A pending Git deletion is absent from the new checkpoint.
        else:
            raise ValueError('regular files and symlinks required: '+name)
        records.append(record)
    return records


def create(root, manifest):
    parent = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    value = dict(schema=SCHEMA, parent_commit=parent,
        scope='Source review checkpoint; includes tracked and nonignored candidate files',
        files=inventory(root, manifest), security_qualified=False, performance_qualified=False)
    write_json_new(manifest, value)
    return value


def verify(root, manifest):
    value = json.loads(Path(manifest).read_text())
    if (value.get('schema') != SCHEMA or value.get('security_qualified') is not False
            or value.get('performance_qualified') is not False or not isinstance(value.get('files'), list)):
        raise ValueError('review-checkpoint schema with no certification required')
    expected = {}
    for row in value['files']:
        if not isinstance(row, dict) or not isinstance(row.get('path'), str) or row['path'] in expected:
            raise ValueError('unique file records required')
        expected[row['path']] = row
    actual = {row['path']: row for row in inventory(root, manifest)}
    return dict(files=len(expected), added=sorted(actual.keys()-expected.keys()),
        removed=sorted(expected.keys()-actual.keys()),
        changed=sorted(name for name in actual.keys() & expected.keys() if actual[name] != expected[name]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', type=Path)
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    path = args.write or args.verify
    path = (root/path).resolve()
    path.relative_to(root)  # Keep the manifest inside this repository.
    if args.write:
        value = create(root, path)
        print('Recorded '+str(len(value['files']))+' files; no security certification.')
    else:
        result = verify(root, path)
        if any(result[key] for key in ('added', 'removed', 'changed')):
            print(json.dumps(result, indent=2))
            raise SystemExit(1)
        print('Verified '+str(result['files'])+' files; no security certification.')


if __name__ == '__main__':
    main()
