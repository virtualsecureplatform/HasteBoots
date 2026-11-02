#!/usr/bin/env python3
"""Check native correctness records and exact frozen-build compatibility.

This checks correctness evidence only, never security or performance eligibility.
"""

import argparse
import hashlib
import json
from pathlib import Path
from classical_profile_descriptor import FIELD_NONRESIDUES, decode_descriptor


PREFIX = "HB_CLASSICAL_VALIDATION "
PROFILE_PREFIX = "HB_CLASSICAL_PROFILE "


def effective_queries(row):
    if 'queries' not in row:
        raise ValueError('missing query-count field')
    count = row.get('queries')
    if type(count) is int and 0 < count < 2**64:
        result = (count,)*4
        if 'role_queries' in row:
            counts = row['role_queries']
            if (not isinstance(counts, list) or len(counts) != 4
                    or any(type(q) is not int for q in counts) or counts != list(result)):
                raise ValueError('uniform query count disagrees with role counts')
        return result
    if count is None:
        counts = row.get('role_queries')
        if (isinstance(counts, list) and len(counts) == 4
                and all(type(q) is int and 0 < q < 2**64 for q in counts)
                and len(set(counts)) > 1):
            return tuple(counts)
    raise ValueError('invalid uniform or four-role query count')


def profile_header(path):
    headers = [json.loads(line[len(PROFILE_PREFIX):]) for line in Path(path).read_text().splitlines()
               if line.startswith(PROFILE_PREFIX)]
    if not headers:
        return None  # Older frozen harnesses did not emit this diagnostic.
    if len(headers) != 1:
        raise ValueError(f'{path}: expected one trusted profile header')
    header = headers[0]
    data = bytes.fromhex(header['descriptor_bincode_hex'])
    if data.hex() != header['descriptor_bincode_hex']:
        raise ValueError(f'{path}: noncanonical descriptor hex')
    if (hashlib.sha512(data).hexdigest() != header['profile_descriptor_sha512']
            or hashlib.sha512(b'HasteBoots classical profile v1'+data).hexdigest()
            != header['profile_id_sha512']):
        raise ValueError(f'{path}: profile descriptor fingerprint mismatch')
    decoded = decode_descriptor(data)
    for key, value in decoded.items():
        if (key not in ('role_left_vars', 'role_block_widths')
                and json.dumps(header.get(key)) != json.dumps(value)):
            raise ValueError(f'{path}: descriptor disagrees with profile header {key}')
    return dict(header, **decoded)


def records(path, *, toy=False):
    header = profile_header(path)
    rows = [json.loads(line[len(PREFIX):]) for line in Path(path).read_text().splitlines()
            if line.startswith(PREFIX)]
    if len(rows) not in (4, 21):
        raise ValueError(f"{path}: expected 4 or 21 completed proofs, got {len(rows)}")
    groups = (4,) if len(rows) == 4 else (1, 4, 16)
    schedule = [(group, index) for group in groups for index in range(group)]
    identity = None
    for ordinal, (row, (group, index)) in enumerate(zip(rows, schedule)):
        ring, lwe = (32, 21) if toy else (1024, 728)
        expected = dict(original_size=not toy, ring_dimension=ring, lwe_dimension=lwe,
                        output_dimension=lwe, protocol_version=12, ordinal=ordinal,
                        group_size=group, group_index=index, left=ordinal // 2 % 2,
                        right=ordinal % 2, decoded_verified=True,
                        altered_output_rejected=True, reused_public_key_setup=True,
                        separate_single_proofs=True, correctness_only=True,
                        security_qualified=False, performance_gate=False)
        for key, value in expected.items():
            if type(row.get(key)) is not type(value) or row[key] != value:
                raise ValueError(f"{path}: ordinal {ordinal}: invalid {key}")
        if (type(row.get('extension_degree')) is not int
                or (row.get('prime'), row.get('extension_degree')) not in FIELD_NONRESIDUES):
            raise ValueError(f"{path}: ordinal {ordinal}: unsupported field")
        role_queries = effective_queries(row)
        for key in ('fhe_parameters_sha256', 'native_keys_sha256',
                    'trusted_setup_sha256', 'statement_sha256', 'proof_sha256',
                    'profile_descriptor_sha512', 'profile_id_sha512'):
            digest = row.get(key)
            size = 128 if key.endswith('sha512') else 64
            if (not isinstance(digest, str) or len(digest) != size
                    or any(c not in '0123456789abcdef' for c in digest)):
                raise ValueError(f"{path}: ordinal {ordinal}: invalid {key}")
        if row['output'] != 1 - row['left'] * row['right']:
            raise ValueError(f"{path}: ordinal {ordinal}: incorrect NAND output")
        current = tuple(row[k] for k in ('prime', 'extension_degree', 'backend',
                        'fragment_vars', 'fhe_parameters_sha256',
                        'native_keys_sha256', 'profile_id_sha512', 'trusted_setup_sha256')) + (role_queries,)
        if identity is not None and current != identity:
            raise ValueError(f"{path}: setup changed within reused-key schedule")
        identity = current
        if header is not None:
            for key in ('profile_id_sha512', 'profile_descriptor_sha512', 'prime',
                        'extension_degree', 'backend', 'fragment_vars'):
                if row.get(key) != header[key]:
                    raise ValueError(f'{path}: proof record disagrees with profile header {key}')
            if header['role_queries'] != list(role_queries):
                raise ValueError(f'{path}: proof record query count disagrees with descriptor')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference')
    parser.add_argument('candidate')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    reference, candidate = records(args.reference), records(args.candidate)
    if reference != candidate:
        raise ValueError('native records differ (including proof bytes/hash or statement/setup)')
    result = dict(reference=args.reference, candidate=args.candidate,
                  completed_proofs=len(candidate), exact_records_equal=True,
                  correctness_only=True, security_qualified=False, performance_gate=False)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
