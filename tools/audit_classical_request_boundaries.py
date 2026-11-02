"""Audit saved query framing; byte inventory assumes completed trusted API calls.

This verifies SHA512 preimages and file identity, but does not replay SHAKE or
authenticate source words. Receipt/stream consistency is a separate premise.
"""
import argparse
import struct

from audit_artifacts import write_json_new
from audit_classical_oracle_event_stream import audit, PHASES

PROTOCOL = b'HasteBoots framed SHAKE256 v1'
PREFIX = b'\0' + (8).to_bytes(8, 'little') + b'protocol' + len(PROTOCOL).to_bytes(8, 'little') + PROTOCOL
RECEIPT = b'HasteBoots consumed field bytes v1'
APPLICATIONS = (b'HasteBoots typed classical prime v1',
                b'HasteBoots typed classical extension v1',
                b'HasteBoots framed SHAKE256 child v1')


def frame(data, pos):
    if pos >= len(data):
        raise ValueError('missing framed query field')
    kind = data[pos]; pos += 1
    parts = []
    for _ in range(2):
        if len(data) - pos < 8:
            raise ValueError('truncated frame length')
        length = struct.unpack_from('<Q', data, pos)[0]; pos += 8
        if length > len(data) - pos:
            raise ValueError('truncated frame body')
        parts.append(data[pos:pos+length]); pos += length
    return kind, parts[0], parts[1], pos


def inspect_input(data, prime):
    """Return family, endpoint, count, profile; None denotes an unframed input."""
    if data[:len(PREFIX)] != PREFIX:
        return None
    kind, label, body, pos = frame(data, len(PREFIX))
    if kind != 0 or label != b'application' or body not in APPLICATIONS:
        raise ValueError('unsupported framed application')
    family = APPLICATIONS.index(body)
    kind, label, profile, pos = frame(data, pos)
    if kind != 0 or label != b'trusted profile' or len(profile) != 64:
        raise ValueError('invalid framed profile')
    profile = profile.hex()
    endpoint, count = None, 0
    while pos < len(data):
        kind, label, body, pos = frame(data, pos)
        if kind not in range(1, 9):
            raise ValueError('unsupported or repeated domain frame kind')
        if kind == 2:
            if len(body) != 8:
                raise ValueError('invalid byte request descriptor')
            count = int.from_bytes(body, 'little')
        elif kind == 4:
            if len(body) != 24 or int.from_bytes(body[:16], 'little') != prime:
                raise ValueError('invalid field request descriptor')
            count = int.from_bytes(body[16:], 'little')
        elif kind == 8:
            if label != b'parent checkpoint' or body or pos != len(data):
                raise ValueError('invalid checkpoint endpoint')
            count = 64
        endpoint = kind
    if endpoint not in (2, 4, 8):
        raise ValueError('framed query must end at request/checkpoint')
    return family, endpoint, count, profile


def audit_boundaries(path, expected_sha512, prime):
    if prime not in (2013265921, 18446744069414584321):
        raise ValueError('unsupported trusted prime')
    if (type(expected_sha512) is not str or len(expected_sha512) != 128
            or any(c not in '0123456789abcdefABCDEF' for c in expected_sha512)):
        raise ValueError('expected SHA512 is mandatory')
    width = ((prime - 1).bit_length() + 7) // 8
    mask = (1 << (prime - 1).bit_length()) - 1
    rows = [dict(namespace_queries=[0, 0, 0], request_kinds=[0, 0, 0, 0],
                 byte_request_bytes=0, field_coefficients=0, field_consumed_bytes=0,
                 field_receipt_queries=0, field_values=0, field_candidates=0,
                 max_candidates_per_value=0, other_unframed_queries=0) for _ in PHASES]
    profiles = set()
    def observe(phase, data):
        row = rows[phase]
        parsed = inspect_input(data, prime)
        if parsed is None:
            if data[:len(RECEIPT)] == RECEIPT:
                raw = data[len(RECEIPT):]
                values = attempts = maximum = 0
                if len(raw) % width:
                    row['other_unframed_queries'] += 1
                    return
                for pos in range(0, len(raw), width):
                    attempts += 1
                    if (int.from_bytes(raw[pos:pos+width], 'little') & mask) < prime:
                        values += 1; maximum = max(maximum, attempts); attempts = 0
                if attempts:
                    row['other_unframed_queries'] += 1
                    return
                row['field_receipt_queries'] += 1
                row['field_consumed_bytes'] += len(data) - len(RECEIPT)
                row['field_values'] += values
                row['field_candidates'] += len(raw) // width
                row['max_candidates_per_value'] = max(row['max_candidates_per_value'], maximum)
            else:
                row['other_unframed_queries'] += 1
            return
        family, kind, count, profile = parsed
        profiles.add(profile); row['namespace_queries'][family] += 1
        index = 0 if kind == 2 else 3 if kind == 8 else 1 if family == 0 else 2
        row['request_kinds'][index] += 1
        if kind == 2:
            row['byte_request_bytes'] += count
        elif kind == 4:
            row['field_coefficients'] += count
    result = audit(path, expected_sha512, on_xof_input=observe)
    for phase, row in zip(PHASES, rows):
        fields = sum(row['request_kinds'][1:3])
        closed = fields == row['field_receipt_queries'] and row['other_unframed_queries'] == 0
        if closed and row['field_values'] != row['field_coefficients']:
            raise ValueError('field receipt acceptance inventory mismatch')
        row['closed_field_receipt_counts'] = closed
        row['consumed_xof_bytes_if_completed_api_calls'] = (
            row['byte_request_bytes'] + row['field_consumed_bytes']
            + 64 * (row['request_kinds'][3] + row['field_receipt_queries'])) if closed else None
        expected_queries = sum(row['namespace_queries']) + row['field_receipt_queries'] + row['other_unframed_queries']
        if expected_queries != result['phases'][phase]['xof_queries']:
            raise ValueError('request classification count mismatch')
    result.update(request_boundary_records_verified=True, prime=str(prime),
                  profile_ids=sorted(profiles), request_inventory=dict(zip(PHASES, rows)),
                  request_kind_order=['bytes', 'prime', 'extension', 'checkpoint'],
                  output_byte_inventory_conditional_on_completed_api_calls=True,
                  cryptographic_streams_replayed=False, source_words_rechecked=False)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', required=True)
    parser.add_argument('--expected-sha512', required=True)
    parser.add_argument('--prime', type=int, required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit_boundaries(args.trace, args.expected_sha512, args.prime))
