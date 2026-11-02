"""Verify captured reader bytes and their ordered legacy-query projection.

Concrete trace consistency only; never an ideal-oracle or security certificate.
"""
import argparse
from contextlib import ExitStack
import hashlib
from pathlib import Path

from audit_artifacts import write_json_new
from audit_classical_oracle_event_stream import HEADER as LEGACY_HEADER, PHASES

HEADER = b'HB_ORACLE_READER_STREAM_V1\n'


def audit(path, expected_sha512=None, *, legacy_path=None, expected_legacy_sha512=None,
          on_reader_start=None, on_output_chunk=None, on_hash=None):
    if expected_legacy_sha512 is not None and legacy_path is None:
        raise ValueError('legacy file required for exact projection comparison')
    digest = hashlib.sha512()
    projection = hashlib.sha512()
    readers = {}
    phases = [dict(hash_queries=0, xof_queries=0, hash_input_bytes=0,
                   xof_input_bytes=0, max_hash_input=0, max_xof_input=0,
                   read_calls=0, output_bytes=0, max_reader_output=0) for _ in PHASES]
    events, previous_phase = 0, 0
    with ExitStack() as stack:
        source = stack.enter_context(Path(path).open('rb'))
        legacy = stack.enter_context(Path(legacy_path).open('rb')) if legacy_path is not None else None

        def project(data):
            projection.update(data)
            if legacy is not None and legacy.read(len(data)) != data:
                raise ValueError('legacy query projection mismatch')

        def take(length):
            data = source.read(length)
            if len(data) != length:
                raise ValueError('truncated reader event')
            digest.update(data)
            return data

        if take(len(HEADER)) != HEADER:
            raise ValueError('unsupported reader-event header')
        project(LEGACY_HEADER)
        while True:
            frame = source.read(2)
            if not frame:
                break
            if len(frame) != 2:
                raise ValueError('truncated reader event header')
            digest.update(frame)
            kind, phase = frame
            if kind not in (1, 2, 3) or phase not in range(3) or phase < previous_phase:
                raise ValueError('invalid reader event or phase order')
            previous_phase = phase
            row = phases[phase]
            if kind in (1, 2):
                reader = int.from_bytes(take(8), 'little') if kind == 2 else None
                if kind == 2 and reader in readers:
                    raise ValueError('duplicate reader identity')
                encoded_length = take(8)
                length = int.from_bytes(encoded_length, 'little')
                project(frame + encoded_length)
                oracle = hashlib.sha512() if kind == 1 else hashlib.shake_256()
                captured = bytearray() if ((kind == 2 and on_reader_start is not None)
                    or (kind == 1 and on_hash is not None)) else None
                remaining = length
                while remaining:
                    # IO block size, not an input-length or adversary cutoff.
                    data = take(min(remaining, 1 << 20))
                    oracle.update(data)
                    if captured is not None:
                        captured.extend(data)
                    project(data)
                    remaining -= len(data)
                if kind == 1:
                    output = take(64)
                    if output != oracle.digest():
                        raise ValueError('SHA-512 preimage/output mismatch')
                    project(output)
                    if on_hash is not None:
                        on_hash(phase, output, memoryview(captured))
                else:
                    readers[reader] = dict(oracle=oracle, consumed=0, expected=b'')
                    if on_reader_start is not None:
                        on_reader_start(phase, reader, memoryview(captured))
                key = 'hash' if kind == 1 else 'xof'
                row[key+'_queries'] += 1
                row[key+'_input_bytes'] += length
                row['max_'+key+'_input'] = max(row['max_'+key+'_input'], length)
            else:
                reader = int.from_bytes(take(8), 'little')
                offset = int.from_bytes(take(16), 'little')
                length = int.from_bytes(take(8), 'little')
                state = readers.get(reader)
                if state is None:
                    raise ValueError('output precedes reader start')
                if offset != state['consumed']:
                    raise ValueError('noncontiguous reader offset')
                remaining = length
                while remaining:
                    data = take(min(remaining, 1 << 20))
                    start = state['consumed']
                    end = start + len(data)
                    if len(state['expected']) < end:
                        # hashlib exposes prefixes rather than advancing reads.
                        # Geometric growth keeps verification linear in actual
                        # consumed bytes, without trusting a claimed huge length.
                        capacity = max(64, len(state['expected']))
                        while capacity < end:
                            capacity *= 2
                        state['expected'] = state['oracle'].digest(capacity)
                    if data != state['expected'][start:end]:
                        raise ValueError('SHAKE256 reader output mismatch')
                    state['consumed'] = end
                    if on_output_chunk is not None:
                        on_output_chunk(phase, reader, start, data)
                    remaining -= len(data)
                if length == 0 and on_output_chunk is not None:
                    on_output_chunk(phase, reader, offset, b'')
                row['read_calls'] += 1
                row['output_bytes'] += length
                row['max_reader_output'] = max(row['max_reader_output'], state['consumed'])
            events += 1
        if legacy is not None and legacy.read(1):
            raise ValueError('trailing legacy query events')
    fingerprint = digest.hexdigest()
    projected = projection.hexdigest()
    if expected_sha512 is not None and fingerprint != expected_sha512.lower():
        raise ValueError('reader-event fingerprint mismatch')
    if expected_legacy_sha512 is not None and projected != expected_legacy_sha512.lower():
        raise ValueError('legacy fingerprint mismatch')
    return dict(path=str(Path(path).resolve()), trace_sha512=fingerprint,
                events=events, reader_instances=len(readers), phases=dict(zip(PHASES, phases)),
                sha512_preimages_verified=True, consumed_shake256_bytes_verified=True,
                legacy_projection_sha512=projected,
                legacy_query_projection_exactly_equal=legacy_path is not None,
                reader_instances_are_distinct_oracle_inputs=False,
                complete_interface_capture_established=False,
                ideal_stream_model_established=False,
                security_qualified=False, performance_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace')
    parser.add_argument('--expected-sha512')
    parser.add_argument('--legacy-trace')
    parser.add_argument('--expected-legacy-sha512')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    write_json_new(args.output, audit(args.trace, args.expected_sha512,
        legacy_path=args.legacy_trace, expected_legacy_sha512=args.expected_legacy_sha512))


if __name__ == '__main__':
    main()
