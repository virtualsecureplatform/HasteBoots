"""Compare exact ordered prover/verifier XOF inputs in a completed event trace.

This is a control of one saved execution, not an all-stream coupling proof.
"""
from itertools import zip_longest
from pathlib import Path

from audit_classical_oracle_event_stream import HEADER, audit


def _requests(source, phase):
    source.seek(len(HEADER))
    while frame := source.read(10):
        if len(frame) != 10:
            raise ValueError('truncated event header')
        kind, current = frame[:2]
        length = int.from_bytes(frame[2:], 'little')
        if kind == 2 and current == phase:
            yield length
            # Caller consumes exactly this request's body before resumption.
        else:
            source.seek(length + (64 if kind == 1 else 0), 1)


def _frame(kind, label, body):
    return bytes([kind]) + len(label).to_bytes(8, 'little') + label + len(body).to_bytes(8, 'little') + body


def compare(path, expected_sha512, *, continuation_prime=None):
    path = Path(path)
    before = path.stat()
    verified = audit(path, expected_sha512)
    count = total = maximum = 0
    trailing = []
    if continuation_prime is not None and (type(continuation_prime) is not int
            or continuation_prime not in (2013265921, 18446744069414584321)):
        raise ValueError('supported native continuation prime required')
    missing = object()
    with path.open('rb') as prover, path.open('rb') as verifier:
        for a, b in zip_longest(_requests(prover, 1), _requests(verifier, 2), fillvalue=missing):
            if b is missing and a is not missing and continuation_prime is not None:
                prefix, tail = b'', b''
                remaining = a
                while remaining:
                    chunk = prover.read(min(remaining, 1 << 20))
                    if not chunk:
                        raise ValueError('truncated continuation input')
                    prefix = (prefix + chunk)[:64]
                    tail = (tail + chunk)[-256:]
                    remaining -= len(chunk)
                trailing.append((prefix, tail))
                if len(trailing) > 3:
                    raise ValueError('unexpected extra prover continuation request')
                continue
            if a is missing or b is missing:
                raise ValueError('prover/verifier XOF request count mismatch')
            if a != b:
                raise ValueError('prover/verifier XOF request length mismatch')
            remaining = a
            while remaining:
                # Buffer size is not a sampler or adversary query limit.
                size = min(remaining, 1 << 20)
                left, right = prover.read(size), verifier.read(size)
                if len(left) != size or len(right) != size:
                    raise ValueError('truncated XOF request input')
                if left != right:
                    raise ValueError('prover/verifier ordered XOF input mismatch')
                remaining -= size
            count += 1
            total += a
            maximum = max(maximum, a)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('event trace changed during comparison')
    if count == 0:
        raise ValueError('no prover/verifier XOF requests')
    if continuation_prime is not None:
        first = _frame(4, b'fresh complete canonical certificate after',
            continuation_prime.to_bytes(16, 'little') + (1).to_bytes(8, 'little'))
        last = _frame(2, b'fresh complete canonical certificate bytes after', (32).to_bytes(8, 'little'))
        if (len(trailing) != 3 or not trailing[0][1].endswith(first)
                or not trailing[1][0].startswith(b'HasteBoots consumed field bytes v1')
                or not trailing[2][1].endswith(last)):
            raise ValueError('unexpected prover continuation request framing')
    return dict(path=str(path.resolve()), trace_sha512=verified['trace_sha512'],
        compared_requests=count, compared_input_bytes=total, maximum_input_bytes=maximum,
        ordered_inputs_equal=not trailing, protocol_prefix_inputs_equal=True,
        excluded_prover_continuation_requests=len(trailing), byte_for_byte_comparison=True,
        all_hash_preimages_verified=True, xof_outputs_recorded=False,
        all_stream_coupling_established=False, security_qualified=False,
        performance_qualified=False)
