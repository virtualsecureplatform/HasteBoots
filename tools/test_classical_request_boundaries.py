import hashlib
from pathlib import Path
import tempfile
import unittest

from audit_classical_oracle_event_stream import HEADER, audit
from audit_classical_request_boundaries import (APPLICATIONS, PREFIX, RECEIPT,
                                               inspect_input, audit_boundaries)

PRIME = 2013265921


def frame(kind, label, body):
    return bytes([kind]) + len(label).to_bytes(8, 'little') + label + len(body).to_bytes(8, 'little') + body


def root(family=0):
    return PREFIX + frame(0, b'application', APPLICATIONS[family]) + frame(0, b'trusted profile', bytes(64))


def event(kind, phase, body):
    return bytes([kind, phase]) + len(body).to_bytes(8, 'little') + body + (
        hashlib.sha512(body).digest() if kind == 1 else b'')


class RequestBoundariesTests(unittest.TestCase):
    def run_audit(self, data, expected=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.events'
            path.write_bytes(data)
            return audit_boundaries(path, expected or hashlib.sha512(data).hexdigest(), PRIME)

    def test_all_namespaces_and_pending_counts_without_output_allocation(self):
        for family in range(3):
            data = root(family) + frame(2, b'current', (2**64-1).to_bytes(8, 'little'))
            self.assertEqual(inspect_input(memoryview(data), PRIME)[:3], (family, 2, 2**64-1))
        descriptor = PRIME.to_bytes(16, 'little') + (6).to_bytes(8, 'little')
        self.assertEqual(inspect_input(root(2) + frame(4, b'current', descriptor), PRIME)[:3], (2, 4, 6))
        self.assertEqual(inspect_input(root() + frame(8, b'parent checkpoint', b''), PRIME)[:3], (0, 8, 64))
        self.assertIsNone(inspect_input(b'arbitrary external input', PRIME))

    def test_unknown_domains_endpoints_and_huge_or_truncated_lengths_reject(self):
        request = frame(2, b'current', (64).to_bytes(8, 'little'))
        bad = [root(), root() + frame(1, b'message', b'no request'),
               root() + frame(2, b'current', bytes(7)),
               root() + frame(8, b'wrong checkpoint', b''),
               root() + frame(8, b'parent checkpoint', b'') + request,
               root() + b'\x01' + (2**64-1).to_bytes(8, 'little')]
        bad += [root() + frame(k, b'unknown/domain', b'') + request for k in (0, 9, 255)]
        for data in bad:
            with self.subTest(data=data[-32:]), self.assertRaises(ValueError):
                inspect_input(data, PRIME)
        valid = root() + request
        for end in range(len(PREFIX), len(valid)):
            with self.assertRaises(ValueError):
                inspect_input(valid[:end], PRIME)
        descriptor = (PRIME+2).to_bytes(16, 'little') + (1).to_bytes(8, 'little')
        with self.assertRaisesRegex(ValueError, 'field request'):
            inspect_input(root() + frame(4, b'current', descriptor), PRIME)

    def test_receipt_draws_and_conditional_output_inventory(self):
        descriptor = PRIME.to_bytes(16, 'little') + (1).to_bytes(8, 'little')
        field = root() + frame(4, b'current', descriptor)
        # Reject 2^31-1, then mask off the high bit and accept one.
        raw = (2**31-1).to_bytes(4, 'little') + (2**31+1).to_bytes(4, 'little')
        byte = root() + frame(2, b'current bytes', (32).to_bytes(8, 'little'))
        data = HEADER + event(1, 0, b'leaf') + event(2, 1, field)
        data += event(2, 1, RECEIPT+raw) + event(2, 1, byte) + event(2, 2, b'other primitive')
        result = self.run_audit(data)
        row = result['request_inventory']['prove']
        self.assertEqual(row['request_kinds'], [1, 1, 0, 0])
        self.assertEqual((row['field_values'], row['field_candidates'], row['max_candidates_per_value']), (1, 2, 2))
        self.assertEqual(row['consumed_xof_bytes_if_completed_api_calls'], 32+8+64)
        self.assertTrue(row['closed_field_receipt_counts'])
        self.assertIsNone(result['request_inventory']['verify']['consumed_xof_bytes_if_completed_api_calls'])
        self.assertFalse(result['cryptographic_streams_replayed'])
        self.assertFalse(result['source_words_rechecked'])
        self.assertFalse(result['security_qualified'])

    def test_incomplete_receipts_make_inventory_unknown_and_complete_mismatch_rejects(self):
        descriptor = PRIME.to_bytes(16, 'little') + (1).to_bytes(8, 'little')
        field = event(2, 1, root() + frame(4, b'current', descriptor))
        for raw in [b'\0', (2**31-1).to_bytes(4, 'little')]:
            result = self.run_audit(HEADER + field + event(2, 1, RECEIPT+raw))
            self.assertIsNone(result['request_inventory']['prove']['consumed_xof_bytes_if_completed_api_calls'])
        with self.assertRaisesRegex(ValueError, 'acceptance inventory'):
            self.run_audit(HEADER + field + event(2, 1, RECEIPT))

    def test_fingerprint_hash_outputs_and_callback_event_scope(self):
        data = HEADER + event(1, 0, b'leaf') + event(2, 1, b'opaque')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.events'; path.write_bytes(data)
            seen = []
            audit(path, on_xof_input=lambda phase, body: seen.append((phase, bytes(body))))
            self.assertEqual(seen, [(1, b'opaque')])
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            self.run_audit(data, '0'*128)
        corrupt = bytearray(data); corrupt[len(HEADER)+10+len(b'leaf')] ^= 1
        with self.assertRaisesRegex(ValueError, 'preimage/output'):
            self.run_audit(corrupt)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            self.run_audit(HEADER + b'\x02\x01' + (2**64-1).to_bytes(8, 'little'))


if __name__ == '__main__':
    unittest.main()
