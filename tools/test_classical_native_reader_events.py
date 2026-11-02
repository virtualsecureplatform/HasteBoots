from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from audit_classical_native_reader_events import METRICS, audit_bound_trace
from test_classical_reader_event_stream import HEADER, hashed, start, output


class NativeReaderBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'capture.reader-events'
        raw = hashlib.shake_256(b'r').digest(7)
        self.data = HEADER+hashed(b'h', 2)+start(0, b'r', 2)+output(0, 0, raw, 2)
        self.path.write_bytes(self.data)
        self.proof = dict(profile_id_sha512='2'*128, proof_sha256='3'*64,
            trusted_setup_sha256='4'*64, statement_sha256='5'*64,
            ring_dimension=1024, lwe_dimension=728)
        self.measurement = dict(hash_queries=1, xof_queries=1, hash_input_bytes=1,
            xof_input_bytes=1, max_hash_input=1, max_xof_input=1,
            xof_output_bytes=7, max_xof_output=7, altered_statement_sha256='6'*64)

    def row(self, kind='accepted'):
        return dict(self.proof, kind=kind, ordinal=0,
            statement_sha256=self.proof['statement_sha256'] if kind == 'accepted' else '6'*64,
            native=True, ordinary_counter_match=True, direct_primitive_calls_included=False,
            security_qualified=False, performance_gate=False,
            trace_path_hex=os.fsencode(self.path).hex(),
            trace_sha512=hashlib.sha512(self.data).hexdigest())

    def test_concrete_trace_binds_both_statement_kinds_without_certification(self):
        for kind in ('accepted', 'rejected'):
            result = audit_bound_trace(self.row(kind), self.proof, self.measurement, kind)
            self.assertEqual(result['phases']['verify']['output_bytes'], 7)
            self.assertTrue(result['consumed_shake256_bytes_verified'])
            self.assertTrue(result['ordinary_counter_match_recorded'])
            self.assertFalse(result['legacy_query_projection_exactly_equal'])
            self.assertFalse(result['security_qualified'])

    def test_wrong_identity_flags_and_integer_types_reject(self):
        changes = dict(kind='rejected', ordinal=False, profile_id_sha512='0'*128,
            proof_sha256='0'*64, trusted_setup_sha256='0'*64, statement_sha256='0'*64,
            native=False, ring_dimension=32, lwe_dimension=21, ordinary_counter_match=False,
            direct_primitive_calls_included=True, security_qualified=True, performance_gate=True)
        for key, value in changes.items():
            row = self.row()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit_bound_trace(row, self.proof, self.measurement, 'accepted')

    def test_every_query_and_output_counter_is_independently_compared(self):
        for key in METRICS+('xof_output_bytes', 'max_xof_output'):
            measurement = deepcopy(self.measurement)
            measurement[key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit_bound_trace(self.row(), self.proof, measurement, 'accepted')

    def test_encoding_phase_and_output_corruption_fail_closed(self):
        for key, value in [('trace_path_hex', 'xx'),
                           ('trace_path_hex', self.row()['trace_path_hex'].upper()),
                           ('trace_sha512', 'z'*128)]:
            row = self.row()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                audit_bound_trace(row, self.proof, self.measurement, 'accepted')
        changed = self.data[:-1]+bytes([self.data[-1]^1])
        self.path.write_bytes(changed)
        row = self.row()
        row['trace_sha512'] = hashlib.sha512(changed).hexdigest()
        with self.assertRaises(ValueError):
            audit_bound_trace(row, self.proof, self.measurement, 'accepted')
        changed = HEADER+start(0, b'r', 1)+output(0, 0, hashlib.shake_256(b'r').digest(7), 1)
        self.path.write_bytes(changed)
        row['trace_sha512'] = hashlib.sha512(changed).hexdigest()
        with self.assertRaises(ValueError):
            audit_bound_trace(row, self.proof, self.measurement, 'accepted')


if __name__ == '__main__':
    unittest.main()
