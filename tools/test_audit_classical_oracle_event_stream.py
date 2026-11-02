import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from audit_classical_oracle_event_stream import (HEADER, CONTROL_PREFIX, SOURCE_PREFIXES,
                                                TEMPORAL_PREFIX, audit, audit_controls, audit_source_controls)


def event(kind, phase, body):
    return bytes((kind, phase)) + len(body).to_bytes(8, 'little') + body + (
        hashlib.sha512(body).digest() if kind == 1 else b'')


class StreamAuditTests(unittest.TestCase):
    def test_temporal_source_records_require_order_scope_and_exact_integer_vectors(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / 'trace.events'
            trace.write_bytes(HEADER + event(1, 2, b'leaf') + event(2, 2, b'coins'))
            observed = audit(trace)
            identity = dict(prime='2013265921', degree=6, version=5, backend='Brakedown')
            temporal = dict(identity, initial_identity_requests=[0, 3, 3],
                            later_child_requests=[0, 76, 76], unique_child_seeds=[0, 3, 3],
                            captured_availability_hits=[0, 0], replayed_receipt_frames=3780,
                            generic_completed_phase_streams_checked=True,
                            all_captured_input_windows_checked=True,
                            same_prover_verifier_seed_sets=True, xof_output_collisions=0,
                            all_input_windows_registered=False, availability_filter_checked=False,
                            security_qualified=False)
            rows = [dict(identity, ntt_components=8, linear_sources=16,
                         complete_transcript_match=True, security_qualified=False), temporal,
                    dict(claims=258, monomial_checked=True, security_qualified=False),
                    dict(identity, ntt_source_claims=128, product_source_claims=15,
                         decomposition_source_claims=16, lookup_source_claims=15,
                         lookup_helper_claims=7, events_replayed=2,
                         all_pbs_stages_coupled=True, security_qualified=False),
                    dict(identity, n=32, lwe=21, queries=8, trace_path=str(trace),
                         trace_sha512=observed['trace_sha512'], encrypted_native=False,
                         security_qualified=False)]
            rows[4].update({'verifier_' + k: v for k, v in observed['phases']['verify'].items()})
            prefixes = (SOURCE_PREFIXES[0], TEMPORAL_PREFIX, *SOURCE_PREFIXES[1:], CONTROL_PREFIX)
            log = Path(directory) / 'controls.log'
            def write(items, order=range(5), suffix=''):
                log.write_text(''.join(prefixes[i] + json.dumps(items[i]) + '\n' for i in order) + suffix)
            write(rows, suffix=SOURCE_PREFIXES[0] + '{')
            result = audit_source_controls(log, require_temporal=True)
            self.assertTrue(result['captured_generic_phase_control_records_verified'])
            self.assertFalse(result['suite_completion_verified'])
            self.assertFalse(result['security_qualified'])
            changes = [('prime', '18446744069414584321'),
                       ('initial_identity_requests', [0, 2, 3]),
                       ('initial_identity_requests', [0, True, True]),
                       ('later_child_requests', [0, 2, 2]),
                       ('unique_child_seeds', [0, 2, 2]),
                       ('captured_availability_hits', [0, 1]),
                       ('captured_availability_hits', [False, False]),
                       ('captured_availability_hits', [0]),
                       ('replayed_receipt_frames', 0), ('replayed_receipt_frames', True),
                       ('xof_output_collisions', 1), ('xof_output_collisions', False)]
            changes += [(key, False) for key in ('generic_completed_phase_streams_checked',
                        'all_captured_input_windows_checked', 'same_prover_verifier_seed_sets')]
            changes += [(key, True) for key in ('all_input_windows_registered',
                        'availability_filter_checked', 'security_qualified')]
            for key, value in changes:
                changed = copy.deepcopy(rows); changed[1][key] = value
                write(changed)
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    audit_source_controls(log, require_temporal=True)
            changed = copy.deepcopy(rows); changed[2]['security_qualified'] = True
            write(changed)
            with self.assertRaisesRegex(ValueError, 'admission'):
                audit_source_controls(log, require_temporal=True)
            for order in [(0, 2, 3, 4), (0, 2, 1, 3, 4), (0, 1, 1, 2, 3, 4)]:
                write(rows, order)
                with self.assertRaisesRegex(ValueError, 'reordered'):
                    audit_source_controls(log, require_temporal=True)

    def run_audit(self, data, expected=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.events'
            path.write_bytes(data)
            return audit(path, expected)

    def test_exact_phase_counts_lengths_and_hash_preimages(self):
        data = HEADER + event(1, 0, b'key') + event(2, 1, b'root declaration')
        data += event(1, 2, b'parent preimage') + event(2, 2, b'challenge request')
        result = self.run_audit(data, hashlib.sha512(data).hexdigest())
        self.assertEqual(result['events'], 4)
        self.assertEqual(result['phases']['setup']['hash_queries'], 1)
        self.assertEqual(result['phases']['verify']['hash_input_bytes'], 15)
        self.assertEqual(result['phases']['verify']['max_xof_input'], 17)
        self.assertFalse(result['security_qualified'])

    def test_corrupted_hash_output_is_rejected(self):
        data = bytearray(HEADER + event(1, 2, b'authenticated leaf'))
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'preimage/output'):
            self.run_audit(data)

    def test_truncation_and_huge_declared_length_reject_without_allocation(self):
        for data in [HEADER + b'\x01', HEADER + event(1, 0, b'root')[:-1],
                     HEADER + b'\x02\x02' + (2**64-1).to_bytes(8, 'little')]:
            with self.assertRaisesRegex(ValueError, 'truncated'):
                self.run_audit(data)

    def test_wrong_version_phase_order_and_fingerprint_reject(self):
        bad = [b'other version', HEADER + event(2, 2, b'a') + event(2, 1, b'b'),
               HEADER + bytes((3, 0)) + bytes(8)]
        for data in bad:
            with self.assertRaises(ValueError):
                self.run_audit(data)
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            self.run_audit(HEADER, '0' * 128)

    def test_control_counters_are_recomputed_and_partial_row_is_not_completed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.events'
            path.write_bytes(HEADER + event(1, 2, b'leaf') + event(2, 2, b'coins'))
            observed = audit(path)
            row = dict(prime='2013265921', degree=6, version=5, backend='Brakedown',
                       trace_path=str(path), trace_sha512=observed['trace_sha512'])
            row.update({'verifier_' + key: value for key, value in observed['phases']['verify'].items()})
            log = Path(directory) / 'controls.log'
            def write(value, suffix=''):
                log.write_text('test is running\n' + CONTROL_PREFIX + json.dumps(value) + '\n' + suffix)
            write(row, CONTROL_PREFIX + '{')
            result = audit_controls(log)
            self.assertEqual(result['completed_controls'], 1)
            self.assertFalse(result['suite_completion_verified'])
            for key in observed['phases']['verify']:
                altered = dict(row)
                altered['verifier_' + key] += 1
                write(altered)
                with self.assertRaisesRegex(ValueError, 'counter mismatch'):
                    audit_controls(log)
            altered = dict(row, verifier_hash_queries=True)
            write(altered)
            with self.assertRaisesRegex(ValueError, 'counter mismatch'):
                audit_controls(log)
            write(row, CONTROL_PREFIX + json.dumps(row) + '\n')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                audit_controls(log)
            # A null fingerprint must not disable the mandatory control-row
            # fingerprint check via the single-trace API's optional argument.
            for fingerprint in [None, '', '0' * 127, 'g' * 128, ' ' * 128]:
                write(dict(row, trace_sha512=fingerprint))
                with self.assertRaisesRegex(ValueError, 'fingerprint'):
                    audit_controls(log)
            log.write_text(CONTROL_PREFIX + '{')
            with self.assertRaisesRegex(ValueError, 'no completed'):
                audit_controls(log)

    def test_all_stage_source_records_counts_identity_order_and_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trace.events'
            path.write_bytes(HEADER + event(1, 2, b'leaf') + event(2, 2, b'coins'))
            observed = audit(path)
            identity = dict(prime='2013265921', degree=6, version=5, backend='Brakedown')
            rows = [dict(identity, ntt_components=8, linear_sources=16,
                         complete_transcript_match=True),
                    dict(claims=258, monomial_checked=True),
                    dict(identity, ntt_source_claims=128, product_source_claims=15,
                         decomposition_source_claims=16, lookup_source_claims=15,
                         lookup_helper_claims=7, events_replayed=2,
                         all_pbs_stages_coupled=True),
                    dict(identity, n=32, lwe=21, queries=8, trace_path=str(path),
                         trace_sha512=observed['trace_sha512'])]
            rows[3].update({'verifier_' + key: value
                            for key, value in observed['phases']['verify'].items()})
            prefixes = SOURCE_PREFIXES + (CONTROL_PREFIX,)
            log = Path(directory) / 'controls.log'
            def write(values, order=range(4), suffix=''):
                log.write_text(''.join(prefixes[i] + json.dumps(values[i]) + '\n'
                                       for i in order) + suffix)
            write(rows, suffix=SOURCE_PREFIXES[0] + '{')
            result = audit_source_controls(log)
            self.assertTrue(result['all_stage_source_control_records_verified'])
            self.assertFalse(result['suite_completion_verified'])
            self.assertFalse(result['security_qualified'])
            for index, keys in [(0, ['ntt_components', 'linear_sources']),
                                (1, ['claims']),
                                (2, ['ntt_source_claims', 'product_source_claims',
                                     'decomposition_source_claims', 'lookup_source_claims',
                                     'lookup_helper_claims', 'events_replayed'])]:
                for key in keys:
                    for value in [rows[index][key] + 1, True]:
                        changed = copy.deepcopy(rows); changed[index][key] = value
                        write(changed)
                        with self.assertRaisesRegex(ValueError, 'count mismatch'):
                            audit_source_controls(log)
            for index, key in [(0, 'complete_transcript_match'), (1, 'monomial_checked'),
                               (2, 'all_pbs_stages_coupled')]:
                changed = copy.deepcopy(rows); changed[index][key] = False
                write(changed)
                with self.assertRaisesRegex(ValueError, 'stage coverage'):
                    audit_source_controls(log)
            for index in [0, 2]:
                changed = copy.deepcopy(rows); changed[index]['version'] = 4
                write(changed)
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    audit_source_controls(log)
            for order in [[3], [0, 2, 1, 3], [0, 1, 1, 2, 3]]:
                write(rows, order=order)
                with self.assertRaisesRegex(ValueError, 'reordered'):
                    audit_source_controls(log)
            changed = copy.deepcopy(rows); changed[3]['n'] = 1024
            write(changed)
            with self.assertRaisesRegex(ValueError, 'fixture geometry'):
                audit_source_controls(log)


if __name__ == '__main__':
    unittest.main()
