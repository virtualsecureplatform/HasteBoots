import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from audit_classical_native_oracle_counts import audit, PREFIX, REJECTION_PREFIX, HONEST_PREFIX
from classical_profile_descriptor import decode_descriptor
from compare_classical_native_validation import PROFILE_PREFIX, PREFIX as PROOF_PREFIX
from test_classical_profile_descriptor import descriptor


def fixture(toy=False, version=5):
    raw = descriptor('2013265921', 6, 31, version=version)
    header = dict(decode_descriptor(raw), descriptor_bincode_hex=raw.hex(),
                  profile_descriptor_sha512=hashlib.sha512(raw).hexdigest(),
                  profile_id_sha512=hashlib.sha512(b'HasteBoots classical profile v1' + raw).hexdigest())
    proofs, counts = [], []
    for i in range(4):
        left, right = i // 2, i % 2
        proof = dict(original_size=not toy, ring_dimension=32 if toy else 1024,
                     lwe_dimension=21 if toy else 728, output_dimension=21 if toy else 728,
                     protocol_version=12, ordinal=i, group_size=4, group_index=i,
                     left=left, right=right, output=1-left*right, decoded_verified=True,
                     altered_output_rejected=True, reused_public_key_setup=True,
                     separate_single_proofs=True, correctness_only=True,
                     security_qualified=False, performance_gate=False, prime='2013265921',
                     extension_degree=6, backend='Brakedown', fragment_vars=None, queries=3)
        for key in ('fhe_parameters_sha256', 'native_keys_sha256', 'trusted_setup_sha256',
                    'statement_sha256', 'proof_sha256'):
            proof[key] = f'{i+1:064x}' if key == 'proof_sha256' else '1'*64
        for key in ('profile_descriptor_sha512', 'profile_id_sha512'):
            proof[key] = header[key]
        proofs.append(proof)
        counts.append(dict(profile_id_sha512=header['profile_id_sha512'],
                           proof_sha256=proof['proof_sha256'], ordinal=i, native=not toy,
                           ring_dimension=proof['ring_dimension'], lwe_dimension=proof['lwe_dimension'],
                           hash_queries=7, hash_input_bytes=448, max_hash_input=128,
                           xof_queries=3, xof_input_bytes=1024, max_xof_input=512,
                           direct_primitive_calls_included=False, security_qualified=False,
                           performance_gate=False))
    return header, proofs, counts


def write(path, header, proofs, counts, rejections=(), activities=()):
    text = PROFILE_PREFIX + json.dumps(header) + '\n'
    text += ''.join(PREFIX + json.dumps(row) + '\n' for row in counts)
    text += ''.join(REJECTION_PREFIX + json.dumps(row) + '\n' for row in rejections)
    text += ''.join(HONEST_PREFIX + json.dumps(row) + '\n' for row in activities)
    text += ''.join(PROOF_PREFIX + json.dumps(row) + '\n' for row in proofs)
    path.write_text(text)


class CountAuditTests(unittest.TestCase):
    def test_sampler_phase_maxima_are_required_explicitly_and_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, rows = fixture(version=4)
            write(path, header, proofs, rows)
            self.assertFalse(audit(path)['sampler_phase_maxima_recorded'])
            self.assertIsNone(audit(path)['observed_maximum_phase_values'])
            with self.assertRaisesRegex(ValueError, 'sampler phase maxima missing'):
                audit(path, require_sampler_phase_maxima=True)
            for row in rows:
                row.update(xof_queries=12, field_sampling_phases=2, field_values_sampled=10,
                    field_candidate_draws=12, max_field_candidates_per_value=2,
                    field_output_bytes=48, max_field_phase_output_bytes=28,
                    column_sampling_phases=2, column_values_sampled=5,
                    column_candidate_draws=5, max_column_candidates_per_value=1,
                    max_field_values_per_phase=7, max_column_values_per_phase=3)
            write(path, header, proofs, rows)
            result = audit(path, require_sampler_phase_maxima=True)
            self.assertTrue(result['sampler_phase_maxima_recorded'])
            self.assertEqual(result['observed_maximum_phase_values'],
                dict(max_field_values_per_phase=7, max_column_values_per_phase=3))
            self.assertFalse(result['deterministic_resource_bound_established'])
            for key, value in [('max_field_values_per_phase', True),
                    ('max_field_values_per_phase', 4), ('max_field_values_per_phase', 11),
                    ('max_field_values_per_phase', 8), ('max_column_values_per_phase', 2),
                    ('max_column_values_per_phase', 6)]:
                changed = copy.deepcopy(rows); changed[0][key] = value
                write(path, header, proofs, changed)
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    audit(path, require_sampler_phase_maxima=True)
            changed = copy.deepcopy(rows); del changed[0]['max_column_values_per_phase']
            write(path, header, proofs, changed)
            with self.assertRaisesRegex(ValueError, 'sampler phase maxima missing'):
                audit(path)

    def test_column_candidate_observations_are_complete_and_uncapped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, rows = fixture(version=4)
            write(path, header, proofs, rows)
            self.assertFalse(audit(path)['column_sampling_counts_recorded'])
            with self.assertRaisesRegex(ValueError, 'column sampler counts missing'):
                audit(path, require_column_sampling_counts=True)
            for row in rows:
                row.update(xof_queries=600, column_sampling_phases=1, column_values_sampled=2,
                           column_candidate_draws=515, max_column_candidates_per_value=514,
                           xof_output_bytes=4120, max_xof_output=8)
            write(path, header, proofs, rows)
            self.assertTrue(audit(path, require_column_sampling_counts=True)['column_sampling_counts_recorded'])
            for key, value in [('column_candidate_draws', 601), ('column_values_sampled', True),
                               ('max_column_candidates_per_value', 516),
                               ('column_sampling_phases', 0), ('xof_output_bytes', 4119)]:
                changed = copy.deepcopy(rows); changed[0][key] = value
                write(path, header, proofs, changed)
                with self.subTest(key=key), self.assertRaises(ValueError):
                    audit(path)
            changed = copy.deepcopy(rows); del changed[0]['column_values_sampled']
            write(path, header, proofs, changed)
            with self.assertRaisesRegex(ValueError, 'partial column sampler'):
                audit(path)

    def test_column_counts_match_trusted_sampler_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, rows = fixture()
            for row in rows:
                row.update(column_sampling_phases=0, column_values_sampled=0,
                           column_candidate_draws=0, max_column_candidates_per_value=0)
            write(path, header, proofs, rows)
            self.assertTrue(audit(path, require_column_sampling_counts=True)['column_sampling_counts_recorded'])
            changed = copy.deepcopy(rows)
            changed[0].update(column_sampling_phases=1, column_values_sampled=1,
                              column_candidate_draws=1, max_column_candidates_per_value=1)
            write(path, header, proofs, changed)
            with self.assertRaisesRegex(ValueError, 'trusted sampler profile'):
                audit(path)
            header, proofs, rows = fixture(version=4)
            for row in rows:
                row.update(column_sampling_phases=0, column_values_sampled=0,
                           column_candidate_draws=0, max_column_candidates_per_value=0)
            write(path, header, proofs, rows)
            with self.assertRaisesRegex(ValueError, 'no observed column sampling'):
                audit(path)
            from test_classical_candidate_terms import native
            raw = native(1, version=4, role_queries=[3] * 4)
            header = dict(decode_descriptor(raw), descriptor_bincode_hex=raw.hex(),
                          profile_descriptor_sha512=hashlib.sha512(raw).hexdigest(),
                          profile_id_sha512=hashlib.sha512(b'HasteBoots classical profile v1' + raw).hexdigest())
            for proof, row in zip(proofs, rows):
                proof['backend'] = header['backend']
                for key in ('profile_id_sha512', 'profile_descriptor_sha512'):
                    proof[key] = header[key]
                row['profile_id_sha512'] = header['profile_id_sha512']
            write(path, header, proofs, rows)
            self.assertTrue(audit(path)['column_sampling_counts_recorded'])
            rows[0].update(column_sampling_phases=1, column_values_sampled=1,
                           column_candidate_draws=1, max_column_candidates_per_value=1)
            write(path, header, proofs, rows)
            with self.assertRaisesRegex(ValueError, 'trusted sampler profile'):
                audit(path)

    def test_native_counts_bind_completed_proofs_and_do_not_certify_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            write(path, *fixture())
            result = audit(path)
            self.assertEqual(result['completed_proofs'], 4)
            self.assertEqual(result['observed_maximum_per_proof']['hash_queries'], 7)
            self.assertFalse(result['deterministic_resource_bound_established'])
            self.assertFalse(result['security_qualified'])

    def test_honest_activity_requires_bound_complete_records_and_unknown_lengths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, counts = fixture()
            activities = []
            for index in range(5):
                row = dict(counts[max(0, index-1)])
                row.pop('hash_input_bytes'); row.pop('max_hash_input')
                row.update(stage='setup' if index == 0 else 'prove',
                           ordinal=None if index == 0 else index-1,
                           proof_sha256=None if index == 0 else proofs[index-1]['proof_sha256'],
                           trusted_setup_sha256=proofs[0]['trusted_setup_sha256'],
                           hash_input_bytes_recorded=False, lookup_reciprocal_rejections=0)
                row.update({key: 0 for key in ('field_sampling_phases', 'field_values_sampled',
                           'field_candidate_draws', 'max_field_candidates_per_value',
                           'field_output_bytes', 'max_field_phase_output_bytes')})
                if index == 0:
                    row.update(xof_queries=0, xof_input_bytes=0, max_xof_input=0)
                activities.append(row)
            write(path, header, proofs, counts, activities=activities)
            self.assertTrue(audit(path, require_honest_activity=True)['honest_activity_recorded'])
            mutations = [('stage', 'setup'), ('ordinal', True), ('proof_sha256', '0'*64),
                         ('trusted_setup_sha256', '0'*64), ('hash_input_bytes', 0),
                         ('max_hash_input', 0), ('hash_input_bytes_recorded', True),
                         ('hash_queries', False), ('field_candidate_draws', 1)]
            for key, value in mutations:
                changed = copy.deepcopy(activities); changed[1][key] = value
                write(path, header, proofs, counts, activities=changed)
                with self.subTest(key=key), self.assertRaises(ValueError):
                    audit(path, require_honest_activity=True)
            for changed in ([], activities[:-1], activities + [activities[-1]]):
                write(path, header, proofs, counts, activities=changed)
                with self.assertRaises(ValueError):
                    audit(path, require_honest_activity=True)

    def test_xof_output_counts_require_complete_consistent_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, counts = fixture()
            write(path, header, proofs, counts)
            self.assertFalse(audit(path)['xof_output_counts_recorded'])
            with self.assertRaisesRegex(ValueError, 'XOF output counts missing'):
                audit(path, require_xof_output_counts=True)
            counts = [dict(row, xof_output_bytes=100, max_xof_output=64) for row in counts]
            write(path, header, proofs, counts)
            self.assertTrue(audit(path, require_xof_output_counts=True)['xof_output_counts_recorded'])
            for key, value in [('xof_output_bytes', True), ('max_xof_output', -1),
                               ('max_xof_output', 101), ('max_xof_output', 33)]:
                changed = copy.deepcopy(counts); changed[0][key] = value
                write(path, header, proofs, changed)
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    audit(path)
            changed = copy.deepcopy(counts); del changed[0]['max_xof_output']
            write(path, header, proofs, changed)
            with self.assertRaisesRegex(ValueError, 'partial XOF output'):
                audit(path)
            for row in counts:
                row.update(field_sampling_phases=1, field_values_sampled=1,
                           field_candidate_draws=16, max_field_candidates_per_value=16,
                           field_output_bytes=64, max_field_phase_output_bytes=64)
            write(path, header, proofs, counts)
            with self.assertRaisesRegex(ValueError, 'omit field stream or receipt'):
                audit(path)
            for row in counts:
                row.update(xof_output_bytes=128)
            write(path, header, proofs, counts)
            self.assertTrue(audit(path)['xof_output_counts_recorded'])

    def test_toy_geometry_requires_explicit_option(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'toy.log'
            write(path, *fixture(toy=True))
            with self.assertRaises(ValueError):
                audit(path)
            self.assertFalse(audit(path, toy=True)['native'])

    def test_binding_count_scope_and_completion_substitutions_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, counts = fixture()
            changes = {'ordinal': 1, 'native': False, 'ring_dimension': 32,
                       'lwe_dimension': 21, 'profile_id_sha512': '0'*128,
                       'proof_sha256': '0'*64, 'hash_queries': True,
                       'xof_queries': 0, 'hash_input_bytes': -1, 'max_hash_input': 449,
                       'direct_primitive_calls_included': True, 'security_qualified': True}
            for key, value in changes.items():
                altered = copy.deepcopy(counts); altered[0][key] = value
                write(path, header, proofs, altered)
                with self.subTest(key=key), self.assertRaises(ValueError):
                    audit(path)
            for altered in [counts[:-1], counts + [counts[0]], list(reversed(counts))]:
                write(path, header, proofs, altered)
                with self.assertRaises(ValueError):
                    audit(path)
            write(path, header, proofs[:-1], counts)
            with self.assertRaises(ValueError):
                audit(path)

    def test_rejected_execution_counts_preserve_rejection_and_zero_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, counts = fixture()
            rejections = [dict(row, rejected=True, altered_statement_sha256='2'*64,
                               hash_queries=0, hash_input_bytes=0, max_hash_input=0,
                               xof_queries=0, xof_input_bytes=0, max_xof_input=0)
                          for row in counts]
            write(path, header, proofs, counts)
            with self.assertRaisesRegex(ValueError, 'rejected execution/completed'):
                audit(path, require_rejections=True)
            write(path, header, proofs, counts, rejections)
            self.assertEqual(audit(path, require_rejections=True)['rejected_executions_checked'], 4)
            for key, value in [('rejected', False), ('ordinal', 1), ('hash_queries', True),
                               ('xof_queries', -1), ('hash_input_bytes', 1),
                               ('altered_statement_sha256', proofs[0]['statement_sha256'])]:
                changed = copy.deepcopy(rejections); changed[0][key] = value
                write(path, header, proofs, counts, changed)
                with self.subTest(key=key), self.assertRaises(ValueError):
                    audit(path, require_rejections=True)

    def test_lookup_retry_observations_do_not_become_runtime_cutoffs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, counts = fixture()
            write(path, header, proofs, counts)
            self.assertIsNone(audit(path)['all_accepted_executions_before_first_lookup_retry'])
            with self.assertRaisesRegex(ValueError, 'retry count missing'):
                audit(path, require_lookup_retry_counts=True)
            observed = [dict(row, lookup_reciprocal_rejections=0) for row in counts]
            write(path, header, proofs, observed)
            self.assertTrue(audit(path, require_lookup_retry_counts=True)[
                'all_accepted_executions_before_first_lookup_retry'])
            observed[0]['lookup_reciprocal_rejections'] = 3
            write(path, header, proofs, observed)
            result = audit(path, require_lookup_retry_counts=True)
            self.assertFalse(result['all_accepted_executions_before_first_lookup_retry'])
            self.assertEqual(result['completed_proofs'], 4)
            for value in [True, -1]:
                observed[0]['lookup_reciprocal_rejections'] = value
                write(path, header, proofs, observed)
                with self.assertRaisesRegex(ValueError, 'retry count'):
                    audit(path, require_lookup_retry_counts=True)

    def test_field_sampling_metrics_and_analytical_threshold_are_observational(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'native.log'
            header, proofs, counts = fixture()
            write(path, header, proofs, counts)
            self.assertIsNone(audit(path)['all_accepted_executions_before_field_candidate_excess'])
            with self.assertRaisesRegex(ValueError, 'field sampler counts missing'):
                audit(path, require_field_sampling_counts=True)
            observed = [dict(row, xof_queries=7, field_sampling_phases=2, field_values_sampled=3,
                             field_candidate_draws=4, max_field_candidates_per_value=2,
                             field_output_bytes=16, max_field_phase_output_bytes=12) for row in counts]
            write(path, header, proofs, observed)
            self.assertTrue(audit(path, require_field_sampling_counts=True)[
                'all_accepted_executions_before_field_candidate_excess'])
            for key, value in [('field_candidate_draws', True), ('field_values_sampled', -1),
                               ('field_candidate_draws', 2), ('field_output_bytes', 15),
                               ('max_field_candidates_per_value', 1),
                               ('field_sampling_phases', 4), ('max_field_phase_output_bytes', 17)]:
                changed = copy.deepcopy(observed); changed[0][key] = value
                write(path, header, proofs, changed)
                with self.subTest(key=key), self.assertRaises(ValueError):
                    audit(path, require_field_sampling_counts=True)
            crossed = copy.deepcopy(observed)
            crossed[0].update(field_candidate_draws=515, max_field_candidates_per_value=513,
                              field_output_bytes=2060, max_field_phase_output_bytes=2056)
            write(path, header, proofs, crossed)
            result = audit(path, require_field_sampling_counts=True)
            self.assertFalse(result['all_accepted_executions_before_field_candidate_excess'])
            self.assertEqual(result['completed_proofs'], 4)


if __name__ == '__main__':
    unittest.main()
