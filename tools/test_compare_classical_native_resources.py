import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from classical_profile_descriptor import decode_descriptor
from compare_classical_native_resources import comparison
from test_audit_classical_native_oracle_counts import fixture, write
from test_classical_candidate_terms import native


def measured(version=5):
    _, proofs, rows = fixture()
    descriptor = native(0, version=version, role_queries=[3] * 4)
    header = dict(decode_descriptor(descriptor), descriptor_bincode_hex=descriptor.hex(),
                  profile_descriptor_sha512=hashlib.sha512(descriptor).hexdigest(),
                  profile_id_sha512=hashlib.sha512(b'HasteBoots classical profile v1' + descriptor).hexdigest())
    for proof, row in zip(proofs, rows):
        for key in ('profile_id_sha512', 'profile_descriptor_sha512'):
            proof[key] = header[key]
        row.update(profile_id_sha512=header['profile_id_sha512'], xof_queries=7,
                   lookup_reciprocal_rejections=0, field_sampling_phases=2,
                   field_values_sampled=3, field_candidate_draws=4,
                   max_field_candidates_per_value=2, field_output_bytes=16,
                   max_field_phase_output_bytes=12, xof_output_bytes=200, max_xof_output=100)
    rejected = [dict(row, rejected=True, altered_statement_sha256='2' * 64) for row in rows]
    return header, proofs, rows, rejected


class NativeResourceComparisonTests(unittest.TestCase):
    def test_agreement_is_sample_only_and_accounts_for_fixed_profile_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            write(path, *measured())
            result = comparison(path, require_xof_output_counts=True)
            self.assertTrue(result['sample_conditional_comparison_passed'])
            self.assertEqual(len(result['executions']), 8)
            first = result['executions'][0]['comparisons']
            self.assertEqual(first['hash_queries']['observed'], 9)
            self.assertFalse(result['direct_calls_observed'])
            self.assertFalse(result['honest_activity_compared_to_verifier_ceilings'])
            self.assertFalse(result['deterministic_resource_bound_established'])
            self.assertFalse(result['security_qualified'])

    def test_missing_output_observations_remain_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            header, proofs, rows, rejected = measured()
            for row in rows + rejected:
                del row['xof_output_bytes']; del row['max_xof_output']
            write(path, header, proofs, rows, rejected)
            result = comparison(path)
            self.assertFalse(result['all_metrics_recorded'])
            self.assertFalse(result['sample_conditional_comparison_passed'])
            self.assertIsNone(result['executions'][0]['comparisons']['xof_output_bytes']['observed'])
            with self.assertRaises(ValueError):
                comparison(path, require_xof_output_counts=True)

    def test_resource_excess_and_crossed_stops_do_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            header, proofs, rows, rejected = measured()
            changed = copy.deepcopy(rows); changed[0]['hash_queries'] = 10**100
            write(path, header, proofs, changed, rejected)
            result = comparison(path)
            self.assertFalse(result['all_recorded_metrics_within_conditional_ceilings'])
            self.assertFalse(result['sample_conditional_comparison_passed'])
            changed = copy.deepcopy(rows)
            changed[0].update(lookup_reciprocal_rejections=1, field_candidate_draws=515,
                              max_field_candidates_per_value=513, field_output_bytes=2060,
                              max_field_phase_output_bytes=2056, xof_output_bytes=2188,
                              max_xof_output=2056)
            write(path, header, proofs, changed, rejected)
            result = comparison(path)
            self.assertTrue(result['all_recorded_metrics_within_conditional_ceilings'])
            self.assertFalse(result['all_executions_observed_in_stopped_domain'])
            self.assertFalse(result['sample_conditional_comparison_passed'])

    def test_v4_column_stop_is_unknown_without_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            write(path, *measured(version=4))
            result = comparison(path)
            self.assertIsNone(result['all_executions_observed_in_stopped_domain'])
            self.assertFalse(result['sample_conditional_comparison_passed'])
            header, proofs, rows, rejected = measured(version=4)
            for row in rows + rejected:
                row.update(column_sampling_phases=1, column_values_sampled=2,
                           column_candidate_draws=2, max_column_candidates_per_value=1)
            write(path, header, proofs, rows, rejected)
            self.assertTrue(comparison(path)['sample_conditional_comparison_passed'])
            rows[0].update(xof_queries=10, column_candidate_draws=10,
                           max_column_candidates_per_value=9, xof_output_bytes=224)
            write(path, header, proofs, rows, rejected)
            result = comparison(path)
            self.assertFalse(result['all_executions_observed_in_stopped_domain'])
            self.assertFalse(result['sample_conditional_comparison_passed'])

    def test_honest_work_is_not_charged_against_verifier_ceilings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            header, proofs, rows, rejected = measured()
            activities = []
            for index in range(5):
                proof = proofs[max(0, index - 1)]
                row = dict(rows[max(0, index - 1)])
                del row['hash_input_bytes']; del row['max_hash_input']
                row.update(stage='setup' if index == 0 else 'prove',
                           ordinal=None if index == 0 else index - 1,
                           proof_sha256=None if index == 0 else proof['proof_sha256'],
                           trusted_setup_sha256=proof['trusted_setup_sha256'],
                           hash_input_bytes_recorded=False, hash_queries=10**100)
                activities.append(row)
            write(path, header, proofs, rows, rejected, activities)
            result = comparison(path, require_xof_output_counts=True)
            self.assertTrue(result['sample_conditional_comparison_passed'])
            self.assertEqual(len(result['executions']), 8)
            self.assertFalse(result['honest_activity_compared_to_verifier_ceilings'])

    def test_log_binding_and_completion_checks_are_mandatory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'run.log'
            header, proofs, rows, rejected = measured()
            write(path, header, proofs, rows, rejected[:-1])
            with self.assertRaises(ValueError):
                comparison(path)
            rows[0]['profile_id_sha512'] = '0' * 128
            write(path, header, proofs, rows, rejected)
            with self.assertRaises(ValueError):
                comparison(path)


if __name__ == '__main__':
    unittest.main()
