from copy import deepcopy
import unittest

from classical_brakedown_resources import call_envelope
from classical_candidate_terms import candidate_terms
from test_classical_candidate_terms import native


class BrakedownCallResourcesTests(unittest.TestCase):
    def test_all_native_roles_reconcile_existing_pcs_request_and_hash_caps(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for version in (4, 5):
                candidate = candidate_terms(native(0, prime, degree, width, version))
                for role in range(4):
                    row = call_envelope(candidate['profile'], role)
                    calls = candidate['shared_stage_schedule']['role_opening_call_ceilings'][role]
                    old = candidate['pcs_xof_resource_envelope']['roles'][role]
                    self.assertEqual(row['xof_queries_upper_bound']*calls, old['xof_queries'])
                    self.assertEqual(row['column_output_bytes_upper_bound']*calls, old['byte_challenge_output_bytes'])
                    self.assertEqual(row['hash_outputs_upper_bound']*calls,
                        candidate['roles'][role]['pcs_total_hash_outputs_upper_bound'])
                    profile = candidate['profile']
                    self.assertEqual(row['field_coefficients_upper_bound'],
                        profile['role_widths'][role]**2*2**profile['role_left_vars'][role])
                    self.assertFalse(row['hash_bound_requires_sampler_stops'])
                    self.assertEqual(row['column_bound_requires_analysis_stop'], version == 4)

    def test_only_stopped_resources_depend_on_analysis_limits(self):
        profile = candidate_terms(native(0, version=4))['profile']
        base = call_envelope(profile, 0, field_candidate_limit=8, column_candidate_limit=2)
        larger = call_envelope(profile, 0, field_candidate_limit=16, column_candidate_limit=4)
        self.assertEqual(base['hash_outputs_upper_bound'], larger['hash_outputs_upper_bound'])
        self.assertEqual(2*base['field_raw_output_bytes_upper_bound'], larger['field_raw_output_bytes_upper_bound'])
        self.assertEqual(2*base['column_xof_queries_upper_bound'], larger['column_xof_queries_upper_bound'])
        self.assertEqual(base['xof_queries_upper_bound'], 2+base['column_xof_queries_upper_bound'])
        self.assertFalse(base['whole_native_resource_bound_established'])

    def test_unsupported_roles_schedules_limits_and_overflow_reject(self):
        profile = candidate_terms(native(0, version=5))['profile']
        for args in [dict(role=True), dict(role=4), dict(role=0, field_candidate_limit=0),
                     dict(role=0, column_candidate_limit=True)]:
            with self.assertRaises(ValueError):
                call_envelope(profile, **args)
        for key, value in [('backend', 'Polyfrim'), ('descriptor_version', 3), ('prime', '17')]:
            with self.assertRaises(ValueError):
                call_envelope(dict(profile, **{key: value}), 0)
        changed = deepcopy(profile)
        changed['role_queries'][0] = 2**63
        with self.assertRaises(ValueError):
            call_envelope(changed, 0)
        changed['descriptor_version'] = 4
        result = call_envelope(changed, 0)
        self.assertEqual(result['ordered_draws'], 2**63)
        self.assertEqual(result['transported_columns_upper_bound'], result['codeword_blocks'])
        changed = deepcopy(profile)
        changed['role_widths'][0] = 2**63
        with self.assertRaisesRegex(ValueError, 'coefficient count'):
            call_envelope(changed, 0)


if __name__ == '__main__':
    unittest.main()
