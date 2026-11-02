from copy import deepcopy
from fractions import Fraction as F
import unittest

from classical_candidate_terms import candidate_terms
from classical_sampler_resources import column_rejection_envelope
from classical_window_work import (native_first_query_field_stop_polynomial,
    native_first_query_sampler_stop_polynomial, native_first_query_sampler_work_report)
from classical_work_cost import exact_rational
from test_classical_candidate_terms import native, rational


class NativeSamplerFirstQueriesTests(unittest.TestCase):
    def test_twenty_profiles_preserve_v5_and_dominate_all_v4_role_tails(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for version in (4, 5):
                for backend in range(5):
                    with self.subTest(prime=prime, version=version, backend=backend):
                        candidate = candidate_terms(native(backend, prime, degree, width, version))
                        row = native_first_query_sampler_stop_polynomial(candidate, honest_xof_outputs=7)
                        field = native_first_query_field_stop_polynomial(candidate, honest_xof_outputs=7)
                        self.assertEqual(row['field_local_bound'], field['per_eligible_first_input'])
                        if backend == 0 and version == 4:
                            geometry = row['column_geometry']
                            self.assertEqual(geometry['domain'], max(geometry['role_domains']))
                            for domain, quota in zip(geometry['role_domains'], geometry['role_quotas']):
                                local = column_rejection_envelope(domain, quota, geometry['rejected_candidate_limit'])
                                self.assertLessEqual(rational(local['first_excess_union']), row['column_local_bound'])
                        else:
                            self.assertIsNone(row['column_geometry'])
                            self.assertEqual(row['column_local_bound'], 0)
                            for key in ('constant', 'linear', 'quadratic'):
                                self.assertEqual(row[key], field[key])
                        self.assertEqual(row['joint_local_bound'], max(row['field_local_bound'], row['column_local_bound']))
                        rate = 1+candidate['verifier_xof_resource_envelope']['totals']['xof_queries']
                        self.assertEqual(row['constant']+13*row['linear'], row['joint_local_bound']*(7+13*rate))
                        full = native_first_query_sampler_work_report(candidate,
                            honest_hash_outputs=0, honest_xof_outputs=7, honest_window_values=0,
                            other_failure_polynomial=dict(constant=1, linear=F(1, 8), quadratic=0),
                            success_probability_lower_bound=F(1, 2))
                        self.assertEqual(exact_rational(full['components']['phase']['constant']), 1+row['constant'])
                        self.assertEqual(exact_rational(full['components']['phase']['linear']), F(1, 8)+row['linear'])
                        self.assertEqual(full['automatic_column_stop_charge'], backend == 0 and version == 4)
                        self.assertFalse(full['automatic_lookup_stop_charge'])
                        self.assertFalse(full['security_qualified'])
                        self.assertFalse(full['conditional_expected_work_target_met'])

    def test_geometry_preconditions_and_unknown_profiles_reject(self):
        candidate = candidate_terms(native(0, version=4))
        bad = deepcopy(candidate)
        bad['roles'][0]['per_opening']['encoded_blocks'] = 3
        with self.assertRaises(ValueError):
            native_first_query_sampler_stop_polynomial(bad, honest_xof_outputs=0)
        bad = deepcopy(candidate)
        bad['roles'][0]['column_sampler_resource_envelope']['per_call']['candidate_limit_per_draw'] = 7
        with self.assertRaises(ValueError):
            native_first_query_sampler_stop_polynomial(bad, honest_xof_outputs=0)
        for field, value in [('descriptor_version', 3), ('backend', 'unreviewed')]:
            bad = deepcopy(candidate)
            bad['profile'][field] = value
            with self.assertRaises(ValueError):
                native_first_query_sampler_stop_polynomial(bad, honest_xof_outputs=0)
        with self.assertRaises(TypeError):
            native_first_query_sampler_stop_polynomial(candidate)


if __name__ == '__main__':
    unittest.main()
