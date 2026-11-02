from fractions import Fraction as F
import unittest

from classical_work_cost import exact_rational
from classical_candidate_terms import candidate_terms
from classical_window_work import (native_first_query_field_stop_polynomial,
                                   native_first_query_field_work_report)
from test_classical_candidate_terms import native


class NativeFirstQueryFieldWorkTests(unittest.TestCase):
    def test_twenty_profiles_charge_all_first_inputs_including_offsets(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for version in (4, 5):
                for backend in range(5):
                    with self.subTest(prime=prime, version=version, backend=backend):
                        candidate = candidate_terms(native(backend, prime, degree, width, version))
                        row = native_first_query_field_stop_polynomial(candidate, honest_xof_outputs=7)
                        count = candidate['sampler_resource_envelope']['coefficient_count_ceiling']
                        limit = candidate['sampler_resource_envelope']['candidate_limit_per_coefficient']
                        support = 1 << (int(prime)-1).bit_length()
                        local = min(F(1), count*F(support-int(prime), support)**limit)
                        rate = 1+candidate['verifier_xof_resource_envelope']['totals']['xof_queries']
                        for budget in (0, 1, 100):
                            self.assertEqual(row['constant']+row['linear']*budget, local*(rate*budget+7))
                        self.assertEqual(row['quadratic'], 0)
                        self.assertFalse(row['complete_request_coverage_established'])
                        self.assertTrue(row['production_loops_unchanged'])
                        full = native_first_query_field_work_report(candidate,
                            honest_hash_outputs=0, honest_xof_outputs=7, honest_window_values=0,
                            other_failure_polynomial=dict(constant=1, linear=0, quadratic=0),
                            success_probability_lower_bound=F(1, 2))
                        self.assertEqual(exact_rational(full['components']['phase']['constant']), 1+row['constant'])
                        self.assertEqual(exact_rational(full['components']['phase']['linear']), row['linear'])
                        self.assertFalse(full['conditional_fixed_budget_target_met'])
                        self.assertFalse(full['conditional_expected_work_target_met'])


    def test_composition_adds_global_field_term_once_and_keeps_measures_separate(self):
        candidate = candidate_terms(native(0, version=5))
        # Unknown remaining coverage forces a trivial result, preserving an
        # explicit open proof obligation in both resource interpretations.
        report = native_first_query_field_work_report(candidate,
            honest_hash_outputs=0, honest_xof_outputs=7, honest_window_values=0,
            other_failure_polynomial=dict(constant=1, linear=F(1, 8), quadratic=0),
            success_probability_lower_bound=F(1, 2))
        stop = native_first_query_field_stop_polynomial(candidate, honest_xof_outputs=7)
        self.assertEqual(exact_rational(report['components']['phase']['constant']), 1+stop['constant'])
        self.assertEqual(exact_rational(report['components']['phase']['linear']), F(1, 8)+stop['linear'])
        self.assertEqual(report['work_measure'], 'fixed_maximum_budget')
        self.assertEqual(report['expected_work']['work_measure'], 'expected_charged_work_with_supplied_success_floor')
        self.assertEqual(F(report['minimum_budget_per_success_bound']), 1)
        self.assertEqual(F(report['expected_work']['expected_work_per_success_bound']), 1)
        self.assertFalse(report['conditional_fixed_budget_target_met'])
        self.assertFalse(report['conditional_expected_work_target_met'])
        self.assertFalse(report['automatic_column_or_lookup_stop_charge'])
        self.assertFalse(report['security_qualified'])

    def test_budget_target_does_not_promote_the_expected_work_target(self):
        candidate = candidate_terms(native(0, version=5))
        report = native_first_query_field_work_report(candidate,
            honest_hash_outputs=0, honest_xof_outputs=0, honest_window_values=0,
            other_failure_polynomial=dict(constant=0, linear=F(1, 1 << 129), quadratic=0),
            success_probability_lower_bound=F(1, 2))
        # Synthetic supplied phase coefficient: a control of resource measures,
        # not an established native protocol phase-error bound.
        self.assertTrue(report['conditional_fixed_budget_target_met'])
        self.assertFalse(report['conditional_expected_work_target_met'])
        self.assertFalse(report['security_qualified'])
        self.assertFalse(report['other_failure_bound_verified'])

    def test_remaining_failure_and_success_floor_cannot_be_omitted(self):
        candidate = candidate_terms(native(0, version=5))
        args = dict(honest_hash_outputs=0, honest_xof_outputs=0, honest_window_values=0,
                    other_failure_polynomial=dict(constant=1, linear=0, quadratic=0),
                    success_probability_lower_bound=1)
        for name in args:
            missing = args.copy()
            del missing[name]
            with self.assertRaises(TypeError):
                native_first_query_field_work_report(candidate, **missing)
        for invalid in (-1, True, 0.5):
            with self.assertRaises(ValueError):
                native_first_query_field_stop_polynomial(candidate, honest_xof_outputs=invalid)
        for invalid in (0, True, 0.5):
            with self.assertRaises(ValueError):
                native_first_query_field_work_report(candidate,
                    **dict(args, success_probability_lower_bound=invalid))


if __name__ == '__main__':
    unittest.main()
