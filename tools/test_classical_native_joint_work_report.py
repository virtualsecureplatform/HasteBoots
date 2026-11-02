from copy import deepcopy
from fractions import Fraction
import unittest

from classical_candidate_terms import candidate_terms
from classical_window_work import native_stopped_joint_work_report
from polyfrim_opening_terms import encode
from test_classical_candidate_terms import native


class NativeJointWorkReportTests(unittest.TestCase):
    def setUp(self):
        self.candidate = candidate_terms(native(0, version=5))
        # A deliberately large synthetic stop error makes failure to charge
        # repeated submissions observable in the optimizer's final work bound.
        self.candidate['verifier_xof_output_envelope']['additional_sampler_stop_union'] = encode(Fraction(1, 4))
        self.offsets = dict(honest_hash_outputs=0, honest_xof_outputs=0, honest_window_values=0)
        self.other = dict(constant=0, linear=Fraction(1, 32), quadratic=0)

    def test_stops_are_charged_before_optimizing_repeated_submissions(self):
        report = native_stopped_joint_work_report(self.candidate,
            **self.offsets, other_failure_polynomial=self.other)
        phase = report['components']['phase']
        self.assertEqual(Fraction(phase['linear']), Fraction(9, 32))
        self.assertEqual(report['additional_verifier_sampler_stop_per_submission'], '1/4')
        for submissions in (1, 2, 10**20):
            delta = Fraction(phase['linear'])*submissions-self.other['linear']*submissions
            self.assertEqual(delta, Fraction(submissions, 4))
        self.assertLessEqual(Fraction(report['minimum_work_per_success_bound']), Fraction(32, 9))
        self.assertFalse(report['conditional_work_target_met'])
        self.assertFalse(report['security_qualified'])
        self.assertFalse(report['other_failure_bound_verified'])

    def test_unknown_remaining_coverage_can_only_give_trivial_bound(self):
        report = native_stopped_joint_work_report(self.candidate,
            **self.offsets, other_failure_polynomial=dict(constant=1, linear=0, quadratic=0))
        self.assertEqual(Fraction(report['minimum_work_per_success_bound']), 1)
        self.assertFalse(report['conditional_work_target_met'])
        self.assertFalse(report['protocol_bound_established'])

    def test_remaining_failure_polynomial_is_mandatory_and_exact(self):
        with self.assertRaises(TypeError):
            native_stopped_joint_work_report(self.candidate, **self.offsets)
        for invalid in ({}, dict(linear=0), dict(self.other, extra=0),
                        dict(self.other, linear=True), dict(self.other, linear=0.5),
                        dict(self.other, constant=-1)):
            with self.assertRaises(ValueError):
                native_stopped_joint_work_report(self.candidate,
                    **self.offsets, other_failure_polynomial=invalid)

    def test_non_probability_stop_bound_is_rejected(self):
        candidate = deepcopy(self.candidate)
        for stop in (Fraction(-1, 2), Fraction(3, 2)):
            candidate['verifier_xof_output_envelope']['additional_sampler_stop_union'] = {
                'exact': {'numerator_hex': hex(stop.numerator), 'denominator_hex': hex(stop.denominator)}}
            with self.assertRaises(ValueError):
                native_stopped_joint_work_report(candidate,
                    **self.offsets, other_failure_polynomial=self.other)


if __name__ == '__main__':
    unittest.main()
