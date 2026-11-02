from fractions import Fraction as F
import sys
import unittest

from classical_work_cost import exact_rational, exact_rational_text, composed_report, expected_work_bound


class ExactRationalTextTests(unittest.TestCase):
    def test_native_denominators_round_trip_without_global_limit_change(self):
        before = sys.get_int_max_str_digits()
        for value in (F((2**27-1)**512, 2**(31*512)), F(1, 10**5000), F(10**5000+1), F(-1, 10**5000)):
            text = exact_rational_text(value)
            self.assertGreater(len(text), 4300)
            self.assertEqual(exact_rational(text), value)
            self.assertEqual(exact_rational_text(exact_rational(text)), text)
        self.assertEqual(sys.get_int_max_str_digits(), before)

    def test_small_formatting_and_existing_exact_notations_remain_compatible(self):
        for value in (F(0), F(2), F(-2), F(1, 3), F(-7, 4)):
            self.assertEqual(exact_rational_text(value), str(value))
        for text in ('1/3', '-7/4', '1.25', '1e-20', '+12'):
            self.assertEqual(exact_rational(text), F(text))
        for value in (True, 0.5, None, 'not a rational'):
            with self.assertRaises(ValueError):
                exact_rational(value)

    def test_large_terms_flow_through_composition_and_expected_sum(self):
        tiny = F(1, 10**5000)
        zero = dict(constant=0, linear=0, quadratic=0)
        report = composed_report(dict(phase=dict(constant=1+tiny, linear=tiny, quadratic=0),
                                      merkle=zero, xof=zero))
        self.assertEqual(exact_rational(report['components']['phase']['constant']), 1+tiny)
        expected = expected_work_bound([tiny], constant=1+tiny, success_probability_lower_bound=F(1, 2))
        self.assertEqual(exact_rational(expected['expected_work_per_success_bound']), 1)


if __name__ == '__main__':
    unittest.main()
