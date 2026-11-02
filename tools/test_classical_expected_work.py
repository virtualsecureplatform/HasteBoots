from fractions import Fraction as F
import unittest

from classical_work_cost import expected_work_bound, minimum_work, report


class ExpectedWorkTests(unittest.TestCase):
    def test_birthday_early_stopping_is_not_the_fixed_budget_ratio(self):
        for support in (16, 256):
            survival = F(1)
            expected = F(1)
            for draws in range(1, support+1):
                survival *= F(support-draws+1, support)
                expected += survival
            coefficients = [0, F(1, 2*support)]
            budget, _ = minimum_work(coefficients)
            self.assertLess(expected, budget)
            row = expected_work_bound(coefficients, success_probability_lower_bound=1)
            self.assertLessEqual(F(row['minimum_expected_work_bound']), expected)
            self.assertEqual(row['minimum_expected_work_bound'], row['expected_work_per_success_bound'])
            fixed = report(coefficients, 128)
            self.assertEqual(fixed['work_measure'], 'fixed_maximum_budget')
            self.assertFalse(fixed['unrestricted_expected_work_certified'])

    def test_closed_form_sum_matches_small_tail_enumeration(self):
        for coefficients in ([F(1, 16)], [0, F(1, 16)], [F(1, 20), F(1, 40), F(1, 80)]):
            for constant in (F(0), F(1, 8)):
                for probability in (F(1, 4), F(2, 3), F(1)):
                    for minimum in (1, 3):
                        row = expected_work_bound(coefficients, constant=constant,
                            minimum_budget=minimum, success_probability_lower_bound=probability)
                        stop = row['first_budget_reaching_success_floor']
                        direct = minimum*probability+sum(
                            max(F(0), probability-constant-sum(a*t**k for k, a in enumerate(coefficients, 1)))
                            for t in range(minimum, stop))
                        self.assertEqual(F(row['minimum_expected_work_bound']), direct)
                        self.assertEqual(F(row['expected_work_per_success_bound']), direct/probability)

    def test_large_security_scale_uses_exact_sums_without_budget_iteration(self):
        scale = 1 << 128
        row = expected_work_bound([0, F(1, scale**2)], success_probability_lower_bound=1)
        self.assertEqual(row['first_budget_reaching_success_floor'], scale)
        exact = F(scale)-F((scale-1)*scale*(2*scale-1), 6*scale**2)
        self.assertEqual(F(row['minimum_expected_work_bound']), exact)
        self.assertFalse(row['security_qualified'])
        low = expected_work_bound([0, F(1, scale**2)], success_probability_lower_bound=F(1, 4))
        self.assertLess(F(low['expected_work_per_success_bound']), exact)

    def test_success_floor_and_minimum_cost_premises_are_explicit(self):
        with self.assertRaises(TypeError):
            expected_work_bound([F(1, 10)])
        for value in (0, -1, 2, True, 0.5):
            with self.assertRaises(ValueError):
                expected_work_bound([F(1, 10)], success_probability_lower_bound=value)
        with self.assertRaises(ValueError):
            expected_work_bound([0], constant=F(1, 4), success_probability_lower_bound=F(1, 2))
        row = expected_work_bound([0], constant=F(1, 2), minimum_budget=7,
                                  success_probability_lower_bound=F(1, 4))
        self.assertEqual(F(row['minimum_expected_work_bound']), F(7, 4))
        self.assertEqual(F(row['expected_work_per_success_bound']), 7)


if __name__ == '__main__':
    unittest.main()
