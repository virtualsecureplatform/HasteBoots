import unittest
from fractions import Fraction as F
from classical_work_cost import all_trials_envelope, composed_report, minimum_work, report
from hash_query_budget import global_work_coefficients, xof_work_coefficients


class ClassicalWorkCostTests(unittest.TestCase):
    def test_composition_matches_union_not_individual_thresholds(self):
        components = dict(
            phase=dict(constant=0, linear=F(1, 2**128), quadratic=0),
            merkle=global_work_coefficients(512, 10, 3, 7, 2),
            xof=xof_work_coefficients(512, 8, 4, 32, 9))
        result = composed_report(components)
        constant = sum(c['constant'] for c in components.values())
        coefficients = [sum(c[key] for c in components.values()) for key in ('linear', 'quadratic')]
        self.assertEqual(result['minimum_work_per_success_bound'],
                         report(coefficients, 128, constant)['minimum_work_per_success_bound'])
        self.assertFalse(result['conditional_work_target_met'])
        self.assertFalse(result['security_qualified'])
        self.assertFalse(result['protocol_bound_established'])
        self.assertEqual(set(result['components']), {'phase', 'merkle', 'xof'})

    def test_composition_requires_explicit_families_and_exact_terms(self):
        zero = dict(constant=0, linear=0, quadratic=0)
        for components in [{}, dict(phase=zero, merkle=zero),
                dict(phase=zero, merkle=zero, xof=dict(zero, other=1)),
                dict(phase=zero, merkle=zero, xof=dict(zero, linear=0.5))]:
            with self.assertRaises(ValueError):
                composed_report(components)

    def test_all_trials_includes_every_submission(self):
        bound = all_trials_envelope(F(1, 101), [(3, F(2, 101)), (2, F(1, 103))],
                                    {'hash': 11, 'xof': 7}, {'hash': 17, 'xof': 19})
        expected = F(7, 101) + F(2, 103)
        self.assertEqual(bound['linear_phase_error'], expected)
        self.assertFalse(bound['protocol_bound_established'])
        for work in range(1, 30):
            for submissions in range(work + 1):
                for adversarial in range(work + 1):
                    self.assertLessEqual(adversarial*F(1, 101) + submissions*(F(6, 101)+F(2, 103)), work*expected)
                    for name, cap, offset in [('hash', 11, 17), ('xof', 7, 19)]:
                        resource = bound['resources'][name]
                        self.assertLessEqual(adversarial + cap*submissions + offset,
                                             resource['per_work']*work + resource['offset'])

    def test_all_trials_rejects_unjustified_input_types(self):
        for phases, resources, offsets in [([(True, F(1, 2))], {}, {}),
                ([(1, 2)], {}, {}), ([(1, 0.5)], {}, {}),
                ([], {'hash': 1}, {}), ([], {'hash': True}, {'hash': 0})]:
            with self.assertRaises(ValueError):
                all_trials_envelope(F(1, 2), phases, resources, offsets)

    def test_original_closed_forms(self):
        self.assertEqual(minimum_work([F(1, 2**128)])[0], 2**128)
        self.assertEqual(minimum_work([0, F(1, 2**256)])[0], 2**128)
        self.assertFalse(report([F(1, 2**128), F(1, 2**256)], 128)['conditional_work_target_met'])

    def test_constant_can_move_optimum_to_smallest_attack(self):
        self.assertEqual(minimum_work([0, F(1, 16)], F(1, 4))[0], F(16, 5))
        self.assertEqual(minimum_work([0], F(1, 16)), (F(16), None))
        self.assertEqual(minimum_work([0], F(1, 16), 8), (F(128), None))
        self.assertEqual(minimum_work([0], 2, 8), (F(8), (8, 8)))

    def test_exhaustive_integer_budgets_with_constants_and_cubic_terms(self):
        for constant in [F(0), F(1, 8), F(3, 4)]:
            for minimum in [1, 3, 8]:
                for a in range(1, 4):
                    for b in range(3):
                        for c in range(3):
                            coefficients = [F(a, 997), F(b, 997), F(c, 997)]
                            expected = min(F(t) / min(F(1), constant + sum(x*t**k
                                for k, x in enumerate(coefficients, 1))) for t in range(minimum, 1001))
                            self.assertEqual(minimum_work(coefficients, constant, minimum)[0], expected)

    def test_invalid_models(self):
        for coefficients, constant, minimum in [([0], 0, 1), ([1], -1, 1),
                ([1], 0.1, 1), ([1], True, 1), ([1], 0, 0), ([1], 0, True)]:
            with self.assertRaises(ValueError):
                minimum_work(coefficients, constant, minimum)


if __name__ == '__main__':
    unittest.main()
