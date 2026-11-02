from fractions import Fraction as F
import unittest
from classical_parent_phases import packed_stages


class ParentPhaseTests(unittest.TestCase):
    def test_native_counts_and_role_geometry(self):
        for prime, width, count, variables in [
                (2013265921, 8, 278, [18, 21, 8, 11]),
                (2013265921, 16, 250, [17, 21, 7, 11]),
                (18446744069414584321, 4, 432, [19, 21, 9, 11]),
                (18446744069414584321, 8, 390, [18, 21, 8, 11])]:
            row = packed_stages(prime, width, schedule_version=4)
            self.assertEqual(row['phase_count'], count)
            self.assertEqual(row['role_variables'], variables)
            union = sum(p['count']*F(p['error']) for p in row['phases'])
            self.assertEqual(F(row['conditional_phase_union']), min(F(1), union))
            self.assertFalse(row['security_qualified'])
            self.assertFalse(row['query_count_selected'])

    def test_fixed_residual_phase_counts_do_not_multiply_constraints(self):
        row = packed_stages(2013265921, 8, schedule_version=4)
        folds = [p for p in row['phases'] if p['phase']=='fixed_residual_fold']
        self.assertEqual([p['count'] for p in folds], [36, 8, 18, 8])
        self.assertTrue(all(F(p['error'])==F(15, 2013265921)**8 for p in folds))

    def test_compression_has_no_response_polynomial_count_factor(self):
        row = packed_stages(2013265921, 8, schedule_version=4)
        folds = [p for p in row['phases'] if p['phase']=='coefficient_fold']
        self.assertEqual([p['count'] for p in folds], [63, 14, 56])
        self.assertTrue(all(F(p['error'])==F(15, 2013265921)**8 for p in folds))

    def test_rejects_old_schedules_and_unselected_shapes(self):
        for prime, width, version in [(2013265921, 8, x) for x in [1, 2, 3, True, 4.0]] + [
                (97, 8, 4), (2013265921, 4, 4), (True, 8, 4)]:
            with self.assertRaises(ValueError):
                packed_stages(prime, width, schedule_version=version)


if __name__ == '__main__':
    unittest.main()
