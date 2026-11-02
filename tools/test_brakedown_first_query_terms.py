from fractions import Fraction as F
import unittest

from brakedown_opening_terms import first_query_terms, opening_terms


class FirstQueryTermsTests(unittest.TestCase):
    geometry = (3, 8, 1, 8, 2, 4, 2013265921)

    def terms(self, rows, families, exceptions=F(0), coverage=F(0), geometry=None):
        return first_query_terms(*(geometry or self.geometry),
            expected_false_row_queries=rows, expected_bad_column_families=families,
            oracle_exception_bound=exceptions, coverage_failure_bound=coverage)

    def test_separate_expected_counts_and_explicit_failures(self):
        row = self.terms(F(3, 2), F(7, 3), F(1, 2**256), F(1, 1000))
        self.assertEqual(row['row_contribution'], F(3, 2)*F(32*33, 2013265921**8))
        self.assertEqual(row['column_contribution'], F(7, 3)*F(21, 32)**4)
        self.assertEqual(row['total'], sum(row[key] for key in (
            'row_contribution', 'column_contribution',
            'oracle_exception_bound', 'coverage_failure_bound')))
        single = self.terms(1, 1)
        self.assertEqual(single['total'], opening_terms(*self.geometry)['total'])
        self.assertEqual(self.terms(0, 0)['total'], 0)
        self.assertFalse(row['input_bounds_verified'])
        self.assertFalse(row['attacker_work_coupling_established'])
        self.assertFalse(row['whole_proof_security_certified'])

    def test_adaptive_stopping_uses_expectation_without_query_cutoff(self):
        geometry = (3, 8, 1, 8, 2, 1, 2013265921)
        probability = F(21, 32)
        # An abstract independent-family experiment stops on its first miss.
        # No deterministic query ceiling: success is certain, E[N]=1/probability.
        self.assertEqual(self.terms(0, 1/probability, geometry=geometry)['total'], 1)
        # Independent finite stopping control, including the survival weights.
        attempts = 3
        expected = sum((1-probability)**j for j in range(attempts))
        self.assertEqual(self.terms(0, expected, geometry=geometry)['total'],
                         1-(1-probability)**attempts)

    def test_missing_coverage_is_not_implicitly_zero(self):
        self.assertEqual(self.terms(0, 0, coverage=1)['total'], 1)
        with self.assertRaises(TypeError):
            first_query_terms(*self.geometry, expected_false_row_queries=1,
                expected_bad_column_families=1, oracle_exception_bound=0)
        with self.assertRaises(TypeError):
            first_query_terms(*self.geometry, expected_false_row_queries=1,
                expected_bad_column_families=1, coverage_failure_bound=0)

    def test_no_query_cap_and_invalid_bounds_reject(self):
        self.assertEqual(self.terms(2**512, 2**512)['total'], 1)
        for value in (True, 0.5, '1', -1, F(-1, 3)):
            with self.assertRaises(ValueError):
                self.terms(value, 1)
        for kw in ({'exceptions': F(3, 2)}, {'coverage': F(3, 2)}):
            with self.assertRaises(ValueError):
                self.terms(1, 1, **kw)


if __name__ == '__main__':
    unittest.main()
