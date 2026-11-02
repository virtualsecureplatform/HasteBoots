"""Exhaustive small-field checks of the packed public-table equality term."""
from fractions import Fraction
from itertools import product
import unittest

from packed_budget import fixed_table_equality_bound, canonical_ntt_algebraic_bounds


def interpolate(values, point, prime):
    # Independent scalar Lagrange interpolation on consecutive nodes.
    result = 0
    for i, value in enumerate(values):
        numerator, denominator = 1, 1
        for j in range(len(values)):
            if i != j:
                numerator = numerator * (point-j) % prime
                denominator = denominator * (i-j) % prime
        result += value * numerator * pow(denominator, -1, prime)
    return result % prime


def fold(table, challenges, prime):
    width = len(challenges)
    result = []
    for offset in range(0, len(table), 2*width):
        pair = table[offset:offset+2*width]
        # Production nodes alternate between zero/one Boolean input blocks.
        nodes = [pair[bit*width+lane]
                 for lane in range(width) for bit in (0, 1)]
        result.extend(interpolate(nodes, point, prime) for point in challenges)
    return result


class PackedEqualityBudgetTests(unittest.TestCase):
    def test_independent_tensor_row_points(self):
        # Every nonzero bivariate multilinear polynomial over F_3, with two
        # independent row points. A dense-vector linear-test bound 1/p^k
        # would be wrong here: (x-a)(y-b) vanishes on five of nine points.
        maximum = Fraction()
        for coefficients in product(range(3), repeat=4):
            if not any(coefficients):
                continue
            a,b,c,d = coefficients
            zeros = sum((a+b*x+c*y+d*x*y)%3 == 0
                        for x,y in product(range(3), repeat=2))
            error = Fraction(zeros, 9)**2
            self.assertLessEqual(error, Fraction(2,3)**2)
            maximum = max(maximum, error)
        self.assertEqual(maximum, Fraction(25,81))
        self.assertGreater(maximum, Fraction(1,3)**2)

    def test_ntt_boundaries_and_native_dimensions(self):
        terms=canonical_ntt_algebraic_bounds(2013265921,8,18,1024,11)
        self.assertEqual(terms['row_identity'],11*Fraction(11,2013265921)**8)
        self.assertEqual(terms['coefficient_compression'],
                         11*16*7*Fraction(15,2013265921)**8)
        # One row has an exact local transform check, with no random row error.
        self.assertEqual(canonical_ntt_algebraic_bounds(17,2,2,8)['row_identity'],0)
        self.assertEqual(canonical_ntt_algebraic_bounds(17,2,2,2)['coefficient_compression'],0)
        for args in [(17,3,3,8),(17,2,1,8),(17,2,2,6),(17,2,2,8,0)]:
            with self.subTest(args=args),self.assertRaises(ValueError):
                canonical_ntt_algebraic_bounds(*args)

    def test_all_nonzero_one_round_tables(self):
        # Every F_5 table with two packed lanes, all independent lane coins.
        bound = fixed_table_equality_bound(5, 2, 1)
        maximum = Fraction()
        for table in product(range(5), repeat=4):
            if not any(table):
                continue
            zeros = sum(not any(fold(table, coins, 5))
                        for coins in product(range(5), repeat=2))
            error = Fraction(zeros, 25)
            self.assertLessEqual(error, bound)
            maximum = max(maximum, error)
        # A degree-three polynomial with three distinct roots attains the term.
        self.assertEqual(maximum, bound)
        self.assertEqual(bound, Fraction(9, 25))

    def test_two_rounds_include_intermediate_collapse(self):
        bound = fixed_table_equality_bound(5, 2, 2)
        challenges = list(product(range(5), repeat=2))
        for table in [(1, 0, 0, 0, 0, 0, 0, 0),
                      (0, 0, 0, 1, 0, 0, 0, 1),
                      (1, 2, 3, 4, 4, 3, 2, 1)]:
            zeros = 0
            for first in challenges:
                intermediate = fold(table, first, 5)
                for second in challenges:
                    zeros += not any(fold(intermediate, second, 5))
            self.assertLessEqual(Fraction(zeros, 625), bound)

    def test_zero_variables_and_invalid_geometry(self):
        self.assertEqual(fixed_table_equality_bound(5, 2, 0), 0)
        self.assertEqual(fixed_table_equality_bound(5, 2, 100), 1)
        for args in [(5, 3, 1), (5, 0, 1), (5, 2, -1), (True, 1, 1),
                     (5, True, 1), (5, 2, True)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                fixed_table_equality_bound(*args)


if __name__ == '__main__':
    unittest.main()
