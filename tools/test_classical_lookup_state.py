"""Finite-field checks of conditional lookup lemmas and their premises.

These are algebraic model checks, not a security certificate for the protocol.
"""

from itertools import product
from fractions import Fraction
import unittest
from packed_budget import lookup_first_retry_bound


class LookupStateTests(unittest.TestCase):
    def test_first_retry_cap_with_duplicate_compressions_and_zero(self):
        p = 7
        for rows in range(1, 5):
            bound = lookup_first_retry_bound(p, 1, rows, 3)
            self.assertEqual(bound['scalar_phases_without_retry'], 6)
            for table in product(range(p), repeat=rows):
                rejected = {0} | {(-value) % p for value in table}
                probability = Fraction(len(rejected), p)
                self.assertLessEqual(probability, bound['per_fresh_reciprocal'])
                self.assertLessEqual(1-(1-probability)**3, bound['first_retry_union'])
        self.assertEqual(lookup_first_retry_bound(p, 1, 2, 0)['first_retry_union'], 0)
        for geometry in [(7, 1, 6, 1), (7, 1, 2, True), (7, 0, 2, 1)]:
            with self.assertRaises(ValueError):
                lookup_first_retry_bound(*geometry)

    def test_invalid_tuple_hash_exception_degree(self):
        p = 7
        table = [(0, 1, 2), (3, 4, 5)]

        def compress(values, y):
            return sum(value*pow(y, i, p) for i, value in enumerate(values)) % p

        for source in product(range(p), repeat=3):
            if source in table:
                continue
            exceptions = sum(any(compress(source, y) == compress(row, y) for row in table)
                             for y in range(p))
            self.assertLessEqual(exceptions, len(table)*(len(source)-1))

    def test_outside_pole_survives_arbitrary_public_multiplicities(self):
        p, table, logical = 7, [0, 1], 2
        for source in product(range(p), repeat=logical):
            if all(value in table for value in source):
                continue
            for multiplicities in product(range(p), repeat=len(table)):
                zeros = 0
                for r in range(1, p):
                    # Public poles are rejected; source-only poles force a
                    # false reciprocal identity and cannot be an escape.
                    if any((r+value) % p == 0 for value in table+list(source)):
                        continue
                    discrepancy = (sum(pow((r+value) % p, -1, p) for value in source)
                        - sum(m*pow((r+value) % p, -1, p)
                              for m, value in zip(multiplicities, table))) % p
                    zeros += discrepancy == 0
                self.assertLessEqual(zeros, logical+len(table)-1)

    def test_characteristic_and_excluded_zero_are_necessary_premises(self):
        p = 7
        # L=p repetitions of one invalid value disappear in characteristic p.
        for r in range(1, p):
            if (r+2) % p:
                self.assertEqual(sum(pow((r+2) % p, -1, p) for _ in range(p)) % p, 0)
        # Outside the logical mask, the implemented residual is r*h.
        for r in range(1, p):
            self.assertEqual([h for h in range(p) if r*h % p == 0], [0])
        self.assertEqual([h for h in range(p) if 0*h % p == 0], list(range(p)))


if __name__ == '__main__':
    unittest.main()
