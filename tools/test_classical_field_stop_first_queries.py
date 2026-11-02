from fractions import Fraction
from itertools import product
import unittest

from classical_sampler_resources import field_stop_first_query_bound


def rational(value):
    return Fraction(int(value['exact']['numerator_hex'], 16),
                    int(value['exact']['denominator_hex'], 16))


def actors(**values):
    return dict(dict(adversary=0, verifier=0, setup=0, unknown=0), **values)


class FieldStopFirstQueriesTests(unittest.TestCase):
    def test_small_sampler_exact_stops_are_bounded_by_coefficient_weight(self):
        # p=3: one of four masked candidates rejects. Pad stopped paths to a
        # common finite depth to enumerate exact probability without truncating
        # a production loop or imposing a bound on adversarial query counts.
        for count in range(3):
            limit = 2
            failures = 0
            for stream in product(range(4), repeat=count*limit):
                accepted = rejected = 0
                for candidate in stream:
                    if accepted == count:
                        break
                    if candidate == 3:
                        rejected += 1
                        if rejected == limit:
                            failures += 1
                            break
                    else:
                        accepted += 1
                        rejected = 0
            probability = Fraction(failures, 4**(count*limit))
            self.assertEqual(probability, 1-Fraction(15, 16)**count)
            row = field_stop_first_query_bound(3, limit, expected_coefficients=actors(adversary=count))
            self.assertLessEqual(probability, rational(row['total']))
            self.assertFalse(row['input_expectation_bounds_verified'])

    def test_unbounded_grinding_and_all_actors_remain_explicit(self):
        # Each fresh one-coefficient stream hits the analysis stop with 1/16.
        # Query until a hit: unbounded query support, mean coefficient sum 16.
        row = field_stop_first_query_bound(3, 2, expected_coefficients=actors(adversary=16))
        self.assertEqual(rational(row['total']), 1)
        row = field_stop_first_query_bound(3, 2, expected_coefficients=dict(
            adversary=Fraction(1, 3), verifier=Fraction(2, 3), setup=1, unknown=2))
        self.assertEqual(rational(row['total']), Fraction(1, 4))
        self.assertEqual(rational(row['actor_contributions']['unknown']), Fraction(1, 8))
        row = field_stop_first_query_bound(2013265921, 512,
            expected_coefficients=actors(adversary=1 << 4096))
        self.assertEqual(rational(row['total']), 1)

    def test_missing_inexact_or_negative_expectations_reject(self):
        with self.assertRaises(TypeError):
            field_stop_first_query_bound(3, 2)
        for invalid in ({}, dict(adversary=1), actors(adversary=True), actors(setup=-1), actors(unknown=0.5)):
            with self.assertRaises(ValueError):
                field_stop_first_query_bound(3, 2, expected_coefficients=invalid)
        for prime, limit in [(1, 2), (3, 0), (True, 2), (3, True)]:
            with self.assertRaises(ValueError):
                field_stop_first_query_bound(prime, limit, expected_coefficients=actors())


if __name__ == '__main__':
    unittest.main()
