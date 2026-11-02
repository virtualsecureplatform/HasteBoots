from fractions import Fraction
from itertools import product
import unittest

from classical_sampler_resources import xof_expected_exposure_bound


def rational(value):
    return Fraction(int(value['exact']['numerator_hex'], 16),
                    int(value['exact']['denominator_hex'], 16))


class ExpectedExposureTests(unittest.TestCase):
    def test_adaptive_stopping_against_exhaustive_oracle(self):
        # Input i is fresh. Targets depend on earlier answers; stop on a hit
        # or at depth three. Padding terminal paths gives equal weight 1/M^3.
        for bits in (1, 2, 3):
            support = 1 << bits
            target_sum = collision_sum = bad = Fraction()
            for path in product(range(support), repeat=3):
                targets, prior = {0}, set()
                for index, answer in enumerate(path):
                    if index:
                        targets.add((path[index-1]+1) % support)
                    target_sum += len(targets)
                    collision_sum += len(prior)
                    if answer in targets or answer in prior:
                        bad += 1
                        break
                    prior.add(answer)
            size = support**3
            result = xof_expected_exposure_bound(
                expected_target_pairs=target_sum/size,
                expected_collision_pairs=collision_sum/size, output_bits=bits)
            self.assertLessEqual(bad/size, rational(result['total']))
            self.assertFalse(result['attacker_work_coupling_established'])

    def test_unbounded_geometric_stopping_has_no_query_cap(self):
        for bits in (1, 4, 512):
            # Query until the first hit of a fixed singleton. The number of
            # fresh queries has unbounded support and expectation 2^bits.
            result = xof_expected_exposure_bound(
                expected_target_pairs=1 << bits,
                expected_collision_pairs=0, output_bits=bits)
            self.assertEqual(rational(result['total']), 1)
        # For a deterministic long run, pairs scale quadratically. The helper
        # accepts arbitrarily large integers without silently clipping counts.
        count = 1 << 1024
        result = xof_expected_exposure_bound(
            expected_target_pairs=0, expected_collision_pairs=count*(count-1)//2)
        self.assertEqual(rational(result['total']), 1)

    def test_exact_fractions_and_invalid_bounds(self):
        result = xof_expected_exposure_bound(
            expected_target_pairs=Fraction(1, 3), expected_collision_pairs=Fraction(2, 7))
        self.assertEqual(rational(result['total']), Fraction(13, 21*(1 << 512)))
        for invalid in (-1, True, 0.5, '1', None):
            with self.assertRaises(ValueError):
                xof_expected_exposure_bound(
                    expected_target_pairs=invalid, expected_collision_pairs=0)
        for invalid in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                xof_expected_exposure_bound(
                    expected_target_pairs=0, expected_collision_pairs=0, output_bits=invalid)
        with self.assertRaises(TypeError):
            xof_expected_exposure_bound(expected_target_pairs=0)


if __name__ == '__main__':
    unittest.main()
