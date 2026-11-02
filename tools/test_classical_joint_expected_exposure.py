from fractions import Fraction
from itertools import product
import unittest

from classical_sampler_resources import ideal_oracle_expected_exposure_bound


def rational(value):
    return Fraction(int(value['exact']['numerator_hex'], 16),
                    int(value['exact']['denominator_hex'], 16))


class JointExpectedExposureTests(unittest.TestCase):
    def test_interleaved_adaptive_oracles_and_stopping(self):
        support = 4
        sums = [Fraction() for _ in range(4)]
        bad = Fraction()
        for answers in product(range(support), repeat=4):
            targets, seen = {0}, [set(), set()]
            for step, answer in enumerate(answers):
                family = step % 2
                if step:
                    targets.add((answers[step-1]+1) % support)
                sums[2*family] += len(targets)
                sums[2*family+1] += len(seen[family])
                if answer in targets or answer in seen[family]:
                    bad += 1
                    break
                seen[family].add(answer)
        size = support**4
        row = ideal_oracle_expected_exposure_bound(
            expected_hash_target_pairs=sums[0]/size,
            expected_hash_collision_pairs=sums[1]/size,
            expected_xof_target_pairs=sums[2]/size,
            expected_xof_collision_pairs=sums[3]/size, output_bits=2)
        self.assertLessEqual(bad/size, rational(row['total']))
        self.assertFalse(row['whole_proof_security_certified'])

    def test_separate_scaling_mandatory_families_and_exact_inputs(self):
        bounds = dict(expected_hash_target_pairs=Fraction(1, 3),
                      expected_hash_collision_pairs=2,
                      expected_xof_target_pairs=3,
                      expected_xof_collision_pairs=4)
        row = ideal_oracle_expected_exposure_bound(**bounds)
        self.assertEqual(rational(row['hash_contribution']), Fraction(7, 3*(1 << 512)))
        self.assertEqual(rational(row['xof_contribution']), Fraction(7, 1 << 512))
        self.assertEqual(rational(row['total']), Fraction(28, 3*(1 << 512)))
        for name in bounds:
            missing = bounds.copy()
            del missing[name]
            with self.assertRaises(TypeError):
                ideal_oracle_expected_exposure_bound(**missing)
            for invalid in (-1, True, 0.5, None):
                changed = dict(bounds, **{name: invalid})
                with self.assertRaises(ValueError):
                    ideal_oracle_expected_exposure_bound(**changed)


if __name__ == '__main__':
    unittest.main()
