"""Model checks for atomic ZeroCheck phases; not complete-protocol security."""
from fractions import Fraction as F
from itertools import product
import unittest

from packed_budget import atomic_zerocheck_phase_bounds, zerocheck_algebraic_bound


class AtomicZeroStateTests(unittest.TestCase):
    def test_phase_terms_and_legacy_union_envelope(self):
        for p, k, d in [(11, 2, 1), (17, 2, 2), (101, 4, 2)]:
            for n in range(1, 5):
                terms = atomic_zerocheck_phase_bounds(p, k, d, n, schedule_version=4)
                self.assertEqual(terms['initial_equality'], F(n-1, p)**k)
                self.assertEqual(terms['first_mixed_challenge'], F((2*k-1)*d+1, p)**k)
                self.assertLessEqual(terms['initial_equality']+terms['first_mixed_challenge']
                    +(n-1)*terms['remaining_round'], zerocheck_algebraic_bound(p, k, d, n))
        for version in [1, 2, 3, True, 4.0]:
            with self.assertRaises(ValueError):
                atomic_zerocheck_phase_bounds(11, 2, 1, 3, schedule_version=version)

    def test_joint_mixing_and_rows_vs_a_conditioned_separate_phase(self):
        p = 11

        def delta(y):
            return y*(y-1)*(y-2) % p

        # Difference-polynomial vector [delta, 0]. A complete block samples
        # each row's two mixing coefficients and its evaluation point together.
        row_zeros = sum(a*delta(y) % p == 0 for a, b, y in product(range(p), repeat=3))
        joint = F(row_zeros, p**3)**2
        bound = atomic_zerocheck_phase_bounds(p, 2, 1, 3, schedule_version=4)['first_mixed_challenge']
        self.assertEqual(joint, F(41, 121)**2)
        self.assertLessEqual(joint, bound)
        # For a separate row phase, conditioning on mixing [[1,0],[0,0]]
        # leaves just one nonzero row. The whole-block bound cannot simply
        # be used at this prefix. This is a model counterexample, not a forgery.
        conditioned = F(sum(delta(a) == 0 for a, b in product(range(p), repeat=2)), p**2)
        self.assertEqual(conditioned, F(3, 11))
        self.assertGreater(conditioned, bound)

    def test_equality_block_vs_a_conditioned_last_point(self):
        p = 11
        joint = F(sum(a == 0 and b == 0 for a, b in product(range(p), repeat=2)), p**2)
        bound = atomic_zerocheck_phase_bounds(p, 2, 1, 2, schedule_version=4)['initial_equality']
        self.assertEqual(joint, bound)
        self.assertGreater(F(1, p), bound)  # Last point after a first zero point.


if __name__ == '__main__':
    unittest.main()
