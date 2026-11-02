from fractions import Fraction
from itertools import product
import unittest

from classical_window_work import WindowWork, shared_window_xof_polynomial


class SharedWindowWorkTests(unittest.TestCase):
    def test_all_short_binary_strings_and_joins(self):
        for width in range(1, 5):
            strings = [bytes(bits) for n in range(5) for bits in product(range(2), repeat=n)]
            for left in strings:
                for right in strings:
                    ledger = WindowWork(width)
                    a, b = ledger.literal(len(left)), ledger.literal(len(right))
                    ledger.concat(a, b)
                    def windows(data):
                        return {data[i:i+width] for i in range(len(data)-width+1)}
                    new = windows(left+right)-windows(left)-windows(right)
                    joined_bound = (ledger.created_window_bound
                                    - max(0, len(left)-width+1)
                                    - max(0, len(right)-width+1))
                    self.assertLessEqual(len(new), joined_bound)
                    self.assertLessEqual(joined_bound, width-1)
                    self.assertLessEqual(ledger.created_window_bound, max(1, width-1)*ledger.work)

    def test_shared_prefix_forks_slices_and_exponentially_long_values(self):
        ledger = WindowWork()
        prefix = ledger.literal(1 << 20)
        original = ledger.created_window_bound
        for _ in range(100):
            branch = ledger.concat(prefix, ledger.literal(1))
            ledger.submit(branch, xof=True)
        self.assertEqual(ledger.created_window_bound-original, 100)
        self.assertEqual(ledger.work, (1 << 20)+300)
        self.assertEqual(ledger.xof_submissions, 100)
        ledger.slice(branch, 10, branch.length-10)
        self.assertEqual(ledger.created_window_bound-original, 100)
        # Shared doubling grows logical length exponentially, yet each join
        # creates at most 63 windows. No logical-length input charge occurs.
        value = ledger.literal(64)
        for _ in range(100):
            value = ledger.concat(value, value)
        self.assertEqual(value.length, 64 << 100)
        self.assertLessEqual(ledger.created_window_bound, 63*ledger.work)

    def test_polynomial_matches_exposure_cap_and_cost_optimizer(self):
        from classical_work_cost import report
        row = shared_window_xof_polynomial(query_per_work=3, query_offset=5,
                                          construction_per_work=7, window_offset=11)
        for work in range(20):
            queries, windows = 3*work+5, 63*7*work+11
            direct = Fraction(queries*windows, 1 << 512)+Fraction(queries**2, 2 << 512)
            polynomial = row['constant']+row['linear']*work+row['quadratic']*work**2
            self.assertEqual(direct, polynomial)
        evaluated = report([row['linear'], row['quadratic']], 128, row['constant'])
        self.assertFalse(evaluated['security_qualified'])
        self.assertFalse(row['attacker_work_coupling_established'])

    def test_invalid_models_and_foreign_strings(self):
        ledger, foreign = WindowWork(), WindowWork()
        a = ledger.literal(3)
        with self.assertRaises(ValueError):
            ledger.concat(a, foreign.literal(1))
        for bounds in [(-1, 1), (0, 4), (True, 2)]:
            with self.assertRaises(ValueError):
                ledger.slice(a, *bounds)
        for invalid in (-1, True, 0.5):
            with self.assertRaises(ValueError):
                shared_window_xof_polynomial(query_per_work=invalid, query_offset=0,
                                             construction_per_work=1, window_offset=0)
        with self.assertRaises(ValueError):
            shared_window_xof_polynomial(output_bits=128, query_per_work=1, query_offset=0,
                                         construction_per_work=1, window_offset=0)
        with self.assertRaises(TypeError):
            shared_window_xof_polynomial(query_per_work=1, query_offset=0, window_offset=0)


if __name__ == '__main__':
    unittest.main()
