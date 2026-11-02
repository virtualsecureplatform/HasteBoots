from fractions import Fraction as F
from itertools import product
import unittest

from classical_sampler_resources import column_stop_first_family_bound


def rational(value):
    return F(int(value['exact']['numerator_hex'], 16), int(value['exact']['denominator_hex'], 16))


def actors(**values):
    return dict(dict(adversary=0, verifier=0, setup=0, unknown=0), **values)


def stops(stream, domain, draws, limit, bits):
    cutoff = (1 << bits)-1-((1 << bits)-1) % domain
    accepted = rejects = 0
    for value in stream:
        if accepted == draws:
            break
        if value >= cutoff:
            rejects += 1
            if rejects == limit:
                return True
        else:
            accepted += 1
            rejects = 0
    return False


class ColumnStopFirstFamiliesTests(unittest.TestCase):
    def test_latent_tree_stop_before_any_first_node_answer(self):
        # 2-bit sampler, domain 2: root outputs 2/3 reject. Children are
        # indexed by the proposed root response. Child zero is off-path after
        # quota one; child two can lie on the rejection path. Neither choice
        # changes the event probability BEFORE its first answer is exposed.
        failures = 0
        selected_failures = selected = 0
        for root, child_two, child_three, offpath in product(range(4), repeat=4):
            bad = root in (2, 3) and (child_two if root == 2 else child_three) in (2, 3)
            failures += bad
            if child_two in (2, 3):
                selected += 1
                selected_failures += bad
        exact = F(failures, 4**4)
        self.assertEqual(exact, F(1, 4))
        row = column_stop_first_family_bound(2, 1, 2,
            expected_families=actors(adversary=1), sample_bits=2)
        self.assertEqual(rational(row['total']), exact)
        # Selecting a family after seeing its first node can bias the selected
        # success probability. The expected two first-family trials charge it.
        selected_probability = F(selected_failures, selected)
        self.assertEqual(selected_probability, F(3, 8))
        self.assertGreater(selected_probability, exact)
        charged = column_stop_first_family_bound(2, 1, 2,
            expected_families=actors(adversary=2), sample_bits=2)
        self.assertLessEqual(selected_probability, rational(charged['total']))

    def test_exact_stream_stops_and_power_of_two_geometry_domination(self):
        for draws in (0, 1, 2):
            failures = sum(stops(stream, 2, draws, 2, 3)
                           for stream in product(range(8), repeat=2*draws))
            probability = F(failures, 8**(2*draws))
            self.assertEqual(probability, 1-F(15, 16)**draws)
            row = column_stop_first_family_bound(2, draws, 2,
                expected_families=actors(verifier=1), sample_bits=3)
            self.assertLessEqual(probability, rational(row['total']))
        for stream in product(range(8), repeat=4):
            for domain in (1, 2, 4):
                for draws in (1, 2):
                    if stops(stream, domain, draws, 2, 3):
                        self.assertTrue(stops(stream, 4, 2, 2, 3))

    def test_unbounded_stopping_and_unknown_actors_are_not_dropped(self):
        row = column_stop_first_family_bound(2, 1, 2,
            expected_families=actors(adversary=4), sample_bits=2)
        self.assertEqual(rational(row['total']), 1)
        row = column_stop_first_family_bound(2, 1, 2,
            expected_families=actors(unknown=F(1, 2)), sample_bits=2)
        self.assertEqual(rational(row['total']), F(1, 8))
        for invalid in ({}, actors(adversary=True), actors(verifier=-1), actors(setup=0.5)):
            with self.assertRaises(ValueError):
                column_stop_first_family_bound(2, 1, 2, expected_families=invalid)
        with self.assertRaises(TypeError):
            column_stop_first_family_bound(2, 1, 2)


if __name__ == '__main__':
    unittest.main()
