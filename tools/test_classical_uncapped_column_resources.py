from fractions import Fraction
import unittest

from classical_sampler_resources import column_run_expected_resources


def rational(value):
    return Fraction(int(value['exact']['numerator_hex'], 16),
                    int(value['exact']['denominator_hex'], 16))


class UncappedColumnResourcesTests(unittest.TestCase):
    def test_small_support_moments_match_first_step_equations(self):
        for bits in range(1, 6):
            support = 1 << bits
            for domain in range(1, support):
                cutoff = support-1-(support-1) % domain
                counts = [sum(x < cutoff and x % domain == i for x in range(support))
                          for i in range(domain)]
                self.assertEqual(len(set(counts)), 1)
                acceptance = Fraction(sum(counts), support)
                rejection = 1-acceptance
                mean = second = Fraction()
                for draws in range(5):
                    row = column_run_expected_resources(domain, draws, 100, sample_bits=bits)
                    self.assertEqual(rational(row['expected_candidate_queries']), mean)
                    self.assertEqual(rational(row['expected_squared_candidate_queries']), second)
                    # First-step equations for waiting for one more acceptance.
                    previous_mean = mean
                    mean = (1+acceptance*previous_mean)/acceptance
                    second = (1+2*(acceptance*previous_mean+rejection*mean)
                              +acceptance*second)/acceptance

    def test_growing_request_cost_and_native_top_bucket(self):
        row = column_run_expected_resources(32, 128, 1000)
        self.assertEqual(row['acceptance_cutoff'], 2**64-32)
        acceptance = Fraction(2**64-32, 2**64)
        mean = rational(row['expected_candidate_queries'])
        second = rational(row['expected_squared_candidate_queries'])
        self.assertEqual(mean, 128/acceptance)
        self.assertGreater(mean, 128)
        self.assertEqual(row['additional_input_bytes_per_candidate'], 86)
        self.assertEqual(rational(row['expected_total_request_input_bytes']),
                         1000*mean+43*(second-mean))
        self.assertEqual(rational(row['expected_reader_bytes']), 8*mean)
        self.assertIsNone(row['deterministic_retry_cap'])
        self.assertFalse(row['global_resource_bound_established'])
        self.assertFalse(row['source_and_first_entry_coupling_established'])
        self.assertFalse(row['whole_proof_security_certified'])
        empty = column_run_expected_resources(32, 0, 1000)
        self.assertEqual(rational(empty['expected_total_request_input_bytes']), 0)

    def test_invalid_or_nonterminating_parameters_reject(self):
        for args in [(0, 1, 100), (2**64, 1, 100), (32, True, 100),
                     (32, 1, 42), (32, -1, 100), (32, 2**64, 100)]:
            with self.assertRaises(ValueError):
                column_run_expected_resources(*args)
        with self.assertRaises(ValueError):
            column_run_expected_resources(4, 1, 100, sample_bits=2)


if __name__ == '__main__':
    unittest.main()
