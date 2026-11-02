from fractions import Fraction as F
import unittest
from brakedown_opening_terms import opening_terms


class BrakedownTermsTests(unittest.TestCase):
    def test_minimum_domain_and_padding_follow_constructor(self):
        row = opening_terms(3, 2, 2, 4, 2, 17, 257)
        self.assertEqual((row['message_scalars'], row['message_blocks'], row['encoded_blocks']), (2, 1, 32))
        self.assertEqual(row['coefficient_padding'], 2)
        self.assertEqual(row['random_test'], F(32*33, 257**2))
        self.assertEqual(row['column_sampling'], F(21, 32)**17)
        self.assertEqual(row['authentication_hash_outputs_upper_bound'], 17*6)

    def test_native_geometry_and_draws_above_domain(self):
        row = opening_terms(18, 8, 9, 8, 2, 1024, 2013265921)
        self.assertEqual((row['message_blocks'], row['encoded_blocks']), (64, 128))
        self.assertEqual(row['minimum_rejecting_columns'], 22)
        self.assertEqual(row['column_sampling'], F(106, 128)**1024)
        self.assertEqual(row['transported_columns_upper_bound'], 128)
        self.assertEqual(row['column_draws'], 1024)
        self.assertEqual(row['authentication_hash_outputs_upper_bound'], 128*8)

    def test_invalid_geometry_and_missing_field_domain(self):
        for args in [(3, True, 2, 4, 2, 8, 257), (3, 4, 2, 2, 2, 8, 257),
                (3, 2, 4, 4, 2, 8, 257), (3, 2, 2, 4, 2, 8, 97),
                (3, 2, 2, 4, 3, 8, 257)]:
            with self.assertRaises(ValueError):
                opening_terms(*args)


if __name__ == '__main__':
    unittest.main()
