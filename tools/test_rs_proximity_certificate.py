import unittest
from itertools import product

from rs_proximity_certificate import (Polynomial, certificate, common_source,
                                      exhaustive_check, near_word)


class ProximityCertificateTests(unittest.TestCase):
    def test_every_two_row_matrix_in_a_tiny_rs_instance(self):
        near, far = 0, 0
        for flat in product(range(3), repeat=6):
            rows = [flat[:3], flat[3:]]
            columns = list(zip(*rows))
            expected = len(set(columns)) < 3
            audit = exhaustive_check(rows, [0, 1, 2], 1, 1, 3)
            self.assertEqual(audit["common_source"], expected)
            if expected:
                near += 1
            else:
                far += 1
                a, b, c = columns
                determinant = ((b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0])) % 3
                self.assertEqual(audit["near"], 7 if determinant else 3)
        self.assertEqual(near, 225)
        self.assertEqual(far, 504)

    def test_every_word_in_a_tiny_rs_instance(self):
        points = list(range(4))
        near, far = 0, 0
        for word in product(range(5), repeat=4):
            audit = exhaustive_check([word], points, 1, 1, 5)
            expected = any(sum(x != constant for x in word) <= 1 for constant in range(5))
            self.assertEqual(audit["common_source"], expected)
            if audit["common_source"]:
                near += 1
            else:
                far += 1
                self.assertEqual(audit["near"], 1)
        self.assertEqual(near, 85)
        self.assertEqual(far, 540)

    def test_disjoint_individually_decodable_rows_need_common_support(self):
        p, points = 101, list(range(6))
        rows = [[int(j == i) for j in points] for i in (0, 1)]
        self.assertTrue(all(near_word(row, points, 2, 1, p) for row in rows))
        self.assertIsNone(common_source(rows, points, 2, 1, p))
        audit = exhaustive_check(rows, points, 2, 1, p)
        self.assertFalse(audit["common_source"])
        self.assertEqual(audit["kind"], "rank")
        self.assertEqual(audit["near"], 2*p-1)
        self.assertEqual(audit["challenges"], p*p)

    def test_rational_kernel_requires_divisibility_not_only_rank(self):
        p, points = 101, list(range(6))
        rational = [pow((x-7) % p, p-2, p) for x in points]
        linear = [(3*x+4) % p for x in points]
        audit = exhaustive_check([rational, linear], points, 2, 1, p)
        self.assertEqual(audit["kind"], "division-remainder")
        self.assertEqual(audit["near"], p)
        self.assertLess(audit["degree"], audit["degree_bound"])

    def test_polynomial_above_message_degree_is_not_a_valid_decode(self):
        p, points = 101, list(range(6))
        audit = exhaustive_check([[x*x % p for x in points]], points, 2, 1, p)
        self.assertEqual(audit["kind"], "quotient-degree")
        self.assertEqual(audit["near"], 1)

    def test_second_degree_locator_and_multiple_pseudodivision_steps(self):
        p, points = 101, list(range(7))
        rational = [pow((x-9)**2 % p, p-2, p) for x in points]
        linear = [(3*x+4) % p for x in points]
        audit = exhaustive_check([rational, linear], points, 2, 2, p)
        self.assertEqual(audit["kind"], "division-remainder")
        self.assertEqual(audit["near"], p)
        self.assertLessEqual(audit["degree"], 56)

    def test_common_source_is_found_before_constructing_exception_polynomial(self):
        p, points = 101, list(range(6))
        rows = [[(a*x+b+(9 if j == 2 else 0)) % p for j, x in enumerate(points)]
                for a, b in [(2, 3), (7, 8)]]
        decoded, errors = common_source(rows, points, 2, 1, p)
        self.assertEqual(decoded, [[3, 2], [8, 7]])
        self.assertEqual(errors, (2,))
        self.assertIsNone(certificate(rows, points, 2, 1, p))

    def test_exact_codeword_radius_zero_and_invalid_hypotheses(self):
        audit = exhaustive_check([[1, 0, 0, 0]], list(range(4)), 2, 0, 101)
        self.assertEqual(audit["near"], 1)
        for points, message, radius, p in [([0, 0, 2, 3], 2, 0, 101),
                                          (list(range(4)), 3, 1, 101),
                                          (list(range(4)), 2, 0, 15),
                                          (list(range(4)), 2, 0, 1009)]:
            with self.assertRaises(ValueError): certificate([[1]*len(points)], points, message, radius, p)
        with self.assertRaises(ValueError): exhaustive_check([[0]*4]*4, list(range(4)), 2, 0, 101)

    def test_polynomials_are_formal_not_reduced_as_field_functions(self):
        t = Polynomial.variable(101, 1, 0)
        power = t
        for _ in range(100): power *= t
        polynomial = power-t
        self.assertTrue(polynomial)
        self.assertEqual(polynomial.degree(), 101)
        self.assertTrue(all(polynomial.evaluate([x]) == 0 for x in range(101)))


if __name__ == "__main__": unittest.main()
