from fractions import Fraction
import unittest

from classical_candidate_terms import candidate_terms
from classical_window_work import native_stopped_joint_window_work
from test_classical_candidate_terms import native


class NativeJointWindowWorkTests(unittest.TestCase):
    def test_twenty_typed_profiles_preserve_stops_and_substitution(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for version in (4, 5):
                for backend in range(5):
                    with self.subTest(prime=prime, version=version, backend=backend):
                        candidate = candidate_terms(native(backend, prime, degree, width, version))
                        row = native_stopped_joint_window_work(candidate,
                            honest_hash_outputs=7, honest_xof_outputs=11, honest_window_values=13)
                        h, x = row['verifier_hash_queries'], row['verifier_xof_queries']
                        c = h*row['verifier_hash_input_bytes_per_query']+x*row['verifier_xof_input_bytes_per_query']
                        self.assertEqual(row['verifier_literal_construction_bytes'], c)
                        for work in (0, 1, 17):
                            qh, qx, windows = (1+h)*work+7, (1+x)*work+11, 63*(1+c)*work+13
                            direct = Fraction((qh+qx)*windows, 1 << 512)+Fraction(qh*qh+qx*qx, 2 << 512)
                            self.assertEqual(row['constant']+row['linear']*work+row['quadratic']*work**2, direct)
                        self.assertTrue(row['analysis_only_stops'])
                        self.assertTrue(row['production_loops_unchanged'])
                        self.assertTrue(any('Canonical field' in stop for stop in row['stopping_conditions']))
                        column_stop = any('column candidate' in stop for stop in row['stopping_conditions'])
                        self.assertEqual(column_stop, backend == 0 and version == 4)
                        self.assertFalse(row['security_qualified'])
                        self.assertFalse(row['native_verifier_caps_established'])
                        self.assertFalse(row['phase_component_supplied'])

    def test_offsets_are_mandatory_exact_and_monotone(self):
        candidate = candidate_terms(native(0, version=5))
        bounds = dict(honest_hash_outputs=0, honest_xof_outputs=0, honest_window_values=0)
        base = native_stopped_joint_window_work(candidate, **bounds)
        for name in bounds:
            omitted = bounds.copy()
            del omitted[name]
            with self.assertRaises(TypeError):
                native_stopped_joint_window_work(candidate, **omitted)
            for invalid in (-1, True, 0.5, None):
                with self.assertRaises(ValueError):
                    native_stopped_joint_window_work(candidate, **dict(bounds, **{name: invalid}))
            larger = native_stopped_joint_window_work(candidate, **dict(bounds, **{name: 100}))
            self.assertEqual(base['quadratic'], larger['quadratic'])
            self.assertGreater(larger['linear'], base['linear'])


if __name__ == '__main__':
    unittest.main()
