from fractions import Fraction
import hashlib
import unittest

from classical_window_work import WindowWork, joint_shared_window_oracle_polynomial
from classical_work_cost import composed_report


class JointWindowWorkTests(unittest.TestCase):
    caps = dict(hash_queries_per_work=3, hash_query_offset=5,
                xof_queries_per_work=7, xof_query_offset=11,
                construction_per_work=13, window_offset=17)

    def test_exact_separate_collision_terms_and_shared_windows(self):
        row = joint_shared_window_oracle_polynomial(**self.caps)
        for work in range(25):
            h, x, windows = 3*work+5, 7*work+11, 63*13*work+17
            direct = Fraction((h+x)*windows, 1 << 512)+Fraction(h*h+x*x, 2 << 512)
            actual = row['constant']+row['linear']*work+row['quadratic']*work*work
            self.assertEqual(actual, direct)
            combined_collision_bound = Fraction((h+x)*windows, 1 << 512)+Fraction((h+x)**2, 2 << 512)
            self.assertEqual(combined_collision_bound-actual, Fraction(h*x, 1 << 512))
            self.assertEqual(actual, sum(c['constant']+c['linear']*work+c['quadratic']*work*work
                                        for c in row['components'].values()))

    def test_constructed_shared_input_trace_respects_work_envelope(self):
        ledger = WindowWork()
        prefix_data = bytes(range(64))
        prefix = ledger.literal(len(prefix_data))
        windows, prior = {prefix_data}, [set(), set()]
        target_pairs = prior_pairs = 0
        for step in range(10):
            data = prefix_data+bytes([step])
            branch = ledger.concat(prefix, ledger.literal(1))
            family = step % 2
            ledger.submit(branch, xof=bool(family))
            windows.update(data[i:i+64] for i in range(len(data)-63))
            target_pairs += len(windows)
            prior_pairs += len(prior[family])
            answer = (hashlib.shake_256(data).digest(64) if family else hashlib.sha512(data).digest())
            prior[family].add(answer)
        self.assertEqual((ledger.hash_submissions, ledger.xof_submissions), (5, 5))
        self.assertEqual(ledger.work, 64+30)
        self.assertLessEqual(len(windows), ledger.created_window_bound)
        row = joint_shared_window_oracle_polynomial(
            hash_queries_per_work=1, hash_query_offset=0,
            xof_queries_per_work=1, xof_query_offset=0,
            construction_per_work=1, window_offset=0)
        bound = row['constant']+row['linear']*ledger.work+row['quadratic']*ledger.work**2
        self.assertLessEqual(Fraction(target_pairs+prior_pairs, 1 << 512), bound)

    def test_explicit_phase_composition_keeps_security_gate_closed(self):
        row = joint_shared_window_oracle_polynomial(**self.caps)
        phase = dict(constant=0, linear=Fraction(1, 1 << 256), quadratic=0)
        report = composed_report(dict(row['components'], phase=phase))
        self.assertFalse(row['phase_component_supplied'])
        self.assertFalse(row['attacker_work_coupling_established'])
        self.assertFalse(report['security_qualified'])
        self.assertFalse(report['protocol_bound_established'])
        with self.assertRaises(ValueError):
            composed_report(row['components'])

    def test_every_cap_is_mandatory_and_exact(self):
        for name in self.caps:
            omitted = self.caps.copy()
            del omitted[name]
            with self.assertRaises(TypeError):
                joint_shared_window_oracle_polynomial(**omitted)
            for invalid in (True, -1, 0.5, None):
                with self.assertRaises(ValueError):
                    joint_shared_window_oracle_polynomial(**dict(self.caps, **{name: invalid}))


if __name__ == '__main__':
    unittest.main()
