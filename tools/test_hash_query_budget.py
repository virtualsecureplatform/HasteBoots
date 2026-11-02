import unittest
from fractions import Fraction
from hash_query_budget import (global_target_bounds, global_work_coefficients,
                               maximum_queries, report, schedule_bounds, worst_bounds,
                               xof_link_bounds, xof_work_coefficients, bounded_input_xof_work,
                               joint_filtered_oracle_work)


class HashQueryBudgetTests(unittest.TestCase):
    def test_joint_filters_count_root_windows_from_both_oracles(self):
        for vh, vx in [(0, 0), (3, 7)]:
            for lh, lx in [(63, 63), (64, 80), (90, 64)]:
                row = joint_filtered_oracle_work(16, vh, vx, lh, lx, 2, 3, 5)
                for work in range(1, 8):
                    hashes, outputs = (1+vh)*work+2, (1+vx)*work+3
                    roots = max(0, lh-1)*hashes+max(0, lx-1)*outputs+5
                    self.assertEqual(roots, row['roots_per_work']*work+row['root_offset'])
                    for family, exact in [('merkle', global_target_bounds(16, hashes, roots)),
                            ('xof', xof_link_bounds(16, outputs, max(0, lx-1)*outputs))]:
                        bound = sum(row[family][key]*work**power for power, key in
                                    enumerate(('constant', 'linear', 'quadratic')))
                        self.assertGreaterEqual(bound, sum(exact.values()))
                self.assertFalse(row['resource_coupling_established'])
        with self.assertRaises(ValueError):
            joint_filtered_oracle_work(16, 1, 1, 64, 64, 0, 0, True)

    def test_filtered_input_caps_cover_all_queries_and_submissions(self):
        for length in [0, 63, 64, 65, 100]:
            for verifier in [0, 1, 7]:
                for honest in [0, 3]:
                    row = bounded_input_xof_work(16, verifier, length, honest)
                    coefficients = row['coefficients']
                    for work in range(1, 6):
                        bound = sum(coefficients[key]*work**power for power, key in
                                    enumerate(('constant', 'linear', 'quadratic')))
                        for adversarial in range(work+1):
                            for submissions in range(work+1):
                                outputs = adversarial+verifier*submissions+honest
                                # Register every possible overlapping target window,
                                # including windows on verifier and honest inputs.
                                windows = max(0, length-1)*outputs
                                exact = sum(xof_link_bounds(16, outputs, windows).values())
                                self.assertGreaterEqual(bound, exact)
                    self.assertFalse(row['resource_coupling_established'])
        for args in [(16, True, 64, 0), (16, 1, -1, 0), (16, 1, 64, 0.0)]:
            with self.assertRaises(ValueError):
                bounded_input_xof_work(*args)

    def test_xof_link_terms_and_all_trials_work_envelope(self):
        self.assertEqual(xof_link_bounds(8, 4, 7),
                         dict(output_collisions=Fraction(6, 256),
                              late_link_hits=Fraction(28, 256)))
        for a in [0, 1, 3]:
            for m in [0, 5]:
                for b in [0, 2, 17]:
                    for w in [0, 9]:
                        c = xof_work_coefficients(16, a, m, b, w)
                        for work in range(21):
                            actual = sum(xof_link_bounds(16, a*work+m, b*work+w).values())
                            upper = c['constant']+c['linear']*work+c['quadratic']*work**2
                            self.assertGreaterEqual(upper, actual)
                            self.assertEqual(upper-actual, Fraction(a*work+m, 2**17))

    def test_xof_resource_validation(self):
        for bits, outputs, windows in [(0, 1, 1), (512, -1, 0),
                                       (512, 1, True), (512, 1, 0.5)]:
            with self.assertRaises(ValueError):
                xof_link_bounds(bits, outputs, windows)
        for resources in [(1, 0, -1, 0), (True, 0, 1, 0), (1, 0, 1, 0.5)]:
            with self.assertRaises(ValueError):
                xof_work_coefficients(512, *resources)

    def test_shared_global_target_set(self):
        self.assertEqual(global_target_bounds(8, 10, 3),
            dict(global_collisions=Fraction(45, 256), late_target_hits=Fraction(230, 256)))
        for roots in [1, 7, 1024]:
            q = maximum_queries(64, roots, 32, global_targets=True)
            self.assertLessEqual(sum(global_target_bounds(64, q, roots).values()), Fraction(1, 2**32))
            self.assertGreater(sum(global_target_bounds(64, q+1, roots).values()), Fraction(1, 2**32))
        result = report(512, 100, 1000, 128, global_targets=True)
        self.assertEqual(result['target_model'], 'global-predictable-target-set')
        self.assertFalse(result['whole_proof_security_certified'])
        with self.assertRaises(ValueError):
            report(512, 100, 1, 128, [dict(pre=0,post=100,roots=1)], global_targets=True)

    def test_attacker_work_envelope_dominates_global_terms(self):
        for a in [0, 1, 2]:
            for h in [0, 3]:
                for b in [0, 1]:
                    for r in [0, 7]:
                        coefficients = global_work_coefficients(16, a, h, b, r)
                        for work in range(1, 21):
                            envelope = coefficients['constant'] + coefficients['linear']*work + coefficients['quadratic']*work*work
                            self.assertGreaterEqual(envelope, sum(global_target_bounds(16, a*work+h, b*work+r).values()))

    def test_global_collision_counted_once(self):
        errors = schedule_bounds(8, 10, [dict(pre=3,post=7,roots=2),dict(pre=8,post=2,roots=1)])
        self.assertEqual(errors["global_collisions"], Fraction(45,256))
        self.assertEqual(errors["late_target_hits"], Fraction(2*7*7+17*2,256))

    def test_worst_freeze_by_exhaustive_schedules(self):
        for queries in range(31):
            for roots in [1,2,7]:
                worst = worst_bounds(16, queries, roots)
                schedules = [schedule_bounds(16, queries,
                    [dict(pre=a,post=queries-a,roots=roots)]) for a in range(queries+1)]
                self.assertEqual(worst["late_target_hits"], max(s["late_target_hits"] for s in schedules))
                if roots == 1:
                    self.assertEqual(sum(worst.values()), Fraction(queries**2,2**16))

    def test_exact_threshold_and_maximum(self):
        self.assertEqual(maximum_queries(256,1,128),2**64)
        for bits,target in [(8,4),(9,12),(64,32),(256,128)]:
            for roots in [1,2,17,1024]:
                q = maximum_queries(bits,roots,target)
                threshold = Fraction(1,2**target)
                self.assertLessEqual(sum(worst_bounds(bits,q,roots).values()),threshold)
                self.assertGreater(sum(worst_bounds(bits,q+1,roots).values()),threshold)

    def test_unsafe_and_hypothetical_scope_remain_explicit(self):
        result = report(256,2**64,2,128)
        self.assertFalse(result["hash_term_fits_target"])
        self.assertFalse(result["whole_proof_security_certified"])
        self.assertGreater(len(result["missing"]),0)
        result = report(256,0,1,128)
        self.assertTrue(result["hash_term_fits_target"])
        self.assertIsNone(result["union_bound"]["bits"])
        self.assertFalse(result["whole_proof_security_certified"])

    def test_grouping_and_monotonic_resources(self):
        grouped = schedule_bounds(32, 100, [dict(pre=40,post=60,roots=3)])
        separate = schedule_bounds(32, 100, [dict(pre=40,post=60,roots=1)]*3)
        self.assertEqual(grouped, separate)
        for queries in range(20):
            for roots in [1,2,10]:
                current = sum(worst_bounds(32,queries,roots).values())
                self.assertLessEqual(current,sum(worst_bounds(32,queries+1,roots).values()))
                self.assertLessEqual(current,sum(worst_bounds(32,queries,roots+1).values()))

    def test_explicit_schedule_can_improve_conservative_bound(self):
        schedule = [dict(pre=0,post=100,roots=2)]
        result = report(256,100,2,128,schedule)
        self.assertEqual(Fraction(int(result["union_bound"]["numerator"]),
                                  int(result["union_bound"]["denominator"])),
                         Fraction(4950+200,2**256))
        self.assertLess(sum(schedule_bounds(256,100,schedule).values()),
                        sum(worst_bounds(256,100,2).values()))

    def test_invalid_resources_and_schedules(self):
        for bits,queries,roots,target in [(0,1,1,128),(256,-1,1,128),(256,1,0,128),(256,True,1,128),(256,1,1,0)]:
            with self.assertRaises(ValueError):
                report(bits,queries,roots,target)
        for schedule in [[],[dict(pre=2,post=3,roots=1)],[dict(pre=1,post=1,roots=2)],
                         [dict(pre=1,post=1,roots=True)],[dict(pre=1,post=1,roots=1,extra=0)]]:
            with self.assertRaises(ValueError):
                report(256,2,1,128,schedule)


if __name__ == "__main__":
    unittest.main()
