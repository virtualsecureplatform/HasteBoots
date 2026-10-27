import unittest
from fractions import Fraction
from hash_query_budget import maximum_queries, report, schedule_bounds, worst_bounds


class HashQueryBudgetTests(unittest.TestCase):
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
