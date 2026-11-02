from fractions import Fraction as F
import unittest
from classical_parent_phases import lookup_stages, packed_stages, parent_stages


class LookupPhaseTests(unittest.TestCase):
    def test_native_requests_and_shared_rounds(self):
        for p, degree, width, count, pairs in [(2013265921, 6, 8, 98, [8, 7]),
                (18446744069414584321, 3, 4, 140, [16, 13])]:
            row = lookup_stages(p, degree, width, schedule_version=4)
            self.assertEqual(row['phase_count'], count)
            self.assertEqual(row['scalar_identity_degree'], 3)
            self.assertEqual([v['count'] for v in row['phases'] if v['phase']=='tuple_compression'], pairs)
            self.assertEqual([v['count'] for v in row['phases'] if v['phase']=='shared_scalar_sumcheck_round'], [42, 11])
            reciprocal = [v for v in row['phases'] if 'rational_escape' in v]
            for v, logical, table in zip(reciprocal, [2**21, 2**11], [512, 64]):
                self.assertEqual(F(v['rational_escape']), F(logical+table-1, p**degree))
                self.assertEqual(F(v['first_retry_stop']), F(table+1, p**degree))
                self.assertEqual(F(v['error']), F(logical+2*table, p**degree))

    def test_parent_union_and_disabled_qualification(self):
        for p, degree, width in [(2013265921, 6, 8), (18446744069414584321, 3, 4)]:
            row = parent_stages(p, degree, width, schedule_version=4)
            base = packed_stages(p, width, schedule_version=4)
            lookup = lookup_stages(p, degree, width, schedule_version=4)
            self.assertEqual(row['phase_count'], base['phase_count']+lookup['phase_count'])
            self.assertEqual(F(row['conditional_phase_union']),
                sum(v['count']*F(v['error']) for v in row['phases']))
            self.assertFalse(row['security_qualified'])
            self.assertFalse(row['query_count_selected'])

    def test_incompatible_fields_widths_and_schedules_reject(self):
        for args in [(2013265921, True, 8, 4), (2013265921, 3, 8, 4),
                     (18446744069414584321, 5, 4, 4), (2013265921, 6, 8, 3)]:
            with self.assertRaises(ValueError):
                lookup_stages(*args[:3], schedule_version=args[3])


if __name__ == '__main__':
    unittest.main()
