from copy import deepcopy
from fractions import Fraction
import unittest

from canonical_candidate_budget import combine, required_algebra_terms, rational
from polyfrim_opening_terms import encode


class CandidateBudgetTests(unittest.TestCase):
    def fixture(self):
        algebra=dict(exact_encoding='hex-rational-v1',observation_manifest_sha256='a'*64,
            summaries=[dict(field='babybear',backend='polyfrim',copies=2,
                terms={name:encode(Fraction(1,2**200)) for name in required_algebra_terms()},
                copies_subtotal=encode(Fraction(2*len(required_algebra_terms()),2**200)))])
        openings=dict(exact_encoding='hex-rational-v1',observation_manifest_sha256='a'*64,
            target_bits=128,summaries=[dict(field='babybear',backend='polyfrim',
                copies_of_observed_pattern=2,count_model='conditional-per-owner-ceiling',
                roles=[dict(contribution=encode(Fraction(1,2**130)),
                            charged_internal_root_declarations=dict(total_merkle_roots=10))],
                total=encode(Fraction(1,2**130)),
                merkle_root_declarations=dict(all_copies=24,internal_per_copy=10,outer_slots_per_copy=2),
                observed_queries=128,evaluated_queries=768,hypothetical_query_override=True)])
        return openings,algebra

    def test_global_hash_collision_once_and_exact_sum(self):
        openings,algebra=self.fixture()
        row=combine(openings,algebra,100)['summaries'][0]
        self.assertEqual(rational(row['terms']['global_collisions']),Fraction(100*99,2**257))
        expected=sum((rational(term) for term in row['terms'].values()),Fraction())
        self.assertEqual(rational(row['candidate_subtotal']),expected)
        self.assertTrue(row['candidate_terms_below_target'])
        self.assertFalse(row['whole_security_certified'])
        self.assertTrue(row['hypothetical_query_override'])
        large=combine(openings,algebra,2**64)['summaries'][0]
        self.assertFalse(large['candidate_terms_below_target'])
        self.assertFalse(large['promotion_gate'])

    def test_reject_mismatched_or_incomplete_reports(self):
        openings,algebra=self.fixture()
        for change in ['manifest','copies','missing','subtotal','roots','observed','duplicate']:
            a,b=deepcopy(openings),deepcopy(algebra)
            if change=='manifest': b['observation_manifest_sha256']='b'*64
            elif change=='copies': b['summaries'][0]['copies']=1
            elif change=='missing': b['summaries'][0]['terms'].pop('main_lookup_rational_identity')
            elif change=='subtotal': b['summaries'][0]['copies_subtotal']=encode(Fraction())
            elif change=='roots': a['summaries'][0]['merkle_root_declarations']['all_copies']=1
            elif change=='observed': a['summaries'][0]['count_model']='observed-valid-trace'
            elif change=='duplicate': a['summaries'].append(a['summaries'][0])
            with self.subTest(change=change),self.assertRaises(ValueError): combine(a,b,100)
        for queries in [0,-1,True]:
            with self.assertRaises(ValueError): combine(openings,algebra,queries)


if __name__=='__main__':
    unittest.main()
