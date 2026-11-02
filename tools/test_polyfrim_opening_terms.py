from fractions import Fraction
import unittest
from polyfrim_opening_terms import opening_terms, encode, schedule_ceiling, internal_root_declarations, shared_stage_schedule, authentication_resources


class OpeningTermsTests(unittest.TestCase):
    def test_authentication_hashes_include_rolling_leaf_contexts(self):
        row = authentication_resources(3, 8, 4, 2, reuse_rolling_context=False)
        self.assertEqual(row['packed_merkle_hash_outputs'], 576)
        self.assertEqual(row['rolling_merkle_hash_outputs'], 80)
        self.assertEqual(row['rolling_leaf_context_hash_outputs'], 32)
        self.assertEqual(row['authentication_hash_outputs'], 688)
        self.assertEqual(row['dictionary_hash_reference_ceiling'], 668)
        cached = authentication_resources(3, 8, 4, 2)
        self.assertEqual(cached['authentication_hash_outputs'], 656)
        self.assertEqual(cached['rolling_leaf_context_hash_outputs'], 0)
        self.assertTrue(cached['rolling_context_reused_from_binding'])
        self.assertEqual(cached['dictionary_hash_reference_ceiling'], 668)

    def test_authentication_counts_match_explicit_path_traversals(self):
        for variables in range(6):
            for blowup in [2, 4, 8]:
                rounds = max(1, variables)
                n = (1 << rounds)*blowup
                for queries, claims, calls in [(1, 1, 1), (3, 5, 2), (8, 16, 16)]:
                    packed = rolling = contexts = 0
                    for _ in range(queries):
                        for _ in range(claims):
                            for _ in range(2):
                                for layer in range(rounds):
                                    depth = ((n >> layer)//2).bit_length()-1
                                    packed += depth+1
                        for _ in range(calls):
                            for layer in range(1, rounds):
                                rolling += ((n >> layer)//2).bit_length()
                                contexts += 1
                    row = authentication_resources(variables, queries, claims, calls, blowup,
                                                   reuse_rolling_context=False)
                    self.assertEqual(row['authentication_hash_outputs'], packed+rolling+contexts)
                    cached = authentication_resources(variables, queries, claims, calls, blowup)
                    self.assertEqual(cached['authentication_hash_outputs'], packed+rolling)
        for args in [(3, True, 1, 1, 2), (3, 1, 1, 2, 2), (3, 1, 1, 1, 3)]:
            with self.assertRaises(ValueError):
                authentication_resources(*args)

    def test_expansion_tradeoff_and_integer_consistency_radius(self):
        for variables in range(1, 7):
            baseline = opening_terms(variables, 101, 6, 7)
            self.assertEqual(baseline, opening_terms(variables, 101, 6, 7, 2))
            previous = baseline
            for blowup in [4, 8]:
                terms = opening_terms(variables, 101, 6, 7, blowup)
                self.assertGreater(terms['vector_projection'], previous['vector_projection'])
                self.assertGreater(terms['rolling_field'], previous['rolling_field'])
                self.assertLess(terms['rolling_sampling'], previous['rolling_sampling'])
                # The fixed nearby-pair rejecting set must give at least the
                # radius-sensitive rolling gap, including the terminal layer.
                self.assertLessEqual(terms['nearby_consistency'], terms['rolling_sampling'])
                previous = terms
        for blowup in [1, 3, 16, True, 2.0]:
            with self.assertRaises(ValueError):
                opening_terms(3, 101, 6, 7, blowup)

    def test_stage_ceilings_cover_independently_recorded_native_calls(self):
        fixtures = [
            (2013265921, 8, [84, 8, 61, 7], [253, 8, 173, 7]),
            (18446744069414584321, 4, [146, 16, 103, 13], [275, 16, 187, 13]),
        ]
        for p, width, calls, queries in fixtures:
            record = dict(prime=p, width=width, lwe_dimension=728, lookup_repetitions=1)
            stage = shared_stage_schedule(record)
            self.assertFalse(stage['uses_owner_allowance_assumption'])
            self.assertTrue(all(n <= cap for n, cap in zip(calls, stage['role_opening_call_ceilings'])))
            self.assertTrue(all(n <= cap for n, cap in zip(queries, stage['role_ordered_query_ceilings'])))
            self.assertTrue(all(cap <= old for cap, old in zip(stage['role_ordered_query_ceilings'],
                                                             schedule_ceiling(record)['ordered_query_ceilings'])))
            self.assertFalse(stage['security_qualified'])

    def test_stage_validation_and_width_dependent_ntt_queries(self):
        for p, widths in [(2013265921, [8, 16]), (18446744069414584321, [4, 8])]:
            records = [dict(prime=p, width=w, lwe_dimension=728, lookup_repetitions=1) for w in widths]
            a, b = map(shared_stage_schedule, records)
            self.assertEqual(a['role_opening_call_ceilings'], b['role_opening_call_ceilings'])
            self.assertGreater(b['role_ordered_query_ceilings'][0], a['role_ordered_query_ceilings'][0])
            self.assertGreater(b['role_ordered_query_ceilings'][2], a['role_ordered_query_ceilings'][2])
        for change in [dict(prime=17), dict(width=32), dict(width=True),
                       dict(lwe_dimension=0), dict(lookup_repetitions=2)]:
            record = dict(prime=2013265921, width=8, lwe_dimension=728, lookup_repetitions=1)
            record.update(change)
            with self.assertRaises(ValueError):
                shared_stage_schedule(record)

    def test_submitted_call_caps_include_rejection_and_keep_work_scope_separate(self):
        for prime, width in [(2013265921, 8), (18446744069414584321, 4)]:
            bits = (prime-1).bit_length()
            d, s = (bits+7)//8, (bits+4)//5
            for lwe in (21, 728):
                schedule = shared_stage_schedule(dict(prime=prime, width=width,
                    lwe_dimension=lwe, lookup_repetitions=1))
                self.assertEqual(schedule['role_opening_call_ceilings'], [16*d+22, 2*d, 8*s+8, s])
                self.assertTrue(schedule['submitted_call_bound_source_reviewed'])
                self.assertFalse(schedule['submitted_call_bound_established'])
                self.assertTrue(schedule['submitted_calls_counted_before_delegation'])
                self.assertFalse(schedule['transcript_byte_and_attacker_work_bounds_established'])
                self.assertFalse(schedule['security_qualified'])

    def test_internal_roots_and_virtual_identifiers_are_separate(self):
        roots=internal_root_declarations(3,5,2)
        self.assertEqual(roots,dict(packed_ladder_roots=10,rolling_derived_roots=4,
                                   total_merkle_roots=14,virtual_projection_identifiers=6))
        # Splitting batches increases rolling roots, never matrix ladders.
        split=internal_root_declarations(3,5,5)
        self.assertEqual(split['packed_ladder_roots'],roots['packed_ladder_roots'])
        self.assertGreater(split['total_merkle_roots'],roots['total_merkle_roots'])
        for variables in (0,1):
            self.assertEqual(internal_root_declarations(variables,1,1)['total_merkle_roots'],0)
        for args in [(3,1,2),(3,0,0),(-1,1,1),(True,1,1)]:
            with self.subTest(args=args),self.assertRaises(ValueError):
                internal_root_declarations(*args)

    def test_schema_and_conservative_native_query_ceiling(self):
        bb=schedule_ceiling(dict(prime=2013265921,width=8,lwe_dimension=728,lookup_repetitions=1))
        gold=schedule_ceiling(dict(prime=18446744069414584321,width=4,lwe_dimension=728,lookup_repetitions=1))
        self.assertEqual(bb['private_root_slots'],76)
        self.assertEqual(gold['private_root_slots'],132)
        self.assertEqual(bb['ordered_query_ceilings'],[266,16,185,14])
        self.assertEqual(gold['ordered_query_ceilings'],[298,32,211,26])
        # Independently observed native traces include repeated calls and aliases.
        for observed,ceilings in [([253,8,173,7],bb['ordered_query_ceilings']),
                                  ([275,16,187,13],gold['ordered_query_ceilings'])]:
            self.assertTrue(all(n<=cap for n,cap in zip(observed,ceilings)))
        toy=schedule_ceiling(dict(prime=2013265921,width=8,lwe_dimension=21,lookup_repetitions=1))
        self.assertLess(toy['ordered_query_ceilings'][0],bb['ordered_query_ceilings'][0])
        with self.assertRaises(ValueError):
            schedule_ceiling(dict(prime=2013265921,width=8,lwe_dimension=728,lookup_repetitions=2))

    def test_large_native_rationals_roundtrip_without_decimal_conversion(self):
        terms=opening_terms(21,2013265921,6,1024)
        self.assertGreater(terms['nearby_consistency'].denominator.bit_length(),20000)
        for value in terms.values():
            encoded=encode(value)['exact']
            restored=Fraction(int(encoded['numerator_hex'],16),int(encoded['denominator_hex'],16))
            self.assertEqual(restored,value)

    def test_dummy_constant_and_terminal_error_radius(self):
        a=opening_terms(0,101,1,1)
        self.assertEqual(a,opening_terms(1,101,1,1))
        self.assertEqual(a['vector_projection'],Fraction(20,101))
        self.assertEqual(a['rolling_field'],Fraction(12,101))
        self.assertEqual(a['nearby_consistency'],0)
        self.assertEqual(a['total'],1)

    def test_nearby_production_witness_geometry(self):
        # Source length sixteen/degree eight matches the tested local witness:
        # two rejecting pairs out of eight => consistency miss fraction 3/4.
        self.assertEqual(opening_terms(3,101,6,1)['nearby_consistency'],Fraction(3,4))

    def test_sampling_does_not_remove_field_error(self):
        low=opening_terms(21,2013265921,6,128)
        high=opening_terms(21,2013265921,6,1024)
        self.assertGreater(low['total'],Fraction(1,2**128))
        self.assertLess(high['total'],Fraction(1,2**128))
        self.assertEqual(low['rolling_field'],high['rolling_field'])
        self.assertGreater(high['total'],high['rolling_field'])
        stronger=opening_terms(21,2013265921,8,1024)
        self.assertLess(stronger['total'],high['total'])

    def test_invalid_and_boolean_geometry_rejected(self):
        for args in [(-1,101,6,128),(True,101,6,128),(3,2,6,128),
                     (3,101,0,128),(3,101,6,0),(3,101,True,128)]:
            with self.subTest(args=args),self.assertRaises(ValueError):opening_terms(*args)


if __name__=='__main__':unittest.main()
