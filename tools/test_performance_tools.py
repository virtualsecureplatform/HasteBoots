import unittest
from fractions import Fraction

from bench_pbs import summarize
from packed_budget import BABYBEAR, bounds, choose, component_bounds, lookup_component_bounds, decomposition_component_bounds, lane_decomposition_component_bounds, accumulator_component_bounds, monomial_component_bounds, key_switch_component_bounds


class BudgetTests(unittest.TestCase):
    def test_actual_component_uses_symbol_distance_and_validates_padding(self):
        component = dict(prime=BABYBEAR, width=8, degree=2, variables=18, factors=17,
                         row_message_scalars=16384, row_message_blocks=2048, row_encoded_blocks=4096,
                         block_width=8, queries=512)
        self.assertLessEqual(sum(component_bounds(component).values()), Fraction(1, 2**128))
        for changes in [dict(row_message_blocks=16384), dict(row_encoded_blocks=4097), dict(block_width=0)]:
            with self.assertRaises(ValueError):
                component_bounds(dict(component, **changes))
    def test_lookup_budget_counts_repetitions_prefix_responses_and_exclusions(self):
        component = dict(prime=BABYBEAR, width=8, degree=3, variables=18, factors=8,
                         row_message_scalars=16384, row_message_blocks=2048, row_encoded_blocks=4096,
                         block_width=8, queries=512, logical_len=1490944, public_table_len=256,
                         excluded_challenges=256, repetitions=16)
        result = lookup_component_bounds(component)
        self.assertEqual(result["rational_identity"], 8 * Fraction(1490944+255, BABYBEAR-256)**16)
        self.assertEqual(result["proximity"], 8*65 * (1-Fraction(2049,4096)/3)**512)
        self.assertGreater(sum(result.values()), Fraction(1,2**128))
        safer = lookup_component_bounds(dict(component, queries=544))
        self.assertLessEqual(sum(safer.values()), Fraction(1,2**128))
        fewer_reps = lookup_component_bounds(dict(component, repetitions=4))
        self.assertGreater(fewer_reps["rational_identity"], result["rational_identity"])
        extra_excluded = lookup_component_bounds(dict(component, excluded_challenges=257))
        self.assertGreater(extra_excluded["rational_identity"], result["rational_identity"])
        for change in [dict(degree=2), dict(excluded_challenges=1), dict(logical_len=1<<31), dict(repetitions=0)]:
            with self.assertRaises(ValueError):
                lookup_component_bounds(dict(component, **change))

    def test_canonical_decomposition_accounts_for_tuple_hashes_and_linear_checks(self):
        component = dict(prime=BABYBEAR, width=8, degree=3, variables=18, factors=8,
                         row_message_scalars=32768, row_message_blocks=4096, row_encoded_blocks=8192,
                         block_width=8, queries=544, logical_len=2097152, public_table_len=512,
                         excluded_challenges=513, repetitions=16, tuple_columns=3,
                         linear_checks=2, linear_sources=20)
        errors = decomposition_component_bounds(component)
        expected = 8*(Fraction(1024,BABYBEAR)+Fraction(2097152+511,BABYBEAR-513))**16
        self.assertEqual(errors["rational_identity"], expected)
        self.assertLessEqual(sum(errors.values()), Fraction(1,2**128))
        scalar = lookup_component_bounds(dict(component, tuple_columns=1))
        self.assertGreater(errors["rational_identity"], scalar["rational_identity"])
        self.assertGreater(errors["proximity"], scalar["proximity"])
        for change in [dict(linear_sources=10),dict(tuple_columns=2),dict(linear_checks=1)]:
            with self.assertRaises(ValueError):
                decomposition_component_bounds(dict(component, **change))

    def test_lane_budget_separates_helper_domain_and_counts_actual_pairs(self):
        component = dict(prime=BABYBEAR,width=8,degree=3,variables=18,factors=8,
                         row_message_scalars=32768,row_message_blocks=4096,row_encoded_blocks=8192,
                         block_width=8,queries=544,logical_len=2097152,public_table_len=512,
                         excluded_challenges=513,repetitions=16,tuple_columns=3,linear_checks=2,linear_sources=20,
                         helper_variables=21,helper_row_message_scalars=65536,helper_row_message_blocks=8192,
                         helper_row_encoded_blocks=16384,helper_block_width=8,helper_queries=544,
                         effective_repetitions=16,lookup_groups=2)
        result = lane_decomposition_component_bounds(component)
        self.assertLessEqual(sum(result.values()),Fraction(1,2**128))
        self.assertEqual(result["helper_random_linear_test"],16*Fraction(16384,BABYBEAR)**8)
        self.assertEqual(result["source_random_linear_test"],24*Fraction(8192,BABYBEAR)**8)
        rounded = lane_decomposition_component_bounds(dict(component,repetitions=9))
        self.assertEqual(rounded,result)
        for change in [dict(effective_repetitions=9),dict(lookup_groups=16),dict(helper_variables=18),dict(helper_row_encoded_blocks=8192)]:
            with self.assertRaises(ValueError):
                lane_decomposition_component_bounds(dict(component,**change))

    def test_accumulator_budget_validates_layout_and_uses_worst_response_count(self):
        component=dict(prime=BABYBEAR,width=8,degree=1,variables=18,factors=7,linear_relations=7,
                       polynomial_size=1024,rounds=728,padded_rounds=1024,coefficient_variables=7,
                       left_vars=3,source_queries=22,response_groups=14,row_message_scalars=32768,
                       row_message_blocks=4096,row_encoded_blocks=8192,block_width=8,queries=544)
        errors=accumulator_component_bounds(component)
        self.assertLessEqual(sum(errors.values()),Fraction(1,2**128))
        self.assertEqual(errors["random_linear_test"],7*Fraction(8192,BABYBEAR)**8)
        split=dict(component,left_vars=8,row_message_scalars=1024,row_message_blocks=128,row_encoded_blocks=256,response_groups=18)
        worst=accumulator_component_bounds(split)
        self.assertEqual(worst["proximity"],29*(1-Fraction(129,768))**544)
        self.assertEqual(accumulator_component_bounds(dict(split,response_groups=14)),worst)

        for change in [dict(rounds=0),dict(response_groups=13),dict(response_groups=15),dict(source_queries=21),dict(coefficient_variables=8),dict(padded_rounds=2048)]:
            with self.assertRaises(ValueError):accumulator_component_bounds(dict(component,**change))

    def test_monomial_budget_counts_links_and_repeated_root_openings(self):
        component=dict(prime=BABYBEAR,width=8,variables=18,polynomial_size=1024,
                       rounds=728,padded_rounds=1024,left_vars=3,row_message_scalars=32768,
                       row_message_blocks=4096,row_encoded_blocks=8192,block_width=8,queries=544)
        errors=monomial_component_bounds(component)
        self.assertLessEqual(sum(errors.values()),Fraction(1,2**128))
        self.assertEqual(errors["random_linear_test"],6*Fraction(8192,BABYBEAR)**8)
        self.assertEqual(errors["ntt_row_identity"],2*Fraction(11,BABYBEAR)**8)
        self.assertEqual(errors["ntt_coefficient_compression"],224*Fraction(15,BABYBEAR)**8)
        split=dict(component,left_vars=8,row_message_scalars=1024,row_message_blocks=128,row_encoded_blocks=256)
        self.assertEqual(monomial_component_bounds(split)["proximity"],40*(1-Fraction(129,768))**544)
        for change in [dict(rounds=0),dict(width=3),dict(padded_rounds=2048),dict(left_vars=19),dict(row_message_scalars=1024)]:
            with self.assertRaises(ValueError):monomial_component_bounds(dict(component,**change))

    def test_key_switch_budget_uses_actual_digit_and_endpoint_relations(self):
        component=dict(prime=BABYBEAR,width=8,variables=8,polynomial_size=1024,
                       output_dimension=728,basis_bits=5,digits=7,repetitions=16,left_vars=1,
                       row_message_scalars=128,row_message_blocks=16,row_encoded_blocks=32,block_width=8,queries=544,
                       helper_variables=11,helper_row_message_scalars=512,helper_row_message_blocks=64,
                       helper_row_encoded_blocks=128,helper_block_width=8,helper_queries=544)
        result=key_switch_component_bounds(component)
        self.assertLessEqual(sum(result.values()),Fraction(1,2**128))
        self.assertEqual(result["ntt_row_identity"],8*Fraction(1,BABYBEAR)**8)
        self.assertEqual(result["decomposition_linear_identity"],8*Fraction(15,BABYBEAR)**8)
        self.assertEqual(result["ntt_product_extraction_random_test"],32*Fraction(32,BABYBEAR)**8)
        self.assertEqual(result["ntt_product_extraction_proximity"],64*(1-Fraction(17,96))**544)
        for change in [dict(digits=8),dict(output_dimension=2000),dict(repetitions=0),dict(variables=9),dict(basis_bits=31)]:
            with self.assertRaises(ValueError):key_switch_component_bounds(dict(component,**change))

    def test_selected_parameters_meet_exact_union_bound(self):
        for target in [100, 128]:
            width, queries, errors = choose(BABYBEAR, 2, 18, 3, 512, 1024, target)
            self.assertLessEqual(sum(errors.values()), Fraction(1, 2**target))
            previous = bounds(BABYBEAR, width, 2, 18, 3, 512, 1024, queries - 1)
            self.assertGreater(sum(previous.values()), Fraction(1, 2**target))

    def test_more_relations_never_improve_bound(self):
        one = bounds(BABYBEAR, 6, 2, 18, 3, 512, 1024, 512)
        many = bounds(BABYBEAR, 6, 2, 18, 12, 512, 1024, 512)
        self.assertGreater(sum(many.values()), sum(one.values()))

    def test_warmups_are_excluded(self):
        result = summarize([
            {"warmup": True, "complete_ns": 10000, "proof_bytes": 7},
            {"warmup": False, "complete_ns": 10, "proof_bytes": 7},
            {"warmup": False, "complete_ns": 20, "proof_bytes": 9},
        ])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["metrics"]["complete_ns"]["median"], 15)
        self.assertEqual(result["metrics"]["proof_bytes"]["max"], 9)


if __name__ == "__main__":
    unittest.main()
