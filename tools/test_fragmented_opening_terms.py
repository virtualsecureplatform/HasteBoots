import unittest
from fractions import Fraction as F
from fragmented_opening_terms import shared_terms, terms, authentication_resources


class FragmentedOpeningTermsTests(unittest.TestCase):
    def test_authentication_counts_distinguish_shared_and_independent_indices(self):
        ordinary = authentication_resources(3, 4, 3, 2, 8, 'reference')
        virtual = authentication_resources(3, 4, 3, 2, 8, 'virtual')
        self.assertEqual(ordinary['authentication_hash_outputs'], 256)
        self.assertEqual(virtual['authentication_hash_outputs'], 128)
        self.assertEqual(ordinary['internal_merkle_root_declarations'], 5)
        self.assertEqual(virtual['internal_merkle_root_declarations'], 4)
        self.assertEqual((ordinary['independent_index_draws'], virtual['independent_index_draws']), (16, 8))
        self.assertEqual(virtual['source_fragment_field_elements_per_pair'], 8)

    def test_constant_authentication_and_invalid_domains(self):
        self.assertEqual(authentication_resources(0, 1, 8, 2, 7, 'reference')['authentication_hash_outputs'], 63)
        self.assertEqual(authentication_resources(0, 1, 8, 2, 7, 'virtual')['authentication_hash_outputs'], 28)
        for args in [(3, 3, 8, 2, 7, 'virtual'), (3, 4, 8, 2, True, 'virtual'),
                     (63, 1, 63, 8, 1, 'virtual')]:
            with self.assertRaises(ValueError):
                authentication_resources(*args)

    def test_shared_stage_composition_preserves_roles_and_sampling_modes(self):
        variables = [17, 21, 7, 11]
        queries = [1000, 1001, 1002, 1003]
        for mode in ['virtual', 'reference']:
            row = shared_terms(2013265921, 6, variables, 8, 12, 4, queries, mode)
            self.assertEqual([r['calls'] for r in row['roles']], [86, 8, 64, 7])
            total = F()
            for i, role in enumerate(row['roles']):
                expected = terms(2013265921, 6, variables[i], 8, 12, 4, queries[i], mode)
                self.assertEqual(role['per_call'], expected)
                total += role['calls']*F(expected['interactive_union'])
            self.assertEqual(F(row['opening_interactive_union']), min(F(1), total))
            self.assertFalse(row['security_qualified'])
            self.assertFalse(row['query_count_selected'])

    def test_shared_stage_rejects_missing_role_dimensions(self):
        for variables, queries in [([1, 2, 3], [8]*4), ([1]*4, [8]*3),
                                   ([1]*4, [8, True, 8, 8])]:
            with self.assertRaises(ValueError):
                shared_terms(2013265921, 6, variables, 8, 12, 2, queries, 'virtual')

    def test_constant_adapter_and_one_fragment_have_no_gamma_error(self):
        row = terms(97, 1, 0, 1, 8, 2, 64, 'virtual')
        self.assertEqual((row['scalar_logical_vars'], row['scalar_physical_vars']), (0, 1))
        self.assertEqual((row['fragment_length'], row['fragment_count']), (2, 1))
        self.assertEqual(F(row['gamma_phase']), 0)
        self.assertEqual(row['bridge_sumcheck_rounds'], 0)

    def test_exact_small_geometry_and_distinct_sampling_modes(self):
        v = terms(97, 1, 1, 1, 8, 2, 64, 'virtual')
        r = terms(97, 1, 1, 1, 8, 2, 64, 'reference')
        self.assertEqual(F(v['bridge_interactive_union']), F(3, 97))
        self.assertEqual(v['rolling_fold_phases'], [str(F(12, 97))])
        self.assertEqual(F(v['sampling_phase']), F(7, 8)**64)
        self.assertEqual(F(r['sampling_phase']), F(15, 16)**64)
        self.assertEqual(r['sampling_phases'], 2)
        self.assertEqual(F(v['interactive_union']), F(15, 97)+F(7, 8)**64)

    def test_power_degree_factor_and_native_helper_dimensions(self):
        row = terms(2013265921, 6, 21, 8, 12, 2, 1, 'virtual')
        self.assertEqual((row['fragment_length'], row['fragment_count']), (4096, 4096))
        self.assertEqual(F(row['gamma_phase']), F(4095*8192*8193, 2013265921**6))
        self.assertFalse(row['security_qualified'])
        self.assertFalse(row['query_count_selected'])

    def test_invalid_inputs(self):
        for index, value in [(0, True), (1, 0), (2, -1), (3, 3), (4, 0), (5, 3), (6, 0), (7, 'unknown')]:
            args = [97, 1, 1, 1, 8, 2, 8, 'virtual']
            args[index] = value
            with self.assertRaises(ValueError):
                terms(*args)


if __name__ == '__main__':
    unittest.main()
