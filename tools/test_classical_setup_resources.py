import unittest

from classical_setup_resources import (setup_resources, prover_commitment_resources,
                                       prover_opening_hash_resources, prover_hash_resources,
                                       prover_stopped_resource_model)
from test_classical_candidate_terms import native


class SetupResourcesTests(unittest.TestCase):
    def test_stopped_prover_model_retains_coupling_and_uncapped_loop_premises(self):
        row = prover_stopped_resource_model(native(0, version=5, role_queries=[1]*4))
        self.assertEqual(row['xof_queries_upper_bound'], 1265)
        self.assertEqual(row['field_sampling_phases_upper_bound'], 544)
        self.assertEqual(len(row['stops']), 2)
        old = prover_stopped_resource_model(native(0, version=4, role_queries=[1]*4))
        self.assertEqual(len(old['stops']), 3)
        self.assertGreater(old['xof_queries_upper_bound'], row['xof_queries_upper_bound'])
        self.assertFalse(row['production_loops_capped'])
        self.assertFalse(row['prover_verifier_resource_coupling_established'])
        self.assertFalse(row['unconditional_prover_resources_bounded'])

    def test_successful_prover_hash_union_keeps_xof_and_rejected_paths_open(self):
        result = prover_hash_resources(native(0, version=5, role_queries=[1]*4))
        self.assertEqual(result['external_role_context_calls'], [177, 15, 144, 16])
        self.assertEqual(result['external_context_hash_queries'], 352)
        self.assertEqual(result['hash_queries_upper_bound'], 20140)
        self.assertEqual(result['hash_input_bytes_upper_bound'], 3787937044+330*199+352*199+712)
        self.assertTrue(result['successful_prover_hash_resources_bounded'])
        self.assertFalse(result['xof_resources_bounded'])
        self.assertFalse(result['rejected_prover_paths_bounded'])
        self.assertFalse(result['full_prover_resources_bounded'])

    def test_openings_charge_state_check_and_binding_without_rehashing_paths(self):
        for version in (4, 5):
            result = prover_opening_hash_resources(native(0, version=version))
            self.assertEqual([row['calls_upper_bound'] for row in result['roles']], [86, 8, 64, 7])
            self.assertEqual(result['hash_queries_upper_bound'], 330)
            self.assertEqual(result['hash_input_bytes_upper_bound'], 330*199)
            self.assertFalse(result['merkle_paths_rehashed'])
            self.assertFalse(result['full_prover_resources_bounded'])
        with self.assertRaises(ValueError):
            prover_opening_hash_resources(native(0, version=5, variables=[5]*4))

    def test_native_prover_commitments_and_lookup_repetitions(self):
        descriptor = native(0, version=5, role_queries=[1]*4)
        result = prover_commitment_resources(descriptor, repetitions=1)
        self.assertEqual([row['tables'] for row in result['roles']], [36, 8, 25, 7])
        self.assertEqual(result['committed_roots'], 76)
        self.assertEqual(result['hash_queries_upper_bound'], 19456)
        repeated = prover_commitment_resources(descriptor, repetitions=3)
        self.assertEqual([row['tables'] for row in repeated['roles']], [36, 24, 25, 21])
        self.assertEqual(repeated['hash_queries_upper_bound']-result['hash_queries_upper_bound'],
                         16*1024 + 14*64)
        self.assertFalse(result['full_prover_resources_bounded'])
        gold = prover_commitment_resources(native(0, prime='18446744069414584321',
            degree=3, width=4, version=4), repetitions=1)
        self.assertEqual([row['tables'] for row in gold['roles']], [60, 16, 43, 13])
        self.assertEqual(gold['committed_roots'], 132)
        for bad in (0, -1, True, 2**64):
            with self.assertRaises(ValueError):
                prover_commitment_resources(descriptor, repetitions=bad)

    def test_native_bb_matches_measured_upper_bound_without_using_measurement(self):
        result = setup_resources(native(0, version=5, role_queries=[1]*4),
                                 br_bits=8, ks_bits=5)
        self.assertEqual(result['standard_hash_queries_upper_bound'], 2502)
        self.assertEqual(result['hash_queries_upper_bound'], 2503)
        self.assertEqual(result['committed_roots'], 15)
        self.assertEqual([r['encoded_columns'] for r in result['commitments']], [128, 32])
        self.assertFalse(result['security_qualified'])
        self.assertEqual(result['profile_id_hash_input_bytes'], 356)
        self.assertEqual(result['commitments'][0]['leaf_hash_input_bytes_upper_bound'],
                         len(b'HasteBoots/mw-column/v1') + 9 + 512*8*8*9)
        self.assertGreater(result['hash_input_bytes_upper_bound'],
                           result['max_hash_input_bytes_upper_bound'])
        self.assertTrue(result['hash_input_bytes_bounded'])

    def test_goldilocks_radices_and_zero_optimization_keep_upper_bound(self):
        result = setup_resources(native(0, prime='18446744069414584321', degree=3,
                                       width=4, version=5), br_bits=8, ks_bits=5)
        self.assertEqual(result['committed_roots'], 29)
        self.assertEqual([r['encoded_columns'] for r in result['commitments']], [512, 32])
        self.assertEqual(result['standard_hash_queries_upper_bound'], 16*1024 + 13*64 + 6)
        self.assertTrue(result['zero_table_optimization_can_reduce_count'])
        self.assertEqual(result['xof_queries'], 0)

    def test_unsupported_paths_and_invalid_radices_fail_closed(self):
        for backend in range(1, 5):
            with self.assertRaises(ValueError):
                setup_resources(native(backend), br_bits=8, ks_bits=5)
        for bits in (0, -1, True, 31, 1.5):
            with self.assertRaises(ValueError):
                setup_resources(native(0), br_bits=bits, ks_bits=5)


if __name__ == '__main__':
    unittest.main()
