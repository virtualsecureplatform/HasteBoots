from fractions import Fraction as F
import hashlib
import unittest
import subprocess
import sys
import tempfile
import json
from pathlib import Path
from classical_candidate_terms import candidate_terms, candidate_oracle_work, candidate_classical_work
from classical_profile_descriptor import FIELD_NONRESIDUES
from test_classical_profile_descriptor import descriptor, uint, string


def native(backend, prime='2013265921', degree=6, width=8, version=4, variables=None, block_width=None, role_queries=None):
    w = FIELD_NONRESIDUES[(prime, degree)]
    old = descriptor(prime, degree, w, version)
    tail = old[old.index(string(prime)+uint(degree)):]
    variables = variables or [21-(width.bit_length()-1), 21, 11-(width.bit_length()-1), 11]
    geometry = lambda v: (b'\1'+uint(v//2)+b'\1'+uint(width if block_width is None else block_width)
                          if backend==0 else b'\0\0')
    roles = b''.join(uint(v)+uint(width)+uint(8+i if role_queries is None else role_queries[i])+geometry(v) for i, v in enumerate(variables))
    return uint(version)+uint(backend)+roles+uint(2)+(b'\1'+uint(12) if backend in (2, 4) else b'\0')+tail


def rational(encoded):
    return F(int(encoded['exact']['numerator_hex'], 16), int(encoded['exact']['denominator_hex'], 16))


class CandidateTermTests(unittest.TestCase):
    def test_combined_work_cli_requires_offsets_and_never_promotes(self):
        with tempfile.TemporaryDirectory() as temporary:
            descriptor_path = Path(temporary)/'profile.bin'
            output = Path(temporary)/'work.json'
            descriptor_path.write_bytes(native(1, version=5, role_queries=[2048]*4))
            command = [sys.executable, str(Path(__file__).with_name('classical_candidate_terms.py')),
                       '--descriptor', str(descriptor_path), '--output', str(output), '--classical-work']
            rejected = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse(output.exists())
            accepted = subprocess.run(command+['--honest-hashes', '0', '--honest-xof-outputs', '0',
                                                '--honest-roots', '0'], capture_output=True, text=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            row = json.loads(output.read_text())
            self.assertTrue(row['conditional_work_target_met'])
            self.assertFalse(row['security_qualified'])
            self.assertFalse(row['promotion_gate'])

    def test_combined_work_sums_components_before_minimizing(self):
        from classical_work_cost import minimum_work
        row = candidate_classical_work(native(1, version=5, role_queries=[2048]*4),
            honest_hashes=0, honest_xof_outputs=0, honest_roots=0)
        cost = rational(row['minimum_work_per_success_bound'])
        for key in ('constant', 'linear', 'quadratic'):
            self.assertEqual(rational(row['combined_polynomial'][key]),
                             sum(rational(c[key]) for c in row['components'].values()))
        for component in row['components'].values():
            isolated, _ = minimum_work([rational(component['linear']), rational(component['quadratic'])],
                                       rational(component['constant']))
            self.assertLessEqual(cost, isolated)
        self.assertTrue(row['conditional_work_target_met'])
        self.assertFalse(row['protocol_bound_established'])
        self.assertFalse(row['promotion_gate'])

    def test_conditional_work_rejects_weak_queries_fields_and_large_offsets(self):
        offsets = dict(honest_hashes=0, honest_xof_outputs=0, honest_roots=0)
        weak_queries = candidate_classical_work(native(1, version=5), **offsets)
        weak_field = candidate_classical_work(native(1, degree=4, version=5, role_queries=[2048]*4), **offsets)
        self.assertFalse(weak_queries['conditional_work_target_met'])
        self.assertFalse(weak_field['conditional_work_target_met'])
        saturated = candidate_classical_work(native(1, version=5, role_queries=[2048]*4),
            honest_hashes=2**512, honest_xof_outputs=0, honest_roots=0)
        self.assertEqual(rational(saturated['minimum_work_per_success_bound']), 1)
        with self.assertRaises(ValueError):
            candidate_classical_work(native(1), **offsets)
        with self.assertRaises(ValueError):
            candidate_classical_work(native(1, version=5), target_bits=True, **offsets)

    def test_strong_count_scenarios_remain_conditional_for_both_fields(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            for backend in range(5):
                row = candidate_classical_work(native(backend, prime, degree, width,
                    version=5, role_queries=[2048]*4), honest_hashes=2**40,
                    honest_xof_outputs=0, honest_roots=2**40)
                self.assertTrue(row['conditional_work_target_met'])
                self.assertFalse(row['security_qualified'])
                self.assertFalse(row['query_count_selected'])

    def test_atomic_columns_remove_retry_queries_but_keep_opening_bound(self):
        for backend in range(5):
            old = candidate_terms(native(backend, version=4))
            new = candidate_terms(native(backend, version=5))
            self.assertNotEqual(old['profile_id_sha512'], new['profile_id_sha512'])
            self.assertEqual(old['conditional_ideal_game_union'], new['conditional_ideal_game_union'])
            self.assertEqual(old['verifier_hash_outputs_upper_bound'], new['verifier_hash_outputs_upper_bound'])
            if backend == 0:
                self.assertLess(new['verifier_xof_resource_envelope']['totals']['xof_queries'],
                                old['verifier_xof_resource_envelope']['totals']['xof_queries'])
                self.assertEqual(rational(new['verifier_xof_output_envelope']['column_stop_union']), 0)
                for role in new['pcs_xof_resource_envelope']['roles']:
                    self.assertEqual(role['byte_challenge_queries'], role['calls'])
                    self.assertTrue(role['atomic_columns'])
            else:
                self.assertEqual(new['verifier_xof_resource_envelope']['totals'], old['verifier_xof_resource_envelope']['totals'])
            self.assertFalse(new['whole_security_certified'])

    def test_descriptor_bound_oracle_terms_require_all_honest_offsets(self):
        for backend in range(5):
            raw = native(backend)
            candidate = candidate_terms(raw)
            with self.assertRaises(TypeError):
                candidate_oracle_work(raw)
            row = candidate_oracle_work(raw, honest_hashes=0, honest_xof_outputs=0, honest_roots=0)
            self.assertEqual(row['profile_id_sha512'], candidate['profile_id_sha512'])
            hash_bound=candidate['verifier_hash_input_envelope']['maximum_hash_query_input_bytes']
            self.assertEqual(hash_bound,2**64-2)
            self.assertEqual(row['hash_windows_per_input'],hash_bound-63)
            self.assertLess(hash_bound,candidate['verifier_frame_resource_envelope']['maximum_xof_query_input_bytes'])
            self.assertEqual(row['hash_per_work'], 1+candidate['verifier_hash_outputs_upper_bound'])
            self.assertEqual(row['xof_per_work'], 1+candidate['verifier_xof_resource_envelope']['totals']['xof_queries'])
            self.assertFalse(row['resource_coupling_established'])
            self.assertFalse(row['whole_proof_security_certified'])
            self.assertEqual(rational(row['merkle']['constant']), 0)
            self.assertEqual(rational(row['xof']['constant']), 0)

    def test_composition_and_profile_identity_for_four_backends(self):
        for backend in [0, 1, 2, 3, 4]:
            data = native(backend)
            row = candidate_terms(data)
            self.assertEqual(row['profile_id_sha512'], hashlib.sha512(b'HasteBoots classical profile v1'+data).hexdigest())
            self.assertEqual([r['queries'] for r in row['roles']], [8, 9, 10, 11])
            pcs = sum(rational(r['contribution']) for r in row['roles'])
            self.assertEqual(rational(row['conditional_ideal_game_union']),
                             min(F(1), pcs+rational(row['parent_union'])))
            self.assertFalse(row['whole_security_certified'])
            self.assertFalse(row['promotion_gate'])
            self.assertFalse(row['fixed_source_contract']['actual_hash_xof_coupling_established'])
            self.assertEqual(row['authentication_hash_outputs_upper_bound'],
                             sum(r['authentication_hash_outputs_upper_bound'] for r in row['roles']))

    def test_goldilocks_geometry(self):
        for backend in [0, 1, 2, 3, 4]:
            row = candidate_terms(native(backend, '18446744069414584321', 3, 4))
            self.assertEqual(row['profile']['role_variables'], [19, 21, 9, 11])

    def test_dictionary_adds_one_context_hash_per_call(self):
        direct = candidate_terms(native(1))
        dictionary = candidate_terms(native(3))
        self.assertEqual(direct['authentication_hash_outputs_upper_bound'],
                         dictionary['authentication_hash_outputs_upper_bound'])
        calls = sum(direct['shared_stage_schedule']['role_opening_call_ceilings'])
        self.assertEqual(dictionary['pcs_total_hash_outputs_upper_bound']-
                         direct['pcs_total_hash_outputs_upper_bound'], calls)
        for backend in range(5):
            row = candidate_terms(native(backend))
            self.assertEqual(row['pcs_total_hash_outputs_upper_bound'], sum(
                r['pcs_total_hash_outputs_upper_bound'] for r in row['roles']))
            self.assertGreater(row['pcs_total_hash_outputs_upper_bound'],
                               row['authentication_hash_outputs_upper_bound'])

    def test_parent_contexts_include_duplicate_preflights_and_profile_ids(self):
        for prime, degree, width, expected in [('2013265921', 6, 8, [176, 15, 137, 15]),
                ('18446744069414584321', 3, 4, [288, 23, 221, 21])]:
            for backend in range(5):
                row = candidate_terms(native(backend, prime, degree, width))
                parent = row['parent_hash_resources']
                self.assertEqual(parent['role_context_calls'], expected)
                self.assertEqual(parent['total_context_hash_outputs'], sum(expected)*(2 if backend==3 else 1))
                self.assertEqual(row['verifier_hash_outputs_upper_bound'],
                    row['pcs_total_hash_outputs_upper_bound']+parent['total_context_hash_outputs']+2)

    def test_unsupported_or_non_native_descriptors_reject(self):
        for data in [native(0, block_width=1), native(1, version=3), native(1, variables=[17, 21, 8, 11])]:
            with self.assertRaises(ValueError):
                candidate_terms(data)


if __name__ == '__main__':
    unittest.main()
