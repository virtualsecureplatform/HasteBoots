from fractions import Fraction as F
from itertools import product
import unittest
from classical_sampler_resources import rejection_envelope, column_rejection_envelope
from classical_candidate_terms import candidate_terms
from test_classical_candidate_terms import native, rational


class SamplerResourceTests(unittest.TestCase):
    def test_fragment_metadata_includes_all_six_fixed_bindings(self):
        # The Rust raw-prefix audit independently counts these fixed bindings
        # plus every bridge message and rolling-root/terminal message.
        for backend in (2,4):
            candidate=candidate_terms(native(backend))
            profile=candidate['profile']
            resources=candidate['pcs_xof_resource_envelope']['roles']
            frames=candidate['pcs_frame_resource_envelope']['roles']
            for resource,row in zip(resources,frames):
                role=row['role']
                scalar=profile['role_variables'][role]+(profile['role_widths'][role]-1).bit_length()
                expected=resource['calls']*(6+scalar+resource['rolling_rounds_per_call'])
                self.assertEqual(row['metadata_frames'],expected)

    def test_column_cutoff_matches_exhaustive_streams(self):
        for domain in (1, 2, 3, 4, 7):
            row = column_rejection_envelope(domain, 1, 3, sample_bits=3)
            counts = [0]*domain
            rejected = 0
            cutoff = 7-7 % domain
            for stream in product(range(8), repeat=3):
                accepted = next((v % domain for v in stream if v < cutoff), None)
                if accepted is None:
                    rejected += 1
                else:
                    counts[accepted] += 1
            self.assertEqual(F(rejected, 512), rational(row['first_excess_union']))
            self.assertEqual(len(set(counts)), 1)
            self.assertEqual(row['byte_challenge_queries_upper_bound'], 3)
        # The existing Rust cutoff rejects a full block even for power-of-two domains.
        self.assertEqual(rational(column_rejection_envelope(128, 1)['rejection_probability']), F(128, 2**64))

    def test_native_column_counts_charge_all_calls_and_retries(self):
        candidate = candidate_terms(native(0))
        for role in candidate['roles']:
            resources = role['column_sampler_resource_envelope']
            total = resources['all_calls']
            self.assertEqual(total['independent_draws'], resources['calls']*role['queries'])
            self.assertEqual(total['byte_challenge_queries_upper_bound'], 8*total['independent_draws'])
            self.assertEqual(total['byte_challenge_output_bytes_upper_bound'], 64*total['independent_draws'])
        for args in [(0, 1), (2**64, 1), (32, True), (32, 1, 0), (32, 1, 1.0)]:
            with self.assertRaises(ValueError):
                column_rejection_envelope(*args)

    def test_pcs_accounting_preserves_backend_invariants(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            resources = [candidate_terms(native(b, prime, degree, width))[
                'pcs_xof_resource_envelope'] for b in range(5)]
            # Dictionary transport changes no transcript sampling or child linkage.
            self.assertEqual(resources[1], resources[3])
            ordinary, virtual = resources[2], resources[4]
            self.assertEqual(ordinary['field_xof_queries'], virtual['field_xof_queries'])
            self.assertEqual(ordinary['checkpoint_queries'], virtual['checkpoint_queries'])
            calls = sum(r['calls'] for r in ordinary['roles'])
            # Virtual mode eliminates exactly the separate consistency-index phase.
            self.assertEqual(ordinary['xof_queries']-virtual['xof_queries'], calls)
            for envelope in resources:
                self.assertEqual(envelope['xof_queries'], envelope['field_xof_queries']+
                    envelope['checkpoint_queries']+envelope['byte_challenge_queries'])
                self.assertFalse(envelope['global_resource_bound_established'])
            self.assertEqual(resources[0]['checkpoint_queries'], 0)

    def test_pcs_frame_transport_and_virtual_phase_invariants(self):
        frames = [candidate_terms(native(b))['pcs_frame_resource_envelope'] for b in range(5)]
        self.assertEqual(frames[1], frames[3])
        calls = sum(r['calls'] for r in candidate_terms(native(2))['pcs_xof_resource_envelope']['roles'])
        self.assertEqual(frames[2]['additional_frames']-frames[4]['additional_frames'], 3*calls)
        for envelope in frames:
            self.assertEqual(envelope['additional_frames'], sum(r['additional_frames'] for r in envelope['roles']))
            self.assertEqual(envelope['additional_framed_input_bytes'],
                             envelope['additional_frames']*envelope['maximum_frame_bytes'])
            self.assertGreater(envelope['maximum_frame_bytes'], 2**65)
            self.assertFalse(envelope['global_resource_bound_established'])

    def test_full_frame_bound_contains_every_reported_component(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            parents = []
            for backend in range(5):
                candidate = candidate_terms(native(backend, prime, degree, width))
                row = candidate['verifier_frame_resource_envelope']
                parents.append(row['parent_frames'])
                self.assertEqual(row['total_frames'], row['parent_frames']+row['pcs_additional_frames'])
                self.assertEqual(row['parent_frames'], sum(row['parent_metadata_frames'].values())+
                    row['parent_prime_field_frames']+row['parent_extension_field_frames']+
                    row['parent_lookup_child_link_frames']+row['parent_checkpoint_frames'])
                self.assertGreaterEqual(row['maximum_xof_query_input_bytes'], row['maximum_framed_prefix_bytes'])
                self.assertGreaterEqual(row['maximum_xof_query_input_bytes'], row['maximum_receipt_producer_input_bytes'])
                self.assertEqual(row['maximum_overlapping_64_byte_windows_per_input'], row['maximum_xof_query_input_bytes']-63)
                self.assertFalse(row['global_resource_bound_established'])
            self.assertEqual(len(set(parents)), 1)

    def test_native_xof_work_offsets_remain_explicit_and_monotone(self):
        from classical_sampler_resources import native_xof_work_envelope
        for backend in range(5):
            candidate = candidate_terms(native(backend))
            args = (candidate['profile'], candidate['shared_stage_schedule'], candidate['parent'])
            with self.assertRaises(TypeError):
                native_xof_work_envelope(*args)
            zero = native_xof_work_envelope(*args, honest_outputs=0)
            offset = native_xof_work_envelope(*args, honest_outputs=1000)
            self.assertEqual(zero['coefficients']['quadratic'], offset['coefficients']['quadratic'])
            for key in ('constant', 'linear'):
                self.assertGreater(rational(offset['coefficients'][key]), rational(zero['coefficients'][key]))
            self.assertEqual(zero['outputs_per_work'],
                1+candidate['verifier_xof_resource_envelope']['totals']['xof_queries'])
            self.assertFalse(offset['resource_coupling_established'])
            self.assertFalse(offset['eligible_input_filter_established'])
            self.assertTrue(offset['length_filter_preserves_bounded_trace_outside_output_collisions'])
            self.assertFalse(offset['whole_proof_security_certified'])

    def test_verifier_parent_inventory_and_child_overheads(self):
        for prime, degree, width in [('2013265921', 6, 8), ('18446744069414584321', 3, 4)]:
            parents = []
            for backend in range(5):
                candidate = candidate_terms(native(backend, prime, degree, width))
                envelope = candidate['verifier_xof_resource_envelope']
                parent = envelope['parent']
                parents.append(parent)
                self.assertEqual(parent['field_phases'], candidate['parent']['phase_count']+3)
                self.assertEqual(parent['checkpoint_queries'], 6)
                self.assertEqual(parent['byte_challenge_queries'], 6)
                for key, value in envelope['totals'].items():
                    self.assertEqual(value, parent[key]+envelope['pcs'][key])
                self.assertFalse(envelope['global_resource_bound_established'])
            self.assertTrue(all(p == parents[0] for p in parents))

    def test_verifier_output_stop_is_nonzero_and_can_be_tightened(self):
        from classical_sampler_resources import native_verifier_output_envelope
        for backend in range(5):
            candidate = candidate_terms(native(backend))
            row = candidate['verifier_xof_output_envelope']
            stronger = native_verifier_output_envelope(candidate['profile'],
                candidate['shared_stage_schedule'], candidate['parent'], candidate_limit=1024)
            self.assertGreater(rational(row['canonical_field_stop_union']), 0)
            self.assertLess(rational(stronger['canonical_field_stop_union']),
                            rational(row['canonical_field_stop_union']))
            self.assertEqual(stronger['field_raw_output_bytes'], 2*row['field_raw_output_bytes'])
            self.assertEqual(stronger['xof_queries'], row['xof_queries'])
            self.assertEqual(rational(row['additional_sampler_stop_union']),
                rational(row['canonical_field_stop_union'])+rational(row['column_stop_union']))
            self.assertEqual(row['total_xof_output_bytes'], sum(row[k] for k in (
                'field_raw_output_bytes', 'field_receipt_output_bytes',
                'byte_challenge_output_bytes', 'checkpoint_output_bytes')))
            self.assertEqual(rational(row['column_stop_union']) > 0, backend == 0)
            self.assertFalse(row['global_resource_bound_established'])

    def test_exact_stopping_event_and_uniform_conditional_values(self):
        counts = [0]*5
        rejected = 0
        for stream in product(range(8), repeat=3):
            accepted = next((v for v in stream if v < 5), None)
            if accepted is None:
                rejected += 1
            else:
                counts[accepted] += 1
        row = rejection_envelope(5, 1, 3)
        self.assertEqual(F(rejected, 8**3), rational(row['first_excess_union']))
        self.assertEqual(len(set(counts)), 1)
        self.assertEqual(row['maximum_raw_bytes'], 3)
        self.assertEqual(rational(rejection_envelope(5, 0, 3)['first_excess_union']), 0)

    def test_native_shapes_and_disabled_global_qualification(self):
        for backend in range(5):
            row = candidate_terms(native(backend))['sampler_resource_envelope']
            self.assertEqual(row['coefficient_count_ceiling'], max(
                row['parent_coefficient_count_ceiling'], *row['pcs_role_coefficient_count_ceilings']))
            self.assertEqual(row['maximum_raw_bytes'], row['coefficient_count_ceiling']*512*4)
            self.assertFalse(row['global_resource_bound_established'])
            self.assertTrue(row['production_loop_unchanged'])

    def test_invalid_exact_inputs(self):
        for args in [(1, 1, 3), (5, True, 3), (5, 1, 0), (5, 1, 3.0), (2**128, 1, 3), (5, 2**64, 3)]:
            with self.assertRaises(ValueError):
                rejection_envelope(*args)


if __name__ == '__main__':
    unittest.main()
