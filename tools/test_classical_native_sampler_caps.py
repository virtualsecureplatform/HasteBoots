from copy import deepcopy
import unittest

from audit_classical_native_sampler_caps import compare_audited_records
from classical_candidate_terms import candidate_terms
from test_classical_candidate_terms import native


def control(version=5):
    raw = native(0, version=version)
    candidate = candidate_terms(raw)
    header = dict(descriptor_bincode_hex=raw.hex(), profile_id_sha512=candidate['profile_id_sha512'],
                  profile_descriptor_sha512=candidate['profile_descriptor_sha512'])
    row = dict(ordinal=0, proof_sha256='1'*64, max_field_values_per_phase=7,
        max_column_values_per_phase=0 if version == 5 else 1,
        lookup_reciprocal_rejections=0, max_field_candidates_per_value=2,
        max_column_candidates_per_value=0 if version == 5 else 1,
        hash_queries=1, xof_queries=4, field_sampling_phases=1,
        max_hash_input=128, max_xof_input=100, xof_output_bytes=100)
    return dict(profile=header, measurements=[row], rejected_measurements=[dict(row)])


class NativeSamplerCapsTests(unittest.TestCase):
    def test_only_observed_records_are_checked_and_never_certify(self):
        for version in (4, 5):
            result = compare_audited_records(control(version))
            self.assertEqual(result['stopped_records_checked'], 2)
            self.assertEqual(result['outside_stopped_game_records'], 0)
            self.assertFalse(result['native_verifier_caps_established'])
            self.assertFalse(result['security_qualified'])
            self.assertFalse(result['honest_activity_compared_to_verifier_caps'])

    def test_shape_excess_and_inside_game_resource_excess_reject(self):
        rows = control()
        caps = compare_audited_records(rows)
        for key, bound in dict(caps['shape_caps'], **caps['conditional_verifier_caps']).items():
            changed = deepcopy(rows)
            changed['measurements'][0][key] = bound+1
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_audited_records(changed)
        changed = deepcopy(rows)
        changed['profile']['profile_id_sha512'] = '0'*128
        with self.assertRaises(ValueError):
            compare_audited_records(changed)

    def test_real_retry_observations_are_outside_not_invalidated(self):
        rows = control(version=4)
        caps = compare_audited_records(rows)
        for key, value in [('lookup_reciprocal_rejections', 1),
                           ('max_field_candidates_per_value', 513),
                           ('max_column_candidates_per_value', 9)]:
            changed = deepcopy(rows)
            changed['measurements'][0][key] = value
            changed['measurements'][0]['xof_queries'] = caps['conditional_verifier_caps']['xof_queries']+1
            result = compare_audited_records(changed)
            self.assertEqual(result['outside_stopped_game_records'], 1)
            self.assertEqual(result['stopped_records_checked'], 1)
            self.assertFalse(result['records'][0]['stopped_caps_checked'])
            # Shape violations are still real envelope mismatches, even when
            # a probabilistic analysis stop has already been crossed.
            changed['measurements'][0]['max_field_values_per_phase'] = caps['shape_caps']['max_field_values_per_phase']+1
            with self.assertRaises(ValueError):
                compare_audited_records(changed)


if __name__ == '__main__':
    unittest.main()
