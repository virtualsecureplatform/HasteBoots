import hashlib
from pathlib import Path
import tempfile
import unittest

from audit_classical_column_readers import (LABEL, MAXIMUM, replay_samples,
    audit_columns, compare_column_counts, COLUMN_METRICS)
from audit_classical_role_contexts import role_geometry
from classical_profile_descriptor import decode_descriptor
from test_classical_candidate_terms import native
from test_classical_reader_event_stream import HEADER, start, output
from test_classical_request_boundaries import root, frame


def fixture(quota=2):
    profile = decode_descriptor(native(0, version=4, variables=[8, 11, 3, 6], role_queries=[quota]*4))
    contexts = dict(profile_id_sha512='0'*128, all_declared_context_preimages_observed=True,
        roles=[dict(role=role, context_sha512=f'{role+1:02x}'*64,
                    geometry=role_geometry(profile, role)) for role in range(4)])
    request = root()+frame(1, b'mw brakedown row-code v2', bytes([1])*64)
    request += frame(1, b'mw linear responses', b'synthetic fixture')+frame(2, LABEL, (8).to_bytes(8, 'little'))
    queries = []
    accepted = 0
    while accepted < quota:
        raw = hashlib.shake_256(request).digest(8)
        queries.append((request, raw))
        accepted += int.from_bytes(raw, 'little') < MAXIMUM-MAXIMUM % 32
        request += frame(3, LABEL, raw)+frame(2, LABEL, (8).to_bytes(8, 'little'))
    return profile, contexts, queries, request


def events(reader, query):
    request, raw = query
    return start(reader, request, 2)+output(reader, 0, raw, 2)


class ColumnReaderTests(unittest.TestCase):
    def inspect(self, data, profile, contexts):
        data = HEADER+data
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'readers'
            path.write_bytes(data)
            return audit_columns(path, hashlib.sha512(data).hexdigest(), profile, contexts)

    def test_production_max_cutoff_retries_and_duplicates_are_not_deduplicated(self):
        result = replay_samples(32, 2, [MAXIMUM, 7, 7])
        self.assertTrue(result['completed'])
        self.assertEqual(result['ordered_indices'], [7, 7])
        self.assertEqual(result['distinct_indices'], [7])
        self.assertEqual(result['candidate_draws'], 3)
        self.assertEqual(result['max_candidates_per_value'], 2)
        self.assertEqual(replay_samples(32, 1, [MAXIMUM])['pending_attempts'], 1)
        self.assertEqual(replay_samples(32, 1, [0, 1])['trailing_candidates'], 1)
        for bad in [-1, 2**64, True]:
            with self.assertRaises(ValueError):
                replay_samples(32, 1, [bad])

    def test_actual_sha_ke_chain_and_repeated_root_instances_match_counters(self):
        profile, contexts, queries, _ = fixture()
        data = b''.join(events(i, query) for i, query in enumerate(queries))
        data += b''.join(events(i+len(queries), query) for i, query in enumerate(queries))
        result = self.inspect(data, profile, contexts)
        self.assertTrue(result['closed_observed_column_inventory'])
        self.assertEqual(result['root_family_count'], 1)
        self.assertEqual(result['families'][0]['root_reader_instances'], 2)
        row = result['column_inventory']['verify']
        self.assertEqual(row['column_sampling_phases'], 2)
        self.assertEqual(row['column_values_sampled'], 4)
        self.assertEqual(row['column_candidate_draws'], 2*len(queries))
        self.assertTrue(compare_column_counts(result, {key: row[key] for key in COLUMN_METRICS})['observed_column_counts_equal'])
        wrong = dict(row, column_values_sampled=5)
        with self.assertRaises(ValueError):
            compare_column_counts(result, wrong)
        self.assertFalse(result['semantic_stage_binding_established'])
        self.assertFalse(result['security_qualified'])

    def test_early_descendant_and_late_parent_output_do_not_repair_history(self):
        profile, contexts, queries, _ = fixture()
        result = self.inspect(events(1, queries[1])+events(0, queries[0]), profile, contexts)
        self.assertFalse(result['closed_observed_column_inventory'])
        self.assertEqual(result['families'][0]['first_position'], 1)
        with self.assertRaises(ValueError):
            compare_column_counts(result, {})
        request, raw = queries[0]
        data = start(0, request, 2)+output(0, 0, raw[:4], 2)
        data += events(1, queries[1])+output(0, 4, raw[4:], 2)
        self.assertFalse(self.inspect(data, profile, contexts)['closed_observed_column_inventory'])

    def test_forked_past_bytes_and_post_quota_queries_remain_unresolved(self):
        profile, contexts, queries, after = fixture()
        request, raw = queries[0]
        changed = bytearray(raw); changed[7] ^= 0x80
        fork = request+frame(3, LABEL, changed)+frame(2, LABEL, (8).to_bytes(8, 'little'))
        data = events(0, queries[0])+events(1, (fork, hashlib.shake_256(fork).digest(8)))
        result = self.inspect(data, profile, contexts)
        self.assertFalse(result['closed_observed_column_inventory'])
        self.assertEqual(result['root_family_count'], 1)
        data = b''.join(events(i, query) for i, query in enumerate(queries))
        data += events(len(queries), (after, hashlib.shake_256(after).digest(8)))
        result = self.inspect(data, profile, contexts)
        self.assertFalse(result['closed_observed_column_inventory'])
        self.assertEqual(result['root_family_count'], 1)

    def test_partial_outputs_and_unknown_contexts_do_not_disappear(self):
        profile, contexts, queries, _ = fixture()
        request, raw = queries[0]
        result = self.inspect(start(0, request, 2)+output(0, 0, raw[:4], 2), profile, contexts)
        self.assertFalse(result['closed_observed_column_inventory'])
        self.assertEqual(result['column_reader_instances'], 1)
        changed = request.replace(bytes([1])*64, bytes([9])*64)
        result = self.inspect(events(0, (changed, hashlib.shake_256(changed).digest(8))), profile, contexts)
        self.assertFalse(result['closed_observed_column_inventory'])
        self.assertEqual(len(result['unresolved_readers']), 1)


if __name__ == '__main__':
    unittest.main()
