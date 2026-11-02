import hashlib
from pathlib import Path
import tempfile
import unittest

from audit_classical_reader_inventory import FIELD_METRICS, audit_inventory, compare_field_counts
from audit_classical_request_boundaries import RECEIPT
from test_classical_reader_event_stream import HEADER, start, output
from test_classical_request_boundaries import PRIME, frame, root


def field_request(count, label=b'field'):
    return root()+frame(4, label, PRIME.to_bytes(16, 'little')+count.to_bytes(8, 'little'))


def sampled_raw(request, count):
    oracle = hashlib.shake_256(request)
    draws = accepted = 0
    while accepted < count:
        draws += 1
        raw = oracle.digest(4*draws)
        accepted += (int.from_bytes(raw[-4:], 'little') & (2**31-1)) < PRIME
    return oracle.digest(4*draws)


def read(reader, request, data, offset=0):
    return output(reader, offset, data, 2)


def receipt(reader, raw):
    request = RECEIPT+raw
    return start(reader, request, 2)+read(reader, request, hashlib.shake_256(request).digest(64))


class ReaderInventoryTests(unittest.TestCase):
    def inspect(self, events, profile='0'*128):
        data = HEADER+events
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'events'
            path.write_bytes(data)
            return audit_inventory(path, hashlib.sha512(data).hexdigest(), PRIME, expected_profile=profile)

    def test_actual_descriptor_completion_receipts_and_counter_comparison(self):
        request = field_request(3)
        raw = sampled_raw(request, 3)
        events = start(0, request, 2)+read(0, request, raw[:2])+read(0, request, raw[2:], 2)
        events += receipt(1, raw)+read(0, request, b'', len(raw))
        for reader, request, length in [(2, root()+frame(2, b'bytes', (9).to_bytes(8, 'little')), 9),
                                        (3, root()+frame(8, b'parent checkpoint', b''), 64)]:
            events += start(reader, request, 2)+read(reader, request, hashlib.shake_256(request).digest(length))
        result = self.inspect(events)
        self.assertTrue(result['closed_observed_inventory'])
        self.assertEqual(len(result['matched_field_receipts']), 1)
        row = result['reader_inventory']['verify']
        self.assertEqual(row['field_values_sampled'], 3)
        self.assertEqual(row['field_candidate_draws'], len(raw)//4)
        self.assertEqual(row['field_output_bytes'], len(raw))
        counts = {key: row[key] for key in FIELD_METRICS}
        self.assertTrue(compare_field_counts(result, counts)['observed_field_counts_equal'])
        counts['field_values_sampled'] += 1
        with self.assertRaises(ValueError):
            compare_field_counts(result, counts)
        self.assertFalse(result['semantic_field_receipt_stage_binding_established'])
        self.assertFalse(result['native_verifier_caps_established'])
        self.assertFalse(result['security_qualified'])

    def test_later_matching_field_bytes_cannot_repair_a_prequeried_receipt(self):
        request = field_request(1)
        raw = sampled_raw(request, 1)
        result = self.inspect(receipt(1, raw)+start(0, request, 2)+read(0, request, raw))
        self.assertFalse(result['closed_observed_inventory'])
        self.assertEqual(result['unmatched_receipt_readers'], [1])
        self.assertEqual(result['unmatched_field_readers'], [0])
        with self.assertRaises(ValueError):
            compare_field_counts(result, {})

    def test_duplicate_empty_field_streams_have_separate_causal_receipts(self):
        events = b''
        for reader, label in [(0, b'a'), (2, b'b')]:
            events += start(reader, field_request(0, label), 2)+receipt(reader+1, b'')
        result = self.inspect(events)
        self.assertTrue(result['closed_observed_inventory'])
        self.assertEqual(len(result['matched_field_receipts']), 2)
        self.assertEqual(result['reader_inventory']['verify']['field_sampling_phases'], 2)
        self.assertEqual(result['reader_inventory']['verify']['field_values_sampled'], 0)

    def test_incomplete_overread_foreign_and_unknown_queries_stay_explicit(self):
        request = field_request(3)
        raw = sampled_raw(request, 2)
        result = self.inspect(start(0, request, 2)+read(0, request, raw)+receipt(1, raw))
        self.assertFalse(result['closed_observed_inventory'])
        self.assertIn(0, result['incomplete_readers'])
        request = field_request(1)
        raw = sampled_raw(request, 1)
        too_long = hashlib.shake_256(request).digest(len(raw)+4)
        result = self.inspect(start(0, request, 2)+read(0, request, too_long))
        self.assertIn(0, result['incomplete_readers'])
        for request, profile in [(b'opaque', '0'*128),
                                  (root()+b'\x04', '0'*128),
                                  (field_request(0), '1'*128)]:
            result = self.inspect(start(0, request, 2), profile)
            self.assertEqual(len(result['unknown_readers']), 1)
            self.assertFalse(result['closed_observed_inventory'])
        request = root()+frame(2, b'huge', (2**64-1).to_bytes(8, 'little'))
        result = self.inspect(start(0, request, 2)+read(0, request, hashlib.shake_256(request).digest(2)))
        self.assertEqual(result['incomplete_readers'], [0])

    def test_wrong_receipt_raw_is_not_an_assumed_zero_probability_event(self):
        request = field_request(1)
        raw = sampled_raw(request, 1)
        result = self.inspect(start(0, request, 2)+read(0, request, raw)+receipt(1, raw+b'x'))
        self.assertEqual(result['unmatched_receipt_readers'], [1])
        self.assertEqual(result['unmatched_field_readers'], [0])
        self.assertFalse(result['closed_observed_inventory'])


if __name__ == '__main__':
    unittest.main()
