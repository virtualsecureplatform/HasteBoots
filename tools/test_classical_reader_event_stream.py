import hashlib
from pathlib import Path
import tempfile
import unittest

from audit_classical_reader_event_stream import HEADER, LEGACY_HEADER, audit


def number(value, size=8):
    return value.to_bytes(size, 'little')


def start(reader, data, phase=1):
    return bytes([2, phase])+number(reader)+number(len(data))+data


def output(reader, offset, data, phase=1):
    return bytes([3, phase])+number(reader)+number(offset, 16)+number(len(data))+data


def legacy_start(data, phase=1):
    return bytes([2, phase])+number(len(data))+data


def hashed(data, phase=0):
    return bytes([1, phase])+number(len(data))+data+hashlib.sha512(data).digest()


class ReaderStreamTests(unittest.TestCase):
    def check(self, data, legacy=None, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'reader.events'
            path.write_bytes(data)
            if legacy is not None:
                prior = Path(directory)/'legacy.events'
                prior.write_bytes(legacy)
                kwargs['legacy_path'] = prior
            return audit(path, **kwargs)

    def test_interleaved_repeated_readers_and_exact_query_projection(self):
        raw = hashlib.shake_256(b'field').digest(80)
        data = HEADER+hashed(b'root')+start(8, b'field')+output(8, 0, raw[:5])
        data += start(2, b'field')+output(2, 0, raw[:8])+output(8, 5, raw[5:])
        data += output(8, 80, b'', 2)+hashed(b'leaf', 2)+start(9, b'unread', 2)
        legacy = LEGACY_HEADER+hashed(b'root')+legacy_start(b'field')*2
        legacy += hashed(b'leaf', 2)+legacy_start(b'unread', 2)
        result = self.check(data, legacy,
            expected_sha512=hashlib.sha512(data).hexdigest(),
            expected_legacy_sha512=hashlib.sha512(legacy).hexdigest())
        self.assertEqual(result['reader_instances'], 3)
        self.assertEqual(result['phases']['prove']['output_bytes'], 88)
        self.assertEqual(result['phases']['verify']['max_reader_output'], 80)
        self.assertTrue(result['legacy_query_projection_exactly_equal'])
        self.assertTrue(result['consumed_shake256_bytes_verified'])
        self.assertFalse(result['reader_instances_are_distinct_oracle_inputs'])
        self.assertFalse(result['security_qualified'])

    def test_rejects_bad_reader_identity_offsets_and_actual_output(self):
        raw = hashlib.shake_256(b'a').digest(8)
        cases = [
            output(0, 0, raw),
            start(0, b'a')+start(0, b'a'),
            start(0, b'a')+output(0, 1, raw),
            start(0, b'a')+output(0, 0, bytes([raw[0]^1])+raw[1:]),
            start(0, b'a')+output(0, 0, raw)+output(0, 0, raw),
        ]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check(HEADER+data)

    def test_rejects_hash_corruption_phase_regression_and_truncation(self):
        raw = hashlib.shake_256(b'a').digest(8)
        good = HEADER+start(0, b'a')+output(0, 0, raw)
        for data in [b'bad header', HEADER+hashed(b'a')[:-1]+b'x',
                     HEADER+start(0, b'a', 2)+output(0, 0, raw, 1), good[:-1]]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.check(data)

    def test_same_query_counts_do_not_hide_reordered_legacy_events(self):
        data = HEADER+start(0, b'a')+start(1, b'b')
        reversed_legacy = LEGACY_HEADER+legacy_start(b'b')+legacy_start(b'a')
        with self.assertRaises(ValueError):
            self.check(data, reversed_legacy)
        with self.assertRaises(ValueError):
            self.check(data, LEGACY_HEADER+legacy_start(b'a')+legacy_start(b'b')+legacy_start(b'c'))

    def test_fingerprints_and_missing_legacy_file_fail_closed(self):
        data = HEADER+start(0, b'a')
        legacy = LEGACY_HEADER+legacy_start(b'a')
        with self.assertRaises(ValueError):
            self.check(data, expected_sha512='0'*128)
        with self.assertRaises(ValueError):
            self.check(data, legacy, expected_legacy_sha512='0'*128)
        with self.assertRaises(ValueError):
            self.check(data, expected_legacy_sha512='0'*128)
        self.assertFalse(self.check(data)['legacy_query_projection_exactly_equal'])


if __name__ == '__main__':
    unittest.main()
