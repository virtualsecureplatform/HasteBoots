import hashlib
from pathlib import Path
import tempfile
import unittest

from audit_classical_oracle_event_stream import HEADER
from test_audit_classical_oracle_event_stream import event
from compare_classical_xof_request_streams import compare, _frame


class XofRequestStreamTests(unittest.TestCase):
    def check(self, data, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'trace.events'
            path.write_bytes(data)
            return compare(path, hashlib.sha512(data).hexdigest(), **kwargs)

    def test_explicit_continuation_mode_validates_exact_three_request_suffix(self):
        prime = 2013265921
        suffix = [_frame(4,b'fresh complete canonical certificate after',
                         prime.to_bytes(16,'little')+(1).to_bytes(8,'little')),
                  b'HasteBoots consumed field bytes v1'+b'abcd',
                  _frame(2,b'fresh complete canonical certificate bytes after',(32).to_bytes(8,'little'))]
        def trace(parts):
            return HEADER+event(2,1,b'protocol')+b''.join(event(2,1,s) for s in parts)+event(2,2,b'protocol')
        result = self.check(trace(suffix), continuation_prime=prime)
        self.assertEqual(result['excluded_prover_continuation_requests'],3)
        self.assertTrue(result['protocol_prefix_inputs_equal'])
        self.assertFalse(result['ordered_inputs_equal'])
        for parts in (suffix[:2], suffix+[b'extra'], [suffix[0],b'wrong receipt',suffix[2]]):
            with self.assertRaises(ValueError):
                self.check(trace(parts), continuation_prime=prime)
        with self.assertRaises(ValueError):
            self.check(trace(suffix))

    def test_ordered_inputs_match_despite_different_hash_events(self):
        body = b'x' * ((1 << 20) + 7)
        data = HEADER + event(1,0,b'setup') + event(2,1,b'')
        data += event(1,1,b'commitment') + event(2,1,body) + event(2,1,b'repeated')
        data += event(2,2,b'') + event(2,2,body) + event(1,2,b'path') + event(2,2,b'repeated')
        result = self.check(data)
        self.assertEqual(result['compared_requests'], 3)
        self.assertEqual(result['compared_input_bytes'], len(body)+8)
        self.assertFalse(result['all_stream_coupling_established'])

    def test_count_length_contents_and_order_mismatches_rejected(self):
        for left, right in (([b'a'], []), ([b'a'], [b'aa']),
                            ([b'a'], [b'b']), ([b'a',b'b'], [b'b',b'a'])):
            data = HEADER + b''.join(event(2,1,b) for b in left)
            data += b''.join(event(2,2,b) for b in right)
            with self.assertRaises(ValueError):
                self.check(data)
        with self.assertRaises(ValueError):
            self.check(HEADER + event(1,0,b'only setup'))

    def test_corrupted_hash_and_truncated_trace_rejected_before_comparison(self):
        data = HEADER + event(1,0,b'setup') + event(2,1,b'a') + event(2,2,b'a')
        bad = bytearray(data); bad[len(HEADER)+10+5] ^= 1
        for changed in (bad, data[:-1]):
            with self.assertRaises(ValueError):
                self.check(changed)


if __name__ == '__main__':
    unittest.main()
