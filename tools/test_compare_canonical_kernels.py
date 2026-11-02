import copy
import unittest
from compare_canonical_kernels import equivalent
from test_compare_canonical_polyfrim import records

class KernelComparison(unittest.TestCase):
    def test_timings_may_differ(self):
        before=records('brakedown');after=copy.deepcopy(before)
        after[1]['complete_s']=9.
        self.assertTrue(equivalent(before,after))
    def test_wire_and_workload_must_match(self):
        for key in ('proof_sha256','parameters_sha256','native_keys_sha256','statement_sha256','trusted_setup_sha256','fhe_parameters_sha256'):
            before=records('brakedown');after=copy.deepcopy(before);after[1][key]='b'*64
            with self.subTest(key=key),self.assertRaises(ValueError):equivalent(before,after)
        for key in ('proof_bytes','queries','root_slots','width','ordinal','group_index'):
            before=records('brakedown');after=copy.deepcopy(before);after[1][key]+=1
            with self.subTest(key=key),self.assertRaises(ValueError):equivalent(before,after)
        with self.assertRaises(ValueError):equivalent(records('brakedown'),[])

if __name__=='__main__':unittest.main()
