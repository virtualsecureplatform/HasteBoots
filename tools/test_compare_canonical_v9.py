import copy
import unittest

from compare_canonical_v9 import matched_workload


def fixture():
    canonical = dict(v9_fixture=True, prime=2013265921, width=8, ring_dimension=1024,
                     lwe_dimension=728, output_dimension=728, extension_degree=6,
                     lookup_repetitions=1, native_keys_sha256='a'*64,
                     fhe_parameters_sha256='b'*64, statement_sha256='c'*64,
                     left=0, right=0, output=1)
    v9 = dict(packets=[dict(prime=2013265921, width=8, polynomial_size=1024,
                           input_dimension=728, output_dimension=728, lookup_field_degree=6,
                           lookup_repetitions=1, native_keys_sha256='a'*64,
                           fhe_parameters_sha256='b'*64)],
              members=[dict(statement_sha256='c'*64, left_plaintext=0,
                            right_plaintext=0, decrypted_plaintext=1)])
    return v9, [canonical]


class WorkloadTests(unittest.TestCase):
    def test_cross_protocol_workload_matches_without_proof_identity(self):
        old, new = fixture()
        old['packets'][0].update(proof_bytes=100, proof_sha256='d'*64)
        new[0].update(proof_bytes=120, proof_sha256='e'*64)
        self.assertTrue(matched_workload(old, new))

    def test_reject_changed_keys_statement_parameters_or_policy(self):
        for key, value in (('v9_fixture', False), ('v9_fixture', 1),
                           ('native_keys_sha256', 'd'*64), ('fhe_parameters_sha256', 'd'*64),
                           ('statement_sha256', 'd'*64), ('left', 1), ('output', 0),
                           ('ring_dimension', 32), ('extension_degree', 3),
                           ('lookup_repetitions', True)):
            old, new = fixture()
            new[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                matched_workload(old, new)
        old, new = fixture()
        with self.assertRaises(ValueError): matched_workload(old, [])
        bad = copy.deepcopy(old); bad['members'] = []
        with self.assertRaises(ValueError): matched_workload(bad, new)


if __name__ == '__main__':
    unittest.main()
