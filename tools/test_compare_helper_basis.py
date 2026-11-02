import copy
import json
from pathlib import Path
import tempfile
import unittest
from compare_canonical_polyfrim import read_records
from compare_helper_basis import compare, cpu_set
from test_compare_canonical_polyfrim import records


def fixtures(basis):
    rows = records('brakedown')
    for row in rows:
        row.update(queries=544, basis_helpers=basis, helper_width=6 if basis else 8,
                   final_helper_width=6 if basis else 8, rs_encoders_sha256=['a'*64]*4,
                   contexts_sha256=[str(i if not basis or i % 2 == 0 else i+3)*64 for i in range(4)],
                   parameters_sha256=('b' if basis else 'a')*64)
        row['rs_layouts'] = []
        for role, n in enumerate((18, 21, 8, 11)):
            left = 3; message = 1 << (n-left-3)
            row['rs_layouts'].append([n, 6 if basis and role % 2 else 8, left, 8, message, max(32, message*2)])
        if basis:
            row.update(proof_bytes=80, complete_s=9, prove_s=7, phase_s=[.8]*7)
    return rows


class HelperBasisTest(unittest.TestCase):
    def read(self, rows, basis):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'run.log'
            path.write_text('\n'.join('HB_CANONICAL_PBS '+json.dumps(row) for row in rows))
            return read_records(path, 'babybear', 'brakedown', True, False, 1, 1, basis_helpers=basis)

    def test_same_encoder_different_bound_helper_geometry(self):
        result = compare(self.read(fixtures(False), False), self.read(fixtures(True), True))
        self.assertAlmostEqual(result['latency_reduction'], .1)
        self.assertEqual(result['maximum_byte_ratio'], .8)
        self.assertFalse(result['whole_security_matched'])
        self.assertFalse(result['performance_gate'])

    def test_reader_rejects_width_domain_and_policy_changes(self):
        rows = fixtures(True)
        for key, value in [('basis_helpers', False), ('helper_width', 8), ('final_helper_width', 5),
                           ('contexts_sha256', []), ('rs_encoders_sha256', ['z'*64]*4)]:
            bad = copy.deepcopy(rows); bad[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.read(bad, True)
        for position in (0, 1, 2, 3, 4, 5):
            bad = copy.deepcopy(rows); bad[0]['rs_layouts'][1][position] += 1
            with self.subTest(position=position), self.assertRaises(ValueError): self.read(bad, True)
        with self.assertRaises(ValueError): self.read(rows, False)

    def test_comparison_rejects_other_protocol_changes(self):
        a, b = fixtures(False), fixtures(True)
        for key in ('native_keys_sha256', 'statement_sha256', 'trusted_setup_sha256'):
            bad = copy.deepcopy(b); bad[0][key] = 'c'*64
            with self.subTest(key=key), self.assertRaises(ValueError): compare(a, bad)
        bad = copy.deepcopy(b); bad[0]['rs_layouts'][1][2] += 1
        with self.assertRaises(ValueError): compare(a, bad)
        bad = copy.deepcopy(b); bad[0]['rs_encoders_sha256'][1] = 'c'*64
        with self.assertRaises(ValueError): compare(a, bad)
        bad = copy.deepcopy(b); bad[0]['contexts_sha256'][1] = a[0]['contexts_sha256'][1]
        with self.assertRaises(ValueError): compare(a, bad)

    def test_explicit_affinity_validation(self):
        self.assertEqual(cpu_set('0-15', range(24)), list(range(16)))
        self.assertEqual(cpu_set('2,4-5', range(24)), [2, 4, 5])
        for value in ('', '0,0', '2-1', '-1', '24', '0-999999999', 'a'):
            with self.subTest(value=value), self.assertRaises(ValueError): cpu_set(value, range(24))

if __name__ == '__main__': unittest.main()
