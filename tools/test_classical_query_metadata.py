"""Ensure correctness evidence cannot silently change trusted role query counts."""

import argparse
import unittest
from pathlib import Path
import subprocess
import sys
import tempfile

from compare_classical_native_validation import effective_queries
from run_classical_native_validation import role_counts


class QueryMetadataTests(unittest.TestCase):
    def test_atomic_columns_reject_conflicting_schedules_before_starting_jobs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/'must-not-be-created'
            for other in ('--atomic-ntt', '--atomic-phases', '--atomic-zerocheck'):
                result = subprocess.run([sys.executable, str(Path(__file__).with_name('run_classical_native_validation.py')),
                    '--runner', '/missing-runner', '--output', str(output), '--atomic-columns', other],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('not allowed with argument', result.stderr)
                self.assertFalse(output.exists())

    def test_legacy_uniform_and_distinct_role_counts(self):
        self.assertEqual(effective_queries({'queries': 7}), (7, 7, 7, 7))
        self.assertEqual(effective_queries({'queries': 7, 'role_queries': [7]*4}), (7,)*4)
        self.assertEqual(effective_queries({'queries': None, 'role_queries': [1, 2, 3, 4]}),
                         (1, 2, 3, 4))

    def test_malformed_or_conflicting_metadata_rejected(self):
        invalid = [
            {}, {'queries': True}, {'queries': 1.0}, {'queries': 0},
            {'queries': 2**64}, {'queries': None},
            {'queries': 1, 'role_queries': [1, 2, 3, 4]},
            {'queries': 1, 'role_queries': [True, 1, 1, 1]},
            {'queries': None, 'role_queries': [1]*4},
            {'queries': None, 'role_queries': [1, 2, 3]},
            {'queries': None, 'role_queries': [1, 2, 3, 0]},
            {'queries': None, 'role_queries': [1, 2, 3, 2**64]},
            {'queries': None, 'role_queries': [1, 2, 3, 4.0]},
            {'queries': None, 'role_queries': [True, 2, 3, 4]},
        ]
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(ValueError):
                effective_queries(row)

    def test_cli_requires_four_positive_machine_counts(self):
        self.assertEqual(role_counts('1, 2,3,4'), [1, 2, 3, 4])
        for value in ('1,2,3', '1,2,3,4,5', '1,2,3,0', '1,2,3,-1',
                      '1,2,3,4.0', '1,2,3,true', f'1,2,3,{2**64}'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                role_counts(value)


if __name__ == '__main__':
    unittest.main()
