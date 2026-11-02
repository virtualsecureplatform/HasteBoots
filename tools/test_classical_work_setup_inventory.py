import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from classical_candidate_terms import (candidate_classical_work,
    candidate_classical_work_with_setups, candidate_classical_work_for_lifetime)
from test_classical_candidate_terms import native


class WorkSetupInventoryTests(unittest.TestCase):
    def test_derived_setup_and_proof_offsets_preserve_conditional_scope(self):
        descriptor = native(0, version=5, role_queries=[2048]*4)
        result = candidate_classical_work_for_lifetime(descriptor, setups=2, proofs=3,
            remaining_hashes=7, remaining_xof_outputs=11, remaining_roots=13)
        direct = candidate_classical_work(descriptor, honest_hashes=7+2*2503+3*20140,
            honest_xof_outputs=11+3*1265, honest_roots=13+2*15+3*76)
        self.assertEqual(result['combined_polynomial'], direct['combined_polynomial'])
        self.assertEqual(result['minimum_work_per_success_bound'], direct['minimum_work_per_success_bound'])
        self.assertEqual(result['honest_offsets'], direct['honest_offsets'])
        inventory = result['honest_offset_inventory']
        self.assertFalse(inventory['all_honest_work_bounded'])
        self.assertFalse(inventory['honest_stopping_composition_established'])
        self.assertFalse(result['security_qualified'])
        with self.assertRaises(ValueError):
            candidate_classical_work_for_lifetime(descriptor, setups=1, proofs=0,
                remaining_hashes=0, remaining_xof_outputs=0, remaining_roots=0)

    def test_lifetime_setup_counts_add_to_remaining_offsets(self):
        descriptor = native(0, version=5, role_queries=[2048]*4)
        result = candidate_classical_work_with_setups(descriptor, setups=3,
            remaining_hashes=17, remaining_xof_outputs=19, remaining_roots=23)
        direct = candidate_classical_work(descriptor, honest_hashes=17+3*2503,
            honest_xof_outputs=19, honest_roots=23+3*15)
        for key in direct:
            self.assertEqual(result[key], direct[key], key)
        self.assertFalse(result['honest_offset_inventory']['all_honest_work_bounded'])
        self.assertFalse(result['protocol_bound_established'])

    def test_invalid_counts_and_unsupported_backend_rejected(self):
        kwargs = dict(setups=1, remaining_hashes=0, remaining_xof_outputs=0, remaining_roots=0)
        for key in kwargs:
            for bad in (-1, True, 1.5):
                with self.assertRaises(ValueError):
                    candidate_classical_work_with_setups(native(0, version=5), **{**kwargs, key:bad})
        with self.assertRaises(ValueError):
            candidate_classical_work_with_setups(native(0, version=5), **{**kwargs, 'setups':0})
        with self.assertRaises(ValueError):
            candidate_classical_work_with_setups(native(1, version=5), **kwargs)

    def test_cli_requires_remaining_offsets_and_explicit_work_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            descriptor = Path(directory)/'profile.bin'
            output = Path(directory)/'work.json'
            descriptor.write_bytes(native(0, version=5))
            command = [sys.executable, str(Path(__file__).with_name('classical_candidate_terms.py')),
                       '--descriptor', str(descriptor), '--output', str(output), '--brakedown-setups', '2']
            for extra in ([], ['--classical-work']):
                result = subprocess.run(command+extra, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(output.exists())
            result = subprocess.run(command+['--classical-work', '--honest-hashes','7',
                '--honest-xof-outputs','11','--honest-roots','13'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads(output.read_text())
            self.assertEqual(row['honest_offsets'], dict(hashes=5013,xof_outputs=11,roots=43))
            self.assertFalse(row['security_qualified'])
            lifetime_command = list(command)
            lifetime_output = Path(directory)/'lifetime.json'
            lifetime_command[lifetime_command.index('--output')+1] = str(lifetime_output)
            extra = ['--classical-work','--honest-hashes','7','--honest-xof-outputs','11',
                     '--honest-roots','13','--brakedown-proofs','3']
            result = subprocess.run(lifetime_command+extra,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            lifetime = json.loads(lifetime_output.read_text())
            self.assertEqual(lifetime['honest_offsets'],
                dict(hashes=7+2*2503+3*20140,xof_outputs=11+3*1265,roots=13+2*15+3*76))
            self.assertFalse(lifetime['honest_offset_inventory']['prover_xof_coupling_established'])


if __name__ == '__main__':
    unittest.main()
