"""Exercise diagnostic parsing for each trusted polynomial-basis field."""

import unittest
from pathlib import Path
import subprocess
import sys
import tempfile

from classical_profile_descriptor import FIELD_NONRESIDUES, decode_descriptor


def uint(value):
    if value < 251:
        return bytes([value])
    for tag, size in [(251, 2), (252, 4), (253, 8), (254, 16)]:
        if value < 1 << (size*8):
            return bytes([tag])+value.to_bytes(size, 'little')
    raise ValueError('fixture integer too large')


def string(value):
    data = value.encode()
    return uint(len(data))+data


def descriptor(prime, degree, nonresidue, version=2):
    # Four Brakedown roles, each with explicit left-variable/block geometry.
    role = uint(8)+uint(8)+uint(3)+b'\x01'+uint(4)+b'\x01'+uint(8)
    result = uint(version)+uint(0)+role*4+uint(2)+b'\x00'
    result += string(prime)+uint(degree)+uint(degree**3)
    for i in range(degree):
        for j in range(degree):
            # Independent polynomial remainder of X^(i+j) modulo X^D-w.
            coefficients = [0]*(2*degree)
            coefficients[i+j] = 1
            for exponent in range(2*degree-1, degree-1, -1):
                coefficients[exponent-degree] += nonresidue*coefficients[exponent]
            result += b''.join(uint(c) for c in coefficients[:degree])
    suite = {1: 'framed-shake256-canonical-rejection-v1',
             2: 'framed-shake256-canonical-rejection-atomic-ntt-v2',
             3: 'framed-shake256-canonical-rejection-atomic-phases-v3',
             4: 'framed-shake256-canonical-rejection-atomic-zerocheck-v4',
             5: 'framed-shake256-canonical-rejection-atomic-columns-v5'}[version]
    return result+string('sha512-v1')+string(suite)


class DescriptorFieldTests(unittest.TestCase):
    def test_version_five_rejects_unrepresentable_atomic_byte_counts(self):
        raw = descriptor('2013265921', 6, 31, version=5)
        prefix = uint(5)+uint(0)+uint(8)+uint(8)
        self.assertTrue(raw.startswith(prefix+uint(3)))
        oversized = prefix+uint(2**63)+raw[len(prefix)+len(uint(3)):]
        with self.assertRaisesRegex(ValueError, 'atomic column byte count overflow'):
            decode_descriptor(oversized)

    def test_runner_rejects_infeasible_field_geometry_before_io(self):
        runner = Path(__file__).with_name('run_classical_native_validation.py')
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)/'uncreated'
            for field, degree, message in [('babybear', 2, 'unsupported extension degree'),
                                           ('goldilocks', 6, 'unsupported extension degree'),
                                           ('goldilocks', 5, 'source width 4')]:
                with self.subTest(field=field, degree=degree):
                    result = subprocess.run([sys.executable, str(runner), '--runner',
                        str(Path(temporary)/'nonexistent-binary'), '--output', str(output),
                        '--fields', field, '--extension-degree', str(degree)],
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(message, result.stderr)
                    self.assertFalse(output.exists())

    def test_all_eight_fields_and_all_schedules(self):
        for (prime, degree), w in FIELD_NONRESIDUES.items():
            for version in [1, 2, 3, 4, 5]:
                with self.subTest(prime=prime, degree=degree, version=version):
                    result = decode_descriptor(descriptor(prime, degree, w, version))
                    self.assertEqual((result['prime'], result['extension_degree']), (prime, degree))
                    self.assertEqual(result['descriptor_version'], version)
                    self.assertEqual(result['role_queries'], [3]*4)
                    with self.assertRaises(ValueError):
                        decode_descriptor(descriptor(prime, degree, w+1, version))

    def test_unknown_field_and_trailing_or_truncated_bytes_rejected(self):
        valid = descriptor('2013265921', 4, 11)
        for data in [valid+b'\x00', valid[:-1], descriptor('2013265921', 2, 11),
                     descriptor('17', 4, 11)]:
            with self.subTest(data=data[:12]), self.assertRaises(ValueError):
                decode_descriptor(data)


if __name__ == '__main__':
    unittest.main()
