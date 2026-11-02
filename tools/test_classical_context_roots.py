from copy import deepcopy
import hashlib
import unittest

from audit_classical_context_roots import check_root, check_context, context_preimage, uint
import test_classical_role_contexts as context_fixtures
from audit_classical_role_contexts import parse_context_geometry


class RootTests(unittest.TestCase):
    def test_root_is_bound_to_the_exact_caller_parameter_preimage(self):
        for prime, degree, generator in [('2013265921', 6, 31),
                                          ('18446744069414584321', 3, 7)]:
            profile = context_fixtures.RoleContextTests().profile(prime, degree)
            p = int(prime)
            for role in range(4):
                # Fixtures independently serialize all context fields.
                root = pow(generator, (p-1)//64, p)
                wire = root*2**32 % p if degree == 6 else root
                raw = context_fixtures.metadata(profile, role, wire)
                self.assertEqual(context_preimage(profile, role, wire), raw)
                digest = hashlib.sha512(raw).hexdigest()
                row = dict(role=role, context_sha512=digest,
                           geometry=parse_context_geometry(raw, profile, role))
                self.assertTrue(check_context(profile, role, row, digest)[
                    'context_preimage_reconstructed_and_hashed'])
                forged = deepcopy(row)
                other = pow(root, 3, p)  # Still exact order 64.
                forged['geometry']['ntt_root_wire_repr'] = other*2**32 % p if degree == 6 else other
                with self.assertRaisesRegex(ValueError, 'preimage'):
                    check_context(profile, role, forged, digest)
                forged['context_sha512'] = hashlib.sha512(context_preimage(
                    profile, role, forged['geometry']['ntt_root_wire_repr'])).hexdigest()
                with self.assertRaisesRegex(ValueError, 'preimage'):
                    check_context(profile, role, forged, digest)
                for key, value in [('role', False), ('geometry', None), ('context_sha512', '0'*128)]:
                    forged = dict(row, **{key: value})
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        check_context(profile, role, forged, digest)

    def test_native_bincode_integer_boundaries(self):
        from classical_profile_descriptor import Reader
        for value in (0, 250, 251, 65535, 65536, 2**32-1, 2**32, 2**64-1):
            reader = Reader(uint(value))
            self.assertEqual(reader.unsigned(), value)
            self.assertEqual(reader.at, len(reader.data))
        for value in (-1, True, 2**64):
            with self.assertRaises(ValueError):
                uint(value)

    def test_both_fields_and_domain_limits(self):
        # Known multiplicative generators; verify each resulting root directly.
        for prime, generator, largest in [('2013265921', 31, 2**26),
                                          ('18446744069414584321', 7, 2**31)]:
            p = int(prime)
            for domain in (32, 128, 512, largest):
                root = pow(generator, (p-1)//(2*domain), p)
                wire = root*2**32 % p if prime == '2013265921' else root
                result = check_root(prime, domain, wire)
                self.assertEqual(result['root_canonical'], root)
                self.assertEqual(pow(root, domain, p), p-1)
                self.assertEqual(result['root_order'], 2*domain)
                lower_order = root*root % p
                lower_wire = lower_order*2**32 % p if prime == '2013265921' else lower_order
                with self.assertRaises(ValueError):
                    check_root(prime, domain, lower_wire)
            with self.assertRaises(ValueError):
                check_root(prime, largest*2, wire)

    def test_captured_babybear_root_requires_montgomery_decode(self):
        result = check_root('2013265921', 32, 292252822)
        self.assertEqual(result['root_canonical'], 492152090)
        self.assertNotEqual(pow(292252822, 32, 2013265921), 2013265920)

    def test_lazy_goldilocks_and_invalid_representatives(self):
        # Small root of exact order 64 whose lazy spelling fits in u64.
        root = 8
        p = 18446744069414584321
        self.assertEqual(check_root(str(p), 32, root+p), check_root(str(p), 32, root))
        for prime, domain, wire in [('2013265921', 32, 2013265921),
                ('2013265921', 32, 0), ('2013265921', 32, 2**32),
                (str(p), 32, 1), (str(p), 32, 2**64),
                (str(p), 32, True), (str(p), True, 8),
                (str(p), 33, 8), (str(p), 16, 8), ('17', 32, 8)]:
            with self.subTest(prime=prime, domain=domain, wire=wire), self.assertRaises(ValueError):
                check_root(prime, domain, wire)


if __name__ == '__main__':
    unittest.main()
