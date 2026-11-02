import unittest

from audit_classical_role_contexts import PARAMETERS, DOMAIN, role_geometry, parse_context_geometry
from classical_profile_descriptor import decode_descriptor
from test_classical_candidate_terms import native
from test_classical_profile_descriptor import uint, string


def metadata(profile, role, root=1):
    geometry = role_geometry(profile, role)
    leading = ('num_vars', 'width', 'left_vars', 'ordered_quota', 'block_width', 'codeword_blocks')
    code = ('message_len', 'block_width', 'message_blocks', 'codeword_blocks')
    return (PARAMETERS+string(profile['prime'])+b''.join(uint(geometry[key]) for key in leading)
            +uint(len(DOMAIN))+DOMAIN+b''.join(uint(geometry[key]) for key in code)
            +string(profile['prime'])+uint(root))


class RoleContextTests(unittest.TestCase):
    def profile(self, prime='2013265921', degree=6):
        return decode_descriptor(native(0, prime=prime, degree=degree, version=4,
            variables=[8, 11, 3, 6], role_queries=[8]*4))

    def test_all_roles_decode_complete_geometry_without_claiming_root_algebra(self):
        for prime, degree in [('2013265921', 6), ('18446744069414584321', 3)]:
            profile = self.profile(prime, degree)
            for role in range(4):
                result = parse_context_geometry(metadata(profile, role), profile, role)
                expected = role_geometry(profile, role)
                self.assertEqual({key: result[key] for key in expected}, expected)
                self.assertEqual(result['ntt_root_wire_repr'], 1)
                self.assertFalse(result['ntt_root_algebra_checked'])

    def test_wrong_role_modulus_namespace_and_trailing_bytes_reject(self):
        profile = self.profile()
        raw = metadata(profile, 0)
        for changed in [raw+b'x', raw.replace(DOMAIN, b'x'*len(DOMAIN)),
                        metadata(self.profile('18446744069414584321', 3), 0), b'wrong'+raw]:
            with self.subTest(changed=changed[:30]), self.assertRaises(ValueError):
                parse_context_geometry(changed, profile, 0)
        with self.assertRaises(ValueError):
            parse_context_geometry(raw, profile, 1)
        for end in range(len(PARAMETERS), len(raw)):
            with self.assertRaises(ValueError):
                parse_context_geometry(raw[:end], profile, 0)

    def test_bad_native_geometry_is_not_inferred_from_a_digest(self):
        profile = self.profile()
        for key, value in [('role_left_vars', None), ('role_queries', 0), ('role_variables', 2**64-1)]:
            changed = dict(profile)
            changed[key] = list(profile[key])
            changed[key][0] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                role_geometry(changed, 0)
        changed = dict(profile, backend='Polyfrim')
        with self.assertRaises(ValueError):
            role_geometry(changed, 0)


if __name__ == '__main__':
    unittest.main()
