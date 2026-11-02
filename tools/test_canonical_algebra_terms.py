from fractions import Fraction
import unittest

from canonical_algebra_terms import partial_terms
from packed_budget import bounds, zerocheck_algebraic_bound, extension_lookup_algebraic_bounds


class CanonicalAlgebraTermsTests(unittest.TestCase):
    def fixture(self):
        return dict(protocol_version=11,group_size=1,prime=2013265921,width=8,
                    ring_dimension=1024,lwe_dimension=728,lookup_repetitions=1,root_slots=76,
                    extension_degree=6)

    def test_zerocheck_code_geometry_is_independent(self):
        # Refactoring must preserve old budgets across different row codes.
        for p,k,degree,n in [(2013265921,8,2,18),(18446744069414584321,4,2,9),
                              (101,2,3,1),(101,2,1,20)]:
            expected=zerocheck_algebraic_bound(p,k,degree,n)
            for message,length in [(16,32),(64,256)]:
                self.assertEqual(bounds(p,k,degree,n,3,message,length,128)['zerocheck'],expected)

    def test_canonical_inventory_has_four_direct_quadratic_checks(self):
        terms=partial_terms(self.fixture(),18,8)
        zero={key:value for key,value in terms.items() if key.endswith('_zerocheck')}
        self.assertEqual(set(zero),{'main_hadamard_zerocheck','monomial_product_zerocheck',
                                    'final_product_zerocheck','extraction_zerocheck'})
        self.assertEqual(zero['main_hadamard_zerocheck'],20*Fraction(45,2013265921)**8)
        self.assertEqual(zero['extraction_zerocheck'],10*Fraction(45,2013265921)**8)
        self.assertEqual(terms['accumulator_linear_identities'],
                         7*18*Fraction(15,2013265921)**8)
        self.assertEqual(terms['main_decomposition_linear_identities'],
                         6*18*Fraction(15,2013265921)**8)
        self.assertEqual(terms['final_decomposition_linear_identities'],
                         3*8*Fraction(15,2013265921)**8)
        self.assertFalse(any('aggregation' in key for key in terms))

    def test_unsupported_profiles_and_invalid_zerocheck_rejected(self):
        for change in [dict(protocol_version=9),dict(group_size=4),dict(root_slots=75),
                       dict(lookup_repetitions=2),dict(extension_degree=5)]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                partial_terms(dict(self.fixture(),**change),18,8)
        for source,final in [(17,8),(18,7),(19,9)]:
            with self.subTest(source=source,final=final),self.assertRaises(ValueError):
                partial_terms(self.fixture(),source,final)
        for args in [(101,2,2,0),(101,True,2,1),(7,2,2,1)]:
            with self.subTest(args=args),self.assertRaises(ValueError):
                zerocheck_algebraic_bound(*args)

    def test_lookup_rejection_domain_mask_and_repetition(self):
        full=extension_lookup_algebraic_bounds(101,2,3,8,4,3,2,1)
        pair=Fraction(8,101**2)+Fraction(11,101**2-5)
        self.assertEqual(full['rational_identity'],2*pair)
        repeated=extension_lookup_algebraic_bounds(101,2,3,8,4,3,2,2)
        self.assertEqual(repeated['rational_identity'],2*pair**2)
        self.assertEqual(repeated['identity_sumcheck'],2*full['identity_sumcheck'])
        masked=extension_lookup_algebraic_bounds(101,2,3,7,4,3,2,1)
        self.assertEqual(masked['identity_sumcheck']*3,full['identity_sumcheck']*4)
        for logical in (9,101):
            with self.assertRaises(ValueError):
                extension_lookup_algebraic_bounds(101,2,3,logical,4,3,2,1)


if __name__=='__main__':
    unittest.main()
