use crate::{
    BinomialExtensionField, BinomiallyExtendable, Goldilocks, HasTwoAdicBionmialExtension,
    extension::TwoAdicField, field::Field,
};

use num_traits::Zero;

impl BinomiallyExtendable<2> for Goldilocks {
    // Verifiable in Sage with
    // `R.<x> = GF(p)[]; assert (x^2 - 7).is_irreducible()`.
    fn w() -> Self {
        Self::new(7)
    }

    // DTH_ROOT = W^((p - 1)/2).
    fn dth_root() -> Self {
        Self::new(18446744069414584320)
    }

    fn ext_generator() -> [Self; 2] {
        [
            Self::new(18081566051660590251),
            Self::new(16121475356294670766),
        ]
    }
}

impl HasTwoAdicBionmialExtension<2> for Goldilocks {
    const EXT_TWO_ADICITY: usize = 33;

    fn ext_two_adic_generator(bits: usize) -> [Self; 2] {
        assert!(bits <= 33);

        if bits == 33 {
            [Self::zero(), Self(15659105665374529263)]
        } else {
            [Self::two_adic_generator(bits), Self::zero()]
        }
    }
}

/// Extension of Goldilocks field.
pub type GoldilocksExtension = BinomialExtensionField<Goldilocks, 2>;

// Each defining polynomial is checked by an independent Rabin test in
// tests/extension_parameters.rs. No primitive-generator capability is claimed.
impl crate::BinomialExtensionParameters<4> for Goldilocks {
    fn binomial_w() -> Self {
        Self::new(7)
    }
    fn binomial_dth_root() -> Self {
        Self::new(281474976710656)
    }
}
/// Degree-4 polynomial-basis extension defined by X^4-7.
/// Field size alone is not a composed proof security certificate.
pub type GoldilocksExtension4 = BinomialExtensionField<Goldilocks, 4>;
impl crate::BinomialExtensionParameters<5> for Goldilocks {
    fn binomial_w() -> Self {
        Self::new(3)
    }
    fn binomial_dth_root() -> Self {
        Self::new(1041288259238279555)
    }
}
/// Degree-5 polynomial-basis extension defined by X^5-3.
/// Field size alone is not a composed proof security certificate.
pub type GoldilocksExtension5 = BinomialExtensionField<Goldilocks, 5>;

impl crate::BinomialExtensionParameters<3> for Goldilocks {
    fn binomial_w() -> Self {
        Self::new(7)
    }
    fn binomial_dth_root() -> Self {
        Self::new(18446744065119617025)
    }
}
/// Degree-3 polynomial-basis extension defined by X^3-7.
/// No primitive-generator capability or composed security level is asserted.
pub type GoldilocksExtension3 = BinomialExtensionField<Goldilocks, 3>;
