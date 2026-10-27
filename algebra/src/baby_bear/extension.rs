use crate::{
    BabyBear, BinomialExtensionField, BinomiallyExtendable, HasTwoAdicBionmialExtension,
    extension::TwoAdicField, field::Field, modulus::to_monty,
};
use num_traits::{One, Zero};

impl BinomiallyExtendable<4> for BabyBear {
    // Verifiable in Sage with
    // `R.<x> = GF(p)[]; assert (x^4 - 11).is_irreducible()`.
    fn w() -> Self {
        Self::new(11)
    }

    // DTH_ROOT = W^((p - 1)/4)
    fn dth_root() -> Self {
        Self::new(1728404513)
    }

    fn ext_generator() -> [Self; 4] {
        [Self::new(8), Self::one(), Self::zero(), Self::zero()]
    }
}

impl HasTwoAdicBionmialExtension<4> for BabyBear {
    const EXT_TWO_ADICITY: usize = 29;

    fn ext_two_adic_generator(bits: usize) -> [Self; 4] {
        assert!(bits <= 29);

        match bits {
            29 => [
                Self::zero(),
                Self::zero(),
                Self::zero(),
                Self(to_monty(124907976)),
            ],
            28 => [
                Self::zero(),
                Self::zero(),
                Self(to_monty(1996171314)),
                Self::zero(),
            ],
            _ => [
                Self::two_adic_generator(bits),
                Self::zero(),
                Self::zero(),
                Self::zero(),
            ],
        }
    }
}

/// Extension of BabyBear field
pub type BabyBearExetension = BinomialExtensionField<BabyBear, 4>;

// Each defining polynomial is checked by an independent Rabin test in
// tests/extension_parameters.rs. No primitive-generator capability is claimed.
impl crate::BinomialExtensionParameters<5> for BabyBear {
    fn binomial_w() -> Self {
        Self::new(2)
    }
    fn binomial_dth_root() -> Self {
        Self::new(815036133)
    }
}
/// Degree-5 polynomial-basis extension defined by X^5-2.
/// Field size alone is not a composed proof security certificate.
pub type BabyBearExtension5 = BinomialExtensionField<BabyBear, 5>;
impl crate::BinomialExtensionParameters<8> for BabyBear {
    fn binomial_w() -> Self {
        Self::new(11)
    }
    fn binomial_dth_root() -> Self {
        Self::new(420899707)
    }
}
/// Degree-8 polynomial-basis extension defined by X^8-11.
/// Field size alone is not a composed proof security certificate.
pub type BabyBearExtension8 = BinomialExtensionField<BabyBear, 8>;

impl crate::BinomialExtensionParameters<6> for BabyBear {
    fn binomial_w() -> Self {
        Self::new(31)
    }
    fn binomial_dth_root() -> Self {
        Self::new(1314723124)
    }
}
/// Degree-6 polynomial-basis extension defined by X^6-31.
/// No primitive-generator capability or composed security level is asserted.
pub type BabyBearExtension6 = BinomialExtensionField<BabyBear, 6>;
