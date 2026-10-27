//! Exact unsigned modulus switching with nearest-integer rounding.

/// Return round(value*after/before) modulo after, with half ties rounded up.
/// The input is a canonical residue below before. A checked fast path handles
/// ordinary 32/64-bit fields; the fallback avoids even u128 product overflow.
///
/// # Panics
/// Panics for zero moduli or a noncanonical input residue.
pub fn round_modulus_u128(value: u128, before: u128, after: u128) -> u128 {
    assert!(
        before > 0 && after > 0 && value < before,
        "invalid modulus-switch residue or modulus"
    );
    if let Some(numerator) = value
        .checked_mul(after)
        .and_then(|n| n.checked_add(before / 2))
    {
        return (numerator / before) % after;
    }
    round_wide(value, before, after)
}
fn round_wide(value: u128, before: u128, after: u128) -> u128 {
    let mut quotient = 0u128;
    let mut remainder = 0u128;
    for bit in (0..128 - after.leading_zeros()).rev() {
        // Double the accumulated fractional product without overflowing 2*r.
        let mut carry = 0;
        if remainder >= before - remainder {
            remainder -= before - remainder;
            carry += 1;
        } else {
            remainder += remainder;
        }
        if (after >> bit) & 1 != 0 {
            if remainder >= before - value {
                remainder -= before - value;
                carry += 1;
            } else {
                remainder += value;
            }
        }
        quotient = quotient * 2 + carry;
    }
    if remainder >= before / 2 + before % 2 {
        quotient += 1;
    }
    if quotient == after { 0 } else { quotient }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fast_and_wide_rounding_match_direct_integer_reference() {
        for p in [3, 257, 2013265921, 18446744069414584321u128] {
            for q in [1, 2, 64, 2048] {
                for i in 0..1000u128 {
                    let a = (i * 18446744073709551557u128 + 17) % p;
                    let expected = ((a * q + p / 2) / p) % q;
                    assert_eq!(round_modulus_u128(a, p, q), expected);
                    assert_eq!(round_wide(a, p, q), expected);
                }
            }
        }
    }
    #[test]
    fn wide_products_and_half_ties_are_exact() {
        let p = u128::MAX;
        assert_eq!(round_modulus_u128(p - 1, p, p - 1), p - 2);
        assert_eq!(round_modulus_u128(p / 2, p, p - 1), p / 2);
        assert_eq!(round_modulus_u128(p - 1, p, 1), 0);
        assert_eq!(round_modulus_u128(1, 4, 2), 1);
        assert_eq!(round_modulus_u128(3, 4, 2), 0);
        let gold = 18446744069414584321u128;
        let q = 2048u128;
        let boundary = (gold - 1) / (2 * q);
        assert_eq!(round_modulus_u128(boundary, gold, q), 0);
        assert_eq!(round_modulus_u128(boundary + 1, gold, q), 1);
        // The old f64 path loses the +1 in the Goldilocks characteristic.
        assert_eq!(
            (boundary as f64 * q as f64 / gold as f64).round() as u128,
            1
        );
    }
}
