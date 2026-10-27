//! Independent integer polynomial arithmetic for extension-parameter validation.
//! Rabin criterion: J.S. Milne, Fields and Galois Theory, Exercise 4-8.
//! https://www.jmilne.org/math/Books/FT0.pdf#page=85
//! No extension multiplication, Frobenius or inverse is used by the reference.
#![cfg(feature = "concrete-ntt")]
use algebra::{
    AbstractExtensionField, AsFrom, AsInto, BinomialExtensionField, BinomialExtensionParameters,
    Field, HasFrobenius, NTTField,
};
use num_traits::{Inv, One, Pow};
use serde::{Serialize, de::DeserializeOwned};

type Poly = Vec<u128>;
fn trim(mut a: Poly) -> Poly {
    while a.last() == Some(&0) {
        a.pop();
    }
    a
}
fn integer_pow(mut a: u128, mut e: u128, p: u128) -> u128 {
    let mut out = 1;
    while e > 0 {
        if e & 1 != 0 {
            out = out * a % p;
        }
        a = a * a % p;
        e >>= 1;
    }
    out
}
fn subtract(a: &[u128], b: &[u128], p: u128) -> Poly {
    trim(
        (0..a.len().max(b.len()))
            .map(|i| (a.get(i).copied().unwrap_or(0) + p - b.get(i).copied().unwrap_or(0)) % p)
            .collect(),
    )
}
fn multiply(a: &[u128], b: &[u128], p: u128) -> Poly {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut out = vec![0; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] = (out[i + j] + x * y % p) % p;
        }
    }
    trim(out)
}
fn divrem(a: &[u128], b: &[u128], p: u128) -> (Poly, Poly) {
    assert!(!b.is_empty());
    let mut a = trim(a.to_vec());
    let mut quotient = vec![0; a.len().saturating_sub(b.len()) + 1];
    let inv = integer_pow(*b.last().unwrap(), p - 2, p);
    while a.len() >= b.len() {
        let degree = a.len() - b.len();
        let c = a.last().unwrap() * inv % p;
        quotient[degree] = c;
        for (i, &x) in b.iter().enumerate() {
            a[degree + i] = (a[degree + i] + p - c * x % p) % p;
        }
        a = trim(a);
    }
    (trim(quotient), a)
}
fn power(a: &[u128], mut e: u128, f: &[u128], p: u128) -> Poly {
    let mut a = a.to_vec();
    let mut out = vec![1];
    while e > 0 {
        if e & 1 != 0 {
            out = divrem(&multiply(&out, &a, p), f, p).1;
        }
        a = divrem(&multiply(&a, &a, p), f, p).1;
        e >>= 1;
    }
    out
}
fn gcd(mut a: Poly, mut b: Poly, p: u128) -> Poly {
    while !b.is_empty() {
        let r = divrem(&a, &b, p).1;
        a = b;
        b = r;
    }
    a
}
fn prime_divisors(mut n: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut d = 2;
    while d <= n {
        if n % d == 0 {
            out.push(d);
            while n % d == 0 {
                n /= d;
            }
        }
        d += 1;
    }
    out
}
fn irreducible(f: &[u128], p: u128) -> bool {
    let degree = f.len() - 1;
    let divisors = prime_divisors(degree);
    let x = vec![0, 1];
    let mut h = x.clone();
    for i in 1..=degree {
        h = power(&h, p, f, p);
        if divisors.iter().any(|&r| i == degree / r)
            && gcd(f.to_vec(), subtract(&h, &x, p), p).len() != 1
        {
            return false;
        }
    }
    h == x
}
fn inverse(a: &[u128], f: &[u128], p: u128) -> Poly {
    let (mut old_r, mut r) = (f.to_vec(), trim(a.to_vec()));
    let (mut old_t, mut t) = (vec![], vec![1]);
    while !r.is_empty() {
        let (q, next_r) = divrem(&old_r, &r, p);
        let next_t = divrem(&subtract(&old_t, &multiply(&q, &t, p), p), f, p).1;
        old_r = r;
        r = next_r;
        old_t = t;
        t = next_t;
    }
    assert_eq!(old_r.len(), 1);
    let c = integer_pow(old_r[0], p - 2, p);
    trim(old_t.iter().map(|x| x * c % p).collect())
}
fn canonical<Base: Field, EF: AbstractExtensionField<Base>>(a: EF) -> Poly {
    trim(
        a.as_base_slice()
            .iter()
            .map(|x| x.value().as_into())
            .collect(),
    )
}
fn exercise<Base, const D: usize>()
where
    Base: NTTField + BinomialExtensionParameters<D> + algebra::Packable,
    BinomialExtensionField<Base, D>: Serialize + DeserializeOwned,
{
    type Ext<B, const N: usize> = BinomialExtensionField<B, N>;
    let p: u128 = Base::MODULUS_VALUE.as_into();
    assert!(p < 1u128 << 64);
    // Primality certificate specialized to these two-adic prime candidates.
    // For every prime divisor r of p the witness has full 2-power order, so
    // 2^k divides r-1. Since 2^k > sqrt(p), p cannot be composite.
    let two_power = 1u128 << (p - 1).trailing_zeros();
    assert!(two_power * two_power > p);
    assert!(
        (2..64).any(|a| integer_pow(a, p - 1, p) == 1 && integer_pow(a, (p - 1) / 2, p) == p - 1)
    );
    let w: u128 = Base::binomial_w().value().as_into();
    let mut f = vec![0; D + 1];
    f[0] = p - w;
    f[D] = 1;
    assert!(irreducible(&f, p));
    let mut reducible = f.clone();
    reducible[0] = p - 1;
    assert!(!irreducible(&reducible, p));
    assert_eq!((p - 1) % D as u128, 0);
    let frobenius_multiplier: u128 = Base::binomial_dth_root().value().as_into();
    assert_eq!(frobenius_multiplier, integer_pow(w, (p - 1) / D as u128, p));
    let x = Ext::<Base, D>::monomial(1);
    assert_eq!(
        x.pow(D as u128),
        Ext::<Base, D>::from_base(Base::binomial_w())
    );
    for mode in 0..12 {
        let values: Vec<u128> = (0..D)
            .map(|j| match mode {
                0 => 0,
                1 => {
                    if j == 0 {
                        1
                    } else {
                        0
                    }
                }
                2 => p - 1,
                3 => p - 1 - j as u128,
                _ => (17 * mode + 13 * j + 1) as u128,
            })
            .collect();
        let a = Ext::<Base, D>::from_base_fn(|j| Base::new(Base::Value::as_from(values[j])));
        let b = Ext::<Base, D>::from_base_fn(|j| {
            Base::new(Base::Value::as_from(p - 1 - 2 * j as u128))
        });
        assert_eq!(
            canonical::<Base, _>(a * b),
            divrem(&multiply(&values, &canonical::<Base, _>(b), p), &f, p).1
        );
        assert_eq!(canonical::<Base, _>(a.square()), power(&values, 2, &f, p));
        assert_eq!(a + b - b, a);
        assert_eq!(
            a * Base::from(7usize),
            a * Ext::<Base, D>::from_base(Base::from(7usize))
        );
        for exponent in [0, 1, 2, 3, 7, 65, (1u128 << 64) + 3, u128::MAX] {
            assert_eq!(
                canonical::<Base, _>(a.pow(exponent)),
                power(&values, exponent, &f, p)
            );
        }
        let expected = power(&values, p, &f, p);
        assert_eq!(canonical::<Base, _>(a.frobenius()), expected);
        assert_eq!(a.repeated_frobenius(D), a);
        if !trim(values.clone()).is_empty() {
            assert_eq!(canonical::<Base, _>(a.inv()), inverse(&values, &f, p));
            assert_eq!(a * a.inv(), Ext::<Base, D>::one());
        }
        let bytes = bincode::serde::encode_to_vec(a, bincode::config::standard()).unwrap();
        let (decoded, used): (Ext<Base, D>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(a, decoded);
    }
}
#[test]
fn existing_babybear4() {
    exercise::<algebra::BabyBear, 4>();
}
#[test]
fn existing_goldilocks2() {
    exercise::<algebra::Goldilocks, 2>();
}
#[test]
fn babybear8() {
    exercise::<algebra::BabyBear, 8>();
}
#[test]
fn goldilocks4() {
    exercise::<algebra::Goldilocks, 4>();
}
#[test]
fn babybear5() {
    exercise::<algebra::BabyBear, 5>();
}
#[test]
fn goldilocks5() {
    exercise::<algebra::Goldilocks, 5>();
}

#[test]
fn goldilocks3() {
    exercise::<algebra::Goldilocks, 3>();
}

#[test]
fn babybear6() {
    exercise::<algebra::BabyBear, 6>();
}

#[test]
fn babybear6_kernel_matches_integer_polynomials_and_legacy_wire() {
    use algebra::{BabyBear as B, BabyBearExtension6 as E};
    let p = B::MODULUS_VALUE as u128;
    let w = <B as BinomialExtensionParameters<6>>::binomial_w();
    let modulus = vec![p - 31, 0, 0, 0, 0, 0, 1];
    let mut state = 0x493a_1fc2_60be_8d75u64;
    for case in 0..552 {
        let mut coefficients = |side: usize| -> [u128; 6] {
            std::array::from_fn(|i| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                match case {
                    0..=35 => u128::from(i == if side == 0 { case / 6 } else { case % 6 }),
                    36 => 0,
                    37 => p - 1,
                    38 => if i & 1 == side { p - 1 } else { 1 },
                    39 => if i == 5 { p - 1 } else { 0 },
                    _ => state as u128 % p,
                }
            })
        };
        let aa = coefficients(0);
        let bb = coefficients(1);
        let a = E::from_base_fn(|i| B::new(aa[i] as u32));
        let b = E::from_base_fn(|i| B::new(bb[i] as u32));
        let fast = a * b;
        assert_eq!(canonical::<B, _>(fast), divrem(&multiply(&aa, &bb, p), &modulus, p).1);
        let mut legacy = [B::new(0); 6];
        for i in 0..6 {
            for j in 0..6 {
                if i + j >= 6 {
                    legacy[i + j - 6] += a.as_base_slice()[i] * w * b.as_base_slice()[j];
                } else {
                    legacy[i + j] += a.as_base_slice()[i] * b.as_base_slice()[j];
                }
            }
        }
        let legacy = E::from_base_fn(|i| legacy[i]);
        assert_eq!(
            bincode::serde::encode_to_vec(fast, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(legacy, bincode::config::standard()).unwrap(),
        );
    }
}
