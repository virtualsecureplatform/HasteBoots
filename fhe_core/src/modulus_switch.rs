use std::iter::once;

use algebra::{AsInto, DecomposableField, UnsignedInteger, modulus_switching::round_modulus_u128};
use lattice::LWE;
use trace::modulus_switching_trace::ModulusSwitchingTrace;

use crate::LWECiphertext;

/// Implementation of modulus switching.
///
/// This function performs on a `LWE<F>`, returns a `LWE<C>` with desired modulus `modulus_after`.
pub fn lwe_modulus_switch<T: UnsignedInteger, F: DecomposableField>(
    c: &LWE<F>,
    modulus_after: T,
) -> LWECiphertext<T> {
    let modulus_before: u128 = F::MODULUS_VALUE.as_into();
    let modulus_after_wide: u128 = modulus_after.as_into();
    let switch = |v: F| {
        T::as_from(round_modulus_u128(
            v.value().as_into(),
            modulus_before,
            modulus_after_wide,
        ))
    };

    let a: Vec<T> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    LWECiphertext::new(a, b)
}

/// Implementation of modulus switching with trace.
pub fn lwe_modulus_switch_w_trace<T: UnsignedInteger, F: DecomposableField>(
    c: &LWE<F>,
    modulus_after: T,
) -> (LWECiphertext<T>, ModulusSwitchingTrace<F>) {
    let modulus_before: u128 = F::MODULUS_VALUE.as_into();
    let modulus_after_wide: u128 = modulus_after.as_into();
    let switch = |v: F| {
        T::as_from(round_modulus_u128(
            v.value().as_into(),
            modulus_before,
            modulus_after_wide,
        ))
    };

    let conver_to_field = |v: T| {
        let v: usize = v.as_into();
        F::new(v.as_into())
    };

    let log_num = (c.a().len() + 1).next_power_of_two().trailing_zeros() as usize;
    let mut trace = ModulusSwitchingTrace::new(log_num, conver_to_field(modulus_after));
    trace.append_input(c.a());
    trace.input.push(c.b());

    let a: Vec<T> = c.a().iter().copied().map(&switch).collect();
    let b = switch(c.b());

    let a_b_field = a
        .iter()
        .chain(once(&b))
        .copied()
        .map(&conver_to_field)
        .collect::<Vec<F>>();
    trace.append_output(&a_b_field);
    // trace.finalize(c.a().len() + 1);

    (LWECiphertext::new(a, b), trace)
}

/// Implementation of modulus switching.
///
/// This function performs on a `LWE<F>`, puts the result `LWE<C>` with desired modulus `modulus_after`
/// into `destination`.
pub fn lwe_modulus_switch_inplace<T: UnsignedInteger, F: DecomposableField>(
    c: LWE<F>,
    modulus_after: T,
    destination: &mut LWECiphertext<T>,
) {
    let modulus_before: u128 = F::MODULUS_VALUE.as_into();
    let modulus_after_wide: u128 = modulus_after.as_into();
    let switch = |v: F| {
        T::as_from(round_modulus_u128(
            v.value().as_into(),
            modulus_before,
            modulus_after_wide,
        ))
    };

    destination
        .a_mut()
        .iter_mut()
        .zip(c.a())
        .for_each(|(des, &inp)| *des = switch(inp));

    *destination.b_mut() = switch(c.b());
}

/// Implementation of modulus switching.
///
/// This function performs on a `LWE<C>` with modulus `modulus_before`, puts the result `LWE<C>` with desired modulus `modulus_after`
/// back to `c`.
pub fn lwe_modulus_switch_assign_between_modulus<T: UnsignedInteger>(
    c: &mut LWE<T>,
    modulus_before: T,
    modulus_after: T,
) {
    let before: u128 = modulus_before.as_into();
    let after: u128 = modulus_after.as_into();
    let switch = |v: T| T::as_from(round_modulus_u128(v.as_into(), before, after));

    c.a_mut().iter_mut().for_each(|v| *v = switch(*v));
    *c.b_mut() = switch(c.b());
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{Field, Goldilocks};
    use num_traits::Zero;
    #[test]
    fn goldilocks_threshold_matches_exact_trace_and_all_entry_points() {
        let q = 2048u64;
        let p = Goldilocks::MODULUS_VALUE;
        let k = (p - 1) / (2 * q);
        let c = LWE::new(
            vec![Goldilocks::new(k), Goldilocks::new(k + 1)],
            Goldilocks::zero(),
        );
        let plain = lwe_modulus_switch::<u64, _>(&c, q);
        assert_eq!(plain.a(), &[0, 1]);
        assert_eq!(plain.b(), 0);
        let (traced, mut trace) = lwe_modulus_switch_w_trace::<u64, _>(&c, q);
        assert_eq!(traced.a(), plain.a());
        trace.finalize(3);
        assert_eq!(trace.helper[0], Goldilocks::new(2 * k));
        assert_eq!(trace.helper[1], Goldilocks::zero());
        let mut destination = LWECiphertext::new(vec![9u64; 2], 9);
        lwe_modulus_switch_inplace(c, q, &mut destination);
        assert_eq!(destination.a(), &[0, 1]);
        assert_eq!(destination.b(), 0);
        let mut integer = LWE::new(vec![k, k + 1], 0u64);
        lwe_modulus_switch_assign_between_modulus(&mut integer, p, q);
        assert_eq!(integer.a(), &[0, 1]);
    }
}
