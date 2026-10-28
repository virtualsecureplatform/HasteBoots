use algebra::{Field, Goldilocks as F, NTTField, transformation::AbstractNTT};
fn pow(mut base: F, mut n: usize) -> F {
    let mut out = F::new(1);
    while n != 0 {
        if n & 1 != 0 {
            out *= base;
        }
        base *= base;
        n >>= 1;
    }
    out
}
fn points(n: usize, root: F) -> Vec<F> {
    (0usize..n)
        .map(|i| {
            pow(
                root,
                2 * (i.reverse_bits() >> (usize::BITS - n.ilog2())) + 1,
            )
        })
        .collect()
}
#[test]
fn forward_lazy_aliases_match_negacyclic_definition() {
    for n in [32usize, 64] {
        let table = F::generate_ntt_table(n.ilog2()).unwrap();
        let canonical: Vec<_> = (0..n).map(|i| F::from(i * 17 + 3)).collect();
        let mut aliases: Vec<_> = canonical
            .iter()
            .map(|v| F::new(F::MODULUS_VALUE + v.value()))
            .collect();
        let expected: Vec<_> = points(n, table.root())
            .into_iter()
            .map(|x| canonical.iter().rev().fold(F::new(0), |v, &a| v * x + a))
            .collect();
        let mut standard = canonical;
        table.transform_slice(&mut standard);
        table.transform_slice(&mut aliases);
        assert_eq!(standard, expected);
        assert_eq!(aliases, expected);
        assert_eq!(
            bincode::serde::encode_to_vec(&standard, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&aliases, bincode::config::standard()).unwrap()
        );
    }
}
#[test]
fn inverse_lazy_aliases_match_negacyclic_definition() {
    for n in [32usize, 64] {
        let table = F::generate_ntt_table(n.ilog2()).unwrap();
        let mut canonical: Vec<_> = (0..n).map(|i| F::from(i * 13 + 1)).collect();
        canonical[n - 1] = F::new(u64::MAX).canonicalized();
        let mut aliases: Vec<_> = canonical
            .iter()
            .map(|v| F::new(F::MODULUS_VALUE + v.value()))
            .collect();
        let inverse_points: Vec<_> = points(n, table.root())
            .into_iter()
            .map(|x| F::new(1) / x)
            .collect();
        let inverse_n = F::new(1) / F::from(n);
        let expected: Vec<_> = (0..n)
            .map(|i| {
                canonical
                    .iter()
                    .zip(&inverse_points)
                    .fold(F::new(0), |v, (&a, &x)| v + a * pow(x, i))
                    * inverse_n
            })
            .collect();
        let mut standard = canonical;
        table.inverse_transform_slice(&mut standard);
        table.inverse_transform_slice(&mut aliases);
        assert_eq!(standard, expected);
        assert_eq!(aliases, expected);
        assert_eq!(
            bincode::serde::encode_to_vec(&standard, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&aliases, bincode::config::standard()).unwrap()
        );
    }
}
