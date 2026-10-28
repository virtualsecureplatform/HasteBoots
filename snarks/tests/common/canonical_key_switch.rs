use algebra::{
    Basis, NTTField, NTTPolynomial, matrix_weighted::PackedTable, transformation::AbstractNTT,
};
use lattice::{NTTGadgetRLWE, NTTRLWE};
use snarks::{packed_key_switch as ks, packed_monomial};
pub fn fixture<F: NTTField>(
    width: usize,
) -> (
    ks::Config,
    Vec<NTTGadgetRLWE<F>>,
    Vec<F>,
    Vec<F>,
    F,
    Vec<PackedTable<F>>,
) {
    fixture_with_bits::<F>(width, 8)
}
pub fn fixture_with_bits<F: NTTField>(
    width: usize,
    bits: u32,
) -> (
    ks::Config,
    Vec<NTTGadgetRLWE<F>>,
    Vec<F>,
    Vec<F>,
    F,
    Vec<PackedTable<F>>,
) {
    let n = 32usize;
    let lwe = 21;
    let vars = (2 * n / width).ilog2() as usize;
    let config = ks::Config::new::<F>(n, lwe, bits, 1).unwrap();
    let d = config.digits::<F>().unwrap();
    F::init_ntt_table(5).unwrap();
    let native = F::get_ntt_table(5).unwrap();
    let key = vec![NTTGadgetRLWE::new(
        (0..d)
            .map(|i| {
                NTTRLWE::new(
                    NTTPolynomial::new((0..n).map(|j| F::from(100 * i + 3 * j + 1)).collect()),
                    NTTPolynomial::new((0..n).map(|j| F::from(70 * i + 5 * j + 2)).collect()),
                )
            })
            .collect(),
        Basis::new(bits),
    )];
    let acc = (0..2 * n).map(|i| F::from(7 * i + 3)).collect::<Vec<_>>();
    let mut sum = vec![F::from(0); 2 * n];
    let mut coefficients = Vec::new();
    for digit in 0..d {
        let values = (0..n)
            .map(|i| {
                let v: u128 = (-acc[i])
                    .canonicalized()
                    .value()
                    .to_string()
                    .parse()
                    .unwrap();
                F::from(((v >> (bits as usize * digit)) & ((1u128 << bits) - 1)) as usize)
            })
            .collect::<Vec<_>>();
        coefficients.push(
            PackedTable::new(vars, width, values.iter().chain(&values).copied().collect()).unwrap(),
        );
        let mut nt = values;
        native.transform_slice(&mut nt);
        for j in 0..n {
            sum[j] += nt[j] * key[0].data()[digit].a_slice()[j];
            sum[n + j] += nt[j] * key[0].data()[digit].b_slice()[j];
        }
    }
    let frequency = sum.clone();
    for p in sum.chunks_exact_mut(n) {
        native.inverse_transform_slice(p);
    }
    let mut roundtrip = sum.iter().map(|v| v.canonicalized()).collect::<Vec<_>>();
    for poly in roundtrip.chunks_exact_mut(n) {
        native.transform_slice(poly);
    }
    assert_eq!(
        roundtrip, frequency,
        "native inverse/forward fixture round trip"
    );
    let out_a = (0..lwe)
        .map(|i| if i == 0 { sum[0] } else { -sum[n - i] })
        .collect::<Vec<_>>();
    let out_b = acc[n] + packed_monomial::nand_lut::<F>(n, 1).unwrap()[0] + sum[n];
    coefficients.push(PackedTable::new(vars, width, sum).unwrap());
    (config, key, acc, out_a, out_b, coefficients)
}
