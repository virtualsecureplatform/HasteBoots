use algebra::{BabyBear as F, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials};
use helper::Transcript;
use std::rc::Rc;
use sumcheck::{MLSumcheck, prover::ProverMsg};
#[test]
fn malformed_sumcheck_messages_are_rejected_without_panics_or_ignored_suffixes() {
    let table = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        3,
        (0..8).map(|i| F::new(i + 1)).collect(),
    ));
    let mut poly = ListOfProductsOfPolynomials::new(3);
    poly.add_product([table.clone(), table.clone()], F::new(1));
    let claim = table
        .evaluations
        .iter()
        .copied()
        .fold(F::new(0), |a, b| a + b * b);
    let (proof, _) = MLSumcheck::prove(&mut Transcript::new_direct(), &poly).unwrap();
    let info = poly.info();
    MLSumcheck::verify(&mut Transcript::new_direct(), &info, claim, &proof).unwrap();
    let mut short = proof.clone();
    short.pop();
    assert!(MLSumcheck::verify(&mut Transcript::new_direct(), &info, claim, &short).is_err());
    let mut long = proof.clone();
    long.push(proof[0].clone());
    assert!(MLSumcheck::verify(&mut Transcript::new_direct(), &info, claim, &long).is_err());
    for len in [0, 1, 4] {
        let bytes =
            bincode::serde::encode_to_vec(vec![F::new(0); len], bincode::config::standard())
                .unwrap();
        let (msg, _): (ProverMsg<F>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        let mut bad = proof.clone();
        bad[0] = msg;
        assert!(MLSumcheck::verify(&mut Transcript::new_direct(), &info, claim, &bad).is_err());
    }
}
