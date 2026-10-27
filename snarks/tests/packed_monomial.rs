use algebra::{
    BabyBear, Goldilocks, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_monomial::{self, Plan, Proof},
    packed_oracle::ProverOracle,
};
fn public_evaluation<F: NTTField + From<usize>>() {
    for (n, k) in [(32usize, 1usize), (32, 4), (32, 32), (64, 8)] {
        let plan = Plan::new(n, vec![0, 1, n - 1, n, n + 5, 2 * n - 1]).unwrap();
        let table = plan.table::<F>(k).unwrap();
        let query: Vec<_> = (0..table.num_vars())
            .map(|i| MatrixPair {
                zero: Matrix::new(k, (0..k * k).map(|j| F::from(i * 17 + j * 3 + 1)).collect())
                    .unwrap(),
                one: Matrix::new(
                    k,
                    (0..k * k).map(|j| F::from(i * 13 + j * 7 + 23)).collect(),
                )
                .unwrap(),
            })
            .collect();
        assert_eq!(
            plan.evaluate(k, &query).unwrap(),
            table.evaluate(&query).unwrap()
        );
    }
}
#[test]
fn public_monomials_match_native_bit_reversed_ntt_and_dense_queries() {
    public_evaluation::<BabyBear>();
    public_evaluation::<Goldilocks>();
}
fn roundtrip<F: NTTField + Serialize + DeserializeOwned + From<usize>>() {
    let n = 32usize;
    let k = 4;
    let plan = Plan::new(n, vec![0, 1, n - 1, n, n + 5, 2 * n - 1]).unwrap();
    let rows = plan.padded_rounds();
    let mut input = vec![F::from(0); 2 * rows * n];
    let mut output = input.clone();
    for h in 0..2 {
        for (row, &rotation) in plan.rotations().iter().enumerate() {
            for coef in 0..n {
                let value = F::from((h * rows + row) * n + coef + 3);
                input[(h * rows + row) * n + coef] = value;
                let to = (coef + rotation) % (2 * n);
                if to < n {
                    output[(h * rows + row) * n + to] += value;
                } else {
                    output[(h * rows + row) * n + to - n] -= value;
                }
            }
        }
    }
    let vars = (input.len() / k).ilog2() as usize;
    let tables: Vec<_> = [input, output]
        .into_iter()
        .map(|v| PackedTable::new(vars, k, v).unwrap())
        .collect();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(vars, k, 32, 2).unwrap();
    let (commitments, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, Sha256>(t).unwrap())
        .unzip();
    let sources: Vec<_> = tables
        .iter()
        .zip(&commitments)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: &pp,
            table,
            commitment,
            state,
        })
        .collect();
    let mut prover = Transcript::new();
    let proof = packed_monomial::prove::<F, Sha256, _>(
        &mut prover,
        &plan,
        &sources.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let mut verifier = Transcript::new();
    packed_monomial::verify::<F, Sha256, _>(&mut verifier, &plan, &public, &proof).unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    let reject = |p: &Proof<F, [u8; 32]>| {
        packed_monomial::verify::<F, Sha256, _>(&mut Transcript::new(), &plan, &public, p).is_err()
    };
    for i in 0..2 {
        let mut bad = proof.clone();
        bad.values[i][0] += F::from(1);
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.openings[i].columns.clear();
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.evaluations[i].root[0] ^= 1;
        assert!(reject(&bad));
    }
    let mut bad = proof.clone();
    bad.ntt.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.product.first.clear();
    assert!(reject(&bad));
    let mut changed = plan.rotations().to_vec();
    changed[0] = 1;
    let changed = Plan::new(n, changed).unwrap();
    assert!(
        packed_monomial::verify::<F, Sha256, _>(&mut Transcript::new(), &changed, &public, &proof)
            .is_err()
    );
    assert!(
        packed_monomial::prove::<F, Sha256, _>(
            &mut Transcript::new(),
            &changed,
            &sources.iter().collect::<Vec<_>>()
        )
        .is_err()
    );
}
#[test]
fn monomial_products_authenticate_both_canonical_sources() {
    roundtrip::<BabyBear>();
    roundtrip::<Goldilocks>();
}
#[test]
fn exact_public_preprocessing_and_negacyclic_initialization() {
    use algebra::Field;
    type F = Goldilocks;
    let p = F::MODULUS_VALUE;
    let a = (p - 1) / 4096;
    assert_eq!(
        packed_monomial::switch_public_scalar(F::new(a), 2048).unwrap(),
        0
    );
    assert_eq!(
        packed_monomial::switch_public_scalar(F::new(a + 1), 2048).unwrap(),
        1
    );
    let plan = Plan::from_field_mask(1024, &[F::new(a), F::new(a + 1)]).unwrap();
    assert_eq!(plan.rotations(), &[0, 1]);
    type B = BabyBear;
    let lut = vec![B::from(1), B::from(2), B::from(3), B::from(4)];
    // body nearest to one eighth of p switches to 1 in Z_8.
    let body = B::new(B::MODULUS_VALUE / 8);
    let initial = packed_monomial::initial_accumulator(&lut, body).unwrap();
    assert_eq!(
        initial,
        vec![
            B::from(0),
            B::from(0),
            B::from(0),
            B::from(0),
            B::from(2),
            B::from(3),
            B::from(4),
            -B::from(1)
        ]
    );
    assert!(Plan::new(32, vec![64]).is_err());
    assert!(Plan::new(32, vec![]).is_err());
}
