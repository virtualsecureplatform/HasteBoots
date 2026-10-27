use algebra::{
    BabyBear, Basis, Goldilocks, NTTField, NTTPolynomial, matrix_weighted::PackedTable,
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use lattice::{NTTGadgetRLWE, NTTRLWE};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{packed_key_switch as ks, packed_monomial};
fn roundtrip<F: NTTField + Serialize + DeserializeOwned + From<usize>>() {
    let n = 32usize;
    let width = 4usize;
    let lwe = 21;
    let config = ks::Config::new::<F>(n, lwe, 5, 2).unwrap();
    let d = config.digits::<F>().unwrap();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(4, width, 32, 2).unwrap();
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(6, width, 32, 2).unwrap();
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
        Basis::new(5),
    )];
    let setup = ks::preprocess::<F, Sha256, _>(&pp, config, &key).unwrap();
    let acc = (0..2 * n).map(|i| F::from(7 * i + 3)).collect::<Vec<_>>();
    let mut sum = vec![F::from(0); 2 * n];
    let mut coefficients = Vec::new();
    for digit in 0..d {
        let values = (0..n)
            .map(|i| {
                let v: u128 = (-acc[i]).value().to_string().parse().unwrap();
                F::from(((v >> (5 * digit)) & 31) as usize)
            })
            .collect::<Vec<_>>();
        coefficients.push(
            PackedTable::new(4, width, values.iter().chain(&values).copied().collect()).unwrap(),
        );
        let mut nt = values;
        native.transform_slice(&mut nt);
        for j in 0..n {
            sum[j] += nt[j] * key[0].data()[digit].a_slice()[j];
            sum[n + j] += nt[j] * key[0].data()[digit].b_slice()[j];
        }
    }
    for p in sum.chunks_exact_mut(n) {
        native.inverse_transform_slice(p);
    }
    let out_a = (0..lwe)
        .map(|i| if i == 0 { sum[0] } else { -sum[n - i] })
        .collect::<Vec<_>>();
    let out_b = acc[n] + packed_monomial::nand_lut::<F>(n, 1).unwrap()[0] + sum[n];
    coefficients.push(PackedTable::new(4, width, sum).unwrap());
    let mut prover = Transcript::new();
    let proof = ks::prove::<F, Sha256, _>(
        &mut prover,
        &pp,
        &helper,
        &setup,
        &acc,
        &out_a,
        out_b,
        &coefficients,
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (ks::Proof<F, [u8; 32]>, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new();
    ks::verify::<F, Sha256, _>(
        &mut verifier,
        &pp,
        &helper,
        setup.expected(),
        &acc,
        &out_a,
        out_b,
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    let reject = |p: &ks::Proof<F, [u8; 32]>| {
        ks::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &pp,
            &helper,
            setup.expected(),
            &acc,
            &out_a,
            out_b,
            p,
        )
        .is_err()
    };
    for i in 0..d + 1 {
        let mut bad = proof.clone();
        bad.coefficients[i].root[0] ^= 1;
        assert!(reject(&bad));
        let mut bad = proof.clone();
        bad.evaluations[i].root[0] ^= 1;
        assert!(reject(&bad));
    }
    let mut bad = proof.clone();
    bad.ntt.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.extraction.value[0] += F::from(1);
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.extraction.opening.columns.clear();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.decomposition.borrow_commitments.pop();
    assert!(reject(&bad));
    for i in [0, 1, lwe - 1] {
        let mut a = out_a.clone();
        a[i] += F::from(1);
        assert!(
            ks::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &pp,
                &helper,
                setup.expected(),
                &acc,
                &a,
                out_b,
                &proof
            )
            .is_err()
        );
    }
    assert!(
        ks::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &pp,
            &helper,
            setup.expected(),
            &acc,
            &out_a,
            out_b + F::from(1),
            &proof
        )
        .is_err()
    );
    for i in [0, n] {
        let mut other = acc.clone();
        other[i] += F::from(1);
        assert!(
            ks::verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &pp,
                &helper,
                setup.expected(),
                &other,
                &out_a,
                out_b,
                &proof
            )
            .is_err()
        );
        assert!(
            ks::prove::<F, Sha256, _>(
                &mut Transcript::new(),
                &pp,
                &helper,
                &setup,
                &other,
                &out_a,
                out_b,
                &coefficients
            )
            .is_err()
        );
    }
    let foreign = vec![NTTGadgetRLWE::zero(n, Basis::new(5))];
    let foreign_setup =
        ks::preprocess::<F, Sha256, _>(&pp, setup.expected().config().clone(), &foreign).unwrap();
    assert!(
        ks::verify::<F, Sha256, _>(
            &mut Transcript::new(),
            &pp,
            &helper,
            foreign_setup.expected(),
            &acc,
            &out_a,
            out_b,
            &proof
        )
        .is_err()
    );
    assert!(ks::Config::new::<F>(64, lwe, 5, 2).is_err());
    assert!(ks::Config::new::<F>(n, lwe, 0, 2).is_err());
    assert!(ks::preprocess::<F, Sha256, _>(&pp, setup.expected().config().clone(), &[]).is_err());
}
#[test]
fn babybear_key_switch_and_unpadded_output_roundtrip() {
    roundtrip::<BabyBear>();
}
#[test]
fn goldilocks_key_switch_and_unpadded_output_roundtrip() {
    roundtrip::<Goldilocks>();
}
