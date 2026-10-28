use algebra::{
    AbstractExtensionField, Basis, NTTField, NTTPolynomial, matrix_weighted::PackedTable,
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use lattice::{NTTGadgetRLWE, NTTRLWE};
use pcs::matrix_weighted::masked_polyfrim::{Parameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_key_switch as ks,
    packed_key_switch::canonical::{self, protocol},
    packed_monomial,
};
fn fixture<F: NTTField>(
    width: usize,
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
    let config = ks::Config::new::<F>(n, lwe, 8, 1).unwrap();
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
        Basis::new(8),
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
                F::from(((v >> (8 * digit)) & 255) as usize)
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
fn exercise<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (config, key, acc, a, b, coefficients) = fixture::<F>(width);
    let d = config.digits::<F>().unwrap();
    let vars = coefficients[0].num_vars();
    let large = if width == 8 { 14 } else { 12 };
    let cpp = Parameters::<F, EF>::new(vars, width, large, 2, 1, width + 2).unwrap();
    let epp = Parameters::<F, EF>::new(vars, width, large, 2, 1, width + 1).unwrap();
    let kpp = Parameters::<F, EF>::new(vars, width, 11, 2, 1, 1).unwrap();
    let ipp = Parameters::<F, EF>::new(vars, width, 11, 2, 1, 2).unwrap();
    let borrow = Parameters::<F, EF>::new(vars, width, 12, 2, 1, 3).unwrap();
    let helper =
        Parameters::<F, EF>::new(vars + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
    let pp = protocol::Parameters {
        coefficients: &cpp,
        evaluations: &epp,
        key: &kpp,
        input: &ipp,
        borrows: &borrow,
        helper: &helper,
    };
    let owner = canonical::preprocess::<F, Sha256, _, _>(
        &kpp,
        config,
        &key,
        &mut StdRng::seed_from_u64(328),
    )
    .unwrap();
    let mut prover = Transcript::new_direct();
    let proof = protocol::prove::<F, EF, Sha256, _, _>(
        &mut prover,
        &pp,
        &owner,
        &acc,
        &a,
        b,
        &coefficients,
        &mut StdRng::seed_from_u64(329),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        protocol::Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    protocol::verify::<F, EF, Sha256, _>(&mut verifier, &pp, owner.expected(), &acc, &a, b, &proof)
        .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
    assert!(
        owner
            .oracles(&kpp)
            .unwrap()
            .iter()
            .all(|s| s.state.spent().unwrap() == 1)
    );
    assert_eq!(proof.input_opening.openings[0].index, 0);
    assert_eq!(proof.decomposition.linear.openings[0].openings[0].index, 1);
    assert_eq!(proof.extraction.opening.openings[0].index, width);
    for i in 0..d {
        assert_eq!(proof.product.openings[2 * i].openings[0].index, width);
        assert_eq!(proof.product.openings[2 * i + 1].openings[0].index, 0);
        assert_eq!(
            proof.decomposition.linear.openings[i + 1].openings[0].index,
            width
        );
        assert_eq!(
            proof.decomposition.comparisons[i].source_openings[0].openings[0].index,
            width + 1
        );
    }
    let reject = |proof: &protocol::Proof<
        F,
        EF,
        [u8; 32],
        MaskedProof<EF, [u8; 32]>,
        MaskedProof<EF, [u8; 32]>,
    >| {
        protocol::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &pp,
            owner.expected(),
            &acc,
            &a,
            b,
            proof,
        )
        .is_err()
    };
    let mut bad = proof.clone();
    bad.input.root[0] ^= 1;
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.input_opening.openings.clear();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.extraction.value[0] += F::one();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.ntt.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.decomposition.borrow_commitments.pop();
    assert!(reject(&bad));
    let mut bad = proof.clone();
    bad.coefficients[0].root[0] ^= 1;
    assert!(reject(&bad));
    let mut wrong = a.clone();
    wrong[0] += F::one();
    assert!(
        protocol::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &pp,
            owner.expected(),
            &acc,
            &wrong,
            b,
            &proof
        )
        .is_err()
    );
    assert!(
        protocol::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &pp,
            owner.expected(),
            &acc,
            &a,
            b + F::one(),
            &proof
        )
        .is_err()
    );
    let foreign = canonical::preprocess::<F, Sha256, _, _>(
        &kpp,
        owner.expected().config().clone(),
        &key,
        &mut StdRng::seed_from_u64(330),
    )
    .unwrap();
    assert!(
        protocol::verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &pp,
            foreign.expected(),
            &acc,
            &a,
            b,
            &proof
        )
        .is_err()
    );
    println!(
        "HB_MASKED_CANONICAL_KEY_SWITCH {{\"prime\":{},\"width\":{},\"digits\":{},\"polynomial_size\":32,\"output_lwe_dimension\":21,\"proof_bytes\":{},\"native_full_pbs\":false,\"whole_security_certified\":false}}",
        F::MODULUS_VALUE,
        width,
        d,
        bytes.len()
    );
}
#[test]
fn babybear() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
#[test]
fn brakedown() {
    use algebra::{BabyBear as F, BabyBearExtension6 as E};
    use pcs::matrix_weighted::{BatchOpening, Opening, Parameters as BaseParameters};
    let (config, key, acc, a, b, coefficients) = fixture::<F>(8);
    let cpp = BaseParameters::balanced_block_rs(3, 8, 8, 2).unwrap();
    let helper = BaseParameters::balanced_block_rs(6, 8, 8, 2).unwrap();
    let pp = protocol::Parameters {
        coefficients: &cpp,
        evaluations: &cpp,
        key: &cpp,
        input: &cpp,
        borrows: &cpp,
        helper: &helper,
    };
    let owner =
        canonical::preprocess::<F, Sha256, _, _>(&cpp, config, &key, &mut StdRng::seed_from_u64(5))
            .unwrap();
    let mut prover = Transcript::new_direct();
    let proof = protocol::prove::<F, E, Sha256, _, _>(
        &mut prover,
        &pp,
        &owner,
        &acc,
        &a,
        b,
        &coefficients,
        &mut StdRng::seed_from_u64(6),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        protocol::Proof<F, E, [u8; 32], Opening<F, [u8; 32]>, BatchOpening<F, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut verifier = Transcript::new_direct();
    protocol::verify::<F, E, Sha256, _>(&mut verifier, &pp, owner.expected(), &acc, &a, b, &proof)
        .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        verifier.get_challenge(b"after")
    );
}

#[test]
fn goldilocks_fixture_ntt_roundtrip() {
    fixture::<algebra::Goldilocks>(4);
}
