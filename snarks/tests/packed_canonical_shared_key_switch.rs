#[path = "common/canonical_key_switch.rs"]
mod native_fixture;
use algebra::{AbstractExtensionField, NTTField};
use helper::{FiatShamirTranscript, Transcript};
use pcs::matrix_weighted::masked_polyfrim::{Parameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::packed_key_switch::{
    self as ks,
    canonical::{
        self,
        protocol::{self, shared},
    },
};
fn masked<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (_, key, acc, a, b, coefficients) = native_fixture::fixture_with_bits::<F>(width, 5);
    let cfg = ks::Config::new::<F>(32, 21, 5, 2).unwrap();
    let d = cfg.digits::<F>().unwrap();
    let vars = coefficients[0].num_vars();
    let large = if width == 8 { 14 } else { 12 };
    let cpp = Parameters::<F, EF>::new(vars, width, large, 2, 1, width + 3).unwrap();
    let epp = Parameters::<F, EF>::new(vars, width, large, 2, 1, width + 1).unwrap();
    let kpp = Parameters::<F, EF>::new(vars, width, 11, 2, 1, 2).unwrap();
    let ipp = Parameters::<F, EF>::new(vars, width, 11, 2, 1, 2).unwrap();
    let borrow = (vars..18)
        .find_map(|physical| Parameters::<F, EF>::new(vars, width, physical, 2, 1, 5).ok())
        .unwrap();
    let helper =
        Parameters::<F, EF>::new(vars + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
    let pp = shared::Parameters {
        coefficients: &cpp,
        evaluations: &epp,
        key: &kpp,
        input: &ipp,
        borrows: &borrow,
        helper: &helper,
    };
    let mut rng = StdRng::seed_from_u64(2701);
    let owner = canonical::preprocess::<F, Sha256, _, _>(&kpp, cfg, &key, &mut rng).unwrap();
    let mut pt = Transcript::new_direct();
    let proof = shared::prove::<F, EF, Sha256, _, _>(
        &mut pt,
        &pp,
        &owner,
        &acc,
        &a,
        b,
        &coefficients,
        &mut rng,
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        shared::Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut vt = Transcript::new_direct();
    shared::verify::<F, EF, Sha256, _>(&mut vt, &pp, owner.expected(), &acc, &a, b, &proof)
        .unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
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
    assert_eq!(
        proof
            .decomposition
            .comparisons
            .source_opening
            .openings
            .len(),
        2 * d + 1
    );
    for i in 0..d {
        assert_eq!(proof.product.openings[2 * i].openings[0].index, width);
        assert_eq!(proof.product.openings[2 * i + 1].openings[0].index, 0);
        assert_eq!(
            proof.decomposition.linear.openings[1 + i].openings[0].index,
            width
        );
        assert_eq!(
            proof.decomposition.comparisons.source_opening.openings[i].openings[0].index,
            width + 1
        );
    }
    for p in &proof.decomposition.comparisons.source_opening.openings[d..] {
        assert_eq!(p.openings[0].index, 1);
    }
    for p in &proof.decomposition.comparisons.helper_openings {
        assert_eq!(p.openings[0].index, 0);
    }
    let reject = |p: &shared::Proof<
        F,
        EF,
        [u8; 32],
        MaskedProof<EF, [u8; 32]>,
        MaskedProof<EF, [u8; 32]>,
    >| {
        assert!(
            shared::verify::<F, EF, Sha256, _>(
                &mut Transcript::new_direct(),
                &pp,
                owner.expected(),
                &acc,
                &a,
                b,
                p
            )
            .is_err()
        )
    };
    let mut bad = proof.clone();
    bad.input.root[0] ^= 1;
    reject(&bad);
    let mut bad = proof.clone();
    bad.input_opening.openings.clear();
    reject(&bad);
    let mut bad = proof.clone();
    bad.ntt.pop();
    reject(&bad);
    let mut bad = proof.clone();
    bad.product.values[0][0] += F::one();
    reject(&bad);
    let mut bad = proof.clone();
    bad.decomposition.borrow_commitments.pop();
    reject(&bad);
    let mut bad = proof.clone();
    bad.decomposition.comparisons.helper_values[0] += EF::one();
    reject(&bad);
    let mut bad = proof.clone();
    bad.extraction.value[0] += F::one();
    reject(&bad);
    let mut wrong = a.clone();
    wrong[0] += F::one();
    assert!(
        shared::verify::<F, EF, Sha256, _>(
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
        shared::verify::<F, EF, Sha256, _>(
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
        &mut rng,
    )
    .unwrap();
    assert!(
        shared::verify::<F, EF, Sha256, _>(
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
    let mut opt = Transcript::new_direct();
    let old = protocol::prove::<F, EF, Sha256, _, _>(
        &mut opt,
        &pp,
        &owner,
        &acc,
        &a,
        b,
        &coefficients,
        &mut rng,
    )
    .unwrap();
    let old_bytes = bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap();
    let (old, used): (
        protocol::Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&old_bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, old_bytes.len());
    let mut ovt = Transcript::new_direct();
    protocol::verify::<F, EF, Sha256, _>(&mut ovt, &pp, owner.expected(), &acc, &a, b, &old)
        .unwrap();
    assert_eq!(opt.get_challenge(b"after"), ovt.get_challenge(b"after"));
    assert!(
        owner
            .oracles(&kpp)
            .unwrap()
            .iter()
            .all(|s| s.state.spent().unwrap() == 2)
    );
    let common = proof.input_opening.openings.len()
        + proof.extraction.opening.openings.len()
        + proof
            .ntt
            .iter()
            .map(|p| p.coefficient_opening.openings.len() + p.evaluation_opening.openings.len())
            .sum::<usize>()
        + proof
            .product
            .openings
            .iter()
            .map(|p| p.openings.len())
            .sum::<usize>();
    let shared_children = common
        + proof
            .decomposition
            .linear
            .openings
            .iter()
            .chain(&proof.decomposition.comparisons.source_opening.openings)
            .chain(&proof.decomposition.comparisons.helper_openings)
            .map(|p| p.openings.len())
            .sum::<usize>();
    let old_common = old.input_opening.openings.len()
        + old.extraction.opening.openings.len()
        + old
            .ntt
            .iter()
            .map(|p| p.coefficient_opening.openings.len() + p.evaluation_opening.openings.len())
            .sum::<usize>()
        + old
            .product
            .openings
            .iter()
            .map(|p| p.openings.len())
            .sum::<usize>();
    assert_eq!(common, old_common);
    let old_children = old_common
        + old
            .decomposition
            .linear
            .openings
            .iter()
            .map(|p| p.openings.len())
            .sum::<usize>()
        + old
            .decomposition
            .comparisons
            .iter()
            .map(|p| {
                p.source_openings
                    .iter()
                    .map(|p| p.openings.len())
                    .sum::<usize>()
                    + p.groups
                        .iter()
                        .map(|g| g.reciprocal_opening.openings.len())
                        .sum::<usize>()
            })
            .sum::<usize>();
    assert_eq!(shared_children, 2 * width * (d + 1) + 8 * d + 6);
    assert_eq!(old_children, 2 * width * (d + 1) + 14 * d + 5);
    assert!(bytes.len() < old_bytes.len());
    println!(
        "HB_CANONICAL_SHARED_KEY_SWITCH {{\"prime\":{},\"digits\":{},\"repetitions\":2,\"radix_bits\":5,\"polynomial_size\":32,\"output_lwe_dimension\":21,\"shared_children\":{},\"standalone_children\":{},\"shared_bytes\":{},\"standalone_bytes\":{},\"whole_security_matched\":false,\"original_size\":false}}",
        F::MODULUS_VALUE,
        d,
        shared_children,
        old_children,
        bytes.len(),
        old_bytes.len()
    );
}
#[test]
fn babybear_masked() {
    masked::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_masked() {
    masked::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
fn ordinary<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::{
        matrix_weighted::{BatchOpening, Opening, Parameters as Base},
        utils::code::BlockReedSolomonCode,
    };
    let (cfg, key, acc, a, b, coefficients) = native_fixture::fixture::<F>(width);
    let vars = coefficients[0].num_vars();
    let pp = Base::<BlockReedSolomonCode<F>>::balanced_block_rs(vars, width, 32, 2).unwrap();
    let helper = Base::<BlockReedSolomonCode<F>>::balanced_block_rs(
        vars + width.ilog2() as usize,
        width,
        32,
        2,
    )
    .unwrap();
    let params = shared::Parameters {
        coefficients: &pp,
        evaluations: &pp,
        key: &pp,
        input: &pp,
        borrows: &pp,
        helper: &helper,
    };
    let mut rng = StdRng::seed_from_u64(2801);
    let owner = canonical::preprocess::<F, Sha256, _, _>(&pp, cfg, &key, &mut rng).unwrap();
    let mut pt = Transcript::new_direct();
    let proof = shared::prove::<F, EF, Sha256, _, _>(
        &mut pt,
        &params,
        &owner,
        &acc,
        &a,
        b,
        &coefficients,
        &mut rng,
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        shared::Proof<F, EF, [u8; 32], Opening<F, [u8; 32]>, BatchOpening<F, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut vt = Transcript::new_direct();
    shared::verify::<F, EF, Sha256, _>(&mut vt, &params, owner.expected(), &acc, &a, b, &proof)
        .unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
}
#[test]
fn babybear_ordinary() {
    ordinary::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_ordinary() {
    ordinary::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
