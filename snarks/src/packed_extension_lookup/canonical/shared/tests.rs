use super::*;
use algebra::NTTField;
use pcs::matrix_weighted::masked_polyfrim::{Parameters as Masked, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
fn roundtrip<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Masked::<F, EF>::new(2, width, 11, 2, 1, 1).unwrap();
    let alternate = Masked::<F, EF>::new(2, width, 12, 2, 1, 1).unwrap();
    let helper = Masked::<F, EF>::new(2 + width.ilog2() as usize, width, 12, 2, 1, 1).unwrap();
    let a = PackedTable::new(2, width, (0..4 * width).map(|i| F::from(i % 2)).collect()).unwrap();
    let b = PackedTable::new(
        2,
        width,
        (0..4 * width).map(|i| F::from((i + 1) % 2)).collect(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(881);
    let (ar, as_) = CanonicalPcs::<F, Sha256>::commit(&pp, &a, &mut rng).unwrap();
    let (br, bs) = CanonicalPcs::<F, Sha256>::commit(&alternate, &b, &mut rng).unwrap();
    let (ur, us) = CanonicalPcs::<F, Sha256>::commit(&pp, &b, &mut rng).unwrap();
    let ao = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &ar,
        state: &as_,
    };
    let bo = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &alternate,
        commitment: &br,
        state: &bs,
    };
    let unused = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &ur,
        state: &us,
    };
    let sources = [&ao, &bo, &ao, &unused];
    let requests = vec![
        Request {
            config: Config::new(
                4 * width,
                vec![vec![F::zero(), F::one()], vec![F::one(), F::zero()]],
                2,
            )
            .unwrap(),
            source_slots: vec![0, 1],
        },
        Request {
            config: Config::new(4 * width - 1, vec![vec![F::zero()], vec![F::one()]], 1).unwrap(),
            source_slots: vec![2],
        },
    ];
    let mut pt = Transcript::new_direct();
    let proof =
        prove::<F, EF, Sha256, _, _>(&mut pt, &helper, &sources, &requests, &mut rng).unwrap();
    assert_eq!(proof.helper_roots.len(), 3);
    assert_eq!(proof.helper_openings.len(), 3);
    assert_eq!(proof.source_opening.openings.len(), 2);
    assert_eq!(as_.spent().unwrap(), 1);
    assert_eq!(bs.spent().unwrap(), 1);
    assert_eq!(us.spent().unwrap(), 0);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let mut vt = Transcript::new_direct();
    verify::<F, EF, Sha256, _>(&mut vt, &helper, &public, &requests, &proof).unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    let reject =
        |p: &Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>| {
            assert!(
                verify::<F, EF, Sha256, _>(
                    &mut Transcript::new_direct(),
                    &helper,
                    &public,
                    &requests,
                    p
                )
                .is_err()
            )
        };
    let mut bad = proof.clone();
    bad.source_values[0][0] += F::one();
    reject(&bad);
    let mut bad = proof.clone();
    bad.helper_values[0] += EF::one();
    reject(&bad);
    let mut bad = proof.clone();
    bad.helper_openings.pop();
    reject(&bad);
    let mut bad = proof.clone();
    bad.source_values[3][0] += F::one();
    reject(&bad);
    let mut bad = proof.clone();
    bad.helper_roots[0].root[0] ^= 1;
    reject(&bad);
    let mut bad = proof.clone();
    bad.source_opening.openings.pop();
    reject(&bad);
    let mut changed_public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    changed_public[3] = bo.verifier();
    assert!(
        verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &helper,
            &changed_public,
            &requests,
            &proof
        )
        .is_err()
    );
    let mut invalid = requests.clone();
    invalid[0].source_slots[0] = sources.len();
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &helper,
            &sources,
            &invalid,
            &mut rng
        )
        .is_err()
    );
    let mut changed = requests.clone();
    changed.reverse();
    assert!(
        verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &helper,
            &public,
            &changed,
            &proof
        )
        .is_err()
    );
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &helper,
            &sources,
            &requests,
            &mut rng
        )
        .is_err()
    );
    assert_eq!(as_.spent().unwrap(), 1);
    assert_eq!(bs.spent().unwrap(), 1);
    assert_eq!(us.spent().unwrap(), 0);
    println!(
        "HB_CANONICAL_SHARED_LOOKUP {{\"prime\":{},\"requests\":2,\"helpers\":3,\"source_packets\":2,\"unused_spent\":0,\"decoded_bytes\":{}}}",
        F::MODULUS_VALUE,
        bytes.len()
    );
}
#[test]
fn babybear_shared() {
    roundtrip::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_shared() {
    roundtrip::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

fn foreign<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Masked::<F, EF>::new(2, width, 11, 2, 1, 1).unwrap();
    let helper = Masked::<F, EF>::new(2 + width.ilog2() as usize, width, 12, 2, 1, 1).unwrap();
    let actual = PackedTable::new(2, width, vec![F::one(); 4 * width]).unwrap();
    let fake = PackedTable::new(2, width, vec![F::zero(); 4 * width]).unwrap();
    let mut rng = StdRng::seed_from_u64(991);
    let (root, state) = CanonicalPcs::<F, Sha256>::commit(&pp, &actual, &mut rng).unwrap();
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &state,
    };
    let requests = vec![Request {
        config: Config::new(
            4 * width - 1,
            vec![vec![F::zero()], vec![F::from(2usize)]],
            2,
        )
        .unwrap(),
        source_slots: vec![0],
    }];
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &helper,
            &[&source],
            &requests,
            &mut rng
        )
        .is_err()
    );
    assert_eq!(state.spent().unwrap(), 0);
    let mut pt = Transcript::new_direct();
    let proof = prove_inner::<F, EF, Sha256, _, _, false>(
        &mut pt,
        &helper,
        &[&source],
        &requests,
        &[&fake],
        &mut ProverStatistics::default(),
        &mut rng,
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut vt = Transcript::new_direct();
    verify_inner::<F, EF, Sha256, _, false>(
        &mut vt,
        &helper,
        &[source.verifier()],
        &requests,
        &proof,
    )
    .unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    let err = verify::<F, EF, Sha256, _>(
        &mut Transcript::new_direct(),
        &helper,
        &[source.verifier()],
        &requests,
        &proof,
    )
    .unwrap_err();
    assert_eq!(err.0, "terminal reciprocal identity");
    assert_eq!(state.spent().unwrap(), 1);
    println!(
        "HB_CANONICAL_SHARED_FORGERY {{\"prime\":{},\"genuine_child_openings\":3,\"production_accepted\":false}}",
        F::MODULUS_VALUE
    );
}
#[test]
fn babybear_foreign() {
    foreign::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_foreign() {
    foreign::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

fn ordinary<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(2, width, 32, 2).unwrap();
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
        2 + width.ilog2() as usize,
        width,
        32,
        2,
    )
    .unwrap();
    let table =
        PackedTable::new(2, width, (0..4 * width).map(|i| F::from(i % 2)).collect()).unwrap();
    let mut rng = StdRng::seed_from_u64(1021);
    let (root, state) = CanonicalPcs::<F, Sha256>::commit(&pp, &table, &mut rng).unwrap();
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &state,
    };
    let requests: Vec<_> = (1..=2)
        .map(|repetitions| Request {
            config: Config::new(
                4 * width - repetitions + 1,
                vec![vec![F::zero()], vec![F::one()]],
                repetitions,
            )
            .unwrap(),
            source_slots: vec![0],
        })
        .collect();
    let mut pt = Transcript::new_direct();
    let proof =
        prove::<F, EF, Sha256, _, _>(&mut pt, &helper, &[&source], &requests, &mut rng).unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<
            F,
            EF,
            [u8; 32],
            pcs::matrix_weighted::Opening<F, [u8; 32]>,
            pcs::matrix_weighted::BatchOpening<F, [u8; 32]>,
        >,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut vt = Transcript::new_direct();
    verify::<F, EF, Sha256, _>(&mut vt, &helper, &[source.verifier()], &requests, &proof).unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    assert_eq!(proof.source_opening.openings.len(), 1);
}
#[test]
fn babybear_ordinary() {
    ordinary::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_ordinary() {
    ordinary::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

fn comparison<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = Masked::<F, EF>::new(2, width, 12, 2, 1, 4).unwrap();
    let helper = Masked::<F, EF>::new(2 + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
    let mut rng = StdRng::seed_from_u64(1181);
    let a = PackedTable::new(2, width, (0..4 * width).map(|i| F::from(i % 2)).collect()).unwrap();
    let b = PackedTable::new(
        2,
        width,
        (0..4 * width).map(|i| F::from((i + 1) % 2)).collect(),
    )
    .unwrap();
    let (ar, as_) = CanonicalPcs::<F, Sha256>::commit(&pp, &a, &mut rng).unwrap();
    let (br, bs) = CanonicalPcs::<F, Sha256>::commit(&pp, &b, &mut rng).unwrap();
    let ao = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &ar,
        state: &as_,
    };
    let bo = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &br,
        state: &bs,
    };
    let sources = [&ao, &bo];
    let requests = vec![
        Request {
            config: Config::new(
                4 * width,
                vec![vec![F::zero(), F::one()], vec![F::one(), F::zero()]],
                2,
            )
            .unwrap(),
            source_slots: vec![0, 1],
        },
        Request {
            config: Config::new(4 * width - 1, vec![vec![F::zero()], vec![F::one()]], 1).unwrap(),
            source_slots: vec![0],
        },
    ];
    let shared = prove::<F, EF, Sha256, _, _>(
        &mut Transcript::new_direct(),
        &helper,
        &sources,
        &requests,
        &mut rng,
    )
    .unwrap();
    let shared_bytes = bincode::serde::encode_to_vec(&shared, bincode::config::standard()).unwrap();
    let (shared, used): (
        Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&shared_bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, shared_bytes.len());
    verify::<F, EF, Sha256, _>(
        &mut Transcript::new_direct(),
        &helper,
        &sources.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
        &requests,
        &shared,
    )
    .unwrap();
    let mut pt = Transcript::new_direct();
    let separate: Vec<_> = requests
        .iter()
        .map(|r| {
            super::super::prove::<F, EF, Sha256, _, _>(
                &mut pt,
                &r.config,
                &helper,
                &r.source_slots
                    .iter()
                    .map(|&i| sources[i])
                    .collect::<Vec<_>>(),
                &mut rng,
            )
            .unwrap()
        })
        .collect();
    let separate_bytes =
        bincode::serde::encode_to_vec(&separate, bincode::config::standard()).unwrap();
    let (separate, used): (
        Vec<super::super::Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>>>,
        usize,
    ) = bincode::serde::decode_from_slice(&separate_bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, separate_bytes.len());
    let mut vt = Transcript::new_direct();
    for (r, p) in requests.iter().zip(&separate) {
        super::super::verify::<F, EF, Sha256, _>(
            &mut vt,
            &r.config,
            &helper,
            &r.source_slots
                .iter()
                .map(|&i| sources[i].verifier())
                .collect::<Vec<_>>(),
            p,
        )
        .unwrap();
    }
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    assert_eq!(as_.spent().unwrap(), 4);
    assert_eq!(bs.spent().unwrap(), 3);
    let shared_children: usize = shared
        .source_opening
        .openings
        .iter()
        .chain(&shared.helper_openings)
        .map(|p| p.openings.len())
        .sum();
    let separate_children: usize = separate
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
        .sum();
    assert_eq!(shared_children, 5);
    assert_eq!(separate_children, 11);
    assert!(shared_bytes.len() < separate_bytes.len());
    println!(
        "HB_CANONICAL_SHARED_COMPARISON {{\"prime\":{},\"shared_children\":{},\"standalone_children\":{},\"shared_bytes\":{},\"standalone_bytes\":{},\"whole_security_matched\":false,\"original_size\":false}}",
        F::MODULUS_VALUE,
        shared_children,
        separate_children,
        shared_bytes.len(),
        separate_bytes.len()
    );
}
#[test]
fn babybear_comparison() {
    comparison::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_comparison() {
    comparison::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
