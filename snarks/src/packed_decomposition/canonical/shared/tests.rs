use super::*;
use algebra::NTTField;
use pcs::matrix_weighted::masked_polyfrim::{Parameters as Masked, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
fn parameters<F, EF>(vars: usize, width: usize, budget: usize) -> Masked<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    (vars..18)
        .find_map(|physical| Masked::new(vars, width, physical, 2, 1, budget).ok())
        .unwrap()
}
fn fixture<F: NTTField>(width: usize, noncanonical: bool) -> (Config, Vec<PackedTable<F>>) {
    let config = Config::new::<F>(8, 2 * width - 1, 2).unwrap();
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let input = [0, 1, p - 1, p - 2, 17, p / 2];
    let values: Vec<_> = (0..2 * width)
        .map(|i| {
            if i >= config.logical_len() {
                0
            } else if noncanonical {
                p
            } else {
                input[i % input.len()]
            }
        })
        .collect();
    let mut tables = vec![
        PackedTable::new(
            1,
            width,
            values
                .iter()
                .map(|&v| {
                    if v == p {
                        F::zero()
                    } else {
                        F::from(v as usize)
                    }
                })
                .collect(),
        )
        .unwrap(),
    ];
    for i in 0..config.num_digits::<F>().unwrap() {
        tables.push(
            PackedTable::new(
                1,
                width,
                values
                    .iter()
                    .map(|&v| F::from(((v >> (8 * i)) & 255) as usize))
                    .collect(),
            )
            .unwrap(),
        );
    }
    (config, tables)
}
fn comparison<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (config, tables) = fixture::<F>(width, false);
    let d = config.num_digits::<F>().unwrap();
    let source_pp = parameters::<F, EF>(1, width, 2);
    let digit_pp = parameters::<F, EF>(1, width, 5);
    let borrow = parameters::<F, EF>(1, width, 5);
    let helper = parameters::<F, EF>(1 + width.ilog2() as usize, width, 2);
    let mut rng = StdRng::seed_from_u64(2301);
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(
                if i == 0 { &source_pp } else { &digit_pp },
                t,
                &mut rng,
            )
            .unwrap()
        })
        .unzip();
    let sources: Vec<_> = roots
        .iter()
        .zip(&states)
        .enumerate()
        .map(
            |(i, (commitment, state))| CanonicalProverOracle::<F, Sha256, _> {
                parameters: if i == 0 { &source_pp } else { &digit_pp },
                commitment,
                state,
            },
        )
        .collect();
    let digits: Vec<_> = sources[1..].iter().collect();
    let public: Vec<_> = digits.iter().map(|s| s.verifier()).collect();
    let mut pt = Transcript::new_direct();
    let proof = prove::<F, EF, Sha256, _, _>(
        &mut pt,
        &config,
        &sources[0],
        &borrow,
        &helper,
        &digits,
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
    verify::<F, EF, Sha256, _>(
        &mut vt,
        &config,
        &sources[0].verifier(),
        &borrow,
        &helper,
        &public,
        &proof,
    )
    .unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    assert_eq!(states[0].spent().unwrap(), 1);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 2));
    assert_eq!(proof.comparisons.source_opening.openings.len(), 2 * d + 1);
    assert_eq!(proof.comparisons.helper_openings.len(), 2 * d);
    for p in &proof.comparisons.source_opening.openings {
        assert_eq!(p.openings.len(), 1);
        assert_eq!(p.openings[0].index, 1);
    }
    for p in &proof.comparisons.helper_openings {
        assert_eq!(p.openings.len(), 1);
        assert_eq!(p.openings[0].index, 0);
    }
    let reject =
        |p: &Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>| {
            assert!(
                verify::<F, EF, Sha256, _>(
                    &mut Transcript::new_direct(),
                    &config,
                    &sources[0].verifier(),
                    &borrow,
                    &helper,
                    &public,
                    p
                )
                .is_err()
            )
        };
    let mut bad = proof.clone();
    bad.borrow_commitments.pop();
    reject(&bad);
    let mut bad = proof.clone();
    bad.linear.values[0][0] += F::one();
    reject(&bad);
    let mut bad = proof.clone();
    bad.comparisons.helper_values[0] += EF::one();
    reject(&bad);
    let mut changed: Vec<_> = digits.iter().map(|s| s.verifier()).collect();
    changed.swap(0, 1);
    assert!(
        verify::<F, EF, Sha256, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0].verifier(),
            &borrow,
            &helper,
            &changed,
            &proof
        )
        .is_err()
    );
    let mut opt = Transcript::new_direct();
    let original = super::super::prove::<F, EF, Sha256, _, _>(
        &mut opt,
        &config,
        &sources[0],
        &borrow,
        &helper,
        &digits,
        &mut rng,
    )
    .unwrap();
    let original_bytes =
        bincode::serde::encode_to_vec(&original, bincode::config::standard()).unwrap();
    let (original, used): (
        super::super::Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&original_bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, original_bytes.len());
    let mut ovt = Transcript::new_direct();
    super::super::verify::<F, EF, Sha256, _>(
        &mut ovt,
        &config,
        &sources[0].verifier(),
        &borrow,
        &helper,
        &public,
        &original,
    )
    .unwrap();
    assert_eq!(opt.get_challenge(b"after"), ovt.get_challenge(b"after"));
    assert_eq!(states[0].spent().unwrap(), 2);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 5));
    let shared_children: usize = proof
        .linear
        .openings
        .iter()
        .chain(&proof.comparisons.source_opening.openings)
        .chain(&proof.comparisons.helper_openings)
        .map(|p| p.openings.len())
        .sum();
    let original_children: usize = original
        .linear
        .openings
        .iter()
        .map(|p| p.openings.len())
        .sum::<usize>()
        + original
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
    assert_eq!(shared_children, 6 * d + 3);
    assert_eq!(original_children, 12 * d + 2);
    assert!(bytes.len() < original_bytes.len());
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0],
            &borrow,
            &helper,
            &digits,
            &mut rng
        )
        .is_err()
    );
    assert_eq!(states[0].spent().unwrap(), 2);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 5));
    println!(
        "HB_CANONICAL_SHARED_DECOMPOSITION {{\"prime\":{},\"digits\":{},\"repetitions\":2,\"shared_children\":{},\"standalone_children\":{},\"shared_bytes\":{},\"standalone_bytes\":{},\"whole_security_matched\":false,\"original_size\":false}}",
        F::MODULUS_VALUE,
        d,
        shared_children,
        original_children,
        bytes.len(),
        original_bytes.len()
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

fn foreign<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let (config, tables) = fixture::<F>(width, true);
    let d = config.num_digits::<F>().unwrap();
    let spp = parameters::<F, EF>(1, width, 1);
    let dpp = parameters::<F, EF>(1, width, 2);
    let borrow = parameters::<F, EF>(1, width, 2);
    let helper = parameters::<F, EF>(1 + width.ilog2() as usize, width, 1);
    let mut rng = StdRng::seed_from_u64(2401);
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .enumerate()
        .map(|(i, t)| {
            CanonicalPcs::<F, Sha256>::commit(if i == 0 { &spp } else { &dpp }, t, &mut rng)
                .unwrap()
        })
        .unzip();
    let sources: Vec<_> = roots
        .iter()
        .zip(&states)
        .enumerate()
        .map(
            |(i, (commitment, state))| CanonicalProverOracle::<F, Sha256, _> {
                parameters: if i == 0 { &spp } else { &dpp },
                commitment,
                state,
            },
        )
        .collect();
    let digits: Vec<_> = sources[1..].iter().collect();
    let public: Vec<_> = digits.iter().map(|s| s.verifier()).collect();
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &config,
            &sources[0],
            &borrow,
            &helper,
            &digits,
            &mut rng
        )
        .is_err()
    );
    assert!(states.iter().all(|s| s.spent().unwrap() == 0));
    let mut words = vec![vec![F::zero(); 2 * width]; d + 1];
    for row in 0..config.logical_len() {
        let mut carry = 0;
        for i in 0..d {
            let digit: usize = tables[i + 1].values()[row]
                .canonicalized()
                .value()
                .try_into()
                .ok()
                .unwrap();
            carry = usize::from(digit + carry > config.modulus_digit::<F>(i).unwrap());
            words[i + 1][row] = F::from(carry);
        }
        assert_eq!(carry, 1);
    }
    let (br, bs): (Vec<_>, Vec<_>) = words
        .into_iter()
        .map(|v| {
            CanonicalPcs::<F, Sha256>::commit(
                &borrow,
                &PackedTable::new(1, width, v).unwrap(),
                &mut rng,
            )
            .unwrap()
        })
        .unzip();
    let borrows: Vec<_> = br
        .iter()
        .zip(&bs)
        .map(
            |(commitment, state)| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &borrow,
                commitment,
                state,
            },
        )
        .collect();
    let mut pt = Transcript::new_direct();
    bind::<F, EF, Sha256, _>(
        &mut pt,
        &config,
        &sources[0].verifier(),
        &borrow,
        &helper,
        &public,
    )
    .unwrap();
    pt.append_message(b"packed canonical decomposition borrow roots", &br);
    let linear_sources: Vec<_> = sources.iter().chain(&borrows).collect();
    let linear = packed_linear::audit::prove::<F, Sha256, _>(
        &mut pt,
        &linear_sources,
        &relations::<F>(&config).unwrap(),
    )
    .unwrap();
    let registry: Vec<_> = digits.iter().copied().chain(borrows.iter()).collect();
    let comparisons = comparisons::prove::<F, EF, Sha256, _, _>(
        &mut pt,
        &helper,
        &registry,
        &comparison_requests::<F>(&config).unwrap(),
        &mut rng,
    )
    .unwrap();
    let proof = Proof {
        borrow_commitments: br.clone(),
        linear,
        comparisons,
    };
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut vt = Transcript::new_direct();
    bind::<F, EF, Sha256, _>(
        &mut vt,
        &config,
        &sources[0].verifier(),
        &borrow,
        &helper,
        &public,
    )
    .unwrap();
    vt.append_message(
        b"packed canonical decomposition borrow roots",
        &proof.borrow_commitments,
    );
    let valid = packed_linear::audit::verify::<F, Sha256, _>(
        &mut vt,
        &linear_sources
            .iter()
            .map(|s| s.verifier())
            .collect::<Vec<_>>(),
        &relations::<F>(&config).unwrap(),
        &proof.linear,
    )
    .unwrap();
    assert_eq!(valid, vec![true, true, false]);
    comparisons::verify::<F, EF, Sha256, _>(
        &mut vt,
        &helper,
        &registry.iter().map(|s| s.verifier()).collect::<Vec<_>>(),
        &comparison_requests::<F>(&config).unwrap(),
        &proof.comparisons,
    )
    .unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    let err = verify::<F, EF, Sha256, _>(
        &mut Transcript::new_direct(),
        &config,
        &sources[0].verifier(),
        &borrow,
        &helper,
        &public,
        &proof,
    )
    .unwrap_err();
    assert!(err.0.contains("false canonical linear identity"));
    assert_eq!(states[0].spent().unwrap(), 1);
    assert!(states[1..].iter().all(|s| s.spent().unwrap() == 2));
    assert!(bs.iter().all(|s| s.spent().unwrap() == 2));
    println!(
        "HB_CANONICAL_SHARED_DECOMPOSITION_FORGERY {{\"prime\":{},\"genuine_child_openings\":{},\"reconstruction_valid\":true,\"initial_borrow_valid\":true,\"final_borrow_valid\":false,\"production_accepted\":false}}",
        F::MODULUS_VALUE,
        6 * d + 3
    );
}
#[test]
fn babybear_noncanonical() {
    foreign::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_noncanonical() {
    foreign::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}

fn ordinary<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::{
        matrix_weighted::{BatchOpening, Opening, Parameters},
        utils::code::BlockReedSolomonCode,
    };
    let (config, tables) = fixture::<F>(width, false);
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, width, 32, 2).unwrap();
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
        1 + width.ilog2() as usize,
        width,
        32,
        2,
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(2501);
    let (roots, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| CanonicalPcs::<F, Sha256>::commit(&pp, t, &mut rng).unwrap())
        .unzip();
    let sources: Vec<_> = roots
        .iter()
        .zip(&states)
        .map(
            |(commitment, state)| CanonicalProverOracle::<F, Sha256, _> {
                parameters: &pp,
                commitment,
                state,
            },
        )
        .collect();
    let mut pt = Transcript::new_direct();
    let proof = prove::<F, EF, Sha256, _, _>(
        &mut pt,
        &config,
        &sources[0],
        &pp,
        &helper,
        &sources[1..].iter().collect::<Vec<_>>(),
        &mut rng,
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, EF, [u8; 32], Opening<F, [u8; 32]>, BatchOpening<F, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut vt = Transcript::new_direct();
    verify::<F, EF, Sha256, _>(
        &mut vt,
        &config,
        &sources[0].verifier(),
        &pp,
        &helper,
        &sources[1..]
            .iter()
            .map(|s| s.verifier())
            .collect::<Vec<_>>(),
        &proof,
    )
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
