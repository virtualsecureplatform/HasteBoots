//! Frozen controls for the existing per-limb proof while sharing preparation code.
use super::*;
use algebra::NTTField;
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
fn wire<F, EF>(width: usize, expected: &str, expected_len: usize)
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let config = Config::new::<F>(8, 2 * width - 1, 2).unwrap();
    let d = config.num_digits::<F>().unwrap();
    let p: u128 = F::MODULUS_VALUE.to_string().parse().unwrap();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(1, width, 32, 2).unwrap();
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
        1 + width.ilog2() as usize,
        width,
        32,
        2,
    )
    .unwrap();
    let input = [0, 1, p - 1, p - 2, 17, p / 2];
    let values: Vec<_> = (0..2 * width)
        .map(|i| {
            if i < config.logical_len() {
                input[i % input.len()]
            } else {
                0
            }
        })
        .collect();
    let mut tables = vec![
        PackedTable::new(
            1,
            width,
            values.iter().map(|&v| F::from(v as usize)).collect(),
        )
        .unwrap(),
    ];
    for limb in 0..d {
        tables.push(
            PackedTable::new(
                1,
                width,
                values
                    .iter()
                    .map(|&v| F::from(((v >> (8 * limb)) & 255) as usize))
                    .collect(),
            )
            .unwrap(),
        );
    }
    let mut rng = StdRng::seed_from_u64(2201);
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
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected);
    assert_eq!(bytes.len(), expected_len);
    println!(
        "HB_CANONICAL_DECOMPOSITION_WIRE {{\"prime\":{},\"bytes\":{},\"sha256\":\"{:x}\"}}",
        F::MODULUS_VALUE,
        bytes.len(),
        Sha256::digest(&bytes)
    );
}
#[test]
fn babybear_wire() {
    wire::<algebra::BabyBear, algebra::BabyBearExtension6>(
        8,
        "7acc0f9ca3801f5a38c92f4c599c5c1309ab7d34924653ada367f392e2d39163",
        219008,
    );
}
#[test]
fn goldilocks_wire() {
    wire::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
        4,
        "c6f62fc295a5dce5f463dca27a12024e4c2035ad41629ce7dcb7e0d627122483",
        306450,
    );
}
