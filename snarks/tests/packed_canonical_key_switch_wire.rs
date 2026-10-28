//! Freeze complete final-stage bytes before comparison-backend dispatch changes.
#[path = "common/canonical_key_switch.rs"]
mod native_fixture;
use algebra::{AbstractExtensionField, NTTField};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use rand::{SeedableRng, rngs::StdRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use snarks::packed_key_switch::canonical::{self, protocol};
fn wire<F, EF>(width: usize, expected: &str, expected_len: usize)
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    let (cfg, key, acc, a, b, coefficients) = native_fixture::fixture::<F>(width);
    let vars = coefficients[0].num_vars();
    let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(vars, width, 32, 2).unwrap();
    let helper = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
        vars + width.ilog2() as usize,
        width,
        32,
        2,
    )
    .unwrap();
    let params = protocol::Parameters {
        coefficients: &pp,
        evaluations: &pp,
        key: &pp,
        input: &pp,
        borrows: &pp,
        helper: &helper,
    };
    let mut rng = StdRng::seed_from_u64(2601);
    let owner = canonical::preprocess::<F, Sha256, _, _>(&pp, cfg, &key, &mut rng).unwrap();
    let mut pt = Transcript::new_direct();
    let proof = protocol::prove::<F, EF, Sha256, _, _>(
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
    let mut vt = Transcript::new_direct();
    protocol::verify::<F, EF, Sha256, _>(&mut vt, &params, owner.expected(), &acc, &a, b, &proof)
        .unwrap();
    assert_eq!(pt.get_challenge(b"after"), vt.get_challenge(b"after"));
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected);
    assert_eq!(bytes.len(), expected_len);
    println!(
        "HB_CANONICAL_KEY_SWITCH_WIRE {{\"prime\":{},\"bytes\":{},\"sha256\":\"{:x}\"}}",
        F::MODULUS_VALUE,
        bytes.len(),
        Sha256::digest(&bytes)
    );
}
#[test]
fn babybear() {
    wire::<algebra::BabyBear, algebra::BabyBearExtension6>(
        8,
        "7fae748a63a394e2782fd772a3438f85742043a0c8a1c5722b11e7c77abe6a0d",
        536782,
    );
}
#[test]
fn goldilocks() {
    wire::<algebra::Goldilocks, algebra::GoldilocksExtension3>(
        4,
        "7d8bd504e83df315c47ea65c43dcf8114a982d43c799a501a34b8b309497b635",
        684146,
    );
}
