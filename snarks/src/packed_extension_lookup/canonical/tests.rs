use super::*;
use algebra::NTTField;
use pcs::matrix_weighted::masked_polyfrim::{Parameters as MaskedParameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
fn fresh<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = MaskedParameters::<F, EF>::new(2, width, 11, 2, 1, 2).unwrap();
    let helper =
        MaskedParameters::<F, EF>::new(2 + width.ilog2() as usize, width, 12, 2, 1, 2).unwrap();
    let fake = PackedTable::new(2, width, vec![F::zero(); 4 * width]).unwrap();
    let actual = PackedTable::new(2, width, vec![F::one(); 4 * width]).unwrap();
    let config = Config::new(
        4 * width - 1,
        vec![vec![F::zero()], vec![F::from(2usize)]],
        2,
    )
    .unwrap();
    let (root, state) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &actual, &mut StdRng::seed_from_u64(532)).unwrap();
    let source = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &pp,
        commitment: &root,
        state: &state,
    };
    assert!(
        prove::<F, EF, Sha256, _, _>(
            &mut Transcript::new_direct(),
            &config,
            &helper,
            &[&source],
            &mut StdRng::seed_from_u64(533)
        )
        .is_err()
    );
    assert_eq!(state.spent().unwrap(), 0);
    // Only test builds instantiate relaxed terminal checking. Algebra uses a
    // satisfying foreign witness; every PCS opening uses the actual retained root.
    let mut prover = Transcript::new_direct();
    let proof = prove_inner::<F, EF, Sha256, _, _, false>(
        &mut prover,
        &config,
        &helper,
        &[&source],
        &[&fake],
        &mut ProverStatistics::default(),
        &mut StdRng::seed_from_u64(534),
    )
    .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (Proof<F, EF, [u8; 32], MaskedProof<EF, [u8; 32]>>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut reference = Transcript::new_direct();
    verify_inner::<F, EF, Sha256, _, false>(
        &mut reference,
        &config,
        &helper,
        &[source.verifier()],
        &proof,
    )
    .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        reference.get_challenge(b"after")
    );
    assert_eq!(state.spent().unwrap(), 2);
    let err = verify::<F, EF, Sha256, _>(
        &mut Transcript::new_direct(),
        &config,
        &helper,
        &[source.verifier()],
        &proof,
    )
    .unwrap_err();
    assert_eq!(err.0, "terminal reciprocal identity");
    println!(
        "HB_CANONICAL_MASKED_LOOKUP_FORGERY {{\"prime\":{},\"genuine_child_openings\":6,\"production_accepted\":false}}",
        F::MODULUS_VALUE
    );
}
#[test]
fn babybear_false_source() {
    fresh::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_false_source() {
    fresh::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
