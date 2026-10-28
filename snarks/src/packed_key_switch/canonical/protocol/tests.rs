use super::*;
use pcs::matrix_weighted::masked_polyfrim::{Parameters as MaskedParameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
fn fresh<F, EF>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let pp = MaskedParameters::<F, EF>::new(1, width, 12, 2, 1, 2).unwrap();
    let expected = PackedTable::new(1, width, vec![F::zero(); 2 * width]).unwrap();
    let actual = PackedTable::new(1, width, vec![F::one(); 2 * width]).unwrap();
    let (root, state) =
        CanonicalPcs::<F, Sha256>::commit(&pp, &actual, &mut StdRng::seed_from_u64(733)).unwrap();
    // Fresh PCS certificate under the requested public-table prefix, but for the
    // actual committed response one instead of the requested response zero.
    let mut prover = Transcript::new_direct();
    let q = public_input_query::<F, Sha256, _>(&mut prover, &pp, &root, &expected).unwrap();
    let actual_value =
        CanonicalPcs::<F, Sha256>::normalize_values(&pp, actual.evaluate(&q).unwrap());
    let proof = CanonicalPcs::<F, Sha256>::open(&pp, &mut prover, &root, &state, &q, &actual_value)
        .unwrap();
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (MaskedProof<EF, [u8; 32]>, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut reference = Transcript::new_direct();
    let q = public_input_query::<F, Sha256, _>(&mut reference, &pp, &root, &expected).unwrap();
    CanonicalPcs::<F, Sha256>::verify(&pp, &mut reference, &root, &q, &actual_value, &proof)
        .unwrap();
    assert_eq!(
        prover.get_challenge(b"after"),
        reference.get_challenge(b"after")
    );
    assert!(
        verify_public_input::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &pp,
            &root,
            &expected,
            &proof
        )
        .is_err()
    );
    assert_eq!(state.spent().unwrap(), 1);
    println!(
        "HB_MASKED_KS_PUBLIC_INPUT_FORGERY {{\"prime\":{},\"genuine_child_openings\":1,\"production_accepted\":false}}",
        F::MODULUS_VALUE
    );
}
#[test]
fn babybear_false_public_input() {
    fresh::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_false_public_input() {
    fresh::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
