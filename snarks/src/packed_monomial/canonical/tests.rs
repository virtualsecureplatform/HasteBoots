use super::*;
use algebra::AbstractExtensionField;
use pcs::matrix_weighted::masked_polyfrim::{Parameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use serde::de::DeserializeOwned;
use sha2::Sha256;
fn fresh<F, EF>()
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let actual = Plan::new(32, vec![0, 0]).unwrap();
    let requested = Plan::new(32, vec![1, 0]).unwrap();
    let cpp = Parameters::<F, EF>::new(6, 2, 11, 2, 1, 4).unwrap();
    let epp = Parameters::<F, EF>::new(6, 2, 12, 2, 1, 6).unwrap();
    let table = PackedTable::new(6, 2, (0usize..128).map(|i| F::from(i + 3)).collect()).unwrap();
    let (cr, cs) =
        CanonicalPcs::<F, Sha256>::commit(&cpp, &table, &mut StdRng::seed_from_u64(17)).unwrap();
    let coefficient = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &cpp,
        commitment: &cr,
        state: &cs,
    };
    let transformed = transform(&actual, &table).unwrap();
    let (er, es) =
        CanonicalPcs::<F, Sha256>::commit(&epp, &transformed, &mut StdRng::seed_from_u64(18))
            .unwrap();
    let evaluation = CanonicalProverOracle::<F, Sha256, _> {
        parameters: &epp,
        commitment: &er,
        state: &es,
    };
    let public = [coefficient.verifier(), coefficient.verifier()];
    let mut prover = Transcript::new_direct();
    bind::<F, Sha256, _>(&mut prover, &requested, &epp, &public).unwrap();
    let roots = vec![er.clone(), er.clone()];
    prover.append_message(b"public canonical monomial NTT roots", &roots);
    let ntt_shape = packed_ntt::Shape::new_canonical::<F, Sha256, _>(&epp, 32).unwrap();
    let ntt = (0..2)
        .map(|_| {
            packed_ntt::prove_canonical::<F, Sha256, _>(
                &mut prover,
                &ntt_shape,
                &coefficient,
                &evaluation,
            )
            .unwrap()
        })
        .collect();
    let shape = product_shape(6, 2);
    let actual_factor = actual.table::<F>(2).unwrap();
    let factors = [evaluation.table(), &actual_factor, evaluation.table()];
    let (product, subclaim, _) =
        packed_zero::prove_with_borrowed_terminal_values(&mut prover, &shape, &factors).unwrap();
    let values = vec![
        CanonicalPcs::<F, Sha256>::normalize_values(
            &epp,
            evaluation.table().evaluate(&subclaim.query).unwrap()
        );
        2
    ];
    let openings = (0..2)
        .map(|i| {
            CanonicalPcs::<F, Sha256>::open(
                &epp,
                &mut prover,
                &er,
                &es,
                &subclaim.query,
                &values[i],
            )
            .unwrap()
        })
        .collect();
    let proof = Proof {
        evaluations: roots,
        ntt,
        product,
        values,
        openings,
    };
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (proof, used): (
        Proof<F, [u8; 32], MaskedProof<EF, [u8; 32]>, MaskedProof<EF, [u8; 32]>>,
        usize,
    ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(used, bytes.len());
    let mut reference = Transcript::new_direct();
    bind::<F, Sha256, _>(&mut reference, &requested, &epp, &public).unwrap();
    reference.append_message(b"public canonical monomial NTT roots", &proof.evaluations);
    for i in 0..2 {
        packed_ntt::verify_canonical::<F, Sha256, _>(
            &mut reference,
            &ntt_shape,
            &public[i],
            &evaluation.verifier(),
            &proof.ntt[i],
        )
        .unwrap();
    }
    let checked = packed_zero::verify(&mut reference, &shape, &proof.product).unwrap();
    checked
        .check(
            &shape,
            &[
                proof.values[0].clone(),
                actual.evaluate(2, &checked.query).unwrap(),
                proof.values[1].clone(),
            ],
        )
        .unwrap();
    for i in 0..2 {
        CanonicalPcs::<F, Sha256>::verify(
            &epp,
            &mut reference,
            &er,
            &checked.query,
            &proof.values[i],
            &proof.openings[i],
        )
        .unwrap();
    }
    assert_eq!(
        prover.get_challenge(b"after"),
        reference.get_challenge(b"after")
    );
    assert_eq!(cs.spent().unwrap(), 4);
    assert_eq!(es.spent().unwrap(), 6);
    let err = verify::<F, Sha256, _>(
        &mut Transcript::new_direct(),
        &requested,
        &epp,
        &public,
        &proof,
    )
    .unwrap_err();
    assert!(err.0.contains("terminal identity"), "{err}");
    println!(
        "HB_MASKED_MONOMIAL_FORGERY {{\"prime\":{},\"genuine_child_openings\":10,\"production_accepted\":false}}",
        F::MODULUS_VALUE
    );
}
#[test]
fn babybear_wrong_rotation() {
    fresh::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
#[test]
fn goldilocks_wrong_rotation() {
    fresh::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}
