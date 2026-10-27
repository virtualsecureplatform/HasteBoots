use algebra::{AbstractExtensionField, DenseMultilinearExtension, NTTField};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    PolynomialCommitmentScheme,
    multilinear::pipfri::{Parameters, PipFRIPCS, Specification},
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
type Backend<F, EF> = PipFRIPCS<F, EF, Sha256>;

fn exercise<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let spec = Specification::new(3, 2, 16).unwrap();
    let mut fixture = Transcript::<EF>::new_direct_extension::<F>();
    for vars in [0, 1, 5, 8] {
        let pp = Backend::<F, EF>::try_setup(vars, &spec).unwrap();
        assert_eq!(pp.num_vars(), Some(vars));
        let base = DenseMultilinearExtension::from_evaluations_vec(
            vars,
            (0..1 << vars).map(|i| F::from(i * i + 3)).collect(),
        );
        let extension = DenseMultilinearExtension::from_evaluations_vec(
            vars,
            (0..1 << vars)
                .map(|i| EF::from_base_fn(|j| F::from(i * 17 + j * 31 + 1)))
                .collect(),
        );
        let (c, s) = Backend::<F, EF>::commit(&pp, &base);
        let (ce, se) = Backend::<F, EF>::commit_ef(&pp, &extension);
        let point = fixture.get_vec_challenge(b"adapter fixture point", vars);
        let value = base.evaluate_ext(&point);
        let ext_value = extension.evaluate(&point);
        let mut prover = Transcript::new_direct_extension::<F>();
        let proof = Backend::<F, EF>::open(&pp, &c, &s, &point, &mut prover);
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct_extension::<F>();
        assert!(Backend::<F, EF>::verify(
            &pp,
            &c,
            &point,
            value,
            &proof,
            &mut verifier
        ));
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        assert!(!Backend::<F, EF>::verify(
            &pp,
            &c,
            &point,
            value + EF::monomial(EF::D - 1),
            &proof,
            &mut Transcript::new_direct_extension::<F>()
        ));
        assert!(!Backend::<F, EF>::verify_ef(
            &pp,
            &c,
            &point,
            value,
            &proof,
            &mut Transcript::new_direct_extension::<F>()
        ));
        assert!(!Backend::<F, EF>::verify(
            &Parameters::default(),
            &c,
            &point,
            value,
            &proof,
            &mut Transcript::new_direct_extension::<F>()
        ));
        let mut wrong = point.clone();
        wrong.push(EF::zero());
        assert!(!Backend::<F, EF>::verify(
            &pp,
            &c,
            &wrong,
            value,
            &proof,
            &mut Transcript::new_direct_extension::<F>()
        ));
        let changed = Backend::<F, EF>::setup(vars, &Specification::new(3, 2, 17).unwrap());
        assert!(!Backend::<F, EF>::verify(
            &changed,
            &c,
            &point,
            value,
            &proof,
            &mut Transcript::new_direct_extension::<F>()
        ));
        let mut bad = proof.clone();
        bad.low_degree.terminal += EF::one();
        assert!(!Backend::<F, EF>::verify(
            &pp,
            &c,
            &point,
            value,
            &bad,
            &mut Transcript::new_direct_extension::<F>()
        ));
        let mut wrong_root = c.clone();
        wrong_root.root[0] ^= 1;
        assert!(!Backend::<F, EF>::verify(
            &pp,
            &wrong_root,
            &point,
            value,
            &proof,
            &mut Transcript::new_direct_extension::<F>()
        ));
        let mut prover = Transcript::new_direct_extension::<F>();
        let proof = Backend::<F, EF>::open_ef(&pp, &ce, &se, &point, &mut prover);
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (proof, used) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct_extension::<F>();
        assert!(Backend::<F, EF>::verify_ef(
            &pp,
            &ce,
            &point,
            ext_value,
            &proof,
            &mut verifier
        ));
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        for count in [0, 1, 4, 16] {
            let points: Vec<_> = (0..count)
                .map(|_| fixture.get_vec_challenge(b"adapter batch point", vars))
                .collect();
            let values: Vec<_> = points.iter().map(|p| base.evaluate_ext(p)).collect();
            let ext_values: Vec<_> = points.iter().map(|p| extension.evaluate(p)).collect();
            let mut prover = Transcript::new_direct_extension::<F>();
            let proofs = Backend::<F, EF>::batch_open(&pp, &c, &s, &points, &mut prover);
            let mut verifier = Transcript::new_direct_extension::<F>();
            assert!(Backend::<F, EF>::batch_verify(
                &pp,
                &c,
                &points,
                &values,
                &proofs,
                &mut verifier
            ));
            assert_eq!(
                prover.get_challenge(b"after batch"),
                verifier.get_challenge(b"after batch")
            );
            let mut prover = Transcript::new_direct_extension::<F>();
            let ext_proofs = Backend::<F, EF>::batch_open_ef(&pp, &ce, &se, &points, &mut prover);
            let mut verifier = Transcript::new_direct_extension::<F>();
            assert!(Backend::<F, EF>::batch_verify_ef(
                &pp,
                &ce,
                &points,
                &ext_values,
                &ext_proofs,
                &mut verifier
            ));
            assert_eq!(
                prover.get_challenge(b"after batch"),
                verifier.get_challenge(b"after batch")
            );
            if count > 0 {
                for len in [0, count - 1] {
                    assert!(!Backend::<F, EF>::batch_verify(
                        &pp,
                        &c,
                        &points,
                        &values,
                        &proofs[..len],
                        &mut Transcript::new_direct_extension::<F>()
                    ));
                    assert!(!Backend::<F, EF>::batch_verify_ef(
                        &pp,
                        &ce,
                        &points,
                        &ext_values[..len],
                        &ext_proofs,
                        &mut Transcript::new_direct_extension::<F>()
                    ));
                }
                let mut bad = values.clone();
                bad[count - 1] += EF::one();
                assert!(!Backend::<F, EF>::batch_verify(
                    &pp,
                    &c,
                    &points,
                    &bad,
                    &proofs,
                    &mut Transcript::new_direct_extension::<F>()
                ));
            }
            if count > 1 && vars > 0 {
                let mut bad = proofs.clone();
                bad.swap(0, count - 1);
                assert!(!Backend::<F, EF>::batch_verify(
                    &pp,
                    &c,
                    &points,
                    &values,
                    &bad,
                    &mut Transcript::new_direct_extension::<F>()
                ));
                let mut bad = points.clone();
                bad.swap(0, count - 1);
                assert!(!Backend::<F, EF>::batch_verify_ef(
                    &pp,
                    &ce,
                    &bad,
                    &ext_values,
                    &ext_proofs,
                    &mut Transcript::new_direct_extension::<F>()
                ));
            }
        }
    }
    // Constant-table padding does not erase logical dimension binding.
    let pp0 = Backend::<F, EF>::setup(0, &spec);
    let pp1 = Backend::<F, EF>::setup(1, &spec);
    let v = EF::from_base(F::from(37usize));
    let (c0, s0) = Backend::<F, EF>::commit_ef(
        &pp0,
        &DenseMultilinearExtension::from_evaluations_vec(0, vec![v]),
    );
    let (c1, _) = Backend::<F, EF>::commit_ef(
        &pp1,
        &DenseMultilinearExtension::from_evaluations_vec(1, vec![v; 2]),
    );
    assert_eq!(c0.root, c1.root);
    let proof = Backend::<F, EF>::open_ef(
        &pp0,
        &c0,
        &s0,
        &[],
        &mut Transcript::new_direct_extension::<F>(),
    );
    assert!(!Backend::<F, EF>::verify_ef(
        &pp1,
        &c1,
        &[EF::zero()],
        v,
        &proof,
        &mut Transcript::new_direct_extension::<F>()
    ));
    assert!(!Backend::<F, EF>::batch_verify(
        &Parameters::default(),
        &c0,
        &[],
        &[],
        &[],
        &mut Transcript::new_direct_extension::<F>()
    ));
    assert!(Backend::<F, EF>::try_setup(usize::MAX, &spec).is_err());
    for (fragment, blowup, q) in [(0, 2, 16), (1, 1, 16), (2, 3, 16), (2, 2, 0)] {
        assert!(Specification::new(fragment, blowup, q).is_err());
    }
}
#[test]
fn babybear_scalar_pcs_interface() {
    exercise::<algebra::BabyBear, algebra::BabyBearExetension>();
}
#[test]
fn goldilocks_scalar_pcs_interface() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension>();
}

#[test]
fn babybearextension8_scalar_pcs_interface() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension8>();
}

#[test]
fn goldilocksextension4_scalar_pcs_interface() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension4>();
}

#[test]
fn babybearextension5_scalar_pcs_interface() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension5>();
}

#[test]
fn goldilocksextension5_scalar_pcs_interface() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

#[test]
fn goldilocksextension3_scalar_pcs_interface() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
}

#[test]
fn babybearextension6_scalar_pcs_interface() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
}
