use algebra::{AbstractExtensionField, DenseMultilinearExtension, NTTField};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    PolynomialCommitmentScheme,
    multilinear::masked_pipfri::{MaskedPipFRIPCS, Parameters, Specification},
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
type Backend<F, EF> = MaskedPipFRIPCS<F, EF, Sha256>;

fn exercise<F, EF>()
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let spec = Specification::new(11, 2, 1, 32).unwrap();
    let mut fixture = Transcript::<EF>::new_direct_extension::<F>();
    for vars in [0, 1, 8, 12] {
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
        let changed = Backend::<F, EF>::setup(vars, &Specification::new(11, 2, 1, 33).unwrap());
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
        let mut spent = 1;
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
            spent += count;
            assert_eq!(s.remaining_openings().unwrap(), 32 - spent);
            assert_eq!(se.remaining_openings().unwrap(), 32 - spent);
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
    assert!(!Backend::<F, EF>::batch_verify(
        &Parameters::default(),
        &pcs::pipfri::masked::Commitment { root: [0u8; 32] },
        &[],
        &[],
        &[],
        &mut Transcript::new_direct_extension::<F>()
    ));
    assert!(Backend::<F, EF>::try_setup(usize::MAX, &spec).is_err());
    for (fragment, blowup, q) in [(0, 2, 16), (1, 1, 16), (2, 3, 16), (2, 2, 0)] {
        assert!(Specification::new(fragment, blowup, q, 32).is_err());
    }
}
#[test]
fn babybear_masked_scalar_pcs_interface() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension5>();
}
#[test]
fn goldilocks_masked_scalar_pcs_interface() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
}

#[test]
fn lifetime_capacity_preflight_and_concurrent_batches() {
    type F = algebra::BabyBear;
    type EF = algebra::BabyBearExtension5;
    type PCS = Backend<F, EF>;
    let spec = Specification::new(8, 2, 1, 4).unwrap();
    let pp = PCS::setup(1, &spec);
    let poly =
        DenseMultilinearExtension::from_evaluations_vec(1, vec![F::from(3usize), F::from(7usize)]);
    let (c, s) = PCS::commit(&pp, &poly);
    let (fresh, _) = PCS::commit(&pp, &poly);
    assert_ne!(c.root, fresh.root);
    let point = vec![EF::from_base(F::from(2usize))];
    let value = poly.evaluate_ext(&point);
    let mut wrong_root = c.clone();
    wrong_root.root[0] ^= 1;
    let other = PCS::setup(1, &Specification::new(8, 2, 1, 5).unwrap());
    for case in 0..5 {
        let mut t = Transcript::new_direct_extension::<F>();
        let result = match case {
            0 => PCS::try_batch_open(&pp, &c, &s, &vec![point.clone(); 5], &mut t),
            1 => PCS::try_batch_open(&pp, &wrong_root, &s, &[point.clone()], &mut t),
            2 => PCS::try_batch_open(&pp, &c, &s, &[vec![]], &mut t),
            3 => PCS::try_batch_open(&other, &c, &s, &[point.clone()], &mut t),
            _ => PCS::try_batch_open_ef(&pp, &c, &s, &[point.clone()], &mut t),
        };
        assert!(result.is_err());
        assert_eq!(s.remaining_openings().unwrap(), 4);
        assert_eq!(
            t.get_challenge(b"preflight"),
            Transcript::<EF>::new_direct_extension::<F>().get_challenge(b"preflight")
        );
    }
    // Two simultaneous batches cannot both pass a stale capacity check.
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let launch = || {
            scope.spawn(|| {
                barrier.wait();
                let mut t = Transcript::new_direct_extension::<F>();
                let result = PCS::try_batch_open(&pp, &c, &s, &vec![point.clone(); 3], &mut t);
                (result, t.get_challenge(b"after race"))
            })
        };
        let a = launch();
        let b = launch();
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|(r, _)| r.is_ok()).count(), 1);
    assert_eq!(s.remaining_openings().unwrap(), 1);
    for (result, after) in results {
        match result {
            Ok(proofs) => {
                assert_eq!(
                    proofs.iter().map(|p| p.opening_index).collect::<Vec<_>>(),
                    vec![0, 1, 2]
                );
                let mut t = Transcript::new_direct_extension::<F>();
                assert!(PCS::batch_verify(
                    &pp,
                    &c,
                    &vec![point.clone(); 3],
                    &vec![value; 3],
                    &proofs,
                    &mut t
                ));
                assert_eq!(after, t.get_challenge(b"after race"));
                let duplicate = vec![proofs[0].clone(); 3];
                assert!(!PCS::batch_verify(
                    &pp,
                    &c,
                    &vec![point.clone(); 3],
                    &vec![value; 3],
                    &duplicate,
                    &mut Transcript::new_direct_extension::<F>()
                ));
            }
            Err(_) => assert_eq!(
                after,
                Transcript::<EF>::new_direct_extension::<F>().get_challenge(b"after race")
            ),
        }
    }
    let proof = PCS::try_open(
        &pp,
        &c,
        &s,
        &point,
        &mut Transcript::new_direct_extension::<F>(),
    )
    .unwrap();
    assert_eq!(proof.opening_index, 3);
    assert!(PCS::verify(
        &pp,
        &c,
        &point,
        value,
        &proof,
        &mut Transcript::new_direct_extension::<F>()
    ));
    // Stateless trait verification deliberately permits replay; it never resets
    // the private prover's allowance. Ordered replay detection is a core API.
    assert!(PCS::verify(
        &pp,
        &c,
        &point,
        value,
        &proof,
        &mut Transcript::new_direct_extension::<F>()
    ));
    assert_eq!(s.remaining_openings().unwrap(), 0);
    assert!(
        PCS::try_open(
            &pp,
            &c,
            &s,
            &point,
            &mut Transcript::new_direct_extension::<F>()
        )
        .is_err()
    );
    let mut out_of_budget = proof;
    out_of_budget.opening_index = 4;
    assert!(!PCS::verify(
        &pp,
        &c,
        &point,
        value,
        &out_of_budget,
        &mut Transcript::new_direct_extension::<F>()
    ));
    for args in [
        (6, 2, 1, 4),
        (8, 2, 0, 4),
        (8, 2, 1, 0),
        (usize::MAX, 2, 1, 1),
        (usize::BITS as usize - 1, 2, 1, 1),
    ] {
        assert!(Specification::new(args.0, args.1, args.2, args.3).is_err());
    }
}

#[test]
fn exact_value_api_preserves_lazy_encodings_for_composition() {
    use algebra::Field;
    use num_traits::{One, Zero};
    type B = algebra::Goldilocks;
    type EF = algebra::GoldilocksExtension5;
    type PCS = Backend<B, EF>;
    let mut exercised_distinct_encoding = false;
    for vars in [0, 1] {
        let pp = PCS::setup(vars, &Specification::new(8, 2, 1, 2).unwrap());
        let point = vec![EF::monomial(1); vars];
        for value in [B::zero(), B::one(), B::neg_one(), B::new(B::MODULUS_VALUE)] {
            let base =
                DenseMultilinearExtension::from_evaluations_vec(vars, vec![value; 1 << vars]);
            let ext_value = EF::from_base_fn(|j| if j == 0 { value } else { B::from(j) });
            let extension =
                DenseMultilinearExtension::from_evaluations_vec(vars, vec![ext_value; 1 << vars]);
            let (root, state) = PCS::commit(&pp, &base);
            let (eroot, estate) = PCS::commit_ef(&pp, &extension);
            for extension_mode in [false, true] {
                let (c, s) = if extension_mode {
                    (&eroot, &estate)
                } else {
                    (&root, &state)
                };
                let mut t = Transcript::new_direct_extension::<B>();
                let (y, p) = if extension_mode {
                    PCS::try_open_at_ef(&pp, c, s, &point, &mut t)
                } else {
                    PCS::try_open_at(&pp, c, s, &point, &mut t)
                }
                .unwrap();
                assert_eq!(
                    y,
                    if extension_mode {
                        extension.evaluate(&point)
                    } else {
                        base.evaluate_ext(&point)
                    }
                );
                let independently_evaluated = if extension_mode {
                    extension.evaluate(&point)
                } else {
                    base.evaluate_ext(&point)
                };
                exercised_distinct_encoding |=
                    bincode::serde::encode_to_vec(&y, bincode::config::standard()).unwrap()
                        != bincode::serde::encode_to_vec(
                            &independently_evaluated,
                            bincode::config::standard(),
                        )
                        .unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&(y, p), bincode::config::standard()).unwrap();
                let ((y, p), used): ((EF, pcs::pipfri::masked::Proof<EF, [u8; 32]>), usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut v = Transcript::new_direct_extension::<B>();
                assert!(if extension_mode {
                    PCS::verify_ef(&pp, c, &point, y, &p, &mut v)
                } else {
                    PCS::verify(&pp, c, &point, y, &p, &mut v)
                });
                assert_eq!(
                    t.get_challenge(b"exact value after"),
                    v.get_challenge(b"exact value after")
                );
                assert_eq!(s.remaining_openings().unwrap(), 1);
                // Existing proof-only APIs retain the same value and transcript contract.
                let mut t = Transcript::new_direct_extension::<B>();
                let p = if extension_mode {
                    PCS::try_open_ef(&pp, c, s, &point, &mut t)
                } else {
                    PCS::try_open(&pp, c, s, &point, &mut t)
                }
                .unwrap();
                let mut v = Transcript::new_direct_extension::<B>();
                assert!(if extension_mode {
                    PCS::verify_ef(&pp, c, &point, y, &p, &mut v)
                } else {
                    PCS::verify(&pp, c, &point, y, &p, &mut v)
                });
                assert_eq!(
                    t.get_challenge(b"legacy method after"),
                    v.get_challenge(b"legacy method after")
                );
                assert_eq!(s.remaining_openings().unwrap(), 0);
            }
        }
    }
    assert!(
        exercised_distinct_encoding,
        "fixture must exercise field-equal, byte-distinct evaluations"
    );
}
