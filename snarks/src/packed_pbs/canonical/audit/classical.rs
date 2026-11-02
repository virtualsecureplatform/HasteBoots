//! Fresh version-12 certificates. Zero/synthetic public keys isolate individual
//! relations; these tests do not establish native encrypted-profile security.
use super::super::classical as protocol;
use super::*;
use pcs::classical_profile::{Backend, ClassicalProfile, ProfileParameters, Role, Specification};
use sha2::Sha512;

fn exercise_bundle<F, EF, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
    P::SingleProof: DeserializeOwned,
    P::BatchProof: DeserializeOwned,
{
    let pp = protocol::parameters(&bundle);
    for attack in [
        Attack::Control,
        Attack::Initial,
        Attack::Final,
        Attack::Addition,
        Attack::Chain,
        Attack::DigitA,
        Attack::DigitB,
        Attack::Rotation,
        Attack::ExtractionA,
        Attack::ExtractionB,
        Attack::KeyProduct,
        Attack::SwitchKeyProduct,
        Attack::CanonicalA,
        Attack::CanonicalB,
        Attack::SwitchCanonical,
        Attack::LookupA,
        Attack::LookupB,
        Attack::SwitchLookup,
    ] {
        let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
        let mut br = vec![NTTRGSW::<F>::zero(32, Basis::new(8)); 21];
        if attack == Attack::KeyProduct {
            let mut weight = F::one();
            for limb in br[0].c_m_mut().iter_mut() {
                limb.b_mut_slice().fill(weight);
                weight *= F::from(256usize);
            }
        }
        let mut ks = vec![NTTGadgetRLWE::<F>::zero(32, Basis::new(5))];
        if attack == Attack::SwitchKeyProduct {
            let mut weight = F::one();
            for limb in br[0].c_m_mut().iter_mut() {
                limb.a_mut_slice().fill(weight);
                weight *= F::from(256usize);
            }
            let mut weight = F::one();
            for limb in ks[0].iter_mut() {
                limb.b_mut_slice().fill(weight);
                weight *= F::from(32usize);
            }
        }
        let setup = protocol::preprocess::<F, EF, P, _>(
            &bundle,
            cfg,
            &br,
            &ks,
            &mut StdRng::seed_from_u64(2300 + attack as u64),
        )
        .unwrap();
        let (statement, payload, (digest, tail)) =
            make_with_transcript::<F, EF, Sha512, P, stages::ClassicalShared>(
                &pp,
                &setup.inner,
                attack,
                2400 + attack as u64,
                bundle.profile().parent_transcript::<F>().unwrap(),
            );
        let proof = protocol::Proof {
            profile_id: bundle.profile().id(),
            payload,
        };
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (mut decoded, used): (protocol::Proof<F, EF, P::SingleProof, P::BatchProof>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());

        // Continue through all children even when a selected algebraic identity
        // is false. Successful replay proves their actual-root paths check.
        let mut replay = bundle.profile().parent_transcript::<F>().unwrap();
        let report = reference_transcript::<F, EF, Sha512, P, stages::ClassicalShared>(
            &pp,
            &setup.inner.verifier(),
            &statement.borrowed(),
            &decoded.payload,
            &mut replay,
        )
        .unwrap();
        assert_eq!(
            report.decomposition[0],
            [true, true, attack != Attack::CanonicalA]
        );
        assert_eq!(
            report.decomposition[1],
            [true, true, attack != Attack::CanonicalB]
        );
        assert_eq!(
            report.switch_decomposition,
            [true, true, attack != Attack::SwitchCanonical]
        );
        assert_eq!(
            report.lookups,
            [attack != Attack::LookupA, attack != Attack::LookupB]
        );
        assert_eq!(report.switch_lookup, attack != Attack::SwitchLookup);
        assert_eq!(report.key_product, attack != Attack::KeyProduct);
        assert_eq!(
            report.switch_key_product,
            attack != Attack::SwitchKeyProduct
        );
        assert_eq!(report.accumulator, attack.accumulator_valid());
        assert_eq!(report.monomial, attack.monomial_valid());
        assert_eq!(report.extraction, attack.extraction_valid());
        assert_eq!(
            digest,
            replay.get_challenge(b"fresh complete canonical certificate after")
        );
        let mut replay_tail = [0; 32];
        replay.get_challenge_bytes(
            b"fresh complete canonical certificate bytes after",
            &mut replay_tail,
        );
        assert_eq!(tail, replay_tail);

        let expected = setup.verifier();
        let result =
            protocol::verify::<F, EF, P>(&bundle, &expected, &statement.borrowed(), &decoded);
        if attack == Attack::Control {
            result.unwrap();
            decoded.payload.protocol_version = 11;
            assert!(
                protocol::verify::<F, EF, P>(&bundle, &expected, &statement.borrowed(), &decoded,)
                    .is_err()
            );
        } else {
            let err = result.unwrap_err();
            let label = match attack {
                Attack::CanonicalA | Attack::CanonicalB | Attack::SwitchCanonical => {
                    "false canonical linear identity"
                }
                Attack::LookupA | Attack::LookupB | Attack::SwitchLookup => {
                    "terminal reciprocal identity"
                }
                Attack::KeyProduct
                | Attack::SwitchKeyProduct
                | Attack::ExtractionA
                | Attack::ExtractionB => "packed ZeroCheck terminal identity",
                Attack::Rotation => "packed public monomial product",
                _ => "packed accumulator linkage",
            };
            assert!(err.0.contains(label), "{attack:?}: {err}");
        }
        println!(
            "classical_fresh_binding prime={} backend={:?} attack={attack:?} bytes={} accepted={}",
            F::MODULUS_VALUE,
            bundle.profile().specification().backend,
            bytes.len(),
            attack == Attack::Control
        );
    }
}

fn exercise<F, EF>(width: usize, schedule: u32)
where
    F: NTTField + Serialize + DeserializeOwned,
    EF: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::classical_profile::Backend::*;
    for backend in [
        Brakedown,
        Polyfrim,
        FragmentedPipfri,
        PolyfrimDictionary,
        FragmentedPipfriVirtual,
    ] {
        let cfg = Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
        let roles = cfg.variables(width).unwrap().map(|num_vars| Role {
            num_vars,
            width,
            queries: 8,
            left_vars: (backend == Brakedown).then_some(num_vars / 2),
            block_width: (backend == Brakedown).then_some(width),
        });
        let specification = Specification {
            backend,
            roles,
            blowup: 2,
            fragment_vars: matches!(backend, FragmentedPipfri | FragmentedPipfriVirtual)
                .then_some(4),
        };
        let profile = match schedule {
            1 => ClassicalProfile::new::<F, EF>(specification),
            2 => ClassicalProfile::new_atomic_ntt::<F, EF>(specification),
            3 => ClassicalProfile::new_atomic_phases::<F, EF>(specification),
            4 => ClassicalProfile::new_atomic_zerocheck::<F, EF>(specification),
            5 => ClassicalProfile::new_atomic_columns::<F, EF>(specification),
            _ => panic!("unsupported test schedule"),
        }
        .unwrap();
        match backend {
            Backend::FragmentedPipfriVirtual => exercise_bundle::<F, EF, _>(
                profile.fragmented_virtual_parameters::<F, EF>().unwrap(),
            ),
            Backend::PolyfrimDictionary => exercise_bundle::<F, EF, _>(
                profile.polyfrim_dictionary_parameters::<F, EF>().unwrap(),
            ),
            Backend::Brakedown => {
                exercise_bundle::<F, EF, _>(profile.brakedown_parameters::<F, EF>().unwrap())
            }
            Backend::Polyfrim => {
                exercise_bundle::<F, EF, _>(profile.polyfrim_parameters::<F, EF>().unwrap())
            }
            Backend::FragmentedPipfri => {
                exercise_bundle::<F, EF, _>(profile.fragmented_parameters::<F, EF>().unwrap())
            }
        }
    }
}

#[test]
#[ignore = "manual complete fresh-certificate audit across five encoding variants"]
fn babybear_classical_fresh_binding() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 1);
}
#[test]
#[ignore = "manual complete fresh-certificate audit for atomic column profiles"]
fn babybear_atomic_columns_fresh_binding() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 5);
}
#[test]
#[ignore = "manual complete fresh-certificate audit for atomic column profiles"]
fn goldilocks_atomic_columns_fresh_binding() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 5);
}
#[test]
#[ignore = "manual complete fresh-certificate audit across five encoding variants"]
fn goldilocks_classical_fresh_binding() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 1);
}

#[test]
#[ignore = "manual complete fresh-certificate audit for atomic NTT profiles"]
fn babybear_atomic_ntt_fresh_binding() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 2);
}
#[test]
#[ignore = "manual complete fresh-certificate audit for atomic NTT profiles"]
fn goldilocks_atomic_ntt_fresh_binding() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 2);
}

#[test]
#[ignore = "manual complete fresh-certificate audit for atomic phase profiles"]
fn babybear_atomic_phases_fresh_binding() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 3);
}
#[test]
#[ignore = "manual complete fresh-certificate audit for atomic phase profiles"]
fn goldilocks_atomic_phases_fresh_binding() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 3);
}

#[test]
#[ignore = "manual complete fresh-certificate audit for atomic zerocheck profiles"]
fn babybear_atomic_zerocheck_fresh_binding() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 4);
}

#[test]
#[ignore = "manual complete fresh-certificate audit for atomic zerocheck profiles"]
fn goldilocks_atomic_zerocheck_fresh_binding() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 4);
}
