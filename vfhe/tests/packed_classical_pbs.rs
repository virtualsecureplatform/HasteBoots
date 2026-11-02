use algebra::{AbstractExtensionField, AsInto, Field, NTTField};
use pcs::{
    classical_profile::{Backend, ClassicalProfile, ProfileParameters, Role, Specification},
    matrix_weighted::backend::CanonicalPcs,
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha512;
use snarks::packed_pbs::{self as pbs, canonical::classical};
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
#[path = "common/canonical_pbs.rs"]
mod fixture;

fn run<F, E, P>(bundle: ProfileParameters<P>)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha512>,
    P::SingleProof: DeserializeOwned,
    P::BatchProof: DeserializeOwned,
{
    let cfg = pbs::Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let sk = fixture::secret::<F>(42);
    let encryptor = Encryptor::new(sk.clone());
    let decryptor = Decryptor::new(sk.clone());
    let evaluator =
        Evaluator::from_public_evaluation_key(Evaluator::new(&sk).public_evaluation_key());
    let setup = classical::preprocess::<F, E, P, _>(
        &bundle,
        cfg,
        evaluator.binary_bootstrap_key().unwrap(),
        evaluator.rlwe_key_switching_key().unwrap().as_slice(),
        &mut StdRng::seed_from_u64(94),
    )
    .unwrap();
    let expected = setup.verifier();
    for (left, right) in [(0usize, 0usize), (0, 1), (1, 0), (1, 1)] {
        let x = encryptor.encrypt(left.as_into());
        let y = encryptor.encrypt(right.as_into());
        let (out, trace) = evaluator.nand(&x, &y);
        let value: <F as Field>::Value = (1 - left * right).as_into();
        assert_eq!(decryptor.decrypt_with_noise(&out).0, value);
        let statement = pbs::Statement {
            left_a: x.a(),
            left_b: x.b(),
            right_a: y.a(),
            right_b: y.b(),
            output_a: out.a(),
            output_b: out.b(),
        };
        let proof = classical::prove::<F, E, P, _>(
            &bundle,
            &setup,
            &statement,
            &trace,
            &mut StdRng::seed_from_u64(95),
        )
        .unwrap();
        drop(trace);
        let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (decoded, used): (classical::Proof<F, E, P::SingleProof, P::BatchProof>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        classical::verify::<F, E, P>(&bundle, &expected, &statement, &decoded).unwrap();
        let mut bad = bytes;
        bad[0] ^= 1;
        let (bad, _): (classical::Proof<F, E, P::SingleProof, P::BatchProof>, usize) =
            bincode::serde::decode_from_slice(&bad, bincode::config::standard()).unwrap();
        assert!(classical::verify::<F, E, P>(&bundle, &expected, &statement, &bad).is_err());
    }
}
fn exercise<F, E>(width: usize, schedule: u32)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    let cfg = pbs::Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    for backend in [
        Backend::Brakedown,
        Backend::Polyfrim,
        Backend::FragmentedPipfri,
        Backend::PolyfrimDictionary,
        Backend::FragmentedPipfriVirtual,
    ] {
        let roles = cfg.variables(width).unwrap().map(|num_vars| Role {
            num_vars,
            width,
            queries: 1,
            left_vars: if backend == Backend::Brakedown {
                Some(num_vars / 2)
            } else {
                None
            },
            block_width: if backend == Backend::Brakedown {
                Some(width)
            } else {
                None
            },
        });
        let specification = Specification {
            backend,
            roles,
            blowup: 2,
            fragment_vars: matches!(
                backend,
                Backend::FragmentedPipfri | Backend::FragmentedPipfriVirtual
            )
            .then_some(4),
        };
        let profile = match schedule {
            1 => ClassicalProfile::new::<F, E>(specification),
            2 => ClassicalProfile::new_atomic_ntt::<F, E>(specification),
            3 => ClassicalProfile::new_atomic_phases::<F, E>(specification),
            4 => ClassicalProfile::new_atomic_zerocheck::<F, E>(specification),
            _ => panic!("unsupported test schedule"),
        }
        .unwrap();
        match backend {
            Backend::FragmentedPipfriVirtual => {
                run::<F, E, _>(profile.fragmented_virtual_parameters::<F, E>().unwrap())
            }
            Backend::Brakedown => run::<F, E, _>(profile.brakedown_parameters::<F, E>().unwrap()),
            Backend::Polyfrim => run::<F, E, _>(profile.polyfrim_parameters::<F, E>().unwrap()),
            Backend::PolyfrimDictionary => {
                run::<F, E, _>(profile.polyfrim_dictionary_parameters::<F, E>().unwrap())
            }
            Backend::FragmentedPipfri => {
                run::<F, E, _>(profile.fragmented_parameters::<F, E>().unwrap())
            }
        }
    }
}
#[test]
fn babybear_classical_complete_truth_tables() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 1);
}
#[test]
fn goldilocks_classical_complete_truth_tables() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 1);
}

#[test]
fn babybear_atomic_ntt_complete_truth_tables() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 2);
}
#[test]
fn goldilocks_atomic_ntt_complete_truth_tables() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 2);
}

#[test]
fn babybear_atomic_phases_complete_truth_tables() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 3);
}
#[test]
fn goldilocks_atomic_phases_complete_truth_tables() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 3);
}

#[test]
fn babybear_atomic_zerocheck_complete_truth_tables() {
    exercise::<algebra::BabyBear, algebra::BabyBearExtension6>(8, 4);
}

#[test]
fn goldilocks_atomic_zerocheck_complete_truth_tables() {
    exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4, 4);
}
