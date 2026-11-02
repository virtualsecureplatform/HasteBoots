use algebra::{AbstractExtensionField, AsInto, Field, NTTField};
use pcs::matrix_weighted::{
    backend::CanonicalPcs,
    polyfrim::{self, Parameters, Proof},
};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use snarks::{
    packed_key_switch::canonical::protocol as ks,
    packed_pbs as pbs,
    packed_pbs::{canonical::shared as canonical, canonical_setup},
};
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
#[path = "common/canonical_pbs.rs"]
mod native_fixture;
use native_fixture::secret;

fn parameters<'a, P>(
    codes: &'a [P],
    helper: &'a P,
    final_helper: &'a P,
) -> canonical::Parameters<'a, P> {
    canonical::Parameters {
        coefficients: &codes[0],
        evaluations: &codes[0],
        key: &codes[0],
        inputs: &codes[0],
        borrows: &codes[0],
        helper,
        accumulators: [&codes[0]; 4],
        monomial: &codes[0],
        final_stage: ks::Parameters {
            coefficients: &codes[2],
            evaluations: &codes[2],
            key: &codes[2],
            input: &codes[2],
            borrows: &codes[2],
            helper: final_helper,
        },
    }
}

fn truth_table_geometry<F, E, P>(
    width: usize,
    helper_width: usize,
    backend: &str,
    make: impl Fn(usize, usize) -> P,
    tamper: impl Fn(&mut P::SingleProof),
) where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256>,
    P::SingleProof: Clone + DeserializeOwned,
    P::BatchProof: Clone + DeserializeOwned,
{
    let cfg = pbs::Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
    let dims = cfg.variables(width).unwrap();
    let codes: Vec<_> = dims
        .into_iter()
        .enumerate()
        .map(|(role, n)| make(n, if role % 2 == 1 { helper_width } else { width }))
        .collect();
    let pp = parameters(&codes, &codes[1], &codes[3]);
    let sk = secret::<F>(42);
    let enc = Encryptor::new(sk.clone());
    let dec = Decryptor::new(sk.clone());
    let evaluator =
        Evaluator::from_public_evaluation_key(Evaluator::new(&sk).public_evaluation_key());
    let setup = canonical_setup::preprocess::<F, Sha256, _, _>(
        &canonical_setup::Parameters {
            source: &codes[0],
            helper: &codes[1],
            final_source: &codes[2],
            final_helper: &codes[3],
        },
        cfg,
        evaluator.binary_bootstrap_key().unwrap(),
        evaluator.rlwe_key_switching_key().unwrap().as_slice(),
        &mut StdRng::seed_from_u64(948),
    )
    .unwrap();
    let expected = setup.verifier();
    for left in 0usize..2 {
        for right in 0usize..2 {
            let x = enc.encrypt(left.as_into());
            let y = enc.encrypt(right.as_into());
            let (out, trace) = evaluator.nand(&x, &y);
            let expected_plain: <F as Field>::Value = (1 - left * right).as_into();
            assert_eq!(dec.decrypt_with_noise(&out).0, expected_plain);
            let statement = pbs::Statement {
                left_a: x.a(),
                left_b: x.b(),
                right_a: y.a(),
                right_b: y.b(),
                output_a: out.a(),
                output_b: out.b(),
            };
            let proof = canonical::prove::<F, E, Sha256, _, _>(
                &pp,
                &setup,
                &statement,
                &trace,
                &mut StdRng::seed_from_u64(949),
            )
            .unwrap();
            drop(trace);
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (
                canonical::Proof<F, E, [u8; 32], P::SingleProof, P::BatchProof>,
                usize,
            ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            canonical::verify::<F, E, Sha256, _>(&pp, &expected, &statement, &proof).unwrap();
            let other_width = if helper_width == width { E::D } else { width };
            let other_helper = make(dims[1], other_width);
            let other_final_helper = make(dims[3], other_width);
            let other_pp = parameters(&codes, &other_helper, &other_final_helper);
            assert!(
                canonical::verify::<F, E, Sha256, _>(&other_pp, &expected, &statement, &proof)
                    .is_err()
            );
            let invalid_helper = make(dims[1], E::D - 1);
            let invalid_pp = parameters(&codes, &invalid_helper, &codes[3]);
            assert!(
                canonical::verify::<F, E, Sha256, _>(&invalid_pp, &expected, &statement, &proof)
                    .is_err()
            );
            assert_eq!(proof.protocol_version, 11);
            let reject = |p: &canonical::Proof<F, E, [u8; 32], P::SingleProof, P::BatchProof>| {
                canonical::verify::<F, E, Sha256, _>(&pp, &expected, &statement, p).is_err()
            };
            let mut bad = proof.clone();
            bad.protocol_version = 10;
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.ntt.pop();
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.decomposition.pop();
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.accumulators.pop();
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.hadamard.values[0][0] += F::from(1usize);
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.key_switch.input.root[0] ^= 1;
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.key_switch.extraction.value[0] += F::from(1usize);
            assert!(reject(&bad));
            let mut bad = proof.clone();
            bad.decomposition[0].comparisons.helper_values[0] +=
                <E as algebra::AbstractExtensionField<F>>::from_base(F::from(1usize));
            assert!(reject(&bad));
            let mut bad = proof.clone();
            tamper(&mut bad.hadamard.openings[0]);
            assert!(reject(&bad));
            let mut changed = statement.clone();
            changed.output_b += F::from(1usize);
            assert!(
                canonical::verify::<F, E, Sha256, _>(&pp, &expected, &changed, &proof).is_err()
            );
            let mut changed = statement.clone();
            changed.left_b += F::from(1usize);
            assert!(
                canonical::verify::<F, E, Sha256, _>(&pp, &expected, &changed, &proof).is_err()
            );

            println!(
                "HB_CANONICAL_SHARED_PBS_TRUTH_TABLE {{\"protocol_version\":11,\"prime\":{},\"left\":{},\"right\":{},\"output\":{},\"backend\":\"{}\",\"complete_pbs\":true,\"original_size\":false,\"whole_security_certified\":false}}",
                F::MODULUS_VALUE,
                left,
                right,
                1 - left * right,
                backend
            );
        }
    }
}

fn truth_table<F, E, P>(
    width: usize,
    backend: &str,
    make: impl Fn(usize, usize) -> P,
    tamper: impl Fn(&mut P::SingleProof),
) where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    P: CanonicalPcs<F, Sha256>,
    P::SingleProof: Clone + DeserializeOwned,
    P::BatchProof: Clone + DeserializeOwned,
{
    truth_table_geometry::<F, E, P>(width, width, backend, make, tamper)
}

#[test]
fn babybear_all_nand_inputs() {
    type F = algebra::BabyBear;
    type E = algebra::BabyBearExtension6;
    truth_table::<F, E, _>(
        8,
        "unmasked-polyfrim",
        |n, w| Parameters::<F, E>::new(n, w, 2, 8).unwrap(),
        |p: &mut Proof<E, [u8; 32]>| p.packed[0][0][0].path[0][0] ^= 1,
    );
}
#[test]
fn goldilocks_all_nand_inputs() {
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    truth_table::<F, E, _>(
        4,
        "unmasked-polyfrim",
        |n, w| Parameters::<F, E>::new(n, w, 2, 8).unwrap(),
        |p: &mut Proof<E, [u8; 32]>| p.packed[0][0][0].path[0][0] ^= 1,
    );
}
#[test]
fn babybear_compact_all_nand_inputs() {
    type F = algebra::BabyBear;
    type E = algebra::BabyBearExtension6;
    truth_table::<F, E, _>(
        8,
        "unmasked-polyfrim-compact",
        |n, w| polyfrim::compact::Parameters::<F, E>::new(n, w, 2, 8).unwrap(),
        |p: &mut polyfrim::compact::Proof<E, [u8; 32]>| p.hashes[0][0] ^= 1,
    );
}
#[test]
fn goldilocks_compact_all_nand_inputs() {
    type F = algebra::Goldilocks;
    type E = algebra::GoldilocksExtension3;
    truth_table::<F, E, _>(
        4,
        "unmasked-polyfrim-compact",
        |n, w| polyfrim::compact::Parameters::<F, E>::new(n, w, 2, 8).unwrap(),
        |p: &mut polyfrim::compact::Proof<E, [u8; 32]>| p.hashes[0][0] ^= 1,
    );
}

fn basis_helpers<F, E>(width: usize)
where
    F: NTTField + Serialize + DeserializeOwned,
    E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
{
    use pcs::{
        matrix_weighted::{Opening, Parameters as Brakedown},
        utils::code::BlockReedSolomonCode,
    };
    truth_table_geometry::<F, E, _>(
        width,
        E::D,
        "brakedown-basis-helpers",
        |n, w| {
            let old =
                Brakedown::<BlockReedSolomonCode<F>>::balanced_block_rs(n, width, 8, 2).unwrap();
            Brakedown::new_encoded::<F>(n, w, old.left_vars(), 8, old.code().clone()).unwrap()
        },
        |p: &mut Opening<F, [u8; 32]>| p.columns[0].path[0][0] ^= 1,
    );
}
#[test]
fn babybear_basis_helpers_all_nand_inputs() {
    basis_helpers::<algebra::BabyBear, algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_basis_helpers_all_nand_inputs() {
    basis_helpers::<algebra::Goldilocks, algebra::GoldilocksExtension3>(4);
}
