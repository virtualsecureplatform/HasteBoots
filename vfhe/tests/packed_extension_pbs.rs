use algebra::{
    AsInto, BabyBear, BabyBearExtension5, Field, Goldilocks, GoldilocksExtension5, NTTField,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use rand::SeedableRng;
use sha2::Sha256;
use snarks::packed_pbs as pbs;
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
fn params<F: NTTField>() -> FheParameters<F> {
    FheParameters::new(ConstParameters {
        lwe_dimension: 21,
        lwe_plain_modulus: 4usize.as_into(),
        lwe_noise_standard_deviation: 1.0,
        lwe_secret_key_type: LWESecretKeyType::Binary,
        ring_dimension: 32,
        ring_modulus: F::MODULUS_VALUE,
        ring_noise_standard_deviation: 1.0,
        ring_secret_key_type: RingSecretKeyType::Ternary,
        blind_rotation_basis_bits: 8,
        key_switching_basis_bits: 5,
        key_switching_standard_deviation: 1.0,
    })
    .unwrap()
}
fn secret<F: NTTField>(seed: u64) -> SecretKeyPack<F> {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    SecretKeyPack::with_rng(params::<F>(), Prg::from_seed(Block::from(bytes)))
}
macro_rules! native_extension_roundtrip {
    ($test:ident,$field:ty,$extension:ty) => {
        native_extension_roundtrip!($test, $field, $extension, 8);
    };
    ($test:ident,$field:ty,$extension:ty,$width:expr) => {
        native_extension_roundtrip!($test, $field, $extension, $width, 0);
    };
    ($test:ident,$field:ty,$extension:ty,$width:expr,$helper_extra:expr) => {
        native_extension_roundtrip!($test,$field,$extension,$width,$helper_extra,
            prove_extension,verify_extension,ExtensionProof,pbs::EXTENSION_PROTOCOL_VERSION);
    };
    ($test:ident,$field:ty,$extension:ty,$width:expr,$helper_extra:expr,
        $prove:ident,$verify:ident,$proof_type:ident,$version:expr) => {
        #[test]
        fn $test() {
            type F = $field;
            type EF = $extension;
            let cfg = pbs::Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
            let dims = cfg.variables($width).unwrap();
            let codes: [_; 4] = std::array::from_fn(|role| {
                let n = dims[role];
                let balanced = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n, $width, 32, 2).unwrap();
                if role % 2 == 0 || $helper_extra == 0 {
                    balanced
                } else {
                    let left = balanced.left_vars() + $helper_extra;
                    let code = BlockReedSolomonCode::<F>::new(1usize << (n-left), $width, 2).unwrap();
                    Parameters::new_encoded::<F>(n, $width, left, 32, code).unwrap()
                }
            });
            let pp = pbs::Parameters {
                source: &codes[0],
                helper: &codes[1],
                final_source: &codes[2],
                final_helper: &codes[3],
            };
            let sk = secret::<F>(42);
            let enc = Encryptor::new(sk.clone());
            let dec = Decryptor::new(sk.clone());
            let evaluator = Evaluator::new(&sk);
            let setup = pbs::preprocess::<F, Sha256, _>(
                &pp,
                cfg.clone(),
                evaluator.binary_bootstrap_key().unwrap(),
                evaluator.rlwe_key_switching_key().unwrap().as_slice(),
            )
            .unwrap();
            let expected = setup.verifier();
            for batch in [1, 4, 16] {
                let mut cases = Vec::new();
                for i in 0..batch {
                    let l = (i & 1) as usize;
                    let r = ((i >> 1) & 1) as usize;
                    let x = enc.encrypt(l.as_into());
                    let y = enc.encrypt(r.as_into());
                    let (out, trace) = evaluator.nand(&x, &y);
                    let expected_plain: <F as Field>::Value = (1 - l * r).as_into();
                    assert_eq!(dec.decrypt_with_noise(&out).0, expected_plain);
                    let statement = pbs::Statement {
                        left_a: x.a(),
                        left_b: x.b(),
                        right_a: y.a(),
                        right_b: y.b(),
                        output_a: out.a(),
                        output_b: out.b(),
                    };
                    let proof =
                        pbs::$prove::<F, EF, Sha256, _>(&pp, &setup, &statement, &trace)
                            .unwrap();
                    assert_eq!(proof.protocol_version, $version);
                    assert!(
                        proof
                            .decomposition
                            .iter()
                            .flat_map(|d| &d.comparisons)
                            .all(|p| p.groups.len() == 1)
                    );
                    assert!(
                        proof
                            .key_switch
                            .decomposition
                            .comparisons
                            .iter()
                            .all(|p| p.groups.len() == 1)
                    );
                    drop(trace);
                    let bytes =
                        bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                    let (proof, used): (pbs::$proof_type<F, EF, [u8; 32]>, _) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                            .unwrap();
                    assert_eq!(used, bytes.len());
                    pbs::$verify::<F, EF, Sha256, _>(&pp, &expected, &statement, &proof)
                        .unwrap();
                    let inventory = snarks::packed_root_inventory::inventory(&proof);
                    let bits = F::MODULUS_VALUE.ilog2() as usize + 1;
                    let d = bits.div_ceil(8);
                    let ks = bits.div_ceil(5);
                    assert_eq!(inventory.categories["decomposition_borrows"], 2 * (d + 1));
                    assert_eq!(inventory.categories["decomposition_reciprocals"], 2 * d);
                    assert_eq!(inventory.categories["key_switch_reciprocals"], ks);
                    assert_eq!(inventory.categories["monomial_evaluations"], 2);
                    assert_eq!(inventory.total(), 6 * d + 3 * ks + 15 + 2 * d + ks);
                    let mut duplicate = proof.clone();
                    duplicate.coefficients.push(duplicate.coefficients[0].clone());
                    assert_eq!(snarks::packed_root_inventory::inventory(&duplicate).total(), inventory.total() + 1);
                    cases.push((x, y, out, proof));
                }
                for (x, y, out, proof) in &cases {
                    let statement = pbs::Statement {
                        left_a: x.a(),
                        left_b: x.b(),
                        right_a: y.a(),
                        right_b: y.b(),
                        output_a: out.a(),
                        output_b: out.b(),
                    };
                    pbs::$verify::<F, EF, Sha256, _>(&pp, &expected, &statement, proof)
                        .unwrap();
                }
                let (x, y, out, proof) = &cases[0];
                let statement = pbs::Statement {
                    left_a: x.a(),
                    left_b: x.b(),
                    right_a: y.a(),
                    right_b: y.b(),
                    output_a: out.a(),
                    output_b: out.b(),
                };
                let reject = |proof: &pbs::$proof_type<F, EF, [u8; 32]>| {
                    pbs::$verify::<F, EF, Sha256, _>(&pp, &expected, &statement, proof)
                        .is_err()
                };
                for version in [1,2,3,4] {
                    if version != $version {
                        let mut bad = proof.clone();
                        bad.protocol_version = version;
                        assert!(reject(&bad));
                    }
                }
                let mut bad = proof.clone();
                bad.final_accumulator[0] += F::from(1usize);
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.final_accumulator[32] += F::from(1usize);
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.accumulators.pop();
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.coefficients.pop();
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.ntt.pop();
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.decomposition.pop();
                assert!(reject(&bad));
                let mut bad = proof.clone();
                bad.key_switch.extraction.value[0] += F::from(1usize);
                assert!(reject(&bad));
                for i in 0..proof.coefficients.len() {
                    let mut bad = proof.clone();
                    bad.coefficients[i].root[0] ^= 1;
                    assert!(reject(&bad));
                    let mut bad = proof.clone();
                    bad.evaluations[i].root[0] ^= 1;
                    assert!(reject(&bad));
                }
                for i in 0..4 {
                    let mut bad = proof.clone();
                    bad.accumulators[i].root[0] ^= 1;
                    assert!(reject(&bad));
                }
                for i in 0..2 {
                    let mut bad = proof.clone();
                    bad.decomposition_inputs[i].root[0] ^= 1;
                    assert!(reject(&bad));
                }
                if batch > 1 {
                    let mut bad = proof.clone();
                    bad.monomial = cases[1].3.monomial.clone();
                    assert!(reject(&bad));
                    let mut bad = proof.clone();
                    bad.key_switch = cases[1].3.key_switch.clone();
                    assert!(reject(&bad));
                }
                let mut wrong = statement.clone();
                wrong.output_b += F::from(1usize);
                assert!(
                    pbs::$verify::<F, EF, Sha256, _>(&pp, &expected, &wrong, proof)
                        .is_err()
                );
            }
            // Fresh valid trace/output, but requested mask differs by one rotation step.
            // Proving actually constructs valid prior child proofs under that requested
            // parent context and then fails the public monomial equation.
            let x = enc.encrypt(1usize.as_into());
            let y = enc.encrypt(1usize.as_into());
            let (out, trace) = evaluator.nand(&x, &y);
            let mut requested = x.a().to_vec();
            requested[0] += F::from((F::MODULUS_VALUE as u128 / 64 + 1) as usize);
            let wrong = pbs::Statement {
                left_a: &requested,
                left_b: x.b(),
                right_a: y.a(),
                right_b: y.b(),
                output_a: out.a(),
                output_b: out.b(),
            };
            assert!(pbs::$prove::<F, EF, Sha256, _>(&pp, &setup, &wrong, &trace).is_err());
            let actual = pbs::Statement {
                left_a: x.a(),
                left_b: x.b(),
                right_a: y.a(),
                right_b: y.b(),
                output_a: out.a(),
                output_b: out.b(),
            };
            let proof =
                pbs::$prove::<F, EF, Sha256, _>(&pp, &setup, &actual, &trace).unwrap();
            let other_sk = secret::<F>(99);
            let other = Evaluator::new(&other_sk);
            for (br, ks) in [
                (
                    other.binary_bootstrap_key().unwrap(),
                    evaluator.rlwe_key_switching_key().unwrap().as_slice(),
                ),
                (
                    evaluator.binary_bootstrap_key().unwrap(),
                    other.rlwe_key_switching_key().unwrap().as_slice(),
                ),
            ] {
                let wrong_key = pbs::preprocess::<F, Sha256, _>(&pp, cfg.clone(), br, ks).unwrap();
                assert!(
                    pbs::$verify::<F, EF, Sha256, _>(
                        &pp,
                        &wrong_key.verifier(),
                        &actual,
                        &proof
                    )
                    .is_err()
                );
                assert!(
                    pbs::$prove::<F, EF, Sha256, _>(&pp, &wrong_key, &actual, &trace)
                        .is_err()
                );
            }
            assert!(pbs::Config::new::<F>(64, 21, 8, 5, 1, 2).is_err());
            assert!(pbs::Config::new::<F>(32, 21, 8, 5, 0, 2).is_err());
        }
    };
}
native_extension_roundtrip!(
    babybear_extension_complete_native_batches_and_binding,
    BabyBear,
    BabyBearExtension5
);
native_extension_roundtrip!(
    goldilocks_extension_complete_native_batches_and_binding,
    Goldilocks,
    GoldilocksExtension5
);

include!("support/packed_pbs_forgery.rs");
complete_foreign_trace_case!(
    complete_extension_foreign_trace_babybear,
    algebra::BabyBear,
    prove_extension,
    verify_extension,
    prove_extension,
    verify_extension,
    snarks::packed_pbs::EXTENSION_PROTOCOL_VERSION,
    b"HasteBoots complete binary NAND PBS extension comparisons v3",
    8,
    1,
    algebra::BabyBearExtension5
);
complete_foreign_trace_case!(
    complete_extension_foreign_trace_goldilocks,
    algebra::Goldilocks,
    prove_extension,
    verify_extension,
    prove_extension,
    verify_extension,
    snarks::packed_pbs::EXTENSION_PROTOCOL_VERSION,
    b"HasteBoots complete binary NAND PBS extension comparisons v3",
    8,
    1,
    algebra::GoldilocksExtension5
);

native_extension_roundtrip!(
    goldilocks_cubic_complete_native_batches_and_binding,
    Goldilocks,
    algebra::GoldilocksExtension3,
    4
);
complete_foreign_trace_case!(
    complete_extension_cubic_foreign_trace_goldilocks,
    algebra::Goldilocks,
    prove_extension,
    verify_extension,
    prove_extension,
    verify_extension,
    snarks::packed_pbs::EXTENSION_PROTOCOL_VERSION,
    b"HasteBoots complete binary NAND PBS extension comparisons v3",
    4,
    1,
    algebra::GoldilocksExtension3
);

native_extension_roundtrip!(
    babybear_degree8_complete_native_batches_and_binding,
    BabyBear,
    algebra::BabyBearExtension8,
    8,
    1
);
complete_foreign_trace_case!(
    complete_extension_degree8_foreign_trace_babybear,
    algebra::BabyBear,
    prove_extension,
    verify_extension,
    prove_extension,
    verify_extension,
    snarks::packed_pbs::EXTENSION_PROTOCOL_VERSION,
    b"HasteBoots complete binary NAND PBS extension comparisons v3",
    8,
    1,
    algebra::BabyBearExtension8
);

native_extension_roundtrip!(
    babybear_degree6_complete_native_batches_and_binding,
    BabyBear,
    algebra::BabyBearExtension6,
    8,
    1
);
complete_foreign_trace_case!(
    complete_extension_degree6_foreign_trace_babybear,
    algebra::BabyBear,
    prove_extension,
    verify_extension,
    prove_extension,
    verify_extension,
    snarks::packed_pbs::EXTENSION_PROTOCOL_VERSION,
    b"HasteBoots complete binary NAND PBS extension comparisons v3",
    8,
    1,
    algebra::BabyBearExtension6
);


native_extension_roundtrip!(babybear_aggregated_complete_batches_and_binding,
    BabyBear,algebra::BabyBearExtension6,8,1,
    prove_aggregated,verify_aggregated,AggregatedProof,pbs::AGGREGATED_PROTOCOL_VERSION);
native_extension_roundtrip!(goldilocks_aggregated_complete_batches_and_binding,
    Goldilocks,algebra::GoldilocksExtension3,4,0,
    prove_aggregated,verify_aggregated,AggregatedProof,pbs::AGGREGATED_PROTOCOL_VERSION);
