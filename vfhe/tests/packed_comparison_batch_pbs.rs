use algebra::{
    AsInto, Field, NTTField,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use rand::SeedableRng;
use sha2::Sha256;
use snarks::packed_pbs::{self as pbs, batch::shared as batch};
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
macro_rules! exercise {
    ($test:ident,$field:ty,$ef:ty,$width:expr,$extra:expr) => {
        #[test]
        fn $test() {
            type F = $field;
            type EF = $ef;
            let cfg = pbs::Config::new::<F>(32, 21, 8, 5, 1, 1).unwrap();
            let dims = cfg.variables($width).unwrap();
            let codes: [_; 4] = std::array::from_fn(|role| {
                let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(
                    dims[role], $width, 32, 2,
                )
                .unwrap();
                if role % 2 == 0 || $extra == 0 {
                    pp
                } else {
                    let left = pp.left_vars() + $extra;
                    Parameters::new_encoded::<F>(
                        dims[role],
                        $width,
                        left,
                        32,
                        BlockReedSolomonCode::<F>::new(1 << (dims[role] - left), $width, 2)
                            .unwrap(),
                    )
                    .unwrap()
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
            let eval = Evaluator::new(&sk);
            let setup = pbs::preprocess::<F, Sha256, _>(
                &pp,
                cfg.clone(),
                eval.binary_bootstrap_key().unwrap(),
                eval.rlwe_key_switching_key().unwrap().as_slice(),
            )
            .unwrap();
            let public = setup.verifier();
            for count in [1usize, 4, 5, 16] {
                let cases: Vec<_> = (0..count)
                    .map(|i| {
                        let l = i & 1;
                        let r = (i >> 1) & 1;
                        let x = enc.encrypt(l.as_into());
                        let y = enc.encrypt(r.as_into());
                        let (out, trace) = eval.nand(&x, &y);
                        let expected: <F as Field>::Value = (1 - l * r).as_into();
                        assert_eq!(dec.decrypt_with_noise(&out).0, expected);
                        (x, y, out, trace)
                    })
                    .collect();
                let statements: Vec<_> = cases
                    .iter()
                    .map(|(x, y, out, _)| pbs::Statement {
                        left_a: x.a(),
                        left_b: x.b(),
                        right_a: y.a(),
                        right_b: y.b(),
                        output_a: out.a(),
                        output_b: out.b(),
                    })
                    .collect();
                let traces: Vec<_> = cases.iter().map(|(_, _, _, trace)| trace).collect();
                let proof =
                    batch::prove::<F, EF, Sha256, _>(&pp, &setup, &statements, &traces).unwrap();
                assert_eq!(proof.protocol_version, 9);
                assert_eq!(proof.members.len(), count);
                assert_eq!(proof.hadamard.zero.instances.len(), count);
                assert_eq!(proof.blind_rotation.len(), (2usize * count).div_ceil(4));
                assert_eq!(proof.key_switch.len(), count.div_ceil(4));
                for member in &proof.members {
                    assert_eq!(member.protocol_version, 9);
                    assert!(
                        member
                            .decomposition
                            .iter()
                            .all(|d| d.comparisons.len() == 1)
                    );
                    assert_eq!(member.key_switch.decomposition.comparisons.len(), 1);
                }
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, used): (batch::Proof<F, EF, [u8; 32]>, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                batch::verify::<F, EF, Sha256, _>(&pp, &public, &statements, &proof).unwrap();
                let reject = |statements: &[_], proof: &_| {
                    assert!(
                        batch::verify::<F, EF, Sha256, _>(&pp, &public, statements, proof).is_err()
                    )
                };
                let mut bad = proof.clone();
                bad.blind_rotation.pop();
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.key_switch.pop();
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.blind_rotation[0].source_values[0][0] += F::from(1usize);
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.key_switch[0].source_values[0][0] += F::from(1usize);
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.protocol_version = 5;
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.members[count - 1].protocol_version = 5;
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.members.pop();
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.hadamard.zero.instances.pop();
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.hadamard.opening.opening.columns.pop();
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.hadamard.values[count - 1][0][0] += F::from(1usize);
                reject(&statements, &bad);
                // Keep the local terminal Hadamard equation valid, but falsify
                // two canonical root claims. Authentication must still reject.
                let mut bad = proof.clone();
                let values = &mut bad.hadamard.values[count - 1];
                let b = values[1][0];
                values[0][0] += F::from(1usize);
                let last = values.len() - 1;
                values[last][0] += b;
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.members[count - 1].key_switch.extraction.value[0] += F::from(1usize);
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.members[count - 1].final_accumulator[0] += F::from(1usize);
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.members[count - 1].decomposition[0].comparisons.clear();
                reject(&statements, &bad);
                let mut bad = proof.clone();
                bad.members[count - 1].evaluations[0].root[0] ^= 1;
                reject(&statements, &bad);
                let mut wrong = statements.clone();
                wrong[count - 1].output_b += F::from(1usize);
                reject(&wrong, &proof);
                assert!(batch::prove::<F, EF, Sha256, _>(&pp, &setup, &wrong, &traces).is_err());
                assert!(
                    batch::prove::<F, EF, Sha256, _>(
                        &pp,
                        &setup,
                        &statements,
                        &traces[..count - 1]
                    )
                    .is_err()
                );
                reject(&[], &proof);
                if proof.blind_rotation.len() > 1 {
                    let mut bad = proof.clone();
                    bad.blind_rotation.swap(0, 1);
                    reject(&statements, &bad);
                }
                if proof.key_switch.len() > 1 {
                    let mut bad = proof.clone();
                    bad.key_switch.swap(0, 1);
                    reject(&statements, &bad);
                }
                if count > 1 {
                    let mut bad = proof.clone();
                    bad.members.swap(0, 1);
                    reject(&statements, &bad);
                    let mut bad = proof.clone();
                    bad.hadamard.values.swap(0, 1);
                    reject(&statements, &bad);
                    let mut bad = proof.clone();
                    bad.hadamard.zero.instances.swap(0, 1);
                    reject(&statements, &bad);
                    let mut reordered = statements.clone();
                    reordered.swap(0, 1);
                    let mut bad = proof.clone();
                    bad.members.swap(0, 1);
                    reject(&reordered, &bad);
                }
                if count == 1 {
                    let other_sk = secret::<F>(99);
                    let other = Evaluator::new(&other_sk);
                    for (br, ks) in [
                        (
                            other.binary_bootstrap_key().unwrap(),
                            eval.rlwe_key_switching_key().unwrap().as_slice(),
                        ),
                        (
                            eval.binary_bootstrap_key().unwrap(),
                            other.rlwe_key_switching_key().unwrap().as_slice(),
                        ),
                    ] {
                        let other_setup =
                            pbs::preprocess::<F, Sha256, _>(&pp, cfg.clone(), br, ks).unwrap();
                        assert!(
                            batch::verify::<F, EF, Sha256, _>(
                                &pp,
                                &other_setup.verifier(),
                                &statements,
                                &proof
                            )
                            .is_err()
                        );
                        assert!(
                            batch::prove::<F, EF, Sha256, _>(
                                &pp,
                                &other_setup,
                                &statements,
                                &traces
                            )
                            .is_err()
                        );
                    }
                }
            }
        }
    };
}
exercise!(
    babybear_complete_joint_batches,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    1
);
exercise!(
    goldilocks_complete_joint_batches,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    0
);
