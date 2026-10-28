use algebra::{
    AsInto, Field, NTTField,
    utils::{Block, Prg},
};
use fhe_core::{
    ConstParameters, LWESecretKeyType, Parameters as FheParameters, RingSecretKeyType,
    SecretKeyPack,
};
use pcs::{
    matrix_weighted::{BatchOpening, Opening, Parameters},
    utils::code::BlockReedSolomonCode,
};
use rand::{SeedableRng, rngs::StdRng};
use sha2::Sha256;
use snarks::{
    packed_key_switch::canonical::protocol as ks,
    packed_pbs as pbs,
    packed_pbs::{canonical, canonical_setup},
};
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

macro_rules! ordinary_truth_table{
 ($name:ident,$field:ty,$extension:ty,$width:expr)=>{
 #[test]fn $name(){type F=$field;type E=$extension;let width=$width;
 let cfg=pbs::Config::new::<F>(32,21,8,5,1,1).unwrap();let dims=cfg.variables(width).unwrap();let codes:Vec<_>=dims.into_iter().map(|n|Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n,width,32,2).unwrap()).collect();
 let pp=canonical::Parameters{coefficients:&codes[0],evaluations:&codes[0],key:&codes[0],inputs:&codes[0],borrows:&codes[0],helper:&codes[1],accumulators:[&codes[0];4],monomial:&codes[0],final_stage:ks::Parameters{coefficients:&codes[2],evaluations:&codes[2],key:&codes[2],input:&codes[2],borrows:&codes[2],helper:&codes[3]}};
 let sk=secret::<F>(42);let enc=Encryptor::new(sk.clone());let dec=Decryptor::new(sk.clone());let evaluator=Evaluator::new(&sk);let setup=canonical_setup::preprocess::<F,Sha256,_,_>(&canonical_setup::Parameters{source:&codes[0],helper:&codes[1],final_source:&codes[2],final_helper:&codes[3]},cfg,evaluator.binary_bootstrap_key().unwrap(),evaluator.rlwe_key_switching_key().unwrap().as_slice(),&mut StdRng::seed_from_u64(948)).unwrap();let expected=setup.verifier();
 for left in 0usize..2{for right in 0usize..2{
 let x=enc.encrypt(left.as_into());let y=enc.encrypt(right.as_into());let(out,trace)=evaluator.nand(&x,&y);let expected_plain:<F as Field>::Value=(1-left*right).as_into();assert_eq!(dec.decrypt_with_noise(&out).0,expected_plain);let statement=pbs::Statement{left_a:x.a(),left_b:x.b(),right_a:y.a(),right_b:y.b(),output_a:out.a(),output_b:out.b()};let proof=canonical::prove::<F,E,Sha256,_,_>(&pp,&setup,&statement,&trace,&mut StdRng::seed_from_u64(949)).unwrap();drop(trace);let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();let(proof,used):(canonical::Proof<F,E,[u8;32],Opening<F,[u8;32]>,BatchOpening<F,[u8;32]>>,usize)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();assert_eq!(used,bytes.len());canonical::verify::<F,E,Sha256,_>(&pp,&expected,&statement,&proof).unwrap();assert_eq!(proof.protocol_version,10);
 println!("HB_CANONICAL_PBS_TRUTH_TABLE {{\"protocol_version\":10,\"prime\":{},\"left\":{},\"right\":{},\"output\":{},\"backend\":\"brakedown\",\"complete_pbs\":true,\"original_size\":false,\"whole_security_certified\":false}}",F::MODULUS_VALUE,left,right,1-left*right);
 }}
 }
 }
}
ordinary_truth_table!(
    babybear_all_nand_inputs,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8
);
ordinary_truth_table!(
    goldilocks_all_nand_inputs,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4
);
