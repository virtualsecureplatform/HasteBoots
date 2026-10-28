//! Frozen complete version-10 certificates before shared-stage dispatch.
#[path = "common/canonical_pbs.rs"]
mod native_fixture;
use algebra::{AsInto, Field};
use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
use rand::{SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use snarks::{
    packed_key_switch::canonical::protocol as ks,
    packed_pbs as pbs,
    packed_pbs::{canonical, canonical_setup},
};
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
macro_rules! wire {
 ($name:ident,$field:ty,$extension:ty,$width:expr,$hash:expr,$bytes:expr)=>{
 #[test]fn $name(){type F=$field;type E=$extension;let width=$width;
 let cfg=pbs::Config::new::<F>(32,21,8,5,1,1).unwrap();let dims=cfg.variables(width).unwrap();
 let codes:Vec<_>=dims.into_iter().map(|n|Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n,width,32,2).unwrap()).collect();
 let pp=canonical::Parameters{coefficients:&codes[0],evaluations:&codes[0],key:&codes[0],inputs:&codes[0],borrows:&codes[0],helper:&codes[1],accumulators:[&codes[0];4],monomial:&codes[0],final_stage:ks::Parameters{coefficients:&codes[2],evaluations:&codes[2],key:&codes[2],input:&codes[2],borrows:&codes[2],helper:&codes[3]}};
 let sk=native_fixture::secret::<F>(42);let enc=Encryptor::new(sk.clone());let dec=Decryptor::new(sk.clone());let eval=Evaluator::new(&sk);
 let setup=canonical_setup::preprocess::<F,Sha256,_,_>(&canonical_setup::Parameters{source:&codes[0],helper:&codes[1],final_source:&codes[2],final_helper:&codes[3]},cfg,eval.binary_bootstrap_key().unwrap(),eval.rlwe_key_switching_key().unwrap().as_slice(),&mut StdRng::seed_from_u64(2901)).unwrap();
 let x=enc.encrypt(1usize.as_into());let y=enc.encrypt(1usize.as_into());let(out,trace)=eval.nand(&x,&y);assert_eq!(dec.decrypt_with_noise(&out).0,0usize.as_into());
 let s=pbs::Statement{left_a:x.a(),left_b:x.b(),right_a:y.a(),right_b:y.b(),output_a:out.a(),output_b:out.b()};
 let proof=canonical::prove::<F,E,Sha256,_,_>(&pp,&setup,&s,&trace,&mut StdRng::seed_from_u64(2902)).unwrap();canonical::verify::<F,E,Sha256,_>(&pp,&setup.verifier(),&s,&proof).unwrap();
 let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
 assert_eq!(format!("{:x}",Sha256::digest(&bytes)),$hash);assert_eq!(bytes.len(),$bytes);
 println!("HB_CANONICAL_PBS_WIRE {{\"protocol_version\":10,\"prime\":{},\"bytes\":{},\"sha256\":\"{:x}\"}}",F::MODULUS_VALUE,bytes.len(),Sha256::digest(&bytes));
 }
 };
}
wire!(
    babybear,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8,
    "baedda5c827820f12e7dee25663397aa938bd84ec6e1748ded23472d8d1771bf",
    3729934
);
wire!(
    goldilocks,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4,
    "c5b9d13fa11ab82d64f55de2a63560de4b7f0ab15b90248af4ee6bb0684eec1c",
    5991222
);
