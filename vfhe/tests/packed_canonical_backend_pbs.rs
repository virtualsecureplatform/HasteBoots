use algebra::{AsInto, Field};
use pcs::matrix_weighted::masked_polyfrim::{Parameters as MaskedParameters, Proof as MaskedProof};
use rand::{SeedableRng, rngs::StdRng};
use sha2::Sha256;
use snarks::{
    packed_key_switch::canonical::protocol as ks,
    packed_pbs as pbs,
    packed_pbs::{canonical, canonical_setup},
};
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
#[path = "common/canonical_pbs.rs"]
mod native_fixture;
use native_fixture::secret;

macro_rules! complete_roundtrip {
 ($name:ident,$field:ty,$extension:ty,$width:expr)=>{
 #[test] fn $name(){
 type F=$field;type E=$extension;const WIDTH:usize=$width;
 let cfg=pbs::Config::new::<F>(32,21,8,5,1,1).unwrap();let dims=cfg.variables(WIDTH).unwrap();
 let make=|vars:usize,budget:usize|{(vars..24).find_map(|physical|MaskedParameters::<F,E>::new(vars,WIDTH,physical,2,1,budget).ok()).expect("bounded test geometry")};
 let cpp=make(dims[0],WIDTH+2);let epp=make(dims[0],WIDTH+1);let kpp=make(dims[0],1);let ipp=make(dims[0],2);let borrow=make(dims[0],3);let helper=make(dims[1],2);let mono=make(dims[0],WIDTH+1);
 let acc_params=[make(dims[0],WIDTH+8),make(dims[0],WIDTH+1),make(dims[0],3),make(dims[0],2)];
 let fco=make(dims[2],WIDTH+2);let fev=make(dims[2],WIDTH+1);let fkey=make(dims[2],1);let fin=make(dims[2],2);let fborrow=make(dims[2],3);let fhelper=make(dims[3],2);
 let pp=canonical::Parameters{coefficients:&cpp,evaluations:&epp,key:&kpp,inputs:&ipp,borrows:&borrow,helper:&helper,accumulators:[&acc_params[0],&acc_params[1],&acc_params[2],&acc_params[3]],monomial:&mono,final_stage:ks::Parameters{coefficients:&fco,evaluations:&fev,key:&fkey,input:&fin,borrows:&fborrow,helper:&fhelper}};
 let sk=secret::<F>(42);let enc=Encryptor::new(sk.clone());let dec=Decryptor::new(sk.clone());let evaluator=Evaluator::new(&sk);let setup=canonical_setup::preprocess::<F,Sha256,_,_>(&canonical_setup::Parameters{source:&kpp,helper:&helper,final_source:&fkey,final_helper:&fhelper},cfg.clone(),evaluator.binary_bootstrap_key().unwrap(),evaluator.rlwe_key_switching_key().unwrap().as_slice(),&mut StdRng::seed_from_u64(941)).unwrap();let expected=setup.verifier();
 let x=enc.encrypt(1usize.as_into());let y=enc.encrypt(1usize.as_into());let(out,trace)=evaluator.nand(&x,&y);assert_eq!(dec.decrypt_with_noise(&out).0,0usize.as_into());
 let statement=pbs::Statement{left_a:x.a(),left_b:x.b(),right_a:y.a(),right_b:y.b(),output_a:out.a(),output_b:out.b()};
 let mut stats=pbs::ProverStatistics::default();let proof=canonical::prove_with_statistics::<F,E,Sha256,_,_>(&pp,&setup,&statement,&trace,&mut StdRng::seed_from_u64(942),&mut stats).unwrap();assert_eq!(proof.protocol_version,10);drop(trace);
 assert!(setup.br_oracles(&kpp).unwrap().iter().all(|s|s.state.spent().unwrap()==1));assert!(setup.ks_oracles(&fkey).unwrap().iter().all(|s|s.state.spent().unwrap()==1));
 let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();let(proof,used):(canonical::Proof<F,E,[u8;32],MaskedProof<E,[u8;32]>,MaskedProof<E,[u8;32]>>,usize)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();assert_eq!(used,bytes.len());canonical::verify::<F,E,Sha256,_>(&pp,&expected,&statement,&proof).unwrap();
 let inventory=snarks::packed_root_inventory::canonical_inventory(&proof);let bits=F::MODULUS_VALUE.ilog2() as usize+1;let d=bits.div_ceil(8);let s=bits.div_ceil(5);assert_eq!(inventory.total(),8*d+4*s+16);assert_eq!(inventory.categories["key_switch_input"],1);
 let reject=|p:&canonical::Proof<F,E,[u8;32],MaskedProof<E,[u8;32]>,MaskedProof<E,[u8;32]>>|canonical::verify::<F,E,Sha256,_>(&pp,&expected,&statement,p).is_err();
 let mut bad=proof.clone();bad.protocol_version=9;assert!(reject(&bad));let mut bad=proof.clone();bad.accumulators.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.final_accumulator[0]+=F::from(1usize);assert!(reject(&bad));let mut bad=proof.clone();bad.ntt.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.decomposition.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.key_switch.input.root[0]^=1;assert!(reject(&bad));let mut bad=proof.clone();bad.monomial.evaluations.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.key_switch.extraction.value[0]+=F::from(1usize);assert!(reject(&bad));
 let mut altered=statement.clone();altered.left_b+=F::from(1usize);assert!(canonical::verify::<F,E,Sha256,_>(&pp,&expected,&altered,&proof).is_err());let mut altered=statement.clone();altered.output_b+=F::from(1usize);assert!(canonical::verify::<F,E,Sha256,_>(&pp,&expected,&altered,&proof).is_err());
 println!("HB_COMPLETE_CANONICAL_PBS {{\"protocol_version\":10,\"prime\":{},\"extension_degree\":{},\"width\":{},\"polynomial_size\":32,\"lwe_dimension\":21,\"proof_bytes\":{},\"root_slots\":{},\"complete_pbs\":true,\"original_size\":false,\"whole_security_certified\":false,\"hiding_certified\":false,\"performance_gate\":false}}",F::MODULUS_VALUE,<E as algebra::AbstractExtensionField<F>>::D,WIDTH,bytes.len(),inventory.total());
 }
 }
}
complete_roundtrip!(
    babybear_complete,
    algebra::BabyBear,
    algebra::BabyBearExtension6,
    8
);
complete_roundtrip!(
    goldilocks_complete,
    algebra::Goldilocks,
    algebra::GoldilocksExtension3,
    4
);
