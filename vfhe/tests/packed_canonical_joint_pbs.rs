use algebra::{AsInto, Field};
use pcs::matrix_weighted::masked_polyfrim::joint::{
    Parameters as MaskedParameters, Proof as MaskedProof,
};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use snarks::{
    packed_key_switch::canonical::protocol as ks,
    packed_pbs as pbs,
    packed_pbs::{canonical, canonical::shared, canonical_setup},
};
use std::time::Instant;
use vfhe::{Decryptor, Encryptor, bfhe::Evaluator};
#[path = "common/canonical_pbs.rs"]
mod native_fixture;
use native_fixture::secret;

fn common_children<F: Field, E: Field, O, D, K>(
    p: &canonical::BackendProof<F, O, MaskedProof<E, O>, MaskedProof<E, O>, D, K>,
) -> usize {
    p.ntt
        .iter()
        .map(|p| p.coefficient_opening.responses.len() + p.evaluation_opening.responses.len())
        .sum::<usize>()
        + p.hadamard
            .openings
            .iter()
            .map(|p| p.responses.len())
            .sum::<usize>()
        + p.accumulator
            .openings
            .iter()
            .map(|p| p.responses.len())
            .sum::<usize>()
        + p.monomial
            .ntt
            .iter()
            .map(|p| p.coefficient_opening.responses.len() + p.evaluation_opening.responses.len())
            .sum::<usize>()
        + p.monomial
            .openings
            .iter()
            .map(|p| p.responses.len())
            .sum::<usize>()
}
fn key_common_children<F: Field, E: Field, O, D>(
    p: &ks::BackendProof<F, O, MaskedProof<E, O>, MaskedProof<E, O>, D>,
) -> usize {
    p.input_opening.responses.len()
        + p.extraction.opening.responses.len()
        + p.ntt
            .iter()
            .map(|p| p.coefficient_opening.responses.len() + p.evaluation_opening.responses.len())
            .sum::<usize>()
        + p.product
            .openings
            .iter()
            .map(|p| p.responses.len())
            .sum::<usize>()
}
fn shared_radix_children<F: Field, E: Field, O>(
    p: &snarks::packed_decomposition::canonical::shared::Proof<
        F,
        E,
        O,
        MaskedProof<E, O>,
        MaskedProof<E, O>,
    >,
) -> usize {
    p.linear
        .openings
        .iter()
        .chain(&p.comparisons.source_opening.openings)
        .chain(&p.comparisons.helper_openings)
        .map(|p| p.responses.len())
        .sum()
}
fn per_limb_children<F: Field, E: Field, O>(
    p: &snarks::packed_decomposition::canonical::Proof<
        F,
        E,
        O,
        MaskedProof<E, O>,
        MaskedProof<E, O>,
    >,
) -> usize {
    p.linear
        .openings
        .iter()
        .map(|p| p.responses.len())
        .sum::<usize>()
        + p.comparisons
            .iter()
            .map(|p| {
                p.source_openings
                    .iter()
                    .map(|p| p.responses.len())
                    .sum::<usize>()
                    + p.groups
                        .iter()
                        .map(|g| g.reciprocal_opening.responses.len())
                        .sum::<usize>()
            })
            .sum::<usize>()
}
fn common_sources<F: Field, E: Field, O, D, K>(
    p: &canonical::BackendProof<F, O, MaskedProof<E, O>, MaskedProof<E, O>, D, K>,
) -> usize {
    p.ntt.iter().map(|_| 2usize).sum::<usize>()
        + p.hadamard.openings.iter().map(|_| 1usize).sum::<usize>()
        + p.accumulator.openings.iter().map(|_| 1usize).sum::<usize>()
        + p.monomial.ntt.iter().map(|_| 2usize).sum::<usize>()
        + p.monomial.openings.iter().map(|_| 1usize).sum::<usize>()
}
fn key_common_sources<F: Field, E: Field, O, D>(
    p: &ks::BackendProof<F, O, MaskedProof<E, O>, MaskedProof<E, O>, D>,
) -> usize {
    1usize
        + 1usize
        + p.ntt.iter().map(|_| 2usize).sum::<usize>()
        + p.product.openings.iter().map(|_| 1usize).sum::<usize>()
}
fn shared_radix_sources<F: Field, E: Field, O>(
    p: &snarks::packed_decomposition::canonical::shared::Proof<
        F,
        E,
        O,
        MaskedProof<E, O>,
        MaskedProof<E, O>,
    >,
) -> usize {
    p.linear
        .openings
        .iter()
        .chain(&p.comparisons.source_opening.openings)
        .chain(&p.comparisons.helper_openings)
        .map(|_| 1usize)
        .sum()
}
fn per_limb_sources<F: Field, E: Field, O>(
    p: &snarks::packed_decomposition::canonical::Proof<
        F,
        E,
        O,
        MaskedProof<E, O>,
        MaskedProof<E, O>,
    >,
) -> usize {
    p.linear.openings.iter().map(|_| 1usize).sum::<usize>()
        + p.comparisons
            .iter()
            .map(|p| {
                p.source_openings.iter().map(|_| 1usize).sum::<usize>()
                    + p.groups.iter().map(|_| 1usize).sum::<usize>()
            })
            .sum::<usize>()
}
macro_rules! complete_roundtrip {
 ($name:ident,$field:ty,$extension:ty,$width:expr)=>{
 #[test] fn $name(){
 type F=$field;type E=$extension;const WIDTH:usize=$width;
 let cfg=pbs::Config::new::<F>(32,21,8,5,1,1).unwrap();let dims=cfg.variables(WIDTH).unwrap();
 let make=|vars:usize,budget:usize|{(vars..24).find_map(|physical|MaskedParameters::<F,E>::new(vars,WIDTH,physical,2,1,budget).ok()).expect("bounded test geometry")};
 let cpp=make(dims[0],WIDTH+2);let epp=make(dims[0],WIDTH+1);let kpp=make(dims[0],2);let ipp=make(dims[0],2);let borrow=make(dims[0],3);let helper=make(dims[1],2);let mono=make(dims[0],WIDTH+1);
 let acc_params=[make(dims[0],WIDTH+8),make(dims[0],WIDTH+1),make(dims[0],3),make(dims[0],2)];
 let fco=make(dims[2],WIDTH+2);let fev=make(dims[2],WIDTH+1);let fkey=make(dims[2],2);let fin=make(dims[2],2);let fborrow=make(dims[2],3);let fhelper=make(dims[3],2);
 let pp=canonical::Parameters{coefficients:&cpp,evaluations:&epp,key:&kpp,inputs:&ipp,borrows:&borrow,helper:&helper,accumulators:[&acc_params[0],&acc_params[1],&acc_params[2],&acc_params[3]],monomial:&mono,final_stage:ks::Parameters{coefficients:&fco,evaluations:&fev,key:&fkey,input:&fin,borrows:&fborrow,helper:&fhelper}};
 let sk=secret::<F>(42);let enc=Encryptor::new(sk.clone());let dec=Decryptor::new(sk.clone());let evaluator=Evaluator::new(&sk);let setup_start=Instant::now();let setup=canonical_setup::preprocess::<F,Sha256,_,_>(&canonical_setup::Parameters{source:&kpp,helper:&helper,final_source:&fkey,final_helper:&fhelper},cfg.clone(),evaluator.binary_bootstrap_key().unwrap(),evaluator.rlwe_key_switching_key().unwrap().as_slice(),&mut StdRng::seed_from_u64(941)).unwrap();let setup_s=setup_start.elapsed().as_secs_f64();let expected=setup.verifier();
 let independent_setup_parameters=canonical_setup::Parameters{source:kpp.independent_parameters(),helper:helper.independent_parameters(),final_source:fkey.independent_parameters(),final_helper:fhelper.independent_parameters()};
 let independent_owner=canonical_setup::preprocess::<F,Sha256,_,_>(&independent_setup_parameters,cfg.clone(),evaluator.binary_bootstrap_key().unwrap(),evaluator.rlwe_key_switching_key().unwrap().as_slice(),&mut StdRng::seed_from_u64(941)).unwrap();
 let independent_expected=independent_owner.verifier();
 let joint_roots=(setup.br_oracles(&kpp).unwrap().iter().map(|s|s.commitment.root).collect::<Vec<_>>(),setup.ks_oracles(&fkey).unwrap().iter().map(|s|s.commitment.root).collect::<Vec<_>>());
 let independent_roots=(independent_owner.br_oracles(kpp.independent_parameters()).unwrap().iter().map(|s|s.commitment.root).collect::<Vec<_>>(),independent_owner.ks_oracles(fkey.independent_parameters()).unwrap().iter().map(|s|s.commitment.root).collect::<Vec<_>>());
 assert_eq!(joint_roots,independent_roots);
 let native_key_roots_sha256=format!("{:x}",Sha256::digest(bincode::serde::encode_to_vec(&joint_roots,bincode::config::standard()).unwrap()));
 assert!(canonical_setup::validate::<F,Sha256,_>(&canonical_setup::Parameters{source:&kpp,helper:&helper,final_source:&fkey,final_helper:&fhelper},&independent_expected).is_err());
 assert!(canonical_setup::validate::<F,Sha256,_>(&independent_setup_parameters,&expected).is_err());
 drop(independent_owner);

 let x=enc.encrypt(1usize.as_into());let y=enc.encrypt(1usize.as_into());let(out,trace)=evaluator.nand(&x,&y);assert_eq!(dec.decrypt_with_noise(&out).0,0usize.as_into());
 let statement=pbs::Statement{left_a:x.a(),left_b:x.b(),right_a:y.a(),right_b:y.b(),output_a:out.a(),output_b:out.b()};
 let parameters_sha256=format!("{:x}",Sha256::digest(bincode::serde::encode_to_vec(&(&cfg,[&cpp,&epp,&kpp,&ipp,&borrow,&helper,&mono,&acc_params[0],&acc_params[1],&acc_params[2],&acc_params[3],&fco,&fev,&fkey,&fin,&fborrow,&fhelper]),bincode::config::standard()).unwrap()));
 let fixture_sha256=format!("{:x}",Sha256::digest(bincode::serde::encode_to_vec(&statement,bincode::config::standard()).unwrap()));
 let trusted_setup_sha256=format!("{:x}",Sha256::digest(bincode::serde::encode_to_vec(&expected,bincode::config::standard()).unwrap()));
 let fhe_parameters_sha256=format!("{:x}",Sha256::digest(format!("{:?}",native_fixture::params::<F>()).as_bytes()));
 let prove_start=Instant::now();
 let mut stats=pbs::ProverStatistics::default();let proof=shared::prove_with_statistics::<F,E,Sha256,_,_>(&pp,&setup,&statement,&trace,&mut StdRng::seed_from_u64(942),&mut stats).unwrap();assert_eq!(proof.protocol_version,11);let prove_s=prove_start.elapsed().as_secs_f64();
 assert!(setup.br_oracles(&kpp).unwrap().iter().all(|s|s.state.spent().unwrap()==1));assert!(setup.ks_oracles(&fkey).unwrap().iter().all(|s|s.state.spent().unwrap()==1));
 let serialization_start=Instant::now();let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();let serialization_s=serialization_start.elapsed().as_secs_f64();let decode_start=Instant::now();let(proof,used):(shared::Proof<F,E,[u8;32],MaskedProof<E,[u8;32]>,MaskedProof<E,[u8;32]>>,usize)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();assert_eq!(used,bytes.len());let decode_s=decode_start.elapsed().as_secs_f64();let verify_start=Instant::now();shared::verify::<F,E,Sha256,_>(&pp,&expected,&statement,&proof).unwrap();let verify_s=verify_start.elapsed().as_secs_f64();
 let inventory=snarks::packed_root_inventory::canonical_shared_inventory(&proof);let bits=F::MODULUS_VALUE.ilog2() as usize+1;let d=bits.div_ceil(8);let s=bits.div_ceil(5);assert_eq!(inventory.total(),8*d+4*s+16);assert_eq!(inventory.categories["key_switch_input"],1);
 let old_prove_start=Instant::now();let old=canonical::prove::<F,E,Sha256,_,_>(&pp,&setup,&statement,&trace,&mut StdRng::seed_from_u64(943)).unwrap();let old_prove_s=old_prove_start.elapsed().as_secs_f64();
 let mut exhausted_rng=StdRng::seed_from_u64(944);let mut untouched_rng=exhausted_rng.clone();
 assert!(shared::prove::<F,E,Sha256,_,_>(&pp,&setup,&statement,&trace,&mut exhausted_rng).unwrap_err().to_string().contains("exhausted retained native key allowance"));
 assert_eq!(exhausted_rng.next_u64(),untouched_rng.next_u64());drop(trace);
 let old_serialization_start=Instant::now();let old_bytes=bincode::serde::encode_to_vec(&old,bincode::config::standard()).unwrap();let old_serialization_s=old_serialization_start.elapsed().as_secs_f64();let old_decode_start=Instant::now();let(old,used):(canonical::Proof<F,E,[u8;32],MaskedProof<E,[u8;32]>,MaskedProof<E,[u8;32]>>,usize)=bincode::serde::decode_from_slice(&old_bytes,bincode::config::standard()).unwrap();assert_eq!(used,old_bytes.len());let old_decode_s=old_decode_start.elapsed().as_secs_f64();let old_verify_start=Instant::now();canonical::verify::<F,E,Sha256,_>(&pp,&expected,&statement,&old).unwrap();assert_eq!(old.protocol_version,10);let old_verify_s=old_verify_start.elapsed().as_secs_f64();
 assert!(setup.br_oracles(&kpp).unwrap().iter().all(|s|s.state.spent().unwrap()==2));assert!(setup.ks_oracles(&fkey).unwrap().iter().all(|s|s.state.spent().unwrap()==2));
 let shared_children=common_children(&proof)+proof.decomposition.iter().map(shared_radix_children).sum::<usize>()+key_common_children(&proof.key_switch)+shared_radix_children(&proof.key_switch.decomposition);
 let old_children=common_children(&old)+old.decomposition.iter().map(per_limb_children).sum::<usize>()+key_common_children(&old.key_switch)+per_limb_children(&old.key_switch.decomposition);
 let shared_sources=common_sources(&proof)+proof.decomposition.iter().map(shared_radix_sources).sum::<usize>()+key_common_sources(&proof.key_switch)+shared_radix_sources(&proof.key_switch.decomposition);
 let old_sources=common_sources(&old)+old.decomposition.iter().map(per_limb_sources).sum::<usize>()+key_common_sources(&old.key_switch)+per_limb_sources(&old.key_switch.decomposition);
 assert!(shared_sources<shared_children);assert!(old_sources<old_children);
 assert_eq!(shared_children,if WIDTH==8{441}else{499});assert_eq!(old_children,if WIDTH==8{468}else{554});
 assert!(shared::verify::<F,E,Sha256,_>(&pp,&independent_expected,&statement,&proof).is_err());
 assert_eq!(old_children-shared_children,2*(2*d-1)+(2*s-1));assert!(bytes.len()<old_bytes.len());
 for (version,proof_bytes,proof_sha256,proving,serialization,decode,verification,children,sources) in [
 (11,bytes.len(),format!("{:x}",Sha256::digest(&bytes)),prove_s,serialization_s,decode_s,verify_s,shared_children,shared_sources),
 (10,old_bytes.len(),format!("{:x}",Sha256::digest(&old_bytes)),old_prove_s,old_serialization_s,old_decode_s,old_verify_s,old_children,old_sources)] {
 println!("HB_COMPLETE_CANONICAL_MASKED_PROFILE {{\"backend\":\"joint-source\",\"protocol_version\":{},\"prime\":{},\"extension_degree\":{},\"width\":{},\"polynomial_size\":32,\"lwe_dimension\":21,\"queries\":1,\"lookup_repetitions\":1,\"fixture_sha256\":\"{}\",\"parameters_sha256\":\"{}\",\"fhe_parameters_sha256\":\"{}\",\"trusted_setup_sha256\":\"{}\",\"proof_sha256\":\"{}\",\"proof_bytes\":{},\"child_openings\":{},\"source_certificates\":{},\"native_key_roots_sha256\":\"{}\",\"setup_s\":{},\"prove_s\":{},\"serialization_s\":{},\"decode_s\":{},\"verify_s\":{},\"verified\":true,\"complete_pbs\":true,\"original_size\":false,\"whole_security_matched\":false,\"performance_gate\":false}}",version,F::MODULUS_VALUE,<E as algebra::AbstractExtensionField<F>>::D,WIDTH,fixture_sha256,parameters_sha256,fhe_parameters_sha256,trusted_setup_sha256,proof_sha256,proof_bytes,children,sources,native_key_roots_sha256,setup_s,proving,serialization,decode,verification);
 }
 let reject=|p:&shared::Proof<F,E,[u8;32],MaskedProof<E,[u8;32]>,MaskedProof<E,[u8;32]>>|shared::verify::<F,E,Sha256,_>(&pp,&expected,&statement,p).is_err();
 let mut bad=proof.clone();bad.protocol_version=10;assert!(reject(&bad));let mut bad=proof.clone();bad.accumulators.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.final_accumulator[0]+=F::from(1usize);assert!(reject(&bad));let mut bad=proof.clone();bad.ntt.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.decomposition.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.key_switch.input.root[0]^=1;assert!(reject(&bad));let mut bad=proof.clone();bad.monomial.evaluations.pop();assert!(reject(&bad));let mut bad=proof.clone();bad.key_switch.extraction.value[0]+=F::from(1usize);assert!(reject(&bad));
 let mut bad=proof.clone();bad.decomposition[0].comparisons.helper_values[0]+=<E as algebra::AbstractExtensionField<F>>::from_base(F::from(1usize));assert!(reject(&bad));let mut bad=proof.clone();bad.hadamard.values[0][0]+=F::from(1usize);assert!(reject(&bad));
 let mut altered=statement.clone();let mut wrong_a=out.a().to_vec();wrong_a[20]+=F::from(1usize);altered.output_a=&wrong_a;assert!(shared::verify::<F,E,Sha256,_>(&pp,&expected,&altered,&proof).is_err());
 let mut altered=statement.clone();altered.left_b+=F::from(1usize);assert!(shared::verify::<F,E,Sha256,_>(&pp,&expected,&altered,&proof).is_err());let mut altered=statement.clone();altered.output_b+=F::from(1usize);assert!(shared::verify::<F,E,Sha256,_>(&pp,&expected,&altered,&proof).is_err());
 println!("HB_COMPLETE_CANONICAL_SHARED_PBS {{\"protocol_version\":11,\"prime\":{},\"extension_degree\":{},\"width\":{},\"polynomial_size\":32,\"lwe_dimension\":21,\"proof_bytes\":{},\"standalone_bytes\":{},\"shared_children\":{},\"standalone_children\":{},\"root_slots\":{},\"complete_pbs\":true,\"original_size\":false,\"whole_security_certified\":false,\"hiding_certified\":false,\"performance_gate\":false}}",F::MODULUS_VALUE,<E as algebra::AbstractExtensionField<F>>::D,WIDTH,bytes.len(),old_bytes.len(),shared_children,old_children,inventory.total());
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
