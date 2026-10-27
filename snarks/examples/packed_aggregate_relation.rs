//! Whole packed sum-of-products relation comparison; not complete PBS.
use algebra::{AbstractExtensionField,NTTField,matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript,Transcript};
use pcs::{matrix_weighted::Parameters,utils::code::BlockReedSolomonCode};
use serde::{Serialize,de::DeserializeOwned};
use sha2::{Digest,Sha256};
use snarks::packed_relation::{self as relation,aggregate,ProverStatistics};
use std::time::Instant;
use sumcheck::packed::PackedShape;

fn run<F,EF>(field:&str,k:usize,n:usize,reverse:bool)
where F:NTTField+Serialize+DeserializeOwned,
      EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
{
    let pp=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n,k,544,2).unwrap();
    for products in [1,4,16] {
        let timer=Instant::now();
        let mut fixture=Transcript::<F>::new_direct();
        fixture.append_message(b"aggregate relation benchmark fixture",&(n,k,products));
        let capacity=(1<<n)*k;
        let mut sum=vec![F::zero();capacity];
        let mut factors=Vec::new();
        let mut terms=Vec::new();
        for p in 0..products {
            let a=fixture.get_vec_challenge(b"factor a",capacity);
            let b=fixture.get_vec_challenge(b"factor b",capacity);
            for i in 0..capacity {sum[i]+=a[i]*b[i];}
            factors.push(PackedTable::new(n,k,a).unwrap());
            factors.push(PackedTable::new(n,k,b).unwrap());
            terms.push((F::one(),vec![2*p,2*p+1]));
        }
        terms.push((-F::one(),vec![factors.len()]));
        factors.push(PackedTable::new(n,k,sum).unwrap());
        let shape=PackedShape {num_vars:n,width:k,num_factors:factors.len(),terms};
        let (roots,states):(Vec<_>,Vec<_>)=factors.iter().map(|t|pp.commit::<F,Sha256>(t).unwrap()).unzip();
        let references:Vec<_>=states.iter().collect();
        let setup_ns=timer.elapsed().as_nanos();
        let statement=bincode::serde::encode_to_vec(&(pp.context_digest::<F,Sha256>().unwrap(),&shape,&roots),bincode::config::standard()).unwrap();
        let statement_sha256=format!("{:x}",Sha256::digest(&statement));
        let transcript=|| {
            let mut trans=Transcript::<F>::new_direct();
            trans.append_message(b"benchmark requested relation",&statement_sha256);
            trans
        };
        for aggregated in if reverse {[true,false]} else {[false,true]} {
            let mut statistics=ProverStatistics::default();
            macro_rules! certificate {
                ($prove:expr,$ty:ty,$verify:expr) => {{
                    let timer=Instant::now();
                    let proof=$prove;
                    let prove_ns=timer.elapsed().as_nanos();
                    let timer=Instant::now();
                    let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
                    let serialization_ns=timer.elapsed().as_nanos();
                    let proof_bytes=bytes.len();
                    let proof_sha256=format!("{:x}",Sha256::digest(&bytes));
                    drop(proof);
                    let timer=Instant::now();
                    let (proof,used):($ty,_)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
                    assert_eq!(used,proof_bytes);
                    let deserialize_ns=timer.elapsed().as_nanos();
                    let timer=Instant::now();($verify)(&proof);
                    let verify_ns=timer.elapsed().as_nanos();
                    (prove_ns,serialization_ns,deserialize_ns,verify_ns,proof_bytes,proof_sha256)
                }};
            }
            let (prove_ns,serialization_ns,deserialize_ns,verify_ns,proof_bytes,proof_sha256)=if aggregated {
                certificate!(aggregate::prove_with_state_references::<F,EF,Sha256,_>(&mut transcript(),&shape,&pp,&factors,&roots,&references,&mut statistics).unwrap(),
                    aggregate::Proof<F,EF,[u8;32]>,
                    |proof|aggregate::verify::<F,EF,Sha256,_>(&mut transcript(),&shape,&pp,&roots,proof).unwrap())
            } else {
                certificate!(relation::prove_with_state_references::<F,Sha256,_>(&mut transcript(),&shape,&pp,&factors,&roots,&references,&mut statistics).unwrap(),
                    relation::RelationProof<F,[u8;32]>,
                    |proof|relation::verify::<F,Sha256,_>(&mut transcript(),&shape,&pp,&roots,proof).unwrap())
            };
            let mode=if aggregated {"aggregate"} else {"independent"};
            let complete_ns=prove_ns+serialization_ns;
            println!("HB_AGG_RELATION {{\"scope\":\"packed-sum-products-relation\",\"field\":\"{field}\",\"mode\":\"{mode}\",\"products\":{products},\"factors\":{},\"extension_degree\":{},\"variables\":{n},\"width\":{k},\"left_vars\":{},\"queries\":544,\"reverse\":{reverse},\"setup_ns\":{setup_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"zero_check_ns\":{},\"terminal_evaluation_ns\":{},\"openings_ns\":{},\"proof_bytes\":{proof_bytes},\"proof_sha256\":\"{proof_sha256}\",\"statement_sha256\":\"{statement_sha256}\",\"verified\":true,\"whole_proof_security_certified\":false}}",shape.num_factors,EF::D,pp.left_vars(),statistics.zero_check.as_nanos(),statistics.terminal_evaluation.as_nanos(),statistics.openings.as_nanos());
        }
    }
}
fn main() {
    let args:Vec<_>=std::env::args().collect();
    let full=args.iter().any(|s|s=="--full");
    let reverse=args.iter().any(|s|s=="--reverse");
    if args.iter().any(|s|s=="--goldilocks") {
        run::<algebra::Goldilocks,algebra::GoldilocksExtension3>("goldilocks",4,if full {19} else {9},reverse);
    } else {
        run::<algebra::BabyBear,algebra::BabyBearExtension6>("babybear",8,if full {18} else {8},reverse);
    }
}
