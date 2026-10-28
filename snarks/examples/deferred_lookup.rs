//! Shared-source lookup comparison; not a complete PBS benchmark.
use algebra::{AbstractExtensionField,NTTField,matrix_weighted::PackedTable};
use helper::Transcript;
use pcs::{matrix_weighted::Parameters,utils::code::{BlockReedSolomonCode,RowCode}};
use serde::{Serialize,de::DeserializeOwned};
use sha2::{Digest,Sha256};
use snarks::{packed_extension_lookup::{self as lookup,deferred::{self,Request}},packed_oracle::ProverOracle,packed_tuple_lookup::Config};
use std::time::Instant;

fn run<F,EF>(field:&str,k:usize,n:usize,reverse:bool)
where F:NTTField+Serialize+DeserializeOwned,EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
{
    let pp=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n,k,544,2).unwrap();
    let hvars=n+k.ilog2() as usize;
    let balanced=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(hvars,k,544,2).unwrap();
    let helper=if field=="babybear" {
        let left=balanced.left_vars()+1;
        Parameters::new_encoded::<F>(hvars,k,left,544,BlockReedSolomonCode::<F>::new(1<<(hvars-left),k,2).unwrap()).unwrap()
    } else {balanced};
    let timer=Instant::now();
    let capacity=(1<<n)*k;
    let tuples:Vec<Vec<_>>=(0..256).map(|i|vec![F::from(i),F::from(2*i+3),F::from(i*i+7)]).collect();
    let mut random=0x9e3779b97f4a7c15u64;
    let indices:Vec<_>=(0..capacity).map(|_| {
        // Reproducible synthetic membership data, not cryptographic randomness.
        random^=random<<13;random^=random>>7;random^=random<<17;
        (random&255) as usize
    }).collect();
    let tables:Vec<_>=(0..3).map(|j|PackedTable::new(n,k,indices.iter().map(|&i|tuples[i][j]).collect()).unwrap()).collect();
    let (roots,states):(Vec<_>,Vec<_>)=tables.iter().map(|t|pp.commit::<F,Sha256>(t).unwrap()).unzip();
    let oracles:Vec<_>=tables.iter().zip(&roots).zip(&states).map(|((table,commitment),state)|ProverOracle {parameters:&pp,table,commitment,state}).collect();
    let refs:Vec<_>=oracles.iter().collect();
    let public:Vec<_>=oracles.iter().map(ProverOracle::verifier).collect();
    let setup_ns=timer.elapsed().as_nanos();
    for count in [1,4,16] {
        let requests:Vec<_>=(0..count).map(|i| {
            let slots=vec![i%3,(i+1)%3];
            let table=tuples.iter().map(|t|slots.iter().map(|&s|t[s]).collect()).collect();
            Request {config:Config::new(capacity,table,1).unwrap(),source_slots:slots}
        }).collect();
        let descriptor=bincode::serde::encode_to_vec(&(pp.context_digest::<F,Sha256>().unwrap(),helper.context_digest::<F,Sha256>().unwrap(),&roots,&requests),bincode::config::standard()).unwrap();
        let statement_sha256=format!("{:x}",Sha256::digest(&descriptor));
        for shared in if reverse {[true,false]} else {[false,true]} {
            macro_rules! certificate {
                ($prove:expr,$ty:ty,$verify:expr) => {{
                    let timer=Instant::now();let proof=$prove;
                    let prove_ns=timer.elapsed().as_nanos();
                    let timer=Instant::now();
                    let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
                    let serialization_ns=timer.elapsed().as_nanos();
                    let proof_bytes=bytes.len();let proof_sha256=format!("{:x}",Sha256::digest(&bytes));
                    drop(proof);let timer=Instant::now();
                    let (proof,used):($ty,_)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
                    assert_eq!(used,proof_bytes);let deserialize_ns=timer.elapsed().as_nanos();
                    let timer=Instant::now();($verify)(&proof);let verify_ns=timer.elapsed().as_nanos();
                    (prove_ns,serialization_ns,deserialize_ns,verify_ns,proof_bytes,proof_sha256)
                }};
            }
            let (prove_ns,serialization_ns,deserialize_ns,verify_ns,proof_bytes,proof_sha256)=if shared {
                certificate!(deferred::prove::<F,EF,Sha256,_>(&mut Transcript::new_direct(),&helper,&refs,&requests).unwrap(),deferred::Proof<F,EF,[u8;32]>,
                    |proof|deferred::verify::<F,EF,Sha256,_>(&mut Transcript::new_direct(),&helper,&public,&requests,proof).unwrap())
            } else {
                certificate!({let mut trans=Transcript::new_direct();requests.iter().map(|r| {
                    let local:Vec<_>=r.source_slots.iter().map(|&s|refs[s]).collect();
                    lookup::prove::<F,EF,Sha256,_>(&mut trans,&r.config,&helper,&local).unwrap()
                }).collect::<Vec<_>>()},Vec<lookup::Proof<F,EF,[u8;32]>>,
                    |proof:&Vec<lookup::Proof<F,EF,[u8;32]>>| {
                        let mut trans=Transcript::new_direct();
                        for (r,p) in requests.iter().zip(proof) {
                            let local:Vec<_>=r.source_slots.iter().map(|&s|oracles[s].verifier()).collect();
                            lookup::verify::<F,EF,Sha256,_>(&mut trans,&r.config,&helper,&local,p).unwrap();
                        }
                    })
            };
            let mode=if shared {"deferred"} else {"immediate"};
            let complete_ns=prove_ns+serialization_ns;
            println!("HB_DEFERRED_LOOKUP {{\"scope\":\"shared-source-lookup-component\",\"field\":\"{field}\",\"mode\":\"{mode}\",\"lookups\":{count},\"sources\":3,\"extension_degree\":{},\"variables\":{n},\"width\":{k},\"source_left_vars\":{},\"helper_left_vars\":{},\"source_encoded_blocks\":{},\"helper_encoded_blocks\":{},\"queries\":544,\"reverse\":{reverse},\"setup_ns\":{setup_ns},\"prove_ns\":{prove_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"proof_bytes\":{proof_bytes},\"proof_sha256\":\"{proof_sha256}\",\"statement_sha256\":\"{statement_sha256}\",\"verified\":true,\"whole_proof_security_certified\":false}}",EF::D,pp.left_vars(),helper.left_vars(),pp.code().codeword_blocks(),helper.code().codeword_blocks());
        }
    }
}
fn main(){
    let args:Vec<_>=std::env::args().collect();let full=args.iter().any(|s|s=="--full");let reverse=args.iter().any(|s|s=="--reverse");
    if args.iter().any(|s|s=="--goldilocks") {run::<algebra::Goldilocks,algebra::GoldilocksExtension3>("goldilocks",4,if full {19} else {5},reverse);}
    else {run::<algebra::BabyBear,algebra::BabyBearExtension6>("babybear",8,if full {18} else {4},reverse);}
}
