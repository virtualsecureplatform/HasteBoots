//! Synthetic common-query PCS comparison, not a complete PBS benchmark.
use algebra::{AbstractExtensionField,NTTField,matrix_weighted::{Matrix,MatrixPair,PackedTable}};
use helper::{FiatShamirTranscript,Transcript};
use pcs::{matrix_weighted::{Parameters,Opening,aggregate},utils::code::BlockReedSolomonCode};
use serde::{Serialize,de::DeserializeOwned};
use sha2::{Digest,Sha256};
use std::time::Instant;

fn run<F,EF>(field:&str,k:usize,n:usize,reverse:bool)
where F:NTTField+Serialize+DeserializeOwned,
      EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
{
    let pp=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n,k,544,2).unwrap();
    let mut fixture=Transcript::<F>::new_direct();
    fixture.append_message(b"multi-root benchmark fixture v1",&(n,k));
    let query:Vec<_>=(0..n).map(|_|MatrixPair {
        zero:Matrix::new(k,fixture.get_vec_challenge(b"dense matrix zero",k*k)).unwrap(),
        one:Matrix::new(k,fixture.get_vec_challenge(b"dense matrix one",k*k)).unwrap(),
    }).collect();
    assert_ne!(query[0].zero.mul(&query[0].one).unwrap(),query[0].one.mul(&query[0].zero).unwrap());
    let timer=Instant::now();
    let tables:Vec<_>=(0..16).map(|_|PackedTable::new(n,k,
        fixture.get_vec_challenge(b"dense source",(1<<n)*k)).unwrap()).collect();
    let committed:Vec<_>=tables.iter().map(|table|pp.commit::<F,Sha256>(table).unwrap()).collect();
    let values:Vec<_>=tables.iter().map(|table|table.evaluate(&query).unwrap()).collect();
    let setup_ns=timer.elapsed().as_nanos();
    let roots:Vec<_>=committed.iter().map(|p|p.0.clone()).collect();
    let states:Vec<_>=committed.iter().map(|p|&p.1).collect();
    drop(tables);
    for count in [1,4,16] {
        let statement=bincode::serde::encode_to_vec(
            &(pp.context_digest::<F,Sha256>().unwrap(),&roots[..count],&query,&values[..count]),
            bincode::config::standard()).unwrap();
        let statement_sha256=format!("{:x}",Sha256::digest(&statement));
        let order=if reverse { [true,false] } else { [false,true] };
        for aggregated in order {
            macro_rules! certificate {
                ($prove:expr,$ty:ty,$verify:expr) => {{
                    let timer=Instant::now();
                    let proof=$prove;
                    let opening_ns=timer.elapsed().as_nanos();
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
                    let timer=Instant::now();
                    ($verify)(&proof);
                    let verify_ns=timer.elapsed().as_nanos();
                    (opening_ns,serialization_ns,deserialize_ns,verify_ns,proof_bytes,proof_sha256)
                }};
            }
            let (opening_ns,serialization_ns,deserialize_ns,verify_ns,proof_bytes,proof_sha256)=if aggregated {
                certificate!(aggregate::prove::<F,EF,Sha256,_>(&pp,&mut Transcript::new_direct(),
                    &roots[..count],&states[..count],&query,&values[..count]).unwrap(),
                    aggregate::Proof<F,EF,[u8;32]>,
                    |proof|aggregate::verify::<F,EF,Sha256,_>(&pp,&mut Transcript::new_direct(),
                        &roots[..count],&query,&values[..count],proof).unwrap())
            } else {
                certificate!((0..count).map(|i|pp.open::<F,Sha256>(&mut Transcript::new_direct(),
                    &roots[i],states[i],&query,&values[i]).unwrap()).collect::<Vec<_>>(),
                    Vec<Opening<F,[u8;32]>>,
                    |proof:&Vec<Opening<F,[u8;32]>>|for i in 0..count {
                        pp.verify::<F,Sha256>(&mut Transcript::new_direct(),&roots[i],&query,&values[i],&proof[i]).unwrap();
                    })
            };
            let complete_ns=opening_ns+serialization_ns;
            let mode=if aggregated {"aggregate"} else {"independent"};
            println!("HB_MULTI_ROOT {{\"scope\":\"synthetic-common-query-pcs\",\"field\":\"{field}\",\"mode\":\"{mode}\",\"roots\":{count},\"extension_degree\":{},\"variables\":{n},\"width\":{k},\"left_vars\":{},\"queries\":544,\"reverse\":{reverse},\"setup_ns\":{setup_ns},\"opening_ns\":{opening_ns},\"serialization_ns\":{serialization_ns},\"complete_ns\":{complete_ns},\"deserialize_ns\":{deserialize_ns},\"verify_ns\":{verify_ns},\"proof_bytes\":{proof_bytes},\"proof_sha256\":\"{proof_sha256}\",\"statement_sha256\":\"{statement_sha256}\",\"verified\":true,\"whole_proof_security_certified\":false}}",EF::D,pp.left_vars());
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
