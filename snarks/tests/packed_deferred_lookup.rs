use algebra::{AbstractExtensionField,NTTField,matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript,Transcript};
use pcs::{matrix_weighted::Parameters,utils::code::BlockReedSolomonCode};
use serde::{Serialize,de::DeserializeOwned};
use sha2::Sha256;
use snarks::{packed_extension_lookup::deferred::{self,Request},packed_oracle::ProverOracle,packed_tuple_lookup::Config};

fn exercise<F,EF>(k:usize)
where F:NTTField+Serialize+DeserializeOwned,EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
{
    let mu=3;
    let capacity=(1<<mu)*k;
    let pp=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu,k,64,2).unwrap();
    let helper=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu+k.ilog2() as usize,k,64,2).unwrap();
    let tuples:Vec<Vec<_>>=(0..4).map(|i|vec![F::from(i),F::from(2*i+3),F::from(i*i+7)]).collect();
    for len in [capacity,capacity-3] {
        let tables:Vec<_>=(0..3).map(|j|PackedTable::new(mu,k,(0..capacity).map(|i|
            if i<len {tuples[i%4][j]} else {F::from(999+j)}).collect()).unwrap()).collect();
        let (roots,states):(Vec<_>,Vec<_>)=tables.iter().map(|t|pp.commit::<F,Sha256>(t).unwrap()).unzip();
        let oracles:Vec<_>=tables.iter().zip(&roots).zip(&states).map(|((table,commitment),state)|ProverOracle {
            parameters:&pp,table,commitment,state}).collect();
        let refs:Vec<_>=oracles.iter().collect();
        let public:Vec<_>=oracles.iter().map(ProverOracle::verifier).collect();
        for count in [1,4,16] {
            let requests:Vec<_>=(0..count).map(|r| {
                let slots=vec![r%3,(r+1)%3];
                let table=tuples.iter().map(|t|slots.iter().map(|&s|t[s]).collect()).collect();
                Request {config:Config::new(len,table,1).unwrap(),source_slots:slots}
            }).collect();
            let mut prover=Transcript::new_direct();
            let proof=deferred::prove::<F,EF,Sha256,_>(&mut prover,&helper,&refs,&requests).unwrap();
            assert!(proof.lookups.iter().all(|p|p.source_openings.is_empty()));
            assert_eq!(proof.source_authentication.openings.len(),if count==1 {2} else {3});
            let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
            let (proof,used):(deferred::Proof<F,EF,[u8;32]>,_)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
            assert_eq!(used,bytes.len());
            let mut verifier=Transcript::new_direct();
            deferred::verify::<F,EF,Sha256,_>(&mut verifier,&helper,&public,&requests,&proof).unwrap();
            assert_eq!(prover.get_challenge(b"after deferred lookup"),verifier.get_challenge(b"after deferred lookup"));
            let reject=|requests:&[_],proof:&_| deferred::verify::<F,EF,Sha256,_>(&mut Transcript::new_direct(),&helper,&public,requests,proof).is_err();
            let mut bad=proof.clone();bad.source_authentication.openings.pop();assert!(reject(&requests,&bad));
            let mut bad=proof.clone();bad.lookups.pop();assert!(reject(&requests,&bad));
            let mut bad=proof.clone();bad.lookups[0].groups[0].source_values[0][0]+=F::one();assert!(reject(&requests,&bad));
            let mut bad=proof.clone();bad.lookups[0].groups[0].source_values.pop();assert!(reject(&requests,&bad));
            let mut bad=proof.clone();bad.lookups[0].groups[0].source_values[0].pop();assert!(reject(&requests,&bad));
            let mut bad=proof.clone();bad.lookups[0].groups[0].reciprocal_opening.test[0]+=F::one();assert!(reject(&requests,&bad));
            let mut bad=proof.clone();bad.lookups[0].source_openings.push(bad.source_authentication.openings[0].clone());assert!(reject(&requests,&bad));
            let mut wrong=requests.clone();wrong[0].source_slots.swap(0,1);assert!(reject(&wrong,&proof));
            assert!(reject(&[],&proof));
        }
    }
}
#[test] fn babybear_lookup_sources_share_authentication(){exercise::<algebra::BabyBear,algebra::BabyBearExtension6>(8);}
#[test] fn goldilocks_lookup_sources_share_authentication(){exercise::<algebra::Goldilocks,algebra::GoldilocksExtension3>(4);}
