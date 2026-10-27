use algebra::{AbstractExtensionField, NTTField, matrix_weighted::{Matrix,MatrixPair,PackedTable}};
use helper::{FiatShamirTranscript,Transcript};
use pcs::{matrix_weighted::{Parameters,aggregate},utils::code::BlockReedSolomonCode};
use serde::{Serialize,de::DeserializeOwned};
use sha2::Sha256;

fn exercise<F,EF>(k: usize)
where F: NTTField+Serialize+DeserializeOwned,
      EF: AbstractExtensionField<F>+Serialize+DeserializeOwned,
{
    let n=5;
    let left=1;
    let code=BlockReedSolomonCode::<F>::new(1<<(n-left),k,2).unwrap();
    let pp=Parameters::new_encoded::<F>(n,k,left,512,code).unwrap();
    let mut fixture=Transcript::<F>::new_direct();
    let query: Vec<_>=(0..n).map(|_| MatrixPair {
        zero:Matrix::new(k,fixture.get_vec_challenge(b"aggregate dense zero",k*k)).unwrap(),
        one:Matrix::new(k,fixture.get_vec_challenge(b"aggregate dense one",k*k)).unwrap(),
    }).collect();
    assert_ne!(query[0].zero.mul(&query[0].one).unwrap(),query[0].one.mul(&query[0].zero).unwrap());
    for count in [1,4,16] {
        let tables: Vec<_>=(0..count).map(|i| PackedTable::new(n,k,
            (0..(1<<n)*k).map(|j|F::from((i+1)*(j*j+3)+j)).collect()).unwrap()).collect();
        let committed: Vec<_>=tables.iter().map(|t|pp.commit::<F,Sha256>(t).unwrap()).collect();
        let roots: Vec<_>=committed.iter().map(|x|x.0.clone()).collect();
        let states: Vec<_>=committed.iter().map(|x|&x.1).collect();
        let values: Vec<_>=tables.iter().map(|t|t.evaluate(&query).unwrap()).collect();
        let mut prover=Transcript::new_direct();
        let proof=aggregate::prove::<F,EF,Sha256,_>(&pp,&mut prover,&roots,&states,&query,&values).unwrap();
        let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
        let (proof,used):(aggregate::Proof<F,EF,[u8;32]>,_)=
            bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
        assert_eq!(used,bytes.len());
        let mut verifier=Transcript::new_direct();
        aggregate::verify::<F,EF,Sha256,_>(&pp,&mut verifier,&roots,&query,&values,&proof).unwrap();
        assert_eq!(prover.get_challenge(b"after aggregate"),verifier.get_challenge(b"after aggregate"));
        let reject=|roots:&[_],query:&[_],values:&[_],proof:&_| {
            let mut trans=Transcript::new_direct();
            aggregate::verify::<F,EF,Sha256,_>(&pp,&mut trans,roots,query,values,proof).is_err()
        };
        let mut bad=proof.clone();bad.test[0]+=F::one();assert!(reject(&roots,&query,&values,&bad));
        let mut bad=proof.clone();bad.evaluation[0]+=EF::one();assert!(reject(&roots,&query,&values,&bad));
        let mut bad=proof.clone();bad.columns[0][0].values[0]+=F::one();assert!(reject(&roots,&query,&values,&bad));
        let mut bad=proof.clone();bad.columns[0][0].path.pop();assert!(reject(&roots,&query,&values,&bad));
        let mut bad=proof.clone();bad.columns.pop();assert!(reject(&roots,&query,&values,&bad));
        let mut wrong=values.clone();wrong[0][0]+=F::one();assert!(reject(&roots,&query,&wrong,&proof));
        let mut wrong=query.clone();wrong[0]=query[1].clone();assert!(reject(&roots,&wrong,&values,&proof));
        assert!(reject(&[],&query,&[],&proof));
        if count>1 {
            let mut swapped=roots.clone();swapped.swap(0,1);assert!(reject(&swapped,&query,&values,&proof));
            let mut swapped=proof.clone();swapped.columns.swap(0,1);assert!(reject(&roots,&query,&values,&swapped));
        }
        if count==16 {
            let independent: Vec<_>=roots.iter().zip(&states).zip(&values).map(|((root,state),value)| {
                pp.open::<F,Sha256>(&mut Transcript::new_direct(),root,state,&query,value).unwrap()
            }).collect();
            let independent_bytes=bincode::serde::encode_to_vec(&independent,bincode::config::standard()).unwrap().len();
            assert!(bytes.len()<independent_bytes,"{} vs {independent_bytes}",bytes.len());
            eprintln!("aggregate roots={count} degree={} bytes={} independent_bytes={independent_bytes}",EF::D,bytes.len());
        }
    }
}

#[test]
fn babybear_common_query_aggregation() {
    exercise::<algebra::BabyBear,algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_common_query_aggregation() {
    exercise::<algebra::Goldilocks,algebra::GoldilocksExtension3>(4);
}
