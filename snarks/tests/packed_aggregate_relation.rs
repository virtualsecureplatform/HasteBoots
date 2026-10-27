use algebra::{AbstractExtensionField,NTTField};
use helper::{FiatShamirTranscript,Transcript};
use pcs::{matrix_weighted::Parameters,utils::code::BlockReedSolomonCode};
use serde::{Serialize,de::DeserializeOwned};
use sha2::Sha256;
use snarks::packed_relation::{self,aggregate,ProverStatistics};
use sumcheck::packed::PackedShape;

fn exercise<F,EF>(width:usize)
where F:NTTField+Serialize+DeserializeOwned,
      EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
{
    for length in [1,7,73] {
        for products in [1,4,16] {
            let mut columns=Vec::new();
            let mut sum=vec![F::zero();length];
            let mut terms=Vec::new();
            for p in 0..products {
                let a:Vec<_>=(0..length).map(|i|F::from(i*i+3*p+1)).collect();
                let b:Vec<_>=(0..length).map(|i|F::from(7*i+5*p+2)).collect();
                for i in 0..length {sum[i]+=a[i]*b[i];}
                terms.push((F::one(),vec![2*p,2*p+1]));
                columns.push(a);columns.push(b);
            }
            terms.push((-F::one(),vec![columns.len()]));
            columns.push(sum);
            let factors=packed_relation::pack_rows(width,&columns.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
            let n=factors[0].num_vars();
            let pp=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(n,width,128,2).unwrap();
            let (roots,states):(Vec<_>,Vec<_>)=factors.iter().map(|t|pp.commit::<F,Sha256>(t).unwrap()).unzip();
            let shape=PackedShape {num_vars:n,width,num_factors:factors.len(),terms};
            let mut prover=Transcript::new_direct();
            prover.append_message(b"requested relation provenance",&99usize);
            let proof=aggregate::prove::<F,EF,Sha256,_>(&mut prover,&shape,&pp,&factors,&roots,&states).unwrap();
            let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
            let mut measured=Transcript::new_direct();
            measured.append_message(b"requested relation provenance",&99usize);
            let measured_proof=aggregate::prove_with_state_references::<F,EF,Sha256,_>(
                &mut measured,&shape,&pp,&factors,&roots,&states.iter().collect::<Vec<_>>(),
                &mut ProverStatistics::default()).unwrap();
            assert_eq!(bytes,bincode::serde::encode_to_vec(&measured_proof,bincode::config::standard()).unwrap());
            let (proof,used):(aggregate::Proof<F,EF,[u8;32]>,_)=
                bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
            assert_eq!(used,bytes.len());
            let mut verifier=Transcript::new_direct();
            verifier.append_message(b"requested relation provenance",&99usize);
            aggregate::verify::<F,EF,Sha256,_>(&mut verifier,&shape,&pp,&roots,&proof).unwrap();
            let after=prover.get_challenge(b"after aggregate relation");
            assert_eq!(after,measured.get_challenge(b"after aggregate relation"));
            assert_eq!(after,verifier.get_challenge(b"after aggregate relation"));
            let reject=|shape:&_,roots:&[_],proof:&_,provenance:usize| {
                let mut trans=Transcript::new_direct();
                trans.append_message(b"requested relation provenance",&provenance);
                aggregate::verify::<F,EF,Sha256,_>(&mut trans,shape,&pp,roots,proof).is_err()
            };
            assert!(reject(&shape,&roots,&proof,100));
            let mut wrong=roots.clone();wrong.swap(0,1);assert!(reject(&shape,&wrong,&proof,99));
            let mut wrong=shape.clone();wrong.terms[0].0+=F::one();assert!(reject(&wrong,&roots,&proof,99));
            let mut bad=proof.clone();bad.values[0][0]+=F::one();assert!(reject(&shape,&roots,&bad,99));
            let mut bad=proof.clone();bad.opening.evaluation[0]+=EF::one();assert!(reject(&shape,&roots,&bad,99));
            let mut bad=proof.clone();bad.opening.columns[0][0].values[0]+=F::one();assert!(reject(&shape,&roots,&bad,99));
            let mut bad=proof.clone();bad.values.pop();assert!(reject(&shape,&roots,&bad,99));
            assert!(reject(&shape,&roots[..roots.len()-1],&proof,99));
        }
    }
}
#[test]
fn babybear_aggregated_relations_roundtrip_and_binding() {
    exercise::<algebra::BabyBear,algebra::BabyBearExtension6>(8);
}
#[test]
fn goldilocks_aggregated_relations_roundtrip_and_binding() {
    exercise::<algebra::Goldilocks,algebra::GoldilocksExtension3>(4);
}
