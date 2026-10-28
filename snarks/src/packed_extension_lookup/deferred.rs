//! Multiple lookup groups with one terminal authentication packet per source.
//! Helper roots retain immediate authentication; source words are registered
//! before all lookup algebra. This is not yet a complete-PBS wire protocol.
use super::*;
use crate::packed_opening_batch;

/// Caller-derived lookup configuration and canonical source slot mapping.
#[derive(Clone,Debug,Serialize)]
pub struct Request<F> {
    /// Trusted public table, logical domain and repetition count.
    pub config:Config<F>,
    /// Ordered source slots in the outer canonical registry.
    pub source_slots:Vec<usize>,
}
/// Lookup algebra/helper proofs followed by shared canonical source checks.
#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct Proof<F:Field,EF:Field,O> {
    /// Inner source opening arrays must be empty in this protocol.
    pub lookups:Vec<super::Proof<F,EF,O>>,
    /// Obligations are reconstructed by the verifier, not carried here.
    pub source_authentication:packed_opening_batch::Proof<F,O>,
}
fn preflight<F,EF,H,C>(parent:&mut Transcript<F>,helper:&Parameters<C>,
    sources:usize,requests:&[Request<F>])->Result<(),Error>
where F:PrimeField+Serialize,EF:AbstractExtensionField<F>,H:Hash,C:RowCode<F>+Serialize,
{
    if requests.is_empty() || requests.iter().any(|r|r.source_slots.len()!=r.config.num_columns()
        || r.source_slots.iter().any(|&s|s>=sources)) {
        return Err(error("deferred lookup request/source dimensions"));
    }
    parent.append_message(b"packed deferred source lookups v1",
        &(helper.context_digest::<F,H>().map_err(convert)?,EF::D,requests));
    Ok(())
}
/// Prove all requests and share each canonical source's random test/columns.
pub fn prove<F,EF,H,C>(parent:&mut Transcript<F>,helper:&Parameters<C>,
    sources:&[&ProverOracle<'_,F,H,C>],requests:&[Request<F>])->Result<Proof<F,EF,H::Output>,Error>
where F:PrimeField+Serialize,EF:AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    preflight::<F,EF,H,C>(parent,helper,sources.len(),requests)?;
    let public:Vec<_>=sources.iter().map(|s|s.verifier()).collect();
    let mut batch=OpeningBatch::<F,H,C>::new(parent,&public).map_err(convert)?;
    let mut lookups=Vec::with_capacity(requests.len());
    for request in requests {
        let local:Vec<_>=request.source_slots.iter().map(|&i|sources[i]).collect();
        let witness:Vec<_>=local.iter().map(|s|s.table).collect();
        lookups.push(super::prove_inner::<F,EF,H,C>(parent,&request.config,helper,&local,&witness,
            &mut ProverStatistics::default(),true,Some((&mut batch,&request.source_slots)))?);
    }
    let states:Vec<_>=sources.iter().map(|s|s.state).collect();
    let source_authentication=batch.prove(parent,&states).map_err(convert)?;
    Ok(Proof {lookups,source_authentication})
}
/// Check lookup algebra and every derived source obligation using public roots.
pub fn verify<F,EF,H,C>(parent:&mut Transcript<F>,helper:&Parameters<C>,
    sources:&[VerifierOracle<'_,H::Output,C>],requests:&[Request<F>],proof:&Proof<F,EF,H::Output>)
    ->Result<(),Error>
where F:PrimeField+Serialize,EF:AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    if proof.lookups.len()!=requests.len() {return Err(error("deferred lookup proof count"));}
    preflight::<F,EF,H,C>(parent,helper,sources.len(),requests)?;
    let mut batch=OpeningBatch::<F,H,C>::new(parent,sources).map_err(convert)?;
    for (request,lookup) in requests.iter().zip(&proof.lookups) {
        let local:Vec<_>=request.source_slots.iter().map(|&i|VerifierOracle {
            parameters:sources[i].parameters,commitment:sources[i].commitment}).collect();
        super::verify_inner::<F,EF,H,C>(parent,&request.config,helper,&local,lookup,true,
            Some((&mut batch,&request.source_slots)))?;
    }
    batch.verify(parent,&proof.source_authentication).map_err(convert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::NTTField;
    use pcs::utils::code::BlockReedSolomonCode;
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    fn forged<F,EF>(k:usize)
    where F:NTTField+Serialize+DeserializeOwned,
          EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
    {
        let mu=2;
        let size=(1<<mu)*k;
        let pp=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu,k,64,2).unwrap();
        let helper=Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(mu+k.ilog2() as usize,k,64,2).unwrap();
        let fake=PackedTable::new(mu,k,vec![F::zero();size]).unwrap();
        let requests=vec![Request {config:Config::new(size,vec![vec![F::zero()],vec![F::from(2usize)]],1).unwrap(),source_slots:vec![0]}];
        for bad in [false,true] {
            let actual=PackedTable::new(mu,k,vec![if bad {F::one()} else {F::zero()};size]).unwrap();
            let (root,state)=pp.commit::<F,Sha256>(&actual).unwrap();
            let source=ProverOracle {parameters:&pp,commitment:&root,state:&state,table:&actual};
            let public=[source.verifier()];
            let mut prover=Transcript::new_direct();
            preflight::<F,EF,Sha256,_>(&mut prover,&helper,1,&requests).unwrap();
            let mut batch=OpeningBatch::<F,Sha256,_>::new(&mut prover,&public).unwrap();
            let lookup=super::super::prove_inner::<F,EF,Sha256,_>(&mut prover,&requests[0].config,&helper,
                &[&source],&[&fake],&mut ProverStatistics::default(),!bad,Some((&mut batch,&[0]))).unwrap();
            let source_authentication=batch.prove(&mut prover,&[&state]).unwrap();
            let proof=Proof {lookups:vec![lookup],source_authentication};
            let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
            let (proof,used):(Proof<F,EF,[u8;32]>,_)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
            assert_eq!(used,bytes.len());
            // Local replay checks every child and genuine deferred opening,
            // skipping only the intended false public reciprocal equation.
            let mut reference=Transcript::new_direct();
            preflight::<F,EF,Sha256,_>(&mut reference,&helper,1,&requests).unwrap();
            let mut expected=OpeningBatch::<F,Sha256,_>::new(&mut reference,&public).unwrap();
            super::super::verify_inner::<F,EF,Sha256,_>(&mut reference,&requests[0].config,&helper,&public,
                &proof.lookups[0],false,Some((&mut expected,&[0]))).unwrap();
            expected.verify(&mut reference,&proof.source_authentication).unwrap();
            assert_eq!(prover.get_challenge(b"after genuine deferred children"),reference.get_challenge(b"after genuine deferred children"));
            let result=verify::<F,EF,Sha256,_>(&mut Transcript::new_direct(),&helper,&public,&requests,&proof);
            if bad {assert_eq!(result.unwrap_err().0,"terminal reciprocal identity");} else {result.unwrap();}
        }
    }
    #[test] fn babybear_genuine_deferred_false_source_rejects(){forged::<algebra::BabyBear,algebra::BabyBearExtension6>(8);}
    #[test] fn goldilocks_genuine_deferred_false_source_rejects(){forged::<algebra::Goldilocks,algebra::GoldilocksExtension3>(4);}
}
