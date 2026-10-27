//! A packed relation with one multi-root terminal authentication packet.
//! Non-hiding; not a complete PBS proof or a whole-security certificate.
use super::*;
use algebra::AbstractExtensionField;
use pcs::matrix_weighted::aggregate as pcs_aggregate;

/// Packed ZeroCheck plus aggregated authentication of all terminal factors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, EF, O> {
    /// Algebraic proof with a common ordered terminal matrix query.
    pub zero: ZeroProof<F>,
    /// Individual factor claims, fixed before aggregation weights.
    pub values: Vec<Vec<F>>,
    /// One shared multi-root PCS proof against the caller's canonical roots.
    pub opening: pcs_aggregate::Proof<F, EF, O>,
}

fn bind<F, EF, H, C>(trans: &mut Transcript<F>, shape: &PackedShape<F>,
    parameters: &Parameters<C>, commitments: &[Commitment<H::Output>],
) -> Result<(), Error>
where F: PrimeField+Serialize, EF: AbstractExtensionField<F>,
      H: Hash, C: RowCode<F>+Serialize,
{
    shape.validate().map_err(convert)?;
    if parameters.num_vars()!=shape.num_vars || parameters.width()!=shape.width
        || commitments.len()!=shape.num_factors || EF::D==0 {
        return Err(Error("aggregate relation parameter/root dimensions".into()));
    }
    trans.append_message(b"HasteBoots packed aggregated relation v1",
        &(shape,parameters.context_digest::<F,H>().map_err(convert)?,EF::D,commitments));
    Ok(())
}

/// Prove using canonical factor states, retaining individual terminal claims.
pub fn prove<F, EF, H, C>(trans: &mut Transcript<F>, shape: &PackedShape<F>,
    parameters: &Parameters<C>, factors: &[PackedTable<F>],
    commitments: &[Commitment<H::Output>], states: &[State<F,H>],
) -> Result<Proof<F,EF,H::Output>,Error>
where F: PrimeField+Serialize, EF: AbstractExtensionField<F>+Serialize,
      H: Hash+Send+Sync, C: RowCode<F>+Serialize,
{
    prove_with_state_references::<F,EF,H,C>(trans,shape,parameters,factors,commitments,
        &states.iter().collect::<Vec<_>>(),&mut ProverStatistics::default())
}

/// Reuse states owned by witness and public-key setup without cloning them.
pub fn prove_with_state_references<F, EF, H, C>(trans: &mut Transcript<F>,
    shape: &PackedShape<F>, parameters: &Parameters<C>, factors: &[PackedTable<F>],
    commitments: &[Commitment<H::Output>], states: &[&State<F,H>],
    statistics: &mut ProverStatistics,
) -> Result<Proof<F,EF,H::Output>,Error>
where F: PrimeField+Serialize, EF: AbstractExtensionField<F>+Serialize,
      H: Hash+Send+Sync, C: RowCode<F>+Serialize,
{
    if states.len()!=shape.num_factors || factors.len()!=shape.num_factors
        || factors.iter().any(|t|t.num_vars()!=shape.num_vars || t.width()!=shape.width) {
        return Err(Error("aggregate relation factor/state dimensions".into()));
    }
    bind::<F,EF,H,C>(trans,shape,parameters,commitments)?;
    let timer=Instant::now();
    let (zero,subclaim,values)=packed_zero::prove_with_terminal_values(trans,shape,factors).map_err(convert)?;
    statistics.zero_check+=timer.elapsed();
    let timer=Instant::now();
    subclaim.check(shape,&values).map_err(convert)?;
    statistics.terminal_evaluation+=timer.elapsed();
    trans.append_message(b"packed aggregated relation terminal values",&values);
    let timer=Instant::now();
    let opening=pcs_aggregate::prove::<F,EF,H,C>(parameters,trans,commitments,states,
        &subclaim.query,&values).map_err(convert)?;
    statistics.openings+=timer.elapsed();
    Ok(Proof {zero,values,opening})
}

/// Verify the algebra and every factor's claim against canonical supplied roots.
pub fn verify<F, EF, H, C>(trans: &mut Transcript<F>, shape: &PackedShape<F>,
    parameters: &Parameters<C>, commitments: &[Commitment<H::Output>],
    proof: &Proof<F,EF,H::Output>,
) -> Result<(),Error>
where F: PrimeField+Serialize, EF: AbstractExtensionField<F>+Serialize,
      H: Hash+Send+Sync, C: RowCode<F>+Serialize,
{
    if proof.values.len()!=shape.num_factors || proof.values.iter().any(|v|v.len()!=shape.width) {
        return Err(Error("aggregate relation terminal dimensions".into()));
    }
    bind::<F,EF,H,C>(trans,shape,parameters,commitments)?;
    let subclaim=packed_zero::verify(trans,shape,&proof.zero).map_err(convert)?;
    subclaim.check(shape,&proof.values).map_err(convert)?;
    trans.append_message(b"packed aggregated relation terminal values",&proof.values);
    pcs_aggregate::verify::<F,EF,H,C>(parameters,trans,commitments,&subclaim.query,
        &proof.values,&proof.opening).map_err(convert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField,matrix_weighted::matrix_weights};
    use pcs::{matrix_weighted::Column,utils::{code::BlockReedSolomonCode,merkle_tree::MerkleTree}};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

    fn leaf<F:Serialize>(values:&[F])->[u8;32] {
        let mut h=<Sha256 as Hash>::new();
        h.update_hash_value(b"HasteBoots/mw-column/v1");
        h.update_hash_value(&bincode::serde::encode_to_vec(values,bincode::config::standard()).unwrap());
        h.output_reset()
    }
    fn forged<F,EF>(k:usize)
    where F:NTTField+Serialize+DeserializeOwned,
          EF:AbstractExtensionField<F>+Serialize+DeserializeOwned,
    {
        let n=1+k.ilog2() as usize;
        let pp=Parameters::new_encoded::<F>(n,k,1,128,BlockReedSolomonCode::<F>::new(k,k,2).unwrap()).unwrap();
        let shape=PackedShape {num_vars:n,width:k,num_factors:3,
            terms:vec![(F::one(),vec![0,1]),(-F::one(),vec![2])]};
        // Requested roots commit a=b=1,c=0: the relation is false on every row.
        // The prover's fake algebra uses a=b=c=1, satisfying the relation.
        let constants=[F::one(),F::one(),F::zero()];
        let actual:Vec<_>=constants.iter().map(|&x|PackedTable::new(n,k,vec![x;(1<<n)*k]).unwrap()).collect();
        let (roots,_):(Vec<_>,Vec<_>)=actual.iter().map(|t|pp.commit::<F,Sha256>(t).unwrap()).unzip();
        let fake=vec![PackedTable::new(n,k,vec![F::one();(1<<n)*k]).unwrap();3];
        let mut prover=Transcript::new_direct();
        bind::<F,EF,Sha256,_>(&mut prover,&shape,&pp,&roots).unwrap();
        let (zero,subclaim,values)=packed_zero::prove_with_terminal_values(&mut prover,&shape,&fake).unwrap();
        subclaim.check(&shape,&values).unwrap();
        assert!(values[2].iter().any(|&v|v!=F::zero()));
        prover.append_message(b"packed aggregated relation terminal values",&values);
        // Independently replay the public PCS binding, under these requested
        // roots/false terminal claims, rather than reuse an honest opening.
        let basis:Vec<EF>=(0..EF::D).map(|i|EF::from_base_fn(|j|if i==j {F::one()} else {F::zero()})).collect();
        let products:Vec<Vec<F>>=basis.iter().flat_map(|&a|basis.iter().map(move |&b|(a*b).as_base_slice().to_vec())).collect();
        prover.append_message(b"mw multi-root common-query v1",
            &(pp.context_digest::<F,Sha256>().unwrap(),EF::D,products,roots.as_slice(),subclaim.query.as_slice(),values.as_slice()));
        let coefficients=prover.get_vec_challenge(b"mw aggregate extension weights",3*EF::D);
        let weights:Vec<EF>=coefficients.chunks_exact(EF::D).map(EF::from_base_slice).collect();
        assert!(weights[2]!=EF::zero());
        let rows=2*k;
        let random=prover.get_vec_challenge(b"mw aggregate joint random test",k*rows*3);
        let matrices=matrix_weights(k,&subclaim.query[..1]).unwrap();
        let mut test=vec![F::zero();k*k];
        let mut evaluation=vec![EF::zero();k*k];
        let alpha=weights.iter().copied().fold(EF::zero(),|a,b|a+b);
        for lane in 0..k {
            let mut t=F::zero();
            for root in 0..3 {
                for row in 0..rows { t+=random[lane*rows*3+root*rows+row]*constants[root]; }
            }
            let s=matrices.iter().flat_map(|m|m.values()[lane*k..(lane+1)*k].iter())
                .copied().fold(F::zero(),|a,b|a+b);
            for right in 0..k { test[lane*k+right]=t; evaluation[lane*k+right]=alpha*s; }
        }
        prover.append_message(b"mw aggregate responses",&(&test,&evaluation));
        let length=pp.code().codeword_blocks();
        assert_eq!(length,32);
        let limit=u64::MAX-u64::MAX%(length as u64);
        let mut indices=Vec::new();
        while indices.len()<128 {
            let mut bytes=[0u8;8];
            prover.get_challenge_bytes(b"mw unbiased column",&mut bytes);
            let value=u64::from_le_bytes(bytes);
            if value<limit {indices.push(value as usize%length);}
        }
        indices.sort_unstable();indices.dedup();
        let columns=constants.iter().zip(&roots).map(|(&x,root)| {
            let values=vec![x;rows*k];
            let mut tree=MerkleTree::<Sha256>::new();
            tree.generate(&vec![leaf(&values);length]);
            assert_eq!(tree.root,root.root);
            indices.iter().map(|&j| {
                let path=tree.query(j);
                assert!(MerkleTree::<Sha256>::check(&root.root,j,&path));
                Column {values:values.clone(),path}
            }).collect()
        }).collect();
        let proof=Proof {zero,values,opening:pcs_aggregate::Proof {test,evaluation,columns}};
        let bytes=bincode::serde::encode_to_vec(&proof,bincode::config::standard()).unwrap();
        let (proof,used):(Proof<F,EF,[u8;32]>,_)=bincode::serde::decode_from_slice(&bytes,bincode::config::standard()).unwrap();
        assert_eq!(used,bytes.len());
        let mut verifier=Transcript::new_direct();
        let error=verify::<F,EF,Sha256,_>(&mut verifier,&shape,&pp,&roots,&proof).unwrap_err();
        assert!(error.0.contains("aggregate linear response inconsistent with columns"),"{error}");
        assert_eq!(prover.get_challenge(b"after forged relation"),verifier.get_challenge(b"after forged relation"));
    }
    #[test]
    fn babybear_genuine_aggregate_opening_of_fake_relation_rejects() {
        forged::<algebra::BabyBear,algebra::BabyBearExtension6>(8);
    }
    #[test]
    fn goldilocks_genuine_aggregate_opening_of_fake_relation_rejects() {
        forged::<algebra::Goldilocks,algebra::GoldilocksExtension3>(4);
    }
}
