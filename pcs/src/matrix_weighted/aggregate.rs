//! Multi-root common-query aggregation; non-hiding and experimental.
//!
//! All roots and individual claims precede full-coordinate extension weights.
//! A joint random linear test checks the concatenated committed row matrix.
//! Every source column remains authenticated; no combined root is trusted.
//! This is a PCS component, not complete-PBS aggregation or an FS certificate.
use super::*;
/// Authenticate repeated canonical roots once at a shared query.
pub mod canonical;
use algebra::AbstractExtensionField;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// One joint row test and one extension-weighted structured response.
pub struct Proof<F, EF, O> {
    /// Base-field random response for all source rows concatenated together.
    pub test: Vec<F>,
    /// Scalar extension combination of the per-root structured responses.
    pub evaluation: Vec<EF>,
    /// Root-major; each inner vector follows the common sorted sample indices.
    pub columns: Vec<Vec<Column<F, O>>>,
}

fn bind<F, EF, H, C>(pp: &Parameters<C>, trans: &mut Transcript<F>,
    roots: &[Commitment<H::Output>], query: &[MatrixPair<F>], values: &[Vec<F>],
) -> Result<Vec<EF>, Error>
where F: PrimeField + Serialize, EF: AbstractExtensionField<F> + Serialize,
      H: Hash, C: RowCode<F> + Serialize,
{
    if roots.is_empty() || roots.len() != values.len() || EF::D == 0
        || query.len() != pp.num_vars || values.iter().any(|v| v.len() != pp.width) {
        return Err(Error("aggregate root/query/value dimensions"));
    }
    for pair in query {
        pair.validate(pp.width).map_err(|_| Error("invalid aggregate matrix"))?;
    }
    let basis: Vec<EF> = (0..EF::D).map(|i| EF::from_base_fn(|j|
        if i == j { F::one() } else { F::zero() })).collect();
    let products: Vec<Vec<F>> = basis.iter().flat_map(|&a|
        basis.iter().map(move |&b| (a*b).as_base_slice().to_vec())).collect();
    trans.append_message(b"mw multi-root common-query v1",
        &(pp.context_digest::<F,H>()?, EF::D, products, roots, query, values));
    let count = roots.len().checked_mul(EF::D).ok_or(Error("aggregate weight overflow"))?;
    let coefficients = trans.get_vec_challenge(b"mw aggregate extension weights", count);
    Ok(coefficients.chunks_exact(EF::D).map(EF::from_base_slice).collect())
}

fn combined_claim<F: PrimeField, EF: AbstractExtensionField<F>>(
    width: usize, weights: &[EF], values: &[Vec<F>],
) -> Vec<EF> {
    (0..width).map(|lane| weights.iter().zip(values)
        .fold(EF::zero(), |sum,(&a,v)| sum+a*v[lane])).collect()
}

fn finish<F, EF, C>(pp: &Parameters<C>, query: &[MatrixPair<F>], response: &[EF])
    -> Result<Vec<EF>, Error>
where F: PrimeField, EF: AbstractExtensionField<F>, C: RowCode<F>,
{
    let coordinates: Vec<Vec<F>> = (0..EF::D).map(|j| {
        let base: Vec<_> = response.iter().map(|v| v.as_base_slice()[j]).collect();
        pp.finish(query,&base)
    }).collect::<Result<_,_>>()?;
    Ok((0..pp.width).map(|lane|
        EF::from_base_fn(|j| coordinates[j][lane])).collect())
}

fn encode<F, EF, C>(pp: &Parameters<C>, response: &[EF]) -> Vec<Vec<F>>
where F: PrimeField, EF: AbstractExtensionField<F>, C: RowCode<F>,
{
    (0..EF::D).map(|j| pp.encode_responses(&response.iter()
        .map(|v| v.as_base_slice()[j]).collect::<Vec<_>>())).collect()
}

/// Prove one common query against ordered roots with fixed individual claims.
pub fn prove<F, EF, H, C>(pp: &Parameters<C>, trans: &mut Transcript<F>,
    roots: &[Commitment<H::Output>], states: &[&State<F,H>],
    query: &[MatrixPair<F>], values: &[Vec<F>],
) -> Result<Proof<F,EF,H::Output>, Error>
where F: PrimeField + Serialize, EF: AbstractExtensionField<F> + Serialize,
      H: Hash + Send + Sync, C: RowCode<F> + Serialize,
{
    let rows = (1usize << pp.left_vars)*pp.width;
    let stride = pp.code.codeword_blocks()*pp.code.block_width();
    if states.len() != roots.len() { return Err(Error("aggregate state count")); }
    let context = pp.context_digest::<F,H>()?;
    for (state,root) in states.iter().zip(roots) {
        if state.parameter_digest != context || state.tree.root != root.root
            || state.table.num_vars() != pp.num_vars || state.table.width() != pp.width
            || state.encoded.len() != rows*stride {
            return Err(Error("aggregate state/root mismatch"));
        }
    }
    let total_rows = rows.checked_mul(roots.len()).ok_or(Error("aggregate row overflow"))?;
    let random_len = total_rows.checked_mul(pp.width).ok_or(Error("aggregate random overflow"))?;
    let weights = bind::<F,EF,H,C>(pp,trans,roots,query,values)?;
    let random = trans.get_vec_challenge(b"mw aggregate joint random test",random_len);
    let structured = pp.structured(query)?;
    let size = pp.width*pp.code.message_len();
    let mut test = vec![F::zero();size];
    let mut evaluation = vec![EF::zero();size];
    for (i,state) in states.iter().enumerate() {
        let local: Vec<_> = (0..pp.width).flat_map(|lane|
            random[lane*total_rows+i*rows..lane*total_rows+(i+1)*rows].iter().copied()).collect();
        let t = pp.aggregate(&state.table,&local);
        let e = pp.aggregate(&state.table,&structured);
        for j in 0..size { test[j] += t[j]; evaluation[j] += weights[i]*e[j]; }
    }
    if finish(pp,query,&evaluation)? != combined_claim(pp.width,&weights,values) {
        return Err(Error("incorrect aggregate claim"));
    }
    trans.append_message(b"mw aggregate responses",&(&test,&evaluation));
    let indices = sample_columns(trans,pp.code.codeword_blocks(),pp.queries);
    let block = pp.code.block_width();
    let columns = states.iter().map(|state| indices.iter().map(|&index| Column {
        values: (0..rows).flat_map(|row|
            state.encoded[row*stride+index*block..row*stride+(index+1)*block].iter().copied()).collect(),
        path: state.tree.query(index),
    }).collect()).collect();
    Ok(Proof { test,evaluation,columns })
}

/// Verify without source tables or states; authenticate every root's columns.
pub fn verify<F, EF, H, C>(pp: &Parameters<C>, trans: &mut Transcript<F>,
    roots: &[Commitment<H::Output>], query: &[MatrixPair<F>], values: &[Vec<F>],
    proof: &Proof<F,EF,H::Output>,
) -> Result<(),Error>
where F: PrimeField + Serialize, EF: AbstractExtensionField<F> + Serialize,
      H: Hash + Send + Sync, C: RowCode<F> + Serialize,
{
    let rows = (1usize << pp.left_vars)*pp.width;
    let n = pp.code.codeword_blocks();
    let block = pp.code.block_width();
    let stride = n*block;
    let path_len = n.next_power_of_two().ilog2() as usize+1;
    let size = pp.width*pp.code.message_len();
    if proof.test.len() != size || proof.evaluation.len() != size
        || proof.columns.len() != roots.len() || proof.columns.iter().any(|columns|
            columns.is_empty() || columns.len() > pp.queries.min(n) || columns.iter().any(|c|
                c.values.len() != rows*block || c.path.len() != path_len)) {
        return Err(Error("malformed aggregate opening"));
    }
    let total_rows = rows.checked_mul(roots.len()).ok_or(Error("aggregate row overflow"))?;
    let random_len = total_rows.checked_mul(pp.width).ok_or(Error("aggregate random overflow"))?;
    let weights = bind::<F,EF,H,C>(pp,trans,roots,query,values)?;
    let random = trans.get_vec_challenge(b"mw aggregate joint random test",random_len);
    let structured = pp.structured(query)?;
    trans.append_message(b"mw aggregate responses",&(&proof.test,&proof.evaluation));
    let indices = sample_columns(trans,n,pp.queries);
    if proof.columns.iter().any(|c| c.len()!=indices.len()) {
        return Err(Error("aggregate distinct column count"));
    }
    let test = pp.encode_responses(&proof.test);
    let evaluation = encode(pp,&proof.evaluation);
    indices.par_iter().enumerate().try_for_each(|(j,&index)| {
        for (i,root) in roots.iter().enumerate() {
            let column = &proof.columns[i][j];
            if column.path[0] != hash_column::<F,H>(&column.values)
                || !MerkleTree::<H>::check(&root.root,index,&column.path) {
                return Err(Error("invalid aggregate column authentication"));
            }
        }
        for lane in 0..pp.width {
            for coordinate in 0..block {
                let mut t = F::zero();
                let mut e = EF::zero();
                for i in 0..roots.len() {
                    let column = &proof.columns[i][j].values;
                    let mut local = F::zero();
                    for row in 0..rows {
                        let value = column[row*block+coordinate];
                        t += random[lane*total_rows+i*rows+row]*value;
                        local += structured[lane*rows+row]*value;
                    }
                    e += weights[i]*local;
                }
                let at = lane*stride+index*block+coordinate;
                if t != test[at] || (0..EF::D).any(|d| e.as_base_slice()[d]!=evaluation[d][at]) {
                    return Err(Error("aggregate linear response inconsistent with columns"));
                }
            }
        }
        Ok(())
    })?;
    if finish(pp,query,&proof.evaluation)? != combined_claim(pp.width,&weights,values) {
        return Err(Error("aggregate response inconsistent with claims"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::matrix_weighted::Matrix;
    use sha2::Sha256;

    fn malicious<F,EF>(k: usize)
    where F: NTTField+Serialize, EF: AbstractExtensionField<F>+Serialize,
    {
        let n=1+k.ilog2() as usize;
        let code=BlockReedSolomonCode::<F>::new(k,k,2).unwrap();
        let pp=Parameters::new_encoded::<F>(n,k,1,128,code).unwrap();
        let rows=2*k;
        let length=pp.code.codeword_blocks();
        assert_eq!(length,32);
        for far in [false,true] {
            // Either a coded zero word with a false claim, or a genuinely
            // committed half-zero/half-one row, farther than t=10 from RS.
            let columns: Vec<Vec<Vec<F>>>=(0..2).map(|root| (0..length).map(|j| {
                let mut v=vec![F::zero();rows*k];
                if far && root==0 && j<length/2 { v[0]=F::one(); }
                v
            }).collect()).collect();
            let trees: Vec<_>=columns.iter().map(|columns| {
                let mut tree=MerkleTree::<Sha256>::new();
                tree.generate(&columns.iter().map(|v|hash_column::<F,Sha256>(v)).collect::<Vec<_>>());
                tree
            }).collect();
            let roots: Vec<_>=trees.iter().map(|t|Commitment {root:t.root}).collect();
            let zero=Matrix::new(k,vec![F::zero();k*k]).unwrap();
            let query: Vec<_>=(0..n).map(|_|MatrixPair {
                zero:if far {zero.clone()} else {Matrix::identity(k).unwrap()},
                one:zero.clone(),
            }).collect();
            let mut values=vec![vec![F::zero();k];2];
            if !far { values[0][0]=F::one(); }
            let mut prover=Transcript::new_direct();
            let weights=bind::<F,EF,Sha256,_>(&pp,&mut prover,&roots,&query,&values).unwrap();
            assert!(weights[0]!=EF::zero());
            let random=prover.get_vec_challenge(b"mw aggregate joint random test",k*rows*2);
            assert!((0..k).any(|lane|random[lane*rows*2]!=F::zero()));
            let test=vec![F::zero();k*k];
            let mut evaluation=vec![EF::zero();k*k];
            if !far { evaluation[0]=weights[0]; }
            assert_eq!(finish(&pp,&query,&evaluation).unwrap(),combined_claim(k,&weights,&values));
            prover.append_message(b"mw aggregate responses",&(&test,&evaluation));
            let indices=sample_columns(&mut prover,length,128);
            assert!(indices.iter().any(|&j|j<length/2));
            let opened: Vec<_>=trees.iter().enumerate().map(|(i,t)|indices.iter().map(|&j| {
                let path=t.query(j);
                assert!(MerkleTree::<Sha256>::check(&roots[i].root,j,&path));
                assert_eq!(path[0],hash_column::<F,Sha256>(&columns[i][j]));
                Column {values:columns[i][j].clone(),path}
            }).collect()).collect();
            let proof=Proof {test,evaluation,columns:opened};
            let mut verifier=Transcript::new_direct();
            let error=verify::<F,EF,Sha256,_>(&pp,&mut verifier,&roots,&query,&values,&proof).unwrap_err();
            assert_eq!(error.0,"aggregate linear response inconsistent with columns");
            assert_eq!(prover.get_challenge(b"after malicious aggregate"),verifier.get_challenge(b"after malicious aggregate"));
        }
    }
    #[test]
    fn babybear_genuine_false_aggregate_responses() {
        malicious::<algebra::BabyBear,algebra::BabyBearExtension6>(8);
    }
    #[test]
    fn goldilocks_genuine_false_aggregate_responses() {
        malicious::<algebra::Goldilocks,algebra::GoldilocksExtension3>(4);
    }
}
