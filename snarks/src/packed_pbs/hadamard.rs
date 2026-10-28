use super::*;
use algebra::AbstractExtensionField;

pub(super) trait Backend<F:NTTField+Serialize,H:Hash+Send+Sync,C:RowCode<F>+Serialize> {
    type Proof;
    const AGGREGATED:bool;
    const BATCHED:bool=false;
    fn prove(trans:&mut Transcript<F>,shape:&PackedShape<F>,pp:&PcsParameters<C>,
        factors:&[PackedTable<F>],roots:&[Commitment<H::Output>],states:&[&State<F,H>]) -> Result<Self::Proof,Error>;
    fn verify(trans:&mut Transcript<F>,pp:&PcsParameters<C>,key:&bk::PublicKey<H::Output>,
        private:&[Commitment<H::Output>],proof:&Self::Proof)->Result<(),Error>;
}
pub(super) struct Independent;
pub(super) struct Aggregated<EF>(std::marker::PhantomData<EF>);
impl<F,H,C> Backend<F,H,C> for Independent
where F:NTTField+Serialize,H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    type Proof=relation::RelationProof<F,H::Output>;
    const AGGREGATED:bool=false;
    fn prove(trans:&mut Transcript<F>,shape:&PackedShape<F>,pp:&PcsParameters<C>,
        factors:&[PackedTable<F>],roots:&[Commitment<H::Output>],states:&[&State<F,H>])->Result<Self::Proof,Error> {
        relation::prove_with_state_references::<F,H,C>(trans,shape,pp,factors,roots,states,
            &mut relation::ProverStatistics::default()).map_err(convert)
    }
    fn verify(trans:&mut Transcript<F>,pp:&PcsParameters<C>,key:&bk::PublicKey<H::Output>,
        private:&[Commitment<H::Output>],proof:&Self::Proof)->Result<(),Error> {
        bk::verify::<F,H,C>(trans,pp,key,private,proof).map_err(convert)
    }
}
impl<F,EF,H,C> Backend<F,H,C> for Aggregated<EF>
where F:NTTField+Serialize,EF:AbstractExtensionField<F>+Serialize,
      H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    type Proof=relation::aggregate::Proof<F,EF,H::Output>;
    const AGGREGATED:bool=true;
    fn prove(trans:&mut Transcript<F>,shape:&PackedShape<F>,pp:&PcsParameters<C>,
        factors:&[PackedTable<F>],roots:&[Commitment<H::Output>],states:&[&State<F,H>])->Result<Self::Proof,Error> {
        relation::aggregate::prove_with_state_references::<F,EF,H,C>(trans,shape,pp,factors,roots,states,
            &mut relation::ProverStatistics::default()).map_err(convert)
    }
    fn verify(trans:&mut Transcript<F>,pp:&PcsParameters<C>,key:&bk::PublicKey<H::Output>,
        private:&[Commitment<H::Output>],proof:&Self::Proof)->Result<(),Error> {
        let roots=bk::commitments::<F,H,C>(pp,key,private).map_err(convert)?;
        let shape=hadamard_shape(pp,key.roots().len());
        relation::aggregate::verify::<F,EF,H,C>(trans,&shape,pp,&roots,proof).map_err(convert)
    }
}

// Private marker backend. No public standalone verifier selects this backend:
// packed_pbs::batch always discharges the omitted relation with its joint proof.
pub(super) struct Batched;
impl<F,H,C> Backend<F,H,C> for Batched
where F:NTTField+Serialize,H:Hash+Send+Sync,C:RowCode<F>+Serialize,
{
    type Proof=();
    const AGGREGATED:bool=true;
    const BATCHED:bool=true;
    fn prove(trans:&mut Transcript<F>,_shape:&PackedShape<F>,_pp:&PcsParameters<C>,
        _factors:&[PackedTable<F>],_roots:&[Commitment<H::Output>],_states:&[&State<F,H>])->Result<(),Error> {
        trans.append_message(b"packed PBS joint batch Hadamard obligation",&());Ok(())
    }
    fn verify(trans:&mut Transcript<F>,_pp:&PcsParameters<C>,_key:&bk::PublicKey<H::Output>,
        _private:&[Commitment<H::Output>],_proof:&())->Result<(),Error> {
        trans.append_message(b"packed PBS joint batch Hadamard obligation",&());Ok(())
    }
}
