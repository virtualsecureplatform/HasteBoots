//! Explicit base-field adapter for jointly authenticated masked query ladders.
//! All opening APIs share one retained source lifetime and trusted geometry.
use super::*;

/// Original-source FRI and one joint query-ladder FRI, with strict source paths.
pub type Proof<EF, O> = core::aggregated::Proof<EF, O>;
impl<F, EF> super::Parameters<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    fn begin_aggregated<H: Hash>(
        &self,
        parent: &mut Transcript<F>,
        root: &H::Output,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        first: usize,
    ) -> Transcript<EF> {
        let context = self.context_digest::<H>();
        parent.append_message(
            b"masked matrix aggregated ordered claims v1",
            &(context, root, queries, values, first),
        );
        let mut seed = [0u8; 32];
        parent.get_challenge_bytes(b"masked matrix aggregated child seed v1", &mut seed);
        let mut child = Transcript::new_direct_extension::<F>();
        child.append_message(
            b"masked matrix aggregated child v1",
            &(context, root, queries, values, first, seed),
        );
        child
    }
    /// Preflight and reserve one allowance per claim on the original locked
    /// source, sharing both source and masked query-ladder proximity certificates.
    pub fn open_many_aggregated<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        state: &State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<EF, H::Output>, Error> {
        let (queries, values) = self.claims(queries, values)?;
        let mut session = self.opening_session::<H>(commitment, state, &queries, &values)?;
        let mut child = self.begin_aggregated::<H>(
            parent,
            &commitment.root,
            &queries,
            &values,
            session.spent(),
        );
        let extended: Vec<_> = queries.iter().map(|q| self.extend(q)).collect();
        let claims: Vec<Vec<_>> = values
            .iter()
            .map(|v| v.iter().copied().map(EF::from_base).collect())
            .collect();
        let proof =
            core::aggregated::prove(&mut child, &self.inner, &mut session, &extended, &claims)
                .map_err(|_| Error("masked aggregated opening"))?;
        finish(parent, &mut child);
        Ok(proof)
    }
    /// Verify every ordered claim against the caller's expected original root.
    /// No packet selects this API or changes its trusted physical geometry.
    pub fn verify_many_aggregated<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<EF, H::Output>,
    ) -> Result<(), Error> {
        let (queries, values) = self.claims(queries, values)?;
        if proof.mask_claims.len() != queries.len()
            || proof.inner.consistency.len() != queries.len()
            || proof
                .first
                .checked_add(queries.len())
                .is_none_or(|n| n > self.max_openings())
        {
            return Err(Error("aggregated opening schedule"));
        }
        let mut child =
            self.begin_aggregated::<H>(parent, &commitment.root, &queries, &values, proof.first);
        let extended: Vec<_> = queries.iter().map(|q| self.extend(q)).collect();
        let claims: Vec<Vec<_>> = values
            .iter()
            .map(|v| v.iter().copied().map(EF::from_base).collect())
            .collect();
        core::aggregated::verify::<EF, H>(
            &mut child,
            &self.inner,
            &commitment.root,
            &extended,
            &claims,
            proof,
        )
        .map_err(|_| Error("masked aggregated verification"))?;
        finish(parent, &mut child);
        Ok(())
    }
}
fn finish<F: Field, EF: Field>(parent: &mut Transcript<F>, child: &mut Transcript<EF>) {
    let mut digest = [0u8; 32];
    child.get_challenge_bytes(b"masked matrix aggregated child finish v1", &mut digest);
    parent.append_message(b"masked matrix verified aggregated child v1", &digest);
}
