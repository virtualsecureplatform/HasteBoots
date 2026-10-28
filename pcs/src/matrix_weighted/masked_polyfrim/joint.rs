//! Base-field matrix adapter for explicit joint original-source proximity.
//! The retained source and lifetime are shared with the independent API. The
//! parent/child opening domains are distinct, and no proof selects this API.
use super::*;

/// One shared source certificate plus independently checked masked ladders.
pub type Proof<EF, O> = core::joint::Proof<EF, O>;

impl<F, EF> Parameters<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    fn begin_joint<H: Hash>(
        &self,
        parent: &mut Transcript<F>,
        root: &H::Output,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        first: usize,
    ) -> Transcript<EF> {
        let context = self.context_digest::<H>();
        parent.append_message(
            b"masked packed matrix joint ordered claims v1",
            &(context, root, queries, values, first),
        );
        let mut seed = [0u8; 32];
        parent.get_challenge_bytes(b"masked packed matrix joint child seed v1", &mut seed);
        let mut child = Transcript::new_direct_extension::<F>();
        child.append_message(
            b"masked packed matrix joint child v1",
            &(context, root, queries, values, first, seed),
        );
        child
    }
    /// Reserve one allowance per claim from the original locked lifetime and
    /// share only original-source proximity. Full query aggregation remains open.
    pub fn open_many_joint<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        state: &State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<EF, H::Output>, Error> {
        let (queries, values) = self.claims(queries, values)?;
        let mut session = self.opening_session::<H>(commitment, state, &queries, &values)?;
        let mut child =
            self.begin_joint::<H>(parent, &commitment.root, &queries, &values, session.spent());
        let extended: Vec<_> = queries.iter().map(|q| self.extend(q)).collect();
        let claims: Vec<Vec<_>> = values
            .iter()
            .map(|v| v.iter().copied().map(EF::from_base).collect())
            .collect();
        let proof = core::joint::prove(&mut child, &self.inner, &mut session, &extended, &claims)
            .map_err(|_| Error("masked joint opening"))?;
        finish_joint(parent, &mut child);
        Ok(proof)
    }
    /// Verify every caller-derived ordered obligation against the expected root,
    /// with one original-source certificate for the entire nonempty batch.
    pub fn verify_many_joint<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<EF, H::Output>,
    ) -> Result<(), Error> {
        let (queries, values) = self.claims(queries, values)?;
        if proof.responses.len() != queries.len() {
            return Err(Error("opening packet count"));
        }
        if proof
            .first
            .checked_add(queries.len())
            .is_none_or(|n| n > self.max_openings())
            || proof
                .responses
                .iter()
                .enumerate()
                .any(|(i, p)| p.index != proof.first + i)
        {
            return Err(Error("opening index schedule"));
        }
        let mut child =
            self.begin_joint::<H>(parent, &commitment.root, &queries, &values, proof.first);
        let extended: Vec<_> = queries.iter().map(|q| self.extend(q)).collect();
        let claims: Vec<Vec<_>> = values
            .iter()
            .map(|v| v.iter().copied().map(EF::from_base).collect())
            .collect();
        core::joint::verify::<EF, H>(
            &mut child,
            &self.inner,
            &commitment.root,
            &extended,
            &claims,
            proof,
        )
        .map_err(|_| Error("masked joint verification"))?;
        finish_joint(parent, &mut child);
        Ok(())
    }
}
fn finish_joint<F: Field, EF: Field>(parent: &mut Transcript<F>, child: &mut Transcript<EF>) {
    let mut digest = [0u8; 32];
    child.get_challenge_bytes(b"masked packed matrix joint child finish v1", &mut digest);
    parent.append_message(b"masked packed matrix verified joint child v1", &digest);
}
