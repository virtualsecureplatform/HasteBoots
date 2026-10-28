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
        context: H::Output,
    ) -> Transcript<EF> {
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
        self.open_aggregated_context::<H>(
            parent,
            commitment,
            state,
            queries,
            values,
            self.context_digest::<H>(),
        )
    }
    fn open_aggregated_context<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        state: &State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        context: H::Output,
    ) -> Result<Proof<EF, H::Output>, Error> {
        let (queries, values) = self.claims(queries, values)?;
        let mut session = self.opening_session::<H>(commitment, state, &queries, &values)?;
        let mut child = self.begin_aggregated::<H>(
            parent,
            &commitment.root,
            &queries,
            &values,
            session.spent(),
            context,
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
        self.verify_aggregated_context::<H>(
            parent,
            commitment,
            queries,
            values,
            proof,
            self.context_digest::<H>(),
        )
    }
    fn verify_aggregated_context<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<EF, H::Output>,
        context: H::Output,
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
        let mut child = self.begin_aggregated::<H>(
            parent,
            &commitment.root,
            &queries,
            &values,
            proof.first,
            context,
        );
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

/// Trusted canonical backend selecting aggregated query-ladder proximity. There is
/// no proof-deserializable backend selector; independent parameters stay distinct.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F, EF> {
    independent: super::Parameters<F, EF>,
}
impl<F, EF> Parameters<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    /// Regenerate source codewords once per batch and discard them afterward.
    /// This memory policy changes no trusted context or proof format.
    pub fn with_transient_source_values(mut self) -> Self {
        self.independent = self.independent.with_transient_source_values();
        self
    }
    /// Validate the same logical/physical geometry and per-query mask lifetime.
    pub fn new(
        logical_vars: usize,
        width: usize,
        physical_vars: usize,
        blowup: usize,
        queries: usize,
        max_openings: usize,
    ) -> Result<Self, Error> {
        Ok(Self::from_independent(super::Parameters::new(
            logical_vars,
            width,
            physical_vars,
            blowup,
            queries,
            max_openings,
        )?))
    }
    /// Select aggregated opening behavior for an already validated trusted geometry.
    /// Commitment data and private lifetime semantics are unchanged.
    pub fn from_independent(independent: super::Parameters<F, EF>) -> Self {
        Self { independent }
    }
    /// The identical trusted geometry using independent opening packets.
    pub fn independent_parameters(&self) -> &super::Parameters<F, EF> {
        &self.independent
    }
    /// Number of logical Boolean cell variables.
    pub fn num_vars(&self) -> usize {
        self.independent.num_vars()
    }
    /// Consecutive lanes per Boolean cell.
    pub fn width(&self) -> usize {
        self.independent.width()
    }
    /// Physical dimension before the private high-variable padding.
    pub fn physical_vars(&self) -> usize {
        self.independent.physical_vars()
    }
    /// Per-query lifetime allowance shared by all APIs on one retained source.
    pub fn max_openings(&self) -> usize {
        self.independent.max_openings()
    }
    /// Distinct complete canonical context, including the selected aggregated backend.
    pub fn context_digest<H: Hash>(&self) -> H::Output {
        hash::<H, _>(&(
            b"aggregated-query masked canonical matrix parameters v1".as_slice(),
            self,
        ))
    }
    pub(crate) fn claims(
        &self,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<(Vec<Vec<MatrixPair<F>>>, Vec<Vec<F>>), Error> {
        self.independent.claims(queries, values)
    }
    /// Retain the same original source owner; no mask refresh or auxiliary root.
    pub fn commit<H: Hash + Send + Sync, R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        rng: &mut R,
    ) -> Result<(Commitment<H::Output>, State<F, EF, H>), Error> {
        self.independent.commit::<H, R>(table, rng)
    }
    /// Authenticate ordered claims with shared source/query-ladder certificates and the canonical context.
    pub fn open_many<H: Hash + Send + Sync>(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<EF, H::Output>, Error> {
        self.independent.open_aggregated_context::<H>(
            t,
            root,
            state,
            queries,
            values,
            self.context_digest::<H>(),
        )
    }
    /// Verify ordered claims using the trusted canonical backend context and root.
    pub fn verify_many<H: Hash + Send + Sync>(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<EF, H::Output>,
    ) -> Result<(), Error> {
        self.independent.verify_aggregated_context::<H>(
            t,
            root,
            queries,
            values,
            proof,
            self.context_digest::<H>(),
        )
    }
}
