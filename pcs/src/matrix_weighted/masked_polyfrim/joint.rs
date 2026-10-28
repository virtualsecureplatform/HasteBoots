//! Base-field matrix adapter for explicit joint original-source proximity.
//! The retained source and lifetime are shared with the independent API. The
//! parent/child opening domains are distinct, and no proof selects this API.
use super::*;

/// One shared source certificate plus independently checked masked ladders.
pub type Proof<EF, O> = core::joint::Proof<EF, O>;

impl<F, EF> super::Parameters<F, EF>
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
        context: H::Output,
    ) -> Transcript<EF> {
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
        self.open_joint_context::<H>(
            parent,
            commitment,
            state,
            queries,
            values,
            self.context_digest::<H>(),
        )
    }
    fn open_joint_context<H: Hash + Send + Sync>(
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
        let mut child = self.begin_joint::<H>(
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
        self.verify_joint_context::<H>(
            parent,
            commitment,
            queries,
            values,
            proof,
            self.context_digest::<H>(),
        )
    }
    fn verify_joint_context<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<EF, H::Output>,
        context: H::Output,
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
        let mut child = self.begin_joint::<H>(
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

/// Trusted canonical backend selecting joint original-source proximity. There is
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
    /// Select joint opening behavior for an already validated trusted geometry.
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
    /// Distinct complete canonical context, including the selected joint backend.
    pub fn context_digest<H: Hash>(&self) -> H::Output {
        hash::<H, _>(&(
            b"joint-source masked canonical matrix parameters v1".as_slice(),
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
    /// Authenticate ordered claims with one source certificate and the canonical context.
    pub fn open_many<H: Hash + Send + Sync>(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<EF, H::Output>, Error> {
        self.independent.open_joint_context::<H>(
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
        self.independent.verify_joint_context::<H>(
            t,
            root,
            queries,
            values,
            proof,
            self.context_digest::<H>(),
        )
    }
}
