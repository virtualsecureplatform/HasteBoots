//! The same ordered-matrix bridge with scalar PipFRI v2. No hiding or finite
//! opening lifetime is introduced, and no concrete security level is claimed.
use super::*;

/// Trusted geometry, field basis and shared-query scalar opening version.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F, E> {
    inner: super::Parameters<F, E>,
}
/// Retained base source and base-field scalar fragments, never proof data.
pub struct State<F, E, H: Hash + Send + Sync> {
    table: PackedTable<F>,
    scalar: pipfri::virtual_source::base::State<F, H>,
    context: H::Output,
    marker: std::marker::PhantomData<E>,
}
impl<F, E, H: Hash + Send + Sync> State<F, E, H> {
    /// Source coefficient/codeword payload bytes, excluding table/tree overhead.
    pub fn source_payload_bytes(&self) -> usize {
        self.scalar.payload_bytes()
    }
}
/// One streamed degree-two bridge and one virtual-initial scalar opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<E: Field, O> {
    sumcheck: sumcheck::Proof<E>,
    value: E,
    opening: pipfri::virtual_source::Proof<E, O>,
}
impl<F, E> Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Set scalar fragmentation and matrix geometry without asserting security.
    pub fn new(
        vars: usize,
        width: usize,
        blowup: usize,
        queries: usize,
        fragment_vars: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: super::Parameters::new(vars, width, blowup, queries, fragment_vars)?,
        })
    }
    fn context_hash<H: Hash>(&self) -> Result<H::Output, Error> {
        let bytes = bincode::serde::encode_to_vec(
            (b"fragmented virtual matrix parameters v2".as_slice(), self),
            bincode::config::standard(),
        )
        .map_err(|_| Error("virtual parameter encoding"))?;
        let mut h = H::new();
        h.update_hash_value(&bytes);
        Ok(h.output_reset())
    }
    fn begin<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Transcript<E>, Error> {
        if !parent.is_classical() {
            return Err(Error("virtual bridge requires classical parent"));
        }
        parent.append_message(
            b"fragmented virtual ordered claims v2",
            &(self.context_hash::<H>()?, root, queries, values),
        );
        parent
            .fork_classical_extension::<F, E>(
                b"fragmented virtual child v2",
                b"unmasked shared-query scalar bridge",
            )
            .map_err(Error)
    }
}
impl<F, E, H> CanonicalPcs<F, H> for Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    type State = State<F, E, H>;
    type SingleProof = Proof<E, H::Output>;
    type BatchProof = Proof<E, H::Output>;
    type Error = Error;
    const LINEAR_DOMAIN: &'static [u8] = b"virtual fragment canonical linear v2";
    const NTT_DOMAIN: &'static [u8] = b"virtual fragment canonical NTT v2";
    const RELATION_DOMAIN: &'static [u8] = b"virtual fragment canonical relation v2";
    const ACCUMULATOR_DOMAIN: &'static [u8] = b"virtual fragment canonical accumulator v2";
    const REGISTRY_DOMAIN: &'static [u8] = b"virtual fragment canonical registry v2";
    const CLAIM_DOMAIN: &'static [u8] = b"virtual fragment canonical claim v2";
    const SEAL_DOMAIN: &'static [u8] = b"virtual fragment canonical seal v2";
    fn num_vars(&self) -> usize {
        self.inner.vars
    }
    fn width(&self) -> usize {
        self.inner.width
    }
    fn context(&self) -> Result<H::Output, Error> {
        self.context_hash::<H>()
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        &state.table
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        _rng: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Error> {
        table
            .validate()
            .map_err(|_| Error("virtual source table"))?;
        if table.num_vars() != self.inner.vars || table.width() != self.inner.width {
            return Err(Error("virtual source dimensions"));
        }
        let scalar = Pcs::<F, E, H>::try_commit_virtual_base(&self.inner.scalar, table.values())?;
        Ok((
            Commitment {
                root: scalar.commitment().root,
            },
            State {
                table: table.clone(),
                scalar,
                context: self.context_hash::<H>()?,
                marker: std::marker::PhantomData,
            },
        ))
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[MatrixPair<F>],
        v: &[F],
    ) -> Result<Self::SingleProof, Error> {
        self.open_many(t, root, state, &[q.to_vec()], &[v.to_vec()])
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[MatrixPair<F>],
        v: &[F],
        proof: &Self::SingleProof,
    ) -> Result<(), Error> {
        <Self as CanonicalPcs<F, H>>::verify_many(
            self,
            t,
            root,
            &[q.to_vec()],
            &[v.to_vec()],
            proof,
        )
    }
    fn open_many(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Self::BatchProof, Error> {
        self.inner.check(queries, values)?;
        if state.context != self.context_hash::<H>()? || root.root != state.scalar.commitment().root
        {
            return Err(Error("virtual source context/root"));
        }
        for (q, v) in queries.iter().zip(values) {
            if state
                .table
                .evaluate(q)
                .map_err(|_| Error("virtual source query"))?
                != *v
            {
                return Err(Error("false virtual source claim"));
            }
        }
        let mut child = self.begin::<H>(parent, root, queries, values)?;
        let rho = child.get_vec_challenge(
            b"virtual bridge lane projections v2",
            queries.len() * self.inner.width,
        );
        let (sumcheck, point) = streamed::prove(
            state.table.values(),
            self.inner.width,
            queries,
            &rho,
            &mut child,
        );
        let (value, opening) = Pcs::<F, E, H>::try_open_virtual_base_at(
            &self.inner.scalar,
            &pipfri::Commitment { root: root.root },
            &state.scalar,
            &point,
            &mut child,
        )?;
        parent.finish_classical_child(&mut child).map_err(Error)?;
        Ok(Proof {
            sumcheck,
            value,
            opening,
        })
    }
    fn verify_many(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Error> {
        self.inner.check(queries, values)?;
        let mut child = self.begin::<H>(parent, root, queries, values)?;
        let rho = child.get_vec_challenge(
            b"virtual bridge lane projections v2",
            queries.len() * self.inner.width,
        );
        let claim = rho
            .iter()
            .zip(values.iter().flatten())
            .fold(E::zero(), |s, (&r, &v)| s + r * v);
        let n = self.inner.vars + self.inner.width.ilog2() as usize;
        let (point, expected) = if n == 0 {
            if !proof.sumcheck.is_empty() {
                return Err(Error("constant virtual bridge proof"));
            }
            (vec![], claim)
        } else {
            let sub = MLSumcheck::verify(
                &mut child,
                &PolynomialInfo {
                    num_variables: n,
                    max_multiplicands: 2,
                },
                claim,
                &proof.sumcheck,
            )
            .map_err(|_| Error("virtual bridge sumcheck"))?;
            (sub.point, sub.expected_evaluations)
        };
        Pcs::<F, E, H>::verify_virtual(
            &self.inner.scalar,
            &pipfri::Commitment { root: root.root },
            &point,
            proof.value,
            &proof.opening,
            &mut child,
        )?;
        if expected != proof.value * terminal_kernel(self.inner.width, queries, &rho, &point) {
            return Err(Error("virtual ordered matrix terminal equation"));
        }
        parent.finish_classical_child(&mut child).map_err(Error)
    }
}
