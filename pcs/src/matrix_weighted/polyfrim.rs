//! Experimental non-hiding ordered-matrix PolyFRIM canonical adapter.
//!
//! Shares rolling FRI across ordered queries of the same retained source. This
//! is the direct full-source construction, not fragmented PipFRI. Concrete
//! vector proximity, extraction and Fiat-Shamir composition remain research gates.
use crate::{
    matrix_weighted::Commitment,
    packed_polyfrim::{Polynomial, authenticated as core},
    utils::hash::Hash,
};
use algebra::{
    AbstractExtensionField, Field, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use serde::Serialize;

/// Invalid trusted geometry, source context, claim, or rejected certificate.
pub use core::Error;
/// Joint consistency and projected rolling-FRI packet, with no private masks.
pub type Proof<E, O> = core::proximity::batch::Proof<E, O>;

/// Separate trusted backend with canonical per-packet Merkle hash dictionaries.
pub mod compact;

/// Trusted logical geometry, field basis and proximity sampling parameters.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F, E> {
    logical_vars: usize,
    width: usize,
    base_modulus: String,
    extension_degree: usize,
    basis_products: Vec<F>,
    inner: core::Parameters<E>,
    #[serde(skip)]
    extension_storage: bool,
}
enum Source<F, E, H: Hash + Send + Sync> {
    Base(core::proximity::batch::base::BaseState<F, H>),
    Extension(core::State<E, H>),
}
impl<F, E, H: Hash + Send + Sync> Source<F, E, H> {
    fn root(&self) -> H::Output {
        match self {
            Self::Base(s) => s.root(),
            Self::Extension(s) => s.root(),
        }
    }
    fn cached_codeword_elements(&self) -> usize {
        match self {
            Self::Base(s) => s.cached_codeword_elements(),
            Self::Extension(s) => s.cached_codeword_elements(),
        }
    }
}
/// Retained logical table and its exact committed oracle, stored in the base
/// field by default and embedded into the extension field at the wire boundary.
/// Prover state is not serializable and is never provided to the verifier.
pub struct State<F, E, H: Hash + Send + Sync> {
    table: PackedTable<F>,
    source: Source<F, E, H>,
    context: H::Output,
}
impl<F: Field, E, H: Hash + Send + Sync> State<F, E, H> {
    /// Original logical table, borrowed by the algebra prover.
    pub fn table(&self) -> &PackedTable<F> {
        &self.table
    }
    /// Retained source oracle elements (excluding Merkle nodes and coefficients).
    pub fn cached_codeword_elements(&self) -> usize {
        self.source.cached_codeword_elements()
    }
    /// Retained codeword payload bytes, excluding coefficients, tree nodes and
    /// allocator overhead. The proof still carries extension-field elements.
    pub fn cached_codeword_bytes(&self) -> usize {
        self.source.cached_codeword_elements()
            * match &self.source {
                Source::Base(_) => std::mem::size_of::<F>(),
                Source::Extension(_) => std::mem::size_of::<E>(),
            }
    }
}
impl<F, E> Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize,
{
    /// Select an explicit power-of-two blowup and number of samples. Neither
    /// parameter by itself asserts a security level. Constants repeat once in
    /// a dummy high coordinate and are queried with (I,0).
    pub fn new(
        logical_vars: usize,
        width: usize,
        blowup: usize,
        queries: usize,
    ) -> Result<Self, Error> {
        if width == 0
            || width.checked_mul(width).is_none()
            || blowup < 2
            || !blowup.is_power_of_two()
            || queries == 0
        {
            return Err(Error("lane, rate or sampling geometry"));
        }
        let message = 1usize
            .checked_shl(
                u32::try_from(logical_vars.max(1)).map_err(|_| Error("logical dimension"))?,
            )
            .ok_or(Error("logical dimension"))?;
        let domain = message
            .checked_mul(2)
            .and_then(|v| v.checked_mul(blowup))
            .ok_or(Error("domain overflow"))?;
        if width == 0
            || message.checked_mul(width).is_none()
            || !domain.is_power_of_two()
            || E::D == 0
        {
            return Err(Error("source geometry"));
        }
        // Native plans are negacyclic: a plan of size n supplies an order-2n root.
        let target_bits = (domain / 2).ilog2();
        let root_bits = target_bits.max(5);
        let mut root =
            F::get_ntt_root(root_bits).map_err(|_| Error("unavailable base-field domain"))?;
        for _ in target_bits..root_bits {
            root *= root;
        }
        let inner = core::Parameters::new(message, width, blowup, queries, E::from_base(root))?
            .with_base_field_encoder::<F>()?
            .with_base_field_folds::<F>();
        let basis: Vec<_> = (0..E::D)
            .map(|i| E::from_base_fn(|j| if i == j { F::one() } else { F::zero() }))
            .collect();
        let basis_products = basis
            .iter()
            .flat_map(|a| {
                basis.iter().flat_map(move |b| {
                    (*a * *b)
                        .as_base_slice()
                        .iter()
                        .map(|v| v.canonicalized())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        Ok(Self {
            logical_vars,
            width,
            base_modulus: F::MODULUS_VALUE.to_string(),
            extension_degree: E::D,
            basis_products,
            inner,
            extension_storage: false,
        })
    }
    /// Retain the extension-field reference representation for differential
    /// checks. This arithmetic policy changes no context or proof wire bytes.
    pub fn with_extension_storage_reference(mut self) -> Self {
        self.extension_storage = true;
        self
    }
    /// Opt into parallel FFT lanes and leaf hashing with extra temporary buffers.
    /// This arithmetic policy changes no context, committed word or proof bytes.
    pub fn with_parallel_oracles(mut self) -> Self {
        self.inner = self.inner.with_parallel_oracles();
        self
    }
    /// Logical Boolean variables, without mask-capacity padding.
    pub fn num_vars(&self) -> usize {
        self.logical_vars
    }
    /// Consecutive base-field lanes per Boolean cell.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Bind the backend, both fields/basis, geometry and sampling parameters.
    pub fn context_digest<H: Hash>(&self) -> H::Output {
        hash::<H, _>(&(b"unmasked packed matrix parameters v1".as_slice(), self))
    }
    /// Deterministically commit one canonical base table; no privacy claim.
    pub fn commit<H: Hash + Send + Sync>(
        &self,
        table: &PackedTable<F>,
    ) -> Result<(Commitment<H::Output>, State<F, E, H>), Error> {
        table.validate().map_err(|_| Error("source shape"))?;
        if table.num_vars() != self.logical_vars || table.width() != self.width {
            return Err(Error("source shape"));
        }
        let table = PackedTable::new(
            self.logical_vars,
            self.width,
            table.values().iter().map(|v| v.canonicalized()).collect(),
        )
        .map_err(|_| Error("source shape"))?;
        let values: Vec<F> = table
            .values()
            .iter()
            .copied()
            .cycle()
            .take((1usize << self.logical_vars.max(1)) * self.width)
            .collect();
        let lifted = PackedTable::new(self.logical_vars.max(1), self.width, values)
            .map_err(|_| Error("lifted source shape"))?;
        let source = if self.extension_storage {
            let lifted = PackedTable::new(
                lifted.num_vars(),
                self.width,
                lifted.values().iter().copied().map(E::from_base).collect(),
            )
            .map_err(|_| Error("lifted extension source"))?;
            Source::Extension(core::commit::<E, H>(
                &self.inner,
                Polynomial::from_table(&lifted).map_err(|_| Error("source polynomial"))?,
            )?)
        } else {
            Source::Base(core::proximity::batch::base::commit::<F, E, H>(
                &self.inner,
                Polynomial::from_table(&lifted).map_err(|_| Error("base source polynomial"))?,
            )?)
        };
        Ok((
            Commitment {
                root: source.root(),
            },
            State {
                table,
                source,
                context: self.context_digest::<H>(),
            },
        ))
    }
    pub(crate) fn claims(
        &self,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<(Vec<Vec<MatrixPair<F>>>, Vec<Vec<F>>), Error> {
        if queries.is_empty() || queries.len() != values.len() {
            return Err(Error("ordered query count"));
        }
        let mut canonical = Vec::with_capacity(queries.len());
        let mut claims = Vec::with_capacity(values.len());
        for (query, value) in queries.iter().zip(values) {
            if query.len() != self.logical_vars || value.len() != self.width {
                return Err(Error("ordered query shape"));
            }
            let mut q = Vec::with_capacity(query.len());
            for pair in query {
                pair.validate(self.width)
                    .map_err(|_| Error("ordered matrix shape"))?;
                q.push(MatrixPair {
                    zero: Matrix::new(
                        self.width,
                        pair.zero
                            .values()
                            .iter()
                            .map(|v| v.canonicalized())
                            .collect(),
                    )
                    .unwrap(),
                    one: Matrix::new(
                        self.width,
                        pair.one
                            .values()
                            .iter()
                            .map(|v| v.canonicalized())
                            .collect(),
                    )
                    .unwrap(),
                });
            }
            canonical.push(q);
            claims.push(value.iter().map(|v| v.canonicalized()).collect());
        }
        Ok((canonical, claims))
    }
    fn extend(&self, query: &[MatrixPair<F>]) -> Vec<MatrixPair<E>> {
        let mut result: Vec<_> = query
            .iter()
            .map(|q| MatrixPair {
                zero: Matrix::new(
                    self.width,
                    q.zero.values().iter().copied().map(E::from_base).collect(),
                )
                .unwrap(),
                one: Matrix::new(
                    self.width,
                    q.one.values().iter().copied().map(E::from_base).collect(),
                )
                .unwrap(),
            })
            .collect();
        result.extend(
            (self.logical_vars..self.logical_vars.max(1)).map(|_| MatrixPair {
                zero: Matrix::identity(self.width).unwrap(),
                one: Matrix::new(self.width, vec![E::zero(); self.width * self.width]).unwrap(),
            }),
        );
        result
    }

    fn begin<H: Hash>(
        &self,
        parent: &mut Transcript<F>,
        root: &H::Output,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        context: H::Output,
    ) -> Transcript<E> {
        parent.append_message(
            b"unmasked packed matrix ordered claims v1",
            &(context, root, queries, values),
        );
        if parent.is_classical() {
            return parent
                .fork_classical_extension::<F, E>(
                    b"classical packed matrix child v1",
                    b"unmasked ordered matrix PCS",
                )
                .expect("classical PCS parent");
        }
        let mut seed = [0u8; 32];
        parent.get_challenge_bytes(b"unmasked packed matrix child seed v1", &mut seed);
        let mut child = Transcript::new_direct_extension::<F>();
        child.append_message(
            b"unmasked packed matrix child v1",
            &(context, root, queries, values, seed),
        );
        child
    }
    /// Preflight all claims before transcript mutation, then share rolling FRI.
    /// The same retained source may be opened repeatedly without mask budgets.
    pub fn open_many<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, E, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<E, H::Output>, Error> {
        self.open_context::<H>(
            parent,
            root,
            state,
            queries,
            values,
            self.context_digest::<H>(),
        )
    }
    fn prepare_open<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, E, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        context: H::Output,
    ) -> Result<(Transcript<E>, Vec<Vec<MatrixPair<F>>>, Vec<Vec<F>>), Error> {
        let (queries, values) = self.claims(queries, values)?;
        if state.context != self.context_digest::<H>() || state.source.root() != root.root {
            return Err(Error("source context or root"));
        }
        for (q, v) in queries.iter().zip(&values) {
            if state
                .table
                .evaluate(q)
                .map_err(|_| Error("source evaluation"))?
                != *v
            {
                return Err(Error("false ordered source claim"));
            }
        }
        let child = self.begin::<H>(parent, &root.root, &queries, &values, context);
        Ok((child, queries, values))
    }
    fn base_queries(
        &self,
        mut queries: Vec<Vec<MatrixPair<F>>>,
    ) -> Result<Vec<Vec<MatrixPair<F>>>, Error> {
        if self.logical_vars == 0 {
            for q in &mut queries {
                q.push(MatrixPair {
                    zero: Matrix::identity(self.width).map_err(|_| Error("constant matrix"))?,
                    one: Matrix::new(self.width, vec![F::zero(); self.width * self.width])
                        .map_err(|_| Error("constant matrix"))?,
                });
            }
        }
        Ok(queries)
    }
    fn open_context<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, E, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        context: H::Output,
    ) -> Result<Proof<E, H::Output>, Error> {
        let (mut child, queries, values) =
            self.prepare_open::<H>(parent, root, state, queries, values, context)?;
        let proof = match &state.source {
            Source::Base(source) => {
                let queries = self.base_queries(queries)?;
                core::proximity::batch::base::prove::<F, E, H>(
                    &mut child,
                    &self.inner,
                    source,
                    &queries,
                    &values,
                )?
            }
            Source::Extension(source) => {
                let queries = queries.iter().map(|q| self.extend(q)).collect::<Vec<_>>();
                let values = values
                    .iter()
                    .map(|v| v.iter().copied().map(E::from_base).collect())
                    .collect::<Vec<_>>();
                core::proximity::batch::prove::<E, H>(
                    &mut child,
                    &self.inner,
                    source,
                    &queries,
                    &values,
                )?
            }
        };
        finish(parent, &mut child);
        Ok(proof)
    }
    fn open_context_mapped<H: Hash + Send + Sync, O>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, E, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        context: H::Output,
        encode: &mut impl FnMut(H::Output) -> Result<O, Error>,
    ) -> Result<Proof<E, O>, Error> {
        let (mut child, queries, values) =
            self.prepare_open::<H>(parent, root, state, queries, values, context)?;
        let proof = match &state.source {
            Source::Base(source) => core::proximity::batch::base::prove_mapped::<F, E, H, O>(
                &mut child,
                &self.inner,
                source,
                &self.base_queries(queries)?,
                &values,
                encode,
            )?,
            Source::Extension(source) => {
                // Retained extension-storage reference and adversarial-source
                // fixtures preserve their original prover before remapping.
                let queries = queries.iter().map(|q| self.extend(q)).collect::<Vec<_>>();
                let values = values
                    .iter()
                    .map(|v| v.iter().copied().map(E::from_base).collect())
                    .collect::<Vec<_>>();
                compact::map_packet(
                    core::proximity::batch::prove::<E, H>(
                        &mut child,
                        &self.inner,
                        source,
                        &queries,
                        &values,
                    )?,
                    encode,
                )?
            }
        };
        finish(parent, &mut child);
        Ok(proof)
    }
    /// Authenticate every caller-derived ordered claim against the expected root.
    pub fn verify_many<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<E, H::Output>,
    ) -> Result<(), Error> {
        self.verify_context::<H>(
            parent,
            root,
            queries,
            values,
            proof,
            self.context_digest::<H>(),
        )
    }
    fn verify_context<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<E, H::Output>,
        context: H::Output,
    ) -> Result<(), Error> {
        let (queries, values) = self.claims(queries, values)?;
        if proof.consistency.len() != queries.len() {
            return Err(Error("opening packet count"));
        }
        let mut child = self.begin::<H>(parent, &root.root, &queries, &values, context);
        let queries = queries.iter().map(|q| self.extend(q)).collect::<Vec<_>>();
        let values = values
            .iter()
            .map(|v| v.iter().copied().map(E::from_base).collect())
            .collect::<Vec<_>>();
        core::proximity::batch::verify::<E, H>(
            &mut child,
            &self.inner,
            &root.root,
            &queries,
            &values,
            proof,
        )?;
        finish(parent, &mut child);
        Ok(())
    }
}
fn finish<F: Field, E: Field>(parent: &mut Transcript<F>, child: &mut Transcript<E>) {
    if parent.is_classical() {
        parent
            .finish_classical_child(child)
            .expect("linked classical PCS child");
        return;
    }
    let mut digest = [0u8; 32];
    child.get_challenge_bytes(b"unmasked packed matrix child finish v1", &mut digest);
    parent.append_message(b"unmasked packed matrix verified child v1", &digest);
}
fn hash<H: Hash, T: Serialize>(value: &T) -> H::Output {
    let mut h = H::new();
    h.update_hash_value(
        &bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("public parameter serialization"),
    );
    h.output_reset()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn nonbase_projection<F, E>()
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize,
    {
        let pp = Parameters::<F, E>::new(3, 2, 2, 8).unwrap();
        // A non-base coordinate constant in the first Boolean variable cancels
        // under the first difference query. Remaining matrices need not commute.
        let values: Vec<_> = (0..16)
            .map(|i| {
                E::from_base_fn(|j| match j {
                    0 => F::from(i * i + 5 * i + 7),
                    1 => F::from((i / 4) * 3 + (i % 2) + 1),
                    _ => F::zero(),
                })
            })
            .collect();
        let expanded = PackedTable::new(3, 2, values).unwrap();
        let table = PackedTable::new(
            3,
            2,
            expanded
                .values()
                .iter()
                .map(|v| v.as_base_slice()[0])
                .collect(),
        )
        .unwrap();
        let source =
            core::commit::<E, Sha256>(&pp.inner, Polynomial::from_table(&expanded).unwrap())
                .unwrap();
        let root = Commitment {
            root: source.root(),
        };
        let state = State {
            table,
            source: Source::Extension(source),
            context: pp.context_digest::<Sha256>(),
        };
        let identity = Matrix::<F>::identity(2).unwrap();
        let negative = Matrix::new(2, identity.values().iter().map(|v| -*v).collect()).unwrap();
        let a = Matrix::new(2, vec![F::one(), F::one(), F::zero(), F::one()]).unwrap();
        let b = Matrix::new(2, vec![F::one(), F::zero(), F::one(), F::one()]).unwrap();
        assert_ne!(a.mul(&b).unwrap(), b.mul(&a).unwrap());
        let queries = vec![vec![
            MatrixPair {
                zero: identity,
                one: negative,
            },
            MatrixPair {
                zero: a.clone(),
                one: b.clone(),
            },
            MatrixPair { zero: b, one: a },
        ]];
        let claims = vec![state.table.evaluate(&queries[0]).unwrap()];
        let extended = pp.extend(&queries[0]);
        let expected: Vec<_> = claims[0].iter().copied().map(E::from_base).collect();
        assert_eq!(expanded.evaluate(&extended).unwrap(), expected);
        // Check the claimed base projection by explicitly expanding every
        // ordered matrix weight, independently of table folding.
        let mut direct = vec![F::zero(); 2];
        for (weight, cell) in algebra::matrix_weighted::matrix_weights(2, &queries[0])
            .unwrap()
            .iter()
            .zip(state.table.values().chunks_exact(2))
        {
            weight.add_mul(cell, &mut direct);
        }
        assert_eq!(direct, claims[0]);
        let mut pt = Transcript::new_direct();
        let proof = pp
            .open_many::<Sha256>(&mut pt, &root, &state, &queries, &claims)
            .unwrap();
        let mut vt = Transcript::new_direct();
        pp.verify_many::<Sha256>(&mut vt, &root, &queries, &claims, &proof)
            .unwrap();
        let mut p = [0; 32];
        let mut v = [0; 32];
        pt.get_challenge_bytes(b"projected source after", &mut p);
        vt.get_challenge_bytes(b"projected source after", &mut v);
        assert_eq!(p, v);
    }
    #[test]
    fn babybear_nonbase_source_has_a_fixed_base_projection() {
        nonbase_projection::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_nonbase_source_has_a_fixed_base_projection() {
        nonbase_projection::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
