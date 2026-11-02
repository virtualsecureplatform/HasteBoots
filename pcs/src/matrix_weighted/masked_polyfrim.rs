//! Experimental masked direct packed PCS adapter for base-field matrix queries.
//!
//! One retained extension-field source defines one base projection. Dummy high
//! variables preserve logical shapes while providing explicit mask capacity.
//! Multi-query calls enforce one private lifetime atomically; they currently
//! contain individual direct openings. The explicit joint API shares original
//! source proximity; the separate aggregated API also shares query-ladder FRI.
use crate::{
    matrix_weighted::Commitment, packed_polyfrim::authenticated::masked as core, utils::hash::Hash,
};
use algebra::{
    AbstractExtensionField, Field, NTTField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, MutexGuard};

/// Explicit batches sharing source and query-ladder rolling proximity.
pub mod aggregated;
/// Explicit original-source-sharing batches; independent openings stay unchanged.
pub mod joint;

/// Invalid geometry, source, claim, private lifetime or rejected proof.
#[derive(Debug, thiserror::Error)]
#[error("masked packed matrix PCS: {0}")]
pub struct Error(pub &'static str);
/// Trusted logical/physical geometry and extension-field masking parameters.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F, EF> {
    logical_vars: usize,
    physical_vars: usize,
    width: usize,
    base_modulus: String,
    extension_degree: usize,
    basis_products: Vec<F>,
    inner: core::Parameters<EF>,
}
/// Private retained base table and non-cloneable mask session behind one lock.
/// Neither the state nor its mask session can be serialized as a proof.
pub struct State<F, EF, H: Hash + Send + Sync> {
    table: PackedTable<F>,
    root: H::Output,
    context: H::Output,
    session: Mutex<core::ProverSession<EF, H>>,
}
impl<F: Field, EF, H: Hash + Send + Sync> State<F, EF, H> {
    /// Borrow the original logical source; no auxiliary commitment is created.
    pub fn table(&self) -> &PackedTable<F> {
        &self.table
    }
    /// Number of encoded field elements retained by the private source owner.
    pub fn cached_codeword_elements(&self) -> Result<usize, Error> {
        self.session
            .lock()
            .map(|s| s.cached_codeword_elements())
            .map_err(|_| Error("poisoned private mask session"))
    }
    /// Query the private lifetime counter; poisoned sessions fail closed.
    pub fn spent(&self) -> Result<usize, Error> {
        self.session
            .lock()
            .map(|s| s.spent())
            .map_err(|_| Error("poisoned private mask session"))
    }
}
/// Ordered independent direct openings of one retained canonical source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<EF, O> {
    /// Consecutive mask indices; exact count comes from caller-derived claims.
    pub openings: Vec<core::Proof<EF, O>>,
}
impl<F, EF> Parameters<F, EF>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
{
    /// Regenerate source codewords per opening batch instead of retaining them.
    /// This memory policy changes no trusted context or proof format.
    pub fn with_transient_source_values(mut self) -> Self {
        self.inner = self.inner.with_transient_source_values();
        self
    }
    /// Fix the logical shape and explicit physical capacity. Physical variables
    /// must cover the logical table; the core disclosure guard must hold.
    /// The domain uses an available base-field root embedded in the extension.
    pub fn new(
        logical_vars: usize,
        width: usize,
        physical_vars: usize,
        blowup: usize,
        queries: usize,
        max_openings: usize,
    ) -> Result<Self, Error> {
        if physical_vars < logical_vars || logical_vars >= usize::BITS as usize || EF::D == 0 {
            return Err(Error("logical or physical geometry"));
        }
        let message = 1usize
            .checked_shl(u32::try_from(physical_vars).map_err(|_| Error("physical dimension"))?)
            .ok_or(Error("physical dimension"))?;
        let domain = message
            .checked_mul(2)
            .and_then(|m| m.checked_mul(blowup))
            .ok_or(Error("physical domain overflow"))?;
        if width == 0 || message.checked_mul(width).is_none() || !domain.is_power_of_two() {
            return Err(Error("physical domain or width"));
        }
        let root = F::generate_ntt_table(domain.ilog2())
            .map_err(|_| Error("unavailable base-field domain"))?
            .root();
        let inner = core::Parameters::new(
            message,
            width,
            blowup,
            queries,
            max_openings,
            EF::from_base(root),
        )
        .and_then(|p| p.with_base_field_encoder::<F>())
        .map_err(|_| Error("mask geometry or disclosure capacity"))?;
        let basis: Vec<_> = (0..EF::D)
            .map(|i| EF::from_base_fn(|j| if i == j { F::one() } else { F::zero() }))
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
            physical_vars,
            width,
            base_modulus: F::MODULUS_VALUE.to_string(),
            extension_degree: EF::D,
            basis_products,
            inner,
        })
    }
    /// Number of variables in the caller's canonical base table.
    pub fn num_vars(&self) -> usize {
        self.logical_vars
    }
    /// Consecutive lanes per Boolean cell.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Physical logical capacity before the core's private high padding.
    pub fn physical_vars(&self) -> usize {
        self.physical_vars
    }
    /// Lifetime opening allowance for every commitment made with these parameters.
    pub fn max_openings(&self) -> usize {
        self.inner.max_openings()
    }
    /// Complete backend/shape/field/basis/mask context for canonical-root aliases.
    pub fn context_digest<H: Hash>(&self) -> H::Output {
        hash::<H, _>(&(b"masked packed matrix parameters v2".as_slice(), self))
    }
    /// Commit the base table once with fresh private randomness. Extra high
    /// Boolean coordinates repeat the logical table and are opened with (I,0).
    pub fn commit<H: Hash + Send + Sync, R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        rng: &mut R,
    ) -> Result<(Commitment<H::Output>, State<F, EF, H>), Error> {
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
        let entries = (1usize << self.physical_vars) * self.width;
        let values = table
            .values()
            .iter()
            .copied()
            .cycle()
            .take(entries)
            .map(EF::from_base)
            .collect();
        let repeated = PackedTable::new(self.physical_vars, self.width, values)
            .map_err(|_| Error("physical source shape"))?;
        let session = core::commit::<EF, H, _>(&self.inner, &repeated, rng)
            .map_err(|_| Error("masked source commitment"))?;
        let root = session.root();
        Ok((
            Commitment { root },
            State {
                table,
                root,
                context: self.context_digest::<H>(),
                session: Mutex::new(session),
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
    fn extend(&self, query: &[MatrixPair<F>]) -> Vec<MatrixPair<EF>> {
        let mut result: Vec<_> = query
            .iter()
            .map(|q| MatrixPair {
                zero: Matrix::new(
                    self.width,
                    q.zero.values().iter().copied().map(EF::from_base).collect(),
                )
                .unwrap(),
                one: Matrix::new(
                    self.width,
                    q.one.values().iter().copied().map(EF::from_base).collect(),
                )
                .unwrap(),
            })
            .collect();
        result.extend((self.logical_vars..self.physical_vars).map(|_| MatrixPair {
            zero: Matrix::identity(self.width).unwrap(),
            one: Matrix::new(self.width, vec![EF::zero(); self.width * self.width]).unwrap(),
        }));
        result
    }
    fn begin<H: Hash>(
        &self,
        parent: &mut Transcript<F>,
        root: &H::Output,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        first: usize,
    ) -> Transcript<EF> {
        let context = self.context_digest::<H>();
        parent.append_message(
            b"masked packed matrix ordered claims v2",
            &(context, root, queries, values, first),
        );
        let mut seed = [0u8; 32];
        parent.get_challenge_bytes(b"masked packed matrix child seed v2", &mut seed);
        let mut child = Transcript::new_direct_extension::<F>();
        child.append_message(
            b"masked packed matrix child v2",
            &(context, root, queries, values, first, seed),
        );
        child
    }
    // One lock guards the common root/context, complete allowance and every
    // actual logical claim before either opening API mutates the parent.
    fn opening_session<'a, H: Hash + Send + Sync>(
        &self,
        commitment: &Commitment<H::Output>,
        state: &'a State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<MutexGuard<'a, core::ProverSession<EF, H>>, Error> {
        if state.context != self.context_digest::<H>() || state.root != commitment.root {
            return Err(Error("source context or root"));
        }
        let session = state
            .session
            .lock()
            .map_err(|_| Error("poisoned private mask session"))?;
        let first = session.spent();
        if first
            .checked_add(queries.len())
            .is_none_or(|n| n > self.max_openings())
        {
            return Err(Error("insufficient private mask lifetime"));
        }
        for (query, value) in queries.iter().zip(values) {
            if state
                .table
                .evaluate(query)
                .map_err(|_| Error("source evaluation"))?
                != *value
            {
                return Err(Error("false ordered source claim"));
            }
        }
        Ok(session)
    }
    /// Atomically preflight every claim and the complete mask allowance before
    /// publishing anything. One lock covers all openings; no budget is refreshed.
    pub fn open_many<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        state: &State<F, EF, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<EF, H::Output>, Error> {
        let (queries, values) = self.claims(queries, values)?;
        let mut session = self.opening_session::<H>(commitment, state, &queries, &values)?;
        let first = session.spent();
        let mut child = self.begin::<H>(parent, &commitment.root, &queries, &values, first);
        let mut openings = Vec::with_capacity(queries.len());
        for (i, (query, value)) in queries.iter().zip(&values).enumerate() {
            child.append_message(b"masked packed matrix opening member v2", &(i, first + i));
            openings.push(
                core::prove(
                    &mut child,
                    &self.inner,
                    &mut session,
                    &self.extend(query),
                    &value.iter().copied().map(EF::from_base).collect::<Vec<_>>(),
                )
                .map_err(|_| Error("masked ordered opening"))?,
            );
        }
        finish(parent, &mut child);
        Ok(Proof { openings })
    }
    /// Verify each caller-derived ordered matrix obligation against one expected
    /// canonical root. No root, geometry or alias choice comes from the proof.
    pub fn verify_many<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        commitment: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<EF, H::Output>,
    ) -> Result<(), Error> {
        let (queries, values) = self.claims(queries, values)?;
        if proof.openings.len() != queries.len() {
            return Err(Error("opening packet count"));
        }
        let first = proof.openings[0].index;
        if first
            .checked_add(queries.len())
            .is_none_or(|n| n > self.max_openings())
            || proof
                .openings
                .iter()
                .enumerate()
                .any(|(i, p)| p.index != first + i)
        {
            return Err(Error("opening index schedule"));
        }
        let mut child = self.begin::<H>(parent, &commitment.root, &queries, &values, first);
        for (i, ((query, value), opening)) in
            queries.iter().zip(&values).zip(&proof.openings).enumerate()
        {
            child.append_message(b"masked packed matrix opening member v2", &(i, first + i));
            core::verify::<EF, H>(
                &mut child,
                &self.inner,
                &commitment.root,
                &self.extend(query),
                &value.iter().copied().map(EF::from_base).collect::<Vec<_>>(),
                opening,
            )
            .map_err(|_| Error("masked ordered verification"))?;
        }
        finish(parent, &mut child);
        Ok(())
    }
}
fn finish<F: Field, EF: Field>(parent: &mut Transcript<F>, child: &mut Transcript<EF>) {
    let mut digest = [0u8; 32];
    child.get_challenge_bytes(b"masked packed matrix child finish v2", &mut digest);
    parent.append_message(b"masked packed matrix verified child v2", &digest);
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
    use algebra::{Goldilocks as F, GoldilocksExtension3 as E};
    use num_traits::{One, Zero};
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;
    #[test]
    fn nonbase_source_authenticates_its_fixed_base_projection() {
        let pp = Parameters::<F, E>::new(1, 1, 9, 2, 1, 1).unwrap();
        let values: Vec<_> = (0..512)
            .map(|i| {
                E::from_base_fn(|coordinate| match coordinate {
                    0 => F::new(if i & 1 == 0 { 5 } else { 7 }),
                    1 => {
                        if i & 1 == 0 {
                            F::one()
                        } else {
                            -F::one()
                        }
                    }
                    _ => F::zero(),
                })
            })
            .collect();
        let expanded = PackedTable::new(9, 1, values).unwrap();
        let session =
            core::commit::<E, Sha256, _>(&pp.inner, &expanded, &mut StdRng::seed_from_u64(196))
                .unwrap();
        let root = Commitment {
            root: session.root(),
        };
        let table = PackedTable::new(1, 1, vec![F::new(5), F::new(7)]).unwrap();
        let state = State {
            table,
            root: root.root,
            context: pp.context_digest::<Sha256>(),
            session: Mutex::new(session),
        };
        let queries = vec![vec![MatrixPair {
            zero: Matrix::identity(1).unwrap(),
            one: Matrix::identity(1).unwrap(),
        }]];
        let values = vec![vec![F::new(12)]];
        let mut prover = Transcript::new_direct();
        let proof = pp
            .open_many::<Sha256>(&mut prover, &root, &state, &queries, &values)
            .unwrap();
        let mut verifier = Transcript::new_direct();
        pp.verify_many::<Sha256>(&mut verifier, &root, &queries, &values, &proof)
            .unwrap();
        assert_eq!(
            prover.get_challenge(b"projection after"),
            verifier.get_challenge(b"projection after")
        );
    }
    #[test]
    fn poisoned_sessions_fail_closed_without_parent_mutation() {
        let pp = Parameters::<F, E>::new(0, 1, 9, 2, 1, 1).unwrap();
        let table = PackedTable::new(0, 1, vec![F::new(3)]).unwrap();
        let (root, state) = pp
            .commit::<Sha256, _>(&table, &mut StdRng::seed_from_u64(197))
            .unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = state.session.lock().unwrap();
            panic!("fixture poison");
        }));
        assert!(state.spent().is_err());
        let mut attempted = Transcript::new_direct();
        let mut unchanged = Transcript::<F>::new_direct();
        assert!(
            pp.open_many::<Sha256>(&mut attempted, &root, &state, &[vec![]], &[vec![F::new(3)]])
                .is_err()
        );
        assert_eq!(
            attempted.get_challenge(b"poison after"),
            unchanged.get_challenge(b"poison after")
        );
    }
}
