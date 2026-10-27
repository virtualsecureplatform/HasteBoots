//! Experimental masked PipFRI adapter for the scalar PCS interface.
//!
//! One locked, non-cloneable private session enforces cumulative opening limits
//! even though the PCS trait borrows commitment state immutably. Trait verification
//! is stateless: it checks bounded indices and batch order, not an acceptance
//! history. For replay detection use the core masked `VerifierSession` API.
//! Small tables repeat over extra dummy coordinates to meet the configured
//! masking capacity. No reviewed hiding or concrete security guarantee is claimed.
use crate::{
    PolynomialCommitmentScheme,
    pipfri::{Basis, masked as core},
    rolling_fri::Error,
    utils::hash::Hash,
};
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, NTTField, transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, sync::Mutex};

/// Explicit fragment geometry and lifetime mask budget, without security bits.
#[derive(Clone, Debug, Serialize)]
pub struct Specification {
    fragment_vars: usize,
    blowup: usize,
    queries: usize,
    max_openings: usize,
}
impl Specification {
    /// Use fixed size-2^fragment_vars fragments. Small tables are repeated in
    /// dummy coordinates. The core numerical mask-capacity check must hold.
    pub fn new(
        fragment_vars: usize,
        blowup: usize,
        queries: usize,
        max_openings: usize,
    ) -> Result<Self, Error> {
        let m = 1usize
            .checked_shl(
                u32::try_from(fragment_vars)
                    .map_err(|_| Error("masked adapter fragment dimension"))?,
            )
            .ok_or(Error("masked adapter fragment dimension"))?;
        let allowance = fragment_vars
            .checked_add(1)
            .and_then(|r| r.checked_mul(4))
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_mul(queries))
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_mul(max_openings))
            .ok_or(Error("masked adapter disclosure overflow"))?;
        if fragment_vars == 0
            || m.checked_mul(2).is_none()
            || blowup < 2
            || !blowup.is_power_of_two()
            || queries == 0
            || max_openings == 0
            || allowance > m
        {
            return Err(Error("masked adapter geometry/budget"));
        }
        Ok(Self {
            fragment_vars,
            blowup,
            queries,
            max_openings,
        })
    }
}
impl Default for Specification {
    /// Experimental capacity for four openings, not a 128-bit configuration.
    fn default() -> Self {
        Self::new(14, 2, 64, 4).unwrap()
    }
}
/// Trusted initialized scalar parameters. The trait-required default is an
/// uninitialized sentinel rejected by verification; use setup/try_setup.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<EF> {
    logical_vars: usize,
    physical_vars: usize,
    inner: Option<core::Parameters<EF>>,
}
impl<EF> Default for Parameters<EF> {
    fn default() -> Self {
        Self {
            logical_vars: 0,
            physical_vars: 0,
            inner: None,
        }
    }
}
impl<EF> Parameters<EF> {
    /// Logical number of variables, or None for the default sentinel.
    pub fn num_vars(&self) -> Option<usize> {
        self.inner.as_ref().map(|_| self.logical_vars)
    }
}
/// Private lifetime-bounded commitment state; not cloneable or serializable.
pub struct State<EF, H: Hash + Send + Sync> {
    context: H::Output,
    session: Mutex<core::ProverSession<EF, H>>,
}
impl<EF: algebra::Field + Serialize, H: Hash + Send + Sync> State<EF, H> {
    /// Remaining openings; poisoned locks are rejected without exposing masks.
    pub fn remaining_openings(&self) -> Result<usize, Error> {
        Ok(self
            .session
            .lock()
            .map_err(|_| Error("masked session lock poisoned"))?
            .remaining_openings())
    }
}
/// Experimental adapter. This is opt-in; existing PBS types are unchanged.
#[derive(Clone, Debug, Serialize)]
pub struct MaskedPipFRIPCS<F, EF, H>(#[serde(skip)] PhantomData<(F, EF, H)>);
impl<F, EF, H> Default for MaskedPipFRIPCS<F, EF, H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}
impl<F, EF, H> MaskedPipFRIPCS<F, EF, H>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    /// Checked setup, including native root availability and domain overflow.
    pub fn try_setup(num_vars: usize, spec: &Specification) -> Result<Parameters<EF>, Error> {
        let physical_vars = num_vars.max(spec.fragment_vars);
        let total = 1usize
            .checked_shl(
                u32::try_from(physical_vars).map_err(|_| Error("scalar adapter dimension"))?,
            )
            .ok_or(Error("scalar adapter dimension"))?;
        let fragment_vars = spec.fragment_vars;
        let fragment_len = 1usize << fragment_vars;
        let encoded = fragment_len
            .checked_mul(2)
            .and_then(|n| n.checked_mul(spec.blowup))
            .ok_or(Error("scalar adapter domain overflow"))?;
        encoded
            .checked_mul(2)
            .ok_or(Error("scalar adapter root order overflow"))?;
        let log = encoded.ilog2();
        // Native plans start at 32 entries. Squaring gives the exact root for
        // smaller domains, whose encoding is handled by the generic DIF FFT.
        let mut root = F::generate_ntt_table(log.max(5))
            .map_err(|_| Error("scalar adapter native NTT domain unavailable"))?
            .root();
        for _ in log..log.max(5) {
            root *= root;
        }
        let inner = core::Parameters::new(
            fragment_len,
            total / fragment_len,
            spec.blowup,
            spec.queries,
            spec.max_openings,
            EF::from_base(root),
            Basis::BooleanEvaluations,
        )?
        .with_base_field_encoder::<F>()?;
        Ok(Parameters {
            logical_vars: num_vars,
            physical_vars,
            inner: Some(inner),
        })
    }
    fn point(pp: &Parameters<EF>, point: &[EF]) -> Option<Vec<EF>> {
        pp.inner.as_ref()?;
        if point.len() != pp.logical_vars {
            return None;
        }
        let mut physical = point.to_vec();
        physical.resize(pp.physical_vars, EF::zero());
        Some(physical)
    }
    fn context(pp: &Parameters<EF>, kind: &'static [u8]) -> H::Output {
        crate::rolling_fri::hash::<H, _>(&(b"masked PipFRI scalar state v1".as_slice(), pp, kind))
    }
    fn open_many_values(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        state: &State<EF, H>,
        points: &[Vec<EF>],
        trans: &mut Transcript<EF>,
        kind: &'static [u8],
        batch: bool,
    ) -> Result<Vec<(EF, core::Proof<EF, H::Output>)>, Error> {
        if pp.inner.is_none() || state.context != Self::context(pp, kind) {
            return Err(Error("masked adapter state parameters/kind"));
        }
        let physical = points
            .iter()
            .map(|p| Self::point(pp, p).ok_or(Error("masked adapter point dimension")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut session = state
            .session
            .lock()
            .map_err(|_| Error("masked session lock poisoned"))?;
        if session.commitment().root != commitment.root {
            return Err(Error("masked adapter expected root"));
        }
        if points.len() > session.remaining_openings() {
            return Err(Error("masked adapter opening budget exhausted"));
        }
        if batch {
            Self::batch_bind(pp, commitment, points, trans, kind);
        }
        physical
            .iter()
            .map(|point| {
                trans.append_message(b"masked PipFRI PCS adapter v1", &(pp, kind));
                session.open_at(trans, point)
            })
            .collect()
    }
    fn open_many(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        state: &State<EF, H>,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
        kind: &'static [u8],
        batch: bool,
    ) -> Result<Vec<core::Proof<EF, H::Output>>, Error> {
        Ok(
            Self::open_many_values(pp, commitment, state, points, t, kind, batch)?
                .into_iter()
                .map(|(_, p)| p)
                .collect(),
        )
    }
    /// Open a base table and return the exact value bound into the PCS transcript.
    /// This avoids recomputing an equivalent value with a different lazy field
    /// representation. It consumes one allowance and retains all preflight checks.
    pub fn try_open_at(
        pp: &Parameters<EF>,
        c: &core::Commitment<H::Output>,
        s: &State<EF, H>,
        point: &[EF],
        t: &mut Transcript<EF>,
    ) -> Result<(EF, core::Proof<EF, H::Output>), Error> {
        Ok(Self::open_many_values(pp, c, s, &[point.to_vec()], t, b"base table", false)?.remove(0))
    }
    /// Extension-table counterpart returning the exact authenticated value.
    pub fn try_open_at_ef(
        pp: &Parameters<EF>,
        c: &core::Commitment<H::Output>,
        s: &State<EF, H>,
        point: &[EF],
        t: &mut Transcript<EF>,
    ) -> Result<(EF, core::Proof<EF, H::Output>), Error> {
        Ok(
            Self::open_many_values(pp, c, s, &[point.to_vec()], t, b"extension table", false)?
                .remove(0),
        )
    }
    /// Checked single base-table opening, consuming one lifetime allowance.
    pub fn try_open(
        pp: &Parameters<EF>,
        c: &core::Commitment<H::Output>,
        s: &State<EF, H>,
        point: &[EF],
        t: &mut Transcript<EF>,
    ) -> Result<core::Proof<EF, H::Output>, Error> {
        Ok(Self::open_many(pp, c, s, &[point.to_vec()], t, b"base table", false)?.remove(0))
    }
    /// Checked single extension-table opening, consuming one lifetime allowance.
    pub fn try_open_ef(
        pp: &Parameters<EF>,
        c: &core::Commitment<H::Output>,
        s: &State<EF, H>,
        point: &[EF],
        t: &mut Transcript<EF>,
    ) -> Result<core::Proof<EF, H::Output>, Error> {
        Ok(Self::open_many(pp, c, s, &[point.to_vec()], t, b"extension table", false)?.remove(0))
    }
    /// Checked base-table batch. Geometry, root and capacity are validated for
    /// the whole batch before transcript mutation or consuming any allowance.
    pub fn try_batch_open(
        pp: &Parameters<EF>,
        c: &core::Commitment<H::Output>,
        s: &State<EF, H>,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
    ) -> Result<Vec<core::Proof<EF, H::Output>>, Error> {
        Self::open_many(pp, c, s, points, t, b"base table", true)
    }
    /// Checked extension-table batch with the same atomic preflight checks.
    pub fn try_batch_open_ef(
        pp: &Parameters<EF>,
        c: &core::Commitment<H::Output>,
        s: &State<EF, H>,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
    ) -> Result<Vec<core::Proof<EF, H::Output>>, Error> {
        Self::open_many(pp, c, s, points, t, b"extension table", true)
    }
    fn verify_one(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        point: &[EF],
        eval: EF,
        proof: &core::Proof<EF, H::Output>,
        trans: &mut Transcript<EF>,
        kind: &'static [u8],
    ) -> bool {
        let Some(physical) = Self::point(pp, point) else {
            return false;
        };
        trans.append_message(b"masked PipFRI PCS adapter v1", &(pp, kind));
        core::verify_opening::<EF, H>(
            trans,
            pp.inner.as_ref().unwrap(),
            commitment,
            &physical,
            eval,
            proof,
        )
        .is_ok()
    }
    fn batch_bind(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        points: &[Vec<EF>],
        trans: &mut Transcript<EF>,
        kind: &'static [u8],
    ) {
        trans.append_message(
            b"masked PipFRI PCS batch v1",
            &(pp, kind, commitment, points),
        );
    }
}
impl<F, EF, H> PolynomialCommitmentScheme<F, EF, Specification> for MaskedPipFRIPCS<F, EF, H>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    type Parameters = Parameters<EF>;
    type Polynomial = DenseMultilinearExtension<F>;
    type EFPolynomial = DenseMultilinearExtension<EF>;
    type Commitment = core::Commitment<H::Output>;
    type CommitmentState = State<EF, H>;
    type CommitmentStateEF = State<EF, H>;
    type Proof = core::Proof<EF, H::Output>;
    type ProofEF = core::Proof<EF, H::Output>;
    type Point = EF;
    fn setup(num_vars: usize, spec: &Specification) -> Self::Parameters {
        Self::try_setup(num_vars, spec).expect("supported experimental scalar PipFRI parameters")
    }
    fn commit(
        pp: &Self::Parameters,
        poly: &Self::Polynomial,
    ) -> (Self::Commitment, Self::CommitmentState) {
        assert_eq!(poly.num_vars, pp.logical_vars);
        assert_eq!(poly.evaluations.len(), 1usize << pp.logical_vars);
        let data = (0..1usize << pp.physical_vars)
            .map(|i| EF::from_base(poly.evaluations[i % poly.evaluations.len()]))
            .collect::<Vec<_>>();
        let session = core::commit::<EF, H, _>(
            pp.inner.as_ref().expect("initialized masked parameters"),
            &data,
            &mut rand::rng(),
        )
        .expect("valid masked scalar table");
        (
            session.commitment(),
            State {
                context: Self::context(pp, b"base table"),
                session: Mutex::new(session),
            },
        )
    }
    fn commit_ef(
        pp: &Self::Parameters,
        poly: &Self::EFPolynomial,
    ) -> (Self::Commitment, Self::CommitmentStateEF) {
        assert_eq!(poly.num_vars, pp.logical_vars);
        assert_eq!(poly.evaluations.len(), 1usize << pp.logical_vars);
        let data = (0..1usize << pp.physical_vars)
            .map(|i| poly.evaluations[i % poly.evaluations.len()])
            .collect::<Vec<_>>();
        let session = core::commit::<EF, H, _>(
            pp.inner.as_ref().expect("initialized masked parameters"),
            &data,
            &mut rand::rng(),
        )
        .expect("valid masked scalar table");
        (
            session.commitment(),
            State {
                context: Self::context(pp, b"extension table"),
                session: Mutex::new(session),
            },
        )
    }
    fn open(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentState,
        p: &[EF],
        t: &mut Transcript<EF>,
    ) -> Self::Proof {
        Self::try_open(pp, c, s, p, t).expect("valid masked scalar opening within lifetime budget")
    }
    fn open_ef(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentStateEF,
        p: &[EF],
        t: &mut Transcript<EF>,
    ) -> Self::ProofEF {
        Self::try_open_ef(pp, c, s, p, t)
            .expect("valid masked scalar opening within lifetime budget")
    }
    fn batch_open(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentState,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
    ) -> Vec<Self::Proof> {
        Self::try_batch_open(pp, c, s, points, t)
            .expect("valid masked scalar batch within lifetime budget")
    }
    fn batch_open_ef(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentStateEF,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
    ) -> Vec<Self::ProofEF> {
        Self::try_batch_open_ef(pp, c, s, points, t)
            .expect("valid masked scalar batch within lifetime budget")
    }
    fn verify(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        p: &[EF],
        v: EF,
        proof: &Self::Proof,
        t: &mut Transcript<EF>,
    ) -> bool {
        Self::verify_one(pp, c, p, v, proof, t, b"base table")
    }
    fn verify_ef(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        p: &[EF],
        v: EF,
        proof: &Self::ProofEF,
        t: &mut Transcript<EF>,
    ) -> bool {
        Self::verify_one(pp, c, p, v, proof, t, b"extension table")
    }
    fn batch_verify(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        points: &[Vec<EF>],
        values: &[EF],
        proofs: &[Self::Proof],
        t: &mut Transcript<EF>,
    ) -> bool {
        if pp.inner.is_none()
            || points.len() != values.len()
            || points.len() != proofs.len()
            || points.iter().any(|p| p.len() != pp.logical_vars)
            || proofs
                .windows(2)
                .any(|pair| pair[0].opening_index.checked_add(1) != Some(pair[1].opening_index))
        {
            return false;
        }
        Self::batch_bind(pp, c, points, t, b"base table");
        points
            .iter()
            .zip(values)
            .zip(proofs)
            .all(|((p, &v), proof)| Self::verify(pp, c, p, v, proof, t))
    }
    fn batch_verify_ef(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        points: &[Vec<EF>],
        values: &[EF],
        proofs: &[Self::ProofEF],
        t: &mut Transcript<EF>,
    ) -> bool {
        if pp.inner.is_none()
            || points.len() != values.len()
            || points.len() != proofs.len()
            || points.iter().any(|p| p.len() != pp.logical_vars)
            || proofs
                .windows(2)
                .any(|pair| pair[0].opening_index.checked_add(1) != Some(pair[1].opening_index))
        {
            return false;
        }
        Self::batch_bind(pp, c, points, t, b"extension table");
        points
            .iter()
            .zip(values)
            .zip(proofs)
            .all(|((p, &v), proof)| Self::verify_ef(pp, c, p, v, proof, t))
    }
}
