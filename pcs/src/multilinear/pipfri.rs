//! Experimental ordinary PipFRI for the repository's scalar PCS interface.
//!
//! Both base and extension input tables are committed in the extension field.
//! This deliberately simple reference adapter does not yet optimize base-field
//! storage or share different query points' proofs. It preserves each scalar
//! claim and binds the logical dimension, including constant (zero-variable)
//! tables. Callers choose their transcript; direct extension sampling is
//! recommended for experiments. No concrete security level or hiding is claimed.
use crate::{PolynomialCommitmentScheme, pipfri as core, rolling_fri::Error, utils::hash::Hash};
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, NTTField, transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Explicit experimental RS geometry; contains no claimed security-bit count.
#[derive(Clone, Debug, Serialize)]
pub struct Specification {
    fragment_vars: usize,
    blowup: usize,
    queries: usize,
}
impl Specification {
    /// Bound fragment size by 2^fragment_vars. Smaller polynomials use their
    /// full size. Blowup must be a power of two >=2; queries must be positive.
    pub fn new(fragment_vars: usize, blowup: usize, queries: usize) -> Result<Self, Error> {
        if fragment_vars == 0
            || fragment_vars >= usize::BITS as usize
            || blowup < 2
            || !blowup.is_power_of_two()
            || queries == 0
        {
            return Err(Error("scalar adapter specification"));
        }
        Ok(Self {
            fragment_vars,
            blowup,
            queries,
        })
    }
}
impl Default for Specification {
    /// Experimental defaults, not a 128-bit configuration.
    fn default() -> Self {
        Self {
            fragment_vars: 14,
            blowup: 2,
            queries: 64,
        }
    }
}
/// Trusted initialized scalar parameters. The trait-required default is an
/// uninitialized sentinel rejected by verification; use setup/try_setup.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<EF> {
    logical_vars: usize,
    inner: Option<core::Parameters<EF>>,
}
impl<EF> Default for Parameters<EF> {
    fn default() -> Self {
        Self {
            logical_vars: 0,
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
/// Experimental adapter. This is opt-in; existing PBS types are unchanged.
#[derive(Clone, Debug, Serialize)]
pub struct PipFRIPCS<F, EF, H>(#[serde(skip)] PhantomData<(F, EF, H)>);
impl<F, EF, H> Default for PipFRIPCS<F, EF, H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}
impl<F, EF, H> PipFRIPCS<F, EF, H>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    /// Checked setup, including native root availability and domain overflow.
    pub fn try_setup(num_vars: usize, spec: &Specification) -> Result<Parameters<EF>, Error> {
        let physical_vars = num_vars.max(1);
        let total = 1usize
            .checked_shl(
                u32::try_from(physical_vars).map_err(|_| Error("scalar adapter dimension"))?,
            )
            .ok_or(Error("scalar adapter dimension"))?;
        let fragment_vars = physical_vars.min(spec.fragment_vars);
        let fragment_len = 1usize << fragment_vars;
        let encoded = fragment_len
            .checked_mul(spec.blowup)
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
            EF::from_base(root),
            core::Basis::BooleanEvaluations,
        )?
        .with_base_field_encoder::<F>()?;
        Ok(Parameters {
            logical_vars: num_vars,
            inner: Some(inner),
        })
    }
    fn point(pp: &Parameters<EF>, point: &[EF]) -> Option<Vec<EF>> {
        pp.inner.as_ref()?;
        if point.len() != pp.logical_vars {
            return None;
        }
        Some(if point.is_empty() {
            vec![EF::zero()]
        } else {
            point.to_vec()
        })
    }
    fn open_one(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        state: &core::State<EF, H>,
        point: &[EF],
        trans: &mut Transcript<EF>,
        kind: &'static [u8],
    ) -> core::Proof<EF, H::Output> {
        let physical = Self::point(pp, point)
            .expect("initialized scalar parameters and correct point dimension");
        trans.append_message(b"ordinary PipFRI PCS adapter v1", &(pp.logical_vars, kind));
        core::open_at(
            trans,
            pp.inner.as_ref().unwrap(),
            commitment,
            state,
            &physical,
        )
        .expect("consistent scalar PCS prover state")
        .1
    }

    /// Checked base-source opening returning the exact authenticated value.
    /// This supports enclosing reductions without recomputing a scalar MLE.
    pub fn try_open_at(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        state: &core::State<EF, H>,
        point: &[EF],
        trans: &mut Transcript<EF>,
    ) -> Result<(EF, core::Proof<EF, H::Output>), Error> {
        let physical = Self::point(pp, point).ok_or(Error("scalar point dimensions"))?;
        let inner = pp
            .inner
            .as_ref()
            .ok_or(Error("uninitialized scalar parameters"))?;
        if commitment.root != state.commitment().root {
            return Err(Error("scalar source root"));
        }
        trans.append_message(
            b"ordinary PipFRI PCS adapter v1",
            &(pp.logical_vars, b"base table".as_slice()),
        );
        core::open_at(trans, inner, commitment, state, &physical)
    }
    /// Commit a base table into the unchanged scalar v2 packed-fragment root.
    pub fn try_commit_virtual_base(
        pp: &Parameters<EF>,
        data: &[F],
    ) -> Result<core::virtual_source::base::State<F, H>, Error> {
        let inner = pp
            .inner
            .as_ref()
            .ok_or(Error("uninitialized scalar parameters"))?;
        if data.len() != 1usize << pp.logical_vars {
            return Err(Error("virtual base table dimensions"));
        }
        if pp.logical_vars == 0 {
            core::virtual_source::base::commit::<F, EF, H>(inner, &[data[0], data[0]])
        } else {
            core::virtual_source::base::commit::<F, EF, H>(inner, data)
        }
    }
    /// Open the base-storage representation with unchanged scalar v2 framing.
    pub fn try_open_virtual_base_at(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        state: &core::virtual_source::base::State<F, H>,
        point: &[EF],
        trans: &mut Transcript<EF>,
    ) -> Result<(EF, core::virtual_source::Proof<EF, H::Output>), Error> {
        let physical = Self::point(pp, point).ok_or(Error("virtual scalar point dimensions"))?;
        let inner = pp
            .inner
            .as_ref()
            .ok_or(Error("uninitialized scalar parameters"))?;
        if commitment.root != state.commitment().root {
            return Err(Error("virtual scalar source root"));
        }
        trans.append_message(b"unmasked virtual PipFRI PCS v2", &pp.logical_vars);
        core::virtual_source::base::open_at::<F, EF, H>(trans, inner, commitment, state, &physical)
    }
    /// Checked unmasked v2 opening, with virtual initial-word authentication.
    pub fn try_open_virtual_at(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        state: &core::State<EF, H>,
        point: &[EF],
        trans: &mut Transcript<EF>,
    ) -> Result<(EF, core::virtual_source::Proof<EF, H::Output>), Error> {
        let physical = Self::point(pp, point).ok_or(Error("virtual scalar point dimensions"))?;
        let inner = pp
            .inner
            .as_ref()
            .ok_or(Error("uninitialized scalar parameters"))?;
        if commitment.root != state.commitment().root {
            return Err(Error("virtual scalar source root"));
        }
        trans.append_message(b"unmasked virtual PipFRI PCS v2", &pp.logical_vars);
        core::virtual_source::open_at(trans, inner, commitment, state, &physical)
    }
    /// Verify the explicitly versioned virtual opening of a base source table.
    pub fn verify_virtual(
        pp: &Parameters<EF>,
        commitment: &core::Commitment<H::Output>,
        point: &[EF],
        value: EF,
        proof: &core::virtual_source::Proof<EF, H::Output>,
        trans: &mut Transcript<EF>,
    ) -> Result<(), Error> {
        let physical = Self::point(pp, point).ok_or(Error("virtual scalar point dimensions"))?;
        trans.append_message(b"unmasked virtual PipFRI PCS v2", &pp.logical_vars);
        core::virtual_source::verify::<EF, H>(
            trans,
            pp.inner.as_ref().unwrap(),
            commitment,
            &physical,
            value,
            proof,
        )
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
        trans.append_message(b"ordinary PipFRI PCS adapter v1", &(pp.logical_vars, kind));
        core::verify::<EF, H>(
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
            b"ordinary PipFRI PCS batch v1",
            &(pp.logical_vars, kind, commitment, points),
        );
    }
}
impl<F, EF, H> PolynomialCommitmentScheme<F, EF, Specification> for PipFRIPCS<F, EF, H>
where
    F: NTTField + Serialize,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    type Parameters = Parameters<EF>;
    type Polynomial = DenseMultilinearExtension<F>;
    type EFPolynomial = DenseMultilinearExtension<EF>;
    type Commitment = core::Commitment<H::Output>;
    type CommitmentState = core::State<EF, H>;
    type CommitmentStateEF = core::State<EF, H>;
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
        let inner = pp.inner.as_ref().expect("initialized scalar parameters");
        assert_eq!(poly.num_vars, pp.logical_vars);
        assert_eq!(poly.evaluations.len(), 1usize << pp.logical_vars);
        let mut data: Vec<_> = poly
            .evaluations
            .iter()
            .copied()
            .map(EF::from_base)
            .collect();
        if pp.logical_vars == 0 {
            data.push(data[0]);
        }
        let state = core::commit::<EF, H>(inner, &data).expect("correct scalar table length");
        (state.commitment(), state)
    }
    fn commit_ef(
        pp: &Self::Parameters,
        poly: &Self::EFPolynomial,
    ) -> (Self::Commitment, Self::CommitmentStateEF) {
        let inner = pp.inner.as_ref().expect("initialized scalar parameters");
        assert_eq!(poly.num_vars, pp.logical_vars);
        assert_eq!(poly.evaluations.len(), 1usize << pp.logical_vars);
        let state = if pp.logical_vars == 0 {
            core::commit::<EF, H>(inner, &[poly.evaluations[0]; 2])
        } else {
            core::commit::<EF, H>(inner, &poly.evaluations)
        }
        .expect("correct scalar table length");
        (state.commitment(), state)
    }
    fn open(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentState,
        p: &[EF],
        t: &mut Transcript<EF>,
    ) -> Self::Proof {
        Self::open_one(pp, c, s, p, t, b"base table")
    }
    fn open_ef(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentStateEF,
        p: &[EF],
        t: &mut Transcript<EF>,
    ) -> Self::ProofEF {
        Self::open_one(pp, c, s, p, t, b"extension table")
    }
    fn batch_open(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentState,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
    ) -> Vec<Self::Proof> {
        assert!(pp.inner.is_some() && points.iter().all(|p| p.len() == pp.logical_vars));
        Self::batch_bind(pp, c, points, t, b"base table");
        points.iter().map(|p| Self::open(pp, c, s, p, t)).collect()
    }
    fn batch_open_ef(
        pp: &Self::Parameters,
        c: &Self::Commitment,
        s: &Self::CommitmentStateEF,
        points: &[Vec<EF>],
        t: &mut Transcript<EF>,
    ) -> Vec<Self::ProofEF> {
        assert!(pp.inner.is_some() && points.iter().all(|p| p.len() == pp.logical_vars));
        Self::batch_bind(pp, c, points, t, b"extension table");
        points
            .iter()
            .map(|p| Self::open_ef(pp, c, s, p, t))
            .collect()
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
