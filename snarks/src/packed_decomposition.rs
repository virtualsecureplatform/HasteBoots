//! Canonical radix decomposition against existing packed commitments.
//!
//! A linear check authenticates x=sum B^i*d_i and zero borrow endpoints.
//! Public tuple lookups certify (digit,borrow_in,borrow_out) for subtraction
//! (p-1)-digits. Thus the integer digit string is <p, not just congruent to x.
use crate::{
    packed_linear::{self, Relation},
    packed_oracle::{ProverOracle, VerifierOracle},
    packed_tuple_lookup,
};
use algebra::{PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::Commitment,
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};

/// Canonical comparisons with shared terminal source authentication.
pub mod deferred;
/// Shared-query comparison algebra and canonical authentication across limbs.
pub mod shared;
/// Shared-query canonical comparison entry points.
pub use shared::{prove as prove_shared,verify as verify_shared};
/// Deferred canonical comparison entry points, for complete-protocol composition.
pub use deferred::{prove as prove_deferred,verify as verify_deferred};

/// Invalid trusted configuration, noncanonical digits, or rejected subproof.
#[derive(Debug, thiserror::Error)]
#[error("packed canonical decomposition: {0}")]
pub struct Error(pub String);
/// Trusted radix, active length and repetition count; digit count derives from p.
#[derive(Clone, Debug, Serialize)]
pub struct Config {
    basis_bits: u32,
    logical_len: usize,
    repetitions: usize,
}
impl Config {
    /// Configure a full canonical prime-field radix decomposition.
    pub fn new<F: PrimeField>(
        basis_bits: u32,
        logical_len: usize,
        repetitions: usize,
    ) -> Result<Self, Error> {
        let config = Self {
            basis_bits,
            logical_len,
            repetitions,
        };
        config.validate::<F>()?;
        Ok(config)
    }
    fn validate<F: PrimeField>(&self) -> Result<(), Error> {
        let radix = self.radix()?;
        let p = characteristic::<F>()?;
        if self.logical_len == 0
            || self.repetitions == 0
            || radix as u128 >= p
            || self.logical_len as u128 + 2 * radix as u128 - 1 >= p
            || radix.checked_mul(2).is_none()
        {
            return Err(error(
                "unsupported radix, length, repetitions or characteristic",
            ));
        }
        Ok(())
    }
    /// Gadget radix, with checked native-size arithmetic.
    pub fn radix(&self) -> Result<usize, Error> {
        if self.basis_bits == 0 {
            return Err(error("zero radix bits"));
        }
        1usize
            .checked_shl(self.basis_bits)
            .ok_or_else(|| error("radix overflow"))
    }
    /// Canonical number of limbs for the prime characteristic.
    pub fn num_digits<F: PrimeField>(&self) -> Result<usize, Error> {
        self.validate::<F>()?;
        let mut x = characteristic::<F>()? - 1;
        let mut count = 0;
        while x != 0 {
            x /= self.radix()? as u128;
            count += 1;
        }
        Ok(count)
    }
    /// Active scalar entries per source/digit column.
    pub fn logical_len(&self) -> usize {
        self.logical_len
    }
    /// Independent tuple hash/reciprocal pairs per limb.
    pub fn repetitions(&self) -> usize {
        self.repetitions
    }
    fn modulus_digit<F: PrimeField>(&self, i: usize) -> Result<usize, Error> {
        let mut x = characteristic::<F>()? - 1;
        let radix = self.radix()? as u128;
        for _ in 0..i {
            x /= radix;
        }
        Ok((x % radix) as usize)
    }
    /// Public transition table for subtracting limb i from p-1, with borrow bits.
    pub fn comparison_table<F: PrimeField>(&self, i: usize) -> Result<Vec<Vec<F>>, Error> {
        if i >= self.num_digits::<F>()? {
            return Err(error("limb index"));
        }
        let radix = self.radix()?;
        let bound = self.modulus_digit::<F>(i)?;
        (0..radix)
            .flat_map(|d| (0..2).map(move |borrow| (d, borrow)))
            .map(|(d, borrow)| {
                Ok(vec![
                    field::<F>(d)?,
                    field::<F>(borrow)?,
                    field::<F>(usize::from(d + borrow > bound))?,
                ])
            })
            .collect()
    }
}
/// Borrow roots are auxiliary; source and digit roots come from the caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O, P = packed_tuple_lookup::Proof<F, O>> {
    /// d+1 borrow columns; initial and final columns are proven zero.
    pub borrow_commitments: Vec<Commitment<O>>,
    /// Shared canonical reconstruction and endpoint check.
    pub linear: packed_linear::Proof<F, O>,
    /// Backend-specific transition packets proving limb ranges and comparison.
    /// Existing backends use one packet per limb; deferred authentication uses one.
    pub comparisons: Vec<P>,
}
/// Canonical decomposition using lane-batched comparison proofs.
pub type LaneProof<F, O> = Proof<F, O, crate::packed_lane_lookup::Proof<F, O>>;

/// Experimental canonical decomposition with extension-field comparisons.
pub type ExtensionProof<F, EF, O> = Proof<F, O, crate::packed_extension_lookup::Proof<F, EF, O>>;

/// Prove canonical decomposition with independently sampled extension pairs.
/// `config.repetitions()` counts extension pairs, not base-field lanes.
/// This experimental backend has no whole-proof security certificate.
pub fn prove_extension<F, EF, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[&ProverOracle<'_, F, H, C>],
) -> Result<ExtensionProof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_extension_with_statistics::<F, EF, H, C>(
        trans,
        config,
        source,
        helper,
        digits,
        &mut crate::packed_lane_lookup::ProverStatistics::default(),
    )
}

/// Prove extension comparisons and accumulate the lookup phase costs.
pub fn prove_extension_with_statistics<F, EF, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[&ProverOracle<'_, F, H, C>],
    statistics: &mut crate::packed_lane_lookup::ProverStatistics,
) -> Result<ExtensionProof<F, EF, H::Output>, Error>
where
    F: PrimeField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, Extension<EF>>(trans, config, source, Some(helper), digits, statistics)
}

/// Verify extension comparisons against expected canonical source/digit roots.
pub fn verify_extension<F, EF, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &VerifierOracle<'_, H::Output, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[VerifierOracle<'_, H::Output, C>],
    proof: &ExtensionProof<F, EF, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, Extension<EF>>(trans, config, source, Some(helper), digits, proof)
}

/// Prove using the original independently repeated comparison backend.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    digits: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, Independent>(
        trans,
        config,
        source,
        None,
        digits,
        &mut crate::packed_lane_lookup::ProverStatistics::default(),
    )
}
/// Verify the original independently repeated comparison backend.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &VerifierOracle<'_, H::Output, C>,
    digits: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, Independent>(trans, config, source, None, digits, proof)
}
/// Prove canonical decomposition with rational challenges in helper lanes.
pub fn prove_lanes<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[&ProverOracle<'_, F, H, C>],
) -> Result<LaneProof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_lanes_with_statistics(
        trans,
        config,
        source,
        helper,
        digits,
        &mut crate::packed_lane_lookup::ProverStatistics::default(),
    )
}
/// Prove lane-batched decomposition and accumulate its lookup phase costs.
pub fn prove_lanes_with_statistics<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[&ProverOracle<'_, F, H, C>],
    statistics: &mut crate::packed_lane_lookup::ProverStatistics,
) -> Result<LaneProof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, Lanes>(trans, config, source, Some(helper), digits, statistics)
}
/// Verify lane-batched canonical comparisons against the same source/digit roots.
pub fn verify_lanes<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &VerifierOracle<'_, H::Output, C>,
    helper: &pcs::matrix_weighted::Parameters<C>,
    digits: &[VerifierOracle<'_, H::Output, C>],
    proof: &LaneProof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, Lanes>(trans, config, source, Some(helper), digits, proof)
}

/// Prove canonical decomposition while reusing all original source/digit roots.
/// Linear reconstruction also covers padding; callers should use consistent
/// zero padding (tuple membership is required only for the active prefix).
pub(crate) fn prove_impl<F, H, C, B>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &ProverOracle<'_, F, H, C>,
    helper: Option<&pcs::matrix_weighted::Parameters<C>>,
    digits: &[&ProverOracle<'_, F, H, C>],
    statistics: &mut crate::packed_lane_lookup::ProverStatistics,
) -> Result<Proof<F, H::Output, B::Proof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: Backend<F, H, C>,
{
    B::bind_domain(trans);
    let public_digits: Vec<_> = digits.iter().map(|d| d.verifier()).collect();
    bind::<F, H, C>(trans, config, &source.verifier(), &public_digits)?;
    bind_helper::<F, H, C>(trans, helper, source.parameters)?;
    let pp = source.parameters;
    let d = config.num_digits::<F>()?;
    for oracle in std::iter::once(source).chain(digits.iter().copied()) {
        oracle.table.validate().map_err(convert)?;
        if oracle.table.width() != pp.width() || oracle.table.num_vars() != pp.num_vars() {
            return Err(error("source table shape"));
        }
    }
    let mut borrows = vec![vec![F::zero(); source.table.values().len()]; d + 1];
    let radix = config.radix()?;
    let bounds = (0..d)
        .map(|i| config.modulus_digit::<F>(i))
        .collect::<Result<Vec<_>, _>>()?;
    for row in 0..config.logical_len {
        let mut borrow = 0;
        for i in 0..d {
            let digit: usize = digits[i].table.values()[row]
                .value()
                .try_into()
                .map_err(|_| error("digit conversion"))?;
            if digit >= radix {
                return Err(error("out-of-range digit"));
            }
            borrow = usize::from(digit + borrow > bounds[i]);
            borrows[i + 1][row] = field::<F>(borrow)?;
        }
        if borrow != 0 {
            return Err(error("digit string is not below the modulus"));
        }
    }
    let borrows = borrows
        .into_iter()
        .map(|v| PackedTable::new(pp.num_vars(), pp.width(), v).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let (borrow_commitments, states): (Vec<_>, Vec<_>) = borrows
        .iter()
        .map(|t| pp.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    trans.append_message(b"packed decomposition borrow roots", &borrow_commitments);
    let borrow_oracles: Vec<_> = borrows
        .iter()
        .zip(&borrow_commitments)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: pp,
            commitment,
            state,
            table,
        })
        .collect();
    let mut linear_sources = vec![source];
    linear_sources.extend(digits.iter().copied());
    linear_sources.extend(borrow_oracles.iter());
    let linear = packed_linear::prove::<F, H, C>(trans, &linear_sources, &relations::<F>(config)?)
        .map_err(convert)?;
    let requests = comparison_requests::<F>(config)?;
    let registry: Vec<_> = digits
        .iter()
        .copied()
        .chain(borrow_oracles.iter())
        .collect();
    let comparisons = B::prove_comparisons(trans, &requests, helper, statistics, &registry)?;
    Ok(Proof {
        borrow_commitments,
        linear,
        comparisons,
    })
}
/// Verify exact integer canonicity and reconstruction against expected roots.
pub(crate) fn verify_impl<F, H, C, B>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &VerifierOracle<'_, H::Output, C>,
    helper: Option<&pcs::matrix_weighted::Parameters<C>>,
    digits: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, H::Output, B::Proof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: Backend<F, H, C>,
{
    B::bind_domain(trans);
    bind::<F, H, C>(trans, config, source, digits)?;
    bind_helper::<F, H, C>(trans, helper, source.parameters)?;
    let d = config.num_digits::<F>()?;
    if proof.borrow_commitments.len() != d + 1
        || proof.comparisons.len() != B::comparison_packets(d)
    {
        return Err(error("decomposition proof counts"));
    }
    trans.append_message(
        b"packed decomposition borrow roots",
        &proof.borrow_commitments,
    );
    let borrow_oracles: Vec<_> = proof
        .borrow_commitments
        .iter()
        .map(|commitment| VerifierOracle {
            parameters: source.parameters,
            commitment,
        })
        .collect();
    let mut linear_sources = vec![VerifierOracle {
        parameters: source.parameters,
        commitment: source.commitment,
    }];
    linear_sources.extend(digits.iter().map(|s| VerifierOracle {
        parameters: s.parameters,
        commitment: s.commitment,
    }));
    linear_sources.extend(borrow_oracles.iter().map(|s| VerifierOracle {
        parameters: s.parameters,
        commitment: s.commitment,
    }));
    packed_linear::verify::<F, H, C>(
        trans,
        &linear_sources,
        &relations::<F>(config)?,
        &proof.linear,
    )
    .map_err(convert)?;
    let requests = comparison_requests::<F>(config)?;
    let registry: Vec<_> = digits
        .iter()
        .chain(&borrow_oracles)
        .map(|s| VerifierOracle {
            parameters: s.parameters,
            commitment: s.commitment,
        })
        .collect();
    B::verify_comparisons(trans, &requests, helper, &registry, &proof.comparisons)?;
    Ok(())
}
/// Extract duplicated external-product input halves in the same physical layout
/// as the native Hadamard digit factors. Their accumulator provenance must be
/// certified by the enclosing PBS protocol, beyond this decomposition component.
pub fn sources_from_blind_rotation<F: PrimeField>(
    width: usize,
    trace: &trace::BlindRotationTrace<F>,
) -> Result<Vec<PackedTable<F>>, Error> {
    let input = &trace.acc_trace.external_product_input.poly;
    if input.0.is_empty()
        || input.0.len() != input.1.len()
        || trace
            .hadamard_trace
            .vec_hadamard
            .iter()
            .any(|t| t.bit.poly.len() != input.0.len())
    {
        return Err(error("native decomposition input/digit lengths"));
    }
    let columns: Vec<Vec<F>> = [&input.0, &input.1]
        .iter()
        .map(|v| v.iter().chain(v.iter()).copied().collect())
        .collect();
    crate::packed_relation::pack_rows(
        width,
        &columns.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
    )
    .map_err(convert)
}

fn relations<F: PrimeField>(config: &Config) -> Result<Vec<Relation<F>>, Error> {
    let d = config.num_digits::<F>()?;
    let mut power = F::one();
    let radix = field::<F>(config.radix()?)?;
    let mut terms = vec![(-F::one(), 0)];
    for i in 0..d {
        terms.push((power, i + 1));
        power *= radix;
    }
    Ok(vec![
        Relation { terms },
        Relation {
            terms: vec![(F::one(), d + 1)],
        },
        Relation {
            terms: vec![(F::one(), 2 * d + 1)],
        },
    ])
}
fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    config: &Config,
    source: &VerifierOracle<'_, H::Output, C>,
    digits: &[VerifierOracle<'_, H::Output, C>],
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    config.validate::<F>()?;
    if digits.len() != config.num_digits::<F>()? {
        return Err(error("canonical digit count"));
    }
    let pp = source.parameters;
    let capacity = 1usize
        .checked_shl(u32::try_from(pp.num_vars()).map_err(convert)?)
        .and_then(|n| n.checked_mul(pp.width()))
        .ok_or_else(|| error("source capacity overflow"))?;
    if pp.num_vars() == 0
        || config.logical_len > capacity
        || digits
            .iter()
            .any(|s| s.parameters.width() != pp.width() || s.parameters.num_vars() != pp.num_vars())
    {
        return Err(error("source dimensions"));
    }
    let contexts = std::iter::once(source)
        .chain(digits)
        .map(|s| {
            Ok((
                s.parameters.context_digest::<F, H>().map_err(convert)?,
                s.commitment,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(
        b"packed canonical radix decomposition v1",
        &(config, F::MODULUS_VALUE.to_string(), contexts),
    );
    Ok(())
}
fn field<F: PrimeField>(value: usize) -> Result<F, Error> {
    Ok(F::new(
        value
            .try_into()
            .map_err(|_| error("field value conversion"))?,
    ))
}
fn characteristic<F: PrimeField>() -> Result<u128, Error> {
    F::MODULUS_VALUE.to_string().parse().map_err(convert)
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

fn comparison_requests<F: PrimeField>(
    config: &Config,
) -> Result<Vec<crate::packed_extension_lookup::deferred::Request<F>>, Error> {
    let d = config.num_digits::<F>()?;
    (0..d)
        .map(|i| {
            Ok(crate::packed_extension_lookup::deferred::Request {
                config: packed_tuple_lookup::Config::new(
                    config.logical_len,
                    config.comparison_table::<F>(i)?,
                    config.repetitions,
                )
                .map_err(convert)?,
                source_slots: vec![i, d + i, d + i + 1],
            })
        })
        .collect()
}

pub(crate) trait Backend<F, H, C>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type Proof;
    const EXTENSION: bool = false;
    const DEFERRED: bool = false;
    const SHARED: bool = false;
    fn bind_domain(_trans: &mut Transcript<F>) {}
    fn comparison_packets(limbs: usize) -> usize {
        limbs
    }
    fn prove_comparisons(
        trans: &mut Transcript<F>,
        requests: &[crate::packed_extension_lookup::deferred::Request<F>],
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        registry: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Vec<Self::Proof>, Error> {
        requests
            .iter()
            .map(|request| {
                let sources: Vec<_> = request.source_slots.iter().map(|&i| registry[i]).collect();
                Self::prove(trans, &request.config, helper, statistics, &sources)
            })
            .collect()
    }
    fn verify_comparisons(
        trans: &mut Transcript<F>,
        requests: &[crate::packed_extension_lookup::deferred::Request<F>],
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        registry: &[VerifierOracle<'_, H::Output, C>],
        proofs: &[Self::Proof],
    ) -> Result<(), Error> {
        if proofs.len() != requests.len() {
            return Err(error("comparison packet count"));
        }
        for (request, proof) in requests.iter().zip(proofs) {
            let sources: Vec<_> = request
                .source_slots
                .iter()
                .map(|&i| VerifierOracle {
                    parameters: registry[i].parameters,
                    commitment: registry[i].commitment,
                })
                .collect();
            Self::verify(trans, &request.config, helper, &sources, proof)?;
        }
        Ok(())
    }
    fn prove(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        sources: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Self::Proof, Error>;
    fn verify(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        sources: &[VerifierOracle<'_, H::Output, C>],
        proof: &Self::Proof,
    ) -> Result<(), Error>;
}
struct Independent;
pub(crate) struct Lanes;
impl<F, H, C> Backend<F, H, C> for Independent
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type Proof = packed_tuple_lookup::Proof<F, H::Output>;
    fn prove(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        _helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        _statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        sources: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Self::Proof, Error> {
        packed_tuple_lookup::prove::<F, H, C>(trans, config, sources).map_err(convert)
    }
    fn verify(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        _helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        sources: &[VerifierOracle<'_, H::Output, C>],
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        packed_tuple_lookup::verify::<F, H, C>(trans, config, sources, proof).map_err(convert)
    }
}
impl<F, H, C> Backend<F, H, C> for Lanes
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type Proof = crate::packed_lane_lookup::Proof<F, H::Output>;
    fn prove(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        sources: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Self::Proof, Error> {
        crate::packed_lane_lookup::prove_with_statistics::<F, H, C>(
            trans,
            config,
            helper.ok_or_else(|| error("missing helper parameters"))?,
            sources,
            statistics,
        )
        .map_err(convert)
    }
    fn verify(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        sources: &[VerifierOracle<'_, H::Output, C>],
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        crate::packed_lane_lookup::verify::<F, H, C>(
            trans,
            config,
            helper.ok_or_else(|| error("missing helper parameters"))?,
            sources,
            proof,
        )
        .map_err(convert)
    }
}
pub(crate) struct Extension<EF>(std::marker::PhantomData<EF>);
impl<F, EF, H, C> Backend<F, H, C> for Extension<EF>
where
    F: PrimeField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    type Proof = crate::packed_extension_lookup::Proof<F, EF, H::Output>;
    const EXTENSION: bool = true;
    fn bind_domain(trans: &mut Transcript<F>) {
        trans.append_message(b"canonical extension decomposition v1", &EF::D);
    }
    fn prove(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        statistics: &mut crate::packed_lane_lookup::ProverStatistics,
        sources: &[&ProverOracle<'_, F, H, C>],
    ) -> Result<Self::Proof, Error> {
        crate::packed_extension_lookup::prove_with_statistics::<F, EF, H, C>(
            trans,
            config,
            helper.ok_or_else(|| error("missing helper parameters"))?,
            sources,
            statistics,
        )
        .map_err(convert)
    }
    fn verify(
        trans: &mut Transcript<F>,
        config: &packed_tuple_lookup::Config<F>,
        helper: Option<&pcs::matrix_weighted::Parameters<C>>,
        sources: &[VerifierOracle<'_, H::Output, C>],
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        crate::packed_extension_lookup::verify::<F, EF, H, C>(
            trans,
            config,
            helper.ok_or_else(|| error("missing helper parameters"))?,
            sources,
            proof,
        )
        .map_err(convert)
    }
}
fn bind_helper<F, H, C>(
    trans: &mut Transcript<F>,
    helper: Option<&pcs::matrix_weighted::Parameters<C>>,
    source: &pcs::matrix_weighted::Parameters<C>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if let Some(helper) = helper {
        if !source.width().is_power_of_two()
            || helper.width() != source.width()
            || helper.num_vars() != source.num_vars() + source.width().ilog2() as usize
            || helper.num_vars() == 0
        {
            return Err(error("lane helper shape"));
        }
        trans.append_message(
            b"canonical lane decomposition v1",
            &helper.context_digest::<F, H>().map_err(convert)?,
        );
    }
    Ok(())
}
