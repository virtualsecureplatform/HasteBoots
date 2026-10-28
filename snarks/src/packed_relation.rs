//! Authenticated packed vector relations. This is a component, not a PBS proof.
//!
//! The verifier supplies the public relation and trusted commitments. In a full
//! PBS protocol those commitments must also be linked to the other PBS stages.
//! This reference construction is non-hiding and has no end-to-end security claim.

use algebra::{PrimeField, matrix_weighted::PackedTable};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{Commitment, Opening, Parameters, State, backend::CanonicalPcs},
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use sumcheck::{
    packed::PackedShape,
    packed_zero::{self, ZeroProof},
};

/// Experimental shared PCS authentication of all relation factor values.
pub mod aggregate;
/// Shared-challenge independent relations with one joint PCS authentication.
pub mod batch;

/// Failure while packing rows, proving or verifying an authenticated relation.
#[derive(Debug, thiserror::Error)]
#[error("packed relation: {0}")]
pub struct Error(pub String);

/// Phase measurements for one honest packed relation proof.
#[derive(Default, Debug)]
pub struct ProverStatistics {
    /// Packed ZeroCheck, including its public equality factor.
    pub zero_check: Duration,
    /// Terminal evaluation of the original committed tables.
    pub terminal_evaluation: Duration,
    /// Matrix-weighted opening generation.
    pub openings: Duration,
}

/// Complete proof of one committed vector relation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalRelationProof<F, P> {
    /// ZeroCheck proof, excluding the matrix-weighted commitment openings.
    pub zero: ZeroProof<F>,
    /// Claimed terminal vector for every committed factor.
    pub values: Vec<Vec<F>>,
    /// Authentication of each terminal vector against its supplied commitment.
    pub openings: Vec<P>,
}

/// Legacy Brakedown relation spelling and unchanged single-opening layout.
pub type RelationProof<F, O> = CanonicalRelationProof<F, Opening<F, O>>;
/// Pack distinct consecutive rows into lanes, padding to a Boolean domain.
/// Every term must contain a factor so all-zero padding satisfies the relation.
pub fn pack_rows<F: PrimeField>(
    width: usize,
    columns: &[&[F]],
) -> Result<Vec<PackedTable<F>>, Error> {
    if width == 0
        || columns.is_empty()
        || columns[0].is_empty()
        || columns.iter().any(|c| c.len() != columns[0].len())
    {
        return Err(Error("empty or unequal columns".into()));
    }
    let rows = columns[0]
        .len()
        .div_ceil(width)
        .max(2)
        .checked_next_power_of_two()
        .ok_or_else(|| Error("row count overflow".into()))?;
    let length = rows
        .checked_mul(width)
        .ok_or_else(|| Error("table length overflow".into()))?;
    columns
        .iter()
        .map(|c| {
            let mut values = c.to_vec();
            values.resize(length, F::zero());
            PackedTable::new(rows.ilog2() as usize, width, values).map_err(convert)
        })
        .collect()
}

/// Extract the external-product Hadamard relations from a native PBS trace.
/// This certifies only the NTT-domain sum of products; NTT correctness, digit
/// ranges, key binding and accumulator continuity require separate arguments.
pub fn from_sum_hadamard<F: PrimeField>(
    width: usize,
    trace: &trace::basic_ops::SumHadamardTrace<F>,
) -> Result<(PackedShape<F>, Vec<PackedTable<F>>), Error> {
    if trace.num_hadamard == 0 || trace.vec_hadamard.len() != trace.num_hadamard {
        return Err(Error("invalid Hadamard trace count".into()));
    }
    let size = trace.sum_prod.ntt.0.len();
    if size == 0
        || trace.sum_prod.ntt.1.len() != size
        || trace.vec_hadamard.iter().any(|t| {
            t.bit.ntt.len() != size || t.rlwe.ntt.0.len() != size || t.rlwe.ntt.1.len() != size
        })
    {
        return Err(Error("invalid Hadamard trace lengths".into()));
    }
    let mut columns: Vec<Vec<F>> = Vec::with_capacity(2 * trace.num_hadamard + 1);
    let mut terms = Vec::with_capacity(trace.num_hadamard + 1);
    for item in &trace.vec_hadamard {
        let index = columns.len();
        columns.push(item.bit.ntt.iter().chain(&item.bit.ntt).copied().collect());
        columns.push(
            item.rlwe
                .ntt
                .0
                .iter()
                .chain(&item.rlwe.ntt.1)
                .copied()
                .collect(),
        );
        terms.push((F::one(), vec![index, index + 1]));
    }
    terms.push((-F::one(), vec![columns.len()]));
    columns.push(
        trace
            .sum_prod
            .ntt
            .0
            .iter()
            .chain(&trace.sum_prod.ntt.1)
            .copied()
            .collect(),
    );
    let factors = pack_rows(
        width,
        &columns.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
    )?;
    let shape = PackedShape {
        num_vars: factors[0].num_vars(),
        width,
        num_factors: factors.len(),
        terms,
    };
    Ok((shape, factors))
}

/// Extract coefficient-domain sources in exactly the factor order and layout
/// used by `from_sum_hadamard`. These are NTT opening sources, not pointwise
/// coefficient-domain product claims (the latter would require convolution).
pub fn coefficients_from_sum_hadamard<F: PrimeField>(
    width: usize,
    trace: &trace::basic_ops::SumHadamardTrace<F>,
) -> Result<Vec<PackedTable<F>>, Error> {
    if trace.num_hadamard == 0 || trace.vec_hadamard.len() != trace.num_hadamard {
        return Err(Error("invalid Hadamard trace count".into()));
    }
    let size = trace.sum_prod.poly.0.len();
    if size == 0
        || trace.sum_prod.poly.1.len() != size
        || trace.vec_hadamard.iter().any(|t| {
            t.bit.poly.len() != size || t.rlwe.poly.0.len() != size || t.rlwe.poly.1.len() != size
        })
    {
        return Err(Error("invalid coefficient trace lengths".into()));
    }
    let mut columns: Vec<Vec<F>> = Vec::with_capacity(2 * trace.num_hadamard + 1);
    for item in &trace.vec_hadamard {
        columns.push(
            item.bit
                .poly
                .iter()
                .chain(&item.bit.poly)
                .copied()
                .collect(),
        );
        columns.push(
            item.rlwe
                .poly
                .0
                .iter()
                .chain(&item.rlwe.poly.1)
                .copied()
                .collect(),
        );
    }
    columns.push(
        trace
            .sum_prod
            .poly
            .0
            .iter()
            .chain(&trace.sum_prod.poly.1)
            .copied()
            .collect(),
    );
    pack_rows(
        width,
        &columns.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
    )
}

/// Prove a committed sum-of-products relation that vanishes on every row.
/// Bind public provenance (for example, ciphertexts) to `trans` before calling.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    parameters: &Parameters<C>,
    factors: &[PackedTable<F>],
    commitments: &[Commitment<H::Output>],
    states: &[State<F, H>],
) -> Result<RelationProof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_with_statistics(
        trans,
        shape,
        parameters,
        factors,
        commitments,
        states,
        &mut ProverStatistics::default(),
    )
}

/// Prove a relation and accumulate per-phase measurements without changing its transcript.
pub fn prove_with_statistics<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    parameters: &Parameters<C>,
    factors: &[PackedTable<F>],
    commitments: &[Commitment<H::Output>],
    states: &[State<F, H>],
    statistics: &mut ProverStatistics,
) -> Result<RelationProof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_with_state_references(
        trans,
        shape,
        parameters,
        factors,
        commitments,
        &states.iter().collect::<Vec<_>>(),
        statistics,
    )
}

/// Reuse canonical states held in different setup/witness owners.
/// This runs the same protocol and transcript as `prove_with_statistics`.
pub fn prove_with_state_references<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    parameters: &Parameters<C>,
    factors: &[PackedTable<F>],
    commitments: &[Commitment<H::Output>],
    states: &[&State<F, H>],
    statistics: &mut ProverStatistics,
) -> Result<RelationProof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if states.len() != shape.num_factors || commitments.len() != shape.num_factors {
        return Err(Error("incorrect factor commitment count".into()));
    }
    let public: Vec<_> = commitments
        .iter()
        .map(|commitment| crate::packed_oracle::CanonicalVerifierOracle {
            parameters,
            commitment,
        })
        .collect();
    prove_inner::<F, H, Parameters<C>>(trans, shape, &public, factors, states, statistics, true)
}
/// Prove a polynomial identity from actual retained canonical source tables.
/// The entire original witness is borrowed; no extra source view is committed.
pub fn prove_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[&crate::packed_oracle::CanonicalProverOracle<'_, F, H, P>],
    statistics: &mut ProverStatistics,
) -> Result<CanonicalRelationProof<F, P::SingleProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let tables: Vec<_> = sources.iter().map(|s| s.table()).collect();
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    prove_inner::<F, H, P>(trans, shape, &public, &tables, &states, statistics, false)
}
fn canonical_shape<F, H, P>(shape: &PackedShape<F>, parameters: &P) -> PackedShape<F>
where
    F: PrimeField,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let coefficients = parameters.normalize_values(shape.terms.iter().map(|(a, _)| *a).collect());
    PackedShape {
        num_vars: shape.num_vars,
        width: shape.width,
        num_factors: shape.num_factors,
        terms: coefficients
            .into_iter()
            .zip(shape.terms.iter().map(|(_, indices)| indices.clone()))
            .collect(),
    }
}
fn bind_sources<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[crate::packed_oracle::CanonicalVerifierOracle<'_, H::Output, P>],
    legacy_wire: bool,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    shape.validate().map_err(convert)?;
    if sources.len() != shape.num_factors
        || sources.is_empty()
        || sources.iter().any(|s| {
            s.parameters.num_vars() != shape.num_vars || s.parameters.width() != shape.width
        })
    {
        return Err(Error("relation source dimensions".into()));
    }
    let roots: Vec<_> = sources.iter().map(|s| s.commitment).collect();
    if legacy_wire {
        trans.append_message(b"HasteBoots packed relation v1", &(shape, roots));
    } else {
        let contexts: Vec<_> = sources
            .iter()
            .map(|s| s.parameters.context().map_err(convert))
            .collect::<Result<_, _>>()?;
        trans.append_message(P::RELATION_DOMAIN, &(shape, contexts, roots));
    }
    Ok(())
}
fn prove_inner<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[crate::packed_oracle::CanonicalVerifierOracle<'_, H::Output, P>],
    factors: &[impl std::borrow::Borrow<PackedTable<F>> + Sync],
    states: &[&P::State],
    statistics: &mut ProverStatistics,
    legacy_wire: bool,
) -> Result<CanonicalRelationProof<F, P::SingleProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.is_empty() || states.len() != shape.num_factors {
        return Err(Error("incorrect factor commitment count".into()));
    }
    let normalized =
        (!legacy_wire).then(|| canonical_shape::<F, H, P>(shape, sources[0].parameters));
    let shape = normalized.as_ref().unwrap_or(shape);
    bind_sources::<F, H, P>(trans, shape, sources, legacy_wire)?;
    let timer = Instant::now();
    let (zero, subclaim, values) =
        packed_zero::prove_with_borrowed_terminal_values(trans, shape, factors).map_err(convert)?;
    statistics.zero_check += timer.elapsed();
    let timer = Instant::now();
    let values: Vec<_> = sources
        .iter()
        .zip(values)
        .map(|(s, v)| s.parameters.normalize_values(v))
        .collect();
    subclaim.check(shape, &values).map_err(convert)?;
    statistics.terminal_evaluation += timer.elapsed();
    trans.append_message(b"packed relation terminal values", &values);
    let timer = Instant::now();
    let openings = sources
        .iter()
        .zip(states)
        .zip(&values)
        .map(|((source, state), value)| {
            source
                .parameters
                .open(trans, source.commitment, state, &subclaim.query, value)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    statistics.openings += timer.elapsed();
    Ok(CanonicalRelationProof {
        zero,
        values,
        openings,
    })
}

/// Verify without any factor tables or private commitment state.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    parameters: &Parameters<C>,
    commitments: &[Commitment<H::Output>],
    proof: &RelationProof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let sources: Vec<_> = commitments
        .iter()
        .map(|commitment| crate::packed_oracle::CanonicalVerifierOracle {
            parameters,
            commitment,
        })
        .collect();
    verify_inner::<F, H, Parameters<C>>(trans, shape, &sources, proof, true)
}
/// Authenticate every canonical factor terminal and check the polynomial identity.
pub fn verify_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[crate::packed_oracle::CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalRelationProof<F, P::SingleProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    verify_inner::<F, H, P>(trans, shape, sources, proof, false)
}
fn verify_inner<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &PackedShape<F>,
    sources: &[crate::packed_oracle::CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalRelationProof<F, P::SingleProof>,
    legacy_wire: bool,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.is_empty() {
        return Err(Error(
            "incorrect factor commitment/opening dimensions".into(),
        ));
    }
    let normalized =
        (!legacy_wire).then(|| canonical_shape::<F, H, P>(shape, sources[0].parameters));
    let shape = normalized.as_ref().unwrap_or(shape);
    shape.validate().map_err(convert)?;
    if sources.len() != shape.num_factors
        || proof.values.len() != shape.num_factors
        || proof.openings.len() != shape.num_factors
        || proof.values.iter().any(|v| v.len() != shape.width)
    {
        return Err(Error(
            "incorrect factor commitment/opening dimensions".into(),
        ));
    }
    for (source, value) in sources.iter().zip(&proof.values) {
        source.parameters.validate_values(value).map_err(convert)?;
    }
    bind_sources::<F, H, P>(trans, shape, sources, legacy_wire)?;
    let subclaim = packed_zero::verify(trans, shape, &proof.zero).map_err(convert)?;
    subclaim.check(shape, &proof.values).map_err(convert)?;
    trans.append_message(b"packed relation terminal values", &proof.values);
    for ((source, value), opening) in sources.iter().zip(&proof.values).zip(&proof.openings) {
        source
            .parameters
            .verify(trans, source.commitment, &subclaim.query, value, opening)
            .map_err(convert)?;
    }
    Ok(())
}

fn convert(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}
