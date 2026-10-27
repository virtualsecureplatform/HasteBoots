//! Canonical key switching for N=next_power_of_two(output LWE dimension).
//! The final accumulator is a shared witness endpoint, constrained upstream by
//! packed_accumulator; the verifier consumes the public output ciphertext here.
use crate::{
    packed_decomposition, packed_monomial, packed_ntt,
    packed_oracle::{ProverOracle, VerifierOracle},
    packed_relation,
};
use algebra::{NTTField, matrix_weighted::PackedTable, transformation::AbstractNTT};
use helper::{FiatShamirTranscript, Transcript};
use lattice::NTTGadgetRLWE;
use pcs::{
    matrix_weighted::{Commitment, Opening, Parameters, State},
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use sumcheck::{
    packed::PackedShape,
    packed_zero::{self, ZeroProof},
};

/// Rejected parameters, witnesses, output relation or authenticated subproof.
#[derive(Debug, thiserror::Error)]
#[error("packed key switch: {0}")]
pub struct Error(String);
/// Trusted native dimensions/radix and independently budgeted lookup repetitions.
#[derive(Clone, Debug, Serialize)]
pub struct Config {
    n: usize,
    lwe: usize,
    bits: u32,
    repetitions: usize,
}
impl Config {
    /// Supports the original BabyBear and Goldilocks PBS parameter sets.
    /// Unequal ring/padded-LWE dimensions require the additional native permutation.
    pub fn new<F: NTTField>(
        n: usize,
        lwe: usize,
        bits: u32,
        repetitions: usize,
    ) -> Result<Self, Error> {
        if lwe == 0 || lwe.checked_next_power_of_two() != Some(n) {
            return Err(error("unsupported ring/output dimension relation"));
        }
        n.checked_mul(2)
            .ok_or_else(|| error("polynomial size overflow"))?;
        let result = Self {
            n,
            lwe,
            bits,
            repetitions,
        };
        result.decomposition::<F>()?;
        F::generate_ntt_table(n.ilog2()).map_err(convert)?;
        Ok(result)
    }
    /// Number of coefficients in each key-switching polynomial.
    pub fn polynomial_size(&self) -> usize {
        self.n
    }
    /// Original, unpadded output LWE dimension.
    pub fn output_dimension(&self) -> usize {
        self.lwe
    }
    /// Number of canonical radix digits.
    pub fn digits<F: NTTField>(&self) -> Result<usize, Error> {
        self.decomposition::<F>()?
            .num_digits::<F>()
            .map_err(convert)
    }
    fn decomposition<F: NTTField>(&self) -> Result<packed_decomposition::Config, Error> {
        packed_decomposition::Config::new::<F>(self.bits, 2 * self.n, self.repetitions)
            .map_err(convert)
    }
    fn validate<F: NTTField, C>(&self, pp: &Parameters<C>) -> Result<(), Error> {
        if !pp.width().is_power_of_two()
            || pp.width() > self.n
            || pp.num_vars() != (2 * self.n / pp.width()).ilog2() as usize
        {
            return Err(error("key switching PCS dimensions"));
        }
        Ok(())
    }
}
/// Expected key roots from authenticated public setup, never from proof bytes.
#[derive(Clone, Debug, Serialize)]
pub struct ExpectedKey<O> {
    config: Config,
    context: O,
    roots: Vec<Commitment<O>>,
}
impl<O> ExpectedKey<O> {
    /// Trusted configuration used by all final-stage subproofs.
    pub fn config(&self) -> &Config {
        &self.config
    }
    /// Public NTT key roots in least-significant digit order.
    pub fn roots(&self) -> &[Commitment<O>] {
        &self.roots
    }
}
/// Reusable prover setup; its states are never serialized or verifier inputs.
pub struct ProverKey<F, H: Hash + Send + Sync> {
    expected: ExpectedKey<H::Output>,
    tables: Vec<PackedTable<F>>,
    states: Vec<State<F, H>>,
}
impl<F, H: Hash + Send + Sync> ProverKey<F, H> {
    /// Strip private PCS state and expose only trusted public-key commitments.
    pub fn expected(&self) -> &ExpectedKey<H::Output> {
        &self.expected
    }
}
/// Commit the native public switching key independently of an execution trace.
pub fn preprocess<F, H, C>(
    pp: &Parameters<C>,
    config: Config,
    key: &[NTTGadgetRLWE<F>],
) -> Result<ProverKey<F, H>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    config.validate::<F, C>(pp)?;
    let d = config.digits::<F>()?;
    if key.len() != 1 || key[0].basis().bits() != config.bits || key[0].data().len() != d {
        return Err(error("switching key radix or chunks"));
    }
    let tables = key[0]
        .iter()
        .map(|p| {
            if p.a_slice().len() != config.n || p.b_slice().len() != config.n {
                return Err(error("switching key polynomial length"));
            }
            PackedTable::new(
                pp.num_vars(),
                pp.width(),
                p.a_slice().iter().chain(p.b_slice()).copied().collect(),
            )
            .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (roots, states) = commit::<F, H, C>(pp, &tables)?;
    Ok(ProverKey {
        expected: ExpectedKey {
            context: pp.context_digest::<F, H>().map_err(convert)?,
            config,
            roots,
        },
        tables,
        states,
    })
}
/// Canonical private coefficients: duplicated digit columns, then the a||b sum.
/// No native key column is trusted or imported by this adapter.
pub fn from_native<F: NTTField>(
    width: usize,
    trace: &trace::key_switching_trace::KeySwitchingTrace<F>,
) -> Result<Vec<PackedTable<F>>, Error> {
    let h = &trace.hadamard_trace;
    let n = h.sum_prod.poly.0.len();
    if h.num_hadamard == 0
        || h.vec_hadamard.len() != h.num_hadamard
        || !n.is_power_of_two()
        || !width.is_power_of_two()
        || width > n
        || h.sum_prod.poly.1.len() != n
        || trace.permutation_trace.is_some()
    {
        return Err(error("unsupported native key-switching trace"));
    }
    let mut columns = h
        .vec_hadamard
        .iter()
        .map(|t| {
            if t.bit.poly.len() != n {
                return Err(error("native switching digit length"));
            }
            Ok(t.bit.poly.iter().chain(&t.bit.poly).copied().collect())
        })
        .collect::<Result<Vec<Vec<F>>, _>>()?;
    columns.push(
        h.sum_prod
            .poly
            .0
            .iter()
            .chain(&h.sum_prod.poly.1)
            .copied()
            .collect(),
    );
    columns
        .into_iter()
        .map(|v| PackedTable::new((2 * n / width).ilog2() as usize, width, v).map_err(convert))
        .collect()
}
/// Authenticated extraction constraints against the canonical coefficient sum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionProof<F, O> {
    pub zero: ZeroProof<F>,
    pub value: Vec<F>,
    pub opening: Opening<F, O>,
}
/// All private roots are fixed before any subproof challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O, D = packed_decomposition::LaneProof<F, O>> {
    pub coefficients: Vec<Commitment<O>>,
    pub evaluations: Vec<Commitment<O>>,
    pub ntt: Vec<packed_ntt::Proof<F, O>>,
    pub product: packed_relation::RelationProof<F, O>,
    pub decomposition: D,
    pub extraction: ExtractionProof<F, O>,
}
/// Prove canonical negative-a decomposition, key products and the public output.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ProverKey<F, H>,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    coefficients: &[PackedTable<F>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, packed_decomposition::Lanes>(
        trans,
        pp,
        helper,
        key,
        final_acc,
        output_a,
        output_b,
        coefficients,
    )
}

/// Experimental key switching with canonical extension-field comparisons.
pub fn prove_extension<F, EF, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ProverKey<F, H>,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    coefficients: &[PackedTable<F>],
) -> Result<Proof<F, H::Output, packed_decomposition::ExtensionProof<F, EF, H::Output>>, Error>
where
    F: NTTField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    prove_impl::<F, H, C, packed_decomposition::Extension<EF>>(
        trans,
        pp,
        helper,
        key,
        final_acc,
        output_a,
        output_b,
        coefficients,
    )
}

pub(crate) fn prove_impl<F, H, C, B>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ProverKey<F, H>,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    coefficients: &[PackedTable<F>],
) -> Result<Proof<F, H::Output, packed_decomposition::Proof<F, H::Output, B::Proof>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: packed_decomposition::Backend<F, H, C>,
{
    let expected = &key.expected;
    let cfg = &expected.config;
    let d = cfg.digits::<F>()?;
    if coefficients.len() != d + 1
        || coefficients
            .iter()
            .any(|t| t.num_vars() != pp.num_vars() || t.width() != pp.width())
    {
        return Err(error("private coefficient source count or dimensions"));
    }
    let (roots, states) = commit::<F, H, C>(pp, coefficients)?;
    F::init_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let native = F::get_ntt_table(cfg.n.ilog2()).map_err(convert)?;
    let tables = coefficients
        .iter()
        .map(|t| {
            let mut v = t.values().to_vec();
            for p in v.chunks_exact_mut(cfg.n) {
                native.transform_slice(p);
            }
            PackedTable::new(pp.num_vars(), pp.width(), v).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, ntt_states) = commit::<F, H, C>(pp, &tables)?;
    bind::<F, H, C>(
        trans,
        pp,
        helper,
        expected,
        final_acc,
        output_a,
        output_b,
        &roots,
        &evaluations,
    )?;
    let co = oracles(pp, coefficients, &roots, &states);
    let no = oracles(pp, &tables, &evaluations, &ntt_states);
    let ko = oracles(pp, &key.tables, &expected.roots, &key.states);
    let shape = packed_ntt::Shape::new::<F, C>(pp, cfg.n).map_err(convert)?;
    let ntt = (0..d + 1)
        .map(|i| packed_ntt::prove::<F, H, C>(trans, &shape, &co[i], &no[i]).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?;
    let mut factors = Vec::new();
    let mut commitments = Vec::new();
    let mut product_states = Vec::new();
    for i in 0..d {
        for o in [&no[i], &ko[i]] {
            factors.push(o.table.clone());
            commitments.push(o.commitment.clone());
            product_states.push(o.state);
        }
    }
    factors.push(tables[d].clone());
    commitments.push(evaluations[d].clone());
    product_states.push(&ntt_states[d]);
    let product = packed_relation::prove_with_state_references::<F, H, C>(
        trans,
        &product_shape(pp, d),
        pp,
        &factors,
        &commitments,
        &product_states,
        &mut packed_relation::ProverStatistics::default(),
    )
    .map_err(convert)?;
    let input = input::<F, C>(pp, cfg, final_acc)?;
    let (input_root, input_state) = pp.commit::<F, H>(&input).map_err(convert)?;
    let source = ProverOracle {
        parameters: pp,
        commitment: &input_root,
        state: &input_state,
        table: &input,
    };
    let decomposition = packed_decomposition::prove_impl::<F, H, C, B>(
        trans,
        &cfg.decomposition::<F>()?,
        &source,
        Some(helper),
        &co[..d].iter().collect::<Vec<_>>(),
        &mut crate::packed_lane_lookup::ProverStatistics::default(),
    )
    .map_err(convert)?;
    let (mask, target) = extraction_tables::<F, C>(pp, cfg, final_acc, output_a, output_b)?;
    let (zero, subclaim, terminals) = packed_zero::prove_with_terminal_values(
        trans,
        &extraction_shape(pp),
        &[coefficients[d].clone(), mask.clone(), target.clone()],
    )
    .map_err(convert)?;
    let value = terminals[0].clone();
    subclaim
        .check(
            &extraction_shape(pp),
            &[
                value.clone(),
                mask.evaluate(&subclaim.query).map_err(convert)?,
                target.evaluate(&subclaim.query).map_err(convert)?,
            ],
        )
        .map_err(convert)?;
    let opening = pp
        .open::<F, H>(trans, &roots[d], &states[d], &subclaim.query, &value)
        .map_err(convert)?;
    Ok(Proof {
        coefficients: roots,
        evaluations,
        ntt,
        product,
        decomposition,
        extraction: ExtractionProof {
            zero,
            value,
            opening,
        },
    })
}
/// Verify using only trusted public setup, a shared accumulator endpoint and
/// the original, unpadded public output ciphertext. No native PBS recomputation.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ExpectedKey<H::Output>,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, packed_decomposition::Lanes>(
        trans, pp, helper, key, final_acc, output_a, output_b, proof,
    )
}

/// Verify experimental extension comparisons and the original output relation.
pub fn verify_extension<F, EF, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ExpectedKey<H::Output>,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    proof: &Proof<F, H::Output, packed_decomposition::ExtensionProof<F, EF, H::Output>>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    EF: algebra::AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    verify_impl::<F, H, C, packed_decomposition::Extension<EF>>(
        trans, pp, helper, key, final_acc, output_a, output_b, proof,
    )
}

pub(crate) fn verify_impl<F, H, C, B>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ExpectedKey<H::Output>,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    proof: &Proof<F, H::Output, packed_decomposition::Proof<F, H::Output, B::Proof>>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
    B: packed_decomposition::Backend<F, H, C>,
{
    bind::<F, H, C>(
        trans,
        pp,
        helper,
        key,
        final_acc,
        output_a,
        output_b,
        &proof.coefficients,
        &proof.evaluations,
    )?;
    let cfg = &key.config;
    let d = cfg.digits::<F>()?;
    if proof.ntt.len() != d + 1 {
        return Err(error("NTT proof count"));
    }
    let co = proof
        .coefficients
        .iter()
        .map(|commitment| VerifierOracle {
            parameters: pp,
            commitment,
        })
        .collect::<Vec<_>>();
    let no = proof
        .evaluations
        .iter()
        .map(|commitment| VerifierOracle {
            parameters: pp,
            commitment,
        })
        .collect::<Vec<_>>();
    let shape = packed_ntt::Shape::new::<F, C>(pp, cfg.n).map_err(convert)?;
    for i in 0..d + 1 {
        packed_ntt::verify::<F, H, C>(trans, &shape, &co[i], &no[i], &proof.ntt[i])
            .map_err(convert)?;
    }
    let mut roots = Vec::with_capacity(2 * d + 1);
    for i in 0..d {
        roots.push(proof.evaluations[i].clone());
        roots.push(key.roots[i].clone());
    }
    roots.push(proof.evaluations[d].clone());
    packed_relation::verify::<F, H, C>(trans, &product_shape(pp, d), pp, &roots, &proof.product)
        .map_err(convert)?;
    let input = input::<F, C>(pp, cfg, final_acc)?;
    let (root, _) = pp.commit::<F, H>(&input).map_err(convert)?;
    packed_decomposition::verify_impl::<F, H, C, B>(
        trans,
        &cfg.decomposition::<F>()?,
        &VerifierOracle {
            parameters: pp,
            commitment: &root,
        },
        Some(helper),
        &proof.coefficients[..d]
            .iter()
            .map(|commitment| VerifierOracle {
                parameters: pp,
                commitment,
            })
            .collect::<Vec<_>>(),
        &proof.decomposition,
    )
    .map_err(convert)?;
    verify_extraction::<F, H, C>(
        trans,
        pp,
        cfg,
        final_acc,
        output_a,
        output_b,
        &proof.coefficients[d],
        &proof.extraction,
    )
}
fn verify_extraction<F, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    cfg: &Config,
    final_acc: &[F],
    output_a: &[F],
    output_b: F,
    root: &Commitment<H::Output>,
    proof: &ExtractionProof<F, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let (mask, target) = extraction_tables::<F, C>(pp, cfg, final_acc, output_a, output_b)?;
    let shape = extraction_shape(pp);
    let subclaim = packed_zero::verify(trans, &shape, &proof.zero).map_err(convert)?;
    subclaim
        .check(
            &shape,
            &[
                proof.value.clone(),
                mask.evaluate(&subclaim.query).map_err(convert)?,
                target.evaluate(&subclaim.query).map_err(convert)?,
            ],
        )
        .map_err(convert)?;
    pp.verify::<F, H>(trans, root, &subclaim.query, &proof.value, &proof.opening)
        .map_err(convert)
}
fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    helper: &Parameters<C>,
    key: &ExpectedKey<H::Output>,
    final_acc: &[F],
    a: &[F],
    b: F,
    coefficients: &[Commitment<H::Output>],
    evaluations: &[Commitment<H::Output>],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let cfg = &key.config;
    cfg.validate::<F, C>(pp)?;
    let d = cfg.digits::<F>()?;
    if coefficients.len() != d + 1
        || evaluations.len() != d + 1
        || key.roots.len() != d
        || pp.context_digest::<F, H>().map_err(convert)? != key.context
        || final_acc.len() != 2 * cfg.n
        || a.len() != cfg.lwe
    {
        return Err(error("key, endpoint or source dimensions/context"));
    }
    trans.append_message(
        b"packed original RLWE key switch v1",
        &(
            key,
            helper.context_digest::<F, H>().map_err(convert)?,
            final_acc,
            a,
            b,
            coefficients,
            evaluations,
        ),
    );
    Ok(())
}
fn input<F: NTTField, C>(
    pp: &Parameters<C>,
    cfg: &Config,
    final_acc: &[F],
) -> Result<PackedTable<F>, Error> {
    if final_acc.len() != 2 * cfg.n {
        return Err(error("final accumulator length"));
    }
    PackedTable::new(
        pp.num_vars(),
        pp.width(),
        final_acc[..cfg.n]
            .iter()
            .chain(&final_acc[..cfg.n])
            .map(|&a| -a)
            .collect(),
    )
    .map_err(convert)
}
fn extraction_tables<F: NTTField, C>(
    pp: &Parameters<C>,
    cfg: &Config,
    acc: &[F],
    a: &[F],
    b: F,
) -> Result<(PackedTable<F>, PackedTable<F>), Error> {
    if acc.len() != 2 * cfg.n || a.len() != cfg.lwe {
        return Err(error("extraction endpoint length"));
    }
    let mut mask = vec![F::zero(); 2 * cfg.n];
    let mut target = mask.clone();
    mask[0] = F::one();
    target[0] = a[0];
    for i in 1..cfg.lwe {
        mask[cfg.n - i] = F::one();
        target[cfg.n - i] = -a[i];
    }
    mask[cfg.n] = F::one();
    let bias = packed_monomial::nand_lut::<F>(cfg.n, 1).map_err(convert)?[0];
    target[cfg.n] = b - acc[cfg.n] - bias;
    Ok((
        PackedTable::new(pp.num_vars(), pp.width(), mask).map_err(convert)?,
        PackedTable::new(pp.num_vars(), pp.width(), target).map_err(convert)?,
    ))
}
fn extraction_shape<F: NTTField, C>(pp: &Parameters<C>) -> PackedShape<F> {
    PackedShape {
        num_vars: pp.num_vars(),
        width: pp.width(),
        num_factors: 3,
        terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
    }
}
fn product_shape<F: NTTField, C>(pp: &Parameters<C>, d: usize) -> PackedShape<F> {
    let mut terms = (0..d)
        .map(|i| (F::one(), vec![2 * i, 2 * i + 1]))
        .collect::<Vec<_>>();
    terms.push((-F::one(), vec![2 * d]));
    PackedShape {
        num_vars: pp.num_vars(),
        width: pp.width(),
        num_factors: 2 * d + 1,
        terms,
    }
}
fn commit<F, H, C>(
    pp: &Parameters<C>,
    tables: &[PackedTable<F>],
) -> Result<(Vec<Commitment<H::Output>>, Vec<State<F, H>>), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    tables
        .iter()
        .map(|t| pp.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.into_iter().unzip())
}
fn oracles<'a, F, H: Hash + Send + Sync, C>(
    pp: &'a Parameters<C>,
    tables: &'a [PackedTable<F>],
    roots: &'a [Commitment<H::Output>],
    states: &'a [State<F, H>],
) -> Vec<ProverOracle<'a, F, H, C>> {
    tables
        .iter()
        .zip(roots)
        .zip(states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: pp,
            table,
            commitment,
            state,
        })
        .collect()
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

#[cfg(test)]
mod extraction_binding_tests {
    use super::*;
    use algebra::BabyBear as F;
    use pcs::utils::code::BlockReedSolomonCode;
    use sha2::Sha256;
    #[test]
    fn genuine_openings_for_another_output_fail_the_requested_public_equation() {
        let n = 32;
        let lwe = 21;
        let cfg = Config::new::<F>(n, lwe, 5, 2).unwrap();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(4, 4, 32, 2).unwrap();
        let values = (0..2 * n).map(|i| F::from(i + 4)).collect::<Vec<_>>();
        let table = PackedTable::new(4, 4, values.clone()).unwrap();
        let (root, state) = pp.commit::<F, Sha256>(&table).unwrap();
        let acc = vec![F::from(13); 2 * n];
        let actual = (0..lwe)
            .map(|i| if i == 0 { values[0] } else { -values[n - i] })
            .collect::<Vec<_>>();
        let body = values[n] + acc[n] + packed_monomial::nand_lut::<F>(n, 1).unwrap()[0];
        let (mask, target) = extraction_tables(&pp, &cfg, &acc, &actual, body).unwrap();
        assert_eq!(mask.values()[1], F::from(0));
        assert_eq!(mask.values()[n - lwe + 1], F::from(1));
        for changed in [0, 1, lwe - 1, lwe] {
            let mut requested = actual.clone();
            let mut requested_body = body;
            if changed == lwe {
                requested_body += F::from(1);
            } else {
                requested[changed] += F::from(1);
            }
            let prefix = |t: &mut Transcript<F>| {
                t.append_message(
                    b"requested original output",
                    &(&requested, requested_body, &root),
                )
            };
            let mut prover = Transcript::new();
            prefix(&mut prover);
            // All child proofs are genuine under the requested context, but
            // the public factor supplied by this malicious prover is the old output.
            let shape = extraction_shape(&pp);
            let (zero, subclaim) = packed_zero::prove(
                &mut prover,
                &shape,
                &[table.clone(), mask.clone(), target.clone()],
            )
            .unwrap();
            let value = table.evaluate(&subclaim.query).unwrap();
            let opening = pp
                .open::<F, Sha256>(&mut prover, &root, &state, &subclaim.query, &value)
                .unwrap();
            let proof = ExtractionProof {
                zero,
                value,
                opening,
            };
            let mut own = Transcript::new();
            prefix(&mut own);
            verify_extraction::<F, Sha256, _>(
                &mut own, &pp, &cfg, &acc, &actual, body, &root, &proof,
            )
            .unwrap();
            assert_eq!(prover.get_challenge(b"after"), own.get_challenge(b"after"));
            let mut verifier = Transcript::new();
            prefix(&mut verifier);
            assert!(
                verify_extraction::<F, Sha256, _>(
                    &mut verifier,
                    &pp,
                    &cfg,
                    &acc,
                    &requested,
                    requested_body,
                    &root,
                    &proof
                )
                .is_err()
            );
        }
    }
}
