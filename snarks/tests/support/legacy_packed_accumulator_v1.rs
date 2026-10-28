//! Frozen accumulator reference from ade5c17; unit modules omitted.
//! Accumulator additions, active-round continuity, endpoints and digit-input links.
//!
//! Canonical roots are supplied by the caller. No shifted/duplicated witness
//! view is committed: deterministic matrix-query maps authenticate those views.
//! Monomial multiplication, key binding and construction of the public initial
//! accumulator remain obligations of the enclosing complete PBS protocol.
use snarks::packed_oracle::{ProverOracle, VerifierOracle};
use algebra::{
    PrimeField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::BatchOpening,
    utils::{code::RowCode, hash::Hash},
};
use serde::{Deserialize, Serialize};
use sumcheck::packed::challenge_pair;

/// Index of the concatenated input accumulator halves.
pub const INPUT_ACC: usize = 0;
/// Index of the concatenated monomial-times-accumulator halves.
pub const MONOMIAL_PRODUCT: usize = 1;
/// Index of the concatenated external-product input halves.
pub const EXTERNAL_INPUT: usize = 2;
/// Index of the concatenated output accumulator halves.
pub const OUTPUT_ACC: usize = 3;
/// Index of the existing Hadamard sum-product coefficient source.
pub const SUM_PRODUCT: usize = 4;
/// Index of the existing duplicated-a input used by canonical decomposition.
pub const DECOMPOSITION_A: usize = 5;
/// Index of the existing duplicated-b input used by canonical decomposition.
pub const DECOMPOSITION_B: usize = 6;
const SOURCES: usize = 7;
/// False relation, incompatible trusted layout, or rejected canonical opening.
#[derive(Debug, thiserror::Error)]
#[error("packed accumulator linkage: {0}")]
pub struct Error(pub String);
/// Trusted native polynomial and active round dimensions.
#[derive(Clone, Debug, Serialize)]
pub struct Shape {
    polynomial_size: usize,
    rounds: usize,
    padded_rounds: usize,
}
impl Shape {
    /// Configure concatenated a||b tables with consecutive polynomial rows.
    pub fn new(polynomial_size: usize, rounds: usize) -> Result<Self, Error> {
        if !polynomial_size.is_power_of_two() || rounds == 0 {
            return Err(error("polynomial size or active rounds"));
        }
        let padded_rounds = rounds
            .checked_next_power_of_two()
            .ok_or_else(|| error("round padding overflow"))?;
        polynomial_size
            .checked_mul(padded_rounds)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| error("scalar length overflow"))?;
        Ok(Self {
            polynomial_size,
            rounds,
            padded_rounds,
        })
    }
    /// Coefficients per polynomial.
    pub fn polynomial_size(&self) -> usize {
        self.polynomial_size
    }
    /// Actual blind-rotation rounds (padding is not a public iteration).
    pub fn rounds(&self) -> usize {
        self.rounds
    }
    /// Power-of-two row domain for each ciphertext half.
    pub fn padded_rounds(&self) -> usize {
        self.padded_rounds
    }
    fn coefficient_variables(&self, width: usize) -> Result<usize, Error> {
        if !width.is_power_of_two() || width > self.polynomial_size {
            return Err(error("packing does not divide polynomial size"));
        }
        Ok((self.polynomial_size / width).ilog2() as usize)
    }
    fn row_variables(&self) -> usize {
        self.padded_rounds.ilog2() as usize
    }
    fn validate<C>(&self, pp: &pcs::matrix_weighted::Parameters<C>) -> Result<(), Error> {
        let expected = self.coefficient_variables(pp.width())? + self.row_variables() + 1;
        if pp.num_vars() != expected {
            return Err(error("canonical table layout differs from native shape"));
        }
        Ok(())
    }
}
/// Authentic source values for all fixed query maps and one opening per root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Per-source, per-query terminal vectors. Counts derive from trusted shape.
    pub values: Vec<Vec<Vec<F>>>,
    /// Shared-column openings; no view commitment is accepted.
    pub openings: Vec<BatchOpening<F, O>>,
}
/// Prove linkage against expected initial/final a||b polynomials. Public endpoints
/// are consumed in equations, not merely hashed into a transcript prefix.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let (base, queries) = bind_queries::<F, H, C>(trans, shape, initial, final_acc, &public)?;
    let mut values = Vec::with_capacity(SOURCES);
    for (source, queries) in sources.iter().zip(&queries) {
        source.table.validate().map_err(convert)?;
        if source.table.width() != source.parameters.width()
            || source.table.num_vars() != source.parameters.num_vars()
        {
            return Err(error("private source shape"));
        }
        values.push(evaluate_many(source.table, queries)?);
    }
    check(shape, initial, final_acc, &base, &values)?;
    let openings = sources
        .iter()
        .zip(&queries)
        .zip(&values)
        .map(|((s, q), v)| {
            s.parameters
                .open_many::<F, H>(trans, s.commitment, s.state, q, v)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Proof { values, openings })
}
/// Verify arithmetic, actual-round endpoints, continuity and every canonical root.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let (base, queries) = bind_queries::<F, H, C>(trans, shape, initial, final_acc, sources)?;
    if proof.values.len() != SOURCES
        || proof.openings.len() != SOURCES
        || proof.values.iter().zip(&queries).any(|(v, q)| {
            v.len() != q.len() || v.iter().any(|v| v.len() != sources[0].parameters.width())
        })
    {
        return Err(error("source proof counts or widths"));
    }
    check(shape, initial, final_acc, &base, &proof.values)?;
    for (((source, q), values), opening) in sources
        .iter()
        .zip(&queries)
        .zip(&proof.values)
        .zip(&proof.openings)
    {
        source
            .parameters
            .verify_many::<F, H>(trans, source.commitment, q, values, opening)
            .map_err(convert)?;
    }
    Ok(())
}
fn bind_queries<F, H, C>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[VerifierOracle<'_, H::Output, C>],
) -> Result<(Vec<MatrixPair<F>>, Vec<Vec<Vec<MatrixPair<F>>>>), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if sources.len() != SOURCES
        || initial.len() != 2 * shape.polynomial_size
        || final_acc.len() != initial.len()
    {
        return Err(error("source count or public endpoint lengths"));
    }
    let pp = sources[0].parameters;
    shape.validate(pp)?;
    if sources
        .iter()
        .any(|s| s.parameters.width() != pp.width() || s.parameters.num_vars() != pp.num_vars())
    {
        return Err(error("incompatible canonical source dimensions"));
    }
    let p: u128 = F::MODULUS_VALUE.to_string().parse().map_err(convert)?;
    if 2 * pp.width() as u128 >= p {
        return Err(error("field too small for lane interpolation"));
    }
    let contexts = sources
        .iter()
        .map(|s| {
            Ok((
                s.parameters.context_digest::<F, H>().map_err(convert)?,
                s.commitment,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(
        b"packed accumulator canonical linkage v1",
        &(shape, initial, final_acc, contexts),
    );
    let base = (0..pp.num_vars())
        .map(|_| {
            challenge_pair(
                &trans.get_vec_challenge(b"accumulator independent lane challenges", pp.width()),
            )
            .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let queries = queries(shape, pp.width(), &base)?;
    Ok((base, queries))
}
fn queries<F: PrimeField>(
    shape: &Shape,
    width: usize,
    base: &[MatrixPair<F>],
) -> Result<Vec<Vec<Vec<MatrixPair<F>>>>, Error> {
    let mut result = vec![vec![base.to_vec()]; SOURCES];
    result[INPUT_ACC].push(select_row(shape, width, base, 0)?);
    result[INPUT_ACC].extend(shift_queries(shape, width, base)?);
    result[OUTPUT_ACC].push(select_row(shape, width, base, shape.rounds - 1)?);
    for half in 0..2 {
        let mut query = base.to_vec();
        let last = query
            .last_mut()
            .ok_or_else(|| error("missing half variable"))?;
        let sum = matrix_add(&last.zero, &last.one)?;
        *last = if half == 0 {
            MatrixPair {
                zero: sum,
                one: zero(width)?,
            }
        } else {
            MatrixPair {
                zero: zero(width)?,
                one: sum,
            }
        };
        result[EXTERNAL_INPUT].push(query);
    }
    Ok(result)
}
fn select_row<F: PrimeField>(
    shape: &Shape,
    width: usize,
    base: &[MatrixPair<F>],
    row: usize,
) -> Result<Vec<MatrixPair<F>>, Error> {
    let c = shape.coefficient_variables(width)?;
    let mut query = base.to_vec();
    for bit in 0..shape.row_variables() {
        query[c + bit] = selector(
            width,
            (row >> bit) & 1,
            Matrix::identity(width).map_err(convert)?,
        )?;
    }
    Ok(query)
}
// r=t+1 mod M. For r!=0 choose its first set bit j: t has low j
// ones and bit j zero. A disjoint branch keeps the ordered low weight in
// matrix C_j; r=0 is the wrap branch. No matrices are commuted.
fn shift_queries<F: PrimeField>(
    shape: &Shape,
    width: usize,
    base: &[MatrixPair<F>],
) -> Result<Vec<Vec<MatrixPair<F>>>, Error> {
    let c = shape.coefficient_variables(width)?;
    let r = shape.row_variables();
    if r == 0 {
        return Ok(vec![base.to_vec()]);
    }
    let mut result = Vec::with_capacity(r + 1);
    let mut low = Matrix::identity(width).map_err(convert)?;
    for j in 0..r {
        let mut query = base.to_vec();
        for i in 0..j {
            query[c + i] = selector(width, 0, Matrix::identity(width).map_err(convert)?)?;
        }
        query[c + j] = selector(width, 1, base[c + j].zero.mul(&low).map_err(convert)?)?;
        result.push(query);
        low = base[c + j].one.mul(&low).map_err(convert)?;
    }
    let mut wrap = base.to_vec();
    wrap[c] = selector(width, 0, low)?;
    for i in 1..r {
        wrap[c + i] = selector(width, 0, Matrix::identity(width).map_err(convert)?)?;
    }
    result.push(wrap);
    Ok(result)
}
fn selector<F: PrimeField>(
    width: usize,
    bit: usize,
    matrix: Matrix<F>,
) -> Result<MatrixPair<F>, Error> {
    Ok(if bit == 0 {
        MatrixPair {
            zero: matrix,
            one: zero(width)?,
        }
    } else {
        MatrixPair {
            zero: zero(width)?,
            one: matrix,
        }
    })
}
fn zero<F: PrimeField>(width: usize) -> Result<Matrix<F>, Error> {
    Matrix::new(
        width,
        vec![
            F::zero();
            width
                .checked_mul(width)
                .ok_or_else(|| error("matrix size overflow"))?
        ],
    )
    .map_err(convert)
}
fn matrix_add<F: PrimeField>(a: &Matrix<F>, b: &Matrix<F>) -> Result<Matrix<F>, Error> {
    Matrix::new(
        a.width(),
        a.values()
            .iter()
            .zip(b.values())
            .map(|(&a, &b)| a + b)
            .collect(),
    )
    .map_err(convert)
}
fn evaluate_many<F: PrimeField>(
    table: &PackedTable<F>,
    queries: &[Vec<MatrixPair<F>>],
) -> Result<Vec<Vec<F>>, Error> {
    let mut common = table.num_vars();
    for query in &queries[1..] {
        common = common.min(
            queries[0]
                .iter()
                .zip(query)
                .take_while(|(a, b)| a == b)
                .count(),
        );
    }
    let mut prefix = table.clone();
    for pair in &queries[0][..common] {
        prefix.fold_in_place(pair).map_err(convert)?;
    }
    queries
        .iter()
        .map(|q| prefix.evaluate(&q[common..]).map_err(convert))
        .collect()
}
fn coefficient_values<F: PrimeField>(
    shape: &Shape,
    width: usize,
    base: &[MatrixPair<F>],
    endpoint: &[F],
) -> Result<Vec<Vec<F>>, Error> {
    let c = shape.coefficient_variables(width)?;
    endpoint
        .chunks_exact(shape.polynomial_size)
        .map(|half| {
            PackedTable::new(c, width, half.to_vec())
                .map_err(convert)?
                .evaluate(&base[..c])
                .map_err(convert)
        })
        .collect()
}
fn mix_halves<F: PrimeField>(
    base: &[MatrixPair<F>],
    halves: &[Vec<F>],
    weight: &Matrix<F>,
) -> Result<Vec<F>, Error> {
    let k = weight.width();
    let mut a = vec![F::zero(); k];
    let mut b = a.clone();
    weight.add_mul(&halves[0], &mut a);
    weight.add_mul(&halves[1], &mut b);
    let mut result = vec![F::zero(); k];
    let half = base.last().ok_or_else(|| error("half query missing"))?;
    half.zero.add_mul(&a, &mut result);
    half.one.add_mul(&b, &mut result);
    Ok(result)
}
fn row_weight<F: PrimeField>(
    shape: &Shape,
    width: usize,
    base: &[MatrixPair<F>],
    row: usize,
) -> Result<Matrix<F>, Error> {
    let c = shape.coefficient_variables(width)?;
    let mut weight = Matrix::identity(width).map_err(convert)?;
    for bit in 0..shape.row_variables() {
        let pair = &base[c + bit];
        weight = if (row >> bit) & 1 == 0 {
            pair.zero.mul(&weight)
        } else {
            pair.one.mul(&weight)
        }
        .map_err(convert)?;
    }
    Ok(weight)
}
fn check<F: PrimeField>(
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    base: &[MatrixPair<F>],
    values: &[Vec<Vec<F>>],
) -> Result<(), Error> {
    let width = values[INPUT_ACC][0].len();
    let init = coefficient_values(shape, width, base, initial)?;
    let end = coefficient_values(shape, width, base, final_acc)?;
    let identity = Matrix::identity(width).map_err(convert)?;
    let expected_initial = mix_halves(base, &init, &identity)?;
    let expected_final = mix_halves(base, &end, &identity)?;
    let correction_initial = mix_halves(
        base,
        &init,
        &row_weight(shape, width, base, shape.padded_rounds - 1)?,
    )?;
    let correction_final = mix_halves(
        base,
        &end,
        &row_weight(shape, width, base, shape.rounds - 1)?,
    )?;
    for lane in 0..width {
        if values[EXTERNAL_INPUT][0][lane]
            != values[MONOMIAL_PRODUCT][0][lane] - values[INPUT_ACC][0][lane]
            || values[OUTPUT_ACC][0][lane]
                != values[INPUT_ACC][0][lane] + values[SUM_PRODUCT][0][lane]
            || values[EXTERNAL_INPUT][1][lane] != values[DECOMPOSITION_A][0][lane]
            || values[EXTERNAL_INPUT][2][lane] != values[DECOMPOSITION_B][0][lane]
            || values[INPUT_ACC][1][lane] != expected_initial[lane]
            || values[OUTPUT_ACC][1][lane] != expected_final[lane]
        {
            return Err(error(
                "false arithmetic, duplicated-half or endpoint identity",
            ));
        }
        let shifted = values[INPUT_ACC][2..]
            .iter()
            .fold(F::zero(), |s, v| s + v[lane]);
        if shifted - values[OUTPUT_ACC][0][lane]
            != correction_initial[lane] - correction_final[lane]
        {
            return Err(error("false accumulator round continuity"));
        }
    }
    Ok(())
}
/// Extract only the four new finalized coefficient tables in INPUT_ACC..OUTPUT_ACC order.
/// Reuse the existing sum-product and decomposition roots as sources 4..6.
pub fn from_native<F: PrimeField>(
    width: usize,
    trace: &trace::BlindRotationTrace<F>,
) -> Result<Vec<PackedTable<F>>, Error> {
    let acc = &trace.acc_trace;
    let half = acc.input_acc.poly.0.len();
    if !half.is_power_of_two()
        || [
            &acc.input_acc.poly,
            &acc.monomial_times_acc.poly,
            &acc.external_product_input.poly,
            &acc.output_acc.poly,
        ]
        .iter()
        .any(|v| v.0.len() != half || v.1.len() != half)
    {
        return Err(error("native tables must have equal finalized halves"));
    }
    let columns: Vec<Vec<F>> = [
        &acc.input_acc.poly,
        &acc.monomial_times_acc.poly,
        &acc.external_product_input.poly,
        &acc.output_acc.poly,
    ]
    .iter()
    .map(|v| v.0.iter().chain(&v.1).copied().collect())
    .collect();
    snarks::packed_relation::pack_rows(
        width,
        &columns.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
    .map_err(convert)
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

