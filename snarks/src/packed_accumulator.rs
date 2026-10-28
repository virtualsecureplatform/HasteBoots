//! Accumulator additions, active-round continuity, endpoints and digit-input links.
//!
//! Canonical roots are supplied by the caller. No shifted/duplicated witness
//! view is committed: deterministic matrix-query maps authenticate those views.
//! Monomial multiplication, key binding and construction of the public initial
//! accumulator remain obligations of the enclosing complete PBS protocol.
use crate::packed_oracle::{
    CanonicalProverOracle, CanonicalVerifierOracle, ProverOracle, VerifierOracle,
};
use algebra::{
    PrimeField,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{BatchOpening, Parameters, backend::CanonicalPcs},
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
    /// Exact query counts for INPUT_ACC through DECOMPOSITION_B, before
    /// any other protocol uses the same owners. Shift branches are retained.
    pub fn opening_counts(&self, width: usize) -> Result<[usize; 7], Error> {
        self.coefficient_variables(width)?;
        Ok([self.row_variables() + 3, 1, 3, 2, 1, 1, 1])
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
    fn validate_dimensions(&self, num_vars: usize, width: usize) -> Result<(), Error> {
        let expected = self.coefficient_variables(width)? + self.row_variables() + 1;
        if num_vars != expected {
            return Err(error("canonical table layout differs from native shape"));
        }
        Ok(())
    }
}
/// Authentic source values for all fixed query maps and one opening per root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalProof<F, P> {
    /// Per-source, per-query terminal vectors. Counts derive from trusted shape.
    pub values: Vec<Vec<Vec<F>>>,
    /// Shared-column openings; no view commitment is accepted.
    pub openings: Vec<P>,
}
/// Legacy Brakedown wire spelling.
pub type Proof<F, O> = CanonicalProof<F, BatchOpening<F, O>>;
/// Prove linkage against caller-supplied initial/final a||b polynomials.
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
    let tables: Vec<_> = sources.iter().map(|s| s.table).collect();
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    prove_inner::<F, H, Parameters<C>>(trans, shape, initial, final_acc, &public, &tables, &states)
}
/// Prove using the original tables retained by the selected canonical backend.
pub fn prove_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[&CanonicalProverOracle<'_, F, H, P>],
) -> Result<CanonicalProof<F, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    let public: Vec<_> = sources.iter().map(|s| s.verifier()).collect();
    let tables: Vec<_> = sources.iter().map(|s| s.table()).collect();
    let states: Vec<_> = sources.iter().map(|s| s.state).collect();
    prove_inner::<F, H, P>(trans, shape, initial, final_acc, &public, &tables, &states)
}
fn prove_inner<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    tables: &[&PackedTable<F>],
    states: &[&P::State],
) -> Result<CanonicalProof<F, P::BatchProof>, Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.len() != SOURCES || tables.len() != SOURCES || states.len() != SOURCES {
        return Err(error("source count"));
    }
    let initial = sources[0].parameters.normalize_values(initial.to_vec());
    let final_acc = sources[0].parameters.normalize_values(final_acc.to_vec());
    let (base, queries) =
        bind_queries_backend::<F, H, P>(trans, shape, &initial, &final_acc, sources)?;
    let mut values = Vec::with_capacity(SOURCES);
    for ((source, table), queries) in sources.iter().zip(tables).zip(&queries) {
        table.validate().map_err(convert)?;
        if table.width() != source.parameters.width()
            || table.num_vars() != source.parameters.num_vars()
        {
            return Err(error("private source shape"));
        }
        values.push(
            evaluate_many(table, queries)?
                .into_iter()
                .map(|v| source.parameters.normalize_values(v))
                .collect(),
        );
    }
    check(shape, &initial, &final_acc, &base, &values)?;
    let openings = sources
        .iter()
        .zip(states)
        .zip(&queries)
        .zip(&values)
        .map(|(((s, state), q), v)| {
            s.parameters
                .open_many(trans, s.commitment, state, q, v)
                .map_err(convert)
        })
        .collect::<Result<_, _>>()?;
    Ok(CanonicalProof { values, openings })
}
/// Verify legacy arithmetic, endpoints, continuity and canonical roots.
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
    verify_canonical::<F, H, Parameters<C>>(trans, shape, initial, final_acc, sources, proof)
}
/// Verify all linkage equations against caller-derived sources and endpoints.
pub fn verify_canonical<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
    proof: &CanonicalProof<F, P::BatchProof>,
) -> Result<(), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.len() != SOURCES {
        return Err(error("source count"));
    }
    let initial = sources[0].parameters.normalize_values(initial.to_vec());
    let final_acc = sources[0].parameters.normalize_values(final_acc.to_vec());
    let (base, queries) =
        bind_queries_backend::<F, H, P>(trans, shape, &initial, &final_acc, sources)?;
    if proof.values.len() != SOURCES
        || proof.openings.len() != SOURCES
        || proof.values.iter().zip(&queries).any(|(v, q)| {
            v.len() != q.len() || v.iter().any(|v| v.len() != sources[0].parameters.width())
        })
    {
        return Err(error("source proof counts or widths"));
    }
    for (s, values) in sources.iter().zip(&proof.values) {
        for value in values {
            s.parameters.validate_values(value).map_err(convert)?;
        }
    }
    check(shape, &initial, &final_acc, &base, &proof.values)?;
    for (((source, q), values), opening) in sources
        .iter()
        .zip(&queries)
        .zip(&proof.values)
        .zip(&proof.openings)
    {
        source
            .parameters
            .verify_many(trans, source.commitment, q, values, opening)
            .map_err(convert)?;
    }
    Ok(())
}
#[cfg(test)]
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
    bind_queries_backend::<F, H, Parameters<C>>(trans, shape, initial, final_acc, sources)
}
fn bind_queries_backend<F, H, P>(
    trans: &mut Transcript<F>,
    shape: &Shape,
    initial: &[F],
    final_acc: &[F],
    sources: &[CanonicalVerifierOracle<'_, H::Output, P>],
) -> Result<(Vec<MatrixPair<F>>, Vec<Vec<Vec<MatrixPair<F>>>>), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
    P: CanonicalPcs<F, H>,
{
    if sources.len() != SOURCES
        || initial.len() != 2 * shape.polynomial_size
        || final_acc.len() != initial.len()
    {
        return Err(error("source count or public endpoint lengths"));
    }
    let pp = sources[0].parameters;
    shape.validate_dimensions(pp.num_vars(), pp.width())?;
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
        .map(|s| Ok((s.parameters.context().map_err(convert)?, s.commitment)))
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(
        P::ACCUMULATOR_DOMAIN,
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
    crate::packed_relation::pack_rows(
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

#[cfg(test)]
mod mapping_tests {
    use super::*;
    use algebra::{BabyBear, Goldilocks};
    fn check_maps<F: PrimeField + From<usize>>() {
        for (n, k, rounds) in [(1usize, 1usize, 1usize), (8, 4, 3), (32, 8, 4), (16, 4, 5)] {
            let shape = Shape::new(n, rounds).unwrap();
            let rows = shape.padded_rounds;
            let vars = shape.coefficient_variables(k).unwrap() + shape.row_variables() + 1;
            let values: Vec<_> = (0..2 * n * rows).map(|i| F::from(i * 7 + 3)).collect();
            let table = PackedTable::new(vars, k, values.clone()).unwrap();
            let base: Vec<_> = (0..vars)
                .map(|i| MatrixPair {
                    zero: Matrix::new(k, (0..k * k).map(|j| F::from(i * 17 + j * 3 + 1)).collect())
                        .unwrap(),
                    one: Matrix::new(
                        k,
                        (0..k * k).map(|j| F::from(i * 13 + j * 7 + 23)).collect(),
                    )
                    .unwrap(),
                })
                .collect();
            let mut shifted = Vec::new();
            for half in 0..2 {
                for row in 0..rows {
                    shifted.extend_from_slice(
                        &values[(half * rows + (row + 1) % rows) * n
                            ..(half * rows + (row + 1) % rows + 1) * n],
                    );
                }
            }
            let shifted = PackedTable::new(vars, k, shifted).unwrap();
            let mut actual = vec![F::zero(); k];
            for query in shift_queries(&shape, k, &base).unwrap() {
                for (a, v) in actual.iter_mut().zip(table.evaluate(&query).unwrap()) {
                    *a += v;
                }
            }
            assert_eq!(actual, shifted.evaluate(&base).unwrap());
            let qs = queries(&shape, k, &base).unwrap();
            assert_eq!(
                qs.iter().map(Vec::len).collect::<Vec<_>>(),
                shape.opening_counts(k).unwrap()
            );
            let optimized = evaluate_many(&table, &qs[INPUT_ACC]).unwrap();
            for (value, query) in optimized.iter().zip(&qs[INPUT_ACC]) {
                assert_eq!(*value, table.evaluate(query).unwrap());
            }
            for half in 0..2 {
                let block = &values[half * rows * n..(half + 1) * rows * n];
                let duplicated =
                    PackedTable::new(vars, k, block.iter().chain(block).copied().collect())
                        .unwrap();
                assert_eq!(
                    table.evaluate(&qs[EXTERNAL_INPUT][half + 1]).unwrap(),
                    duplicated.evaluate(&base).unwrap()
                );
            }
            let initial: Vec<_> = (0..2 * n).map(|i| F::from(i * i + 5)).collect();
            let final_acc: Vec<_> = (0..2 * n).map(|i| F::from(i * 11 + 9)).collect();
            let mut correction = vec![F::zero(); 2 * rows * n];
            for half in 0..2 {
                for coef in 0..n {
                    correction[(half * rows + rows - 1) * n + coef] += initial[half * n + coef];
                    correction[(half * rows + rounds - 1) * n + coef] -= final_acc[half * n + coef];
                }
            }
            let correction = PackedTable::new(vars, k, correction).unwrap();
            let init = coefficient_values(&shape, k, &base, &initial).unwrap();
            let end = coefficient_values(&shape, k, &base, &final_acc).unwrap();
            let a = mix_halves(
                &base,
                &init,
                &row_weight(&shape, k, &base, rows - 1).unwrap(),
            )
            .unwrap();
            let b = mix_halves(
                &base,
                &end,
                &row_weight(&shape, k, &base, rounds - 1).unwrap(),
            )
            .unwrap();
            assert_eq!(
                correction.evaluate(&base).unwrap(),
                a.iter().zip(b).map(|(&a, b)| a - b).collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn query_maps_match_explicit_noncommuting_tables() {
        check_maps::<BabyBear>();
        check_maps::<Goldilocks>();
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use algebra::BabyBear as F;
    use num_traits::{One, Zero};
    use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
    use sha2::Sha256;
    #[test]
    fn genuine_openings_under_requested_endpoints_do_not_bypass_equations() {
        let shape = Shape::new(2, 3).unwrap();
        let width = 2;
        let rows = 4;
        for broken_chain in [false, true] {
            let mut input = vec![F::zero(); 16];
            let mut output = input.clone();
            let mut sum = input.clone();
            for h in 0..2 {
                for r in 0..3 {
                    for c in 0..2 {
                        let at = (h * rows + r) * 2 + c;
                        input[at] = F::from(r);
                        output[at] = F::from(r + 1);
                        sum[at] = F::one();
                    }
                }
            }
            let mut monomial = input.clone();
            let mut initial = vec![F::zero(); 4];
            let final_acc = vec![F::from(3usize); 4];
            if broken_chain {
                input[2] += F::one();
                monomial[2] += F::one();
                output[2] += F::one();
            } else {
                initial[0] += F::one();
            } // Requested endpoint differs from actual source.
            let vectors = vec![
                input,
                monomial,
                vec![F::zero(); 16],
                output,
                sum,
                vec![F::zero(); 16],
                vec![F::zero(); 16],
            ];
            let tables: Vec<_> = vectors
                .into_iter()
                .map(|v| PackedTable::new(3, width, v).unwrap())
                .collect();
            let pp =
                Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(3, width, 32, 2).unwrap();
            let (commitments, states): (Vec<_>, Vec<_>) = tables
                .iter()
                .map(|t| pp.commit::<F, Sha256>(t).unwrap())
                .unzip();
            let oracles: Vec<_> = tables
                .iter()
                .zip(&commitments)
                .zip(&states)
                .map(|((table, commitment), state)| ProverOracle {
                    parameters: &pp,
                    table,
                    commitment,
                    state,
                })
                .collect();
            let public: Vec<_> = oracles.iter().map(|s| s.verifier()).collect();
            // A malicious prover uses the correct requested transcript prefix
            // and genuine openings of different data, bypassing only `check`.
            let mut prover = Transcript::new();
            let (_, queries) =
                bind_queries::<F, Sha256, _>(&mut prover, &shape, &initial, &final_acc, &public)
                    .unwrap();
            let values = oracles
                .iter()
                .zip(&queries)
                .map(|(s, q)| evaluate_many(s.table, q).unwrap())
                .collect::<Vec<_>>();
            let openings = oracles
                .iter()
                .zip(&queries)
                .zip(&values)
                .map(|((s, q), v)| {
                    pp.open_many::<F, Sha256>(&mut prover, s.commitment, s.state, q, v)
                        .unwrap()
                })
                .collect();
            let forged = Proof { values, openings };
            let mut verifier = Transcript::new();
            let (_, queries) =
                bind_queries::<F, Sha256, _>(&mut verifier, &shape, &initial, &final_acc, &public)
                    .unwrap();
            for ((s, q), (v, p)) in public
                .iter()
                .zip(&queries)
                .zip(forged.values.iter().zip(&forged.openings))
            {
                pp.verify_many::<F, Sha256>(&mut verifier, s.commitment, q, v, p)
                    .unwrap();
            }
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
            let error = verify::<F, Sha256, _>(
                &mut Transcript::new(),
                &shape,
                &initial,
                &final_acc,
                &public,
                &forged,
            )
            .unwrap_err();
            if broken_chain {
                assert!(error.0.contains("continuity"));
            } else {
                assert!(error.0.contains("endpoint"));
            }
        }
    }
}

#[cfg(test)]
mod canonical_tests;

#[cfg(test)]
pub(crate) mod audit;
