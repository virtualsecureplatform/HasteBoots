//! Public negacyclic rotations and their product with canonical accumulators.
//! Expected exponents are caller inputs; the verifier derives the monomial
//! evaluation itself. Two NTT checks reuse the original coefficient roots.
use crate::{
    packed_ntt,
    packed_oracle::{ProverOracle, VerifierOracle},
};
use algebra::{
    NTTField, PrimeField,
    matrix_weighted::{MatrixPair, PackedTable},
    modulus_switching::round_modulus_u128,
    transformation::AbstractNTT,
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::{
    matrix_weighted::{Commitment, Opening},
    utils::{code::RowCode, hash::Hash},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sumcheck::{
    packed::PackedShape,
    packed_zero::{self, ZeroProof},
};
/// Invalid public plan, false product, or rejected authenticated subproof.
#[derive(Debug, thiserror::Error)]
#[error("packed public monomial product: {0}")]
pub struct Error(pub String);
/// Trusted public exponents in Z_(2N), one per actual blind-rotation round.
#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    polynomial_size: usize,
    rotations: Vec<usize>,
    padded_rounds: usize,
}
impl Plan {
    /// Configure public signed negacyclic monomials; padding rows are zero.
    pub fn new(polynomial_size: usize, rotations: Vec<usize>) -> Result<Self, Error> {
        let twice = polynomial_size
            .checked_mul(2)
            .ok_or_else(|| error("polynomial size overflow"))?;
        if !polynomial_size.is_power_of_two()
            || rotations.is_empty()
            || rotations.iter().any(|&r| r >= twice)
        {
            return Err(error("invalid polynomial size or public exponent"));
        }
        let padded_rounds = rotations
            .len()
            .checked_next_power_of_two()
            .ok_or_else(|| error("round padding overflow"))?;
        polynomial_size
            .checked_mul(padded_rounds)
            .and_then(|n| n.checked_mul(2))
            .ok_or_else(|| error("table size overflow"))?;
        Ok(Self {
            polynomial_size,
            rotations,
            padded_rounds,
        })
    }
    /// Derive exponents by exact public modulus switching, without trace data.
    pub fn from_field_mask<F: PrimeField>(
        polynomial_size: usize,
        mask: &[F],
    ) -> Result<Self, Error> {
        let modulus = polynomial_size
            .checked_mul(2)
            .ok_or_else(|| error("rotation modulus overflow"))?;
        Self::new(
            polynomial_size,
            mask.iter()
                .map(|&a| switch_public_scalar(a, modulus))
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
    /// Coefficients per polynomial.
    pub fn polynomial_size(&self) -> usize {
        self.polynomial_size
    }
    /// Explicit expected exponent sequence.
    pub fn rotations(&self) -> &[usize] {
        &self.rotations
    }
    /// Padded row count per ciphertext half.
    pub fn padded_rounds(&self) -> usize {
        self.padded_rounds
    }
    fn variables(&self, width: usize) -> Result<usize, Error> {
        if !width.is_power_of_two() || width > self.polynomial_size {
            return Err(error("packing does not divide polynomial size"));
        }
        Ok((self.polynomial_size / width).ilog2() as usize
            + self.padded_rounds.ilog2() as usize
            + 1)
    }
    /// Materialize public monomials with the native NTT for prover/reference use.
    /// The verifier uses `evaluate` and does not construct this full table.
    pub fn table<F: NTTField>(&self, width: usize) -> Result<PackedTable<F>, Error> {
        let vars = self.variables(width)?;
        let n = self.polynomial_size;
        ntt_table::<F>(n)?;
        let mut half = vec![F::zero(); self.padded_rounds * n];
        half.par_chunks_exact_mut(n)
            .enumerate()
            .try_for_each(|(row, poly)| {
                if let Some(&rotation) = self.rotations.get(row) {
                    poly[rotation % n] = if rotation < n { F::one() } else { -F::one() };
                    F::get_ntt_table(n.ilog2())
                        .map_err(convert)?
                        .transform_slice(poly);
                }
                Ok::<(), Error>(())
            })?;
        PackedTable::new(vars, width, half.iter().chain(&half).copied().collect()).map_err(convert)
    }
    /// Evaluate the public NTT table in O(L*k²*log(N/k)+M*k²) field work,
    /// keeping row and half matrix order. Native outputs are bit-reversed.
    pub fn evaluate<F: NTTField>(
        &self,
        width: usize,
        query: &[MatrixPair<F>],
    ) -> Result<Vec<F>, Error> {
        let vars = self.variables(width)?;
        if query.len() != vars {
            return Err(error("public monomial query variable count"));
        }
        for pair in query {
            pair.validate(width).map_err(convert)?;
        }
        let root = ntt_table::<F>(self.polynomial_size)?.root();
        let nbits = self.polynomial_size.ilog2();
        let lane_bits = width.ilog2();
        let coefficient = (nbits - lane_bits) as usize;
        let mut rows = vec![F::zero(); self.padded_rounds * width];
        rows.par_chunks_exact_mut(width)
            .enumerate()
            .for_each(|(row, out)| {
                let Some(&rotation) = self.rotations.get(row) else {
                    return;
                };
                let phase = power(root, rotation);
                let mut value: Vec<_> = (0..width)
                    .map(|lane| {
                        let reversed = if nbits == 0 {
                            0
                        } else {
                            lane.reverse_bits() >> (usize::BITS - nbits)
                        };
                        power(phase, 2 * reversed + 1)
                    })
                    .collect();
                for (bit, pair) in query[..coefficient].iter().enumerate() {
                    let multiplier = power(phase, 1usize << (nbits - lane_bits - bit as u32));
                    let mut zero = vec![F::zero(); width];
                    let mut one = zero.clone();
                    pair.zero.add_mul(&value, &mut zero);
                    pair.one.add_mul(&value, &mut one);
                    for (a, b) in zero.iter_mut().zip(one) {
                        *a += multiplier * b;
                    }
                    value = zero;
                }
                out.copy_from_slice(&value);
            });
        let value = PackedTable::new(self.padded_rounds.ilog2() as usize, width, rows)
            .map_err(convert)?
            .evaluate(&query[coefficient..vars - 1])
            .map_err(convert)?;
        let mut result = vec![F::zero(); width];
        query[vars - 1].zero.add_mul(&value, &mut result);
        query[vars - 1].one.add_mul(&value, &mut result);
        Ok(result)
    }
}
/// Exact public scalar preprocessing. Invalid residues/moduli return an error.
pub fn switch_public_scalar<F: PrimeField>(value: F, after: usize) -> Result<usize, Error> {
    let p: u128 = F::MODULUS_VALUE.to_string().parse().map_err(convert)?;
    let a: u128 = value.value().to_string().parse().map_err(convert)?;
    if after == 0 || after as u128 >= p || a >= p {
        return Err(error("invalid public modulus-switch input"));
    }
    usize::try_from(round_modulus_u128(a, p, after as u128)).map_err(convert)
}
/// Public native NAND lookup polynomial, including its configured stride.
pub fn nand_lut<F: PrimeField>(size: usize, stride: usize) -> Result<Vec<F>, Error> {
    if !size.is_power_of_two() || stride == 0 {
        return Err(error("invalid public LUT shape"));
    }
    let p: u128 = F::MODULUS_VALUE.to_string().parse().map_err(convert)?;
    let low = F::new(
        usize::try_from(p / 8)
            .map_err(convert)?
            .try_into()
            .map_err(|_| error("field conversion"))?,
    );
    let mut lut = vec![F::zero(); size];
    let mid = (size >> 1) + (size >> 2);
    for i in (0..mid).step_by(stride) {
        lut[i] = low;
    }
    for i in (mid..size).step_by(stride) {
        lut[i] = -low;
    }
    Ok(lut)
}
/// Derive the initial (zero-a, X^(-b)*LUT) accumulator from public data.
pub fn initial_accumulator<F: PrimeField>(lut: &[F], body: F) -> Result<Vec<F>, Error> {
    let n = lut.len();
    let twice = n.checked_mul(2).ok_or_else(|| error("LUT size overflow"))?;
    if !n.is_power_of_two() {
        return Err(error("LUT is not a power-of-two polynomial"));
    }
    let switched = switch_public_scalar(body, twice)?;
    let rotation = (twice - switched) % twice;
    let mut result = vec![F::zero(); twice];
    for (j, &value) in lut.iter().enumerate() {
        let at = (j + rotation) % twice;
        if at < n {
            result[n + at] += value;
        } else {
            result[at] -= value;
        }
    }
    Ok(result)
}
/// Product proof: exactly two derived NTT roots, linked to expected coefficients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Input/product NTT roots fixed before algebraic checks.
    pub evaluations: Vec<Commitment<O>>,
    /// Coefficient-to-NTT consistency for both original canonical roots.
    pub ntt: Vec<packed_ntt::Proof<F, O>>,
    /// Public monomial times input equals product, in the NTT domain.
    pub product: ZeroProof<F>,
    /// Authenticated input/product NTT terminal vectors.
    pub values: Vec<Vec<F>>,
    /// Openings against the two derived roots.
    pub openings: Vec<Opening<F, O>>,
}
/// Prove input*X^expected_rotation=product using the caller's coefficient roots.
pub fn prove<F, H, C>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    coefficients: &[&ProverOracle<'_, F, H, C>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let public: Vec<_> = coefficients.iter().map(|s| s.verifier()).collect();
    bind::<F, H, C>(trans, plan, &public)?;
    let pp = coefficients[0].parameters;
    ntt_table::<F>(plan.polynomial_size)?;
    let tables = coefficients
        .iter()
        .map(|s| {
            s.table.validate().map_err(convert)?;
            if s.table.width() != pp.width() || s.table.num_vars() != pp.num_vars() {
                return Err(error("coefficient table shape"));
            }
            let mut values = s.table.values().to_vec();
            values
                .par_chunks_exact_mut(plan.polynomial_size)
                .try_for_each(|poly| {
                    F::get_ntt_table(plan.polynomial_size.ilog2())
                        .map_err(convert)?
                        .transform_slice(poly);
                    Ok::<(), Error>(())
                })?;
            PackedTable::new(pp.num_vars(), pp.width(), values).map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (evaluations, states): (Vec<_>, Vec<_>) = tables
        .iter()
        .map(|t| pp.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    trans.append_message(b"public monomial NTT roots", &evaluations);
    let oracles: Vec<_> = tables
        .iter()
        .zip(&evaluations)
        .zip(&states)
        .map(|((table, commitment), state)| ProverOracle {
            parameters: pp,
            table,
            commitment,
            state,
        })
        .collect();
    let ntt_shape = packed_ntt::Shape::new::<F, C>(pp, plan.polynomial_size).map_err(convert)?;
    let mut ntt = Vec::with_capacity(2);
    for i in 0..2 {
        ntt.push(
            packed_ntt::prove::<F, H, C>(trans, &ntt_shape, coefficients[i], &oracles[i])
                .map_err(convert)?,
        );
    }
    let shape = product_shape(pp.num_vars(), pp.width());
    let factors = vec![
        tables[0].clone(),
        plan.table::<F>(pp.width())?,
        tables[1].clone(),
    ];
    let (product, subclaim, terminals) =
        packed_zero::prove_with_terminal_values(trans, &shape, &factors).map_err(convert)?;
    let values = vec![terminals[0].clone(), terminals[2].clone()];
    subclaim
        .check(
            &shape,
            &[
                values[0].clone(),
                plan.evaluate(pp.width(), &subclaim.query)?,
                values[1].clone(),
            ],
        )
        .map_err(convert)?;
    let openings = oracles
        .iter()
        .zip(&values)
        .map(|(s, v)| {
            pp.open::<F, H>(trans, s.commitment, s.state, &subclaim.query, v)
                .map_err(convert)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Proof {
        evaluations,
        ntt,
        product,
        values,
        openings,
    })
}
/// Verify public rotations and both NTT links without private coefficient tables.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    coefficients: &[VerifierOracle<'_, H::Output, C>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    bind::<F, H, C>(trans, plan, coefficients)?;
    if proof.evaluations.len() != 2
        || proof.ntt.len() != 2
        || proof.values.len() != 2
        || proof.openings.len() != 2
    {
        return Err(error("monomial proof counts"));
    }
    let pp = coefficients[0].parameters;
    trans.append_message(b"public monomial NTT roots", &proof.evaluations);
    let oracles: Vec<_> = proof
        .evaluations
        .iter()
        .map(|commitment| VerifierOracle {
            parameters: pp,
            commitment,
        })
        .collect();
    let ntt_shape = packed_ntt::Shape::new::<F, C>(pp, plan.polynomial_size).map_err(convert)?;
    for i in 0..2 {
        packed_ntt::verify::<F, H, C>(
            trans,
            &ntt_shape,
            &coefficients[i],
            &oracles[i],
            &proof.ntt[i],
        )
        .map_err(convert)?;
    }
    let shape = product_shape(pp.num_vars(), pp.width());
    let subclaim = packed_zero::verify(trans, &shape, &proof.product).map_err(convert)?;
    subclaim
        .check(
            &shape,
            &[
                proof.values[0].clone(),
                plan.evaluate(pp.width(), &subclaim.query)?,
                proof.values[1].clone(),
            ],
        )
        .map_err(convert)?;
    for i in 0..2 {
        pp.verify::<F, H>(
            trans,
            oracles[i].commitment,
            &subclaim.query,
            &proof.values[i],
            &proof.openings[i],
        )
        .map_err(convert)?;
    }
    Ok(())
}
fn bind<F, H, C>(
    trans: &mut Transcript<F>,
    plan: &Plan,
    coefficients: &[VerifierOracle<'_, H::Output, C>],
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if coefficients.len() != 2 {
        return Err(error("expected input/product coefficient roots"));
    }
    let pp = coefficients[0].parameters;
    if pp.num_vars() != plan.variables(pp.width())?
        || coefficients
            .iter()
            .any(|s| s.parameters.width() != pp.width() || s.parameters.num_vars() != pp.num_vars())
    {
        return Err(error("canonical rotation table shape"));
    }
    let root = ntt_table::<F>(plan.polynomial_size)?.root();
    let contexts = coefficients
        .iter()
        .map(|s| {
            Ok((
                s.parameters.context_digest::<F, H>().map_err(convert)?,
                s.commitment,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    trans.append_message(
        b"packed expected monomial product v1",
        &(plan, root, contexts),
    );
    Ok(())
}
fn product_shape<F: PrimeField>(num_vars: usize, width: usize) -> PackedShape<F> {
    PackedShape {
        num_vars,
        width,
        num_factors: 3,
        terms: vec![(F::one(), vec![0, 1]), (-F::one(), vec![2])],
    }
}
fn ntt_table<F: NTTField>(size: usize) -> Result<std::sync::Arc<F::Table>, Error> {
    F::generate_ntt_table(size.ilog2()).map_err(convert)?;
    F::init_ntt_table(size.ilog2()).map_err(convert)?;
    F::get_ntt_table(size.ilog2()).map_err(convert)
}
fn power<F: PrimeField>(mut base: F, mut exponent: usize) -> F {
    let mut result = F::one();
    while exponent != 0 {
        if exponent & 1 != 0 {
            result *= base;
        }
        base *= base;
        exponent >>= 1;
    }
    result
}
fn error(s: &str) -> Error {
    Error(s.into())
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use algebra::BabyBear as F;
    use pcs::{matrix_weighted::Parameters, utils::code::BlockReedSolomonCode};
    use sha2::Sha256;
    #[test]
    fn genuine_subproofs_for_wrong_rotations_fail_requested_public_factor() {
        let actual = Plan::new(32, vec![0, 0]).unwrap();
        let requested = Plan::new(32, vec![1, 0]).unwrap();
        let pp = Parameters::<BlockReedSolomonCode<F>>::balanced_block_rs(6, 2, 32, 2).unwrap();
        let table = PackedTable::new(6, 2, (0..128).map(|i| F::from(i + 3)).collect()).unwrap();
        let (coefficient_root, coefficient_state) = pp.commit::<F, Sha256>(&table).unwrap();
        let coefficient = ProverOracle {
            parameters: &pp,
            commitment: &coefficient_root,
            state: &coefficient_state,
            table: &table,
        };
        // Actual rotation zero makes input and output coefficient tables equal.
        let mut values = table.values().to_vec();
        let native = ntt_table::<F>(32).unwrap();
        for poly in values.chunks_exact_mut(32) {
            native.transform_slice(poly);
        }
        let transformed = PackedTable::new(6, 2, values).unwrap();
        let (root, state) = pp.commit::<F, Sha256>(&transformed).unwrap();
        let evaluation = ProverOracle {
            parameters: &pp,
            commitment: &root,
            state: &state,
            table: &transformed,
        };
        let expected = [coefficient.verifier(), coefficient.verifier()];
        let mut prover = Transcript::new();
        bind::<F, Sha256, _>(&mut prover, &requested, &expected).unwrap();
        let roots = vec![root.clone(), root.clone()];
        prover.append_message(b"public monomial NTT roots", &roots);
        let ntt_shape = packed_ntt::Shape::new::<F, _>(&pp, 32).unwrap();
        let ntt = (0..2)
            .map(|_| {
                packed_ntt::prove::<F, Sha256, _>(
                    &mut prover,
                    &ntt_shape,
                    &coefficient,
                    &evaluation,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let shape = product_shape(6, 2);
        let factors = [
            transformed.clone(),
            actual.table::<F>(2).unwrap(),
            transformed.clone(),
        ];
        let (product, subclaim) = packed_zero::prove(&mut prover, &shape, &factors).unwrap();
        let values = vec![evaluation.table.evaluate(&subclaim.query).unwrap(); 2];
        let openings = (0..2)
            .map(|i| {
                pp.open::<F, Sha256>(
                    &mut prover,
                    evaluation.commitment,
                    evaluation.state,
                    &subclaim.query,
                    &values[i],
                )
                .unwrap()
            })
            .collect();
        let forged = Proof {
            evaluations: roots,
            ntt,
            product,
            values,
            openings,
        };
        // Every supplied NTT, ZeroCheck and source opening is individually
        // genuine under the requested prefix, using the *actual* public factor.
        let mut verifier = Transcript::new();
        bind::<F, Sha256, _>(&mut verifier, &requested, &expected).unwrap();
        verifier.append_message(b"public monomial NTT roots", &forged.evaluations);
        for i in 0..2 {
            packed_ntt::verify::<F, Sha256, _>(
                &mut verifier,
                &ntt_shape,
                &expected[i],
                &evaluation.verifier(),
                &forged.ntt[i],
            )
            .unwrap();
        }
        let subclaim = packed_zero::verify(&mut verifier, &shape, &forged.product).unwrap();
        subclaim
            .check(
                &shape,
                &[
                    forged.values[0].clone(),
                    actual.evaluate(2, &subclaim.query).unwrap(),
                    forged.values[1].clone(),
                ],
            )
            .unwrap();
        for i in 0..2 {
            pp.verify::<F, Sha256>(
                &mut verifier,
                evaluation.commitment,
                &subclaim.query,
                &forged.values[i],
                &forged.openings[i],
            )
            .unwrap();
        }
        assert_eq!(
            prover.get_challenge(b"after"),
            verifier.get_challenge(b"after")
        );
        assert!(
            verify::<F, Sha256, _>(&mut Transcript::new(), &requested, &expected, &forged).is_err()
        );
    }
}
