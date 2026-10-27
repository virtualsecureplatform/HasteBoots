//! Experimental ordered-matrix-to-scalar opening reduction.
//!
//! A degree-two sumcheck authenticates a public matrix-product weight function
//! against one masked scalar PipFRI opening. This is an additional reduction,
//! not a direct packed PolyFRIM protocol or a complete-PBS backend. Conditional
//! interactive error is at most (1+2v)/|EF| plus scalar PCS evaluation-binding
//! error, for v scalar variables, assuming a fixed committed scalar polynomial.
//! This bridge is not zero knowledge; masked PCS does not hide its sumcheck.
//! Base responses authenticate a fixed base-coordinate projection of the scalar
//! polynomial; this is not a proof that all its coefficients lie in the base field.
//! Fiat–Shamir/composition and full-PBS integration remain open.
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials,
    NTTField, PolynomialInfo,
    matrix_weighted::{BroadcastQuery, Matrix, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use pcs::utils::hash::Hash;
use pcs::{PolynomialCommitmentScheme, multilinear::masked_pipfri as scalar, pipfri::masked};
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use sumcheck::MLSumcheck;

/// Invalid trusted shape, prover input or rejected reduction certificate.
#[derive(Debug, thiserror::Error)]
#[error("packed scalar opening: {0}")]
pub struct Error(pub &'static str);
/// Trusted source geometry. Scalar indices place lane bits first (little endian).
#[derive(Clone, Debug, Serialize)]
pub struct Shape {
    num_vars: usize,
    width: usize,
}
impl Shape {
    /// Require power-of-two lanes and an addressable flattened source table.
    pub fn new(num_vars: usize, width: usize) -> Result<Self, Error> {
        if !width.is_power_of_two() || width.checked_mul(width).is_none() {
            return Err(Error("packing width"));
        }
        let v = num_vars
            .checked_add(width.ilog2() as usize)
            .ok_or(Error("scalar dimension overflow"))?;
        if v >= usize::BITS as usize {
            return Err(Error("scalar dimension overflow"));
        }
        Ok(Self { num_vars, width })
    }
    /// Number of Boolean cell variables.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
    /// Number of consecutive lanes in each Boolean cell.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Number of variables in the canonical flattened scalar table.
    pub fn scalar_vars(&self) -> usize {
        self.num_vars + self.width.ilog2() as usize
    }
    fn validate_queries<F: Field>(&self, queries: &[BroadcastQuery<F>]) -> Result<(), Error> {
        if queries.is_empty() || queries.len().checked_mul(self.width).is_none() {
            return Err(Error("query batch length"));
        }
        for q in queries {
            if q.query.len() != self.num_vars {
                return Err(Error("query dimensions"));
            }
            for pair in &q.query {
                pair.validate(self.width)
                    .map_err(|_| Error("matrix dimensions"))?;
            }
            if let Some(post) = &q.post_matrix {
                post.validate(self.width)
                    .map_err(|_| Error("post matrix dimensions"))?;
            }
        }
        Ok(())
    }
    fn validate<F: Field>(
        &self,
        queries: &[BroadcastQuery<F>],
        values: &[Vec<F>],
    ) -> Result<(), Error> {
        self.validate_queries(queries)?;
        if queries.len() != values.len() || values.iter().any(|y| y.len() != self.width) {
            return Err(Error("query/value dimensions"));
        }
        Ok(())
    }
}
/// Trusted scalar PCS geometry and original packed source shape.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<EF> {
    shape: Shape,
    scalar: scalar::Parameters<EF>,
}
impl<EF> Parameters<EF> {
    /// Original source shape.
    pub fn shape(&self) -> &Shape {
        &self.shape
    }
    /// Scalar parameters authenticating the original flattened source.
    pub fn scalar_parameters(&self) -> &scalar::Parameters<EF> {
        &self.scalar
    }
}
/// Certificate containing one sumcheck and one scalar opening for the whole batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<EF: Field, O> {
    /// Degree-two sumcheck; empty only for a zero-variable scalar source.
    pub sumcheck: sumcheck::Proof<EF>,
    /// Original scalar MLE evaluation at the fresh sumcheck point.
    pub scalar_value: EF,
    /// Mask-budgeted opening of the original source, with no weight-table root.
    pub opening: masked::Proof<EF, O>,
}
type Pcs<B, EF, H> = scalar::MaskedPipFRIPCS<B, EF, H>;
/// Initialize the reduction with explicit experimental masking/FRI parameters.
pub fn setup<B, EF, H>(
    num_vars: usize,
    width: usize,
    spec: &scalar::Specification,
) -> Result<Parameters<EF>, Error>
where
    B: NTTField + Serialize,
    EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    let shape = Shape::new(num_vars, width)?;
    let scalar = Pcs::<B, EF, H>::try_setup(shape.scalar_vars(), spec)
        .map_err(|_| Error("scalar PCS parameters"))?;
    Ok(Parameters { shape, scalar })
}
/// Commit the canonical flattened source once, drawing fresh private masks.
pub fn commit<B, EF, H>(
    pp: &Parameters<EF>,
    table: &PackedTable<B>,
) -> Result<(masked::Commitment<H::Output>, scalar::State<EF, H>), Error>
where
    B: NTTField + Serialize,
    EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    validate_table(pp.shape(), table)?;
    Ok(Pcs::<B, EF, H>::commit(
        &pp.scalar,
        &DenseMultilinearExtension::from_evaluations_vec(
            pp.shape.scalar_vars(),
            table.values().to_vec(),
        ),
    ))
}
fn validate_table<B: Field>(shape: &Shape, table: &PackedTable<B>) -> Result<(), Error> {
    table
        .validate()
        .map_err(|_| Error("source table dimensions"))?;
    if table.num_vars() != shape.num_vars || table.width() != shape.width {
        return Err(Error("source table shape"));
    }
    Ok(())
}
// Multiplication by base-field matrix entries acts coordinate-wise in EF.
fn row_mul<B: Field, EF: AbstractExtensionField<B>>(row: &[EF], matrix: &Matrix<B>) -> Vec<EF> {
    let k = row.len();
    (0..k)
        .map(|j| {
            EF::from_base_fn(|d| {
                (0..k).fold(B::zero(), |sum, i| {
                    sum + row[i]
                        .as_base_slice()
                        .get(d)
                        .copied()
                        .unwrap_or_else(B::zero)
                        * matrix.values()[i * k + j]
                })
            })
        })
        .collect()
}
/// Evaluate the public multilinear weight without materializing its Boolean table.
/// `projections` has one EF row vector per query. Matrix order and terminal maps
/// are preserved. Matrix products use O(batch * (num_vars+1) * width² * EF::D)
/// base operations, plus extension-field interpolation.
pub fn evaluate_kernel<B: Field, EF: AbstractExtensionField<B>>(
    shape: &Shape,
    queries: &[BroadcastQuery<B>],
    projections: &[EF],
    point: &[EF],
) -> Result<EF, Error> {
    shape.validate_queries(queries)?;
    if projections.len() != queries.len() * shape.width || point.len() != shape.scalar_vars() {
        return Err(Error("kernel dimensions"));
    }
    let lane_bits = shape.width.ilog2() as usize;
    let lane = (0..shape.width)
        .map(|j| {
            point[..lane_bits]
                .iter()
                .enumerate()
                .fold(EF::one(), |w, (i, &x)| {
                    w * if j >> i & 1 == 1 { x } else { EF::one() - x }
                })
        })
        .collect::<Vec<_>>();
    let mut out = EF::zero();
    for (q, rho) in queries.iter().zip(projections.chunks_exact(shape.width)) {
        let mut row = match &q.post_matrix {
            Some(post) => row_mul(rho, post),
            None => rho.to_vec(),
        };
        for (i, pair) in q.query.iter().enumerate().rev() {
            let a = row_mul(&row, &pair.zero);
            let b = row_mul(&row, &pair.one);
            let x = point[lane_bits + i];
            row = a
                .iter()
                .zip(b)
                .map(|(&a, b)| (EF::one() - x) * a + x * b)
                .collect();
        }
        out += row
            .iter()
            .zip(&lane)
            .fold(EF::zero(), |sum, (&a, &b)| sum + a * b);
    }
    Ok(out)
}
fn kernel_table<B: Field, EF: AbstractExtensionField<B>>(
    shape: &Shape,
    queries: &[BroadcastQuery<B>],
    rho: &[EF],
) -> Vec<EF> {
    let mut out = vec![EF::zero(); 1usize << shape.scalar_vars()];
    for (q, rho) in queries.iter().zip(rho.chunks_exact(shape.width)) {
        let row = match &q.post_matrix {
            Some(post) => row_mul(rho, post),
            None => rho.to_vec(),
        };
        let mut rows = vec![row];
        for pair in q.query.iter().rev() {
            rows = rows
                .iter()
                .flat_map(|r| [row_mul(r, &pair.zero), row_mul(r, &pair.one)])
                .collect();
        }
        for (out, value) in out.iter_mut().zip(rows.into_iter().flatten()) {
            *out += value;
        }
    }
    out
}
fn bind<B: Field + Serialize, EF: AbstractExtensionField<B> + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<EF>,
    pp: &Parameters<EF>,
    root: &masked::Commitment<H::Output>,
    queries: &[BroadcastQuery<B>],
    values: &[Vec<B>],
) -> Result<(Vec<EF>, EF), Error> {
    pp.shape.validate(queries, values)?;
    let framed = queries
        .iter()
        .map(|q| (&q.query, &q.post_matrix))
        .collect::<Vec<_>>();
    t.append_message(
        b"HasteBoots ordered matrix scalar reduction v1",
        &(pp, root, framed, values),
    );
    let rho = t.get_vec_challenge(
        b"ordered matrix lane projections",
        queries.len() * pp.shape.width,
    );
    let claim = rho
        .iter()
        .zip(values.iter().flatten())
        .fold(EF::zero(), |sum, (&r, &y)| sum + r * EF::from_base(y));
    Ok((rho, claim))
}
/// Prove a batch against its original canonical scalar root. Exactly one mask
/// allowance is spent. Public claims are checked against the supplied witness
/// before transcript mutation; the scalar PCS authenticates its source at the
/// fresh terminal point. The table and private state must describe the same
/// source; a mismatched witness can produce an invalid certificate. The public
/// kernel receives no separate commitment.
pub fn prove<B, EF, H>(
    t: &mut Transcript<EF>,
    pp: &Parameters<EF>,
    root: &masked::Commitment<H::Output>,
    state: &scalar::State<EF, H>,
    table: &PackedTable<B>,
    queries: &[BroadcastQuery<B>],
    values: &[Vec<B>],
) -> Result<Proof<EF, H::Output>, Error>
where
    B: NTTField + Serialize,
    EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    validate_table(pp.shape(), table)?;
    pp.shape.validate(queries, values)?;
    if state
        .remaining_openings()
        .map_err(|_| Error("scalar session lock"))?
        == 0
    {
        return Err(Error("scalar mask budget exhausted"));
    }
    for (q, value) in queries.iter().zip(values) {
        let got = table
            .evaluate(&q.query)
            .map_err(|_| Error("matrix query"))?;
        if q.apply(&got, pp.shape.width)
            .map_err(|_| Error("terminal map"))?
            != *value
        {
            return Err(Error("claimed matrix value"));
        }
    }
    let (rho, _) = bind::<B, EF, H>(t, pp, root, queries, values)?;
    let table = DenseMultilinearExtension::from_evaluations_vec(
        pp.shape.scalar_vars(),
        table.values().iter().copied().map(EF::from_base).collect(),
    );
    let (sumcheck, point) = if pp.shape.scalar_vars() == 0 {
        (vec![], vec![])
    } else {
        let weights = DenseMultilinearExtension::from_evaluations_vec(
            pp.shape.scalar_vars(),
            kernel_table(&pp.shape, queries, &rho),
        );
        let mut poly = ListOfProductsOfPolynomials::new(pp.shape.scalar_vars());
        poly.add_product([Rc::new(table.clone()), Rc::new(weights)], EF::one());
        let (proof, state) = MLSumcheck::prove(t, &poly).map_err(|_| Error("sumcheck prover"))?;
        (proof, state.randomness)
    };
    let (scalar_value, opening) = Pcs::<B, EF, H>::try_open_at(&pp.scalar, root, state, &point, t)
        .map_err(|_| Error("scalar opening prover"))?;
    Ok(Proof {
        sumcheck,
        scalar_value,
        opening,
    })
}
/// Verify using only trusted shape/parameters/root and the public queries/claims.
/// No source table, kernel table, or witness-derived evaluation vector is used.
pub fn verify<B, EF, H>(
    t: &mut Transcript<EF>,
    pp: &Parameters<EF>,
    root: &masked::Commitment<H::Output>,
    queries: &[BroadcastQuery<B>],
    values: &[Vec<B>],
    proof: &Proof<EF, H::Output>,
) -> Result<(), Error>
where
    B: NTTField + Serialize,
    EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    verify_inner::<B, EF, H>(t, pp, root, queries, values, proof, true)
}
fn verify_inner<B, EF, H>(
    t: &mut Transcript<EF>,
    pp: &Parameters<EF>,
    root: &masked::Commitment<H::Output>,
    queries: &[BroadcastQuery<B>],
    values: &[Vec<B>],
    proof: &Proof<EF, H::Output>,
    strict: bool,
) -> Result<(), Error>
where
    B: NTTField + Serialize,
    EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    let (rho, claim) = bind::<B, EF, H>(t, pp, root, queries, values)?;
    let v = pp.shape.scalar_vars();
    let (point, expected) = if v == 0 {
        if !proof.sumcheck.is_empty() {
            return Err(Error("constant sumcheck shape"));
        }
        (vec![], claim)
    } else {
        let sub = MLSumcheck::verify(
            t,
            &PolynomialInfo {
                num_variables: v,
                max_multiplicands: 2,
            },
            claim,
            &proof.sumcheck,
        )
        .map_err(|_| Error("sumcheck verification"))?;
        (sub.point, sub.expected_evaluations)
    };
    if !Pcs::<B, EF, H>::verify(
        &pp.scalar,
        root,
        &point,
        proof.scalar_value,
        &proof.opening,
        t,
    ) {
        return Err(Error("scalar source opening"));
    }
    if strict && expected != proof.scalar_value * evaluate_kernel(&pp.shape, queries, &rho, &point)?
    {
        return Err(Error("ordered matrix terminal equation"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::matrix_weighted::{MatrixPair, matrix_weights};
    use num_traits::{One, Zero};
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::Sha256;
    fn query<B: Field>(n: usize, k: usize, rng: &mut StdRng, post: bool) -> BroadcastQuery<B> {
        let mut matrix = || Matrix::new(k, (0..k * k).map(|_| B::random(rng)).collect()).unwrap();
        BroadcastQuery {
            query: (0..n)
                .map(|_| MatrixPair {
                    zero: matrix(),
                    one: matrix(),
                })
                .collect(),
            post_matrix: post.then(&mut matrix),
        }
    }
    fn claims<B: Field>(table: &PackedTable<B>, queries: &[BroadcastQuery<B>]) -> Vec<Vec<B>> {
        queries
            .iter()
            .map(|q| {
                q.apply(&table.evaluate(&q.query).unwrap(), table.width())
                    .unwrap()
            })
            .collect()
    }
    fn kernel_references<B: NTTField + Serialize, EF: AbstractExtensionField<B> + Serialize>() {
        let mut rng = StdRng::seed_from_u64(1941);
        for k in [1, 2, 4, 8] {
            for n in [0, 1, 3] {
                let shape = Shape::new(n, k).unwrap();
                let table =
                    PackedTable::new(n, k, (0..k << n).map(|_| B::random(&mut rng)).collect())
                        .unwrap();
                let queries = (0..3)
                    .map(|i| query(n, k, &mut rng, i % 2 == 0))
                    .collect::<Vec<_>>();
                let rho = (0..3 * k).map(|_| EF::random(&mut rng)).collect::<Vec<_>>();
                let mut reference = vec![EF::zero(); k << n];
                // Independent full matrix products, unlike the production row recursion.
                for (q, projection) in queries.iter().zip(rho.chunks_exact(k)) {
                    for (b, weight) in matrix_weights(k, &q.query).unwrap().iter().enumerate() {
                        let weight = match &q.post_matrix {
                            Some(post) => post.mul(weight).unwrap(),
                            None => weight.clone(),
                        };
                        for j in 0..k {
                            reference[b * k + j] += projection
                                .iter()
                                .enumerate()
                                .fold(EF::zero(), |s, (i, &r)| {
                                    s + r * EF::from_base(weight.values()[i * k + j])
                                });
                        }
                    }
                }
                assert_eq!(kernel_table(&shape, &queries, &rho), reference);
                let mle = DenseMultilinearExtension::from_evaluations_vec(
                    shape.scalar_vars(),
                    reference.clone(),
                );
                for point in [
                    vec![EF::zero(); shape.scalar_vars()],
                    vec![EF::one(); shape.scalar_vars()],
                    (0..shape.scalar_vars())
                        .map(|_| EF::random(&mut rng))
                        .collect(),
                ] {
                    assert_eq!(
                        evaluate_kernel(&shape, &queries, &rho, &point).unwrap(),
                        mle.evaluate(&point)
                    );
                }
                let y = claims(&table, &queries);
                let projected = rho
                    .iter()
                    .zip(y.iter().flatten())
                    .fold(EF::zero(), |s, (&r, &v)| s + r * EF::from_base(v));
                assert_eq!(
                    projected,
                    reference
                        .iter()
                        .zip(table.values())
                        .fold(EF::zero(), |s, (&w, &v)| s + w * EF::from_base(v))
                );
            }
        }
    }
    #[test]
    fn babybear_ordered_kernel_matches_independent_products() {
        kernel_references::<algebra::BabyBear, algebra::BabyBearExtension5>();
    }
    #[test]
    fn goldilocks_ordered_kernel_matches_independent_products() {
        kernel_references::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }

    fn roundtrips<B, EF>()
    where
        B: NTTField + Serialize,
        EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    {
        let mut rng = StdRng::seed_from_u64(8751);
        let spec = scalar::Specification::new(8, 2, 1, 4).unwrap();
        for (n, k) in [(0, 1), (0, 4), (3, 2), (3, 8), (8, 4)] {
            let pp = setup::<B, EF, Sha256>(n, k, &spec).unwrap();
            let table =
                PackedTable::new(n, k, (0..k << n).map(|_| B::random(&mut rng)).collect()).unwrap();
            let (root, state) = commit::<B, EF, Sha256>(&pp, &table).unwrap();
            for (opening, count) in [1, 4, 16].into_iter().enumerate() {
                let queries = (0..count)
                    .map(|i| query(n, k, &mut rng, i % 2 == 0))
                    .collect::<Vec<_>>();
                let values = claims(&table, &queries);
                let mut t = Transcript::new_direct_extension::<B>();
                let proof =
                    prove::<B, EF, Sha256>(&mut t, &pp, &root, &state, &table, &queries, &values)
                        .unwrap();
                assert_eq!(proof.opening.opening_index, opening);
                assert_eq!(state.remaining_openings().unwrap(), 3 - opening);
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (p, used): (Proof<EF, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut v = Transcript::new_direct_extension::<B>();
                verify::<B, EF, Sha256>(&mut v, &pp, &root, &queries, &values, &p).unwrap();
                assert_eq!(
                    t.get_challenge(b"bridge after"),
                    v.get_challenge(b"bridge after")
                );
                let reject = |q: &[BroadcastQuery<B>], y: &[Vec<B>], p: &Proof<EF, [u8; 32]>| {
                    assert!(
                        verify::<B, EF, Sha256>(
                            &mut Transcript::new_direct_extension::<B>(),
                            &pp,
                            &root,
                            q,
                            y,
                            p
                        )
                        .is_err()
                    )
                };
                let mut bad = p.clone();
                bad.scalar_value += EF::one();
                reject(&queries, &values, &bad);
                let mut bad = p.clone();
                bad.opening.low_degree.terminal += EF::one();
                reject(&queries, &values, &bad);
                let mut bad = p.clone();
                bad.sumcheck.push({
                    let bytes = bincode::serde::encode_to_vec(
                        Vec::<EF>::new(),
                        bincode::config::standard(),
                    )
                    .unwrap();
                    bincode::serde::decode_from_slice::<sumcheck::prover::ProverMsg<EF>, _>(
                        &bytes,
                        bincode::config::standard(),
                    )
                    .unwrap()
                    .0
                });
                reject(&queries, &values, &bad);
                let mut wrong = values.clone();
                wrong[0][0] += B::one();
                reject(&queries, &wrong, &p);
                if n > 0 {
                    let mut q = queries.clone();
                    let pair = &mut q[0].query[0];
                    std::mem::swap(&mut pair.zero, &mut pair.one);
                    reject(&q, &values, &p);
                }
                reject(&queries, &values[..values.len() - 1], &p);
                let mut wrong_root = root.clone();
                wrong_root.root[0] ^= 1;
                assert!(
                    verify::<B, EF, Sha256>(
                        &mut Transcript::new_direct_extension::<B>(),
                        &pp,
                        &wrong_root,
                        &queries,
                        &values,
                        &p
                    )
                    .is_err()
                );
                // A false claimed value fails before transcript/budget changes.
                let before = state.remaining_openings().unwrap();
                let mut preflight = Transcript::new_direct_extension::<B>();
                assert!(
                    prove::<B, EF, Sha256>(
                        &mut preflight,
                        &pp,
                        &root,
                        &state,
                        &table,
                        &queries,
                        &wrong
                    )
                    .is_err()
                );
                assert_eq!(state.remaining_openings().unwrap(), before);
                assert_eq!(
                    preflight.get_challenge(b"preflight"),
                    Transcript::<EF>::new_direct_extension::<B>().get_challenge(b"preflight")
                );
                if opening == 2 {
                    let fourth = prove::<B, EF, Sha256>(
                        &mut Transcript::new_direct_extension::<B>(),
                        &pp,
                        &root,
                        &state,
                        &table,
                        &queries,
                        &values,
                    )
                    .unwrap();
                    verify::<B, EF, Sha256>(
                        &mut Transcript::new_direct_extension::<B>(),
                        &pp,
                        &root,
                        &queries,
                        &values,
                        &fourth,
                    )
                    .unwrap();
                    assert_eq!(state.remaining_openings().unwrap(), 0);
                    let mut exhausted = Transcript::new_direct_extension::<B>();
                    assert_eq!(
                        prove::<B, EF, Sha256>(
                            &mut exhausted,
                            &pp,
                            &root,
                            &state,
                            &table,
                            &queries,
                            &values
                        )
                        .unwrap_err()
                        .0,
                        "scalar mask budget exhausted"
                    );
                    assert_eq!(
                        exhausted.get_challenge(b"exhausted"),
                        Transcript::<EF>::new_direct_extension::<B>().get_challenge(b"exhausted")
                    );
                }
            }
        }
    }
    #[test]
    fn babybear_matrix_batches_roundtrip_one_mask_allowance() {
        roundtrips::<algebra::BabyBear, algebra::BabyBearExtension5>();
    }
    #[test]
    fn goldilocks_matrix_batches_roundtrip_one_mask_allowance() {
        roundtrips::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }

    fn fresh_false<B, EF>()
    where
        B: NTTField + Serialize,
        EF: AbstractExtensionField<B> + Serialize + for<'de> Deserialize<'de>,
    {
        let mut rng = StdRng::seed_from_u64(9071);
        let spec = scalar::Specification::new(8, 2, 1, 4).unwrap();
        for (n, k) in [(0, 1), (2, 4)] {
            let pp = setup::<B, EF, Sha256>(n, k, &spec).unwrap();
            let table =
                PackedTable::new(n, k, (0..k << n).map(|_| B::random(&mut rng)).collect()).unwrap();
            let mut fake = table.values().to_vec();
            fake[0] += B::one();
            let fake = PackedTable::new(n, k, fake).unwrap();
            let queries = (0..4)
                .map(|i| query(n, k, &mut rng, i % 2 == 0))
                .collect::<Vec<_>>();
            let values = claims(&fake, &queries);
            assert_ne!(values, claims(&table, &queries));
            let (root, state) = commit::<B, EF, Sha256>(&pp, &table).unwrap();
            let mut t = Transcript::new_direct_extension::<B>();
            // Fresh public false claims; genuine sumcheck for the false witness,
            // but a genuine scalar opening against the original committed table.
            let proof =
                prove::<B, EF, Sha256>(&mut t, &pp, &root, &state, &fake, &queries, &values)
                    .unwrap();
            let mut prefix = Transcript::new_direct_extension::<B>();
            let (_, claim) =
                bind::<B, EF, Sha256>(&mut prefix, &pp, &root, &queries, &values).unwrap();
            let point = if pp.shape.scalar_vars() == 0 {
                vec![]
            } else {
                MLSumcheck::verify(
                    &mut prefix,
                    &PolynomialInfo {
                        num_variables: pp.shape.scalar_vars(),
                        max_multiplicands: 2,
                    },
                    claim,
                    &proof.sumcheck,
                )
                .unwrap()
                .point
            };
            let actual_value = DenseMultilinearExtension::from_evaluations_vec(
                pp.shape.scalar_vars(),
                table.values().iter().copied().map(EF::from_base).collect(),
            )
            .evaluate(&point);
            assert_eq!(proof.scalar_value, actual_value);
            let mut replay = Transcript::new_direct_extension::<B>();
            verify_inner::<B, EF, Sha256>(
                &mut replay,
                &pp,
                &root,
                &queries,
                &values,
                &proof,
                false,
            )
            .unwrap();
            assert_eq!(
                t.get_challenge(b"genuine children"),
                replay.get_challenge(b"genuine children")
            );
            assert_eq!(
                verify::<B, EF, Sha256>(
                    &mut Transcript::new_direct_extension::<B>(),
                    &pp,
                    &root,
                    &queries,
                    &values,
                    &proof
                )
                .unwrap_err()
                .0,
                "ordered matrix terminal equation"
            );
        }
    }
    #[test]
    fn babybear_fresh_false_witness_genuine_scalar_opening_rejects_terminal() {
        fresh_false::<algebra::BabyBear, algebra::BabyBearExtension5>();
    }
    #[test]
    fn goldilocks_fresh_false_witness_genuine_scalar_opening_rejects_terminal() {
        fresh_false::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }

    #[test]
    fn noncommuting_suffix_cannot_move_through_public_fold() {
        type B = algebra::BabyBear;
        type EF = algebra::BabyBearExtension5;
        let a = Matrix::new(2, vec![B::one(), B::one(), B::zero(), B::one()]).unwrap();
        let b = Matrix::new(2, vec![B::one(), B::zero(), B::one(), B::one()]).unwrap();
        let zero = Matrix::new(2, vec![B::zero(); 4]).unwrap();
        let q = BroadcastQuery {
            query: vec![
                MatrixPair {
                    zero: a.clone(),
                    one: zero.clone(),
                },
                MatrixPair {
                    zero: b.clone(),
                    one: zero,
                },
            ],
            post_matrix: None,
        };
        let table = PackedTable::new(
            2,
            2,
            vec![
                B::one(),
                B::zero(),
                B::zero(),
                B::zero(),
                B::zero(),
                B::zero(),
                B::zero(),
                B::zero(),
            ],
        )
        .unwrap();
        let correct = table.evaluate(&q.query).unwrap();
        let mut wrong = vec![B::zero(); 2];
        a.mul(&b).unwrap().add_mul(table.at(0), &mut wrong);
        assert_eq!(correct, vec![B::one(), B::one()]);
        assert_eq!(wrong, vec![B::from(2usize), B::one()]);
        assert_ne!(correct, wrong);
        let kernel = kernel_table(&Shape::new(2, 2).unwrap(), &[q], &[EF::one(), EF::zero()]);
        assert_eq!(kernel[0], EF::one());
        assert!(Shape::new(0, 3).is_err());
        assert!(Shape::new(usize::MAX, 2).is_err());
    }
    #[test]
    fn plain_sumcheck_reveals_more_than_the_claimed_sum() {
        type B = algebra::BabyBear;
        type EF = algebra::BabyBearExtension5;
        let pp =
            setup::<B, EF, Sha256>(1, 1, &scalar::Specification::new(8, 2, 1, 4).unwrap()).unwrap();
        let table = PackedTable::new(1, 1, vec![B::from(3usize), B::from(7usize)]).unwrap();
        let q = BroadcastQuery {
            query: vec![MatrixPair {
                zero: Matrix::identity(1).unwrap(),
                one: Matrix::identity(1).unwrap(),
            }],
            post_matrix: None,
        };
        let queries = vec![q];
        let values = claims(&table, &queries);
        assert_eq!(values, vec![vec![B::from(10usize)]]);
        let (root, state) = commit::<B, EF, Sha256>(&pp, &table).unwrap();
        let proof = prove::<B, EF, Sha256>(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &root,
            &state,
            &table,
            &queries,
            &values,
        )
        .unwrap();
        verify::<B, EF, Sha256>(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &root,
            &queries,
            &values,
            &proof,
        )
        .unwrap();
        let (rho, _) = bind::<B, EF, Sha256>(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &root,
            &queries,
            &values,
        )
        .unwrap();
        assert_ne!(rho[0], EF::zero());
        let bytes =
            bincode::serde::encode_to_vec(&proof.sumcheck[0], bincode::config::standard()).unwrap();
        let (round, used): (Vec<EF>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(round[0] / rho[0], EF::from_base(table.values()[0]));
        assert_eq!(round[1] / rho[0], EF::from_base(table.values()[1]));
    }
    #[test]
    fn non_base_commitment_authenticates_its_base_projection() {
        use algebra::transformation::AbstractNTT;
        type B = algebra::BabyBear;
        type EF = algebra::BabyBearExtension5;
        let pp =
            setup::<B, EF, Sha256>(1, 1, &scalar::Specification::new(8, 2, 1, 4).unwrap()).unwrap();
        let u = EF::monomial(1);
        let entries = vec![
            EF::from_base(B::from(3usize)) + u,
            EF::from_base(B::from(7usize)) - u,
        ];
        assert_ne!(entries[0], EF::from_base(entries[0].as_base_slice()[0]));
        let base =
            PackedTable::new(1, 1, entries.iter().map(|v| v.as_base_slice()[0]).collect()).unwrap();
        let query = BroadcastQuery {
            query: vec![MatrixPair {
                zero: Matrix::identity(1).unwrap(),
                one: Matrix::identity(1).unwrap(),
            }],
            post_matrix: None,
        };
        let queries = vec![query];
        let values = claims(&base, &queries);
        assert_eq!(values, vec![vec![B::from(10usize)]]);
        // An adversarial committer can use EF data and the public base-table
        // transcript tag; the type tag is not an algebraic membership proof.
        let core = masked::Parameters::new(
            256,
            1,
            2,
            1,
            4,
            EF::from_base(B::generate_ntt_table(10).unwrap().root()),
            pcs::pipfri::Basis::BooleanEvaluations,
        )
        .unwrap()
        .with_base_field_encoder::<B>()
        .unwrap();
        let data = (0..256).map(|i| entries[i & 1]).collect::<Vec<_>>();
        let mut state =
            masked::commit::<EF, Sha256, _>(&core, &data, &mut StdRng::seed_from_u64(4917))
                .unwrap();
        let root = state.commitment();
        let mut t = Transcript::new_direct_extension::<B>();
        let (rho, _) = bind::<B, EF, Sha256>(&mut t, &pp, &root, &queries, &values).unwrap();
        let source = DenseMultilinearExtension::from_evaluations_vec(1, entries);
        let weights = DenseMultilinearExtension::from_evaluations_vec(
            1,
            kernel_table(&pp.shape, &queries, &rho),
        );
        let mut poly = ListOfProductsOfPolynomials::new(1);
        poly.add_product([Rc::new(source.clone()), Rc::new(weights)], EF::one());
        let (sumcheck, sc) = MLSumcheck::prove(&mut t, &poly).unwrap();
        let scalar_value = source.evaluate(&sc.randomness);
        t.append_message(
            b"masked PipFRI PCS adapter v1",
            &(&pp.scalar, b"base table".as_slice()),
        );
        let mut point = sc.randomness;
        point.resize(8, EF::zero());
        let opening = state.open(&mut t, &point, scalar_value).unwrap();
        let proof = Proof {
            sumcheck,
            scalar_value,
            opening,
        };
        let mut v = Transcript::new_direct_extension::<B>();
        verify::<B, EF, Sha256>(&mut v, &pp, &root, &queries, &values, &proof).unwrap();
        assert_eq!(
            t.get_challenge(b"projection after"),
            v.get_challenge(b"projection after")
        );
    }
    #[test]
    fn goldilocks_lazy_boundary_values_roundtrip() {
        type B = algebra::Goldilocks;
        type EF = algebra::GoldilocksExtension5;
        let spec = scalar::Specification::new(8, 2, 1, 4).unwrap();
        for (n, k) in [(0, 1), (1, 2)] {
            for value in [B::zero(), B::one(), B::neg_one(), B::new(B::MODULUS_VALUE)] {
                let pp = setup::<B, EF, Sha256>(n, k, &spec).unwrap();
                let table = PackedTable::new(n, k, vec![value; k << n]).unwrap();
                let pair = MatrixPair {
                    zero: Matrix::identity(k).unwrap(),
                    one: Matrix::identity(k).unwrap(),
                };
                let queries = vec![BroadcastQuery {
                    query: vec![pair; n],
                    post_matrix: None,
                }];
                let values = claims(&table, &queries);
                let (root, state) = commit::<B, EF, Sha256>(&pp, &table).unwrap();
                let mut t = Transcript::new_direct_extension::<B>();
                let proof =
                    prove::<B, EF, Sha256>(&mut t, &pp, &root, &state, &table, &queries, &values)
                        .unwrap();
                let mut v = Transcript::new_direct_extension::<B>();
                verify::<B, EF, Sha256>(&mut v, &pp, &root, &queries, &values, &proof).unwrap();
                assert_eq!(
                    t.get_challenge(b"lazy after"),
                    v.get_challenge(b"lazy after")
                );
            }
        }
    }
}
