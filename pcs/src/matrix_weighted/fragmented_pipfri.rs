//! Unmasked canonical scalar-fragment bridge with a streamed ordered-matrix
//! sumcheck kernel. No concrete security level is claimed.
use super::{Commitment, backend::CanonicalPcs};
use crate::{
    PolynomialCommitmentScheme, multilinear::pipfri as scalar, pipfri, rolling_fri::Error,
    utils::hash::Hash,
};
use algebra::{
    AbstractExtensionField, DenseMultilinearExtension, Field, NTTField, PolynomialInfo,
    matrix_weighted::{Matrix, MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sumcheck::MLSumcheck;

mod streamed;
/// Versioned unmasked virtual-initial variant with shared scalar authentication.
pub mod virtual_source;

/// Trusted source geometry and ordinary (unmasked) scalar PCS parameters.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F, E> {
    vars: usize,
    width: usize,
    prime: String,
    degree: usize,
    basis: Vec<F>,
    scalar: scalar::Parameters<E>,
}
/// Retained base source and one unmasked scalar-fragment commitment.
pub struct State<F, E, H: Hash + Send + Sync> {
    table: PackedTable<F>,
    scalar: pipfri::State<E, H>,
    context: H::Output,
}
/// One degree-two bridge sumcheck and one source scalar opening per batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<E: Field, O> {
    sumcheck: sumcheck::Proof<E>,
    value: E,
    opening: pipfri::Proof<E, O>,
}
type Pcs<F, E, H> = scalar::PipFRIPCS<F, E, H>;

fn row_mul<F: Field, E: AbstractExtensionField<F>>(row: &[E], matrix: &Matrix<F>) -> Vec<E> {
    let k = row.len();
    let mut out = vec![E::zero(); k];
    for i in 0..k {
        for j in 0..k {
            out[j] += row[i] * matrix.values()[i * k + j];
        }
    }
    out
}
#[cfg(test)]
fn kernel<F: Field, E: AbstractExtensionField<F>>(
    width: usize,
    queries: &[Vec<MatrixPair<F>>],
    rho: &[E],
) -> Vec<E> {
    let mut output = vec![E::zero(); (1usize << queries[0].len()) * width];
    for (query, row) in queries.iter().zip(rho.chunks_exact(width)) {
        let mut rows = vec![row.to_vec()];
        for pair in query.iter().rev() {
            rows = rows
                .iter()
                .flat_map(|r| [row_mul(r, &pair.zero), row_mul(r, &pair.one)])
                .collect();
        }
        for (out, value) in output.iter_mut().zip(rows.into_iter().flatten()) {
            *out += value;
        }
    }
    output
}
fn terminal_kernel<F: Field, E: AbstractExtensionField<F>>(
    width: usize,
    queries: &[Vec<MatrixPair<F>>],
    rho: &[E],
    point: &[E],
) -> E {
    let bits = width.ilog2() as usize;
    let lane: Vec<_> = (0..width)
        .map(|j| {
            point[..bits]
                .iter()
                .enumerate()
                .fold(E::one(), |v, (i, &r)| {
                    v * if j >> i & 1 == 1 { r } else { E::one() - r }
                })
        })
        .collect();
    let mut result = E::zero();
    for (query, row) in queries.iter().zip(rho.chunks_exact(width)) {
        let mut row = row.to_vec();
        for (i, pair) in query.iter().enumerate().rev() {
            let a = row_mul(&row, &pair.zero);
            let b = row_mul(&row, &pair.one);
            let r = point[bits + i];
            row = a
                .iter()
                .zip(b)
                .map(|(&a, b)| (E::one() - r) * a + r * b)
                .collect();
        }
        for (a, b) in row.iter().zip(&lane) {
            result += *a * *b;
        }
    }
    result
}
impl<F, E> Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Build an unmasked fragmented source with power-of-two lane packing.
    pub fn new(
        vars: usize,
        width: usize,
        blowup: usize,
        queries: usize,
        fragment_vars: usize,
    ) -> Result<Self, Error> {
        if !width.is_power_of_two() || E::D == 0 {
            return Err(Error("fragmented packing"));
        }
        let scalar_vars = vars
            .checked_add(width.ilog2() as usize)
            .ok_or(Error("scalar dimension overflow"))?;
        let specification = scalar::Specification::new(fragment_vars, blowup, queries)?;
        let scalar = Pcs::<F, E, sha2::Sha256>::try_setup(scalar_vars, &specification)?;
        let mut basis = Vec::new();
        for i in 0..E::D {
            for j in 0..E::D {
                let product = E::monomial(i) * E::monomial(j);
                for k in 0..E::D {
                    basis.push(
                        product
                            .as_base_slice()
                            .get(k)
                            .copied()
                            .unwrap_or_else(F::zero)
                            .canonicalized(),
                    );
                }
            }
        }
        Ok(Self {
            vars,
            width,
            prime: F::MODULUS_VALUE.to_string(),
            degree: E::D,
            basis,
            scalar,
        })
    }
    fn context_hash<H: Hash>(&self) -> Result<H::Output, Error> {
        let mut h = H::new();
        h.update_hash_value(
            &bincode::serde::encode_to_vec(
                (b"canonical unmasked fragmented matrix v1".as_slice(), self),
                bincode::config::standard(),
            )
            .map_err(|_| Error("parameter encoding"))?,
        );
        Ok(h.output_reset())
    }
    fn check(&self, queries: &[Vec<MatrixPair<F>>], values: &[Vec<F>]) -> Result<(), Error> {
        if queries.is_empty()
            || queries.len() != values.len()
            || queries.len().checked_mul(self.width).is_none()
        {
            return Err(Error("fragmented batch dimensions"));
        }
        for (q, v) in queries.iter().zip(values) {
            if q.len() != self.vars || v.len() != self.width {
                return Err(Error("fragmented claim dimensions"));
            }
            for pair in q {
                pair.validate(self.width)
                    .map_err(|_| Error("matrix dimensions"))?;
            }
        }
        Ok(())
    }
    fn begin<H: Hash + Send + Sync>(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Transcript<E>, Error> {
        if !parent.is_classical() {
            return Err(Error("fragmented adapter requires classical parent"));
        }
        parent.append_message(
            b"fragmented ordered claims v1",
            &(self.context_hash::<H>()?, root, queries, values),
        );
        parent
            .fork_classical_extension::<F, E>(
                b"fragmented matrix child v1",
                b"unmasked scalar bridge",
            )
            .map_err(Error)
    }
}

impl<F, E, H> CanonicalPcs<F, H> for Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    H: Hash + Send + Sync,
{
    type State = State<F, E, H>;
    type SingleProof = Proof<E, H::Output>;
    type BatchProof = Proof<E, H::Output>;
    type Error = Error;
    const LINEAR_DOMAIN: &'static [u8] = b"fragmented canonical linear v1";
    const NTT_DOMAIN: &'static [u8] = b"fragmented canonical NTT v1";
    const RELATION_DOMAIN: &'static [u8] = b"fragmented canonical relation v1";
    const ACCUMULATOR_DOMAIN: &'static [u8] = b"fragmented canonical accumulator v1";
    const REGISTRY_DOMAIN: &'static [u8] = b"fragmented canonical registry v1";
    const CLAIM_DOMAIN: &'static [u8] = b"fragmented canonical claim v1";
    const SEAL_DOMAIN: &'static [u8] = b"fragmented canonical seal v1";
    fn num_vars(&self) -> usize {
        self.vars
    }
    fn width(&self) -> usize {
        self.width
    }
    fn context(&self) -> Result<H::Output, Error> {
        self.context_hash::<H>()
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        &state.table
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        _rng: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Error> {
        table.validate().map_err(|_| Error("source table"))?;
        if table.width() != self.width || table.num_vars() != self.vars {
            return Err(Error("source dimensions"));
        }
        let polynomial = DenseMultilinearExtension::from_evaluations_vec(
            self.vars + self.width.ilog2() as usize,
            table.values().to_vec(),
        );
        let (root, scalar) = Pcs::<F, E, H>::commit(&self.scalar, &polynomial);
        Ok((
            Commitment { root: root.root },
            State {
                table: table.clone(),
                scalar,
                context: self.context_hash::<H>()?,
            },
        ))
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        s: &Self::State,
        q: &[MatrixPair<F>],
        v: &[F],
    ) -> Result<Self::SingleProof, Error> {
        self.open_many(t, root, s, &[q.to_vec()], &[v.to_vec()])
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[MatrixPair<F>],
        v: &[F],
        p: &Self::SingleProof,
    ) -> Result<(), Error> {
        <Self as CanonicalPcs<F, H>>::verify_many(self, t, root, &[q.to_vec()], &[v.to_vec()], p)
    }
    fn open_many(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        s: &Self::State,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Self::BatchProof, Error> {
        self.check(queries, values)?;
        if s.context != self.context_hash::<H>()? || root.root != s.scalar.commitment().root {
            return Err(Error("source context/root"));
        }
        for (q, v) in queries.iter().zip(values) {
            if s.table.evaluate(q).map_err(|_| Error("source query"))? != *v {
                return Err(Error("false claimed value"));
            }
        }
        let mut child = self.begin::<H>(parent, root, queries, values)?;
        let rho =
            child.get_vec_challenge(b"fragmented lane projections", queries.len() * self.width);
        let (sumcheck, point) =
            streamed::prove(s.table.values(), self.width, queries, &rho, &mut child);
        let (value, opening) = Pcs::<F, E, H>::try_open_at(
            &self.scalar,
            &pipfri::Commitment { root: root.root },
            &s.scalar,
            &point,
            &mut child,
        )?;
        parent.finish_classical_child(&mut child).map_err(Error)?;
        Ok(Proof {
            sumcheck,
            value,
            opening,
        })
    }
    fn verify_many(
        &self,
        parent: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Self::BatchProof,
    ) -> Result<(), Error> {
        self.check(queries, values)?;
        let mut child = self.begin::<H>(parent, root, queries, values)?;
        let rho =
            child.get_vec_challenge(b"fragmented lane projections", queries.len() * self.width);
        let claim = rho
            .iter()
            .zip(values.iter().flatten())
            .fold(E::zero(), |s, (&r, &v)| s + r * v);
        let n = self.vars + self.width.ilog2() as usize;
        let (point, expected) = if n == 0 {
            if !proof.sumcheck.is_empty() {
                return Err(Error("constant bridge proof"));
            }
            (vec![], claim)
        } else {
            let sub = MLSumcheck::verify(
                &mut child,
                &PolynomialInfo {
                    num_variables: n,
                    max_multiplicands: 2,
                },
                claim,
                &proof.sumcheck,
            )
            .map_err(|_| Error("bridge sumcheck"))?;
            (sub.point, sub.expected_evaluations)
        };
        if !Pcs::<F, E, H>::verify(
            &self.scalar,
            &pipfri::Commitment { root: root.root },
            &point,
            proof.value,
            &proof.opening,
            &mut child,
        ) {
            return Err(Error("scalar source opening"));
        }
        if expected != proof.value * terminal_kernel(self.width, queries, &rho, &point) {
            return Err(Error("ordered matrix terminal equation"));
        }
        parent.finish_classical_child(&mut child).map_err(Error)
    }
}
