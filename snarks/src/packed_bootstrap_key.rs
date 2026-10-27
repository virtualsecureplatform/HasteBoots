//! Trusted public binary key preprocessing. Never construct expected keys from a trace.
use crate::packed_relation::{self, Error, RelationProof};
use algebra::{NTTField, matrix_weighted::PackedTable};
use helper::Transcript;
use lattice::NTTRGSW;
use pcs::{
    matrix_weighted::{Commitment, Parameters, State},
    utils::{code::RowCode, hash::Hash},
};
use serde::Serialize;
use sumcheck::packed::PackedShape;

/// Expected public key roots produced from trusted native key material.
/// Intentionally not deserializable from untrusted proof bytes.
#[derive(Clone, Debug, Serialize)]
pub struct PublicKey<O> {
    roots: Vec<Commitment<O>>,
    context: O,
    polynomial_size: usize,
    rounds: usize,
    basis_bits: u32,
}
impl<O> PublicKey<O> {
    /// Public root count: a digits first, then b digits, in native order.
    pub fn roots(&self) -> &[Commitment<O>] {
        &self.roots
    }
    /// Native polynomial size of the expected public key.
    pub fn polynomial_size(&self) -> usize {
        self.polynomial_size
    }
    /// Number of input-mask coefficients in the trusted key.
    pub fn rounds(&self) -> usize {
        self.rounds
    }
    /// Trusted radix bits used by both RGSW halves.
    pub fn basis_bits(&self) -> u32 {
        self.basis_bits
    }
}
/// Canonical NTT tables from public key samples only, including native zero padding.
pub fn tables<F: NTTField>(
    width: usize,
    n: usize,
    key: &[NTTRGSW<F>],
) -> Result<Vec<PackedTable<F>>, Error> {
    if key.is_empty() || !n.is_power_of_two() || !width.is_power_of_two() || width > n {
        return Err(Error("invalid public binary key shape".into()));
    }
    let basis = key[0].c_neg_s_m().basis();
    let d = basis.decompose_len();
    if d == 0
        || key.iter().any(|r| {
            [r.c_neg_s_m(), r.c_m()].iter().any(|g| {
                g.basis().bits() != basis.bits()
                    || g.data().len() != d
                    || g.iter()
                        .any(|p| p.a_slice().len() != n || p.b_slice().len() != n)
            })
        })
    {
        return Err(Error("inconsistent public RGSW dimensions or radix".into()));
    }
    let m = key
        .len()
        .checked_next_power_of_two()
        .ok_or_else(|| Error("key padding overflow".into()))?;
    let half = n
        .checked_mul(m)
        .ok_or_else(|| Error("key table overflow".into()))?;
    let length = half
        .checked_mul(2)
        .ok_or_else(|| Error("key table overflow".into()))?;
    let mut result = Vec::with_capacity(2 * d);
    for component in 0..2 * d {
        let mut values = vec![F::zero(); length];
        for (row, r) in key.iter().enumerate() {
            let g = if component < d {
                r.c_neg_s_m()
            } else {
                r.c_m()
            };
            let p = &g.data()[component % d];
            values[row * n..(row + 1) * n].copy_from_slice(p.a_slice());
            values[half + row * n..half + (row + 1) * n].copy_from_slice(p.b_slice());
        }
        result.push(
            PackedTable::new((length / width).ilog2() as usize, width, values).map_err(convert)?,
        );
    }
    Ok(result)
}
/// Reusable public setup. The verifier must authenticate the key given here.
pub fn preprocess<F, H, C>(
    pp: &Parameters<C>,
    n: usize,
    key: &[NTTRGSW<F>],
) -> Result<PublicKey<H::Output>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    Ok(prepare::<F, H, C>(pp, n, key)?.expected)
}
/// Reusable public-key tables and prover states, excluded from proof bytes.
pub struct ProverKey<F, H: Hash + Send + Sync> {
    expected: PublicKey<H::Output>,
    tables: Vec<PackedTable<F>>,
    states: Vec<State<F, H>>,
}
impl<F, H: Hash + Send + Sync> ProverKey<F, H> {
    /// Expected public roots, with no prover state.
    pub fn expected(&self) -> &PublicKey<H::Output> {
        &self.expected
    }
    /// Borrow canonical public-key opening sources for a proof invocation.
    pub fn oracles<'a, C>(
        &'a self,
        pp: &'a Parameters<C>,
    ) -> Result<Vec<crate::packed_oracle::ProverOracle<'a, F, H, C>>, Error>
    where
        F: NTTField + Serialize,
        C: RowCode<F> + Serialize,
    {
        if pp.context_digest::<F, H>().map_err(convert)? != self.expected.context {
            return Err(Error("public key context mismatch".into()));
        }
        Ok(self
            .tables
            .iter()
            .zip(&self.expected.roots)
            .zip(&self.states)
            .map(
                |((table, commitment), state)| crate::packed_oracle::ProverOracle {
                    parameters: pp,
                    table,
                    commitment,
                    state,
                },
            )
            .collect())
    }
}
/// Reusable prover setup from the authenticated native public key only.
pub fn prepare<F, H, C>(
    pp: &Parameters<C>,
    n: usize,
    key: &[NTTRGSW<F>],
) -> Result<ProverKey<F, H>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let sources = tables(pp.width(), n, key)?;
    if sources[0].num_vars() != pp.num_vars() {
        return Err(Error("public key PCS dimensions".into()));
    }
    let (roots, states): (Vec<_>, Vec<_>) = sources
        .iter()
        .map(|t| pp.commit::<F, H>(t).map_err(convert))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .unzip();
    Ok(ProverKey {
        expected: PublicKey {
            roots,
            context: pp.context_digest::<F, H>().map_err(convert)?,
            polynomial_size: n,
            rounds: key.len(),
            basis_bits: key[0].c_neg_s_m().basis().bits(),
        },
        tables: sources,
        states,
    })
}
/// Interleave private digit roots and expected key roots; append the private sum.
/// Private roots contain exactly all digit roots followed by the output-sum root.
pub fn commitments<F, H, C>(
    pp: &Parameters<C>,
    key: &PublicKey<H::Output>,
    private: &[Commitment<H::Output>],
) -> Result<Vec<Commitment<H::Output>>, Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    if private.len() != key.roots.len() + 1
        || pp.context_digest::<F, H>().map_err(convert)? != key.context
    {
        return Err(Error("public key context or private source count".into()));
    }
    let mut roots = Vec::with_capacity(2 * key.roots.len() + 1);
    for (digit, expected) in private.iter().zip(&key.roots) {
        roots.push(digit.clone());
        roots.push(expected.clone());
    }
    roots.push(private.last().unwrap().clone());
    Ok(roots)
}
/// Verify the canonical external-product relation using trusted public key roots.
pub fn verify<F, H, C>(
    trans: &mut Transcript<F>,
    pp: &Parameters<C>,
    key: &PublicKey<H::Output>,
    private: &[Commitment<H::Output>],
    proof: &RelationProof<F, H::Output>,
) -> Result<(), Error>
where
    F: NTTField + Serialize,
    H: Hash + Send + Sync,
    C: RowCode<F> + Serialize,
{
    let roots = commitments::<F, H, C>(pp, key, private)?;
    let count = key.roots.len();
    let mut terms = (0..count)
        .map(|i| (F::one(), vec![2 * i, 2 * i + 1]))
        .collect::<Vec<_>>();
    terms.push((-F::one(), vec![2 * count]));
    let shape = PackedShape {
        num_vars: pp.num_vars(),
        width: pp.width(),
        num_factors: 2 * count + 1,
        terms,
    };
    packed_relation::verify::<F, H, C>(trans, &shape, pp, &roots, proof)
}
fn convert(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
