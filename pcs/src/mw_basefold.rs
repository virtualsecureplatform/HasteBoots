//! Experimental structured MW-Basefold, 2025/719 Appendix D.1.
//!
//! Oracles contain k interleaved rows of k-coordinate symbols. All arithmetic
//! is in the prime field. Each fold root is fixed before fresh query coins and
//! before the next packed-sumcheck challenge. This is a streaming primitive,
//! not an after-query PCS or a whole-proof security certificate. The structured
//! challenge distribution must be supplied by the enclosing packed protocol.
use crate::{
    rolling_fri,
    utils::{hash::Hash, merkle_tree::MerkleTree},
};
use algebra::{
    PrimeField,
    matrix_weighted::{MatrixPair, PackedTable},
};
use helper::{FiatShamirTranscript, Transcript};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Invalid trusted geometry, state, schedule or rejected certificate.
#[derive(Debug, thiserror::Error)]
#[error("MW-Basefold: {0}")]
pub struct Error(pub &'static str);
/// Trusted geometry. Each symbol contains width squared prime-field scalars.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F> {
    variables: usize,
    width: usize,
    blowup: usize,
    queries: usize,
    root: F,
}
impl<F: PrimeField + Serialize> Parameters<F> {
    /// Use an exact-order 2N-th root, N=blowup*2^variables/width. Width and
    /// blowup must be powers of two; variables must be at least log2(width).
    /// No security level is inferred from these experimental parameters.
    pub fn new(
        variables: usize,
        width: usize,
        blowup: usize,
        queries: usize,
        root: F,
    ) -> Result<Self, Error> {
        if !width.is_power_of_two()
            || !blowup.is_power_of_two()
            || blowup < 2
            || queries == 0
            || variables >= usize::BITS as usize
            || variables < width.ilog2() as usize
        {
            return Err(Error("invalid geometry"));
        }
        let n = (1usize << (variables - width.ilog2() as usize))
            .checked_mul(blowup)
            .ok_or(Error("encoded size overflow"))?;
        n.checked_mul(width)
            .and_then(|n| n.checked_mul(width))
            .ok_or(Error("symbol size overflow"))?;
        let twice = n.checked_mul(2).ok_or(Error("domain size overflow"))?;
        if F::one() + F::one() == F::zero()
            || power(root, n) != -F::one()
            || power(root, twice) != F::one()
        {
            return Err(Error("root order or characteristic"));
        }
        Ok(Self {
            variables,
            width,
            blowup,
            queries,
            root,
        })
    }
    /// Boolean variables in the original canonical table.
    pub fn num_vars(&self) -> usize {
        self.variables
    }
    /// Number of packed lanes and residual Boolean cells.
    pub fn width(&self) -> usize {
        self.width
    }
    /// Oracle folds, followed by log2(width) local folds.
    pub fn rounds(&self) -> usize {
        self.variables - self.width.ilog2() as usize
    }
    /// Initial encoded block-symbol count.
    pub fn encoded_len(&self) -> usize {
        (1usize << self.rounds()) * self.blowup
    }
    /// Independent uniform samples with replacement per oracle fold.
    pub fn queries(&self) -> usize {
        self.queries
    }
    fn len(&self, layer: usize) -> usize {
        self.encoded_len() >> layer
    }
    fn shift(&self, layer: usize) -> F {
        power(self.root, 1usize << layer)
    }
    fn scalars(&self) -> usize {
        self.width * self.width
    }
    fn context<H: Hash>(&self) -> H::Output {
        rolling_fri::hash::<H, _>(&(
            b"HasteBoots structured MW Basefold v1".as_slice(),
            F::MODULUS_VALUE.to_string(),
            self,
        ))
    }
}
/// Original or folded oracle root; role/layer/index are authenticated in leaves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment<O> {
    /// Merkle root. Geometry is always supplied by trusted parameters.
    pub root: O,
}
/// Prover-only committed codeword. No caller-controlled degree flag is trusted.
pub struct State<F, H: Hash + Send + Sync> {
    values: Vec<F>,
    tree: MerkleTree<H>,
    context: H::Output,
    layer: usize,
}
/// One complete block symbol and its Merkle path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Opening<F, O> {
    /// Row-major [lane][residual-coordinate] values, exactly width squared.
    pub values: Vec<F>,
    /// Leaf hash followed by siblings; exact length derives from parameters.
    pub path: Vec<O>,
}
/// Authentication of both parent symbols and their folded child.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query<F, O> {
    /// Parent at x and -x in adjacent bit-reversed positions.
    pub parents: [Opening<F, O>; 2],
    /// Child at x squared.
    pub child: Opening<F, O>,
}
/// One oracle fold, fixed and checked before the next sumcheck challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundProof<F, O> {
    /// Newly fixed folded root.
    pub root: Commitment<O>,
    /// One certificate per distinct transcript-derived sampled position.
    /// Repeated samples reuse it; the trusted independent draw count is unchanged.
    pub queries: Vec<Query<F, O>>,
    /// Final decoded block, only on the last oracle fold.
    pub terminal: Option<Vec<F>>,
}
/// Initialization message: a complete terminal block only when no oracle folds
/// are needed. It is authenticated before any packed challenges are requested.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartProof<F> {
    /// Present exactly when num_vars=log2(width).
    pub terminal: Option<Vec<F>>,
}
/// Commit the canonical little-endian table. Low variables become coefficient
/// indices; the final log2(width) variables occupy symbol coordinates. Thus
/// folding variable zero does not reverse or commute the matrix query order.
pub fn commit<F, H>(
    pp: &Parameters<F>,
    table: &PackedTable<F>,
) -> Result<(Commitment<H::Output>, State<F, H>), Error>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    table.validate().map_err(|_| Error("table dimensions"))?;
    if table.num_vars() != pp.variables || table.width() != pp.width {
        return Err(Error("table shape"));
    }
    let k = pp.width;
    let m = 1usize << pp.rounds();
    let n = pp.encoded_len();
    let columns: Vec<Vec<F>> = (0..pp.scalars())
        .into_par_iter()
        .map(|coordinate| {
            let lane = coordinate / k;
            let residual = coordinate % k;
            let coefficients: Vec<F> = (0..m)
                .map(|b| table.values()[(b + residual * m) * k + lane])
                .collect();
            if coefficients.iter().all(|&v| v == F::zero()) {
                vec![F::zero(); n]
            } else {
                rolling_fri::encode(&coefficients, n, pp.root)
            }
        })
        .collect();
    let mut values = vec![F::zero(); n * pp.scalars()];
    values
        .par_chunks_mut(pp.scalars())
        .enumerate()
        .for_each(|(i, out)| {
            for (out, c) in out.iter_mut().zip(&columns) {
                *out = c[i];
            }
        });
    let state = state::<F, H>(pp, 0, values);
    Ok((
        Commitment {
            root: state.tree.root,
        },
        state,
    ))
}
/// Streaming prover that borrows reusable original state and owns only its
/// current folded codeword. Future matrix challenges must not be precomputed.
pub struct Prover<'a, F, H: Hash + Send + Sync> {
    pp: &'a Parameters<F>,
    initial: &'a State<F, H>,
    current: Option<State<F, H>>,
    tail: Option<PackedTable<F>>,
    round: usize,
}
/// Streaming verifier; it stores one current root and the small decoded tail.
pub struct Verifier<'a, F, H: Hash + Send + Sync> {
    pp: &'a Parameters<F>,
    root: Commitment<H::Output>,
    tail: Option<PackedTable<F>>,
    round: usize,
}
impl<'a, F, H> Prover<'a, F, H>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    /// Bind the original root/parameters before the enclosing packed protocol.
    pub fn begin(
        trans: &mut Transcript<F>,
        pp: &'a Parameters<F>,
        root: &Commitment<H::Output>,
        initial: &'a State<F, H>,
    ) -> Result<(Self, StartProof<F>), Error> {
        if initial.layer != 0
            || initial.context != pp.context::<H>()
            || initial.tree.root != root.root
        {
            return Err(Error("initial state/context/root"));
        }
        bind_start::<F, H>(trans, pp, root);
        let terminal = (pp.rounds() == 0).then(|| initial.values[..pp.scalars()].to_vec());
        let tail = terminal
            .as_ref()
            .map(|v| terminal_table::<F, H>(pp, 0, root, v))
            .transpose()?;
        let proof = StartProof { terminal };
        trans.append_message(b"mw basefold initial tail", &proof);
        Ok((
            Self {
                pp,
                initial,
                current: None,
                tail,
                round: 0,
            },
            proof,
        ))
    }
    /// Apply the just-sampled matrix pair, commit its child, answer fresh
    /// queries, and bind all answers before returning to the packed protocol.
    /// Local tail folds return None and introduce no further oracle messages.
    pub fn advance(
        &mut self,
        trans: &mut Transcript<F>,
        pair: &MatrixPair<F>,
    ) -> Result<Option<RoundProof<F, H::Output>>, Error> {
        validate_round(self.pp, self.round, pair)?;
        if self.round >= self.pp.rounds() {
            self.tail
                .as_mut()
                .ok_or(Error("missing decoded tail"))?
                .fold_in_place(pair)
                .map_err(|_| Error("local tail shape"))?;
            self.round += 1;
            return Ok(None);
        }
        let layer = self.round;
        let parent = self.current.as_ref().unwrap_or(self.initial);
        let values = fold(self.pp, layer, &parent.values, pair);
        let child = state::<F, H>(self.pp, layer + 1, values);
        let root = Commitment {
            root: child.tree.root,
        };
        bind_fold(trans, layer, &root);
        let indices = sample(trans, self.pp.len(layer + 1), self.pp.queries);
        let queries = indices
            .iter()
            .map(|&j| Query {
                parents: [
                    opening(self.pp, parent, 2 * j),
                    opening(self.pp, parent, 2 * j + 1),
                ],
                child: opening(self.pp, &child, j),
            })
            .collect::<Vec<_>>();
        trans.append_message(b"mw basefold query answers", &queries);
        let terminal =
            (layer + 1 == self.pp.rounds()).then(|| child.values[..self.pp.scalars()].to_vec());
        if let Some(v) = &terminal {
            self.tail = Some(terminal_table::<F, H>(self.pp, layer + 1, &root, v)?);
        }
        trans.append_message(b"mw basefold decoded tail", &terminal);
        self.current = Some(child);
        self.round += 1;
        Ok(Some(RoundProof {
            root,
            queries,
            terminal,
        }))
    }
    /// Return the authenticated terminal only after every original variable
    /// has been consumed. Prover output alone is not verifier acceptance.
    pub fn finish(&self) -> Result<Vec<F>, Error> {
        finish(self.pp, self.round, self.tail.as_ref())
    }
}
impl<'a, F, H> Verifier<'a, F, H>
where
    F: PrimeField + Serialize,
    H: Hash + Send + Sync,
{
    /// Authenticate a possible initial tail and bind the same start message.
    pub fn begin(
        trans: &mut Transcript<F>,
        pp: &'a Parameters<F>,
        root: &Commitment<H::Output>,
        proof: &StartProof<F>,
    ) -> Result<Self, Error> {
        if proof.terminal.is_some() != (pp.rounds() == 0) {
            return Err(Error("initial tail presence"));
        }
        bind_start::<F, H>(trans, pp, root);
        let tail = proof
            .terminal
            .as_ref()
            .map(|v| terminal_table::<F, H>(pp, 0, root, v))
            .transpose()?;
        trans.append_message(b"mw basefold initial tail", proof);
        Ok(Self {
            pp,
            root: root.clone(),
            tail,
            round: 0,
        })
    }
    /// Check exactly one fresh-challenge oracle fold or one local tail fold.
    /// Proof messages cannot supply the matrix challenge or sampled indices.
    pub fn advance(
        &mut self,
        trans: &mut Transcript<F>,
        pair: &MatrixPair<F>,
        proof: Option<&RoundProof<F, H::Output>>,
    ) -> Result<(), Error> {
        validate_round(self.pp, self.round, pair)?;
        if self.round >= self.pp.rounds() {
            if proof.is_some() {
                return Err(Error("extra oracle round"));
            }
            self.tail
                .as_mut()
                .ok_or(Error("missing decoded tail"))?
                .fold_in_place(pair)
                .map_err(|_| Error("local tail shape"))?;
            self.round += 1;
            return Ok(());
        }
        let proof = proof.ok_or(Error("missing oracle round"))?;
        let layer = self.round;
        if proof.queries.is_empty()
            || proof.queries.len() > self.pp.queries.min(self.pp.len(layer + 1))
            || proof.terminal.is_some() != (layer + 1 == self.pp.rounds())
        {
            return Err(Error("round proof dimensions"));
        }
        bind_fold(trans, layer, &proof.root);
        let indices = sample(trans, self.pp.len(layer + 1), self.pp.queries);
        if proof.queries.len() != indices.len() {
            return Err(Error("distinct query count"));
        }
        let half = F::one() / (F::one() + F::one());
        let inverse_shift = F::one() / self.pp.shift(layer);
        for (&j, q) in indices.iter().zip(&proof.queries) {
            check_opening::<F, H>(self.pp, layer, &self.root, 2 * j, &q.parents[0])?;
            check_opening::<F, H>(self.pp, layer, &self.root, 2 * j + 1, &q.parents[1])?;
            check_opening::<F, H>(self.pp, layer + 1, &proof.root, j, &q.child)?;
            let inverse_x = rolling_fri::point(inverse_shift, self.pp.len(layer), 2 * j);
            if fold_symbol(
                self.pp,
                &q.parents[0].values,
                &q.parents[1].values,
                pair,
                inverse_x,
                half,
            ) != q.child.values
            {
                return Err(Error("false folding identity"));
            }
        }
        trans.append_message(b"mw basefold query answers", &proof.queries);
        if let Some(v) = &proof.terminal {
            self.tail = Some(terminal_table::<F, H>(self.pp, layer + 1, &proof.root, v)?);
        }
        trans.append_message(b"mw basefold decoded tail", &proof.terminal);
        self.root = proof.root.clone();
        self.round += 1;
        Ok(())
    }
    /// Return the fully folded original table's value after all rounds.
    pub fn finish(&self) -> Result<Vec<F>, Error> {
        finish(self.pp, self.round, self.tail.as_ref())
    }
}
fn validate_round<F: PrimeField + Serialize>(
    pp: &Parameters<F>,
    round: usize,
    pair: &MatrixPair<F>,
) -> Result<(), Error> {
    if round >= pp.variables {
        return Err(Error("extra matrix challenge"));
    }
    pair.validate(pp.width)
        .map_err(|_| Error("matrix pair dimensions"))
}
fn finish<F: PrimeField + Serialize>(
    pp: &Parameters<F>,
    round: usize,
    tail: Option<&PackedTable<F>>,
) -> Result<Vec<F>, Error> {
    let tail = tail.ok_or(Error("missing decoded tail"))?;
    if round != pp.variables || tail.num_vars() != 0 {
        return Err(Error("incomplete matrix schedule"));
    }
    Ok(tail.values().to_vec())
}
fn bind_start<F: PrimeField + Serialize, H: Hash>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
) {
    trans.append_message(b"mw basefold original root", &(pp.context::<H>(), root));
}
fn bind_fold<F: PrimeField, O: Serialize>(
    trans: &mut Transcript<F>,
    layer: usize,
    root: &Commitment<O>,
) {
    trans.append_message(b"mw basefold folded root", &(layer, root));
}
fn sample<F: PrimeField>(trans: &mut Transcript<F>, len: usize, count: usize) -> Vec<usize> {
    let mut seen = std::collections::HashSet::with_capacity(count.min(len));
    let mut distinct = Vec::with_capacity(count.min(len));
    // Retain every independent draw in the transcript. Deduplicating only the
    // transmitted certificates preserves the with-replacement query test.
    for _ in 0..count {
        let mut bytes = [0u8; 8];
        trans.get_challenge_bytes(b"mw basefold unbiased block", &mut bytes);
        let j = (u64::from_le_bytes(bytes) as usize) & (len - 1);
        if seen.insert(j) {
            distinct.push(j);
        }
    }
    distinct
}

fn leaf<F: PrimeField + Serialize, H: Hash>(
    context: H::Output,
    layer: usize,
    index: usize,
    v: &[F],
) -> H::Output {
    rolling_fri::hash::<H, _>(&(
        b"mw basefold whole block v1".as_slice(),
        context,
        layer,
        index,
        v,
    ))
}
fn state<F: PrimeField + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    layer: usize,
    values: Vec<F>,
) -> State<F, H> {
    assert_eq!(values.len(), pp.len(layer) * pp.scalars());
    // Goldilocks permits lazy representatives; a constant codeword must have
    // one deterministic wire representation at every domain position.
    let values: Vec<F> = values.into_iter().map(|v| F::new(v.value())).collect();
    let context = pp.context::<H>();
    let hashes = values
        .par_chunks_exact(pp.scalars())
        .enumerate()
        .map(|(i, v)| leaf::<F, H>(context, layer, i, v))
        .collect::<Vec<_>>();
    let mut tree = MerkleTree::new();
    tree.generate(&hashes);
    State {
        values,
        tree,
        context,
        layer,
    }
}
fn opening<F: PrimeField + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    s: &State<F, H>,
    index: usize,
) -> Opening<F, H::Output> {
    Opening {
        values: s.values[index * pp.scalars()..(index + 1) * pp.scalars()].to_vec(),
        path: s.tree.query(index),
    }
}
fn check_opening<F: PrimeField + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    layer: usize,
    root: &Commitment<H::Output>,
    index: usize,
    p: &Opening<F, H::Output>,
) -> Result<(), Error> {
    if index >= pp.len(layer)
        || p.values.len() != pp.scalars()
        || p.path.len() != pp.len(layer).ilog2() as usize + 1
    {
        return Err(Error("opening dimensions"));
    }
    if p.path[0] != leaf::<F, H>(pp.context::<H>(), layer, index, &p.values)
        || !MerkleTree::<H>::check(&root.root, index, &p.path)
    {
        return Err(Error("block authentication"));
    }
    Ok(())
}
fn terminal_table<F: PrimeField + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    layer: usize,
    root: &Commitment<H::Output>,
    block: &[F],
) -> Result<PackedTable<F>, Error> {
    if layer != pp.rounds() || block.len() != pp.scalars() {
        return Err(Error("terminal block dimensions"));
    }
    let values = (0..pp.len(layer))
        .flat_map(|_| block.iter().copied())
        .collect();
    if state::<F, H>(pp, layer, values).tree.root != root.root {
        return Err(Error("terminal codeword"));
    }
    let k = pp.width;
    let mut values = vec![F::zero(); k * k];
    for c in 0..k {
        for lane in 0..k {
            values[c * k + lane] = block[lane * k + c];
        }
    }
    PackedTable::new(k.ilog2() as usize, k, values).map_err(|_| Error("terminal table shape"))
}
fn fold<F: PrimeField + Serialize>(
    pp: &Parameters<F>,
    layer: usize,
    values: &[F],
    pair: &MatrixPair<F>,
) -> Vec<F> {
    let n = pp.len(layer);
    let size = pp.scalars();
    let half = F::one() / (F::one() + F::one());
    let inverse_shift = F::one() / pp.shift(layer);
    let mut inverse_points = Vec::with_capacity(n / 2);
    let mut x = inverse_shift;
    let step = x * x;
    for _ in 0..n / 2 {
        inverse_points.push(x);
        x *= step;
    }
    let bits = (n / 2).ilog2();
    values
        .par_chunks_exact(2 * size)
        .enumerate()
        .flat_map_iter(|(j, p)| {
            let exponent = if bits == 0 {
                0
            } else {
                j.reverse_bits() >> (usize::BITS - bits)
            };
            fold_symbol(
                pp,
                &p[..size],
                &p[size..],
                pair,
                inverse_points[exponent],
                half,
            )
        })
        .collect()
}
fn fold_symbol<F: PrimeField + Serialize>(
    pp: &Parameters<F>,
    a: &[F],
    b: &[F],
    pair: &MatrixPair<F>,
    inverse_x: F,
    half: F,
) -> Vec<F> {
    let k = pp.width;
    let mut out = vec![F::zero(); k * k];
    for input in 0..k {
        for c in 0..k {
            let even = (a[input * k + c] + b[input * k + c]) * half;
            let odd = (a[input * k + c] - b[input * k + c]) * half * inverse_x;
            for lane in 0..k {
                out[lane * k + c] += pair.zero.values()[lane * k + input] * even
                    + pair.one.values()[lane * k + input] * odd;
            }
        }
    }
    out
}
fn power<F: PrimeField>(mut x: F, mut n: usize) -> F {
    let mut out = F::one();
    while n > 0 {
        if n & 1 != 0 {
            out *= x;
        }
        x *= x;
        n >>= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, matrix_weighted::Matrix, transformation::AbstractNTT};
    use num_traits::One;
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

    fn parameters<F: NTTField + Serialize + From<usize>>(
        variables: usize,
        k: usize,
    ) -> Parameters<F> {
        let n = (1usize << variables) / k * 2;
        let root = power(
            F::generate_ntt_table(n.max(64).ilog2()).unwrap().root(),
            n.max(64) / n,
        );
        Parameters::new(variables, k, 2, 12, root).unwrap()
    }
    fn challenge<F: PrimeField + From<usize>>(t: &mut Transcript<F>, k: usize) -> MatrixPair<F> {
        let points = t.get_vec_challenge(b"independent test packed challenges", k);
        let mut zero = Vec::new();
        let mut one = Vec::new();
        for x in points {
            for j in 0..2 * k {
                let node = F::from(j);
                let mut w = F::one();
                for h in 0..2 * k {
                    if h != j {
                        w *= (x - F::from(h)) / (node - F::from(h));
                    }
                }
                if j % 2 == 0 {
                    zero.push(w);
                } else {
                    one.push(w);
                }
            }
        }
        MatrixPair {
            zero: Matrix::new(k, zero).unwrap(),
            one: Matrix::new(k, one).unwrap(),
        }
    }
    fn exercise<F: NTTField + Serialize + DeserializeOwned + From<usize>>() {
        for k in [1usize, 2, 4, 8] {
            for extra in 0..=4 {
                let vars = k.ilog2() as usize + extra;
                let pp = parameters::<F>(vars, k);
                let table = PackedTable::new(
                    vars,
                    k,
                    (0..(1 << vars) * k)
                        .map(|i| F::from(i * i + 7 * i + 19))
                        .collect(),
                )
                .unwrap();
                let (root, state) = commit::<F, Sha256>(&pp, &table).unwrap();
                // Independent Horner evaluation of every coordinate. The residual
                // high Boolean variables are inside each block, never reversed.
                let m = 1usize << pp.rounds();
                let n = pp.encoded_len();
                for j in 0..n {
                    let reversed = if n == 1 {
                        0
                    } else {
                        j.reverse_bits() >> (usize::BITS - n.ilog2())
                    };
                    let x = power(pp.root, 2 * reversed + 1);
                    for lane in 0..k {
                        for residual in 0..k {
                            let value = (0..m).rev().fold(F::zero(), |out, b| {
                                out * x + table.values()[(b + residual * m) * k + lane]
                            });
                            assert_eq!(state.values[j * k * k + lane * k + residual], value);
                        }
                    }
                }
                let mut t = Transcript::new_direct();
                let (mut prover, start) = Prover::begin(&mut t, &pp, &root, &state).unwrap();
                if vars > 0 {
                    assert!(prover.finish().is_err());
                }
                let mut proofs = Vec::new();
                let mut query = Vec::new();
                let mut folded = table.clone();
                for i in 0..vars {
                    let pair = challenge(&mut t, k);
                    folded.fold_in_place(&pair).unwrap();
                    proofs.push(prover.advance(&mut t, &pair).unwrap());
                    query.push(pair);
                    if i < pp.rounds() {
                        let remaining = Parameters::new(
                            vars - i - 1,
                            k,
                            pp.blowup,
                            pp.queries,
                            pp.shift(i + 1),
                        )
                        .unwrap();
                        let (_, fresh) = commit::<F, Sha256>(&remaining, &folded).unwrap();
                        assert_eq!(prover.current.as_ref().unwrap().values, fresh.values);
                    }
                }
                let expected = table.evaluate(&query).unwrap();
                assert_eq!(prover.finish().unwrap(), expected);
                if vars > 0 {
                    assert!(prover.advance(&mut t, &query[0]).is_err());
                }
                let bytes =
                    bincode::serde::encode_to_vec(&(start, proofs), bincode::config::standard())
                        .unwrap();
                let ((start, proofs), used): (
                    (StartProof<F>, Vec<Option<RoundProof<F, [u8; 32]>>>),
                    _,
                ) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let replay = |start: &StartProof<F>,
                              proofs: &[Option<RoundProof<F, [u8; 32]>>]|
                 -> Result<(Vec<F>, F), Error> {
                    let mut v = Transcript::new_direct();
                    let mut verifier = Verifier::<F, Sha256>::begin(&mut v, &pp, &root, start)?;
                    for (i, p) in proofs.iter().enumerate() {
                        let pair = challenge(&mut v, k);
                        assert!(i < vars);
                        verifier.advance(&mut v, &pair, p.as_ref())?;
                    }
                    let value = verifier.finish()?;
                    Ok((value, v.get_challenge(b"after streamed opening")))
                };
                let (value, after) = replay(&start, &proofs).unwrap();
                assert_eq!(value, expected);
                assert_eq!(after, t.get_challenge(b"after streamed opening"));
                if pp.rounds() > 0 {
                    let mut bad = proofs.clone();
                    bad[0].as_mut().unwrap().queries.pop();
                    assert!(replay(&start, &bad).is_err());
                    let mut bad = proofs.clone();
                    bad[0].as_mut().unwrap().queries[0].parents[0].values.pop();
                    assert!(replay(&start, &bad).is_err());
                    let mut bad = proofs.clone();
                    bad[0].as_mut().unwrap().queries[0].child.path.clear();
                    assert!(replay(&start, &bad).is_err());
                    let mut bad = proofs.clone();
                    bad[pp.rounds() - 1]
                        .as_mut()
                        .unwrap()
                        .terminal
                        .as_mut()
                        .unwrap()[0] += F::one();
                    assert!(replay(&start, &bad).is_err());
                    let mut bad = proofs.clone();
                    bad[0] = None;
                    assert!(replay(&start, &bad).is_err());
                } else {
                    let mut bad = start.clone();
                    bad.terminal.as_mut().unwrap()[0] += F::one();
                    assert!(replay(&bad, &proofs).is_err());
                }
            }
        }
    }
    #[test]
    fn babybear_stream_matches_independent_encoding() {
        exercise::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_stream_matches_independent_encoding() {
        exercise::<algebra::Goldilocks>();
    }
    #[test]
    fn noncommuting_lane_matrices_preserve_query_order() {
        type F = algebra::BabyBear;
        let pp = parameters::<F>(4, 2);
        let table = PackedTable::new(4, 2, (0..32).map(|i| F::from(i * i + 1)).collect()).unwrap();
        let (_, s) = commit::<F, Sha256>(&pp, &table).unwrap();
        let pair = |a: [usize; 4], b: [usize; 4]| MatrixPair {
            zero: Matrix::new(2, a.map(F::from).to_vec()).unwrap(),
            one: Matrix::new(2, b.map(F::from).to_vec()).unwrap(),
        };
        let a = pair([1, 2, 3, 5], [0, 1, 1, 0]);
        let b = pair([2, 0, 1, 3], [3, 2, 0, 1]);
        assert_ne!(a.zero.mul(&b.zero).unwrap(), b.zero.mul(&a.zero).unwrap());
        let once = fold(&pp, 0, &s.values, &a);
        let twice = fold(&pp, 1, &once, &b);
        let q = vec![a.clone(), b.clone()];
        let mut direct = table.clone();
        for pair in &q {
            direct.fold_in_place(pair).unwrap();
        }
        let remaining = Parameters::new(2, 2, 2, 12, pp.shift(2)).unwrap();
        let (_, reference) = commit::<F, Sha256>(&remaining, &direct).unwrap();
        assert_eq!(twice, reference.values);
        let wrong = fold(&pp, 1, &fold(&pp, 0, &s.values, &b), &a);
        assert_ne!(twice, wrong);
    }
    fn invalid_degree_attack<F: NTTField + Serialize + From<usize>>() {
        let pp = parameters::<F>(3, 2);
        let n = pp.encoded_len();
        let m = 1usize << pp.rounds();
        // This is X^m, not a polynomial of the committed degree bound <m.
        // The oracle and all its Merkle paths are genuine and fixed first.
        let mut values = vec![F::zero(); n * pp.scalars()];
        for j in 0..n {
            values[j * pp.scalars()] = power(rolling_fri::point(pp.root, n, j), m);
        }
        let initial = state::<F, Sha256>(&pp, 0, values);
        let root = Commitment {
            root: initial.tree.root,
        };
        let mut t = Transcript::new_direct();
        let (mut prover, start) = Prover::begin(&mut t, &pp, &root, &initial).unwrap();
        let first_pair = challenge(&mut t, 2);
        let first = prover.advance(&mut t, &first_pair).unwrap().unwrap();
        let last_pair = challenge(&mut t, 2);
        let parent = prover.current.as_ref().unwrap();
        // A fresh dishonest final oracle claims zero. Authentication is valid
        // for this root; the folding equation, not a hash replay, must fail.
        let child = state::<F, Sha256>(&pp, 2, vec![F::zero(); pp.len(2) * pp.scalars()]);
        let next = Commitment {
            root: child.tree.root,
        };
        bind_fold(&mut t, 1, &next);
        let indices = sample(&mut t, pp.len(2), pp.queries);
        let queries = indices
            .iter()
            .map(|&j| Query {
                parents: [opening(&pp, parent, 2 * j), opening(&pp, parent, 2 * j + 1)],
                child: opening(&pp, &child, j),
            })
            .collect::<Vec<_>>();
        let proof = RoundProof {
            root: next,
            queries,
            terminal: Some(vec![F::zero(); pp.scalars()]),
        };
        let begin = || {
            let mut v = Transcript::new_direct();
            let mut verifier = Verifier::<F, Sha256>::begin(&mut v, &pp, &root, &start).unwrap();
            let pair = challenge(&mut v, 2);
            assert_eq!(pair, first_pair);
            verifier.advance(&mut v, &pair, Some(&first)).unwrap();
            let pair = challenge(&mut v, 2);
            assert_eq!(pair, last_pair);
            (v, verifier, pair)
        };
        let (mut auth, verifier, pair) = begin();
        bind_fold(&mut auth, 1, &proof.root);
        for (&j, q) in sample(&mut auth, pp.len(2), pp.queries)
            .iter()
            .zip(&proof.queries)
        {
            check_opening::<F, Sha256>(&pp, 1, &verifier.root, 2 * j, &q.parents[0]).unwrap();
            check_opening::<F, Sha256>(&pp, 1, &verifier.root, 2 * j + 1, &q.parents[1]).unwrap();
            check_opening::<F, Sha256>(&pp, 2, &proof.root, j, &q.child).unwrap();
            let x = rolling_fri::point(pp.shift(1), pp.len(1), 2 * j);
            assert_ne!(
                fold_symbol(
                    &pp,
                    &q.parents[0].values,
                    &q.parents[1].values,
                    &pair,
                    F::one() / x,
                    F::one() / (F::one() + F::one())
                ),
                q.child.values
            );
        }
        terminal_table::<F, Sha256>(&pp, 2, &proof.root, proof.terminal.as_ref().unwrap()).unwrap();
        let (mut v, mut verifier, pair) = begin();
        assert_eq!(
            verifier.advance(&mut v, &pair, Some(&proof)).unwrap_err().0,
            "false folding identity"
        );
    }
    #[test]
    fn babybear_fresh_invalid_degree_with_genuine_paths_fails_fold() {
        invalid_degree_attack::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_fresh_invalid_degree_with_genuine_paths_fails_fold() {
        invalid_degree_attack::<algebra::Goldilocks>();
    }
    #[test]
    fn duplicate_certificates_preserve_every_independent_draw() {
        type F = algebra::BabyBear;
        let mut t = Transcript::<F>::new_direct();
        let actual = sample(&mut t, 2, 100);
        let mut v = Transcript::<F>::new_direct();
        let mut expected = Vec::new();
        for _ in 0..100 {
            let mut bytes = [0u8; 8];
            v.get_challenge_bytes(b"mw basefold unbiased block", &mut bytes);
            let j = (u64::from_le_bytes(bytes) as usize) & 1;
            if !expected.contains(&j) {
                expected.push(j);
            }
        }
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 2);
        assert_eq!(
            t.get_challenge(b"after every draw"),
            v.get_challenge(b"after every draw")
        );
    }
    #[test]
    fn malformed_geometry_and_mismatched_reusable_state_are_rejected() {
        type F = algebra::BabyBear;
        let pp = parameters::<F>(3, 2);
        for (n, k, b, q) in [
            (3, 0, 2, 12),
            (3, 3, 2, 12),
            (0, 2, 2, 12),
            (3, 2, 1, 12),
            (3, 2, 2, 0),
            (usize::BITS as usize, 2, 2, 12),
        ] {
            assert!(Parameters::new(n, k, b, q, pp.root).is_err());
        }
        assert!(Parameters::new(3, 2, 2, 12, F::one()).is_err());
        let table = PackedTable::new(3, 2, vec![F::one(); 16]).unwrap();
        let (root, state) = commit::<F, Sha256>(&pp, &table).unwrap();
        let wrong = Parameters::new(3, 2, 2, 13, pp.root).unwrap();
        assert!(Prover::begin(&mut Transcript::new_direct(), &wrong, &root, &state).is_err());
        let pp = parameters::<F>(0, 1);
        let table = PackedTable::new(0, 1, vec![F::one()]).unwrap();
        let (root, state) = commit::<F, Sha256>(&pp, &table).unwrap();
        let (_, start) = Prover::begin(&mut Transcript::new_direct(), &pp, &root, &state).unwrap();
        let mut missing = start;
        missing.terminal = None;
        assert!(
            Verifier::<F, Sha256>::begin(&mut Transcript::new_direct(), &pp, &root, &missing)
                .is_err()
        );
    }
}
