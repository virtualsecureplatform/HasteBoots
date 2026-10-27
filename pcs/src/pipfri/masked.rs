//! Experimental Protocol-3-style masked PipFRI reference (2025/1354, §4.2).
//!
//! Random high-half padding hides original-fragment queries. An independent
//! full polynomial masks the virtual target; no fragment evaluation vector is
//! sent. A virtual initial batch oracle and one shared query experiment bind the
//! original fragments/mask and all public folds. Explicit stateful opening
//! budgets limit reuse of those masks. This construction is not a reviewed
//! zero-knowledge or whole-proof security certificate.
use super::{Basis, evaluate, fold_coefficients};
use crate::{
    rolling_fri as fri,
    utils::{hash::Hash, merkle_tree::MerkleTree},
};
use algebra::{AbstractExtensionField, Field};
use helper::{FiatShamirTranscript, Transcript};
use rand::{CryptoRng, Rng};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Trusted original fragment size, RS domain and cumulative opening budget.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F> {
    fri: fri::Parameters<F>,
    fragments: usize,
    basis: Basis,
    max_openings: usize,
}
impl<F: Field + Serialize> Parameters<F> {
    /// Each data fragment has `m` entries, padded privately to `2m`. The root
    /// must have exact order `2*(2m*blowup)`. A conservative numerical disclosure
    /// allowance requires m >= max_openings*(2 + queries*(2+4*log2(2m))). This
    /// capacity check alone is not a proof of statistical zero knowledge.
    pub fn new(
        m: usize,
        fragments: usize,
        blowup: usize,
        queries: usize,
        max_openings: usize,
        root: F,
        basis: Basis,
    ) -> Result<Self, fri::Error> {
        if m < 2
            || !m.is_power_of_two()
            || !fragments.is_power_of_two()
            || max_openings == 0
            || m.checked_mul(fragments).is_none()
        {
            return Err(fri::Error("masked fragment geometry/budget"));
        }
        let padded = m
            .checked_mul(2)
            .ok_or(fri::Error("masked fragment overflow"))?;
        let fri = fri::Parameters::new(padded, blowup, queries, root)?;
        let allowance = 4usize
            .checked_mul(fri.rounds())
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_mul(queries))
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_mul(max_openings))
            .ok_or(fri::Error("masked disclosure budget overflow"))?;
        if allowance > m {
            return Err(fri::Error("insufficient random padding for opening budget"));
        }
        Ok(Self {
            fri,
            fragments,
            basis,
            max_openings,
        })
    }
    /// Select the existing coordinate-wise encoder without changing wire data.
    pub fn with_base_field_encoder<Base: Field>(mut self) -> Result<Self, fri::Error>
    where
        F: AbstractExtensionField<Base>,
    {
        self.fri = self.fri.with_base_field_encoder::<Base>()?;
        Ok(self)
    }
    /// Number of unpadded scalar entries in each original fragment.
    pub fn fragment_len(&self) -> usize {
        1usize << (self.fri.rounds() - 1)
    }
    /// Original scalar-table size.
    pub fn table_len(&self) -> usize {
        self.fragment_len() * self.fragments
    }
    /// Original point dimension; the padding coordinate is internal.
    pub fn num_vars(&self) -> usize {
        self.table_len().ilog2() as usize
    }
    /// Maximum openings across this commitment's complete lifetime.
    pub fn max_openings(&self) -> usize {
        self.max_openings
    }
    fn context<H: Hash>(&self) -> H::Output {
        fri::hash::<H, _>(&(
            b"HasteBoots masked scalar PipFRI parameters v1".as_slice(),
            self.fri.context::<H>(),
            self,
        ))
    }
}
/// Masked packed-fragment commitment, including the independent mask polynomial.
pub type Commitment<O> = fri::Commitment<O>;
/// Original-source pair at every padded fragment and at the independent mask.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceOpening<F, O> {
    /// Fragment-order pairs, followed by the independent mask pair.
    pub values: Vec<[F; 2]>,
    /// One shared packed-pair authentication path.
    pub path: Vec<O>,
}
/// Evaluation proof with no individual fragment-evaluation claims.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Monotone session index, bound before challenges and checked externally.
    pub opening_index: usize,
    /// Evaluation of the committed random mask at the internal padded point.
    pub mask_value: F,
    /// Public-point folded originals h_1,...,h_(log2(2m)-1).
    pub ladder: Vec<Commitment<O>>,
    /// Virtual-source batch FRI, sharing all consistency-query locations.
    pub low_degree: fri::Proof<F, O>,
    /// Authenticate every original padded fragment/mask at those same locations.
    pub sources: Vec<SourceOpening<F, O>>,
}
struct State<F, H: Hash + Send + Sync> {
    context: H::Output,
    coefficients: Vec<Vec<F>>,
    values: Vec<Vec<F>>,
    tree: MerkleTree<H>,
}
/// Non-cloneable, non-serializable private masks and cumulative opening counter.
/// Each new commitment must receive fresh private cryptographic randomness.
pub struct ProverSession<F, H: Hash + Send + Sync> {
    parameters: Parameters<F>,
    state: State<F, H>,
    next: usize,
}
/// Expected commitment/parameters and accepted opening sequence, with no witness.
/// Reusing a verifier session detects replay; the prover independently enforces
/// its own lifetime budget even if a verifier starts a new session.
pub struct VerifierSession<F, H: Hash + Send + Sync> {
    parameters: Parameters<F>,
    root: Commitment<H::Output>,
    next: usize,
}
/// Commit with fresh private padding and an independent size-2m random mask.
/// Publicly seeded RNGs are suitable for reproducible tests, not privacy.
pub fn commit<F, H, R>(
    pp: &Parameters<F>,
    data: &[F],
    rng: &mut R,
) -> Result<ProverSession<F, H>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
    R: Rng + CryptoRng,
{
    if data.len() != pp.table_len() {
        return Err(fri::Error("masked table length"));
    }
    let m = pp.fragment_len();
    let mut coefficients = data
        .chunks_exact(m)
        .map(|c| {
            let mut c = c.to_vec();
            c.extend((0..m).map(|_| F::random(rng)));
            c
        })
        .collect::<Vec<_>>();
    coefficients.push((0..2 * m).map(|_| F::random(rng)).collect());
    // Randomness stays in its original sequential order; only independent
    // encoding jobs and ordered leaf hashes are scheduled across workers.
    let values = coefficients
        .par_iter()
        .map(|c| pp.fri.encode(c, 0))
        .collect::<Vec<_>>();
    let context = pp.context::<H>();
    let hashes = (0..pp.fri.encoded_len() / 2)
        .into_par_iter()
        .map(|i| leaf::<F, H>(context, i, &pairs(&values, i)))
        .collect::<Vec<_>>();
    let mut tree = MerkleTree::new();
    tree.generate(&hashes);
    Ok(ProverSession {
        parameters: pp.clone(),
        state: State {
            context,
            coefficients,
            values,
            tree,
        },
        next: 0,
    })
}
impl<F, H> ProverSession<F, H>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    /// Expected public root; no private masks or codewords are exposed.
    pub fn commitment(&self) -> Commitment<H::Output> {
        Commitment {
            root: self.state.tree.root,
        }
    }
    /// Remaining lifetime opening allowance.
    pub fn remaining_openings(&self) -> usize {
        self.parameters.max_openings - self.next
    }
    /// Compute a scalar evaluation and prove it, consuming one opening allowance.
    pub fn open_at(
        &mut self,
        t: &mut Transcript<F>,
        point: &[F],
    ) -> Result<(F, Proof<F, H::Output>), fri::Error> {
        let value = self.value(point)?;
        Ok((value, self.open(t, point, value)?))
    }
    /// Prove the caller's scalar claim. Wrong claims/point dimensions are
    /// rejected before publishing mask evaluations or consuming an allowance.
    pub fn open(
        &mut self,
        t: &mut Transcript<F>,
        point: &[F],
        value: F,
    ) -> Result<Proof<F, H::Output>, fri::Error> {
        if self.next >= self.parameters.max_openings {
            return Err(fri::Error("masked opening budget exhausted"));
        }
        if self.value(point)? != value {
            return Err(fri::Error("masked claimed evaluation"));
        }
        let index = self.next;
        self.next += 1;
        open_impl::<F, H>(t, &self.parameters, &self.state, index, point, value)
    }
    fn value(&self, point: &[F]) -> Result<F, fri::Error> {
        let pp = &self.parameters;
        if point.len() != pp.num_vars() {
            return Err(fri::Error("masked point dimension"));
        }
        let low = pp.fri.rounds() - 1;
        let weights = weights(pp, point);
        Ok(self.state.coefficients[..pp.fragments]
            .iter()
            .zip(weights)
            .fold(F::zero(), |sum, (c, w)| {
                sum + w * evaluate(&c[..pp.fragment_len()], &point[..low], pp.basis)
            }))
    }
}
impl<F, H> VerifierSession<F, H>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    /// Initialize from trusted parameters and an expected external commitment.
    pub fn new(pp: &Parameters<F>, root: Commitment<H::Output>) -> Self {
        Self {
            parameters: pp.clone(),
            root,
            next: 0,
        }
    }
    /// Remaining accepted-opening allowance.
    pub fn remaining_openings(&self) -> usize {
        self.parameters.max_openings - self.next
    }
    /// Verify the next opening; invalid certificates do not advance the counter.
    pub fn verify(
        &mut self,
        t: &mut Transcript<F>,
        point: &[F],
        value: F,
        proof: &Proof<F, H::Output>,
    ) -> Result<(), fri::Error> {
        self.verify_details(t, point, value, proof).map(|_| ())
    }
    fn verify_details(
        &mut self,
        t: &mut Transcript<F>,
        point: &[F],
        value: F,
        proof: &Proof<F, H::Output>,
    ) -> Result<DisclosureTrace<F>, fri::Error> {
        if self.next >= self.parameters.max_openings {
            return Err(fri::Error("masked verifier budget exhausted"));
        }
        if proof.opening_index != self.next {
            return Err(fri::Error("masked opening sequence"));
        }
        let trace = verify_impl::<F, H>(t, &self.parameters, &self.root, point, value, proof)?;
        self.next += 1;
        Ok(trace)
    }
}
fn open_impl<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    s: &State<F, H>,
    index: usize,
    point: &[F],
    value: F,
) -> Result<Proof<F, H::Output>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if s.context != pp.context::<H>() {
        return Err(fri::Error("masked state context"));
    }
    let z = padded_point(pp, point)?;
    let mask_value = evaluate(&s.coefficients[pp.fragments], &z, pp.basis);
    open_claim::<F, H>(t, pp, s, index, point, value, mask_value, true)
}
fn open_claim<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    s: &State<F, H>,
    index: usize,
    point: &[F],
    value: F,
    mask_value: F,
    strict: bool,
) -> Result<Proof<F, H::Output>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let root = Commitment { root: s.tree.root };
    let z = padded_point(pp, point)?;
    let alpha = bind::<F, H>(t, pp, &root, index, point, value, mask_value)?;
    let weights = weights(pp, point);
    let mut coefficients = s.coefficients[pp.fragments]
        .iter()
        .map(|&c| alpha * c)
        .collect::<Vec<_>>();
    coefficients = add_linear_combination(coefficients, &s.coefficients[..pp.fragments], &weights);
    let mut ladder = Vec::with_capacity(pp.fri.rounds() - 1);
    for (i, &x) in z.iter().enumerate() {
        coefficients = fold_coefficients(&coefficients, pp.basis.weights(x));
        if i + 1 < pp.fri.rounds() {
            ladder.push(fri::commit_original::<F, H>(&pp.fri, i + 1, &coefficients)?);
        }
    }
    if strict && coefficients != vec![value + alpha * mask_value] {
        return Err(fri::Error("masked terminal evaluation"));
    }
    let roots = ladder
        .iter()
        .map(fri::State::commitment)
        .collect::<Vec<_>>();
    t.append_message(b"masked PipFRI public fold roots", &roots);
    let gamma = nonzero(t, b"masked PipFRI original batch");
    let powers = batch_weights(gamma, pp.fragments);
    let virtual_values = add_linear_combination(
        s.values[pp.fragments].clone(),
        &s.values[..pp.fragments],
        &powers,
    );
    let identifier = virtual_id::<F, H>(pp, &root, index, gamma);
    let refs = ladder.iter().collect::<Vec<_>>();
    let (low_degree, trace) =
        fri::prove_virtual_initial::<F, H>(t, &pp.fri, identifier, virtual_values, &refs)?;
    let sources = trace
        .indices
        .iter()
        .map(|&index| SourceOpening {
            values: pairs(&s.values, index / 2),
            path: s.tree.query(index / 2),
        })
        .collect::<Vec<_>>();
    Ok(Proof {
        opening_index: index,
        mask_value,
        ladder: roots,
        low_degree,
        sources,
    })
}
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct DisclosureTrace<F> {
    alpha: F,
    gamma: F,
    z: Vec<F>,
    fri: fri::Trace<F>,
}
/// Verify one opening against trusted parameters and an expected commitment.
/// This stateless entry point checks the proof index is within the committed
/// budget, but does not track prior acceptances. Use `VerifierSession` when
/// ordered acceptance/replay detection is required. Privacy also requires the
/// honest prover to retain one lifetime-bounded `ProverSession` per commitment.
pub fn verify_opening<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    point: &[F],
    value: F,
    proof: &Proof<F, H::Output>,
) -> Result<(), fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    verify_impl::<F, H>(t, pp, root, point, value, proof).map(|_| ())
}
fn verify_impl<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    point: &[F],
    value: F,
    proof: &Proof<F, H::Output>,
) -> Result<DisclosureTrace<F>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    verify_claim::<F, H>(t, pp, root, point, value, proof, true)
}
fn verify_claim<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    point: &[F],
    value: F,
    proof: &Proof<F, H::Output>,
    strict: bool,
) -> Result<DisclosureTrace<F>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let z = padded_point(pp, point)?;
    if proof.ladder.len() + 1 != pp.fri.rounds() || proof.sources.len() != pp.fri.queries() {
        return Err(fri::Error("masked proof dimensions"));
    }
    let alpha = bind::<F, H>(
        t,
        pp,
        root,
        proof.opening_index,
        point,
        value,
        proof.mask_value,
    )?;
    t.append_message(b"masked PipFRI public fold roots", &proof.ladder);
    let gamma = nonzero(t, b"masked PipFRI original batch");
    let powers = batch_weights(gamma, pp.fragments);
    let identifier = virtual_id::<F, H>(pp, root, proof.opening_index, gamma);
    let mut seen = 0;
    let trace = fri::verify_virtual_initial::<F, H, _>(
        t,
        &pp.fri,
        identifier,
        &proof.ladder,
        &proof.low_degree,
        |index, pair| {
            let source = &proof.sources[seen];
            seen += 1;
            authenticate::<F, H>(pp, root, index / 2, source)?;
            let combined = combine(&source.values, &powers, F::one());
            if pair.values != combined {
                return Err(fri::Error("masked virtual original mismatch"));
            }
            Ok(())
        },
    )?;
    let high = weights(pp, point);
    let half = F::one() / (F::one() + F::one());
    for ((&index, source), q) in trace
        .indices
        .iter()
        .zip(&proof.sources)
        .zip(&proof.low_degree.queries)
    {
        let first = combine(&source.values, &high, alpha);
        for i in 0..pp.fri.rounds() {
            let [a, b] = if i == 0 { first } else { q.originals[i].values };
            let x = fri::point(pp.fri.shift(i), pp.fri.len(i), (index >> i) & !1);
            let [w0, w1] = pp.basis.weights(z[i]);
            let folded = w0 * (a + b) * half + w1 * (a - b) * half / x;
            let expected = if i + 1 == pp.fri.rounds() {
                value + alpha * proof.mask_value
            } else {
                q.originals[i + 1].values[(index >> (i + 1)) & 1]
            };
            if folded != expected && (strict || i + 1 < pp.fri.rounds()) {
                return Err(fri::Error("masked public fold mismatch"));
            }
        }
    }
    Ok(DisclosureTrace {
        alpha,
        gamma,
        z,
        fri: trace,
    })
}
fn bind<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    index: usize,
    point: &[F],
    value: F,
    mask_value: F,
) -> Result<F, fri::Error> {
    if point.len() != pp.num_vars() || index >= pp.max_openings {
        return Err(fri::Error("masked claim dimensions/budget"));
    }
    t.append_message(
        b"HasteBoots masked scalar PipFRI v1",
        &(pp.context::<H>(), root, index, point, value, mask_value),
    );
    Ok(nonzero(t, b"masked PipFRI nonzero mask challenge"))
}
fn nonzero<F: Field>(t: &mut Transcript<F>, label: &'static [u8]) -> F {
    loop {
        let value = t.get_challenge(label);
        if value != F::zero() {
            return value;
        }
    }
}
fn padded_point<F: Field + Serialize>(
    pp: &Parameters<F>,
    point: &[F],
) -> Result<Vec<F>, fri::Error> {
    if point.len() != pp.num_vars() {
        return Err(fri::Error("masked point dimension"));
    }
    let mut z = point[..pp.fri.rounds() - 1].to_vec();
    z.push(F::zero());
    Ok(z)
}
fn weights<F: Field + Serialize>(pp: &Parameters<F>, point: &[F]) -> Vec<F> {
    let high = &point[pp.fri.rounds() - 1..];
    (0..pp.fragments)
        .map(|j| {
            high.iter()
                .enumerate()
                .fold(F::one(), |w, (i, &x)| w * pp.basis.weights(x)[(j >> i) & 1])
        })
        .collect()
}
fn batch_weights<F: Field>(gamma: F, count: usize) -> Vec<F> {
    let mut p = gamma;
    (0..count)
        .map(|_| {
            let out = p;
            p *= gamma;
            out
        })
        .collect()
}
fn virtual_id<F: Field + Serialize, H: Hash>(
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    index: usize,
    gamma: F,
) -> H::Output {
    fri::hash::<H, _>(&(
        b"masked PipFRI virtual original v1".as_slice(),
        pp.context::<H>(),
        root,
        index,
        gamma,
    ))
}
// Disjoint output blocks retain the exact per-coordinate source/addition order.
// This matters for wire compatibility with fields that permit lazy encodings.
fn add_linear_combination<F: Field>(mut out: Vec<F>, sources: &[Vec<F>], weights: &[F]) -> Vec<F> {
    out.par_chunks_mut(512)
        .enumerate()
        .for_each(|(block, output)| {
            let start = block * 512;
            let end = start + output.len();
            for (source, &weight) in sources.iter().zip(weights) {
                for (out, &value) in output.iter_mut().zip(&source[start..end]) {
                    *out += weight * value;
                }
            }
        });
    out
}
fn combine<F: Field>(pairs: &[[F; 2]], weights: &[F], mask: F) -> [F; 2] {
    let mut out = pairs[weights.len()].map(|v| mask * v);
    for (pair, &w) in pairs.iter().zip(weights) {
        for j in 0..2 {
            out[j] += w * pair[j];
        }
    }
    out
}
fn pairs<F: Field>(values: &[Vec<F>], index: usize) -> Vec<[F; 2]> {
    values
        .iter()
        .map(|v| [v[2 * index], v[2 * index + 1]])
        .collect()
}
fn leaf<F: Field + Serialize, H: Hash>(
    context: H::Output,
    index: usize,
    values: &[[F; 2]],
) -> H::Output {
    fri::hash::<H, _>(&(
        b"masked PipFRI packed pair v1".as_slice(),
        context,
        index,
        values,
    ))
}
fn authenticate<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    index: usize,
    p: &SourceOpening<F, H::Output>,
) -> Result<(), fri::Error> {
    let leaves = pp.fri.encoded_len() / 2;
    if index >= leaves
        || p.values.len() != pp.fragments + 1
        || p.path.len() != leaves.ilog2() as usize + 1
    {
        return Err(fri::Error("masked source dimensions"));
    }
    if p.path[0] != leaf::<F, H>(pp.context::<H>(), index, &p.values)
        || !MerkleTree::<H>::check(&root.root, index, &p.path)
    {
        return Err(fri::Error("masked source authentication"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, transformation::AbstractNTT};
    use num_traits::One;
    use rand::{SeedableRng, rngs::StdRng};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;
    fn parameters<B, F>(
        m: usize,
        fragments: usize,
        budget: usize,
        basis: Basis,
        embed: fn(B) -> F,
    ) -> Parameters<F>
    where
        B: NTTField + Serialize,
        F: Field + Serialize,
    {
        let n = 4 * m;
        Parameters::new(
            m,
            fragments,
            2,
            1,
            budget,
            embed(B::generate_ntt_table(n.ilog2()).unwrap().root()),
            basis,
        )
        .unwrap()
    }
    fn direct<F: Field>(data: &[F], point: &[F], basis: Basis) -> F {
        data.iter().enumerate().fold(F::zero(), |sum, (j, &v)| {
            sum + point.iter().enumerate().fold(v, |v, (i, &x)| {
                v * if j >> i & 1 == 1 {
                    x
                } else if basis == Basis::Coefficients {
                    F::one()
                } else {
                    F::one() - x
                }
            })
        })
    }
    fn exercise<B, F>(embed: fn(B) -> F, transcript: fn() -> Transcript<F>)
    where
        B: NTTField + Serialize + From<usize>,
        F: Field + Serialize + DeserializeOwned,
    {
        for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
            for fragments in [1, 2, 4] {
                let pp = parameters::<B, F>(64, fragments, 2, basis, embed);
                let mut rng = StdRng::seed_from_u64(781);
                let data = (0..pp.table_len())
                    .map(|_| F::random(&mut rng))
                    .collect::<Vec<_>>();
                let mut prover = commit::<F, Sha256, _>(&pp, &data, &mut rng).unwrap();
                let root = prover.commitment();
                let mut verifier = VerifierSession::<F, Sha256>::new(&pp, root.clone());
                for opening in 0..2 {
                    let point = if opening == 0 {
                        vec![F::zero(); pp.num_vars()]
                    } else {
                        (0..pp.num_vars()).map(|_| F::random(&mut rng)).collect()
                    };
                    let value = direct(&data, &point, basis);
                    let mut t = transcript();
                    let proof = prover.open(&mut t, &point, value).unwrap();
                    let bytes =
                        bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                    let (proof, used): (Proof<F, [u8; 32]>, _) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                            .unwrap();
                    assert_eq!(used, bytes.len());
                    assert_eq!(proof.opening_index, opening);
                    assert!(
                        proof
                            .low_degree
                            .queries
                            .iter()
                            .all(|q| q.originals[0].path.is_empty())
                    );
                    let mut v = transcript();
                    verifier.verify(&mut v, &point, value, &proof).unwrap();
                    assert_eq!(
                        t.get_challenge(b"after masked opening"),
                        v.get_challenge(b"after masked opening")
                    );
                    assert!(
                        verifier
                            .verify(&mut transcript(), &point, value, &proof)
                            .is_err()
                    );
                    if opening == 0 {
                        let reject = |p: &Proof<F, [u8; 32]>| {
                            assert!(
                                VerifierSession::<F, Sha256>::new(&pp, root.clone())
                                    .verify(&mut transcript(), &point, value, p)
                                    .is_err()
                            )
                        };
                        let mut bad = proof.clone();
                        bad.mask_value += F::one();
                        reject(&bad);
                        let mut bad = proof.clone();
                        bad.sources[0].values[0][0] += F::one();
                        reject(&bad);
                        let mut bad = proof.clone();
                        bad.sources[0].path.clear();
                        reject(&bad);
                        let mut bad = proof.clone();
                        bad.low_degree.queries[0].originals[0].values[0] += F::one();
                        reject(&bad);
                        let mut bad = proof.clone();
                        bad.low_degree.queries[0].originals[0].path.push([0u8; 32]);
                        reject(&bad);
                        let mut bad = proof.clone();
                        bad.ladder.pop();
                        reject(&bad);
                        let mut bad = proof.clone();
                        bad.sources.pop();
                        reject(&bad);
                    }
                }
                assert_eq!(prover.remaining_openings(), 0);
                assert_eq!(verifier.remaining_openings(), 0);
                assert!(
                    prover
                        .open_at(&mut transcript(), &vec![F::zero(); pp.num_vars()])
                        .is_err()
                );
                // Fresh false public claims, not a replay under a changed prefix.
                // All original masks/roots are fixed, and every child is genuine.
                let point = (0..pp.num_vars())
                    .map(|_| F::random(&mut rng))
                    .collect::<Vec<_>>();
                let value = direct(&data, &point, basis);
                let z = padded_point(&pp, &point).unwrap();
                let ys = evaluate(&prover.state.coefficients[fragments], &z, basis);
                for (claimed_y, claimed_s) in [(value + F::one(), ys), (value, ys + F::one())] {
                    let mut t = transcript();
                    let proof = open_claim::<F, Sha256>(
                        &mut t,
                        &pp,
                        &prover.state,
                        0,
                        &point,
                        claimed_y,
                        claimed_s,
                        false,
                    )
                    .unwrap();
                    let mut replay = transcript();
                    verify_claim::<F, Sha256>(
                        &mut replay,
                        &pp,
                        &root,
                        &point,
                        claimed_y,
                        &proof,
                        false,
                    )
                    .unwrap();
                    assert_eq!(
                        t.get_challenge(b"after genuine children"),
                        replay.get_challenge(b"after genuine children")
                    );
                    assert_eq!(
                        verify_impl::<F, Sha256>(
                            &mut transcript(),
                            &pp,
                            &root,
                            &point,
                            claimed_y,
                            &proof
                        )
                        .unwrap_err()
                        .0,
                        "masked public fold mismatch"
                    );
                }
            }
        }
    }
    #[test]
    fn babybear_masked_roundtrips_and_fresh_false_claims() {
        exercise::<algebra::BabyBear, algebra::BabyBear>(|x| x, Transcript::new_direct);
    }
    #[test]
    fn goldilocks_masked_roundtrips_and_fresh_false_claims() {
        exercise::<algebra::Goldilocks, algebra::Goldilocks>(|x| x, Transcript::new_direct);
    }
    #[test]
    fn babybear_extension_masked_roundtrips() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension5>(
            algebra::BabyBearExtension5::from_base,
            Transcript::new_direct_extension::<algebra::BabyBear>,
        );
    }
    #[test]
    fn goldilocks_extension_masked_roundtrips() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension5>(
            algebra::GoldilocksExtension5::from_base,
            Transcript::new_direct_extension::<algebra::Goldilocks>,
        );
    }
    #[test]
    fn private_randomness_budget_and_encoder_invariants() {
        type B = algebra::BabyBear;
        type F = algebra::BabyBearExtension5;
        let pp = parameters::<B, F>(64, 2, 2, Basis::BooleanEvaluations, F::from_base);
        let fast = pp.clone().with_base_field_encoder::<B>().unwrap();
        let mut rng = StdRng::seed_from_u64(973);
        let data = (0..pp.table_len())
            .map(|_| F::random(&mut rng))
            .collect::<Vec<_>>();
        let mut a_rng = StdRng::seed_from_u64(1234);
        let mut b_rng = StdRng::seed_from_u64(1234);
        let mut c_rng = StdRng::seed_from_u64(1235);
        let mut a = commit::<F, Sha256, _>(&pp, &data, &mut a_rng).unwrap();
        let mut b = commit::<F, Sha256, _>(&fast, &data, &mut b_rng).unwrap();
        let c = commit::<F, Sha256, _>(&pp, &data, &mut c_rng).unwrap();
        assert_eq!(a.commitment().root, b.commitment().root);
        assert_ne!(a.commitment().root, c.commitment().root);
        let point = vec![F::one(); pp.num_vars()];
        let mut ta = Transcript::new_direct_extension::<B>();
        let mut tb = Transcript::new_direct_extension::<B>();
        let (value, pa) = a.open_at(&mut ta, &point).unwrap();
        let (other, pb) = b.open_at(&mut tb, &point).unwrap();
        assert_eq!(value, other);
        assert_eq!(
            bincode::serde::encode_to_vec(&pa, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&pb, bincode::config::standard()).unwrap()
        );
        assert_eq!(ta.get_challenge(b"after"), tb.get_challenge(b"after"));
        let before = a.remaining_openings();
        assert!(
            a.open(&mut Transcript::new(), &point, value + F::one())
                .is_err()
        );
        assert_eq!(a.remaining_openings(), before);
        let root = F::from_base(B::generate_ntt_table(8).unwrap().root());
        assert!(Parameters::new(64, 2, 2, 1, 3, root, Basis::Coefficients).is_err());
        assert!(Parameters::new(64, 3, 2, 1, 1, root, Basis::Coefficients).is_err());
    }

    // Archived pre-parallel commit schedule, retained only as a byte-for-byte
    // protocol compatibility reference. RNG draws and source order are fixed.
    fn serial_commit<F: Field + Serialize>(
        pp: &Parameters<F>,
        data: &[F],
        rng: &mut StdRng,
    ) -> ProverSession<F, Sha256> {
        let m = pp.fragment_len();
        let mut coefficients = data
            .chunks_exact(m)
            .map(|c| {
                let mut c = c.to_vec();
                c.extend((0..m).map(|_| F::random(rng)));
                c
            })
            .collect::<Vec<_>>();
        coefficients.push((0..2 * m).map(|_| F::random(rng)).collect());
        let values = coefficients
            .iter()
            .map(|c| pp.fri.encode(c, 0))
            .collect::<Vec<_>>();
        let context = pp.context::<Sha256>();
        let hashes = (0..pp.fri.encoded_len() / 2)
            .map(|i| leaf::<F, Sha256>(context, i, &pairs(&values, i)))
            .collect::<Vec<_>>();
        let mut tree = MerkleTree::new();
        tree.generate(&hashes);
        ProverSession {
            parameters: pp.clone(),
            state: State {
                context,
                coefficients,
                values,
                tree,
            },
            next: 0,
        }
    }
    fn serial_add<F: Field>(mut out: Vec<F>, sources: &[Vec<F>], weights: &[F]) -> Vec<F> {
        for (source, &w) in sources.iter().zip(weights) {
            for (out, &v) in out.iter_mut().zip(source) {
                *out += w * v;
            }
        }
        out
    }
    fn wire<F: Serialize>(value: &F) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
    }
    fn parallel_compatibility<B, F>()
    where
        B: NTTField + Serialize,
        F: AbstractExtensionField<B> + Serialize,
    {
        for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
            let generic = parameters::<B, F>(512, 4, 2, basis, F::from_base);
            for pp in [
                generic.clone(),
                generic.with_base_field_encoder::<B>().unwrap(),
            ] {
                let mut fixture = StdRng::seed_from_u64(3841);
                let mut data = (0..pp.table_len())
                    .map(|_| F::random(&mut fixture))
                    .collect::<Vec<_>>();
                data[0] = -F::one() + F::one();
                data[1] = -F::one();
                data[2] = F::one();
                let points = [
                    vec![F::one(); pp.num_vars()],
                    (0..pp.num_vars())
                        .map(|_| F::random(&mut fixture))
                        .collect(),
                ];
                let mut serial_rng = StdRng::seed_from_u64(5241);
                let mut reference = serial_commit(&pp, &data, &mut serial_rng);
                let expected_root = reference.commitment();
                let mut expected = Vec::new();
                for point in &points {
                    let mut t = Transcript::new_direct_extension::<B>();
                    let (value, proof) = reference.open_at(&mut t, point).unwrap();
                    expected.push((value, wire(&proof), t.get_challenge(b"parallel after")));
                }
                for threads in [1, 2, 4] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(threads)
                        .build()
                        .unwrap();
                    pool.install(|| {
                        let mut rng = StdRng::seed_from_u64(5241);
                        let mut session = commit::<F, Sha256, _>(&pp, &data, &mut rng).unwrap();
                        assert_eq!(session.commitment().root, expected_root.root);
                        assert_eq!(
                            wire(&session.state.coefficients),
                            wire(&reference.state.coefficients)
                        );
                        assert_eq!(wire(&session.state.values), wire(&reference.state.values));
                        let mut expected_rng = serial_rng.clone();
                        assert_eq!(F::random(&mut rng), F::random(&mut expected_rng));
                        let c = &session.state.coefficients;
                        let v = &session.state.values;
                        let gamma = F::random(&mut fixture.clone());
                        let powers = batch_weights(gamma, pp.fragments);
                        for scale in [F::zero(), F::one(), gamma] {
                            let initial = c[pp.fragments]
                                .iter()
                                .map(|&x| scale * x)
                                .collect::<Vec<_>>();
                            assert_eq!(
                                wire(&add_linear_combination(
                                    initial.clone(),
                                    &c[..pp.fragments],
                                    &powers
                                )),
                                wire(&serial_add(initial, &c[..pp.fragments], &powers))
                            );
                        }
                        assert_eq!(
                            wire(&add_linear_combination(
                                v[pp.fragments].clone(),
                                &v[..pp.fragments],
                                &powers
                            )),
                            wire(&serial_add(
                                v[pp.fragments].clone(),
                                &v[..pp.fragments],
                                &powers
                            ))
                        );
                        let mut verifier =
                            VerifierSession::<F, Sha256>::new(&pp, expected_root.clone());
                        for (point, (value, proof, after)) in points.iter().zip(&expected) {
                            let mut t = Transcript::new_direct_extension::<B>();
                            let (got, p) = session.open_at(&mut t, point).unwrap();
                            assert_eq!(got, *value);
                            assert_eq!(wire(&p), *proof);
                            assert_eq!(t.get_challenge(b"parallel after"), *after);
                            verifier
                                .verify(
                                    &mut Transcript::new_direct_extension::<B>(),
                                    point,
                                    got,
                                    &p,
                                )
                                .unwrap();
                        }
                    });
                }
            }
        }
    }
    #[test]
    fn babybear_parallel_schedule_preserves_wire_and_entropy() {
        parallel_compatibility::<algebra::BabyBear, algebra::BabyBearExtension5>();
    }
    #[test]
    fn goldilocks_parallel_schedule_preserves_wire_and_entropy() {
        parallel_compatibility::<algebra::Goldilocks, algebra::GoldilocksExtension5>();
    }
    // Independent coefficient-space simulation of every revealed field element.
    // Hashes/challenge dependence require a separate random-oracle argument.
    fn numerical_view<F: Field + Serialize>(
        pp: &Parameters<F>,
        c: &[Vec<F>],
        point: &[F],
        trace: &DisclosureTrace<F>,
    ) -> Vec<F> {
        let r = pp.fri.rounds();
        let w = weights(pp, point);
        let mut target = c[pp.fragments]
            .iter()
            .map(|&v| trace.alpha * v)
            .collect::<Vec<_>>();
        let mut batch = c[pp.fragments].clone();
        for (j, &power) in batch_weights(trace.gamma, pp.fragments).iter().enumerate() {
            for k in 0..target.len() {
                target[k] += w[j] * c[j][k];
                batch[k] += power * c[j][k];
            }
        }
        let mut originals = vec![batch];
        for i in 0..r - 1 {
            target = fold_coefficients(&target, pp.basis.weights(trace.z[i]));
            originals.push(target.clone());
        }
        let mut combined = originals[0].clone();
        let mut derived = Vec::new();
        for (i, &a) in trace.fri.alphas.iter().enumerate() {
            let next = fold_coefficients(&combined, [F::one(), a]);
            if i + 1 == r {
                combined = next;
            } else {
                derived.push(next.clone());
                combined = next
                    .iter()
                    .zip(&originals[i + 1])
                    .map(|(&x, &y)| x + a * a * y)
                    .collect();
            }
        }
        let mut out = vec![evaluate(&c[pp.fragments], &trace.z, pp.basis), combined[0]];
        let pair = |coefficients: &[F], layer: usize, index: usize| {
            let x = fri::point(
                pp.fri.shift(layer),
                pp.fri.len(layer),
                (index >> layer) & !1,
            );
            [x, -x].map(|x| coefficients.iter().rev().fold(F::zero(), |y, &a| y * x + a))
        };
        for &index in &trace.fri.indices {
            for polynomial in c {
                out.extend(pair(polynomial, 0, index));
            }
            for (i, polynomial) in originals.iter().enumerate() {
                out.extend(pair(polynomial, i, index));
            }
            for (i, polynomial) in derived.iter().enumerate() {
                out.extend(pair(polynomial, i + 1, index));
            }
        }
        out
    }
    fn revealed<F: Field>(p: &Proof<F, [u8; 32]>) -> Vec<F> {
        let mut out = vec![p.mask_value, p.low_degree.terminal];
        for (s, q) in p.sources.iter().zip(&p.low_degree.queries) {
            for pair in &s.values {
                out.extend(*pair);
            }
            for pair in &q.originals {
                out.extend(pair.values);
            }
            for pair in &q.derived {
                out.extend(pair.values);
            }
        }
        out
    }
    fn rank<F: Field>(mut matrix: Vec<Vec<F>>) -> usize {
        if matrix.is_empty() {
            return 0;
        }
        let mut row = 0;
        for col in 0..matrix[0].len() {
            let Some(pivot) = (row..matrix.len()).find(|&i| matrix[i][col] != F::zero()) else {
                continue;
            };
            matrix.swap(row, pivot);
            let inverse = F::one() / matrix[row][col];
            for value in &mut matrix[row][col..] {
                *value *= inverse;
            }
            let normalized = matrix[row].clone();
            for lower in matrix.iter_mut().skip(row + 1) {
                let scale = lower[col];
                if scale != F::zero() {
                    for k in col..lower.len() {
                        lower[k] -= scale * normalized[k];
                    }
                }
            }
            row += 1;
            if row == matrix.len() {
                break;
            }
        }
        row
    }
    fn disclosure_audit<F: NTTField + Serialize + From<usize>>() {
        for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
            let pp = parameters::<F, F>(64, 2, 2, basis, |x| x);
            let m = pp.fragment_len();
            let witness = m * pp.fragments;
            let columns = 2 * m * (pp.fragments + 1);
            let mut rng = StdRng::seed_from_u64(9217);
            let data = (0..witness)
                .map(|_| F::random(&mut rng))
                .collect::<Vec<_>>();
            let mut prover = commit::<F, Sha256, _>(&pp, &data, &mut rng).unwrap();
            let mut verifier = VerifierSession::<F, Sha256>::new(&pp, prover.commitment());
            // Non-Boolean high coordinate ensures the allowed evaluation mixes both fragments.
            let points = [
                vec![F::from(2usize); pp.num_vars()],
                vec![F::from(3usize); pp.num_vars()],
            ];
            let mut traces = Vec::new();
            for point in &points {
                let (y, p) = prover
                    .open_at(&mut Transcript::new_direct(), point)
                    .unwrap();
                let trace = verifier
                    .verify_details(&mut Transcript::new_direct(), point, y, &p)
                    .unwrap();
                assert_eq!(
                    numerical_view(&pp, &prover.state.coefficients, point, &trace),
                    revealed(&p)
                );
                traces.push(trace);
            }
            let view = |c: &[Vec<F>]| {
                points
                    .iter()
                    .zip(&traces)
                    .flat_map(|(p, t)| numerical_view(&pp, c, p, t))
                    .collect::<Vec<_>>()
            };
            let zero = vec![vec![F::zero(); 2 * m]; pp.fragments + 1];
            let rows = view(&zero).len();
            let mut a = vec![vec![F::zero(); columns]; rows];
            for col in 0..columns {
                let mut c = zero.clone();
                let (fragment, k) = if col < witness {
                    (col / m, col % m)
                } else if col < 2 * witness {
                    ((col - witness) / m, m + (col - witness) % m)
                } else {
                    (pp.fragments, col - 2 * witness)
                };
                c[fragment][k] = F::one();
                for (row, value) in view(&c).into_iter().enumerate() {
                    a[row][col] = value;
                }
            }
            let mut allowed = Vec::new();
            for point in &points {
                let mut row = vec![F::zero(); columns];
                for j in 0..witness {
                    row[j] = point
                        .iter()
                        .enumerate()
                        .fold(F::one(), |v, (i, &x)| v * pp.basis.weights(x)[j >> i & 1]);
                }
                allowed.push(row);
            }
            let random_rank = rank(a.iter().map(|row| row[witness..].to_vec()).collect());
            let allowed_rank = rank(allowed.clone());
            let mut joined = a.clone();
            joined.extend(allowed);
            let full_rank = rank(joined.clone());
            assert_eq!(
                full_rank,
                random_rank + allowed_rank,
                "numerical disclosure exceeds public evaluations"
            );
            // Sending one individual fragment evaluation (as in the unmasked
            // protocol) must fail this audit despite the random high padding.
            let mut leak = vec![F::zero(); columns];
            for j in 0..m {
                leak[j] = points[1][..pp.fri.rounds() - 1]
                    .iter()
                    .enumerate()
                    .fold(F::one(), |v, (i, &x)| v * pp.basis.weights(x)[j >> i & 1]);
            }
            joined.push(leak);
            let negative_rank = rank(joined);
            assert!(negative_rank > full_rank);
            println!(
                "HB_MASK_RANK {{\"field\":\"{}\",\"basis\":\"{:?}\",\"openings\":2,\"m\":64,\"fragments\":2,\"rows\":{},\"random_rank\":{},\"allowed_rank\":{},\"full_rank\":{},\"negative_control_rank\":{}}}",
                std::any::type_name::<F>(),
                basis,
                rows,
                random_rank,
                allowed_rank,
                full_rank,
                negative_rank
            );
        }
    }
    #[test]
    fn babybear_masked_cumulative_disclosure_rank() {
        disclosure_audit::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_masked_cumulative_disclosure_rank() {
        disclosure_audit::<algebra::Goldilocks>();
    }
}
