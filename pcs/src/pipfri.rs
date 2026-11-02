//! Non-hiding ordinary PipFRI reference construction from refs/2025-1354.pdf.
//!
//! Protocol 2 fragments a scalar table; batch PolyFRIM checks the fragment
//! evaluations using public-point folds and rolling batch FRI. Same-location
//! fragment pairs share a Merkle leaf. This reference variant additionally
//! commits the random combined first oracle, authenticating its equality to the
//! packed fragments by independent queries. It does not implement Protocol 3
//! masking, virtual-oracle query reuse, packed matrix queries, or a concrete
//! security certificate. It is not selected by the default PBS prover.
/// Experimental padded/masked variant with virtual-oracle query reuse.
pub mod masked;
/// Versioned unmasked virtual-combination opening with shared authentication.
pub mod virtual_source;

use crate::{
    rolling_fri as fri,
    utils::{hash::Hash, merkle_tree::MerkleTree},
};
use algebra::{AbstractExtensionField, Field};
use helper::{FiatShamirTranscript, Transcript};
use serde::{Deserialize, Serialize};

/// Interpretation of the scalar input vector, with low variable first.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Basis {
    /// Multilinear monomial coefficients, with weights (1,x).
    Coefficients,
    /// Boolean evaluations, with weights (1-x,x), including x=0 or 1.
    BooleanEvaluations,
}
impl Basis {
    fn weights<F: Field>(self, x: F) -> [F; 2] {
        [
            if self == Self::Coefficients {
                F::one()
            } else {
                F::one() - x
            },
            x,
        ]
    }
}
/// Trusted fragment, code-domain, and consistency-query geometry.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F> {
    fri: fri::Parameters<F>,
    fragments: usize,
    basis: Basis,
}
impl<F: Field + Serialize> Parameters<F> {
    /// Each fragment has power-of-two length >=2; fragment count is a power
    /// of two. Both consistency and proximity use `queries` independent samples.
    /// No security level is inferred from these parameters.
    pub fn new(
        fragment_len: usize,
        fragments: usize,
        blowup: usize,
        queries: usize,
        root: F,
        basis: Basis,
    ) -> Result<Self, fri::Error> {
        if !fragments.is_power_of_two() || fragment_len.checked_mul(fragments).is_none() {
            return Err(fri::Error("fragment geometry"));
        }
        Ok(Self {
            fri: fri::Parameters::new(fragment_len, blowup, queries, root)?,
            fragments,
            basis,
        })
    }
    /// Use coefficient-wise base-field FFTs for an extension-field domain whose
    /// root is embedded from Base. This is a prover arithmetic optimization;
    /// parameter serialization and the protocol remain byte-compatible.
    pub fn with_base_field_encoder<Base: Field>(mut self) -> Result<Self, fri::Error>
    where
        F: AbstractExtensionField<Base>,
    {
        self.fri = self.fri.with_base_field_encoder::<Base>()?;
        Ok(self)
    }
    /// Scalar entries per fragment.
    pub fn fragment_len(&self) -> usize {
        1 << self.fri.rounds()
    }
    /// Length of the complete scalar table.
    pub fn table_len(&self) -> usize {
        self.fragment_len() * self.fragments
    }
    /// Number of scalar variables in an evaluation point.
    pub fn num_vars(&self) -> usize {
        self.table_len().ilog2() as usize
    }
    fn context<H: Hash>(&self) -> H::Output {
        fri::hash::<H, _>(&(
            b"HasteBoots scalar PipFRI parameters v1".as_slice(),
            self.fri.context::<H>(),
            self,
        ))
    }
}
/// Public packed-fragment Merkle commitment.
pub type Commitment<O> = fri::Commitment<O>;
/// Prover-only coefficient vectors, codewords and authentication tree.
pub struct State<F, H: Hash + Send + Sync> {
    context: H::Output,
    coefficients: Vec<Vec<F>>,
    values: Vec<Vec<F>>,
    tree: MerkleTree<H>,
}
impl<F, H: Hash + Send + Sync> State<F, H> {
    /// Extract the expected public commitment.
    pub fn commitment(&self) -> Commitment<H::Output> {
        Commitment {
            root: self.tree.root,
        }
    }
}
/// Authenticated +/- pair from every fragment in one Merkle leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FragmentPair<F, O> {
    /// Fragment-order positive/negative values.
    pub values: Vec<[F; 2]>,
    /// Packed leaf hash followed by sibling hashes.
    pub path: Vec<O>,
}
/// One public-point folding and initial-combination consistency query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyQuery<F, O> {
    /// Open the packed fragment tree.
    pub fragments: FragmentPair<F, O>,
    /// Open the random combined oracle and every public-point fold.
    pub ladder: Vec<fri::PairOpening<F, O>>,
}
/// Scalar evaluation certificate; excludes private state and trusted parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Common-low-point fragment evaluations, fixed before the batch challenge.
    pub fragment_evaluations: Vec<F>,
    /// Random combined original and public-point folded original roots.
    pub ladder: Vec<Commitment<O>>,
    /// Rolling low-degree certificate for the original ladder.
    pub low_degree: fri::Proof<F, O>,
    /// Independent public-fold and initial-combination checks.
    pub consistency: Vec<ConsistencyQuery<F, O>>,
}
/// Commit a scalar coefficient or Boolean-evaluation vector in fragment order.
pub fn commit<F, H>(pp: &Parameters<F>, data: &[F]) -> Result<State<F, H>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if data.len() != pp.table_len() {
        return Err(fri::Error("scalar table length"));
    }
    let coefficients: Vec<_> = data
        .chunks_exact(pp.fragment_len())
        .map(<[F]>::to_vec)
        .collect();
    let values: Vec<_> = coefficients.iter().map(|c| pp.fri.encode(c, 0)).collect();
    let hashes: Vec<_> = (0..pp.fri.encoded_len() / 2)
        .map(|i| packed_leaf::<F, H>(pp, i, &pairs(&values, i)))
        .collect();
    let mut tree = MerkleTree::new();
    tree.generate(&hashes);
    Ok(State {
        context: pp.context::<H>(),
        coefficients,
        values,
        tree,
    })
}
/// Prove the expected scalar evaluation. Caller binds the enclosing statement.
/// The commitment, full point and value are also framed by this protocol.
pub fn open<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    s: &State<F, H>,
    point: &[F],
    value: F,
) -> Result<Proof<F, H::Output>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let u = fragment_evaluations(pp, expected, s, point)?;
    if evaluate(&u, &point[pp.fri.rounds()..], pp.basis) != value {
        return Err(fri::Error("scalar claimed evaluation"));
    }
    open_claim(t, pp, expected, s, point, value, u)
}
/// Compute the evaluation from private state and prove it without evaluating
/// the fragment table twice. Verification still takes the expected public value.
pub fn open_at<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    s: &State<F, H>,
    point: &[F],
) -> Result<(F, Proof<F, H::Output>), fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let u = fragment_evaluations(pp, expected, s, point)?;
    let value = evaluate(&u, &point[pp.fri.rounds()..], pp.basis);
    Ok((value, open_claim(t, pp, expected, s, point, value, u)?))
}
fn fragment_evaluations<F, H>(
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    s: &State<F, H>,
    point: &[F],
) -> Result<Vec<F>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if s.context != pp.context::<H>()
        || expected.root != s.tree.root
        || point.len() != pp.num_vars()
    {
        return Err(fri::Error("scalar opening state or point"));
    }
    Ok(s.coefficients
        .iter()
        .map(|c| evaluate(c, &point[..pp.fri.rounds()], pp.basis))
        .collect())
}
fn open_claim<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    s: &State<F, H>,
    point: &[F],
    value: F,
    u: Vec<F>,
) -> Result<Proof<F, H::Output>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let gamma = bind::<F, H>(t, pp, expected, point, value, &u)?;
    let powers = powers(gamma, pp.fragments);
    let mut coefficients = vec![F::zero(); pp.fragment_len()];
    for (c, &w) in s.coefficients.iter().zip(&powers) {
        for (a, &b) in coefficients.iter_mut().zip(c) {
            *a += w * b;
        }
    }
    let mut ladder = Vec::with_capacity(pp.fri.rounds());
    for (i, &x) in point[..pp.fri.rounds()].iter().enumerate() {
        ladder.push(fri::commit_original::<F, H>(&pp.fri, i, &coefficients)?);
        coefficients = fold_coefficients(&coefficients, pp.basis.weights(x));
    }
    let roots: Vec<_> = ladder.iter().map(fri::State::commitment).collect();
    t.append_message(b"PipFRI public fold roots", &roots);
    let refs: Vec<_> = ladder.iter().collect();
    let low_degree = fri::prove(t, &pp.fri, &refs)?;
    let consistency = indices(t, pp)
        .into_iter()
        .map(|index| ConsistencyQuery {
            fragments: FragmentPair {
                values: pairs(&s.values, index / 2),
                path: s.tree.query(index / 2),
            },
            ladder: ladder
                .iter()
                .enumerate()
                .map(|(i, s)| fri::opening(s, (index >> i) / 2))
                .collect(),
        })
        .collect();
    Ok(Proof {
        fragment_evaluations: u,
        ladder: roots,
        low_degree,
        consistency,
    })
}
/// Verify from trusted parameters, an expected commitment and a scalar claim.
pub fn verify<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    point: &[F],
    value: F,
    proof: &Proof<F, H::Output>,
) -> Result<(), fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let gamma = bind::<F, H>(t, pp, expected, point, value, &proof.fragment_evaluations)?;
    if proof.ladder.len() != pp.fri.rounds()
        || proof.consistency.len() != pp.fri.queries()
        || proof
            .consistency
            .iter()
            .any(|q| q.ladder.len() != pp.fri.rounds())
    {
        return Err(fri::Error("scalar certificate dimensions"));
    }
    t.append_message(b"PipFRI public fold roots", &proof.ladder);
    fri::verify::<F, H>(t, &pp.fri, &proof.ladder, &proof.low_degree)?;
    let weights = powers(gamma, pp.fragments);
    let target = proof
        .fragment_evaluations
        .iter()
        .zip(&weights)
        .fold(F::zero(), |a, (&v, &w)| a + v * w);
    let half = F::one() / (F::one() + F::one());
    for (index, q) in indices(t, pp).into_iter().zip(&proof.consistency) {
        authenticate::<F, H>(pp, expected, &proof.ladder, index, q)?;
        let mut combined = [F::zero(); 2];
        for (pair, &w) in q.fragments.values.iter().zip(&weights) {
            for j in 0..2 {
                combined[j] += w * pair[j];
            }
        }
        if combined != q.ladder[0].values {
            return Err(fri::Error("fragment combination mismatch"));
        }
        for i in 0..pp.fri.rounds() {
            let [a, b] = q.ladder[i].values;
            let x = fri::point(pp.fri.shift(i), pp.fri.len(i), (index >> i) & !1);
            let [w0, w1] = pp.basis.weights(point[i]);
            let folded = w0 * (a + b) * half + w1 * (a - b) * half / x;
            let expected = if i + 1 == pp.fri.rounds() {
                target
            } else {
                q.ladder[i + 1].values[(index >> (i + 1)) & 1]
            };
            if folded != expected {
                return Err(fri::Error("public fold mismatch"));
            }
        }
    }
    Ok(())
}
fn bind<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    point: &[F],
    value: F,
    u: &[F],
) -> Result<F, fri::Error> {
    let low = pp.fri.rounds();
    if point.len() != pp.num_vars() || u.len() != pp.fragments {
        return Err(fri::Error("scalar claim dimensions"));
    }
    if evaluate(u, &point[low..], pp.basis) != value {
        return Err(fri::Error("fragment evaluation aggregation"));
    }
    t.append_message(
        b"HasteBoots ordinary PipFRI v1",
        &(pp.context::<H>(), expected, point, value, u),
    );
    Ok(t.get_challenge(b"PipFRI fragment batch"))
}
fn indices<F: Field + Serialize>(t: &mut Transcript<F>, pp: &Parameters<F>) -> Vec<usize> {
    t.get_index_challenges(
        b"PipFRI consistency domain index",
        pp.fri.encoded_len(),
        pp.fri.queries(),
    )
    .expect("trusted fragmented sampling geometry")
}
fn pairs<F: Field>(values: &[Vec<F>], i: usize) -> Vec<[F; 2]> {
    values.iter().map(|v| [v[2 * i], v[2 * i + 1]]).collect()
}
fn packed_leaf<F: Field + Serialize, H: Hash>(
    pp: &Parameters<F>,
    i: usize,
    pairs: &[[F; 2]],
) -> H::Output {
    fri::hash::<H, _>(&(b"PipFRI packed pair leaf v1", pp.context::<H>(), i, pairs))
}
fn authenticate<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    expected: &Commitment<H::Output>,
    roots: &[Commitment<H::Output>],
    index: usize,
    q: &ConsistencyQuery<F, H::Output>,
) -> Result<(), fri::Error> {
    let pair = index / 2;
    if q.fragments.values.len() != pp.fragments
        || q.fragments.path.len() != (pp.fri.encoded_len() / 2).ilog2() as usize + 1
    {
        return Err(fri::Error("fragment pair dimensions"));
    }
    if q.fragments.path[0] != packed_leaf::<F, H>(pp, pair, &q.fragments.values)
        || !MerkleTree::<H>::check(&expected.root, pair, &q.fragments.path)
    {
        return Err(fri::Error("fragment pair authentication"));
    }
    for (i, (root, opening)) in roots.iter().zip(&q.ladder).enumerate() {
        fri::check_pair::<F, H>(
            &pp.fri,
            fri::Role::Original,
            i,
            root,
            (index >> i) / 2,
            opening,
        )?;
    }
    Ok(())
}
fn fold_coefficients<F: Field>(c: &[F], [w0, w1]: [F; 2]) -> Vec<F> {
    c.chunks_exact(2).map(|p| w0 * p[0] + w1 * p[1]).collect()
}
fn evaluate<F: Field>(c: &[F], point: &[F], basis: Basis) -> F {
    let mut v = c.to_vec();
    for &x in point {
        v = fold_coefficients(&v, basis.weights(x));
    }
    v[0]
}
fn powers<F: Field>(gamma: F, n: usize) -> Vec<F> {
    let mut w = F::one();
    (0..n)
        .map(|_| {
            let out = w;
            w *= gamma;
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, transformation::AbstractNTT};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

    #[test]
    fn authentication_hash_counts_match_reference_and_virtual_modes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static OUTPUTS: AtomicUsize = AtomicUsize::new(0);
        #[derive(Clone, Debug, Default)]
        struct Counted(sha2::Sha512);
        impl Hash for Counted {
            type Output = crate::utils::hash::Digest512;
            fn update_hash_value(&mut self, input: &[u8]) {
                Hash::update_hash_value(&mut self.0, input);
            }
            fn output_reset(&mut self) -> Self::Output {
                OUTPUTS.fetch_add(1, Ordering::Relaxed);
                Hash::output_reset(&mut self.0)
            }
        }
        fn check<Base: NTTField, E: AbstractExtensionField<Base> + Serialize>() {
            let native = Base::generate_ntt_table(5).unwrap().root();
            for blowup in [2, 4, 8] {
                for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
                    let mut shift = native;
                    let mut domain = 4 * blowup;
                    while domain < 32 {
                        shift *= shift;
                        domain *= 2;
                    }
                    let root = E::from_base(shift);
                    let pp = Parameters::new(4, 4, blowup, 3, root, basis).unwrap();
                    let data: Vec<_> = (0..pp.table_len())
                        .map(|i| E::from_base_fn(|j| Base::from(17 * i + 29 * j + 1)))
                        .collect();
                    let point = vec![E::from_base(Base::from(7usize)); pp.num_vars()];
                    let value = tensor(&data, &point, basis);
                    let source = commit::<E, Counted>(&pp, &data).unwrap();
                    let expected = source.commitment();
                    let proof = open::<E, Counted>(
                        &mut Transcript::new_classical_extension::<Base>(&[77; 64]),
                        &pp,
                        &expected,
                        &source,
                        &point,
                        value,
                    )
                    .unwrap();
                    let (virtual_value, virtual_proof) = virtual_source::open_at::<E, Counted>(
                        &mut Transcript::new_classical_extension::<Base>(&[77; 64]),
                        &pp,
                        &expected,
                        &source,
                        &point,
                    )
                    .unwrap();
                    assert_eq!(virtual_value, value);
                    let paths: Vec<_> = (0..pp.fri.rounds())
                        .map(|i| pp.fri.len(i).ilog2() as usize)
                        .collect();
                    let mut transcript = Transcript::new_classical_extension::<Base>(&[77; 64]);
                    OUTPUTS.store(0, Ordering::Relaxed);
                    verify::<E, Counted>(&mut transcript, &pp, &expected, &point, value, &proof)
                        .unwrap();
                    // Authentication plus PipFRI binding (2) and rolling binding (1).
                    let ordinary_auth = 3
                        * (2 * paths.iter().sum::<usize>()
                            + paths[1..].iter().sum::<usize>()
                            + paths[0]
                            + 2
                            + pp.fri.rounds());
                    assert_eq!(OUTPUTS.load(Ordering::Relaxed), ordinary_auth + 3);
                    let mut transcript = Transcript::new_classical_extension::<Base>(&[77; 64]);
                    OUTPUTS.store(0, Ordering::Relaxed);
                    virtual_source::verify::<E, Counted>(
                        &mut transcript,
                        &pp,
                        &expected,
                        &point,
                        value,
                        &virtual_proof,
                    )
                    .unwrap();
                    // Binding (2), virtual identifier including its contexts (3), rolling (1).
                    let virtual_auth = 3 * (2 * paths[1..].iter().sum::<usize>() + paths[0] + 2);
                    assert_eq!(OUTPUTS.load(Ordering::Relaxed), virtual_auth + 6);
                }
            }
        }
        check::<algebra::BabyBear, algebra::BabyBearExtension6>();
        check::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    // Independent tensor contraction, rather than the prover's fold routine.
    fn tensor<F: Field>(data: &[F], point: &[F], basis: Basis) -> F {
        data.iter().enumerate().fold(F::zero(), |sum, (index, &a)| {
            let weight = point.iter().enumerate().fold(F::one(), |w, (j, &x)| {
                w * if index >> j & 1 == 1 {
                    x
                } else if basis == Basis::Coefficients {
                    F::one()
                } else {
                    F::one() - x
                }
            });
            sum + a * weight
        })
    }
    fn exercise<F: NTTField + Serialize + DeserializeOwned>() {
        let root = F::generate_ntt_table(6).unwrap().root();
        for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
            for (m, fragments) in [(2, 1), (4, 2), (8, 8), (16, 4)] {
                let pp = Parameters::new(m, fragments, 64 / m, 32, root, basis).unwrap();
                let data: Vec<_> = (0..pp.table_len())
                    .map(|i| F::from(i * i + 13 * i + 17))
                    .collect();
                let point: Vec<_> = (0..pp.num_vars())
                    .map(|i| F::from([0, 1, 2, 7, 11, 13][i % 6]))
                    .collect();
                let value = tensor(&data, &point, basis);
                let s = commit::<F, Sha256>(&pp, &data).unwrap();
                let expected = s.commitment();
                let mut prover = Transcript::new_direct();
                let proof = open(&mut prover, &pp, &expected, &s, &point, value).unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, used): (Proof<F, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut verifier = Transcript::new_direct();
                verify::<F, Sha256>(&mut verifier, &pp, &expected, &point, value, &proof).unwrap();
                assert_eq!(
                    prover.get_challenge(b"after"),
                    verifier.get_challenge(b"after")
                );
                assert!(
                    open(
                        &mut Transcript::new_direct(),
                        &pp,
                        &expected,
                        &s,
                        &point,
                        value + F::one()
                    )
                    .is_err()
                );
                let reject = |p: &Proof<F, [u8; 32]>| {
                    assert!(
                        verify::<F, Sha256>(
                            &mut Transcript::new_direct(),
                            &pp,
                            &expected,
                            &point,
                            value,
                            p
                        )
                        .is_err()
                    )
                };
                let mut bad = proof.clone();
                bad.fragment_evaluations[0] += F::one();
                reject(&bad);
                let mut bad = proof.clone();
                bad.consistency.pop();
                reject(&bad);
                let mut bad = proof.clone();
                bad.consistency[0].ladder.pop();
                reject(&bad);
                let mut bad = proof.clone();
                bad.consistency[0].fragments.values.pop();
                reject(&bad);
                let mut bad = proof.clone();
                bad.consistency[0].fragments.path.clear();
                reject(&bad);
                for i in 0..fragments {
                    for j in 0..2 {
                        let mut bad = proof.clone();
                        bad.consistency[0].fragments.values[i][j] += F::one();
                        reject(&bad);
                    }
                }
                for i in 0..pp.fri.rounds() {
                    let mut bad = proof.clone();
                    bad.ladder[i].root[0] ^= 1;
                    reject(&bad);
                    let mut bad = proof.clone();
                    bad.consistency[0].ladder[i].values[0] += F::one();
                    reject(&bad);
                    let mut bad = proof.clone();
                    bad.consistency[0].ladder[i].path.clear();
                    reject(&bad);
                }
                let mut wrong = point.clone();
                wrong[0] += F::one();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new_direct(),
                        &pp,
                        &expected,
                        &wrong,
                        value,
                        &proof
                    )
                    .is_err()
                );
                let mut wrong = expected.clone();
                wrong.root[0] ^= 1;
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new_direct(),
                        &pp,
                        &wrong,
                        &point,
                        value,
                        &proof
                    )
                    .is_err()
                );
                let changed = Parameters::new(m, fragments, 64 / m, 33, root, basis).unwrap();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new_direct(),
                        &changed,
                        &expected,
                        &point,
                        value,
                        &proof
                    )
                    .is_err()
                );
                assert!(
                    open(
                        &mut Transcript::new_direct(),
                        &changed,
                        &expected,
                        &s,
                        &point,
                        value
                    )
                    .is_err()
                );
            }
            // Complete fresh malicious evaluation certificate: every source,
            // public-fold and FRI tree/path is genuine under the false claim's
            // transcript. LDT accepts; the final public-factor equation fails.
            let pp = Parameters::new(8, 4, 8, 64, root, basis).unwrap();
            let data: Vec<_> = (0..pp.table_len()).map(|i| F::from(i + 3)).collect();
            let point: Vec<_> = (0..pp.num_vars()).map(|i| F::from(i + 2)).collect();
            let s = commit::<F, Sha256>(&pp, &data).unwrap();
            let expected = s.commitment();
            let mut u: Vec<_> = data
                .chunks_exact(8)
                .map(|c| tensor(c, &point[..3], basis))
                .collect();
            u[0] += F::one();
            let false_value = tensor(&u, &point[3..], basis);
            assert_ne!(false_value, tensor(&data, &point, basis));
            let mut prover = Transcript::new_direct();
            let proof =
                open_claim(&mut prover, &pp, &expected, &s, &point, false_value, u).unwrap();
            let mut replay = Transcript::new_direct();
            bind::<F, Sha256>(
                &mut replay,
                &pp,
                &expected,
                &point,
                false_value,
                &proof.fragment_evaluations,
            )
            .unwrap();
            replay.append_message(b"PipFRI public fold roots", &proof.ladder);
            fri::verify::<F, Sha256>(&mut replay, &pp.fri, &proof.ladder, &proof.low_degree)
                .unwrap();
            for (index, q) in indices(&mut replay, &pp)
                .into_iter()
                .zip(&proof.consistency)
            {
                authenticate::<F, Sha256>(&pp, &expected, &proof.ladder, index, q).unwrap();
            }
            assert_eq!(
                prover.get_challenge(b"after"),
                replay.get_challenge(b"after")
            );
            assert_eq!(
                verify::<F, Sha256>(
                    &mut Transcript::new_direct(),
                    &pp,
                    &expected,
                    &point,
                    false_value,
                    &proof
                )
                .unwrap_err()
                .0,
                "public fold mismatch"
            );
            // A fresh valid low-degree ladder and valid fixed folds for a
            // different polynomial, with genuine openings of the original
            // packed fragment tree. Only their combination equation is false.
            let mut alternate = commit::<F, Sha256>(&pp, &data).unwrap();
            alternate.coefficients[0][0] += F::one();
            let u: Vec<_> = alternate
                .coefficients
                .iter()
                .map(|c| tensor(c, &point[..3], basis))
                .collect();
            let false_value = tensor(&u, &point[3..], basis);
            let proof = open_claim(
                &mut Transcript::new_direct(),
                &pp,
                &expected,
                &alternate,
                &point,
                false_value,
                u,
            )
            .unwrap();
            let mut replay = Transcript::new_direct();
            bind::<F, Sha256>(
                &mut replay,
                &pp,
                &expected,
                &point,
                false_value,
                &proof.fragment_evaluations,
            )
            .unwrap();
            replay.append_message(b"PipFRI public fold roots", &proof.ladder);
            fri::verify::<F, Sha256>(&mut replay, &pp.fri, &proof.ladder, &proof.low_degree)
                .unwrap();
            for (index, q) in indices(&mut replay, &pp)
                .into_iter()
                .zip(&proof.consistency)
            {
                authenticate::<F, Sha256>(&pp, &expected, &proof.ladder, index, q).unwrap();
            }
            assert_eq!(
                verify::<F, Sha256>(
                    &mut Transcript::new_direct(),
                    &pp,
                    &expected,
                    &point,
                    false_value,
                    &proof
                )
                .unwrap_err()
                .0,
                "fragment combination mismatch"
            );
        }
        assert!(Parameters::new(8, 3, 8, 32, root, Basis::Coefficients).is_err());
        let pp = Parameters::new(8, 4, 8, 32, root, Basis::Coefficients).unwrap();
        assert!(commit::<F, Sha256>(&pp, &[]).is_err());
    }
    #[test]
    fn baby_bear() {
        exercise::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks() {
        exercise::<algebra::Goldilocks>();
    }
    fn exercise_extension<Base, EF>()
    where
        Base: NTTField,
        EF: algebra::AbstractExtensionField<Base> + Serialize + DeserializeOwned,
    {
        let root = EF::from_base(Base::generate_ntt_table(5).unwrap().root());
        let mut points = Transcript::<EF>::new_direct_extension::<Base>();
        for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
            let pp = Parameters::new(8, 4, 4, 64, root, basis).unwrap();
            let data: Vec<EF> = (0..32)
                .map(|i| EF::from_base_fn(|j| Base::from(i * i + 19 * j + 1)))
                .collect();
            let point = points.get_vec_challenge(b"extension PCS point", pp.num_vars());
            let value = tensor(&data, &point, basis);
            if basis == Basis::BooleanEvaluations {
                assert_eq!(
                    value,
                    algebra::DenseMultilinearExtension::from_evaluations_vec(
                        pp.num_vars(),
                        data.clone()
                    )
                    .evaluate(&point)
                );
            }
            let state = commit::<EF, Sha256>(&pp, &data).unwrap();
            let expected = state.commitment();
            let mut prover = Transcript::new_direct_extension::<Base>();
            let proof = open(&mut prover, &pp, &expected, &state, &point, value).unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<EF, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut verifier = Transcript::new_direct_extension::<Base>();
            verify::<EF, Sha256>(&mut verifier, &pp, &expected, &point, value, &proof).unwrap();
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
            let mut bad = proof.clone();
            bad.consistency[0].fragments.values[0][0] += EF::monomial(EF::D - 1);
            assert!(
                verify::<EF, Sha256>(
                    &mut Transcript::new_direct_extension::<Base>(),
                    &pp,
                    &expected,
                    &point,
                    value,
                    &bad
                )
                .is_err()
            );
            let mut u: Vec<_> = data
                .chunks_exact(8)
                .map(|c| tensor(c, &point[..3], basis))
                .collect();
            u[0] += EF::monomial(EF::D - 1);
            let false_value = tensor(&u, &point[3..], basis);
            assert_ne!(false_value, value);
            let proof = open_claim(
                &mut Transcript::new_direct_extension::<Base>(),
                &pp,
                &expected,
                &state,
                &point,
                false_value,
                u,
            )
            .unwrap();
            let mut replay = Transcript::new_direct_extension::<Base>();
            bind::<EF, Sha256>(
                &mut replay,
                &pp,
                &expected,
                &point,
                false_value,
                &proof.fragment_evaluations,
            )
            .unwrap();
            replay.append_message(b"PipFRI public fold roots", &proof.ladder);
            fri::verify::<EF, Sha256>(&mut replay, &pp.fri, &proof.ladder, &proof.low_degree)
                .unwrap();
            for (index, q) in indices(&mut replay, &pp)
                .into_iter()
                .zip(&proof.consistency)
            {
                authenticate::<EF, Sha256>(&pp, &expected, &proof.ladder, index, q).unwrap();
            }
            assert_eq!(
                verify::<EF, Sha256>(
                    &mut Transcript::new_direct_extension::<Base>(),
                    &pp,
                    &expected,
                    &point,
                    false_value,
                    &proof
                )
                .unwrap_err()
                .0,
                "public fold mismatch"
            );
        }
    }
    #[test]
    fn baby_bear_extension() {
        exercise_extension::<algebra::BabyBear, algebra::BabyBearExetension>();
    }
    #[test]
    fn goldilocks_extension() {
        exercise_extension::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    }
}
