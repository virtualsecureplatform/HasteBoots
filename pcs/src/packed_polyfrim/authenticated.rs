//! Authenticated consistency ladder for ordered matrix folds.
//!
//! This proves sampled transitions only. It is not an evaluation-binding PCS:
//! a separately composed proximity proof is required for every oracle lane.
use super::{Polynomial, fold_symbol};
/// Experimental private padding and bounded-reuse masking.
pub mod masked;
/// Same-root rolling proximity checks composed with matrix consistency.
pub mod proximity;
use crate::{
    rolling_fri,
    utils::{hash::Hash, merkle_tree::MerkleTree},
};
use algebra::{AbstractExtensionField, Field, matrix_weighted::MatrixPair};
use helper::{FiatShamirTranscript, Transcript};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Invalid shape, mismatched state or rejected consistency certificate.
#[derive(Debug, thiserror::Error)]
#[error("packed PolyFRIM consistency: {0}")]
pub struct Error(pub &'static str);

/// Trusted vector-polynomial degree, domain and sampling geometry.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F> {
    message: usize,
    width: usize,
    blowup: usize,
    queries: usize,
    root: F,
    // Arithmetic choice only: canonical codewords and protocol parameters agree.
    #[serde(skip)]
    encoder: fn(&[F], usize, F) -> Vec<F>,
    #[serde(skip)]
    parallel_oracles: bool,
    #[serde(skip)]
    folder: fn(
        &Polynomial<F>,
        &MatrixPair<F>,
    ) -> Result<Polynomial<F>, algebra::matrix_weighted::ShapeError>,
}
impl<F: Field + Serialize> Parameters<F> {
    /// Require power-of-two message >=2, blowup >=2, nonzero width/query count
    /// and an exact-order 2*message*blowup root. No security level is inferred.
    pub fn new(
        message: usize,
        width: usize,
        blowup: usize,
        queries: usize,
        root: F,
    ) -> Result<Self, Error> {
        let root = root.canonicalized();
        rolling_fri::Parameters::new(message, blowup, queries, root)
            .map_err(|_| Error("degree, domain or sampling geometry"))?;
        if width == 0
            || message
                .checked_mul(blowup)
                .and_then(|n| n.checked_mul(width))
                .is_none()
        {
            return Err(Error("lane count or encoded size"));
        }
        Ok(Self {
            message,
            width,
            blowup,
            queries,
            root,
            encoder: rolling_fri::encode::<F>,
            folder: Polynomial::<F>::fold,
            parallel_oracles: false,
        })
    }
    /// Use coordinate-wise base FFTs on a base-field coset. This changes no
    /// serialized parameter, canonical codeword, commitment or proof bytes.
    pub fn with_base_field_encoder<Base: Field>(mut self) -> Result<Self, Error>
    where
        F: AbstractExtensionField<Base>,
    {
        let base = self
            .root
            .as_base_slice()
            .first()
            .copied()
            .unwrap_or_else(Base::zero);
        if F::from_base(base) != self.root {
            return Err(Error("encoding root is outside requested base field"));
        }
        self.encoder = rolling_fri::encode_extension::<Base, F>;
        Ok(self)
    }
    /// Fold embedded base coefficients and matrix entries in Base arithmetic.
    /// Non-base inputs use the original full-field fold. This changes no
    /// parameter serialization, committed value, verifier equation or transcript.
    pub fn with_base_field_folds<Base: Field>(mut self) -> Self
    where
        F: AbstractExtensionField<Base>,
    {
        self.folder = Polynomial::<F>::fold_base::<Base>;
        self
    }
    /// Encode independent lanes and hash leaves in parallel on large oracles.
    /// Additional lane buffers trade temporary memory for concurrency. Default
    /// callers retain the original sequential schedule and identical wire data.
    pub fn with_parallel_oracles(mut self) -> Self {
        self.parallel_oracles = true;
        self
    }
    fn rounds(&self) -> usize {
        self.message.ilog2() as usize
    }

    /// Trusted rounds, lane width, encoded-domain logarithm and sample count.
    pub(crate) fn proof_geometry(&self) -> (usize, usize, usize, usize) {
        (self.rounds(), self.width, self.len(0).ilog2() as usize, self.queries)
    }
    fn len(&self, layer: usize) -> usize {
        self.message * self.blowup >> layer
    }
    fn shift(&self, layer: usize) -> F {
        power(self.root, 1usize << layer)
    }
    fn query(&self, query: &[MatrixPair<F>], claim: &[F]) -> Result<(), Error> {
        if query.len() != self.rounds() || claim.len() != self.width {
            return Err(Error("query or claim shape"));
        }
        for pair in query {
            pair.validate(self.width)
                .map_err(|_| Error("matrix shape"))?;
        }
        Ok(())
    }
}

/// Prover-only source polynomial and packed oracle. Never serialized as a proof.
pub struct State<F, H: Hash + Send + Sync> {
    polynomial: Polynomial<F>,
    values: OnceLock<Vec<F>>,
    encoding: Parameters<F>,
    tree: MerkleTree<H>,
    context: H::Output,
    layer: usize,
}
impl<F, H: Hash + Send + Sync> State<F, H> {
    /// Number of encoded field elements currently retained in the source cache.
    pub fn cached_codeword_elements(&self) -> usize {
        self.values.get().map_or(0, Vec::len)
    }
    fn evict_values(&mut self) {
        self.values.take();
    }
    /// Extract the expected public root, without private oracle values.
    pub fn root(&self) -> H::Output {
        self.tree.root
    }
}

impl<F: Field + Serialize, H: Hash + Send + Sync> State<F, H> {
    fn values(&self) -> &[F] {
        self.values
            .get_or_init(|| encode_values(&self.encoding, self.layer, &self.polynomial))
    }
}

/// Authenticate all lanes at a domain pair in one Merkle leaf.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pair<F, O> {
    /// P(beta), then P(-beta), each in original lane order.
    pub values: Vec<F>,
    /// Leaf hash followed by sibling hashes.
    pub path: Vec<O>,
}
/// Sampled consistency certificate, with no low-degree/proximity assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Intermediate layer roots, in increasing layer order; source is external.
    pub roots: Vec<O>,
    /// One pair per layer per sample; repeated samples are retained.
    pub queries: Vec<Vec<Pair<F, O>>>,
}

/// Commit all source lanes on the trusted initial coset, in bit-reversed order.
pub fn commit<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    polynomial: Polynomial<F>,
) -> Result<State<F, H>, Error> {
    if polynomial.len() != pp.message || polynomial.width != pp.width {
        return Err(Error("source polynomial shape"));
    }
    Ok(state(pp, 0, polynomial))
}
fn state<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    layer: usize,
    polynomial: Polynomial<F>,
) -> State<F, H> {
    let values = encode_values(pp, layer, &polynomial);
    let mut tree = MerkleTree::<H>::new();
    let leaves: Vec<_> = if pp.parallel_oracles && values.len() >= 1 << 15 {
        values
            .par_chunks_exact(2 * pp.width)
            .enumerate()
            .map(|(i, v)| leaf::<F, H>(pp, layer, i, v))
            .collect()
    } else {
        values
            .chunks_exact(2 * pp.width)
            .enumerate()
            .map(|(i, v)| leaf::<F, H>(pp, layer, i, v))
            .collect()
    };
    tree.generate(&leaves);
    State {
        polynomial,
        values: OnceLock::from(values),
        encoding: pp.clone(),
        tree,
        context: hash::<H, _>(&(b"packed PolyFRIM parameters v2", pp)),
        layer,
    }
}

fn encode_values<F: Field + Serialize>(
    pp: &Parameters<F>,
    layer: usize,
    polynomial: &Polynomial<F>,
) -> Vec<F> {
    let n = pp.len(layer);
    if !pp.parallel_oracles || pp.width == 1 || n * pp.width < 1 << 15 {
        return encode_values_sequential(pp, layer, polynomial);
    }
    // Each lane uses the identical independent FFT. The indexed collection and
    // tiled transpose preserve lane order and avoid shared output writes.
    let columns: Vec<Vec<F>> = (0..pp.width)
        .into_par_iter()
        .map(|lane| {
            let coefficients: Vec<_> = polynomial
                .coefficients
                .chunks_exact(pp.width)
                .map(|v| v[lane])
                .collect();
            (pp.encoder)(&coefficients, n, pp.shift(layer))
        })
        .collect();
    let mut values = vec![F::zero(); n * pp.width];
    values
        .par_chunks_exact_mut(pp.width)
        .enumerate()
        .for_each(|(i, cell)| {
            for (lane, value) in cell.iter_mut().enumerate() {
                *value = columns[lane][i].canonicalized();
            }
        });
    values
}
fn encode_values_sequential<F: Field + Serialize>(
    pp: &Parameters<F>,
    layer: usize,
    polynomial: &Polynomial<F>,
) -> Vec<F> {
    let n = pp.len(layer);
    let mut values = vec![F::zero(); n * pp.width];
    for lane in 0..pp.width {
        let coefficients: Vec<F> = polynomial
            .coefficients
            .chunks_exact(pp.width)
            .map(|v| v[lane])
            .collect();
        let encoded = (pp.encoder)(&coefficients, n, pp.shift(layer));
        for (i, v) in encoded.into_iter().enumerate() {
            values[i * pp.width + lane] = v;
        }
    }
    for value in &mut values {
        *value = value.canonicalized();
    }
    values
}

/// Prove sampled public-matrix transitions against a retained source root.
/// Reject an incorrect honest claim before changing the caller's transcript.
pub fn prove<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &State<F, H>,
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Result<Proof<F, H::Output>, Error> {
    let layers = ladder(pp, source, query, claim)?;
    let states: Vec<_> = std::iter::once(source).chain(layers.iter()).collect();
    Ok(certificate(t, pp, &states, query, claim))
}
fn ladder<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    source: &State<F, H>,
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Result<Vec<State<F, H>>, Error> {
    pp.query(query, claim)?;
    if source.layer != 0 || source.context != hash::<H, _>(&(b"packed PolyFRIM parameters v2", pp))
    {
        return Err(Error("source parameter context"));
    }
    let mut layers = Vec::new();
    let mut polynomial =
        (pp.folder)(&source.polynomial, &query[0]).map_err(|_| Error("source fold"))?;
    for layer in 1..pp.rounds() {
        let next =
            (pp.folder)(&polynomial, &query[layer]).map_err(|_| Error("intermediate fold"))?;
        layers.push(state::<F, H>(pp, layer, polynomial));
        polynomial = next;
    }
    if polynomial.evaluate(F::zero()) != claim {
        return Err(Error("false terminal claim"));
    }
    Ok(layers)
}

fn certificate<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    states: &[&State<F, H>],
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Proof<F, H::Output> {
    certificate_traced(t, pp, states, query, claim, false).0
}
fn certificate_traced<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    states: &[&State<F, H>],
    query: &[MatrixPair<F>],
    claim: &[F],
    virtual_source: bool,
) -> (Proof<F, H::Output>, Vec<usize>) {
    if virtual_source {
        t.append_message(b"packed PolyFRIM virtual source v2", &());
    }
    let roots: Vec<_> = states[1..].iter().map(|s| s.root()).collect();
    bind(t, pp, &states[0].root(), &roots, query, claim);
    let indices = sample_indices(t, pp);
    let queries = indices
        .iter()
        .copied()
        .map(|index| {
            states
                .iter()
                .enumerate()
                .map(|(layer, state)| {
                    let pair = (index >> layer) / 2;
                    Pair {
                        values: state.values()[pair * 2 * pp.width..(pair + 1) * 2 * pp.width]
                            .to_vec(),
                        path: if virtual_source && layer == 0 {
                            vec![]
                        } else {
                            state.tree.query(pair)
                        },
                    }
                })
                .collect()
        })
        .collect();
    (Proof { roots, queries }, indices)
}

/// Verify authentication and every sampled matrix transition, including the
/// terminal vector. Success alone supplies no low-degree or hiding guarantee.
pub fn verify<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    query: &[MatrixPair<F>],
    claim: &[F],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error> {
    verify_source::<F, H, _>(t, pp, source, query, claim, proof, false, |_, _| {
        Err(Error("unexpected virtual source"))
    })
}
fn verify_source<F: Field + Serialize, H: Hash + Send + Sync, V>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    query: &[MatrixPair<F>],
    claim: &[F],
    proof: &Proof<F, H::Output>,
    virtual_source: bool,
    mut authenticate: V,
) -> Result<(), Error>
where
    V: FnMut(usize, &Pair<F, H::Output>) -> Result<(), Error>,
{
    pp.query(query, claim)?;
    if proof.roots.len() != pp.rounds() - 1
        || proof.queries.len() != pp.queries
        || proof.queries.iter().any(|q| q.len() != pp.rounds())
    {
        return Err(Error("certificate shape"));
    }
    if proof
        .queries
        .iter()
        .flatten()
        .any(|p| p.values.iter().any(|v| !v.is_canonical()))
    {
        return Err(Error("noncanonical packed field encoding"));
    }
    if virtual_source {
        t.append_message(b"packed PolyFRIM virtual source v2", &());
    }
    bind(t, pp, source, &proof.roots, query, claim);
    // Complete the no-prover-message sampling phase before processing any
    // openings or invoking virtual-source authentication. This matches the
    // prover's order and preserves the accepted transcript byte for byte.
    let indices = sample_indices(t, pp);
    for (index, openings) in indices.into_iter().zip(&proof.queries) {
        for (layer, pair) in openings.iter().enumerate() {
            let position = (index >> layer) / 2;
            let depth = (pp.len(layer) / 2).ilog2() as usize;
            let root = if layer == 0 {
                source
            } else {
                &proof.roots[layer - 1]
            };
            if virtual_source && layer == 0 {
                if pair.values.len() != 2 * pp.width || !pair.path.is_empty() {
                    return Err(Error("virtual source shape"));
                }
                authenticate(index, pair)?;
            } else if pair.values.len() != 2 * pp.width
                || pair.path.len() != depth + 1
                || pair.path[0] != leaf::<F, H>(pp, layer, position, &pair.values)
                || !MerkleTree::<H>::check(root, position, &pair.path)
            {
                return Err(Error("pair authentication"));
            }
        }
        for layer in 0..pp.rounds() {
            let pair = &openings[layer];
            let even = (index >> layer) & !1;
            let n = pp.len(layer);
            let exponent = 2 * (even.reverse_bits() >> (usize::BITS - n.ilog2())) + 1;
            let beta = power(pp.shift(layer), exponent);
            let folded = fold_symbol(
                &query[layer],
                beta,
                &pair.values[..pp.width],
                &pair.values[pp.width..],
            )
            .map_err(|_| Error("public fold"))?;
            let expected = if layer + 1 == pp.rounds() {
                claim
            } else {
                let offset = ((index >> (layer + 1)) & 1) * pp.width;
                &openings[layer + 1].values[offset..offset + pp.width]
            };
            if folded != expected {
                return Err(Error("matrix transition"));
            }
        }
    }
    Ok(())
}
fn bind<F: Field + Serialize, O: Serialize>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &O,
    roots: &[O],
    query: &[MatrixPair<F>],
    claim: &[F],
) {
    t.append_message(
        b"packed PolyFRIM consistency v2",
        &(pp, source, roots, query, claim),
    );
}
#[cfg(test)]
fn sample<F: Field>(t: &mut Transcript<F>, n: usize) -> usize {
    let mut bytes = [0u8; 8];
    t.get_challenge_bytes(b"packed PolyFRIM domain index v2", &mut bytes);
    (u64::from_le_bytes(bytes) & (n as u64 - 1)) as usize
}
fn sample_indices<F: Field + Serialize>(t: &mut Transcript<F>, pp: &Parameters<F>) -> Vec<usize> {
    t.get_index_challenges(b"packed PolyFRIM domain index v2", pp.len(0), pp.queries)
        .expect("trusted consistency sampling geometry")
}
fn hash<H: Hash, T: Serialize>(value: &T) -> H::Output {
    let mut h = H::new();
    h.update_hash_value(
        &bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("serializable public context"),
    );
    h.output_reset()
}
fn leaf<F: Field + Serialize, H: Hash>(
    pp: &Parameters<F>,
    layer: usize,
    index: usize,
    values: &[F],
) -> H::Output {
    hash::<H, _>(&(b"packed PolyFRIM pair leaf v2", pp, layer, index, values))
}
fn power<F: Field>(mut b: F, mut n: usize) -> F {
    let mut out = F::one();
    while n > 0 {
        if n & 1 != 0 {
            out *= b;
        }
        b *= b;
        n >>= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        NTTField,
        matrix_weighted::{Matrix, PackedTable},
        transformation::AbstractNTT,
    };
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

    fn exercise<F: NTTField + Serialize + DeserializeOwned>() {
        for variables in 1..=4 {
            for width in [1, 2, 4, 8] {
                let message = 1usize << variables;
                let root = power(F::generate_ntt_table(6).unwrap().root(), 64 / (message * 4));
                let pp = Parameters::new(message, width, 4, 12, root).unwrap();
                let table = PackedTable::new(
                    variables,
                    width,
                    (0..message * width).map(|i| F::from(i * i + 9)).collect(),
                )
                .unwrap();
                let query: Vec<_> = (0..variables)
                    .map(|i| MatrixPair {
                        zero: Matrix::new(
                            width,
                            (0..width * width).map(|j| F::from(i + j * j + 1)).collect(),
                        )
                        .unwrap(),
                        one: Matrix::new(
                            width,
                            (0..width * width)
                                .map(|j| F::from(3 * i + 2 * j + 5))
                                .collect(),
                        )
                        .unwrap(),
                    })
                    .collect();
                let claim = table.evaluate(&query).unwrap();
                let source =
                    commit::<F, Sha256>(&pp, Polynomial::from_table(&table).unwrap()).unwrap();
                // Independent Horner checks pin packed FFT lane and pair order.
                for index in 0..pp.len(0) {
                    let rev = index.reverse_bits() >> (usize::BITS - pp.len(0).ilog2());
                    let beta = power(root, 2 * rev + 1);
                    assert_eq!(
                        source.polynomial.evaluate(beta),
                        source.values()[index * width..(index + 1) * width]
                    );
                }
                let mut prover = Transcript::new();
                let proof = prove(&mut prover, &pp, &source, &query, &claim).unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (decoded, used): (Proof<F, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut verifier = Transcript::new();
                verify::<F, Sha256>(&mut verifier, &pp, &source.root(), &query, &claim, &decoded)
                    .unwrap();
                assert_eq!(
                    prover.get_challenge(b"after"),
                    verifier.get_challenge(b"after")
                );
                let mut complete_prover = Transcript::new();
                let complete = proximity::prove::<F, Sha256>(
                    &mut complete_prover,
                    &pp,
                    &source,
                    &query,
                    &claim,
                )
                .unwrap();
                let bytes =
                    bincode::serde::encode_to_vec(&complete, bincode::config::standard()).unwrap();
                let (complete, used): (proximity::Proof<F, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                let mut complete_verifier = Transcript::new();
                proximity::verify::<F, Sha256>(
                    &mut complete_verifier,
                    &pp,
                    &source.root(),
                    &query,
                    &claim,
                    &complete,
                )
                .unwrap();
                assert_eq!(
                    complete_prover.get_challenge(b"after complete"),
                    complete_verifier.get_challenge(b"after complete")
                );
                let mut changed = complete.clone();
                changed.packed[0][0].values[0] += F::one();
                assert!(
                    proximity::verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &source.root(),
                        &query,
                        &claim,
                        &changed
                    )
                    .is_err()
                );
                let mut changed = complete.clone();
                changed.proximity.queries[0].originals[0].path.push([0; 32]);
                assert!(
                    proximity::verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &source.root(),
                        &query,
                        &claim,
                        &changed
                    )
                    .is_err()
                );
                let mut bad = decoded.clone();
                bad.queries[0][0].path.clear();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &source.root(),
                        &query,
                        &claim,
                        &bad
                    )
                    .is_err()
                );
                let mut bad = decoded.clone();
                bad.queries[0][0].values[0] += F::one();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &source.root(),
                        &query,
                        &claim,
                        &bad
                    )
                    .is_err()
                );
                let mut bad = decoded.clone();
                bad.queries[0].pop();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &source.root(),
                        &query,
                        &claim,
                        &bad
                    )
                    .is_err()
                );
                let mut wrong = claim.clone();
                wrong[0] += F::one();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &source.root(),
                        &query,
                        &wrong,
                        &decoded
                    )
                    .is_err()
                );
                let mut unchanged = Transcript::<F>::new();
                let mut attempted = Transcript::new();
                assert!(prove::<F, Sha256>(&mut attempted, &pp, &source, &query, &wrong).is_err());
                assert_eq!(
                    unchanged.get_challenge(b"after"),
                    attempted.get_challenge(b"after")
                );
            }
        }
    }
    #[test]
    fn babybear_authenticated_ladders() {
        exercise::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_authenticated_ladders() {
        exercise::<algebra::Goldilocks>();
    }

    fn false_transition<F: NTTField + Serialize>() {
        for variables in [1, 3] {
            let width = 2;
            let message = 1usize << variables;
            let root = power(F::generate_ntt_table(6).unwrap().root(), 64 / (message * 4));
            let pp = Parameters::new(message, width, 4, 16, root).unwrap();
            let table = PackedTable::new(
                variables,
                width,
                (0..message * width).map(|i| F::from(i + 2)).collect(),
            )
            .unwrap();
            let query = vec![
                MatrixPair {
                    zero: Matrix::identity(width).unwrap(),
                    one: Matrix::new(width, vec![F::zero(); width * width]).unwrap()
                };
                variables
            ];
            let source = commit::<F, Sha256>(&pp, Polynomial::from_table(&table).unwrap()).unwrap();
            let mut claim = table.evaluate(&query).unwrap();
            claim[0] += F::one();
            let mut layers = Vec::new();
            let mut polynomial = source.polynomial.fold(&query[0]).unwrap();
            polynomial.coefficients[0] += F::one();
            for layer in 1..variables {
                let next = polynomial.fold(&query[layer]).unwrap();
                layers.push(state::<F, Sha256>(&pp, layer, polynomial));
                polynomial = next;
            }
            assert_eq!(polynomial.evaluate(F::zero()), claim);
            let states: Vec<_> = std::iter::once(&source).chain(layers.iter()).collect();
            // Fresh roots, paths and transcript under the false claim.
            let proof = certificate(&mut Transcript::new(), &pp, &states, &query, &claim);
            let mut replay = Transcript::new();
            bind(
                &mut replay,
                &pp,
                &source.root(),
                &proof.roots,
                &query,
                &claim,
            );
            for openings in &proof.queries {
                let index = sample(&mut replay, pp.len(0));
                for (layer, pair) in openings.iter().enumerate() {
                    let position = (index >> layer) / 2;
                    assert_eq!(
                        pair.path[0],
                        leaf::<F, Sha256>(&pp, layer, position, &pair.values)
                    );
                    assert!(MerkleTree::<Sha256>::check(
                        &states[layer].root(),
                        position,
                        &pair.path
                    ));
                }
            }
            let error = verify::<F, Sha256>(
                &mut Transcript::new(),
                &pp,
                &source.root(),
                &query,
                &claim,
                &proof,
            )
            .unwrap_err();
            assert_eq!(error.0, "matrix transition");
        }
    }
    #[test]
    fn babybear_fresh_false_transitions_with_valid_paths() {
        false_transition::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_fresh_false_transitions_with_valid_paths() {
        false_transition::<algebra::Goldilocks>();
    }
}

#[cfg(test)]
mod base_fold_tests {
    use super::*;
    use algebra::{
        NTTField,
        matrix_weighted::{Matrix, PackedTable},
        transformation::AbstractNTT,
    };
    use sha2::Sha256;

    fn reference<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize,
    {
        for width in [1, 2, 4, 8] {
            let reference = Parameters::new(
                16,
                width,
                2,
                8,
                E::from_base(B::generate_ntt_table(5).unwrap().root()),
            )
            .unwrap()
            .with_base_field_encoder::<B>()
            .unwrap();
            let optimized = reference.clone().with_base_field_folds::<B>();
            assert_eq!(
                bincode::serde::encode_to_vec(&reference, bincode::config::standard()).unwrap(),
                bincode::serde::encode_to_vec(&optimized, bincode::config::standard()).unwrap()
            );
            for mode in 0..4 {
                let scalar = |i: usize, nonbase: bool| {
                    E::from_base_fn(|j| {
                        if j == 0 || nonbase {
                            B::from(i * 17 + j * 31 + 1)
                        } else {
                            B::zero()
                        }
                    })
                    .canonicalized()
                };
                let table = PackedTable::new(
                    4,
                    width,
                    (0..16 * width).map(|i| scalar(i, mode & 2 != 0)).collect(),
                )
                .unwrap();
                let source =
                    commit::<E, Sha256>(&reference, Polynomial::from_table(&table).unwrap())
                        .unwrap();
                let queries: Vec<Vec<_>> = (0..16)
                    .map(|member| {
                        (0..4)
                            .map(|round| MatrixPair {
                                zero: Matrix::new(
                                    width,
                                    (0..width * width)
                                        .map(|i| scalar(13 * member + round + i, mode & 1 != 0))
                                        .collect(),
                                )
                                .unwrap(),
                                one: Matrix::new(
                                    width,
                                    (0..width * width)
                                        .map(|i| {
                                            scalar(
                                                7 * member + 3 * round + 2 * i + 5,
                                                mode & 1 != 0,
                                            )
                                        })
                                        .collect(),
                                )
                                .unwrap(),
                            })
                            .collect()
                    })
                    .collect();
                // Independent direct three-product algebra remains the verifier
                // reference; canonical committed words must be byte-identical.
                let generic = source.polynomial.fold(&queries[0][0]).unwrap();
                let fast = source.polynomial.fold_base::<B>(&queries[0][0]).unwrap();
                assert_eq!(generic.coefficients, fast.coefficients);
                for count in [1, 4, 16] {
                    let claims: Vec<_> = queries[..count]
                        .iter()
                        .map(|q| {
                            table
                                .evaluate(q)
                                .unwrap()
                                .into_iter()
                                .map(Field::canonicalized)
                                .collect()
                        })
                        .collect();
                    let mut a = Transcript::<E>::new_direct_extension::<B>();
                    let mut b = Transcript::<E>::new_direct_extension::<B>();
                    let before = proximity::batch::prove::<E, Sha256>(
                        &mut a,
                        &reference,
                        &source,
                        &queries[..count],
                        &claims,
                    )
                    .unwrap();
                    let after = proximity::batch::prove::<E, Sha256>(
                        &mut b,
                        &optimized,
                        &source,
                        &queries[..count],
                        &claims,
                    )
                    .unwrap();
                    assert_eq!(
                        bincode::serde::encode_to_vec(&before, bincode::config::standard())
                            .unwrap(),
                        bincode::serde::encode_to_vec(&after, bincode::config::standard()).unwrap()
                    );
                    let mut v = Transcript::<E>::new_direct_extension::<B>();
                    proximity::batch::verify::<E, Sha256>(
                        &mut v,
                        &optimized,
                        &source.root(),
                        &queries[..count],
                        &claims,
                        &after,
                    )
                    .unwrap();
                    let mut x = [0; 32];
                    let mut y = [0; 32];
                    let mut z = [0; 32];
                    a.get_challenge_bytes(b"base fold reference after", &mut x);
                    b.get_challenge_bytes(b"base fold reference after", &mut y);
                    v.get_challenge_bytes(b"base fold reference after", &mut z);
                    assert_eq!(x, y);
                    assert_eq!(x, z);
                }
            }
        }
    }
    #[test]
    fn babybear_base_folds_preserve_full_packets_and_fallback() {
        reference::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_base_folds_preserve_full_packets_and_fallback() {
        reference::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    fn profile<B, E>()
    where
        B: NTTField,
        E: AbstractExtensionField<B>,
    {
        let width = 8;
        let table = PackedTable::new(
            15,
            width,
            (0..(1 << 15) * width)
                .map(|i| E::from_base(B::from(17 * i + 1)))
                .collect(),
        )
        .unwrap();
        let source = Polynomial::from_table(&table).unwrap();
        let query = MatrixPair {
            zero: Matrix::new(
                width,
                (0..width * width)
                    .map(|i| E::from_base(B::from(13 * i + 1)))
                    .collect(),
            )
            .unwrap(),
            one: Matrix::new(
                width,
                (0..width * width)
                    .map(|i| E::from_base(B::from(7 * i + 3)))
                    .collect(),
            )
            .unwrap(),
        };
        for order in [false, true] {
            for fast in if order { [true, false] } else { [false, true] } {
                let start = std::time::Instant::now();
                let folded = if fast {
                    source.fold_base::<B>(&query)
                } else {
                    source.fold(&query)
                }
                .unwrap();
                let elapsed = start.elapsed().as_secs_f64();
                assert_eq!(
                    folded.coefficients,
                    source.fold(&query).unwrap().coefficients
                );
                println!(
                    "HB_BASE_FOLD_KERNEL {{\"field\":\"{}\",\"fast\":{},\"order\":{},\"seconds\":{},\"variables\":15,\"width\":8,\"whole_pbs\":false}}",
                    std::any::type_name::<E>(),
                    fast,
                    order,
                    elapsed
                );
            }
        }
    }
    #[test]
    #[ignore = "manual fold arithmetic microbenchmark"]
    fn base_fold_kernel_profile() {
        profile::<algebra::BabyBear, algebra::BabyBearExtension6>();
        profile::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}

#[cfg(test)]
mod parallel_word_tests {
    use super::*;
    use algebra::{NTTField, matrix_weighted::PackedTable, transformation::AbstractNTT};
    use sha2::Sha256;
    fn compare<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize,
    {
        for width in [1, 2, 4, 8] {
            for dense in [false, true] {
                let pp = Parameters::new(
                    4096,
                    width,
                    2,
                    8,
                    E::from_base(B::generate_ntt_table(13).unwrap().root()),
                )
                .unwrap()
                .with_base_field_encoder::<B>()
                .unwrap()
                .with_parallel_oracles();
                let table = PackedTable::new(
                    12,
                    width,
                    (0..4096 * width)
                        .map(|i| {
                            E::from_base_fn(|j| {
                                if j == 0 || dense {
                                    B::from(17 * i + 31 * j + 1)
                                } else {
                                    B::zero()
                                }
                            })
                        })
                        .collect(),
                )
                .unwrap();
                let polynomial = Polynomial::from_table(&table).unwrap();
                let sequential = encode_values_sequential(&pp, 0, &polynomial);
                let parallel = encode_values(&pp, 0, &polynomial);
                assert_eq!(
                    bincode::serde::encode_to_vec(&sequential, bincode::config::standard())
                        .unwrap(),
                    bincode::serde::encode_to_vec(&parallel, bincode::config::standard()).unwrap()
                );
                let source = commit::<E, Sha256>(&pp, polynomial).unwrap();
                let leaves: Vec<_> = sequential
                    .chunks_exact(2 * width)
                    .enumerate()
                    .map(|(i, v)| leaf::<E, Sha256>(&pp, 0, i, v))
                    .collect();
                let mut reference = MerkleTree::<Sha256>::new();
                reference.generate(&leaves);
                assert_eq!(reference.tree, source.tree.tree);
                assert_eq!(reference.root, source.root());
            }
        }
    }
    #[test]
    fn babybear_parallel_words_preserve_every_leaf_and_root() {
        compare::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_parallel_words_preserve_every_leaf_and_root() {
        compare::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
