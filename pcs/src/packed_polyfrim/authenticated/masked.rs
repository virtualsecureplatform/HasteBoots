//! Experimental bounded-reuse masking for direct packed PolyFRIM.
//!
//! High-coefficient padding and an independent vector polynomial mask all
//! public folds. A numerical disclosure guard is not a zero-knowledge theorem.
#[cfg(test)]
mod disclosure;

use super::*;
use algebra::matrix_weighted::{Matrix, PackedTable};
use rand::{CryptoRng, Rng};

/// Trusted logical geometry, private-mask lifetime and padded oracle domain.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F> {
    message: usize,
    width: usize,
    blowup: usize,
    queries: usize,
    max_openings: usize,
    root: F,
}
impl<F: Field + Serialize> Parameters<F> {
    /// Commit m logical vector coefficients, pad to 2m, and retain masks for an
    /// explicit lifetime. Requires m >= max_openings*(width +
    /// 8*queries*(width+1)*(log2(2m)+1)). This conservative numerical allowance
    /// does not establish independence/rank or adaptive zero knowledge.
    pub fn new(
        message: usize,
        width: usize,
        blowup: usize,
        queries: usize,
        max_openings: usize,
        root: F,
    ) -> Result<Self, Error> {
        let root = root.canonicalized();
        let padded = message
            .checked_mul(2)
            .ok_or(Error("masked size overflow"))?;
        let wide = width.checked_mul(2).ok_or(Error("masked width overflow"))?;
        super::Parameters::new(padded, wide, blowup, queries, root)?;
        if !message.is_power_of_two() || max_openings == 0 {
            return Err(Error("masked logical geometry or lifetime"));
        }
        let allowance = width
            .checked_add(1)
            .and_then(|v| v.checked_mul(8))
            .and_then(|v| v.checked_mul(queries))
            .and_then(|v| v.checked_mul(padded.ilog2() as usize + 1))
            .and_then(|v| v.checked_add(width))
            .and_then(|v| v.checked_mul(max_openings))
            .ok_or(Error("masked disclosure allowance overflow"))?;
        if allowance > message {
            return Err(Error("insufficient packed mask capacity"));
        }
        Ok(Self {
            message,
            width,
            blowup,
            queries,
            max_openings,
            root,
        })
    }
    /// Maximum opening attempts after successful preflight, across this source.
    pub fn max_openings(&self) -> usize {
        self.max_openings
    }
    fn oracle(&self, wide: bool) -> super::Parameters<F> {
        super::Parameters::new(
            2 * self.message,
            self.width * if wide { 2 } else { 1 },
            self.blowup,
            self.queries,
            self.root,
        )
        .expect("validated masked geometry")
    }
}
/// Private retained padding/mask state. Cannot be cloned or serialized.
pub struct ProverSession<F, H: Hash + Send + Sync> {
    source: super::State<F, H>,
    context: H::Output,
    spent: usize,
}
impl<F, H: Hash + Send + Sync> ProverSession<F, H> {
    /// Public root of the padded source and independent mask in one packed tree.
    pub fn root(&self) -> H::Output {
        self.source.root()
    }
    /// Opening attempts spent from the private mask lifetime.
    pub fn spent(&self) -> usize {
        self.spent
    }
}
/// Masked direct packed opening. No individual unmasked lane evaluation is sent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Monotone private-session opening index.
    pub index: usize,
    /// Ordered matrix response of the independent random vector polynomial.
    pub mask_claim: Vec<F>,
    /// Independent source/mask lane-projection proximity certificate.
    pub source_proximity: rolling_fri::Proof<F, O>,
    /// Original packed paths authenticating the independent source projection.
    pub source_pairs: Vec<Pair<F, O>>,
    /// Masked virtual-source consistency and same-root projected proximity.
    pub inner: proximity::Proof<F, O>,
    /// Actual padded-source/mask pairs: consistency samples, then FRI samples.
    pub sources: Vec<Pair<F, O>>,
}
/// Commit with fresh private cryptographic randomness; callers retain one session
/// for the entire mask lifetime. Public seeds are appropriate only for tests.
pub fn commit<F: Field + Serialize, H: Hash + Send + Sync, R: Rng + CryptoRng>(
    pp: &Parameters<F>,
    table: &PackedTable<F>,
    rng: &mut R,
) -> Result<ProverSession<F, H>, Error> {
    table.validate().map_err(|_| Error("masked source table"))?;
    if table.width() != pp.width || table.values().len() != pp.message * pp.width {
        return Err(Error("masked source shape"));
    }
    let mut polynomial =
        Polynomial::from_table(table).map_err(|_| Error("masked source coefficients"))?;
    let padding: Vec<_> = (0..pp.message * pp.width).map(|_| F::random(rng)).collect();
    polynomial
        .pad(&padding)
        .map_err(|_| Error("masked high coefficients"))?;
    let mut coefficients = Vec::with_capacity(4 * pp.message * pp.width);
    for cell in polynomial.coefficients.chunks_exact(pp.width) {
        coefficients.extend_from_slice(cell);
        coefficients.extend((0..pp.width).map(|_| F::random(rng)));
    }
    let paired = Polynomial {
        width: 2 * pp.width,
        coefficients,
    };
    let source = super::commit(&pp.oracle(true), paired)?;
    Ok(ProverSession {
        source,
        context: hash::<H, _>(&(b"masked packed PolyFRIM parameters v2".as_slice(), pp)),
        spent: 0,
    })
}
fn padded_query<F: Field + Serialize>(
    pp: &Parameters<F>,
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Result<Vec<MatrixPair<F>>, Error> {
    if query.len() != pp.message.ilog2() as usize || claim.len() != pp.width {
        return Err(Error("masked query or claim shape"));
    }
    for pair in query {
        pair.validate(pp.width)
            .map_err(|_| Error("masked query matrix"))?;
    }
    let mut result = query.to_vec();
    result.push(MatrixPair {
        zero: Matrix::identity(pp.width).map_err(|_| Error("masked identity"))?,
        one: Matrix::new(pp.width, vec![F::zero(); pp.width * pp.width])
            .map_err(|_| Error("masked zero"))?,
    });
    Ok(result)
}
fn canonical_public<F: Field + Serialize>(
    pp: &Parameters<F>,
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Result<(Vec<MatrixPair<F>>, Vec<F>), Error> {
    padded_query(pp, query, claim)?;
    let query = query
        .iter()
        .map(|pair| MatrixPair {
            zero: Matrix::new(
                pp.width,
                pair.zero
                    .values()
                    .iter()
                    .map(|v| v.canonicalized())
                    .collect(),
            )
            .expect("validated width"),
            one: Matrix::new(
                pp.width,
                pair.one
                    .values()
                    .iter()
                    .map(|v| v.canonicalized())
                    .collect(),
            )
            .expect("validated width"),
        })
        .collect();
    Ok((query, claim.iter().map(|v| v.canonicalized()).collect()))
}
fn response<F: Field>(
    mut polynomial: Polynomial<F>,
    query: &[MatrixPair<F>],
) -> Result<Vec<F>, Error> {
    for pair in query {
        polynomial = polynomial
            .fold(pair)
            .map_err(|_| Error("masked response fold"))?;
    }
    Ok(polynomial.evaluate(F::zero()))
}
fn split<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    session: &ProverSession<F, H>,
) -> (Polynomial<F>, Polynomial<F>) {
    let mut data = Vec::new();
    let mut mask = Vec::new();
    for cell in session
        .source
        .polynomial
        .coefficients
        .chunks_exact(2 * pp.width)
    {
        data.extend_from_slice(&cell[..pp.width]);
        mask.extend_from_slice(&cell[pp.width..]);
    }
    (
        Polynomial {
            width: pp.width,
            coefficients: data,
        },
        Polynomial {
            width: pp.width,
            coefficients: mask,
        },
    )
}
/// Open under the original matrix query and expected claim. Invalid statements,
/// parameters and exhausted sessions reject before transcript mutation. Once
/// preflight succeeds the allowance is spent even if later proving fails.
pub fn prove<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    session: &mut ProverSession<F, H>,
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Result<Proof<F, H::Output>, Error> {
    if session.context != hash::<H, _>(&(b"masked packed PolyFRIM parameters v2".as_slice(), pp))
        || session.spent >= pp.max_openings
    {
        return Err(Error("masked parameter context or exhausted lifetime"));
    }
    let (canonical_query, canonical_claim) = canonical_public(pp, query, claim)?;
    let query = canonical_query.as_slice();
    let claim = canonical_claim.as_slice();
    let padded = padded_query(pp, query, claim)?;
    let (data, mask) = split(pp, session);
    let data_claim = response(
        Polynomial {
            width: pp.width,
            coefficients: data.coefficients.clone(),
        },
        &padded,
    )?;
    if data_claim != claim {
        return Err(Error("false masked source claim"));
    }
    let mask_claim = response(
        Polynomial {
            width: pp.width,
            coefficients: mask.coefficients.clone(),
        },
        &padded,
    )?;
    let mask_claim: Vec<_> = mask_claim.into_iter().map(Field::canonicalized).collect();
    let index = session.spent;
    session.spent += 1;
    let alpha = bind(t, pp, &session.root(), index, query, claim, &mask_claim);
    let (source_proximity, source_pairs) = source_prove::<F, H>(t, pp, &session.source, index)?;
    let identifier = identifier::<F, H>(pp, &session.root(), index, alpha);
    let coefficients = data
        .coefficients
        .iter()
        .zip(&mask.coefficients)
        .map(|(&p, &s)| (p + alpha * s).canonicalized())
        .collect();
    let polynomial = Polynomial {
        width: pp.width,
        coefficients,
    };
    let values = session
        .source
        .values
        .chunks_exact(2 * pp.width)
        .flat_map(|v| {
            v[..pp.width]
                .iter()
                .zip(&v[pp.width..])
                .map(|(&p, &s)| (p + alpha * s).canonicalized())
        })
        .collect();
    let oracle = pp.oracle(false);
    let mut tree = MerkleTree::<H>::new();
    tree.root = identifier;
    let virtual_source = super::State {
        polynomial,
        values,
        tree,
        context: hash::<H, _>(&(b"packed PolyFRIM parameters v2", &oracle)),
        layer: 0,
    };
    let combined: Vec<_> = claim
        .iter()
        .zip(&mask_claim)
        .map(|(&p, &s)| (p + alpha * s).canonicalized())
        .collect();
    let (inner, indices) =
        proximity::prove_source(t, &oracle, &virtual_source, &padded, &combined, true)?;
    let sources = indices
        .iter()
        .map(|index| {
            let pair = index / 2;
            let width = 2 * pp.width;
            Pair {
                values: session.source.values[pair * 2 * width..(pair + 1) * 2 * width].to_vec(),
                path: session.source.tree.query(pair),
            }
        })
        .collect();
    Ok(Proof {
        index,
        mask_claim,
        source_proximity,
        source_pairs,
        inner,
        sources,
    })
}
/// Stateless cryptographic check; applications requiring ordered acceptance use
/// VerifierSession. This check deliberately permits independent proof replays.
pub fn verify<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    query: &[MatrixPair<F>],
    claim: &[F],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error> {
    let (canonical_query, canonical_claim) = canonical_public(pp, query, claim)?;
    let query = canonical_query.as_slice();
    let claim = canonical_claim.as_slice();
    let padded = padded_query(pp, query, claim)?;
    if proof.index >= pp.max_openings
        || proof.mask_claim.len() != pp.width
        || proof.sources.len() != 2 * pp.queries
        || proof.source_pairs.len() != pp.queries
    {
        return Err(Error("masked proof index or shape"));
    }
    if proof.mask_claim.iter().any(|v| !v.is_canonical())
        || proof
            .sources
            .iter()
            .chain(&proof.source_pairs)
            .any(|p| p.values.iter().any(|v| !v.is_canonical()))
    {
        return Err(Error("noncanonical masked field encoding"));
    }
    let alpha = bind(t, pp, source, proof.index, query, claim, &proof.mask_claim);
    source_verify::<F, H>(
        t,
        pp,
        source,
        proof.index,
        &proof.source_proximity,
        &proof.source_pairs,
    )?;
    let identifier = identifier::<F, H>(pp, source, proof.index, alpha);
    let combined: Vec<_> = claim
        .iter()
        .zip(&proof.mask_claim)
        .map(|(&p, &s)| (p + alpha * s).canonicalized())
        .collect();
    let wide = pp.oracle(true);
    let mut calls = 0;
    proximity::verify_source::<F, H, _>(
        t,
        &pp.oracle(false),
        &identifier,
        &padded,
        &combined,
        &proof.inner,
        true,
        |index, virtual_pair| {
            let opening = proof
                .sources
                .get(calls)
                .ok_or(Error("masked source callback count"))?;
            calls += 1;
            let pair = index / 2;
            let depth = (wide.len(0) / 2).ilog2() as usize;
            if opening.values.len() != 4 * pp.width
                || opening.path.len() != depth + 1
                || opening.path[0] != leaf::<F, H>(&wide, 0, pair, &opening.values)
                || !MerkleTree::<H>::check(source, pair, &opening.path)
            {
                return Err(Error("masked source authentication"));
            }
            let expected: Vec<_> = opening
                .values
                .chunks_exact(2 * pp.width)
                .flat_map(|v| {
                    v[..pp.width]
                        .iter()
                        .zip(&v[pp.width..])
                        .map(|(&p, &s)| p + alpha * s)
                })
                .collect();
            if expected != virtual_pair.values {
                return Err(Error("masked virtual source mismatch"));
            }
            Ok(())
        },
    )?;
    if calls != 2 * pp.queries {
        return Err(Error("masked source callback count"));
    }
    Ok(())
}
fn bind<F: Field + Serialize, O: Serialize>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &O,
    index: usize,
    query: &[MatrixPair<F>],
    claim: &[F],
    mask_claim: &[F],
) -> F {
    t.append_message(
        b"masked direct packed PolyFRIM opening v2",
        &(pp, source, index, query, claim, mask_claim),
    );
    loop {
        let alpha = t.get_challenge(b"masked direct packed PolyFRIM alpha v2");
        if alpha != F::zero() {
            return alpha;
        }
    }
}
fn identifier<F: Field + Serialize, H: Hash>(
    pp: &Parameters<F>,
    source: &H::Output,
    index: usize,
    alpha: F,
) -> H::Output {
    hash::<H, _>(&(
        b"masked direct packed PolyFRIM virtual source v2".as_slice(),
        pp,
        source,
        index,
        alpha,
    ))
}
/// Optional ordered acceptance state; advances only after successful verification.
pub struct VerifierSession<O> {
    root: O,
    next: usize,
}
impl<O> VerifierSession<O> {
    /// Start acceptance at index zero for one retained commitment.
    pub fn new(root: O) -> Self {
        Self { root, next: 0 }
    }
    /// Successfully accepted proofs.
    pub fn accepted(&self) -> usize {
        self.next
    }
}
impl<O: Copy> VerifierSession<O> {
    /// Verify the next indexed opening; failed verification leaves the counter.
    pub fn verify<F: Field + Serialize, H: Hash<Output = O> + Send + Sync>(
        &mut self,
        t: &mut Transcript<F>,
        pp: &Parameters<F>,
        query: &[MatrixPair<F>],
        claim: &[F],
        proof: &Proof<F, O>,
    ) -> Result<(), Error> {
        if proof.index != self.next {
            return Err(Error("masked opening order"));
        }
        verify::<F, H>(t, pp, &self.root, query, claim, proof)?;
        self.next += 1;
        Ok(())
    }
}

fn source_projection<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    index: usize,
) -> (Vec<F>, Vec<H::Output>) {
    t.append_message(b"masked packed source proximity v2", &(pp, source, index));
    let weights = t.get_vec_challenge(b"masked packed source projection v2", 2 * pp.width);
    let ids = (0..(2 * pp.message).ilog2() as usize)
        .map(|layer| {
            hash::<H, _>(&(
                b"masked packed source oracle v2".as_slice(),
                pp,
                source,
                index,
                layer,
                &weights,
            ))
        })
        .collect();
    (weights, ids)
}
fn source_prove<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &super::State<F, H>,
    index: usize,
) -> Result<(rolling_fri::Proof<F, H::Output>, Vec<Pair<F, H::Output>>), Error> {
    let (weights, ids) = source_projection::<F, H>(t, pp, &source.root(), index);
    let wide = pp.oracle(true);
    let mut values = vec![
        source
            .values
            .chunks_exact(2 * pp.width)
            .map(|v| {
                v.iter()
                    .zip(&weights)
                    .fold(F::zero(), |a, (&v, &w)| a + v * w)
            })
            .collect(),
    ];
    values.extend((1..wide.rounds()).map(|layer| vec![F::zero(); wide.len(layer)]));
    let fri = rolling_fri::Parameters::new(2 * pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("masked source proximity geometry"))?;
    let (proof, trace) =
        rolling_fri::prove_virtual_all::<F, H>(t, &fri, &ids, values).map_err(|e| Error(e.0))?;
    let pairs = trace
        .indices
        .iter()
        .map(|index| {
            let position = index / 2;
            let width = 2 * pp.width;
            Pair {
                values: source.values[position * 2 * width..(position + 1) * 2 * width].to_vec(),
                path: source.tree.query(position),
            }
        })
        .collect();
    Ok((proof, pairs))
}
fn source_verify<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    index: usize,
    proof: &rolling_fri::Proof<F, H::Output>,
    pairs: &[Pair<F, H::Output>],
) -> Result<(), Error> {
    if pairs.len() != pp.queries {
        return Err(Error("masked source proximity count"));
    }
    let (weights, ids) = source_projection::<F, H>(t, pp, source, index);
    let wide = pp.oracle(true);
    let fri = rolling_fri::Parameters::new(2 * pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("masked source proximity geometry"))?;
    let mut count = 0;
    rolling_fri::verify_virtual_all::<F, H, _>(t, &fri, &ids, proof, |layer, index, pair| {
        if layer > 0 {
            if pair.values != [F::zero(); 2] {
                return Err(rolling_fri::Error("masked source nonzero placeholder"));
            }
        } else {
            let opening = &pairs[count];
            count += 1;
            let position = index / 2;
            if opening.values.len() != 4 * pp.width
                || opening.path.len() != (wide.len(0) / 2).ilog2() as usize + 1
                || opening.path[0] != leaf::<F, H>(&wide, 0, position, &opening.values)
                || !MerkleTree::<H>::check(source, position, &opening.path)
            {
                return Err(rolling_fri::Error("masked source proximity authentication"));
            }
            let expected: Vec<_> = opening
                .values
                .chunks_exact(2 * pp.width)
                .map(|v| {
                    v.iter()
                        .zip(&weights)
                        .fold(F::zero(), |a, (&v, &w)| a + v * w)
                })
                .collect();
            if pair.values != [expected[0], expected[1]] {
                return Err(rolling_fri::Error("masked source projection mismatch"));
            }
        }
        Ok(())
    })
    .map_err(|e| Error(e.0))?;
    if count != pp.queries {
        return Err(Error("masked source projection callback count"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, transformation::AbstractNTT};
    use rand::{SeedableRng, rngs::StdRng};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

    fn field_disclosures<F, O>(proof: &Proof<F, O>) -> usize {
        fn fri_count<F, O>(proof: &rolling_fri::Proof<F, O>) -> usize {
            1 + proof
                .queries
                .iter()
                .map(|q| {
                    q.originals
                        .iter()
                        .chain(&q.derived)
                        .map(|p| p.values.len())
                        .sum::<usize>()
                })
                .sum::<usize>()
        }
        proof.mask_claim.len()
            + fri_count(&proof.source_proximity)
            + fri_count(&proof.inner.proximity)
            + proof
                .sources
                .iter()
                .chain(&proof.source_pairs)
                .map(|p| p.values.len())
                .sum::<usize>()
            + proof
                .inner
                .consistency
                .queries
                .iter()
                .flatten()
                .map(|p| p.values.len())
                .sum::<usize>()
            + proof
                .inner
                .packed
                .iter()
                .flatten()
                .map(|p| p.values.len())
                .sum::<usize>()
    }
    fn exercise<F: NTTField + Serialize + DeserializeOwned>() {
        for width in [1, 2, 4, 8] {
            let message = 2048;
            let variables = 11;
            let root = F::generate_ntt_table(13).unwrap().root();
            let pp = Parameters::new(message, width, 2, 1, 2, root).unwrap();
            let table = PackedTable::new(
                variables,
                width,
                (0..message * width)
                    .map(|i| F::from(i * i + 3 * i + 5))
                    .collect(),
            )
            .unwrap();
            let mut rng = StdRng::seed_from_u64(100 + width as u64);
            let mut session = commit::<F, Sha256, _>(&pp, &table, &mut rng).unwrap();
            let mut verifier = VerifierSession::new(session.root());
            let mut saved = None;
            for opening in 0..2 {
                let query: Vec<_> = (0..variables)
                    .map(|i| {
                        if opening == 1 {
                            MatrixPair {
                                zero: Matrix::identity(width).unwrap(),
                                one: Matrix::new(width, vec![F::zero(); width * width]).unwrap(),
                            }
                        } else {
                            MatrixPair {
                                zero: Matrix::new(
                                    width,
                                    (0..width * width).map(|j| F::from(i + 2 * j + 1)).collect(),
                                )
                                .unwrap(),
                                one: Matrix::new(
                                    width,
                                    (0..width * width)
                                        .map(|j| F::from(j * j + 3 * i + 2))
                                        .collect(),
                                )
                                .unwrap(),
                            }
                        }
                    })
                    .collect();
                let claim = table.evaluate(&query).unwrap();
                let mut wrong = claim.clone();
                wrong[0] += F::one();
                let mut attempted = Transcript::new();
                let mut unchanged = Transcript::<F>::new();
                assert!(prove(&mut attempted, &pp, &mut session, &query, &wrong).is_err());
                assert_eq!(session.spent(), opening);
                assert_eq!(
                    attempted.get_challenge(b"preflight"),
                    unchanged.get_challenge(b"preflight")
                );
                let mut prover = Transcript::new();
                let proof = prove(&mut prover, &pp, &mut session, &query, &claim).unwrap();
                assert_eq!(proof.index, opening);
                assert_eq!(session.spent(), opening + 1);
                let bytes =
                    bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                let (proof, used): (Proof<F, [u8; 32]>, usize) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
                assert_eq!(used, bytes.len());
                assert!(field_disclosures(&proof) * pp.max_openings <= pp.message);

                let mut transcript = Transcript::new();
                verifier
                    .verify::<F, Sha256>(&mut transcript, &pp, &query, &claim, &proof)
                    .unwrap();
                assert_eq!(verifier.accepted(), opening + 1);
                assert_eq!(
                    prover.get_challenge(b"after"),
                    transcript.get_challenge(b"after")
                );
                // Core cryptographic verification is intentionally stateless.
                verify::<F, Sha256>(
                    &mut Transcript::new(),
                    &pp,
                    &session.root(),
                    &query,
                    &claim,
                    &proof,
                )
                .unwrap();
                assert!(
                    verifier
                        .verify::<F, Sha256>(&mut Transcript::new(), &pp, &query, &claim, &proof)
                        .is_err()
                );
                for source_layer in [false, true] {
                    let mut changed = proof.clone();
                    if source_layer {
                        changed.source_pairs[0].path.clear();
                    } else {
                        changed.sources[0].values[0] += F::one();
                    }
                    assert!(
                        verify::<F, Sha256>(
                            &mut Transcript::new(),
                            &pp,
                            &session.root(),
                            &query,
                            &claim,
                            &changed
                        )
                        .is_err()
                    );
                }
                let mut changed = proof.clone();
                changed.mask_claim[0] += F::one();
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &session.root(),
                        &query,
                        &claim,
                        &changed
                    )
                    .is_err()
                );
                let mut changed = proof.clone();
                changed.inner.consistency.queries[0][0].path.push([0; 32]);
                assert!(
                    verify::<F, Sha256>(
                        &mut Transcript::new(),
                        &pp,
                        &session.root(),
                        &query,
                        &claim,
                        &changed
                    )
                    .is_err()
                );
                saved = Some((query, claim));
            }
            let (query, claim) = saved.unwrap();
            let mut exhausted = Transcript::new();
            let mut unchanged = Transcript::<F>::new();
            assert!(prove(&mut exhausted, &pp, &mut session, &query, &claim).is_err());
            assert_eq!(session.spent(), 2);
            assert_eq!(
                exhausted.get_challenge(b"after exhausted"),
                unchanged.get_challenge(b"after exhausted")
            );
            let fresh = commit::<F, Sha256, _>(&pp, &table, &mut rng).unwrap();
            assert_ne!(fresh.root(), session.root());
            let other = Parameters::new(message, width, 2, 1, 1, root).unwrap();
            let mut fresh_session = fresh;
            assert!(
                prove(
                    &mut Transcript::new(),
                    &other,
                    &mut fresh_session,
                    &query,
                    &claim
                )
                .is_err()
            );
            assert_eq!(fresh_session.spent(), 0);
        }
    }
    #[test]
    fn babybear_masked_sessions() {
        exercise::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_masked_sessions() {
        exercise::<algebra::Goldilocks>();
    }
    fn fresh_false_claims<F: NTTField + Serialize>() {
        for false_mask in [false, true] {
            let width = 1;
            let message = 2048;
            let pp = Parameters::new(
                message,
                width,
                2,
                1,
                1,
                F::generate_ntt_table(13).unwrap().root(),
            )
            .unwrap();
            let table = PackedTable::new(11, width, (0..message).map(|i| F::from(i + 7)).collect())
                .unwrap();
            let mut rng = StdRng::seed_from_u64(999 + false_mask as u64);
            let session = commit::<F, Sha256, _>(&pp, &table, &mut rng).unwrap();
            let query = vec![
                MatrixPair {
                    zero: Matrix::identity(1).unwrap(),
                    one: Matrix::new(1, vec![F::zero()]).unwrap()
                };
                11
            ];
            let mut claim = table.evaluate(&query).unwrap();
            let padded = padded_query(&pp, &query, &claim).unwrap();
            let (data, mask) = split(&pp, &session);
            let mut mask_claim = response(
                Polynomial {
                    width,
                    coefficients: mask.coefficients.clone(),
                },
                &padded,
            )
            .unwrap();
            if false_mask {
                mask_claim[0] += F::one();
            } else {
                claim[0] += F::one();
            }
            let mut prover = Transcript::new();
            let alpha = bind(
                &mut prover,
                &pp,
                &session.root(),
                0,
                &query,
                &claim,
                &mask_claim,
            );
            let (source_proximity, source_pairs) =
                source_prove::<F, Sha256>(&mut prover, &pp, &session.source, 0).unwrap();
            let delta = if false_mask { alpha } else { F::one() };
            let mut coefficients: Vec<_> = data
                .coefficients
                .iter()
                .zip(&mask.coefficients)
                .map(|(&p, &s)| p + alpha * s)
                .collect();
            coefficients[0] += delta;
            let values = session
                .source
                .values
                .chunks_exact(2)
                .map(|v| v[0] + alpha * v[1] + delta)
                .collect();
            let oracle = pp.oracle(false);
            let mut tree = MerkleTree::<Sha256>::new();
            tree.root = identifier::<F, Sha256>(&pp, &session.root(), 0, alpha);
            let foreign = super::super::State {
                polynomial: Polynomial {
                    width,
                    coefficients,
                },
                values,
                tree,
                context: hash::<Sha256, _>(&(b"packed PolyFRIM parameters v2", &oracle)),
                layer: 0,
            };
            let combined: Vec<_> = claim
                .iter()
                .zip(&mask_claim)
                .map(|(&p, &s)| p + alpha * s)
                .collect();
            let (inner, indices) =
                proximity::prove_source(&mut prover, &oracle, &foreign, &padded, &combined, true)
                    .unwrap();
            let wide = pp.oracle(true);
            let sources = indices
                .iter()
                .map(|index| {
                    let pair = index / 2;
                    Pair {
                        values: session.source.values[pair * 4..(pair + 1) * 4].to_vec(),
                        path: session.source.tree.query(pair),
                    }
                })
                .collect();
            let proof = Proof {
                index: 0,
                mask_claim,
                source_proximity,
                source_pairs,
                inner,
                sources,
            };
            // Rebuild the requested parent transcript. All child proofs and
            // actual source paths pass; only the disputed virtual link differs.
            let mut reference = Transcript::new();
            let checked_alpha = bind(
                &mut reference,
                &pp,
                &session.root(),
                0,
                &query,
                &claim,
                &proof.mask_claim,
            );
            assert_eq!(alpha, checked_alpha);
            source_verify::<F, Sha256>(
                &mut reference,
                &pp,
                &session.root(),
                0,
                &proof.source_proximity,
                &proof.source_pairs,
            )
            .unwrap();
            let mut calls = 0;
            proximity::verify_source::<F, Sha256, _>(
                &mut reference,
                &oracle,
                &foreign.root(),
                &padded,
                &combined,
                &proof.inner,
                true,
                |index, pair| {
                    let opening = &proof.sources[calls];
                    calls += 1;
                    let position = index / 2;
                    assert_eq!(
                        opening.path[0],
                        leaf::<F, Sha256>(&wide, 0, position, &opening.values)
                    );
                    assert!(MerkleTree::<Sha256>::check(
                        &session.root(),
                        position,
                        &opening.path
                    ));
                    let expected: Vec<_> = opening
                        .values
                        .chunks_exact(2)
                        .map(|v| v[0] + alpha * v[1] + delta)
                        .collect();
                    assert_eq!(pair.values, expected);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(calls, 2 * pp.queries);
            assert_eq!(
                prover.get_challenge(b"after fresh masked forgery"),
                reference.get_challenge(b"after fresh masked forgery")
            );
            let error = verify::<F, Sha256>(
                &mut Transcript::new(),
                &pp,
                &session.root(),
                &query,
                &claim,
                &proof,
            )
            .unwrap_err();
            assert_eq!(error.0, "masked virtual source mismatch");
        }
    }
    #[test]
    fn babybear_fresh_false_masked_claims() {
        fresh_false_claims::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_fresh_false_masked_claims() {
        fresh_false_claims::<algebra::Goldilocks>();
    }
    #[test]
    fn goldilocks_aliases_produce_one_masked_wire_and_reject_lazy_proofs() {
        use algebra::Goldilocks as F;
        let m = 512;
        let width = 1;
        let root = F::generate_ntt_table(11).unwrap().root();
        let pp = Parameters::new(m, width, 2, 1, 1, root).unwrap();
        let zero = F::new(0);
        let lazy = F::new(F::MODULUS_VALUE);
        let table = PackedTable::new(9, 1, vec![zero; m]).unwrap();
        let alias = PackedTable::new(9, 1, vec![lazy; m]).unwrap();
        let query = vec![
            MatrixPair {
                zero: Matrix::new(1, vec![zero]).unwrap(),
                one: Matrix::new(1, vec![F::new(1)]).unwrap()
            };
            9
        ];
        let alias_query = vec![
            MatrixPair {
                zero: Matrix::new(1, vec![lazy]).unwrap(),
                one: Matrix::new(1, vec![F::new(1)]).unwrap()
            };
            9
        ];
        let mut a = commit::<F, Sha256, _>(&pp, &table, &mut StdRng::seed_from_u64(8121)).unwrap();
        let mut b = commit::<F, Sha256, _>(&pp, &alias, &mut StdRng::seed_from_u64(8121)).unwrap();
        assert_eq!(a.root(), b.root());
        let mut ta = Transcript::new_direct();
        let mut tb = Transcript::new_direct();
        let pa = prove(&mut ta, &pp, &mut a, &query, &[zero]).unwrap();
        let pb = prove(&mut tb, &pp, &mut b, &alias_query, &[lazy]).unwrap();
        assert_eq!(
            bincode::serde::encode_to_vec(&pa, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&pb, bincode::config::standard()).unwrap()
        );
        assert_eq!(
            ta.get_challenge(b"alias after"),
            tb.get_challenge(b"alias after")
        );
        verify::<F, Sha256>(
            &mut Transcript::new_direct(),
            &pp,
            &a.root(),
            &alias_query,
            &[lazy],
            &pa,
        )
        .unwrap();
        let mut changed = pa;
        assert_eq!(
            changed.source_proximity.queries[0].originals[1].values[0],
            zero
        );
        changed.source_proximity.queries[0].originals[1].values[0] = lazy;
        let error = verify::<F, Sha256>(
            &mut Transcript::new_direct(),
            &pp,
            &a.root(),
            &query,
            &[zero],
            &changed,
        )
        .unwrap_err();
        assert_eq!(error.0, "noncanonical virtual-all field encoding");
    }
    #[test]
    fn goldilocks_extension_canonical_wire_preserves_nonbase_coordinates() {
        use algebra::{AbstractExtensionField, Goldilocks as B, GoldilocksExtension3 as E};
        let root = E::from_base(B::generate_ntt_table(11).unwrap().root());
        let pp = Parameters::new(512, 1, 2, 1, 1, root).unwrap();
        let table = PackedTable::new(
            9,
            1,
            (0..512)
                .map(|i| E::from_base_fn(|j| B::new((i * (j + 1) + j + 1) as u64)))
                .collect(),
        )
        .unwrap();
        let alias = PackedTable::new(
            9,
            1,
            (0..512)
                .map(|i| {
                    E::from_base_fn(|j| B::new(B::MODULUS_VALUE + (i * (j + 1) + j + 1) as u64))
                })
                .collect(),
        )
        .unwrap();
        let zero = E::from_base(B::new(0));
        let one = E::from_base(B::new(1));
        let lazy_zero = E::from_base_fn(|j| B::new(if j == 1 { B::MODULUS_VALUE } else { 0 }));
        let query = vec![
            MatrixPair {
                zero: Matrix::new(1, vec![zero]).unwrap(),
                one: Matrix::new(1, vec![one]).unwrap()
            };
            9
        ];
        let raw_query = vec![
            MatrixPair {
                zero: Matrix::new(1, vec![lazy_zero]).unwrap(),
                one: Matrix::new(1, vec![one]).unwrap()
            };
            9
        ];
        let claim = table.evaluate(&query).unwrap();
        assert_ne!(claim[0].as_base_slice()[1], B::new(0));
        let mut a = commit::<E, Sha256, _>(&pp, &table, &mut StdRng::seed_from_u64(8122)).unwrap();
        let mut b = commit::<E, Sha256, _>(&pp, &alias, &mut StdRng::seed_from_u64(8122)).unwrap();
        assert_eq!(a.root(), b.root());
        let mut ta = Transcript::new_direct_extension::<B>();
        let mut tb = Transcript::new_direct_extension::<B>();
        let pa = prove(&mut ta, &pp, &mut a, &query, &claim).unwrap();
        let pb = prove(&mut tb, &pp, &mut b, &raw_query, &claim).unwrap();
        let bytes = bincode::serde::encode_to_vec(&pa, bincode::config::standard()).unwrap();
        assert_eq!(
            bytes,
            bincode::serde::encode_to_vec(&pb, bincode::config::standard()).unwrap()
        );
        let (mut decoded, used): (Proof<E, [u8; 32]>, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(used, bytes.len());
        let mut verifier = Transcript::new_direct_extension::<B>();
        verify::<E, Sha256>(&mut verifier, &pp, &a.root(), &query, &claim, &decoded).unwrap();
        let after = ta.get_challenge(b"extension canonical after");
        assert_eq!(after, tb.get_challenge(b"extension canonical after"));
        assert_eq!(after, verifier.get_challenge(b"extension canonical after"));
        decoded.source_proximity.queries[0].originals[1].values[0] = lazy_zero;
        let error = verify::<E, Sha256>(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &a.root(),
            &query,
            &claim,
            &decoded,
        )
        .unwrap_err();
        assert_eq!(error.0, "noncanonical virtual-all field encoding");
    }
    #[test]
    fn capacity_checks() {
        type F = algebra::BabyBear;
        let root = F::generate_ntt_table(13).unwrap().root();
        assert!(Parameters::new(2048, 8, 2, 1, 2, root).is_ok());
        assert!(Parameters::new(2048, 8, 2, 1, 0, root).is_err());
        assert!(Parameters::new(2048, 8, 2, 1, 3, root).is_err());
        assert!(Parameters::new(2048, 0, 2, 1, 1, root).is_err());
    }
}
