//! Rolling batch FRI, Protocol 1 of refs/2025-1354.pdf.
//!
//! This authenticates a ladder of RS proximity claims. It is not yet PolyFRIM,
//! PipFRI evaluation binding, a hiding PCS, or a concrete security certificate.
use crate::utils::{hash::Hash, merkle_tree::MerkleTree};
use algebra::{AbstractExtensionField, Field};
use helper::{FiatShamirTranscript, Transcript};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod radius_tests;

/// Invalid trusted parameters, oracle state, or rejected certificate.
#[derive(Debug, thiserror::Error)]
#[error("rolling FRI: {0}")]
pub struct Error(pub &'static str);
/// Trusted power-of-two degree/rate geometry and primitive 2N-th root.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F> {
    message: usize,
    blowup: usize,
    queries: usize,
    root: F,
    // An arithmetic implementation choice, excluded from mathematical protocol
    // parameters. Both encoders must produce identical codewords and hashes.
    #[serde(skip)]
    encoder: fn(&[F], usize, F) -> Vec<F>,
}
impl<F: Field + Serialize> Parameters<F> {
    /// Set the initial degree bound <message, encoded length message*blowup.
    /// root must have exact order twice the encoded length. No security-bit
    /// assertion is inferred from a query count or field type.
    pub fn new(message: usize, blowup: usize, queries: usize, root: F) -> Result<Self, Error> {
        if message < 2
            || !message.is_power_of_two()
            || blowup < 2
            || !blowup.is_power_of_two()
            || queries == 0
            || F::one() + F::one() == F::zero()
        {
            return Err(Error("invalid degree, rate, query count or characteristic"));
        }
        let n = message
            .checked_mul(blowup)
            .ok_or(Error("encoded size overflow"))?;
        let twice = n.checked_mul(2).ok_or(Error("domain size overflow"))?;
        if power(root, n) != -F::one() || power(root, twice) != F::one() {
            return Err(Error("root does not have exact order 2N"));
        }
        Ok(Self {
            message,
            blowup,
            queries,
            root,
            encoder: encode::<F>,
        })
    }
    /// Encode extension coordinates with base-field FFTs when the domain root
    /// lies in that base field. Zero coordinates skip their FFT. This changes
    /// no serialized parameters, codewords, roots, transcript or proof format.
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
        self.encoder = encode_extension::<Base, F>;
        Ok(self)
    }
    pub(crate) fn encode(&self, coefficients: &[F], layer: usize) -> Vec<F> {
        (self.encoder)(coefficients, self.len(layer), self.shift(layer))
    }
    /// Number of original oracles and rolling folding challenges.
    pub fn rounds(&self) -> usize {
        self.message.ilog2() as usize
    }
    /// Independent query count, without an inferred security level.
    pub fn queries(&self) -> usize {
        self.queries
    }
    /// Initial RS codeword length.
    pub fn encoded_len(&self) -> usize {
        self.message * self.blowup
    }
    pub(crate) fn len(&self, i: usize) -> usize {
        self.encoded_len() >> i
    }
    pub(crate) fn shift(&self, i: usize) -> F {
        power(self.root, 1usize << i)
    }
    pub(crate) fn context<H: Hash>(&self) -> H::Output {
        hash::<H, _>(&(
            b"HasteBoots rolling FRI parameters v1".as_slice(),
            F::MODULUS_VALUE.to_string(),
            self,
        ))
    }
}
/// Root of an original or derived, domain-separated pair-leaf oracle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment<O> {
    /// Merkle root; geometry comes from trusted parameters.
    pub root: O,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Role {
    Original,
    Derived,
}
/// Private oracle values/tree, never a verifier input or proof field.
pub struct State<F, H: Hash + Send + Sync> {
    values: Vec<F>,
    tree: MerkleTree<H>,
    context: H::Output,
    role: Role,
    layer: usize,
}
impl<F, H: Hash + Send + Sync> State<F, H> {
    /// Extract the public commitment without exposing prover state.
    pub fn commitment(&self) -> Commitment<H::Output> {
        Commitment {
            root: self.tree.root,
        }
    }
}
/// Commit f_i, with degree <message/2^i on the squared domain L_i.
/// Values are stored in bit-reversed order; adjacent entries are at x and -x.
pub fn commit_original<F, H>(
    pp: &Parameters<F>,
    layer: usize,
    coefficients: &[F],
) -> Result<State<F, H>, Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if layer >= pp.rounds() || coefficients.len() > pp.message >> layer {
        return Err(Error("original oracle degree or layer"));
    }
    let values = pp.encode(coefficients, layer);
    Ok(state::<F, H>(pp, Role::Original, layer, values))
}
/// Authenticated values at an adjacent +/- domain pair.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairOpening<F, O> {
    /// Values at the canonical positive and negative pair points.
    pub values: [F; 2],
    /// Leaf hash followed by sibling hashes.
    pub path: Vec<O>,
}
/// One sampled initial index and all its squared-domain checks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query<F, O> {
    /// One pair per original oracle, in layer order.
    pub originals: Vec<PairOpening<F, O>>,
    /// Pairs for derived p_1 through p_sigma.
    pub derived: Vec<PairOpening<F, O>>,
}
/// Certificate against expected original roots fixed before folding challenges.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Roots of p_1 through p_sigma, bound sequentially.
    pub derived: Vec<Commitment<O>>,
    /// Revealed final degree-zero polynomial.
    pub terminal: F,
    /// Independent initial-domain index queries, with replacement.
    pub queries: Vec<Query<F, O>>,
}
/// Prove the rolling proximity checks for all original oracles.
/// The caller must bind its enclosing statement before this call.
pub fn prove<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    originals: &[&State<F, H>],
) -> Result<Proof<F, H::Output>, Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_inner(trans, pp, originals, true)
}
fn prove_inner<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    originals: &[&State<F, H>],
    strict: bool,
) -> Result<Proof<F, H::Output>, Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_mode(trans, pp, originals, strict, Virtual::None).map(|(proof, _)| proof)
}
/// Public verifier coins/locations, retained for virtual-oracle consistency
/// checks and numerical disclosure auditing by the enclosing protocol.
#[derive(Debug)]
pub(crate) struct Trace<F> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) alphas: Vec<F>,
    pub(crate) indices: Vec<usize>,
}
/// A virtual first oracle is authenticated by its enclosing commitment. It has
/// a protocol identifier rather than a standalone Merkle root. Other original
/// states remain actual roots fixed before the rolling challenges.
pub(crate) fn prove_virtual_initial<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifier: H::Output,
    values: Vec<F>,
    following: &[&State<F, H>],
) -> Result<(Proof<F, H::Output>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if values.len() != pp.len(0) || following.len() + 1 != pp.rounds() {
        return Err(Error("virtual initial geometry"));
    }
    let mut tree = MerkleTree::new();
    tree.root = identifier;
    let first = State {
        values,
        tree,
        context: pp.context::<H>(),
        role: Role::Original,
        layer: 0,
    };
    let mut originals = vec![&first];
    originals.extend_from_slice(following);
    prove_mode(trans, pp, &originals, true, Virtual::First)
}
#[derive(Clone, Copy)]
enum Virtual {
    None,
    First,
    All,
}
impl Virtual {
    fn contains(self, layer: usize) -> bool {
        match self {
            Self::None => false,
            Self::First => layer == 0,
            Self::All => true,
        }
    }
}
/// All original words are virtual projections of enclosing authenticated roots.
/// The enclosing protocol must fix those roots before selecting the projections.
pub(crate) fn prove_virtual_all<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifiers: &[H::Output],
    values: Vec<Vec<F>>,
) -> Result<(Proof<F, H::Output>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_virtual_all_inner::<F, H>(trans, pp, identifiers, values, true)
}
#[cfg(test)]
pub(crate) fn prove_virtual_all_for_audit<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifiers: &[H::Output],
    values: Vec<Vec<F>>,
) -> Result<(Proof<F, H::Output>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_virtual_all_inner::<F, H>(trans, pp, identifiers, values, false)
}
fn prove_virtual_all_inner<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifiers: &[H::Output],
    values: Vec<Vec<F>>,
    strict: bool,
) -> Result<(Proof<F, H::Output>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_virtual_all_mapped_inner::<F, H, H::Output>(
        trans,
        pp,
        identifiers,
        values,
        strict,
        &mut |h| Ok(h),
    )
}
/// Emit mapped proof hashes directly while all transcript bindings retain the
/// original hashes. The callback sees roots before paths in wire traversal order.
pub(crate) fn prove_virtual_all_mapped<F, H, O>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifiers: &[H::Output],
    values: Vec<Vec<F>>,
    encode: &mut impl FnMut(H::Output) -> Result<O, Error>,
) -> Result<(Proof<F, O>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_virtual_all_mapped_inner::<F, H, O>(trans, pp, identifiers, values, true, encode)
}
fn prove_virtual_all_mapped_inner<F, H, O>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifiers: &[H::Output],
    values: Vec<Vec<F>>,
    strict: bool,
    encode: &mut impl FnMut(H::Output) -> Result<O, Error>,
) -> Result<(Proof<F, O>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if identifiers.len() != pp.rounds()
        || values.len() != pp.rounds()
        || values.iter().enumerate().any(|(i, v)| v.len() != pp.len(i))
    {
        return Err(Error("virtual original geometry"));
    }
    let states: Vec<_> = values
        .into_iter()
        .enumerate()
        .map(|(layer, values)| {
            let values = values.into_iter().map(Field::canonicalized).collect();
            let mut tree = MerkleTree::<H>::new();
            tree.root = identifiers[layer];
            State {
                values,
                tree,
                context: pp.context::<H>(),
                role: Role::Original,
                layer,
            }
        })
        .collect();
    let originals: Vec<_> = states.iter().collect();
    prove_mode_mapped(trans, pp, &originals, strict, Virtual::All, encode)
}
/// Authenticate every projected original pair at (layer, initial-domain index).
/// Empty virtual paths are mandatory; callbacks must check the enclosing roots.
pub(crate) fn verify_virtual_all<F, H, V>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifiers: &[H::Output],
    proof: &Proof<F, H::Output>,
    authenticate: V,
) -> Result<Trace<F>, Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
    V: FnMut(usize, usize, &PairOpening<F, H::Output>) -> Result<(), Error>,
{
    let originals: Vec<_> = identifiers
        .iter()
        .map(|&root| Commitment { root })
        .collect();
    verify_mode::<F, H, V>(trans, pp, &originals, proof, Virtual::All, authenticate)
}
fn prove_mode<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    originals: &[&State<F, H>],
    strict: bool,
    virtual_mode: Virtual,
) -> Result<(Proof<F, H::Output>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    prove_mode_mapped::<F, H, H::Output>(trans, pp, originals, strict, virtual_mode, &mut |h| Ok(h))
}
fn prove_mode_mapped<F, H, O>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    originals: &[&State<F, H>],
    strict: bool,
    virtual_mode: Virtual,
    encode: &mut impl FnMut(H::Output) -> Result<O, Error>,
) -> Result<(Proof<F, O>, Trace<F>), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    if originals.len() != pp.rounds()
        || originals.iter().enumerate().any(|(i, s)| {
            s.role != Role::Original
                || s.layer != i
                || s.context != pp.context::<H>()
                || s.values.len() != pp.len(i)
        })
    {
        return Err(Error("original oracle states or contexts"));
    }
    let roots = originals.iter().map(|s| s.commitment()).collect::<Vec<_>>();
    if matches!(virtual_mode, Virtual::None) {
        bind::<F, H>(trans, pp, &roots)?;
    } else {
        bind_mode::<F, H>(trans, pp, &roots, virtual_mode)?;
    }
    let mut combined = originals[0].values.clone();
    let mut derived = Vec::new();
    let mut terminal = F::zero();
    let mut alphas = Vec::with_capacity(pp.rounds());
    for i in 0..pp.rounds() {
        let alpha = trans.get_challenge(b"rolling FRI fold challenge");
        alphas.push(alpha);
        let next = fold(&combined, pp.shift(i), alpha);
        if i + 1 == pp.rounds() {
            terminal = if matches!(virtual_mode, Virtual::All) {
                next[0].canonicalized()
            } else {
                next[0]
            };
            if strict && next.iter().any(|&v| v != terminal) {
                return Err(Error("nonconstant terminal"));
            }
            trans.append_message(b"rolling FRI terminal", &terminal);
        } else {
            let next = if matches!(virtual_mode, Virtual::All) {
                next.into_iter().map(Field::canonicalized).collect()
            } else {
                next
            };
            let oracle = state::<F, H>(pp, Role::Derived, i + 1, next);
            trans.append_message(b"rolling FRI derived root", &(i + 1, oracle.commitment()));
            combined = oracle
                .values
                .iter()
                .zip(&originals[i + 1].values)
                .map(|(&a, &b)| a + alpha * alpha * b)
                .collect();
            derived.push(oracle);
        }
    }
    let indices = indices(trans, pp);
    let mapped_roots = derived
        .iter()
        .map(|s| {
            Ok(Commitment {
                root: encode(s.tree.root)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let mut queries = Vec::with_capacity(indices.len());
    for &index in &indices {
        let mut original_pairs = Vec::with_capacity(originals.len());
        for (i, s) in originals.iter().enumerate() {
            let pair = if virtual_mode.contains(i) {
                PairOpening {
                    values: [
                        s.values[(index >> i) & !1],
                        s.values[((index >> i) & !1) + 1],
                    ],
                    path: vec![],
                }
            } else {
                opening(s, (index >> i) / 2)
            };
            original_pairs.push(PairOpening {
                values: pair.values,
                path: pair
                    .path
                    .into_iter()
                    .map(&mut *encode)
                    .collect::<Result<Vec<_>, Error>>()?,
            });
        }
        let mut derived_pairs = Vec::with_capacity(derived.len());
        for (i, s) in derived.iter().enumerate() {
            let pair = opening(s, (index >> (i + 1)) / 2);
            derived_pairs.push(PairOpening {
                values: pair.values,
                path: pair
                    .path
                    .into_iter()
                    .map(&mut *encode)
                    .collect::<Result<Vec<_>, Error>>()?,
            });
        }
        queries.push(Query {
            originals: original_pairs,
            derived: derived_pairs,
        });
    }
    Ok((
        Proof {
            derived: mapped_roots,
            terminal,
            queries,
        },
        Trace { alphas, indices },
    ))
}
/// Verify original/derived authentication, squared-domain folds, and terminal.
/// This is proximity testing, not a proof of a multilinear evaluation claim.
pub fn verify<F, H>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    originals: &[Commitment<H::Output>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    verify_mode::<F, H, _>(trans, pp, originals, proof, Virtual::None, |_, _, _| {
        Err(Error("unexpected virtual oracle"))
    })
    .map(|_| ())
}
/// The callback must authenticate the first pair using the original enclosing
/// commitment and compare its linear combination with the virtual pair values.
pub(crate) fn verify_virtual_initial<F, H, V>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    identifier: H::Output,
    following: &[Commitment<H::Output>],
    proof: &Proof<F, H::Output>,
    mut authenticate: V,
) -> Result<Trace<F>, Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
    V: FnMut(usize, &PairOpening<F, H::Output>) -> Result<(), Error>,
{
    let mut originals = vec![Commitment { root: identifier }];
    originals.extend_from_slice(following);
    verify_mode::<F, H, _>(
        trans,
        pp,
        &originals,
        proof,
        Virtual::First,
        |_, index, pair| authenticate(index, pair),
    )
}
fn verify_mode<F, H, V>(
    trans: &mut Transcript<F>,
    pp: &Parameters<F>,
    originals: &[Commitment<H::Output>],
    proof: &Proof<F, H::Output>,
    virtual_mode: Virtual,
    mut authenticate: V,
) -> Result<Trace<F>, Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
    V: FnMut(usize, usize, &PairOpening<F, H::Output>) -> Result<(), Error>,
{
    if matches!(virtual_mode, Virtual::All)
        && (!proof.terminal.is_canonical()
            || proof.queries.iter().any(|q| {
                q.originals
                    .iter()
                    .chain(&q.derived)
                    .any(|p| p.values.iter().any(|v| !v.is_canonical()))
            }))
    {
        return Err(Error("noncanonical virtual-all field encoding"));
    }
    let context = bind_mode::<F, H>(trans, pp, originals, virtual_mode)?;
    let rounds = pp.rounds();
    if proof.derived.len() != rounds - 1
        || proof.queries.len() != pp.queries
        || proof
            .queries
            .iter()
            .any(|q| q.originals.len() != rounds || q.derived.len() != rounds - 1)
    {
        return Err(Error("certificate dimensions"));
    }
    let mut alphas = Vec::with_capacity(rounds);
    for i in 0..rounds {
        alphas.push(trans.get_challenge(b"rolling FRI fold challenge"));
        if i + 1 == rounds {
            trans.append_message(b"rolling FRI terminal", &proof.terminal);
        } else {
            trans.append_message(b"rolling FRI derived root", &(i + 1, &proof.derived[i]));
        }
    }
    let indices = indices(trans, pp);
    for (index, q) in indices.iter().copied().zip(&proof.queries) {
        for i in 0..rounds {
            if virtual_mode.contains(i) {
                if !q.originals[i].path.is_empty() {
                    return Err(Error("virtual oracle supplied Merkle path"));
                }
                authenticate(i, index, &q.originals[i])?;
            } else {
                check_pair_with_context::<F, H>(
                    pp,
                    &context,
                    Role::Original,
                    i,
                    &originals[i],
                    (index >> i) / 2,
                    &q.originals[i],
                )?;
            }
            if i > 0 {
                check_pair_with_context::<F, H>(
                    pp,
                    &context,
                    Role::Derived,
                    i,
                    &proof.derived[i - 1],
                    (index >> i) / 2,
                    &q.derived[i - 1],
                )?;
            }
        }
        for i in 0..rounds {
            let [mut a, mut b] = q.originals[i].values;
            if i > 0 {
                let square = alphas[i - 1] * alphas[i - 1];
                a = q.derived[i - 1].values[0] + square * a;
                b = q.derived[i - 1].values[1] + square * b;
            }
            let pair = (index >> i) & !1;
            let x = point(pp.shift(i), pp.len(i), pair);
            let folded =
                (a + b) / (F::one() + F::one()) + alphas[i] * (a - b) / ((F::one() + F::one()) * x);
            let expected = if i + 1 == rounds {
                proof.terminal
            } else {
                q.derived[i].values[(index >> (i + 1)) & 1]
            };
            if folded != expected {
                return Err(Error("rolling fold mismatch"));
            }
        }
    }
    Ok(Trace { alphas, indices })
}
fn bind<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    roots: &[Commitment<H::Output>],
) -> Result<(), Error> {
    bind_mode::<F, H>(t, pp, roots, Virtual::None).map(|_| ())
}
fn bind_mode<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    roots: &[Commitment<H::Output>],
    virtual_mode: Virtual,
) -> Result<H::Output, Error> {
    if roots.len() != pp.rounds() {
        return Err(Error("expected original root count"));
    }
    let context = pp.context::<H>();
    t.append_message(
        match virtual_mode {
            Virtual::None => b"HasteBoots rolling batch FRI v1".as_slice(),
            Virtual::First => b"HasteBoots rolling batch FRI virtual initial v1".as_slice(),
            Virtual::All => b"HasteBoots rolling batch FRI virtual all v2".as_slice(),
        },
        &(context, roots),
    );
    Ok(context)
}
fn indices<F: Field + Serialize>(t: &mut Transcript<F>, pp: &Parameters<F>) -> Vec<usize> {
    t.get_index_challenges(
        b"rolling FRI unbiased domain index",
        pp.encoded_len(),
        pp.queries,
    )
    .expect("trusted rolling sampling geometry")
}
pub(crate) fn hash<H: Hash, T: Serialize>(value: &T) -> H::Output {
    let mut h = H::new();
    h.update_hash_value(
        &bincode::serde::encode_to_vec(value, bincode::config::standard())
            .expect("serializable FRI data"),
    );
    h.output_reset()
}
fn leaf_with_context<F: Field + Serialize, H: Hash>(
    context: &H::Output,
    role: Role,
    layer: usize,
    index: usize,
    values: &[F; 2],
) -> H::Output {
    hash::<H, _>(&(
        b"rolling FRI pair leaf v1",
        context,
        role,
        layer,
        index,
        values,
    ))
}
fn state<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    role: Role,
    layer: usize,
    values: Vec<F>,
) -> State<F, H> {
    let context = pp.context::<H>();
    let hashes = values
        .chunks_exact(2)
        .enumerate()
        .map(|(j, p)| leaf_with_context::<F, H>(&context, role, layer, j, &[p[0], p[1]]))
        .collect::<Vec<_>>();
    let mut tree = MerkleTree::new();
    tree.generate(&hashes);
    State {
        values,
        tree,
        context,
        role,
        layer,
    }
}
pub(crate) fn opening<F: Field, H: Hash + Send + Sync>(
    s: &State<F, H>,
    index: usize,
) -> PairOpening<F, H::Output> {
    PairOpening {
        values: [s.values[2 * index], s.values[2 * index + 1]],
        path: s.tree.query(index),
    }
}
pub(crate) fn check_pair<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    role: Role,
    layer: usize,
    root: &Commitment<H::Output>,
    index: usize,
    p: &PairOpening<F, H::Output>,
) -> Result<(), Error> {
    check_pair_with_context::<F, H>(pp, &pp.context::<H>(), role, layer, root, index, p)
}
fn check_pair_with_context<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    context: &H::Output,
    role: Role,
    layer: usize,
    root: &Commitment<H::Output>,
    index: usize,
    p: &PairOpening<F, H::Output>,
) -> Result<(), Error> {
    let depth = (pp.len(layer) / 2).ilog2() as usize;
    if p.path.len() != depth + 1 || index >= pp.len(layer) / 2 {
        return Err(Error("pair path dimensions"));
    }
    if p.path[0] != leaf_with_context::<F, H>(context, role, layer, index, &p.values)
        || !MerkleTree::<H>::check(&root.root, index, &p.path)
    {
        return Err(Error("pair authentication"));
    }
    Ok(())
}
fn reverse(index: usize, bits: u32) -> usize {
    if bits == 0 {
        0
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
pub(crate) fn point<F: Field>(shift: F, n: usize, index: usize) -> F {
    power(shift, 2 * reverse(index, n.ilog2()) + 1)
}
fn power<F: Field>(mut base: F, mut exp: usize) -> F {
    let mut out = F::one();
    while exp > 0 {
        if exp & 1 != 0 {
            out *= base;
        }
        base *= base;
        exp >>= 1;
    }
    out
}
// Coefficients -> bit-reversed evaluations on the odd-power coset. DIF avoids
// relying on native NTT plans for the very small squared domains.
pub(crate) fn encode<F: Field>(coefficients: &[F], n: usize, shift: F) -> Vec<F> {
    let mut values = vec![F::zero(); n];
    let mut twist = F::one();
    for (out, &c) in values.iter_mut().zip(coefficients) {
        *out = c * twist;
        twist *= shift;
    }
    let omega = shift * shift;
    let mut len = n;
    while len > 1 {
        let half = len / 2;
        let step = power(omega, n / len);
        for chunk in values.chunks_exact_mut(len) {
            let mut w = F::one();
            for i in 0..half {
                let a = chunk[i];
                let b = chunk[i + half];
                chunk[i] = a + b;
                chunk[i + half] = (a - b) * w;
                w *= step;
            }
        }
        len /= 2;
    }
    values
}
// The coset is in Base, so evaluation commutes with taking polynomial-basis
// coordinates. Retain the generic encoder as an independent arithmetic path.
pub(crate) fn encode_extension<Base: Field, EF: AbstractExtensionField<Base>>(
    coefficients: &[EF],
    n: usize,
    shift: EF,
) -> Vec<EF> {
    let base_shift = shift.as_base_slice()[0];
    debug_assert_eq!(EF::from_base(base_shift), shift);
    let mut columns = Vec::with_capacity(EF::D);
    let mut scratch = vec![Base::zero(); coefficients.len()];
    for coordinate in 0..EF::D {
        let mut nonzero = false;
        for (out, c) in scratch.iter_mut().zip(coefficients) {
            *out = c
                .as_base_slice()
                .get(coordinate)
                .copied()
                .unwrap_or_else(Base::zero);
            nonzero |= *out != Base::zero();
        }
        columns.push(if nonzero {
            Some(encode(&scratch, n, base_shift))
        } else {
            None
        });
    }
    (0..n)
        .map(|i| EF::from_base_fn(|j| columns[j].as_ref().map_or_else(Base::zero, |v| v[i])))
        .collect()
}
fn fold<F: Field>(values: &[F], shift: F, alpha: F) -> Vec<F> {
    let pairs = values.len() / 2;
    let inverse_shift = F::one() / shift;
    let step = inverse_shift * inverse_shift;
    let half = F::one() / (F::one() + F::one());
    let mut powers = Vec::with_capacity(pairs);
    let mut w = inverse_shift;
    for _ in 0..pairs {
        powers.push(w);
        w *= step;
    }
    values
        .chunks_exact(2)
        .enumerate()
        .map(|(i, p)| {
            (p[0] + p[1]) * half + alpha * (p[0] - p[1]) * half * powers[reverse(i, pairs.ilog2())]
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
    fn cached_leaf_context_preserves_preimages_and_hash_count() {
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
                let root = E::from_base(power(native, 32 / (4 * blowup)));
                let pp = Parameters::new(4, blowup, 8, root).unwrap();
                for layer in 0..pp.rounds() {
                    for role in [Role::Original, Role::Derived] {
                        let values: Vec<E> = (0..pp.len(layer))
                            .map(|i| E::from_base_fn(|j| Base::from(17 * i + 29 * j + 1)))
                            .collect();
                        OUTPUTS.store(0, Ordering::Relaxed);
                        let cached = state::<E, Counted>(&pp, role, layer, values.clone());
                        let leaves = values.len() / 2;
                        assert_eq!(OUTPUTS.load(Ordering::Relaxed), 2 * leaves);
                        let hashes: Vec<_> = values
                            .chunks_exact(2)
                            .enumerate()
                            .map(|(index, p)| {
                                // Original owned-context leaf tuple, independently
                                // of leaf_with_context and the cache path.
                                hash::<sha2::Sha512, _>(&(
                                    b"rolling FRI pair leaf v1",
                                    pp.context::<sha2::Sha512>(),
                                    role,
                                    layer,
                                    index,
                                    &[p[0], p[1]],
                                ))
                            })
                            .collect();
                        let mut reference = MerkleTree::<sha2::Sha512>::new();
                        reference.generate(&hashes);
                        assert_eq!(cached.tree.root, reference.root);
                        let context = pp.context::<sha2::Sha512>();
                        OUTPUTS.store(0, Ordering::Relaxed);
                        for index in 0..leaves {
                            assert_eq!(cached.tree.query(index), reference.query(index));
                            check_pair_with_context::<E, Counted>(
                                &pp,
                                &context,
                                role,
                                layer,
                                &cached.commitment(),
                                index,
                                &opening(&cached, index),
                            )
                            .unwrap();
                        }
                        assert_eq!(
                            OUTPUTS.load(Ordering::Relaxed),
                            leaves * cached.tree.query(0).len()
                        );
                    }
                }
            }
        }
        check::<algebra::BabyBear, algebra::BabyBearExtension6>();
        check::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    #[test]
    fn virtual_all_normalizes_and_rejects_lazy_field_bytes() {
        use algebra::Goldilocks as F;
        let root = power(F::generate_ntt_table(6).unwrap().root(), 8);
        let pp = Parameters::new(4, 2, 4, root).unwrap();
        let lazy = F::new(F::MODULUS_VALUE);
        let ids = vec![[17u8; 32]; 2];
        let mut prover = Transcript::new_direct();
        let (proof, _) = prove_virtual_all::<F, Sha256>(
            &mut prover,
            &pp,
            &ids,
            vec![vec![lazy; 8], vec![lazy; 4]],
        )
        .unwrap();
        assert!(proof.terminal.is_canonical());
        assert!(proof.queries.iter().all(|q| {
            q.originals
                .iter()
                .chain(&q.derived)
                .all(|p| p.values.iter().all(|v| v.is_canonical()))
        }));
        let mut verifier = Transcript::new_direct();
        verify_virtual_all::<F, Sha256, _>(&mut verifier, &pp, &ids, &proof, |_, _, p| {
            assert!(p.values.iter().all(|v| *v == F::new(0)));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            prover.get_challenge(b"canonical after"),
            verifier.get_challenge(b"canonical after")
        );
        let mut changed = proof;
        changed.queries[0].originals[0].values[0] = lazy;
        let error = verify_virtual_all::<F, Sha256, _>(
            &mut Transcript::new_direct(),
            &pp,
            &ids,
            &changed,
            |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.0, "noncanonical virtual-all field encoding");
    }
    fn exercise<F: NTTField + Serialize + DeserializeOwned>() {
        let table = F::generate_ntt_table(6).unwrap();
        let root = table.root();
        let c: Vec<F> = (0..64).map(|i| F::from(i * i + 7)).collect();
        let mut native = c.clone();
        table.transform_slice(&mut native);
        assert_eq!(encode(&c, 64, root), native);
        for log in 1..=6 {
            let n = 1 << log;
            let shift = power(root, 64 / n);
            let values = encode(&c[..n], n, shift);
            for (i, &v) in values.iter().enumerate() {
                let x = point(shift, n, i);
                let horner = c[..n].iter().rev().fold(F::zero(), |a, &b| a * x + b);
                assert_eq!(v, horner);
            }
            let alpha = F::from(17usize);
            let folded: Vec<F> = c[..n]
                .chunks_exact(2)
                .map(|p| p[0] + alpha * p[1])
                .collect();
            assert_eq!(
                fold(&values, shift, alpha),
                encode(&folded, n / 2, shift * shift)
            );
        }
        for message in [2, 4, 8, 16] {
            let pp = Parameters::new(message, 64 / message, 64, root).unwrap();
            let states: Vec<_> = (0..pp.rounds())
                .map(|i| {
                    let coefficients: Vec<F> = (0..message >> i)
                        .map(|j| F::from(j * j + 31 * i + 1))
                        .collect();
                    commit_original::<F, Sha256>(&pp, i, &coefficients).unwrap()
                })
                .collect();
            let roots: Vec<_> = states.iter().map(State::commitment).collect();
            let refs: Vec<_> = states.iter().collect();
            let mut prover = Transcript::<F>::new_direct();
            let proof = prove(&mut prover, &pp, &refs).unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (proof, used): (Proof<F, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut verifier = Transcript::<F>::new_direct();
            verify::<F, Sha256>(&mut verifier, &pp, &roots, &proof).unwrap();
            assert_eq!(
                prover.get_challenge(b"after"),
                verifier.get_challenge(b"after")
            );
            let reject = |p: &Proof<F, [u8; 32]>| {
                assert!(verify::<F, Sha256>(&mut Transcript::new_direct(), &pp, &roots, p).is_err())
            };
            let mut bad = proof.clone();
            bad.terminal += F::one();
            reject(&bad);
            let mut bad = proof.clone();
            bad.queries.pop();
            reject(&bad);
            let mut bad = proof.clone();
            bad.queries[0].originals.pop();
            reject(&bad);
            for i in 0..pp.rounds() {
                let mut bad = proof.clone();
                bad.queries[0].originals[i].values[0] += F::one();
                reject(&bad);
                let mut bad = proof.clone();
                bad.queries[0].originals[i].path.clear();
                reject(&bad);
                let mut bad_roots = roots.clone();
                bad_roots[i].root[0] ^= 1;
                assert!(
                    verify::<F, Sha256>(&mut Transcript::new_direct(), &pp, &bad_roots, &proof)
                        .is_err()
                );
            }
            for i in 0..proof.derived.len() {
                let mut bad = proof.clone();
                bad.derived[i].root[0] ^= 1;
                reject(&bad);
                let mut bad = proof.clone();
                bad.queries[0].derived[i].values.swap(0, 1);
                reject(&bad);
                let mut bad = proof.clone();
                bad.queries[0].derived[i].path.pop();
                reject(&bad);
            }
        }
        assert!(Parameters::new(3, 4, 2, root).is_err());
        assert!(Parameters::new(8, 1, 2, root).is_err());
        assert!(Parameters::new(8, 8, 0, root).is_err());
        assert!(Parameters::new(8, 8, 2, F::one()).is_err());

        // A malicious degree-message polynomial, with real trees and openings.
        // Its final fold remains nonconstant. Reject the algebra, not auth.
        let pp = Parameters::new(8, 8, 64, root).unwrap();
        let mut high = vec![F::zero(); 9];
        high[8] = F::one();
        assert!(commit_original::<F, Sha256>(&pp, 0, &high).is_err());
        let mut states = vec![state::<F, Sha256>(
            &pp,
            Role::Original,
            0,
            encode(&high, 64, root),
        )];
        for i in 1..pp.rounds() {
            states.push(commit_original::<F, Sha256>(&pp, i, &[]).unwrap());
        }
        let refs: Vec<_> = states.iter().collect();
        assert_eq!(
            prove(&mut Transcript::new_direct(), &pp, &refs)
                .unwrap_err()
                .0,
            "nonconstant terminal"
        );
        let proof = prove_inner(&mut Transcript::new_direct(), &pp, &refs, false).unwrap();
        let roots: Vec<_> = states.iter().map(State::commitment).collect();
        let mut t = Transcript::<F>::new_direct();
        bind::<F, Sha256>(&mut t, &pp, &roots).unwrap();
        for i in 0..pp.rounds() {
            let _ = t.get_challenge(b"rolling FRI fold challenge");
            if i + 1 == pp.rounds() {
                t.append_message(b"rolling FRI terminal", &proof.terminal);
            } else {
                t.append_message(b"rolling FRI derived root", &(i + 1, &proof.derived[i]));
            }
        }
        for (index, q) in indices(&mut t, &pp).into_iter().zip(&proof.queries) {
            for i in 0..pp.rounds() {
                check_pair::<F, Sha256>(
                    &pp,
                    Role::Original,
                    i,
                    &roots[i],
                    (index >> i) / 2,
                    &q.originals[i],
                )
                .unwrap();
                if i > 0 {
                    check_pair::<F, Sha256>(
                        &pp,
                        Role::Derived,
                        i,
                        &proof.derived[i - 1],
                        (index >> i) / 2,
                        &q.derived[i - 1],
                    )
                    .unwrap();
                }
            }
        }
        assert_eq!(
            verify::<F, Sha256>(&mut Transcript::new_direct(), &pp, &roots, &proof)
                .unwrap_err()
                .0,
            "rolling fold mismatch"
        );
    }
    #[test]
    fn baby_bear() {
        exercise::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks() {
        exercise::<algebra::Goldilocks>();
    }
    fn extension_arithmetic<Base, EF>()
    where
        Base: NTTField,
        EF: algebra::AbstractExtensionField<Base> + Serialize,
    {
        let root = EF::from_base(Base::generate_ntt_table(5).unwrap().root());
        let coefficients: Vec<_> = (0..32)
            .map(|i| EF::from_base_fn(|j| Base::from(i * 17 + j * 29 + 1)))
            .collect();
        let mut t = Transcript::<EF>::new_direct_extension::<Base>();
        for log in 1..=5 {
            let n = 1usize << log;
            let shift = power(root, 32 / n);
            let values = encode(&coefficients[..n], n, shift);
            assert_eq!(
                values,
                encode_extension::<Base, EF>(&coefficients[..n], n, shift)
            );
            assert_eq!(
                encode_extension::<Base, EF>(&[], n, shift),
                vec![EF::zero(); n]
            );
            for (i, &v) in values.iter().enumerate() {
                let x = point(shift, n, i);
                assert_eq!(
                    v,
                    coefficients[..n]
                        .iter()
                        .rev()
                        .fold(EF::zero(), |a, &c| a * x + c)
                );
            }
            let alpha = t.get_challenge(b"extension fold fixture");
            assert!(
                alpha.as_base_slice()[1..]
                    .iter()
                    .any(|&c| c != Base::zero())
            );
            let folded: Vec<_> = coefficients[..n]
                .chunks_exact(2)
                .map(|p| p[0] + alpha * p[1])
                .collect();
            assert_eq!(
                fold(&values, shift, alpha),
                encode(&folded, n / 2, shift * shift)
            );
        }
    }
    #[test]
    fn baby_bear_extension_arithmetic() {
        extension_arithmetic::<algebra::BabyBear, algebra::BabyBearExetension>();
    }
    #[test]
    fn goldilocks_extension_arithmetic() {
        extension_arithmetic::<algebra::Goldilocks, algebra::GoldilocksExtension>();
    }
}
