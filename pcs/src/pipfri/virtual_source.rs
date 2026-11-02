//! Unmasked scalar PipFRI with a virtual combined initial word. Rolling-FRI
//! locations also check public-point folds against authenticated fragment pairs.
//! This changes the protocol and query composition; no security level is claimed.
use super::*;

/// Base-field private source storage with the unchanged extension-field wire.
pub mod base;

/// Explicit opening version, separate from the ordinary reference transcript.
pub const PROTOCOL_VERSION: u32 = 2;
/// No combined-initial Merkle root and no independent consistency query batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Reject cross-version payloads before transcript mutation.
    pub protocol_version: u32,
    /// Fragment evaluations at the common low point; this protocol is unmasked.
    pub fragment_evaluations: Vec<F>,
    /// Actual public-point fold roots, excluding the virtual initial word.
    pub ladder: Vec<Commitment<O>>,
    /// Rolling proof whose first original is authenticated through `sources`.
    pub low_degree: fri::Proof<F, O>,
    /// One authenticated packed fragment pair per rolling sample, in sample order.
    pub sources: Vec<FragmentPair<F, O>>,
}

fn bind<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    point: &[F],
    value: F,
    u: &[F],
) -> Result<F, fri::Error> {
    if point.len() != pp.num_vars() || u.len() != pp.fragments {
        return Err(fri::Error("virtual scalar claim dimensions"));
    }
    if evaluate(u, &point[pp.fri.rounds()..], pp.basis) != value {
        return Err(fri::Error("virtual fragment evaluation aggregation"));
    }
    t.append_message(
        b"unmasked scalar PipFRI virtual v2",
        &(PROTOCOL_VERSION, pp.context::<H>(), root, point, value, u),
    );
    Ok(t.get_challenge(b"virtual PipFRI fragment batch v2"))
}
fn identifier<F: Field + Serialize, H: Hash>(
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    point: &[F],
    gamma: F,
) -> H::Output {
    fri::hash::<H, _>(&(
        b"unmasked PipFRI virtual initial v2".as_slice(),
        pp.context::<H>(),
        root,
        point,
        gamma,
    ))
}
fn combined<F: Field>(pairs: &[[F; 2]], weights: &[F]) -> [F; 2] {
    let mut out = [F::zero(); 2];
    for (pair, &w) in pairs.iter().zip(weights) {
        out[0] += w * pair[0];
        out[1] += w * pair[1];
    }
    out
}

/// Open the same immutable packed-fragment commitment as the ordinary reference.
/// No masks, opening allowances or prover/verifier sessions are introduced.
pub fn open_at<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    source: &State<F, H>,
    point: &[F],
) -> Result<(F, Proof<F, H::Output>), fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let u = fragment_evaluations(pp, root, source, point)?;
    let value = evaluate(&u, &point[pp.fri.rounds()..], pp.basis);
    Ok((value, open_claim(t, pp, root, source, point, value, u)?))
}
fn open_claim<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    source: &State<F, H>,
    point: &[F],
    value: F,
    u: Vec<F>,
) -> Result<Proof<F, H::Output>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let gamma = bind::<F, H>(t, pp, root, point, value, &u)?;
    let weights = powers(gamma, pp.fragments);
    let mut coefficients = vec![F::zero(); pp.fragment_len()];
    let mut virtual_values = vec![F::zero(); pp.fri.encoded_len()];
    for ((c, v), &w) in source.coefficients.iter().zip(&source.values).zip(&weights) {
        for (out, &x) in coefficients.iter_mut().zip(c) {
            *out += w * x;
        }
        for (out, &x) in virtual_values.iter_mut().zip(v) {
            *out += w * x;
        }
    }
    open_prepared::<F, H>(
        t,
        pp,
        root,
        point,
        value,
        u,
        gamma,
        coefficients,
        virtual_values,
        |index| FragmentPair {
            values: pairs(&source.values, index / 2),
            path: source.tree.query(index / 2),
        },
    )
}
fn open_prepared<F, H>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    root: &Commitment<H::Output>,
    point: &[F],
    _value: F,
    u: Vec<F>,
    gamma: F,
    mut coefficients: Vec<F>,
    virtual_values: Vec<F>,
    mut source_pair: impl FnMut(usize) -> FragmentPair<F, H::Output>,
) -> Result<Proof<F, H::Output>, fri::Error>
where
    F: Field + Serialize,
    H: Hash + Send + Sync,
{
    let mut following = Vec::with_capacity(pp.fri.rounds() - 1);
    for (i, &x) in point[..pp.fri.rounds()].iter().enumerate() {
        if i > 0 {
            following.push(fri::commit_original::<F, H>(&pp.fri, i, &coefficients)?);
        }
        coefficients = fold_coefficients(&coefficients, pp.basis.weights(x));
    }
    let ladder = following
        .iter()
        .map(fri::State::commitment)
        .collect::<Vec<_>>();
    t.append_message(b"unmasked virtual PipFRI public roots v2", &ladder);
    let refs = following.iter().collect::<Vec<_>>();
    let (low_degree, trace) = fri::prove_virtual_initial::<F, H>(
        t,
        &pp.fri,
        identifier::<F, H>(pp, root, point, gamma),
        virtual_values,
        &refs,
    )?;
    let sources = trace.indices.into_iter().map(&mut source_pair).collect();
    Ok(Proof {
        protocol_version: PROTOCOL_VERSION,
        fragment_evaluations: u,
        ladder,
        low_degree,
        sources,
    })
}

/// Verify every packed fragment path and public fold at the rolling-FRI samples.
pub fn verify<F, H>(
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
    if proof.protocol_version != PROTOCOL_VERSION
        || proof.ladder.len() + 1 != pp.fri.rounds()
        || proof.sources.len() != pp.fri.queries()
    {
        return Err(fri::Error("virtual scalar version or dimensions"));
    }
    let gamma = bind::<F, H>(t, pp, root, point, value, &proof.fragment_evaluations)?;
    let weights = powers(gamma, pp.fragments);
    t.append_message(b"unmasked virtual PipFRI public roots v2", &proof.ladder);
    let mut seen = 0;
    let trace = fri::verify_virtual_initial::<F, H, _>(
        t,
        &pp.fri,
        identifier::<F, H>(pp, root, point, gamma),
        &proof.ladder,
        &proof.low_degree,
        |index, pair| {
            let source = proof
                .sources
                .get(seen)
                .ok_or(fri::Error("virtual sample schedule"))?;
            seen += 1;
            let position = index / 2;
            if source.values.len() != pp.fragments
                || source.path.len() != (pp.fri.encoded_len() / 2).ilog2() as usize + 1
            {
                return Err(fri::Error("virtual fragment pair dimensions"));
            }
            if source.path[0] != packed_leaf::<F, H>(pp, position, &source.values)
                || !MerkleTree::<H>::check(&root.root, position, &source.path)
            {
                return Err(fri::Error("virtual fragment authentication"));
            }
            if combined(&source.values, &weights) != pair.values {
                return Err(fri::Error("virtual fragment combination"));
            }
            Ok(())
        },
    )?;
    if seen != proof.sources.len() {
        return Err(fri::Error("virtual sample count"));
    }
    let target = proof
        .fragment_evaluations
        .iter()
        .zip(&weights)
        .fold(F::zero(), |s, (&u, &w)| s + u * w);
    let half = F::one() / (F::one() + F::one());
    for (&index, query) in trace.indices.iter().zip(&proof.low_degree.queries) {
        for i in 0..pp.fri.rounds() {
            let [a, b] = query.originals[i].values;
            let x = fri::point(pp.fri.shift(i), pp.fri.len(i), (index >> i) & !1);
            let [w0, w1] = pp.basis.weights(point[i]);
            let folded = w0 * (a + b) * half + w1 * (a - b) * half / x;
            let expected = if i + 1 == pp.fri.rounds() {
                target
            } else {
                query.originals[i + 1].values[(index >> (i + 1)) & 1]
            };
            if folded != expected {
                return Err(fri::Error("virtual public fold mismatch"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hash::Digest512;
    use algebra::{NTTField, transformation::AbstractNTT};
    use serde::de::DeserializeOwned;
    use sha2::Sha512;

    fn tensor<F: Field>(data: &[F], point: &[F], basis: Basis) -> F {
        data.iter().enumerate().fold(F::zero(), |sum, (i, &value)| {
            let weight = point.iter().enumerate().fold(F::one(), |w, (j, &x)| {
                w * if i >> j & 1 == 1 {
                    x
                } else if basis == Basis::Coefficients {
                    F::one()
                } else {
                    F::one() - x
                }
            });
            sum + value * weight
        })
    }
    fn run<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        let mut coins = Transcript::<E>::new_classical_extension::<B>(&[81; 64]);
        for length in [2usize, 8] {
            let bits = (length * 2).ilog2();
            let mut root = B::generate_ntt_table(bits.max(5)).unwrap().root();
            for _ in bits..bits.max(5) {
                root *= root;
            }
            for fragments in [1, 2, 4, 16] {
                for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
                    let pp =
                        Parameters::<E>::new(length, fragments, 2, 8, E::from_base(root), basis)
                            .unwrap()
                            .with_base_field_encoder::<B>()
                            .unwrap();
                    let data = coins.get_vec_challenge(b"full extension source", pp.table_len());
                    let source = super::super::commit::<E, Sha512>(&pp, &data).unwrap();
                    let root = source.commitment();
                    let mut point = coins.get_vec_challenge(b"full extension point", pp.num_vars());
                    for (i, x) in point.iter_mut().enumerate() {
                        if i % 3 == 0 {
                            *x = E::zero();
                        } else if i % 3 == 1 {
                            *x = E::one();
                        }
                    }
                    let expected = tensor(&data, &point, basis);
                    let mut pt = Transcript::<E>::new_classical_extension::<B>(&[82; 64]);
                    let (value, proof) =
                        open_at::<E, Sha512>(&mut pt, &pp, &root, &source, &point).unwrap();
                    assert_eq!(value, expected);
                    assert_eq!(proof.ladder.len() + 1, pp.fri.rounds());
                    assert_eq!(proof.sources.len(), pp.fri.queries());
                    assert!(
                        proof
                            .low_degree
                            .queries
                            .iter()
                            .all(|q| q.originals[0].path.is_empty())
                    );
                    let bytes =
                        bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
                    let (decoded, used): (Proof<E, Digest512>, usize) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                            .unwrap();
                    assert_eq!(used, bytes.len());
                    let mut vt = Transcript::<E>::new_classical_extension::<B>(&[82; 64]);
                    verify::<E, Sha512>(&mut vt, &pp, &root, &point, value, &decoded).unwrap();
                    let mut a = [0; 32];
                    let mut b = [0; 32];
                    pt.get_challenge_bytes(b"after", &mut a);
                    vt.get_challenge_bytes(b"after", &mut b);
                    assert_eq!(a, b);
                    let (old_value, old) = super::super::open_at::<E, Sha512>(
                        &mut Transcript::new_classical_extension::<B>(&[82; 64]),
                        &pp,
                        &root,
                        &source,
                        &point,
                    )
                    .unwrap();
                    assert_eq!(value, old_value);
                    assert_eq!(old.ladder.len(), proof.ladder.len() + 1);
                    assert!(
                        bytes.len()
                            < bincode::serde::encode_to_vec(old, bincode::config::standard())
                                .unwrap()
                                .len()
                    );

                    let rejects = |p: &Proof<E, Digest512>| {
                        assert!(
                            verify::<E, Sha512>(
                                &mut Transcript::new_classical_extension::<B>(&[82; 64]),
                                &pp,
                                &root,
                                &point,
                                value,
                                p,
                            )
                            .is_err()
                        )
                    };
                    let mut bad = decoded.clone();
                    bad.protocol_version = 1;
                    rejects(&bad);
                    let mut bad = decoded.clone();
                    bad.sources.pop();
                    rejects(&bad);
                    let mut bad = decoded.clone();
                    bad.sources[0].path.clear();
                    rejects(&bad);
                    let mut bad = decoded.clone();
                    bad.sources[0].values.pop();
                    rejects(&bad);
                    let mut bad = decoded.clone();
                    bad.sources[0].values[0][0] += E::one();
                    rejects(&bad);
                    let mut bad = decoded.clone();
                    bad.low_degree.queries[0].originals[0].values[0] += E::one();
                    // Genuine packed source paths cannot authenticate a
                    // separately chosen virtual initial pair. Check the
                    // coupling itself rejects before any rolling equation.
                    let error = verify::<E, Sha512>(
                        &mut Transcript::new_classical_extension::<B>(&[82; 64]),
                        &pp,
                        &root,
                        &point,
                        value,
                        &bad,
                    )
                    .unwrap_err();
                    assert!(error.0.contains("virtual fragment combination"), "{error}");
                    let mut bad = decoded.clone();
                    bad.low_degree.queries[0].originals[0]
                        .path
                        .push(Digest512::default());
                    rejects(&bad);
                    if !decoded.ladder.is_empty() {
                        let mut bad = decoded.clone();
                        bad.ladder[0].root.0[0] ^= 1;
                        rejects(&bad);
                    }
                    // Freshly bind a false vector of fragment evaluations while
                    // retaining genuine source words, public folds and paths.
                    let mut false_u = fragment_evaluations(&pp, &root, &source, &point).unwrap();
                    false_u[0] += E::one();
                    // Pick a high point at zero so fragment zero has weight one
                    // in both bases; a different claim is then guaranteed.
                    let mut false_point = point.clone();
                    false_point[pp.fri.rounds()..].fill(E::zero());
                    let actual = tensor(&data, &false_point, basis);
                    let false_value = evaluate(&false_u, &false_point[pp.fri.rounds()..], basis);
                    assert_ne!(actual, false_value);
                    let forged = open_claim::<E, Sha512>(
                        &mut Transcript::new_classical_extension::<B>(&[83; 64]),
                        &pp,
                        &root,
                        &source,
                        &false_point,
                        false_value,
                        false_u,
                    )
                    .unwrap();
                    let error = verify::<E, Sha512>(
                        &mut Transcript::new_classical_extension::<B>(&[83; 64]),
                        &pp,
                        &root,
                        &false_point,
                        false_value,
                        &forged,
                    )
                    .unwrap_err();
                    assert!(error.0.contains("virtual public fold mismatch"), "{error}");
                }
            }
        }
    }
    #[test]
    fn babybear_unmasked_virtual_source() {
        run::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_unmasked_virtual_source() {
        run::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
