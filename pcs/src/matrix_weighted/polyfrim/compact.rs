//! Lossless Merkle-hash dictionaries for a distinct trusted PolyFRIM backend.
//!
//! All independent samples, paths, roots and field elements remain present after
//! expansion. This codec neither changes the checking equations nor supplies a
//! proximity/Fiat-Shamir/security theorem for the underlying research protocol.
use super::{Error, State, hash};
use crate::{
    matrix_weighted::{Commitment, backend::CanonicalPcs},
    packed_polyfrim::authenticated as core,
    rolling_fri as fri,
    utils::hash::Hash,
};
use algebra::{
    AbstractExtensionField, NTTField,
    matrix_weighted::{MatrixPair, PackedTable},
};
use helper::Transcript;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash as KeyHash,
};

/// Canonical dictionary in first-use order plus the unchanged indexed packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Unique hashes, in the traversal order specified by the codec.
    pub hashes: Vec<O>,
    /// Original proof shape and field values; every hash is a dictionary index.
    pub inner: super::Proof<F, u32>,
}
struct Dictionary<O> {
    hashes: Vec<O>,
    positions: HashMap<O, u32>,
}
impl<O: Copy + Eq + KeyHash> Dictionary<O> {
    fn new() -> Self {
        Self {
            hashes: Vec::new(),
            positions: HashMap::new(),
        }
    }
    fn intern(&mut self, value: O) -> Result<u32, Error> {
        if let Some(&index) = self.positions.get(&value) {
            return Ok(index);
        }
        let index =
            u32::try_from(self.hashes.len()).map_err(|_| Error("compact hash count overflow"))?;
        self.hashes.push(value);
        self.positions.insert(value, index);
        Ok(index)
    }
}
impl<F: Clone, O: Copy + Eq + KeyHash> Proof<F, O> {
    /// Replace repeated hashes without dropping any independent query draw.
    pub fn compress(proof: super::Proof<F, O>) -> Result<Self, Error> {
        let mut dictionary = Dictionary::new();
        let inner = map_packet(proof, &mut |value| dictionary.intern(value))?;
        Ok(Self {
            hashes: dictionary.hashes,
            inner,
        })
    }
    /// Recover the exact full packet. Reject unused, duplicate, out-of-range or
    /// noncanonical first-use entries before the verification transcript changes.
    pub fn expand(&self) -> Result<super::Proof<F, O>, Error> {
        let mut next = 0usize;
        let mut seen = HashSet::new();
        let full = map_packet(self.inner.clone(), &mut |index| {
            let index = index as usize;
            let value = self
                .hashes
                .get(index)
                .copied()
                .ok_or(Error("compact hash index"))?;
            if index > next {
                return Err(Error("compact hash first-use order"));
            }
            if index == next {
                if !seen.insert(value) {
                    return Err(Error("duplicate compact hash"));
                }
                next += 1;
            }
            Ok(value)
        })?;
        if next != self.hashes.len() {
            return Err(Error("unused compact hashes"));
        }
        Ok(full)
    }
}
fn path<O, T>(values: Vec<O>, f: &mut impl FnMut(O) -> Result<T, Error>) -> Result<Vec<T>, Error> {
    values.into_iter().map(f).collect()
}
fn packed_pair<F, O, T>(
    p: core::Pair<F, O>,
    f: &mut impl FnMut(O) -> Result<T, Error>,
) -> Result<core::Pair<F, T>, Error> {
    Ok(core::Pair {
        values: p.values,
        path: path(p.path, f)?,
    })
}
fn scalar_pair<F, O, T>(
    p: fri::PairOpening<F, O>,
    f: &mut impl FnMut(O) -> Result<T, Error>,
) -> Result<fri::PairOpening<F, T>, Error> {
    Ok(fri::PairOpening {
        values: p.values,
        path: path(p.path, f)?,
    })
}
// A single traversal implements both directions, fixing a unique spelling:
// consistency roots/paths, FRI roots/paths, then packed projection paths.
pub(super) fn map_packet<F, O, T>(
    p: super::Proof<F, O>,
    f: &mut impl FnMut(O) -> Result<T, Error>,
) -> Result<super::Proof<F, T>, Error> {
    let consistency = p
        .consistency
        .into_iter()
        .map(|p| {
            Ok(core::Proof {
                roots: path(p.roots, f)?,
                queries: p
                    .queries
                    .into_iter()
                    .map(|q| q.into_iter().map(|p| packed_pair(p, f)).collect())
                    .collect::<Result<_, Error>>()?,
            })
        })
        .collect::<Result<_, Error>>()?;
    let proximity = fri::Proof {
        derived: p
            .proximity
            .derived
            .into_iter()
            .map(|c| Ok(fri::Commitment { root: f(c.root)? }))
            .collect::<Result<_, Error>>()?,
        terminal: p.proximity.terminal,
        queries: p
            .proximity
            .queries
            .into_iter()
            .map(|q| {
                Ok(fri::Query {
                    originals: q
                        .originals
                        .into_iter()
                        .map(|p| scalar_pair(p, f))
                        .collect::<Result<_, Error>>()?,
                    derived: q
                        .derived
                        .into_iter()
                        .map(|p| scalar_pair(p, f))
                        .collect::<Result<_, Error>>()?,
                })
            })
            .collect::<Result<_, Error>>()?,
    };
    let packed = p
        .packed
        .into_iter()
        .map(|q| {
            q.into_iter()
                .map(|layers| layers.into_iter().map(|p| packed_pair(p, f)).collect())
                .collect()
        })
        .collect::<Result<_, Error>>()?;
    Ok(super::Proof {
        consistency,
        proximity,
        packed,
    })
}

/// Trusted compact backend. Source ownership and arithmetic are unchanged;
/// its public context and canonical relation domains differ from the full format.
#[derive(Clone, Debug, Serialize)]
pub struct Parameters<F, E> {
    inner: super::Parameters<F, E>,
}
impl<F, E> Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize,
{
    /// Select the same explicit source geometry as the uncompressed backend.
    pub fn new(
        variables: usize,
        width: usize,
        blowup: usize,
        queries: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: super::Parameters::new(variables, width, blowup, queries)?,
        })
    }
    /// Opt into parallel source/oracle encoding without changing the wire format.
    pub fn with_parallel_oracles(mut self) -> Self {
        self.inner = self.inner.with_parallel_oracles();
        self
    }
    /// Original logical Boolean variables.
    pub fn num_vars(&self) -> usize {
        self.inner.num_vars()
    }
    /// Original consecutive lane count.
    pub fn width(&self) -> usize {
        self.inner.width()
    }
    /// Bind the dictionary format, both fields and original trusted geometry.
    pub fn context_digest<H: Hash>(&self) -> H::Output {
        hash::<H, _>(&(
            b"compact unmasked packed matrix parameters v1".as_slice(),
            self.inner.context_digest::<H>(),
        ))
    }
    /// Deterministically commit the same original source; no masks are added.
    pub fn commit<H: Hash + Send + Sync>(
        &self,
        table: &PackedTable<F>,
    ) -> Result<(Commitment<H::Output>, State<F, E, H>), Error> {
        self.inner.commit::<H>(table)
    }
    /// Authenticate every ordered claim and emit canonical dictionary indices
    /// directly, without retaining an intermediate full-hash packet.
    pub fn open_many<H: Hash + Send + Sync>(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &State<F, E, H>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
    ) -> Result<Proof<E, H::Output>, Error>
    where
        H::Output: Eq + KeyHash,
    {
        let mut dictionary = Dictionary::new();
        let inner = self.inner.open_context_mapped::<H, u32>(
            t,
            root,
            state,
            queries,
            values,
            self.context_digest::<H>(),
            &mut |value| dictionary.intern(value),
        )?;
        Ok(Proof {
            hashes: dictionary.hashes,
            inner,
        })
    }
    /// Expand canonical paths and run the unchanged strict full-packet verifier.
    pub fn verify_many<H: Hash + Send + Sync>(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        queries: &[Vec<MatrixPair<F>>],
        values: &[Vec<F>],
        proof: &Proof<E, H::Output>,
    ) -> Result<(), Error>
    where
        H::Output: Eq + KeyHash,
    {
        self.check_shape(queries.len(), proof)?;
        let expanded = proof.expand()?;
        self.inner.verify_context::<H>(
            t,
            root,
            queries,
            values,
            &expanded,
            self.context_digest::<H>(),
        )
    }

    // Validate borrowed lengths before expand clones any proof-owned vectors.
    // The full verifier retains all semantic/authentication checks afterward.
    fn check_shape<O>(&self, claims: usize, proof: &Proof<E, O>) -> Result<(), Error> {
        let (rounds, width, domain_log, samples) = self.inner.inner.proof_geometry();
        let packet = &proof.inner;
        if packet.consistency.len() != claims
            || packet.packed.len() != samples
            || packet.proximity.derived.len() != rounds - 1
            || packet.proximity.queries.len() != samples
        {
            return Err(Error("compact certificate shape"));
        }
        let pair_ok = |layer: usize, pair: &core::Pair<E, u32>| {
            pair.values.len() == 2 * width && pair.path.len() == domain_log - layer
        };
        for member in &packet.consistency {
            if member.roots.len() != rounds - 1
                || member.queries.len() != samples
                || member.queries.iter().any(|q| {
                    q.len() != rounds || q.iter().enumerate().any(|(layer, p)| !pair_ok(layer, p))
                })
            {
                return Err(Error("compact certificate shape"));
            }
        }
        if packet.packed.iter().any(|sample| {
            sample.len() != claims
                || sample.iter().any(|member| {
                    member.len() != rounds
                        || member
                            .iter()
                            .enumerate()
                            .any(|(layer, p)| !pair_ok(layer, p))
                })
        }) || packet.proximity.queries.iter().any(|q| {
            q.originals.len() != rounds
                || q.derived.len() != rounds - 1
                || q.originals.iter().any(|p| !p.path.is_empty())
                || q.derived
                    .iter()
                    .enumerate()
                    .any(|(layer, p)| p.path.len() != domain_log - layer - 1)
        }) {
            return Err(Error("compact certificate shape"));
        }
        // Every canonical dictionary entry is used by at least one reference.
        // Saturation preserves compatibility for oversized trusted parameters;
        // it is not a new query-count limit or a protocol resource allowance.
        let all_paths: usize = (0..rounds).map(|i| domain_log - i).sum();
        let derived_paths: usize = (1..rounds).map(|i| domain_log - i).sum();
        let references = claims
            .saturating_add(1)
            .saturating_mul(rounds - 1)
            .saturating_add(
                samples
                    .saturating_mul(claims)
                    .saturating_mul(all_paths)
                    .saturating_mul(2),
            )
            .saturating_add(samples.saturating_mul(derived_paths));
        if proof.hashes.len() > references {
            return Err(Error("compact dictionary shape"));
        }
        Ok(())
    }
}
impl<F, E, H> CanonicalPcs<F, H> for Parameters<F, E>
where
    F: NTTField + Serialize,
    E: AbstractExtensionField<F> + Serialize,
    H: Hash + Send + Sync,
    H::Output: Eq + KeyHash,
{
    type State = State<F, E, H>;
    type SingleProof = Proof<E, H::Output>;
    type BatchProof = Proof<E, H::Output>;
    type Error = Error;
    const LINEAR_DOMAIN: &'static [u8] = b"compact unmasked packed canonical linear v1";
    const NTT_DOMAIN: &'static [u8] = b"compact unmasked packed tensor NTT v1";
    const RELATION_DOMAIN: &'static [u8] = b"HasteBoots compact unmasked packed relation v1";
    const ACCUMULATOR_DOMAIN: &'static [u8] = b"compact unmasked packed accumulator v1";
    const REGISTRY_DOMAIN: &'static [u8] = b"compact unmasked packed registry v1";
    const CLAIM_DOMAIN: &'static [u8] = b"compact unmasked packed claim v1";
    const SEAL_DOMAIN: &'static [u8] = b"compact unmasked packed seal v1";
    fn num_vars(&self) -> usize {
        self.num_vars()
    }
    fn width(&self) -> usize {
        self.width()
    }
    fn context(&self) -> Result<H::Output, Error> {
        Ok(self.context_digest::<H>())
    }
    fn normalize_claim(
        &self,
        q: Vec<MatrixPair<F>>,
        v: Vec<F>,
    ) -> Result<(Vec<MatrixPair<F>>, Vec<F>), Error> {
        CanonicalPcs::<F, H>::normalize_claim(&self.inner, q, v)
    }
    fn normalize_values(&self, v: Vec<F>) -> Vec<F> {
        CanonicalPcs::<F, H>::normalize_values(&self.inner, v)
    }
    fn validate_values(&self, v: &[F]) -> Result<(), Error> {
        CanonicalPcs::<F, H>::validate_values(&self.inner, v)
    }
    fn commit<R: Rng + CryptoRng>(
        &self,
        table: &PackedTable<F>,
        _rng: &mut R,
    ) -> Result<(Commitment<H::Output>, Self::State), Error> {
        self.commit::<H>(table)
    }
    fn table(state: &Self::State) -> &PackedTable<F> {
        state.table()
    }
    fn open(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[MatrixPair<F>],
        v: &[F],
    ) -> Result<Self::SingleProof, Error> {
        self.open_many::<H>(t, root, state, &[q.to_vec()], &[v.to_vec()])
    }
    fn verify(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[MatrixPair<F>],
        v: &[F],
        p: &Self::SingleProof,
    ) -> Result<(), Error> {
        self.verify_many::<H>(t, root, &[q.to_vec()], &[v.to_vec()], p)
    }
    fn open_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        state: &Self::State,
        q: &[Vec<MatrixPair<F>>],
        v: &[Vec<F>],
    ) -> Result<Self::BatchProof, Error> {
        self.open_many::<H>(t, root, state, q, v)
    }
    fn verify_many(
        &self,
        t: &mut Transcript<F>,
        root: &Commitment<H::Output>,
        q: &[Vec<MatrixPair<F>>],
        v: &[Vec<F>],
        p: &Self::BatchProof,
    ) -> Result<(), Error> {
        self.verify_many::<H>(t, root, q, v, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::matrix_weighted::Matrix;
    use helper::FiatShamirTranscript;
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

    fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
        bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap()
    }
    fn after<F: algebra::Field>(t: &mut Transcript<F>) -> [u8; 32] {
        let mut out = [0; 32];
        t.get_challenge_bytes(b"compact adapter after", &mut out);
        out
    }
    fn exercise<F, E>()
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        let pp = Parameters::<F, E>::new(3, 2, 2, 8).unwrap();
        let full = super::super::Parameters::<F, E>::new(3, 2, 2, 8).unwrap();
        let table =
            PackedTable::new(3, 2, (0..16).map(|i| F::from(i * i + 3 * i + 7)).collect()).unwrap();
        let (root, state) = pp.commit::<Sha256>(&table).unwrap();
        let (same, _) = full.commit::<Sha256>(&table).unwrap();
        assert_eq!(root.root, same.root);
        assert_ne!(
            pp.context_digest::<Sha256>(),
            full.context_digest::<Sha256>()
        );
        for count in [1, 4, 16] {
            let queries: Vec<Vec<_>> = (0..count)
                .map(|member| {
                    (0..3)
                        .map(|r| MatrixPair {
                            zero: Matrix::new(
                                2,
                                (0..4)
                                    .map(|i| F::from(7 * member + 13 * r + i + 1))
                                    .collect(),
                            )
                            .unwrap(),
                            one: Matrix::new(
                                2,
                                (0..4)
                                    .map(|i| F::from(11 * member + 3 * r + 2 * i + 3))
                                    .collect(),
                            )
                            .unwrap(),
                        })
                        .collect()
                })
                .collect();
            let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
            let mut pt = Transcript::new_direct();
            let proof = pp
                .open_many::<Sha256>(&mut pt, &root, &state, &queries, &values)
                .unwrap();
            let mut reference_t = Transcript::new_direct();
            let reference = pp
                .inner
                .open_context::<Sha256>(
                    &mut reference_t,
                    &root,
                    &state,
                    &queries,
                    &values,
                    pp.context_digest::<Sha256>(),
                )
                .unwrap();
            assert_eq!(bytes(&reference), bytes(&proof.expand().unwrap()));
            assert_eq!(
                bytes(&proof),
                bytes(&Proof::compress(reference.clone()).unwrap())
            );
            assert!(bytes(&proof).len() < bytes(&reference).len());
            assert_eq!(after(&mut pt), after(&mut reference_t));
            let wire = bytes(&proof);
            let (decoded, used): (Proof<E, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&wire, bincode::config::standard()).unwrap();
            assert_eq!(used, wire.len());
            let mut vt = Transcript::new_direct();
            pp.verify_many::<Sha256>(&mut vt, &root, &queries, &values, &decoded)
                .unwrap();
            let mut replay = Transcript::new_direct();
            pp.inner
                .verify_context::<Sha256>(
                    &mut replay,
                    &root,
                    &queries,
                    &values,
                    &reference,
                    pp.context_digest::<Sha256>(),
                )
                .unwrap();
            assert_eq!(after(&mut vt), after(&mut replay));
            assert!(
                full.verify_many::<Sha256>(
                    &mut Transcript::new_direct(),
                    &root,
                    &queries,
                    &values,
                    &reference
                )
                .is_err()
            );
            let reject_early = |p: &Proof<E, [u8; 32]>| {
                let mut t = Transcript::new_direct();
                assert!(
                    pp.verify_many::<Sha256>(&mut t, &root, &queries, &values, p)
                        .is_err()
                );
                assert_eq!(after(&mut t), after(&mut Transcript::<F>::new_direct()));
            };
            let reject_shape = |p: &Proof<E, [u8; 32]>, label: &str| {
                let mut t = Transcript::new_direct();
                let error = pp
                    .verify_many::<Sha256>(&mut t, &root, &queries, &values, p)
                    .unwrap_err();
                assert_eq!(error.0, label);
                assert_eq!(after(&mut t), after(&mut Transcript::<F>::new_direct()));
            };
            let mut bad = decoded.clone();
            bad.inner.consistency[0].queries.pop();
            bad.inner.consistency[0].roots[0] = u32::MAX;
            reject_shape(&bad, "compact certificate shape");
            let mut bad = decoded.clone();
            bad.inner.packed[0][0][0].values.push(E::zero());
            reject_shape(&bad, "compact certificate shape");
            let mut bad = decoded.clone();
            bad.inner.proximity.queries[0].originals[0]
                .path
                .push(u32::MAX);
            reject_shape(&bad, "compact certificate shape");
            let mut bad = decoded.clone();
            bad.inner.consistency[0].queries[0][0].path.push(u32::MAX);
            reject_shape(&bad, "compact certificate shape");
            let mut references = 0;
            map_packet(decoded.inner.clone(), &mut |index| {
                references += 1;
                Ok(index)
            })
            .unwrap();
            let mut bad = decoded.clone();
            bad.hashes.resize(references + 1, [0; 32]);
            reject_shape(&bad, "compact dictionary shape");
            let mut bad = decoded.clone();
            bad.inner.consistency[0].roots[0] = u32::MAX;
            reject_early(&bad);
            let mut bad = decoded.clone();
            bad.hashes.push([0; 32]);
            reject_early(&bad);
            let mut bad = decoded.clone();
            bad.hashes[1] = bad.hashes[0];
            reject_early(&bad);
            // Equivalent hashes/paths with a different dictionary order are
            // still rejected: accepted packets have a unique first-use order.
            let mut bad = decoded.clone();
            bad.hashes.swap(0, 1);
            bad.inner = map_packet(bad.inner, &mut |index| {
                Ok(match index {
                    0 => 1,
                    1 => 0,
                    x => x,
                })
            })
            .unwrap();
            reject_early(&bad);
            let mut bad = decoded.clone();
            bad.hashes[0][0] ^= 1;
            assert!(
                pp.verify_many::<Sha256>(
                    &mut Transcript::new_direct(),
                    &root,
                    &queries,
                    &values,
                    &bad
                )
                .is_err()
            );
            let mut wrong = values.clone();
            wrong[count - 1][0] += F::one();
            let mut t = Transcript::new_direct();
            assert!(
                pp.open_many::<Sha256>(&mut t, &root, &state, &queries, &wrong)
                    .is_err()
            );
            assert_eq!(after(&mut t), after(&mut Transcript::<F>::new_direct()));
        }
    }
    #[test]
    fn babybear_dictionary_roundtrip_and_rejection() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_dictionary_roundtrip_and_rejection() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    fn classical_emission<F, E>()
    where
        F: NTTField + Serialize,
        E: AbstractExtensionField<F> + Serialize + DeserializeOwned,
    {
        use crate::utils::hash::Digest512;
        use sha2::Sha512;
        for (vars, width, blowup) in
            [(0, 1), (0, 4), (3, 2), (4, 4)]
                .into_iter()
                .flat_map(|(vars, width)| {
                    [2, 4, 8]
                        .into_iter()
                        .map(move |blowup| (vars, width, blowup))
                })
        {
            let pp = Parameters::<F, E>::new(vars, width, blowup, 8).unwrap();
            let reference = pp.inner.clone().with_extension_storage_reference();
            let table = PackedTable::new(
                vars,
                width,
                (0..(width << vars))
                    .map(|i| F::from(i * i + 7 * i + 3))
                    .collect(),
            )
            .unwrap();
            let (root, state) = pp.commit::<Sha512>(&table).unwrap();
            let (old_root, old_state) = reference.commit::<Sha512>(&table).unwrap();
            assert_eq!(root.root, old_root.root);
            for count in [1, 4, 16] {
                let mut coins = Transcript::<F>::new_classical(&[71; 64]);
                let mut queries: Vec<Vec<_>> = (0..count)
                    .map(|_| {
                        (0..vars)
                            .map(|_| {
                                let v = coins.get_vec_challenge(
                                    b"dense compact matrices",
                                    2 * width * width,
                                );
                                MatrixPair {
                                    zero: Matrix::new(width, v[..width * width].to_vec()).unwrap(),
                                    one: Matrix::new(width, v[width * width..].to_vec()).unwrap(),
                                }
                            })
                            .collect()
                    })
                    .collect();
                if vars > 1 {
                    for i in 1..count {
                        for j in 0..(if i % 2 == 0 { vars - 1 } else { 1 }) {
                            queries[i][j] = queries[0][j].clone();
                        }
                    }
                }
                let values: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
                let mut pt = Transcript::<F>::new_classical(&[72; 64]);
                let proof = pp
                    .open_many::<Sha512>(&mut pt, &root, &state, &queries, &values)
                    .unwrap();
                let mut rt = Transcript::<F>::new_classical(&[72; 64]);
                let full = reference
                    .open_context::<Sha512>(
                        &mut rt,
                        &old_root,
                        &old_state,
                        &queries,
                        &values,
                        pp.context_digest::<Sha512>(),
                    )
                    .unwrap();
                let compressed = Proof::compress(full.clone()).unwrap();
                assert_eq!(bytes(&proof), bytes(&compressed));
                assert_eq!(bytes(&proof.expand().unwrap()), bytes(&full));
                assert_eq!(after(&mut pt), after(&mut rt));
                let wire = bytes(&proof);
                let (decoded, used): (Proof<E, Digest512>, usize) =
                    bincode::serde::decode_from_slice(&wire, bincode::config::standard()).unwrap();
                assert_eq!(used, wire.len());
                pp.verify_many::<Sha512>(
                    &mut Transcript::new_classical(&[72; 64]),
                    &root,
                    &queries,
                    &values,
                    &decoded,
                )
                .unwrap();
            }
        }
    }
    #[test]
    fn babybear_classical_direct_emission_matches_reference() {
        classical_emission::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_classical_direct_emission_matches_reference() {
        classical_emission::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
