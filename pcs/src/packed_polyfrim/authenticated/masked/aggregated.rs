//! Experimental masked batches sharing original-source and query-ladder FRI.
//!
//! Every virtual source is authenticated against the original paired oracle.
//! Opening allowances and the original numerical disclosure guard are retained.
//! This is not a robust proximity, adaptive hiding or full-security theorem.
use super::super::proximity::batch;
use super::*;

/// Two rolling certificates: original paired source, then all masked ladders.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// First reserved mask-session index.
    pub first: usize,
    /// Ordered independent-mask responses, one per caller-supplied query.
    pub mask_claims: Vec<Vec<F>>,
    /// Shared original paired-source proximity certificate.
    pub source_proximity: rolling_fri::Proof<F, O>,
    /// Original packed paths authenticating that source projection.
    pub source_pairs: Vec<Pair<F, O>>,
    /// Matrix consistency ladders and one jointly projected rolling FRI.
    pub inner: batch::Proof<F, O>,
    /// Actual source paths for each member's consistency samples.
    pub consistency_sources: Vec<Vec<Pair<F, O>>>,
    /// Actual source paths shared by all members at each joint FRI sample.
    pub proximity_sources: Vec<Pair<F, O>>,
}
fn schedule<F>(pp: &Parameters<F>, first: usize, count: usize) -> Result<(), Error> {
    if count == 0
        || first
            .checked_add(count)
            .is_none_or(|end| end > pp.max_openings)
    {
        return Err(Error("aggregated masked schedule or exhausted lifetime"));
    }
    Ok(())
}
fn begin<F: Field + Serialize, O: Serialize>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &O,
    first: usize,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    masks: &[Vec<F>],
) {
    t.append_message(
        b"masked packed aggregated query batch v1",
        &(pp, source, first, queries.len(), queries, claims, masks),
    );
}
fn finish<F: Field>(t: &mut Transcript<F>, first: usize, count: usize) {
    t.append_message(b"masked packed aggregated query finish v1", &(first, count));
}
fn source_pair<F: Field + Serialize, H: Hash + Send + Sync>(
    pp: &Parameters<F>,
    source: &super::super::State<F, H>,
    index: usize,
) -> Pair<F, H::Output> {
    let position = index / 2;
    let width = 2 * pp.width;
    Pair {
        values: source.values()[position * 2 * width..(position + 1) * 2 * width].to_vec(),
        path: source.tree.query(position),
    }
}
/// Preflight the complete ordered batch, reserve every allowance, then prove.
/// Any later Result error keeps the reservation and releases transient caches.
pub fn prove<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    session: &mut ProverSession<F, H>,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
) -> Result<Proof<F, H::Output>, Error> {
    let first = session.spent;
    schedule(pp, first, queries.len())?;
    if queries.len() != claims.len() {
        return Err(Error("aggregated masked claim count"));
    }
    let prepared = queries
        .iter()
        .zip(claims)
        .map(|(q, c)| prepare(pp, session, q, c))
        .collect::<Result<Vec<_>, _>>()?;
    session.spent += prepared.len();
    let result = (|| {
        let queries: Vec<_> = prepared.iter().map(|p| p.query.clone()).collect();
        let claims: Vec<_> = prepared.iter().map(|p| p.claim.clone()).collect();
        let mask_claims: Vec<_> = prepared.iter().map(|p| p.mask_claim.clone()).collect();
        begin(
            t,
            pp,
            &session.root(),
            first,
            &queries,
            &claims,
            &mask_claims,
        );
        let (source_proximity, source_pairs) = source_prove::<F, H>(t, pp, &session.source, first)?;
        let alphas =
            t.get_vec_challenge(b"masked aggregated source combinations v1", queries.len());
        let oracle = pp.oracle(false);
        let virtual_sources: Vec<_> = alphas
            .iter()
            .enumerate()
            .map(|(i, &alpha)| {
                let coefficients = session
                    .source
                    .polynomial
                    .coefficients
                    .chunks_exact(2 * pp.width)
                    .flat_map(|v| {
                        v[..pp.width]
                            .iter()
                            .zip(&v[pp.width..])
                            .map(|(&p, &s)| (p + alpha * s).canonicalized())
                    })
                    .collect();
                let values: Vec<_> = session
                    .source
                    .values()
                    .chunks_exact(2 * pp.width)
                    .flat_map(|v| {
                        v[..pp.width]
                            .iter()
                            .zip(&v[pp.width..])
                            .map(|(&p, &s)| (p + alpha * s).canonicalized())
                    })
                    .collect();
                let mut tree = MerkleTree::<H>::new();
                tree.root = identifier::<F, H>(pp, &session.root(), first + i, alpha);
                super::super::State {
                    polynomial: Polynomial {
                        width: pp.width,
                        coefficients,
                    },
                    values: std::sync::OnceLock::from(values),
                    encoding: oracle.clone(),
                    tree,
                    context: hash::<H, _>(&(b"packed PolyFRIM parameters v2", &oracle)),
                    layer: 0,
                }
            })
            .collect();
        let sources: Vec<_> = virtual_sources.iter().collect();
        let padded: Vec<_> = prepared.iter().map(|p| p.padded.clone()).collect();
        let combined: Vec<Vec<_>> = claims
            .iter()
            .zip(&mask_claims)
            .zip(&alphas)
            .map(|((c, m), &alpha)| {
                c.iter()
                    .zip(m)
                    .map(|(&c, &m)| (c + alpha * m).canonicalized())
                    .collect()
            })
            .collect();
        let (inner, trace) = batch::prove_sources::<F, H>(
            t,
            &oracle,
            &session.root(),
            &sources,
            &padded,
            &combined,
        )?;
        let consistency_sources = trace
            .consistency
            .iter()
            .map(|indices| {
                indices
                    .iter()
                    .map(|&index| source_pair(pp, &session.source, index))
                    .collect()
            })
            .collect();
        let proximity_sources = trace
            .proximity
            .iter()
            .map(|&index| source_pair(pp, &session.source, index))
            .collect();
        finish(t, first, queries.len());
        Ok(Proof {
            first,
            mask_claims,
            source_proximity,
            source_pairs,
            inner,
            consistency_sources,
            proximity_sources,
        })
    })();
    session.evict_if_transient();
    result
}
/// Verify the original source, every virtual source and the shared ladder FRI.
/// The root and all ordered public queries/claims are trusted caller inputs.
pub fn verify<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error> {
    schedule(pp, proof.first, queries.len())?;
    let count = queries.len();
    if claims.len() != count
        || proof.mask_claims.len() != count
        || proof.mask_claims.iter().any(|m| m.len() != pp.width)
        || proof.source_pairs.len() != pp.queries
        || proof.consistency_sources.len() != count
        || proof
            .consistency_sources
            .iter()
            .any(|s| s.len() != pp.queries)
        || proof.proximity_sources.len() != pp.queries
    {
        return Err(Error("aggregated masked certificate shape"));
    }
    if proof
        .mask_claims
        .iter()
        .flatten()
        .any(|v| !v.is_canonical())
        || proof
            .source_pairs
            .iter()
            .chain(proof.consistency_sources.iter().flatten())
            .chain(&proof.proximity_sources)
            .any(|p| p.values.iter().any(|v| !v.is_canonical()))
    {
        return Err(Error("noncanonical aggregated masked encoding"));
    }
    let canonical = queries
        .iter()
        .zip(claims)
        .map(|(q, c)| canonical_public(pp, q, c))
        .collect::<Result<Vec<_>, _>>()?;
    let queries: Vec<_> = canonical.iter().map(|(q, _)| q.clone()).collect();
    let claims: Vec<_> = canonical.into_iter().map(|(_, c)| c).collect();
    let padded = queries
        .iter()
        .zip(&claims)
        .map(|(q, c)| padded_query(pp, q, c))
        .collect::<Result<Vec<_>, _>>()?;
    begin(
        t,
        pp,
        source,
        proof.first,
        &queries,
        &claims,
        &proof.mask_claims,
    );
    source_verify::<F, H>(
        t,
        pp,
        source,
        proof.first,
        &proof.source_proximity,
        &proof.source_pairs,
    )?;
    let alphas = t.get_vec_challenge(b"masked aggregated source combinations v1", count);
    let identifiers: Vec<_> = alphas
        .iter()
        .enumerate()
        .map(|(i, &a)| identifier::<F, H>(pp, source, proof.first + i, a))
        .collect();
    let combined: Vec<Vec<_>> = claims
        .iter()
        .zip(&proof.mask_claims)
        .zip(&alphas)
        .map(|((c, m), &a)| {
            c.iter()
                .zip(m)
                .map(|(&c, &m)| (c + a * m).canonicalized())
                .collect()
        })
        .collect();
    let wide = pp.oracle(true);
    let mut calls = vec![0; count];
    batch::verify_sources::<F, H>(
        t,
        &pp.oracle(false),
        source,
        &identifiers,
        &padded,
        &combined,
        &proof.inner,
        true,
        |member, index, virtual_pair| {
            let call = calls[member];
            calls[member] += 1;
            let opening = if call < pp.queries {
                &proof.consistency_sources[member][call]
            } else {
                proof
                    .proximity_sources
                    .get(call - pp.queries)
                    .ok_or(Error("aggregated masked source callback count"))?
            };
            let position = index / 2;
            let depth = (wide.len(0) / 2).ilog2() as usize;
            if opening.values.len() != 4 * pp.width
                || opening.path.len() != depth + 1
                || opening.path[0] != leaf::<F, H>(&wide, 0, position, &opening.values)
                || !MerkleTree::<H>::check(source, position, &opening.path)
            {
                return Err(Error("aggregated masked source authentication"));
            }
            let expected: Vec<_> = opening
                .values
                .chunks_exact(2 * pp.width)
                .flat_map(|v| {
                    v[..pp.width]
                        .iter()
                        .zip(&v[pp.width..])
                        .map(|(&p, &s)| p + alphas[member] * s)
                })
                .collect();
            if expected != virtual_pair.values {
                return Err(Error("aggregated masked virtual source mismatch"));
            }
            Ok(())
        },
    )?;
    if calls.iter().any(|&c| c != 2 * pp.queries) {
        return Err(Error("aggregated masked source callback count"));
    }
    finish(t, proof.first, count);
    Ok(())
}
impl<O: Copy> VerifierSession<O> {
    /// Accept only the next complete aggregated batch, advancing on success.
    pub fn verify_aggregated<F: Field + Serialize, H: Hash<Output = O> + Send + Sync>(
        &mut self,
        t: &mut Transcript<F>,
        pp: &Parameters<F>,
        queries: &[Vec<MatrixPair<F>>],
        claims: &[Vec<F>],
        proof: &Proof<F, O>,
    ) -> Result<(), Error> {
        if proof.first != self.next {
            return Err(Error("masked opening order"));
        }
        verify::<F, H>(t, pp, &self.root, queries, claims, proof)?;
        self.next += queries.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, transformation::AbstractNTT};
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use serde::de::DeserializeOwned;
    use sha2::{Digest, Sha256};
    fn fri_fields<F, O>(p: &rolling_fri::Proof<F, O>) -> usize {
        1 + p
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
    fn consistency_fields<F, O>(p: &super::super::super::Proof<F, O>) -> usize {
        p.queries.iter().flatten().map(|p| p.values.len()).sum()
    }
    fn fields<F, O>(p: &Proof<F, O>) -> usize {
        p.mask_claims.iter().map(Vec::len).sum::<usize>()
            + fri_fields(&p.source_proximity)
            + fri_fields(&p.inner.proximity)
            + p.inner
                .consistency
                .iter()
                .map(consistency_fields)
                .sum::<usize>()
            + p.source_pairs
                .iter()
                .chain(p.consistency_sources.iter().flatten())
                .chain(&p.proximity_sources)
                .map(|p| p.values.len())
                .sum::<usize>()
            + p.inner
                .packed
                .iter()
                .flatten()
                .flatten()
                .map(|p| p.values.len())
                .sum::<usize>()
    }
    fn old_fields<F, O>(p: &super::super::joint::Proof<F, O>) -> usize {
        fri_fields(&p.source_proximity)
            + p.source_pairs.iter().map(|p| p.values.len()).sum::<usize>()
            + p.responses
                .iter()
                .map(|p| {
                    p.mask_claim.len()
                        + fri_fields(&p.inner.proximity)
                        + consistency_fields(&p.inner.consistency)
                        + p.inner
                            .packed
                            .iter()
                            .flatten()
                            .chain(&p.sources)
                            .map(|p| p.values.len())
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
    fn exercise<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        let variables = 13;
        let width = 2;
        let pp = Parameters::new(
            1 << variables,
            width,
            2,
            1,
            21,
            E::from_base(B::generate_ntt_table(15).unwrap().root()),
        )
        .unwrap()
        .with_base_field_encoder::<B>()
        .unwrap();
        let transient = pp.clone().with_transient_source_values();
        let table = PackedTable::new(
            variables,
            width,
            (0..(1 << variables) * width)
                .map(|i| E::from_base_fn(|j| B::from(i * (j + 1) + 9 * j + 3)))
                .collect(),
        )
        .unwrap();
        let mut ra = StdRng::seed_from_u64(921);
        let mut rb = ra.clone();
        let mut session = commit::<E, Sha256, _>(&transient, &table, &mut ra).unwrap();
        let mut old_session = commit::<E, Sha256, _>(&pp, &table, &mut rb).unwrap();
        assert_eq!(session.root(), old_session.root());
        assert_eq!(ra.next_u64(), rb.next_u64());
        assert_eq!(session.cached_codeword_elements(), 0);
        let mut accepted = VerifierSession::new(session.root());
        let mut coins = Transcript::<E>::new_direct_extension::<B>();
        let mut end = 0;
        let mut cumulative = 0;
        let mut old_cumulative = 0;
        for count in [1, 4, 16] {
            let first = end;
            let queries: Vec<Vec<_>> = (0..count)
                .map(|_| {
                    (0..variables)
                        .map(|_| {
                            let v = coins
                                .get_vec_challenge(b"aggregated dense matrices", 2 * width * width);
                            MatrixPair {
                                zero: Matrix::new(width, v[..width * width].to_vec()).unwrap(),
                                one: Matrix::new(width, v[width * width..].to_vec()).unwrap(),
                            }
                        })
                        .collect()
                })
                .collect();
            let claims: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
            let mut wrong = claims.clone();
            wrong[count - 1][0] += E::one();
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert!(prove(&mut attempted, &pp, &mut session, &queries, &wrong).is_err());
            assert_eq!(session.spent(), first);
            assert_eq!(session.cached_codeword_elements(), 0);
            assert_eq!(
                attempted.get_challenge(b"preflight after"),
                untouched.get_challenge(b"preflight after")
            );
            let mut pt = Transcript::new_direct_extension::<B>();
            let proof = prove(&mut pt, &pp, &mut session, &queries, &claims).unwrap();
            assert_eq!(session.cached_codeword_elements(), 0);
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (decoded, used): (Proof<E, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut vt = Transcript::new_direct_extension::<B>();
            accepted
                .verify_aggregated::<E, Sha256>(&mut vt, &pp, &queries, &claims, &decoded)
                .unwrap();
            assert_eq!(
                pt.get_challenge(b"aggregated after"),
                vt.get_challenge(b"aggregated after")
            );
            end += count;
            assert_eq!(session.spent(), end);
            assert_eq!(accepted.accepted(), end);
            let mut old_t = Transcript::new_direct_extension::<B>();
            let old =
                super::super::joint::prove(&mut old_t, &pp, &mut old_session, &queries, &claims)
                    .unwrap();
            let mut old_v = Transcript::new_direct_extension::<B>();
            super::super::joint::verify::<E, Sha256>(
                &mut old_v,
                &pp,
                &old_session.root(),
                &queries,
                &claims,
                &old,
            )
            .unwrap();
            assert_eq!(
                old_t.get_challenge(b"old after"),
                old_v.get_challenge(b"old after")
            );
            assert_eq!(
                decoded.mask_claims,
                old.responses
                    .iter()
                    .map(|p| p.mask_claim.clone())
                    .collect::<Vec<_>>()
            );
            let old_bytes =
                bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap();
            let entries = fields(&decoded);
            let old_entries = old_fields(&old);
            assert!(entries <= old_entries);
            cumulative += entries;
            old_cumulative += old_entries;
            assert!(cumulative <= old_cumulative && old_cumulative <= pp.message);
            if count > 1 {
                assert!(bytes.len() < old_bytes.len());
            }
            let reject =
                |p: &Proof<E, [u8; 32]>, qs: &[Vec<MatrixPair<E>>], cs: &[Vec<E>], root| {
                    let mut state = VerifierSession { root, next: first };
                    assert!(
                        state
                            .verify_aggregated::<E, Sha256>(
                                &mut Transcript::new_direct_extension::<B>(),
                                &pp,
                                qs,
                                cs,
                                p
                            )
                            .is_err()
                    );
                    assert_eq!(state.accepted(), first);
                };
            reject(&decoded, &queries, &wrong, session.root());
            let mut root = session.root();
            root[0] ^= 1;
            reject(&decoded, &queries, &claims, root);
            let mut bad = decoded.clone();
            bad.mask_claims[count - 1][0] =
                (bad.mask_claims[count - 1][0] + E::one()).canonicalized();
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.consistency_sources[count - 1][0].path[0][0] ^= 1;
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.proximity_sources[0].path[0][0] ^= 1;
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.inner.packed[0][count - 1][0].values[0] =
                (bad.inner.packed[0][count - 1][0].values[0] + E::one()).canonicalized();
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.inner.packed[0][0][0].path.push(session.root());
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.source_proximity = old.source_proximity.clone();
            bad.source_pairs = old.source_pairs.clone();
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.inner.proximity = old.responses[0].inner.proximity.clone();
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.proximity_sources.pop();
            reject(&bad, &queries, &claims, session.root());
            let mut bad = decoded.clone();
            bad.first = usize::MAX;
            reject(&bad, &queries, &claims, session.root());
            if count > 1 {
                let mut qs = queries.clone();
                let mut cs = claims.clone();
                qs.swap(0, count - 1);
                cs.swap(0, count - 1);
                reject(&decoded, &qs, &cs, session.root());
            }
            let mut replay = Transcript::new_direct_extension::<B>();
            assert!(
                accepted
                    .verify_aggregated::<E, Sha256>(&mut replay, &pp, &queries, &claims, &decoded)
                    .is_err()
            );
            assert_eq!(accepted.accepted(), end);
            println!(
                "HB_MASKED_QUERY_FRI {{\"prime\":{},\"extension_degree\":{},\"batch_size\":{},\"first\":{},\"proof_bytes\":{},\"previous_joint_bytes\":{},\"field_entries\":{},\"previous_field_entries\":{},\"proof_sha256\":\"{:x}\",\"source_certificates\":1,\"query_ladder_fri_certificates\":1,\"spent\":{},\"verified\":true,\"whole_security_matched\":false,\"hiding_certified\":false,\"complete_pbs\":false}}",
                B::MODULUS_VALUE,
                E::D,
                count,
                first,
                bytes.len(),
                old_bytes.len(),
                entries,
                old_entries,
                Sha256::digest(&bytes),
                end
            );
        }
        let mut attempted = Transcript::new_direct_extension::<B>();
        let mut untouched = Transcript::<E>::new_direct_extension::<B>();
        assert!(prove(&mut attempted, &pp, &mut session, &[], &[]).is_err());
        assert_eq!(
            attempted.get_challenge(b"exhausted after"),
            untouched.get_challenge(b"exhausted after")
        );
        assert_eq!(session.spent(), 21);
    }
    #[test]
    fn babybear_masked_aggregate_1_4_16() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_masked_aggregate_1_4_16() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
    fn fresh_false_claims<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize,
    {
        let pp = Parameters::new(
            1024,
            1,
            2,
            1,
            1,
            E::from_base(B::generate_ntt_table(12).unwrap().root()),
        )
        .unwrap();
        let table = PackedTable::new(
            10,
            1,
            (0..1024)
                .map(|i| E::from_base_fn(|j| B::from(i * (j + 1) + j + 7)))
                .collect(),
        )
        .unwrap();
        let session = commit::<E, Sha256, _>(&pp, &table, &mut StdRng::seed_from_u64(922)).unwrap();
        let query = vec![
            MatrixPair {
                zero: Matrix::identity(1).unwrap(),
                one: Matrix::new(1, vec![E::zero()]).unwrap()
            };
            10
        ];
        let claim = table.evaluate(&query).unwrap();
        let honest = prepare(&pp, &session, &query, &claim).unwrap();
        for false_mask in [false, true] {
            let queries = vec![honest.query.clone()];
            let mut claims = vec![honest.claim.clone()];
            let mut masks = vec![honest.mask_claim.clone()];
            if false_mask {
                masks[0][0] = (masks[0][0] + E::one()).canonicalized();
            } else {
                claims[0][0] = (claims[0][0] + E::one()).canonicalized();
            }
            let mut pt = Transcript::new_direct_extension::<B>();
            begin(&mut pt, &pp, &session.root(), 0, &queries, &claims, &masks);
            let (source_proximity, source_pairs) =
                source_prove::<E, Sha256>(&mut pt, &pp, &session.source, 0).unwrap();
            let alphas = pt.get_vec_challenge(b"masked aggregated source combinations v1", 1);
            assert_ne!(alphas[0], E::zero());
            let delta = if false_mask { alphas[0] } else { E::one() };
            let mut coefficients: Vec<_> = session
                .source
                .polynomial
                .coefficients
                .chunks_exact(2)
                .map(|v| (v[0] + alphas[0] * v[1]).canonicalized())
                .collect();
            coefficients[0] = (coefficients[0] + delta).canonicalized();
            let values: Vec<_> = session
                .source
                .values()
                .chunks_exact(2)
                .map(|v| (v[0] + alphas[0] * v[1] + delta).canonicalized())
                .collect();
            let oracle = pp.oracle(false);
            let mut tree = MerkleTree::<Sha256>::new();
            let id = identifier::<E, Sha256>(&pp, &session.root(), 0, alphas[0]);
            tree.root = id;
            let foreign = super::super::super::State {
                polynomial: Polynomial {
                    width: 1,
                    coefficients,
                },
                values: std::sync::OnceLock::from(values),
                encoding: oracle.clone(),
                tree,
                context: hash::<Sha256, _>(&(b"packed PolyFRIM parameters v2", &oracle)),
                layer: 0,
            };
            let padded = vec![padded_query(&pp, &queries[0], &claims[0]).unwrap()];
            let combined = vec![vec![
                (claims[0][0] + alphas[0] * masks[0][0]).canonicalized(),
            ]];
            let (inner, trace) = batch::prove_sources::<E, Sha256>(
                &mut pt,
                &oracle,
                &session.root(),
                &[&foreign],
                &padded,
                &combined,
            )
            .unwrap();
            let consistency_sources = trace
                .consistency
                .iter()
                .map(|indices| {
                    indices
                        .iter()
                        .map(|&i| source_pair(&pp, &session.source, i))
                        .collect()
                })
                .collect();
            let proximity_sources = trace
                .proximity
                .iter()
                .map(|&i| source_pair(&pp, &session.source, i))
                .collect();
            finish(&mut pt, 0, 1);
            let forged = Proof {
                first: 0,
                mask_claims: masks.clone(),
                source_proximity,
                source_pairs,
                inner,
                consistency_sources,
                proximity_sources,
            };
            // Genuine original-source FRI, full matrix consistency and joint
            // ladder FRI all pass. Only original-to-virtual authentication is omitted.
            let mut audit = Transcript::new_direct_extension::<B>();
            begin(
                &mut audit,
                &pp,
                &session.root(),
                0,
                &queries,
                &claims,
                &masks,
            );
            source_verify::<E, Sha256>(
                &mut audit,
                &pp,
                &session.root(),
                0,
                &forged.source_proximity,
                &forged.source_pairs,
            )
            .unwrap();
            assert_eq!(
                audit.get_vec_challenge(b"masked aggregated source combinations v1", 1),
                alphas
            );
            batch::verify_sources::<E, Sha256>(
                &mut audit,
                &oracle,
                &session.root(),
                &[id],
                &padded,
                &combined,
                &forged.inner,
                true,
                |_, _, _| Ok(()),
            )
            .unwrap();
            finish(&mut audit, 0, 1);
            assert_eq!(
                pt.get_challenge(b"fresh audit after"),
                audit.get_challenge(b"fresh audit after")
            );
            assert_eq!(
                verify::<E, Sha256>(
                    &mut Transcript::new_direct_extension::<B>(),
                    &pp,
                    &session.root(),
                    &queries,
                    &claims,
                    &forged
                )
                .unwrap_err()
                .0,
                "aggregated masked virtual source mismatch"
            );
        }
    }
    #[test]
    fn babybear_fresh_false_aggregated_claims() {
        fresh_false_claims::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_fresh_false_aggregated_claims() {
        fresh_false_claims::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }

    #[test]
    fn goldilocks_aggregated_noncanonical_source_views_reject_early() {
        use num_traits::Zero;
        type B = algebra::Goldilocks;
        type E = algebra::GoldilocksExtension3;
        let pp = Parameters::new(
            512,
            1,
            2,
            1,
            1,
            E::from_base(B::generate_ntt_table(11).unwrap().root()),
        )
        .unwrap();
        let table = PackedTable::new(9, 1, vec![E::from_base(B::from(7usize)); 512]).unwrap();
        let mut session =
            commit::<E, Sha256, _>(&pp, &table, &mut StdRng::seed_from_u64(923)).unwrap();
        let zero = Matrix::new(1, vec![E::zero()]).unwrap();
        let queries = vec![vec![
            MatrixPair {
                zero: zero.clone(),
                one: zero
            };
            9
        ]];
        let claims = vec![vec![E::zero()]];
        let proof = prove(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &mut session,
            &queries,
            &claims,
        )
        .unwrap();
        let alias = E::from_base_fn(|j| B::new(if j == 1 { B::MODULUS_VALUE } else { 0 }));
        assert!(!alias.is_canonical());
        assert_eq!(alias.canonicalized(), E::zero());
        for location in 0..4 {
            let mut bad = proof.clone();
            match location {
                0 => bad.mask_claims[0][0] = alias,
                1 => bad.source_pairs[0].values[0] = alias,
                2 => bad.consistency_sources[0][0].values[0] = alias,
                _ => bad.proximity_sources[0].values[0] = alias,
            }
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert_eq!(
                verify::<E, Sha256>(
                    &mut attempted,
                    &pp,
                    &session.root(),
                    &queries,
                    &claims,
                    &bad
                )
                .unwrap_err()
                .0,
                "noncanonical aggregated masked encoding"
            );
            assert_eq!(
                attempted.get_challenge(b"canonical after"),
                untouched.get_challenge(b"canonical after")
            );
        }
    }
}
