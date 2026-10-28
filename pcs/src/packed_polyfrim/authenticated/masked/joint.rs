//! Experimental ordered batches sharing original-source proximity once.
//!
//! Query-specific masked ladders remain separate. All claims and mask responses
//! bind before source projection coins; one lifetime allowance is charged per
//! query. This is not a robust vector-proximity or whole-proof hiding theorem.
use super::*;

/// One original-source proximity certificate and ordered query-specific ladders.
/// The verifier receives the expected root and every query/claim independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// First reserved private-session index.
    pub first: usize,
    /// Shared certificate for the same original paired source/mask oracle.
    pub source_proximity: rolling_fri::Proof<F, O>,
    /// Actual original-source paths for that shared certificate.
    pub source_pairs: Vec<Pair<F, O>>,
    /// Consecutively indexed response certificates, without repeated source FRI.
    pub responses: Vec<ResponseProof<F, O>>,
}
fn schedule<F>(pp: &Parameters<F>, first: usize, count: usize) -> Result<(), Error> {
    if count == 0
        || first
            .checked_add(count)
            .is_none_or(|end| end > pp.max_openings)
    {
        return Err(Error("joint masked opening count or lifetime"));
    }
    Ok(())
}
fn begin<F: Field + Serialize, O: Serialize>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &O,
    first: usize,
    ordered: &[(&[MatrixPair<F>], &[F], &[F])],
) {
    t.append_message(
        b"masked packed joint source batch v1",
        &(pp, source, first, ordered.len(), ordered),
    );
}
fn member<F: Field>(t: &mut Transcript<F>, first: usize, position: usize) {
    t.append_message(
        b"masked packed joint response member v1",
        &(position, first + position),
    );
}
fn finish<F: Field>(t: &mut Transcript<F>, first: usize, count: usize) {
    t.append_message(
        b"masked packed joint source batch finish v1",
        &(first, count),
    );
}
/// Preflight the complete batch atomically, then reserve all allowances before
/// emitting proof messages. Later failure never refunds the reserved lifetime.
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
        return Err(Error("joint masked query/claim count"));
    }
    let prepared = queries
        .iter()
        .zip(claims)
        .map(|(q, c)| prepare(pp, session, q, c))
        .collect::<Result<Vec<_>, _>>()?;
    session.spent += prepared.len();
    let result = (|| {
        let ordered: Vec<_> = prepared
            .iter()
            .map(|p| {
                (
                    p.query.as_slice(),
                    p.claim.as_slice(),
                    p.mask_claim.as_slice(),
                )
            })
            .collect();
        begin(t, pp, &session.root(), first, &ordered);
        let (source_proximity, source_pairs) = source_prove::<F, H>(t, pp, &session.source, first)?;
        let mut responses = Vec::with_capacity(prepared.len());
        for (position, p) in prepared.into_iter().enumerate() {
            member(t, first, position);
            let ((), response) =
                prove_response(t, pp, session, first + position, p, |_, _, _, _| Ok(()))?;
            responses.push(response);
        }
        finish(t, first, responses.len());
        Ok(Proof {
            first,
            source_proximity,
            source_pairs,
            responses,
        })
    })();
    session.evict_if_transient();
    result
}
/// Verify the shared original source before any query-specific response. The
/// original source root, trusted parameters and ordered claims are caller inputs.
pub fn verify<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error> {
    schedule(pp, proof.first, queries.len())?;
    if queries.len() != claims.len() || queries.len() != proof.responses.len() {
        return Err(Error("joint masked query/claim count"));
    }
    if proof.source_pairs.len() != pp.queries {
        return Err(Error("masked source proximity count"));
    }
    if proof
        .source_pairs
        .iter()
        .any(|p| p.values.iter().any(|v| !v.is_canonical()))
    {
        return Err(Error("noncanonical masked field encoding"));
    }
    let canonical = queries
        .iter()
        .zip(claims)
        .zip(&proof.responses)
        .enumerate()
        .map(|(position, ((q, c), response))| {
            if response.index != proof.first + position {
                return Err(Error("joint masked response index"));
            }
            validate_response(pp, &response.as_ref())?;
            canonical_public(pp, q, c)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ordered: Vec<_> = canonical
        .iter()
        .zip(&proof.responses)
        .map(|((q, c), p)| (q.as_slice(), c.as_slice(), p.mask_claim.as_slice()))
        .collect();
    begin(t, pp, source, proof.first, &ordered);
    source_verify::<F, H>(
        t,
        pp,
        source,
        proof.first,
        &proof.source_proximity,
        &proof.source_pairs,
    )?;
    for (position, ((q, c), response)) in canonical.iter().zip(&proof.responses).enumerate() {
        member(t, proof.first, position);
        verify_response::<F, H>(t, pp, source, q, c, response.as_ref(), |_| Ok(()))?;
    }
    finish(t, proof.first, proof.responses.len());
    Ok(())
}
impl<O: Copy> VerifierSession<O> {
    /// Accept the next joint batch atomically; failure leaves acceptance state.
    pub fn verify_joint<F: Field + Serialize, H: Hash<Output = O> + Send + Sync>(
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
        self.next += proof.responses.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{NTTField, transformation::AbstractNTT};
    use num_traits::Zero;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use serde::de::DeserializeOwned;
    use sha2::Sha256;

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
    fn source_fields<F, O>(fri: &rolling_fri::Proof<F, O>, pairs: &[Pair<F, O>]) -> usize {
        fri_fields(fri) + pairs.iter().map(|p| p.values.len()).sum::<usize>()
    }
    fn response_fields<F, O>(p: ResponseRef<'_, F, O>) -> usize {
        p.mask_claim.len()
            + fri_fields(&p.inner.proximity)
            + p.sources.iter().map(|p| p.values.len()).sum::<usize>()
            + p.inner
                .consistency
                .queries
                .iter()
                .flatten()
                .map(|p| p.values.len())
                .sum::<usize>()
            + p.inner
                .packed
                .iter()
                .flatten()
                .map(|p| p.values.len())
                .sum::<usize>()
    }
    fn exercise<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        let variables = 13;
        let width = 2;
        let root = E::from_base(B::generate_ntt_table(15).unwrap().root());
        let pp = Parameters::new(1 << variables, width, 2, 1, 21, root)
            .unwrap()
            .with_base_field_encoder::<B>()
            .unwrap();
        let table = PackedTable::new(
            variables,
            width,
            (0..(1 << variables) * width)
                .map(|i| E::from_base_fn(|j| B::from(i * (j + 1) + 17 * j + 5)))
                .collect(),
        )
        .unwrap();
        let mut ra = StdRng::seed_from_u64(719);
        let mut rb = ra.clone();
        let mut rc = ra.clone();
        let mut rd = ra.clone();
        let transient_pp = pp.clone().with_transient_source_values();
        assert_eq!(
            bincode::serde::encode_to_vec(&pp, bincode::config::standard()).unwrap(),
            bincode::serde::encode_to_vec(&transient_pp, bincode::config::standard()).unwrap()
        );
        let mut transient = commit::<E, Sha256, _>(&transient_pp, &table, &mut rc).unwrap();
        let mut transient_independent =
            commit::<E, Sha256, _>(&transient_pp, &table, &mut rd).unwrap();
        assert_eq!(transient.cached_codeword_elements(), 0);
        let mut joint = commit::<E, Sha256, _>(&pp, &table, &mut ra).unwrap();
        let mut independent = commit::<E, Sha256, _>(&pp, &table, &mut rb).unwrap();
        assert_eq!(joint.root(), independent.root());
        assert_eq!(joint.root(), transient.root());
        assert!(joint.cached_codeword_elements() > 0);
        assert_eq!(ra.clone().next_u64(), rc.next_u64());
        assert_eq!(ra.next_u64(), rb.next_u64());
        let mut acceptance = VerifierSession::new(joint.root());
        let mut matrix_coins = Transcript::<E>::new_direct_extension::<B>();
        let mut end = 0;
        let mut joint_fields = 0;
        let mut independent_fields = 0;
        for count in [1, 4, 16] {
            let first = end;
            let queries: Vec<Vec<_>> = (0..count)
                .map(|_| {
                    (0..variables)
                        .map(|_| {
                            let values = matrix_coins
                                .get_vec_challenge(b"joint dense matrices", 2 * width * width);
                            MatrixPair {
                                zero: Matrix::new(width, values[..width * width].to_vec()).unwrap(),
                                one: Matrix::new(width, values[width * width..].to_vec()).unwrap(),
                            }
                        })
                        .collect()
                })
                .collect();
            let claims: Vec<_> = queries.iter().map(|q| table.evaluate(q).unwrap()).collect();
            // A false late claim must not publish earlier members or spend any
            // part of the complete reservation.
            let mut wrong = claims.clone();
            wrong[count - 1][0] += E::one();
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert_eq!(
                prove(&mut attempted, &pp, &mut joint, &queries, &wrong)
                    .unwrap_err()
                    .0,
                "false masked source claim"
            );
            let mut transient_attempt = Transcript::new_direct_extension::<B>();
            assert!(
                prove(
                    &mut transient_attempt,
                    &pp,
                    &mut transient,
                    &queries,
                    &wrong
                )
                .is_err()
            );
            assert_eq!(transient.spent(), first);
            assert_eq!(transient.cached_codeword_elements(), 0);
            assert_eq!(
                transient_attempt.get_challenge(b"preflight after"),
                Transcript::<E>::new_direct_extension::<B>().get_challenge(b"preflight after")
            );
            assert_eq!(joint.spent(), first);
            assert_eq!(
                attempted.get_challenge(b"preflight after"),
                untouched.get_challenge(b"preflight after")
            );

            let mut pt = Transcript::new_direct_extension::<B>();
            let proof = prove(&mut pt, &pp, &mut joint, &queries, &claims).unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let mut transient_t = Transcript::new_direct_extension::<B>();
            // Retention policy belongs to the owner, even with retained parameters here.
            let transient_proof =
                prove(&mut transient_t, &pp, &mut transient, &queries, &claims).unwrap();
            assert_eq!(transient.cached_codeword_elements(), 0);
            assert_eq!(
                bytes,
                bincode::serde::encode_to_vec(&transient_proof, bincode::config::standard())
                    .unwrap()
            );

            let (decoded, used): (Proof<E, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut vt = Transcript::new_direct_extension::<B>();
            acceptance
                .verify_joint::<E, Sha256>(&mut vt, &pp, &queries, &claims, &decoded)
                .unwrap();
            let mut stateless = Transcript::new_direct_extension::<B>();
            verify::<E, Sha256>(
                &mut stateless,
                &pp,
                &joint.root(),
                &queries,
                &claims,
                &decoded,
            )
            .unwrap();
            let after = pt.get_challenge(b"joint batch after");
            assert_eq!(after, transient_t.get_challenge(b"joint batch after"));
            assert_eq!(after, vt.get_challenge(b"joint batch after"));
            assert_eq!(after, stateless.get_challenge(b"joint batch after"));
            end += count;
            assert_eq!(joint.spent(), end);
            assert_eq!(acceptance.accepted(), end);
            assert_eq!(decoded.first, first);
            assert_eq!(decoded.responses.len(), count);
            assert_eq!(decoded.source_pairs.len(), 1);

            // Same original source, parameters, mask indices and responses;
            // independent source FRI is the only certificate class shared here.
            let mut old_transcript = Transcript::new_direct_extension::<B>();
            let old: Vec<_> = queries
                .iter()
                .zip(&claims)
                .map(|(q, c)| {
                    super::super::prove(&mut old_transcript, &pp, &mut independent, q, c).unwrap()
                })
                .collect();
            let mut transient_old_t = Transcript::new_direct_extension::<B>();
            let transient_old: Vec<_> = queries
                .iter()
                .zip(&claims)
                .map(|(q, c)| {
                    let proof = super::super::prove(
                        &mut transient_old_t,
                        &pp,
                        &mut transient_independent,
                        q,
                        c,
                    )
                    .unwrap();
                    assert_eq!(transient_independent.cached_codeword_elements(), 0);
                    proof
                })
                .collect();
            assert_eq!(
                bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap(),
                bincode::serde::encode_to_vec(&transient_old, bincode::config::standard()).unwrap()
            );
            let old_bytes =
                bincode::serde::encode_to_vec(&old, bincode::config::standard()).unwrap();
            for (p, q) in decoded.responses.iter().zip(&old) {
                assert_eq!(p.index, q.index);
                assert_eq!(p.mask_claim, q.mask_claim);
            }
            assert_eq!(independent.spent(), end);
            let mut old_verifier = Transcript::new_direct_extension::<B>();
            for ((q, c), p) in queries.iter().zip(&claims).zip(&old) {
                super::super::verify::<E, Sha256>(
                    &mut old_verifier,
                    &pp,
                    &independent.root(),
                    q,
                    c,
                    p,
                )
                .unwrap();
            }
            assert_eq!(
                old_transcript.get_challenge(b"independent after"),
                old_verifier.get_challenge(b"independent after")
            );

            let joint_count = source_fields(&decoded.source_proximity, &decoded.source_pairs)
                + decoded
                    .responses
                    .iter()
                    .map(|p| response_fields(p.as_ref()))
                    .sum::<usize>();
            let independent_count: usize = old
                .iter()
                .map(|p| {
                    source_fields(&p.source_proximity, &p.source_pairs)
                        + response_fields(ResponseRef {
                            index: p.index,
                            mask_claim: &p.mask_claim,
                            inner: &p.inner,
                            sources: &p.sources,
                        })
                })
                .sum();
            assert!(joint_count <= independent_count);
            joint_fields += joint_count;
            independent_fields += independent_count;
            // Count every serialized field entry conservatively (including
            // repeats and public zero placeholders), not just sampled positions.
            assert!(joint_fields <= independent_fields && independent_fields <= pp.message);
            if count > 1 {
                assert!(bytes.len() < old_bytes.len());
            }
            println!(
                "HB_JOINT_SOURCE_BATCH {{\"prime\":{},\"extension_degree\":{},\"queries\":{},\"first\":{},\"joint_bytes\":{},\"independent_bytes\":{},\"shared_source_certificates\":1,\"independent_source_certificates\":{},\"masked_ladders\":{},\"whole_security_certified\":false,\"full_query_aggregation\":false}}",
                B::MODULUS_VALUE,
                E::D,
                count,
                first,
                bytes.len(),
                old_bytes.len(),
                count,
                count
            );

            let rejected =
                |p: &Proof<E, [u8; 32]>, qs: &[Vec<MatrixPair<E>>], cs: &[Vec<E>], root| {
                    let mut state = VerifierSession { root, next: first };
                    assert!(
                        state
                            .verify_joint::<E, Sha256>(
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
            let mut bad = decoded.clone();
            bad.source_pairs[0].values[0] += E::one();
            rejected(&bad, &queries, &claims, joint.root());
            let mut bad = decoded.clone();
            bad.responses[count - 1].sources[0].values[0] += E::one();
            rejected(&bad, &queries, &claims, joint.root());
            let mut bad = decoded.clone();
            bad.responses[count - 1].mask_claim[0] += E::one();
            rejected(&bad, &queries, &claims, joint.root());
            let mut bad = decoded.clone();
            bad.responses.pop();
            rejected(&bad, &queries, &claims, joint.root());
            let mut bad = decoded.clone();
            bad.first = usize::MAX;
            rejected(&bad, &queries, &claims, joint.root());
            let mut wrong_root = joint.root();
            wrong_root[0] ^= 1;
            rejected(&decoded, &queries, &claims, wrong_root);
            rejected(&decoded, &queries, &wrong, joint.root());
            if count > 1 {
                let mut reordered = queries.clone();
                let mut reordered_claims = claims.clone();
                reordered.swap(0, count - 1);
                reordered_claims.swap(0, count - 1);
                rejected(&decoded, &reordered, &reordered_claims, joint.root());
                let mut bad = decoded.clone();
                bad.responses.swap(0, count - 1);
                // Preserve the expected shape/schedule, testing transcript order.
                for (i, p) in bad.responses.iter_mut().enumerate() {
                    p.index = first + i;
                }
                rejected(&bad, &queries, &claims, joint.root());
            }
            // A standalone certificate cannot replace the shared one: the batch
            // prefix and complete ordered statement precede projection coins.
            let mut replay = decoded.clone();
            replay.source_proximity = old[0].source_proximity.clone();
            replay.source_pairs = old[0].source_pairs.clone();
            rejected(&replay, &queries, &claims, joint.root());
            let mut replay_t = Transcript::new_direct_extension::<B>();
            assert!(
                acceptance
                    .verify_joint::<E, Sha256>(&mut replay_t, &pp, &queries, &claims, &decoded)
                    .is_err()
            );
            assert_eq!(acceptance.accepted(), end);
        }
        assert_eq!(joint.spent(), 21);
        let mut pt = Transcript::new_direct_extension::<B>();
        let mut untouched = Transcript::<E>::new_direct_extension::<B>();
        assert!(prove(&mut pt, &pp, &mut joint, &[], &[]).is_err());
        let query = vec![
            MatrixPair {
                zero: Matrix::identity(width).unwrap(),
                one: Matrix::new(width, vec![E::zero(); width * width]).unwrap()
            };
            variables
        ];
        let claim = table.evaluate(&query).unwrap();
        assert!(prove(&mut pt, &pp, &mut joint, &[query], &[claim]).is_err());
        assert_eq!(joint.spent(), 21);
        assert_eq!(
            pt.get_challenge(b"exhausted after"),
            untouched.get_challenge(b"exhausted after")
        );
    }
    #[test]
    fn goldilocks_joint_noncanonical_entries_reject_before_transcript_mutation() {
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
            commit::<E, Sha256, _>(&pp, &table, &mut StdRng::seed_from_u64(720)).unwrap();
        let query = vec![
            MatrixPair {
                zero: Matrix::identity(1).unwrap(),
                one: Matrix::new(1, vec![E::zero()]).unwrap()
            };
            9
        ];
        let queries = vec![query];
        let claims = vec![vec![E::from_base(B::from(7usize))]];
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
        for location in 0..3 {
            let mut bad = proof.clone();
            match location {
                0 => bad.source_pairs[0].values[0] = alias,
                1 => bad.responses[0].mask_claim[0] = alias,
                _ => bad.responses[0].sources[0].values[0] = alias,
            }
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            let mut acceptance = VerifierSession::new(session.root());
            assert_eq!(
                acceptance
                    .verify_joint::<E, Sha256>(&mut attempted, &pp, &queries, &claims, &bad)
                    .unwrap_err()
                    .0,
                "noncanonical masked field encoding"
            );
            assert_eq!(acceptance.accepted(), 0);
            assert_eq!(
                attempted.get_challenge(b"alias after"),
                untouched.get_challenge(b"alias after")
            );
        }
    }
    #[test]
    fn babybear_joint_source_1_4_16() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_joint_source_1_4_16() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
