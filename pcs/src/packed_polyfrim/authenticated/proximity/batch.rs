//! Joint proximity for multiple ordered matrix queries on one retained source.
//!
//! Each query keeps its authenticated consistency ladder. Their lane projections
//! share one rolling FRI certificate, sampled after every ladder root is bound.
//! This non-hiding experimental kernel is not a concrete soundness, knowledge,
//! Fiat–Shamir, masked-PCS or complete-PBS security certificate.
use super::*;

/// Independent matrix consistency ladders with one joint projected rolling FRI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// One ordered consistency certificate per caller-supplied query.
    pub consistency: Vec<super::super::Proof<F, O>>,
    /// One rolling certificate for all query/lane projections at every layer.
    pub proximity: rolling_fri::Proof<F, O>,
    /// Packed authentication pairs in sample, query, then layer order.
    pub packed: Vec<Vec<Vec<Pair<F, O>>>>,
}

// Source indices are prover-only authentication routing, never wire metadata.
pub(in crate::packed_polyfrim::authenticated) struct SourceTrace {
    pub(in crate::packed_polyfrim::authenticated) consistency: Vec<Vec<usize>>,
    pub(in crate::packed_polyfrim::authenticated) proximity: Vec<usize>,
}

fn statements<F: Field + Serialize>(
    pp: &Parameters<F>,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
) -> Result<(), Error> {
    if queries.is_empty() || queries.len() != claims.len() {
        return Err(Error("joint proximity query/claim count"));
    }
    for (query, claim) in queries.iter().zip(claims) {
        pp.query(query, claim)?;
        if query.iter().any(|p| {
            p.zero
                .values()
                .iter()
                .chain(p.one.values())
                .any(|v| !v.is_canonical())
        }) || claim.iter().any(|v| !v.is_canonical())
        {
            return Err(Error("noncanonical joint proximity statement"));
        }
    }
    Ok(())
}

fn begin<F: Field + Serialize, O: Serialize>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &O,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    roots: &[Vec<O>],
) {
    t.append_message(
        b"packed PolyFRIM joint query proximity v1",
        &(pp, source, queries.len(), queries, claims, roots),
    );
}
fn member<F: Field>(t: &mut Transcript<F>, index: usize) {
    t.append_message(b"packed PolyFRIM joint consistency member v1", &index);
}
fn project<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    roots: &[Vec<H::Output>],
) -> (Vec<Vec<Vec<F>>>, Vec<H::Output>) {
    t.append_message(b"packed PolyFRIM joint projections v1", &(pp, roots));
    let weights: Vec<Vec<Vec<F>>> = (0..pp.rounds())
        .map(|_| {
            (0..roots.len())
                .map(|_| {
                    t.get_vec_challenge(b"packed PolyFRIM joint query lane weights v1", pp.width)
                })
                .collect()
        })
        .collect();
    let identifiers = weights
        .iter()
        .enumerate()
        .map(|(layer, rows)| {
            hash::<H, _>(&(
                b"packed PolyFRIM joint virtual layer v1".as_slice(),
                pp,
                layer,
                roots,
                rows,
            ))
        })
        .collect();
    (weights, identifiers)
}

/// Commit every query ladder before sampling joint proximity weights.
/// An invalid last claim rejects before changing the caller's transcript.
/// Public matrices and claims must use canonical field representatives.
pub fn prove<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &State<F, H>,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
) -> Result<Proof<F, H::Output>, Error> {
    prove_inner(
        t,
        pp,
        source,
        queries,
        claims,
        rolling_fri::prove_virtual_all::<F, H>,
    )
}
fn prove_inner<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &State<F, H>,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    prove_fri: impl FnOnce(
        &mut Transcript<F>,
        &rolling_fri::Parameters<F>,
        &[H::Output],
        Vec<Vec<F>>,
    ) -> Result<
        (rolling_fri::Proof<F, H::Output>, rolling_fri::Trace<F>),
        rolling_fri::Error,
    >,
) -> Result<Proof<F, H::Output>, Error> {
    let sources = vec![source; queries.len()];
    prove_sources_inner(
        t,
        pp,
        &source.root(),
        &sources,
        queries,
        claims,
        false,
        prove_fri,
    )
    .map(|(proof, _)| proof)
}
#[cfg(test)]
pub(in crate::packed_polyfrim::authenticated) fn prove_sources<
    F: Field + Serialize,
    H: Hash + Send + Sync,
>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    binding: &H::Output,
    sources: &[&State<F, H>],
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
) -> Result<(Proof<F, H::Output>, SourceTrace), Error> {
    prove_sources_inner(
        t,
        pp,
        binding,
        sources,
        queries,
        claims,
        true,
        rolling_fri::prove_virtual_all::<F, H>,
    )
}
// Regenerate one virtual source at a time. Intermediate ladders remain retained,
// but no collection of full-size initial virtual codewords is kept alive.
pub(in crate::packed_polyfrim::authenticated) fn prove_generated_sources<
    F: Field + Serialize,
    H: Hash + Send + Sync,
>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    binding: &H::Output,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    mut source: impl FnMut(usize) -> State<F, H>,
) -> Result<(Proof<F, H::Output>, SourceTrace), Error> {
    statements(pp, queries, claims)?;
    let mut layers = Vec::with_capacity(queries.len());
    let mut roots = Vec::with_capacity(queries.len());
    for (index, (query, claim)) in queries.iter().zip(claims).enumerate() {
        let source = source(index);
        let next = ladder(pp, &source, query, claim)?;
        roots.push(
            std::iter::once(source.root())
                .chain(next.iter().map(State::root))
                .collect(),
        );
        layers.push(next);
    }
    t.append_message(b"packed PolyFRIM joint virtual sources v1", &());
    begin(t, pp, binding, queries, claims, &roots);
    let mut consistency = Vec::with_capacity(queries.len());
    let mut consistency_indices = Vec::with_capacity(queries.len());
    for (index, (query, claim)) in queries.iter().zip(claims).enumerate() {
        let source = source(index);
        let states: Vec<_> = std::iter::once(&source)
            .chain(layers[index].iter())
            .collect();
        member(t, index);
        let (proof, indices) = certificate_traced(t, pp, &states, query, claim, true);
        consistency.push(proof);
        consistency_indices.push(indices);
    }
    let (weights, identifiers) = project::<F, H>(t, pp, &roots);
    let mut values: Vec<Vec<F>> = (0..pp.rounds())
        .map(|layer| vec![F::zero(); pp.len(layer)])
        .collect();
    for index in 0..queries.len() {
        let source = source(index);
        for (layer, state) in std::iter::once(&source)
            .chain(layers[index].iter())
            .take(pp.rounds())
            .enumerate()
        {
            for (sum, cell) in values[layer]
                .iter_mut()
                .zip(state.values().chunks_exact(pp.width))
            {
                *sum += dot(cell, &weights[layer][index]);
            }
        }
    }
    for layer in &mut values {
        for value in layer {
            *value = value.canonicalized();
        }
    }
    let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("joint proximity geometry"))?;
    let (proximity, trace) = rolling_fri::prove_virtual_all::<F, H>(t, &fri, &identifiers, values)
        .map_err(|e| Error(e.0))?;
    let mut packed: Vec<Vec<Vec<Pair<F, H::Output>>>> = (0..trace.indices.len())
        .map(|_| Vec::with_capacity(queries.len()))
        .collect();
    for index in 0..queries.len() {
        let source = source(index);
        for (sample, position) in trace.indices.iter().enumerate() {
            packed[sample].push(
                std::iter::once(&source)
                    .chain(layers[index].iter())
                    .enumerate()
                    .map(|(layer, state)| {
                        let position = (position >> layer) / 2;
                        Pair {
                            values: state.values()
                                [position * 2 * pp.width..(position + 1) * 2 * pp.width]
                                .to_vec(),
                            path: if layer == 0 {
                                vec![]
                            } else {
                                state.tree.query(position)
                            },
                        }
                    })
                    .collect(),
            );
        }
    }
    Ok((
        Proof {
            consistency,
            proximity,
            packed,
        },
        SourceTrace {
            consistency: consistency_indices,
            proximity: trace.indices,
        },
    ))
}

fn prove_sources_inner<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    binding: &H::Output,
    sources: &[&State<F, H>],
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    virtual_source: bool,
    prove_fri: impl FnOnce(
        &mut Transcript<F>,
        &rolling_fri::Parameters<F>,
        &[H::Output],
        Vec<Vec<F>>,
    ) -> Result<
        (rolling_fri::Proof<F, H::Output>, rolling_fri::Trace<F>),
        rolling_fri::Error,
    >,
) -> Result<(Proof<F, H::Output>, SourceTrace), Error> {
    statements(pp, queries, claims)?;
    if sources.len() != queries.len() {
        return Err(Error("joint proximity source count"));
    }
    let layers = sources
        .iter()
        .zip(queries)
        .zip(claims)
        .map(|((source, q), c)| ladder(pp, source, q, c))
        .collect::<Result<Vec<_>, _>>()?;
    let states: Vec<Vec<_>> = sources
        .iter()
        .zip(&layers)
        .map(|(source, layers)| std::iter::once(*source).chain(layers.iter()).collect())
        .collect();
    let roots: Vec<Vec<_>> = states
        .iter()
        .map(|s| s.iter().map(|s| s.root()).collect())
        .collect();
    if virtual_source {
        t.append_message(b"packed PolyFRIM joint virtual sources v1", &());
    }
    begin(t, pp, binding, queries, claims, &roots);
    let (consistency, consistency_indices): (Vec<_>, Vec<_>) = states
        .iter()
        .zip(queries)
        .zip(claims)
        .enumerate()
        .map(|(index, ((states, query), claim))| {
            member(t, index);
            certificate_traced(t, pp, states, query, claim, virtual_source)
        })
        .unzip();
    let (weights, identifiers) = project::<F, H>(t, pp, &roots);
    let values = (0..pp.rounds())
        .map(|layer| {
            let mut values = vec![F::zero(); pp.len(layer)];
            for (states, row) in states.iter().zip(&weights[layer]) {
                for (sum, cell) in values
                    .iter_mut()
                    .zip(states[layer].values().chunks_exact(pp.width))
                {
                    *sum += dot(cell, row);
                }
            }
            values.into_iter().map(Field::canonicalized).collect()
        })
        .collect();
    let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("joint proximity geometry"))?;
    let (proximity, trace) = prove_fri(t, &fri, &identifiers, values).map_err(|e| Error(e.0))?;
    let packed = trace
        .indices
        .iter()
        .map(|index| {
            states
                .iter()
                .map(|states| {
                    states
                        .iter()
                        .enumerate()
                        .map(|(layer, state)| {
                            let position = (index >> layer) / 2;
                            Pair {
                                values: state.values()
                                    [position * 2 * pp.width..(position + 1) * 2 * pp.width]
                                    .to_vec(),
                                path: if virtual_source && layer == 0 {
                                    vec![]
                                } else {
                                    state.tree.query(position)
                                },
                            }
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    Ok((
        Proof {
            consistency,
            proximity,
            packed,
        },
        SourceTrace {
            consistency: consistency_indices,
            proximity: trace.indices,
        },
    ))
}

/// Check every same-root matrix ladder and authenticate the joint projection
/// against each actual packed layer root; aggregate oracle copies are virtual.
pub fn verify<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &H::Output,
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    proof: &Proof<F, H::Output>,
) -> Result<(), Error> {
    let sources = vec![*source; queries.len()];
    verify_sources::<F, H>(
        t,
        pp,
        source,
        &sources,
        queries,
        claims,
        proof,
        false,
        |_, _, _| Err(Error("unexpected virtual source")),
    )
}
pub(in crate::packed_polyfrim::authenticated) fn verify_sources<
    F: Field + Serialize,
    H: Hash + Send + Sync,
>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    binding: &H::Output,
    sources: &[H::Output],
    queries: &[Vec<MatrixPair<F>>],
    claims: &[Vec<F>],
    proof: &Proof<F, H::Output>,
    virtual_source: bool,
    mut authenticate: impl FnMut(usize, usize, &Pair<F, H::Output>) -> Result<(), Error>,
) -> Result<(), Error> {
    statements(pp, queries, claims)?;
    let count = queries.len();
    if sources.len() != count
        || proof.consistency.len() != count
        || proof
            .consistency
            .iter()
            .any(|p| p.roots.len() != pp.rounds() - 1)
        || proof.packed.len() != pp.queries
        || proof
            .packed
            .iter()
            .any(|s| s.len() != count || s.iter().any(|q| q.len() != pp.rounds()))
    {
        return Err(Error("joint proximity certificate shape"));
    }
    if proof
        .packed
        .iter()
        .flatten()
        .flatten()
        .any(|p| p.values.iter().any(|v| !v.is_canonical()))
    {
        return Err(Error("noncanonical joint projected encoding"));
    }
    let roots: Vec<Vec<_>> = proof
        .consistency
        .iter()
        .zip(sources)
        .map(|(p, source)| {
            std::iter::once(*source)
                .chain(p.roots.iter().copied())
                .collect()
        })
        .collect();
    if virtual_source {
        t.append_message(b"packed PolyFRIM joint virtual sources v1", &());
    }
    begin(t, pp, binding, queries, claims, &roots);
    for (index, ((query, claim), consistency)) in queries
        .iter()
        .zip(claims)
        .zip(&proof.consistency)
        .enumerate()
    {
        member(t, index);
        super::super::verify_source::<F, H, _>(
            t,
            pp,
            &sources[index],
            query,
            claim,
            consistency,
            virtual_source,
            |position, pair| authenticate(index, position, pair),
        )?;
    }
    let (weights, identifiers) = project::<F, H>(t, pp, &roots);
    let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("joint proximity geometry"))?;
    let mut calls = 0;
    rolling_fri::verify_virtual_all::<F, H, _>(
        t,
        &fri,
        &identifiers,
        &proof.proximity,
        |layer, index, virtual_pair| {
            let sample = calls / pp.rounds();
            calls += 1;
            let position = (index >> layer) / 2;
            let depth = (pp.len(layer) / 2).ilog2() as usize;
            let mut projected = [F::zero(); 2];
            for (query, root) in roots.iter().enumerate() {
                let opening = &proof.packed[sample][query][layer];
                if virtual_source && layer == 0 {
                    if opening.values.len() != 2 * pp.width || !opening.path.is_empty() {
                        return Err(rolling_fri::Error("joint virtual source shape"));
                    }
                    authenticate(query, index, opening).map_err(|e| rolling_fri::Error(e.0))?;
                } else if opening.values.len() != 2 * pp.width
                    || opening.path.len() != depth + 1
                    || opening.path[0] != leaf::<F, H>(pp, layer, position, &opening.values)
                    || !MerkleTree::<H>::check(&root[layer], position, &opening.path)
                {
                    return Err(rolling_fri::Error("joint packed projection authentication"));
                }
                projected[0] += dot(&opening.values[..pp.width], &weights[layer][query]);
                projected[1] += dot(&opening.values[pp.width..], &weights[layer][query]);
            }
            if projected != virtual_pair.values {
                return Err(rolling_fri::Error("joint packed projection mismatch"));
            }
            Ok(())
        },
    )
    .map_err(|e| Error(e.0))?;
    if calls != pp.queries * pp.rounds() {
        return Err(Error("joint proximity callback count"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        AbstractExtensionField, NTTField,
        matrix_weighted::{Matrix, PackedTable},
        transformation::AbstractNTT,
    };
    use num_traits::Zero;
    use serde::de::DeserializeOwned;
    use sha2::{Digest, Sha256};

    fn exercise<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        let variables = 5;
        let width = 2;
        let root = E::from_base(B::generate_ntt_table(6).unwrap().root());
        let pp = Parameters::new(1 << variables, width, 2, 8, root)
            .unwrap()
            .with_base_field_encoder::<B>()
            .unwrap();
        let table = PackedTable::new(
            variables,
            width,
            (0..(1 << variables) * width)
                .map(|i| E::from_base_fn(|j| B::from(17 * i + 9 * i * j + 13 * j + 1)))
                .collect(),
        )
        .unwrap();
        let source =
            super::super::super::commit::<E, Sha256>(&pp, Polynomial::from_table(&table).unwrap())
                .unwrap();
        let mut coins = Transcript::<E>::new_direct_extension::<B>();
        for count in [1, 4, 16] {
            let queries: Vec<Vec<_>> = (0..count)
                .map(|_| {
                    (0..variables)
                        .map(|_| {
                            let v = coins.get_vec_challenge(
                                b"joint FRI dense ordered matrices",
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
            let claims: Vec<Vec<_>> = queries
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
            // The sequential source factory must preserve the previous retained
            // virtual-source proof, indices and full transcript byte for byte.
            let mut retained_t = Transcript::new_direct_extension::<B>();
            let retained = prove_sources::<E, Sha256>(
                &mut retained_t,
                &pp,
                &source.root(),
                &vec![&source; count],
                &queries,
                &claims,
            )
            .unwrap();
            let mut generated_t = Transcript::new_direct_extension::<B>();
            let mut generations = 0;
            let generated = prove_generated_sources::<E, Sha256>(
                &mut generated_t,
                &pp,
                &source.root(),
                &queries,
                &claims,
                |_| {
                    generations += 1;
                    super::super::super::commit::<E, Sha256>(
                        &pp,
                        Polynomial::from_table(&table).unwrap(),
                    )
                    .unwrap()
                },
            )
            .unwrap();
            assert_eq!(generations, 4 * count);
            assert_eq!(
                bincode::serde::encode_to_vec(&retained.0, bincode::config::standard()).unwrap(),
                bincode::serde::encode_to_vec(&generated.0, bincode::config::standard()).unwrap(),
            );
            assert_eq!(retained.1.consistency, generated.1.consistency);
            assert_eq!(retained.1.proximity, generated.1.proximity);
            let mut retained_after = [0; 32];
            let mut generated_after = [0; 32];
            retained_t.get_challenge_bytes(b"source regeneration after", &mut retained_after);
            generated_t.get_challenge_bytes(b"source regeneration after", &mut generated_after);
            assert_eq!(retained_after, generated_after);
            let mut wrong = claims.clone();
            wrong[count - 1][0] = (wrong[count - 1][0] + E::one()).canonicalized();
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert!(prove(&mut attempted, &pp, &source, &queries, &wrong).is_err());
            assert_eq!(
                attempted.get_challenge(b"joint preflight after"),
                untouched.get_challenge(b"joint preflight after")
            );
            let mut pt = Transcript::new_direct_extension::<B>();
            let proof = prove(&mut pt, &pp, &source, &queries, &claims).unwrap();
            let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
            let (decoded, used): (Proof<E, [u8; 32]>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            let mut vt = Transcript::new_direct_extension::<B>();
            verify::<E, Sha256>(&mut vt, &pp, &source.root(), &queries, &claims, &decoded).unwrap();
            assert_eq!(
                pt.get_challenge(b"joint FRI after"),
                vt.get_challenge(b"joint FRI after")
            );
            let independent: Vec<_> = queries
                .iter()
                .zip(&claims)
                .map(|(q, c)| {
                    let mut t = Transcript::new_direct_extension::<B>();
                    let proof = super::super::prove(&mut t, &pp, &source, q, c).unwrap();
                    let mut v = Transcript::new_direct_extension::<B>();
                    super::super::verify::<E, Sha256>(&mut v, &pp, &source.root(), q, c, &proof)
                        .unwrap();
                    assert_eq!(
                        t.get_challenge(b"independent FRI after"),
                        v.get_challenge(b"independent FRI after")
                    );
                    proof
                })
                .collect();
            let independent_bytes =
                bincode::serde::encode_to_vec(&independent, bincode::config::standard()).unwrap();
            if count > 1 {
                assert!(bytes.len() < independent_bytes.len());
            }
            let reject =
                |p: &Proof<E, [u8; 32]>, qs: &[Vec<MatrixPair<E>>], cs: &[Vec<E>], root| {
                    assert!(
                        verify::<E, Sha256>(
                            &mut Transcript::new_direct_extension::<B>(),
                            &pp,
                            &root,
                            qs,
                            cs,
                            p
                        )
                        .is_err()
                    );
                };
            reject(&decoded, &queries, &wrong, source.root());
            let mut foreign = source.root();
            foreign[0] ^= 1;
            reject(&decoded, &queries, &claims, foreign);
            let mut bad = decoded.clone();
            bad.packed[0][count - 1][0].values[0] += E::one();
            reject(&bad, &queries, &claims, source.root());
            let mut bad = decoded.clone();
            bad.packed[0][count - 1][1].path[0][0] ^= 1;
            reject(&bad, &queries, &claims, source.root());
            let mut bad = decoded.clone();
            bad.proximity.queries[0].originals[0].values[0] += E::one();
            reject(&bad, &queries, &claims, source.root());
            let mut bad = decoded.clone();
            bad.consistency[0].queries[0][0].values[0] += E::one();
            reject(&bad, &queries, &claims, source.root());
            let mut bad = decoded.clone();
            bad.proximity = independent[0].proximity.clone();
            reject(&bad, &queries, &claims, source.root());
            let mut bad = decoded.clone();
            bad.consistency.pop();
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert!(
                verify::<E, Sha256>(&mut attempted, &pp, &source.root(), &queries, &claims, &bad)
                    .is_err()
            );
            assert_eq!(
                attempted.get_challenge(b"shape after"),
                untouched.get_challenge(b"shape after")
            );
            let mut bad = decoded.clone();
            bad.packed[0][0].pop();
            reject(&bad, &queries, &claims, source.root());
            if count > 1 {
                let mut qs = queries.clone();
                let mut cs = claims.clone();
                qs.swap(0, count - 1);
                cs.swap(0, count - 1);
                let mut reordered = decoded.clone();
                reordered.consistency.swap(0, count - 1);
                for sample in &mut reordered.packed {
                    sample.swap(0, count - 1);
                }
                reject(&reordered, &qs, &cs, source.root());
            }
            println!(
                "HB_JOINT_QUERY_FRI {{\"prime\":{},\"extension_degree\":{},\"batch_size\":{},\"sampling_queries\":{},\"message\":{},\"width\":{},\"joint_bytes\":{},\"independent_bytes\":{},\"proof_sha256\":\"{:x}\",\"independent_proof_sha256\":\"{:x}\",\"rolling_fri_certificates\":1,\"consistency_ladders\":{},\"verified\":true,\"whole_security_matched\":false,\"masked_pcs\":false,\"complete_pbs\":false}}",
                B::MODULUS_VALUE,
                E::D,
                count,
                pp.queries,
                pp.message,
                width,
                bytes.len(),
                independent_bytes.len(),
                Sha256::digest(&bytes),
                Sha256::digest(&independent_bytes),
                count
            );
        }
    }
    #[test]
    fn babybear_joint_query_fri_1_4_16() {
        exercise::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_joint_query_fri_1_4_16() {
        exercise::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
    fn fresh_overdegree<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize,
    {
        let width = 2;
        let message = 16;
        let root = E::from_base(B::generate_ntt_table(6).unwrap().root());
        let pp = Parameters::new(message, width, 4, 32, root).unwrap();
        let zero = PackedTable::new(4, width, vec![E::zero(); message * width]).unwrap();
        let mut source =
            super::super::super::commit::<E, Sha256>(&pp, Polynomial::from_table(&zero).unwrap())
                .unwrap();
        // Real evaluations and Merkle paths for X^message in one lane. Zero
        // matrix queries keep every sampled consistency transition valid.
        let mut coefficients = vec![E::zero(); message + 1];
        coefficients[message] = E::one();
        let bad = rolling_fri::encode(&coefficients, pp.len(0), root);
        for (cell, value) in source
            .values
            .get_mut()
            .unwrap()
            .chunks_exact_mut(width)
            .zip(bad)
        {
            cell[0] = value.canonicalized();
        }
        let leaves: Vec<_> = source
            .values()
            .chunks_exact(2 * width)
            .enumerate()
            .map(|(i, values)| leaf::<E, Sha256>(&pp, 0, i, values))
            .collect();
        source.tree.generate(&leaves);
        let zero_matrix = Matrix::new(width, vec![E::zero(); width * width]).unwrap();
        let queries = vec![
            vec![
                MatrixPair {
                    zero: zero_matrix.clone(),
                    one: zero_matrix
                };
                4
            ];
            4
        ];
        let claims = vec![vec![E::zero(); width]; queries.len()];
        assert_eq!(
            prove(
                &mut Transcript::new_direct_extension::<B>(),
                &pp,
                &source,
                &queries,
                &claims
            )
            .unwrap_err()
            .0,
            "nonconstant terminal"
        );
        let mut prover = Transcript::new_direct_extension::<B>();
        let forged = prove_inner(
            &mut prover,
            &pp,
            &source,
            &queries,
            &claims,
            rolling_fri::prove_virtual_all_for_audit::<E, Sha256>,
        )
        .unwrap();
        let roots: Vec<Vec<_>> = forged
            .consistency
            .iter()
            .map(|p| {
                std::iter::once(source.root())
                    .chain(p.roots.iter().copied())
                    .collect()
            })
            .collect();
        let mut consistency = Transcript::new_direct_extension::<B>();
        begin(
            &mut consistency,
            &pp,
            &source.root(),
            &queries,
            &claims,
            &roots,
        );
        for (i, ((query, claim), proof)) in queries
            .iter()
            .zip(&claims)
            .zip(&forged.consistency)
            .enumerate()
        {
            member(&mut consistency, i);
            super::super::super::verify::<E, Sha256>(
                &mut consistency,
                &pp,
                &source.root(),
                query,
                claim,
                proof,
            )
            .unwrap();
        }
        let error = verify::<E, Sha256>(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &source.root(),
            &queries,
            &claims,
            &forged,
        )
        .unwrap_err();
        assert_eq!(error.0, "rolling fold mismatch");
    }
    #[test]
    fn babybear_fresh_joint_overdegree_rejected() {
        fresh_overdegree::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_fresh_joint_overdegree_rejected() {
        fresh_overdegree::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
    #[test]
    fn goldilocks_joint_noncanonical_statement_and_packet_reject_early() {
        type B = algebra::Goldilocks;
        type E = algebra::GoldilocksExtension3;
        let pp = Parameters::new(
            8,
            1,
            2,
            4,
            E::from_base(B::generate_ntt_table(4).unwrap().root()),
        )
        .unwrap();
        let table = PackedTable::new(3, 1, vec![E::zero(); 8]).unwrap();
        let source =
            super::super::super::commit::<E, Sha256>(&pp, Polynomial::from_table(&table).unwrap())
                .unwrap();
        let queries = vec![vec![
            MatrixPair {
                zero: Matrix::identity(1).unwrap(),
                one: Matrix::new(1, vec![E::zero()]).unwrap()
            };
            3
        ]];
        let claims = vec![vec![E::zero()]];
        let proof = prove(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &source,
            &queries,
            &claims,
        )
        .unwrap();
        let alias = E::from_base_fn(|j| B::new(if j == 1 { B::MODULUS_VALUE } else { 0 }));
        assert!(!alias.is_canonical());
        assert_eq!(alias.canonicalized(), E::zero());
        let mut bad = proof.clone();
        bad.packed[0][0][0].values[0] = alias;
        let mut attempted = Transcript::new_direct_extension::<B>();
        let mut untouched = Transcript::<E>::new_direct_extension::<B>();
        assert_eq!(
            verify::<E, Sha256>(&mut attempted, &pp, &source.root(), &queries, &claims, &bad)
                .unwrap_err()
                .0,
            "noncanonical joint projected encoding"
        );
        assert_eq!(
            attempted.get_challenge(b"noncanonical after"),
            untouched.get_challenge(b"noncanonical after")
        );
        for location in 0..2 {
            let mut qs = queries.clone();
            let mut cs = claims.clone();
            if location == 0 {
                qs[0][0].one = Matrix::new(1, vec![alias]).unwrap();
            } else {
                cs[0][0] = alias;
            }
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert_eq!(
                prove(&mut attempted, &pp, &source, &qs, &cs).unwrap_err().0,
                "noncanonical joint proximity statement"
            );
            assert_eq!(
                attempted.get_challenge(b"noncanonical after"),
                untouched.get_challenge(b"noncanonical after")
            );
            let mut attempted = Transcript::new_direct_extension::<B>();
            let mut untouched = Transcript::<E>::new_direct_extension::<B>();
            assert_eq!(
                verify::<E, Sha256>(&mut attempted, &pp, &source.root(), &qs, &cs, &proof)
                    .unwrap_err()
                    .0,
                "noncanonical joint proximity statement"
            );
            assert_eq!(
                attempted.get_challenge(b"noncanonical after"),
                untouched.get_challenge(b"noncanonical after")
            );
        }
    }
    fn fresh_foreign_projection<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize,
    {
        // Derive the small domain from a table size supported by both NTT backends.
        let root = power(E::from_base(B::generate_ntt_table(6).unwrap().root()), 4);
        let pp = Parameters::new(8, 2, 2, 8, root).unwrap();
        let table = PackedTable::new(
            3,
            2,
            (0..16)
                .map(|i| E::from_base_fn(|j| B::from(i * (j + 1) + j + 5)))
                .collect(),
        )
        .unwrap();
        let source =
            super::super::super::commit::<E, Sha256>(&pp, Polynomial::from_table(&table).unwrap())
                .unwrap();
        let query = vec![
            MatrixPair {
                zero: Matrix::identity(2).unwrap(),
                one: Matrix::new(2, vec![E::zero(); 4]).unwrap()
            };
            3
        ];
        let claim: Vec<_> = table
            .evaluate(&query)
            .unwrap()
            .into_iter()
            .map(Field::canonicalized)
            .collect();
        let queries = vec![query; 4];
        let claims = vec![claim; 4];
        let forged = prove_inner(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &source,
            &queries,
            &claims,
            |t, fri, identifiers, mut values| {
                // All scalar degree bounds remain valid, but these are copies
                // shifted away from the actual committed joint projections.
                for row in &mut values {
                    for v in row {
                        *v = (*v + E::one()).canonicalized();
                    }
                }
                rolling_fri::prove_virtual_all::<E, Sha256>(t, fri, identifiers, values)
            },
        )
        .unwrap();
        let roots: Vec<Vec<_>> = forged
            .consistency
            .iter()
            .map(|p| {
                std::iter::once(source.root())
                    .chain(p.roots.iter().copied())
                    .collect()
            })
            .collect();
        let mut audit = Transcript::new_direct_extension::<B>();
        begin(&mut audit, &pp, &source.root(), &queries, &claims, &roots);
        for (i, ((query, claim), proof)) in queries
            .iter()
            .zip(&claims)
            .zip(&forged.consistency)
            .enumerate()
        {
            member(&mut audit, i);
            super::super::super::verify::<E, Sha256>(
                &mut audit,
                &pp,
                &source.root(),
                query,
                claim,
                proof,
            )
            .unwrap();
        }
        let (_, identifiers) = project::<E, Sha256>(&mut audit, &pp, &roots);
        let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root).unwrap();
        // Test-only selective audit: the rolling proof is valid for the foreign
        // low-degree values. Only actual-root projection binding is omitted.
        rolling_fri::verify_virtual_all::<E, Sha256, _>(
            &mut audit,
            &fri,
            &identifiers,
            &forged.proximity,
            |_, _, _| Ok(()),
        )
        .unwrap();
        let error = verify::<E, Sha256>(
            &mut Transcript::new_direct_extension::<B>(),
            &pp,
            &source.root(),
            &queries,
            &claims,
            &forged,
        )
        .unwrap_err();
        assert_eq!(error.0, "joint packed projection mismatch");
    }
    #[test]
    fn babybear_fresh_joint_foreign_projection_rejected() {
        fresh_foreign_projection::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_fresh_joint_foreign_projection_rejected() {
        fresh_foreign_projection::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
