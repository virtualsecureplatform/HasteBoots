//! Same-root vector projections and virtual-original rolling FRI.
//!
//! Experimental non-hiding composition. Acceptance is not a concrete soundness,
//! knowledge, Fiat–Shamir or whole-PBS security certificate.
use super::*;

/// Matrix consistency and same-root projected rolling-proximity certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<F, O> {
    /// Authenticated public matrix transitions.
    pub consistency: super::Proof<F, O>,
    /// Scalar rolling FRI with every original oracle virtual.
    pub proximity: rolling_fri::Proof<F, O>,
    /// Actual packed pairs authenticating every virtual original projection.
    pub packed: Vec<Vec<Pair<F, O>>>,
}

/// Prove consistency and rolling proximity from the same retained source state.
pub fn prove<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &State<F, H>,
    query: &[MatrixPair<F>],
    claim: &[F],
) -> Result<Proof<F, H::Output>, Error> {
    prove_source(t, pp, source, query, claim, false).map(|(proof, _)| proof)
}
pub(super) fn prove_source<F: Field + Serialize, H: Hash + Send + Sync>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    source: &State<F, H>,
    query: &[MatrixPair<F>],
    claim: &[F],
    virtual_source: bool,
) -> Result<(Proof<F, H::Output>, Vec<usize>), Error> {
    let layers = ladder(pp, source, query, claim)?;
    let states: Vec<_> = std::iter::once(source).chain(layers.iter()).collect();
    let (consistency, mut source_indices) =
        certificate_traced(t, pp, &states, query, claim, virtual_source);
    let roots: Vec<_> = states.iter().map(|s| s.root()).collect();
    let (weights, identifiers) = project::<F, H>(t, pp, &roots);
    let values = states
        .iter()
        .zip(&weights)
        .map(|(state, row)| {
            state
                .values()
                .chunks_exact(pp.width)
                .map(|v| dot(v, row))
                .collect()
        })
        .collect();
    let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("proximity geometry"))?;
    let (proximity, trace) = rolling_fri::prove_virtual_all::<F, H>(t, &fri, &identifiers, values)
        .map_err(|_| Error("proximity prover"))?;
    let packed = trace
        .indices
        .iter()
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
    source_indices.extend_from_slice(&trace.indices);
    Ok((
        Proof {
            consistency,
            proximity,
            packed,
        },
        source_indices,
    ))
}

/// Verify matrix transitions and projected proximity against the exact same
/// packed roots. Recommitted copies of lane polynomials are not accepted.
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
pub(super) fn verify_source<F: Field + Serialize, H: Hash + Send + Sync, V>(
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
    if proof.packed.len() != pp.queries || proof.packed.iter().any(|q| q.len() != pp.rounds()) {
        return Err(Error("proximity packed query shape"));
    }
    if proof
        .packed
        .iter()
        .flatten()
        .any(|p| p.values.iter().any(|v| !v.is_canonical()))
    {
        return Err(Error("noncanonical projected packed encoding"));
    }
    super::verify_source::<F, H, _>(
        t,
        pp,
        source,
        query,
        claim,
        &proof.consistency,
        virtual_source,
        &mut authenticate,
    )?;
    let roots: Vec<_> = std::iter::once(*source)
        .chain(proof.consistency.roots.iter().copied())
        .collect();
    let (weights, identifiers) = project::<F, H>(t, pp, &roots);
    let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("proximity geometry"))?;
    let mut calls = 0;
    rolling_fri::verify_virtual_all::<F, H, _>(
        t,
        &fri,
        &identifiers,
        &proof.proximity,
        |layer, index, virtual_pair| {
            let opening = &proof.packed[calls / pp.rounds()][layer];
            calls += 1;
            let position = (index >> layer) / 2;
            let depth = (pp.len(layer) / 2).ilog2() as usize;
            if virtual_source && layer == 0 {
                if opening.values.len() != 2 * pp.width || !opening.path.is_empty() {
                    return Err(rolling_fri::Error("virtual source shape"));
                }
                authenticate(index, opening).map_err(|e| rolling_fri::Error(e.0))?;
            } else if opening.values.len() != 2 * pp.width
                || opening.path.len() != depth + 1
                || opening.path[0] != leaf::<F, H>(pp, layer, position, &opening.values)
                || !MerkleTree::<H>::check(&roots[layer], position, &opening.path)
            {
                return Err(rolling_fri::Error("packed projection authentication"));
            }
            let values = [
                dot(&opening.values[..pp.width], &weights[layer]),
                dot(&opening.values[pp.width..], &weights[layer]),
            ];
            if values != virtual_pair.values {
                return Err(rolling_fri::Error("packed projection mismatch"));
            }
            Ok(())
        },
    )
    .map_err(|e| Error(e.0))?;
    if calls != pp.queries * pp.rounds() {
        return Err(Error("proximity projection callback count"));
    }
    Ok(())
}
fn project<F: Field + Serialize, H: Hash>(
    t: &mut Transcript<F>,
    pp: &Parameters<F>,
    roots: &[H::Output],
) -> (Vec<Vec<F>>, Vec<H::Output>) {
    t.append_message(b"packed PolyFRIM same-root proximity v2", &(pp, roots));
    let weights: Vec<_> = (0..pp.rounds())
        .map(|_| t.get_vec_challenge(b"packed PolyFRIM lane projection v2", pp.width))
        .collect();
    let identifiers = roots
        .iter()
        .zip(&weights)
        .enumerate()
        .map(|(layer, (root, row))| {
            hash::<H, _>(&(b"packed PolyFRIM virtual layer v2", pp, layer, root, row))
        })
        .collect();
    (weights, identifiers)
}
fn dot<F: Field>(values: &[F], weights: &[F]) -> F {
    values
        .iter()
        .zip(weights)
        .fold(F::zero(), |a, (&v, &w)| a + v * w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        NTTField,
        matrix_weighted::{Matrix, PackedTable},
        transformation::AbstractNTT,
    };
    use sha2::Sha256;

    fn forged_projection<F: NTTField + Serialize>() {
        for variables in [1, 3] {
            let message = 1usize << variables;
            let width = 4;
            let root = power(F::generate_ntt_table(6).unwrap().root(), 64 / (message * 4));
            let pp = Parameters::new(message, width, 4, 16, root).unwrap();
            let table = PackedTable::new(
                variables,
                width,
                (0..message * width).map(|i| F::from(i * i + 3)).collect(),
            )
            .unwrap();
            let query = vec![
                MatrixPair {
                    zero: Matrix::identity(width).unwrap(),
                    one: Matrix::identity(width).unwrap()
                };
                variables
            ];
            let claim = table.evaluate(&query).unwrap();
            let source = commit::<F, Sha256>(&pp, Polynomial::from_table(&table).unwrap()).unwrap();
            let layers = ladder(&pp, &source, &query, &claim).unwrap();
            let states: Vec<_> = std::iter::once(&source).chain(layers.iter()).collect();
            let roots: Vec<_> = states.iter().map(|s| s.root()).collect();
            let mut prover = Transcript::new();
            let consistency = certificate(&mut prover, &pp, &states, &query, &claim);
            let (weights, identifiers) = project::<F, Sha256>(&mut prover, &pp, &roots);
            // Each foreign scalar word is a genuine low-degree polynomial, but
            // it adds one to every claimed projection of the committed vector.
            let values: Vec<Vec<F>> = states
                .iter()
                .zip(&weights)
                .map(|(s, w)| {
                    s.values()
                        .chunks_exact(width)
                        .map(|v| dot(v, w) + F::one())
                        .collect()
                })
                .collect();
            let fri = rolling_fri::Parameters::new(message, 4, 16, root).unwrap();
            let (proximity, trace) = rolling_fri::prove_virtual_all::<F, Sha256>(
                &mut prover,
                &fri,
                &identifiers,
                values.clone(),
            )
            .unwrap();
            let packed = trace
                .indices
                .iter()
                .map(|index| {
                    states
                        .iter()
                        .enumerate()
                        .map(|(layer, s)| {
                            let position = (index >> layer) / 2;
                            Pair {
                                values: s.values()
                                    [position * 2 * width..(position + 1) * 2 * width]
                                    .to_vec(),
                                path: s.tree.query(position),
                            }
                        })
                        .collect()
                })
                .collect();
            let proof = Proof {
                consistency,
                proximity,
                packed,
            };
            let mut reference = Transcript::new();
            super::super::verify::<F, Sha256>(
                &mut reference,
                &pp,
                &source.root(),
                &query,
                &claim,
                &proof.consistency,
            )
            .unwrap();
            let (_, ids) = project::<F, Sha256>(&mut reference, &pp, &roots);
            // Verify the actual packed paths independently of projected values.
            for (index, openings) in trace.indices.iter().zip(&proof.packed) {
                for (layer, opening) in openings.iter().enumerate() {
                    let position = (index >> layer) / 2;
                    assert_eq!(
                        opening.path[0],
                        leaf::<F, Sha256>(&pp, layer, position, &opening.values)
                    );
                    assert!(MerkleTree::<Sha256>::check(
                        &roots[layer],
                        position,
                        &opening.path
                    ));
                }
            }
            rolling_fri::verify_virtual_all::<F, Sha256, _>(
                &mut reference,
                &fri,
                &ids,
                &proof.proximity,
                |layer, index, pair| {
                    let position = (index >> layer) & !1;
                    assert_eq!(
                        pair.values,
                        [values[layer][position], values[layer][position + 1]]
                    );
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                prover.get_challenge(b"after forgery"),
                reference.get_challenge(b"after forgery")
            );
            let error = verify::<F, Sha256>(
                &mut Transcript::new(),
                &pp,
                &source.root(),
                &query,
                &claim,
                &proof,
            )
            .unwrap_err();
            assert_eq!(error.0, "packed projection mismatch");
        }
    }
    #[test]
    fn babybear_fresh_foreign_projection_rejected() {
        forged_projection::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_fresh_foreign_projection_rejected() {
        forged_projection::<algebra::Goldilocks>();
    }
    fn bad_degree<F: NTTField + Serialize>() {
        let message = 8;
        let variables = 3;
        let width = 2;
        let root = power(F::generate_ntt_table(6).unwrap().root(), 2);
        let pp = Parameters::new(message, width, 4, 32, root).unwrap();
        let zero = PackedTable::new(variables, width, vec![F::zero(); message * width]).unwrap();
        let query = vec![
            MatrixPair {
                zero: Matrix::new(width, vec![F::zero(); width * width]).unwrap(),
                one: Matrix::new(width, vec![F::zero(); width * width]).unwrap()
            };
            variables
        ];
        let claim = vec![F::zero(); width];
        let mut source = commit::<F, Sha256>(&pp, Polynomial::from_table(&zero).unwrap()).unwrap();
        // Commit an actual over-degree lane X^message, not a mutated path.
        let mut coefficients = vec![F::zero(); message + 1];
        coefficients[message] = F::one();
        let bad = rolling_fri::encode(&coefficients, pp.len(0), root);
        for (v, &b) in source
            .values
            .get_mut()
            .unwrap()
            .chunks_exact_mut(width)
            .zip(&bad)
        {
            v[0] = b;
        }
        let leaves: Vec<_> = source
            .values()
            .chunks_exact(2 * width)
            .enumerate()
            .map(|(index, v)| leaf::<F, Sha256>(&pp, 0, index, v))
            .collect();
        source.tree.generate(&leaves);
        let layers = ladder(&pp, &source, &query, &claim).unwrap();
        let states: Vec<_> = std::iter::once(&source).chain(layers.iter()).collect();
        let roots: Vec<_> = states.iter().map(|s| s.root()).collect();
        let mut prover = Transcript::new();
        let consistency = certificate(&mut prover, &pp, &states, &query, &claim);
        let (weights, ids) = project::<F, Sha256>(&mut prover, &pp, &roots);
        assert_ne!(weights[0][0], F::zero());
        let values = states
            .iter()
            .zip(&weights)
            .map(|(s, w)| s.values().chunks_exact(width).map(|v| dot(v, w)).collect())
            .collect();
        let fri = rolling_fri::Parameters::new(message, 4, 32, root).unwrap();
        let (proximity, trace) =
            rolling_fri::prove_virtual_all_for_audit::<F, Sha256>(&mut prover, &fri, &ids, values)
                .unwrap();
        let packed = trace
            .indices
            .iter()
            .map(|index| {
                states
                    .iter()
                    .enumerate()
                    .map(|(layer, s)| {
                        let position = (index >> layer) / 2;
                        Pair {
                            values: s.values()[position * 2 * width..(position + 1) * 2 * width]
                                .to_vec(),
                            path: s.tree.query(position),
                        }
                    })
                    .collect()
            })
            .collect();
        let proof = Proof {
            consistency,
            proximity,
            packed,
        };
        // Zero matrix folds pass consistency even for this bad initial word.
        super::super::verify::<F, Sha256>(
            &mut Transcript::new(),
            &pp,
            &source.root(),
            &query,
            &claim,
            &proof.consistency,
        )
        .unwrap();
        for (sample_index, (index, openings)) in trace.indices.iter().zip(&proof.packed).enumerate()
        {
            for (layer, pair) in openings.iter().enumerate() {
                let position = (index >> layer) / 2;
                assert_eq!(
                    pair.path[0],
                    leaf::<F, Sha256>(&pp, layer, position, &pair.values)
                );
                assert!(MerkleTree::<Sha256>::check(
                    &roots[layer],
                    position,
                    &pair.path
                ));
                assert_eq!(
                    proof.proximity.queries[sample_index].originals[layer].values,
                    [
                        dot(&pair.values[..width], &weights[layer]),
                        dot(&pair.values[width..], &weights[layer])
                    ]
                );
            }
        }
        let mut bad_terminals = 0;
        for (&index, q) in trace.indices.iter().zip(&proof.proximity.queries) {
            for layer in 1..variables {
                let pair = &q.derived[layer - 1];
                let position = (index >> layer) / 2;
                assert_eq!(pair.path.len(), (pp.len(layer) / 2).ilog2() as usize + 1);
                assert_eq!(
                    pair.path[0],
                    hash::<Sha256, _>(&(
                        b"rolling FRI pair leaf v1",
                        fri.context::<Sha256>(),
                        rolling_fri::Role::Derived,
                        layer,
                        position,
                        &pair.values
                    ))
                );
                assert!(MerkleTree::<Sha256>::check(
                    &proof.proximity.derived[layer - 1].root,
                    position,
                    &pair.path
                ));
            }
            for layer in 0..variables {
                let [mut a, mut b] = q.originals[layer].values;
                if layer > 0 {
                    let scale = trace.alphas[layer - 1] * trace.alphas[layer - 1];
                    a = q.derived[layer - 1].values[0] + scale * a;
                    b = q.derived[layer - 1].values[1] + scale * b;
                }
                let x = rolling_fri::point(pp.shift(layer), pp.len(layer), (index >> layer) & !1);
                let two = F::one() + F::one();
                let folded = (a + b) / two + trace.alphas[layer] * (a - b) / (two * x);
                if layer + 1 == variables {
                    if folded != proof.proximity.terminal {
                        bad_terminals += 1;
                    }
                } else {
                    assert_eq!(folded, q.derived[layer].values[(index >> (layer + 1)) & 1]);
                }
            }
        }
        assert!(bad_terminals > 0);
        let error = verify::<F, Sha256>(
            &mut Transcript::new(),
            &pp,
            &source.root(),
            &query,
            &claim,
            &proof,
        )
        .unwrap_err();
        assert_eq!(error.0, "rolling fold mismatch");
    }
    #[test]
    fn babybear_fresh_bad_degree_with_valid_paths() {
        bad_degree::<algebra::BabyBear>();
    }
    #[test]
    fn goldilocks_fresh_bad_degree_with_valid_paths() {
        bad_degree::<algebra::Goldilocks>();
    }
}
