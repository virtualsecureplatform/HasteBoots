//! Base-alphabet prover storage for the unchanged extension-alphabet proof.
use super::*;

pub(crate) struct BaseState<B, H: Hash + Send + Sync> {
    polynomial: Polynomial<B>,
    values: Vec<B>,
    tree: crate::utils::merkle_tree::MerkleTree<H>,
    context: H::Output,
    layer: usize,
}
impl<B, H: Hash + Send + Sync> BaseState<B, H> {
    pub(crate) fn root(&self) -> H::Output {
        self.tree.root
    }
    pub(crate) fn cached_codeword_elements(&self) -> usize {
        self.values.len()
    }
}

fn parameters<B: Field + Serialize, E: AbstractExtensionField<B> + Serialize>(
    pp: &Parameters<E>,
) -> Result<Parameters<B>, Error> {
    let root = pp
        .root
        .as_base_slice()
        .first()
        .copied()
        .unwrap_or_else(B::zero);
    if E::from_base(root) != pp.root {
        return Err(Error("base-storage root"));
    }
    let mut base = Parameters::new(pp.message, pp.width, pp.blowup, pp.queries, root)?;
    base.parallel_oracles = pp.parallel_oracles;
    Ok(base)
}

fn state<B, E, H>(
    pp: &Parameters<E>,
    base: &Parameters<B>,
    layer: usize,
    polynomial: Polynomial<B>,
) -> BaseState<B, H>
where
    B: Field + Serialize,
    E: AbstractExtensionField<B> + Serialize,
    H: Hash + Send + Sync,
{
    let values = encode_values(base, layer, &polynomial);
    let make_leaf = |(i, v): (usize, &[B])| {
        let embedded: Vec<E> = v.iter().copied().map(E::from_base).collect();
        leaf::<E, H>(pp, layer, i, &embedded)
    };
    let leaves: Vec<_> = if pp.parallel_oracles && values.len() >= 1 << 15 {
        values
            .par_chunks_exact(2 * pp.width)
            .enumerate()
            .map(make_leaf)
            .collect()
    } else {
        values
            .chunks_exact(2 * pp.width)
            .enumerate()
            .map(make_leaf)
            .collect()
    };
    let mut tree = crate::utils::merkle_tree::MerkleTree::<H>::new();
    tree.generate(&leaves);
    BaseState {
        polynomial,
        values,
        tree,
        context: hash::<H, _>(&(b"packed PolyFRIM parameters v2", pp)),
        layer,
    }
}

pub(crate) fn commit<B, E, H>(
    pp: &Parameters<E>,
    polynomial: Polynomial<B>,
) -> Result<BaseState<B, H>, Error>
where
    B: Field + Serialize,
    E: AbstractExtensionField<B> + Serialize,
    H: Hash + Send + Sync,
{
    if polynomial.len() != pp.message || polynomial.width != pp.width {
        return Err(Error("base-storage source shape"));
    }
    Ok(state::<B, E, H>(pp, &parameters(pp)?, 0, polynomial))
}

fn pair<B: Field, E: AbstractExtensionField<B>, H: Hash + Send + Sync, O>(
    state: &BaseState<B, H>,
    width: usize,
    index: usize,
    encode: &mut impl FnMut(H::Output) -> Result<O, Error>,
) -> Result<Pair<E, O>, Error> {
    Ok(Pair {
        values: state.values[index * 2 * width..(index + 1) * 2 * width]
            .iter()
            .copied()
            .map(E::from_base)
            .collect(),
        path: state
            .tree
            .query(index)
            .into_iter()
            .map(&mut *encode)
            .collect::<Result<Vec<_>, Error>>()?,
    })
}

pub(crate) fn prove<B, E, H>(
    t: &mut Transcript<E>,
    pp: &Parameters<E>,
    source: &BaseState<B, H>,
    queries: &[Vec<MatrixPair<B>>],
    claims: &[Vec<B>],
) -> Result<Proof<E, H::Output>, Error>
where
    B: Field + Serialize,
    E: AbstractExtensionField<B> + Serialize,
    H: Hash + Send + Sync,
{
    prove_mapped::<B, E, H, H::Output>(t, pp, source, queries, claims, &mut |h| Ok(h))
}
pub(crate) fn prove_mapped<B, E, H, O>(
    t: &mut Transcript<E>,
    pp: &Parameters<E>,
    source: &BaseState<B, H>,
    queries: &[Vec<MatrixPair<B>>],
    claims: &[Vec<B>],
    encode: &mut impl FnMut(H::Output) -> Result<O, Error>,
) -> Result<Proof<E, O>, Error>
where
    B: Field + Serialize,
    E: AbstractExtensionField<B> + Serialize,
    H: Hash + Send + Sync,
{
    if queries.is_empty() || queries.len() != claims.len() {
        return Err(Error("base query/claim count"));
    }
    for (query, claim) in queries.iter().zip(claims) {
        if query.len() != pp.rounds() || claim.len() != pp.width {
            return Err(Error("base query shape"));
        }
        for pair in query {
            pair.validate(pp.width)
                .map_err(|_| Error("base matrix shape"))?;
        }
    }
    let lifted: Vec<Vec<_>> = queries
        .iter()
        .map(|q| {
            q.iter()
                .map(|p| algebra::matrix_weighted::MatrixPair {
                    zero: algebra::matrix_weighted::Matrix::new(
                        pp.width,
                        p.zero.values().iter().copied().map(E::from_base).collect(),
                    )
                    .unwrap(),
                    one: algebra::matrix_weighted::Matrix::new(
                        pp.width,
                        p.one.values().iter().copied().map(E::from_base).collect(),
                    )
                    .unwrap(),
                })
                .collect()
        })
        .collect();
    let embedded: Vec<Vec<_>> = claims
        .iter()
        .map(|c| c.iter().copied().map(E::from_base).collect())
        .collect();
    statements(pp, &lifted, &embedded)?;
    if source.layer != 0 || source.context != hash::<H, _>(&(b"packed PolyFRIM parameters v2", pp))
    {
        return Err(Error("base-storage source context"));
    }
    let base = parameters::<B, E>(pp)?;
    let mut cache = HashMap::new();
    let mut retained = 0usize;
    let mut ladders = Vec::with_capacity(queries.len());
    for (query, claim) in queries.iter().zip(claims) {
        let mut layers: Vec<Arc<BaseState<B, H>>> = Vec::with_capacity(pp.rounds() - 1);
        for layer in 1..pp.rounds() {
            let parent = layers.last().map(Arc::as_ref).unwrap_or(source);
            let key = (
                parent as *const BaseState<B, H> as usize,
                bincode::serde::encode_to_vec(&query[layer - 1], bincode::config::standard())
                    .map_err(|_| Error("base matrix prefix"))?,
            );
            let next = if let Some(existing) = cache.get(&key) {
                Arc::clone(existing)
            } else {
                let polynomial = parent
                    .polynomial
                    .fold(&query[layer - 1])
                    .map_err(|_| Error("base source fold"))?;
                let next = Arc::new(state::<B, E, H>(pp, &base, layer, polynomial));
                let bytes = (next.polynomial.len() * pp.width + next.values.len())
                    .saturating_mul(std::mem::size_of::<B>())
                    .saturating_add(
                        next.tree
                            .tree
                            .len()
                            .saturating_mul(std::mem::size_of::<H::Output>()),
                    )
                    .saturating_add(key.1.len());
                if retained.saturating_add(bytes) <= 1usize << 30 {
                    retained += bytes;
                    cache.insert(key, Arc::clone(&next));
                }
                next
            };
            layers.push(next);
        }
        let parent = layers.last().map(Arc::as_ref).unwrap_or(source);
        let terminal = parent
            .polynomial
            .fold(&query[pp.rounds() - 1])
            .map_err(|_| Error("base terminal fold"))?;
        if terminal.evaluate(B::zero()) != *claim {
            return Err(Error("false base terminal claim"));
        }
        ladders.push(layers);
    }
    let states: Vec<Vec<_>> = ladders
        .iter()
        .map(|l| {
            std::iter::once(source)
                .chain(l.iter().map(Arc::as_ref))
                .collect()
        })
        .collect();
    let roots: Vec<Vec<_>> = states
        .iter()
        .map(|s| s.iter().map(|s| s.root()).collect())
        .collect();
    begin(t, pp, &source.root(), &lifted, &embedded, &roots);
    let mut consistency = Vec::with_capacity(states.len());
    for (i, states) in states.iter().enumerate() {
        member(t, i);
        bind(
            t,
            pp,
            &source.root(),
            &roots[i][1..],
            &lifted[i],
            &embedded[i],
        );
        let mapped_roots = roots[i][1..]
            .iter()
            .copied()
            .map(&mut *encode)
            .collect::<Result<Vec<_>, Error>>()?;
        let mut queries = Vec::with_capacity(pp.queries);
        for index in sample_indices(t, pp) {
            let mut pairs = Vec::with_capacity(states.len());
            for (layer, s) in states.iter().enumerate() {
                pairs.push(pair::<B, E, H, O>(
                    s,
                    pp.width,
                    (index >> layer) / 2,
                    encode,
                )?);
            }
            queries.push(pairs);
        }
        consistency.push(crate::packed_polyfrim::authenticated::Proof {
            roots: mapped_roots,
            queries,
        });
    }
    let (weights, identifiers) = project::<E, H>(t, pp, &roots);
    let values = (0..pp.rounds())
        .map(|layer| {
            let mut sums = vec![E::zero(); pp.len(layer)];
            // Every weight was sampled for the original ordered statement.
            // Linearity permits summing rows attached to the exact same
            // retained state before scanning its base-field codeword. Identity
            // is private object identity, never equality of untrusted roots.
            let mut positions = HashMap::new();
            let mut groups: Vec<(&BaseState<B, H>, Vec<E>)> = Vec::new();
            for (states, row) in states.iter().zip(&weights[layer]) {
                let state = states[layer];
                let identity = state as *const BaseState<B, H> as usize;
                if let Some(&index) = positions.get(&identity) {
                    let (_, combined): &mut (&BaseState<B, H>, Vec<E>) = &mut groups[index];
                    for (sum, &value) in combined.iter_mut().zip(row) {
                        *sum += value;
                    }
                } else {
                    positions.insert(identity, groups.len());
                    groups.push((state, row.clone()));
                }
            }
            for (state, row) in groups {
                for (sum, cell) in sums.iter_mut().zip(state.values.chunks_exact(pp.width)) {
                    for (&value, &weight) in cell.iter().zip(&row) {
                        *sum += weight * value;
                    }
                }
            }
            sums.into_iter().map(Field::canonicalized).collect()
        })
        .collect();
    let fri = rolling_fri::Parameters::new(pp.message, pp.blowup, pp.queries, pp.root)
        .map_err(|_| Error("base proximity geometry"))?;
    let (proximity, trace) =
        rolling_fri::prove_virtual_all_mapped::<E, H, O>(t, &fri, &identifiers, values, &mut |h| {
            encode(h).map_err(|e| rolling_fri::Error(e.0))
        })
        .map_err(|e| Error(e.0))?;
    let mut packed = Vec::with_capacity(trace.indices.len());
    for index in trace.indices {
        let mut members = Vec::with_capacity(states.len());
        for states in &states {
            let mut layers = Vec::with_capacity(states.len());
            for (layer, s) in states.iter().enumerate() {
                layers.push(pair::<B, E, H, O>(
                    s,
                    pp.width,
                    (index >> layer) / 2,
                    encode,
                )?);
            }
            members.push(layers);
        }
        packed.push(members);
    }
    Ok(Proof {
        consistency,
        proximity,
        packed,
    })
}
