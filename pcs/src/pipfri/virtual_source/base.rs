//! Retain honest source coefficients and encoded words in the base field.
//! Packed leaves and all proof values retain their existing extension encoding.
use super::*;
use rayon::prelude::*;

/// Immutable base-field source; no masks, sessions or lifetime counters.
pub struct State<B, H: Hash + Send + Sync> {
    coefficients: Vec<Vec<B>>,
    values: Vec<Vec<B>>,
    tree: MerkleTree<H>,
    context: H::Output,
}
impl<B, H: Hash + Send + Sync> State<B, H> {
    /// Public commitment, identical to the embedded extension-field source.
    pub fn commitment(&self) -> Commitment<H::Output> {
        Commitment {
            root: self.tree.root,
        }
    }
    /// Retained coefficient/codeword payload bytes, excluding tree/allocator data.
    pub fn payload_bytes(&self) -> usize {
        (self.coefficients.iter().map(Vec::len).sum::<usize>()
            + self.values.iter().map(Vec::len).sum::<usize>())
            * std::mem::size_of::<B>()
    }
}
fn source_pair<B: Field, E: AbstractExtensionField<B>, H: Hash + Send + Sync>(
    state: &State<B, H>,
    index: usize,
) -> FragmentPair<E, H::Output> {
    FragmentPair {
        values: state
            .values
            .iter()
            .map(|v| [E::from_base(v[2 * index]), E::from_base(v[2 * index + 1])])
            .collect(),
        path: state.tree.query(index),
    }
}
/// Commit a base source using exactly the original packed extension leaves.
pub fn commit<B, E, H>(pp: &Parameters<E>, data: &[B]) -> Result<State<B, H>, fri::Error>
where
    B: Field + Serialize,
    E: AbstractExtensionField<B> + Serialize,
    H: Hash + Send + Sync,
{
    if data.len() != pp.table_len() {
        return Err(fri::Error("base virtual source dimensions"));
    }
    let shift = pp.fri.shift(0);
    let root = shift
        .as_base_slice()
        .first()
        .copied()
        .unwrap_or_else(B::zero);
    if E::from_base(root) != shift {
        return Err(fri::Error("base virtual source root"));
    }
    let geometry = fri::Parameters::new(
        pp.fragment_len(),
        pp.fri.encoded_len() / pp.fragment_len(),
        pp.fri.queries(),
        root,
    )?;
    let coefficients: Vec<Vec<B>> = data
        .chunks_exact(pp.fragment_len())
        .map(<[B]>::to_vec)
        .collect();
    let values = coefficients
        .par_iter()
        .map(|c| {
            // Match the coordinate encoder's skipped all-zero column, including
            // noncanonical representations that compare equal to base zero.
            if c.iter().all(|&x| x == B::zero()) {
                vec![B::zero(); pp.fri.encoded_len()]
            } else {
                geometry.encode(c, 0)
            }
        })
        .collect();
    let mut state = State {
        coefficients,
        values,
        tree: MerkleTree::new(),
        context: pp.context::<H>(),
    };
    let leaf = |i| {
        let pairs: Vec<[E; 2]> = state
            .values
            .iter()
            .map(|v| [E::from_base(v[2 * i]), E::from_base(v[2 * i + 1])])
            .collect();
        packed_leaf::<E, H>(pp, i, &pairs)
    };
    let count = pp.fri.encoded_len() / 2;
    let leaves = if count >= 128 {
        (0..count).into_par_iter().map(leaf).collect::<Vec<_>>()
    } else {
        (0..count).map(leaf).collect::<Vec<_>>()
    };
    state.tree.generate(&leaves);
    Ok(state)
}

/// Open a base source without allocating a complete extension source table.
/// The existing version-two verifier and transcript remain unchanged.
pub fn open_at<B, E, H>(
    t: &mut Transcript<E>,
    pp: &Parameters<E>,
    root: &Commitment<H::Output>,
    source: &State<B, H>,
    point: &[E],
) -> Result<(E, Proof<E, H::Output>), fri::Error>
where
    B: Field + Serialize,
    E: AbstractExtensionField<B> + Serialize,
    H: Hash + Send + Sync,
{
    if source.context != pp.context::<H>()
        || root.root != source.tree.root
        || point.len() != pp.num_vars()
    {
        return Err(fri::Error("base virtual state context/root/point"));
    }
    let u = source
        .coefficients
        .iter()
        .map(|c| {
            let embedded = c.iter().copied().map(E::from_base).collect::<Vec<_>>();
            evaluate(&embedded, &point[..pp.fri.rounds()], pp.basis)
        })
        .collect::<Vec<_>>();
    let value = evaluate(&u, &point[pp.fri.rounds()..], pp.basis);
    let gamma = bind::<E, H>(t, pp, root, point, value, &u)?;
    let weights = powers(gamma, pp.fragments);
    let mut coefficients = vec![E::zero(); pp.fragment_len()];
    let mut virtual_values = vec![E::zero(); pp.fri.encoded_len()];
    for ((c, v), &w) in source.coefficients.iter().zip(&source.values).zip(&weights) {
        // Preserve the reference extension arithmetic as well as field values;
        // in particular, do not silently normalize Goldilocks representatives.
        for (out, &x) in coefficients.iter_mut().zip(c) {
            *out += w * E::from_base(x);
        }
        for (out, &x) in virtual_values.iter_mut().zip(v) {
            *out += w * E::from_base(x);
        }
    }
    let proof = open_prepared::<E, H>(
        t,
        pp,
        root,
        point,
        value,
        u,
        gamma,
        coefficients,
        virtual_values,
        |index| source_pair::<B, E, H>(source, index / 2),
    )?;
    Ok((value, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hash::Digest512;
    use algebra::{NTTField, transformation::AbstractNTT};
    use serde::de::DeserializeOwned;
    use sha2::Sha512;

    fn run<B, E>()
    where
        B: NTTField + Serialize,
        E: AbstractExtensionField<B> + Serialize + DeserializeOwned,
    {
        let mut coins = Transcript::<B>::new_classical(&[101; 64]);
        let mut points = Transcript::<E>::new_classical_extension::<B>(&[102; 64]);
        for length in [2usize, 8, 128] {
            let bits = (length * 2).ilog2();
            let mut root = B::generate_ntt_table(bits.max(5)).unwrap().root();
            for _ in bits..bits.max(5) {
                root *= root;
            }
            for fragments in [1, 4, 16] {
                for basis in [Basis::Coefficients, Basis::BooleanEvaluations] {
                    let pp =
                        Parameters::<E>::new(length, fragments, 2, 8, E::from_base(root), basis)
                            .unwrap()
                            .with_base_field_encoder::<B>()
                            .unwrap();
                    for mode in 0..5 {
                        let data: Vec<B> = match mode {
                            0 => vec![B::zero(); pp.table_len()],
                            1 => vec![B::one(); pp.table_len()],
                            2 => coins.get_vec_challenge(b"base source", pp.table_len()),
                            3 => vec![B::new(B::MODULUS_VALUE); pp.table_len()],
                            _ => (0..pp.table_len())
                                .map(|i| {
                                    if i % 2 == 0 {
                                        B::new(B::MODULUS_VALUE)
                                    } else {
                                        B::from(i + 3)
                                    }
                                })
                                .collect(),
                        };
                        let source = commit::<B, E, Sha512>(&pp, &data).unwrap();
                        let embedded = data.iter().copied().map(E::from_base).collect::<Vec<_>>();
                        let reference = crate::pipfri::commit::<E, Sha512>(&pp, &embedded).unwrap();
                        assert_eq!(
                            source.commitment().root,
                            reference.commitment().root,
                            "mode={mode}"
                        );
                        assert_eq!(
                            source.payload_bytes(),
                            (pp.table_len() + pp.fragments * pp.fri.encoded_len())
                                * std::mem::size_of::<B>()
                        );
                        let mut point = points.get_vec_challenge(b"point", pp.num_vars());
                        for (i, x) in point.iter_mut().enumerate() {
                            if i % 3 == 0 {
                                *x = E::zero();
                            } else if i % 3 == 1 {
                                *x = E::one();
                            }
                        }
                        let mut pt = Transcript::<E>::new_classical_extension::<B>(&[103; 64]);
                        let (value, proof) = open_at::<B, E, Sha512>(
                            &mut pt,
                            &pp,
                            &source.commitment(),
                            &source,
                            &point,
                        )
                        .unwrap();
                        let mut rt = Transcript::<E>::new_classical_extension::<B>(&[103; 64]);
                        let (expected, old) = super::super::open_at::<E, Sha512>(
                            &mut rt,
                            &pp,
                            &reference.commitment(),
                            &reference,
                            &point,
                        )
                        .unwrap();
                        assert_eq!(value, expected);
                        let bytes =
                            bincode::serde::encode_to_vec(&proof, bincode::config::standard())
                                .unwrap();
                        assert_eq!(
                            bytes,
                            bincode::serde::encode_to_vec(old, bincode::config::standard())
                                .unwrap(),
                            "length={length} fragments={fragments} mode={mode}"
                        );
                        let mut a = [0; 32];
                        let mut b = [0; 32];
                        pt.get_challenge_bytes(b"after", &mut a);
                        rt.get_challenge_bytes(b"after", &mut b);
                        assert_eq!(a, b);
                        let (decoded, used): (Proof<E, Digest512>, usize) =
                            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                                .unwrap();
                        assert_eq!(used, bytes.len());
                        super::super::verify::<E, Sha512>(
                            &mut Transcript::new_classical_extension::<B>(&[103; 64]),
                            &pp,
                            &source.commitment(),
                            &point,
                            value,
                            &decoded,
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    #[test]
    fn babybear_base_source_preserves_virtual_wire() {
        run::<algebra::BabyBear, algebra::BabyBearExtension6>();
    }
    #[test]
    fn goldilocks_base_source_preserves_virtual_wire() {
        run::<algebra::Goldilocks, algebra::GoldilocksExtension3>();
    }
}
