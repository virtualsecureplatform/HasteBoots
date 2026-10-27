//! Production-format checks for the proposed query-log extractor.
//! This test-only extractor is not a cryptographic security certificate.
use algebra::PrimeField;
use pcs::utils::{hash::Hash, merkle_tree::MerkleTree};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use std::collections::HashMap;

const TAG: &[u8] = b"HasteBoots/mw-column/v1";
type Log = HashMap<[u8; 32], Vec<u8>>;

fn digest(input: &[u8]) -> [u8; 32] {
    let mut h = <Sha256 as Hash>::new();
    h.update_hash_value(input);
    h.output_reset()
}

fn leaf<F: Serialize>(values: &[F]) -> Vec<u8> {
    let mut bytes = TAG.to_vec();
    bytes.extend(bincode::serde::encode_to_vec(values, bincode::config::standard()).unwrap());
    bytes
}

fn parse<F: Serialize + DeserializeOwned>(input: &[u8], count: usize) -> Option<Vec<F>> {
    let bytes = input.strip_prefix(TAG)?;
    let (values, used): (Vec<F>, usize) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).ok()?;
    if used != bytes.len() || values.len() != count || leaf(&values) != input {
        return None;
    }
    Some(values)
}

fn extract<F: PrimeField + Serialize + DeserializeOwned>(
    log: &Log, root: [u8; 32], depth: usize, index: usize, count: usize,
) -> Vec<F> {
    assert!(index < 1usize << depth);
    let mut node = root;
    for level in (1..=depth).rev() {
        let Some(input) = log.get(&node).filter(|input| input.len() == 64) else {
            return vec![F::zero(); count];
        };
        let side = (index >> (level - 1)) & 1;
        node.copy_from_slice(&input[side * 32..(side + 1) * 32]);
    }
    log.get(&node).and_then(|input| parse(input, count))
        .unwrap_or_else(|| vec![F::zero(); count])
}

fn audit<F: PrimeField + Serialize + DeserializeOwned>(width: usize) {
    // Native unpadded symbol widths and more than one row per column.
    let count = 2 * width * width;
    let columns: Vec<_> = (0..8).map(|i| {
        let value = (0..=i).fold(F::zero(), |acc, _| acc + F::one());
        vec![value; count]
    }).collect();
    let mut log = Log::new();
    let mut layer: Vec<_> = columns.iter().map(|values| {
        let bytes = leaf(values);
        let out = digest(&bytes);
        assert!(log.insert(out, bytes).is_none());
        out
    }).collect();
    let leaves = layer.clone();
    while layer.len() > 1 {
        layer = layer.chunks_exact(2).map(|pair| {
            let bytes = [pair[0].as_slice(), pair[1].as_slice()].concat();
            let out = digest(&bytes);
            assert!(log.insert(out, bytes).is_none());
            out
        }).collect();
    }
    let root = layer[0];
    let mut production = MerkleTree::<Sha256>::new();
    production.generate(&leaves);
    assert_eq!(production.root, root);
    for (i, values) in columns.iter().enumerate() {
        let path = production.query(i);
        assert_eq!(path.len(), 4);
        assert_eq!(path[0], digest(&leaf(values)));
        assert!(MerkleTree::<Sha256>::check(&root, i, &path));
        assert_eq!(&extract::<F>(&log, root, 3, i, count), values);
    }
    // An inverse history may have only a partial tree. Removing a leaf must
    // default that column without altering any other extracted column.
    log.remove(&leaves[3]);
    for (i, values) in columns.iter().enumerate() {
        let expected = if i == 3 { vec![F::zero(); count] } else { values.clone() };
        assert_eq!(extract::<F>(&log, root, 3, i, count), expected);
    }
    // Freeze is an owned snapshot, not an alias of the subsequently extended log.
    let frozen = log.clone();
    log.insert(leaves[3], leaf(&columns[3]));
    assert_eq!(extract::<F>(&frozen, root, 3, 3, count), vec![F::zero(); count]);
    assert_eq!(extract::<F>(&log, root, 3, 3, count), columns[3]);

    let valid = leaf(&columns[0]);
    assert!(parse::<F>(&valid, count).is_some());
    assert!(parse::<F>(&valid, count + 1).is_none());
    assert!(parse::<F>(&valid[1..], count).is_none());
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(parse::<F>(&trailing, count).is_none());
    assert!(parse::<F>(&valid[..valid.len() - 1], count).is_none());
    // Nonminimal vector length encoding must not be mistaken for the exact
    // verifier-generated serialization, even if the decoder accepts it.
    assert!(count < 251);
    assert_eq!(valid[TAG.len()], count as u8);
    let mut alternate = TAG.to_vec();
    alternate.extend([251, count as u8, 0]);
    alternate.extend_from_slice(&valid[TAG.len() + 1..]);
    assert!(parse::<F>(&alternate, count).is_none());
}

#[test]
fn babybear_production_leaf_and_path_extraction() {
    audit::<algebra::BabyBear>(8);
}

#[test]
fn goldilocks_production_leaf_and_path_extraction() {
    audit::<algebra::Goldilocks>(4);
}

#[test]
fn goldilocks_lazy_representations_keep_exact_bytes_and_field_semantics() {
    use algebra::{Field, Goldilocks as F};
    let canonical = vec![F::new(0), F::new(1)];
    let lazy = vec![F::new(F::MODULUS_VALUE), F::new(F::MODULUS_VALUE + 1)];
    assert_eq!(canonical, lazy);
    let bytes = leaf(&lazy);
    assert_ne!(bytes, leaf(&canonical));
    let parsed = parse::<F>(&bytes, 2).unwrap();
    assert_eq!(parsed, canonical);
    assert_eq!(leaf(&parsed), bytes);
    let root = digest(&bytes);
    let log = Log::from([(root, bytes)]);
    assert_eq!(extract::<F>(&log, root, 0, 0, 2), canonical);
}
