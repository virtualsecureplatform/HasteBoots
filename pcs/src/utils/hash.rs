use std::fmt::Debug;

/// Optional scoped standard-SHA512 output observer, excluded from default builds.
#[cfg(feature = "hash-audit")]
pub mod audit;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Fixed-width SHA-512 output. Its wire spelling is exactly 64 bytes, with no
/// vector length prefix; legacy SHA-256 outputs retain their original spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest512(pub [u8; 64]);

impl Default for Digest512 {
    fn default() -> Self {
        Self([0; 64])
    }
}
impl AsRef<[u8]> for Digest512 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Serialize for Digest512 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let first: &[u8; 32] = self.0[..32].try_into().expect("fixed digest half");
        let last: &[u8; 32] = self.0[32..].try_into().expect("fixed digest half");
        (first, last).serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Digest512 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (first, last): ([u8; 32], [u8; 32]) = Deserialize::deserialize(deserializer)?;
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&first);
        bytes[32..].copy_from_slice(&last);
        Ok(Self(bytes))
    }
}

/// Define the Hash trait
pub trait Hash: Debug + Clone + Default + Sized {
    /// output
    type Output: Clone
        + Copy
        + PartialEq
        + Default
        + Debug
        + Sized
        + AsRef<[u8]>
        + Serialize
        + for<'de> Deserialize<'de>
        + Sync
        + Send;

    /// Create a new instance.
    fn new() -> Self {
        Self::default()
    }

    /// Update with input
    fn update_hash_value(&mut self, input: &[u8]);

    /// Output a hash value and reset
    fn output_reset(&mut self) -> Self::Output;
}

impl Hash for Sha256 {
    type Output = [u8; 32];

    #[inline]
    fn update_hash_value(&mut self, input: &[u8]) {
        self.update(input);
    }

    #[inline]
    fn output_reset(&mut self) -> Self::Output {
        self.finalize_reset().into()
    }
}

impl Hash for Sha512 {
    type Output = Digest512;
    fn update_hash_value(&mut self, input: &[u8]) {
        self.update(input);
    }
    fn output_reset(&mut self) -> Self::Output {
        let output = Digest512(self.finalize_reset().into());
        #[cfg(feature = "hash-audit")]
        audit::record(output);
        output
    }
}

#[cfg(test)]
mod classical_hash_tests {
    use super::*;

    #[test]
    fn sha512_merkle_paths_match_independent_tree() {
        use crate::utils::merkle_tree::MerkleTree;
        let leaves: Vec<_> = (0u8..8)
            .map(|i| Digest512(Sha512::digest([i]).into()))
            .collect();
        let mut reference: Vec<[u8; 64]> = leaves.iter().map(|d| d.0).collect();
        while reference.len() > 1 {
            reference = reference
                .chunks_exact(2)
                .map(|pair| {
                    let mut bytes = [0; 128];
                    bytes[..64].copy_from_slice(&pair[0]);
                    bytes[64..].copy_from_slice(&pair[1]);
                    Sha512::digest(bytes).into()
                })
                .collect();
        }
        let mut tree = MerkleTree::<Sha512>::new();
        tree.generate(&leaves);
        assert_eq!(tree.root.0, reference[0]);
        for index in 0..leaves.len() {
            let path = tree.query(index);
            assert_eq!(path[0], leaves[index]);
            let bytes = bincode::serde::encode_to_vec(&path, bincode::config::standard()).unwrap();
            let (decoded, used): (Vec<Digest512>, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(used, bytes.len());
            assert!(MerkleTree::<Sha512>::check(&tree.root, index, &decoded));
            let mut bad = decoded;
            bad[1].0[63] ^= 1;
            assert!(!MerkleTree::<Sha512>::check(&tree.root, index, &bad));
        }
    }

    #[test]
    fn sha512_known_answer_reset_and_fixed_wire() {
        let mut hash = <Sha512 as Hash>::new();
        hash.update_hash_value(b"a");
        hash.update_hash_value(b"bc");
        let value = hash.output_reset();
        // FIPS 180-4 SHA-512("abc"), independent of this wrapper's reset path.
        let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        let actual: String = value.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(actual, expected);
        hash.update_hash_value(b"abc");
        assert_eq!(hash.output_reset(), value);
        let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap();
        assert_eq!(bytes, value.0);
        let (decoded, used): (Digest512, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!((decoded, used), (value, 64));
        assert!(
            bincode::serde::decode_from_slice::<Digest512, _>(
                &bytes[..63],
                bincode::config::standard()
            )
            .is_err()
        );
    }
}
