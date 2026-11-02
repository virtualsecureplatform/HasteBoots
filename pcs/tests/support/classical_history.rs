//! Shared first-declaration analysis history; not a full ROM reduction.
//! Length filters select eligible inputs, never a bound on adversary queries.
use super::classical_assignment;
use algebra::NTTField;
use pcs::utils::hash::Digest512;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha512};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
pub(crate) type Preimages = HashMap<Digest512, Vec<u8>>;

/// Post-authentication diagnosis at the root's immutable first declaration.
/// No variant establishes a probability or charged-work bound.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FrozenPathStatus {
    Known,
    Missing {
        digest: Digest512,
        input: Vec<u8>,
        declared_at: usize,
        answered_at: Option<usize>,
        root_boundary: usize,
    },
    Collision {
        digest: Digest512,
        known: Vec<u8>,
        expected: Vec<u8>,
    },
    Ineligible {
        digest: Digest512,
        input_bytes: usize,
    },
    Unregistered {
        digest: Digest512,
    },
}

/// Realized predictable sums, conservatively charging repeated hash queries.
/// These are not expectation bounds or an attacker-work certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HashExposure {
    pub(crate) queries: usize,
    pub(crate) target_pairs: u128,
    pub(crate) prior_output_pairs: u128,
}

pub(crate) struct History {
    known: Preimages,
    answered_at: HashMap<Digest512, usize>,
    eligible_answer_epochs: Vec<usize>,
    targets: HashSet<Digest512>,
    prefixes: HashMap<Digest512, Vec<u8>>,
    availability_hits: usize,
    exposure: HashExposure,
    views: Mutex<HashMap<usize, Arc<Preimages>>>,
    first_declarations: HashMap<Digest512, usize>,
    hash_limit: usize,
    xof_limit: usize,
    events: usize,
    hash_queries: usize,
    xof_queries: usize,
}
impl Default for History {
    fn default() -> Self {
        Self::bounded(usize::MAX, usize::MAX)
    }
}
impl History {
    pub(crate) fn bounded(hash_limit: usize, xof_limit: usize) -> Self {
        Self {
            known: HashMap::new(),
            answered_at: HashMap::new(),
            eligible_answer_epochs: Vec::new(),
            targets: HashSet::new(),
            prefixes: HashMap::new(),
            availability_hits: 0,
            exposure: HashExposure::default(),
            views: Mutex::new(HashMap::new()),
            first_declarations: HashMap::new(),
            hash_limit,
            xof_limit,
            events: 0,
            hash_queries: 0,
            xof_queries: 0,
        }
    }
    fn register(&mut self, input: &[u8]) {
        let Some(prefix) = input.get(..64) else {
            return;
        };
        let key = Digest512(prefix.try_into().unwrap());
        let shared = self.prefixes.get(&key).map_or(0, |previous| {
            if input.starts_with(previous) {
                return previous.len();
            }
            if previous.starts_with(input) {
                return input.len();
            }
            previous
                .iter()
                .zip(input)
                .take_while(|(a, b)| a == b)
                .count()
        });
        if shared == input.len() {
            return;
        }
        // Earlier identical prefix windows retain their original declarations.
        // Include every window crossing the last shared byte.
        for window in input[shared.saturating_sub(63)..].windows(64) {
            let digest = Digest512(window.try_into().unwrap());
            self.targets.insert(digest);
            self.first_declarations.entry(digest).or_insert(self.events);
        }
        self.prefixes.insert(key, input.to_vec());
    }
    pub(crate) fn expose(&mut self, digest: Digest512, input: Vec<u8>) {
        assert_eq!(digest.0, <[u8; 64]>::from(Sha512::digest(&input)));
        self.hash_queries += 1;
        // Eligible input windows are declared before this hash is answered.
        if input.len() <= self.hash_limit {
            self.register(&input);
        }
        // Count from pre-answer state, including this eligible input's windows.
        // Charging repeats is conservative: a repeated input creates no new
        // first-answer availability/collision event. This avoids storing a
        // second copy of every input solely to identify fresh queries.
        self.exposure = HashExposure {
            queries: self
                .exposure
                .queries
                .checked_add(1)
                .expect("hash exposure query overflow"),
            target_pairs: self
                .exposure
                .target_pairs
                .checked_add(self.targets.len() as u128)
                .expect("hash target exposure overflow"),
            prior_output_pairs: self
                .exposure
                .prior_output_pairs
                .checked_add(self.known.len() as u128)
                .expect("hash output exposure overflow"),
        };
        if !self.known.contains_key(&digest) && self.targets.contains(&digest) {
            self.availability_hits += 1;
        }
        // Register both possible child targets for every 128-byte preimage.
        // Treating a same-length leaf this way is conservative (at most 2H).
        if input.len() == 128 && input.len() <= self.hash_limit {
            self.targets
                .insert(Digest512(input[..64].try_into().unwrap()));
            self.targets
                .insert(Digest512(input[64..].try_into().unwrap()));
        }
        if let Some(old) = self.known.insert(digest, input.clone()) {
            assert_eq!(old, input, "global output collision is an excluded event");
        } else {
            self.answered_at.insert(digest, self.events);
            if input.len() <= self.hash_limit {
                self.eligible_answer_epochs.push(self.events);
            }
        }
        self.events += 1;
    }
    pub(crate) fn declare_input(&mut self, input: &[u8]) {
        // Every window is registered before answering this candidate XOF input.
        // Geometry is supplied independently when interpreting a frozen word.
        self.xof_queries += 1;
        if input.len() <= self.xof_limit {
            self.register(input);
        }
        self.events += 1;
    }
    pub(crate) fn leaf(&self, root: Digest512, depth: usize, index: usize) -> Option<&[u8]> {
        if index >= 1usize.checked_shl(u32::try_from(depth).ok()?)? {
            return None;
        }
        let before = *self.first_declarations.get(&root)?;
        let get = |digest: Digest512| {
            let input = self.known.get(&digest)?;
            (self.answered_at.get(&digest)? < &before && input.len() <= self.hash_limit)
                .then_some(input)
        };
        let mut node = root;
        for level in (0..depth).rev() {
            let input = get(node)?;
            if input.len() != 128 {
                return None;
            }
            let offset = ((index >> level) & 1) * 64;
            node = Digest512(input[offset..offset + 64].try_into().ok()?);
        }
        get(node).map(Vec::as_slice)
    }
    /// Validate a concrete SHA512 Merkle path and find the first unavailable
    /// preimage from root to leaf. Leaf bytes must be supplied in the exact
    /// authenticated encoding. This does not register/answer any new query.
    pub(crate) fn frozen_path_status(
        &self,
        root: Digest512,
        index: usize,
        path: &[Digest512],
        leaf_input: &[u8],
    ) -> Option<FrozenPathStatus> {
        let depth = path.len().checked_sub(1)?;
        if index >= 1usize.checked_shl(u32::try_from(depth).ok()?)? {
            return None;
        }
        let boundary = *self.first_declarations.get(&root)?;
        let mut node = Digest512(Sha512::digest(leaf_input).into());
        if node != path[0] {
            return None;
        }
        let mut entries = vec![(node, leaf_input.to_vec())];
        for (level, sibling) in path[1..].iter().enumerate() {
            let input = if (index >> level) & 1 == 0 {
                [node.0, sibling.0].concat()
            } else {
                [sibling.0, node.0].concat()
            };
            node = Digest512(Sha512::digest(&input).into());
            entries.push((node, input));
        }
        if node != root {
            return None;
        }
        for (digest, input) in entries.into_iter().rev() {
            if let Some(known) = self.known.get(&digest) {
                if known != &input {
                    return Some(FrozenPathStatus::Collision {
                        digest,
                        known: known.clone(),
                        expected: input,
                    });
                }
            }
            if input.len() > self.hash_limit {
                return Some(FrozenPathStatus::Ineligible {
                    digest,
                    input_bytes: input.len(),
                });
            }
            let answered_at = self.answered_at.get(&digest).copied();
            if answered_at.is_some_and(|at| at < boundary) {
                continue;
            }
            let Some(&declared_at) = self.first_declarations.get(&digest) else {
                return Some(FrozenPathStatus::Unregistered { digest });
            };
            if declared_at > boundary {
                // A known root-to-parent prefix must have declared this child
                // before the root boundary in a complete eligible history.
                return Some(FrozenPathStatus::Unregistered { digest });
            }
            return Some(FrozenPathStatus::Missing {
                digest,
                input,
                declared_at,
                answered_at,
                root_boundary: boundary,
            });
        }
        Some(FrozenPathStatus::Known)
    }

    pub(crate) fn columns<F: NTTField + Serialize + DeserializeOwned>(
        &self,
        root: Digest512,
        depth: usize,
        cells: usize,
    ) -> Option<Vec<Vec<F>>> {
        let view = self.view(root)?;
        classical_assignment::frozen_brakedown_columns(view.as_ref(), root, depth, cells)
    }
    pub(crate) fn view(&self, root: Digest512) -> Option<Arc<Preimages>> {
        let before = *self.first_declarations.get(&root)?;
        let revision = self
            .eligible_answer_epochs
            .partition_point(|&at| at < before);
        let mut views = self.views.lock().unwrap();
        // All declarations with the same eligible answer prefix share a view,
        // even across intervening XOF requests or ineligible hash answers.
        Some(Arc::clone(views.entry(revision).or_insert_with(|| {
            Arc::new(
                self.known
                    .iter()
                    .filter(|(digest, input)| {
                        self.answered_at.get(digest).is_some_and(|&at| at < before)
                            && input.len() <= self.hash_limit
                    })
                    .map(|(&digest, input)| (digest, input.clone()))
                    .collect(),
            )
        })))
    }
    pub(crate) fn known(&self) -> &Preimages {
        &self.known
    }
    pub(crate) fn first_declarations(&self) -> &HashMap<Digest512, usize> {
        &self.first_declarations
    }
    pub(crate) fn exposure(&self) -> HashExposure {
        self.exposure
    }
    pub(crate) fn availability_hits(&self) -> usize {
        self.availability_hits
    }
    pub(crate) fn events(&self) -> usize {
        self.events
    }
    pub(crate) fn hash_queries(&self) -> usize {
        self.hash_queries
    }
    pub(crate) fn xof_queries(&self) -> usize {
        self.xof_queries
    }
}
