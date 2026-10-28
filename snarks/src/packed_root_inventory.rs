//! Commitment slots carried by a complete packed PBS proof.
//!
//! Count only after verification: this describes the supplied proof, not its
//! validity or a trusted upper bound on adversarial resource use. Equal roots
//! in different slots are conservatively counted separately. Trusted public-key
//! roots, authentication siblings and transcript digests are excluded.
use crate::{
    packed_decomposition, packed_extension_lookup, packed_lane_lookup, packed_pbs,
    packed_tuple_lookup,
};
use algebra::Field;
use std::collections::BTreeMap;

/// Counts of root slots by their place in the complete proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootInventory {
    pub categories: BTreeMap<&'static str, usize>,
}
impl RootInventory {
    pub fn total(&self) -> usize {
        self.categories.values().sum()
    }
}

/// Supported lookup proof formats expose only their newly committed helpers.
pub trait LookupRoots {
    fn reciprocal_roots(&self) -> usize;
}
impl<F, O> LookupRoots for packed_lane_lookup::Proof<F, O> {
    fn reciprocal_roots(&self) -> usize {
        self.reciprocal_commitments.len()
    }
}
impl<F: Field, EF: Field, O> LookupRoots for packed_extension_lookup::Proof<F, EF, O> {
    fn reciprocal_roots(&self) -> usize {
        self.reciprocal_commitments.len()
    }
}
impl<F: Field, EF: Field, O> LookupRoots for packed_extension_lookup::deferred::Proof<F, EF, O> {
    fn reciprocal_roots(&self) -> usize {
        self.lookups.iter().map(LookupRoots::reciprocal_roots).sum()
    }
}
impl<F: Field, EF: Field, O> LookupRoots for packed_extension_lookup::shared::Proof<F, EF, O> {
    fn reciprocal_roots(&self) -> usize {
        self.helper_roots.len()
    }
}
impl<F, O> LookupRoots for packed_tuple_lookup::Proof<F, O> {
    fn reciprocal_roots(&self) -> usize {
        self.reciprocal_commitments.len()
    }
}

/// Auxiliary commitments introduced by one canonical decomposition.
pub trait DecompositionRoots {
    fn borrow_roots(&self) -> usize;
    fn reciprocal_roots(&self) -> usize;
}
impl<F, O, P: LookupRoots> DecompositionRoots for packed_decomposition::Proof<F, O, P> {
    fn borrow_roots(&self) -> usize {
        self.borrow_commitments.len()
    }
    fn reciprocal_roots(&self) -> usize {
        self.comparisons
            .iter()
            .map(LookupRoots::reciprocal_roots)
            .sum()
    }
}

/// Inventory serialized root declarations; no proof or security checks occur here.
pub fn inventory<F, O, D: DecompositionRoots, A>(
    proof: &packed_pbs::Proof<F, O, D, A>,
) -> RootInventory {
    inventory_with(proof, D::borrow_roots, D::reciprocal_roots)
}

fn inventory_with<F, O, D, A>(
    proof: &packed_pbs::Proof<F, O, D, A>,
    borrow_roots: impl Fn(&D) -> usize,
    reciprocal_roots: impl Fn(&D) -> usize,
) -> RootInventory {
    RootInventory {
        categories: BTreeMap::from([
            ("coefficients", proof.coefficients.len()),
            ("evaluations", proof.evaluations.len()),
            ("decomposition_inputs", proof.decomposition_inputs.len()),
            ("accumulators", proof.accumulators.len()),
            (
                "decomposition_borrows",
                proof.decomposition.iter().map(&borrow_roots).sum(),
            ),
            (
                "decomposition_reciprocals",
                proof.decomposition.iter().map(&reciprocal_roots).sum(),
            ),
            ("monomial_evaluations", proof.monomial.evaluations.len()),
            (
                "key_switch_coefficients",
                proof.key_switch.coefficients.len(),
            ),
            ("key_switch_evaluations", proof.key_switch.evaluations.len()),
            (
                "key_switch_borrows",
                borrow_roots(&proof.key_switch.decomposition),
            ),
            (
                "key_switch_reciprocals",
                reciprocal_roots(&proof.key_switch.decomposition),
            ),
        ]),
    }
}

/// Root declarations in a complete version-9 certificate. Helpers belong to the
/// outer packets, not to partial members; count them once in their actual place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComparisonBatchInventory {
    pub members: Vec<RootInventory>,
    pub blind_rotation_reciprocals: usize,
    pub key_switch_reciprocals: usize,
}
impl ComparisonBatchInventory {
    pub fn total(&self) -> usize {
        self.members.iter().map(RootInventory::total).sum::<usize>()
            + self.blind_rotation_reciprocals
            + self.key_switch_reciprocals
    }
}
/// Call only after the complete batch verifier succeeds. This counts serialized
/// commitments, not a validity check or an adversarial resource/security bound.
pub fn comparison_batch_inventory<F: Field, EF: Field, O>(
    proof: &packed_pbs::batch::shared::Proof<F, EF, O>,
) -> ComparisonBatchInventory {
    ComparisonBatchInventory {
        members: proof
            .members
            .iter()
            .map(|m| inventory_with(m, |d| d.borrow_commitments.len(), |_| 0))
            .collect(),
        blind_rotation_reciprocals: proof
            .blind_rotation
            .iter()
            .map(|p| p.helper_roots.len())
            .sum(),
        key_switch_reciprocals: proof.key_switch.iter().map(|p| p.helper_roots.len()).sum(),
    }
}

/// Serialized source/helper root slots in a verified version-10 complete proof.
/// Internal PCS roots and trusted public-key roots are excluded as above.
pub fn canonical_inventory<F: Field, EF: Field, O, S, B>(
    proof: &packed_pbs::canonical::Proof<F, EF, O, S, B>,
) -> RootInventory {
    RootInventory {
        categories: BTreeMap::from([
            ("coefficients", proof.coefficients.len()),
            ("evaluations", proof.evaluations.len()),
            ("decomposition_inputs", proof.decomposition_inputs.len()),
            ("accumulators", proof.accumulators.len()),
            (
                "decomposition_borrows",
                proof
                    .decomposition
                    .iter()
                    .map(|d| d.borrow_commitments.len())
                    .sum(),
            ),
            (
                "decomposition_reciprocals",
                proof
                    .decomposition
                    .iter()
                    .flat_map(|d| &d.comparisons)
                    .map(|p| p.reciprocal_commitments.len())
                    .sum(),
            ),
            ("monomial_evaluations", proof.monomial.evaluations.len()),
            (
                "key_switch_coefficients",
                proof.key_switch.coefficients.len(),
            ),
            ("key_switch_evaluations", proof.key_switch.evaluations.len()),
            ("key_switch_input", 1),
            (
                "key_switch_borrows",
                proof.key_switch.decomposition.borrow_commitments.len(),
            ),
            (
                "key_switch_reciprocals",
                proof
                    .key_switch
                    .decomposition
                    .comparisons
                    .iter()
                    .map(|p| p.reciprocal_commitments.len())
                    .sum(),
            ),
        ]),
    }
}
