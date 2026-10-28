//! Commitment slots carried by a complete packed PBS proof.
//!
//! Count only after verification: this describes the supplied proof, not its
//! validity or a trusted upper bound on adversarial resource use. Equal roots
//! in different slots are conservatively counted separately. Trusted public-key
//! roots, authentication siblings and transcript digests are excluded.
use algebra::Field;
use crate::{packed_decomposition, packed_extension_lookup, packed_lane_lookup,
            packed_pbs, packed_tuple_lookup};
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
    fn reciprocal_roots(&self) -> usize { self.reciprocal_commitments.len() }
}
impl<F: Field, EF: Field, O> LookupRoots for packed_extension_lookup::Proof<F, EF, O> {
    fn reciprocal_roots(&self) -> usize { self.reciprocal_commitments.len() }
}
impl<F:Field,EF:Field,O> LookupRoots for packed_extension_lookup::deferred::Proof<F,EF,O> {
    fn reciprocal_roots(&self)->usize {self.lookups.iter().map(LookupRoots::reciprocal_roots).sum()}
}
impl<F:Field,EF:Field,O> LookupRoots for packed_extension_lookup::shared::Proof<F,EF,O> {
    fn reciprocal_roots(&self)->usize {self.helper_roots.len()}
}
impl<F, O> LookupRoots for packed_tuple_lookup::Proof<F, O> {
    fn reciprocal_roots(&self) -> usize { self.reciprocal_commitments.len() }
}

/// Auxiliary commitments introduced by one canonical decomposition.
pub trait DecompositionRoots {
    fn borrow_roots(&self) -> usize;
    fn reciprocal_roots(&self) -> usize;
}
impl<F, O, P: LookupRoots> DecompositionRoots for packed_decomposition::Proof<F, O, P> {
    fn borrow_roots(&self) -> usize { self.borrow_commitments.len() }
    fn reciprocal_roots(&self) -> usize {
        self.comparisons.iter().map(LookupRoots::reciprocal_roots).sum()
    }
}

/// Inventory serialized root declarations; no proof or security checks occur here.
pub fn inventory<F, O, D: DecompositionRoots, A>(proof: &packed_pbs::Proof<F, O, D, A>) -> RootInventory {
    RootInventory { categories: BTreeMap::from([
        ("coefficients", proof.coefficients.len()),
        ("evaluations", proof.evaluations.len()),
        ("decomposition_inputs", proof.decomposition_inputs.len()),
        ("accumulators", proof.accumulators.len()),
        ("decomposition_borrows", proof.decomposition.iter().map(D::borrow_roots).sum()),
        ("decomposition_reciprocals", proof.decomposition.iter().map(D::reciprocal_roots).sum()),
        ("monomial_evaluations", proof.monomial.evaluations.len()),
        ("key_switch_coefficients", proof.key_switch.coefficients.len()),
        ("key_switch_evaluations", proof.key_switch.evaluations.len()),
        ("key_switch_borrows", proof.key_switch.decomposition.borrow_roots()),
        ("key_switch_reciprocals", proof.key_switch.decomposition.reciprocal_roots()),
    ]) }
}
