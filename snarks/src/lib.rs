use algebra::{AbstractExtensionField, Field};
use helper::Transcript;
use pcs::PolynomialCommitmentScheme;

pub mod cmp;
pub mod fhe_batch_op;
pub mod fhe_op;
pub mod lookup;
pub mod ntt;
/// Accumulator arithmetic, endpoint, continuity and decomposition-root linkage.
pub mod packed_accumulator;
/// Trusted public binary bootstrapping-key preprocessing and Hadamard binding.
pub mod packed_bootstrap_key;
/// Canonical radix reconstruction and public-table borrow comparison.
pub mod packed_decomposition;
/// Extension-field evaluations authenticated against canonical packed roots.
pub mod packed_extension;
/// Experimental extension-field tuple lookups over canonical packed roots.
pub mod packed_extension_lookup;
/// Original-size RLWE key switching and public LWE extraction linkage.
pub mod packed_key_switch;
/// Independent lookup challenges packed into helper lanes with canonical pullbacks.
pub mod packed_lane_lookup;
/// Linear identities between canonical packed source tables.
pub mod packed_linear;
/// Packed reciprocal lookup against a trusted small public scalar table.
pub mod packed_lookup;
/// Expected public monomial products and deterministic input preprocessing.
pub mod packed_monomial;
/// Packed NTT checks against canonical coefficient and evaluation commitments.
pub mod packed_ntt;
/// Canonical committed-table references shared across packed relations.
pub mod packed_oracle;
/// Experimental complete binary NAND PBS statement, proof and verifier API.
pub mod packed_pbs;
/// Root declarations in decoded complete packed proofs, for resource audits.
pub mod packed_root_inventory;
/// Experimental packed vector relations with authenticated terminal openings.
pub mod packed_relation;
/// Repeated tuple lookups authenticating original canonical columns.
pub mod packed_tuple_lookup;
pub mod sparse_matrix_eval;

#[derive(Default, Debug)]
pub struct SnarkStatistics {
    pub prover_pcs_time: std::time::Duration,
    pub verifier_pcs_time: std::time::Duration,
    /// Subset of prover PCS time spent committing (including helper oracles).
    pub prover_commit_time: std::time::Duration,
    /// Subset of prover PCS time spent opening commitments.
    pub prover_open_time: std::time::Duration,
    /// Explicitly tracked trace/bit/helper-input extension conversions.
    /// This excludes key preprocessing and does not cover every allocation.
    pub prover_extension_time: std::time::Duration,
}

impl SnarkStatistics {
    pub fn add_prover_commit_time(&mut self, dur: std::time::Duration) {
        self.prover_commit_time += dur;
        self.add_prover_pcs_time(dur);
    }

    pub fn add_prover_open_time(&mut self, dur: std::time::Duration) {
        self.prover_open_time += dur;
        self.add_prover_pcs_time(dur);
    }

    pub fn add_prover_pcs_time(&mut self, dur: std::time::Duration) {
        self.prover_pcs_time += dur;
    }

    pub fn add_verifier_pcs_time(&mut self, dur: std::time::Duration) {
        self.verifier_pcs_time += dur;
    }
}

/// Oracle used in the NTT matrix evaluation PIOP
pub struct EvalOracle<F, EF, S, PCS>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    PCS: PolynomialCommitmentScheme<F, EF, S>,
{
    pub poly: PCS::Polynomial,
    pub params: PCS::Parameters,
}

impl<F, EF, S, PCS> EvalOracle<F, EF, S, PCS>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    PCS: PolynomialCommitmentScheme<F, EF, S>,
{
    pub fn commit(&self) -> (PCS::Commitment, PCS::CommitmentState) {
        PCS::commit(&self.params, &self.poly)
    }

    pub fn open(
        &self,
        trans: &mut Transcript<EF>,
        comm: &PCS::Commitment,
        state: &PCS::CommitmentState,
        points: &[PCS::Point],
    ) -> PCS::Proof {
        PCS::open(&self.params, comm, state, points, trans)
    }
}

