//! Complete ordered NAND PBS batches with one cross-statement Hadamard proof.
//! Each member retains every other canonical PBS check, including deferred
//! extension comparisons and final key switching into the original output key.
//! Experimental and non-hiding; no whole-proof security or promotion claim.
use super::*;
use algebra::AbstractExtensionField;

/// Transcript identifier for the outer complete joint-Hadamard batch protocol.
pub const TRANSCRIPT_ID:&str="merlin-direct-joint-hadamard-pbs-batch-v1";

/// Canonical-source joint authentication in a separate outer protocol.
pub mod canonical;
use relation::batch as relations;
const OUTER_VERSION: u32 = BATCH_PROTOCOL_VERSION;
const DOMAIN: &[u8] = b"HasteBoots complete binary NAND PBS joint Hadamard batch v6";
include!("batch/protocol.rs.inc");
