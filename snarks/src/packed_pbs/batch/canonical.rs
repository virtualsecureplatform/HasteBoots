//! Complete PBS batch with canonical root deduplication.
//! The outer v7 packet checks all v6 member constraints and independently
//! checks every Hadamard equation, then authenticates each distinct root once.
//! Experimental, non-hiding; no whole-proof security certification.
use crate::packed_pbs::*;
use algebra::AbstractExtensionField;
use relation::batch::canonical as relations;
/// Identifier for the canonical-source complete batch transcript.
pub const TRANSCRIPT_ID: &str = "merlin-direct-canonical-source-pbs-batch-v1";
const OUTER_VERSION: u32 = 7;
const DOMAIN: &[u8] = b"HasteBoots complete binary NAND PBS canonical-source batch v7";
include!("protocol.rs.inc");
