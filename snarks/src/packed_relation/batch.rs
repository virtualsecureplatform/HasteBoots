//! Ordered independent relations sharing a terminal matrix query and PCS packet.
//! Every relation equation is checked separately before joint authentication.
//! This is a non-hiding component, not yet a complete cross-statement PBS batch.
/// Shared relations with canonical root deduplication and distinct framing.
pub mod canonical;

use super::*;
use algebra::AbstractExtensionField;
use pcs::matrix_weighted::aggregate as pcs_batch;
use sumcheck::packed_zero::batch as zero;

const DOMAIN: &[u8] = b"HasteBoots shared-challenge packed relations v1";
include!("batch/protocol.rs.inc");
