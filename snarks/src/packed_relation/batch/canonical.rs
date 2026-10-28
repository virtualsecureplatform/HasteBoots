//! Shared independent equations with canonical source authentication.
//! Root aliases are caller-derived under one context and common query.
use super::*;
use pcs::matrix_weighted::aggregate::canonical as pcs_batch;
const DOMAIN: &[u8] = b"HasteBoots canonical-source shared-challenge packed relations v1";
include!("protocol.rs.inc");
