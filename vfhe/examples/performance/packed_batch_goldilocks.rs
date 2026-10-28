type F = algebra::Goldilocks;
type EF = algebra::GoldilocksExtension3;
use vfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "goldilocks";
const WIDTH: usize = 4;
const HELPER_EXTRA: usize = 0;
include!("packed_batch_pbs.rs.inc");
