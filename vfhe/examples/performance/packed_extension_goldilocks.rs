type F = algebra::Goldilocks;
type EF = algebra::GoldilocksExtension5;
use vfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "goldilocks";
include!("packed_extension_pbs.rs.inc");
