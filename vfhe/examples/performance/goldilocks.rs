type FF = algebra::Goldilocks;
type EF = algebra::GoldilocksExtension;
use vfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "goldilocks";
const BASE_FIELD_BITS: usize = 64;
include!("pbs.rs.inc");
