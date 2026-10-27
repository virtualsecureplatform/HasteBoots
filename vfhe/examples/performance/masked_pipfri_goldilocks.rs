type FF = algebra::Goldilocks;
type EF = algebra::GoldilocksExtension5;
use vfhe::bfhe::GOLDILOCKS_BINARY_128_BITS_PARAMETERS as PARAMETERS;
const FIELD: &str = "goldilocks-ext5";
include!("masked_pipfri_pbs.rs.inc");
